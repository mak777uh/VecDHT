//! Издательский конвейер: корпус → центроиды → карта шардов → опубликованные строки → `cluster_id`.
//!
//! Спека §7.1 и §7.4.1, решение `ADR-0004`. Здесь собирается воедино то, что до этого
//! существовало по частям: обучение центроидов (`crate::kmeans`), построение карты шардов
//! (`crate::shardmap`) и правило присваивания кластера (`crate::model::quantize_pooled` +
//! `vecdht_crypto::quant::assign_cluster`).
//!
//! **Что этот модуль НЕ меняет в протоколе.** Ни wire, ни формат артефакта, ни
//! `preprocessing_version`. Издатель публикует те же 1024 центроида, но в порядке «ячейка 0 →
//! её 16 строк, ячейка 1 → её 16 строк, …». Строка `i` остаётся кластером `i`, шард остаётся
//! `i / CLUSTERS_PER_SHARD` (§7.4), а правило §7.2 («argmin по опубликованным строкам») остаётся
//! тем же — меняется только то, в каком порядке строки лежат в файле.
//!
//! Три следствия, которые обязаны быть видны в коде, а не в комментарии:
//!
//! * **номера кластеров меняются.** Разрешённая перестановка `order` переводит кластер `c` в
//!   позицию `position(c)`, поэтому `cluster_id` каждой записи меняется вместе с картой;
//! * **присваивание пересчитывается по опубликованным строкам.** Узел при publish считает argmin
//!   по тем строкам, что лежат в артефакте, поэтому издатель обязан считать ровно то же самое —
//!   иначе запись легла бы в один кластер, а пришла бы в другой;
//! * **старые индексы не годятся.** Записи уже опубликованной сети несут `cluster_id` в старой
//!   нумерации; их надо переприсвоить ([`remap_clusters`]) и перестроить индекс.
//!
//! Оракул и записи: `E-0012` (карта), `E-0015` (цена потолка §7.5), `E-0016` (издатель на 50k).

use vecdht_artifact::Centroids;
use vecdht_crypto::quant::{assign_cluster, l2_normalize, quantize_slice};
use vecdht_crypto::DIM;
use vecdht_wire::{CLUSTERS_PER_SHARD, NLIST};

use crate::kmeans::{KMeansConfig, KMeansError};
use crate::model::{quantize_pooled, EmbedError};
use crate::shardmap::{build_shard_map, ShardMapError};

/// Seed нижнего уровня (k-means на корпусе) — тот же, что и в гейте (ii) §18.1.
///
/// Значение не произвольное: `E-0012` измерил карту именно на этом seed'е, и артефакт,
/// собранный с другим seed'ом, — это другой артефакт с другим `artifact_hash`, то есть другая
/// сеть. Менять seed — новая запись E, а не «подкрутить и повторить».
pub const PUBLISH_SEED: u64 = 0x5645_4344_4854_0002;

/// Верхний уровень карты шардов обучается с другим seed'ом: иначе оба уровня выбрали бы одну и
/// ту же случайную точку инициализации, и карта шардов получилась бы вырожденной.
const MAP_SEED_XOR: u64 = 0x0007;

/// Верхняя граница итераций k-means. Та же, что в гейте (ii): число влияет на скорость и на
/// сходимость, но не на порог.
pub const DEFAULT_MAX_ITERS: usize = 12;

/// Параметры издательского прогона.
#[derive(Debug, Clone, Copy)]
pub struct PublishConfig {
    /// Число центроидов (`nlist`). В протоколе — 1024, и `centroid.bin` обязан нести ровно
    /// столько строк (§7.1, §15.1).
    pub nlist: usize,
    /// Число кластеров на шард (`CLUSTERS_PER_SHARD`): 16.
    pub clusters_per_shard: usize,
    /// Верхняя граница итераций k-means на обоих уровнях.
    pub max_iters: usize,
    /// Seed нижнего уровня.
    pub seed: u64,
}

impl Default for PublishConfig {
    fn default() -> Self {
        Self {
            nlist: NLIST as usize,
            clusters_per_shard: CLUSTERS_PER_SHARD as usize,
            max_iters: DEFAULT_MAX_ITERS,
            seed: PUBLISH_SEED,
        }
    }
}

/// Ошибка издательского прогона.
#[derive(Debug, thiserror::Error)]
pub enum PublishError {
    #[error("корпус пуст: обучать центроиды не на чем")]
    Empty,
    #[error("корпус: {values} значений не делятся на DIM={DIM}")]
    BadShape { values: usize },
    #[error("корпус из {docs} документов меньше nlist={nlist}: k-means не может дать больше кластеров, чем точек")]
    TooFewDocs { nlist: usize, docs: usize },
    #[error("nlist={nlist} не кратно числу кластеров на шард {per_shard}: ровная карта невозможна (§7.4.1)")]
    NotDivisible { nlist: usize, per_shard: usize },
    #[error("k-means: {0}")]
    KMeans(#[from] KMeansError),
    #[error("карта шардов: {0}")]
    ShardMap(#[from] ShardMapError),
    #[error("вектор записи: {0}")]
    Embed(#[from] EmbedError),
    #[error("квантование: {0}")]
    Quant(#[from] vecdht_crypto::quant::QuantError),
    #[error("centroid.bin: {0}")]
    Centroids(#[from] vecdht_artifact::CentroidError),
}

/// Диагностика прогона: то, что оператор обязан увидеть, а не то, что можно не заметить.
#[derive(Debug, Clone)]
pub struct PublishStats {
    /// Число документов корпуса.
    pub docs: usize,
    /// Итераций k-means нижнего уровня.
    pub kmeans_iterations: usize,
    /// Итераций k-means верхнего уровня (карты шардов).
    pub map_iterations: usize,
    /// Сумма `l2_sq` (int8) от мелкого центроида до центроида своей ячейки — цена назначения.
    pub map_cost: u64,
    /// Размеры кластеров в **опубликованной** нумерации.
    pub counts: Vec<u32>,
    /// Сколько кластеров осталось пустыми.
    pub empty_clusters: usize,
    /// Размер самого большого кластера.
    pub max_cluster: u32,
    /// Компактность шардов: среднее по шардам расстояние от члена шарда до центроида шарда
    /// (int8 `l2_sq`). Чем меньше, тем шард связнее. Та же метрика, что в `E-0012`, — по ней
    /// карта издателя сверяется с картой, на которой измерялся гейт.
    pub dispersion: f64,
}

/// Результат издательского прогона: всё, что нужно, чтобы собрать артефакт и построить индекс.
#[derive(Debug, Clone)]
pub struct Published {
    /// Опубликованные строки `centroid.bin` — в порядке шардов: строки `0..16` — шард 0,
    /// `16..32` — шард 1 и так далее.
    pub rows: Vec<[i8; DIM]>,
    /// `order[p]` — исходный номер кластера на опубликованной позиции `p`.
    pub order: Vec<u16>,
    /// `cluster_of_doc[d]` — кластер документа `d` в **опубликованной** нумерации.
    pub cluster_of_doc: Vec<u16>,
    /// Исходные центроиды (до перенумерации): нужны для сверки с оракулом и для диагностики.
    pub source_rows: Vec<[i8; DIM]>,
    /// Номер грубой ячейки для каждого исходного кластера (те же ячейки, что и в карте).
    pub cell_of_cluster: Vec<u16>,
    /// Статистика прогона.
    pub stats: PublishStats,
    /// Число кластеров на шард.
    pub per_shard: usize,
}

impl Published {
    /// Число шардов карты.
    pub fn shards(&self) -> usize {
        self.rows.len() / self.per_shard
    }

    /// Шард кластера в опубликованной нумерации: `cluster_id / CLUSTERS_PER_SHARD` (§7.4).
    pub fn shard_of(&self, cluster: u16) -> u16 {
        cluster / self.per_shard as u16
    }

    /// Позиция исходного кластера `c` в опубликованном порядке — обратная перестановка.
    pub fn published_position(&self, source_cluster: u16) -> Option<u16> {
        self.order.iter().position(|&c| c == source_cluster).map(|p| p as u16)
    }

    /// `centroid.bin` из опубликованных строк.
    ///
    /// Ошибка — не «упалось записать», а несоответствие контракту: файл обязан нести ровно
    /// `NLIST × DIM` байт (§15.1), и артефакт с другим числом строк сеть не примет.
    pub fn centroids(&self) -> Result<Centroids, PublishError> {
        let mut bytes: Vec<i8> = Vec::with_capacity(self.rows.len() * DIM);
        for row in &self.rows {
            bytes.extend_from_slice(row);
        }
        Centroids::from_i8(&bytes).map_err(PublishError::Centroids)
    }
}

/// Издать сеть по корпусу: обучить центроиды, построить карту шардов, перенумеровать и
/// переприсвоить кластеры документов.
///
/// `vectors` — эмбеддинги корпуса в том виде, в каком их отдаёт шаг 4 (pooled `f32`,
/// **ненормированные**): нормализация и квантование — шаги 6–7 (§6.2), и издатель обязан
/// выполнить их сам, иначе опубликованный `cluster_id` разошёлся бы с тем, что посчитает узел.
///
/// Порядок шагов и почему он именно такой:
///
/// 1. **квантование документов** — тем же кодом, что и у записи (`quantize_pooled`), иначе
///    узел и издатель посчитают разные кластеры для одного и того же вектора;
/// 2. **k-means нижнего уровня** — `nlist` центроидов по корпусу, cap §7.6 (`2×N/nlist`);
/// 3. **квантование центроидов** — в ту же сетку Δ=1/127, что и у записей (§6.3);
/// 4. **карта шардов** — транспортная задача (§7.4.1, `crate::shardmap`): ровно
///    `clusters_per_shard` кластеров на шард при минимальной сумме расстояний;
/// 5. **присваивание документов** — argmin по **опубликованным** строкам (§7.2), то есть ровно
///    то, что узел посчитает при publish.
///
/// Результат детерминирован: тот же корпус, тот же seed и тот же `nlist` дают побайтово те же
/// строки и тот же `artifact_hash`. Число потоков на результат не влияет.
pub fn publish(
    vectors: &[f32],
    config: &PublishConfig,
    threads: usize,
) -> Result<Published, PublishError> {
    if vectors.is_empty() {
        return Err(PublishError::Empty);
    }
    if vectors.len() % DIM != 0 {
        return Err(PublishError::BadShape { values: vectors.len() });
    }
    let docs = vectors.len() / DIM;
    if config.nlist == 0 || config.nlist > docs {
        return Err(PublishError::TooFewDocs { nlist: config.nlist, docs });
    }
    if config.clusters_per_shard == 0 || config.nlist % config.clusters_per_shard != 0 {
        return Err(PublishError::NotDivisible {
            nlist: config.nlist,
            per_shard: config.clusters_per_shard,
        });
    }
    let threads = threads.max(1);

    // Шаги 6–7 для документов: нормализация и квантование — ровно те, что у записи (§6.3).
    let doc_q: Vec<[i8; DIM]> = vectors
        .chunks_exact(DIM)
        .map(|row| {
            let pooled: &[f32; DIM] = row.try_into().expect("строка ровно DIM");
            quantize_pooled(pooled)
        })
        .collect::<Result<Vec<_>, _>>()?;

    // Единичные строки для k-means: тот же L2, что и у `finalize`, иначе центроиды считались бы
    // по другой геометрии, чем та, по которой потом считается расстояние.
    let unit = normalize_rows(vectors)?;

    // Нижний уровень: центроиды по корпусу. Cap §7.6 — `2×N/NLIST`.
    let cap = (2 * docs).div_ceil(config.nlist).max(1);
    let lower = KMeansConfig {
        k: config.nlist,
        max_iters: config.max_iters,
        seed: config.seed,
        balance_cap: cap,
    };
    let trained = crate::kmeans::train(&unit, DIM, lower, threads)?;

    // Центроиды — в ту же сетку, что и записи: сравнивать вектор с центроидом без общего
    // масштаба нельзя (§6.3).
    let centroid_f64: Vec<f64> = trained.centroids.iter().map(|&x| f64::from(x)).collect();
    let source_rows: Vec<[i8; DIM]> = centroid_f64
        .chunks_exact(DIM)
        .map(quantize_slice)
        .collect::<Result<Vec<_>, _>>()?;

    // Карта шардов: ровно `clusters_per_shard` кластеров на шард при минимальной цене (§7.4.1).
    let map = build_shard_map(
        &trained.centroids,
        &source_rows,
        config.clusters_per_shard,
        KMeansConfig {
            k: config.nlist / config.clusters_per_shard,
            max_iters: config.max_iters,
            seed: config.seed ^ MAP_SEED_XOR,
            balance_cap: config.clusters_per_shard,
        },
        threads,
    )?;

    // Присваивание по опубликованным строкам: ровно то, что посчитает узел (§7.2).
    let cluster_of_doc = assign_all(&doc_q, &map.rows, threads);

    let mut counts = vec![0u32; map.rows.len()];
    for &c in &cluster_of_doc {
        counts[c as usize] += 1;
    }
    let empty_clusters = counts.iter().filter(|&&c| c == 0).count();
    let max_cluster = counts.iter().copied().max().unwrap_or(0);
    let dispersion = dispersion_of_shards(&map.rows, config.clusters_per_shard);

    Ok(Published {
        rows: map.rows,
        order: map.order,
        cluster_of_doc,
        source_rows,
        cell_of_cluster: map.cell_of_cluster,
        stats: PublishStats {
            docs,
            kmeans_iterations: trained.iterations,
            map_iterations: map.iterations,
            map_cost: map.total_cost,
            counts,
            empty_clusters,
            max_cluster,
            dispersion,
        },
        per_shard: config.clusters_per_shard,
    })
}

/// Переприсвоить кластеры записей под опубликованные центроиды.
///
/// Номера кластеров после смены карты другие, поэтому записи, уже лежащие в индексе, надо
/// пересчитать: иначе шард продолжит отдавать записи не из того кластера, в который их
/// положили. Правило — то же, что у узла при publish (§7.2): argmin `l2_sq` по опубликованным
/// строкам. Считать «просто переставить номера» нельзя: при равных расстояниях tie-break —
/// наименьший индекс центроида, а после перенумерации он указывает на другой кластер.
pub fn remap_clusters(vectors: &[[i8; DIM]], rows: &[[i8; DIM]]) -> Vec<u16> {
    assign_all(vectors, rows, 1)
}

/// Присвоить кластер каждому вектору по опубликованным строкам. Потоки не влияют на результат:
/// каждое присваивание независимо, а порядок обхода внутри чанка фиксирован.
fn assign_all(vectors: &[[i8; DIM]], rows: &[[i8; DIM]], threads: usize) -> Vec<u16> {
    let refs: Vec<&[i8; DIM]> = rows.iter().collect();
    let threads = threads.max(1);
    if threads == 1 || vectors.len() < 1024 {
        return vectors.iter().map(|v| assign_cluster(v, &refs)).collect();
    }
    let chunk = vectors.len().div_ceil(threads);
    let mut out = vec![0u16; vectors.len()];
    // `refs` копируется в замыкание по ссылке: сам вектор ссылок не перемещается, иначе второй
    // поток его уже не увидел бы.
    let refs = &refs;
    std::thread::scope(|scope| {
        for (t, part) in out.chunks_mut(chunk).enumerate() {
            let start = t * chunk;
            scope.spawn(move || {
                for (i, slot) in part.iter_mut().enumerate() {
                    *slot = assign_cluster(&vectors[start + i], refs);
                }
            });
        }
    });
    out
}

/// Единичные строки корпуса для k-means: тот же L2, что и у `finalize` (§6.2 шаг 6).
fn normalize_rows(vectors: &[f32]) -> Result<Vec<f32>, PublishError> {
    let mut out = Vec::with_capacity(vectors.len());
    for row in vectors.chunks_exact(DIM) {
        let mut d = [0f64; DIM];
        for (dst, &src) in d.iter_mut().zip(row) {
            *dst = f64::from(src);
        }
        l2_normalize(&mut d).map_err(EmbedError::Quant)?;
        out.extend(d.iter().map(|&x| x as f32));
    }
    Ok(out)
}

/// Компактность шардов: среднее по шардам расстояние от члена шарда до центроида шарда.
///
/// Метрика та же, что в `E-0012`, чтобы карту издателя можно было сверить с картой, на которой
/// измерялся гейт: те же 16 строк шарда, тот же центроид (среднее по int8-строкам, квантованное
/// на сетке Δ=1/127), то же усреднение по всем членам.
fn dispersion_of_shards(rows: &[[i8; DIM]], per_shard: usize) -> f64 {
    let mut sum = 0f64;
    let mut count = 0f64;
    for shard in rows.chunks_exact(per_shard) {
        if shard.is_empty() {
            continue;
        }
        let mut mean = vec![0f64; DIM];
        for row in shard {
            for (acc, &v) in mean.iter_mut().zip(row) {
                *acc += f64::from(v);
            }
        }
        for v in mean.iter_mut() {
            *v /= shard.len() as f64;
        }
        let center = match quantize_slice(&mean) {
            Ok(c) => c,
            Err(_) => continue,
        };
        for row in shard {
            sum += f64::from(vecdht_crypto::quant::l2_sq(row, &center));
            count += 1.0;
        }
    }
    if count == 0.0 {
        0.0
    } else {
        sum / count
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vecdht_crypto::quant::l2_sq;

    /// Корпус из `n` облаков по `per_cloud` векторов: кластеры должны получиться различимыми,
    /// а карта — ровной. Модель данных простая, но контракт проверяет целиком.
    fn clouds(n_clouds: usize, per_cloud: usize, dim: usize) -> Vec<f32> {
        let mut out = Vec::with_capacity(n_clouds * per_cloud * dim);
        for c in 0..n_clouds {
            for i in 0..per_cloud {
                let mut v = vec![0f32; dim];
                v[c % dim] = 1.0;
                v[(c + 1) % dim] = (i as f32 + 1.0) * 1e-3;
                let norm: f32 = v.iter().map(|x| x * x).sum::<f32>().sqrt();
                for x in v.iter_mut() {
                    *x /= norm;
                }
                out.extend(v);
            }
        }
        out
    }

    fn config(nlist: usize, per_shard: usize) -> PublishConfig {
        PublishConfig { nlist, clusters_per_shard: per_shard, max_iters: 6, seed: PUBLISH_SEED }
    }

    #[test]
    fn published_rows_are_shard_blocks_of_exact_size() {
        let corpus = clouds(16, 8, DIM);
        let pub_ = publish(&corpus, &config(64, 8), 2).expect("издатель публикует");
        assert_eq!(pub_.rows.len(), 64);
        assert_eq!(pub_.order.len(), 64);
        assert_eq!(pub_.per_shard, 8);
        assert_eq!(pub_.shards(), 8);
        for shard in 0..8usize {
            let block = &pub_.rows[shard * 8..(shard + 1) * 8];
            assert_eq!(block.len(), 8, "шард {shard} неполон");
        }
        // Строка `p` публикуется как кластер `p`, и её шард — `p / per_shard` (§7.4).
        for p in 0..pub_.order.len() {
            assert_eq!(pub_.shard_of(p as u16) as usize, p / 8);
            assert_eq!(pub_.cell_of_cluster[pub_.order[p] as usize] as usize, p / 8);
        }
        // Перестановка — перестановка: ни один кластер не потерян и не продублирован.
        let mut sorted = pub_.order.clone();
        sorted.sort_unstable();
        assert_eq!(sorted, (0..64u16).collect::<Vec<_>>());
    }

    #[test]
    fn documents_get_the_cluster_the_node_rule_gives() {
        let corpus = clouds(16, 8, DIM);
        let pub_ = publish(&corpus, &config(64, 8), 2).expect("издатель публикует");
        let refs: Vec<&[i8; DIM]> = pub_.rows.iter().collect();
        for (d, &cluster) in pub_.cluster_of_doc.iter().enumerate() {
            let row: &[f32; DIM] = corpus[d * DIM..(d + 1) * DIM].try_into().expect("DIM");
            let vec_q = quantize_pooled(row).expect("квантование документа");
            assert_eq!(
                assign_cluster(&vec_q, &refs),
                cluster,
                "документ {d}: издатель и узел обязаны посчитать один кластер (§7.2)"
            );
            // Кластер лежит в своём шарде.
            assert_eq!(pub_.shard_of(cluster) as usize, cluster as usize / 8);
        }
    }

    #[test]
    fn publishing_is_deterministic_and_thread_count_does_not_matter() {
        let corpus = clouds(16, 8, DIM);
        let a = publish(&corpus, &config(64, 8), 1).expect("издатель публикует");
        let b = publish(&corpus, &config(64, 8), 4).expect("издатель публикует");
        assert_eq!(a.rows, b.rows, "строки артефакта обязаны совпадать побайтово");
        assert_eq!(a.order, b.order);
        assert_eq!(a.cluster_of_doc, b.cluster_of_doc);
        assert_eq!(a.stats.map_cost, b.stats.map_cost);
    }

    #[test]
    fn remap_moves_records_into_the_new_numbering() {
        let corpus = clouds(16, 8, DIM);
        let pub_ = publish(&corpus, &config(64, 8), 2).expect("издатель публикует");
        let rows: Vec<[i8; DIM]> = pub_.rows.clone();
        let vectors: Vec<[i8; DIM]> = corpus
            .chunks_exact(DIM)
            .map(|row| {
                let pooled: &[f32; DIM] = row.try_into().expect("DIM");
                quantize_pooled(pooled).expect("квантование")
            })
            .collect();
        let remapped = remap_clusters(&vectors, &rows);
        assert_eq!(remapped, pub_.cluster_of_doc, "переприсвоение обязано совпасть с издателем");
        // Переприсвоенный кластер действительно ближе к опубликованной строке, чем любая другая.
        for (v, &c) in vectors.iter().zip(remapped.iter()) {
            let best = l2_sq(v, &rows[c as usize]);
            for (other, row) in rows.iter().enumerate() {
                if other != c as usize {
                    assert!(l2_sq(v, row) >= best, "кластер {c} не является ближайшим");
                }
            }
        }
    }

    #[test]
    fn fewer_documents_than_clusters_is_refused_not_silently_truncated() {
        let corpus = clouds(4, 2, DIM);
        let err = publish(&corpus, &config(64, 8), 1).expect_err("nlist больше корпуса");
        assert!(matches!(err, PublishError::TooFewDocs { nlist: 64, docs: 8 }));
    }

    #[test]
    fn an_indivisible_nlist_is_refused() {
        let corpus = clouds(16, 8, DIM);
        let err = publish(&corpus, &config(60, 8), 1).expect_err("nlist не кратен 8");
        assert!(matches!(err, PublishError::NotDivisible { nlist: 60, per_shard: 8 }));
    }

    #[test]
    fn a_broken_shape_is_refused() {
        let err = publish(&[0.1f32; DIM + 1], &config(2, 1), 1).expect_err("хвост");
        assert!(matches!(err, PublishError::BadShape { .. }));
        let err = publish(&[], &config(2, 1), 1).expect_err("пусто");
        assert!(matches!(err, PublishError::Empty));
    }
}
