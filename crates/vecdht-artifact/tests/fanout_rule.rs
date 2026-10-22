//! Измерение `E-0032`: два правила выбора — по кластерам (собранный код) и по шардам
//! (спека §7.5.1). Пороги были зафиксированы в
//! `lab/hypotheses/H-0032-shard-rule-not-in-client-code.md` ДО прогона; прогон их не подтвердил,
//! поэтому `H-0032` закрыта как `refuted` (см. `lab/experiments/E-0032-shard-rule-vs-client-code.md`).
//!
//! Этот файл после закрытия гипотезы переписан в **описание измеренного** (characterization):
//! assert'ы ниже фиксируют то, что было снято в прогоне, а не предрегистрированный порог, и
//! служат регрессией на структуру выбора. Разница между «что утверждали» и «что измерено»
//! проговорена в записи эксперимента, здесь — только в именах и комментариях.
//!
//! Корпуса и `candle` нет: числа относятся к структуре выбора на эталонном артефакте
//! (`reference_artifact()`, синтетические центроиды-сетка), а не к recall.

use vecdht_artifact::reference_artifact;
use vecdht_crypto::quant::l2_sq;
use vecdht_wire::codec::DIM;
use vecdht_wire::constants::{CLUSTERS_PER_SHARD, SHARDS};

/// Детерминированный набор запросов: LCG, никаких случайных источников.
fn queries(n: usize) -> Vec<[i8; DIM]> {
    let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
    (0..n)
        .map(|_| {
            let mut v = [0i8; DIM];
            for slot in v.iter_mut() {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                *slot = ((state >> 33) & 0xFF) as i8;
            }
            v
        })
        .collect()
}

/// Правило собранного клиента: топ-`nprobe` кластеров, шарды — производные.
fn cluster_rule_shards(clusters: &[u16]) -> Vec<u16> {
    let mut set: Vec<u16> = clusters.iter().map(|c| c / CLUSTERS_PER_SHARD).collect();
    set.sort_unstable();
    set.dedup();
    set
}

/// Правило §7.5.1: расстояние до шарда = минимум по его 16 строкам; берутся `nprobe` наименьших.
fn shard_rule(vec_q: &[i8; DIM], rows: &[&[i8; DIM]], nprobe: usize) -> Vec<u16> {
    let mut by_shard: Vec<(u32, u16)> = (0..SHARDS)
        .map(|s| {
            let base = usize::from(s) * usize::from(CLUSTERS_PER_SHARD);
            let d = rows[base..base + usize::from(CLUSTERS_PER_SHARD)]
                .iter()
                .map(|r| l2_sq(vec_q, r))
                .min()
                .expect("у шарда есть строки");
            (d, s)
        })
        .collect();
    by_shard.sort_unstable();
    by_shard.truncate(nprobe);
    let mut out: Vec<u16> = by_shard.iter().map(|(_, s)| *s).collect();
    out.sort_unstable();
    out
}

fn jaccard(a: &[u16], b: &[u16]) -> f64 {
    let inter = a.iter().filter(|x| b.contains(x)).count();
    let union = a.len() + b.len() - inter;
    if union == 0 {
        0.0
    } else {
        inter as f64 / union as f64
    }
}

fn mean(v: &[usize]) -> f64 {
    v.iter().map(|x| *x as f64).sum::<f64>() / v.len() as f64
}

fn mean_f(v: &[f64]) -> f64 {
    v.iter().sum::<f64>() / v.len() as f64
}

fn median(mut v: Vec<usize>) -> f64 {
    v.sort_unstable();
    let n = v.len();
    if n % 2 == 1 {
        v[n / 2] as f64
    } else {
        (v[n / 2 - 1] + v[n / 2]) as f64 / 2.0
    }
}

/// Одна строка отчёта на одно значение `nprobe`.
struct Row {
    nprobe: usize,
    mean_cluster: f64,
    median_cluster: f64,
    min_cluster: usize,
    share_equal: f64,
    collisions: usize,
    mean_shard: f64,
    jaccard: f64,
    list_len: usize,
    all_shard_equal: bool,
    differing: usize,
}

#[test]
fn the_two_rules_coincide_at_nprobe_4_and_diverge_above_it() {
    let a = reference_artifact();
    let rows = a.centroids.rows();
    let qs = queries(256);

    // Снимка: сначала измеряем и печатаем все три значения `nprobe`, проверки после.
    // Assert внутри цикла обрывал бы прогон на первой точке, поэтому проверка вынесена в конец.
    let mut table: Vec<Row> = Vec::new();

    for nprobe in [4usize, 16, 32] {
        let mut by_cluster: Vec<usize> = Vec::new();
        let mut by_shard: Vec<usize> = Vec::new();
        let mut jac: Vec<f64> = Vec::new();
        let mut equal_to_nprobe = 0usize;
        let mut collision_queries = 0usize;
        let mut cluster_list_len = 0usize;

        for q in &qs {
            let clusters = a.centroids.top(q, nprobe);
            cluster_list_len = clusters.len();
            let shards_cluster = cluster_rule_shards(&clusters);
            let shards_rule = shard_rule(q, &rows, nprobe);
            by_cluster.push(shards_cluster.len());
            by_shard.push(shards_rule.len());
            jac.push(jaccard(&shards_cluster, &shards_rule));
            if shards_cluster.len() == nprobe {
                equal_to_nprobe += 1;
            }
            // Столкновение: два выбранных кластера в одном шарде (тогда fan-out < nprobe).
            if shards_cluster.len() < clusters.len() {
                collision_queries += 1;
            }
        }

        table.push(Row {
            nprobe,
            mean_cluster: mean(&by_cluster),
            median_cluster: median(by_cluster.clone()),
            min_cluster: *by_cluster.iter().min().expect("256 замеров"),
            share_equal: 100.0 * equal_to_nprobe as f64 / qs.len() as f64,
            collisions: collision_queries,
            mean_shard: mean(&by_shard),
            jaccard: mean_f(&jac),
            list_len: cluster_list_len,
            all_shard_equal: by_shard.iter().all(|&x| x == nprobe),
            differing: jac.iter().filter(|&&j| j < 1.0).count(),
        });
    }

    for r in &table {
        eprintln!(
            "## nprobe={}: кластерное правило — средний fan-out {:.2}, медиана {:.1}, минимум {}, ровно nprobe в {:.1} % запросов, запросов со столкновением кластеров в одном шарде {}; шардовое (§7.5.1) — {:.2}; список кластеров в Find {} (полный скан потребовал бы {}); средний Jaccard {:.3}; запросов с разными множествами шардов {} из 256 ##",
            r.nprobe,
            r.mean_cluster,
            r.median_cluster,
            r.min_cluster,
            r.share_equal,
            r.collisions,
            r.mean_shard,
            r.list_len,
            r.nprobe * usize::from(CLUSTERS_PER_SHARD),
            r.jaccard,
            r.differing
        );
    }

    // Ниже — описание измеренного, снятого в прогоне E-0032 (числа в записи эксперимента).
    // Инварианты, которые от порога не зависели и подтвердились:
    for r in &table {
        // Клиент шлёт список кластеров длины `nprobe`, никогда `nprobe * 16` («полный скан шарда»
        // через тип Find не выражается).
        assert_eq!(r.list_len, r.nprobe, "длина списка кластеров в Find поехала");
        // Шардовое правило по построению отдаёт ровно `nprobe` шардов на каждом запросе.
        assert!(r.all_shard_equal, "шардовое правило не отдаёт ровно nprobe шардов");
    }

    // Измеренная nprobe-зависимость (то, из-за чего H-0032 опровергнута): при nprobe = 4 правила
    // совпадают на всех 256 запросах, при 16 и 32 — расходятся.
    let r4 = &table[0];
    assert_eq!(r4.mean_cluster, 4.0, "при nprobe=4 средний fan-out не равен nprobe");
    assert_eq!(r4.collisions, 0, "при nprobe=4 столкновений не было");
    assert_eq!(r4.differing, 0, "при nprobe=4 множества шардов совпали на всех запросах");
    for r in &table[1..] {
        assert!(
            r.mean_cluster < r.nprobe as f64,
            "nprobe={}: кластерное правило не уже шардового",
            r.nprobe
        );
        assert!(
            r.differing * 2 >= qs.len(),
            "nprobe={}: различие множеств шардов на меньшинстве запросов",
            r.nprobe
        );
    }
}
