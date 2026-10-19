//! Оракулы для тестов и harness'а (§18.1).
//!
//! Здесь живёт то, что позволяет измерять детерминизм **до** появления весов: модель, чей output
//! вычисляется из blake3 текста, и синтетический int8-корпус для IVF. Ни то, ни другое не является
//! «моделью получше» — это ровно те байты, на которых проверяются шаги 6–8 пайплайна §6.2,
//! квантование и маршрутизация.

use vecdht_artifact::Pooling;
use vecdht_crypto::DIM;
use vecdht_wire::NLIST;

use crate::model::{EmbedError, EmbeddingModel, Pooled};

/// Контекст для derive-ключей: чтобы оракул никогда не столкнулся с настоящими доменами (§6.5).
const HASH_MODEL_CONTEXT: &str = "vecdht/v8/testing/hash-model";
const SYNTHETIC_CONTEXT: &str = "vecdht/v8/testing/synthetic";

/// Имя тестовой модели в `manifest.model_version`. Отдельное от гранита, чтобы `check_model`
/// не мог принять оракул за контрактную модель.
pub const HASH_MODEL_VERSION: &str = "test-hash-model-v1";

/// Детерминированная «модель»: pooled-вектор = blake3-XOF от входа.
///
/// Свойства, которые делают её полезной:
/// * выход зависит от каждого байта входа и не зависит от порядка вызовов, потоков и машины
///   (blake3 даёт один и тот же XOF-поток на любой платформе);
/// * без `sin`/`exp`/`log` — никаких libm-расхождений, на которых как раз и ломается детерминизм;
/// * координаты лежат в `[-1, 1]`, поэтому шаг 6 (L2 в f64) и шаг 7 (Δ=1/127) отрабатывают на
///   правдоподобном входе, а не на нулевом векторе.
#[derive(Debug, Clone)]
pub struct HashModel {
    preprocessing_version: u16,
}

impl Default for HashModel {
    fn default() -> Self {
        Self::new()
    }
}

impl HashModel {
    /// Модель на `PREPROCESSING_VERSION` этого crate — совпадает с эталонным манифестом.
    pub fn new() -> Self {
        Self { preprocessing_version: crate::PREPROCESSING_VERSION }
    }

    /// Модель «из другой генерации preprocessинга» — для теста `MODEL_MISMATCH` (§6.7).
    pub fn with_preprocessing(version: u16) -> Self {
        Self { preprocessing_version: version }
    }
}

impl EmbeddingModel for HashModel {
    fn embed_pooled(&self, model_input: &str) -> Result<Pooled, EmbedError> {
        let mut h = blake3::Hasher::new_derive_key(HASH_MODEL_CONTEXT);
        h.update(model_input.as_bytes());
        // Двух байтов на координату хватает: i16 → f32 делением на 32767 даёт сетку ~6e-5, что
        // мельче шага квантования 1/127 ≈ 7.9e-3 — то есть вход не «уже квантован» заранее.
        let mut raw = [0u8; DIM * 2];
        h.finalize_xof().fill(&mut raw);
        let mut out = [0f32; DIM];
        for i in 0..DIM {
            let q = i16::from_le_bytes([raw[2 * i], raw[2 * i + 1]]);
            out[i] = f32::from(q) / 32767.0;
        }
        // Нулевой вектор нормализуется в ноль и был бы ошибкой `DegenerateNorm`; вероятность
        // случайно получить его из 384 координат — 2⁻⁷⁶⁸, но проверка обязана быть, а не «повезёт».
        if out.iter().all(|x| *x == 0.0) {
            out[0] = 1.0;
        }
        Ok(out)
    }

    fn model_version(&self) -> &str {
        HASH_MODEL_VERSION
    }

    fn preprocessing_version(&self) -> u16 {
        self.preprocessing_version
    }

    fn pooling(&self) -> Pooling {
        // Оракул не делает pooling'а вообще: он выдаёт уже «pooled». CLS выбран как значение по
        // умолчанию эталонного манифеста (§6.1), чтобы тесты не падали на сверке полей.
        Pooling::Cls
    }
}

/// Синтетический int8-корпус для измерения IVF (§8.6) и стоимости assign (§6.1).
///
/// Геометрия трёхуровневая, целиком целочисленная: супер-блок (амплитуда 48) → центроид кластера
/// (±8) → точка внутри кластера (±6). Каждый `BOUNDARY_EVERY`-й записи корпуса — «пограничная»: её
/// сознательно тянет к соседнему центроиду того же супер-блока.
///
/// Зачем пограничные точки нужны отдельным правилом. Случайно-знаковый шум сам границу не
/// пересекает никогда: присваивание кластера (`assign_cluster`, §7.2) separable по координатам,
/// знак каждой координаты точки = знак её центроида, пока `|шум| < AMP_CENTER`, а одного
/// перевёрнутого знака уже достаточно, чтобы точка ушла в другой из 1024 кластеров. Значит либо
/// `шум >= AMP_CENTER` и уходит практически всё (кластерная структура исчезает), либо `шум <
/// AMP_CENTER` и не уходит ничего — а второй случай делает гейт (ii) тождеством: `nprobe=1`
/// давал бы recall 1.0 и стенд не измерял бы ничего. Пограничная точка лежит ровно посередине
/// между двумя центроидами, и её принадлежность решает бросок монеты по каждой координате — то
/// есть настоящий трудный случай IVF, а не искусственный.
///
/// Значения — из blake3-XOF, без `sin`/`exp`: данные замера обязаны быть одинаковыми на двух
/// машинах (§18.3 про golden-векторы), иначе recall-число нельзя сравнить с чужим прогоном.
#[derive(Debug, Clone)]
pub struct Synthetic {
    /// Ровно `NLIST` строк — глобальный квантизатор (§7.1).
    pub centers: Vec<[i8; DIM]>,
    /// Точки корпуса: `points[c * per_center .. (c + 1) * per_center]` относятся к `centers[c]`.
    pub points: Vec<[i8; DIM]>,
    /// Зоны видимости запроса: отдельные точки того же распределения, **не** входящие в корпус.
    pub queries: Vec<[i8; DIM]>,
}

/// Амплитуды уровней: расстояние между кластерами одного супер-блока сопоставимо с разбросом
/// внутри кластера — это и есть режим, в котором `nprobe` решает recall.
const AMP_SUPER: i32 = 48;
const AMP_CENTER: i32 = 8;
const AMP_POINT: i32 = 6;

/// Каждая восьмая запись корпуса — пограничная между двумя кластерами. Доля выбрана так, чтобы
/// и пограничные случаи были видны в статистике за несколько тысяч точек, и корпус не превратился
/// в кашу.
const BOUNDARY_EVERY: usize = 8;

/// Сдвиг сида запросов: зоны «корпус» и «запросы» не должны порождать одинаковые точки.
const QUERY_SEED_BASE: usize = 9_000;

impl Synthetic {
    /// `per_center` точек на каждый из `NLIST` центроидов плюс `n_queries` отдельных запросов.
    pub fn generate(per_center: usize, n_queries: usize) -> Self {
        let centers: Vec<[i8; DIM]> = (0..NLIST as usize).map(center_vector).collect();
        let mut points = Vec::with_capacity(NLIST as usize * per_center);
        for c in 0..NLIST as usize {
            for p in 0..per_center {
                // Шаг считается по абсолютному индексу точки, а не по `p`: иначе при
                // `per_center < BOUNDARY_EVERY` граница не появилась бы вообще, и быстрый режим
                // harness'а измерял бы другой корпус, чем полный.
                let id = c * per_center + p;
                points.push(point_vector(c, p, (id + 1) % BOUNDARY_EVERY == 0));
            }
        }
        // Запросы раскидываем по кластерам круговым сдвигом, чтобы их «правильный» центроид не
        // совпадал с индексом точки — иначе тест измерял бы нумерацию, а не маршрутизацию.
        let queries: Vec<[i8; DIM]> = (0..n_queries)
            .map(|q| point_vector((q * 7 + 3) % NLIST as usize, QUERY_SEED_BASE + q, false))
            .collect();
        Self { centers, points, queries }
    }

    pub fn len(&self) -> usize {
        self.points.len()
    }

    pub fn is_empty(&self) -> bool {
        self.points.is_empty()
    }

    /// Байты всех центроидов в формате `centroid.bin` (для `Centroids::from_i8`).
    pub fn centroid_bytes(&self) -> Vec<i8> {
        let mut out = Vec::with_capacity(NLIST as usize * DIM);
        for row in &self.centers {
            out.extend_from_slice(row);
        }
        out
    }
}

fn xof(tag: &str, seed: u64) -> [u8; DIM] {
    let mut h = blake3::Hasher::new_derive_key(SYNTHETIC_CONTEXT);
    h.update(tag.as_bytes());
    h.update(&seed.to_le_bytes());
    let mut b = [0u8; DIM];
    h.finalize_xof().fill(&mut b);
    b
}

/// Случайные знаки на фиксированной амплитуде: `+amp` или `-amp` по биту из XOF.
fn signed(bytes: &[u8; DIM], amp: i32) -> Vec<i32> {
    bytes.iter().map(|&b| if b & 1 == 0 { amp } else { -amp }).collect()
}

fn center_vector(c: usize) -> [i8; DIM] {
    let super_part = signed(&xof("super", (c / 16) as u64), AMP_SUPER);
    let center_part = signed(&xof("center", c as u64), AMP_CENTER);
    let mut v = [0i8; DIM];
    for i in 0..DIM {
        v[i] = (super_part[i] + center_part[i]) as i8;
    }
    v
}

fn point_vector(c: usize, p: usize, boundary: bool) -> [i8; DIM] {
    let base = center_vector(c);
    // Сид точки привязан к (c, p) и к «зоне» (корпус/запросы), чтобы запросы не дублировали точки.
    let noise = signed(&xof("point", (c as u64) * 1_000_003 + p as u64), AMP_POINT);
    // Пограничный сдвиг применяется только к корпусу: запросы обязаны оставаться «обычными»
    // точками своего кластера, иначе стенд путал бы трудный случай индексирования с трудным
    // случаем поиска.
    let pull = if boundary { half_toward(c) } else { [0i32; DIM] };
    let mut v = [0i8; DIM];
    for i in 0..DIM {
        v[i] = (base[i] as i32 + noise[i] + pull[i]).clamp(-127, 127) as i8;
    }
    v
}

/// Соседний центроид того же супер-блока: чётные индексы идут парами, а блок начинается с чётного,
/// поэтому `c` и его пара всегда имеют одинаковую `super`-часть и различаются только знаками
/// `center`-части.
fn sibling_of(c: usize) -> usize {
    if c % 2 == 0 {
        c + 1
    } else {
        c - 1
    }
}

/// Половина пути от центроида `c` к его соседнему центроиду: по координатам, где знаки совпадают,
/// сдвиг нулевой, а где различаются — ровно `AMP_CENTER`. Точка с таким сдвигом одинаково удалена
/// от обоих центроидов до броска шума, то есть лежит на границе их разбиения.
fn half_toward(c: usize) -> [i32; DIM] {
    let me = center_vector(c);
    let other = center_vector(sibling_of(c));
    std::array::from_fn(|i| (i32::from(other[i]) - i32::from(me[i])) / 2)
}

#[cfg(test)]
mod tests {
    use super::*;
    use vecdht_crypto::quant::l2_sq;

    #[test]
    fn hash_model_is_stable_and_text_sensitive() {
        let m = HashModel::new();
        let a = m.embed_pooled("ищу партнёра").unwrap();
        let b = m.embed_pooled("ищу партнёра").unwrap();
        assert_eq!(a, b);
        assert_ne!(a, m.embed_pooled("ищу  партнёра").unwrap());
        assert_eq!(m.preprocessing_version(), crate::PREPROCESSING_VERSION);
    }

    #[test]
    fn hash_model_output_is_finite_and_in_range() {
        let m = HashModel::new();
        for t in ["", "а", "\u{1f600} emoji", &"x".repeat(2000)] {
            let p = m.embed_pooled(t).unwrap();
            assert_eq!(p.len(), DIM);
            for &x in p.iter() {
                assert!(x.is_finite() && x.abs() <= 1.0, "pooled вне контракта: {x}");
            }
            // И не вырождается в нуль: иначе `quantize_pooled` упал бы на `DegenerateNorm`.
            assert!(p.iter().any(|x| *x != 0.0));
        }
    }

    #[test]
    fn synthetic_is_reproducible_and_within_i8() {
        let a = Synthetic::generate(2, 4);
        let b = Synthetic::generate(2, 4);
        assert_eq!(a.points, b.points);
        assert_eq!(a.centers, b.centers);
        assert_eq!(a.queries, b.queries);
        assert_eq!(a.centroid_bytes().len(), NLIST as usize * DIM);
        assert_eq!(a.len(), NLIST as usize * 2);
        for v in a.points.iter().chain(a.centers.iter()).chain(a.queries.iter()) {
            for &x in v.iter() {
                // Максимум по амплитудам: 48 + 8 + 6 = 62, и ни одна координата не вылезла за
                // сетку — иначе `point_vector` уже резал бы данные, а замер искажался бы молча.
                // Пограничный сдвиг не добавляет сверху: он `(C' - C)/2`, то есть там, где он
                // ненулевой, он ровно *отнимает* `AMP_CENTER` у базового центроида.
                assert!(i32::from(x).abs() <= AMP_SUPER + AMP_CENTER + AMP_POINT);
            }
        }
    }

    #[test]
    fn synthetic_geometry_is_a_real_ivf_test_not_an_identity() {
        // Точка обязана быть ближе к своему центроиду, чем к чужому — иначе корпус вообще не
        // похож на данные, и recall по нему ничего не значит. Но не обязана быть *самой* близкой:
        // как раз пограничные записи (`BOUNDARY_EVERY`) уходят в соседний кластер, и это то, что
        // делает гейт (ii) измерением, а не тождеством.
        let s = Synthetic::generate(2, 4);
        let mut own = 0usize;
        let mut moved = 0usize;
        // Первые 200 точек: полный перебор 2048 × 1024 дистанций в debug — это секунды, а смысл
        // проверки от последних 1800 ничего не выигрывает.
        for (i, p) in s.points.iter().take(200).enumerate() {
            let want = (i / 2) as u16;
            if best_center(&s, p) == want {
                own += 1;
            } else {
                moved += 1;
            }
        }
        let pct = 100.0 * moved as f64 / (own + moved) as f64;
        println!("пограничных записей сменило кластер: {moved} из {} ({pct:.1}%)", own + moved);
        assert!(own > moved, "большая часть точек обязана оставаться в своём кластере");
        assert!(moved > 0, "шум обязан хотя бы иногда менять кластер — иначе (ii) ничего не меряет");
        assert!(pct > 1.0, "доля ушедших {pct:.1}% мала: nprobe=1 давал бы recall почти 1.0");
        assert!(pct < 25.0, "доля ушедших {pct:.1}% велика: корпус перестаёт быть кластерным");
    }

    #[test]
    fn synthetic_centroids_are_loadable_by_the_real_artifact_type() {
        // Корпус обязан проходить через `Centroids` (§7.1): если `centroid_bytes()` не бьётся с
        // NLIST×DIM, harness молча измерял бы другой квантизатор.
        let s = Synthetic::generate(1, 0);
        let c = vecdht_artifact::Centroids::from_i8(&s.centroid_bytes()).unwrap();
        assert_eq!(c.len(), NLIST as usize * DIM);
        for (i, p) in s.points.iter().take(64).enumerate() {
            assert_eq!(
                c.assign(p) as usize,
                best_center(&s, p) as usize,
                "assign обязан совпадать с прямым перебором тех же строк"
            );
            let _ = i;
        }
    }

    /// Кластер, чей центроид ближайший (по `l2_sq`, §6.3).
    fn best_center(s: &Synthetic, p: &[i8; DIM]) -> u16 {
        let mut best = (u32::MAX, 0u16);
        for (c, cent) in s.centers.iter().enumerate() {
            let d = l2_sq(p, cent);
            if d < best.0 {
                best = (d, c as u16);
            }
        }
        best.1
    }
}
