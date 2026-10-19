//! `centroid.bin` — замороженный coarse-квантизатор сети (спека §7.1, §15.1).
//!
//! 1024 центроида по 384 значения int8 = ровно 384 КиБ. int8 вместо f32 (1.57 МБ) — это не
//! экономия ради экономии: присваивание кластера тогда считается той же целочисленной операцией,
//! что и refine, и отдельного float-пути с его платформенной неопределённостью в routing просто
//! нет. Отсюда два правила: размер файла фиксирован, а значения уже лежат в сетке Δ=1/127.

use vecdht_crypto::quant::{
    assign_cluster, quantize_slice, top_clusters, QuantError, DIM,
};
use vecdht_wire::constants::NLIST;

/// Число байт в `centroid.bin`: `NLIST × DIM` знаковых байтов.
pub const CENTROID_BYTES: usize = (NLIST as usize) * DIM;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Centroids {
    /// Плоский массив `NLIST` строк по `DIM`; хеш и подпись считаются именно по этим байтам.
    bytes: Vec<i8>,
}

#[derive(Debug, thiserror::Error)]
pub enum CentroidError {
    #[error("centroid.bin: ожидалось {CENTROID_BYTES} байт (NLIST×DIM), найдено {0}")]
    WrongSize(usize),
    #[error("centroid.bin: строка {0} не квантуется ({1})")]
    Row(usize, #[source] QuantError),
}

impl Centroids {
    /// Из готовых байтов `centroid.bin` в порядке строк кластеров.
    pub fn from_i8(bytes: &[i8]) -> Result<Self, CentroidError> {
        if bytes.len() != CENTROID_BYTES {
            return Err(CentroidError::WrongSize(bytes.len()));
        }
        Ok(Self { bytes: bytes.to_vec() })
    }

    /// Из `u8`-дампa файла (тот же массив, но как байты, а не как знаковые значения).
    pub fn from_u8(bytes: &[u8]) -> Result<Self, CentroidError> {
        let as_i8: Vec<i8> = bytes.iter().map(|b| *b as i8).collect();
        Self::from_i8(&as_i8)
    }

    /// Из f64-значений, как их выдаёт k-means на P0: каждая строка проходит то же квантование,
    /// что и векторы записей (§6.3), поэтому центроид и запись сравнимы без пересчёта масштаба.
    pub fn from_f64(values: &[f64]) -> Result<Self, CentroidError> {
        let mut out = Vec::with_capacity(CENTROID_BYTES);
        for (row, chunk) in values.chunks(DIM).enumerate() {
            let q = quantize_slice(chunk).map_err(|e| CentroidError::Row(row, e))?;
            out.extend_from_slice(&q);
        }
        Self::from_i8(&out)
    }

    /// Байты как `u8` — то, что идёт в blake3 и в файл.
    pub fn as_bytes(&self) -> Vec<u8> {
        self.bytes.iter().map(|v| *v as u8).collect()
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Пустой ли набор центроидов. Для фиксированного `NLIST` — константный `false`, но
    /// `len`/`is_empty` обязаны быть парой по конвенванию clippy.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Строка кластера `cluster`. Индекс проверяется вызывающим через `covers`.
    pub fn row(&self, cluster: u16) -> &[i8; DIM] {
        let start = cluster as usize * DIM;
        self.bytes[start..start + DIM].try_into().expect("row(): срез ровно DIM")
    }

    pub fn covers(&self, cluster: u16) -> bool {
        (cluster as usize) < NLIST as usize
    }

    /// Ссылки на все строки — вход для `assign_cluster`/`top_clusters`.
    pub fn rows(&self) -> Vec<&[i8; DIM]> {
        (0..NLIST).map(|c| self.row(c)).collect()
    }

    /// `cluster_id` для квантованного вектора — аргминимум целочисленного L2² (§6.3, §7.2).
    pub fn assign(&self, vec_q: &[i8; DIM]) -> u16 {
        let rows = self.rows();
        assign_cluster(vec_q, &rows)
    }

    /// Топ-`nprobe` кластеров с контрактом сортировки `(d2 ASC, cluster ASC)` (§7.5).
    pub fn top(&self, vec_q: &[i8; DIM], nprobe: usize) -> Vec<u16> {
        let rows = self.rows();
        top_clusters(vec_q, &rows, nprobe)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vecdht_wire::codec::DIM as WIRE_DIM;

    /// Детерминированная сетка центроидов. Строки обязаны быть различными — иначе тест
    /// «собственный центроид выигрывает аргминимум» проверяет tie-break, а не близость.
    /// Поэтому номер кластера стоит в первых двух координатах, остальное — целая функция
    /// (row, col), никаких `sin`/`exp`: их libm различается между платформами.
    fn grid(i: usize) -> i8 {
        let (row, col) = (i / DIM, i % DIM);
        let v: i64 = match col {
            0 => (row % 128) as i64,
            1 => (row / 128) as i64 + 1,
            _ => (col as i64 * 131 + row as i64 * 17) % 251 - 125,
        };
        assert!((-128..=127).contains(&v), "сетка обязана лежать в i8");
        v as i8
    }

    fn all_centroids() -> Centroids {
        let bytes: Vec<i8> = (0..CENTROID_BYTES).map(grid).collect();
        Centroids::from_i8(&bytes).unwrap()
    }

    #[test]
    fn size_is_exactly_nlist_times_dim() {
        assert_eq!(CENTROID_BYTES, 1024 * 384);
        assert_eq!(CENTROID_BYTES, 393_216, "384 КиB — размер центрального файла (§7.1)");
        let c = all_centroids();
        assert_eq!(c.len(), CENTROID_BYTES);
        assert_eq!(c.as_bytes().len(), CENTROID_BYTES);
        assert!(!c.is_empty());
        assert_eq!(WIRE_DIM, DIM);
    }

    #[test]
    fn wrong_size_rejected_not_truncated() {
        for n in [CENTROID_BYTES - 1, CENTROID_BYTES + 1, 0, DIM] {
            let bytes: Vec<i8> = (0..n).map(grid).collect();
            assert!(
                matches!(Centroids::from_i8(&bytes), Err(CentroidError::WrongSize(got)) if got == n),
                "размер {n} принят"
            );
        }
    }

    #[test]
    fn u8_and_i8_views_agree_and_rows_are_stable() {
        let c = all_centroids();
        let bytes = c.as_bytes();
        let back = Centroids::from_u8(&bytes).unwrap();
        assert_eq!(back, c, "u8-дамп потерял знаковые байты");
        // Размещение по строкам: первые DIM байт файла — кластер 0, последние DIM — кластер
        // NLIST-1. Сравнивать «хвост строки» с «последними четырьмя байтами» нельзя: это
        // разные координаты одной строки.
        let signed: Vec<i8> = bytes.iter().map(|b| *b as i8).collect();
        assert_eq!(c.row(0).as_slice(), &signed[..DIM]);
        let last = c.row(NLIST - 1);
        assert_eq!(
            last.as_slice(),
            &signed[CENTROID_BYTES - DIM..CENTROID_BYTES]
        );
        assert!(c.covers(NLIST - 1));
        assert!(!c.covers(NLIST));
    }

    #[test]
    fn f64_input_uses_the_same_grid_as_records() {
        // Строка f64 вне [-1, 1] обязана попасть в clamp сетки, а не «как-то округлиться».
        let values: Vec<f64> = (0..CENTROID_BYTES).map(|i| (i % 7) as f64 / 3.0 - 1.0).collect();
        let from_f64 = Centroids::from_f64(&values).unwrap();
        let expected: Vec<i8> = values
            .chunks(DIM)
            .flat_map(|row| quantize_slice(row).unwrap().into_iter())
            .collect();
        assert_eq!(from_f64.bytes, expected);
        assert_eq!(from_f64.len(), CENTROID_BYTES);
    }

    #[test]
    fn f64_input_with_wrong_length_is_rejected() {
        let mut values: Vec<f64> = (0..CENTROID_BYTES).map(|i| i as f64).collect();
        values.truncate(CENTROID_BYTES - 3);
        // Последняя строка короче DIM → строка №1023 не квантуется.
        match Centroids::from_f64(&values) {
            Err(CentroidError::Row(1023, _)) => {}
            other => panic!("обрыв размера принят иначе: {other:?}"),
        }
    }

    #[test]
    fn assign_and_top_agree_with_raw_crypto() {
        let c = all_centroids();
        let query = [-127i8; DIM];
        let rows = c.rows();
        let a = vecdht_crypto::quant::assign_cluster(&query, &rows);
        assert_eq!(a, c.assign(&query));
        let top = c.top(&query, 16);
        assert_eq!(top.len(), 16);
        assert_eq!(top, vecdht_crypto::quant::top_clusters(&query, &rows, 16));
        // Контракт сортировки: d2 невозрастающий по соседним, при равенстве — меньший индекс.
        for w in top.windows(2) {
            let x = vecdht_crypto::quant::l2_sq(&query, c.row(w[0]));
            let y = vecdht_crypto::quant::l2_sq(&query, c.row(w[1]));
            assert!(x < y || (x == y && w[0] < w[1]), "top вне контракта: {w:?}");
        }
        // Собственный центроид — нулевая дистанция и первый в топ-списке.
        let mine = *c.row(777);
        assert_eq!(c.assign(&mine), 777);
        assert_eq!(c.top(&mine, 4)[0], 777);
    }
}
