//! Построитель карты шардов (§7.4.1 спеки, `ADR-0004`).
//!
//! **Карта шардов — это порядок строк `centroid.bin`, а не формат.** Издатель не меняет ни wire,
//! ни формат артефакта, ни `preprocessing_version`: он лишь публикует те же 1024 мелких центроида
//! в порядке «ячейка 0 → её 16 строк, ячейка 1 → её 16 строк, …». Строка `i` — это кластер `i`,
//! шард `i / CLUSTERS_PER_SHARD`, и формула §7.4 остаётся в силе буквально.
//!
//! Порядок вычисляется как **транспортная задача**: 1024 мелких центроида распределяются по 64
//! грубым ячейкам **ровно по 16** с минимализацией суммы `l2_sq` (int8) до центроида своей
//! ячейки; решение — поток минимальной стоимости по полному двудольному графу, то есть оптимум.
//!
//! Почему именно так (все три альтернативы измерены и опровергнуты):
//!
//! * `E-0008` — жадная починка до ровных шардов: из переполненной ячейки вытесняется самый дальний
//!   кластер, то есть «дальние» кластеры уезжают в чужие ячейки и связность рвётся (0.9055);
//! * `E-0009` — назначение при обучении верхнего уровня: ёмкость 16 не выдерживается вовсе
//!   (ячейки 4…30), потому что перелив идёт только во второй ближайший центроид;
//! * `E-0011` — рекурсивное деление по оси максимальной дисперсии: ровность достигнута по
//!   построению, но ячейки вытянуты вдоль одной оси (0.8601).
//!
//! Транспортная задача отличается от них тем, что кластеры **меняются местами** (избыток ячейки
//! компенсируется обменом с дефицитной), а пространство не режется плоскостями.
//!
//! Оракул: `crates/vecdht-embed/tests/p0_real_corpus.rs::gate_ii_real_corpus_recall`
//! (`VEC_DHT_P0_COARSE=1 VEC_DHT_P0_COHERENT=1`), записи `E-0012`, `H-0012`.

use std::cmp::Ordering;
use std::collections::BinaryHeap;

use vecdht_crypto::quant::{l2_sq, quantize_slice, QuantError};

use crate::kmeans::{KMeansConfig, KMeansError};

/// Размерность вектора §6.1.
pub const DIM: usize = 384;

/// Ошибка построения карты.
#[derive(Debug, thiserror::Error)]
pub enum ShardMapError {
    /// Число мелких центроидов не кратно числу кластеров на шард.
    #[error("размер карты {nlist} не кратен числу кластеров на шард {per_shard}")]
    NotDivisible { nlist: usize, per_shard: usize },
    /// Число `f32`-строк не совпадает с числом опубликованных `int8`-строк.
    #[error("мелких центроидов {rows} строк, а опубликованных int8-строк {i8}")]
    RowMismatch { rows: usize, i8: usize },
    /// Параметры верхнего уровня не согласованы с формой карты.
    #[error("k-means верхнего уровня не согласован с картой: k={k} (ожидалось {expected}), cap={cap} (ожидалось {per_shard})")]
    ConfigMismatch {
        k: usize,
        expected: usize,
        cap: usize,
        per_shard: usize,
    },
    /// Ошибка k-means верхнего уровня.
    #[error("k-means верхнего уровня: {0}")]
    KMeans(#[from] KMeansError),
    /// Ошибка квантования центроида ячейки.
    #[error("квантование центроида ячейки: {0}")]
    Quant(#[from] QuantError),
}

/// Готовая карта шардов: порядок публикации строк и всё, что нужно издателю и проверяющему.
#[derive(Debug, Clone)]
pub struct ShardMap {
    /// Опубликованные строки в порядке «ячейка 0 → её строки, …». Строка `i` — кластер `i`.
    pub rows: Vec<[i8; DIM]>,
    /// Исходный номер мелкого центроида на каждой опубликованной позиции.
    ///
    /// `order[p] = c` значит «строка `p` — это кластер `c` исходной нумерации». Это перестановка:
    /// ни один кластер не теряется и не дублируется.
    pub order: Vec<u16>,
    /// Номер грубой ячейки для каждого **исходного** кластера.
    ///
    /// Для опубликованной строки `p` выполняется `cell_of_cluster[order[p]] == p / per_shard` —
    /// то есть контракт §7.4 выполнен буквально.
    pub cell_of_cluster: Vec<u16>,
    /// Грубые центроиды ячеек (int8). В артефакт они **не** публикуются: в `centroid.bin` лежат
    /// только 1024 мелких строки (§15.1), и удалённый агент не может вычислить расстояние до
    /// центроида ячейки — поэтому клиентская политика §7.5.1 считает минимум по 16 строкам шарда.
    pub coarse: Vec<[i8; DIM]>,
    /// Сумма `l2_sq` (int8) от мелкого центроида до центроида своей ячейки — цена назначения.
    pub total_cost: u64,
    /// Число итераций k-means верхнего уровня.
    pub iterations: usize,
    /// Число кластеров на шард (в протоколе `CLUSTERS_PER_SHARD` = 16).
    pub per_shard: usize,
}

impl ShardMap {
    /// Число кластеров в шарде.
    pub fn clusters_per_shard(&self) -> usize {
        self.per_shard
    }

    /// Число шардов карты.
    pub fn shards(&self) -> usize {
        self.coarse.len()
    }
}

/// Построить карту шардов: 64 грубые ячейки (k-means) + транспортная задача (§7.4.1).
///
/// * `fine_f32` — обученные мелкие центроиды, `nlist × DIM` значений `f32` (нормированные);
///   из них обучается верхний уровень карты;
/// * `fine_i8` — их опубликованные `int8`-версии, те же `nlist` строк; **стоимость назначения
///   считается по ним**, потому что карта обязана быть функцией опубликованных данных;
/// * `per_shard` — число кластеров на шард (в протоколе `CLUSTERS_PER_SHARD` = 16);
/// * `config` — параметры верхнего уровня: `k` обязан равняться `nlist / per_shard`, а
///   `balance_cap` — `per_shard`.
///
/// Возвращаемая карта: строки в порядке публикации и перестановка исходных кластеров.
pub fn build_shard_map(
    fine_f32: &[f32],
    fine_i8: &[[i8; DIM]],
    per_shard: usize,
    config: KMeansConfig,
    threads: usize,
) -> Result<ShardMap, ShardMapError> {
    let nlist = fine_i8.len();
    if nlist == 0 {
        return Err(ShardMapError::NotDivisible { nlist, per_shard });
    }
    if per_shard == 0 || nlist % per_shard != 0 {
        return Err(ShardMapError::NotDivisible { nlist, per_shard });
    }
    if fine_f32.len() != nlist * DIM {
        return Err(ShardMapError::RowMismatch { rows: fine_f32.len() / DIM.max(1), i8: nlist });
    }
    let k = nlist / per_shard;
    if config.k != k || config.balance_cap != per_shard {
        return Err(ShardMapError::ConfigMismatch {
            k: config.k,
            expected: k,
            cap: config.balance_cap,
            per_shard,
        });
    }

    // Верхний уровень карты: k-means по тем же 1024 мелким центроидам.
    let trained = crate::kmeans::train(fine_f32, DIM, config, threads)?;
    let coarse_f64: Vec<f64> = trained.centroids.iter().map(|&x| f64::from(x)).collect();
    let coarse_rows: Vec<[i8; DIM]> = coarse_f64
        .chunks_exact(DIM)
        .map(quantize_slice)
        .collect::<Result<Vec<_>, _>>()?;

    // Стоимость «мелкий центроид → ячейка» — по тем же int8-строкам, которые видит клиент.
    let mut cost: Vec<Vec<f64>> = Vec::with_capacity(nlist);
    for fine in fine_i8 {
        let mut row: Vec<f64> = Vec::with_capacity(k);
        for coarse in &coarse_rows {
            row.push(f64::from(l2_sq(fine, coarse)));
        }
        cost.push(row);
    }
    let assignment = min_cost_assignment(&cost, k, per_shard);

    // Раскладка по ячейкам: внутри ячейки кластеры идут по возрастанию исходного номера — так
    // порядок строк детерминирован и не зависит от порядка обхода потока назначения.
    let mut clusters_of_cell: Vec<Vec<u16>> = vec![Vec::new(); k];
    let mut cell_of_cluster = vec![0u16; nlist];
    for (cluster, &cell) in assignment.iter().enumerate() {
        clusters_of_cell[cell].push(cluster as u16);
        cell_of_cluster[cluster] = cell as u16;
    }
    for (cell, members) in clusters_of_cell.iter().enumerate() {
        if members.len() != per_shard {
            // Сюда попасть нельзя: транспортная задача даёт ровно `per_shard` предметов в ячейке.
            // Но «нельзя» — не «невозможно»: лучше явная ошибка, чем молчаливая неравномерность.
            return Err(ShardMapError::ConfigMismatch {
                k: cell,
                expected: per_shard,
                cap: members.len(),
                per_shard,
            });
        }
    }

    let mut rows: Vec<[i8; DIM]> = Vec::with_capacity(nlist);
    let mut order: Vec<u16> = Vec::with_capacity(nlist);
    for members in &clusters_of_cell {
        for &cluster in members {
            rows.push(fine_i8[cluster as usize]);
            order.push(cluster);
        }
    }

    let total_cost = cost
        .iter()
        .zip(assignment.iter())
        .map(|(row, &cell)| row[cell])
        .sum::<f64>() as u64;

    Ok(ShardMap {
        rows,
        order,
        cell_of_cluster,
        coarse: coarse_rows,
        total_cost,
        iterations: trained.iterations,
        per_shard,
    })
}

/// Транспортная задача: `n_items` предметов, `n_cells` ячеек, в каждой **ровно** `per_cell`
/// предметов; стоимость `cost[item][cell]`. Возвращает `item → cell`.
///
/// Решение — поток минимальной стоимости по полному двудольному графу, то есть оптимум
/// транспортной задачи. В отличие от жадной починки (`E-0008`) кластеры здесь **меняются
/// местами**: избыток ячейки компенсируется обменом с дефицитной.
pub fn min_cost_assignment(cost: &[Vec<f64>], n_cells: usize, per_cell: usize) -> Vec<usize> {
    let n_items = cost.len();
    assert_eq!(n_items, n_cells * per_cell, "предметов должно быть ровно n_cells × per_cell");
    let src = 0usize;
    let item_base = 1usize;
    let cell_base = item_base + n_items;
    let sink = cell_base + n_cells;
    let mut flow = MinCostFlow::new(sink + 1);
    for (i, row) in cost.iter().enumerate() {
        flow.add_edge(src, item_base + i, 1, 0.0);
        for (c, &cst) in row.iter().enumerate().take(n_cells) {
            flow.add_edge(item_base + i, cell_base + c, 1, cst);
        }
    }
    for c in 0..n_cells {
        flow.add_edge(cell_base + c, sink, per_cell as i32, 0.0);
    }
    let chosen = flow
        .solve(src, sink, n_items)
        .expect("транспортная задача без полного графа всегда имеет допустимое решение");
    let mut assignment = vec![usize::MAX; n_items];
    for (item, cell) in chosen {
        if item >= item_base && item < cell_base {
            assignment[item - item_base] = cell - cell_base;
        }
    }
    assert!(
        assignment.iter().all(|&c| c != usize::MAX),
        "назначение неполное: транспортная задача не покрыла все предметы"
    );
    assignment
}

/// Суммарная стоимость назначения `item → cell`.
pub fn assignment_cost(cost: &[Vec<f64>], assignment: &[usize]) -> f64 {
    cost.iter()
        .zip(assignment.iter())
        .map(|(row, &cell)| row[cell])
        .sum()
}

/// Ребро с остаточной пропускной способностью и стоимостью.
struct FlowEdge {
    to: usize,
    cap: i32,
    cost: f64,
}

/// Поток минимальной стоимости: последовательные кратчайшие пути с потенциалами (Дейкстра).
struct MinCostFlow {
    edges: Vec<FlowEdge>,
    adj: Vec<Vec<usize>>,
}

impl MinCostFlow {
    fn new(nodes: usize) -> Self {
        Self { edges: Vec::new(), adj: vec![Vec::new(); nodes] }
    }

    fn add_edge(&mut self, u: usize, v: usize, cap: i32, cost: f64) {
        let id = self.edges.len();
        self.edges.push(FlowEdge { to: v, cap, cost });
        self.edges.push(FlowEdge { to: u, cap: 0, cost: -cost });
        self.adj[u].push(id);
        self.adj[v].push(id + 1);
    }

    /// Максимальный поток минимальной стоимости величины `required`. Возвращает `None`, если
    /// поток величины `required` невозможен (граф не пропускает).
    fn solve(&mut self, src: usize, sink: usize, required: usize) -> Option<Vec<(usize, usize)>> {
        let n = self.adj.len();
        let mut pot = vec![0f64; n];
        let mut flow = 0usize;
        let mut chosen: Vec<(usize, usize)> = Vec::new(); // (предмет, ячейка)
        while flow < required {
            let mut dist = vec![f64::INFINITY; n];
            let mut prev: Vec<Option<(usize, usize)>> = vec![None; n];
            let mut heap = BinaryHeap::new();
            dist[src] = 0.0;
            heap.push(std::cmp::Reverse((OrdF64(0.0), src)));
            while let Some(std::cmp::Reverse((OrdF64(d), u))) = heap.pop() {
                if d > dist[u] {
                    continue;
                }
                for &eid in &self.adj[u] {
                    let e = &self.edges[eid];
                    if e.cap == 0 {
                        continue;
                    }
                    let rc = e.cost + pot[u] - pot[e.to];
                    debug_assert!(rc >= -1e-6, "отрицательная приведённая стоимость {rc}");
                    let nd = d + rc.max(0.0);
                    if nd < dist[e.to] - 1e-9 {
                        dist[e.to] = nd;
                        prev[e.to] = Some((u, eid));
                        heap.push(std::cmp::Reverse((OrdF64(nd), e.to)));
                    }
                }
            }
            if !dist[sink].is_finite() {
                return None;
            }
            for v in 0..n {
                if dist[v].is_finite() {
                    pot[v] += dist[v];
                }
            }
            let mut v = sink;
            while v != src {
                let (u, eid) = prev[v].expect("путь найден");
                self.edges[eid].cap -= 1;
                self.edges[eid ^ 1].cap += 1;
                v = u;
            }
            flow += 1;
        }
        // Итоговое назначение: предмет → ячейка по рёбрам потока.
        for (u, eids) in self.adj.iter().enumerate() {
            for &eid in eids {
                if eid % 2 == 1 {
                    continue; // обратное ребро
                }
                let e = &self.edges[eid];
                if e.cap == 0 && e.to > u && self.edges[eid ^ 1].cap > 0 {
                    chosen.push((u, e.to));
                }
            }
        }
        Some(chosen)
    }
}

/// Обёртка для `f64` в куче Дейкстры: `f64` не `Ord`, а `total_cmp` даёт нужный порядок.
/// `Eq` вручную: значение — единственное поле, `total_cmp` различает любые два `f64`
/// (включая NaN), поэтому рефлексивность и транзитивность наследуются от `total_cmp`.
#[derive(PartialEq)]
struct OrdF64(f64);

impl Eq for OrdF64 {}

impl Ord for OrdF64 {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.total_cmp(&other.0)
    }
}

impl PartialOrd for OrdF64 {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vecdht_crypto::quant::l2_normalize;

    /// Синтетические центроиды: `k` «облаков» по `per_shard` точек вокруг k центров.
    fn synthetic(nlist: usize, per_shard: usize) -> (Vec<f32>, Vec<[i8; DIM]>) {
        let mut f32_rows: Vec<f32> = Vec::with_capacity(nlist * DIM);
        let mut i8_rows: Vec<[i8; DIM]> = Vec::with_capacity(nlist);
        for c in 0..nlist {
            let cell = c / per_shard;
            let mut v = vec![0f64; DIM];
            // Центр облака на единичной сфере: первая координата 1.0, остальные 0.0.
            v[0] = 1.0;
            // Малый разброс внутри облака, детерминированный по номеру кластера.
            let jitter = ((c % per_shard) as f64 + 1.0) * 1e-3;
            v[1] = jitter;
            v[2] = (cell as f64) * 1e-2;
            l2_normalize(&mut v).expect("вектор нормируется");
            f32_rows.extend(v.iter().map(|x| *x as f32));
            i8_rows.push(quantize_slice(&v).expect("центроид квантуется"));
        }
        (f32_rows, i8_rows)
    }

    fn config(nlist: usize, per_shard: usize) -> KMeansConfig {
        KMeansConfig {
            k: nlist / per_shard,
            max_iters: 12,
            seed: 0x5645_4344_4854_0002 ^ 0x0007,
            balance_cap: per_shard,
        }
    }

    #[test]
    fn map_is_even_and_covers_every_cluster() {
        let (f32_rows, i8_rows) = synthetic(64, 8);
        let map =
            build_shard_map(&f32_rows, &i8_rows, 8, config(64, 8), 1).expect("карта строится");
        assert_eq!(map.rows.len(), 64);
        assert_eq!(map.order.len(), 64);
        assert_eq!(map.coarse.len(), 8);
        // Каждый шард — ровно 8 кластеров, и это проверяется по публикуемой нумерации.
        for shard in 0..8u16 {
            let members: Vec<u16> = (0..64)
                .filter(|p| (p / 8) as u16 == shard)
                .map(|p| map.order[p as usize])
                .collect();
            assert_eq!(members.len(), 8, "шард {shard} неполон");
        }
    }

    #[test]
    fn published_order_respects_the_shard_contract() {
        let (f32_rows, i8_rows) = synthetic(64, 8);
        let map =
            build_shard_map(&f32_rows, &i8_rows, 8, config(64, 8), 1).expect("карта строится");
        for p in 0..map.rows.len() {
            // Строка `p` публикуется как кластер `p`, её шард — `p / per_shard`, и она лежит
            // именно в той ячейке, которой была назначена исходным номером.
            assert_eq!(map.cell_of_cluster[map.order[p] as usize] as usize, p / 8);
            assert_eq!(map.rows[p], i8_rows[map.order[p] as usize]);
        }
    }

    #[test]
    fn map_is_deterministic() {
        let (f32_rows, i8_rows) = synthetic(64, 8);
        let a = build_shard_map(&f32_rows, &i8_rows, 8, config(64, 8), 1).expect("карта строится");
        let b = build_shard_map(&f32_rows, &i8_rows, 8, config(64, 8), 1).expect("карта строится");
        assert_eq!(a.order, b.order);
        assert_eq!(a.total_cost, b.total_cost);
    }

    #[test]
    fn transport_is_not_worse_than_a_greedy_feasible_assignment() {
        // Стоимость: каждый предмет дешевле всего в своей ячейке, но часть ячеек перегружена.
        let n_cells = 3usize;
        let per_cell = 2usize;
        let cost = vec![
            vec![1.0, 10.0, 10.0], // предмет 0 — ячейка 0
            vec![1.0, 10.0, 10.0], // предмет 1 — ячейка 0
            vec![1.0, 10.0, 10.0], // предмет 2 — ячейка 0 (перегруз)
            vec![10.0, 2.0, 10.0], // предмет 3 — ячейка 1
            vec![10.0, 2.0, 10.0], // предмет 4 — ячейка 1
            vec![10.0, 10.0, 3.0], // предмет 5 — ячейка 2
        ];
        let assignment = min_cost_assignment(&cost, n_cells, per_cell);
        // Ровность: в каждой ячейке ровно per_cell предметов.
        let mut counts = vec![0usize; n_cells];
        for &cell in &assignment {
            counts[cell] += 1;
        }
        assert_eq!(counts, vec![per_cell; n_cells]);
        // Жадная эталонная раскладка: предмет идёт в ближайшую ячейку, а если там нет места —
        // в ближайшую со свободным местом. Транспортная задача обязана быть не хуже.
        let mut greedy = vec![usize::MAX; cost.len()];
        let mut taken = vec![0usize; n_cells];
        for (i, row) in cost.iter().enumerate() {
            let mut order: Vec<usize> = (0..n_cells).collect();
            order.sort_by(|&a, &b| {
                row[a]
                    .total_cmp(&row[b])
                    .then(a.cmp(&b))
            });
            let cell = *order
                .iter()
                .find(|&&c| taken[c] < per_cell)
                .expect("свободная ячейка есть");
            greedy[i] = cell;
            taken[cell] += 1;
        }
        assert!(
            assignment_cost(&cost, &assignment) <= assignment_cost(&cost, &greedy),
            "транспортная задача хуже жадной: {} против {}",
            assignment_cost(&cost, &assignment),
            assignment_cost(&cost, &greedy)
        );
    }

    #[test]
    fn config_mismatch_is_rejected() {
        let (f32_rows, i8_rows) = synthetic(64, 8);
        let bad = KMeansConfig { k: 3, ..config(64, 8) };
        let err = build_shard_map(&f32_rows, &i8_rows, 8, bad, 1).expect_err("k не совпадает");
        assert!(matches!(err, ShardMapError::ConfigMismatch { .. }));
    }
}
