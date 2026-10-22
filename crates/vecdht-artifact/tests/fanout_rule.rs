//! Оракул `E-0032` (`H-0032`): два правила выбора — по кластерам (собранный код) и по шардам
//! (спека §7.5.1). Пороги зафиксированы в `lab/hypotheses/H-0032-shard-rule-not-in-client-code.md`
//! ДО прогона; здесь только измерение, ничего не правится.
//!
//! Пункты: (1) кластерное правило = `Centroids::top` (то, что зовёт `embed::model::encode_query` и
//! `cli/index_cmd`), (2) шардовое правило = минимум `l2_sq` по 16 строкам шарда (то, что предписано
//! спекой и что считает стенд гейта), (3) выразимость «полного скана шарда» через длину списка
//! кластеров в `Find`. Корпуса и `candle` нет: числа относятся к структуре выбора на эталонном
//! артефакте, а не к recall.

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
fn cluster_rule_shards(artifact_clusters: &[u16]) -> Vec<u16> {
    let mut set: Vec<u16> = artifact_clusters
        .iter()
        .map(|c| c / CLUSTERS_PER_SHARD)
        .collect();
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

fn median(mut v: Vec<usize>) -> f64 {
    v.sort_unstable();
    let n = v.len();
    if n % 2 == 1 {
        v[n / 2] as f64
    } else {
        (v[n / 2 - 1] + v[n / 2]) as f64 / 2.0
    }
}

#[test]
fn the_shipped_cluster_rule_fans_out_less_than_nprobe() {
    let a = reference_artifact();
    let rows = a.centroids.rows();
    let qs = queries(256);

    for &nprobe in [4usize, 16, 32] {
        let mut by_cluster: Vec<usize> = Vec::new();
        let mut by_shard: Vec<usize> = Vec::new();
        let mut jac: Vec<f64> = Vec::new();
        let mut equal_to_nprobe = 0usize;
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
        }

        eprintln!(
            "## nprobe={nprobe}: кластерное правило — средний fan-out {:.2}, медиана {:.1}, ровно nprobe в {:.1} % запросов ##",
            mean(&by_cluster),
            median(by_cluster.clone()),
            100.0 * equal_to_nprobe as f64 / qs.len() as f64
        );
        eprintln!(
            "## nprobe={nprobe}: шардовое правило (§7.5.1) — средний fan-out {:.2}; список кластеров в Find: {cluster_list_len} (полный скан потребовал бы {}); средний Jaccard двух множеств шардов {:.3} ##",
            mean(&by_shard),
            nprobe * usize::from(CLUSTERS_PER_SHARD),
            mean(&jac)
        );

        // Порог (3): кластерное правило строго меньше nprobe, шардовое — ровно nprobe.
        assert!(
            mean(&by_cluster) < nprobe as f64,
            "кластерное правило даёт fan-out == nprobe: различие двух правил несущественно (фальсификатор в)"
        );
        assert!(
            by_shard.iter().all(|&x| x == nprobe),
            "шардовое правило не отдаёт ровно nprobe шардов"
        );
        // Порог (4): на половине запросов множества шардов различаются (средний Jaccard < 1).
        let differing = jac.iter().filter(|&&j| j < 1.0).count();
        assert!(
            differing * 2 >= qs.len(),
            "правила выбирают одно и то же множество шардов почти всегда: {differing} из {}",
            qs.len()
        );
        // Пункт (2) о выразимости: клиент шлёт список длины nprobe, а не nprobe * 16.
        assert_eq!(cluster_list_len, nprobe, "длина списка кластеров в Find поехала");
    }
}
