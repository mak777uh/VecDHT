//! Оракул `E-0033` (`H-0033`): один и тот же запросный поток на двух стендах центроидов —
//! сетка эталонного артефакта и случайные `i8`-строки того же размера. Пороги зафиксированы в
//! `lab/hypotheses/H-0033-stand-grid-degeneracy.md` ДО прогона.
//!
//! Вопрос не проколе и не про recall, а про пригодность стенда: `E-0032` снял на сетке при
//! `nprobe = 4` ноль столкновений из 256 запросов (при равномерной модели ожидалось ≈22). Если на
//! случайных центроидах столкновения появятся, то нулевой зазор был свойством сетки, и `E-0032` в
//! этой точке ничего не измерил.

use vecdht_artifact::{reference_artifact, Centroids, CENTROID_BYTES};
use vecdht_crypto::quant::l2_sq;
use vecdht_wire::codec::DIM;
use vecdht_wire::constants::{CLUSTERS_PER_SHARD, NLIST, SHARDS};

/// Детерминированный LCG: тот же поток, что в `fanout_rule.rs` (`E-0032`), чтобы стенды
/// сравнивались на идентичных запросах.
fn lcg(state: &mut u64) -> u64 {
    *state = state
        .wrapping_mul(6_364_136_223_846_793_005)
        .wrapping_add(1_442_695_040_888_963_407);
    *state
}

fn queries(n: usize) -> Vec<[i8; DIM]> {
    let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
    (0..n)
        .map(|_| {
            let mut v = [0i8; DIM];
            for slot in v.iter_mut() {
                *slot = ((lcg(&mut state) >> 33) & 0xFF) as i8;
            }
            v
        })
        .collect()
}

/// Второй стенд: случайные строки центроидов, никакого `(row, col)`-кода в первых координатах.
fn random_centroids() -> Centroids {
    let mut state: u64 = 0xDEAD_BEEF_CAFE_1234;
    let bytes: Vec<i8> = (0..CENTROID_BYTES)
        .map(|_| ((lcg(&mut state) >> 29) & 0xFF) as i8)
        .collect();
    Centroids::from_i8(&bytes).expect("случайные центроиды того же размера")
}

fn shards_of(clusters: &[u16]) -> Vec<u16> {
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

fn mean(v: &[f64]) -> f64 {
    v.iter().sum::<f64>() / v.len() as f64
}

/// Снимка по одному стенду: для каждого `nprobe` — число запросов со столкновением,
/// средний fan-out двух правил и средний Jaccard.
struct Snapshot {
    nprobe: usize,
    collisions: usize,
    mean_cluster: f64,
    mean_shard: f64,
    jaccard: f64,
    shard_always_exact: bool,
}

fn measure(centroids: &Centroids, qs: &[[i8; DIM]], nprobe: usize) -> Snapshot {
    let rows = centroids.rows();
    let mut by_cluster: Vec<f64> = Vec::new();
    let mut by_shard: Vec<f64> = Vec::new();
    let mut jac: Vec<f64> = Vec::new();
    let mut collisions = 0usize;
    let mut exact = true;

    for q in qs {
        let clusters = centroids.top(q, nprobe);
        let s_cluster = shards_of(&clusters);
        let s_rule = shard_rule(q, &rows, nprobe);
        if s_cluster.len() < clusters.len() {
            collisions += 1;
        }
        if s_rule.len() != nprobe {
            exact = false;
        }
        by_cluster.push(s_cluster.len() as f64);
        by_shard.push(s_rule.len() as f64);
        jac.push(jaccard(&s_cluster, &s_rule));
    }

    Snapshot {
        nprobe,
        collisions,
        mean_cluster: mean(&by_cluster),
        mean_shard: mean(&by_shard),
        jaccard: mean(&jac),
        shard_always_exact: exact,
    }
}

#[test]
fn the_grid_stands_in_the_way_of_the_nprobe_4_measurement() {
    let grid = reference_artifact().centroids;
    let random = random_centroids();
    let qs = queries(256);

    // Оба стенда обязаны быть одного размера — иначе сравниваем не то.
    assert_eq!(grid.len(), random.len());
    assert_eq!(random.len(), usize::from(NLIST) * DIM);

    let mut table: Vec<(&'static str, Snapshot)> = Vec::new();
    for nprobe in [4usize, 16, 32] {
        table.push(("сетка эталона", measure(&grid, &qs, nprobe)));
        table.push(("случайные строки", measure(&random, &qs, nprobe)));
    }

    for (stand, s) in &table {
        eprintln!(
            "## {stand}: nprobe={} — запросов со столкновением {} из {}, средний fan-out кластерного \
             правила {:.2}, шардового {:.2}, средний Jaccard {:.3}, шардовое правило всегда ровно \
             nprobe: {} ##",
            s.nprobe,
            s.collisions,
            qs.len(),
            s.mean_cluster,
            s.mean_shard,
            s.jaccard,
            s.shard_always_exact
        );
    }

    // Порог (3): на случайных центроидах контрольная копия §7.5.1 исправна во всех точках.
    for (stand, s) in table.iter().filter(|(name, _)| *name == "случайные строки") {
        let _ = stand;
        assert!(
            s.shard_always_exact,
            "nprobe={}: шардовое правило не отдаёт ровно nprobe — прогон неинтерпретируем \
             (фальсификатор в)",
            s.nprobe
        );
    }

    // Порог (1): воспроизведение E-0032 на сетке.
    let grid4 = table
        .iter()
        .find(|(name, s)| *name == "сетка эталона" && s.nprobe == 4)
        .map(|(_, s)| s)
        .expect("точка снята");
    assert_eq!(
        grid4.collisions, 0,
        "на сетке при nprobe=4 столкновения появились ({}/256) — воспроизведение E-0032 не сошлось",
        grid4.collisions
    );

    // Порог (2): на случайных центроидах при nprobe=4 столкновения есть (не меньше 11 из 256)
    // и средний fan-out строго меньше 4.00. Провал при исправном (3) = фальсификатор (а)/(б).
    let rnd4 = table
        .iter()
        .find(|(name, s)| *name == "случайные строки" && s.nprobe == 4)
        .map(|(_, s)| s)
        .expect("точка снята");
    assert!(
        rnd4.collisions >= 11,
        "на случайных центроидах при nprobe=4 столкновений {} из 256 — меньше 4 %: зазора нет и без \
         сетки, объяснение «сетка мешает стенду» не подтверждается (фальсификатор а)",
        rnd4.collisions
    );
    assert!(
        rnd4.mean_cluster < 4.0,
        "на случайных центроидах при nprobe=4 средний fan-out {:.2} не меньше 4.00 \
         (фальсификатор б)",
        rnd4.mean_cluster
    );
}
