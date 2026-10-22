//! Оракул `E-0030` (`H-0030`): класс (H) — две реализации отображения «кластер → шард».
//! Пороги зафиксированы в `lab/hypotheses/H-0030-two-shard-maps.md` ДО написания этого файла.
//!
//! Здесь только измерение: (1) совпадают ли две реализации при протокольной геометрии,
//! (2) где начинается расхождение, если `clusters_per_shard` приходит из данных (8 вместо 16),
//! (3) достижима ли такая геометрия сегодня легальным путём через манифест.

use vecdht_artifact::reference_artifact;
use vecdht_net::agent::NetworkParams;
use vecdht_wire::constants::{shard_of, CLUSTERS_PER_SHARD, NLIST, SHARDS};

fn params() -> NetworkParams {
    NetworkParams::from_artifact(&reference_artifact()).expect("эталонный артефакт v8")
}

// ------------------------------------------------------------------ (1)

#[test]
fn the_two_implementations_agree_on_every_cluster_at_protocol_geometry() {
    let p = params();
    assert_eq!(p.clusters_per_shard, CLUSTERS_PER_SHARD, "эталон поехал");
    let mut mismatch = Vec::new();
    for c in 0..NLIST {
        let by_const = shard_of(c);
        let by_param = p.shard_of_cluster(c).expect("кластер внутри nlist");
        if by_const != by_param {
            mismatch.push((c, by_const, by_param));
        }
    }
    eprintln!(
        "## (1) NLIST={NLIST}, CLUSTERS_PER_SHARD={CLUSTERS_PER_SHARD}: расходящихся кластеров {} ##",
        mismatch.len()
    );
    assert!(mismatch.is_empty(), "расхождение при протокольной геометрии: {mismatch:?}");
}

// ------------------------------------------------------------------ (2)

#[test]
fn rotating_clusters_per_shard_diverges_from_cluster_cps_and_never_panics() {
    // Именно так значение придёт после стадии 1: из манифеста, а не из кодека.
    let mut p = params();
    let new_cps: u16 = 8;
    p.clusters_per_shard = new_cps;
    let mut first = None;
    let mut diverged = 0usize;
    for c in 0..NLIST {
        let by_const = shard_of(c);
        let by_param = p.shard_of_cluster(c).expect("кластер внутри прежнего nlist");
        if by_const != by_param {
            diverged += 1;
            if first.is_none() {
                first = Some((c, by_param, by_const));
            }
        }
    }
    eprintln!(
        "## (2) cps: константа {CLUSTERS_PER_SHARD} → параметр {new_cps}: первый расходящийся {:?}, всего {diverged} из {NLIST} ##",
        first
    );
    assert_eq!(first.map(|f| f.0), Some(new_cps), "первый расходящийся кластер обязан быть ровно {new_cps}");
    assert_eq!(diverged, NLIST as usize - new_cps as usize, "число расходящихся кластеров");
    // Тихость ошибки: обе реализации возвращают корректный номер (None только вне nlist),
    // то есть ни паники, ни отказа декодера — неверный шард просто используется.
    assert!(p.shard_of_cluster(new_cps).is_some() && shard_of(new_cps) < SHARDS);
}

// ------------------------------------------------------------------ (3)

#[test]
fn a_manifest_with_other_geometry_is_refused_today() {
    let mut a = reference_artifact();
    a.manifest.routing.clusters_per_shard = 8;
    let res = NetworkParams::from_artifact(&a);
    eprintln!("## (3) манифест с cps=8: {:?} ##", res.as_ref().err().map(|e| e.to_string()));
    assert!(res.is_err(), "ФАЛЬСИФИКАТОР (в): runtime-геометрия достижима сегодня без правки wire");
    // Печатается слой, который отвергает: проверка обязательна, но где именно она стоит —
    // это факт для карты правок (манифест-vs-кодек, а не сверка в from_artifact).
    if let Err(e) = res {
        let s = e.to_string();
        eprintln!("## (3а) кто отверг: {}", if s.contains("манифест:") { "сверка from_artifact (agent.rs:80-86)" } else { "manifest.check() раньше сверки" });
    }
}
