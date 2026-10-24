//! Оракул `H-0104`/`E-0104`: снимок наблюдения узла конечен и не подменяет поля.
//!
//! Приложение C перечисляет метрики, которые обязаны быть в проде, но до `H-0104` у узла не было
//! ни одного способа их снять: счётчики лежали в `admission.stats`, `store` и `index`, и каждый
//! потребитель собирал бы свой список — с разными именами и без гарантии, что поле не перепутано.
//! Снимок `NodeMetrics` закрывает это по построению: имя берётся из `NAMES`, значение — из
//! конкретного поля, и тест `each_counter_maps_to_its_own_name` ставит каждому счётчику своё
//! число, чтобы перестановка двух полей была видна как факт, а не как «в проде и так сойдёт».
//!
//! Что проверяется:
//!
//! * (1) снимок содержит ровно `NAMES` имён в том же порядке, без повторов и лишних;
//! * (2) каждое имя читает своё поле: статистике приёма, состоянию шарда, памяти и роли даются
//!   различные значения, и снимок обязан вернуть именно их;
//! * (3) `render()` — обратимая запись: разбор строк даёт те же пары, что `pairs()`;
//! * (4) в снимке нет метки цены и меток двери — у цены нет числового источника (§5.5), а дверь
//!   принадлежит транспорту (`NetMetrics`);
//! * (5) снимок читает `centroids_loaded`: `None` → 0, `Some` → 1, то есть fail-open §7.3
//!   наблюдаем, а не выводится из молчания.
//!
//! Границы: это проверка поверхности наблюдения, а не её провода. Эндпоинта в v1 нет, формат —
//! текст `имя=значение` для оператора и стенда P1. Метрики, для которых у продукта нет источника
//! (`shard_resolve_ms`, `index_scan_us`, `replica_lag_ops`, …), сюда не входят и названы в
//! `ADR-0059`; отсутствие поля здесь — не «ноль», а «нет источника».

use std::sync::Arc;

use vecdht_artifact::Centroids;
use vecdht_crypto::quant::DIM;
use vecdht_index::testing::{dir, remove};
use vecdht_node::metrics::{NodeMetrics, NAMES};
use vecdht_node::{candidates, testing, Params, ShardNode};

const SHARD: u16 = 7;
const SEEDS: [u8; 3] = [1, 2, 3];
const POW: u32 = 8;

fn params() -> Params {
    let mut p = testing::params(POW);
    p.lease_buckets = 1_000_000;
    p
}

/// Каталог, удаляемый при выходе: PRE_FIX-прогон падает, и ручной `remove` оставил бы мусор
/// (`E-0085`, ДИАГНОЗ-2).
struct Tmp(std::path::PathBuf);

impl Drop for Tmp {
    fn drop(&mut self) {
        remove(&self.0);
    }
}

fn primary(dir_name: &str) -> (ShardNode, Tmp) {
    let order = candidates::ordered(1, SHARD, &testing::holders(&SEEDS));
    let seed = *SEEDS
        .iter()
        .find(|s| testing::identity(**s).pubkey() == order[0].owner_ed25519)
        .expect("первый в порядке эпохи 1 — один из тестовых сидов");
    let d = Tmp(dir(dir_name));
    let mut n = testing::node(&d.0, SHARD, seed, params(), &SEEDS);
    n.on_frame(
        testing::identity(9).pubkey(),
        &testing::signed_frame(&testing::genesis_update(SHARD, &SEEDS, 0)),
        testing::clock(0),
    )
    .expect("genesis");
    (n, d)
}

fn grid_row(c: u16) -> [i8; DIM] {
    let mut row = [0i8; DIM];
    row[0] = (c % 100) as i8 - 50;
    row[1] = (c / 100) as i8 - 5;
    row
}

fn all_centroids() -> Arc<Centroids> {
    let bytes: Vec<i8> = (0..1024u16).flat_map(grid_row).collect();
    Arc::new(Centroids::from_i8(&bytes).expect("1024 строки по DIM"))
}

#[test]
fn names_are_exact_and_render_round_trips() {
    let (n, _d) = primary("c104-names");
    let m = NodeMetrics::of(&n);
    let got: Vec<&str> = m.pairs().iter().map(|(name, _)| *name).collect();
    assert_eq!(got, NAMES.to_vec(), "снимок разошёлся с объявленным списком имён");
    assert_eq!(m.pairs().len(), NAMES.len());
    let mut seen = std::collections::BTreeSet::new();
    for name in &got {
        assert!(seen.insert(*name), "имя повторено: {name}");
    }
    // Разбор `render()` — тот же источник, что увидит оператор; расхождение с `pairs()` значило
    // бы, что напечатанное и прочитанное — разные снимки.
    let text = m.render();
    let mut parsed = std::collections::BTreeMap::new();
    for line in text.lines() {
        let (name, value) = line.split_once('=').expect("строка снимка без `=`");
        parsed.insert(name.to_string(), value.parse::<u64>().expect("значение не u64"));
    }
    assert_eq!(parsed.len(), NAMES.len());
    for (name, value) in m.pairs() {
        assert_eq!(parsed.get(*name), Some(value), "render потерял {name}");
    }
    println!("## C104_NODE_NAMES={} C104_NODE_EXACT=1 C104_NODE_RENDER_OK=1 ##", NAMES.len());
}

#[test]
fn each_counter_maps_to_its_own_name() {
    let (mut n, _d) = primary("c104-map");
    // Различные числа на каждое поле: перестановка двух полей ловится сравнением с именем,
    // а не «примерно теми же» значениями.
    {
        let mut adm = n.admission.borrow_mut();
        let s = &mut adm.stats;
        s.publishes_allowed = 101;
        s.finds_allowed = 102;
        s.denied_by_denylist = 103;
        s.denylist_refused_at_bound = 104;
        s.denylist_save_errors = 105;
        s.rejected_publish_quota = 106;
        s.rejected_find_quota = 107;
        s.rejected_node_busy = 108;
        s.forgotten_peers = 109;
        s.cell_cap_moves = 110;
        s.cell_cap_rejections = 111;
        s.cluster_reassigned = 112;
        s.cluster_cross_shard = 113;
        s.cluster_unverified = 114;
    }
    n.store.applied_seq = 201;
    n.store.next_seq = 202;
    n.store.max_epoch_served = 203;
    n.store.epoch = 204;
    n.store.last_snapshot_seq = 205;
    n.store.replayed = 206;
    n.store.time_mark_bucket = 207;
    n.store.index.live = 208;
    n.store.index.tombstones = 209;
    n.gc_ticks = 210;

    let m = NodeMetrics::of(&n);
    let expect = [
        ("admit_publishes_allowed", 101),
        ("admit_finds_allowed", 102),
        ("admit_denied_by_denylist", 103),
        ("admit_denylist_refused_at_bound", 104),
        ("admit_denylist_save_errors", 105),
        ("admit_rejected_publish_quota", 106),
        ("admit_rejected_find_quota", 107),
        ("admit_rejected_node_busy", 108),
        ("admit_forgotten_peers", 109),
        ("cell_cap_moves", 110),
        ("cell_cap_rejections", 111),
        ("cluster_reassigned", 112),
        ("cluster_cross_shard", 113),
        ("cluster_unverified", 114),
        ("applied_seq", 201),
        ("next_seq", 202),
        ("max_epoch_served", 203),
        ("epoch_served", 204),
        ("live_records", 208),
        ("tombstone_slots", 209),
        ("last_snapshot_seq", 205),
        ("replayed_ops", 206),
        ("time_mark_bucket", 207),
        ("gc_ticks", 210),
    ];
    for (name, value) in expect {
        assert_eq!(m.get(name), Some(value), "поле `{name}` читает не свой счётчик");
    }

    // Память: каждая строка — своя, сумма — их сумма, а не ещё одно поле.
    let mem = n.store.index.mem_bytes();
    assert_eq!(m.get("mem_arena_bytes"), Some(mem.arena as u64));
    assert_eq!(m.get("mem_lists_bytes"), Some(mem.lists as u64));
    assert_eq!(m.get("mem_owners_bytes"), Some(mem.owners as u64));
    assert_eq!(m.get("mem_bitmap_bytes"), Some(mem.bitmap as u64));
    assert_eq!(m.get("mem_slot_attr_bytes"), Some(mem.slot_attr as u64));
    assert_eq!(m.get("mem_total_bytes"), Some(mem.total() as u64));
    assert_eq!(m.get("wal_bytes"), Some(n.store.wal.bytes()));

    // Роль: биты и членство — из узла, lease — из его последней наблюдённой метки.
    assert_eq!(m.get("pow_bits_current"), Some(u64::from(n.pow_bits)));
    assert_eq!(m.get("membership_epoch"), Some(n.membership.as_ref().unwrap().epoch()));
    assert_eq!(m.get("membership_members"), Some(3));
    assert_eq!(m.get("lease_epoch"), Some(n.lease.as_ref().unwrap().epoch));
    let active = n.lease.as_ref().unwrap().active_at(n.store.time_mark_bucket);
    assert_eq!(m.get("lease_active_at_mark"), Some(active as u64));

    // (5) fail-open наблюдаем: до артефакта — 0, после — 1, и это одно и то же поле.
    assert_eq!(m.get("centroids_loaded"), Some(0), "узел без артефакта посчитан как загруженный");
    n.centroids = Some(all_centroids());
    assert_eq!(NodeMetrics::of(&n).get("centroids_loaded"), Some(1));

    println!("## C104_NODE_MAPPED=24 C104_NODE_MEMORY_ROWS=6 C104_NODE_CENTROIDS_OBSERVABLE=1 ##");
}

#[test]
fn no_price_no_door_and_no_free_text() {
    let (n, _d) = primary("c104-bounds");
    let m = NodeMetrics::of(&n);
    let mut door = 0usize;
    for (name, _) in m.pairs() {
        for bad in ["price", "cost", "amount", "unit"] {
            assert!(!name.contains(bad), "в снимке узла метка `{name}` содержит `{bad}`");
        }
        if name.starts_with("door_refusal.") {
            door += 1;
        }
    }
    // Дверь — наблюдение транспорта (`NetMetrics`), а не узла: смешать их значило бы, что у
    // одного процесса два источника одной метрики.
    assert_eq!(door, 0, "метки двери просочились в снимок узла");
    // Свободного текста в снимке нет по типу: имя — `&'static str` из `NAMES`, значение — u64.
    println!("## C104_NODE_NO_PRICE=1 C104_NODE_DOOR_SEPARATE=1 ##");
}
