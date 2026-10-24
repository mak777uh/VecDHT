//! Оракул `H-0104`/`E-0104` для транспорта: снимок `NetMetrics` конечен, а метки двери замкнуты.
//!
//! Проверяется две вещи, которые легко перепутать:
//!
//! * **проводка** — `NetService::metrics()` читает именно те счётчики, что объявлены, и на
//!   свежем агенте даёт нули, а не «нет данных»: нуль здесь означает «событие не происходило»;
//! * **проекция** — `NetMetrics::from_parts` печатает только ненулевые причины, каждая причина
//!   берётся из `DoorReason::ALL` (22 имени, `E-0095`), сумма `door_refusals_total` равна сумме
//!   напечатанных, а порядок не зависит от порядка входа.
//!
//! Границы: это не проверка libp2p-двери — её ветки измерены `E-0095`. Здесь доказывается, что
//! наблюдение не открывает кардинальность заново: свободная строка в метку не проходит, потому
//! что типа для неё нет.

use std::time::Duration;

use vecdht_net::door::DoorReason;
use vecdht_net::metrics::{NetMetrics, DOOR_LABEL_PREFIX, FIXED};
use vecdht_net::{NetConfig, NetService};
use vecdht_node::testing;
use vecdht_wire::messages::Role;

fn cfg() -> NetConfig {
    NetConfig {
        listen: vec!["/ip4/127.0.0.1/udp/0/quic-v1".parse().expect("listen-адрес QUIC")],
        bootstrap: Vec::new(),
        genesis_hash: testing::genesis_hash(),
        model_version: vecdht_artifact::reference_manifest().model_version,
        preprocessing_version: testing::PREPROCESSING_VERSION,
        agent_version: "vecdht-net-c104/0.1".to_string(),
        request_timeout: Duration::from_secs(5),
        idle_timeout: Duration::from_secs(60),
        provider_republish: Duration::from_secs(180),
        poll_interval: Duration::from_millis(5),
        revoked_dir: None,
    }
}

#[test]
fn fresh_agent_service_reports_fixed_zeros() {
    // QUIC-сварок строит сокет через tokio-реактор: без него `quinn` паникует «no reactor
    // running», и тест падал бы не на метрике, а на отсутствии рантайма.
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(async {
        let svc = NetService::new(
            testing::identity(31),
            Role::Agent,
            None,
            Vec::new(),
            testing::authority_set(),
            cfg(),
        )
        .expect("сервис агента");
        let m = svc.metrics();
        let got: Vec<&str> = m.fixed().iter().map(|(n, _)| *n).collect();
        assert_eq!(got, FIXED.to_vec(), "фиксированная часть снимка разошлась с объявленной");
        for (name, value) in m.fixed() {
            assert_eq!(*value, 0, "свежий агент уже насчитал `{name}`");
        }
        assert!(m.door().is_empty(), "у свежего агента не было отказов двери");
        assert_eq!(m.get("door_refusals_total"), Some(0));
    });
    println!("## C104_NET_WIRING=1 C104_NET_FIXED={} ##", FIXED.len());
}

#[test]
fn door_labels_are_closed_and_total_is_the_sum() {
    // Вход нарочно в обратном порядке и с нулём: снимок обязан отсортировать и отбросить нули.
    let mut refusals: Vec<(&'static str, u64)> = DoorReason::ALL
        .iter()
        .enumerate()
        .map(|(i, r)| (r.name(), (i as u64 + 1) * 3))
        .collect();
    refusals.reverse();
    refusals.push((DoorReason::ALL[3].name(), 0));
    let m = NetMetrics::from_parts(9, 4, (1, 2, 3), 5, refusals.clone());
    assert_eq!(m.door().len(), 22, "напечатаны не все ненулевые причины");
    let known: Vec<&str> = DoorReason::ALL.iter().map(|r| r.name()).collect();
    let mut sum = 0u64;
    let mut prev: Option<&str> = None;
    for (name, value) in m.door() {
        assert!(known.contains(name), "метка вне ALL: {name}");
        assert!(*value > 0, "нулевая причина попала в снимок");
        if let Some(p) = prev {
            assert!(p < *name, "порядок меток не возрастающий: {p} → {name}");
        }
        prev = Some(name);
        sum += *value;
    }
    assert_eq!(m.get("door_refusals_total"), Some(sum));
    // 3·(1+…+22) = 3·253 = 759 — сумма, а не «примерно столько».
    assert_eq!(m.get("door_refusals_total"), Some(759));
    // Полное имя метки читается и через `get`: потребителю не нужно знать, что причина была.
    let first = DoorReason::ALL[0].name();
    assert_eq!(m.get(&format!("{DOOR_LABEL_PREFIX}{first}")), Some(3));
    // Разбор печати даёт те же значения.
    let text = m.render();
    assert_eq!(text.lines().count(), FIXED.len() + m.door().len());
    for line in text.lines() {
        let (name, value) = line.split_once('=').expect("строка снимка без `=`");
        let parsed: u64 = value.parse().expect("значение не u64");
        assert_eq!(m.get(name), Some(parsed), "render и get разошлись на `{name}`");
    }
    println!(
        "## C104_NET_DOOR_LABELS=22 C104_NET_LABELS_CLOSED=1 C104_NET_SUM=759 \
C104_NET_SUM_OK=1 C104_NET_RENDER_OK=1 ##"
    );
}

#[test]
fn size_does_not_grow_with_the_number_of_refusals() {
    let one: Vec<(&'static str, u64)> = vec![(DoorReason::ALL[0].name(), 1)];
    let many: Vec<(&'static str, u64)> = vec![(DoorReason::ALL[0].name(), 1_000_000)];
    let a = NetMetrics::from_parts(0, 0, (0, 0, 0), 0, one);
    let b = NetMetrics::from_parts(0, 0, (0, 0, 0), 0, many);
    assert_eq!(a.door().len(), 1);
    assert_eq!(b.door().len(), 1, "размер снимка вырос от числа отказов");
    assert_eq!(a.fixed().len(), FIXED.len());
    assert_eq!(b.fixed().len(), FIXED.len());
    for (name, _) in a.fixed() {
        for bad in ["price", "cost", "amount", "unit"] {
            assert!(!name.contains(bad), "метка `{name}` содержит `{bad}`");
        }
    }
    println!("## C104_NET_SIZE_STABLE=1 C104_NET_NO_PRICE=1 ##");
}
