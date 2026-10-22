//! Оракул E-0037, пороги (1)…(2): кодек `Find` не знает границы длины списка кластеров,
//! кроме физической (`u16`-префикс), а усечение префикса при `len > 65 535` — это отказ декода,
//! а не молчаливый приём.
//!
//! Ни сети, ни корпуса. Единственные проверки — побайтовое равенство после round-trip,
//! длина тела против `MAX_BODY_LEN` и то, что тело с 65 536 элементами не декодируется как
//! валидный `Find` (variant ошибки записывается в протокол как есть; порог требует отказа,
//! а не конкретного variant'а).

use vecdht_wire::codec::{DIM, MAX_BODY_LEN};
use vecdht_wire::messages::{Codec, Find};

/// Кластеры шарда 7 (112..128) — законные для узла из соседнего оракула, но здесь важен только
/// порядок: детерминированная последовательность, в которой дубликаты идут подряд блоками.
fn clusters_of_len(n: usize) -> Vec<u16> {
    (0..n as u32).map(|i| 112 + (i % 16) as u16).collect()
}

fn find_with(clusters: Vec<u16>) -> Find {
    Find {
        preprocessing_version: 1,
        query_vector: [3i8; DIM],
        clusters,
        top_k: 10,
        query_id: 42,
        requester_ed25519: [7u8; 32],
        tlv: Vec::new(),
    }
}

#[test]
fn maximal_u16_list_round_trips_through_the_codec() {
    // Порог (1): 65 535 элементов — максимум, который вмещает u16-префикс, — проходит кодек
    // туда-обратно без изменения порядка.
    let clusters = clusters_of_len(65_535);
    let f = find_with(clusters.clone());
    let body = f.body_bytes();
    // 2 версии + 384 вектора + 2 префикса + 2·65 535 списка + 2 top_k + 8 query_id + 32 ключа.
    assert_eq!(body.len(), 2 + DIM + 2 + 2 * 65_535 + 2 + 8 + 32);
    assert!(
        body.len() < MAX_BODY_LEN,
        "тело предельного списка {} байт — `MAX_BODY_LEN` его не ограничивает",
        body.len()
    );
    let back = Find::decode(&f.encode_unsigned()).expect("порог (1): предельный список обязан декодироваться");
    assert_eq!(back.clusters, clusters, "порядок или содержимое списка изменены кодеком");
    eprintln!("## порог (1): 65 535 кластеров — round-trip ОК, тело {} байт ##", body.len());
}

#[test]
fn overflowing_list_is_rejected_not_silently_accepted() {
    // Порог (2): 65 536 элементов. `Writer::u16_list` пишет `v.len() as u16` (codec.rs:136) —
    // префикс записывается усечённым нулём, а байты элементов остаются в теле. Требуемый исход: такой кадр
    // НЕ декодируется как валидный `Find`. Variant ошибки — справочный.
    let clusters = clusters_of_len(65_536);
    let f = find_with(clusters);
    let body = f.body_bytes();
    assert_eq!(
        &body[2 + DIM..2 + DIM + 2],
        &[0u8, 0u8],
        "префикс длины при 65 536 элементах обязан записаться как усечённый ноль — \
         иначе описанный в гипотезе механизм молчаливого усечения не тот"
    );
    let res = Find::decode(&f.encode_unsigned());
    assert!(res.is_err(), "порог (2): тело с 65 536 элементами декодировалось как валидный Find");
    eprintln!("## порог (2): 65 536 кластеров — отказ, variant: {:?} ##", res.err().unwrap());
}
