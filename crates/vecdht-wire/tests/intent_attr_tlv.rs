//! Оракул `E-0100`, порог (2): каноническая форма атрибутов объявления (§5.5) и фильтров
//! поиска (§12.7) на настоящем кодеке.
//!
//! Проверяется четыре вещи, и каждая обязана уметь покраснеть:
//!   1. интент без объявления байт-в-байт прежний (`free` + `unspecified` не добавляет тегов);
//!   2. четыре канонические комбинации проходят круг `encode → decode → intent()` без потерь;
//!   3. явные нули схлопываются так, что подписанные байты совпадают с записью без тегов;
//!   4. неканоничные сочетания отвергаются декодом, а не «трактуются как free».
//!
//! Ни сети, ни корпуса: единственный прибор — `vecdht_wire::Codec`.

use vecdht_wire::codec::{DecodeError, DIM};
use vecdht_wire::messages::{
    ClassFilter, Codec, DirFilter, Find, IntentAttrs, IntentClass, IntentDir, Publish,
};

fn publish_with(tlv: Vec<(u16, Vec<u8>)>) -> Publish {
    Publish {
        preprocessing_version: 1,
        cluster_id: 7,
        vec_q: [0i8; DIM],
        owner_ed25519: [3u8; 32],
        ttl_buckets: 225,
        published_bucket: 106_250_000,
        pow_bits: 20,
        pow_nonce: 0,
        intent_id: [4u8; 32],
        tlv,
    }
}

fn find_with(tlv: Vec<(u16, Vec<u8>)>) -> Find {
    Find {
        preprocessing_version: 1,
        query_vector: [0i8; DIM],
        clusters: vec![7],
        top_k: 4,
        query_id: 9,
        requester_ed25519: [5u8; 32],
        tlv,
    }
}

#[test]
fn free_and_unspecified_add_no_bytes() {
    // Порог (1) в той части, которая принадлежит кодеку: механизм «тегов нет» — это отсутствие
    // тегов, а не запись нулей. Собираем атрибуты через тот же `set_intent`, которым пользуется
    // публикующий агент, и сравниваем с кадром, где TLV вообще не трогали.
    let plain = publish_with(Vec::new());
    let mut via_attrs = publish_with(Vec::new());
    via_attrs.set_intent(IntentAttrs::default());
    assert!(via_attrs.tlv.is_empty(), "free+unspecified обязан не оставить тегов");
    assert_eq!(plain.encode_unsigned(), via_attrs.encode_unsigned());
    assert_eq!(plain.body_bytes().len(), via_attrs.body_bytes().len());
}

#[test]
fn four_canonical_combinations_round_trip() {
    let cases = [
        (IntentClass::Free, None, IntentDir::Unspecified),
        (IntentClass::Free, None, IntentDir::Buy),
        (IntentClass::Paid, Some(500), IntentDir::Sell),
        (IntentClass::Paid, Some(1), IntentDir::Buy),
    ];
    for (class, price, dir) in cases {
        let attrs = IntentAttrs { class, price, dir };
        let mut p = publish_with(Vec::new());
        p.set_intent(attrs);
        let back = Publish::decode(&p.encode_unsigned()).expect("каноничная форма обязана декодироваться");
        assert_eq!(back.intent().expect("декод уже проверил форму"), attrs, "потеря атрибутов в круге");
        // Канонический круг: повторный энкод не меняет байтов.
        assert_eq!(back.encode_unsigned(), p.encode_unsigned());
        // Повторная запись тех же атрибутов не дублирует теги.
        let mut again = back.clone();
        again.set_intent(attrs);
        assert_eq!(again.tlv, back.tlv, "set_intent обязан быть идемпотентным");
    }
}

#[test]
fn explicit_zero_tags_collapse_before_signature() {
    // §5.5 п. 1: `intent_class = 0` и `intent_dir = 0` неканоничны; обе записи подписаны теми же
    // байтами, что запись без тегов. Проверяем именно байты, а не флаг в структуре.
    let noncanon = publish_with(vec![(0x0002, vec![0u8]), (0x0004, vec![0u8])]);
    let plain = publish_with(Vec::new());
    let decoded = Publish::decode(&noncanon.encode_unsigned()).expect("нули схлопываются, а не отвергаются");
    assert!(decoded.tlv.is_empty(), "после декода нулевые теги обязаны исчезнуть");
    assert_eq!(decoded.body_bytes(), plain.body_bytes());
    assert_eq!(decoded.intent().unwrap(), IntentAttrs::default());
}

#[test]
fn non_canonical_combinations_are_rejected() {
    let price = 500u64.to_le_bytes().to_vec();
    let cases: Vec<(&str, Vec<(u16, Vec<u8>)>)> = vec![
        ("price without intent_class", vec![(0x0003, price.clone())]),
        ("price zero for paid", vec![(0x0002, vec![1]), (0x0003, 0u64.to_le_bytes().to_vec())]),
        ("price missing for paid", vec![(0x0002, vec![1])]),
        ("price for free", vec![(0x0002, vec![0]), (0x0003, price.clone())]),
        ("class out of enum", vec![(0x0002, vec![2])]),
        ("dir out of enum", vec![(0x0004, vec![3])]),
        ("price wrong length", vec![(0x0002, vec![1]), (0x0003, vec![9, 9, 9])]),
        ("class wrong length", vec![(0x0002, vec![1, 0])]),
    ];
    for (what, tlv) in cases {
        let err = Publish::decode(&publish_with(tlv).encode_unsigned())
            .expect_err(&format!("{what}: неканоничная форма принята декодом"));
        assert!(
            matches!(err, DecodeError::BadEnum { .. } | DecodeError::IntentAttr(_)),
            "{what}: ожидался отказ формы, получено {err:?}"
        );
        eprintln!("## отбито: {what} -> {err} ##");
    }
}

#[test]
fn unknown_tags_survive_and_do_not_confuse_attrs() {
    // «Неизвестный тег игнорируется» (§5.1) — иначе старый узел не смог бы жить рядом с новым
    // полем. Известные теги при этом читаются, а чужой остаётся в байтах.
    let mut p = publish_with(vec![(0x0FF0, vec![7, 7])]);
    p.set_intent(IntentAttrs { class: IntentClass::Paid, price: Some(30), dir: IntentDir::Buy });
    let back = Publish::decode(&p.encode_unsigned()).unwrap();
    assert!(back.tlv.iter().any(|(t, _)| *t == 0x0FF0), "неизвестный тег потерян");
    assert_eq!(back.intent().unwrap().price, Some(30));
}

#[test]
fn find_any_is_absence_of_tags() {
    let plain = find_with(Vec::new());
    let mut explicit = find_with(Vec::new());
    explicit.set_filters(ClassFilter::Any, DirFilter::Any);
    assert!(explicit.tlv.is_empty());
    assert_eq!(plain.encode_unsigned(), explicit.encode_unsigned());
    let back = Find::decode(&plain.encode_unsigned()).unwrap();
    assert_eq!(back.filters().unwrap(), (ClassFilter::Any, DirFilter::Any));
    // Явные нули фильтров схлопываются так же, как у атрибутов.
    let noncanon = find_with(vec![(0x0002, vec![0u8]), (0x0003, vec![0u8])]);
    let decoded = Find::decode(&noncanon.encode_unsigned()).unwrap();
    assert!(decoded.tlv.is_empty());
    assert_eq!(decoded.body_bytes(), plain.body_bytes());
}

#[test]
fn find_filters_round_trip_and_reject_bad_enums() {
    for (class, dir) in [
        (ClassFilter::OnlyPaid, DirFilter::Buy),
        (ClassFilter::OnlyFree, DirFilter::Sell),
        (ClassFilter::Any, DirFilter::Unspecified),
        (ClassFilter::OnlyPaid, DirFilter::Any),
    ] {
        let mut f = find_with(Vec::new());
        f.set_filters(class, dir);
        let back = Find::decode(&f.encode_unsigned()).unwrap();
        assert_eq!(back.filters().unwrap(), (class, dir));
    }
    for tlv in [vec![(0x0002, vec![3u8])], vec![(0x0003, vec![4u8])], vec![(0x0002, vec![1, 1])]] {
        let err = Find::decode(&find_with(tlv).encode_unsigned()).expect_err("неканоничный фильтр принят");
        assert!(
            matches!(err, DecodeError::BadEnum { .. } | DecodeError::IntentAttr(_)),
            "ожидался отказ фильтра, получено {err:?}"
        );
    }
}

#[test]
fn predicates_are_over_the_record_bit_not_the_query_word() {
    // §12.7: `OnlyFree` пропускает только `paid = 0`, `OnlyPaid` — только `paid = 1`;
    // `Buy`/`Sell`/`Unspecified` сравнивают младшие два бита `slot_attr` с направлением АВТОРА.
    assert!(ClassFilter::OnlyFree.rejects(true));
    assert!(!ClassFilter::OnlyFree.rejects(false));
    assert!(ClassFilter::OnlyPaid.rejects(false));
    assert!(!ClassFilter::Any.rejects(true));
    assert!(DirFilter::Buy.rejects(IntentDir::Sell.as_u8()));
    assert!(!DirFilter::Buy.rejects(IntentDir::Buy.as_u8()));
    assert!(DirFilter::Unspecified.rejects(IntentDir::Buy.as_u8()));
    assert!(!DirFilter::Any.rejects(IntentDir::Sell.as_u8()));
}
