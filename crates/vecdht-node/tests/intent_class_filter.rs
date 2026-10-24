//! Оракул `E-0100`, пороги (3) и (4): класс и направление объявления доезжают от `Publish`
//! через WAL и репликацию до индекса и участвуют в выборе `Find`, а цена не сохраняется.
//!
//! Что здесь доказывается исполнением, а не чтением кода:
//!
//! * три записи с разными объявлениями живут в одном кластере, и `Find` с фильтром класса
//!   возвращает ровно ту, которую просили, — включая случай, когда платная запись дальше всех
//!   по расстоянию (фильтр стоит до отбора `top_k`, §8.4);
//! * фильтр направления читает направление АВТОРА (§12.7), а не просителя;
//! * отсутствие тега — `Any`, то есть поиск до этой правки не изменился;
//! * байт индекса — три бита: `dir | paid<<2`; цена в него не входит и в теле `Insert` её нет.
//!
//! Цена (`price`) живёт только в TLV `Publish` и не попадает ни в `IndexEntry` (424 Б), ни в
//! `slot_attr` (один байт). Порог (4) проверяется длиной тела фрейма: она равна «424 + один
//! байт объявления», а не «424 + байт + 8 байт цены».

use vecdht_index::testing::{dir, remove};
use vecdht_node::{candidates, testing, Params, ShardNode};
use vecdht_wire::frame::{decode_frame, Kind};
use vecdht_wire::messages::{
    ClassFilter, Codec, DirFilter, Find, MatchResult, ProtocolError, TLV_CLASS_FILTER,
    TLV_DIR_FILTER, TLV_INTENT_CLASS, TLV_INTENT_DIR, TLV_PRICE,
};

const SHARD: u16 = 7;
const CLUSTER: u16 = SHARD * 16;
const SEEDS: [u8; 3] = [1, 2, 3];
const POW: u32 = 8;

/// Каталог, удаляемый при выходе из области видимости: паникующий тест не оставляет мусора
/// (ДИАГНОЗ-2 прогона `E-0085` — `dir()` без Drop-гарда оседает на диске).
struct Tmp(std::path::PathBuf);

impl Drop for Tmp {
    fn drop(&mut self) {
        remove(&self.0);
    }
}

fn primary_on(dir_name: &str, p: Params) -> (ShardNode, Tmp) {
    let order = candidates::ordered(1, SHARD, &testing::holders(&SEEDS));
    let seed = *SEEDS
        .iter()
        .find(|s| testing::identity(**s).pubkey() == order[0].owner_ed25519)
        .expect("первый в порядке эпохи 1 — один из тестовых сидов");
    let d = Tmp(dir(dir_name));
    let mut n = testing::node(&d.0, SHARD, seed, p, &SEEDS);
    n.on_frame(
        testing::identity(9).pubkey(),
        &testing::signed_frame(&testing::genesis_update(SHARD, &SEEDS, 0)),
        testing::clock(0),
    )
    .expect("genesis");
    assert!(n.is_primary(), "Find обслуживает primary эпизоды");
    (n, d)
}

fn error_to(replies: &[vecdht_node::Envelope], agent: [u8; 32]) -> Option<ProtocolError> {
    replies
        .iter()
        .find(|e| e.to == agent)
        .and_then(|e| ProtocolError::decode(&e.frame).ok())
}

fn match_result(replies: &[vecdht_node::Envelope]) -> Option<MatchResult> {
    replies
        .iter()
        .find(|e| decode_frame(&e.frame).map(|f| f.header.kind) == Ok(Kind::MatchResult))
        .and_then(|e| MatchResult::decode(&e.frame).ok())
}

/// TLV объявления в каноническом порядке ключей (§5.5).
fn intent_tlv(class: u8, price: Option<u64>, dir: u8) -> Vec<(u16, Vec<u8>)> {
    let mut tlv = vec![
        (TLV_INTENT_CLASS, vec![class]),
        (TLV_INTENT_DIR, vec![dir]),
    ];
    if let Some(p) = price {
        tlv.push((TLV_PRICE, p.to_le_bytes().to_vec()));
    }
    tlv.sort_by_key(|(t, _)| *t);
    tlv
}

fn publish(n: &mut ShardNode, seed: u8, vec_seed: u8, tlv: Vec<(u16, Vec<u8>)>) {
    let agent = testing::identity(seed);
    let v = testing::vector(vec_seed);
    let spec = testing::PublishSpec {
        agent: &agent,
        vec_q: &v,
        cluster_id: CLUSTER,
        shard: SHARD,
        epoch: 1,
        published_bucket: 0,
        ttl_buckets: 225,
        bits: POW,
    };
    let frame = spec.msg(tlv).encode_unsigned();
    let replies = n
        .on_frame(agent.pubkey(), &frame, testing::clock(0))
        .expect("publish обязан обработаться");
    assert!(
        error_to(&replies, agent.pubkey()).is_none(),
        "publish отвергнут: {:?}",
        error_to(&replies, agent.pubkey()).map(|e| e.code)
    );
}

/// Ищет 8-байтовое значение цены во всех файлах каталога узла: WAL, MANIFEST, снапшот, что есть.
fn files_contain(dir: &std::path::Path, needle: &[u8; 8]) -> Vec<String> {
    let mut hits = Vec::new();
    for e in std::fs::read_dir(dir).expect("каталог узла") {
        let p = e.expect("entry").path();
        if !p.is_file() {
            continue;
        }
        let bytes = std::fs::read(&p).expect("файл узла");
        if bytes.windows(8).any(|w| w == needle) {
            hits.push(p.display().to_string());
        }
    }
    hits
}

fn find_with(
    n: &mut ShardNode,
    seed: u8,
    query_id: u64,
    class: ClassFilter,
    dir: DirFilter,
) -> MatchResult {
    let seeker = testing::identity(seed);
    let mut f = Find::decode(&testing::find_frame(
        &seeker,
        &testing::vector(1),
        &[CLUSTER],
        8,
        query_id,
    ))
    .expect("find decode");
    f.set_filters(class, dir);
    let replies = n
        .on_frame(seeker.pubkey(), &f.encode_unsigned(), testing::clock(0))
        .expect("find обязан обработаться");
    assert!(
        error_to(&replies, seeker.pubkey()).is_none(),
        "find отвергнут: {:?}",
        error_to(&replies, seeker.pubkey()).map(|e| e.code)
    );
    match_result(&replies).expect("ответ обязан быть MatchResult")
}

#[test]
fn publish_attrs_reach_the_index_and_select_the_find() {
    let (mut n, d) = primary_on("intent-class", testing::params(POW));

    // Цена — редкая восьмибайтовая константа, чтобы её случайное совпадение с вектором или
    // ключом было исключено, а поиск по байтам что-то значил.
    const PRICE: u64 = 0xD1CE_B00C_5EED_F00D;
    let price_le = PRICE.to_le_bytes();

    // (1) бесплатно, куплю; (2) платно, продам — самая ДАЛЬНЯЯ по расстоянию;
    // (3) бесплатно, направление не указано.
    publish(&mut n, 101, 1, intent_tlv(1, Some(PRICE), 2));
    publish(&mut n, 102, 60, intent_tlv(0, None, 1));
    publish(&mut n, 103, 2, intent_tlv(0, None, 0));
    assert_eq!(n.store.len(), 3, "три разных владельца — три живые записи");

    // Порог (4): цена не сохранена нигде. Проверяются и байты арены, и все файлы узла (WAL,
    // MANIFEST, снапшот) — узел пересобирает `Publish` в `Insert` и цену в него не кладёт.
    let mut arena = Vec::new();
    for e in &n.store.index.entries {
        arena.extend_from_slice(&e.to_bytes());
    }
    let arena_hits = arena.windows(8).filter(|w| *w == price_le).count();
    let hits = files_contain(&d.0, &price_le);
    println!("NODE_PRICE_ARENA_HITS={arena_hits}");
    println!("NODE_PRICE_FILE_HITS={}", hits.len());
    println!("NODE_INDEX_ENTRY_BYTES={}", core::mem::size_of::<vecdht_index::IndexEntry>());
    assert!(
        arena_hits == 0,
        "восемь байт цены найдены в арене индекса — §5.5 запрещает хранить цену"
    );
    assert!(hits.is_empty(), "цена попала в файлы узла: {hits:?}");
    assert_eq!(
        core::mem::size_of::<vecdht_index::IndexEntry>(),
        424,
        "арена остаётся 424 Б на запись (§8.2)"
    );

    // Any/Any — поведение до §5.5: все три записи, без учёта объявления.
    let any = find_with(&mut n, 201, 1, ClassFilter::Any, DirFilter::Any);
    println!("NODE_FILTER_ANY={}", any.matches.len());
    assert_eq!(any.matches.len(), 3, "Any не должен сужать выдачу");

    // Порог (3): платная запись самая дальняя — при фильтре после отбора её бы выбросило.
    let paid = find_with(&mut n, 202, 2, ClassFilter::OnlyPaid, DirFilter::Any);
    println!("NODE_FILTER_ONLYPAID={}", paid.matches.len());
    assert_eq!(paid.matches.len(), 1, "OnlyPaid обязан вернуть ровно платную");
    assert_eq!(paid.matches[0].owner_ed25519, testing::identity(101).pubkey());

    let free = find_with(&mut n, 203, 3, ClassFilter::OnlyFree, DirFilter::Any);
    println!("NODE_FILTER_ONLYFREE={}", free.matches.len());
    assert_eq!(free.matches.len(), 2, "OnlyFree — две бесплатные");
    assert!(
        free.matches
            .iter()
            .all(|m| m.owner_ed25519 != testing::identity(101).pubkey()),
        "бесплатный фильтр не выдаёт платную"
    );

    // §12.7: фильтр выбирает направление АВТОРА, а не просителя.
    let sell = find_with(&mut n, 204, 4, ClassFilter::Any, DirFilter::Sell);
    println!("NODE_FILTER_SELL={}", sell.matches.len());
    assert_eq!(sell.matches.len(), 1);
    assert_eq!(sell.matches[0].owner_ed25519, testing::identity(101).pubkey());

    let buy = find_with(&mut n, 205, 5, ClassFilter::OnlyFree, DirFilter::Buy);
    println!("NODE_FILTER_FREE_BUY={}", buy.matches.len());
    assert_eq!(buy.matches.len(), 1);
    assert_eq!(buy.matches[0].owner_ed25519, testing::identity(102).pubkey());

    let none = find_with(&mut n, 206, 6, ClassFilter::OnlyPaid, DirFilter::Buy);
    println!("NODE_FILTER_PAID_BUY={}", none.matches.len());
    assert!(none.matches.is_empty(), "платного «куплю» в шарде нет");

    // Байт индекса — ровно три бита, а не угадывание по цене.
    let slots: Vec<u32> = any.matches.iter().map(|m| m.slot).collect();
    for (owner, want) in [
        (101u8, 0b110u8), // продам (2) + платно (4)
        (102, 0b001),     // куплю (1)
        (103, 0b000),     // ничего не указано
    ] {
        let slot = slots
            .iter()
            .find(|s| n.store.index.entry(**s).unwrap().owner_ed25519 == testing::identity(owner).pubkey())
            .copied()
            .expect("запись в выдаче");
        assert_eq!(
            n.store.index.slot_attr(slot),
            Some(want),
            "slot_attr владельца {owner} обязан быть {want:#05b}"
        );
        println!("NODE_SLOT_ATTR_{owner}={want}");
    }
}

/// Тег фильтра с недопустимым значением обязан быть отказом декода, а не «Any»: иначе проситель
/// молча получил бы не тот класс, который просил (§12.7).
#[test]
fn unknown_filter_enum_is_a_decode_error() {
    let seeker = testing::identity(210);
    let raw = testing::find_frame(&seeker, &testing::vector(1), &[CLUSTER], 8, 1);
    let mut f = Find::decode(&raw).expect("find decode");
    f.tlv = vec![(TLV_CLASS_FILTER, vec![9u8])];
    assert!(Find::decode(&f.encode_unsigned()).is_err(), "class_filter=9 не должен пройти");

    let mut g = Find::decode(&raw).expect("find decode");
    g.tlv = vec![(TLV_DIR_FILTER, vec![7u8])];
    assert!(Find::decode(&g.encode_unsigned()).is_err(), "dir_filter=7 не должен пройти");

    // А нули схлопываются при декоде: явный `Any` — это отсутствие тега, байты совпадают с
    // кадром без TLV после канонического перекодирования.
    let mut h = Find::decode(&raw).expect("find decode");
    h.tlv = vec![(TLV_CLASS_FILTER, vec![0u8]), (TLV_DIR_FILTER, vec![0u8])];
    let recoded = Find::decode(&h.encode_unsigned())
        .expect("нулевые теги обязаны схлопнуться")
        .encode_unsigned();
    assert_eq!(recoded, raw, "Any не должен занимать байты на проводе");

    // Плата за неверный фильтр — существующий отказ декода, а не новый код на проводе.
    let (mut n, _d) = primary_on("intent-class-bad", testing::params(POW));
    let mut bad = Find::decode(&raw).expect("find decode");
    bad.tlv = vec![(TLV_CLASS_FILTER, vec![9u8])];
    match n.on_frame(seeker.pubkey(), &bad.encode_unsigned(), testing::clock(0)) {
        Err(err) => eprintln!("## факт: class_filter=9 отвергнут декодом: {err} ##"),
        Ok(replies) => panic!("кадр с чужим enum обязан не декодироваться, ответы: {replies:?}"),
    }
}
