//! Детерминизм состояния на уровне живого store: кросс-часовой GC (§9.6), стабильность
//! `slot`/`entry_key` после compaction (§8.3), дедупликация перепубликации и воспроизводимость
//! контракта поиска (§8.4). Всё это — гейты §19.1.

use std::path::PathBuf;

use vecdht_crypto::ids::entry_key;
use vecdht_index::entry::IndexEntry;
use vecdht_index::snapshot::snapshot_name;
use vecdht_index::store::ShardStore;
use vecdht_index::testing::{Rng, dir, remove};
use vecdht_index::wal::WalFrame;
use vecdht_index::{CLUSTERS_PER_SHARD, now_bucket};
use vecdht_wire::codec::DIM;
use vecdht_wire::messages::{Codec, MatchResult, OpKind, encode_mark};

fn owner_of(id: u64) -> [u8; 32] {
    let mut o = [0u8; 32];
    o[..8].copy_from_slice(&id.to_le_bytes());
    o[8] = 0x5d;
    o
}

/// Вектор записи — детерминированная функция от `id`: два узла на одном потоке обязаны видеть
/// одни и те же байты, иначе сравнение файлов теряет смысл. Перемешивание — xorshift-подобное,
/// потому что разные `id` должны давать разные векторы (иначе `d2` везде одинаков и контракт
/// поиска §8.4 проверяется на вырожденном входе).
fn fake_vector(id: u64) -> [i8; DIM] {
    const A: u64 = 0x9E37_79B9_7F4A_7C15;
    const B: u64 = 0xC2B2_AE3D_27D4_EB4F;
    const C: u64 = 6_364_136_223_846_793_005;
    let mut v = [0i8; DIM];
    for (k, lane) in v.iter_mut().enumerate() {
        let mut x = (k as u64).wrapping_mul(A) ^ id.wrapping_mul(B);
        x = x.wrapping_mul(C).wrapping_add(1_442_695_040_888_963_407);
        x ^= x >> 29;
        *lane = ((x >> 33) % 7) as i8 - 3;
    }
    v
}

/// Запись шарда 0 (`cluster % 16 < CLUSTERS_PER_SHARD`).
fn entry(id: u64, published: u32, ttl: u16) -> IndexEntry {
    IndexEntry {
        owner_ed25519: owner_of(id),
        vec_q: fake_vector(id),
        cluster_id: (id % CLUSTERS_PER_SHARD as u64) as u16,
        published_bucket: published,
        ttl_buckets: ttl,
    }
}

fn open(tag: &str) -> (PathBuf, ShardStore) {
    let d = dir(tag);
    let s = ShardStore::create(&d, 0, 1).unwrap();
    (d, s)
}

/// Ключи живых записей: `(owner, slot, entry_key)` по возрастанию slot'а (§6.5, §8.3).
fn keys(store: &ShardStore) -> Vec<([u8; 32], u32, [u8; 32])> {
    store
        .index
        .live_slots()
        .map(|(slot, e)| (e.owner_ed25519, slot, entry_key(&e.owner_ed25519, store.shard, slot, store.max_epoch_served)))
        .collect()
}

/// Локальные часы узла в тесте. Единственное, для чего они нужны, — решить, *когда* выдать
/// `TimeMark`; в путь применения бакет приходит данными опса (§9.6).
fn write_stream(store: &mut ShardStore, stream: &[WalFrame]) {
    for f in stream {
        store.wal.append(f).unwrap();
        store.apply_frame(f).unwrap();
    }
    store.wal.fsync().unwrap();
}

// --- кросс-часовой GC -------------------------------------------------------

#[test]
fn replicas_with_clocks_40_minutes_apart_write_the_same_index_file() {
    const T0: u64 = 1_700_000_000;
    let a_now = now_bucket(T0);
    let b_now = now_bucket(T0 + 2_400); // 40 минут = ровно 150 бакетов по 16 с
    assert_eq!(b_now - a_now, 150);

    let ttl = 150u16; // «протухла» бы на B, если бы GC заглядывал в его часы
    let mark = a_now + 10; // TimeMark/GcTick из потока; он раньше дедлайна
    assert!(mark < b_now, "иначе тест не различает часы и поток");

    let mut stream: Vec<WalFrame> = Vec::new();
    let mut seq = 0u64;
    for i in 0..200u64 {
        seq += 1;
        let e = entry(i, a_now, ttl);
        stream.push(WalFrame::new(seq, OpKind::Insert, e.to_insert().body_bytes()));
        if i % 64 == 63 {
            seq += 1;
            let b = a_now + (i / 64) as u32;
            stream.push(WalFrame::new(seq, OpKind::TimeMark, encode_mark(seq, b)));
        }
    }
    seq += 1;
    stream.push(WalFrame::new(seq, OpKind::TimeMark, encode_mark(seq, mark)));
    seq += 1;
    stream.push(WalFrame::new(seq, OpKind::GcTick, encode_mark(seq, mark)));

    let (da, mut a) = open("clock-a");
    let (db, mut b) = open("clock-b");
    write_stream(&mut a, &stream);
    write_stream(&mut b, &stream);

    assert_eq!(a.applied_seq, seq);
    assert_eq!(b.applied_seq, seq);
    // «Сейчас» обоих узлов — бакет из потока, а не локальное время (§9.6).
    assert_eq!(a.time_mark_bucket, mark);
    assert_eq!(b.time_mark_bucket, mark);
    assert_eq!(a.index.live, 200, "GcTick раньше дедлайна ⇒ ничего не снято");

    a.flush_snapshot().unwrap();
    b.flush_snapshot().unwrap();
    let fa = std::fs::read(da.join(snapshot_name(seq))).unwrap();
    let fb = std::fs::read(db.join(snapshot_name(seq))).unwrap();
    assert_eq!(fa, fb, "часы расходятся на 40 минут ⇒ файл индекса обязан побайтово совпасть (§19.1)");
    drop(a);
    drop(b);

    // Тот же результат после перезагрузки обоих узлов.
    let a2 = ShardStore::open(&da, 0).unwrap();
    let b2 = ShardStore::open(&db, 0).unwrap();
    assert_eq!(keys(&a2), keys(&b2));
    assert_eq!(a2.time_mark_bucket, b2.time_mark_bucket);

    // Негативный контроль: GC по локальным часам B снял бы все 200 записей. Равенство файлов
    // обеспечивает не «длинный TTL», а запрет читать часы в пути применения (§9.6).
    let (dc, mut c) = open("clock-c");
    write_stream(&mut c, &stream);
    let removed = c.index.expire(b_now).len();
    assert_eq!(removed, 200, "контроль не сработал: бакет B не снимает записи");
    assert_ne!(c.index.live, a2.index.live);

    remove(&da);
    remove(&db);
    remove(&dc);
}

// --- compaction и стабильность slot'ов -------------------------------------

#[test]
fn compaction_does_not_renumber_slots_nor_change_entry_keys() {
    let (d, mut s) = open("compact");
    for i in 0..200u64 {
        s.publish(entry(i, 5, 1_000)).unwrap();
    }
    let before = keys(&s);
    assert_eq!(before.len(), 200);
    let next_slot = s.index.next_slot();
    assert_eq!(next_slot, 200);

    // Каждая вторая запись уходит через `Delete`, а каждая четвёртая нечётная (i ≡ 1 mod 4)
    // перепубликуется с коротким TTL и снимается `GcTick`-ом. Остальные 50 обязаны выжить:
    // иначе compaction проверялась бы на пустом индексе.
    let mut dead: Vec<u32> = Vec::new();
    for i in (0..200u64).step_by(2) {
        dead.push(s.index.owner_slot(&owner_of(i)).unwrap());
        s.stage_delete(owner_of(i)).unwrap();
    }
    let short: Vec<u64> = (1..200u64).step_by(4).collect();
    for i in &short {
        // replace-in-place: slot не меняется, но published/ttl — да (5 + 100 ≤ 105 ⇒ снимется).
        dead.push(s.index.owner_slot(&owner_of(*i)).unwrap());
        s.stage_insert(entry(*i, 5, 100)).unwrap();
    }
    s.commit().unwrap();
    s.stage_gc_tick(105).unwrap();
    s.commit().unwrap();

    let survivors_after_gc = keys(&s);
    assert_eq!(survivors_after_gc.len(), 50, "compaction без живых записей ничего не доказывает");
    // «Утряска» v8 — это `flush_snapshot` (§8.3): файл содержит только живые записи.
    let seq = s.applied_seq;
    s.flush_snapshot().unwrap();
    let after_flush = keys(&s);
    assert_eq!(survivors_after_gc, after_flush, "flush меняет slot'ы или entry_key");
    drop(s);

    let s = ShardStore::open(&d, 0).unwrap();
    assert_eq!(keys(&s), after_flush, "recovery перенумеровал записи");
    assert_eq!(s.index.next_slot(), next_slot, "дыры не переиспользованы (§8.3)");
    // Мёртвые slot'ы остались мёртвыми и не вернулись из снапшота.
    let live_slots: Vec<u32> = s.index.live_slots().map(|(slot, _)| slot).collect();
    assert_eq!(dead.len(), 150);
    for slot in &dead {
        assert!(!live_slots.contains(slot), "slot {slot} воскрес после compaction");
    }
    // Выжившие — те же самые `(owner, slot, entry_key)`, что и до удаления/тряски.
    for k in &survivors_after_gc {
        assert!(before.contains(k), "выжившая запись сменила slot или entry_key");
    }
    // Снапшот не содержит ни одной мёртвой записи, но содержит все живые.
    let loaded = vecdht_index::snapshot::read_snapshot(&d.join(snapshot_name(seq))).unwrap();
    assert_eq!(loaded.index.live, live_slots.len());
    assert_eq!(loaded.meta.next_slot, next_slot as u64);
    remove(&d);
}

// --- дедупликация перепубликации --------------------------------------------

#[test]
fn republish_of_the_same_owner_replaces_in_place_through_the_wal() {
    let (d, mut s) = open("dedup");
    let first = entry(9, 10, 500);
    let slot1 = s.publish(first).unwrap();
    // Тот же `(owner, shard)`, другие вектор, кластер и бакет — перепубликация интента (§6.5).
    let mut second = first;
    second.vec_q = fake_vector(77);
    second.cluster_id = (first.cluster_id + 5) % CLUSTERS_PER_SHARD;
    second.published_bucket = 40;
    let slot2 = s.publish(second).unwrap();
    assert_eq!(slot1, slot2, "перепубликация обязана заменить на месте");
    assert_eq!(s.index.live, 1, "живых записей — одна");
    assert_eq!(s.index.next_slot(), 1);
    assert_eq!(s.applied_seq, 2, "а опсов в журнале два");
    assert_eq!(s.index.cluster_slots(first.cluster_id).to_vec(), Vec::<u32>::new());
    assert_eq!(s.index.cluster_slots(second.cluster_id).to_vec(), vec![slot1]);
    assert_eq!(s.index.entry(slot1).unwrap().published_bucket, 40);

    let keys_before = keys(&s);
    s.flush_snapshot().unwrap();
    drop(s);
    let s = ShardStore::open(&d, 0).unwrap();
    assert_eq!(s.index.live, 1);
    assert_eq!(keys(&s), keys_before, "после recovery изменился slot или entry_key");
    assert_eq!(s.index.entry(slot1).unwrap().vec_q, second.vec_q);
    remove(&d);
}

// --- контракт поиска --------------------------------------------------------

/// Два независимых прогона одного потока опсов ⇒ идентичные `MatchResult`-байты ⇒ идентичная
/// подпись (§8.4, §19.1).
#[test]
fn two_independent_runs_produce_identical_canonical_match_bodies() {
    let mut r = Rng::new(0xC10C);
    let mut stream: Vec<WalFrame> = Vec::new();
    let mut seq = 0u64;
    for _ in 0..400u64 {
        seq += 1;
        let id = r.below(300);
        // Бакеты и TTL подобраны так, чтобы `GcTick` из потока действительно что-то снимал:
        // дедлайн 1020..1050, тики — 1040, 1080, 1120, …
        let published = 1_000 + r.below(50) as u32;
        let ttl = 20 + r.below(30) as u16;
        let e = entry(id, published, ttl);
        let kind = if r.below(20) == 0 { OpKind::Delete } else { OpKind::Insert };
        let body = if kind == OpKind::Delete {
            let op = vecdht_wire::messages::DeleteOp { owner_ed25519: owner_of(id), shard: 0 };
            op.body_bytes()
        } else {
            e.to_insert().body_bytes()
        };
        stream.push(WalFrame::new(seq, kind, body));
        if seq % 128 == 0 {
            let b = 1_000 + 40 * (seq / 128) as u32;
            stream.push(WalFrame::new(seq + 1, OpKind::GcTick, encode_mark(seq + 1, b)));
            seq += 1;
        }
    }
    let last_tick = 1_000 + 40 * (400 / 128) as u32;

    let (d1, mut a) = open("runs-a");
    let (d2, mut b) = open("runs-b");
    write_stream(&mut a, &stream);
    write_stream(&mut b, &stream);
    assert_eq!(a.time_mark_bucket, last_tick);
    assert_eq!(b.time_mark_bucket, last_tick);
    assert!(a.index.live > 0, "поток снял всё — тест не о чём");
    assert!(a.index.tombstones() > 0, "ни удалений, ни экспирации — искать нечего");

    // Один и тот же запрос, nprobe = все кластеры шарда.
    let clusters: Vec<u16> = (0..CLUSTERS_PER_SHARD).collect();
    let mut q = [0i8; DIM];
    for (k, lane) in q.iter_mut().enumerate() {
        *lane = ((k % 5) as i8) - 2;
    }
    let mut bodies: Vec<Vec<u8>> = Vec::new();
    for s in [&a, &b] {
        let hits = s.search(&q, &clusters, 10);
        let mr = MatchResult {
            shard: s.shard,
            epoch: s.max_epoch_served,
            query_id: 7,
            responder_ed25519: [0x11; 32],
            matches: s.index.matches(&hits),
        };
        mr.check_sort_contract().expect("контракт §8.4 нарушен");
        assert!(
            hits.windows(2).all(|w| (w[0].0, w[0].1) <= (w[1].0, w[1].1)),
            "порядок (§8.4): d2 ASC, затем slot ASC"
        );
        bodies.push(mr.body_bytes());
    }
    assert_eq!(bodies[0], bodies[1], "два прогона дали разные canonical-байты");
    assert_eq!(keys(&a), keys(&b));

    // Tie-break по slot'у: одинаковые векторы ⇒ одинаковый d2, порядок — по возрастанию slot.
    let (d3, mut c) = open("runs-tie");
    for _ in 0..5 {
        c.publish(entry(3_000 + c.index.next_slot() as u64 % 7, 1, 1_000)).unwrap();
    }
    // пять записей с идентичным вектором (id % 7 = 0 ⇒ один и тот же fake_vector)
    let mut tie = Vec::new();
    for i in 0..5u64 {
        let mut e = entry(0, 1, 1_000);
        e.owner_ed25519 = owner_of(4_000 + i);
        let slot = c.publish(e).unwrap();
        tie.push(slot);
    }
    let hits = c.search(&fake_vector(0), &[0], 10);
    assert!(hits.iter().all(|(_, slot)| tie.contains(slot)));
    let slots: Vec<u32> = hits.iter().map(|(_, s)| *s).collect();
    let mut sorted = slots.clone();
    sorted.sort_unstable();
    assert_eq!(slots, sorted, "при равном d2 порядок обязан быть по slot'у (§8.4)");
    assert_eq!(hits[0].1, hits.iter().map(|h| h.1).min().unwrap());

    remove(&d1);
    remove(&d2);
    remove(&d3);
}

/// Инвариант, без которого сравнение файлов было бы сравнением пустоты: хелперы потока
/// детерминированы и не схлопывают записи дедупликацией.
#[test]
fn stream_helpers_are_deterministic() {
    assert_eq!(fake_vector(3), fake_vector(3));
    assert_ne!(fake_vector(3), fake_vector(4));
    assert_eq!(owner_of(1), owner_of(1));
    // Разные id ⇒ разные владельцы: иначе 200 «записей» схлопнулись бы дедупликацией.
    let mut s = IvfLike::new();
    for i in 0..200u64 {
        s.push(entry(i, 5, 1_000));
    }
    assert_eq!(s.count(), 200);
    // Один и тот же вызов `entry` даёт идентичные canonical-байты опса — иначе сравнение
    // `snap.*.log` между узлами не имеет смысла.
    assert_eq!(entry(7, 5, 9).to_insert().body_bytes(), entry(7, 5, 9).to_insert().body_bytes());
    assert_ne!(entry(7, 5, 9).to_insert().body_bytes(), entry(7, 5, 10).to_insert().body_bytes());
}

/// Мини-обёртка над `IvfIndex` для последней проверки — без неё тест сравнивал бы null-арены.
struct IvfLike {
    index: vecdht_index::ivf::IvfIndex,
}

impl IvfLike {
    fn new() -> Self {
        IvfLike { index: vecdht_index::ivf::IvfIndex::with_capacity(0, 256) }
    }
    fn push(&mut self, e: IndexEntry) {
        self.index.insert(e).unwrap();
    }
    fn count(&self) -> usize {
        self.index.live
    }
}
