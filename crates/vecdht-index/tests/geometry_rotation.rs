//! Оракул `E-0028` (`H-0027`): стадия 1 плана v9 — «`nlist` как данные». Пять пунктов оракула,
//! пороги и фальсификаторы зафиксированы в `lab/hypotheses/H-0027-stage1-geometry-as-data.md`
//! ДО написания этого файла; здесь только измерение.
//!
//! Лёгкий файл: без `candle`, без корпуса, секунды CPU — по дисциплине замеров запускается
//! только в паузе между тяжёлыми прогонами (не конкурентно с цепочкой `e0027`).
//!
//! Пункты: (1) layout-invariance кадров, (2) откуда именно приходит отказ, (3) снапшот чужой
//! геометрии, (4) потолок `MAX_CERT_SHARDS` и wildcard, (5) `ArtifactAnnounce` как данные.

use vecdht_index::entry::IndexEntry;
use vecdht_index::ivf::IvfIndex;
use vecdht_index::snapshot::{parse_snapshot, write_snapshot, SnapshotMeta, SNAP_HEADER_LEN};
use vecdht_wire::cert::{NodeCert, CERT_VERSION, MAX_CERT_SHARDS};
use vecdht_wire::codec::DIM;
use vecdht_wire::messages::{
    ArtifactAnnounce, Codec, Find, Match, MatchResult, RendezvousAccept, Role, SnapshotOffer,
};
use vecdht_wire::{NLIST, SHARDS};

/// Значения поля геометрии: два протокольных, верх протокольного диапазона (`NLIST-1`) и два
/// внепротокольных (`4096-1`, `8192-1` — те же, что измерялись в `E-0025`).
const GEOM: [u16; 5] = [15, 511, 1023, 4095, 8191];

fn find_with(clusters: Vec<u16>) -> Find {
    Find {
        preprocessing_version: 3,
        query_vector: [7i8; DIM],
        clusters,
        top_k: 10,
        query_id: 42,
        requester_ed25519: [9; 32],
        tlv: vec![],
    }
}

fn m_with(cluster_id: u16) -> Match {
    Match { owner_ed25519: [3; 32], cluster_id, d2: 1000, slot: 7 }
}

fn mr_with(shard: u16) -> MatchResult {
    MatchResult {
        shard,
        epoch: 4,
        query_id: 42,
        responder_ed25519: [8; 32],
        matches: vec![m_with(1)],
    }
}

fn ra_with(shard: u16) -> RendezvousAccept {
    RendezvousAccept {
        seeker: [1; 32],
        target: [2; 32],
        shard,
        slot: 9,
        issued_bucket: 1000,
        ttl_sec: 300,
    }
}

fn so_with(shard: u16) -> SnapshotOffer {
    SnapshotOffer {
        shard,
        epoch: 4,
        snapshot_seq: 9,
        oldest_wal_needed: 1,
        applied_seq: 9,
        next_slot: 12,
        time_mark_bucket: 77,
        total_len: 64,
        offset: 0,
        content_hash: [5; 32],
        chunk: vec![0xAA; 8],
    }
}

fn entry(owner: u8, cluster: u16) -> IndexEntry {
    IndexEntry {
        owner_ed25519: [owner; 32],
        vec_q: [(owner as i8) ^ 0x5a; DIM],
        cluster_id: cluster,
        published_bucket: 100,
        ttl_buckets: 10,
    }
}

/// Побайтовое сравнение двух кодировок одинаковой формы.
fn diff(a: &[u8], b: &[u8]) -> (usize, usize, Vec<usize>) {
    let pos = if a.len() == b.len() {
        (0..a.len()).filter(|&i| a[i] != b[i]).collect()
    } else {
        Vec::new()
    };
    (a.len(), b.len(), pos)
}

// ------------------------------------------------------------------ пункт (1)

#[test]
fn layout_invariance_frame_length_does_not_depend_on_geometry_value() {
    // Порог (1): длина кадра не зависит от значения поля; различие — ровно 2 байта (u16 LE)
    // на изменённое поле. Ни одна раскладка не «съезжает» при значении вне протокольного
    // диапазона — кодек не знает про геометрию вообще.
    let mut checked = 0usize;
    for v in GEOM {
        for (name, base, other) in [
            ("Match", m_with(15).encode_unsigned(), m_with(v).encode_unsigned()),
            (
                "MatchResult",
                mr_with(0).encode_unsigned(),
                // значения ≥ SHARDS здесь тоже нужны: проверяется раскладка, а валидатор
                // диапазона измеряется пунктом (2); decode для них обязан не проходить,
                // но encode даёт тот же каркас байтов,
                mr_with(v).encode_unsigned(),
            ),
            ("RendezvousAccept", ra_with(0).encode_unsigned(), ra_with(v).encode_unsigned()),
            ("SnapshotOffer", so_with(0).encode_unsigned(), so_with(v).encode_unsigned()),
        ] {
            let (la, lb, pos) = diff(&base, &other);
            assert_eq!(la, lb, "{name}: длина кадра зависит от значения геометрии {v}");
            // GEOM не содержит 0, поэтому скалярное поле отличается от основания при любом v,
            // кроме v=15 у Match: ровно 2 байта little-endian u16.
            let expect = if name == "Match" && v == 15 { 0 } else { 2 };
            assert_eq!(pos.len(), expect, "{name} значением {v}: отличлись {pos:?}, ожидалось {expect}");
            checked += 1;
        }
        // Find: список фиксированного числа элементов — меняются только байты значений.
        let base = find_with(vec![15, 511, 1023]).encode_unsigned();
        let other = find_with(vec![v, 511, 1023]).encode_unsigned();
        let (la, lb, pos) = diff(&base, &other);
        assert_eq!(la, lb, "Find: длина зависит от cluster={v}");
        assert_eq!(pos.len(), if v == 15 { 0 } else { 2 }, "Find cluster={v}: {pos:?}");
        checked += 1;

        // NodeCert: при одном числе шардов значение элемента не меняет длину.
        // (15 % 63) + 1 == 16, (1023 % 63) + 1 == 37 — ни одно v не совпадает с основанием 3.
        let a = cert_with(vec![0, 1, 3]).encode();
        let b = cert_with(vec![0, 1, (v % (SHARDS as u16 - 1)) + 1]).encode();
        let (la, lb, pos) = diff(&a, &b);
        assert_eq!(la, lb, "NodeCert: длина зависит от значения shard={v}");
        assert_eq!(pos.len(), 2, "NodeCert shard={v}: ожидалось 2 байта различия, {pos:?}");
        checked += 1;
    }
    eprintln!("## пункт (1): сравнено {checked} пар кодировок, все длины совпали ##");
}

// ------------------------------------------------------------------ пункт (2)

#[test]
fn validity_not_layout_refusals_come_from_validators() {
    // Фиксируем таблицу «значение → принимает/отвергает и чем». Порог (2): отказ обязан
    // приходить из проверки допустимости (класс B), а не из кодера или раскладки.
    let mut table = String::new();
    for v in GEOM {
        let find = Find::decode(&find_with(vec![v, 15]).encode_unsigned());
        let mr = MatchResult::decode(&mr_with(v).encode_unsigned());
        let ra = RendezvousAccept::decode(&ra_with(v).encode_unsigned());
        let so = SnapshotOffer::decode(&so_with(v).encode_unsigned());
        let mt = Match::decode(&m_with(v).encode_unsigned());
        table.push_str(&format!(
            "v={v:>5}  Find:{:?}  MatchResult:{:?}  RendAccept:{:?}  SnapOffer:{:?}  Match:{:?}\n",
            find.err().map(|e| format!("{e:?}")).unwrap_or_else(|| "accept".into()),
            mr.err().map(|e| format!("{e:?}")).unwrap_or_else(|| "accept".into()),
            ra.err().map(|e| format!("{e:?}")).unwrap_or_else(|| "accept".into()),
            so.err().map(|e| format!("{e:?}")).unwrap_or_else(|| "accept".into()),
            mt.err().map(|e| format!("{e:?}")).unwrap_or_else(|| "accept".into()),
        ));
    }
    eprintln!("## пункт (2): кто отвергает значение геометрии ##\n{table}");

    // Обязательства из H-0027, проверяемые жёстко:
    // (2-а) скалярные валидаторы диапазона стоят на месте для shard (класс B);
    for v in [4095u16, 8191] {
        assert!(MatchResult::decode(&mr_with(v).encode_unsigned()).is_err(), "MatchResult shard={v} принят");
        assert!(RendezvousAccept::decode(&ra_with(v).encode_unsigned()).is_err(), "RendezvousAccept shard={v} принят");
        assert!(SnapshotOffer::decode(&so_with(v).encode_unsigned()).is_err(), "SnapshotOffer shard={v} принят");
    }
    // (2-б) `Find.clusters` сегодня НЕ валидируется по NLIST на декоде — находка: проверка
    // стоит только на cluster_id кадра Publish (`messages.rs:259`). Если это изменится,
    // assert below обязан упасть и быть перезаписан как новое измерение.
    let unvalidated = Find::decode(&find_with(vec![4095, 8191, 65535]).encode_unsigned());
    assert!(unvalidated.is_ok(), "Find.cluster_id теперь валидируется — обновить запись (2-б)");
    // (2-в) то же для `Match.cluster_id` внутри MatchResult:
    assert!(Match::decode(&m_with(4095).encode_unsigned()).is_ok(), "Match.cluster_id теперь валидируется");
}

// ------------------------------------------------------------------ пункт (3)

const CRC_LEN: usize = 4;
const ENTRY_LINE_BYTES: usize = 4 + 32 + DIM + 2 + 4 + 2; // slot + IndexEntry

fn recrc(bytes: &mut [u8]) {
    let body = bytes.len() - CRC_LEN;
    let crc = blake3::hash(&bytes[..body]);
    bytes[body..].copy_from_slice(&crc.to_le_bytes());
}

fn write_to_bytes(ix: &IvfIndex, seq: u64) -> Vec<u8> {
    let m = SnapshotMeta {
        snapshot_seq: seq,
        next_slot: ix.next_slot() as u64,
        time_mark_bucket: 77,
        max_epoch_served: 3,
        shard: ix.shard,
    };
    let mut path = std::env::temp_dir();
    path.push(format!("vecdht-e0028-{}-{seq}.bin", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let mut file = std::fs::File::create(&path).unwrap();
    let n = write_snapshot(&mut file, m, ix).unwrap();
    file.sync_all().unwrap();
    drop(file);
    let bytes = std::fs::read(&path).unwrap();
    assert_eq!(n as usize, bytes.len(), "писатель вернул неверный размер");
    let _ = std::fs::remove_file(&path);
    bytes
}

#[test]
fn snapshot_cross_geometry_rejected_but_header_has_no_geometry_field() {
    let mut ix = IvfIndex::new(0);
    ix.insert(entry(1, 0)).unwrap();
    ix.insert(entry(2, 1)).unwrap();
    let bytes = write_to_bytes(&ix, 9);

    // (3-а) заголовок не различает геометрию: NLIST не встречается ни в одном u16-окне
    // 48-байтного заголовка (метрики выбраны так, чтобы не совпасть с 1024 случайно).
    let mut found_at = Vec::new();
    for off in 0..=(SNAP_HEADER_LEN - 2) {
        if u16::from_le_bytes(bytes[off..off + 2].try_into().unwrap()) == NLIST {
            found_at.push(off);
        }
    }
    eprintln!("## (3-а) SNAP_HEADER_LEN={SNAP_HEADER_LEN}, u16==NLIST в заголовке: {found_at:?}");
    assert!(found_at.is_empty(), "в заголовке снапшота есть u16==NLIST на {found_at:?}");

    // (3-б) фальсификатор (б): файл «чужой геометрии» — лишняя пустая секция списков.
    // Вставка в НАЧАЛО блока списков: читатель ждёт NLIST секций и не знает о лишней.
    let lists_at = SNAP_HEADER_LEN + 2 * ENTRY_LINE_BYTES;
    let mut head_extra = bytes.clone();
    head_extra.splice(lists_at..lists_at, [0u8; 4]);
    recrc(&mut head_extra);
    let res = parse_snapshot(&head_extra);
    eprintln!("## (3-б) лишняя секция в начале: {:?}", res.as_ref().err().map(|e| e.to_string()));
    assert!(res.is_err(), "ФАЛЬСИФИКАТОР (б): снапшот чужой геометрии прочитался как Ok");

    // (3-в) та же лишняя секция в КОНЕЦ блока списков (перед CRC).
    let mut tail_extra = bytes.clone();
    let crc_at = tail_extra.len() - CRC_LEN;
    tail_extra.splice(crc_at..crc_at, [0u8; 4]);
    recrc(&mut tail_extra);
    let res2 = parse_snapshot(&tail_extra);
    eprintln!("## (3-в) лишняя секция в конце: {:?}", res2.as_ref().err().map(|e| e.to_string()));
    assert!(res2.is_err(), "ФАЛЬСИФИКАТОР (б): хвост чужой геометрии принят как Ok");

    // Ключевой нюанс H-0027 (класс H1-3): отказ приходит ПОБОЧНЫМ ЭФФЕКТОМ сдвига потока
    // байтов (TooShort/расхождение списков), а не потому, что загрузчик сверяет геометрию:
    // он физически не знает числа секций файла. Печатаем вид ошибки, чтобы запись `E-0028`
    // не записала «загрузчик проверяет геометрию».
    if let Err(e) = &res {
        let s = e.to_string();
        eprintln!("## (3-г) характер отказа в (3-б): {s}");
        assert!(!s.contains("геометр") && !s.contains("nlist"), "загрузчик всё-таки сверяет геометрию — обновить H-0027");
    }
}

// ------------------------------------------------------------------ пункт (4)

fn cert_with(shards: Vec<u16>) -> NodeCert {
    NodeCert {
        version: CERT_VERSION,
        genesis_hash: [7; 32],
        role: Role::IndexNode,
        owner_ed25519: [3; 32],
        dht_peer_id: vec![0x9C; 32],
        shards,
        capacity_entries: 10_000,
        valid_from: 100,
        valid_until: 200,
        nonce: [4; 16],
        authority_sigs: vec![[6u8; 64]; 3],
    }
}

#[test]
fn cert_shard_cap_forces_wildcard_and_wildcard_disables_filtering() {
    // (4-а) явный список из MAX_CERT_SHARDS+1 шардов — отказ (класс E).
    let over = cert_with((0..=MAX_CERT_SHARDS as u16).map(|i| i % SHARDS as u16).collect());
    let res = NodeCert::decode(&over.encode());
    eprintln!("## (4-а) {} шардов: {:?}", over.shards.len(), res.as_ref().err().map(|e| e.to_string()));
    assert!(res.is_err(), "decode принял {}+1 шардов", MAX_CERT_SHARDS);

    // (4-б) wildcard принимается и покрывает любой шард, включая внепротокольные 255/511.
    // Это и есть форма, к которой стадия 1 обязана свестись при shards>64, — вместе с тем,
    // что `covers_shard` для пустого списка всегда true, то есть фильтрация покрытия
    // отключается (класс H1-4; сюда, в ростер, это измерение не входит — см. H-0027).
    let wild = cert_with(vec![]);
    assert!(NodeCert::decode(&wild.encode()).is_ok(), "wildcard не проходит decode");
    assert!(wild.covers_shard(255) && wild.covers_shard(511), "wildcard не покрывает будущие шарды");

    // (4-в) явный список валидируется `s < SHARDS`: при shards > 64 явная форма невыразима.
    assert!(NodeCert::decode(&cert_with(vec![SHARDS as u16]).encode()).is_err());
}

// ------------------------------------------------------------------ пункт (5)

#[test]
fn artifact_announce_already_carries_geometry_as_data() {
    for (nlist, cps) in [(4096u16, 16u16), (8192, 16), (1024, 8), (u16::MAX, 1)] {
        let ann = ArtifactAnnounce {
            artifact_hash: [1; 32],
            model_version: "granite-embedding-97m-r2".to_string(),
            preprocessing_version: 3,
            nlist,
            clusters_per_shard: cps,
            issued_at: 1000,
        };
        let bytes = ann.encode_unsigned();
        let back = ArtifactAnnounce::decode(&bytes)
            .unwrap_or_else(|e| panic!("decode отказал nlist={nlist}: {e:?}"));
        assert_eq!(back, ann, "round-trip nlist={nlist}");
        assert_eq!(back.encode_unsigned(), bytes, "канон байтов после round-trip");
    }
    // Число читателей кадра в нетестовом коде — grep, результат печатается в логе `E-0028`
    // (ожидание `H-0027`: ноль; `node.rs` относит ArtifactAnnounce к `_ => Ok(Vec::new())`).
}
