//! Оракул `E-0031` (`H-0031`): валидатор манифеста как единственная стена стадии 1.
//!
//! Три пункта, все — против существующего кода, ничего не правится:
//! (1) сетка согласованных троек геометрии и число проходимых `Manifest::check()`;
//! (2) достижима ли ветка потолка `routing.shards > MAX_CERT_SHARDS` (`manifest.rs:858`)
//!     при живой проверке равенства `routing.shards != SHARDS` (`manifest.rs:735`);
//! (3) граница **значения** номера шарда в кредашиале (`cert.rs:90-94`) — `decode` по константе,
//!     а не по данным; пустой список как контроль («покрытие не ограничитель»).
//!
//! Пороги зафиксированы в `lab/experiments/E-0031-manifest-geometry-wall.md` до прогона.

use vecdht_artifact::manifest::{Manifest, ManifestError};
use vecdht_artifact::reference_manifest;
use vecdht_wire::cert::{NodeCert, CERT_VERSION, MAX_CERT_SHARDS};
use vecdht_wire::codec::DecodeError;
use vecdht_wire::constants::{CLUSTERS_PER_SHARD, NLIST, SHARDS};
use vecdht_wire::messages::Role;

/// Согласованная тройка: `nlist = clusters_per_shard * shards`; `None`, если не влезает в `u16`.
fn triple(cps: u16, shards: u16) -> Option<u16> {
    let n = u32::from(cps) * u32::from(shards);
    u16::try_from(n).ok()
}

fn with_geometry(cps: u16, shards: u16) -> Option<Manifest> {
    let nlist = triple(cps, shards)?;
    let mut m = reference_manifest();
    m.routing.nlist = nlist;
    m.routing.clusters_per_shard = cps;
    m.routing.shards = shards;
    Some(m)
}

/// Классификация отказа: равенство константе (по имени поля) или что-то иное.
fn classify(e: &ManifestError) -> String {
    match e {
        ManifestError::CodecMismatch { field, expected, actual } => {
            format!("равенство-константе `{field}` (кодек: {expected}, манифест: {actual})")
        }
        other => format!("иное: {other}"),
    }
}

const CPS: [u16; 6] = [1, 2, 4, 8, 16, 32];
const SHARD_GRID: [u16; 6] = [8, 16, 32, 64, 128, 256];

// ------------------------------------------------------------------ пункт (1)

#[test]
fn only_the_reference_geometry_triple_passes_manifest_check() {
    assert!(reference_manifest().check().is_ok(), "контроль: эталонный манифест не проходит check() — стенд сломан");

    let mut passed: Vec<String> = Vec::new();
    let mut table = String::new();
    let mut checked = 0usize;
    let mut by_first_field: std::collections::BTreeMap<String, usize> = Default::default();

    for &cps in CPS.iter() {
        for &shards in SHARD_GRID.iter() {
            let Some(m) = with_geometry(cps, shards) else { continue };
            checked += 1;
            let label = format!("nlist={} cps={cps} shards={shards}", m.routing.nlist);
            match m.check() {
                Ok(()) => passed.push(label),
                Err(e) => {
                    let why = classify(&e);
                    // поле, названное первым в сообщении — это та проверка, что сработала;
                    // порядок в теле `check()` фиксирован: nlist (725) → cps (728) → shards (735)
                    // → разбиение (738) → … → потолок (858).
                    if let ManifestError::CodecMismatch { field, .. } = &e {
                        *by_first_field.entry((*field).to_string()).or_default() += 1;
                    } else {
                        *by_first_field.entry("не равенство".into()).or_default() += 1;
                    }
                    table.push_str(&format!("  {label} → {why}\n"));
                }
            }
        }
    }

    eprintln!(
        "## пункт (1): пройдёт {}/{} троек; прошли: {:?} ##\n{}",
        passed.len(),
        checked,
        passed,
        table
    );
    eprintln!("## (1а) распределение отвергнувших полей ##");
    for (k, v) in &by_first_field {
        eprintln!("  {k}: {v}");
    }

    // Порог (1): единственная проходимая тройка — эталонная.
    assert_eq!(passed.len(), 1, "валидатор принимает не одну тройку геометрии: {:?}", passed);
    assert!(
        passed[0].contains(&format!("cps={CLUSTERS_PER_SHARD} shards={SHARDS}")),
        "прошла не эталонная тройка: {:?}",
        passed
    );
    // Фальсификатор (г): ни один отказ не должен приходить от проверки разбиения (738).
    assert_eq!(
        *by_first_field.get("не равенство").unwrap_or(&0),
        0,
        "есть отказ, не являющийся равенством константе — валидатор уже проверяет геометрию как данные"
    );
}

// ------------------------------------------------------------------ пункт (2)

#[test]
fn the_shards_ceiling_branch_cannot_be_reached_while_the_equality_lives() {
    // (2-а) сегодня это одно и то же число — поэтому отказ ветки 858 неотличим от отказа 735.
    assert_eq!(
        MAX_CERT_SHARDS, SHARDS as usize,
        "потолок и число шардов разошлись: проверка (2) теряет смысл, переписать запись"
    );

    // (2-б) ни одна проходимая тройка не имеет shards > MAX_CERT_SHARDS: проверка равна
    // `shards == SHARDS`, и если она пройдена, потолок заведомо не нарушен.
    let mut reachable_ceiling = 0usize;
    let mut over_cap_examples = Vec::new();
    for &cps in CPS.iter() {
        for &shards in SHARD_GRID.iter() {
            let Some(m) = with_geometry(cps, shards) else { continue };
            if m.check().is_ok() && u64::from(m.routing.shards) > MAX_CERT_SHARDS as u64 {
                reachable_ceiling += 1;
            }
            if u64::from(m.routing.shards) > MAX_CERT_SHARDS as u64 {
                over_cap_examples.push((cps, shards, classify(&m.check().unwrap_err())));
            }
        }
    }
    eprintln!("## пункт (2): MAX_CERT_SHARDS = {MAX_CERT_SHARDS}, SHARDS = {SHARDS} ##");
    for (cps, shards, why) in &over_cap_examples {
        eprintln!("  cps={cps} shards={shards} (больше потолка) → {why}");
    }
    eprintln!("## (2а) прошедших манифестов с shards > потолка: {reachable_ceiling} ##");
    assert_eq!(reachable_ceiling, 0, "найдён манифест с числом шардов выше потолка");

    // (2-в) различающий случай: nlist остаётся эталонным (1024), а shards перешагивает потолок
    // (cps = 8, shards = 128). Отказ обязан прийти от `clusters_per_shard`, то есть ветка 858
    // не успевает заговорить никогда, пока жива проверка 735.
    let discriminating = with_geometry(8, 128).expect("8 * 128 влезает в u16");
    assert_eq!(discriminating.routing.nlist, NLIST);
    let err = discriminating.check().unwrap_err();
    eprintln!("## (2в) различающий случай nlist={NLIST} cps=8 shards=128 → {} ##", classify(&err));
    match &err {
        ManifestError::CodecMismatch { field, expected, actual } => {
            assert_eq!(*field, "routing.clusters_per_shard", "сработала не та проверка: {field}");
            assert_eq!((*expected, *actual), (CLUSTERS_PER_SHARD as u64, 8));
        }
        other => panic!("ожидалось равенство константе, получено: {other}"),
    }
}

// ------------------------------------------------------------------ пункт (3)

fn cert_with(shards: Vec<u16>) -> NodeCert {
    NodeCert {
        version: CERT_VERSION,
        genesis_hash: [7u8; 32],
        role: Role::IndexNode,
        owner_ed25519: [3u8; 32],
        dht_peer_id: vec![0x9C; 32],
        shards,
        capacity_entries: 10_000,
        valid_from: 100,
        valid_until: 200,
        nonce: [4u8; 16],
        authority_sigs: vec![[6u8; 64]; 1],
    }
}

#[test]
fn credential_shard_numbers_are_bounded_by_the_compiled_constant() {
    // (3-а) значение на единицу выше границы протокола — отказ декодера; длина списка при этом
    // в пределах `MAX_CERT_SHARDS`, так что отказывает именно проверка значения (`cert.rs:92`).
    let at_boundary = cert_with(vec![SHARDS]).encode();
    match NodeCert::decode(&at_boundary) {
        Ok(_) => panic!("decode принял шард {SHARDS} — кредашиалы переносят новую геометрию сами"),
        Err(DecodeError::BadEnum { value, what, .. }) => {
            eprintln!("## пункт (3): shard={SHARDS} отвергнут: BadEnum {{ value: {value}, what: `{what}` }} ##");
            assert_eq!(value, u64::from(SHARDS));
            assert_eq!(what, "shard");
        }
        Err(other) => panic!("ожидался BadEnum по значению шарда, получено {other:?}"),
    }

    // (3-б) последний легальный номер проходит: граница — `shard < SHARDS`, а не `<=`.
    let last_legal = cert_with(vec![SHARDS - 1]).encode();
    let back = match NodeCert::decode(&last_legal) {
        Ok(c) => c,
        Err(e) => panic!("шард {} отвергнут, хотя он легален: {e:?}", SHARDS - 1),
    };
    assert!(back.covers_shard(SHARDS - 1));
    assert!(!back.covers_shard(SHARDS), "кредашиал с последним легальным шардом покрывает нелегальный");

    // (3-в) контроль «покрытие не ограничитель»: пустой список покрывает любой номер, включая
    // тот, который декодер не пропустил бы явным значением. Это не путь к росту геометрии
    // (номера шардов в кадрах по-прежнему проверяются), но фильтр ростера такой кредашиал выключает.
    let wild = cert_with(Vec::new());
    assert!(NodeCert::decode(&wild.encode()).is_ok(), "пустой список шардов не прошёл decode");
    assert!(wild.covers_shard(60_000), "wildcard не покрывает произвольный номер");
    eprintln!("## (3в) пустой список: covers_shard(SHARDS) = {}, covers_shard(60000) = true ##", wild.covers_shard(SHARDS));
}
