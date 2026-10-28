//! `index …` — один шард на диске, без сети (§8, §9.2, §10).
//!
//! Это не «мини-узел», а инструмент над конкретным состоянием индекса: создать каталог шарда,
//! загнать в него записи, посмотреть, что он отдаёт на поиск, и проверить барьер снапшота. Всё,
//! что здесь происходит, проходит через тот же `ShardStore`, что и на боевом узле, — включая
//! WAL, fsync и отказ публиковать без подтверждённой эпизоды (§9.2).
//!
//! Вход для `add` — файл конкатенированных 424-байтовых `IndexEntry` (§8.2), а не JSON: отдельного
//! «формата хранения» в v8 нет намеренно, и CLI обязан уметь скормить индексу ровно те байты,
//! которые в нём лежат и которые подписываются как `InsertOp`. JSON-обёртка добавила бы второй
//! формат, который однажды разошёлся бы с первым.
//!
//! Экспирация и «сейчас» берутся из `--time-mark` / `--gc`, то есть из данных, а не из часов
//! машины (§9.6): два оператора на разных машинах обязаны получать один и тот же ответ поиска.

use std::path::{Path, PathBuf};

use vecdht_crypto::quant::{clusters_of_shard, shard_of_cluster, similarity_from_d2};
use vecdht_index::{IndexEntry, ShardStore, INDEX_ENTRY_BYTES, SNAPSHOT_OPS};
use vecdht_wire::messages::{ClassFilter, DirFilter, IntentDir, SLOT_ATTR_PAID};
use vecdht_wire::{CLUSTERS_PER_SHARD, DIM, NLIST, SHARDS};

use crate::args::Parsed;
use crate::{CliError, fail, vector_hex};

pub const CMD_CREATE: &str = "index create";
pub const CMD_ADD: &str = "index add";
pub const CMD_SEARCH: &str = "index search";
pub const CMD_STATS: &str = "index stats";
pub const CMD_SNAPSHOT: &str = "index snapshot";

pub const FLAGS_CREATE: &[&str] = &["dir", "shard", "epoch"];
pub const FLAGS_ADD: &[&str] =
    &["dir", "shard", "entries", "epoch", "time-mark", "gc", "limit", "class", "intent-dir"];
pub const FLAGS_SEARCH: &[&str] = &[
    "dir", "shard", "vec", "clusters", "artifact", "nprobe", "top-k", "show-entries", "class",
    "intent-dir",
];
pub const FLAGS_STATS: &[&str] = &["dir", "shard"];
pub const FLAGS_SNAPSHOT: &[&str] = &["dir", "shard", "epoch"];

pub const HELP_CREATE: &str = "\
index create — каталог шарда и подтверждение эпизоды на диске (§9.2)

  --dir DIR      каталог; пустой каталог — это новый шард
  --shard N      0..63 (обязателен: шард зашит в MANIFEST и в проверку кластеров)
  --epoch N      эпизода lease. Без неё шард создан, но publish откажет (NeedLease):
                 «стою на эпизоде E» — решение держателя lease, а не побочный эффект
                 создания каталога (§9.2)";

pub const HELP_ADD: &str = "\
index add — записи через WAL (§10.1: append → fsync → apply)

  --entries FILE   конкатенация 424-байтовых IndexEntry (§8.2), без заголовка и без JSON
  --epoch N        подтвердить эпизоду перед записью, иначе publish будет отвергнут
  --time-mark N    применённый TimeMark-бакет после пачки (§9.6)
  --gc N           GcTick в бакет N: снимает всё, у чего published+ttl <= N
  --limit N        остановиться после N записей
  --class free|paid         класс записи в байт объявления (§5.5); без флага — 0 (free)
  --intent-dir unspecified|buy|sell  направление автора в тот же байт; без флага — 0";

pub const HELP_SEARCH: &str = "\
index search — поиск по int8-вектору внутри одного шарда

  --vec HEX768     запрос: 384 знаковых координат по сетке i8/127 (§6.3)
  --clusters LIST  явные кластеры через запятую; иначе --artifact+nprobe; иначе все 16 кластеров
                   шарда — то есть полный скан одного шарда
  --artifact DIR   глобальные центроиды: из них берётся топ-nprobe (§7.5)
  --nprobe N       сколько глобальных кластеров зондировать (нужен --artifact)
  --top-k N        сколько хитов печатать; по умолчанию 10
  --show-entries   напечатать владельца, бакет публикации, TTL и дедлайн каждого хита
  --class any|free|paid      фильтр класса по байту объявления (§12.7); по умолчанию any
  --intent-dir any|unspecified|buy|sell  фильтр направления автора; по умолчанию any
                   (--dir остаётся каталогом шарда: для направления имя --intent-dir)";

pub const HELP_STATS: &str = "\
index stats — состояние шарда: seq, слоты, эпоха, снапшот, память (§8.2, §10.3)

  достаточно --dir и --shard";

pub const HELP_SNAPSHOT: &str = "\
index snapshot — принудительный барьер §10.4 и усечение перекрытых сегментов WAL

  --dir DIR --shard N [--epoch N]";

struct Opened {
    store: ShardStore,
    dir: PathBuf,
    shard: u16,
}

fn dir_and_shard(p: &Parsed, cmd: &'static str) -> Result<(String, u16), CliError> {
    let dir = p.required(cmd, "dir")?;
    let raw = p.required(cmd, "shard")?;
    let shard: u16 = crate::args::parse_num(cmd, "shard", &raw).map_err(CliError::Arg)?;
    if shard >= SHARDS {
        return Err(CliError::Fail(format!(
            "--shard {shard}: в v8 ровно {SHARDS} шардов; чужой номер открылся бы пустым индексом, \
             который выглядит как «записей нет», а не как ошибка оператора (§7.1)"
        )));
    }
    Ok((dir, shard))
}

fn open(p: &Parsed, cmd: &'static str) -> Result<Opened, CliError> {
    let (dir, shard) = dir_and_shard(p, cmd)?;
    let path = Path::new(&dir);
    let store = ShardStore::open(path, shard).map_err(|e| fail("открытие шарда", e))?;
    Ok(Opened { store, dir: path.to_path_buf(), shard })
}

/// Подтверждение эпизоды по флагу (§9.2). Печатает, был ли это новый раунд: из `true` следует
/// «переподписать ShardMembership», и молчать об этом нельзя.
fn maybe_grant(
    s: &mut ShardStore,
    p: &Parsed,
    cmd: &'static str,
    out: &mut String,
) -> Result<(), CliError> {
    let Some(raw) = p.value(cmd, "epoch")? else { return Ok(()) };
    let epoch: u64 = crate::args::parse_num(cmd, "epoch", &raw).map_err(CliError::Arg)?;
    let fresh = s.grant_epoch(epoch).map_err(|e| fail("выдача эпизоды", e))?;
    out.push_str(&format!(
        "эпизода {epoch}: {} (max_epoch_served {})\n",
        if fresh {
            "новый раунд — ShardMembership обязан быть переподписан (§9.8)"
        } else {
            "возобновлена, раунда подписей не нужно"
        },
        s.max_epoch_served
    ));
    Ok(())
}

/// Класс из флага. Без флага — `Any`: для `search` это прежний ответ, для `add` — нулевой бит.
/// `any` у `add` не принимается: объявление записи не бывает «любым», это отсутствие флага.
fn parse_class(p: &Parsed, cmd: &'static str, search: bool) -> Result<ClassFilter, CliError> {
    let Some(raw) = p.value(cmd, "class")? else { return Ok(ClassFilter::Any) };
    match raw.as_str() {
        "free" => Ok(ClassFilter::OnlyFree),
        "paid" => Ok(ClassFilter::OnlyPaid),
        "any" if search => Ok(ClassFilter::Any),
        _ => Err(CliError::Fail(if search {
            format!("--class {raw}: допустимо any|free|paid; имя класса — часть протокола (§5.5)")
        } else {
            format!(
                "--class {raw}: у add допустимо free|paid; `any` — это отсутствие флага, а не \
                 значение: запись обязана объявить свой класс (§5.5)"
            )
        })),
    }
}

/// Направление из флага, уже в фильтровой форме. `unspecified` у `add` — нулевые биты.
fn parse_dir(p: &Parsed, cmd: &'static str, search: bool) -> Result<DirFilter, CliError> {
    let Some(raw) = p.value(cmd, "intent-dir")? else { return Ok(DirFilter::Any) };
    match raw.as_str() {
        "buy" => Ok(DirFilter::Buy),
        "sell" => Ok(DirFilter::Sell),
        "unspecified" => Ok(DirFilter::Unspecified),
        "any" if search => Ok(DirFilter::Any),
        _ => Err(CliError::Fail(if search {
            format!("--intent-dir {raw}: допустимо any|unspecified|buy|sell (§12.7)")
        } else {
            format!(
                "--intent-dir {raw}: у add допустимо unspecified|buy|sell; `any` — это отсутствие \
                 флага, а не направление автора"
            )
        })),
    }
}

/// Фильтровая форма → биты объявления. `Any` и `Unspecified` дают 0, как `IntentDir::Unspecified`
/// на узле: у фильтра свой код (`Unspecified = 3`), и писать его в `slot_attr` значило бы объявить
/// направление, которого нет.
fn dir_for_attr(dir: DirFilter) -> IntentDir {
    match dir {
        DirFilter::Buy => IntentDir::Buy,
        DirFilter::Sell => IntentDir::Sell,
        DirFilter::Any | DirFilter::Unspecified => IntentDir::Unspecified,
    }
}

fn dir_label(dir: IntentDir) -> &'static str {
    match dir {
        IntentDir::Buy => "buy",
        IntentDir::Sell => "sell",
        IntentDir::Unspecified => "unspecified",
    }
}

/// Обратный разбор для `--show-entries`: биты `slot_attr` — это направление `IntentDir` и бит
/// `paid` (§5.5), а не коды фильтра, поэтому `3` здесь означало бы испорченный байт.
fn attr_label(attr: u8) -> String {
    let dir = match attr & 0b11 {
        0 => "unspecified",
        1 => "buy",
        2 => "sell",
        _ => "неизвестно",
    };
    format!("класс {}, направление {dir}", if attr & SLOT_ATTR_PAID != 0 { "paid" } else { "free" })
}

pub fn exec_create(p: &Parsed, out: &mut String) -> Result<(), CliError> {
    let (dir, shard) = dir_and_shard(p, CMD_CREATE)?;
    let path = Path::new(&dir);
    if path.exists() && std::fs::read_dir(path).map_err(|e| fail("чтение каталога", e))?.next().is_some() {
        return Err(CliError::Fail(format!(
            "каталог `{dir}` непуст: index create не перематывает состояние шарда. существующий \
             индекс открывается теми же add/search/stats, а стирать историю — решение оператора"
        )));
    }
    let epoch = p.num::<u64>(CMD_CREATE, "epoch")?;
    let s = match epoch {
        Some(e) => ShardStore::create(path, shard, e).map_err(|err| fail("создание шарда", err))?,
        // Без флага — `open`, а не `create(…, 0)`: нулевая эпизода, записанная молча, означала бы,
        // что CLI сам выдал себе lease (§9.2).
        None => ShardStore::open(path, shard).map_err(|e2| fail("создание шарда", e2))?,
    };
    out.push_str(&format!(
        "шард {shard} создан в {dir}: epoch {}, lease подтверждён = {}, записей {}\n",
        s.epoch,
        !s.need_lease(),
        s.len()
    ));
    if s.need_lease() {
        out.push_str(
            "ВНИМАНИЕ: без --epoch шард открыт, но publish будет отвергнут (NeedLease, §9.2).\n",
        );
    }
    print_stats_fields(&s, out);
    s.shutdown().map_err(|e| fail("штатное закрытие", e))?;
    Ok(())
}

pub fn exec_add(p: &Parsed, out: &mut String) -> Result<(), CliError> {
    let mut o = open(p, CMD_ADD)?;
    maybe_grant(&mut o.store, p, CMD_ADD, out)?;
    let file = p.required(CMD_ADD, "entries")?;
    let bytes = std::fs::read(&file).map_err(|e| fail("чтение файла записей", e))?;
    let entries = split_entries(&bytes)?;
    if entries.is_empty() {
        return Err(CliError::Fail(format!(
            "в `{file}` ни одной 424-байтовой записи: пустой вход ничего не публикует, и молчаливый \
             «успех» здесь означал бы, что оператор перепутал файл"
        )));
    }
    let limit = p.num_or::<usize>(CMD_ADD, "limit", entries.len())?;
    if limit == 0 {
        return Err(CliError::Fail("--limit 0 не имеет смысла: публиковать нечего".into()));
    }
    let take = limit.min(entries.len());
    // Объявление едет в том же WAL-фрейме, что и запись (§5.5): отдельного «параметра вызова»
    // здесь нет, иначе после рестарта фильтр поиска видел бы не то, что публиковали.
    let class = parse_class(p, CMD_ADD, false)?;
    let dir = parse_dir(p, CMD_ADD, false)?;
    let slot_attr = dir_for_attr(dir).as_u8()
        | if class == ClassFilter::OnlyPaid { SLOT_ATTR_PAID } else { 0 };
    if p.value(CMD_ADD, "class")?.is_some() || p.value(CMD_ADD, "intent-dir")?.is_some() {
        out.push_str(&format!(
            "объявление записей: класс {}, направление {} → slot_attr {slot_attr:#04x}\n",
            match class {
                ClassFilter::OnlyPaid => "paid",
                _ => "free",
            },
            dir_label(dir_for_attr(dir))
        ));
    }
    let mut published = 0usize;
    for (n, e) in entries.iter().take(take).enumerate() {
        let slot = o.store.publish_with_attr(*e, slot_attr).map_err(|err| {
            fail(
                format!(
                    "запись №{} (кластер {}, owner {}…)",
                    n + 1,
                    e.cluster_id,
                    &hex::encode(e.owner_ed25519)[..16]
                ),
                err,
            )
        })?;
        published += 1;
        if take <= 8 {
            out.push_str(&format!("  запись {} → slot {slot}\n", n + 1));
        }
    }
    // Отдельные опсы времени применяются тем же путём, что и на узле: это WAL-фреймы, а не
    // «параметр вызова» (§9.6), иначе локальная проверка экспирации не имела бы отношения к сети.
    if let Some(bucket) = p.num::<u32>(CMD_ADD, "time-mark")? {
        o.store.stage_time_mark(bucket).map_err(|e| fail("TimeMark", e))?;
        o.store.commit().map_err(|e| fail("commit TimeMark", e))?;
        out.push_str(&format!("TimeMark применён: бакет {bucket}\n"));
    }
    if let Some(bucket) = p.num::<u32>(CMD_ADD, "gc")? {
        let before = o.store.len();
        o.store.stage_gc_tick(bucket).map_err(|e| fail("GcTick", e))?;
        o.store.commit().map_err(|e| fail("commit GcTick", e))?;
        out.push_str(&format!("GcTick в бакет {bucket}: живых было {before}, стало {}\n", o.store.len()));
    }
    out.push_str(&format!(
        "опубликовано {published} из {} записей файла; applied_seq {}, живых {}\n",
        entries.len(),
        o.store.applied_seq,
        o.store.len()
    ));
    if take < entries.len() {
        out.push_str(&format!("остальное ({}) не читалось: сработал --limit\n", entries.len() - take));
    }
    match o.store.maybe_snapshot() {
        Ok(true) => out.push_str(&format!("сработал автоматический снапшот (дельта ≥ {SNAPSHOT_OPS})\n")),
        Ok(false) => {}
        Err(e) => out.push_str(&format!(
            "ВНИМАНИЕ: автоматический снапшот не состоялся: {e} — записи при этом durable\n"
        )),
    }
    print_stats_fields(&o.store, out);
    let dir = o.dir.clone();
    o.store.shutdown().map_err(|e| fail("штатное закрытие", e))?;
    out.push_str(&format!("WAL и MANIFEST закрыты в `{}`\n", dir.display()));
    Ok(())
}

pub fn exec_search(p: &Parsed, out: &mut String) -> Result<(), CliError> {
    let o = open(p, CMD_SEARCH)?;
    let raw = p.required(CMD_SEARCH, "vec")?;
    let q: [i8; DIM] = crate::args::parse_hex::<DIM>(CMD_SEARCH, "vec", &raw)
        .map(|b| b.map(|v| v as i8))
        .map_err(CliError::Arg)?;
    let top_k = p.num_or::<usize>(CMD_SEARCH, "top-k", 10)?;
    if top_k == 0 {
        return Err(CliError::Fail(
            "--top-k 0: контракт §8.4 отдаёт ровно top_k хитов, и нулевой запрос — это не «все», \
             а гарантированно пустой ответ".into(),
        ));
    }
    let class = parse_class(p, CMD_SEARCH, true)?;
    let dir = parse_dir(p, CMD_SEARCH, true)?;
    let filtered = class != ClassFilter::Any || dir != DirFilter::Any;
    let (clusters, how) = clusters_to_scan(p, &o, &q, out)?;
    out.push_str(&format!(
        "шард {} ищет в {} кластерах ({}): {:?}\n",
        o.shard,
        clusters.len(),
        how,
        clusters
    ));
    if filtered {
        out.push_str(&format!(
            "фильтр по объявлению (§12.7): класс {}, направление {}\n",
            match class {
                ClassFilter::OnlyPaid => "paid",
                ClassFilter::OnlyFree => "free",
                ClassFilter::Any => "any",
            },
            match dir {
                DirFilter::Buy => "buy",
                DirFilter::Sell => "sell",
                DirFilter::Unspecified => "unspecified",
                DirFilter::Any => "any",
            }
        ));
    }
    out.push_str(&format!("vec_q {}\n", vector_hex(&q)));
    out.push_str(&format!("TimeMark индекса: бакет {}\n", o.store.time_mark_bucket));
    if clusters.is_empty() {
        out.push_str(
            "хитов 0: ни один кластер этого шарда не попал в список зондирования — при nprobe < \
             nlist это нормальный случай, а не пустой индекс (§7.5).\n",
        );
        return Ok(());
    }
    // `Any/Any` — ровно `search` (§12.7), поэтому один путь и для фильтрованного, и для
    // прежнего ответа: отдельная ветка разошлась бы с ним молча.
    let hits = o.store.search_filtered(&q, &clusters, top_k, class, dir);
    out.push_str(&format!("хитов {} (top_k {top_k})\n", hits.len()));
    let show = p.bool_flag(CMD_SEARCH, "show-entries")?;
    for (d2, slot) in &hits {
        let e = o.store.index.entry(*slot).ok_or_else(|| {
            CliError::Fail(format!("хит по slot {slot}, а записи там нет: инвариант IVF нарушен (§8.3)"))
        })?;
        out.push_str(&format!(
            "  slot {slot:<6} l2_sq {d2:<8} сходство {:.4}\n",
            similarity_from_d2(*d2)
        ));
        if show {
            let attr = o.store.index.slot_attr(*slot).unwrap_or(0);
            out.push_str(&format!(
                "    owner {}… cluster {} published {} ttl {} дедлайн {}; объявление: {}\n",
                &hex::encode(e.owner_ed25519)[..16],
                e.cluster_id,
                e.published_bucket,
                e.ttl_buckets,
                e.deadline_bucket(),
                attr_label(attr)
            ));
        }
    }
    // Оракул для одного шарда: полный скан дешевле ANN по затратам и уже является определением
    // правильного ответа (§18.1, часть ii). Расхождение с ним — не «так и должно быть», а то, что
    // измеряется как потеря recall, поэтому здесь оно печатается числами.
    if clusters.len() < CLUSTERS_PER_SHARD as usize {
        let full = o.store.search_filtered(
            &q,
            &clusters_of_shard(o.shard),
            top_k,
            class,
            dir,
        );
        let same = full == hits;
        let shared = full.iter().filter(|h| hits.contains(h)).count();
        out.push_str(&format!(
            "полный скан шарда: {} хитов, совпало {shared} из {}, тот же результат: {}\n",
            full.len(),
            hits.len(),
            same
        ));
    }
    Ok(())
}

pub fn exec_stats(p: &Parsed, out: &mut String) -> Result<(), CliError> {
    let o = open(p, CMD_STATS)?;
    print_stats_fields(&o.store, out);
    let mf = o.store.manifest();
    out.push_str(&format!(
        "MANIFEST: snapshot_seq {} oldest_wal_needed {} next_slot {} applied_seq {}\n",
        mf.snapshot_seq, mf.oldest_wal_needed, mf.next_slot, mf.applied_seq
    ));
    let mut sizes: Vec<(usize, u16)> = clusters_of_shard(o.shard)
        .into_iter()
        .map(|c| (o.store.index.cluster_len(c), c))
        .collect();
    sizes.sort_unstable_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
    out.push_str(&format!(
        "кластеры шарда: {} слотов в {}, максимум {}, минимум {}\n",
        sizes.iter().map(|(n, _)| n).sum::<usize>(),
        CLUSTERS_PER_SHARD,
        sizes.first().map(|(n, _)| *n).unwrap_or(0),
        sizes.last().map(|(n, _)| *n).unwrap_or(0)
    ));
    out.push_str(&format!("  топ-5 {:?}\n", &sizes[..sizes.len().min(5)]));
    // Инварианты проверяются всегда: stats, который их не смотрит, показывает испорченное
    // состояние и называет его нормой.
    match o.store.index.check_invariants() {
        Ok(()) => out.push_str("инварианты IVF (§8.3): выполнены\n"),
        Err(e) => out.push_str(&format!("ВНИМАНИЕ: инварианты нарушены: {e}\n")),
    }
    match o.store.tail_corruption.as_deref() {
        None => out.push_str("хвост WAL цел\n"),
        Some(m) => {
            out.push_str(&format!("хвост WAL оборван: {m} (опсы до него применены, §10.5)\n"))
        }
    }
    out.push_str(&format!("применено при открытии: {} опсов хвоста\n", o.store.replayed));
    Ok(())
}

pub fn exec_snapshot(p: &Parsed, out: &mut String) -> Result<(), CliError> {
    let mut o = open(p, CMD_SNAPSHOT)?;
    maybe_grant(&mut o.store, p, CMD_SNAPSHOT, out)?;
    if o.store.staged_len() > 0 {
        // Барьер §10.4 начинается с fsync WAL: staged опсы обязаны быть в журнале до снимка,
        // иначе снапшот «съест» запись, которой в нём нет.
        o.store.commit().map_err(|e| fail("commit перед барьером", e))?;
    }
    let delta = o.store.applied_seq.saturating_sub(o.store.last_snapshot_seq);
    let written = o.store.flush_snapshot().map_err(|e| fail("барьер снапшота", e))?;
    let applied = o.store.applied_seq;
    let shard = o.shard;
    let dir = o.dir.clone();
    out.push_str(&format!(
        "снапшот на applied_seq {applied}: {} записей индекса, дельта до барьера {delta} \
         (автоматический триггер — при {SNAPSHOT_OPS})\n",
        written
    ));
    // Имена файлов берёт у самого индекса: CLI, который пересобрал бы `snap.<seq>.log` своим
    // `format!`, разошёлся бы с реальным барьером при первом же изменении раскладки (§10.4).
    let name = vecdht_index::snapshot::snapshot_name(applied);
    let path = dir.join(&name);
    let size = std::fs::metadata(&path).map_err(|e| fail("проверка файла снапшота", e))?.len();
    out.push_str(&format!(
        "файл {} размером {size} байт, partial не осталось: {}\n",
        name,
        !dir.join(vecdht_index::snapshot::partial_name(applied)).exists()
    ));
    print_stats_fields(&o.store, out);
    o.store.shutdown().map_err(|e| fail("штатное закрытие", e))?;
    // Самое полезное для оператора: открытие того же каталога — это recovery, и он обязан дать то
    // же состояние, иначе барьер что-то потерял (§10.5).
    let back = ShardStore::open(&dir, shard).map_err(|e| fail("открытие после барьера", e))?;
    out.push_str(&format!(
        "recovery: записей {}, applied_seq {} — совпало: {}\n",
        back.len(),
        back.applied_seq,
        back.applied_seq == applied
    ));
    Ok(())
}

fn print_stats_fields(s: &ShardStore, out: &mut String) {
    let mem = s.index.mem_bytes();
    out.push_str(&format!(
        "шард {}: живых {}, tombstones {}, next_slot {}, applied_seq {}, next_seq {}\n",
        s.shard,
        s.len(),
        s.index.tombstones,
        s.index.next_slot(),
        s.applied_seq,
        s.next_seq
    ));
    out.push_str(&format!(
        "эпизода: epoch {}, max_epoch_served {}, lease подтверждён = {}, serving {}\n",
        s.epoch,
        s.max_epoch_served,
        !s.need_lease(),
        s.serving_epoch().map(|e| e.to_string()).unwrap_or_else(|| "нет".into())
    ));
    out.push_str(&format!(
        "время: TimeMark-бакет {}, снапшот на seq {}, до автоматического триггера ещё {}\n",
        s.time_mark_bucket,
        s.last_snapshot_seq,
        SNAPSHOT_OPS.saturating_sub(s.applied_seq.saturating_sub(s.last_snapshot_seq))
    ));
    out.push_str(&format!(
        "память (§8.2): арена {} + списки {} + owner {} + bitmap {} = {} байт, {:.1} Б на запись\n",
        mem.arena,
        mem.lists,
        mem.owners,
        mem.bitmap,
        mem.total(),
        mem.per_entry(s.len())
    ));
}

/// Нарезка файла на записи. Кратность проверяется до первой публикации, а не «в цикле»: половину
/// записи применить нельзя, а молча отбросить хвост значило бы потерять запись без единой строки
/// в выводе.
fn split_entries(bytes: &[u8]) -> Result<Vec<IndexEntry>, CliError> {
    if bytes.len() % INDEX_ENTRY_BYTES != 0 {
        return Err(CliError::Fail(format!(
            "размер файла {} не кратен {}: лишними оказались {} байт. IndexEntry — это ровно {} \
             байт (§8.2), и неполную запись публиковать нельзя",
            bytes.len(),
            INDEX_ENTRY_BYTES,
            bytes.len() % INDEX_ENTRY_BYTES,
            INDEX_ENTRY_BYTES
        )));
    }
    let mut out = Vec::with_capacity(bytes.len() / INDEX_ENTRY_BYTES);
    for (n, chunk) in bytes.chunks_exact(INDEX_ENTRY_BYTES).enumerate() {
        out.push(
            IndexEntry::from_bytes(chunk)
                .map_err(|err| fail(format!("запись №{}", n + 1), err))?,
        );
    }
    Ok(out)
}

/// Откуда берётся список кластеров — три варианта. Источник печатается, потому что пустой
/// результат из-за неверного списка выглядит ровно как пустой индекс.
fn clusters_to_scan(
    p: &Parsed,
    o: &Opened,
    q: &[i8; DIM],
    out: &mut String,
) -> Result<(Vec<u16>, &'static str), CliError> {
    if let Some(list) = p.value(CMD_SEARCH, "clusters")? {
        let mut clusters = Vec::new();
        for part in list.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            let c: u16 = crate::args::parse_num(CMD_SEARCH, "clusters", part).map_err(CliError::Arg)?;
            if c >= NLIST {
                return Err(CliError::Fail(format!(
                    "кластер {c}: в v8 {NLIST} кластеров (0..{NLIST}), чужой номер означал бы \
                     «искать в списке, которого нет» (§7.1)"
                )));
            }
            clusters.push(c);
        }
        if clusters.is_empty() {
            return Err(CliError::Fail(
                "--clusters обязан перечислять хотя бы один кластер: пустой список — это не \
                 «полный скан», а гарантированно пустой ответ".into(),
            ));
        }
        let foreign: Vec<u16> =
            clusters.iter().copied().filter(|c| shard_of_cluster(*c) != o.shard).collect();
        if !foreign.is_empty() {
            return Err(CliError::Fail(format!(
                "кластеры {foreign:?} принадлежат не шарду {}: записей там быть не может, и поиск \
                 по ним врал бы пустотой (§7.4)",
                o.shard
            )));
        }
        clusters.sort_unstable();
        clusters.dedup();
        return Ok((clusters, "из --clusters"));
    }
    if let Some(dir) = p.value(CMD_SEARCH, "artifact")? {
        let a = vecdht_artifact::Artifact::load(Path::new(&dir))
            .map_err(|e| fail("чтение артефакта", e))?;
        let nprobe = p.num_or::<usize>(
            CMD_SEARCH,
            "nprobe",
            usize::from(a.manifest.routing.nprobe_default),
        )?;
        if nprobe == 0 || nprobe > usize::from(a.manifest.routing.nlist) {
            return Err(CliError::Fail(format!(
                "--nprobe {nprobe}: вне 1..nlist (§7.5)"
            )));
        }
        let top = a.centroids.top(q, nprobe);
        out.push_str(&format!(
            "глобальный топ-{nprobe} по артефакту {}: {:?}\n",
            a.manifest.model_version,
            top
        ));
        let mine: Vec<u16> = top.into_iter().filter(|c| shard_of_cluster(*c) == o.shard).collect();
        return Ok((mine, "из --artifact+nprobe"));
    }
    Ok((clusters_of_shard(o.shard), "полный список кластеров шарда"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use vecdht_index::StoreError;

    fn entry(owner: u8, cluster: u16, published: u32, ttl: u16) -> IndexEntry {
        IndexEntry {
            owner_ed25519: [owner; 32],
            vec_q: [(owner as i8) % 7; DIM],
            cluster_id: cluster,
            published_bucket: published,
            ttl_buckets: ttl,
        }
    }

    fn parse(cmd: &str, args: &[&str]) -> Parsed {
        let mut argv: Vec<&str> = vec!["index", cmd];
        argv.extend_from_slice(args);
        Parsed::parse(&argv[1..]).unwrap()
    }

    #[test]
    fn a_file_is_cut_into_exact_records() {
        let mut bytes = entry(1, 0, 0, 10).to_bytes();
        bytes.extend_from_slice(&entry(2, 1, 0, 10).to_bytes());
        assert_eq!(split_entries(&bytes).unwrap().len(), 2);
        bytes.push(0);
        let err = split_entries(&bytes).unwrap_err().to_string();
        assert!(err.contains("не кратен"), "{err}");
        assert!(err.contains("424"), "{err}");
    }

    #[test]
    fn create_then_add_then_search_reads_back_what_was_published() {
        let d = vecdht_index::testing::dir("cli-index-roundtrip");
        let ds = d.display().to_string();
        let mut out = String::new();
        exec_create(&parse("create", &["--dir", &ds, "--shard", "3"]), &mut out).unwrap();
        assert!(out.contains("NeedLease"), "без --epoch шард не обязан обслуживать: {out}");

        // Кластеры шарда 3 — это 48..63 (§7.1), записи кладём только в свои.
        let mut bytes = Vec::new();
        for n in 1..6u8 {
            bytes.extend_from_slice(&entry(n, 48 + u16::from(n), 10, 1000).to_bytes());
        }
        let file = d.join("entries.bin");
        std::fs::write(&file, &bytes).unwrap();
        let fs = file.display().to_string();
        let mut out = String::new();
        exec_add(
            &parse(
                "add",
                &[
                    "--dir", &ds, "--shard", "3", "--entries", &fs, "--epoch", "1",
                    "--time-mark", "12",
                ],
            ),
            &mut out,
        )
        .unwrap();
        assert!(out.contains("опубликовано 5"), "{out}");
        assert!(out.contains("новый раунд"), "{out}");

        let mut out = String::new();
        exec_stats(&parse("stats", &["--dir", &ds, "--shard", "3"]), &mut out).unwrap();
        assert!(out.contains("инварианты IVF (§8.3): выполнены"), "{out}");
        assert!(out.contains("кластеры шарда: 5 слотов в 16"), "{out}");

        let q = vector_hex(&[3i8; DIM]);
        let mut out = String::new();
        exec_search(
            &parse(
                "search",
                &["--dir", &ds, "--shard", "3", "--vec", &q, "--clusters", "49,50,51", "--show-entries"],
            ),
            &mut out,
        )
        .unwrap();
        assert!(out.contains("хитов 3"), "{out}");
        assert!(out.contains("дедлайн 1010"), "{out}");

        // Та же пачка после GcTick, который снимает всё: published 10 + ttl 1000 ≤ 1011.
        let mut out = String::new();
        exec_add(
            &parse("add", &["--dir", &ds, "--shard", "3", "--entries", &fs, "--gc", "1011"]),
            &mut out,
        )
        .unwrap();
        assert!(out.contains("стало 0"), "{out}");
        vecdht_index::testing::remove(&d);
    }

    #[test]
    fn publishing_into_a_foreign_cluster_is_refused_not_silently_dropped() {
        let d = vecdht_index::testing::dir("cli-index-foreign");
        let ds = d.display().to_string();
        let mut out = String::new();
        exec_create(&parse("create", &["--dir", &ds, "--shard", "0", "--epoch", "1"]), &mut out)
            .unwrap();
        let mut bytes = entry(1, 0, 0, 10).to_bytes();
        // Кластер 20 — это шард 1 (§7.1), в индексе шарда 0 его быть не может.
        bytes.extend_from_slice(&entry(2, 20, 0, 10).to_bytes());
        let file = d.join("entries.bin");
        std::fs::write(&file, &bytes).unwrap();
        let fs = file.display().to_string();
        let err = exec_add(
            &parse("add", &["--dir", &ds, "--shard", "0", "--entries", &fs]),
            &mut String::new(),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("запись №2"), "{err}");
        vecdht_index::testing::remove(&d);
    }

    #[test]
    fn a_shard_outside_the_geometry_is_rejected_before_io() {
        for bad in ["64", "1024"] {
            for cmd in ["stats", "snapshot", "search"] {
                let args = ["--dir", ".", "--shard", bad];
                let p = parse(cmd, &args);
                let res = match cmd {
                    "stats" => exec_stats(&p, &mut String::new()),
                    "snapshot" => exec_snapshot(&p, &mut String::new()),
                    _ => exec_search(&p, &mut String::new()),
                };
                let err = res.unwrap_err().to_string();
                assert!(err.contains("ровно 64 шардов"), "{cmd}: {err}");
            }
        }
    }

    #[test]
    fn clusters_of_another_shard_never_produce_an_empty_answer() {
        let d = vecdht_index::testing::dir("cli-index-clusters");
        let ds = d.display().to_string();
        let mut out = String::new();
        exec_create(&parse("create", &["--dir", &ds, "--shard", "0", "--epoch", "1"]), &mut out)
            .unwrap();
        let q = vector_hex(&[0i8; DIM]);
        // Кластер 17 принадлежит шарду 1: поиск по нему на нулевом шарде — ошибка оператора, а не
        // пустой ответ.
        let err = exec_search(
            &parse("search", &["--dir", &ds, "--shard", "0", "--vec", &q, "--clusters", "17"]),
            &mut String::new(),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("принадлежат не шарду"), "{err}");
        vecdht_index::testing::remove(&d);
    }

    #[test]
    fn snapshot_barrier_survives_reopening_the_directory() {
        let d = vecdht_index::testing::dir("cli-index-snapshot");
        let ds = d.display().to_string();
        let mut out = String::new();
        exec_create(&parse("create", &["--dir", &ds, "--shard", "2", "--epoch", "5"]), &mut out)
            .unwrap();
        let mut bytes = Vec::new();
        // Кластеры шарда 2 — 32..47 (§7.1): чужие кластеры индекс отверг бы, и тест проверял бы
        // отказ вместо барьера.
        for n in 1..30u8 {
            bytes.extend_from_slice(&entry(n, 32 + u16::from(n % 16), 1, 5000).to_bytes());
        }
        let file = d.join("entries.bin");
        std::fs::write(&file, &bytes).unwrap();
        let fs = file.display().to_string();
        let mut out = String::new();
        exec_add(&parse("add", &["--dir", &ds, "--shard", "2", "--entries", &fs]), &mut out).unwrap();
        assert!(
            !out.contains("→ slot"),
            "пачка из 29 записей не обязана печататься поштучно: {out}"
        );
        let mut out = String::new();
        exec_snapshot(&parse("snapshot", &["--dir", &ds, "--shard", "2"]), &mut out).unwrap();
        assert!(out.contains("recovery: записей 29"), "{out}");
        assert!(out.contains("совпало: true"), "{out}");
        vecdht_index::testing::remove(&d);
    }

    #[test]
    fn the_store_refuses_to_publish_without_a_lease_on_its_own() {
        // CLI обязан показывать отказ, которого не придумал: сам `ShardStore` говорит NeedLease.
        let d = vecdht_index::testing::dir("cli-index-lease");
        let ds = d.display().to_string();
        let mut out = String::new();
        exec_create(&parse("create", &["--dir", &ds, "--shard", "1"]), &mut out).unwrap();
        let file = d.join("entries.bin");
        std::fs::write(&file, entry(1, 16, 0, 10).to_bytes()).unwrap();
        let fs = file.display().to_string();
        let err = exec_add(
            &parse("add", &["--dir", &ds, "--shard", "1", "--entries", &fs]),
            &mut String::new(),
        )
        .unwrap_err();
        assert!(err.to_string().contains("lease"), "{err}");
        let direct = ShardStore::open(&d, 1).and_then(|mut s| s.publish(entry(2, 17, 0, 10)).map(|_| ()));
        assert!(
            matches!(direct, Err(StoreError::NeedLease)),
            "store обязан отказать сам, а не только через CLI"
        );
        vecdht_index::testing::remove(&d);
    }

    #[test]
    fn filters_are_stored_in_slot_attr_and_survive_reopen() {
        let d = vecdht_index::testing::dir("cli-index-filters");
        let ds = d.display().to_string();
        let mut out = String::new();
        exec_create(&parse("create", &["--dir", &ds, "--shard", "0", "--epoch", "1"]), &mut out)
            .unwrap();

        // Свободная запись ближе к запросу, платная — дальше. Фильтр обязан применяться до
        // усечения: иначе `--top-k 1 --class paid` вернул бы именно свободную, то есть чужой класс.
        let free = d.join("free.bin");
        std::fs::write(&free, entry(1, 0, 0, 100).to_bytes()).unwrap();
        let paid = d.join("paid.bin");
        std::fs::write(&paid, entry(2, 0, 0, 100).to_bytes()).unwrap();
        let fs = free.display().to_string();
        let ps = paid.display().to_string();
        let mut out = String::new();
        exec_add(
            &parse(
                "add",
                &["--dir", &ds, "--shard", "0", "--entries", &fs, "--epoch", "1",
                  "--class", "free", "--intent-dir", "buy"],
            ),
            &mut out,
        )
        .unwrap();
        assert!(out.contains("slot_attr 0x01"), "{out}");
        let mut out = String::new();
        exec_add(
            &parse(
                "add",
                &["--dir", &ds, "--shard", "0", "--entries", &ps, "--epoch", "1",
                  "--class", "paid", "--intent-dir", "sell"],
            ),
            &mut out,
        )
        .unwrap();
        assert!(out.contains("slot_attr 0x06"), "{out}");

        // Байт объявления едет в WAL-фрейме, значит его видно после открытия каталога заново.
        let back = ShardStore::open(&d, 0).unwrap();
        assert_eq!(back.index.slot_attr(0), Some(0x01));
        assert_eq!(back.index.slot_attr(1), Some(0x06));

        let q = [0i8; DIM];
        let hits =
            back.search_filtered(&q, &clusters_of_shard(0), 1, ClassFilter::OnlyPaid, DirFilter::Sell);
        assert_eq!(hits.len(), 1, "фильтр обязан применяться до усечения: {hits:?}");
        assert_eq!(hits[0].1, 1, "единственный хит — платная запись: {hits:?}");

        let qh = vector_hex(&q);
        let mut out = String::new();
        exec_search(
            &parse(
                "search",
                &["--dir", &ds, "--shard", "0", "--vec", &qh, "--clusters", "0", "--top-k", "1",
                  "--class", "paid", "--intent-dir", "sell", "--show-entries"],
            ),
            &mut out,
        )
        .unwrap();
        assert!(out.contains("хитов 1"), "{out}");
        assert!(out.contains("объявление: класс paid, направление sell"), "{out}");
        vecdht_index::testing::remove(&d);
    }

    #[test]
    fn any_filter_reproduces_the_unfiltered_answer() {
        let d = vecdht_index::testing::dir("cli-index-any");
        let ds = d.display().to_string();
        let mut out = String::new();
        exec_create(&parse("create", &["--dir", &ds, "--shard", "1", "--epoch", "1"]), &mut out)
            .unwrap();
        let mut bytes = Vec::new();
        for n in 1..4u8 {
            bytes.extend_from_slice(&entry(n, 16 + u16::from(n), 0, 100).to_bytes());
        }
        let f = d.join("entries.bin");
        std::fs::write(&f, &bytes).unwrap();
        let fs = f.display().to_string();
        let mut out = String::new();
        exec_add(
            &parse(
                "add",
                &["--dir", &ds, "--shard", "1", "--entries", &fs, "--epoch", "1",
                  "--class", "paid", "--intent-dir", "buy"],
            ),
            &mut out,
        )
        .unwrap();

        let back = ShardStore::open(&d, 1).unwrap();
        let q = [0i8; DIM];
        let clusters = clusters_of_shard(1);
        // `Any/Any` — это прежний ответ, а не «фильтр, который ничего не нашёл» (§12.7).
        assert_eq!(
            back.search(&q, &clusters, 3),
            back.search_filtered(&q, &clusters, 3, ClassFilter::Any, DirFilter::Any)
        );
        vecdht_index::testing::remove(&d);
    }
}
