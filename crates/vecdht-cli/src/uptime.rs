//! Долговечный счётчик аптайма, привязанный к старту (`ADR-0071`, карта `A7b`).
//!
//! Зачем это отдельный файл, а не поле `NodeMetrics`. Критерий H1 в `ROADMAP.md` сформулирован
//! как отчёт, а не как слово оператора: «each node writes a startup-anchored counter; the report
//! is the counter, not a human claim». Слово «startup-anchored» задаёт форму: обнуление при
//! рестарте — потому что мёртвое время не должно записываться как живое, и переживание рестарта
//! суммой сессий — потому что «30 дней» из одной текущей сессии не собираются. Ни одна из этих
//! двух половин не живёт в `crates/vecdht-node`: §9.6 вынесло локальное время из реплицированного
//! пути целиком («Локальное время исключено из replicated-пути полностью», `docs/VecDHT-SPEC-v8.md`),
//! и комментарий в `crates/vecdht-node/src/config.rs` прямо говорит, что у узла нет ни `Instant`,
//! ни таймера. Значит счётчик читает часы CLI-слой — тот же слой, что уже зовёт `now_sec()` для
//! `Clock::at`, — и остаётся операторским артефактом на диске, а не протокольным состоянием.
//!
//! Почему файл обязан переживать рестарт, а не жить в RAM. До этого цикла `NODE_STATUS` печатал
//! только `t=` — секунды от `Instant::now()` текущего процесса (`node_cmd.rs`). Это ровно половина
//! требования: рестарт (или `kill -9`) обнулял счётчик, и накопленное окно исчезало без следа.
//!
//! Почему отказ, а не тихое обнуление битого файла. `L-0013` (RFC 5280 §6.3.2) разделяет «не
//! отозван» и «не определён»: состояние, которого нет, обязано быть различимо от состояния,
//! которое испорчено. Молчаливое `sessions = 0` на обрезанном файле означало бы «списать 30 дней
//! из-за повреждённого байта» — тот же антипаттерн амнистии, что отвергнут у предела `revocation.bin`
//! (`ADR-0050`) и у вытеснения denylist (`ADR-0047`). Поэтому битый ledger — код 2 с именем файла,
//! а новый цикл с нуля — только по явному флагу `--uptime-reset`, который сам печатает, что сделал.
//!
//! Почему гранулярность = `--status-sec`. Узел обновляет `last_seen` на каждом бите статуса, и
//! сессия, убитая `kill -9`, закрывается по последнему биту, а не по моменту смерти: хвост до
//! интервала теряется. Это названо, а не спрятано: вердикт «аптайм ≥ 30 дней» означает «сумма
//! сессионных окон с точностью до периода бита», и период входит в отчёт числом.
//!
//! Формат (ровно 46 байт, размер не зависит от содержимого — предела списка нет и амнистии по
//! упору тоже нет):
//!
//! ```text
//! | magic "VECDHTUP" u8[8] | версия u16 | sessions u32 | accumulated_sec u64 |
//! | open_start_sec u64 | last_seen_sec u64 | clock_regressions u32 | tag u8[4] |
//! ```
//!
//! `tag` — первые четыре байта blake3 от всего предыдущего: задача поля заметить обрезку и
//! подправку, а не исправить их. `accumulated_sec` — сумма уже закрытых сессий; текущая сессия
//! в сумму не входит, пока не закрыта следующим стартом, и печатается отдельно числом.
//!
//! Откат часов. `beat` и `open_session` при `now < last_seen` не двигают `last_seen` назад и не
//! вычитают секунды: они увеличивают `clock_regressions`. Счётчик умеет только расти или стоять,
//! и «стоять из-за отката часов» — различимое состояние, а не тихая потеря.

use std::io::Write as _;
use std::path::{Path, PathBuf};

use thiserror::Error;

/// Имя файла ledger'а в каталоге узла.
pub const FILE: &str = "uptime.bin";

const MAGIC: [u8; 8] = *b"VECDHTUP";
const VERSION: u16 = 1;
const TAG_LEN: usize = 4;

/// Байт в файле ровно столько, сколько места у полей: список сессий не хранится целиком,
/// хранится сумма. Поэтому цена ledger'а — константа, а не `O(рестартов)`.
pub const FIXED_LEN: usize = 8 + 2 + 4 + 8 + 8 + 8 + 4 + TAG_LEN;

const _: () = assert!(FIXED_LEN == 46, "формат uptime.bin назван в ADR-0071 числом 46");

#[derive(Debug, Error, PartialEq, Eq)]
pub enum UptimeError {
    #[error("файл `{0}` короче формата ({1} байт при {FIXED_LEN})")]
    TooShort(String, usize),
    #[error("файл `{0}` длиннее формата ({1} байт при {FIXED_LEN})")]
    TooLong(String, usize),
    #[error("magic не VECDHTUP: файл `{0}` — не ledger аптайма")]
    BadMagic(String),
    #[error("версия ledger'а {0}, этот бинарь понимает только {VERSION}")]
    BadVersion(u16),
    #[error("tag не сходится: файл `{0}` обрезан или подправлен")]
    BadTag(String),
    #[error("файл `{0}` не читается: {1}")]
    Unreadable(String, String),
}

/// Состояние ledger'а. Поля — ровно те же числа, что лежат в файле, поэтому отчёт `node uptime`
/// не пересчитывает смысл, а переносит байты.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ledger {
    /// Сколько сессий закрыто и записано, включая открытую сейчас.
    pub sessions: u32,
    /// Сумма закрытых сессий в секундах системного времени.
    pub accumulated_sec: u64,
    /// Метка старта открытой сессии; у закрытого ledger'а равна `last_seen_sec`.
    pub open_start_sec: u64,
    /// Последний бит (или момент закрытия) — верхняя граница открытой сессии.
    pub last_seen_sec: u64,
    /// Сколько раз часы встали назад; каждая такая ветка не дала счётчику ни убавить, ни промолчать.
    pub clock_regressions: u32,
}

impl Ledger {
    /// Первый запуск в каталоге, где файла нет: одна открытая сессия с нулевой суммой.
    pub fn fresh(now: u64) -> Self {
        Ledger {
            sessions: 1,
            accumulated_sec: 0,
            open_start_sec: now,
            last_seen_sec: now,
            clock_regressions: 0,
        }
    }

    /// Секунды текущей (открытой) сессии на момент `now`. Верхняя граница окна — `max(now,
    /// last_seen)`: счётчик умеет только расти, поэтому откат часов не вычитает уже засчитанные
    /// секунды (ветка названа числом `clock_regressions`, а не молчаливой потерей).
    pub fn current_sec(&self, now: u64) -> u64 {
        now.max(self.last_seen_sec).saturating_sub(self.open_start_sec)
    }

    /// Что отдаёт отчёт: сумма закрытого плюс открытое. Для файла, прочитанного без процесса
    /// узла, `now = last_seen_sec`, и тогда это ровно накопленное на момент последней записи.
    pub fn total_sec(&self, now: u64) -> u64 {
        self.accumulated_sec + self.current_sec(now)
    }

    /// Бит статуса: продвинуть `last_seen`. Назад счётчик не ходит никогда; откат часов — это
    /// отдельное число, а не молчание.
    pub fn beat(&mut self, now: u64) -> bool {
        if now > self.last_seen_sec {
            self.last_seen_sec = now;
            return true;
        }
        if now < self.last_seen_sec {
            self.clock_regressions += 1;
        }
        false
    }

    /// Закрытие предыдущей сессии и открытие новой тем же процессом старта. Возвращает, сколько
    /// секунд дало закрытие, — факт, который носитель цикла печатает, а не выводит из кода.
    pub fn reopen(&mut self, now: u64) -> u64 {
        let closed = self.last_seen_sec.saturating_sub(self.open_start_sec);
        self.accumulated_sec += closed;
        self.sessions += 1;
        if now < self.last_seen_sec {
            // Часы отстали от последнего бита: новая сессия начинается по старому `last_seen`,
            // иначе откат часов добавлял бы аптайм. Заморозка названа числом.
            self.clock_regressions += 1;
            self.open_start_sec = self.last_seen_sec;
        } else {
            self.open_start_sec = now;
            self.last_seen_sec = now;
        }
        closed
    }
}

/// Путь файла в каталоге узла.
pub fn path(dir: &Path) -> PathBuf {
    dir.join(FILE)
}

/// Байты файла. Порядок полей — формат, поэтому `encode`/`decode` проверяются раундтрипом
/// в юнит-тесте, а не «на глаз по спеке».
pub fn encode(l: &Ledger) -> Vec<u8> {
    let mut out = Vec::with_capacity(FIXED_LEN);
    out.extend_from_slice(&MAGIC);
    out.extend_from_slice(&VERSION.to_le_bytes());
    out.extend_from_slice(&l.sessions.to_le_bytes());
    out.extend_from_slice(&l.accumulated_sec.to_le_bytes());
    out.extend_from_slice(&l.open_start_sec.to_le_bytes());
    out.extend_from_slice(&l.last_seen_sec.to_le_bytes());
    out.extend_from_slice(&l.clock_regressions.to_le_bytes());
    let h = blake3::hash(&out);
    out.extend_from_slice(&h.as_bytes()[..TAG_LEN]);
    out
}

/// Байты файла в состояние. Ни одна ветка отказа не возвращает «пустой ledger»: вызывающий
/// обязан остановиться, а не списать накопленное.
pub fn decode(bytes: &[u8], name: &str) -> Result<Ledger, UptimeError> {
    if bytes.len() < FIXED_LEN {
        return Err(UptimeError::TooShort(name.to_string(), bytes.len()));
    }
    if bytes.len() > FIXED_LEN {
        return Err(UptimeError::TooLong(name.to_string(), bytes.len()));
    }
    if bytes[..8] != MAGIC {
        return Err(UptimeError::BadMagic(name.to_string()));
    }
    let version = u16::from_le_bytes([bytes[8], bytes[9]]);
    if version != VERSION {
        return Err(UptimeError::BadVersion(version));
    }
    let g = |o: usize, n: usize| &bytes[o..o + n];
    let h = blake3::hash(&bytes[..FIXED_LEN - TAG_LEN]);
    if h.as_bytes()[..TAG_LEN] != *g(FIXED_LEN - TAG_LEN, TAG_LEN) {
        return Err(UptimeError::BadTag(name.to_string()));
    }
    Ok(Ledger {
        sessions: u32::from_le_bytes(g(10, 4).try_into().unwrap()),
        accumulated_sec: u64::from_le_bytes(g(14, 8).try_into().unwrap()),
        open_start_sec: u64::from_le_bytes(g(22, 8).try_into().unwrap()),
        last_seen_sec: u64::from_le_bytes(g(30, 8).try_into().unwrap()),
        clock_regressions: u32::from_le_bytes(g(38, 4).try_into().unwrap()),
    })
}

/// Прочитать ledger без изменения файла — это путь отчёта `node uptime`. `Ok(None)` — файла нет
/// (узел здесь ещё не стартовал), `Err` — файл есть и он не ledger.
pub fn load(dir: &Path) -> Result<Option<Ledger>, UptimeError> {
    let p = path(dir);
    match std::fs::read(&p) {
        Ok(bytes) => decode(&bytes, &p.display().to_string()).map(Some),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(UptimeError::Unreadable(p.display().to_string(), e.to_string())),
    }
}

/// Записать ledger: partial → fsync файла → rename → fsync каталога. Тот же барьер, что у
/// `revocation.bin` (`ADR-0050`), `denylist.bin` и снапшота §10.4: файл появляется целиком либо
/// не появляется вовсе, и полураспавшийся ledger не виден следующему открытию.
pub fn save(dir: &Path, l: &Ledger) -> Result<(), std::io::Error> {
    std::fs::create_dir_all(dir)?;
    let bytes = encode(l);
    let tmp = dir.join(format!("{FILE}.partial"));
    {
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&tmp)?;
        f.write_all(&bytes)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path(dir))?;
    // На Windows fsync каталога невозможен, и NTFS журналирует rename сама; барьер обязан
    // переживать и этот ответ — ровно как в §10.4 и в `vecdht_index::fsync_dir`.
    vecdht_index::fsync_dir(dir)?;
    Ok(())
}

/// Что произошло при открытии узла. Варианты различимы в отчёте, потому что «файла не было» и
/// «файл был, сессия закрыта» — разные факты о прошлом каталога.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Opened {
    /// Каталог без ledger'а: счётчик начинается с нуля.
    Fresh,
    /// Ledger пережил рестарт; столько секунд закрылось из предыдущей сессии.
    Resumed { closed_sec: u64 },
    /// Битый ledger сброшен явно по флагу оператора, а не молча.
    Reset { was_bytes: usize },
}

/// Ledger вместе с местом, где он живёт, и со счётом неудачных записей. Тип нужен, потому что
/// цикл узла обязан продвигать все три значения разом: отдельный параметр на каждое превратил
/// `serve` в список аргументов, а молчаливый `io_errors` — в «аптайм не копился, но выглядит
/// как будто».
#[derive(Debug)]
pub struct Sink {
    /// Каталог узла: сюда пишется `uptime.bin`.
    pub dir: PathBuf,
    pub ledger: Ledger,
    pub opened: Opened,
    /// Сколько битов подряд не удалось записать. Узел от этого не останавливается — но «дни не
    /// копились» и «дни копились и не записались» обязаны быть различимы в той же строке.
    pub io_errors: u32,
}

impl Sink {
    /// Один шаг счётчика: продвинуть `last_seen` и переписать файл целиком (partial → fsync →
    /// rename). Возвращает ошибку записи, а не текст: как именно отказ называть в выводе, решает
    /// вызывающий слой, а счётчик лишь честно отвечает «не вышло».
    pub fn beat(&mut self, now: u64) -> Option<std::io::Error> {
        self.ledger.beat(now);
        match save(&self.dir, &self.ledger) {
            Ok(()) => None,
            Err(e) => {
                self.io_errors += 1;
                Some(e)
            }
        }
    }
}

/// Открыть сессию в каталоге узла. Битый файл — ошибка вызывающего, а не повод начать заново:
/// `reset` обязан попросить оператор, и тогда отказ назван действием с числом байтов.
pub fn open_session(dir: &Path, now: u64, reset: bool) -> Result<(Ledger, Opened), UptimeError> {
    let p = path(dir);
    let bytes = match std::fs::read(&p) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok((Ledger::fresh(now), Opened::Fresh));
        }
        Err(e) => return Err(UptimeError::Unreadable(p.display().to_string(), e.to_string())),
    };
    match decode(&bytes, &p.display().to_string()) {
        Ok(mut l) => {
            let closed = l.reopen(now);
            Ok((l, Opened::Resumed { closed_sec: closed }))
        }
        Err(e) => {
            if reset {
                // Оператор попросил начать заново — и получил это действием с числом байтов,
                // а не молчаливым «ок, считаем с нуля».
                Ok((Ledger::fresh(now), Opened::Reset { was_bytes: bytes.len() }))
            } else {
                Err(e)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn led() -> Ledger {
        Ledger { sessions: 3, accumulated_sec: 100, open_start_sec: 7, last_seen_sec: 57, clock_regressions: 1 }
    }

    /// Временный каталог с Remove-гардом: паника внутри проверки не должна оставлять мусор в
    /// `%TEMP%` (счёт осевших каталогов уже был находкой цикла — гард обязателен, а не «удалить в
    /// конце строкой»).
    struct TmpDir(PathBuf);

    impl TmpDir {
        fn new(tag: &str) -> Self {
            let p = std::env::temp_dir().join(format!("vecdht-uptime-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&p);
            std::fs::create_dir_all(&p).unwrap();
            Self(p)
        }
    }

    impl Drop for TmpDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn format_is_forty_six_bytes_and_roundtrips() {
        let l = led();
        let b = encode(&l);
        assert_eq!(b.len(), 46, "цена ledger'а названа форматом");
        assert_eq!(decode(&b, "t").unwrap(), l, "encode/decode обязаны сходиться побайтово");
    }

    #[test]
    fn truncation_and_single_byte_edit_are_both_refused() {
        let b = encode(&led());
        assert!(matches!(decode(&b[..45], "t"), Err(UptimeError::TooShort(..))));
        assert!(matches!(decode(&b[..8], "t"), Err(UptimeError::TooShort(..))));
        let mut flipped = b.clone();
        // Подмена одного байта в теле меняет tag, но не длину: ловится ровно проверкой tag.
        flipped[14] ^= 1;
        assert!(matches!(decode(&flipped, "t"), Err(UptimeError::BadTag(..))), "подправленный файл не должен открыться");
        let mut long = b.clone();
        long.push(0);
        assert!(matches!(decode(&long, "t"), Err(UptimeError::TooLong(..))));
    }

    #[test]
    fn foreign_file_is_not_read_as_a_ledger() {
        assert!(matches!(decode(&[0u8; 46], "t"), Err(UptimeError::BadMagic(..))));
        let mut b = encode(&led());
        b[8] = 2; // версия, tag после правки не сходится — проверка версии обязана быть до tag
        assert!(matches!(decode(&b, "t"), Err(UptimeError::BadVersion(2))));
    }

    #[test]
    fn restart_folds_the_previous_session_and_grows_the_counter() {
        let mut l = led();
        let closed = l.reopen(120);
        assert_eq!(closed, 50, "закрытое окно = last_seen - open_start");
        assert_eq!((l.sessions, l.accumulated_sec), (4, 150), "накопленное обязано пережить рестарт");
        assert_eq!(l.open_start_sec, 120, "новая сессия привязана к своему старту");
        assert_eq!(l.total_sec(130), 160);
    }

    #[test]
    fn clock_regression_never_subtracts_and_never_inflates() {
        let mut l = led();
        // Бит с откатом: last_seen стоит, окно не уменьшается, откат назван числом.
        assert!(!l.beat(40));
        assert_eq!((l.last_seen_sec, l.clock_regressions, l.total_sec(40)), (57, 2, 150));
        // Старт с часами, отстающими от последнего бита: закрытая сессия отдаёт ровно своё
        // замороженное окно (57 − 7 = 50 с: часы откатились ПОСЛЕ того, как эти секунды были
        // засчитаны битом, и «сессия дала ноль» означало бы списать их задним числом), а новая
        // сессия открывается по старому `last_seen` и откат не добавляет ни секунды.
        let closed = l.reopen(10);
        assert_eq!(closed, 50, "закрытое окно — замороженный последний бит, а не откатившиеся часы");
        assert_eq!(
            (l.sessions, l.accumulated_sec),
            (4, 150),
            "сумма растёт ровно на закрытое окно"
        );
        assert_eq!((l.open_start_sec, l.last_seen_sec, l.clock_regressions), (57, 57, 3));
        assert_eq!(l.total_sec(30), 150, "пока часы не догнали старое last_seen, счётчик стоит");
    }

    #[test]
    fn corrupt_ledger_is_not_resumable_without_an_explicit_reset() {
        let tmp = TmpDir::new("corrupt");
        std::fs::write(path(&tmp.0), b"not a ledger").unwrap();
        let e = open_session(&tmp.0, 100, false).unwrap_err();
        assert!(matches!(e, UptimeError::BadMagic(_) | UptimeError::TooShort(_, _)));
        let (l, opened) = open_session(&tmp.0, 100, true).unwrap();
        assert!(matches!(opened, Opened::Reset { .. }), "сброс обязан быть явным действием");
        assert_eq!(l.sessions, 1);
    }

    #[test]
    fn writes_leave_no_partial_and_restart_reads_the_same_bytes() {
        let tmp = TmpDir::new("roundtrip");
        let mut l = Ledger::fresh(1_000);
        save(&tmp.0, &l).expect("первая запись барьера");
        l.beat(1_004);
        save(&tmp.0, &l).expect("бит статуса пишет тот же файл целиком");
        assert!(
            !tmp.0.join(format!("{FILE}.partial")).exists(),
            "rename обязан убрать временный файл: его след = незакрытый барьер"
        );
        assert_eq!(load(&tmp.0).unwrap(), Some(l), "прочитанное = записанное побайтово");

        // «Рестарт» — то же чтение другим открытием: сумма закрывает сессию числом, а не памятью.
        let (mut l2, opened) = open_session(&tmp.0, 1_010, false).unwrap();
        assert_eq!(opened, Opened::Resumed { closed_sec: 4 });
        assert_eq!((l2.sessions, l2.accumulated_sec), (2, 4));
        l2.beat(1_020);
        save(&tmp.0, &l2).unwrap();
        assert_eq!(
            load(&tmp.0).unwrap().unwrap().total_sec(1_020),
            14,
            "4 с закрытой сессии плюс 10 с открытой"
        );
        assert_eq!(load(std::path::Path::new(&format!("{}-нет", tmp.0.display()))).unwrap(), None, "каталог без истории читается как None, не как ошибка");
    }
}
