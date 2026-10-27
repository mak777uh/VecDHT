//! Долговечная форма множества отозванных `nonce` (§4.2:155 и §4.2:181, `ADR-0050`).
//!
//! Зачем отдельный файл, а не часть WAL или снапшота. Отзыв — исполнение чужого подписанного
//! события, а не состояние индекса: две копии шарда обязаны иметь одинаковый *индекс*, но не
//! одинаковую *память о том, какие ключи они уже приняли к исполнению*. При этом RAM-форма (что
//! была до `H-0094`) обнулялась одним перезапуском, и `E-0094` измерил это на живом QUIC-стенде:
//! наблюдатель, отказавший отозванному пиру, после пересоздания с тем же каталогом принимал его
//! снова (`rv_g3_accepted_after_restart=1`), а узел, собственный кредашиал которого отозван,
//! возобновлял обслуживание (`rv_g6_serves_after_restart=1`). Цена здесь выше, чем у `ADR-0047`:
//! denylist — про удобство и отказ обслуживания, отзыв — про необратимость права обслуживать, и
//! снятый отзыв возвращает это право именно тому, кого его уже лишили.
//!
//! Почему отказ, а не «пересоздать пустой». `L-0013` (RFC 5280 §6.3.2) разделяет «не отозван» и
//! «не определён»: состояние, которого нет, обязано быть различимо от состояния, которое известно.
//! Молчаливый `revoked = {}` на битом файле означал бы «снять все отзывы из-за испорченного
//! файла» — тот же антипаттерн, что отвергнут у `L-0007` (`BanMan`) и что `ADR-0047` запретил для
//! denylist.
//!
//! Почему предел и почему отказ при упоре, а не вытеснение. Вытеснение старого `nonce` — это
//! амнистия: необратимость §4.2 получила бы срок службы, которого в спеке нет. Рост множества при
//! этом не надуть извне: вставка идемпотентна по `nonce`, повторная рассылка ничего не добавляет,
//! а подпись обязана пройти порог авторитетов (§15). Значит предел нужен не как анти-DoS, а как
//! условие «файл обязан иметь конечный размер» — и он обязан отказывать, а не счищать. Тупик
//! политики назван в `ADR-0050` и в `OPEN-QUESTIONS`: «снять что-то руками» для отзыва означает
//! амнистию отозванного ключа.
//!
//! Формат (18 + 16·N байт, N — число отзывов):
//!
//! ```text
//! | magic "VECDHTRV" u8[8] | версия u16 | count u32 | nonce 16·count по возрастанию | tag u8[4] |
//! ```
//!
//! `tag` — первые четыре байта blake3 от всего предыдущего; задача поля — заметить обрезку и
//! подправку, а не исправить их. Порядок детерминирован (`BTreeSet`), поэтому байты и размер файла
//! после данного множества фиксированы: проверка «цена переживаемости = 18 + 16·N» в оракуле есть
//! проверка формата, а не совпадение повезло.

use std::collections::BTreeSet;
use std::io::Write;
use std::path::{Path, PathBuf};

/// Предел множества. Число — решение `ADR-0050`, а не теорема: при 16-байтном ключе файл стоит
/// `18 + 16·4096 = 65 554` байта, тот же порядок, что уже оплачен `denylist.bin`
/// (`18 + 32·4096 = 131 090`).
pub const MAX_REVOCATIONS: usize = 4_096;
/// Имя файла состояния в каталоге узла.
pub const FILE: &str = "revocation.bin";
const MAGIC: [u8; 8] = *b"VECDHTRV";
const VERSION: u16 = 1;
const KEY_LEN: usize = 16;
/// Фиксированная часть до ключей: magic + версия + count.
const FIXED_LEN: usize = 8 + 2 + 4;
const TAG_LEN: usize = 4;
/// Весь служебный объём файла при пустом множестве: 14 + 4 = 18 байт, цена списка — `18 + 16·N`.
const OVERHEAD: usize = FIXED_LEN + TAG_LEN;

/// Причина, по которой сервис не поднимается или не может записать отзыв.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RevocationError {
    /// Файл есть, но он не множество отзывов: обрезан, подправлен, чужая версия или битый tag.
    #[error("файл отзывов не читается как список: {0}")]
    Corrupt(String),
    /// Ошибка самой файловой системы (нет места, каталог снят, права).
    #[error("файл отзывов не записать: {0}")]
    Io(String),
}

impl From<std::io::Error> for RevocationError {
    fn from(e: std::io::Error) -> Self {
        RevocationError::Io(e.to_string())
    }
}

/// Чем кончилась удачная попытка применить отзыв. Различия обязаны быть наблюдаемыми: «дубликат» —
/// штатный retry gossip, «отказ по пределу» — потеря нового отзыва. Ошибка файловой системы в этот
/// список не входит нарочно: она возвращается как `Err`, и вызывающий обязан отнестись к ней как к
/// неприменённому отзыву (вставка уже откатана), а не как ещё об одном штатном исходе.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Insert {
    Applied,
    Duplicate,
    RefusedAtBound,
}

/// Путь файла в каталоге узла.
pub fn path(dir: &Path) -> PathBuf {
    dir.join(FILE)
}

/// Байты файла для данного множества. Пустое множество кодируется корректно, но [`save`] вызывается
/// только при изменении, поэтому «пустой» узел без файла и «пустой» узел с файлом — одно состояние.
pub fn encode(keys: &BTreeSet<[u8; 16]>) -> Vec<u8> {
    let mut out = Vec::with_capacity(OVERHEAD + KEY_LEN * keys.len());
    out.extend_from_slice(&MAGIC);
    out.extend_from_slice(&VERSION.to_le_bytes());
    out.extend_from_slice(&(keys.len() as u32).to_le_bytes());
    for k in keys {
        out.extend_from_slice(k);
    }
    let h = blake3::hash(&out);
    out.extend_from_slice(&h.as_bytes()[..TAG_LEN]);
    out
}

/// Байты файла в множество. Проверка tag — до возврата состояния, и ни одна ветка отказа не
/// возвращает пустое множество как «ничего страшного»: см. документацию модуля.
pub fn decode(bytes: &[u8]) -> Result<Vec<[u8; 16]>, RevocationError> {
    if bytes.len() < OVERHEAD {
        return Err(RevocationError::Corrupt(format!(
            "файл короче заголовка с tag: {} байт",
            bytes.len()
        )));
    }
    if bytes[..MAGIC.len()] != MAGIC {
        return Err(RevocationError::Corrupt(
            "magic не VECDHTRV: файл не множество отзывов".to_string(),
        ));
    }
    let version = u16::from_le_bytes([bytes[8], bytes[9]]);
    if version != VERSION {
        return Err(RevocationError::Corrupt(format!(
            "версия списка отзывов {version}, узел понимает только {VERSION}"
        )));
    }
    let count = u32::from_le_bytes([bytes[10], bytes[11], bytes[12], bytes[13]]) as usize;
    let body = FIXED_LEN + KEY_LEN * count;
    let want = body + TAG_LEN;
    if bytes.len() != want {
        return Err(RevocationError::Corrupt(format!(
            "длина файла {} не равна 18 + 16·count ({want}) при count={count}",
            bytes.len()
        )));
    }
    let h = blake3::hash(&bytes[..body]);
    if bytes[body..want] != h.as_bytes()[..TAG_LEN] {
        return Err(RevocationError::Corrupt(
            "битая контрольная сумма: файл обрезан или подправлен".to_string(),
        ));
    }
    let mut keys = Vec::with_capacity(count);
    for i in 0..count {
        let at = FIXED_LEN + KEY_LEN * i;
        let mut k: [u8; 16] = [0u8; 16];
        k.copy_from_slice(&bytes[at..at + KEY_LEN]);
        keys.push(k);
    }
    if keys.windows(2).any(|w| w[0] >= w[1]) {
        return Err(RevocationError::Corrupt(
            "nonce в файле не упорядочены или повторяются".to_string(),
        ));
    }
    Ok(keys)
}

/// Прочитать множество из каталога. `Ok(None)` — файла нет (первый запуск узла); `Err` — файл есть
/// и он не множество отзывов: вызывающий обязан не поднимать сервис.
pub fn load(dir: &Path) -> Result<Option<Vec<[u8; 16]>>, RevocationError> {
    let p = path(dir);
    match std::fs::read(&p) {
        Ok(bytes) => decode(&bytes).map(Some),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// Записать множество: partial → fsync файла → rename → fsync каталога. Тот же барьер, что у
/// цепочки членства, у снапшота (§10.4) и у `denylist.rs`: `.bin` появляется целиком или не
/// появляется вовсе, полураспавшийся файл не виден следующим открытием.
pub fn save(dir: &Path, keys: &BTreeSet<[u8; 16]>) -> Result<(), RevocationError> {
    // Каталог создаётся при первой записи, а не при открытии: `open` не оставляет следов, пока
    // узел ничего не применил (тот же порядок, что у снапшота §10.4).
    std::fs::create_dir_all(dir)?;
    let bytes = encode(keys);
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

/// Множество отзывов вместе с его носителем. `dir = None` — поведение до `ADR-0050`: состояние
/// живёт в памяти, файла нет (агенту §4.2 права обслуживать не даёт, поэтому файл не нужен).
#[derive(Debug)]
pub struct Revocations {
    keys: BTreeSet<[u8; 16]>,
    dir: Option<PathBuf>,
    /// Сколько отзывов отвергнуто из-за предела. Наблюдаемость для оператора: отказ применить
    /// отзыв — это потеря необратимости, а не штатная ветка.
    pub refused_at_bound: u64,
    /// Сколько раз множество не удалось записать; каждая такая попытка откатана, и отзыв не
    /// считается применённым.
    pub save_errors: u64,
    /// Сколько пришедших отзывов уже были в множестве. Этот счётчик нужен не оператору, а
    /// оракулу: повторный отзыв ничем не отличается снаружи, и без него гейт идемпотентности
    /// пришлось бы мерить фиксированным окном ожидания — то есть временем, которое правило 7
    /// пункт (е) запрещает как вердикт.
    pub duplicates: u64,
}

impl Revocations {
    /// Поднять состояние из каталога. Ошибка здесь означает «сервис не стартует»: молчаливое
    /// пустое множество на битом файле снимало бы все отзывы разом. Счётчики относятся к эпизоду
    /// и обнуляются при открытии: на диске лежит множество, а не статистика (`ADR-0050`).
    pub fn open(dir: Option<PathBuf>) -> Result<Self, RevocationError> {
        let mut keys = BTreeSet::new();
        if let Some(d) = &dir {
            if let Some(loaded) = load(d)? {
                // Загрузка сохраняет всё, что лежит на диске, даже больше предела: предел
                // замораживает внесение, а не чистит (`ADR-0047` в той же форме).
                keys.extend(loaded);
            }
        }
        Ok(Self {
            keys,
            dir,
            refused_at_bound: 0,
            save_errors: 0,
            duplicates: 0,
        })
    }

    pub fn contains(&self, nonce: &[u8; 16]) -> bool {
        self.keys.contains(nonce)
    }

    /// Заимствованное множество — для `handshake::Verifier`, который принимает `&BTreeSet`.
    /// Копию множества в сервисе держать нельзя: тогда «что в памяти» и «что на диске» могли бы
    /// разойтись, а переживаемость — ровно про их совпадение.
    pub fn set(&self) -> &BTreeSet<[u8; 16]> {
        &self.keys
    }

    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Каталог носителя, если он задан; `None` — состояние только в памяти.
    pub fn dir(&self) -> Option<PathBuf> {
        self.dir.clone()
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// Байт файла состояния на диске; 0 — файла нет (нет каталога или ещё ничего не применено).
    /// Гейт цены переживаемости в оракуле меряет именно это число.
    pub fn file_bytes(&self) -> u64 {
        match &self.dir {
            Some(d) => std::fs::metadata(path(d)).map(|m| m.len()).unwrap_or(0),
            None => 0,
        }
    }

    /// Применить проверенный отзыв: вставка идемпотентна по `nonce`, при упоре в предел — отказ
    /// новому (старые не вытесняются никогда), после изменения — запись на диск; не удалось
    /// записать — вставка откатывается и возвращается `Err`, то есть отзыв считается
    /// неприменённым.
    pub fn insert(&mut self, nonce: [u8; 16]) -> Result<Insert, RevocationError> {
        if self.keys.contains(&nonce) {
            self.duplicates += 1;
            return Ok(Insert::Duplicate);
        }
        if self.keys.len() >= MAX_REVOCATIONS {
            self.refused_at_bound += 1;
            return Ok(Insert::RefusedAtBound);
        }
        self.keys.insert(nonce);
        if let Some(d) = &self.dir {
            if let Err(e) = save(d, &self.keys) {
                self.keys.remove(&nonce);
                self.save_errors += 1;
                return Err(e);
            }
        }
        Ok(Insert::Applied)
    }

    /// Итератор по множеству — для теста «старейший отзыв по-прежнему отказывает».
    pub fn nonces(&self) -> impl Iterator<Item = &[u8; 16]> {
        self.keys.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nonce(i: usize) -> [u8; 16] {
        let mut k = [0u8; 16];
        k[0] = 211;
        k[8..].copy_from_slice(&(i as u64).to_le_bytes());
        k
    }

    fn set(n: usize) -> BTreeSet<[u8; 16]> {
        (0..n).map(nonce).collect()
    }

    fn tmp(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("vecdht-rev-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).expect("временный каталог");
        p
    }

    #[test]
    fn the_price_is_exactly_eighteen_plus_sixteen_per_nonce() {
        for n in [0usize, 1, 3, 4_096] {
            assert_eq!(
                encode(&set(n)).len(),
                OVERHEAD + KEY_LEN * n,
                "размер файла при N={n}"
            );
        }
        assert_eq!(OVERHEAD + KEY_LEN * MAX_REVOCATIONS, 65_554, "цена полного списка");
    }

    #[test]
    fn roundtrip_through_the_filesystem_preserves_the_set() {
        let d = tmp("roundtrip");
        let k = set(3);
        save(&d, &k).expect("записать множество");
        let got = load(&d).expect("прочитать множество").expect("файл есть");
        assert_eq!(got.len(), 3);
        assert_eq!(got[2], nonce(2), "порядок и состав совпадают");
        assert_eq!(std::fs::metadata(path(&d)).unwrap().len(), 66);
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn no_corruption_of_the_file_ever_decodes_to_an_empty_list() {
        // Теорема `corrupt_file_is_never_empty` (модель `Denylist.lean`) на настоящем формате:
        // единственный способ получить пустое множество — записать пустое.
        let good = encode(&set(3));
        assert_eq!(decode(&encode(&BTreeSet::new())).unwrap().len(), 0, "пустой список легален");
        let mut broken: Vec<Vec<u8>> = Vec::new();
        for cut in 1..good.len() {
            broken.push(good[..cut].to_vec());
        }
        for i in 0..good.len() {
            let mut tampered = good.clone();
            tampered[i] ^= 0x01;
            broken.push(tampered);
        }
        for b in &broken {
            if let Ok(v) = decode(b) {
                assert!(!v.is_empty(), "обрезка или подправка дали пустой список");
            }
        }
    }

    #[test]
    fn count_that_promises_more_than_the_file_holds_is_refused() {
        let mut good = encode(&set(3));
        good[10] = 4; // count = 4 при трёх nonce, длина файла прежняя
        assert!(matches!(decode(&good), Err(RevocationError::Corrupt(_))));

        let one = nonce(0);
        let mut dup = Vec::new();
        dup.extend_from_slice(&MAGIC);
        dup.extend_from_slice(&VERSION.to_le_bytes());
        dup.extend_from_slice(&2u32.to_le_bytes());
        dup.extend_from_slice(&one);
        dup.extend_from_slice(&one);
        let h = blake3::hash(&dup);
        dup.extend_from_slice(&h.as_bytes()[..TAG_LEN]);
        assert!(matches!(decode(&dup), Err(RevocationError::Corrupt(_))));
    }

    #[test]
    fn the_bound_refuses_new_revocations_and_never_amnesties_old_ones() {
        let mut r = Revocations::open(None).expect("множество без каталога поднимается");
        let mut applied = 0usize;
        for i in 0..MAX_REVOCATIONS {
            if r.insert(nonce(i)).expect("вставка без каталога не падает") == Insert::Applied {
                applied += 1;
            }
        }
        let oldest = nonce(0);
        assert_eq!(applied, MAX_REVOCATIONS, "предел принят целиком");
        assert_eq!(r.insert(nonce(9_999)), Ok(Insert::RefusedAtBound));
        assert_eq!(r.refused_at_bound, 1);
        assert_eq!(r.len(), MAX_REVOCATIONS, "множество не выросло");
        assert!(r.contains(&oldest), "старейший отзыв по-прежнему отказывает");
    }

    #[test]
    fn a_duplicate_revocation_changes_neither_the_set_nor_the_file() {
        let d = tmp("idempotent");
        let mut r = Revocations::open(Some(d.clone())).expect("открыть множество");
        assert_eq!(r.insert(nonce(1)), Ok(Insert::Applied));
        let bytes_after_first = r.file_bytes();
        assert_eq!(bytes_after_first, 34, "18 + 16·1");
        assert_eq!(r.insert(nonce(1)), Ok(Insert::Duplicate));
        assert_eq!(r.len(), 1);
        assert_eq!(r.duplicates, 1, "повтор наблюдаем: иначе оракул мерил бы время, а не исход");
        assert_eq!(r.file_bytes(), bytes_after_first, "повтор ничего не дописал");
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn without_a_directory_the_state_stays_in_memory_and_no_file_appears() {
        let mut r = Revocations::open(None).expect("множество без каталога");
        assert_eq!(r.insert(nonce(7)), Ok(Insert::Applied));
        assert_eq!(r.file_bytes(), 0, "писателя в файл нет, если каталог не задан");
        assert!(r.contains(&nonce(7)));
    }

    /// Прибор `H-0136`: что делает код, когда носитель отказывает. Тест ничего не утверждает о
    /// желаемом и ничего не чинит: он печатает наблюдаемые числа, потому что политика (отказываться
    /// ли обслуживать при ошибке диска) относится к владельцу.
    ///
    /// Пара ветвей обязательна: без контрольной ветки «носитель исправен» проба печатала бы `0` и
    /// на здоровом дереве, то есть была бы слепой, а не красной. Каждый факт печатается воронкой
    /// `emit_fact` ровно один раз — прибор `lab/e0136-run.sh` сверяет число воронок в источнике с
    /// числом строк `FACT` в выводе, и расхождение делает сверку красной, а не молчаливой.
    #[test]
    fn a_write_failure_forgets_the_revocation_while_a_healthy_carrier_remembers_it() {
        fn emit_fact(name: &str, value: impl std::fmt::Display) {
            println!("FACT {name} {value}");
        }
        let n = nonce(4242);

        // (1) Контроль: обычный каталог, отзыв применяется и ложится в файл ценой `18 + 16·1`.
        let ok = tmp("write-ok");
        let mut healthy = Revocations::open(Some(ok.clone())).expect("пустой каталог открывается");
        let ok_res = healthy.insert(n);
        emit_fact(
            "CTRL_INSERT_APPLIED",
            matches!(ok_res, Ok(Insert::Applied)) as u8,
        );
        emit_fact("CTRL_NONCE_FORGOTTEN", (!healthy.contains(&n)) as u8);
        emit_fact("CTRL_FILE_BYTES", healthy.file_bytes());
        emit_fact("CTRL_SAVE_ERRORS", healthy.save_errors);
        std::fs::remove_dir_all(&ok).unwrap();

        // (2) Отказ носителя: на пути временного файла стоит каталог, поэтому `create` обязан
        //     упасть на любой платформе. Это названный способ вывести носитель из строя, а не
        //     игра с правами: `readonly`-каталог на Windows пишущий процесс не останавливает.
        let bad = tmp("write-fail");
        let mut degraded = Revocations::open(Some(bad.clone())).expect("пустой каталог открывается");
        std::fs::create_dir_all(bad.join(format!("{FILE}.partial"))).expect("каталог вместо .partial");
        let err = degraded.insert(n);
        emit_fact("FAIL_INSERT_IS_ERR", matches!(err, Err(_)) as u8);
        emit_fact("FAIL_NONCE_FORGOTTEN", (!degraded.contains(&n)) as u8);
        emit_fact("FAIL_SET_LEN", degraded.len());
        emit_fact("FAIL_SAVE_ERRORS", degraded.save_errors);
        emit_fact("FAIL_STATE_FILE_BYTES", degraded.file_bytes());
        std::fs::remove_dir_all(&bad).unwrap();
    }

    #[test]
    fn a_corrupt_file_refuses_to_open_rather_than_losing_every_revocation() {
        let d = tmp("corrupt");
        let mut r = Revocations::open(Some(d.clone())).expect("пустой каталог открывается");
        r.insert(nonce(3)).expect("применить отзыв");
        let good = std::fs::read(path(&d)).expect("файл есть");
        let mut truncated = good.clone();
        truncated.truncate(good.len() - 3);
        std::fs::write(path(&d), &truncated).expect("обрезать файл");
        assert!(matches!(
            Revocations::open(Some(d.clone())),
            Err(RevocationError::Corrupt(_))
        ));
        let mut tampered = good;
        tampered[20] ^= 0x01;
        std::fs::write(path(&d), &tampered).expect("подправить байт");
        assert!(matches!(
            Revocations::open(Some(d.clone())),
            Err(RevocationError::Corrupt(_))
        ));
        std::fs::remove_dir_all(&d).unwrap();
    }
}
