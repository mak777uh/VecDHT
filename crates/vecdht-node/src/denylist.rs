//! Долговечная форма denylist'а (§11.4, пункт ii): файл запрета в каталоге узла.
//!
//! Зачем отдельный файл, а не часть WAL или снапшота. Запрет — локальная политика приёма, как
//! кап ячейки (§11.3): его решения не попадают в индекс, не реплицируются и не участвуют в
//! кворуме, поэтому в WAL ему нечего делать — две копии шарда обязаны иметь одинаковый *индекс*,
//! а не одинаковый *список запрета*. При этом RAM-форма (что была до `H-0092`) обнулялась одним
//! перезапуском: `E-0042` измерил, что цепочка членства поднимается с диска, а список — нет, и
//! внесённый оператором ключ получал прежнюю квоту бесплатно. Отсюда отдельный файл и жёсткий
//! отказ при его нечитаемости.
//!
//! Почему отказ, а не «пересоздать пустой». Молчаливый `m_banned = {}` на битой базе — ровно тот
//! defect, который `L-0007` (Bitcoin Core `BanMan`) выбирает осознанно и который для нас
//! означает «снять все запреты из-за испорченного файла». Модель `lab/lean/VecDHT/Denylist.lean`
//! формулирует это как теорему `corrupt_file_is_never_empty`: ни один обрезанный или подправленный
//! файл не обязан декодироваться в пустое множество, и путь узла — не открыть шард.
//!
//! Почему предел и почему отказ при упоре, а не вытеснение. `MAX_DENYLIST` — та же цена, что
//! `E-0091` посчитал для `provider_peers`: список растёт не от легитимных агентов, а от
//! наблюдений встраивателя, и без предела это неограниченный рост памяти. Выбор политики — не
//! мнение: перебор четырёх кандидатов в модели Lean оставляет ровно одного, у которого
//! «ни один не отозванный запрет не исчезает сам» выполняется при полном списке, — отказ новому
//! внесению. Это совпадает с `E-0088` (`SHARD_FULL` вместо вытеснения живой записи) и с
//! `L-0008` (HAProxy stick table: счистить можно только истёкшее и неиспользуемое, иначе —
//! отказ вставки). Следствие обязан знать встраиватель: при полном списке множество
//! **замораживается**, и снять заморозку может только `undeny` (теоремы `frozen_at_cap` и
//! `undeny_makes_room` в той же модели).
//!
//! Формат (18 + 32·N байт, N — число ключей):
//!
//! ```text
//! | magic "VECDHTNL" u8[8] | версия u16 | count u32 | ключи 32·count по возрастанию | tag u8[4] |
//! ```
//!
//! `tag` — первые четыре байта blake3 от всего предыдущего. Это не crc32 из `vecdht-index`: узел
//! не тянет `crc32fast` второй зависимостью ради одного файла, а задача поля — заметить обрезку и
//! подправку, а не исправить их. Порядок ключей детерминирован (`BTreeSet`), поэтому байты и
//! размер файла после данного множества фиксированы: проверка «цена переживаемости = 18 + 32·N»
//! в оракуле — проверка формата, а не совпадение повезло.

use std::collections::BTreeSet;
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::net::Addr;

/// Предел списка. Число — решение `ADR-0047`, а не теорема: модель Lean конечна (3 ключа, предел
/// 2) и про 4096 ничего не утверждает; проверкой числа является гейт (6) оракула.
pub const MAX_DENYLIST: usize = 4_096;
/// Имя файла запрета в каталоге шарда.
pub const FILE: &str = "denylist.bin";
const MAGIC: [u8; 8] = *b"VECDHTNL";
const VERSION: u16 = 1;
const KEY_LEN: usize = 32;
/// Фиксированная часть до ключей: magic + версия + count.
const FIXED_LEN: usize = 8 + 2 + 4;
const TAG_LEN: usize = 4;
/// Весь служебный объём файла при пустом списке: 14 + 4 = 18 байт, и цена списка — `18 + 32·N`.
const OVERHEAD: usize = FIXED_LEN + TAG_LEN;

/// Причина, по которой узел не открывается или не может записать список.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DenylistError {
    /// Файл есть, но он не список запрета: обрезан, подправлен, чужая версия или битый tag.
    #[error("файл запрета не читается как список: {0}")]
    Corrupt(String),
    /// Ошибка самой файловой системы (нет места, каталог снят, права).
    #[error("файл запрета не записать: {0}")]
    Io(String),
}

impl From<std::io::Error> for DenylistError {
    fn from(e: std::io::Error) -> Self {
        DenylistError::Io(e.to_string())
    }
}

/// Путь файла в каталоге шарда.
pub fn path(dir: &Path) -> PathBuf {
    dir.join(FILE)
}

/// Байты файла для данного множества. Пустое множество кодируется корректно (заголовок и tag без
/// payload), но [`save`] вызывается только при изменении, поэтому «пустой» узел без файла и
/// «пустой» узел с файлом — одно и то же состояние.
pub fn encode(keys: &BTreeSet<Addr>) -> Vec<u8> {
    let mut out = Vec::with_capacity(OVERHEAD + KEY_LEN * keys.len());
    out.extend_from_slice(&MAGIC);
    out.extend_from_slice(&VERSION.to_le_bytes());
    // count не влезает в u32 только при 2^32 ключей, а предел — 4096 (или больше ровно на
    // столько, насколько больше принёс файл); saturate здесь безопаснее паники в узле.
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
pub fn decode(bytes: &[u8]) -> Result<Vec<Addr>, DenylistError> {
    if bytes.len() < OVERHEAD {
        return Err(DenylistError::Corrupt(format!(
            "файл короче заголовка с tag: {} байт",
            bytes.len()
        )));
    }
    if bytes[..MAGIC.len()] != MAGIC {
        return Err(DenylistError::Corrupt(
            "magic не VECDHTNL: файл не список запрета".to_string(),
        ));
    }
    let version = u16::from_le_bytes([bytes[8], bytes[9]]);
    if version != VERSION {
        return Err(DenylistError::Corrupt(format!(
            "версия списка {version}, узел понимает только {VERSION}"
        )));
    }
    let count = u32::from_le_bytes([bytes[10], bytes[11], bytes[12], bytes[13]]) as usize;
    let body = FIXED_LEN + KEY_LEN * count;
    let want = body + TAG_LEN;
    if bytes.len() != want {
        return Err(DenylistError::Corrupt(format!(
            "длина файла {} не равна 18 + 32·count ({want}) при count={count}",
            bytes.len()
        )));
    }
    let h = blake3::hash(&bytes[..body]);
    if bytes[body..want] != h.as_bytes()[..TAG_LEN] {
        return Err(DenylistError::Corrupt(
            "битая контрольная сумма: файл обрезан или подправлен".to_string(),
        ));
    }
    let mut keys = Vec::with_capacity(count);
    for i in 0..count {
        let at = FIXED_LEN + KEY_LEN * i;
        let mut k: Addr = [0u8; 32];
        k.copy_from_slice(&bytes[at..at + KEY_LEN]);
        keys.push(k);
    }
    if keys.windows(2).any(|w| w[0] >= w[1]) {
        return Err(DenylistError::Corrupt(
            "ключи в файле не упорядочены или повторяются".to_string(),
        ));
    }
    Ok(keys)
}

/// Прочитать список из каталога. `Ok(None)` — файла нет (первое открытие шарда); `Err` — файл
/// есть и он не список запрета: вызывающий обязан не открыть узел.
pub fn load(dir: &Path) -> Result<Option<Vec<Addr>>, DenylistError> {
    let p = path(dir);
    match std::fs::read(&p) {
        Ok(bytes) => decode(&bytes).map(Some),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// Записать список: partial → fsync файла → rename → fsync каталога. Тот же барьер, что у цепочки
/// членства (`node::persist`) и у снапшота (§10.4): `.bin` появляется целиком или не появляется
/// вовсе, полураспавшийся файл не виден следующим открытием.
pub fn save(dir: &Path, keys: &BTreeSet<Addr>) -> Result<(), DenylistError> {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn key(i: usize) -> Addr {
        let mut k = [0u8; 32];
        k[0] = 199;
        k[24..].copy_from_slice(&(i as u64).to_le_bytes());
        k
    }

    fn keys(n: usize) -> BTreeSet<Addr> {
        (0..n).map(key).collect()
    }

    #[test]
    fn the_price_is_exactly_eighteen_plus_thirty_two_per_key() {
        // Тот же расчёт, что в гейте (2) оракула: цена переживаемости — заголовок и ключи,
        // ничего сверх.
        for n in [0usize, 1, 3, 4_096] {
            let got = encode(&keys(n)).len();
            assert_eq!(got, OVERHEAD + KEY_LEN * n, "размер файла при N={n}");
        }
    }

    #[test]
    fn roundtrip_through_the_filesystem_preserves_the_set() {
        let d = vecdht_index::testing::dir("deny-codec");
        let k = keys(3);
        save(&d, &k).expect("записать список");
        let got = load(&d).expect("прочитать список").expect("файл есть");
        assert_eq!(got.len(), 3);
        assert_eq!(got[2], key(2), "порядок и состав совпадают");
        assert_eq!(std::fs::metadata(path(&d)).unwrap().len(), 114);
        vecdht_index::testing::remove(&d);
    }

    #[test]
    fn no_corruption_of_the_file_ever_decodes_to_an_empty_list() {
        // Теорема модели Lean `corrupt_file_is_never_empty` на настоящем формате: единственный
        // способ получить пустое множество — записать пустое.
        let good = encode(&keys(3));
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
        // Отдельно от перебора выше: сюда попадают поля, которые сами обещают состояние, которого
        // в payload нет, и обрезанный хвост от целого tag их не ловит.
        let mut good = encode(&keys(3));
        good[10] = 4; // count = 4 при трёх ключах, длина файла прежняя
        assert!(matches!(decode(&good), Err(DenylistError::Corrupt(_))));

        // Тот же трюк с честной длиной и пересчитанным tag: два одинаковых ключа подряд.
        let one = key(0);
        let mut dup = Vec::new();
        dup.extend_from_slice(&MAGIC);
        dup.extend_from_slice(&VERSION.to_le_bytes());
        dup.extend_from_slice(&2u32.to_le_bytes());
        dup.extend_from_slice(&one);
        dup.extend_from_slice(&one);
        let h = blake3::hash(&dup);
        dup.extend_from_slice(&h.as_bytes()[..TAG_LEN]);
        assert!(matches!(decode(&dup), Err(DenylistError::Corrupt(_))));
    }
}
