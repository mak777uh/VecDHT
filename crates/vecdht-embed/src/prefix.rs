//! Instruction-prefix как часть контракта (§6.2 шаг 2, §6.7).
//!
//! Порядок фиксирован: сначала нормализация (§6.6), потом префикс. Префикс **не** участвует ни в
//! `intent_text_hash`, ни в ключе кеша, ни в подписи автора: те берут шаг 1. Если бы префикс
//! входил в хеш текста, две модели с разными карточными префиксами давали бы разные идентификаторы
//! для одного и того же интента, а §6.5 отводит идентификаторам роль идемпотентности, а не
//! «отпечатка модели».
//!
//! Разделитель не добавляется: префикс берётся из манифеста дословно (§6.7), и вставка пробела или
//! переноса здесь означала бы токенизацию не тех байтов, которые запинены `tokenizer_blake3`.

use thiserror::Error;
use unicode_normalization::UnicodeNormalization;

use vecdht_artifact::Manifest;

/// Разумный предел длины префикса: он входит в `max_length=256` токенов вместе с текстом, и
/// манифест с килобайтным «префиксом» — это опечатка в артефакте, а не контракт.
pub const MAX_PREFIX_BYTES: usize = 256;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PrefixError {
    #[error("префикс `{field}` содержит перевод строки или control-символ (§6.6: одна строка)")]
    NotOneLine { field: &'static str },
    #[error("префикс `{field}` не в NFC — артефакт обязан хранить его канонически")]
    NotNormalized { field: &'static str },
    #[error("префикс `{field}` длиннее {MAX_PREFIX_BYTES} байт ({got})")]
    TooLong { field: &'static str, got: usize },
    #[error("префикс intent_prefix обязан быть пустым: индексирование идёт без префикса (§6.7), а манифест даёт `{got:?}`")]
    IntentPrefixMustBeEmpty { got: String },
}

/// Префиксы, которые объявил артефакт. Оба поля уже проверены, поэтому `apply_*` не возвращают
/// ошибку: решение о том, что артефакт испорчен, принимается один раз при загрузке.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PrefixPolicy {
    /// Всегда пуст для v1 (§6.7); поле есть, чтобы смена контракта была видна в типе.
    pub intent_prefix: String,
    /// Карточный query-префикс модели, дословно.
    pub query_prefix: String,
}

impl PrefixPolicy {
    /// Из манифеста артефакта, с проверкой обоих префиксов. Узел и агент вызывают это на одном и
    /// том же `artifact_hash`, поэтому расхождение «у тебя в манифесте перенос строки» не может
    /// превратиться в тихую разницу векторов (§6.7 про `MODEL_MISMATCH`).
    pub fn from_manifest(m: &Manifest) -> Result<Self, PrefixError> {
        check_shape("intent_prefix", &m.intent_prefix)?;
        check_shape("query_prefix", &m.query_prefix)?;
        if !m.intent_prefix.is_empty() {
            return Err(PrefixError::IntentPrefixMustBeEmpty { got: m.intent_prefix.clone() });
        }
        Ok(Self { intent_prefix: m.intent_prefix.clone(), query_prefix: m.query_prefix.clone() })
    }

    /// Текст интента на вход модели: без префикса (§6.7). Отдельный метод, а не `&str`, потому
    /// что вызывающий код обязан пройти через контракт, а не «сам решить, что publish'у префикс
    /// не нужен».
    pub fn apply_index<'a>(&self, canonical: &'a str) -> &'a str {
        debug_assert!(self.intent_prefix.is_empty(), "проверено в from_manifest");
        canonical
    }

    /// Текст запроса на вход модели: `query_prefix ‖ canonical` дословно.
    pub fn apply_query(&self, canonical: &str) -> String {
        let mut s = String::with_capacity(self.query_prefix.len() + canonical.len());
        s.push_str(&self.query_prefix);
        s.push_str(canonical);
        s
    }

    /// Пустая политика — для тестов и для модели без query-префикса. `from_manifest` остаётся
    /// единственным путём, которым политика попадает в рабочий код.
    pub fn none() -> Self {
        Self::default()
    }
}

/// Структурная проверка строки из манифеста. Она не чинит префикс (NFC к уже испорченному файлу —
/// это подделка артефакта), а отказывает.
fn check_shape(field: &'static str, s: &str) -> Result<(), PrefixError> {
    if s.chars().any(|c| c.is_control() || c == '\u{2028}' || c == '\u{2029}') {
        return Err(PrefixError::NotOneLine { field });
    }
    if !s.nfc().eq(s.chars()) {
        return Err(PrefixError::NotNormalized { field });
    }
    if s.len() > MAX_PREFIX_BYTES {
        return Err(PrefixError::TooLong { field, got: s.len() });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use vecdht_artifact::reference_manifest;

    fn manifest_with(intent: &str, query: &str) -> Manifest {
        let mut m = reference_manifest();
        m.intent_prefix = intent.into();
        m.query_prefix = query.into();
        m
    }

    #[test]
    fn reference_manifest_has_no_prefixes_yet() {
        // Приложение B пинит пустые префиксы: гранитный query-префикс приедет вместе с весами на
        // P0, и до этого момента контракт обязан быть честным — пустая строка, а не выдуманная.
        let p = PrefixPolicy::from_manifest(&reference_manifest()).unwrap();
        assert_eq!(p, PrefixPolicy::none());
    }

    #[test]
    fn query_prefix_is_applied_verbatim_without_separator() {
        let m = manifest_with("", "Query: ");
        let p = PrefixPolicy::from_manifest(&m).unwrap();
        assert_eq!(p.apply_query("ищу партнёра"), "Query: ищу партнёра");
        // Пустой префикс — идентичность, а не «добавили пробел».
        assert_eq!(PrefixPolicy::none().apply_query("ищу партнёра"), "ищу партнёра");
    }

    #[test]
    fn index_side_is_identity_and_never_sees_the_query_prefix() {
        let m = manifest_with("", "Query: ");
        let p = PrefixPolicy::from_manifest(&m).unwrap();
        assert_eq!(p.apply_index("ищу партнёра"), "ищу партнёра");
        // Префикс не входит в идентификатор текста: он часть шага 2 пайплайна, а `intent_text_hash`
        // и подпись автора (§6.6) считаются над шагом 1.
        use vecdht_crypto::ids::intent_text_hash;
        assert_eq!(
            intent_text_hash(p.apply_index("ищу партнёра").as_bytes()),
            intent_text_hash("ищу партнёра".as_bytes())
        );
        assert_ne!(
            intent_text_hash(p.apply_query("ищу партнёра").as_bytes()),
            intent_text_hash("ищу партнёра".as_bytes()),
            "query-префикс меняет байты, уходящие в модель, — и только"
        );
    }

    #[test]
    fn intent_prefix_is_refused_not_applied() {
        // §6.7: publish обязан быть без префикса. Манифест, объявляющий обратное, — это другая
        // генерация preprocessing, и молча применить её значило бы потерять пункты качества
        // (в спеке измерено: 48.0 -> 51.9 на разнице «с префиксом / без»).
        let err = PrefixPolicy::from_manifest(&manifest_with("Index: ", "")).unwrap_err();
        assert_eq!(
            err,
            PrefixError::IntentPrefixMustBeEmpty { got: "Index: ".into() }
        );
    }

    #[test]
    fn malformed_prefixes_are_rejected() {
        assert_eq!(
            PrefixPolicy::from_manifest(&manifest_with("", "a\nb")).unwrap_err(),
            PrefixError::NotOneLine { field: "query_prefix" }
        );
        assert_eq!(
            PrefixPolicy::from_manifest(&manifest_with("", "a\u{7}b")).unwrap_err(),
            PrefixError::NotOneLine { field: "query_prefix" }
        );
        let long = "x".repeat(MAX_PREFIX_BYTES + 1);
        assert_eq!(
            PrefixPolicy::from_manifest(&manifest_with("", &long)).unwrap_err(),
            PrefixError::TooLong { field: "query_prefix", got: MAX_PREFIX_BYTES + 1 }
        );
    }

    #[test]
    fn non_nfc_prefix_is_refused() {
        // Разложенный «e + U+0301»: сворачивание в NFC меняет байты, значит артефакт хранит
        // неканоническую строку и её нельзя сравнить с pinned хешем.
        let raw = "Query: Re\u{301}sume ";
        assert_ne!(raw.nfc().collect::<String>(), raw, "пример обязан быть разложенным");
        assert_eq!(
            PrefixPolicy::from_manifest(&manifest_with("", raw)).unwrap_err(),
            PrefixError::NotNormalized { field: "query_prefix" }
        );
        let canon: String = raw.nfc().collect();
        assert!(PrefixPolicy::from_manifest(&manifest_with("", &canon)).is_ok());
    }
}
