//! Канонический `intent_text` — шаг 1 пайплайна §6.2 и §6.6.
//!
//! Нормализация — не украшение, а часть идентичности записи. На канонической форме считается
//! `intent_text_hash` (§6.5), она уходит в подпись автора (§6.6) и она же — ключ кеша
//! ([`crate::cache`]). Отсюда два правила, которые определяют весь этот модуль:
//!
//! 1. **Идемпотентность.** `normalize_text(normalize_text(x)) == normalize_text(x)`. Если бы
//!    правило зависело от уже нормализованного входа, два агента, копирующие текст друг у друга,
//!    получили бы разные `intent_text_hash` и разные векторы для одного и того же интента.
//! 2. **Никаких тихих переписываний.** NFC, trim и схлопывание пробелов — обратимые до одной
//!    формы правки, и они разрешены. Разрешающая «мардаун-список в прозу» нормализация меняла бы
//!    *содержание*, а не представление, поэтому списки, блоки кода и JSON отбрасываются с
//!    ошибкой: ложное отклонение видно автору и лечится одним переформулированием, а тихая правка
//!    интента — нет.
//!
//! Порядок шагов зафиксирован: NFC → проверка переводов строк и control-символов → схлопывание
//! пробелов → проверка длины. NFC до ограничения длины, потому что composition меняет число
//! байт: 1000 байт до NFC и 1000 байт после NFC — это разные тексты, а лимит (§6.6) контрактный
//! именно для нормализованной формы.

use thiserror::Error;
use unicode_normalization::UnicodeNormalization;

/// Жёсткий лимит UTF-8 канонического текста (§6.6). Тот же символ, что в кодеке сообщений.
pub use vecdht_wire::messages::MAX_INTENT_TEXT_BYTES;

/// Рекомендованный диапазон длины в символах (§6.6). Это рекомендация модели, а не протокола:
/// вне диапазона текст принимается, но агенту стоит показать замечание (§12.1 — слишком короткий
/// интент плохо различим в ANN, слишком длинный съедает `max_length=256` токенов).
pub const RECOMMENDED_MIN_CHARS: usize = 300;
pub const RECOMMENDED_MAX_CHARS: usize = 700;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum TextError {
    #[error("intent_text: после нормализации текст пуст")]
    Empty,
    #[error("intent_text: перевод строки на позиции {0} — интент обязан быть одним абзацем (§6.6)")]
    LineBreak(usize),
    #[error("intent_text: control-символ на позиции {0}")]
    Control(usize),
    #[error("intent_text: markup-конструкция `{0}` — интент публикуется текстом, без markdown (§6.6)")]
    Markup(&'static str),
    #[error("intent_text: структура вместо абзаца (начинается с `{0}`) — JSON и списки не публикуются (§6.6)")]
    Structured(&'static str),
    #[error("intent_text: {bytes} байт после нормализации при лимите {limit} (§6.6)")]
    TooLong { bytes: usize, limit: usize },
}

/// Шаг 1 пайплайна: NFC, отбрасывание переносов и control-символов, trim, схлопывание
/// повторяющихся пробелов, лимит 1000 байт. Возвращает `String` в нормализованной форме — то,
/// что подписывается и кладётся в кеш.
///
/// Позиции в ошибках — в **символах**, а не в байтах: текст показывает человек, который правит
/// его в редакторе, а не в hexdump. Там, где контрактный размер именно байтовый (лимит §6.6),
/// ошибка так и говорит «байт».
pub fn normalize_text(input: &str) -> Result<String, TextError> {
    let nfc: String = input.nfc().collect();

    let mut out = String::with_capacity(nfc.len());
    let mut pending_space = false;
    for (idx, ch) in nfc.chars().enumerate() {
        // Перевод строки проверяется до схлопывания: whitespace-правило проглотило бы его и
        // слило два абзаца в одну строку — то есть сделало бы ровно то, что §6.6 запрещает.
        if matches!(ch, '\n' | '\r' | '\u{2028}' | '\u{2029}') {
            return Err(TextError::LineBreak(idx));
        }
        // TAB — тоже пробельный символ §6.6 («схлопывание повторяющихся пробелов»), а не
        // управляющий: текст с раскладки-таблицы легитимен, и отклонять его значило бы
        // ложное отказывание автору. Остальные C0 (BEL, ESC, U+0000) — мусор или инъекция.
        if ch != '\t' && ch.is_control() {
            return Err(TextError::Control(idx));
        }
        if ch.is_whitespace() {
            // Пробел перед первым словом не ставим: `pending_space` выставляется только когда
            // вывод уже непуст, поэтому leading whitespace отсекается вместе с trim'ом.
            pending_space = !out.is_empty();
            continue;
        }
        if pending_space {
            out.push(' ');
            pending_space = false;
        }
        out.push(ch);
    }

    if out.is_empty() {
        return Err(TextError::Empty);
    }
    check_markup(&out)?;
    if out.len() > MAX_INTENT_TEXT_BYTES {
        return Err(TextError::TooLong { bytes: out.len(), limit: MAX_INTENT_TEXT_BYTES });
    }
    Ok(out)
}

/// True, если строка уже в канонической форме. Проверка, а не предположение: узел принимает
/// `IntentTextResponse` от агента и обязан уметь отличить «автор опубликовал мусор» от «мусор
/// подмешан в пути» (§19.2), не переписывая полученный текст молча.
pub fn is_canonical(text: &str) -> bool {
    matches!(normalize_text(text), Ok(ref c) if *c == text)
}

/// Замечание о длине (§6.6: рекомендация 300–700 символов). Отдельный метод, а не ошибка,
/// потому что рекомендация не является условием валидации.
pub fn length_advice(text: &str) -> Option<LengthAdvice> {
    let chars = text.chars().count();
    if chars < RECOMMENDED_MIN_CHARS {
        Some(LengthAdvice::TooShort(chars))
    } else if chars > RECOMMENDED_MAX_CHARS {
        Some(LengthAdvice::TooLong(chars))
    } else {
        None
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LengthAdvice {
    TooShort(usize),
    TooLong(usize),
}

/// Консервативная проверка на markup/структуру по нормализованной однострочной форме.
///
/// Правило намеренно смотрит только в начало строки и на два символа, которые в прозе не
/// встречаются: `-`, `*`, `#`, `>` и т. п. в середине предложения остаются легитимны (стек-список
/// вида «Rust, C++/CUDA» должен проходить), а markdown-блок или JSON-объект, которые кто-то
/// вставил в интент, отсекаются на входе до инференса — дешевле, чем потом объяснять, почему
/// вектор уехал (§6.1).
fn check_markup(s: &str) -> Result<(), TextError> {
    if s.contains('`') {
        return Err(TextError::Markup("код в backtick"));
    }
    let head = s.chars().next().unwrap_or(' ');
    if matches!(head, '{' | '[') {
        return Err(TextError::Structured("{ или ["));
    }
    if matches!(head, '#' | '>' | '|') {
        return Err(TextError::Markup("заголовок или цитата"));
    }
    // Маркер списка обязателен с пробелом после: дефис в слове («well-known стек») не ловится.
    for marker in ["- ", "* ", "+ ", "\u{2022} ", "1. ", "2. "] {
        if s.starts_with(marker) {
            return Err(TextError::Structured("маркер списка"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(n: usize) -> String {
        // Детерминированно и по-русски: проверка длины должна считать символы, а не байты.
        "ищу контрагента по поиску векторов — ".repeat(n)
    }

    #[test]
    fn normalizes_nfc_and_spaces_and_trims() {
        // «e» + combining acute (U+0301) обязан схлопнуться в precomposed U+00E9.
        let raw = "  Re\u{301}sume\u{0301}   ищет   партнёра  ";
        let got = normalize_text(raw).unwrap();
        assert_eq!(got, "R\u{e9}sum\u{e9} ищет партнёра");
        assert_eq!(got.as_bytes(), "Résumé ищет партнёра".as_bytes());
    }

    #[test]
    fn collapse_uses_unicodewhitespace_not_only_ascii_space() {
        // NBSP и таблица — whitespace: они не должны остаться внутри канонической формы, иначе
        // два визуально одинаковых текста дадут разные `intent_text_hash`.
        assert_eq!(normalize_text("а\u{a0}б\u{9}в").unwrap(), "а б в");
        assert_eq!(normalize_text("  \t\t ").unwrap_err(), TextError::Empty);
    }

    #[test]
    fn normalization_is_idempotent() {
        for raw in [
            "  много   пробелов\tи\tтабуляции ",
            "Re\u{301}sume\u{0301} ищет   партнёра",
            "ищу\n\tконтрагента",
            text(3).as_str(),
        ] {
            let once = normalize_text(raw.replace('\n', " ").as_str()).unwrap();
            let twice = normalize_text(&once).unwrap();
            assert_eq!(once, twice, "normalize_text обязан быть идемпотентным: {raw:?}");
            assert!(is_canonical(&once));
        }
    }

    #[test]
    fn line_break_is_rejected_not_merged() {
        // Ключевое отличие от «мягкой» нормализации: два абзаца — это ошибка автора, а не
        // опечатка, которую можно склеить.
        assert_eq!(normalize_text("первый\nвторой"), Err(TextError::LineBreak(6)));
        assert_eq!(normalize_text("а\r\nб"), Err(TextError::LineBreak(1)));
        assert!(matches!(normalize_text("а\u{2028}б"), Err(TextError::LineBreak(1))));
    }

    #[test]
    fn control_characters_rejected() {
        assert_eq!(normalize_text("а\u{7}б"), Err(TextError::Control(1)));
    }

    #[test]
    fn markup_and_structured_rejected() {
        assert!(matches!(normalize_text("# заголовок"), Err(TextError::Markup(_))));
        assert!(matches!(normalize_text("> цитата"), Err(TextError::Markup(_))));
        assert!(matches!(normalize_text("{\"a\": 1}"), Err(TextError::Structured(_))));
        assert!(matches!(normalize_text("- пункт один"), Err(TextError::Structured(_))));
        assert!(matches!(normalize_text("1. пункт"), Err(TextError::Structured(_))));
        assert!(matches!(normalize_text("текст `code` внутри"), Err(TextError::Markup(_))));
        // А дефис внутри строки и слэш в стеке — легитимный текст.
        assert!(normalize_text("well-known стек: Rust/C++ — ищу партнёра").is_ok());
    }

    #[test]
    fn limit_applies_to_normalized_bytes() {
        let ok = "а".repeat(MAX_INTENT_TEXT_BYTES / 2); // 2 байта на букву
        assert_eq!(normalize_text(&ok).unwrap().len(), MAX_INTENT_TEXT_BYTES);
        let long = "а".repeat(MAX_INTENT_TEXT_BYTES / 2 + 1);
        assert!(matches!(
            normalize_text(&long),
            Err(TextError::TooLong { bytes, limit: MAX_INTENT_TEXT_BYTES })
                if bytes == MAX_INTENT_TEXT_BYTES + 2
        ));
    }

    #[test]
    fn nfc_before_length_check() {
        // Разложенная форма длиннее composed: 500 «e+́» = 1000 байт до NFC, 500 после. Лимит
        // обязан считаться по нормализованной форме, иначе один и тот же текст проходил бы или
        // нет в зависимости от способа ввода.
        let decomposed = "Re\u{301}".repeat(250);
        assert_eq!(decomposed.len(), 1000);
        let canon = normalize_text(&decomposed).unwrap();
        assert_eq!(canon.len(), 750, "NFC применён до проверки лимита");
        assert_eq!(normalize_text(&canon).unwrap(), canon);
    }

    #[test]
    fn length_advice_is_about_characters_not_bytes() {
        // 300 русских букв = 600 байт: если считать байты, рекомендация стала бы «в два раза
        // короче» для нет-ASCII, и русские интенты попадали бы в TooShort молча.
        let short = "a".repeat(RECOMMENDED_MIN_CHARS - 1);
        assert_eq!(length_advice(&short), Some(LengthAdvice::TooShort(RECOMMENDED_MIN_CHARS - 1)));
        let cyr = "а".repeat(RECOMMENDED_MIN_CHARS);
        assert_eq!(cyr.len(), RECOMMENDED_MIN_CHARS * 2);
        assert_eq!(length_advice(&cyr), None);
        let many = "а".repeat(RECOMMENDED_MAX_CHARS + 1);
        assert_eq!(length_advice(&many), Some(LengthAdvice::TooLong(RECOMMENDED_MAX_CHARS + 1)));
    }

    #[test]
    fn empty_input_errors_instead_of_empty_ok() {
        assert_eq!(normalize_text(""), Err(TextError::Empty));
        assert_eq!(normalize_text("   "), Err(TextError::Empty));
    }
}
