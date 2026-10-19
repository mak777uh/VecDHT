//! Канонический JSON для `manifest.json` (спека §15.1).
//!
//! Manifest сети — consensus-материал: его байты идут в `artifact_hash` и в подпись авторитета.
//! Поэтому парсер здесь не «удобный», а строгий и единственный:
//!
//! * числа только целые (`i64`), без точки, экспоненты, ведущего нуля и `+`: float в подписанном
//!   материале означал бы расхождение хеша между платформами, а §6 как раз затем и убирает
//!   плавающую точку из consensus-path;
//! * ключи объекта обязаны идти в фиксированном порядке и без дублей: §15.1 описывает схему,
//!   а не произвольный набор полей;
//! * `decode` после разбора пересобирает байты и сверяет их с входом. Это тот же инвариант
//!   каноничности, что и в фаззере декодера (§5.1): принятые байты обязывают быть собой.
//!
//! Никакого `serde_json`: у него порядок ключей в `Map` зависит от feature'ы, и полагаться на
//! «как-нибудь сериализуется» в месте, где байты подписываются, нельзя.

use std::fmt::Write as _;

/// Значение канонического JSON. `Obj` сохраняет порядок ключей таким, каким он задан схемой.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Json {
    Null,
    Bool(bool),
    Int(i64),
    Str(String),
    Arr(Vec<Json>),
    Obj(Vec<(String, Json)>),
}

impl Json {
    /// Байты канонической формы: без пробелов, ключи в порядке хранения.
    pub fn render(&self) -> Vec<u8> {
        let mut s = String::new();
        self.write(&mut s);
        s.into_bytes()
    }

    fn write(&self, out: &mut String) {
        match self {
            Json::Null => out.push_str("null"),
            Json::Bool(true) => out.push_str("true"),
            Json::Bool(false) => out.push_str("false"),
            Json::Int(v) => out.push_str(&v.to_string()),
            Json::Str(v) => write_string(out, v),
            Json::Arr(items) => {
                out.push('[');
                for (i, it) in items.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    it.write(out);
                }
                out.push(']');
            }
            Json::Obj(fields) => {
                out.push('{');
                for (i, (k, v)) in fields.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    write_string(out, k);
                    out.push(':');
                    v.write(out);
                }
                out.push('}');
            }
        }
    }

    /// Объект с полями в фиксированном порядке; `None`-значения не пишутся вовсе (отсутствующий
    /// ключ и ключ с `null` — разные байты, и схема это различает).
    pub fn obj(fields: Vec<(&str, Option<Json>)>) -> Json {
        Json::Obj(
            fields
                .into_iter()
                .filter_map(|(k, v)| v.map(|v| (k.to_string(), v)))
                .collect(),
        )
    }

    pub fn int(v: i64) -> Json {
        Json::Int(v)
    }

    pub fn string(v: impl Into<String>) -> Json {
        Json::Str(v.into())
    }

    pub fn bool(v: bool) -> Json {
        Json::Bool(v)
    }

    pub fn as_int(&self) -> Option<i64> {
        match self {
            Json::Int(v) => Some(*v),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Json::Str(v) => Some(v.as_str()),
            _ => None,
        }
    }

    pub fn as_arr(&self) -> Option<&[Json]> {
        match self {
            Json::Arr(v) => Some(v.as_slice()),
            _ => None,
        }
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum JsonError {
    #[error("пустой вход")]
    Empty,
    #[error("нечитаемые байты (не UTF-8) на позиции {0}")]
    NotUtf8(usize),
    #[error("ожиданное значение отсутствует на позиции {0}")]
    UnexpectedEof(usize),
    #[error("лишние символы после значения на позиции {0}")]
    Trailing(usize),
    #[error("неканоническое число на позиции {0}: только целые, без `.`/`e`/`+`/ведущего нуля")]
    Number(usize),
    #[error("число вне диапазона i64 на позиции {0}")]
    NumberRange(usize),
    #[error("неканонический escape на позиции {0}")]
    Escape(usize),
    #[error("неподписанный суррогат или невалидный скаляр на позиции {0}")]
    Surrogate(usize),
    #[error("сырой управляющий символ в строке на позиции {0}")]
    ControlChar(usize),
    #[error("дублирующийся ключ `{0}`")]
    DuplicateKey(String),
    #[error("ключи объекта обязаны быть строкой (позиция {0})")]
    KeyType(usize),
    #[error("в объекте нет поля `{0}`")]
    MissingField(String),
    #[error("ожидался символ `{expected}` на позиции {pos}, найден `{found}`")]
    Expected { pos: usize, expected: char, found: char },
    #[error("вход не в канонической форме: {0} байт против {1} у пересборки")]
    NotCanonical(usize, usize),
    #[error("вход не в канонической форме: байт {at} расходится")]
    NotCanonicalByte { at: usize },
}

/// Разбор с последующей проверкой каноничности: `{ "a" : 1 }` не принимается, хотя синтаксически
/// это валидный JSON.
pub fn parse(bytes: &[u8]) -> Result<Json, JsonError> {
    let value = parse_value(bytes)?;
    let canon = value.render();
    if canon.len() != bytes.len() {
        return Err(JsonError::NotCanonical(bytes.len(), canon.len()));
    }
    for (i, (a, b)) in bytes.iter().zip(canon.iter()).enumerate() {
        if a != b {
            return Err(JsonError::NotCanonicalByte { at: i });
        }
    }
    Ok(value)
}

struct P<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> P<'a> {
    fn peek(&self) -> Result<u8, JsonError> {
        self.b.get(self.i).copied().ok_or(JsonError::UnexpectedEof(self.i))
    }
    fn skip_ws(&mut self) {
        // Каноническая форма пробелов не содержит, поэтому whitespace допускается только внутри
        // строк; сюда приходим лишь за тем, чтобы ошибка была на нужной позиции.
        while matches!(self.b.get(self.i), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.i += 1;
        }
    }
    fn eat(&mut self, c: u8) -> Result<(), JsonError> {
        self.skip_ws();
        if self.peek()? == c {
            self.i += 1;
            Ok(())
        } else {
            Err(JsonError::Expected {
                pos: self.i,
                expected: c as char,
                found: self.peek()? as char,
            })
        }
    }
    fn lit(&mut self, word: &str) -> Result<(), JsonError> {
        if self.b[self.i..].starts_with(word.as_bytes()) {
            self.i += word.len();
            Ok(())
        } else {
            Err(JsonError::Expected {
                pos: self.i,
                expected: word.chars().next().unwrap(),
                found: self.peek()? as char,
            })
        }
    }
}

fn parse_value(bytes: &[u8]) -> Result<Json, JsonError> {
    if bytes.is_empty() {
        return Err(JsonError::Empty);
    }
    let mut p = P { b: bytes, i: 0 };
    let v = p.value()?;
    p.skip_ws();
    if p.i != bytes.len() {
        return Err(JsonError::Trailing(p.i));
    }
    Ok(v)
}

impl P<'_> {
    fn value(&mut self) -> Result<Json, JsonError> {
        self.skip_ws();
        match self.peek()? {
            b'{' => self.object(),
            b'[' => self.array(),
            b'"' => Ok(Json::Str(self.string()?)),
            b't' => {
                self.lit("true")?;
                Ok(Json::Bool(true))
            }
            b'f' => {
                self.lit("false")?;
                Ok(Json::Bool(false))
            }
            b'n' => {
                self.lit("null")?;
                Ok(Json::Null)
            }
            b'-' | b'0'..=b'9' => self.number(),
            c => Err(JsonError::Expected {
                pos: self.i,
                expected: 'v',
                found: c as char,
            }),
        }
    }

    fn number(&mut self) -> Result<Json, JsonError> {
        let start = self.i;
        if self.peek()? == b'-' {
            self.i += 1;
        }
        let digits_start = self.i;
        while matches!(self.peek(), Ok(b'0'..=b'9')) {
            self.i += 1;
        }
        if self.i == digits_start {
            return Err(JsonError::Number(start));
        }
        if matches!(self.peek(), Ok(b'.' | b'e' | b'E')) {
            return Err(JsonError::Number(start));
        }
        let text = std::str::from_utf8(&self.b[start..self.i])
            .map_err(|_| JsonError::NotUtf8(start))?;
        let digits = &text[digits_start - start..];
        if digits.len() > 1 && digits.starts_with('0') {
            return Err(JsonError::Number(start));
        }
        text.parse::<i64>()
            .map_err(|_| JsonError::NumberRange(start))
            .map(Json::Int)
    }

    fn string(&mut self) -> Result<String, JsonError> {
        self.eat(b'"')?;
        let mut out = String::new();
        loop {
            let c = self.peek()?;
            match c {
                b'"' => {
                    self.i += 1;
                    return Ok(out);
                }
                b'\\' => {
                    self.i += 1;
                    let e = self.peek()?;
                    let pos = self.i;
                    self.i += 1;
                    match e {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{8}'),
                        b'f' => out.push('\u{c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => out.push(self.unicode_escape(pos)?),
                        _ => return Err(JsonError::Escape(pos)),
                    }
                }
                0x00..=0x1f => return Err(JsonError::ControlChar(self.i)),
                _ => {
                    // Копируем целый UTF-8 скаляр: байты >= 0x80 невалидны поодиночке.
                    let start = self.i;
                    let len = utf8_len(c).ok_or(JsonError::NotUtf8(start))?;
                    if self.b.len() < start + len {
                        return Err(JsonError::UnexpectedEof(start));
                    }
                    let chunk = &self.b[start..start + len];
                    let s = std::str::from_utf8(chunk).map_err(|_| JsonError::NotUtf8(start))?;
                    out.push_str(s);
                    self.i += len;
                }
            }
        }
    }

    /// `\uXXXX` в канонической форме встречается только для управляющих символов, для которых
    /// нет короткого escape'а; суррогатные пары и латиница выше 0x7f здесь — ошибка.
    fn unicode_escape(&mut self, pos: usize) -> Result<char, JsonError> {
        let cp = self.hex4(pos)?;
        if cp >= 0x20 || matches!(cp, 0x08 | 0x09 | 0x0a | 0x0c | 0x0d) {
            return Err(JsonError::Escape(pos));
        }
        char::from_u32(cp).ok_or(JsonError::Surrogate(pos))
    }

    fn hex4(&mut self, pos: usize) -> Result<u32, JsonError> {
        if self.b.len() < self.i + 4 {
            return Err(JsonError::UnexpectedEof(self.i));
        }
        let mut v = 0u32;
        for _ in 0..4 {
            let c = self.b[self.i];
            let d = match c {
                b'0'..=b'9' => (c - b'0') as u32,
                b'a'..=b'f' => (c - b'a' + 10) as u32,
                _ => return Err(JsonError::Escape(pos)),
            };
            v = v * 16 + d;
            self.i += 1;
        }
        Ok(v)
    }

    fn array(&mut self) -> Result<Json, JsonError> {
        self.eat(b'[')?;
        let mut items = Vec::new();
        self.skip_ws();
        if self.peek()? == b']' {
            self.i += 1;
            return Ok(Json::Arr(items));
        }
        loop {
            items.push(self.value()?);
            self.skip_ws();
            match self.peek()? {
                b',' => {
                    self.i += 1;
                }
                b']' => {
                    self.i += 1;
                    return Ok(Json::Arr(items));
                }
                c => {
                    return Err(JsonError::Expected {
                        pos: self.i,
                        expected: ']',
                        found: c as char,
                    })
                }
            }
        }
    }

    fn object(&mut self) -> Result<Json, JsonError> {
        self.eat(b'{')?;
        let mut fields: Vec<(String, Json)> = Vec::new();
        self.skip_ws();
        if self.peek()? == b'}' {
            self.i += 1;
            return Ok(Json::Obj(fields));
        }
        loop {
            self.skip_ws();
            if self.peek()? != b'"' {
                return Err(JsonError::KeyType(self.i));
            }
            let key = self.string()?;
            if fields.iter().any(|(k, _)| *k == key) {
                return Err(JsonError::DuplicateKey(key));
            }
            self.eat(b':')?;
            let value = self.value()?;
            fields.push((key, value));
            self.skip_ws();
            match self.peek()? {
                b',' => {
                    self.i += 1;
                }
                b'}' => {
                    self.i += 1;
                    return Ok(Json::Obj(fields));
                }
                c => {
                    return Err(JsonError::Expected {
                        pos: self.i,
                        expected: '}',
                        found: c as char,
                    })
                }
            }
        }
    }
}

fn utf8_len(first: u8) -> Option<usize> {
    match first {
        0x00..=0x7f => Some(1),
        0xc2..=0xdf => Some(2),
        0xe0..=0xef => Some(3),
        0xf0..=0xf4 => Some(4),
        _ => None,
    }
}

/// Экранирование в канонической форме: `"` и `\` всегда, управляющие — через `\u00xx`,
/// остальное идёт как есть (UTF-8). Остаток — `\b \f \n \r \t`, где они короче.
fn write_string(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// Достаёт поле из объекта по имени, помня, что порядок фиксирован схемой.
pub fn field<'a>(obj: &'a Json, name: &str) -> Result<&'a Json, JsonError> {
    match obj {
        Json::Obj(fields) => match fields.iter().find(|(k, _)| k == name) {
            Some((_, v)) => Ok(v),
            None => Err(JsonError::MissingField(name.to_string())),
        },
        _ => Err(JsonError::MissingField(name.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn j(v: &str) -> Json {
        parse(v.as_bytes()).unwrap()
    }

    #[test]
    fn canonical_round_trip_is_exact() {
        let doc = Json::obj(vec![
            ("a", Some(Json::int(1))),
            ("b", Some(Json::string("x"))),
            ("c", Some(Json::Arr(vec![Json::bool(true), Json::Null]))),
            ("d", None),
        ]);
        let bytes = doc.render();
        assert_eq!(bytes, br#"{"a":1,"b":"x","c":[true,null]}"#);
        assert_eq!(parse(&bytes).unwrap(), doc);
    }

    #[test]
    fn negative_and_boundary_integers() {
        assert_eq!(j("-1").as_int(), Some(-1));
        assert_eq!(j(&i64::MIN.to_string()).as_int(), Some(i64::MIN));
        assert_eq!(j(&i64::MAX.to_string()).as_int(), Some(i64::MAX));
    }

    #[test]
    fn floats_and_non_canonical_numbers_rejected() {
        for bad in ["1.0", "1e3", "01", "-01", "0.5", "1E+2", "99999999999999999999999"] {
            assert!(
                matches!(
                    parse(bad.as_bytes()),
                    Err(JsonError::Number(_)) | Err(JsonError::NumberRange(_))
                ),
                "{bad} принят как число"
            );
        }
        // `+1` — это не число, а символ, которым значение в JSON вообще не может начаться.
        // Ошибка здесь про «ожидалось значение», а не про формат числа: важен инвариант
        // «неканонические байты не принимаются», а не то, каким именно текстом она пришла.
        assert!(matches!(
            parse(b"+1"),
            Err(JsonError::Expected {
                pos: 0,
                found: '+',
                ..
            })
        ));
        // Одинокий ноль — каноничен.
        assert_eq!(j("0").as_int(), Some(0));
    }

    #[test]
    fn whitespace_and_trailing_content_rejected() {
        assert!(matches!(parse(b" 1").unwrap_err(), JsonError::NotCanonical(2, 1)));
        assert!(matches!(parse(b"1 ").unwrap_err(), JsonError::NotCanonical(2, 1)));
        // Байт после закрывающей скобки — лишний, и позиция в ошибке это индекс именно он.
        assert!(matches!(parse(br#"{"a":1}x"#).unwrap_err(), JsonError::Trailing(7)));
        assert!(matches!(parse(b"{\"a\": 1}").unwrap_err(), JsonError::NotCanonical(8, 7)));
        assert!(matches!(parse(b"").unwrap_err(), JsonError::Empty));
        assert_eq!(parse(b"[]").unwrap(), Json::Arr(vec![]));
        assert_eq!(parse(b"{}").unwrap(), Json::Obj(vec![]));
    }

    #[test]
    fn duplicate_keys_and_bad_escapes_rejected() {
        assert!(matches!(
            parse(br#"{"a":1,"a":2}"#).unwrap_err(),
            JsonError::DuplicateKey(k) if k == "a"
        ));
        for bad in [
            r#""a\x41""#,
            r#""a\q""#,
            r#""a\u0041""#,
            r#""a\u00e9""#,
            "\"a\u{7}\u{7}b\"",
        ] {
            assert!(parse(bad.as_bytes()).is_err(), "{bad} принят");
        }
        // Управляющий символ экранирован канонически — принимается и пересобирается в себя.
        assert_eq!(parse(br#""a\u0001""#).unwrap(), Json::Str("a\u{1}".into()));
    }

    #[test]
    fn utf8_passes_through_verbatim() {
        let s = Json::string("найди мне контрагента по rust");
        let bytes = s.render();
        assert_eq!(parse(&bytes).unwrap(), s);
        assert!(String::from_utf8(bytes).unwrap().contains("контрагента"));
    }

    #[test]
    fn field_lookup_and_types() {
        let doc = j(r#"{"a":1,"b":"x"}"#);
        assert_eq!(field(&doc, "a").unwrap().as_int(), Some(1));
        assert_eq!(field(&doc, "b").unwrap().as_str(), Some("x"));
        assert!(field(&doc, "c").is_err());
        assert!(field(&Json::int(1), "a").is_err());
    }
}
