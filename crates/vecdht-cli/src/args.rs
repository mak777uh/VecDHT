//! Разбор аргументов без зависимостей (§17.2: в whitelist нет ни `clap`, ни `structopt`).
//!
//! Отказ от фреймворка — не экономия на сборке, а следствие двух уже написанных правил.
//! Первая: CLI оператора обязан собираться там же, где собирается ядро, то есть на
//! `x86_64-pc-windows-gnu` без лишней C-линковки. Вторая: разбор здесь — часть протокольного
//! инструмента, и он должен быть предсказуемо скучным: никаких выведенных подсказок, никакого
//! автодополнения и никаких «может, имелось в виду…», потому что скрипт, который угадал флаг,
//! это скрипт, который однажды выполнит не ту команду.
//!
//! Правила разбора:
//!
//! * путь подкоманды — токены до первого флага (`artifact init --out x`); явный разделитель `--`
//!   тоже принимается и ничему не противоречит;
//! * флаг — `--имя значение` или `--имя=значение`; `--имя` без значения считается булевым;
//! * значение, начинающееся с `--`, передаётся только формой `--имя=значение`;
//! * токен без `--`, стоящий после флагов, — ошибка: позиционных аргументов здесь нет;
//! * подкоманда не длиннее двух токенов; исключение — `help pow mine`, где тема справки сама
//!   является двухтокенной командой;
//! * неизвестный флаг отвергается списком команды, а не игнорируется.

use std::fmt;
use std::str::FromStr;

#[derive(Debug, Clone)]
pub struct Flag {
    pub name: String,
    /// `None` — флаг-переключатель, `Some` — значение.
    pub value: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct Parsed {
    path: Vec<String>,
    flags: Vec<Flag>,
}

impl Parsed {
    /// `argv` — аргументы без имени программы.
    pub fn parse(argv: &[&str]) -> Result<Self, ArgError> {
        let mut p = Parsed::default();
        let mut i = 0usize;
        // Путь собирается, пока не встретился флаг или явный `--`. Оба варианта окончания пути
        // равноправны: требовать `--` значило бы заставлять оператора писать команду, которую
        // нигде в справке не обещали, а `artifact init --out x` читается раньше, чем ломается.
        while i < argv.len() {
            let tok = argv[i];
            if tok == "--" {
                i += 1;
                break;
            }
            if tok.starts_with("--") {
                break;
            }
            p.path.push(tok.to_string());
            i += 1;
        }
        // Три токена дозволено только `help <команда>`, у самой справки тема — двухтокенная
        // команда; для рабочих путей третий токен означал бы, что оператор перепутал команду.
        let max_words = if p.path.first().map(|s| s.as_str()) == Some("help") { 3 } else { 2 };
        if p.path.len() > max_words {
            return Err(ArgError::TooManyWords(p.path.clone()));
        }
        while i < argv.len() {
            let tok = argv[i];
            let Some(rest) = tok.strip_prefix("--") else {
                return Err(ArgError::Positional(tok.to_string()));
            };
            let (name, value) = match rest.split_once('=') {
                Some((n, v)) => (n.to_string(), Some(v.to_string())),
                // Значение — следующий токен, если он не выглядит как флаг.
                None => {
                    let next = argv.get(i + 1).filter(|t| !t.starts_with("--"));
                    match next {
                        Some(v) => {
                            i += 1;
                            (rest.to_string(), Some(v.to_string()))
                        }
                        None => (rest.to_string(), None),
                    }
                }
            };
            if name.is_empty() {
                return Err(ArgError::EmptyFlagPos);
            }
            p.flags.push(Flag { name, value });
            i += 1;
        }
        Ok(p)
    }

    pub fn path(&self) -> &[String] {
        &self.path
    }

    /// Есть ли вообще флаги — нужно диспетчеру: путь пуст, а флаги есть, значит команда не названа.
    pub fn has_flags(&self) -> bool {
        !self.flags.is_empty()
    }

    /// Первый флаг по имени — для сообщения «флаг до подкоманды».
    pub fn first_flag(&self) -> Option<&str> {
        self.flags.first().map(|f| f.name.as_str())
    }

    /// Путь подкоманды одной строкой — для сообщений об ошибках.
    pub fn path_str(&self) -> String {
        if self.path.is_empty() { String::new() } else { self.path.join(" ") }
    }

    fn find_all(&self, name: &str) -> Vec<&Flag> {
        self.flags.iter().filter(|f| f.name == name).collect()
    }

    /// Отклоняет всё, чего команда не объявила. Именно объявленный список, а не «разрешили
    /// что успели забыть»: опечатка в имени флага должна остановить скрипт, а не промолчать.
    pub fn reject_unknown(&self, cmd: &str, allowed: &[&str]) -> Result<(), ArgError> {
        for f in &self.flags {
            if !allowed.contains(&f.name.as_str()) {
                return Err(ArgError::Unknown { cmd: cmd.to_string(), flag: f.name.clone() });
            }
        }
        Ok(())
    }

    /// Переключатель: присутствует без значения.
    pub fn bool_flag(&self, cmd: &str, name: &str) -> Result<bool, ArgError> {
        let hits = self.find_all(name);
        match hits.as_slice() {
            [] => Ok(false),
            [f] => f.value.as_ref().map_or(
                Ok(true),
                |v| Err(ArgError::UnexpectedValue { flag: full(cmd, name), value: v.clone() }),
            ),
            many => Err(ArgError::Duplicated { flag: full(cmd, name), count: many.len() }),
        }
    }

    /// Один флаг со значением.
    pub fn value(&self, cmd: &str, name: &str) -> Result<Option<String>, ArgError> {
        let hits = self.find_all(name);
        match hits.as_slice() {
            [] => Ok(None),
            [f] => match f.value.clone() {
                Some(v) => Ok(Some(v)),
                None => Err(ArgError::NeedsValue { flag: full(cmd, name) }),
            },
            many => Err(ArgError::Duplicated { flag: full(cmd, name), count: many.len() }),
        }
    }

    pub fn required(&self, cmd: &str, name: &str) -> Result<String, ArgError> {
        self.value(cmd, name)?.ok_or_else(|| ArgError::Missing { flag: full(cmd, name) })
    }

    /// Повторяемый флаг (списки: `--authority`, `--intent`).
    pub fn values(&self, cmd: &str, name: &str) -> Result<Vec<String>, ArgError> {
        let mut out = Vec::new();
        for f in self.find_all(name) {
            out.push(
                f.value.clone()
                    .ok_or_else(|| ArgError::NeedsValue { flag: full(cmd, name) })?,
            );
        }
        Ok(out)
    }

    pub fn num<T>(&self, cmd: &str, name: &str) -> Result<Option<T>, ArgError>
    where
        T: FromStr,
        T::Err: fmt::Display,
    {
        match self.value(cmd, name)? {
            None => Ok(None),
            Some(raw) => parse_num(cmd, name, &raw).map(Some),
        }
    }

    pub fn num_or<T>(&self, cmd: &str, name: &str, default: T) -> Result<T, ArgError>
    where
        T: FromStr,
        T::Err: fmt::Display,
    {
        Ok(self.num(cmd, name)?.unwrap_or(default))
    }

    /// Строгий hex: ровно `2N` строчных `[0-9a-f]`. Заглавные отвергаются по той же причине, по
    /// которой их отвергает `Manifest::decode` (§15.1.5): `hex::decode` их принимает, а
    /// `hex::encode` отдаёт строчные, значит принятая заглавная буква не пересобралась бы в те же
    /// байты, и документ с ней стал бы другим после нормализации.
    pub fn hex_fixed<const N: usize>(&self, cmd: &str, name: &str) -> Result<Option<[u8; N]>, ArgError> {
        match self.value(cmd, name)? {
            None => Ok(None),
            Some(raw) => parse_hex(cmd, name, &raw).map(Some),
        }
    }

    pub fn hex_or<const N: usize>(
        &self,
        cmd: &str,
        name: &str,
        default: [u8; N],
    ) -> Result<[u8; N], ArgError> {
        Ok(self.hex_fixed(cmd, name)?.unwrap_or(default))
    }
}

fn full(cmd: &str, name: &str) -> String {
    if cmd.is_empty() {
        format!("--{name}")
    } else {
        format!("{cmd} --{name}")
    }
}

pub fn parse_num<T>(cmd: &str, name: &str, raw: &str) -> Result<T, ArgError>
where
    T: FromStr,
    T::Err: fmt::Display,
{
    raw.parse::<T>().map_err(|e| ArgError::BadNumber {
        flag: full(cmd, name),
        value: raw.to_string(),
        detail: e.to_string(),
    })
}

/// Hex переменной длины — для дампов кадров, где длина известна только из заголовка. Те же два
/// правила, что и у `parse_hex`: строчные символы и чётная длина. Нечётная длина отсекается
/// здесь, а не в `hex::decode`, потому что иначе «кадр из 5 hex-символов» выглядел бы как
/// испорченный протокол, а не как опечатка в терминале.
pub fn parse_hex_bytes(cmd: &str, name: &str, raw: &str) -> Result<Vec<u8>, ArgError> {
    if !raw.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        return Err(ArgError::BadHex { flag: full(cmd, name), value: raw.to_string() });
    }
    if raw.len() % 2 != 0 {
        return Err(ArgError::HexOddLength {
            flag: full(cmd, name),
            value: raw.to_string(),
            len: raw.len(),
        });
    }
    hex::decode(raw).map_err(|_| ArgError::BadHex { flag: full(cmd, name), value: raw.to_string() })
}

pub fn parse_hex<const N: usize>(cmd: &str, name: &str, raw: &str) -> Result<[u8; N], ArgError> {
    if !raw.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        return Err(ArgError::BadHex { flag: full(cmd, name), value: raw.to_string() });
    }
    if raw.len() != 2 * N {
        return Err(ArgError::HexLength {
            flag: full(cmd, name),
            value: raw.to_string(),
            want: 2 * N,
        });
    }
    let bytes = hex::decode(raw)
        .map_err(|_| ArgError::BadHex { flag: full(cmd, name), value: raw.to_string() })?;
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    Ok(out)
}

#[derive(Debug, thiserror::Error)]
pub enum ArgError {
    #[error("пустой флаг `--`")]
    EmptyFlagPos,
    #[error("лишний аргумент `{0}`: после флагов позиционные аргументы не принимаются")]
    Positional(String),
    #[error("флаг `--{0}` стоит до подкоманды: сначала путь (`artifact init`), потом флаги")]
    FlagBeforeCommand(String),
    #[error("слишком длинная подкоманда: {} токенов (не больше двух, а у `help` — трёх: тема справки сама может быть двухсловной)", .0.len())]
    TooManyWords(Vec<String>),
    #[error("`{cmd}` не знает флага `--{flag}`")]
    Unknown { cmd: String, flag: String },
    #[error("команда `{0}` не существует, см. `help`")]
    UnknownCommand(String),
    #[error("флаг `{flag}` не принимает значение `{value}`")]
    UnexpectedValue { flag: String, value: String },
    #[error("флаг `{flag}` указан {count} раз: повтор для одного и того же флага — ошибка, а не «последнее выигрывает»")]
    Duplicated { flag: String, count: usize },
    #[error("флаг `{flag}` требует значения")]
    NeedsValue { flag: String },
    #[error("не указан обязательный флаг `{flag}`")]
    Missing { flag: String },
    #[error("`{flag}={value}` — не число: {detail}")]
    BadNumber { flag: String, value: String, detail: String },
    #[error("`{flag}={value}` — не строчный hex [0-9a-f]")]
    BadHex { flag: String, value: String },
    #[error("`{flag}={value}` — нечётная длина hex ({len} символов): байт кодируется ровно двумя символами")]
    HexOddLength { flag: String, value: String, len: usize },
    #[error("`{flag}` ждёт {want} hex-символов, получено `{value}`")]
    HexLength { flag: String, value: String, want: usize },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_path_ends_at_the_first_flag_and_double_dash_still_works() {
        let p = Parsed::parse(&["artifact", "init", "--out", "x", "--force"]).unwrap();
        assert_eq!(p.path(), ["artifact", "init"]);
        assert_eq!(p.required("artifact init", "out").unwrap(), "x");
        assert!(p.bool_flag("artifact init", "force").unwrap());
        // Явный разделитель ничего не меняет в результате: оператор мог выучить его в другой CLI.
        let sep = Parsed::parse(&["artifact", "init", "--", "--out", "x"]).unwrap();
        assert_eq!(sep.required("artifact init", "out").unwrap(), "x");
    }

    #[test]
    fn equals_form_lets_a_value_start_with_dashes() {
        // Текст интента вполне может начинаться с `--`, и `--text=--странно` обязан читаться
        // как значение, а не как флаг `--странно`.
        let p = Parsed::parse(&["encode", "--text=--странно"]).unwrap();
        assert_eq!(p.required("encode", "text").unwrap(), "--странно");
    }

    #[test]
    fn unknown_flag_is_rejected_not_ignored() {
        // `--start` здесь лишний: команда обязана отвергать флаг, которого нет в её списке, а не
        // молча его проглотить — опечатка в имени должна остановить скрипт.
        let p = Parsed::parse(&["pow", "mine", "--bits", "24", "--start", "9"]).unwrap();
        let err = p.reject_unknown("pow mine", &["bits"]).unwrap_err();
        assert!(err.to_string().contains("не знает флага"), "{err}");
        assert!(err.to_string().contains("--start"), "{err}");
        p.reject_unknown("pow mine", &["bits", "start"]).unwrap();
    }

    #[test]
    fn duplicated_flag_is_an_error() {
        let p = Parsed::parse(&["x", "--a", "1", "--a", "2"]).unwrap();
        assert!(matches!(
            p.value("x", "a"),
            Err(ArgError::Duplicated { count: 2, .. })
        ));
        // А вот повторяемый флаг — это штатный `values`, и он молча собирает список.
        assert_eq!(p.values("x", "a").unwrap(), ["1", "2"]);
    }

    #[test]
    fn a_value_flag_cannot_be_read_as_a_switch_and_absence_is_false() {
        let p = Parsed::parse(&["x", "--out"]).unwrap();
        // `--out` без значения — это переключатель для `bool_flag`, но как флаг со значением он
        // обязан быть отвергнут: иначе команда прочитала бы каталог «None» как путь.
        assert!(matches!(p.value("x", "out"), Err(ArgError::NeedsValue { .. })));
        assert!(p.bool_flag("x", "out").unwrap());
        assert!(!p.bool_flag("x", "absent").unwrap());
        let with = Parsed::parse(&["x", "--out=y"]).unwrap();
        assert!(matches!(with.bool_flag("x", "out"), Err(ArgError::UnexpectedValue { .. })));
    }

    #[test]
    fn a_leading_flag_leaves_the_path_empty_for_the_dispatcher_to_refuse() {
        // Разбор не знает команд, поэтому он здесь не врет: путь пуст, флаг есть. Отказать обязан
        // диспетчер (`run(&["--force"])` → код 1 с именем флага), а не парсер, который мог бы
        // отвергнуть законченное написание `--text=…` для команды из одного токена.
        let p = Parsed::parse(&["--verbose", "artifact"]).unwrap();
        assert!(p.path().is_empty());
        assert_eq!(p.first_flag(), Some("verbose"));
        assert!(p.has_flags());
        let bare = Parsed::parse(&[]).unwrap();
        assert!(bare.path().is_empty() && !bare.has_flags());
    }

    #[test]
    fn a_positional_token_after_flags_is_still_an_error() {
        // Третий токен пути и токен-«хвост» после флагов ловятся разными ошибками, и оба случая
        // обязаны быть ошибками: иначе `vecdht-cli index add лишнее` что-то да опубликует.
        assert!(matches!(
            Parsed::parse(&["index", "add", "лишнее", "--dir", "d"]),
            Err(ArgError::TooManyWords(_))
        ));
        assert!(matches!(
            Parsed::parse(&["index", "add", "--dir", "d", "лишнее"]),
            Err(ArgError::Positional(_))
        ));
    }

    #[test]
    fn hex_is_lowercase_and_exact_length() {
        // Заглавные — не косметика: `hex::encode` их не производит, значит документ с ними
        // пересобрался бы другими байтами (§15.1.5).
        assert!(matches!(
            parse_hex::<32>("c", "seed", &"A1".repeat(32)),
            Err(ArgError::BadHex { .. })
        ));
        assert!(matches!(
            parse_hex::<32>("c", "seed", &"a1".repeat(31)),
            Err(ArgError::HexLength { want: 64, .. })
        ));
        let v = parse_hex::<4>("c", "x", "00ff10a5").unwrap();
        assert_eq!(v, [0x00, 0xff, 0x10, 0xa5]);
        // Дамп кадра: длина известна только из заголовка, поэтому есть отдельный читатель.
        assert_eq!(parse_hex_bytes("c", "hex", "0108").unwrap(), vec![0x01, 0x08]);
        assert!(matches!(
            parse_hex_bytes("c", "hex", "010"),
            Err(ArgError::HexOddLength { len: 3, .. })
        ));
        assert!(matches!(
            parse_hex_bytes("c", "hex", "0A"),
            Err(ArgError::BadHex { .. })
        ));
    }

    #[test]
    fn numbers_are_parsed_into_the_target_type() {
        let p = Parsed::parse(&["c", "--n", "1024"]).unwrap();
        assert_eq!(p.num_or::<u16>("c", "n", 16).unwrap(), 1024);
        let bad = Parsed::parse(&["c", "--n", "70000"]).unwrap();
        assert!(matches!(bad.num::<u16>("c", "n"), Err(ArgError::BadNumber { .. })));
    }
}
