//! VecDHT v8 — бинарник оператора (спека §17.1: «vecdht-cli/ бинарник node/agent/demo»).
//!
//! Что здесь реализовано. Сетевой путь (`agent publish|find|session`) собран поверх
//! `vecdht-net::agent`, как только появился транспорт: кадры, PoW и проверки подписей не
//! дублируются в CLI. Офлайн-работа оператора тоже на месте:
//!
//! * `artifact init|show|verify` — собрать, посмотреть и проверить артефакт сети (§15);
//! * `encode` — прогнать текст через пайплайн §6.2 и увидеть `cluster_id`, шард и fan-out;
//! * `agent publish|find|session|run` — §12 целиком: публикация, fan-out поиска, приём, прямой
//!   канал и постоянный listener, без которого агент не принимает входящий handshake;
//! * `pow mine|verify` — стоимость publish и её проверка (§11.1);
//! * `index create|add|search|stats|snapshot` — одноузловой индекс шарда на диске (§8, §10);
//! * `wire kinds|decode` — разобрать кадр по таблице §5.3, включая проверку каноничности;
//! * `demo` — весь офлайн-путь в одном процессе: артефакт → encode → 64 шарда → search.
//!
//! Честная граница v1: `agent run` поднимает listener и шагает, но смыслового слоя входящих нет —
//! `IntentTextRequest` узлом не обслуживается (в `ShardNode` нет держателя текста), поэтому
//! команда делает агента достижимым для handshake/ack/приёма, а не «сервером, который отвечает на
//! всё». Команда `node` (машина шарда из CLI) не сделана: ей нужен bootstrap членства и genesis,
//! и «заглушка, которая печатает успех», была бы дороже её отсутствия. Relay/DCUtR не подняты,
//! поэтому `agent session` идёт прямым dial'ом по адресу из address book или Kademlia.
//!
//! Разбор аргументов свой и без зависимостей ([`args`]), а весь вывод пишется в буфер внутри
//! `run`, поэтому тесты проверяют бинарник как функцию, а не через `spawn` — и один интеграционный
//! тест всё-таки запускает настоящий `main`, чтобы поймать расхождение между ними.
//!
//! Коды возврата стабильны и задокументированы в `USAGE`: 0 — успех, 1 — ошибка разбора
//! аргументов (скрипт переписать), 2 — команда выполнена быть не могла (данные, диск, подпись).
//! Различение принципиально: первый случай означает «оператор ошибся в командной строке», второй —
//! «протокол или артефакт не согласованы», и молча сводить их к единице нельзя.

#![forbid(unsafe_code)]

pub mod agent_cmd;
pub mod args;
pub mod artifact_cmd;
pub mod demo_cmd;
pub mod encode_cmd;
pub mod index_cmd;
pub mod model;
pub mod pow_cmd;
pub mod wire_cmd;

use std::fmt::Display;

use args::Parsed;

pub const CODE_OK: i32 = 0;
pub const CODE_USAGE: i32 = 1;
pub const CODE_FAILED: i32 = 2;

#[derive(Debug, thiserror::Error)]
pub enum CliError {
    #[error(transparent)]
    Arg(#[from] args::ArgError),
    /// Всё, что случилось после успешного разбора: ввод-вывод, негодный артефакт, отказ индекса.
    #[error("{0}")]
    Fail(String),
}

/// Ошибка с контекстом шага: оператор обязан получить не `No such file or directory`, а
/// «какой именно файл артефакта не читается».
pub fn fail(ctx: impl Display, e: impl Display) -> CliError {
    CliError::Fail(format!("{ctx}: {e}"))
}

/// Hex-представление int8-вектора (`vec_q`, сетка i8/127 — §6.3).
///
/// Отдельная функция, а не `hex::encode(&v)`, потому что `[i8; DIM]` не удовлетворяет
/// `AsRef<[u8]>`: байты подписанные, и приведение обязано быть явным — иначе в выводе CLI
/// появилась бы тихая интерпретация знака, а оператор сверяет с артефактом именно байты (§15.3).
pub fn vector_hex(v: &[i8]) -> String {
    hex::encode(v.iter().map(|x| *x as u8).collect::<Vec<u8>>())
}

/// Результат вызова: коды плюс потоки. `stdout` — машиночитаемый вывод, `stderr` — только
/// сообщения об ошибках; пустой строкой считается «писать было нечего».
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
}

impl Outcome {
    fn ok(stdout: String) -> Self {
        Self { code: CODE_OK, stdout, stderr: String::new() }
    }

    fn err(code: i32, message: String) -> Self {
        Self { code, stdout: String::new(), stderr: message }
    }
}

/// Одна строка диспетчера. `flags` и `help` берутся из модуля команды, поэтому список флагов в
/// справке физически не может разъехаться с разбором: и то и другое читается из одного const.
pub struct Command {
    pub path: &'static str,
    pub summary: &'static str,
    pub flags: &'static [&'static str],
    pub help: &'static str,
    pub run: fn(&Parsed, &mut String) -> Result<(), CliError>,
}

pub static COMMANDS: &[Command] = &[
    Command {
        path: artifact_cmd::CMD_INIT,
        summary: "собрать и подписать артефакт сети (dev-набор центроидов из seed)",
        flags: artifact_cmd::FLAGS_INIT,
        help: artifact_cmd::HELP_INIT,
        run: artifact_cmd::exec_init,
    },
    Command {
        path: artifact_cmd::CMD_SHOW,
        summary: "распечатать манифест и хеши артефакта без проверки подписи",
        flags: artifact_cmd::FLAGS_SHOW,
        help: artifact_cmd::HELP_SHOW,
        run: artifact_cmd::exec_show,
    },
    Command {
        path: artifact_cmd::CMD_VERIFY,
        summary: "проверить артефакт целиком: хеши, порог подписей, preprocessing_version",
        flags: artifact_cmd::FLAGS_VERIFY,
        help: artifact_cmd::HELP_VERIFY,
        run: artifact_cmd::exec_verify,
    },
    Command {
        path: encode_cmd::CMD,
        summary: "прогнать текст через пайплайн §6.2: канонический текст, вектор, кластер, fan-out",
        flags: encode_cmd::FLAGS,
        help: encode_cmd::HELP,
        run: encode_cmd::exec,
    },
    Command {
        path: agent_cmd::CMD_PUBLISH,
        summary: "опубликовать интент в сеть: DHT → primary → эпоха → PoW → ack W=2 (§12.1)",
        flags: agent_cmd::FLAGS_PUBLISH,
        help: agent_cmd::HELP_PUBLISH,
        run: agent_cmd::exec_publish,
    },
    Command {
        path: agent_cmd::CMD_FIND,
        summary: "найти записи одним Find на шард и получить подписанные приёмы (§12.2)",
        flags: agent_cmd::FLAGS_FIND,
        help: agent_cmd::HELP_FIND,
        run: agent_cmd::exec_find,
    },
    Command {
        path: agent_cmd::CMD_SESSION,
        summary: "открыть прямой аутентифицированный канал по приёму (§12.5)",
        flags: agent_cmd::FLAGS_SESSION,
        help: agent_cmd::HELP_SESSION,
        run: agent_cmd::exec_session,
    },
    Command {
        path: agent_cmd::CMD_RUN,
        summary: "постоянный listener: шагать вне вызовов и принимать входящие (§12.5)",
        flags: agent_cmd::FLAGS_RUN,
        help: agent_cmd::HELP_RUN,
        run: agent_cmd::exec_run,
    },
    Command {
        path: pow_cmd::CMD_MINE,
        summary: "нафармить publish-PoW для конкретного контекста записи (§11.1)",
        flags: pow_cmd::FLAGS,
        help: pow_cmd::HELP_MINE,
        run: pow_cmd::exec_mine,
    },
    Command {
        path: pow_cmd::CMD_VERIFY,
        summary: "проверить nonce против контекста: один blake3, ≈0,14 мкс (замер §19.5)",
        flags: pow_cmd::FLAGS,
        help: pow_cmd::HELP_VERIFY,
        run: pow_cmd::exec_verify,
    },
    Command {
        path: index_cmd::CMD_CREATE,
        summary: "создать каталог шарда и подтвердить эпизоду на диске (§9.2)",
        flags: index_cmd::FLAGS_CREATE,
        help: index_cmd::HELP_CREATE,
        run: index_cmd::exec_create,
    },
    Command {
        path: index_cmd::CMD_ADD,
        summary: "записать записи из файла `IndexEntry`-байтов через WAL (§10.1)",
        flags: index_cmd::FLAGS_ADD,
        help: index_cmd::HELP_ADD,
        run: index_cmd::exec_add,
    },
    Command {
        path: index_cmd::CMD_SEARCH,
        summary: "поиск по int8-вектору: кластеры явно или из артефакта по nprobe (§7.5)",
        flags: index_cmd::FLAGS_SEARCH,
        help: index_cmd::HELP_SEARCH,
        run: index_cmd::exec_search,
    },
    Command {
        path: index_cmd::CMD_STATS,
        summary: "состояние индекса: seq, слоты, эпоха, снапшот, разбивка памяти (§8.2)",
        flags: index_cmd::FLAGS_STATS,
        help: index_cmd::HELP_STATS,
        run: index_cmd::exec_stats,
    },
    Command {
        path: index_cmd::CMD_SNAPSHOT,
        summary: "принудительный снапшот-барьер и усечении хвоста WAL (§10.4)",
        flags: index_cmd::FLAGS_SNAPSHOT,
        help: index_cmd::HELP_SNAPSHOT,
        run: index_cmd::exec_snapshot,
    },
    Command {
        path: wire_cmd::CMD_KINDS,
        summary: "таблица видов кадра §5.3 с флагом «подпись обязательна»",
        flags: wire_cmd::FLAGS_KINDS,
        help: wire_cmd::HELP_KINDS,
        run: wire_cmd::exec_kinds,
    },
    Command {
        path: wire_cmd::CMD_DECODE,
        summary: "разобрать кадр из hex и проверить, что принятые байты пересобираются в себя",
        flags: wire_cmd::FLAGS_DECODE,
        help: wire_cmd::HELP_DECODE,
        run: wire_cmd::exec_decode,
    },
    Command {
        path: demo_cmd::CMD,
        summary: "весь офлайн-путь в одном процессе: артефакт → encode → 64 шарда → search",
        flags: demo_cmd::FLAGS,
        help: demo_cmd::HELP,
        run: demo_cmd::exec,
    },
];

/// Печатаемая справка. Собирается из `COMMANDS`, а не пишется отдельно: список команд и список
/// флагов в ней обязаны устаревать вместе с кодом.
pub fn usage() -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "vecdht-cli {} — VecDHT v8 (§12: agent publish/find/session/run; §18.1–§18.5 офлайн)\n\n",
        env!("CARGO_PKG_VERSION")
    ));
    out.push_str("КОМАНДЫ\n");
    for c in COMMANDS {
        out.push_str(&format!("  {:<22} {}\n", c.path, c.summary));
    }
    out.push_str("\n  help [--команда]     справка по команде (флаги и смысл)\n");
    out.push_str("  version              версия, константы протокола и preprocessing_version\n");
    out.push_str(
        "\nКОДЫ ВОЗВРАТА\n  0 успех; 1 ошибка разбора аргументов; 2 команда не могла быть выполнена\n",
    );
    out.push_str(
        "\nВсе hex-поля — ровно 2N строчных символов [0-9a-f] (§15.1.5), все числа — десятичные \
         без разделителей.\n",
    );
    out
}

fn help_for(path: &str) -> String {
    match COMMANDS.iter().find(|c| c.path == path) {
        Some(c) => format!("{}\n\nФЛАГИ:\n{}", c.help, flag_list(c.flags)),
        None => format!("неизвестная команда `{path}`\n\n{}", usage()),
    }
}

fn flag_list(flags: &[&str]) -> String {
    let mut s = String::new();
    for f in flags {
        s.push_str(&format!("  --{f}\n"));
    }
    s
}

/// Точка входа: `argv` — аргументы без имени программы. Функция чистая (никаких `exit`, никаких
/// глобальных часов), поэтому вызывается и из `main`, и из тестов.
pub fn run(argv: &[&str]) -> Outcome {
    match dispatch(argv) {
        Ok(stdout) => Outcome::ok(stdout),
        Err(CliError::Arg(e)) => Outcome::err(CODE_USAGE, format!("разбор: {e}\n")),
        Err(CliError::Fail(m)) => Outcome::err(CODE_FAILED, format!("{m}\n")),
    }
}

fn dispatch(argv: &[&str]) -> Result<String, CliError> {
    let p = Parsed::parse(argv)?;
    if p.path().is_empty() {
        // Флаг без команды: `vecdht-cli --force` не обязан печатать справку и делать вид, что
        // понял оператора, — это ошибка разбора, и имя флага в ней обязано быть названо.
        if let Some(f) = p.first_flag() {
            return Err(CliError::Arg(args::ArgError::FlagBeforeCommand(f.to_string())));
        }
        return Ok(usage());
    }
    let joined = p.path_str();
    match p.path()[0].as_str() {
        "help" => {
            // Тема справки — часть пути (`help pow mine`), а не позиционный аргумент после `--`:
            // флаги после `help` значат только одно — какой формат подсказки напечатать, и их тут
            // нет вовсе.
            p.reject_unknown("help", &[])?;
            let topic = joined.strip_prefix("help").unwrap_or("").trim();
            Ok(if topic.is_empty() { usage() } else { help_for(topic) })
        }
        "version" => {
            p.reject_unknown("version", &[])?;
            Ok(version())
        }
        _ => {
            let cmd = COMMANDS
                .iter()
                .find(|c| c.path == joined)
                .ok_or_else(|| CliError::Arg(args::ArgError::UnknownCommand(joined.clone())))?;
            p.reject_unknown(cmd.path, cmd.flags)?;
            let mut out = String::new();
            (cmd.run)(&p, &mut out)?;
            Ok(out)
        }
    }
}

/// Константы, которые оператор сверяет с артефактом руками при отладке (§15.3): несогласованный
/// `preprocessing_version` видит здесь, а не в тихо деградировавшем поиске.
pub fn version() -> String {
    use vecdht_wire::{CLUSTERS_PER_SHARD, DIM, NLIST, SHARDS, TIME_BUCKET_SEC};
    format!(
        "vecdht-cli {}\n\
         протокол: version 8, nlist {NLIST}, clusters_per_shard {CLUSTERS_PER_SHARD}, \
         shards {SHARDS}, dim {DIM}, бакет {TIME_BUCKET_SEC} с\n\
         preprocessing_version: {}\n\
         сетка квантования: i8/127, округление half_away (§6.3)\n\
         инференс: {}\n",
        env!("CARGO_PKG_VERSION"),
        vecdht_embed::PREPROCESSING_VERSION,
        if cfg!(feature = "candle") { "candle (ModernBERT) собран" } else { "не собран (feature `candle`)" },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_command_path_is_unique_and_two_tokens_or_one() {
        let mut seen: Vec<&str> = Vec::new();
        for c in COMMANDS {
            assert!(!c.path.is_empty() && !c.path.contains("  "));
            assert!(c.summary.split_whitespace().count() > 2, "{}: пустая справка", c.path);
            assert!(c.help.contains(c.path), "{}: HELP не называет команду", c.path);
            for f in c.flags {
                assert!(!f.starts_with('-') && !f.is_empty(), "{}: флаг `--{f}`", c.path);
            }
            assert!(!seen.contains(&c.path), "дубликат команды {}", c.path);
            seen.push(c.path);
        }
    }

    #[test]
    fn empty_argv_prints_usage_with_zero_code() {
        let o = run(&[]);
        assert_eq!(o.code, CODE_OK);
        assert!(o.stdout.contains("vecdht-cli"), "{}", o.stdout);
        assert!(o.stdout.contains("artifact init"));
    }

    #[test]
    fn version_prints_the_protocol_constants() {
        let o = run(&["version"]);
        assert_eq!(o.code, CODE_OK);
        assert!(o.stdout.contains("nlist 1024"), "{}", o.stdout);
        assert!(o.stdout.contains("preprocessing_version: 1"));
    }

    #[test]
    fn unknown_command_is_a_usage_error_and_names_the_command() {
        let o = run(&["artifact", "launch"]);
        assert_eq!(o.code, CODE_USAGE, "{}", o.stderr);
        assert!(o.stderr.contains("artifact launch"), "{}", o.stderr);
    }

    #[test]
    fn help_for_a_known_command_lists_its_flags() {
        let o = run(&["help", "pow", "mine"]);
        assert_eq!(o.code, CODE_OK);
        assert!(o.stdout.contains("--bits"), "{}", o.stdout);
        assert!(o.stdout.contains("pow mine"), "{}", o.stdout);
    }

    #[test]
    fn help_for_unknown_command_falls_back_to_usage_but_still_says_so() {
        let o = run(&["help", "nope"]);
        assert_eq!(o.code, CODE_OK);
        assert!(o.stdout.contains("неизвестная команда `nope`"), "{}", o.stdout);
    }

    #[test]
    fn a_leading_flag_without_a_command_is_a_usage_error_naming_the_flag() {
        let o = run(&["--force"]);
        assert_eq!(o.code, CODE_USAGE, "{o:?}");
        assert!(o.stderr.contains("--force"), "{}", o.stderr);
    }

    #[test]
    fn a_missing_required_flag_is_code_usage_not_code_failed() {
        let o = run(&["artifact", "verify"]);
        assert_eq!(o.code, CODE_USAGE, "{o:?}");
        assert!(o.stderr.contains("--artifact"), "{}", o.stderr);
    }
}
