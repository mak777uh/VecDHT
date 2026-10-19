//! Тонкая обёртка над [`vecdht_cli::run`]: собрать argv, напечатать два потока, выйти кодом.
//!
//! `main` намеренно не содержит логики. Вся она живёт в `run(&[&str]) -> Outcome`, и тесты могут
//! вызывать её напрямую; отдельный интеграционный тест всё же запускает этот бинарник через
//! `CARGO_BIN_EXE`, чтобы обёртка не разошлась с библиотекой — например кодом выхода или тем, что
//! вывод идёт в stdout, а ошибка в stderr.

use std::io::Write as _;
use std::process::ExitCode;

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let refs: Vec<&str> = argv.iter().map(String::as_str).collect();
    let out = vecdht_cli::run(&refs);
    // Ошибку записи в stdout/stderr печатать в stderr того же потока бессмысленно: если поток
    // закрыт (обрванный pipe, `| head`), сообщение о ней туда же и упадёт. Поэтому здесь
    // возвращается код 2, а текст идёт в `eprintln!` — он пишет в другой хэндл и обычно жив.
    let mut stdout = std::io::stdout();
    let mut stderr = std::io::stderr();
    let printed = stdout.write_all(out.stdout.as_bytes())
        .and_then(|()| stdout.flush())
        .and_then(|()| stderr.write_all(out.stderr.as_bytes()))
        .and_then(|()| stderr.flush());
    match printed {
        Ok(()) => ExitCode::from(out.code.max(0) as u8),
        Err(e) => {
            eprintln!("vecdht-cli: вывод не записывается: {e} (команда вернула код {})", out.code);
            ExitCode::from(2)
        }
    }
}
