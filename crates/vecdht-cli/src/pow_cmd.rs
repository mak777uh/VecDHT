//! `pow mine|verify` — стоимость publish (§11.1, §11.2).
//!
//! PoW в v8 привязан к контексту конкретной записи: `(owner, shard, epoch, slot_key,
//! expires_bucket)`. Команда поэтому не умеет «нафармить N бит просто так» — вход всегда
//! собирается из тех же полей, что проверяет узел, и это единственная защита от того, чтобы
//! инструментом пользовались для pre-farmed пула (adversarial-пункт §19.3).
//!
//! `verify` — один blake3, ≈0,14 мкс на измеренной скорости (замер §19.5). Им оператор отвечает на
//! вопрос «почему узел отбил мой publish», не гадая: либо nonce не проходит по сложности, либо вход
//! собран по другому контексту.
//!
//! Про сложность у `mine` и `verify` намеренно разные правила. `mine` требует диапазон §11.2,
//! потому что иначе он производит nonce, который сеть обязана отвергнуть, — это был бы инструмент,
//! генерирующий заведомо rejected publish. `verify` диапазон не требует, а предупреждает: его
//! задача — воспроизвести чужое утверждение, а отказ по `POW_BITS_LOW` (§11.3) по определению
//! про сложность вне диапазона, и запрещать проверять то, что нужно расследовать, — значит
//! оставить оператора один на один с кодом ошибки.

use std::path::Path;

use vecdht_crypto::pow::{
    BLAKE3_MHZ_CORE_FALLBACK, POW_BITS_DEFAULT, POW_BITS_MAX, POW_BITS_MIN, expected_millis,
    mine_pow, pow_input, pow_ok,
};

use crate::args::Parsed;
use crate::{CliError, fail};

pub const CMD_MINE: &str = "pow mine";
pub const CMD_VERIFY: &str = "pow verify";
pub const FLAGS: &[&str] = &[
    "owner", "shard", "epoch", "slot-key", "expiry", "bits", "start", "max-attempts", "nonce",
    "artifact", "mhz",
];

pub const HELP_MINE: &str = "\
pow mine — найти nonce для конкретного контекста записи (§11.1)

  --owner HEX64      публичный ключ ed25519 автора (обязателен)
  --shard N          шард 0..63 (обязателен)
  --epoch N          эпизода членства (обязательна)
  --slot-key HEX64   entry_key записи (§6.5), то есть слот, а не «любой»
  --expiry N         expires_bucket — TTL, в бакетах (обязателен)
  --bits N           сложность, адаптивный диапазон §11.2; по умолчанию POW_BITS_DEFAULT
  --start N          первый перебираемый nonce; по умолчанию 0, но боевой код обязан
                     передавать случайное число, чтобы пиры не толкались в одном префиксе
  --max-attempts N   потолок перебора; по умолчанию 8·2^bits
  --artifact DIR     взять blake3 МХеш/с из манифеста для оценки стоимости
  --mhz N            явная скорость вместо манифеста";

pub const HELP_VERIFY: &str = "\
pow verify — проверить nonce против контекста: один blake3

  те же флаги контекста, плюс --nonce N; в отличие от mine, здесь разрешены и bits вне
  адаптивного диапазона §11.2 — ровно для того, чтобы воспроизвести чужой отказ по
  POW_BITS_LOW (§11.3)";

/// Сколько переборов допустимо искать по умолчанию: ожидание `2^bits` попыток умножается на
/// восьмёрку. Это не «гарантия найти», а потолок, после которого CLI честно говорит, что
/// повезло меньше, чем на 3 сигма, и стоит посмотреть на `--start`.
fn default_attempts(bits: u32) -> u64 {
    (1u128 << bits).saturating_mul(8).min(u64::MAX as u128) as u64
}

fn input_of(p: &Parsed, cmd: &str) -> Result<(Vec<u8>, u32), CliError> {
    let owner = p.required(cmd, "owner")?;
    let shard = p.required(cmd, "shard")?;
    let epoch = p.required(cmd, "epoch")?;
    let slot = p.required(cmd, "slot-key")?;
    let expiry = p.required(cmd, "expiry")?;
    let owner_b = crate::args::parse_hex::<32>(cmd, "owner", &owner).map_err(CliError::Arg)?;
    let slot_b = crate::args::parse_hex::<32>(cmd, "slot-key", &slot).map_err(CliError::Arg)?;
    let shard_n: u16 = crate::args::parse_num(cmd, "shard", &shard).map_err(CliError::Arg)?;
    let epoch_n: u64 = crate::args::parse_num(cmd, "epoch", &epoch).map_err(CliError::Arg)?;
    let expiry_n: u32 = crate::args::parse_num(cmd, "expiry", &expiry).map_err(CliError::Arg)?;
    let bits = p.num_or(cmd, "bits", POW_BITS_DEFAULT)?;
    let input = pow_input(&owner_b, shard_n, epoch_n, &slot_b, expiry_n);
    Ok((input, bits))
}

/// Скорость blake3 для оценки: явный `--mhz` важнее манифеста, манифест важнее fallback'а.
/// Обратный порядок означал бы, что откалиброванный артефакт (§11.2) можно перебить флагом в
/// скрипте, и расходание «узел по артефакту обещает 150 мс, а у меня 3 мс» стало бы
/// необъяснимым.
fn mhz_of(p: &Parsed, cmd: &str) -> Result<(f64, &'static str), CliError> {
    if let Some(v) = p.num::<u32>(cmd, "mhz")? {
        return Ok((f64::from(v), "--mhz"));
    }
    if let Some(dir) = p.value(cmd, "artifact")? {
        let a = vecdht_artifact::Artifact::load(Path::new(&dir))
            .map_err(|e| fail("чтение артефакта", e))?;
        return Ok((f64::from(a.manifest.power.blake3_mhz_core), "манифест"));
    }
    Ok((BLAKE3_MHZ_CORE_FALLBACK, "fallback §17.2"))
}

pub fn exec_mine(p: &Parsed, out: &mut String) -> Result<(), CliError> {
    let (input, bits) = input_of(p, CMD_MINE)?;
    if !in_range(bits) {
        return Err(CliError::Fail(format!(
            "--bits {bits} вне адаптивного диапазона §11.2 ({POW_BITS_MIN}..={POW_BITS_MAX}): \
             такой nonce сеть отвергнет как POW_BITS_LOW, и фармить его бессмысленно"
        )));
    }
    let start = p.num_or(CMD_MINE, "start", 0u64)?;
    let max_attempts = p.num_or(CMD_MINE, "max-attempts", default_attempts(bits))?;
    if max_attempts == 0 {
        return Err(CliError::Fail(
            "--max-attempts 0: перебор нулевой длины ничего не ищет (§11.1)".into(),
        ));
    }
    let (mhz, mhz_src) = mhz_of(p, CMD_MINE)?;
    let t0 = std::time::Instant::now();
    let nonce = mine_pow(&input, bits, start, max_attempts).map_err(|e| fail("поиск nonce", e))?;
    let spent = t0.elapsed();
    let attempts = nonce.wrapping_sub(start) + 1;
    out.push_str(&format!(
        "вход PoW   {} байт, hex {}\n",
        input.len(),
        hex::encode(&input[..16])
    ));
    out.push_str(&format!("bits        {bits}\n"));
    out.push_str(&format!("nonce       {nonce} (попыток {attempts} от start {start})\n"));
    out.push_str(&format!(
        "проверено   pow_ok = {} (обязано быть true: это тот же код, что на узле)\n",
        pow_ok(&input, nonce, bits)
    ));
    out.push_str(&format!(
        "время       {:.3} мс фактически; оценка §11.2 при {mhz} МХеш/с ({mhz_src}) — {:.1} мс на {bits} бит\n",
        spent.as_secs_f64() * 1e3,
        expected_millis(bits, mhz)
    ));
    Ok(())
}

pub fn exec_verify(p: &Parsed, out: &mut String) -> Result<(), CliError> {
    let (input, bits) = input_of(p, CMD_VERIFY)?;
    let nonce = p.required(CMD_VERIFY, "nonce")?;
    let nonce: u64 = crate::args::parse_num(CMD_VERIFY, "nonce", &nonce).map_err(CliError::Arg)?;
    if bits == 0 || bits > 64 {
        return Err(CliError::Fail(format!(
            "--bits {bits}: проверка сложности определена только для 1..=64, при нуле и при \
             переполнении `1 << (64 - bits)` утверждение «nonce проходит» потеряло бы смысл"
        )));
    }
    if !in_range(bits) {
        out.push_str(&format!(
            "ВНИМАНИЕ: bits {bits} вне адаптивного диапазона §11.2 ({POW_BITS_MIN}..={POW_BITS_MAX}) \
             — publish с такой сложностью узел отвергнет (POW_BITS_LOW), независимо от nonce.\n"
        ));
    }
    let ok = pow_ok(&input, nonce, bits);
    out.push_str(&format!(
        "pow verify: bits {bits}, nonce {nonce} → {}\n",
        if ok { "ПРИНЯТО" } else { "ОТКЛОНЕНО (сложность не выполнена)" }
    ));
    // Контекст печатается всегда, потому что отказ по nonce и отказ по «узел считал вход от другой
    // эпизоды» выглядят для агента одинаково — как `Error{code:"POW_INVALID"}` (§11.3).
    out.push_str(&format!("hex входа {}…\n", &hex::encode(&input)[..32]));
    Ok(())
}

fn in_range(bits: u32) -> bool {
    (POW_BITS_MIN..=POW_BITS_MAX).contains(&bits)
}

#[cfg(test)]
mod tests {
    use super::*;
    use vecdht_crypto::pow::pow_ok;

    fn base(cmd: &str) -> Vec<String> {
        vec![
            cmd.split(' ').next().unwrap().to_string(),
            cmd.split(' ').nth(1).unwrap().to_string(),
            "--owner".to_string(),
            "aa".repeat(32),
            "--shard".to_string(),
            "7".to_string(),
            "--epoch".to_string(),
            "3".to_string(),
            "--slot-key".to_string(),
            "bb".repeat(32),
            "--expiry".to_string(),
            "1234".to_string(),
            "--bits".to_string(),
            "8".to_string(),
            "--mhz".to_string(),
            // Измеренная скорость (§11.1), а не «круглое 200»: оценка стоимости в тесте обязана
            // быть того же порядка, что и в бою.
            "7".to_string(),
        ]
    }

    fn run(argv: &[String]) -> String {
        let r: Vec<&str> = argv.iter().map(String::as_str).collect();
        let p = Parsed::parse(&r[1..]).unwrap();
        let mut out = String::new();
        let cmd = argv[1].as_str();
        if cmd == "mine" {
            exec_mine(&p, &mut out).unwrap();
        } else {
            exec_verify(&p, &mut out).unwrap();
        }
        out
    }

    fn set_flag(argv: &mut [String], name: &str, value: &str) {
        let flag = format!("--{name}");
        let pos = argv.iter().position(|s| s == &flag).expect("флаг обязан быть в базе");
        argv[pos + 1] = value.to_string();
    }

    /// Перебор «в лоб» при низкой сложности — ровно для того, чтобы тест не зависел от RNG и не
    /// тратил секунды на 2^24 хешей; `mine` на реальной сложности стоит под `#[ignore]` ниже.
    fn brute(bits: u32, input: &[u8]) -> u64 {
        let mut n = 0u64;
        while !pow_ok(input, n, bits) {
            n += 1;
            assert!(n < 1 << 24, "на {bits} битах решение обязано найтись далеко до 2^24");
        }
        n
    }

    #[test]
    fn verify_accepts_a_real_solution_and_says_the_difficulty_is_off_policy() {
        let argv = base(CMD_VERIFY);
        let input = pow_input(
            &crate::args::parse_hex::<32>("c", "owner", &argv[3]).unwrap(),
            7,
            3,
            &crate::args::parse_hex::<32>("c", "slot-key", &argv[9]).unwrap(),
            1234,
        );
        let nonce = brute(8, &input);
        let mut v = argv.clone();
        v.extend(["--nonce".to_string(), nonce.to_string()]);
        let out = run(&v);
        assert!(out.contains("ПРИНЯТО"), "{out}");
        assert!(out.contains("ВНИМАНИЕ"), "{out}");
        assert!(out.contains("POW_BITS_LOW"), "{out}");
    }

    #[test]
    fn a_wrong_context_is_rejected_even_with_a_valid_looking_nonce() {
        // Тот же nonce, но другой шард: вход другой, и «нафармленное впрок» не проходит (§19.3).
        let argv = base(CMD_VERIFY);
        let owner = crate::args::parse_hex::<32>("c", "owner", &argv[3]).unwrap();
        let slot = crate::args::parse_hex::<32>("c", "slot-key", &argv[9]).unwrap();
        let nonce = brute(8, &pow_input(&owner, 7, 3, &slot, 1234));
        let mut v = argv.clone();
        v.extend(["--nonce".to_string(), nonce.to_string()]);
        assert!(run(&v).contains("ПРИНЯТО"), "исходный контекст обязан проходить");
        let mut other = v.clone();
        set_flag(&mut other, "shard", "8");
        assert!(run(&other).contains("ОТКЛОНЕНО"), "{other:?}");
        let mut other = v.clone();
        set_flag(&mut other, "epoch", "4");
        assert!(run(&other).contains("ОТКЛОНЕНО"), "смена эпизоды обязана менять вход");
        let mut other = v.clone();
        set_flag(&mut other, "expiry", "1235");
        assert!(run(&other).contains("ОТКЛОНЕНО"), "смена TTL обязана менять вход");
    }

    #[test]
    fn a_random_nonce_fails_at_the_real_difficulty() {
        // Верх адаптивного диапазона — это не «почти наверняка», а настолько мало, что тест
        // детерминирован по построению: nonce 0 не зависит ни от какого RNG.
        let mut v = base(CMD_VERIFY);
        set_flag(&mut v, "bits", &POW_BITS_MAX.to_string());
        v.extend(["--nonce".to_string(), "0".to_string()]);
        let out = run(&v);
        assert!(out.contains("ОТКЛОНЕНО"), "{out}");
        assert!(!out.contains("ВНИМАНИЕ"), "сложность внутри диапазона — предупреждать не о чем");
    }

    #[test]
    fn bits_outside_the_adaptive_range_never_start_a_search() {
        for bits in [
            "0".to_string(),
            "8".to_string(),
            (POW_BITS_MIN - 1).to_string(),
            (POW_BITS_MAX + 1).to_string(),
            "64".to_string(),
        ] {
            let mut x = base(CMD_MINE);
            set_flag(&mut x, "bits", &bits);
            let r: Vec<&str> = x.iter().map(String::as_str).collect();
            let p = Parsed::parse(&r[1..]).unwrap();
            let err = exec_mine(&p, &mut String::new()).unwrap_err();
            assert!(err.to_string().contains("вне адаптивного диапазона"), "{err}");
        }
    }

    #[test]
    fn zero_attempts_is_refused_before_any_hashing() {
        let mut x = base(CMD_MINE);
        set_flag(&mut x, "bits", &POW_BITS_DEFAULT.to_string());
        x.extend(["--max-attempts".to_string(), "0".to_string()]);
        let r: Vec<&str> = x.iter().map(String::as_str).collect();
        let p = Parsed::parse(&r[1..]).unwrap();
        let err = exec_mine(&p, &mut String::new()).unwrap_err();
        assert!(err.to_string().contains("нулевой длины"), "{err}");
    }

    #[test]
    fn default_attempt_budget_is_bounded_by_the_difficulty() {
        assert_eq!(default_attempts(8), 2048);
        assert_eq!(default_attempts(24), 8 * (1 << 24));
        assert_eq!(default_attempts(64), u64::MAX, "переползание обязано упираться в потолок");
    }

    /// Полный цикл `mine → verify` на боевой сложности. Гоняется отдельно и только в
    /// release: 2^20 blake3 в debug-сборке — это десятки секунд, а тест не имеет права быть
    /// медленным «за глазок», он обязан быть медленным осознанно и помеченным.
    #[test]
    #[ignore = "2^POW_BITS_DEFAULT хешей: cargo test --release -p vecdht-cli -- --ignored"]
    fn mining_at_the_minimum_policy_difficulty_verifies() {
        let mut x = base(CMD_MINE);
        let bits = POW_BITS_DEFAULT.to_string();
        set_flag(&mut x, "bits", &bits);
        let out = run(&x);
        assert!(out.contains("pow_ok = true"), "{out}");
        let nonce = out
            .lines()
            .find(|l| l.starts_with("nonce"))
            .unwrap()
            .split_whitespace()
            .nth(1)
            .unwrap()
            .to_string();
        let mut v = base(CMD_VERIFY);
        set_flag(&mut v, "bits", &bits);
        v.extend(["--nonce".to_string(), nonce]);
        assert!(run(&v).contains("ПРИНЯТО"));
    }
}
