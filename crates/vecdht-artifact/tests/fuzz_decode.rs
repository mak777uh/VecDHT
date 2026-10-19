//! Фаззинг разбора артефакта (гейт P2 из §20: «fuzz-decode без panic»).
//!
//! Манифест — consensus-материал: его байты подписываются и идут в `artifact_hash`, поэтому у
//! его разбора два инварианта, а не один:
//!
//! * не паниковать ни на каких байтах (сеть получает их из чужого HTTP-зеркала);
//! * принятые байты обязаны пересобираться в себя — если `decode` что-то принял, то
//!   `encode(decode(x)) == x`, иначе два узла могут подписывать разные байты одного и того же
//!   «манифеста».
//!
//! Второй инвариант и есть настоящая проверка каноничности парсера: фаззер ловит случаи, когда
//! разбор терпит пробел, лишний ноль в числе или не тот порядок ключей, а пересборка их
//! «причёсывает».
//!
//! Запуск: `VEC_DHT_FUZZ_SECS=1800 VEC_DHT_FUZZ_SEED=1 cargo test --release -p vecdht-artifact
//! --test fuzz_decode -- --nocapture`.

use std::panic::{catch_unwind, AssertUnwindSafe};

use vecdht_artifact::json::parse;
use vecdht_artifact::{reference_manifest, Centroids, CENTROID_BYTES};
use vecdht_wire::codec::DIM;

/// Детерминированный xorshift64*: фаззер, который нельзя воспроизвести по сиду, бесполезен.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn byte(&mut self) -> u8 {
        (self.next() >> 33) as u8
    }
    fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next() % (n as u64)) as usize
        }
    }
    fn bytes<const N: usize>(&mut self) -> [u8; N] {
        let mut a = [0u8; N];
        for x in a.iter_mut() {
            *x = self.byte();
        }
        a
    }
}

fn seed_mix(base: u64) -> u64 {
    let mix = std::env::var("VEC_DHT_FUZZ_SEED")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(0)
        .wrapping_mul(0x9E37_79B9_7F4A_7C15);
    let s = base ^ mix;
    if s == 0 {
        1
    } else {
        s
    }
}

/// Число итераций, если wall-clock бюджет не задан. Дефолты подобраны под debug-профиль:
/// `assign` на 1024 центроидах там стоит миллионы операций, и «миллион итераций» превратился
/// бы обычный `cargo test` в часовой прогон. Длинные прогоны (§20) идут в release и с `SECS`.
fn budget(default_iters: u64) -> u64 {
    std::env::var("VEC_DHT_FUZZ_ITERS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(if std::env::var("VEC_DHT_FUZZ_SECS").is_ok() {
            u64::MAX
        } else {
            default_iters
        })
}

/// Wall-clock бюджет теста: `None` — работать по числу итераций.
fn deadline() -> Option<std::time::Duration> {
    std::env::var("VEC_DHT_FUZZ_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .map(std::time::Duration::from_secs)
}

/// `i8` в hex: у фаззера panic-сообщение должно воспроизводить вход байт в байт.
fn hexi8(v: &[i8]) -> String {
    v.iter().map(|b| format!("{b:02x}")).collect()
}

/// Corpus: эталонный манифест и его куски, а также заведомо неканонические варианты — иначе
/// фаззер по случайным байтам почти никогда не доходит до разбора полей.
fn corpus() -> Vec<Vec<u8>> {
    let full = reference_manifest().to_json_bytes();
    let unsigned = reference_manifest().unsigned_json();
    let mut out = vec![
        full.clone(),
        unsigned.clone(),
        br#"{"schema":1}"#.to_vec(),
        b"{}".to_vec(),
        b"[]".to_vec(),
        b"null".to_vec(),
        br#"{"signatures":[]}"#.to_vec(),
    ];
    // Обрывки на границах ключей: здесь живёт проверка порядка ключей и «не тот тип поля».
    for cut in [1usize, 2, 7, 40, 97, 256, 1000, 1500] {
        if cut < full.len() {
            out.push(full[..cut].to_vec());
        }
        if cut < unsigned.len() {
            out.push(unsigned[..cut].to_vec());
        }
    }
    // Каноничный вход с одним вставленным байтом / удалённым байтом / заменённым байтом.
    for at in [0usize, 1, 12, 120, 900] {
        if at < full.len() {
            let mut ins = full.clone();
            ins.insert(at, b' ');
            out.push(ins);
            let mut del = full.clone();
            del.remove(at);
            out.push(del);
            let mut rep = full.clone();
            rep[at] = rep[at].wrapping_add(1);
            out.push(rep);
        }
    }
    out
}

#[test]
fn json_parse_never_panics_and_accepts_only_canonical_bytes() {
    let mut rng = Rng(seed_mix(0xA11C_0FFE_1234_5678));
    let cp = corpus();
    let started = std::time::Instant::now();
    let secs = deadline();
    let limit = budget(300_000);
    let (mut accepted, mut rejected, mut mutations) = (0u64, 0u64, 0u64);

    let mut iter = 0u64;
    while iter < limit && secs.map(|d| started.elapsed() < d).unwrap_or(true) {
        iter += 1;
        // Два класса входов: мутации канонических байтов и совсем случайные. Первые проходят
        // дальше по разбору, вторые проверяют границы (EOF, UTF-8, escape).
        let input = if rng.below(4) == 0 {
            (0..rng.below(64) + 1).map(|_| rng.byte()).collect::<Vec<u8>>()
        } else {
            mutations += 1;
            let mut b = cp[rng.below(cp.len())].clone();
            for _ in 0..(rng.below(3) + 1) {
                if b.is_empty() {
                    b.push(rng.byte());
                    continue;
                }
                match rng.below(4) {
                    0 => {
                        let at = rng.below(b.len());
                        b[at] = rng.byte();
                    }
                    1 => {
                        let at = rng.below(b.len() + 1);
                        b.insert(at, rng.byte());
                    }
                    2 => {
                        b.remove(rng.below(b.len()));
                    }
                    _ => {
                        let tail: Vec<u8> = (0..rng.below(8)).map(|_| rng.byte()).collect();
                        b.extend_from_slice(&tail);
                    }
                }
            }
            b
        };

        let res = catch_unwind(AssertUnwindSafe(|| parse(&input)));
        match res {
            Err(_) => panic!(
                "panic в json::parse на {}\n  seed={}",
                hex::encode(&input),
                std::env::var("VEC_DHT_FUZZ_SEED").unwrap_or_default()
            ),
            Ok(Ok(v)) => {
                accepted += 1;
                let canon = v.render();
                assert_eq!(
                    canon,
                    input,
                    "принят неканонический вход\n   было:  {}\n   стало: {}",
                    hex::encode(&input),
                    hex::encode(&canon)
                );
                // Пересборка из структуры обязана быть идемпотентной.
                assert_eq!(parse(&canon).ok(), Some(v), "ререндер не читается");
            }
            Ok(Err(_)) => rejected += 1,
        }

        if iter >= limit || secs.map(|d| started.elapsed() >= d).unwrap_or(false) {
            break;
        }
    }
    eprintln!(
        "json fuzz: {iter} итераций за {:.1} с, принято {accepted}, отклонено {rejected}, мутаций эталона {mutations}",
        started.elapsed().as_secs_f32()
    );
    assert!(accepted > 0, "ни один вход не принят — фаззер ничего не проверял");
    assert!(rejected > 0, "ни один вход не отклонён — парсер слишком терпим");
}

/// `Manifest::decode` — то же требование каноничности, но поверх схемы: принятые байты обязаны
/// пересобираться в тот же манифест, иначе подпись автора и подпись проверщика считаются по
/// разным документам.
#[test]
fn manifest_decode_accepts_only_its_own_rendition() {
    let mut rng = Rng(seed_mix(0x1500_0000_DEAD_BEEF));
    let cp = corpus();
    let started = std::time::Instant::now();
    let secs = deadline();
    let limit = budget(20_000);
    let (mut accepted, mut rejected) = (0u64, 0u64);

    let mut iter = 0u64;
    while iter < limit && secs.map(|d| started.elapsed() < d).unwrap_or(true) {
        iter += 1;
        let mut b = cp[rng.below(cp.len())].clone();
        for _ in 0..(rng.below(2) + 1) {
            if b.is_empty() {
                break;
            }
            match rng.below(3) {
                0 => {
                    let at = rng.below(b.len());
                    b[at] = rng.byte();
                }
                1 => {
                    let at = rng.below(b.len());
                    b.remove(at);
                }
                _ => {
                    let at = rng.below(b.len() + 1);
                    b.insert(at, match rng.below(6) {
                        0 => b',',
                        1 => b'"',
                        2 => b'{',
                        3 => b'}',
                        4 => b'0',
                        _ => b' ',
                    });
                }
            }
        }

        let res = catch_unwind(AssertUnwindSafe(|| {
            vecdht_artifact::Manifest::decode(&b).map(|m| m.to_json_bytes())
        }));
        match res {
            Err(_) => panic!(
                "panic в Manifest::decode на {}\n  seed={}",
                hex::encode(&b),
                std::env::var("VEC_DHT_FUZZ_SEED").unwrap_or_default()
            ),
            Ok(Ok(canonical)) => {
                accepted += 1;
                assert_eq!(
                    canonical,
                    b,
                    "манифест принят из неканонических байтов\n   было:  {}\n   стало: {}",
                    hex::encode(&b),
                    hex::encode(&canonical)
                );
            }
            Ok(Err(_)) => rejected += 1,
        }
        if iter >= limit || secs.map(|d| started.elapsed() >= d).unwrap_or(false) {
            break;
        }
    }
    eprintln!(
        "manifest fuzz: {iter} итераций за {:.1} с, принято {accepted}, отклонено {rejected}",
        started.elapsed().as_secs_f32()
    );
    assert!(accepted > 0, "ни один манифест не принят (seed-корпус пуст?)");
    assert!(rejected > 0, "схема не отклоняет ничего");
}

/// Центроиды — вход из файла: проверка размера и отсутствие паник при присваивании кластера.
#[test]
fn centroid_input_and_assignment_are_total() {
    let mut rng = Rng(seed_mix(0xCE01_D105_0000_0001));
    let started = std::time::Instant::now();
    let secs = deadline();
    let limit = budget(400);
    let mut kept = 0u64;

    let mut iter = 0u64;
    while iter < limit && secs.map(|d| started.elapsed() < d).unwrap_or(true) {
        iter += 1;
        let n = match rng.below(4) {
            0 => CENTROID_BYTES,
            1 => rng.below(CENTROID_BYTES + 1),
            2 => CENTROID_BYTES + rng.below(1024),
            _ => rng.below(1 << 12),
        };
        let raw: Vec<u8> = (0..n).map(|_| rng.byte()).collect();
        let c = catch_unwind(AssertUnwindSafe(|| Centroids::from_u8(&raw))).ok().and_then(|r| r.ok());
        match c {
            Some(c) => {
                kept += 1;
                assert_eq!(c.len(), CENTROID_BYTES);
                for _ in 0..3 {
                    let q: [i8; DIM] = rng.bytes::<DIM>().map(|b| b as i8);
                    let cluster = catch_unwind(AssertUnwindSafe(|| c.assign(&q)))
                        .unwrap_or_else(|_| panic!("panic в assign на {}", hexi8(&q)));
                    assert!((cluster as usize) < CENTROID_BYTES / DIM, "cluster {cluster} вне nlist");
                    let top = catch_unwind(AssertUnwindSafe(|| c.top(&q, 4)))
                        .unwrap_or_else(|_| panic!("panic в top на {}", hexi8(&q)));
                    assert_eq!(top.len(), 4, "top(4) вернул {} кластеров", top.len());
                    // Контракт сортировки §7.5: без убывания d2, а при равенстве — по возрастанию id.
                    for w in top.windows(2) {
                        assert_ne!(w[0], w[1], "дубликат в top: {top:?}");
                    }
                }
            }
            None => {
                assert_ne!(n, CENTROID_BYTES, "верный размер отклонён: {n}");
            }
        }
        if iter >= limit || secs.map(|d| started.elapsed() >= d).unwrap_or(false) {
            break;
        }
    }
    eprintln!(
        "centroids fuzz: {iter} входов за {:.1} с, принято {kept}",
        started.elapsed().as_secs_f32()
    );
    assert!(kept > 0, "ни один вход верного размера не принят");
}

/// Отдельно — байты, на которых парсер обязан отвечать ошибкой, а не «значением по умолчанию».
/// Фаззинг находит их редко, а последствия у них консенсусные.
#[test]
fn known_non_canonical_shapes_are_rejected() {
    let json_bad: &[&str] = &[
        "{ \"schema\":1}",
        "{\"schema\" :1}",
        "{\"schema\":01}",
        "{\"schema\":+1}",
        "{\"schema\":1.0}",
        "{\"schema\":1e1}",
        "{\"schema\":1,\"schema\":2}",
        "{\"a\":\"\\x41\"}",
        "{\"a\":\"\\u0041\"}",
        "{\"a\":\"\\uD83D\"}",
        "{\"a\":\"\\uD83D\\uDE00\"}",
        // `\u0041` и `\u0008` короче в виде `A` и `\b`: каноническая форма не допускает длинной записи.
        "{\"a\":\"\\u0008\"}",
        "{\"a\":\"\\u000A\"}",
        "{\"a\":\"\\U00000041\"}",
        "[1, 2]",
        "[1,2,]",
        "{\"a\":1,}",
        "true ",
        " tru",
        "\u{feff}{}",
        "{\"a\":}",
        "{\"a\":1}}",
        "-0",
        // Число вне i64 — не канонический JSON в этом парсере: принимать его значит молча
        // менять значение при пересборке.
        "{\"schema\":99999999999999999999999}",
    ];
    for bad in json_bad {
        let r = parse(bad.as_bytes());
        assert!(
            r.is_err(),
            "неканонический вход принят: {bad} -> {:?}",
            r.map(|v| String::from_utf8_lossy(&v.render()).into_owned())
        );
    }

    // Синтаксически это правильный канонический JSON, но не манифест: проверка типа — уже уровень
    // схемы, и она обязана отказать, а не подставить ноль.
    for wrong_type in [
        "{\"schema\":null}",
        "{\"schema\":true}",
        "{\"schema\":\"1\"}",
        "{\"schema\":-1}",
    ] {
        assert!(parse(wrong_type.as_bytes()).is_ok(), "{wrong_type} даже не JSON");
        assert!(
            vecdht_artifact::Manifest::decode(wrong_type.as_bytes()).is_err(),
            "{wrong_type} принят как манифест"
        );
    }

    // А это канонично и обязано пересобраться в себя.
    for good in [
        "{}",
        "[]",
        "null",
        "true",
        "false",
        "0",
        "-1",
        "9223372036854775807",
        "-9223372036854775808",
        "{\"a\":{}}",
        "{\"a\":[[],{}]}",
        "{\"a\":\"\\u001f\"}",
        "{\"a\":\"\\u0000\"}",
        "{\"a\":\"\\b\"}",
        "{\"a\":\"\\n\"}",
        "{\"a\":\"\\\"\"}",
        "{\"a\":\"\\\\\"}",
        "{\"a\":\"é\"}",
        "{\"a\":\"😀\"}",
    ] {
        let v = parse(good.as_bytes()).unwrap_or_else(|e| panic!("{good} отклонён: {e}"));
        assert_eq!(v.render().as_slice(), good.as_bytes(), "ререндер {good}");
        assert_eq!(
            parse(&v.render()).unwrap(),
            v,
            "вторичный разбор {good} расходится"
        );
    }
}
