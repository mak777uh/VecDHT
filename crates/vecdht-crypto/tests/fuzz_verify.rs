//! Фаззинг крипто-слоя (гейт P2: отсутствие паников плюс инварианты consensus-path).
//!
//! Здесь фиксируются не байты (это делают `golden_vectors`), а свойства, которые спека §4–§6
//! объявляет инвариантами:
//!
//! * верификация подписи на произвольных ключах и подписях обязана возвращать `false` или
//!   `Err`, но никогда `true`, и никогда не паниковать — это про malleability и small-order
//!   точки, на которых v7.5 полагалась молча;
//! * квантование: выход всегда в сетке `[-127, 127]`, `l2_sq` всегда в границе `u32`,
//! * вырожденные float (0, NaN, ±inf) отклоняются, а не превращаются в мусорный индекс;
//! * присваивание кластера и `top_clusters` детерминированы, tie-break — меньший индекс;
//! * порог PoW монотонен по числу бит: nonce, прошедший `b` бит, обязан пройти `b−1`;
//! * `verify_cert` не паникует ни на какой форме кредашиала и пропускает только подписанный
//!   авторитетом, непросроченный, неотозванный и генис-совпадающий.

use std::panic::{catch_unwind, AssertUnwindSafe};

use ed25519_dalek::SigningKey;
use vecdht_crypto::cert::{sign_cert, verify_cert, verify_index_cert, AuthoritySet, DOMAIN_NODE_CERT};
use vecdht_crypto::pow::pow_ok;
use vecdht_crypto::quant::{
    assign_cluster, l2_normalize, l2_sq, quantize_slice, similarity_from_d2, top_clusters, DIM,
};
use vecdht_crypto::sig::{sig_digest, verify_body, verify_domain, Identity};
use vecdht_wire::cert::NodeCert;
use vecdht_wire::frame::{Kind, FLAG_SIGNED};
use vecdht_wire::messages::domain;
use vecdht_wire::messages::Role;

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn byte(&mut self) -> u8 {
        (self.next() >> 31) as u8
    }
    fn bytes<const N: usize>(&mut self) -> [u8; N] {
        let mut b = [0u8; N];
        for x in b.iter_mut() {
            *x = self.byte();
        }
        b
    }
    fn i8v<const N: usize>(&mut self) -> [i8; N] {
        self.bytes::<N>().map(|b| b as i8)
    }
    /// Произвольные биты = любые float, включая NaN, ±inf и субнормалы.
    fn f64s(&mut self, n: usize) -> Vec<f64> {
        (0..n).map(|_| f64::from_bits(self.next())).collect()
    }
    fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next() % n as u64) as usize
        }
    }
}

/// Базовый сид каждого теста перемешивается с `VEC_DHT_FUZZ_SEED`: сегменты долгого прогона
/// §20 с разными сидами не повторяют друг друга. Без переменной прогон остаётся тем же
/// детерминированным, что и в `cargo test`.
fn fuzz_rng(base: u64) -> Rng {
    let mix = std::env::var("VEC_DHT_FUZZ_SEED")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(0)
        .wrapping_mul(0x9E37_79B9_7F4A_7C15);
    let s = base ^ mix;
    Rng(if s == 0 { 1 } else { s })
}

/// Бюджет фаззера. По умолчанию скромный — секунды в debug-профиле, чтобы `cargo test`
/// оставался быстрым. Для гейта P2 (§20: «fuzz 30 мин без panic») задают либо итерации
/// `VEC_DHT_FUZZ_ITERS=…`, либо wall-clock `VEC_DHT_FUZZ_SECS=1800`; второе честнее, потому
/// что стоимость итерации у четырёх тестов различается на порядки (ed25519-верификация против
/// целочисленного `l2_sq`). Прогон гейта:
/// `VEC_DHT_FUZZ_SECS=1800 cargo test -p vecdht-crypto --test fuzz_verify --release -- --nocapture`.
struct Budget {
    limit: u64,
    deadline: Option<std::time::Instant>,
    started: std::time::Instant,
    done: u64,
}

impl Budget {
    fn new(default_iters: u64) -> Self {
        let secs = std::env::var("VEC_DHT_FUZZ_SECS").ok().and_then(|s| s.parse::<u64>().ok());
        let limit = match secs {
            Some(_) => u64::MAX,
            None => std::env::var("VEC_DHT_FUZZ_ITERS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(default_iters),
        };
        Self {
            limit,
            deadline: secs.map(|s| std::time::Instant::now() + std::time::Duration::from_secs(s)),
            started: std::time::Instant::now(),
            done: 0,
        }
    }

    /// Проверить бюджет и посчитать итерацию: тело цикла не должно думать о границах.
    fn run(&mut self) -> bool {
        if self.done >= self.limit {
            return false;
        }
        if let Some(t) = self.deadline {
            if std::time::Instant::now() >= t {
                return false;
            }
        }
        self.done += 1;
        true
    }

    /// Итог длинного прогона виден только с `--nocapture` — обычный `cargo test` молчит
    /// намеренно, чтобы вывод юнит-тестов не засорялся.
    fn finish(&self, name: &str) {
        if self.deadline.is_some() {
            eprintln!(
                "{name}: {} итераций за {:.1} с",
                self.done,
                self.started.elapsed().as_secs_f64()
            );
        }
    }
}

#[test]
fn signature_verification_never_panics_and_never_fabricates() {
    let mut rng = fuzz_rng(0xC0FF_EE00_0000_0008);
    let real = Identity::from_seed([0x77; 32]);
    let body: Vec<u8> = (0..64).map(|i| i as u8).collect();
    let good_sig = real.sign_body(domain::MATCH, Kind::MatchResult, &body);
    let domains = [domain::MATCH, domain::MEMBER, domain::REPLICA, DOMAIN_NODE_CERT];

    // ed25519-верификация в debug-профиле стоит миллисекунды, поэтому бюджет здесь
    // меньше, чем у целочисленных тестов; полный прогон — `--release`.
    let mut budget = Budget::new(300);
    while budget.run() {
        let pk: [u8; 32] = rng.bytes();
        let sig: [u8; 64] = rng.bytes();
        let dom = domains[rng.below(domains.len())];
        // (1) случайная пара ключ/подпись: не panic и не true.
        let r = catch_unwind(AssertUnwindSafe(|| {
            verify_body(&pk, dom, Kind::MatchResult, &body, &sig)
        }));
        match r {
            Err(_) => panic!("panic в verify_body на pubkey {}", hex::encode(pk)),
            Ok(Ok(true)) => {
                panic!("подделка прошла проверку: pk {} sig {}", hex::encode(pk), hex::encode(sig))
            }
            Ok(_) => {}
        }
        // (2) настоящая подпись, чужой ключ — отклоняется всегда.
        assert!(
            !verify_domain(&pk, dom, &body, &good_sig),
            "verify_domain пропустил подпись чужим ключом {}",
            hex::encode(pk)
        );
        // (3) настоящая подпись с одним перевёрнутым битом — отклоняется.
        let mut tampered = good_sig;
        tampered[rng.below(64)] ^= 1 << rng.below(8);
        if tampered != good_sig {
            assert_ne!(
                verify_body(&real.pubkey(), domain::MATCH, Kind::MatchResult, &body, &tampered),
                Ok(true),
                "подпись, изменённая на один бит, прошла проверку (malleability)"
            );
        }
    }
    // Домен и flags обязаны входить в digest (§5.2) — это про одного ключа, вне цикла.
    assert_ne!(
        sig_digest(domain::MATCH, Kind::MatchResult, FLAG_SIGNED, &body),
        sig_digest(domain::FIND, Kind::MatchResult, FLAG_SIGNED, &body)
    );
    assert_ne!(
        sig_digest(domain::MATCH, Kind::MatchResult, FLAG_SIGNED, &body),
        sig_digest(domain::MATCH, Kind::MatchResult, 0, &body)
    );
    assert_eq!(
        verify_body(&real.pubkey(), domain::MATCH, Kind::MatchResult, &body, &good_sig),
        Ok(true),
        "настоящая подпись перестала проходить"
    );
    budget.finish("signature_verification_never_panics_and_never_fabricates");
}

#[test]
fn quantization_and_distances_keep_their_invariants() {
    let mut rng = fuzz_rng(0x5EED_F00D_0000_0008);
    let mut budget = Budget::new(2_000);
    while budget.run() {
        // (a) размерность проверяется, вырожденные float — тоже
        let n = if rng.below(4) == 0 { DIM } else { rng.below(DIM + 3) };
        let v = rng.f64s(n);
        let mut m = v.clone();
        let norm = catch_unwind(AssertUnwindSafe(|| l2_normalize(&mut m))).expect("panic в l2_normalize");
        let q = catch_unwind(AssertUnwindSafe(|| quantize_slice(&v))).expect("panic в quantize_slice");
        if n != DIM {
            assert!(q.is_err(), "вектор размерности {n} принят как {DIM}");
            assert!(norm.is_err() || n == DIM);
        } else if let Ok(q) = q {
            for &x in q.iter() {
                assert!((-127..=127).contains(&(x as i32)), "квант вне сетки: {x}");
            }
        }
        // (b) l2_sq: симметричен, неотрицателен, в границе u32 без переполнения
        let a = rng.i8v::<DIM>();
        let b = rng.i8v::<DIM>();
        let d = l2_sq(&a, &b);
        assert_eq!(d, l2_sq(&b, &a), "дистанция не симметрична");
        assert!(d <= (384 * 255 * 255), "l2_sq вышел за границу сетки: {d}");
        assert!((0.0..=1.0).contains(&similarity_from_d2(d)), "similarity вне [0,1]");
        // (c) argmin корректен и tie-break берёт меньший индекс
        let centroids: Vec<[i8; DIM]> = (0..8).map(|_| rng.i8v::<DIM>()).collect();
        let refs: Vec<&[i8; DIM]> = centroids.iter().collect();
        let c = assign_cluster(&a, &refs);
        let dc = l2_sq(&a, &centroids[c as usize]);
        for (i, cent) in centroids.iter().enumerate() {
            let di = l2_sq(&a, cent);
            assert!(dc <= di, "argmin неверен: выбран {c} с {dc}, есть {i} с {di}");
            if di == dc {
                assert!((i as u16) >= c, "tie-break обязан брать меньший индекс, взял {c} при {i}");
            }
        }
        // (d) top_clusters — по контракту (d2 ASC, cluster ASC)
        let top = top_clusters(&a, &refs, 4);
        assert!(top.len() <= 4);
        for w in top.windows(2) {
            let x = l2_sq(&a, &centroids[w[0] as usize]);
            let y = l2_sq(&a, &centroids[w[1] as usize]);
            assert!(x < y || (x == y && w[0] < w[1]), "top_clusters вне контракта сортировки");
        }
    }
    budget.finish("quantization_and_distances_keep_their_invariants");
}

#[test]
fn pow_threshold_is_monotone_in_bits() {
    let mut rng = fuzz_rng(0x9E37_79B9_0000_0008);
    let mut budget = Budget::new(1_500);
    while budget.run() {
        let input: Vec<u8> = (0..40).map(|_| rng.byte()).collect();
        let nonce = rng.next();
        let mut prev = false;
        for bits in 1..=32u32 {
            let ok = pow_ok(&input, nonce, bits);
            if ok {
                assert!(
                    prev || bits == 1,
                    "порог не монотонен: {bits} бит прошёл, а {} — нет",
                    bits - 1
                );
            }
            prev = ok;
        }
        // вне диапазона — отказ без паника
        assert!(!pow_ok(&input, nonce, 0));
        assert!(!pow_ok(&input, nonce, 65));
    }
    budget.finish("pow_threshold_is_monotone_in_bits");
}

#[test]
fn cert_verification_rejects_every_malformed_shape_without_panicking() {
    let mut rng = fuzz_rng(0xC0DE_0000_0000_0008);
    let authority = Identity::from_seed([0x05; 32]);
    let set = AuthoritySet::new(vec![authority.pubkey()], 1);
    let sk = SigningKey::from_bytes(&authority.seed());
    let genesis = [1u8; 32];
    let base = NodeCert {
        version: vecdht_wire::cert::CERT_VERSION,
        genesis_hash: genesis,
        role: Role::IndexNode,
        owner_ed25519: [2; 32],
        dht_peer_id: vec![0x00, 0x24, 0x00],
        shards: vec![0, 63],
        capacity_entries: 1000,
        valid_from: 1_000,
        valid_until: 2_000,
        nonce: [7; 16],
        authority_sigs: vec![],
    };
    // Хороший сертификат: подпись авторитета поверх unsigned_body.
    let good = sign_cert(&base, &sk);
    assert_eq!(verify_cert(&good, &set, &genesis, 1_500, |_| false), Ok(()));
    assert_eq!(verify_index_cert(&good, &set, &genesis, 1_500, |_| false, 63), Ok(()));

    let mut budget = Budget::new(1_500);
    while budget.run() {
        let i = budget.done;
        let mut c = base.clone();
        match rng.below(8) {
            0 => c.version = rng.below(65536) as u16,
            1 => c.role = [Role::Agent, Role::Relay][rng.below(2)],
            2 => c.shards = (0..rng.below(80)).map(|_| rng.below(80) as u16).collect(),
            3 => c.capacity_entries = rng.next() as u32,
            4 => c.valid_from = rng.next() as u32,
            5 => c.valid_until = rng.next() as u32,
            6 => c.authority_sigs = vec![rng.bytes::<64>(); rng.below(5)],
            _ => c = sign_cert(&base, &sk),
        }
        c.genesis_hash = if rng.below(4) == 0 { rng.bytes() } else { genesis };
        c.nonce = rng.bytes();
        let now = rng.next() as u32;
        let revoked = rng.below(4) == 0;
        let res = catch_unwind(AssertUnwindSafe(|| {
            verify_cert(&c, &set, &genesis, now, |_| revoked)
        }))
        .unwrap_or_else(|_| panic!("panic в verify_cert на {}", hex::encode(c.encode())));
        if let Ok(()) = res {
            // Пропустить мог только подписанный, своевременный и не отозванный сертификат.
            assert_eq!(c.version, vecdht_wire::cert::CERT_VERSION, "пропущен чужой version (iter {i})");
            assert_eq!(c.genesis_hash, genesis, "пропущен чужой genesis (iter {i})");
            assert!(c.capacity_entries > 0, "пропущен нулевой capacity (iter {i})");
            assert!(!revoked, "пропущен отозванный кредашиал (iter {i})");
            assert!(c.valid_from <= now && now < c.valid_until, "пропущен просроченный (iter {i})");
            assert!(
                set.count_valid(&c.unsigned_body(), DOMAIN_NODE_CERT, &c.authority_sigs) >= set.threshold,
                "пропущен кредашиал без подписи авторитета (iter {i})"
            );
        }
    }
    budget.finish("cert_verification_rejects_every_malformed_shape_without_panicking");
}
