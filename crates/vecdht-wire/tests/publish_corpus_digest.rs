//! Прибор (1) порога `E-0100`: корпус `Publish`-кадров БЕЗ объявлений (пустой TLV) обязан
//! остаться байт-в-байт прежним после правки атрибутов (§5.5, «нет тегов = free + unspecified»).
//!
//! Тест намеренно собран только из API, которое существовало до правки, чтобы его можно было
//! положить в worktree базового коммита `9687c32` и снять отпечаток ДО. Никаких `set_intent`,
//! `intent()` и констант фильтров здесь нет: если бы они понадобились, прибор сравнивал бы
//! правку с правкой.
//!
//! Печатает три строки, которые и замораживаются в `lab/expectations/e0100.tsv`:
//! `PUBLISH_CORPUS_FRAMES`, `PUBLISH_CORPUS_BYTES`, `PUBLISH_CORPUS_FNV1A64`.
//! FNV-1a 64 — потому что он не зависит от версии `std` (в отличие от `DefaultHasher`) и
//! пересчитывается вручную из лога.

use vecdht_wire::codec::DIM;
use vecdht_wire::messages::{Codec, Publish};

const FRAMES: usize = 256;

/// Детерминированный генератор: корпус должен быть одинаков в любом worktree и на любой машине.
struct Lcg(u64);

impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        self.0
    }

    fn fill(&mut self, out: &mut [u8]) {
        for b in out.iter_mut() {
            *b = self.next() as u8;
        }
    }
}

fn frame(i: usize, rng: &mut Lcg) -> Publish {
    let mut raw = [0u8; DIM];
    rng.fill(&mut raw);
    let mut vec_q = [0i8; DIM];
    for (dst, src) in vec_q.iter_mut().zip(raw.iter()) {
        *dst = *src as i8;
    }
    let mut owner = [0u8; 32];
    rng.fill(&mut owner);
    let mut intent_id = [0u8; 32];
    rng.fill(&mut intent_id);
    Publish {
        preprocessing_version: 1,
        cluster_id: (i % 16) as u16,
        vec_q,
        owner_ed25519: owner,
        ttl_buckets: 225,
        published_bucket: 106_250_000 + i as u32,
        pow_bits: 20,
        // Nonce — тот же генератор: тело кадра обязано быть разным у всех 256 записей.
        pow_nonce: rng.next(),
        intent_id,
        tlv: Vec::new(),
    }
}

fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in bytes {
        h ^= *b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

#[test]
fn declaration_free_corpus_is_byte_stable() {
    let mut rng = Lcg(0x5eed_0100_d1ce_b00c);
    let mut all = Vec::new();
    for i in 0..FRAMES {
        let f = frame(i, &mut rng);
        assert!(f.tlv.is_empty(), "корпус обязан быть без объявлений");
        all.extend_from_slice(&f.encode_unsigned());
    }
    let digest = fnv1a64(&all);
    println!("PUBLISH_CORPUS_FRAMES={FRAMES}");
    println!("PUBLISH_CORPUS_BYTES={}", all.len());
    println!("PUBLISH_CORPUS_FNV1A64={digest:016x}");
}
