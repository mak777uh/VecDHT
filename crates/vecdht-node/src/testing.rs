//! Помощники интеграционных тестов и гейтов §19.1.
//!
//! Всё, что здесь есть, существует по одной причине: тесты обязаны строить *легитимные* сообщения,
//! а не байты, которые библиотека случайно принимает. Поэтому минимум три вещи нельзя заменить
//! литералами в самом тесте:
//!
//! * genesis эпохи 1 подписывается bootstrap-авторитетом из артефакта (3 из 5, §15.2) — иначе
//!   ни один переход цепочки не пройдёт `Chain::validate`;
//! * PoW майнится под фактическую сложность манифеста, причём дешёвую: 24 бита превращают
//!   интеграционный тест в бенчмарк blake3, а политический пол («не ниже 24») живёт в артефакте,
//!   а не в этом модуле (§11.2);
//! * состав epoch 1 идёт в детерминированном порядке (§9.3): собранный вручную список
//!   расходится с `candidates::members` и ловится `MembersOutOfOrder`.
//!
//! Помощники публичны и вне `cfg(test)` намеренно: `tests/gates_p4.rs`, `vecdht-cli demo` и
//! `sdk`-харнес собирают сеть одними и теми же руками, и «тест прошёл на своей сборке» не должен
//! стать способом прохождения гейта.

use std::path::Path;

use vecdht_artifact::Manifest;
use vecdht_crypto::{intent_id, pow_input, pow_ok, AuthoritySet, Identity};
use vecdht_wire::messages::{Codec, Find, Member, MembershipUpdate, Publish, Tlv};
use vecdht_wire::DIM;

use crate::candidates::{self, Holder};
use crate::config::Params;
use crate::membership::{self, Chain, GENESIS_EPOCH};
use crate::node::ShardNode;

/// Байты `dht_peer_id` тестового узла: транспорт здесь не настоящий, но длина и непустота — как
/// в спеке (§4.1: libp2p PeerId 34 байта).
pub const DHT_PEER_ID: [u8; 34] = [0xAA; 34];

/// Пять ключей bootstrap-авторитета эталонного артефакта. Совпадают с `reference_manifest`
/// намеренно: тот же seed ⇒ тот же pubkey ⇒ порогу 3-of-5 есть что набирать (§15.2).
pub const AUTHORITY_SEEDS: [u8; 5] = [1, 2, 3, 4, 5];

/// Ёмкость тестового держателя: заведомо больше любого тестового шарда, чтобы фильтр `fits`
/// не мешал сценариям, где он не проверяется (§9.3).
pub const SPACIOUS_CAPACITY: u64 = 1 << 20;

/// Эталонный манифест с другой сложностью PoW.
///
/// Диапазон `[bits, bits+4]` двигается вместе со значением по умолчанию: `Params::from_manifest`
/// требует `min ≤ default ≤ max`, и «дешёвый тестовый артефакт» иначе отвергался бы как
/// внутренне противоречивый.
pub fn manifest(pow_bits: u32) -> Manifest {
    let mut m = vecdht_artifact::reference_manifest();
    m.power.pow_bits_default = pow_bits;
    m.power.pow_bits_min = pow_bits;
    m.power.pow_bits_max = pow_bits + 4;
    m
}

/// Параметры узла для теста: тот же манифест, что в бою, только со своей сложностью.
pub fn params(pow_bits: u32) -> Params {
    Params::from_manifest(&manifest(pow_bits))
        .expect("тестовый манифест обязан быть внутренне согласован")
}

pub fn identity(seed: u8) -> Identity {
    Identity::from_seed([seed; 32])
}

pub fn authorities() -> Vec<Identity> {
    AUTHORITY_SEEDS.iter().map(|s| identity(*s)).collect()
}

/// Тот же набор, что записан в `reference_manifest().authority`: 3 из 5 (§15.2).
pub fn authority_set() -> AuthoritySet {
    let m = vecdht_artifact::reference_manifest();
    AuthoritySet::new(m.authority.keys.clone(), m.authority.threshold as usize)
}

/// Держатель кредашиала с тестовой ёмкостью. `Holder` собирается напрямую, а не из `NodeCert`:
/// валидность кредашиала — ответственность §4.2 и её own-тесты, здесь важна только роль и
/// покрытые шарды.
pub fn holder(seed: u8) -> Holder {
    Holder {
        owner_ed25519: identity(seed).pubkey(),
        dht_peer_id: DHT_PEER_ID.to_vec(),
        capacity_entries: SPACIOUS_CAPACITY,
    }
}

pub fn holders(seeds: &[u8]) -> Vec<Holder> {
    seeds.iter().map(|s| holder(*s)).collect()
}

pub fn member(seed: u8) -> Member {
    holder(seed).as_member()
}

/// Цепочка валидации для теста: шард + параметры + авторитеты из эталонного артефакта.
pub fn chain(shard: u16, pow_bits: u32) -> Chain {
    Chain { shard, params: params(pow_bits), authorities: authority_set() }
}

/// Состав эпохи 1 в детерминированном порядке (§9.3): те же `seeds`, но отсортированные по
/// `candidate_order_key`, поэтому `validate_with_candidates` проходит при `entries = 0` и
/// `holders.len() ≤ r`.
pub fn genesis_members(shard: u16, seeds: &[u8]) -> Vec<Member> {
    candidates::ordered(GENESIS_EPOCH, shard, &holders(seeds))
        .iter()
        .map(Holder::as_member)
        .collect()
}

/// Genesis-переход, подписанный первыми тремя авторитетами.
///
/// Подписи идут по индексам в порядке `authority_set().keys`, а не «сколько удалось собрать»:
/// порог 3 из 5 проверяется именно как 3 разных ключа (§15.2).
pub fn genesis_update(shard: u16, seeds: &[u8], generated_at: u32) -> MembershipUpdate {
    let list = candidates::MemberList {
        epoch: GENESIS_EPOCH,
        shard,
        members: genesis_members(shard, seeds),
        generated_at,
    };
    let upd = membership::build_update(&list, Vec::new());
    let payload = upd.unsigned_body();
    let need = authority_set().threshold;
    let sigs: Vec<(u8, [u8; 64])> = authorities()
        .iter()
        .take(need)
        .enumerate()
        .map(|(i, a)| (i as u8, a.sign_domain(vecdht_wire::messages::domain::MEMBER, &payload)))
        .collect();
    membership::build_update(&list, sigs)
}

/// Кадр `MembershipUpdate` с первой подписью: `on_frame` требует подписанного кадра (§5.3), а
/// список подписей перехода лежит в теле.
pub fn signed_frame(upd: &MembershipUpdate) -> Vec<u8> {
    match upd.sigs.first() {
        Some((_, sig)) => upd.encode_signed(sig),
        None => upd.encode_unsigned(),
    }
}

/// Детерминированный тестовый вектор: значения зависят только от сида и координаты, без `sin`
/// и `exp` — платформенные расхождения libm не должны появляться в golden-тестах (§6.3).
pub fn vector(seed: u8) -> [i8; DIM] {
    let mut v = [0i8; DIM];
    for (i, x) in v.iter_mut().enumerate() {
        // Арифметика идёт в i32, в i8 значение превращается уже со сдвигом: `(0..200) as i8`
        // даёт отрицательные числа, и `- 100` на них падало бы panic'ом в debug-сборке — тест
        // должен проверять протокол, а не арифметику помощника.
        *x = ((i as i32 * 7 + seed as i32 * 13) % 200 - 100) as i8;
    }
    v
}

/// Наивный майнинг nonce.
///
/// `vecdht_crypto::mine_pow` не используется: он проверяет политический диапазон 24..=28, а
/// тестам нужен дешёвый PoW. Ограничение попыток остаётся — отсутствие nonce за разумное число
/// итераций означает «сложность для теста выбрана слишком высокая», и это надо увидеть сразу.
pub fn mine(input: &[u8], bits: u32) -> u64 {
    for nonce in 0..(1u64 << 32) {
        if pow_ok(input, nonce, bits) {
            return nonce;
        }
    }
    panic!("PoW: nonce не найден за 2^32 попыток при bits={bits}");
}

/// Что тестовый агент сообщает о записи (§5.4, §9.6, §11.2).
///
/// Девять позиционных аргументов clippy отвергает не зря: `epoch` и `published_bucket` нельзя
/// перепутать, когда они именованы. Литерал `Publish`, собранный «на глаз», был бы тестом на
/// удачу, а не на протокол: узел отвергает кадр по чужой эпизоде, и этот отказ надо ловить
/// проверкой, а не аргументом не того порядка.
#[derive(Debug, Clone, Copy)]
pub struct PublishSpec<'a> {
    pub agent: &'a Identity,
    pub vec_q: &'a [i8; DIM],
    pub cluster_id: u16,
    pub shard: u16,
    /// Эпизода, которую агент считает действующей (§9.2): она входит в PoW-вход.
    pub epoch: u64,
    /// Бакет публикации из `TimeMark`, а не из локальных часов (§9.6).
    pub published_bucket: u32,
    /// TTL в бакетах: 225 = час (§2).
    pub ttl_buckets: u16,
    /// Сложность PoW: ровно та, что в манифесте этого теста (§11.2).
    pub bits: u32,
}

impl PublishSpec<'_> {
    /// Структура `Publish` с произвольным TLV: `intent_id` из вектора, nonce под фактическую
    /// сложность, `expires = published_bucket + ttl` — тот же расчёт, что делает клиент.
    pub fn msg(&self, tlv: Tlv) -> Publish {
        let intent = intent_id(self.vec_q, PREPROCESSING_VERSION);
        let expires = self.published_bucket.saturating_add(self.ttl_buckets as u32);
        let input =
            pow_input(&self.agent.pubkey(), self.shard, self.epoch, &intent, expires);
        Publish {
            preprocessing_version: PREPROCESSING_VERSION,
            cluster_id: self.cluster_id,
            vec_q: *self.vec_q,
            owner_ed25519: self.agent.pubkey(),
            ttl_buckets: self.ttl_buckets,
            published_bucket: self.published_bucket,
            pow_bits: self.bits as u8,
            pow_nonce: mine(&input, self.bits),
            intent_id: intent,
            tlv,
        }
    }

    /// Кадр для `on_frame`, без TLV.
    ///
    /// Кадр не подписывается: подпись `Publish` опциональна (§5.3), а `owner_ed25519` в теле узел
    /// сверяет с PoW-привязкой, так что подделка не даёт ничего.
    pub fn frame(&self) -> Vec<u8> {
        self.msg(Vec::new()).encode_unsigned()
    }
}

/// `preprocessing_version` эталонного артефакта: клиент обязан объявить ровно её, иначе узел
/// ответит `MODEL_MISMATCH` (§6.6).
pub const PREPROCESSING_VERSION: u16 = 1;

/// Кадр `Find` по одному кластеру: `clusters` обязан принадлежать этому шарду (§7.4).
pub fn find_frame(
    agent: &Identity,
    query: &[i8; DIM],
    clusters: &[u16],
    top_k: u16,
    query_id: u64,
) -> Vec<u8> {
    Find {
        preprocessing_version: PREPROCESSING_VERSION,
        query_vector: *query,
        clusters: clusters.to_vec(),
        top_k,
        query_id,
        requester_ed25519: agent.pubkey(),
        tlv: Vec::new(),
    }
    .encode_unsigned()
}

/// Открыть узел шарда в тестовом каталоге: identity и ростер по сидам, остальное — из параметров.
pub fn node(
    dir: &Path,
    shard: u16,
    seed: u8,
    params: Params,
    roster_seeds: &[u8],
) -> ShardNode {
    let id = identity(seed);
    ShardNode::open(
        dir,
        shard,
        id,
        DHT_PEER_ID.to_vec(),
        params,
        authority_set(),
        holders(roster_seeds),
    )
    .expect("открыть тестовый узел шарда")
}

#[cfg(test)]
mod tests {
    use super::*;
    use vecdht_crypto::shard_of_cluster;

    #[test]
    fn genesis_from_helpers_passes_the_chain_and_the_candidate_order() {
        let p = params(8);
        let c = chain(0, 8);
        let roster = holders(&[1, 2, 3]);
        let upd = genesis_update(0, &[1, 2, 3], 100);
        let m = c.validate_with_candidates(None, &upd, &roster, 0).unwrap();
        assert_eq!(m.epoch(), GENESIS_EPOCH);
        assert_eq!(m.len(), 3);
        assert_eq!(m.primary(), Some(upd.members[0].owner_ed25519));
        // Primary — первый по порядку, а не «первый, кого назвали» (§9.3).
        assert_eq!(m.primary(), Some(genesis_members(0, &[1, 2, 3])[0].owner_ed25519));
        assert!(p.pow_bits == 8, "тестовая сложность берётся из манифеста, а не из константы");
    }

    #[test]
    fn genesis_order_is_the_same_on_every_shard_but_the_keys_differ() {
        // Тот же ростер на другом шарде — другой порядок: иначе состав можно «застолбить».
        assert_ne!(
            genesis_members(0, &[1, 2, 3, 4, 5])
                .iter()
                .map(|m| m.owner_ed25519)
                .collect::<Vec<_>>(),
            genesis_members(1, &[1, 2, 3, 4, 5])
                .iter()
                .map(|m| m.owner_ed25519)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn mined_publish_satisfies_the_nodes_own_pow_check() {
        let agent = identity(77);
        let v = vector(3);
        let bits = 8;
        let spec = PublishSpec {
            agent: &agent,
            vec_q: &v,
            cluster_id: 0,
            shard: 0,
            epoch: 1,
            published_bucket: 500,
            ttl_buckets: 225,
            bits,
        };
        let msg = spec.msg(Vec::new());
        assert_eq!(shard_of_cluster(msg.cluster_id), 0);
        let expires = msg.published_bucket + msg.ttl_buckets as u32;
        let input = pow_input(&agent.pubkey(), 0, 1, &msg.intent_id, expires);
        assert!(
            pow_ok(&input, msg.pow_nonce, msg.pow_bits as u32),
            "узел обязан принять то, что намайнил помощник"
        );
        // Другой бакет TTL — уже другой вход: nonce переиспользовать нельзя (§11.1).
        assert!(!pow_ok(&pow_input(&agent.pubkey(), 0, 1, &msg.intent_id, expires + 1), msg.pow_nonce, bits));
    }

    #[test]
    fn vector_is_a_function_of_the_seed_only() {
        assert_eq!(vector(9), vector(9));
        assert_ne!(vector(9), vector(10));
    }
}
