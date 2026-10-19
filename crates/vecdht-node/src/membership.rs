//! `ShardMembership`: самовалидируемая цепочка эпизод (§9.2).
//!
//! Валидация не зависит ни от DHT, ни от gossip: узел держит последнюю принятую эпизоду и
//! проверяет переход локально — `t` подписей участников **предыдущей** эпизоды над байтами
//! `unsigned_body()`, а genesis — порог подписей bootstrap-авторитета из артефакта.

use thiserror::Error;
use vecdht_crypto::{AuthoritySet, Identity};
use vecdht_wire::messages::{domain, Member, MembershipUpdate};

use crate::candidates::{self, Holder, MemberList};
use crate::config::Params;

/// Первая эпизода шарда подписывается авторитетами, а не участниками: участников ещё нет.
pub const GENESIS_EPOCH: u64 = 1;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum MembershipError {
    #[error("членство для шарда {found}, а узел держит {want}")]
    ForeignShard { want: u16, found: u16 },
    #[error("ожидается genesis (epoch = {need}), пришло epoch = {got} (§9.2)")]
    NotGenesis { got: u64, need: u64 },
    #[error("epoch = {got}: следующая эпизода {need} (цепочка не пропускает эпохи)")]
    EpochNotNext { got: u64, need: u64 },
    #[error("genesis не может быть пустым составом: объявить свободным можно только тот шард, который кто-то держал")]
    EmptyGenesis,
    #[error("primary_idx = {idx} вне состава из {len} участников (§9.2)")]
    PrimaryOutOfRange { idx: u8, len: usize },
    #[error("primary_idx = {0}: primary обязан быть первым в детерминированном порядке (§9.3)")]
    PrimaryNotFirst(u8),
    #[error("один ключ в составе дважды: слоты шарда занимают разные узлы, а не один дважды (§9.3)")]
    DuplicateMember,
    #[error("подписант {idx} вне предыдущего состава из {len} (§9.2: индекс смотрит в epoch−1)")]
    SignerOutOfRange { idx: u8, len: usize },
    #[error("подписант {0} подписывает переход дважды")]
    DuplicateSigner(u8),
    #[error("подписей {have} при пороге {need} (§9.2)")]
    BelowThreshold { have: usize, need: usize },
    #[error("состав не совпадает с детерминированным выбором кандидатов (§9.3)")]
    MembersOutOfOrder,
}

/// Принятая эпизода. Держится узлом как единственный источник истины о составе шарда: всё,
/// что дальше проверяется подписью, опирается на `members` именно этого множества.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Membership {
    pub update: MembershipUpdate,
}

impl Membership {
    #[inline]
    pub fn epoch(&self) -> u64 {
        self.update.epoch
    }

    #[inline]
    pub fn shard(&self) -> u16 {
        self.update.shard
    }

    #[inline]
    pub fn members(&self) -> &[Member] {
        &self.update.members
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.update.members.len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.update.members.is_empty()
    }

    /// Primary эпизоды — первый участник (§9.3: он же keeper §9.5, «минимальная позиция в
    /// сортировке»). `None` у пустого состава: там обслуживать некому.
    #[inline]
    pub fn primary(&self) -> Option<[u8; 32]> {
        self.update.members.get(self.update.primary_idx as usize).map(|m| m.owner_ed25519)
    }

    #[inline]
    pub fn index_of(&self, owner: &[u8; 32]) -> Option<usize> {
        self.update.members.iter().position(|m| &m.owner_ed25519 == owner)
    }

    #[inline]
    pub fn is_member(&self, owner: &[u8; 32]) -> bool {
        self.index_of(owner).is_some()
    }

    pub fn peers(&self, me: &[u8; 32]) -> Vec<[u8; 32]> {
        self.update
            .members
            .iter()
            .filter(|m| &m.owner_ed25519 != me)
            .map(|m| m.owner_ed25519)
            .collect()
    }

    /// Keeper (§9.5): минимальная позиция в сортировке этой эпизоды.
    #[inline]
    pub fn keeper(&self) -> Option<[u8; 32]> {
        candidates::keeper(self.epoch(), self.shard(), self.members())
    }

    /// Байты перехода, которые подписывают участники **этого** множества.
    #[inline]
    pub fn signing_payload(next: &MembershipUpdate) -> Vec<u8> {
        next.unsigned_body()
    }

    /// Подписать переход к `next`. `None`, если подписант в этот состав не входит: его подпись
    /// не была бы подписью участника epoch−1, и валидатор её отверг бы.
    pub fn sign_transition(&self, id: &Identity, next: &MembershipUpdate) -> Option<(u8, [u8; 64])> {
        let idx = self.index_of(&id.pubkey())? as u8;
        Some((idx, id.sign_domain(domain::MEMBER, &next.unsigned_body())))
    }
}

/// Валидатор цепочки. `params` задаёт пороги, `authorities` — только genesis.
#[derive(Debug, Clone)]
pub struct Chain {
    pub shard: u16,
    pub params: Params,
    pub authorities: AuthoritySet,
}

impl Chain {
    /// Проверить переход. `prev = None` означает «у узла ещё нет членства этого шарда» — тогда
    /// принимается только genesis.
    pub fn validate(
        &self,
        prev: Option<&Membership>,
        upd: &MembershipUpdate,
    ) -> Result<Membership, MembershipError> {
        if upd.shard != self.shard {
            return Err(MembershipError::ForeignShard { want: self.shard, found: upd.shard });
        }
        if upd.members.len() > self.params.r {
            // Состав больше R — это не «шард расширили», а попытка раздуть кворум своими узлами.
            return Err(MembershipError::MembersOutOfOrder);
        }
        let mut seen: Vec<[u8; 32]> = Vec::with_capacity(upd.members.len());
        for m in &upd.members {
            if seen.contains(&m.owner_ed25519) {
                return Err(MembershipError::DuplicateMember);
            }
            seen.push(m.owner_ed25519);
        }
        if upd.members.is_empty() {
            if upd.primary_idx != 0 {
                return Err(MembershipError::PrimaryOutOfRange { idx: upd.primary_idx, len: 0 });
            }
        } else if upd.primary_idx != 0 {
            // §9.3: primary — функция детерминированного порядка, а не результат раунда
            // «кто успел объявить себя». Иначе два честных узла могли бы принять два разных
            // состава одной эпохи с разными primary.
            return Err(MembershipError::PrimaryNotFirst(upd.primary_idx));
        }

        let payload = upd.unsigned_body();
        let have = match prev {
            None => {
                if upd.epoch != GENESIS_EPOCH {
                    return Err(MembershipError::NotGenesis { got: upd.epoch, need: GENESIS_EPOCH });
                }
                if upd.members.is_empty() {
                    return Err(MembershipError::EmptyGenesis);
                }
                self.check_authorities(&payload, &upd.sigs)?
            }
            Some(prev) => {
                let need = prev.epoch() + 1;
                if upd.epoch != need {
                    return Err(MembershipError::EpochNotNext { got: upd.epoch, need });
                }
                self.check_members(prev, &payload, &upd.sigs)?
            }
        };
        debug_assert!(have >= 1, "порог проверяется в check_*");
        Ok(Membership { update: upd.clone() })
    }

    /// То же плюс сверка состава с детерминированным выбором (§9.3). Без этого проверки подписи
    /// достаточно, чтобы принять состав, который выбрал атакующий: кворум из своих узлов
    /// подписывается так же хорошо, как честный.
    pub fn validate_with_candidates(
        &self,
        prev: Option<&Membership>,
        upd: &MembershipUpdate,
        holders: &[Holder],
        entries: u64,
    ) -> Result<Membership, MembershipError> {
        let m = self.validate(prev, upd)?;
        let expected =
            candidates::members(upd.epoch, self.shard, holders, self.params.r, entries);
        if expected != m.members() {
            return Err(MembershipError::MembersOutOfOrder);
        }
        Ok(m)
    }

    /// Порог авторитетов: индексы смотрят в порядок ключей `authorities` (§15.2).
    fn check_authorities(
        &self,
        payload: &[u8],
        sigs: &[(u8, [u8; 64])],
    ) -> Result<usize, MembershipError> {
        let n = self.authorities.keys.len();
        Self::check_indices(sigs, n)?;
        let list: Vec<[u8; 64]> = sigs.iter().map(|(_, s)| *s).collect();
        // Порог авторитета, а не порог членства: genesis — действие сети, а не шарда.
        // `count_valid`, а не `check`: последний сообщает «недостаточно» как `Err` без числа,
        // а диагностика обязана говорить, сколько подписей всё-таки прошло (§15.2).
        let have = self.authorities.count_valid(payload, domain::MEMBER, &list);
        if have >= self.params.authority_threshold {
            Ok(have)
        } else {
            Err(MembershipError::BelowThreshold {
                have,
                need: self.params.authority_threshold,
            })
        }
    }

    /// Порог участников предыдущей эпизоды: каждая подпись проверяется ровно по ключу своего
    /// индекса, поэтому «подпись участника» — это не «подпись, которую кто-то провёл как
    /// участника».
    fn check_members(
        &self,
        prev: &Membership,
        payload: &[u8],
        sigs: &[(u8, [u8; 64])],
    ) -> Result<usize, MembershipError> {
        let n = prev.len();
        Self::check_indices(sigs, n)?;
        let need = self.params.membership_threshold;
        let mut have = 0usize;
        for (idx, sig) in sigs {
            let key = prev.members()[*idx as usize].owner_ed25519;
            if vecdht_crypto::verify_domain(&key, domain::MEMBER, payload, sig) {
                have += 1;
            }
        }
        if have >= need {
            Ok(have)
        } else {
            Err(MembershipError::BelowThreshold { have, need })
        }
    }

    fn check_indices(sigs: &[(u8, [u8; 64])], len: usize) -> Result<(), MembershipError> {
        let mut used: Vec<u8> = Vec::with_capacity(sigs.len());
        for (idx, _) in sigs {
            if *idx as usize >= len {
                return Err(MembershipError::SignerOutOfRange { idx: *idx, len });
            }
            if used.contains(idx) {
                return Err(MembershipError::DuplicateSigner(*idx));
            }
            used.push(*idx);
        }
        Ok(())
    }
}

/// Собрать `MembershipUpdate` из ожидаемого состава и собранных подписей.
pub fn build_update(list: &MemberList, sigs: Vec<(u8, [u8; 64])>) -> MembershipUpdate {
    MembershipUpdate {
        epoch: list.epoch,
        shard: list.shard,
        members: list.members.clone(),
        primary_idx: 0,
        generated_at: list.generated_at,
        sigs,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vecdht_artifact::reference_manifest;
    use vecdht_wire::messages::Codec;

    fn id(seed: u8) -> Identity {
        Identity::from_seed([seed; 32])
    }

    fn params() -> Params {
        Params::from_manifest(&reference_manifest()).unwrap()
    }

    fn member(i: u8) -> Member {
        Member {
            owner_ed25519: id(i).pubkey(),
            dht_peer_id: vec![0xAA; 34],
            capacity_entries: 10_000,
        }
    }

    fn upd(epoch: u64, members: Vec<Member>, sigs: Vec<(u8, [u8; 64])>) -> MembershipUpdate {
        MembershipUpdate { epoch, shard: 0, members, primary_idx: 0, generated_at: 100, sigs }
    }

    /// Авторитеты genesis: те же пять ключей, что в эталонном манифесте (3-of-5).
    fn authorities() -> AuthoritySet {
        let m = reference_manifest();
        AuthoritySet::new(m.authority.keys.clone(), m.authority.threshold as usize)
    }

    fn authority_keys() -> Vec<Identity> {
        (1u8..=5).map(id).collect()
    }

    fn genesis(members: Vec<Member>) -> MembershipUpdate {
        let list = MemberList { epoch: GENESIS_EPOCH, shard: 0, members, generated_at: 100 };
        let u = upd(GENESIS_EPOCH, list.members.clone(), Vec::new());
        let payload = u.unsigned_body();
        let sigs: Vec<(u8, [u8; 64])> = authority_keys()
            .iter()
            .take(3)
            .enumerate()
            .map(|(i, a)| (i as u8, a.sign_domain(domain::MEMBER, &payload)))
            .collect();
        build_update(&list, sigs)
    }

    fn chain() -> Chain {
        Chain { shard: 0, params: params(), authorities: authorities() }
    }

    #[test]
    fn genesis_needs_the_authority_threshold_and_nothing_else() {
        let c = chain();
        let g = genesis(vec![member(10), member(11), member(12)]);
        let m = c.validate(None, &g).expect("genesis 3-of-5 принимается");
        assert_eq!(m.epoch(), GENESIS_EPOCH);
        assert_eq!(m.len(), 3);
        assert_eq!(m.primary(), Some(member(10).owner_ed25519));

        // Две подписи вместо порога трёх.
        let weak = {
            let members = vec![member(10), member(11), member(12)];
            let u = upd(GENESIS_EPOCH, members.clone(), Vec::new());
            let payload = u.unsigned_body();
            let sigs: Vec<(u8, [u8; 64])> = authority_keys()
                .iter()
                .take(2)
                .enumerate()
                .map(|(i, a)| (i as u8, a.sign_domain(domain::MEMBER, &payload)))
                .collect();
            upd(GENESIS_EPOCH, members, sigs)
        };
        assert_eq!(
            c.validate(None, &weak),
            Err(MembershipError::BelowThreshold { have: 2, need: 3 }),
            "порог авторитета — 3 из 5 (§15.2), а не «сколько прислали»"
        );

        // Эпизода 2 без предыдущей — это не genesis.
        assert_eq!(
            c.validate(None, &upd(2, vec![member(10)], Vec::new())),
            Err(MembershipError::NotGenesis { got: 2, need: 1 })
        );
        // Пустой genesis.
        assert_eq!(c.validate(None, &genesis(vec![])), Err(MembershipError::EmptyGenesis));
    }

    #[test]
    fn transition_needs_t_signatures_from_the_previous_set() {
        let c = chain();
        let prev = c.validate(None, &genesis(vec![member(10), member(11), member(12)])).unwrap();
        let next_members = vec![member(10), member(11), member(12)];
        let mut next = upd(prev.epoch() + 1, next_members.clone(), Vec::new());
        let payload = next.unsigned_body();
        next.sigs = vec![
            prev.sign_transition(&id(10), &next).unwrap(),
            prev.sign_transition(&id(12), &next).unwrap(),
        ];
        assert_eq!(
            payload,
            next.unsigned_body(),
            "список подписей не входит в подписываемые байты"
        );
        let m = c.validate(Some(&prev), &next).unwrap();
        assert_eq!(m.epoch(), 2);

        // Подпись узла, которого в предыдущем составе нет, не считается участником.
        let mut forged = next.clone();
        forged.sigs = vec![
            (
                0,
                id(10).sign_domain(domain::MEMBER, &forged.unsigned_body()),
            ),
            (
                9,
                id(99).sign_domain(domain::MEMBER, &forged.unsigned_body()),
            ),
        ];
        assert_eq!(
            c.validate(Some(&prev), &forged),
            Err(MembershipError::SignerOutOfRange { idx: 9, len: 3 }),
            "индекс смотрит в набор epoch−1, а не в новый состав"
        );

        // Одна подпись при пороге две.
        let mut one = next.clone();
        one.sigs.truncate(1);
        assert_eq!(c.validate(Some(&prev), &one), Err(MembershipError::BelowThreshold {
            have: 1,
            need: 2
        }));

        // Пропуск эпохи.
        let mut skip = next.clone();
        skip.epoch += 1;
        skip.sigs = vec![
            prev.sign_transition(&id(10), &skip).unwrap(),
            prev.sign_transition(&id(11), &skip).unwrap(),
        ];
        assert_eq!(c.validate(Some(&prev), &skip), Err(MembershipError::EpochNotNext {
            got: 3,
            need: 2
        }));
    }

    #[test]
    fn signer_must_belong_to_the_previous_epoch_not_the_new_one() {
        let c = chain();
        let prev = c.validate(None, &genesis(vec![member(10), member(11), member(12)])).unwrap();
        // Состав без 12: уходящий подписывает собственный уход (индекс — в prev).
        let mut next = upd(2, vec![member(10), member(11)], Vec::new());
        next.sigs = vec![
            prev.sign_transition(&id(10), &next).unwrap(),
            prev.sign_transition(&id(12), &next).unwrap(),
        ];
        let m = c.validate(Some(&prev), &next).unwrap();
        assert!(!m.is_member(&member(12).owner_ed25519));
        assert_eq!(
            prev.sign_transition(&id(99), &next),
            None,
            "не-участник не может выдать подпись перехода"
        );
    }

    #[test]
    fn empty_membership_is_a_legitimate_transition_not_a_bug() {
        // §9.5: объявить шард свободным можно только подписью участников последней эпизоды.
        let c = chain();
        let prev = c.validate(None, &genesis(vec![member(10), member(11), member(12)])).unwrap();
        let mut next = upd(2, Vec::new(), Vec::new());
        next.sigs = vec![
            prev.sign_transition(&id(10), &next).unwrap(),
            prev.sign_transition(&id(11), &next).unwrap(),
        ];
        let m = c.validate(Some(&prev), &next).unwrap();
        assert!(m.is_empty());
        assert_eq!(m.primary(), None, "у пустого состава нет primary");
        assert_eq!(m.keeper(), None);
        // Пустой состав с «primary» — неканонический переход. Декодер так не считает (длина
        // списка для него — часть потока, а не политика, §5.3), поэтому правило проверяет
        // валидатор цепочки: ровно один нулевой индекс при нулевом составе.
        let mut bad = next.clone();
        bad.primary_idx = 1;
        assert_eq!(
            vecdht_wire::messages::MembershipUpdate::decode(&bad.encode_signed(&[0u8; 64])).unwrap().primary_idx,
            1,
            "байты читаются: отвергать обязан валидатор, а не разбор"
        );
        assert_eq!(
            c.validate(Some(&prev), &bad),
            Err(MembershipError::PrimaryOutOfRange { idx: 1, len: 0 }),
            "пустому составу некому назначать primary"
        );
    }

    #[test]
    fn primary_is_always_the_first_in_the_deterministic_order() {
        let c = chain();
        let members = vec![member(10), member(11), member(12)];
        let g = genesis(members.clone());
        let mut selfish = g.clone();
        selfish.primary_idx = 2;
        // Перекодировка: подписываемое тело не меняется, поэтому подпись бы прошла — и именно
        // поэтому правило проверяется отдельно от подписи.
        assert_eq!(
            c.validate(None, &selfish),
            Err(MembershipError::PrimaryNotFirst(2)),
            "иначе два узла приняли бы две разные версии одной эпохи"
        );
    }

    #[test]
    fn duplicate_signer_is_counted_once() {
        let c = chain();
        let prev = c.validate(None, &genesis(vec![member(10), member(11), member(12)])).unwrap();
        let mut next = upd(2, vec![member(10), member(11), member(12)], Vec::new());
        let one = prev.sign_transition(&id(10), &next).unwrap();
        next.sigs = vec![one, one];
        assert_eq!(c.validate(Some(&prev), &next), Err(MembershipError::DuplicateSigner(0)));
    }

    #[test]
    fn duplicate_member_is_rejected() {
        let c = chain();
        let members = vec![member(10), member(10)];
        assert_eq!(c.validate(None, &genesis(members)), Err(MembershipError::DuplicateMember));
    }

    #[test]
    fn shard_mismatch_is_rejected_before_anything_else() {
        let c = Chain { shard: 7, ..chain() };
        let mut g = genesis(vec![member(10)]);
        g.shard = 8;
        assert_eq!(c.validate(None, &g), Err(MembershipError::ForeignShard { want: 7, found: 8 }));
    }

    #[test]
    fn composition_must_be_the_deterministic_choice() {
        let holders: Vec<Holder> = (10u8..15)
            .map(|i| Holder {
                owner_ed25519: member(i).owner_ed25519,
                dht_peer_id: vec![0xAA; 34],
                capacity_entries: 10_000,
            })
            .collect();
        let c = chain();
        // Честный состав: R=3 первых по порядку.
        let honest = candidates::members(GENESIS_EPOCH, 0, &holders, 3, 0);
        let g = genesis(honest.clone());
        assert_eq!(c.validate_with_candidates(None, &g, &holders, 0).unwrap().len(), 3);

        // Тот же genesis, но состав выбран «вручную» — не по порядку.
        let mut twisted = honest.clone();
        twisted.reverse();
        let bad = genesis(twisted);
        assert_eq!(
            c.validate_with_candidates(None, &bad, &holders, 0),
            Err(MembershipError::MembersOutOfOrder),
            "подписанный, но не детерминированный состав — это захват шарда"
        );

        // Ёмкость отсекается самим выбором: кандидат, не помещающий шард, не попадает в
        // `expected`, и подписанный «вручную» состав с ним расходится (§9.3).
        let g_big = genesis(honest);
        assert_eq!(
            c.validate_with_candidates(None, &g_big, &holders, 20_000),
            Err(MembershipError::MembersOutOfOrder)
        );
    }

    #[test]
    fn too_many_members_is_captured_as_out_of_order() {
        // R — из артефакта; «расширим кворум своими» не является легитимным переходом.
        let c = chain();
        let members: Vec<Member> = (20u8..25).map(member).collect();
        assert_eq!(
            c.validate(None, &genesis(members)),
            Err(MembershipError::MembersOutOfOrder)
        );
    }
}
