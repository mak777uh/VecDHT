//! Детерминированный выбор кандидатов на шард (§9.3).
//!
//! Порядок задаёт `blake3(epoch ‖ shard ‖ owner)`: верифицируемая случайная перестановка,
//! которую действующий состав не может сместить в свою пользу. Tie-break — сам ключ владельца,
//! потому что два разных ключа не дают одинаковый `blake3`-вход, а вот одинаковый префикс
//! теоретически возможен: без второго уровня сортировки два узла могли бы разойтись в порядке.

use vecdht_crypto::ids::candidate_order_key;
use vecdht_wire::cert::NodeCert;
use vecdht_wire::messages::{Member, Role};

/// Держатель кредашиала `role=index_node`, годный для этого шарда.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Holder {
    pub owner_ed25519: [u8; 32],
    pub dht_peer_id: Vec<u8>,
    pub capacity_entries: u64,
}

impl Holder {
    /// Ниша кандидата: кредашиал должен покрывать шард и иметь роль index-node (§9.3).
    /// Валидность самого кредашиала (подпись авторитета, срок, отзыв) проверяет вызывающий —
    /// здесь только отбор по роли и покрытию, чтобы функция осталась чистой.
    pub fn from_cert(cert: &NodeCert, shard: u16) -> Option<Holder> {
        if cert.role != Role::IndexNode || !cert.covers_shard(shard) {
            return None;
        }
        Some(Holder {
            owner_ed25519: cert.owner_ed25519,
            dht_peer_id: cert.dht_peer_id.clone(),
            capacity_entries: cert.capacity_entries as u64,
        })
    }

    pub fn as_member(&self) -> Member {
        Member {
            owner_ed25519: self.owner_ed25519,
            dht_peer_id: self.dht_peer_id.clone(),
            capacity_entries: self.capacity_entries,
        }
    }

    /// Запись шарда обязана помещаться в декларируемую ёмкость: иначе членство говорит «я держу
    /// этот шард», а диск у этого члена — нет (§9.3, `capacity_entries` из кредашиала).
    #[inline]
    pub fn fits(&self, entries: u64) -> bool {
        self.capacity_entries >= entries
    }
}

/// Порядок кандидатов: по возрастанию `candidate_order_key`, затем по ключу (§9.3).
/// Входная последовательность не важна: результат одинаков на любом узле, у которого тот же
/// набор кредашиалов.
pub fn ordered(epoch: u64, shard: u16, holders: &[Holder]) -> Vec<Holder> {
    let mut v = holders.to_vec();
    v.sort_by(|a, b| {
        let ka = candidate_order_key(epoch, shard, &a.owner_ed25519);
        let kb = candidate_order_key(epoch, shard, &b.owner_ed25519);
        ka.cmp(&kb).then_with(|| a.owner_ed25519.cmp(&b.owner_ed25519))
    });
    v.dedup_by(|a, b| a.owner_ed25519 == b.owner_ed25519);
    v
}

/// Состав шарда на эту эпизоде: первые `r` из порядка, отфильтрованные по ёмкости.
///
/// Фильтр по `entries` — не косметика: без него шард с 2M записей достался бы узлу с
/// `capacity_entries = 1000`, и тот честно начал бы его обслуживать до первого OOM.
pub fn select(epoch: u64, shard: u16, holders: &[Holder], r: usize, entries: u64) -> Vec<Holder> {
    ordered(epoch, shard, holders).into_iter().filter(|h| h.fits(entries)).take(r).collect()
}

/// Те же держатели как `Member`-ы — то, что кладётся в `MembershipUpdate`.
pub fn members(epoch: u64, shard: u16, holders: &[Holder], r: usize, entries: u64) -> Vec<Member> {
    select(epoch, shard, holders, r, entries).iter().map(Holder::as_member).collect()
}

/// Ожидание состава для `epoch`: то, против чего проверяется пришедший `MembershipUpdate`
/// (§9.3: состав обязан быть детерминированным выбором, а не тем, что придумал primary).
pub fn expected_update(
    epoch: u64,
    shard: u16,
    holders: &[Holder],
    r: usize,
    entries: u64,
    generated_at: u32,
) -> MemberList {
    MemberList {
        epoch,
        shard,
        members: members(epoch, shard, holders, r, entries),
        generated_at,
    }
}

/// Кандидат-список до подписания: отдельный тип, потому что подписывать надо байты ровно того
/// списка, который сверяли, а `MembershipUpdate` уже несёт подписи.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberList {
    pub epoch: u64,
    pub shard: u16,
    pub members: Vec<Member>,
    pub generated_at: u32,
}

impl MemberList {
    #[inline]
    pub fn is_primary(&self, owner: &[u8; 32]) -> bool {
        self.members.first().map(|m| &m.owner_ed25519) == Some(owner)
    }

    pub fn index_of(&self, owner: &[u8; 32]) -> Option<usize> {
        self.members.iter().position(|m| &m.owner_ed25519 == owner)
    }

    pub fn peers(&self, me: &[u8; 32]) -> Vec<[u8; 32]> {
        self.members.iter().filter(|m| &m.owner_ed25519 != me).map(|m| m.owner_ed25519).collect()
    }
}

/// Keeper — минимальная позиция в сортировке (§9.5). Именно он не удаляет файлы шарда,
/// пока не увидит живое `epoch + 1`.
#[inline]
pub fn keeper(epoch: u64, shard: u16, members: &[Member]) -> Option<[u8; 32]> {
    members
        .iter()
        .map(|m| (candidate_order_key(epoch, shard, &m.owner_ed25519), m.owner_ed25519))
        .min()
        .map(|(_, owner)| owner)
}

/// Очередь тех, кто имеет право объявить следующую эпизоду.
///
/// Тот же ключ, что и для состава, но по списку ключей, а не по `Holder`: говорить обязан мочь
/// и уходящий участник, а в следующем составе его уже нет (§9.5, п.2 — «ушли все» объявляют те,
/// кто уходит). Молчание k-го в этой очереди переживает `k` окон election, как и в `ordered`.
pub fn speaker_order(epoch: u64, shard: u16, owners: &[[u8; 32]]) -> Vec<[u8; 32]> {
    let mut v = owners.to_vec();
    v.sort_by(|a, b| {
        candidate_order_key(epoch, shard, a)
            .cmp(&candidate_order_key(epoch, shard, b))
            .then_with(|| a.cmp(b))
    });
    v.dedup();
    v
}

#[cfg(test)]
mod tests {
    use super::*;
    use vecdht_wire::cert::CERT_VERSION;

    fn cert(owner: [u8; 32], role: Role, shards: Vec<u16>, capacity: u32) -> NodeCert {
        NodeCert {
            version: CERT_VERSION,
            genesis_hash: [0x11; 32],
            role,
            owner_ed25519: owner,
            dht_peer_id: vec![0xAA; 34],
            shards,
            capacity_entries: capacity,
            valid_from: 0,
            valid_until: u32::MAX,
            nonce: [0x77; 16],
            authority_sigs: Vec::new(),
        }
    }

    fn holders(owners: &[[u8; 32]]) -> Vec<Holder> {
        owners
            .iter()
            .map(|o| Holder::from_cert(&cert(*o, Role::IndexNode, vec![0], u32::MAX), 0).unwrap())
            .collect()
    }

    fn owner(i: u8) -> [u8; 32] {
        [i; 32]
    }

    #[test]
    fn selection_is_a_function_of_the_epoch_not_of_insertion_order() {
        let h = holders(&[owner(1), owner(2), owner(3), owner(4), owner(5)]);
        let a = ordered(1, 0, &h);
        let mut shuffled = h.clone();
        shuffled.reverse();
        assert_eq!(ordered(1, 0, &shuffled), a, "порядок не должен зависеть от входа");
        // Смена эпохи — новая перестановка: состав нельзя «застолбить», пережидая эпохи.
        assert_ne!(ordered(2, 0, &h), a);
        assert_eq!(a.len(), 5);
    }

    #[test]
    fn only_the_first_r_are_selected_and_wildcard_certs_count() {
        let h = holders(&[owner(1), owner(2), owner(3), owner(4)]);
        let top = select(1, 0, &h, 3, 0);
        assert_eq!(top.len(), 3);
        assert_eq!(top, ordered(1, 0, &h)[..3].to_vec());
        // Пустой список шардов = wildcard (§4.2).
        let wild =
            Holder::from_cert(&cert(owner(9), Role::IndexNode, vec![], 10), 63).unwrap();
        assert_eq!(wild.capacity_entries, 10);
    }

    #[test]
    fn non_index_roles_and_uncovered_shards_are_not_candidates() {
        assert!(Holder::from_cert(&cert(owner(1), Role::Agent, vec![0], 10), 0).is_none());
        assert!(Holder::from_cert(&cert(owner(1), Role::IndexNode, vec![1], 10), 0).is_none());
        assert!(Holder::from_cert(&cert(owner(1), Role::IndexNode, vec![0], 10), 0).is_some());
    }

    #[test]
    fn capacity_filter_drops_holders_that_cannot_hold_the_shard() {
        let small = Holder { owner_ed25519: owner(1), dht_peer_id: vec![], capacity_entries: 10 };
        let big = Holder { owner_ed25519: owner(2), dht_peer_id: vec![], capacity_entries: 1_000 };
        let picked = select(1, 0, &[small.clone(), big], 1, 100);
        assert_eq!(picked.iter().map(|h| h.owner_ed25519).collect::<Vec<_>>(), vec![owner(2)]);
        // Если помещаются none — состав пустой, и это честно: шард объявляется свободным (§9.5).
        assert!(select(1, 0, &[small], 3, 11).is_empty());
    }

    #[test]
    fn duplicate_keys_collapse_to_one_slot() {
        // Один ключ — один слот. Иначе атакующий с одним кредашиалом занял бы R мест.
        let h = holders(&[owner(7), owner(7), owner(8)]);
        let sel = select(1, 0, &h, 3, 0);
        assert_eq!(sel.len(), 2, "дубликат кредашиала не даёт второго места в составе");
        assert_eq!(sel, ordered(1, 0, &h), "и порядок остаётся детерминированным");
        let mut keys: Vec<[u8; 32]> = sel.iter().map(|x| x.owner_ed25519).collect();
        keys.sort();
        assert_eq!(keys, vec![owner(7), owner(8)]);
    }

    #[test]
    fn keeper_is_the_first_in_the_same_order_as_selection() {
        let h = holders(&[owner(1), owner(2), owner(3)]);
        let m: Vec<Member> = h.iter().map(Holder::as_member).collect();
        assert_eq!(keeper(1, 0, &m).unwrap(), ordered(1, 0, &h)[0].owner_ed25519);
        assert_eq!(keeper(1, 0, &[]), None, "пустой состав некому хранить");
    }

    #[test]
    fn member_list_helpers_agree_with_the_order() {
        let h = holders(&[owner(1), owner(2), owner(3), owner(4)]);
        let list = expected_update(1, 0, &h, 3, 0, 100);
        assert_eq!(list.members.len(), 3);
        assert!(list.is_primary(&ordered(1, 0, &h)[0].owner_ed25519));
        assert_eq!(list.index_of(&list.members[1].owner_ed25519), Some(1));
        let me = list.members[0].owner_ed25519;
        assert_eq!(list.peers(&me).len(), 2, "peers — это остальные члены, без самого себя");
        assert!(!list.peers(&me).contains(&me));
    }
}
