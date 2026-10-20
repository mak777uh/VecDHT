//! Приёмы rendezvous (§12.3): выпуск на index-node и одноразовый расход у цели.
//!
//! Токен выпускает **тот, кто нашёл**, а не тот, кто опубликовал. Это не деталь реализации, а
//! ответ на дыру v7.5: одноразовый токен, который должен пережить час жизни интента, не мог
//! быть выдан автором заранее, потому что автор не знает, к кому придут. Index-node знает:
//! пару `(seeker, target)` он видит в момент `Find` и подписывает её своим ключом.
//!
//! Почему таблица ограничена ста тысячами: приём — это не протокольное состояние и не WAL, а
//! RAM-запись ≈90 Б. Выписывать их может каждый `Find` — до `top_k` штук, — поэтому таблица
//! обязана иметь потолок, и отказ на потолке дешевле, чем рост памяти от чужого поиска:
//! `MatchResult` всё равно уходит, просто без части приёмов. Живые приёмы старше TTL
//! выбрасываются по бакетам, без скана таблицы.
//!
//! Одноразовость обеспечивает **цель**, а не издатель: издатель не видит расхода и не может
//! его проверить. Цель дедуплицирует ключ `(issuer, seeker, target, slot, issued_bucket)` и
//! хранит его столько же, сколько живёт приём; этого достаточно, потому что тот же ключ с
//! другим `issued_bucket` — другой приём, а старый уже истёк.

use std::collections::{BTreeMap, BTreeSet};

use thiserror::Error;
use vecdht_crypto::verify_body;
use vecdht_wire::frame::{decode_frame, Kind};
use vecdht_wire::messages::{domain, Codec, RendezvousAccept};

use crate::config::buckets;
use crate::net::Addr;

/// Потолок живой lease-таблицы издателя (§12.3): 100 000 × ~90 Б ≈ 9 МБ.
pub const MAX_ACCEPTS: usize = 100_000;

/// Ключ приёма. `issued_bucket` входит в него намеренно: повторный `Find` в том же бакете не
/// должен ни тратить вторую запись, ни делать первый приём недействительным.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Key {
    seeker: Addr,
    target: Addr,
    shard: u16,
    slot: u32,
    issued_bucket: u32,
}

impl Key {
    fn accept(&self, ttl_sec: u16) -> RendezvousAccept {
        RendezvousAccept {
            seeker: self.seeker,
            target: self.target,
            shard: self.shard,
            slot: self.slot,
            issued_bucket: self.issued_bucket,
            ttl_sec,
        }
    }
}

/// Выпуск приёмов на index-node (§12.3). Живёт на шарде: `slot` адресует запись этого шарда.
#[derive(Debug)]
pub struct Issuer {
    ttl_sec: u16,
    ttl_buckets: u32,
    cap: usize,
    by_bucket: BTreeMap<u32, Vec<Key>>,
    seen: BTreeSet<Key>,
    live: usize,
    pub issued: u64,
    /// Отказы по потолку таблицы. Не ошибка протокола: `MatchResult` уже собран, приём —
    /// дополнение к нему.
    pub refused_full: u64,
}

impl Issuer {
    pub fn new(ttl_sec: u16) -> Self {
        Self::with_capacity(ttl_sec, MAX_ACCEPTS)
    }

    pub fn with_capacity(ttl_sec: u16, cap: usize) -> Self {
        Issuer {
            ttl_sec,
            // `Params` отвергает ttl=0 на старте; `max(1)` здесь — страховка от деления на ноль
            // в тестах, которые строят `Issuer` напрямую.
            ttl_buckets: buckets(ttl_sec as u32).max(1),
            cap: cap.max(1),
            by_bucket: BTreeMap::new(),
            seen: BTreeSet::new(),
            live: 0,
            issued: 0,
            refused_full: 0,
        }
    }

    #[inline]
    pub fn ttl_sec(&self) -> u16 {
        self.ttl_sec
    }

    #[inline]
    pub fn live(&self) -> usize {
        self.live
    }

    /// Выписать приём. `None` — таблица на потолке; вызывающий обязан отличить это от «уже
    /// выписан» и не считать отказ изменением протокола.
    pub fn issue(
        &mut self,
        seeker: Addr,
        target: Addr,
        shard: u16,
        slot: u32,
        now_bucket: u32,
    ) -> Option<RendezvousAccept> {
        self.prune(now_bucket);
        let key = Key { seeker, target, shard, slot, issued_bucket: now_bucket };
        if self.seen.contains(&key) {
            // Идемпотентность: агент повторил `Find` в том же бакете. Тот же приём, та же
            // запись таблицы — иначе повторный поиск вытеснял бы из неё чужие приёмы.
            return Some(key.accept(self.ttl_sec));
        }
        if self.live >= self.cap {
            self.refused_full += 1;
            return None;
        }
        self.seen.insert(key);
        self.by_bucket.entry(now_bucket).or_default().push(key);
        self.live += 1;
        self.issued += 1;
        Some(key.accept(self.ttl_sec))
    }

    /// Выбросить приёмы, у которых `issued_bucket + ttl_buckets < now_bucket`. Стоимость — число
    /// истёкших, а не размер таблицы: TTL фиксирован, поэтому истекают целые бакеты.
    ///
    /// Граница выбрана строго по [`Spend::consume`]: там приём действителен при
    /// `now <= issued + ttl`, и издатель обязан хранить его ровно столько же. `checked_sub`
    /// вместо `saturating_sub` — не педантизм: на заре эпохи (`now < ttl`) «истёкших» бакетов
    /// нет вовсе, а `saturating_sub` дал бы cutoff=0 и выбросил бы свежие приёмы бакета 0.
    fn prune(&mut self, now_bucket: u32) {
        let Some(cutoff) = now_bucket.checked_sub(self.ttl_buckets) else {
            return;
        };
        while let Some((&bucket, _)) = self.by_bucket.first_key_value() {
            if bucket >= cutoff {
                break;
            }
            let keys = self.by_bucket.remove(&bucket).unwrap_or_default();
            for k in &keys {
                self.seen.remove(k);
            }
            self.live = self.live.saturating_sub(keys.len());
        }
    }
}

/// Что цель узнала из проверенного приёма. `seeker` — тот, кому index-node выписал приём; сессию
/// открывает именно он, а не любой предъявитель байтов.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Grant {
    pub issuer: Addr,
    pub seeker: Addr,
    pub shard: u16,
    pub slot: u32,
    pub issued_bucket: u32,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum AcceptError {
    #[error("кадр не разобран как RendezvousAccept")]
    Malformed,
    #[error("кадр не RendezvousAccept")]
    WrongKind,
    #[error("RendezvousAccept обязан быть подписан (§5.3)")]
    Unsigned,
    #[error("подпись не принадлежит заявленному index-node")]
    BadSignature,
    #[error("приём выписан на другого адресата")]
    WrongTarget,
    #[error("ttl_sec={0} вне политики цели")]
    TtlOutOfPolicy(u16),
    #[error("приём истёк: issued_bucket + ttl < now_bucket")]
    Expired,
    #[error("приём уже израсходован")]
    AlreadySpent,
}

/// Проверка и одноразовый расход на стороне цели (§12.3).
///
/// Проверяется ровно то, что спека обещает цели: подпись издателя (его ключ приходит из
/// `Handshake` и верифицирован кредашиалом — это забота вызывающего), `target == self`, TTL и
/// однократность. Сам `seeker` не проверяется: приём выписан на него, и предъявить его может
/// любой, кто эти байты видел, — но сессию открывает ключ из `seeker`, а не предъявитель.
#[derive(Debug)]
pub struct Spend {
    max_ttl_sec: u16,
    spent: BTreeSet<(Addr, Key)>,
    by_expiry: BTreeMap<u32, Vec<(Addr, Key)>>,
}

impl Spend {
    pub fn new(max_ttl_sec: u16) -> Self {
        Spend { max_ttl_sec, spent: BTreeSet::new(), by_expiry: BTreeMap::new() }
    }

    #[inline]
    pub fn spent(&self) -> usize {
        self.spent.len()
    }

    pub fn consume(
        &mut self,
        frame: &[u8],
        issuer: &Addr,
        me: &Addr,
        now_bucket: u32,
    ) -> Result<Grant, AcceptError> {
        self.prune(now_bucket);
        let f = decode_frame(frame).map_err(|_| AcceptError::Malformed)?;
        if f.header.kind != Kind::RendezvousAccept {
            return Err(AcceptError::WrongKind);
        }
        let sig: [u8; 64] = match f.signature {
            Some(s) => s.try_into().map_err(|_| AcceptError::Unsigned)?,
            None => return Err(AcceptError::Unsigned),
        };
        let acc = RendezvousAccept::decode(frame).map_err(|_| AcceptError::Malformed)?;
        if !verify_body(issuer, domain::RENDEZVOUS, Kind::RendezvousAccept, f.body, &sig)
            .unwrap_or(false)
        {
            return Err(AcceptError::BadSignature);
        }
        if acc.target != *me {
            return Err(AcceptError::WrongTarget);
        }
        if acc.ttl_sec == 0 || acc.ttl_sec > self.max_ttl_sec {
            return Err(AcceptError::TtlOutOfPolicy(acc.ttl_sec));
        }
        let ttl_buckets = buckets(acc.ttl_sec as u32).max(1);
        if now_bucket > acc.issued_bucket.saturating_add(ttl_buckets) {
            return Err(AcceptError::Expired);
        }
        let key = Key {
            seeker: acc.seeker,
            target: acc.target,
            shard: acc.shard,
            slot: acc.slot,
            issued_bucket: acc.issued_bucket,
        };
        if !self.spent.insert((*issuer, key)) {
            return Err(AcceptError::AlreadySpent);
        }
        // Не `issued + ttl`, а `+1`: на границе `now == issued + ttl` приём ещё действителен
        // (`Expired` выше — строгое `>`), и запись расхода обязана пережить этот бакет. Иначе
        // повторное предъявление ровно на границе прошло бы как новое.
        let expires = acc.issued_bucket.saturating_add(ttl_buckets).saturating_add(1);
        self.by_expiry.entry(expires).or_default().push((*issuer, key));
        Ok(Grant {
            issuer: *issuer,
            seeker: acc.seeker,
            shard: acc.shard,
            slot: acc.slot,
            issued_bucket: acc.issued_bucket,
        })
    }

    fn prune(&mut self, now_bucket: u32) {
        while let Some((&expires, _)) = self.by_expiry.first_key_value() {
            if expires > now_bucket {
                break;
            }
            let keys = self.by_expiry.remove(&expires).unwrap_or_default();
            for k in &keys {
                self.spent.remove(k);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vecdht_crypto::Identity;

    fn addr(i: u8) -> Addr {
        [i; 32]
    }

    fn signed(issuer: &Identity, acc: RendezvousAccept) -> Vec<u8> {
        let body = acc.body_bytes();
        let sig = issuer.sign_body(domain::RENDEZVOUS, Kind::RendezvousAccept, &body);
        acc.encode_signed(&sig)
    }

    #[test]
    fn issue_is_idempotent_inside_a_bucket_and_fresh_in_the_next() {
        let mut i = Issuer::new(300);
        let a = i.issue(addr(1), addr(2), 7, 41, 100).expect("приём");
        assert_eq!((a.seeker, a.target, a.shard, a.slot, a.issued_bucket, a.ttl_sec), (addr(1), addr(2), 7, 41, 100, 300));
        // Повторный Find в том же бакете — тот же приём и одна запись таблицы.
        let b = i.issue(addr(1), addr(2), 7, 41, 100).expect("повтор");
        assert_eq!(a, b);
        assert_eq!(i.live(), 1);
        assert_eq!(i.issued, 1);
        // Новый бакет — новый приём: `issued_bucket` входит в ключ и в подпись.
        let c = i.issue(addr(1), addr(2), 7, 41, 101).expect("следующий бакет");
        assert_ne!(a, c);
        assert_eq!(i.live(), 2);
    }

    #[test]
    fn expired_leases_are_dropped_by_bucket_not_by_scan() {
        let mut i = Issuer::new(300);
        // 300 с — 19 бакетов (§2: TIME_BUCKET_SEC=16, округление вверх).
        i.issue(addr(1), addr(2), 7, 1, 10).unwrap();
        i.issue(addr(3), addr(4), 7, 2, 10).unwrap();
        assert_eq!(i.live(), 2);
        // Приём из бакета 10 жив до 29 включительно; в 30 он истекает.
        i.issue(addr(5), addr(6), 7, 3, 29).unwrap();
        assert_eq!(i.live(), 3, "в 29-м приём из 10-го ещё жив — граница включена");
        // В 30-м бакет 10 истёк (10 + 19 = 29 < 30), а бакет 29 — ещё нет: его TTL кончается
        // в 48. Новый приём добавляется к живым, а не к выброшенным.
        i.issue(addr(5), addr(6), 7, 3, 30).unwrap();
        assert_eq!(i.live(), 2, "два приёма из бакета 10 выброшены вместе с бакетом");
    }

    #[test]
    fn the_cap_refuses_new_leases_but_keeps_the_old_ones_working() {
        let mut i = Issuer::with_capacity(300, 2);
        let first = i.issue(addr(1), addr(2), 7, 1, 0).expect("первый");
        i.issue(addr(3), addr(4), 7, 2, 0).expect("второй");
        assert_eq!(i.issue(addr(5), addr(6), 7, 3, 0), None, "потолок таблицы");
        assert_eq!(i.refused_full, 1);
        assert_eq!(i.live(), 2);
        // Ровно тот приём, что уже выписан, продолжает возвращаться: это не новый расход.
        assert_eq!(i.issue(addr(1), addr(2), 7, 1, 0), Some(first));
    }

    #[test]
    fn a_target_consumes_the_accept_once_and_only_for_itself() {
        let issuer = Identity::from_seed([9; 32]);
        let mut i = Issuer::new(300);
        let acc = i.issue(addr(1), addr(2), 7, 41, 100).unwrap();
        let frame = signed(&issuer, acc);

        let mut spend = Spend::new(300);
        assert_eq!(
            spend.consume(&frame, &issuer.pubkey(), &addr(3), 100),
            Err(AcceptError::WrongTarget),
            "приём на другого адресата не расходуется и не считается"
        );
        let g = spend.consume(&frame, &issuer.pubkey(), &addr(2), 100).expect("цель");
        assert_eq!((g.issuer, g.seeker, g.shard, g.slot), (issuer.pubkey(), addr(1), 7, 41));
        assert_eq!(
            spend.consume(&frame, &issuer.pubkey(), &addr(2), 101),
            Err(AcceptError::AlreadySpent),
            "повтор предъявления — не сессия"
        );
        assert_eq!(spend.spent(), 1);
    }

    #[test]
    fn a_forged_or_expired_or_overlong_accept_is_refused() {
        let issuer = Identity::from_seed([10; 32]);
        let attacker = Identity::from_seed([11; 32]);
        let mut i = Issuer::new(300);
        let acc = i.issue(addr(1), addr(2), 7, 41, 100).unwrap();

        let mut spend = Spend::new(300);
        // Чужая подпись при чужом ключе издателя.
        let forged = signed(&attacker, acc);
        assert_eq!(
            spend.consume(&forged, &issuer.pubkey(), &addr(2), 100),
            Err(AcceptError::BadSignature)
        );
        // Неподписанный кадр обязательного вида.
        assert_eq!(
            spend.consume(&acc.encode_unsigned(), &issuer.pubkey(), &addr(2), 100),
            Err(AcceptError::Unsigned)
        );
        // Истёк: 100 + 19 < 120.
        let frame = signed(&issuer, acc);
        assert_eq!(spend.consume(&frame, &issuer.pubkey(), &addr(2), 120), Err(AcceptError::Expired));
        // Издатель не вправе растянуть TTL выше политики цели.
        let mut long = acc;
        long.ttl_sec = 301;
        let frame = signed(&issuer, long);
        assert_eq!(
            spend.consume(&frame, &issuer.pubkey(), &addr(2), 100),
            Err(AcceptError::TtlOutOfPolicy(301))
        );
    }

    #[test]
    fn a_republished_slot_needs_a_fresh_accept() {
        let issuer = Identity::from_seed([12; 32]);
        let mut i = Issuer::new(300);
        let old = i.issue(addr(1), addr(2), 7, 41, 100).unwrap();
        let new = i.issue(addr(1), addr(2), 7, 42, 100).unwrap();
        let mut spend = Spend::new(300);
        spend.consume(&signed(&issuer, old), &issuer.pubkey(), &addr(2), 100).expect("старый слот");
        spend.consume(&signed(&issuer, new), &issuer.pubkey(), &addr(2), 100).expect("другой slot — другой приём");
    }

    #[test]
    fn spent_entries_expire_with_the_same_ttl() {
        let issuer = Identity::from_seed([13; 32]);
        let mut i = Issuer::new(300);
        let acc = i.issue(addr(1), addr(2), 7, 41, 100).unwrap();
        let frame = signed(&issuer, acc);
        let mut spend = Spend::new(300);
        spend.consume(&frame, &issuer.pubkey(), &addr(2), 100).unwrap();
        assert_eq!(spend.spent(), 1);
        // Живёт до 119 включительно; в 120 память возвращается, и тот же байт уже не приём.
        assert_eq!(spend.consume(&frame, &issuer.pubkey(), &addr(2), 120), Err(AcceptError::Expired));
        assert_eq!(spend.spent(), 0);
    }
}
