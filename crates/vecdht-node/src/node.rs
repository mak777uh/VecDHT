//! `ShardNode`: один шард на одном узле как машина состояний (§9.2–§9.8, §10, §12).
//!
//! Узел ничего не ждёт и никуда не звонит сам: у него нет ни потока, ни таймеров. Внешний мир
//! вызывает `on_frame(from, bytes, now)` и `tick(now_bucket)`, а узел возвращает список
//! писем, которые транспорт обязан доставить. Отсюда три следствия, и все три нужны для гейтов:
//!
//! * детерминизм — при тех же кадрах и тех же бакетах та же последовательность ответов;
//! * тестируемость — `kill` узла это «перестали вызывать», а задержка доставки — параметр
//!   сети, а не `sleep` внутри кода;
//! * нет wall-clock в replicated-пути (§9.6): часы использует только primary, и только когда
//!   пишет `TimeMark`; реплики применяют тот фрейм дословно.
//!
//! Каждая подпись проверяется по ключу, заявленному *в теле*, и по аутентифицированному
//! транспортному `from` (§4.3). Кадр с непроверенной подписью не получает ответа: тихий drop
//! дешевле oracle «подпись верна / не верна», которым стал бы любой `Error` на подделке.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use thiserror::Error;
use vecdht_crypto::{pow_input, pow_ok, shard_of_cluster, verify_body, AuthoritySet, Identity};
use vecdht_index::wal::{list_segments, read_segment, WalFrame};
use vecdht_index::{IndexEntry, ShardStore, StoreError, StoreManifest};
use vecdht_wire::codec::MAX_BODY_LEN;
use vecdht_wire::frame::{decode_frame, Kind};
use vecdht_wire::messages::{
    domain, encode_mark, err_code, Codec, DeleteOp, Find, LeaveNotice, MatchResult, Member,
    MembershipUpdate, OpKind, ProtocolError, Publish, PublishAck, ReplicateAck, ReplicateOp,
    SnapshotOffer, WalPullRequest, WalPullResponse,
};
use vecdht_wire::DecodeError;

use crate::admission::{self, Candidate, Evictor, SharedAdmission};
use crate::candidates::{self, Holder, MemberList};
use crate::config::{Clock, Params};
use crate::lease::Lease;
use crate::membership::{self, Chain, Membership, MembershipError, GENESIS_EPOCH};
use crate::net::{Addr, Envelope};
use crate::rendezvous::Issuer;
use crate::snapshot::{self, Assembler, SyncError};

#[derive(Debug, Error)]
pub enum NodeError {
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Decode(#[from] DecodeError),
    #[error(transparent)]
    Sync(#[from] SyncError),
    #[error(transparent)]
    Membership(#[from] MembershipError),
    #[error("io {ctx}: {detail}")]
    Io { ctx: &'static str, detail: String },
    #[error("кадр {kind} сломал инвариант узла: {why}")]
    Unexpected { kind: &'static str, why: String },
}

/// Сколько раз подряд догоняющий pull мог не принести прогресса, прежде чем узел перестанет
/// настаивать. Это не протокольное число, а предохранитель от self-sustaining цикла
/// «запросили дыру → получили дыру» (§10.5).
const MAX_PULL_ATTEMPTS: u32 = 4;

/// Одна запись primary: ждём `w-1` ack от реплик, потом отвечаем агенту (§9.4).
#[derive(Debug, Clone)]
struct Awaiting {
    /// Кому отвечать `PublishAck`.
    agent: Addr,
    slot: u32,
    /// Уже подтвердившие, включая самого primary: его fsync — первое подтверждение кворума.
    acks: Vec<Addr>,
}

/// Сборка снапшота от seed: метаданные последнего куска задают `MANIFEST`, который мы ставим.
#[derive(Debug)]
struct Assembly {
    asm: Assembler,
    epoch: u64,
    snapshot_seq: u64,
    oldest_wal_needed: u64,
    applied_seq: u64,
    next_slot: u64,
    time_mark_bucket: u32,
}

/// Состояние холодной отдачи снапшота одному пиру. `content_hash` считается один раз на
/// передачу: blake3 сотни мегабайт на каждый кусок превратил бы отдачу в CPU-DoS.
#[derive(Debug, Clone, Copy)]
struct Cold {
    snapshot_seq: u64,
    offset: u32,
    total: u32,
    content_hash: [u8; 32],
}

/// Один шард на одном узле.
pub struct ShardNode {
    pub shard: u16,
    pub id: Identity,
    /// Байты libp2p-адреса: кладутся в `LeaseGrant` и `Member`, сверяет их транспорт (§4.3).
    pub dht_peer_id: Vec<u8>,
    pub params: Params,
    pub store: ShardStore,
    pub chain: Chain,
    /// Последняя принятая эпизода. `None` — шард ещё не объявлен.
    pub membership: Option<Membership>,
    pub lease: Option<Lease>,
    /// Держатели кредашиалов этого шарда из DHT (§9.3): единственный источник состава.
    pub roster: Vec<Holder>,
    /// Текущая сложность PoW, которую узел требует и возвращает в `next_pow_bits` (§11.2).
    pub pow_bits: u8,
    /// Ушли по `LeaveNotice`: их не обязано быть в следующем составе (§9.5).
    draining: Vec<Addr>,
    /// Транспорт подтвердил обрыв соединения: для протокола это то же самое, что `LeaveNotice`,
    /// только без подписи уходящего (§9.8: election timeout остаётся границей для случая, когда
    /// события от транспорта нет).
    unreachable: Vec<Addr>,
    /// Мы сами объявили уход: своё имя обязаны исключить из следующего состава, но остаться в
    /// числе тех, кто может этот состав предложить (§9.5, п.2).
    leaving: bool,
    /// Наш черновик перехода: байты фиксированы, к ним копятся подписи.
    proposal: Option<MembershipUpdate>,
    awaiting: BTreeMap<u64, Awaiting>,
    assembly: Option<Assembly>,
    cold: BTreeMap<Addr, Cold>,
    /// Подряд идущие безрезультатные `WalPullResponse` (см. `MAX_PULL_ATTEMPTS`).
    pull_attempts: u32,
    /// `applied_seq` на момент последнего `TimeMark` — по нему считается барьер в 512 опсов.
    last_mark_applied: u64,
    /// Локальная политика приёма (§11.3). Разделяется всеми шардами одного процесса: §11.3.4
    /// нормирует «100 admits/с на узел», а не на шард.
    pub admission: SharedAdmission,
    /// Кандидаты на вытеснение и достигнутые биты PoW (§11.3.3). RAM и на шард: slot'ы
    /// принадлежат индексу этого шарда.
    pub evictor: Evictor,
    /// Выпущенные rendezvous-приёмы (§12.3). RAM и на шард: `slot` в приёме адресует запись
    /// именно этого шарда, и при переносе шарда на другой узел старые приёмы всё равно истекают
    /// по TTL, а не переезжают.
    pub rendezvous: Issuer,
    /// Сколько `GcTick`-фреймов выпущено. Счётчик нужен не для протокола, а чтобы «GC пишется
    /// по нужде, а не каждый бакет» было проверяемым утверждением, а не обещанием.
    pub gc_ticks: u64,
}

impl ShardNode {
    /// Открыть шард: индекс с диска и цепочка членства с диска (§9.5, пункт 3: последняя
    /// принятая цепочка персистится каждым членом), с повторной валидацией всей цепочки.
    pub fn open(
        dir: &Path,
        shard: u16,
        id: Identity,
        dht_peer_id: Vec<u8>,
        params: Params,
        authorities: AuthoritySet,
        roster: Vec<Holder>,
    ) -> Result<Self, NodeError> {
        let admission = admission::shared(&params);
        Self::open_with_admission(dir, shard, id, dht_peer_id, params, authorities, roster, admission)
    }

    /// Открыть шард с уже существующим admission узла.
    ///
    /// Процесс, держащий несколько шардов (§11.3.4: узел — это процесс, а не шард), обязан
    /// передать один и тот же [`SharedAdmission`] всем `open_with_admission`: иначе лимит 100/с
    /// молча умножался бы на число шардов, и «на узел» в спеке означало бы «на шард». `open`
    /// создаёт собственный — это верно ровно для процесса с одним шардом, поэтому мультишардовый
    /// тест `shards_of_one_process_share_the_node_budget` фиксирует, что второй путь существует
    /// и работает.
    #[allow(clippy::too_many_arguments)]
    pub fn open_with_admission(
        dir: &Path,
        shard: u16,
        id: Identity,
        dht_peer_id: Vec<u8>,
        params: Params,
        authorities: AuthoritySet,
        roster: Vec<Holder>,
        admission: SharedAdmission,
    ) -> Result<Self, NodeError> {
        let store = ShardStore::open(dir, shard)?;
        let rendezvous_ttl = params.rendezvous_ttl;
        let chain = Chain { shard, params, authorities };
        let last_mark_applied = store.applied_seq;
        let mut node = ShardNode {
            shard,
            id,
            dht_peer_id,
            pow_bits: params.pow_bits,
            store,
            chain,
            roster,
            last_mark_applied,
            membership: None,
            lease: None,
            params,
            draining: Vec::new(),
            unreachable: Vec::new(),
            leaving: false,
            proposal: None,
            awaiting: BTreeMap::new(),
            assembly: None,
            cold: BTreeMap::new(),
            pull_attempts: 0,
            admission,
            evictor: Evictor::new(admission::EVICT_RESERVOIR),
            rendezvous: Issuer::new(rendezvous_ttl),
            gc_ticks: 0,
        };
        node.membership = node.load_chain()?;
        Ok(node)
    }

    #[inline]
    pub fn me(&self) -> Addr {
        self.id.pubkey()
    }

    #[inline]
    pub fn dir(&self) -> &Path {
        &self.store.dir
    }

    #[inline]
    pub fn epoch(&self) -> Option<u64> {
        self.membership.as_ref().map(|m| m.epoch())
    }

    #[inline]
    pub fn is_member(&self) -> bool {
        self.membership.as_ref().map(|m| m.is_member(&self.me())).unwrap_or(false)
    }

    #[inline]
    pub fn is_primary(&self) -> bool {
        self.membership.as_ref().and_then(|m| m.primary()) == Some(self.me())
    }

    /// Все члены этой эпизоды, кроме самого узла.
    pub fn peers(&self) -> Vec<Addr> {
        let me = self.me();
        self.membership.as_ref().map(|m| m.peers(&me)).unwrap_or_default()
    }

    /// Транспорт подтвердил недоступность адреса (§9.8). Наблюдаемость для гейтов:
    /// «соединение закрылось» и «узел узнал, что коллега умер» — разные звенья одной
    /// цепочки, и проверять надо второе.
    pub fn is_unreachable(&self, addr: &Addr) -> bool {
        self.unreachable.contains(addr)
    }

    #[inline]
    pub fn applied_seq(&self) -> u64 {
        self.store.applied_seq
    }

    /// Lease действует на текущую эпизоду (§9.8).
    #[inline]
    pub fn lease_active(&self, now_bucket: u32) -> bool {
        match (&self.lease, self.membership.as_ref()) {
            (Some(l), Some(m)) => l.active_at(now_bucket) && l.epoch == m.epoch(),
            _ => false,
        }
    }

    /// Эпизода, с которой узел готов писать: lease + durable-подтверждение на диске (§9.2).
    /// Оба условия обязательны и проверять их надо вместе: lease без `grant_epoch` — это обещание,
    /// которого нет на диске, а `grant_epoch` без lease — пережиток уже несуществующего primary.
    #[inline]
    pub fn serving_epoch(&self, now_bucket: u32) -> Option<u64> {
        if !self.lease_active(now_bucket) {
            return None;
        }
        self.durable_epoch()
    }

    /// Эпизода, подтверждённая на диске и совпадающая с принятой цепочкой.
    ///
    /// Расхождение означает откат: `max_epoch_served` ушёл вперёд, а цепочка членства — нет
    /// (restoration из резервной копии, потеря `.log`). Обслуживать «эпизоду, о которой никто не
    /// договаривался» §9.2 запрещает, и это не косметика: `epoch` из диска попал бы в
    /// `ReplicateOp`, а реплики сверяют его с собственной цепочкой и опс отбросили бы.
    #[inline]
    fn durable_epoch(&self) -> Option<u64> {
        let e = self.store.serving_epoch()?;
        (Some(e) == self.epoch()).then_some(e)
    }

    pub fn set_roster(&mut self, roster: Vec<Holder>) {
        self.roster = roster;
    }

    // --- часы ------------------------------------------------------------------

    /// Вызывается транспортом на границе бакета: продлить lease, выбрать нового primary,
    /// записать `TimeMark`.
    pub fn tick(&mut self, now_bucket: u32) -> Result<Vec<Envelope>, NodeError> {
        let mut out = Vec::new();
        let empty = self.membership.as_ref().map(|m| m.is_empty()).unwrap_or(false);
        if self.is_member() && !empty {
            if self.lease_active(now_bucket) && self.is_primary() {
                let due =
                    self.lease.map(|l| l.remaining(now_bucket) <= self.params.renew_buckets).unwrap_or(false);
                if due {
                    out.extend(self.grant_lease(now_bucket));
                }
                out.extend(self.maybe_time_mark(now_bucket)?);
                out.extend(self.maybe_gc(now_bucket)?);
            }
            // Отдельно от ветки выше: состав мог сузиться, пока primary жив и lease активен
            // (ушёл репликант). Ждать чистки чужого lease, чтобы убрать объявленного ушедшего,
            // незачем — кворум до конца эпохи держался бы на мёртвом узле.
            if self.should_propose(now_bucket) {
                out.extend(self.propose_next(now_bucket)?);
            }
        }
        Ok(out)
    }

    /// Кто предлагает следующую эпизоду и когда.
    ///
    /// Право голоса — позиция среди живых участников **текущего** состава в порядке следующей
    /// эпохи (§9.3), а не нового: уходящий обязан уметь объявить и пустой состав (§9.5, п.2),
    /// а в нём его уже нет, и предложение «ушли все» осталось бы некому сделать. k-й в этой
    /// очереди ждёт `k` окон election, чтобы при каскаде падений за выбор не взялись все сразу
    /// (§9.8: протокола выборов нет, и очередь — единственный способ не превратить handoff в
    /// гонку объявлений).
    ///
    /// Триггера два: lease истёк (классика §9.8) или живое множество разошлось с принятым
    /// составом. Во втором случае отсчёт идёт от текущего бакета — сузация состава не должна
    /// ждать чужого продления.
    fn should_propose(&self, now_bucket: u32) -> bool {
        let cur = match self.membership.as_ref() {
            Some(m) => m,
            None => return false,
        };
        if cur.is_empty() || !cur.is_member(&self.me()) {
            return false;
        }
        let next = self.next_list(now_bucket);
        if let Some(p) = self.proposal.as_ref() {
            if p.epoch == next.epoch && p.members == next.members {
                // Черновик этого состава уже разослан: повторять его каждый тик — шум, а не
                // прогресс. Порог добирается подписями в `handle_membership`.
                return false;
            }
        }
        let changed = !same_members(cur.members(), &next.members);
        if self.lease_active(now_bucket) && !changed {
            return false;
        }
        let rank = match candidates::speaker_order(next.epoch, self.shard, &self.speakers(now_bucket))
            .iter()
            .position(|o| *o == self.me())
        {
            Some(r) => r,
            None => return false,
        };
        let base = if !changed {
            self.lease.map(|l| l.expires_at_bucket).unwrap_or(now_bucket)
        } else {
            now_bucket
        };
        now_bucket >= base.saturating_add(rank as u32 * self.params.election_buckets)
    }

    /// Кто имеет право говорить на этих выборах: участники текущего состава, которых мы не
    /// считаем ушедшими. Само исключение по `leaving` здесь не применяется — уходящий подписывает
    /// собственный уход (§9.2 про индексы в `sigs`).
    fn speakers(&self, now_bucket: u32) -> Vec<[u8; 32]> {
        let dead = self.excluded(now_bucket);
        let me = self.me();
        self.membership
            .as_ref()
            .map(|m| {
                m.members()
                    .iter()
                    .map(|x| x.owner_ed25519)
                    .filter(|o| *o == me || !dead.contains(o))
                    .collect()
            })
            .unwrap_or_default()
    }

    // --- членство -------------------------------------------------------------

    /// Состав следующей эпизоды из живого ростера (§9.3, §9.5).
    fn next_list(&self, now_bucket: u32) -> MemberList {
        let epoch = self.epoch().unwrap_or(GENESIS_EPOCH - 1) + 1;
        let entries = self.store.len() as u64;
        MemberList {
            epoch,
            shard: self.shard,
            members: candidates::members(epoch, self.shard, &self.live_roster(now_bucket), self.params.r, entries),
            generated_at: now_bucket,
        }
    }

    /// Ростер минус те, кого мы считаем недоступными, и минус сам узел, если он объявил уход.
    ///
    /// Разные узлы обязаны видеть здесь *одное и то же* множество, иначе два честных узла
    /// предложат два разных состава одной эпохи и primary перестанет быть свойством протокола.
    /// Поэтому молчание реплики основанием не считается: реплике нечего сказать, и судить о её
    /// смерти по тишине — значит гарантировать расхождение мнений. Недоступность доказывается
    /// только событием: `LeaveNotice`, подтверждённый транспортом обрыв, либо просроченный lease
    /// того, кто обязан продлеваться (§9.8). Остаточный риск разделения это не отменяет (спека
    /// §9.2, §11.4): он ограничен fencing'ом `max_epoch_served`, а не обещанием, что разделения
    /// не бывает.
    fn live_roster(&self, now_bucket: u32) -> Vec<Holder> {
        let dead = self.excluded(now_bucket);
        let me = self.me();
        self.roster
            .iter()
            .filter(|h| !dead.contains(&h.owner_ed25519))
            .filter(|h| h.owner_ed25519 != me || !self.leaving)
            .cloned()
            .collect()
    }

    /// Множество исключённых: ушедшие объявленные, мёртвые по транспорту и primary, не продливший
    /// lease.
    fn excluded(&self, now_bucket: u32) -> Vec<Addr> {
        let mut v: Vec<Addr> = self.draining.clone();
        v.extend(self.unreachable.iter().copied());
        if let Some(l) = self.lease {
            if !l.active_at(now_bucket) && !v.contains(&l.primary) {
                v.push(l.primary);
            }
        }
        v
    }

    /// Предложить `epoch + 1`: поставить свою подпись и разослать черновик.
    pub fn propose_next(&mut self, now_bucket: u32) -> Result<Vec<Envelope>, NodeError> {
        let list = self.next_list(now_bucket);
        let mut upd = membership::build_update(&list, Vec::new());
        if let Some(cur) = self.membership.clone() {
            if let Some(sig) = cur.sign_transition(&self.id, &upd) {
                upd.sigs.push(sig);
            }
        }
        self.proposal = Some(upd.clone());
        Ok(self.broadcast_membership(&upd))
    }

    fn broadcast_membership(&self, upd: &MembershipUpdate) -> Vec<Envelope> {
        let frame = self.membership_frame(upd);
        self.peers().into_iter().map(|p| Envelope::new(p, frame.clone())).collect()
    }

    /// Кадр `MembershipUpdate`: подпись ретранслятора поверх тела вместе со списком подписей.
    /// Порог проверяется по списку в теле, а кадровая подпись нужна, чтобы отличить «мне прислал
    /// участник» от «мне прислал наблюдатель».
    fn membership_frame(&self, upd: &MembershipUpdate) -> Vec<u8> {
        let body = upd.body_bytes();
        let sig = self.id.sign_body(domain::MEMBER, Kind::MembershipUpdate, &body);
        upd.encode_signed(&sig)
    }

    fn handle_membership(
        &mut self,
        bytes: &[u8],
        now_bucket: u32,
    ) -> Result<Vec<Envelope>, NodeError> {
        let incoming = MembershipUpdate::decode(bytes)?;
        if incoming.shard != self.shard {
            return Ok(Vec::new());
        }
        if self.membership.as_ref().map(|m| incoming.epoch <= m.epoch()).unwrap_or(false) {
            return Ok(Vec::new());
        }
        let mut upd = incoming.clone();
        // То же предложение, что разослали мы: подписи объединяются, а не заводится второй черновик.
        if let Some(ours) = self.proposal.clone() {
            if ours.epoch == upd.epoch && ours.unsigned_body() == upd.unsigned_body() {
                merge_sigs(&mut upd, &ours.sigs);
            }
        }
        // Своя подпись: индекс смотрит в epoch−1 (§9.2).
        if let Some(cur) = self.membership.clone() {
            if let Some((idx, sig)) = cur.sign_transition(&self.id, &upd) {
                if !upd.sigs.iter().any(|(i, _)| *i == idx) {
                    upd.sigs.push((idx, sig));
                }
            }
        }
        let entries = self.store.len() as u64;
        let roster = self.live_roster(now_bucket);
        let prev = self.membership.clone();
        match self.chain.validate_with_candidates(prev.as_ref(), &upd, &roster, entries) {
            Ok(m) => {
                self.persist(&m.update)?;
                self.adopt(m, now_bucket)
            }
            // Порога ещё нет: черновик живой, рассылаем его с нашей подписью дальше.
            Err(MembershipError::BelowThreshold { .. }) => {
                self.proposal = Some(upd.clone());
                Ok(self.broadcast_membership(&upd))
            }
            Err(_) => Ok(Vec::new()),
        }
    }

    /// Принять эпизоду: durable-подтверждение на диске раньше, чем начнём её обслуживать (§9.2).
    fn adopt(&mut self, m: Membership, now_bucket: u32) -> Result<Vec<Envelope>, NodeError> {
        self.proposal = None;
        self.draining.retain(|d| !m.is_member(d));
        // Принятый состав включает узла, которого мы считали мёртвым, — значит он жив. Держать
        // пометку нельзя: иначе этот узел вечно отсутствовал бы в наших предложениях.
        self.unreachable.retain(|d| !m.is_member(d));
        self.membership = Some(m.clone());
        if m.is_empty() {
            // Шард объявлен свободным: узел становится seed и обязан успеть опубликовать
            // снапшот, пока его ещё есть что отдать (§9.5, пункт 2).
            self.lease = None;
            if self.store.last_snapshot_seq == 0 {
                self.store.flush_snapshot()?;
            }
            return Ok(Vec::new());
        }
        let me = self.me();
        let primary = m.primary().unwrap_or(me);
        self.lease = Some(Lease::grant(m.epoch(), primary, now_bucket, self.params.lease_buckets));
        self.store.grant_epoch(m.epoch())?;
        // Принятую эпизоду обязан увидеть каждый: инициатор перехода сам ничего не узнает, если
        // принявший промолчит, а цепочка §9.2 живёт у каждого узла своя. Лишние ретрансляции
        // отсекаются на входе (`incoming.epoch <= своей`) — цикл из двух писем на эпизод.
        let mut out = self.broadcast_membership(&m.update);
        if self.is_primary() {
            out.extend(self.grant_lease(now_bucket));
            return Ok(out);
        }
        // Догоняемся с нового primary: anti-entropy обязана случиться при смене эпизоды (§9.4).
        out.push(self.pull_request(primary));
        Ok(out)
    }

    /// Персистить принятую эпизоду: `membership.<epoch>.log` через partial→rename, как снапшот.
    fn persist(&self, upd: &MembershipUpdate) -> Result<(), NodeError> {
        let name = format!("membership.{:020}.log", upd.epoch);
        let tmp = self.dir().join(format!("{name}.partial"));
        let bytes = upd.encode_signed(&upd.sigs.first().map(|(_, s)| *s).unwrap_or([0u8; 64]));
        std::fs::write(&tmp, &bytes)
            .map_err(|e| NodeError::Io { ctx: "write membership", detail: e.to_string() })?;
        std::fs::rename(&tmp, self.dir().join(&name))
            .map_err(|e| NodeError::Io { ctx: "rename membership", detail: e.to_string() })?;
        vecdht_index::fsync_dir(self.dir())
            .map_err(|e| NodeError::Io { ctx: "fsync dir", detail: e.to_string() })?;
        Ok(())
    }

    /// Пересобрать и заново проверить цепочку с диска. Дыра в истории — это не предупреждение:
    /// узел обязан остаться без членства, а не обслуживать из подозрительного состояния.
    fn load_chain(&self) -> Result<Option<Membership>, NodeError> {
        let mut files: Vec<(u64, PathBuf)> = Vec::new();
        let rd = match std::fs::read_dir(self.dir()) {
            Ok(rd) => rd,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(NodeError::Io { ctx: "read_dir", detail: e.to_string() }),
        };
        for entry in rd {
            let entry = entry.map_err(|e| NodeError::Io { ctx: "read_dir entry", detail: e.to_string() })?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if let Some(rest) = name.strip_prefix("membership.") {
                if let Some(seq) = rest.strip_suffix(".log") {
                    if let Ok(epoch) = seq.parse::<u64>() {
                        files.push((epoch, entry.path()));
                    }
                }
            }
        }
        files.sort_by_key(|(e, _)| *e);
        let mut prev: Option<Membership> = None;
        for (epoch, path) in files {
            let bytes = std::fs::read(&path)
                .map_err(|e| NodeError::Io { ctx: "read membership", detail: e.to_string() })?;
            let upd = MembershipUpdate::decode(&bytes)?;
            if upd.epoch != epoch {
                return Err(NodeError::Unexpected {
                    kind: "membership",
                    why: format!("файл обещает epoch={epoch}, тело — {}", upd.epoch),
                });
            }
            // Ростер на рестарте мог измениться, поэтому проверяется самовалидируемость
            // цепочки (§9.2), а не совпадение состава с сегодняшним DHT.
            prev = Some(self.chain.validate(prev.as_ref(), &upd)?);
        }
        Ok(prev)
    }

    // --- lease -----------------------------------------------------------------

    fn grant_lease(&mut self, now_bucket: u32) -> Vec<Envelope> {
        let Some(m) = self.membership.clone() else { return Vec::new() };
        let me = self.me();
        if m.primary() != Some(me) {
            return Vec::new();
        }
        let lease = Lease::grant(m.epoch(), me, now_bucket, self.params.lease_buckets);
        let frame = lease.signed_frame(self.shard, &self.id, self.dht_peer_id.clone());
        self.lease = Some(lease);
        m.peers(&me).into_iter().map(|p| Envelope::new(p, frame.clone())).collect()
    }

    fn handle_lease_grant(
        &mut self,
        from: Addr,
        bytes: &[u8],
        now_bucket: u32,
    ) -> Result<Vec<Envelope>, NodeError> {
        let have = self.epoch();
        match Lease::verify(bytes, self.shard, have, now_bucket) {
            Ok((lease, grant)) => {
                // Грант обязан прийти от того же ключа, который он объявляет primary (§4.3):
                // иначе любой наблюдатель пересылает чужой lease и становится «primary» в глазах
                // реплики.
                if grant.primary_ed25519 != from || lease.primary != from {
                    return Ok(Vec::new());
                }
                self.lease = Some(lease);
                Ok(Vec::new())
            }
            // Грант из прошлой эпизоды — это воскресший старый primary. Ему отказываем, и он
            // демотерируется сам: его фреймы не пройдут fencing на репликах (§9.8). Истёкший грант
            // отличается от устаревшего только причиной, а реакция одна — «не обслуживай эту эпизоду».
            Err(_) => self.err(from, err_code::EPOCH_STALE, 1_000),
        }
    }

    // --- publish ---------------------------------------------------------------

    /// Путь агента: admission (§11.3) → PoW → durable WAL primary → `ReplicateOp` репликам →
    /// `PublishAck` после `w` подтверждений (§9.4, §10.1).
    fn handle_publish(
        &mut self,
        from: Addr,
        bytes: &[u8],
        now: Clock,
    ) -> Result<Vec<Envelope>, NodeError> {
        let frame = decode_frame(bytes)?;
        let msg = Publish::decode(bytes)?;
        if frame.header.signed() {
            let ok = match frame.signature {
                Some(sig) => verify_body(
                    &msg.owner_ed25519,
                    domain::PUBLISH,
                    Kind::Publish,
                    frame.body,
                    &sig.try_into().unwrap_or([0u8; 64]),
                )
                .unwrap_or(false),
                None => false,
            };
            if !ok {
                return self.err(from, err_code::DENIED, 0);
            }
        }
        if shard_of_cluster(msg.cluster_id) != self.shard {
            return self.err(from, err_code::SHARD_MISMATCH, 0);
        }
        // Publish принимает только primary: реплика, у которой тоже активный lease и подтверждённый
        // `grant_epoch`, иначе ответила бы агенту `PublishAck`, не имея возможности разослать опс
        // (§9.4 — кворум собирает пишущая сторона). Агенту нужен адрес держателя, а не нам,
        // поэтому `NOT_OWNER` (§12.1).
        if !self.is_primary() {
            return self.err(from, err_code::NOT_OWNER, 1_000);
        }
        let epoch = match self.serving_epoch(now.bucket) {
            Some(e) => e,
            None => return self.err(from, err_code::EPOCH_STALE, 1_000),
        };
        // §11.3: локальный приём — до работы, которую отказ делает бессмысленной. Denylist и
        // бакет ключа стоят поиска в двух BTreeMap, а PoW — один blake3, поэтому бакет идёт
        // раньше проверки nonce: иначе узел верифицировал бы работу, которую заведомо не примет.
        // Платит и `from`, и заявленный owner: подпись в Publish опциональна (§5.3), поэтому
        // бакет только по owner обнулялся бы сменой литерала (см. `Admission::check_publish`).
        let verdict = self.admission.borrow_mut().check_publish(&from, &msg.owner_ed25519, now.sec);
        if let Some(code) = verdict.code() {
            return self.err(from, code, verdict.retry_after_ms());
        }
        // `slot_key` из §11.1 — это `intent_id`: слот узел назначает сам и агент узнать его
        // не может (спека, §11.1: привязка к identity, которую доприём вычисляет клиент).
        let expires = msg.published_bucket.saturating_add(msg.ttl_buckets as u32);
        let input = pow_input(&msg.owner_ed25519, self.shard, epoch, &msg.intent_id, expires);
        let bits = msg.pow_bits as u32;
        if bits < self.pow_bits as u32 {
            return self.err(from, err_code::POW_BITS_LOW, 1_000);
        }
        if bits > self.params.pow_bits_max as u32 {
            return self.err(from, err_code::POW_INVALID, 1_000);
        }
        if !pow_ok(&input, msg.pow_nonce, bits) {
            return self.err(from, err_code::POW_INVALID, 0);
        }
        // §11.3.4: узловой бюджет резервируется *до* вытеснения. Обратный порядок оставлял бы
        // за `BUSY` уже удалённую чужую запись — отказ дешевле принятия, но не ценой чужого
        // слота. Токен при последующем `SHARD_FULL` не возвращается: см. политику в
        // `Admission::check_publish`.
        let verdict = self.admission.borrow_mut().reserve_admit(now.sec);
        if let Some(code) = verdict.code() {
            return self.err(from, code, verdict.retry_after_ms());
        }
        // §11.3.2: живая запись у owner'а ровно одна, и перепубликация (§6.5) заменяет её на
        // месте. Поэтому вместимость шарда её не касается — иначе полный шард замёрз бы навсегда:
        // M записей не смогли бы даже обновиться, а TTL у них общий, и обновление продлевало бы
        // жизнь записи, не занимая нового slot'а.
        let replacing = self.store.index.owner_slot(&msg.owner_ed25519).is_some();
        let mut victim = None;
        if !replacing && (self.store.len() as u64) >= self.params.max_live_per_shard {
            let newcomer = Candidate::newcomer(bits, msg.published_bucket);
            victim = self.evictor.victim(newcomer, |s| self.store.index.is_live(s));
            if victim.is_none() {
                // Резервуар не знает всех цен: он видел только те записи, что принял этот узел
                // (рестарт и handoff обнуляют знание, §11.3.3). Один ограниченный проход по арене
                // дешевле, чем O(M) на каждый publish, и честнее, чем «жертвы нет» при живой
                // дешёвой записи.
                let from_slot = self.evictor.scan_from();
                let arena_end = self.store.index.next_slot();
                let entries = self
                    .store
                    .index
                    .live_slots_from(from_slot)
                    .map(|(s, e)| (s, e.published_bucket));
                self.evictor.refill(entries, arena_end, admission::EVICT_SCAN_BUDGET);
                victim = self.evictor.victim(newcomer, |s| self.store.index.is_live(s));
            }
            if victim.is_none() {
                // §11.3.3: дешевле новичка никого — значит отказ, а не вытеснение дорогой записи.
                return self.err(from, err_code::SHARD_FULL, 10_000);
            }
        }
        // Владелец жертвы нужен и для WAL-фрейма `Delete`, и для реплики: удаление — это
        // изменение индекса, а не локальная политика, и сойтись после handoff'a узлы смогут
        // только если обе стороны применили один и тот же фрейм (§8.3).
        let victim_entry = match victim {
            Some(c) => match self.store.index.entry(c.slot) {
                Some(e) => Some((c, e)),
                None => {
                    self.evictor.forget(c.slot);
                    return self.err(from, err_code::SHARD_FULL, 10_000);
                }
            },
            None => None,
        };
        let entry = IndexEntry {
            owner_ed25519: msg.owner_ed25519,
            vec_q: msg.vec_q,
            cluster_id: msg.cluster_id,
            published_bucket: msg.published_bucket,
            ttl_buckets: msg.ttl_buckets,
        };
        let insert_seq = match self.store.stage_insert(entry) {
            Ok(seq) => seq,
            Err(StoreError::WalFailed(_)) => return self.err(from, err_code::WAL_FAILED, 100),
            Err(e) => return Err(NodeError::Store(e)),
        };
        // insert ставится в WAL раньше delete, и реплицируется в том же порядке: реплика
        // отвергает фрейм с `seq > applied_seq + 1` (`WalGap`), поэтому «удалить, потом вставить»
        // на проводе потеряло бы delete, а «вставить, потом удалить» — нет.
        let delete_seq = match victim_entry {
            Some((_, e)) => match self.store.stage_delete(e.owner_ed25519) {
                Ok(seq) => Some(seq),
                Err(StoreError::WalFailed(_)) => return self.err(from, err_code::WAL_FAILED, 100),
                Err(e) => return Err(NodeError::Store(e)),
            },
            None => None,
        };
        if let Err(e) = self.store.commit() {
            return match e {
                StoreError::WalFailed(_) => self.err(from, err_code::WAL_FAILED, 100),
                other => Err(NodeError::Store(other)),
            };
        }
        let slot = self.store.index.owner_slot(&msg.owner_ed25519).unwrap_or(0);
        self.evictor.observe(slot, bits as u8, msg.published_bucket);
        let mut out = self.replicate(insert_seq, OpKind::Insert, entry.to_insert().body_bytes());
        if let (Some(seq), Some((c, e))) = (delete_seq, victim_entry) {
            let op = DeleteOp { owner_ed25519: e.owner_ed25519, shard: self.shard };
            out.extend(self.replicate(seq, OpKind::Delete, op.body_bytes()));
            self.evictor.forget(c.slot);
            self.evictor.evicted += 1;
        }
        // Собственный fsync — первое подтверждение кворума, а не весь кворум (§9.4: «сам + один
        // реплика»). Поэтому здесь никогда не может быть немедленного `PublishAck{OK}`: если
        // подтверждать при пустом составе, агент получил бы гарантию durable для записи, которую
        // держит один диск, и потеря шарда стала бы тихой потерей данных. `w >= 2` гарантируется
        // `Params` (`WTooSmall`), так что ожидающий ack набор всегда имеет смысл.
        self.awaiting.insert(insert_seq, Awaiting { agent: from, slot, acks: vec![self.me()] });
        Ok(out)
    }

    fn publish_ack_frame(&self, epoch: u64, seq: u64, slot: u32, code: &str, retry_after_ms: u32) -> Vec<u8> {
        PublishAck {
            shard: self.shard,
            epoch,
            seq,
            slot,
            next_pow_bits: self.pow_bits,
            error_code: code.to_string(),
            retry_after_ms,
        }
        .encode_unsigned()
    }

    fn handle_replicate(
        &mut self,
        from: Addr,
        bytes: &[u8],
    ) -> Result<Vec<Envelope>, NodeError> {
        let frame = decode_frame(bytes)?;
        let op = ReplicateOp::decode(bytes)?;
        let sig: [u8; 64] = match frame.signature {
            Some(s) => s.try_into().unwrap_or([0u8; 64]),
            None => return Ok(Vec::new()),
        };
        // Пишет только primary принятой эпизоды и только своим ключом.
        let allowed = self
            .membership
            .as_ref()
            .filter(|m| m.epoch() == op.epoch)
            .and_then(|m| m.primary());
        if allowed != Some(from) || !verify_body(&from, domain::REPLICA, Kind::ReplicateOp, frame.body, &sig).unwrap_or(false)
        {
            return Ok(Vec::new());
        }
        // `Err` здесь — это не «реплика сломалась», а fencing-сигнал: старый primary обязан
        // замолчать, увидев ok=false (§9.8).
        let ok = self.store.apply_replicated(&op).is_ok();
        let ack = ReplicateAck {
            shard: self.shard,
            epoch: op.epoch,
            seq: op.seq,
            replica_ed25519: self.me(),
            applied_seq: self.store.applied_seq,
            ok,
        };
        let body = ack.body_bytes();
        let sig = self.id.sign_body(domain::ACK, Kind::ReplicateAck, &body);
        Ok(vec![Envelope::new(from, ack.encode_signed(&sig))])
    }

    fn handle_replicate_ack(
        &mut self,
        from: Addr,
        bytes: &[u8],
    ) -> Result<Vec<Envelope>, NodeError> {
        let frame = decode_frame(bytes)?;
        let ack = ReplicateAck::decode(bytes)?;
        let sig: [u8; 64] = match frame.signature {
            Some(s) => s.try_into().unwrap_or([0u8; 64]),
            None => return Ok(Vec::new()),
        };
        let trusted = self
            .membership
            .as_ref()
            .map(|m| m.epoch() == ack.epoch && m.is_member(&ack.replica_ed25519))
            .unwrap_or(false);
        // Подпись кадра проверяется над байтами кадра с флагом подписанности и `kind` в дайджесте
        // (§5.3), поэтому здесь именно `verify_body`. `verify_domain` — для цепочки членства,
        // где подписывается `unsigned_body()` без kind: перепутать их означает молча отвергнуть
        // каждый ack, и кворум W=2 никогда не соберётся.
        if ack.shard != self.shard
            || !trusted
            || !verify_body(&ack.replica_ed25519, domain::ACK, Kind::ReplicateAck, frame.body, &sig)
                .unwrap_or(false)
        {
            return Ok(Vec::new());
        }
        let Some(mut aw) = self.awaiting.remove(&ack.seq) else { return Ok(Vec::new()) };
        if ack.ok && !aw.acks.contains(&from) {
            aw.acks.push(from);
        }
        if aw.acks.len() < self.params.w {
            self.awaiting.insert(ack.seq, aw);
            return Ok(Vec::new());
        }
        let epoch = self.epoch().unwrap_or(0);
        Ok(vec![Envelope::new(aw.agent, self.publish_ack_frame(epoch, ack.seq, aw.slot, "OK", 0))])
    }

    /// Разослать подписанный `ReplicateOp` всем членам, кроме себя.
    fn replicate(&mut self, seq: u64, kind: OpKind, body: Vec<u8>) -> Vec<Envelope> {
        let epoch = match self.serving_epoch_for_write() {
            Some(e) => e,
            None => return Vec::new(),
        };
        let op = ReplicateOp { shard: self.shard, epoch, seq, op_kind: kind, body };
        let bytes = op.body_bytes();
        let sig = self.id.sign_body(domain::REPLICA, Kind::ReplicateOp, &bytes);
        let frame = op.encode_signed(&sig);
        self.peers().into_iter().map(|p| Envelope::new(p, frame.clone())).collect()
    }

    /// Эпизода для записи. Отдельно от `serving_epoch`: чтение переживает потерю lease, а
    /// запись — нет (§9.4, §9.8). Fallback на `self.epoch()` здесь сознательно нет: опс,
    /// помеченный эпизодой, которой нет на диске, был бы ровно тем «неподтверждённым fsync'ом»,
    /// который §9.2 обещает не допустить.
    fn serving_epoch_for_write(&self) -> Option<u64> {
        if !self.is_primary() {
            return None;
        }
        self.durable_epoch()
    }

    /// `TimeMark` каждые 512 применённых опсов (§9.6). Часы берёт только primary, и только в
    /// момент записи фрейма: реплики применяют его дословно на том же `seq`, поэтому расхождение
    /// реальных часов на 40 минут не меняет содержимое индекса.
    fn maybe_time_mark(&mut self, now_bucket: u32) -> Result<Vec<Envelope>, NodeError> {
        // Тот же gate, что у репликации: `TimeMark` — это WAL-фрейм, и писать его без
        // подтверждённой эпизоды нельзя (§9.2).
        if self.serving_epoch_for_write().is_none() {
            return Ok(Vec::new());
        }
        if self.store.applied_seq.saturating_sub(self.last_mark_applied) < self.params.time_mark_every {
            return Ok(Vec::new());
        }
        let seq = self.store.stage_time_mark(now_bucket)?;
        self.store.commit()?;
        self.last_mark_applied = self.store.applied_seq;
        Ok(self.replicate(seq, OpKind::TimeMark, encode_mark(seq, now_bucket)))
    }

    /// `GcTick`, когда есть что истекать (§9.6). Фрейм пишется только primary с подтверждённой
    /// эпизодой, а реплики применяют тот же `bucket` на том же `seq` — поэтому расхождение
    /// локальных часов не меняет содержимое индекса.
    ///
    /// Проверка `next_deadline` стоит до `stage`: на TTL-плато живой счётчик не растёт, и
    /// безусловный `GcTick` каждый бакет давал бы пустые фреймы, от которых WAL растёт от одного
    /// времени, а барьер снапшота (§10.3) видит дельту, которой нет. Более поздний `GcTick`
    /// другого primary безопасен: `expire` идемпотентен по бакету, а `time_mark_bucket` только
    /// растёт; повторный фрейм в том же бакете — не ошибка, а лишняя работа.
    fn maybe_gc(&mut self, now_bucket: u32) -> Result<Vec<Envelope>, NodeError> {
        if self.serving_epoch_for_write().is_none() {
            return Ok(Vec::new());
        }
        match self.store.index.next_deadline() {
            Some(deadline) if deadline <= now_bucket => {}
            _ => return Ok(Vec::new()),
        }
        let seq = self.store.stage_gc_tick(now_bucket)?;
        self.store.commit()?;
        self.gc_ticks += 1;
        Ok(self.replicate(seq, OpKind::GcTick, encode_mark(seq, now_bucket)))
    }

    // --- чтение ----------------------------------------------------------------

    /// Поиск по шарду. Бакет берётся по `Clock::sec` (§11.3.6) — это локальная политика приёма,
    /// единственное место, где время допустимо не из `TimeMark`; сама выдача по-прежнему смотрит
    /// на последний применённый `TimeMark` (`search`), а не на часы узла (§9.6).
    fn handle_find(&mut self, from: Addr, bytes: &[u8], now: Clock) -> Result<Vec<Envelope>, NodeError> {
        // Отказ до разбора тела: `Find` — самый дорогой decode в протоколе (§19.5), и тратить его
        // на ключ, который всё равно получит `QUOTA_FIND`, незачем. Ключ — аутентифицированный
        // `from`, а не `requester_ed25519` из тела: второй в неподписанном кадре свободен.
        let verdict = self.admission.borrow_mut().check_find(&from, now.sec);
        if let Some(code) = verdict.code() {
            return self.err(from, code, verdict.retry_after_ms());
        }
        let q = Find::decode(bytes)?;
        if q.clusters.iter().any(|c| shard_of_cluster(*c) != self.shard) {
            return self.err(from, err_code::SHARD_MISMATCH, 0);
        }
        let epoch = self.epoch().unwrap_or(0);
        let top_k = (q.top_k as usize).min(self.params.top_k_max as usize);
        let hits = self.store.search(&q.query_vector, &q.clusters, top_k);
        let res = MatchResult {
            shard: self.shard,
            epoch,
            query_id: q.query_id,
            responder_ed25519: self.me(),
            matches: self.store.index.matches(&hits),
        };
        // Контракт сортировки проверяется до подписания: подписанный неканонический список
        // агент не отличит от подделанного (§8.4).
        if res.check_sort_contract().is_err() {
            return Err(NodeError::Unexpected {
                kind: "MatchResult",
                why: "индекс отдал неканонически отсортированный список".into(),
            });
        }
        let body = res.body_bytes();
        let sig = self.id.sign_body(domain::MATCH, Kind::MatchResult, &body);
        let mut out = Vec::with_capacity(1 + res.matches.len());
        out.push(Envelope::new(from, res.encode_signed(&sig)));
        // Приём — отдельный кадр 0x50 на каждую найденную запись (§12.3): у `Match` нет поля под
        // него, и склеивать их значило бы менять формат `MatchResult`. `seeker` — транспортный
        // `from`, а не `requester_ed25519` из тела: тело `Find` не подписано, и второй свободен
        // для подмены; привязка к аутентифицированному адресу — единственная, которую цель может
        // перепроверить (§4.3).
        for m in &res.matches {
            let Some(acc) = self.rendezvous.issue(from, m.owner_ed25519, self.shard, m.slot, now.bucket)
            else {
                // Потолок lease-таблицы. Это не ошибка `Find`: `MatchResult` уже собран, а приём —
                // дополнение к нему, без которого поиск остаётся корректным (§12.3).
                continue;
            };
            let body = acc.body_bytes();
            let sig = self.id.sign_body(domain::RENDEZVOUS, Kind::RendezvousAccept, &body);
            out.push(Envelope::new(from, acc.encode_signed(&sig)));
        }
        Ok(out)
    }

    // --- догоняющий WAL и снапшот ------------------------------------------------

    /// Запрос хвоста WAL у держателя. `to_seq = 0` означает «до текущего» (§5.3), а лимит байт —
    /// половина тела кадра, чтобы ответ гарантированно влез в `MAX_BODY_LEN` без переделки wire.
    ///
    /// Пустой узел просит с `from_seq = 0`, а не с 1: у узла без единого применённого опса это
    /// единственный способ сказать «мне нужен снапшот, а не хвост» — seed трактует запрос младше
    /// `oldest_wal_needed` как холодный (§9.5, п.2). Отдельного kind для этого нет намеренно:
    /// повторный запрос от того же пира = «дай следующий кусок».
    fn pull_request(&self, to: Addr) -> Envelope {
        let from_seq = if self.store.applied_seq == 0 { 0 } else { self.store.applied_seq + 1 };
        let frame = WalPullRequest {
            shard: self.shard,
            from_seq,
            to_seq: 0,
            max_bytes: (MAX_BODY_LEN / 2) as u32,
        }
        .encode_unsigned();
        Envelope::new(to, frame)
    }

    fn handle_pull_request(
        &mut self,
        from: Addr,
        bytes: &[u8],
        now_bucket: u32,
    ) -> Result<Vec<Envelope>, NodeError> {
        let req = WalPullRequest::decode(bytes)?;
        if req.shard != self.shard {
            return Ok(Vec::new());
        }
        let mf = self.store.manifest();
        // Хвост перекрыт снапшотом: кадры отсюда не выдаются, и честный ответ — кусок снапшота
        // (§9.7 + §9.5). Повторный холодный запрос от того же пира = «дай следующий кусок».
        if req.from_seq < mf.oldest_wal_needed && self.store.last_snapshot_seq > 0 {
            return self.serve_snapshot(from, &mf, now_bucket);
        }
        let mut frames = Vec::new();
        let mut last = req.from_seq.saturating_sub(1);
        let limit = req.max_bytes.min(MAX_BODY_LEN as u32 / 2) as usize;
        let mut used = 0usize;
        let segments = list_segments(self.dir())
            .map_err(|e| NodeError::Io { ctx: "list_segments", detail: e.to_string() })?;
        'segments: for (_start, path) in segments {
            let seg =
                read_segment(&path).map_err(|e| NodeError::Io { ctx: "read_segment", detail: e.to_string() })?;
            for frame in seg.frames {
                // `seq` растёт и внутри сегмента, и от сегмента к сегменту. Младше запроса —
                // просто пропускаем; старше `to_seq` — читать больше нечего, дальше только хуже.
                if frame.seq < req.from_seq {
                    continue;
                }
                if req.to_seq != 0 && frame.seq > req.to_seq {
                    break 'segments;
                }
                let encoded = frame.encode();
                if used + encoded.len() > limit {
                    break 'segments;
                }
                used += encoded.len();
                last = frame.seq;
                frames.extend_from_slice(&encoded);
            }
        }
        let resp = WalPullResponse {
            shard: self.shard,
            from_seq: req.from_seq,
            to_seq: last,
            primary_epoch: self.durable_epoch().or_else(|| self.epoch()).unwrap_or(0),
            frames,
        };
        Ok(vec![Envelope::new(from, resp.encode_unsigned())])
    }

    /// Отдать следующий кусок снапшота (§9.5, пункт 2).
    fn serve_snapshot(
        &mut self,
        to: Addr,
        mf: &StoreManifest,
        _now_bucket: u32,
    ) -> Result<Vec<Envelope>, NodeError> {
        let seq = self.store.last_snapshot_seq;
        let path = snapshot::path_of(self.dir(), seq);
        let total = std::fs::metadata(&path)
            .map_err(|e| NodeError::Io { ctx: "stat snapshot", detail: e.to_string() })?
            .len() as u32;
        let mut state = match self.cold.get(&to) {
            // `total` входит в условие: снапшот переписали в другом размере посреди передачи —
            // это другой файл, и продолжать прежним отсчётом нельзя.
            Some(c) if c.snapshot_seq == seq && c.total == total => *c,
            _ => Cold {
                snapshot_seq: seq,
                offset: 0,
                total,
                content_hash: snapshot::file_hash(&path).map_err(NodeError::Sync)?,
            },
        };
        if total == 0 || state.offset >= total {
            self.cold.remove(&to);
            return Ok(Vec::new());
        }
        let chunk = snapshot::read_chunk(&path, state.offset, total).map_err(NodeError::Sync)?;
        let offer = SnapshotOffer {
            shard: self.shard,
            epoch: self.epoch().unwrap_or(0),
            snapshot_seq: seq,
            oldest_wal_needed: mf.oldest_wal_needed,
            applied_seq: mf.applied_seq,
            next_slot: mf.next_slot,
            time_mark_bucket: mf.time_mark_bucket,
            total_len: total,
            offset: state.offset,
            content_hash: state.content_hash,
            chunk,
        };
        state.offset += offer.chunk.len() as u32;
        if state.offset >= total {
            self.cold.remove(&to);
        } else {
            self.cold.insert(to, state);
        }
        let body = offer.body_bytes();
        let sig = self.id.sign_body(domain::SNAPSHOT, Kind::SnapshotOffer, &body);
        Ok(vec![Envelope::new(to, offer.encode_signed(&sig))])
    }

    fn handle_snapshot_offer(
        &mut self,
        from: Addr,
        bytes: &[u8],
    ) -> Result<Vec<Envelope>, NodeError> {
        let frame = decode_frame(bytes)?;
        let offer = SnapshotOffer::decode(bytes)?;
        if offer.shard != self.shard {
            return Ok(Vec::new());
        }
        // Кусок обязан быть подписан тем, кому мы его заказывали: `SnapshotOffer` — «пояс», а не
        // гарантия (§9.5), и без атрибуции куска пояс не стоит ничего.
        let sig: [u8; 64] = match frame.signature {
            Some(s) => s.try_into().unwrap_or([0u8; 64]),
            None => return Ok(Vec::new()),
        };
        // Подпись кадра — это подпись над байтами кадра с `kind` (§5.3), а не над произвольной
        // структурой, как в цепочке членства: сверять её `verify_domain` означало бы отвергнуть
        // каждый кусок снапшота и никогда не догнать seed.
        if !verify_body(&from, domain::SNAPSHOT, Kind::SnapshotOffer, frame.body, &sig)
            .unwrap_or(false)
        {
            return Ok(Vec::new());
        }
        let mut asm = match self.assembly.take() {
            Some(a) if a.snapshot_seq == offer.snapshot_seq && a.epoch == offer.epoch => a,
            _ => Assembly {
                asm: Assembler::new(offer.total_len, offer.content_hash),
                epoch: offer.epoch,
                snapshot_seq: offer.snapshot_seq,
                oldest_wal_needed: offer.oldest_wal_needed,
                applied_seq: offer.applied_seq,
                next_slot: offer.next_slot,
                time_mark_bucket: offer.time_mark_bucket,
            },
        };
        // Метаданные берём из последнего куска: все куски одной передачи обязаны нести одинаковые,
        // и расхождение — это попытка подменить геометрию файла.
        asm.oldest_wal_needed = offer.oldest_wal_needed;
        asm.applied_seq = offer.applied_seq;
        asm.next_slot = offer.next_slot;
        asm.time_mark_bucket = offer.time_mark_bucket;
        match asm.asm.push(offer.offset, &offer.chunk) {
            Ok(Some(file)) => self.install_snapshot(&asm, &file, from),
            // Кусок принят, но файла ещё нет: следующий запрос — это «дай дальше». Холодный путь
            // (`from_seq` младше `oldest_wal_needed`) сохраняется, пока сборка не завершена:
            // `applied_seq` всё ещё ноль, поэтому `pull_request` снова просит с нуля и seed
            // отдаёт очередной кусок, а не хвост WAL (§9.5, п.2).
            Ok(None) => {
                self.assembly = Some(asm);
                Ok(vec![self.pull_request(from)])
            }
            // Битый набор кусков: приём сброшен, просим заново с нуля.
            Err(_) => {
                self.assembly = None;
                Ok(vec![self.pull_request(from)])
            }
        }
    }

    /// Поставить собранный снапшот и перезагрузить индекс. Живой индекс с собственными опсами
    /// не откатывается (§9.5): приём разрешён только пустому узлу.
    fn install_snapshot(
        &mut self,
        asm: &Assembly,
        file: &[u8],
        from: Addr,
    ) -> Result<Vec<Envelope>, NodeError> {
        self.assembly = None;
        if self.store.applied_seq != 0 || !self.store.is_empty() {
            return Ok(Vec::new());
        }
        let mf = StoreManifest {
            shard: self.shard,
            snapshot_seq: asm.snapshot_seq,
            oldest_wal_needed: asm.oldest_wal_needed,
            applied_seq: asm.applied_seq,
            next_slot: asm.next_slot,
            time_mark_bucket: asm.time_mark_bucket,
        };
        snapshot::install(self.dir(), file, &mf)?;
        self.store = ShardStore::open(self.dir(), self.shard)?;
        self.last_mark_applied = self.store.applied_seq;
        if let Some(epoch) = self.epoch() {
            self.store.grant_epoch(epoch)?;
        }
        // Снапшот перекрывает не всё: дальше обычный хвост от того же seed'а (§9.7). `pull_request`
        // сам считает `from_seq` от нового `applied_seq`, поэтому «догнать хвост» и «попросить
        // следующий кусок» — один и тот же кадр.
        Ok(vec![self.pull_request(from)])
    }

    fn handle_pull_response(&mut self, from: Addr, bytes: &[u8]) -> Result<Vec<Envelope>, NodeError> {
        let resp = WalPullResponse::decode(bytes)?;
        if resp.shard != self.shard || resp.primary_epoch == 0 {
            return Ok(Vec::new());
        }
        let before = self.store.applied_seq;
        let mut rest = &resp.frames[..];
        while !rest.is_empty() {
            let (frame, used) = WalFrame::decode(rest)
                .map_err(|e| NodeError::Io { ctx: "wal frame", detail: e.to_string() })?;
            rest = &rest[used..];
            let op = ReplicateOp {
                shard: self.shard,
                epoch: resp.primary_epoch,
                seq: frame.seq,
                op_kind: frame.kind,
                body: frame.body,
            };
            // Догоняющий применяет чужой `seq` дословно: перенумерация разошлась бы с потоком
            // primary (§8.3). Эпоха источника — из ответа, а не из фрейма: догонять можно и
            // опсами прошлой эпизоды, но только от узла, который уже обслуживает новую (§9.7).
            if self.store.apply_replicated(&op).is_err() {
                break;
            }
        }
        // Счётчик безрезультатных попыток: дыра в WAL источника иначе превращает anti-entropy в
        // бесконечный цикл pull → ответ → та же ошибка → pull. После `MAX_PULL_ATTEMPTS` узел
        // ждёт следующее событие — смену эпизоды или новый запрос агента.
        if self.store.applied_seq > before {
            self.pull_attempts = 0;
        } else {
            self.pull_attempts += 1;
        }
        if self.store.applied_seq < resp.to_seq && self.pull_attempts < MAX_PULL_ATTEMPTS {
            return Ok(vec![self.pull_request(from)]);
        }
        // Догнали: `TimeMark` барьер считает заново от актуального `applied_seq`.
        self.last_mark_applied = self.last_mark_applied.max(self.store.applied_seq);
        Ok(Vec::new())
    }

    // --- уход и отказ -------------------------------------------------------------

    fn handle_leave(
        &mut self,
        from: Addr,
        bytes: &[u8],
        now_bucket: u32,
    ) -> Result<Vec<Envelope>, NodeError> {
        let frame = decode_frame(bytes)?;
        let notice = LeaveNotice::decode(bytes)?;
        let sig: [u8; 64] = match frame.signature {
            Some(s) => s.try_into().unwrap_or([0u8; 64]),
            None => return Ok(Vec::new()),
        };
        let member = self
            .membership
            .as_ref()
            .map(|m| m.epoch() == notice.epoch && m.is_member(&notice.leaving_owner))
            .unwrap_or(false);
        if notice.shard != self.shard
            || notice.leaving_owner != from
            || !verify_body(&from, domain::LEAVE, Kind::LeaveNotice, frame.body, &sig)
                .unwrap_or(false)
            || !member
        {
            return Ok(Vec::new());
        }
        if !self.draining.contains(&from) {
            self.draining.push(from);
        }
        // Handoff начинается сразу: ждать `drain_deadline` — это просто лишние секунды простоя,
        // а уходящий ещё может подписать собственный уход (§9.5).
        if self.should_propose(now_bucket) {
            return self.propose_next(now_bucket);
        }
        Ok(Vec::new())
    }

    /// Транспорт подтвердил, что соединения с узлом больше нет (§9.8: детекция недоступности —
    /// событие транспорта, а не таймер; election timeout остаётся верхней границей для случая,
    /// когда события нет вовсе). Отличие от `LeaveNotice` только одно: подписи уходящего нет,
    /// поэтому решение о его судьбе принимается без его голоса.
    ///
    /// Вызывать обязан транспорт при `peer-disconnected`. Без этого вызова мёртвый узел
    /// оставался бы в составе до истечения его lease, а шард — без primary на все 90 с.
    pub fn peer_lost(&mut self, addr: Addr, now_bucket: u32) -> Result<Vec<Envelope>, NodeError> {
        if !self.unreachable.contains(&addr) {
            self.unreachable.push(addr);
        }
        if self.should_propose(now_bucket) {
            return self.propose_next(now_bucket);
        }
        Ok(Vec::new())
    }

    /// Публичное «я ухожу»: подписать `LeaveNotice`, сдать право писать и предложить состав без
    /// себя. Возвращает письма, чтобы транспорт успел их отправить до остановки процесса.
    pub fn leave(&mut self, now_bucket: u32, drain_after_buckets: u32) -> Result<Vec<Envelope>, NodeError> {
        let Some(m) = self.membership.clone() else { return Ok(Vec::new()) };
        let me = self.me();
        let notice = LeaveNotice {
            epoch: m.epoch(),
            shard: self.shard,
            leaving_owner: me,
            drain_deadline_bucket: now_bucket.saturating_add(drain_after_buckets),
        };
        let body = notice.body_bytes();
        let sig = self.id.sign_body(domain::LEAVE, Kind::LeaveNotice, &body);
        let frame = notice.encode_signed(&sig);
        let mut out: Vec<Envelope> =
            m.peers(&me).into_iter().map(|p| Envelope::new(p, frame.clone())).collect();
        self.leaving = true;
        // Lease — право писать, а не право занимать место: уходящий primary обязан сдать его
        // сразу, иначе шард стоит без возможности записи все `lease_buckets` (§9.5, п.1 — уход
        // завершается handoff'ом, а не молчанием).
        if m.primary() == Some(me) {
            self.lease = None;
        }
        // Состав без себя предлагает сам уходящий: его подпись участника epoch−1 легитимна
        // (§9.2 про индексы в `sigs`), а у остальных на момент его ухода нет никаких
        // доказательств, кроме его `LeaveNotice`.
        if self.should_propose(now_bucket) {
            out.extend(self.propose_next(now_bucket)?);
        }
        Ok(out)
    }

    // --- диспетчер -----------------------------------------------------------------

    /// Один входящий кадр. `from` — аутентифицированный ключ пира из транспорта (§4.3); для
    /// агентов это его `owner_ed25519`. `now` несёт и секунду, и бакет: бакет обслуживает
    /// протокол (§9.6), секунда — только per-key бакеты admission (§11.3), которым часовая
    /// гранулярность не подходит.
    pub fn on_frame(&mut self, from: Addr, bytes: &[u8], now: Clock) -> Result<Vec<Envelope>, NodeError> {
        let f = decode_frame(bytes)?;
        if f.header.kind.signature_required() && !f.header.signed() {
            // Обязательная подпись отсутствует (§5.3): кадр не проходит дальше.
            return Ok(Vec::new());
        }
        // `kind` захвачен до `match`: сообщение об ошибке не должно описываться переменной,
        // живущей внутри одного обработчика.
        let kind = f.header.kind;
        match kind {
            Kind::Publish => self.handle_publish(from, bytes, now),
            Kind::Find => self.handle_find(from, bytes, now),
            Kind::ReplicateOp => self.handle_replicate(from, bytes),
            Kind::ReplicateAck => self.handle_replicate_ack(from, bytes),
            Kind::MembershipUpdate => self.handle_membership(bytes, now.bucket),
            Kind::LeaseGrant => self.handle_lease_grant(from, bytes, now.bucket),
            Kind::WalPullRequest => self.handle_pull_request(from, bytes, now.bucket),
            Kind::WalPullResponse => self.handle_pull_response(from, bytes),
            Kind::SnapshotOffer => self.handle_snapshot_offer(from, bytes),
            Kind::LeaveNotice => self.handle_leave(from, bytes, now.bucket),
            // Handshake/Error/PublishAck/IntentText*/ArtifactAnnounce/RendezvousAccept/CertRevoke —
            // не входят в путь шарда; узел их не порождает и принимать не обязан (§4.3).
            _ => Ok(Vec::new()),
        }
        .map_err(|e| match e {
            // Ошибка разбора чужого кадра — это не инвариант узла, а входные данные: оборачиваем
            // с именем kind, чтобы тест отличал «протокол сломался» от «пришёл мусор».
            NodeError::Decode(d) => {
                NodeError::Unexpected { kind: kind.name(), why: format!("не разобран: {d}") }
            }
            other => other,
        })
    }

    fn err(&self, to: Addr, code: &str, retry_after_ms: u32) -> Result<Vec<Envelope>, NodeError> {
        let e = ProtocolError { code: code.to_string(), retry_after_ms, shard: self.shard };
        Ok(vec![Envelope::new(to, e.encode_unsigned())])
    }
}

fn merge_sigs(upd: &mut MembershipUpdate, extra: &[(u8, [u8; 64])]) {
    for (idx, sig) in extra {
        if !upd.sigs.iter().any(|(i, _)| i == idx) {
            upd.sigs.push((*idx, *sig));
        }
    }
}

/// Тот ли это состав, только с другой эпизоды. Порядок в списках разный по построению (§9.3
/// сортирует по ключу `epoch ‖ shard ‖ owner`), поэтому сравниваются множества: иначе узел
/// предлагал бы «новый» состав каждые `lease_buckets`, хотя состав не менялся.
fn same_members(cur: &[Member], next: &[Member]) -> bool {
    cur.len() == next.len() && cur.iter().all(|m| next.iter().any(|n| n.owner_ed25519 == m.owner_ed25519))
}

