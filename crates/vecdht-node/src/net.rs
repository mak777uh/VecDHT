//! Транспорт в процессе: почтовые ящики, симулированные часы и `kill` (§19.1).
//!
//! `Addr` — это `owner_ed25519`: в v8 аутентифицированный ключ пира и есть адрес (§4.1), а
//! байты libp2p `PeerId` живут в `Member.dht_peer_id` и `LeaseGrant.dht_peer_id` для сверки
//! настоящим транспортом. Здесь транспорта нет намеренно: гейты P4 обязаны измерять
//! *протокольное* время handoff, а не задержку localhost, поэтому в сети один часовой
//! интервал и одна стоимость доставки, обе — параметры конструктора.
//!
//! Узел не спит и не опрашивает сеть сам: кадры доставляются по расписанию, а `tick` вызывается
//! на границе 16-секундного бакета. Именно так тест может сказать «прошло 5 секунд» и получить
//! ответ, который в боевом коде зависит от wall-clock.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use crate::config::bucket_of;
use crate::node::ShardNode;

/// Адрес узла или агента = его Ed25519-ключ (§4.1).
pub type Addr = [u8; 32];

/// Куда и что отправить: кадр уже собранный, транспорт его не анализирует.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    pub to: Addr,
    pub frame: Vec<u8>,
}

impl Envelope {
    pub fn new(to: Addr, frame: Vec<u8>) -> Self {
        Envelope { to, frame }
    }
}

/// Очередь с временем доставки: `(from, due_sec, frame)`.
type Item = (Addr, u64, Vec<u8>);

pub struct LocalNet {
    nodes: BTreeMap<Addr, ShardNode>,
    inbox: BTreeMap<Addr, VecDeque<Item>>,
    /// Адреса вне сети (агенты, тест): кадр просто копится, пока его не прочитали.
    mailbox: BTreeMap<Addr, Vec<(Addr, Vec<u8>)>>,
    dead: BTreeSet<Addr>,
    now_sec: u64,
    latency_sec: u64,
    last_bucket: u32,
    pub delivered: usize,
    pub dropped: usize,
    /// Ошибки диспетчера узлов: тест обязан видеть их, а не молча терять кадры.
    pub errors: Vec<String>,
}

impl LocalNet {
    /// `latency_sec` — сколько wall-секунд стоит одна доставка. При 1 с три round-trip
    /// дают 6 с, что и проверяется гейтом «handoff < 10 с».
    pub fn new(latency_sec: u64) -> Self {
        LocalNet {
            nodes: BTreeMap::new(),
            inbox: BTreeMap::new(),
            mailbox: BTreeMap::new(),
            dead: BTreeSet::new(),
            now_sec: 0,
            latency_sec,
            last_bucket: 0,
            delivered: 0,
            dropped: 0,
            errors: Vec::new(),
        }
    }

    pub fn add(&mut self, node: ShardNode) -> Addr {
        let addr = node.me();
        self.nodes.insert(addr, node);
        addr
    }

    pub fn node(&self, addr: &Addr) -> Option<&ShardNode> {
        self.nodes.get(addr)
    }

    pub fn node_mut(&mut self, addr: &Addr) -> Option<&mut ShardNode> {
        self.nodes.get_mut(addr)
    }

    pub fn addrs(&self) -> Vec<Addr> {
        self.nodes.keys().copied().collect()
    }

    pub fn now_sec(&self) -> u64 {
        self.now_sec
    }

    pub fn now_bucket(&self) -> u32 {
        bucket_of(self.now_sec)
    }

    /// Отправить кадр. Мёртвому узлу не отправляется: доставка ему и есть потеря (§9.4 —
    /// именно так и теряется ack убитой реплики).
    pub fn send(&mut self, from: Addr, to: Addr, frame: Vec<u8>) {
        if self.dead.contains(&to) {
            self.dropped += 1;
            return;
        }
        if self.nodes.contains_key(&to) {
            self.inbox.entry(to).or_default().push_back((from, self.now_sec + self.latency_sec, frame));
        } else {
            self.mailbox.entry(to).or_default().push((from, frame));
        }
    }

    /// Кадры, пришедшие на адрес вне сети (агент читает свои `PublishAck` отсюда).
    pub fn take(&mut self, addr: &Addr) -> Vec<(Addr, Vec<u8>)> {
        self.mailbox.remove(addr).unwrap_or_default()
    }

    pub fn has_mail(&self, addr: &Addr) -> bool {
        self.mailbox.get(addr).map(|v| !v.is_empty()).unwrap_or(false)
    }

    /// Убить узел: он перестаёт обрабатывать и отвечать, его очередь теряется. Кредашиал
    /// остаётся вестимым — сеть обязана разобраться с этим по lease, а не по факту удаления.
    ///
    /// Оставшимся узлам сообщается об обрыве соединения (`ShardNode::peer_lost`) — ровно то, что
    /// делает настоящий транспорт при закрытой сессии. Без этого сигнала handoff был бы ограничен
    /// истечением lease (96 с), а гейт P4 (§19.1) измеряет время от факта смерти узла, поэтому
    /// событие транспорта здесь не «подсказка тесту», а часть модели (§9.8).
    pub fn kill(&mut self, addr: &Addr) {
        self.nodes.remove(addr);
        self.inbox.remove(addr);
        self.dead.insert(*addr);
        let bucket = self.now_bucket();
        let addrs: Vec<Addr> = self.nodes.keys().copied().collect();
        for live in addrs {
            let replies = match self.nodes.get_mut(&live) {
                Some(node) => node.peer_lost(*addr, bucket),
                None => continue,
            };
            match replies {
                Ok(list) => {
                    for env in list {
                        self.send(live, env.to, env.frame);
                    }
                }
                Err(e) => self.errors.push(format!("{live:?}: peer_lost {addr:?}: {e}")),
            }
        }
    }

    /// Пройти `sec` секунд: на каждом шаге доставить положенное и вызвать `tick` на границе
    /// бакета. Новые кадры, рождённые доставкой, положены на `now + latency`, поэтому в этот
    /// же шаг они не попадают — петли нет по построению.
    pub fn step(&mut self, sec: u64) {
        for _ in 0..sec {
            self.now_sec += 1;
            self.deliver_due();
            let bucket = self.now_bucket();
            if bucket != self.last_bucket {
                self.last_bucket = bucket;
                self.tick(bucket);
            }
        }
    }

    fn deliver_due(&mut self) {
        let addrs: Vec<Addr> = self.nodes.keys().copied().collect();
        for addr in addrs {
            let mut due: Vec<Item> = Vec::new();
            if let Some(q) = self.inbox.get_mut(&addr) {
                while q.front().map(|(_, t, _)| *t <= self.now_sec).unwrap_or(false) {
                    due.push(q.pop_front().unwrap());
                }
            }
            for (from, _, frame) in due {
                self.delivered += 1;
                // `now_bucket` считается до заимствования: вызов `on_frame` держит `&mut self.nodes`,
                // и тот же `self` внутри аргумента — это конфликт заимствований.
                let bucket = self.now_bucket();
                let replies = match self.nodes.get_mut(&addr) {
                    Some(node) => node.on_frame(from, &frame, bucket),
                    None => continue,
                };
                match replies {
                    Ok(list) => {
                        for env in list {
                            self.send(addr, env.to, env.frame);
                        }
                    }
                    Err(e) => self.errors.push(format!("{addr:?}: {e}")),
                }
            }
        }
    }

    fn tick(&mut self, bucket: u32) {
        let addrs: Vec<Addr> = self.nodes.keys().copied().collect();
        for addr in addrs {
            let Some(node) = self.nodes.get_mut(&addr) else { continue };
            match node.tick(bucket) {
                Ok(list) => {
                    for env in list {
                        self.send(addr, env.to, env.frame);
                    }
                }
                Err(e) => self.errors.push(format!("{addr:?}: tick {bucket}: {e}")),
            }
        }
    }

    /// Шагать по секунде, пока в сети не станет тихо. `max_sec` — предохранитель: спорный
    /// lease порождает трафик, и тест обязан услышать «не разошлось», а не зависнуть.
    pub fn settle(&mut self, max_sec: u64) -> bool {
        for _ in 0..max_sec {
            self.step(1);
            if self.is_quiet() {
                return true;
            }
        }
        false
    }

    pub fn is_quiet(&self) -> bool {
        self.inbox.values().all(|q| q.is_empty())
    }

    pub fn pending(&self) -> usize {
        self.inbox.values().map(|q| q.len()).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(i: u8) -> Addr {
        [i; 32]
    }

    #[test]
    fn frames_to_non_nodes_are_delivered_into_a_mailbox_once() {
        let mut net = LocalNet::new(3);
        let agent = addr(9);
        let peer = addr(8);
        net.send(agent, peer, vec![0x02, 0x00]);
        assert_eq!(net.pending(), 0, "очередей узлов нет — значит и отложенной доставки нет");
        assert!(net.has_mail(&peer));
        let got = net.take(&peer);
        assert_eq!(got, vec![(agent, vec![0x02u8, 0x00])], "кадр читается ровно один раз");
        assert!(!net.has_mail(&peer));
        net.step(5);
        assert_eq!(net.take(&peer), Vec::new(), "шаг времени не должен возвращать прочитанное");
    }

    #[test]
    fn killed_node_never_receives_again() {
        let mut net = LocalNet::new(1);
        net.kill(&addr(5));
        net.send(addr(1), addr(5), vec![0x02]);
        assert_eq!(net.dropped, 1);
        assert_eq!(net.pending(), 0);
    }
}
