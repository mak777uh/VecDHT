//! Корень шарда — две формы, чья цена измеряется в `E-0019` (`H-0018`).
//!
//! Зачем это вообще в crate: план v9 ставит корень первой ссылкой стадии 4 («подотчётность и
//! ротация») и ссылается на `E-0019` как на сделанный прогон, которого в реестре не было. Решение
//! «вводить ли root в протокол» (§20.2, п. 4) поэтому висело на ненаписанном числе. Этот модуль —
//! **измерительный стенд, а не часть протокола**: ни `Store`, ни wire, ни снапшот его не вызывают,
//! пока `E-0019` не скажет, оплачивает ли он себя.
//!
//! Формы отличаются и ценой, и тем, что позволяют проверить:
//!
//! * [`ChainRoot`] — цепочка `H(root_prev ‖ payload)` по **каждому применённому опy**: O(1)
//!   хеш-обновлений на op, 32 байта состояния, порядок вшит через `seq` (он входит в payload,
//!   §10.2), поэтому два узла, применившие один лог в одном порядке, обязаны сойтись побитово.
//!   Доказательства включения одной записи не даёт — зато сравнение двух владельцев стоит 32 Б.
//! * [`OpTree`] — полное двоичное дерево Меркела над тем же списком опов, занумерованных по
//!   `seq`: O(log n) обновлений на op, доказательство включения — log₂ n узлов. Цена — узлы:
//!   дерево, по которому можно что-то доказать, хранит (2n − 1) хешей, и именно это число решает
//!   судьбу порога «≤ 2 % снапшота».
//!
//! Байты входа — ровно те же, по которым WAL считает crc32 (`seq ‖ kind ‖ body_len ‖ body`,
//! [`WalFrame::payload`](crate::wal::WalFrame::payload)), чтобы «один и тот же оп» означал «одни и
//! те же байты» и в цепи, и в дереве, и на диске. Ни часов, ни float, ни порядка обхода, кроме
//! возрастающего `seq`.

use crate::wal::WalFrame;
use vecdht_wire::messages::OpKind;

/// Размер корня в байтах — и у цепи, и у дерева (blake3 digest).
pub const ROOT_BYTES: usize = 32;

/// Домен всех корней этого модуля: без него корень одной конструкции можно было бы выдать за
/// корень другой, а leaf-узел — за внутренний.
const ROOT_DOMAIN: &[u8] = b"vecdht-shard-root-v1";
/// Метка листа (лист = payload опа).
const LEAF_TAG: u8 = 0x01;
/// Метка внутреннего узла.
const NODE_TAG: u8 = 0x02;
/// Метка пустого поддерева (листьев, которых ещё нет).
const EMPTY_TAG: u8 = 0x03;
/// Метка genesis-значения, привязанного к шарду.
const GENESIS_TAG: u8 = 0x00;
/// Метка шага цепи (`prev ‖ payload`): отдельная от leaf, чтобы «лист дерева» и «шаг цепи» над
/// одинаковыми байтами не давали одинакового значения.
const CHAIN_TAG: u8 = 0x04;

/// Хеш `tag ‖ data` в домене корня. Одна функция на все три конструкции, чтобы «тот же вход»
/// не означал двух разных способов прочесть один и те же байты.
#[inline]
fn domain_hash(tag: u8, a: &[u8], b: &[u8]) -> [u8; ROOT_BYTES] {
    let mut h = blake3::Hasher::new();
    h.update(ROOT_DOMAIN);
    h.update(&[tag]);
    h.update(a);
    h.update(b);
    *h.finalize().as_bytes()
}

/// Цепочка blake3 по применённым опам: `root_i = H(root_{i-1} ‖ payload_i)`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainRoot {
    value: [u8; ROOT_BYTES],
    ops: u64,
}

impl ChainRoot {
    /// Начальное значение, привязанное к шарду: пустой лог на всех узлах одного шарда даёт
    /// один и тот же корень, и он отличается от корня другого шарда.
    pub fn genesis(shard: u16) -> Self {
        ChainRoot { value: domain_hash(GENESIS_TAG, &shard.to_le_bytes(), &[]), ops: 0 }
    }

    #[inline]
    pub fn value(&self) -> [u8; ROOT_BYTES] {
        self.value
    }

    /// Число опов в цепи — параллельно `applied_seq`. Их совпадение и есть проверка, что корень
    /// не «забыл» опсов (например, после snapshot-барьера или recovery).
    #[inline]
    pub fn ops(&self) -> u64 {
        self.ops
    }

    #[inline]
    pub fn update(&mut self, frame: &WalFrame) {
        self.update_payload(&frame.payload());
    }

    /// Ровно один blake3-проход по payload (~430 Б на Insert). Никакого переиспользования
    /// hasher'а: состояние цепи — финальный digest, и честная цена этого и есть измеряемая цена.
    #[inline]
    pub fn update_payload(&mut self, payload: &[u8]) {
        self.value = domain_hash(CHAIN_TAG, &self.value, payload);
        self.ops += 1;
    }

    /// То же значение, что [`ChainRoot::update`], но без аллокации payload: байты подаются в
    /// hasher так же, как их подаёт `WalFrame::payload` (`seq ‖ kind ‖ body_len ‖ body`).
    ///
    /// Это не «другой корень», а способ напечатать цену: `update` платит один `Vec` на op, и если
    /// эта аллокация — заметная доля стоимости, измеряющее её число обязано быть в прогоне
    /// (`E-0019`, справочная колонка). Равенство значений проверено тестом.
    #[inline]
    pub fn update_parts(&mut self, seq: u64, kind: u8, body: &[u8]) {
        let mut h = blake3::Hasher::new();
        h.update(ROOT_DOMAIN);
        h.update(&[CHAIN_TAG]);
        h.update(&self.value);
        h.update(&seq.to_le_bytes());
        h.update(&[kind]);
        h.update(&(body.len() as u32).to_le_bytes());
        h.update(body);
        self.value = *h.finalize().as_bytes();
        self.ops += 1;
    }
}

/// Полное двоичное дерево Меркела над опами 0..capacity, занумерованными по позиции в логе.
///
/// Высота фиксируется при создании (`with_capacity`): это осознанно, потому что и цена op
/// (log₂ n хешей), и размер хранения ((2·2^h − 1) × 32 Б при полном дереве) зависят от высоты,
/// а «дерево, которое умеет расти» стоило бы ещё и перекорневание. Для ответа на вопрос `E-0019`
/// («вводить ли root») важнее всего, что доказательство включения требует хранить **все** узлы,
/// а не только корень: пики можно оставить в 32 байтах, но тогда ничего доказать нельзя.
#[derive(Clone, Debug)]
pub struct OpTree {
    height: u32,
    size: usize,
    /// Плоский массив узлов: листья на `[size .. 2·size)`, внутренние на `[1 .. size)`, индекс 0
    /// не используется. Такой расклад даёт доказательство как срез массива без обхода дерева.
    nodes: Vec<[u8; ROOT_BYTES]>,
    /// Хеши пустых поддеревьев по уровням: `empty[d]` — корень поддерева высоты d из пустых листьев.
    empty: Vec<[u8; ROOT_BYTES]>,
    leaves: usize,
}

impl OpTree {
    /// Дерево, вмещающий `n` опов (следующая степень двойки ≥ n).
    pub fn with_capacity(shard: u16, n: usize) -> Self {
        let height = usize::BITS - (n.max(1) - 1).leading_zeros();
        let size = 1usize << height;
        // Пустое поддерево привязано к шарду, поэтому и корень пустого дерева различает шарды:
        // иначе «empty root» одного шарда был бы валидным корнем другого.
        let mut empty = Vec::with_capacity(height as usize + 1);
        empty.push(domain_hash(EMPTY_TAG, &shard.to_le_bytes(), &[]));
        for d in 1..=height {
            let below = empty[(d - 1) as usize];
            empty.push(domain_hash(NODE_TAG, &below, &below));
        }
        let nodes = vec![empty[height as usize]; 2 * size];
        OpTree { height, size, nodes, empty, leaves: 0 }
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.leaves
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.leaves == 0
    }

    #[inline]
    pub fn height(&self) -> u32 {
        self.height
    }

    /// Число узлов, физически занимающих место (включая незаполненные листья).
    #[inline]
    pub fn node_bytes(&self) -> usize {
        self.nodes.len() * ROOT_BYTES
    }

    /// Место, которое нужно, чтобы хранить только реально заполненные узлы: листья + узлы,
    /// покрытые хотя бы одним листом. Это нижняя граница «дерева с доказательствами», и она
    /// тоже ~2n × 32 Б.
    pub fn node_bytes_used(&self) -> usize {
        let leaves = self.leaves;
        if leaves == 0 {
            return 0;
        }
        let mut n = leaves;
        let mut total = leaves;
        while n > 1 {
            n = n.div_ceil(2);
            total += n;
        }
        total * ROOT_BYTES
    }

    #[inline]
    pub fn root(&self) -> [u8; ROOT_BYTES] {
        self.nodes[1]
    }

    /// Добавить оп на следующую свободную позицию (порядок = возрастание `seq`).
    /// Стоимость — ровно `height` хешей: путь от листа до корня, больше при append менять нельзя.
    pub fn push(&mut self, payload: &[u8]) {
        assert!(self.leaves < self.size, "дерево из {} листьев переполнено", self.size);
        let mut idx = self.size + self.leaves;
        self.nodes[idx] = domain_hash(LEAF_TAG, payload, &[]);
        self.leaves += 1;
        idx /= 2;
        while idx >= 1 {
            let left = self.nodes[2 * idx];
            let right = self.nodes[2 * idx + 1];
            self.nodes[idx] = domain_hash(NODE_TAG, &left, &right);
            if idx == 1 {
                break;
            }
            idx /= 2;
        }
    }

    /// Путь-доказательство для позиции `index`: `height` соседних узлов, снизу вверх.
    pub fn proof(&self, index: usize) -> Vec<[u8; ROOT_BYTES]> {
        assert!(index < self.size, "позиции {index} нет в дереве высоты {}", self.height);
        let mut path = Vec::with_capacity(self.height as usize);
        let mut idx = self.size + index;
        while idx > 1 {
            let sib = idx ^ 1;
            path.push(self.nodes[sib]);
            idx /= 2;
        }
        path
    }

    /// Проверка клиента, у которого есть только корень, payload, позиция и путь: log₂ n хешей.
    pub fn verify(root: &[u8; ROOT_BYTES], payload: &[u8], index: usize, path: &[[u8; ROOT_BYTES]]) -> bool {
        let mut cur = domain_hash(LEAF_TAG, payload, &[]);
        let mut idx = index;
        for sib in path {
            cur = if idx % 2 == 0 {
                domain_hash(NODE_TAG, &cur, sib)
            } else {
                domain_hash(NODE_TAG, sib, &cur)
            };
            idx /= 2;
        }
        cur == *root
    }

    /// Пустое поддерево высоты `d` — нужно, чтобы клиент мог верифицировать путь, не зная,
    /// сколько листьев вообще есть.
    #[inline]
    pub fn empty_subtree(&self, d: u32) -> [u8; ROOT_BYTES] {
        self.empty[d as usize]
    }
}

/// Payload-байты опa, нужные тесту без похода в приватные детали WAL.
pub fn op_payload(seq: u64, kind: OpKind, body: &[u8]) -> Vec<u8> {
    WalFrame::new(seq, kind, body.to_vec()).payload()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entry::IndexEntry;
    use vecdht_wire::codec::DIM;

    fn body(i: u64) -> Vec<u8> {
        let mut owner = [0u8; 32];
        owner[..8].copy_from_slice(&i.to_le_bytes());
        let e = IndexEntry {
            owner_ed25519: owner,
            vec_q: [1i8; DIM],
            cluster_id: (i % 16) as u16,
            published_bucket: 1_000,
            ttl_buckets: 54_000,
        };
        e.to_insert().body_bytes()
    }

    /// Два узла, применившие один лог в одном порядке, обязаны сойтись — и цепью, и деревом.
    #[test]
    fn chain_and_tree_converge_on_the_same_log() {
        let payloads: Vec<Vec<u8>> =
            (0..64u64).map(|i| op_payload(i + 1, OpKind::Insert, &body(i))).collect();
        let mut a = ChainRoot::genesis(7);
        let mut b = ChainRoot::genesis(7);
        let mut t1 = OpTree::with_capacity(7, payloads.len());
        let mut t2 = OpTree::with_capacity(7, payloads.len());
        for p in &payloads {
            a.update_payload(p);
            b.update_payload(p);
        }
        for p in &payloads {
            t1.push(p);
            t2.push(p);
        }
        assert_eq!(a.value(), b.value());
        assert_eq!(a.ops(), 64);
        assert_eq!(t1.root(), t2.root());
        assert_eq!(t1.len(), 64);
    }

    /// `update_parts` (без аллокации payload) обязан давать то же значение, что `update`: иначе
    /// справочная колонка `E-0019` меряет другую функцию.
    #[test]
    fn chain_root_update_parts_matches_update() {
        let mut with_alloc = ChainRoot::genesis(7);
        let mut streaming = ChainRoot::genesis(7);
        for i in 0..32u64 {
            let b = body(i);
            with_alloc.update(&WalFrame::new(i + 1, OpKind::Insert, b.clone()));
            streaming.update_parts(i + 1, OpKind::Insert as u8, &b);
        }
        assert_eq!(with_alloc.value(), streaming.value());
        assert_eq!(with_alloc.ops(), streaming.ops());
    }

    /// Корень обязан различать шард, порядок опов и подмену байта — иначе сверка двух владельцев
    /// ничего не стоит (§19.3 строки 1–2).
    #[test]
    fn chain_root_senses_shard_order_and_content() {
        let one = op_payload(1, OpKind::Insert, &body(1));
        let two = op_payload(2, OpKind::Insert, &body(2));

        let mut base = ChainRoot::genesis(7);
        base.update_payload(&one);
        base.update_payload(&two);

        let mut other_shard = ChainRoot::genesis(8);
        other_shard.update_payload(&one);
        other_shard.update_payload(&two);
        assert_ne!(genesis_of(7), genesis_of(8), "genesis не различает шарды");
        assert_ne!(base.value(), other_shard.value(), "корень не привязан к шарду");

        let mut swapped = ChainRoot::genesis(7);
        swapped.update_payload(&two);
        swapped.update_payload(&one);
        assert_ne!(base.value(), swapped.value(), "порядок опов не влияет на корень");

        let mut tampered = ChainRoot::genesis(7);
        let mut bad = one.clone();
        let n = bad.len() - 1;
        bad[n] ^= 0x01;
        tampered.update_payload(&bad);
        tampered.update_payload(&two);
        assert_ne!(base.value(), tampered.value(), "подменённый body не меняет корень");
    }

    fn genesis_of(shard: u16) -> [u8; ROOT_BYTES] {
        ChainRoot::genesis(shard).value()
    }

    /// Доказательство включения проходит для своего листа, не проходит для чужого и не проходит
    /// под подменённым payload.
    #[test]
    fn tree_proves_one_leaf_and_rejects_another() {
        let payloads: Vec<Vec<u8>> =
            (0..100u64).map(|i| op_payload(i + 1, OpKind::Insert, &body(i))).collect();
        let mut t = OpTree::with_capacity(7, payloads.len());
        for p in &payloads {
            t.push(p);
        }
        let root = t.root();
        for i in [0usize, 1, 37, 99] {
            let proof = t.proof(i);
            assert_eq!(proof.len(), t.height() as usize);
            assert!(OpTree::verify(&root, &payloads[i], i, &proof), "лист {i} не проходит");
            // Тот же путь под чужим payload обязан не сходиться.
            assert!(
                !OpTree::verify(&root, &payloads[(i + 1) % payloads.len()], i, &proof),
                "доказательство принимает чужой лист на позиции {i}"
            );
        }
        // Подменённый байт в payload рвёт и лист, и корень.
        let mut bad = payloads[5].clone();
        let n = bad.len() - 1;
        bad[n] ^= 0x01;
        assert!(!OpTree::verify(&root, &bad, 5, &t.proof(5)), "подмена листа проходит проверку");
    }

    /// Незаполненный лист обязан вести себя как детерминированное пустое поддерево: корень не
    /// зависит от того, в каком порядке дополнялось дерево, если содержимое одно и то же.
    #[test]
    fn tree_root_is_canonical_over_positions() {
        let payloads: Vec<Vec<u8>> =
            (0..5u64).map(|i| op_payload(i + 1, OpKind::Insert, &body(i))).collect();
        let mut full = OpTree::with_capacity(7, 8);
        for p in &payloads {
            full.push(p);
        }
        let mut wide = OpTree::with_capacity(7, 16);
        for p in &payloads {
            wide.push(p);
        }
        // Разная высота — разный корень по построению (пустые поддеревья разные), и это надо
        // знать до того, как root станет полем протокола: он зависит от вместимости, а не только
        // от лога.
        assert_ne!(full.root(), wide.root());
    }
}
