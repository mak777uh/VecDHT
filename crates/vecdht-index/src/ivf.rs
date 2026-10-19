//! IVF-индекс одного шарда: арена int8-записей + inverted lists + дедупликация (§8.2–§8.4).
//!
//! Инварианты, которые держит этот модуль:
//!
//! * `slot` живой записи не меняется никогда: ни при перепубликации того же `(owner, shard)`
//!   (замена на месте), ни при тряске снапшота (§8.3) — поэтому `entry_key`, в котором `slot`
//!   участвует, не «переезжает» под ногами у держателя `MatchResult`;
//! * мёртвый `slot` переиспользуется детерминированно: alloc берёт **наименьший** мёртвый slot,
//!   а если мёртвых нет — продолжает арену (§8.3, recycling; см. «Почему без этого гейт P5
//!   недостижим» ниже). Живые при этом не переносятся, поэтому первый инвариант не нарушается;
//! * `lists[c]` отсортирован по возрастанию `slot` — из этого следует побайтовая идентичность
//!   снапшота двух реплик на одном потоке опсов (§19.1);
//! * путь применения опсов не читает часы: экспирация считается только от `TimeMark`/`GcTick`
//!   (§9.6), поэтому узлы с часами ±40 мин дают один и тот же файл;
//! * `search` возвращает `(l2_sq, slot)` и сортирует строго по контракту §8.4.
//!
//! Почему без этого гейт P5 недостижим. §11.3.3 разрешает переполнение шарда вытеснением, а
//! арена растёт монотонным `next_slot`. Их сочетание — это не «дороже», а вектор атаки: вытесненная
//! запись оставляет tombstone на 424 Б, который не снимает даже снапшот (формат файла хранит
//! slot'ы, §10.4). Атакующий на 100 admits/с (§11.3.4) раздувал бы арену на 42 КБ/с — 3,7 ГБ
//! сутки на шард, и «память узла плоская» (§18.6) было бы невыполнимо даже после того, как спам
//! истечёт по TTL. Переиспользование мёртвого slot'а стоит одно поле (`min_dead`) и делает память
//! плоской: арена ограничена пиком живых записей, а не суммой живых и вытесненных.
//!
//! Чисел с плавающей точкой в путях индекса нет; `f64` встречается только в диагностике
//! бюджета памяти.

use vecdht_crypto::quant::l2_sq;
use vecdht_wire::constants::{shard_of, NLIST};
use vecdht_wire::messages::Match;
use vecdht_wire::DIM;

use crate::entry::IndexEntry;
use crate::owner_table::OwnerTable;

/// Шаг роста арены. `Vec::push` удваивал бы ёмкость: при 1M записей лишняя ёмкость — до
/// 404 МБ, и бюджет §8.2 не сходится. `reserve_exact` блоком стоит ≤ 4096·424 Б ≈ 1.7 МБ.
pub const ARENA_BLOCK: usize = 4096;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum IndexError {
    #[error("кластер {cluster} относится к шарду {want}, а индекс — шарду {shard} (§7.4)")]
    ShardMismatch { cluster: u16, shard: u16, want: u16 },
    #[error("кластер {0} вне NLIST=1024")]
    ClusterOutOfRange(u16),
    #[error("арена переполнена: {0} записей, предел u32::MAX")]
    ArenaFull(usize),
    #[error("slot {0} уже занят живой записью")]
    SlotAlreadyLive(u32),
}

/// Результат вставки: «замена на месте» отличается от новой записи только флагом, slot один.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InsertOutcome {
    pub slot: u32,
    pub replaced: bool,
}

/// Разбивка по строкам таблицы §8.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MemBytes {
    pub arena: usize,
    pub lists: usize,
    pub owners: usize,
    pub bitmap: usize,
}

impl MemBytes {
    pub fn total(&self) -> usize {
        self.arena + self.lists + self.owners + self.bitmap
    }

    /// Байт на живую запись — против ≈449 Б из §8.2. Диагностика бюджета, не путь поиска.
    pub fn per_entry(&self, live: usize) -> f64 {
        if live == 0 {
            0.0
        } else {
            self.total() as f64 / live as f64
        }
    }
}

#[derive(Debug)]
pub struct IvfIndex {
    pub shard: u16,
    /// Арена: `entries[slot]`. Мёртвые slot'ы остаются в массиве (§8.3).
    pub entries: Vec<IndexEntry>,
    /// Inverted lists по кластерам глобального квантизатора; внутри — slot'ы по возрастанию.
    pub lists: Vec<Vec<u32>>,
    /// Bitmap живых slot'ов, по биту на запись.
    pub live_words: Vec<u64>,
    pub owners: OwnerTable,
    pub live: usize,
    pub tombstones: usize,
    /// Наименьший мёртвый slot ниже `next_slot`, если такой есть. Это не отдельное состояние, а
    /// функция bitmap: `mark_dead` умеет только понижать его, `alloc` поднимает сканом вперёд,
    /// загрузка снапшота пересчитывает значение заново. Поэтому primary и реплика, применившие
    /// один и тот же поток опсов, обязаны сойтись на одном значении — и на выданном slot'е.
    min_dead: Option<u32>,
}

impl IvfIndex {
    pub fn new(shard: u16) -> Self {
        Self::with_capacity(shard, ARENA_BLOCK)
    }

    /// Индекс, заранее рассчитанный на `n` записей.
    ///
    /// Нужен для теста бюджета §19.1: рост шагом `ARENA_BLOCK` копирует всю арену на каждом
    /// блоке, и 1M вставок дают Θ(n²/блок) ≈ 48 ГБ memcpy — мерить после этого байты на запись
    /// бессмысленно. Здесь ёмкость задаётся один раз, а после `n` запись всё равно растёт
    /// блоками, так что ограничение на память не превращается в ограничение на `slot`.
    pub fn with_capacity(shard: u16, n: usize) -> Self {
        let n = n.max(ARENA_BLOCK);
        IvfIndex {
            shard,
            entries: Vec::with_capacity(n),
            lists: vec![Vec::new(); NLIST as usize],
            live_words: Vec::with_capacity(n.div_ceil(64)),
            owners: OwnerTable::with_capacity(n),
            live: 0,
            tombstones: 0,
            min_dead: None,
        }
    }

    // --- bitmap -------------------------------------------------------------

    #[inline]
    fn bit_pos(slot: u32) -> (usize, u32) {
        ((slot >> 6) as usize, slot & 63)
    }

    #[inline]
    pub fn is_live(&self, slot: u32) -> bool {
        let (w, b) = Self::bit_pos(slot);
        self.live_words.get(w).map(|v| (v >> b) & 1 == 1).unwrap_or(false)
    }

    fn set_live(&mut self, slot: u32) {
        let (w, b) = Self::bit_pos(slot);
        while self.live_words.len() <= w {
            self.live_words.push(0);
        }
        self.live_words[w] |= 1u64 << b;
    }

    fn clear_live(&mut self, slot: u32) {
        let (w, b) = Self::bit_pos(slot);
        if let Some(word) = self.live_words.get_mut(w) {
            *word &= !(1u64 << b);
        }
    }

    // --- доступ -------------------------------------------------------------

    /// Живая запись по slot'у. Дыра и выход за арену ⇒ `None` (код ответа `NO_SUCH_SLOT`, §5.3).
    #[inline]
    pub fn entry(&self, slot: u32) -> Option<IndexEntry> {
        if self.is_live(slot) {
            self.entries.get(slot as usize).copied()
        } else {
            None
        }
    }

    #[inline]
    pub fn owner_slot(&self, owner: &[u8; 32]) -> Option<u32> {
        let entries = &self.entries;
        self.owners.get(owner, |s| entries.get(s as usize).map(|e| e.owner_ed25519))
    }

    #[inline]
    pub fn next_slot(&self) -> u32 {
        self.entries.len() as u32
    }

    /// Все живые записи по возрастанию slot'а — тот порядок, из которого стримится снапшот.
    pub fn live_slots(&self) -> impl Iterator<Item = (u32, IndexEntry)> + '_ {
        self.entries
            .iter()
            .enumerate()
            .filter(move |(i, _)| self.is_live(*i as u32))
            .map(|(i, e)| (i as u32, *e))
    }

    // --- мутации ------------------------------------------------------------

    /// Слот для **новой** записи (не перепубликации): наименьший мёртвый, а если дыр нет —
    /// продолжение арены. После вызова `entries[slot]` существует и не жив.
    ///
    /// Порядок «наименьший, а не любой» выбран не для локальности: он обязан быть выводим из
    /// состояния индекса, чтобы primary и реплика выдали один и тот же slot одному и тому же
    /// опсу. Любой список-буфер дыр для этого не подошёл бы — его пришлось бы персистить и
    /// согласовывать, а он вычитается из bitmap за одну строку.
    fn alloc_slot(&mut self) -> Result<u32, IndexError> {
        if let Some(slot) = self.min_dead {
            if slot < self.next_slot() {
                debug_assert!(!self.is_live(slot), "min_dead указал на живой slot {slot}");
                // Забираем дыру: следующий кандидат ищётся сканом вперёд, `min_dead` при этом
                // остаётся корректной нижней границей.
                self.min_dead = self.next_dead_from(slot + 1);
                self.tombstones = self.tombstones.saturating_sub(1);
                return Ok(slot);
            }
            // Дыра за хвостом невозможна по построению; эта ветка — страховка на случай, если
            // арену подрезали (`truncate_holes`), а подсказка осталась за новым концом.
            self.min_dead = None;
        }
        let len = self.entries.len();
        let slot = u32::try_from(len).map_err(|_| IndexError::ArenaFull(len))?;
        if len == self.entries.capacity() {
            self.entries.reserve_exact(ARENA_BLOCK);
        }
        self.entries.push(IndexEntry::default());
        Ok(slot)
    }

    /// Наименьший мёртвый slot, начиная с `from`, в пределах арены.
    ///
    /// Слово bitmap целиком живое ⇒ переход на 64 slot'а за одну итерацию: полный скан 2M
    /// slot'ов стоит 31 250 проверок слова, а не 2 000 000 проверок бита, и именно поэтому
    /// подсказку можно сбрасывать и пересчитывать без страха за бюджет (§11.3.4 — 100 admits/с).
    fn next_dead_from(&self, from: u32) -> Option<u32> {
        let limit = self.next_slot();
        let mut s = from;
        while s < limit {
            let (w, b) = Self::bit_pos(s);
            let word = self.live_words.get(w).copied().unwrap_or(0);
            if word == u64::MAX {
                s = (w as u32 + 1) * 64;
                continue;
            }
            for bit in b..64 {
                if s >= limit {
                    return None;
                }
                if word >> bit & 1 == 0 {
                    return Some(s);
                }
                s += 1;
            }
        }
        None
    }

    /// Пересчитать подсказку с нуля: нужно после загрузки снапшота, где `load_entry` заполняет
    /// живые slot'ы, а дыры между ними остаются от `resize`. Идемпотентно и дорого ровно один
    /// раз на открытие узла.
    pub fn recompute_min_dead(&mut self) {
        self.min_dead = self.next_dead_from(0);
    }

    /// Конец арены без хвоста из мёртвых slot'ов: `max(live) + 1`, или 0, если живых нет.
    ///
    /// Подрезка не меняет поведение аллокатора. Если живые занимают `0..=k`, а выше только
    /// дыры, то «наименьшая дыра» у подрезанной и неподрезанной копий одна и та же: дыры ниже
    /// `k` либо есть (тогда они и выбираются, `k+1` до них не доходит), либо их нет — и тогда
    /// `0..=k` целиком живые, а следующая дыра в обеих копиях ровно `k + 1`. Значит снапшот,
    /// из которого убрали хвост, и индекс, который его не резал, выдают одинаковые slot'ы на
    /// одинаковом потоке опсов — а это и есть требование §10.5 («recover == replay»).
    pub fn trimmed_next_slot(&self) -> u32 {
        // Старший живой бит сверху вниз: нулевое слово стоит одной итерации, а не 64.
        let mut w = self.live_words.len();
        while w > 0 {
            let word = self.live_words[w - 1];
            if word != 0 {
                return (w as u32 - 1) * 64 + (64 - word.leading_zeros());
            }
            w -= 1;
        }
        0
    }

    /// Убрать хвост из мёртвых slot'ов: память, которую снапшот уже не описывает (§10.4).
    /// Вызывать сразу после записи снапшота, когда `trimmed_next_slot()` — это и есть записанный
    /// `next_slot`.
    pub fn truncate_holes(&mut self) {
        self.entries.truncate(self.trimmed_next_slot() as usize);
        // Слова bitmap оставляем длиннее: биты выше хвоста нулевые, и `is_live` за пределами
        // арены отвечает «мёртв», как и обязана.
        self.recompute_min_dead();
    }

    /// Вставить запись. Дедупликация: перепубликация того же `(owner, shard)` заменяет на месте
    /// в том же slot'е (§8.3, тест §19.1 «живых записей одна»).
    pub fn insert(&mut self, e: IndexEntry) -> Result<InsertOutcome, IndexError> {
        if e.cluster_id >= NLIST {
            return Err(IndexError::ClusterOutOfRange(e.cluster_id));
        }
        let want = shard_of(e.cluster_id);
        if want != self.shard {
            return Err(IndexError::ShardMismatch { cluster: e.cluster_id, shard: self.shard, want });
        }
        if let Some(slot) = self.owner_slot(&e.owner_ed25519) {
            let old = self.entries[slot as usize];
            if old.cluster_id != e.cluster_id {
                // Меняется только состав списков: slot остаётся прежним.
                self.list_remove(old.cluster_id, slot);
                self.list_insert(e.cluster_id, slot);
            }
            self.entries[slot as usize] = e;
            return Ok(InsertOutcome { slot, replaced: true });
        }
        let slot = self.alloc_slot()?;
        self.entries[slot as usize] = e;
        self.set_live(slot);
        self.live += 1;
        // Slot'ы из дыр обязаны вставиться в список по порядку; «новый slot всегда максимальный»
        // больше не инвариант, поэтому здесь `list_insert`, а не `push`.
        self.list_insert(e.cluster_id, slot);
        let entries = &self.entries;
        self.owners.put(&e.owner_ed25519, slot, |s| {
            entries.get(s as usize).map(|x| x.owner_ed25519)
        });
        Ok(InsertOutcome { slot, replaced: false })
    }

    /// Удаление по владельцу (§5.3 `Delete`): tombstone + выписка из списка и таблицы.
    pub fn remove_owner(&mut self, owner: &[u8; 32]) -> Option<u32> {
        let slot = self.owner_slot(owner)?;
        self.mark_dead(slot);
        Some(slot)
    }

    /// Пометить slot мёртвым. Запись остаётся в арене и ждёт переиспольования: `slot` живой
    /// записи при этом не меняется (§8.3), а `CompactOp` с перенумерацией в v8 по-прежнему нет.
    pub fn mark_dead(&mut self, slot: u32) -> bool {
        if !self.is_live(slot) {
            return false;
        }
        let e = self.entries[slot as usize];
        self.clear_live(slot);
        self.list_remove(e.cluster_id, slot);
        let owner = e.owner_ed25519;
        let entries = &self.entries;
        self.owners.remove(&owner, |s| entries.get(s as usize).map(|x| x.owner_ed25519));
        self.live -= 1;
        self.tombstones += 1;
        // Единственное место, где дыра появляется: подсказка обязана её заметить, иначе
        // `alloc_slot` пропустит наименьшую дыру и выдал бы не тот slot, что другой узел.
        self.min_dead = Some(match self.min_dead {
            Some(m) => m.min(slot),
            None => slot,
        });
        true
    }

    /// GC по бакету (§9.6): снимает всё, где `published + ttl ≤ now_bucket`.
    /// Обход по возрастанию slot'а ⇒ состав удалённого не зависит от часов узла.
    pub fn expire(&mut self, now_bucket: u32) -> Vec<u32> {
        let dead: Vec<u32> = (0..self.next_slot())
            .filter(|s| self.is_live(*s) && self.entries[*s as usize].is_expired(now_bucket))
            .collect();
        for &s in &dead {
            self.mark_dead(s);
        }
        dead
    }

    /// Восстановление одной записи из снапшота (§10.4, читатель шага 2). Вызывающий обязан идти
    /// по возрастанию slot'а — тогда списки остаются отсортированными без вставки в середину, и
    /// файл, прочитанный дважды, даёт идентичное состояние (§19.1).
    pub fn load_entry(&mut self, slot: u32, e: IndexEntry) -> Result<(), IndexError> {
        if e.cluster_id >= NLIST {
            return Err(IndexError::ClusterOutOfRange(e.cluster_id));
        }
        let want = shard_of(e.cluster_id);
        if want != self.shard {
            return Err(IndexError::ShardMismatch { cluster: e.cluster_id, shard: self.shard, want });
        }
        if self.is_live(slot) {
            return Err(IndexError::SlotAlreadyLive(slot));
        }
        let need = slot as usize + 1;
        if self.entries.len() < need {
            let need_u32 = u32::try_from(need).map_err(|_| IndexError::ArenaFull(need))?;
            debug_assert!(need_u32 as usize == need);
            self.entries.resize(need, IndexEntry::default());
        }
        self.entries[slot as usize] = e;
        self.set_live(slot);
        self.live += 1;
        self.lists[e.cluster_id as usize].push(slot);
        let entries = &self.entries;
        self.owners.put(&e.owner_ed25519, slot, |s| {
            entries.get(s as usize).map(|x| x.owner_ed25519)
        });
        Ok(())
    }

    /// Compaction без перенумерации (§8.3, §9.6): файл снапшота содержит только живые записи,
    /// поэтому «утряска» — это `flush_snapshot`, а не перестройка арены. `slot` и `entry_key`
    /// при этом не меняются (тест §19.1), а дыры стоят 424 Б на удалённую запись — цену,
    /// которую спека принимает сознательно ради воспроизводимости реплик.
    #[inline]
    pub fn tombstones(&self) -> usize {
        self.tombstones
    }

    // --- списки -------------------------------------------------------------

    fn list_insert(&mut self, cluster: u16, slot: u32) {
        let list = &mut self.lists[cluster as usize];
        let i = list.partition_point(|&s| s < slot);
        debug_assert!(i >= list.len() || list[i] != slot, "slot {slot} уже в списке {cluster}");
        list.insert(i, slot);
    }

    fn list_remove(&mut self, cluster: u16, slot: u32) -> bool {
        let list = &mut self.lists[cluster as usize];
        let i = list.partition_point(|&s| s <= slot);
        if i > 0 && list[i - 1] == slot {
            list.remove(i - 1);
            return true;
        }
        false
    }

    #[inline]
    pub fn cluster_len(&self, cluster: u16) -> usize {
        self.lists.get(cluster as usize).map(Vec::len).unwrap_or(0)
    }

    #[inline]
    pub fn cluster_slots(&self, cluster: u16) -> &[u32] {
        self.lists.get(cluster as usize).map(Vec::as_slice).unwrap_or(&[])
    }

    // --- поиск --------------------------------------------------------------

    /// Контракт §8.4: `(l2_sq ASC, slot ASC)`, только целые числа; `now_bucket` — последний
    /// применённый `TimeMark`, не локальное время.
    ///
    /// Реализация — потоковый отбор, а не «собрать всех и отсортировать»: держим ровно `top_k`
    /// пар, буфер живёт на куче размером `8·top_k` байт вместо 64 КиБ на запрос. Порядок
    /// совпадает с полным сортировкой по тому же компаратору, поэтому canonical-байты
    /// `MatchResult` идентичны на всех узлах (§19.1).
    pub fn search(
        &self,
        q: &[i8; DIM],
        clusters: &[u16],
        top_k: usize,
        now_bucket: u32,
    ) -> Vec<(u32, u32)> {
        if top_k == 0 {
            return Vec::new();
        }
        let mut best: Vec<(u32, u32)> = Vec::with_capacity(top_k);
        for &c in clusters {
            let Some(list) = self.lists.get(c as usize) else { continue };
            for &slot in list {
                let e = &self.entries[slot as usize];
                // Запись могла пережить дедлайн, но ещё не быть снята GcTick'ом.
                if e.is_expired(now_bucket) {
                    continue;
                }
                let hit = (l2_sq(q, &e.vec_q), slot);
                // Худший из удержанных — последний: буфер всегда отсортирован по компаратору §8.4.
                if best.len() == top_k && hit >= best[top_k - 1] {
                    continue;
                }
                let pos = best.partition_point(|&h| h < hit);
                best.insert(pos, hit);
                best.truncate(top_k);
            }
        }
        best
    }

    /// Те же хиты в wire-представлении: `MatchResult` подписывается именно по ним (§8.4).
    pub fn matches(&self, hits: &[(u32, u32)]) -> Vec<Match> {
        hits.iter()
            .filter_map(|(d2, slot)| {
                let e = self.entry(*slot)?;
                Some(Match {
                    owner_ed25519: e.owner_ed25519,
                    cluster_id: e.cluster_id,
                    d2: *d2,
                    slot: *slot,
                })
            })
            .collect()
    }

    // --- память -------------------------------------------------------------

    /// Байты по строкам таблицы §8.2 — вход для теста «1M записей ≤ 428 МБ ±5%» (§19.1).
    pub fn mem_bytes(&self) -> MemBytes {
        let arena = self.entries.capacity() * core::mem::size_of::<IndexEntry>();
        let lists = self
            .lists
            .iter()
            .map(|l| l.capacity() * core::mem::size_of::<u32>())
            .sum::<usize>()
            + self.lists.capacity() * core::mem::size_of::<Vec<u32>>();
        MemBytes {
            arena,
            lists,
            owners: self.owners.bytes(),
            bitmap: self.live_words.capacity() * core::mem::size_of::<u64>(),
        }
    }

    /// Проверка внутренних инвариантов: нужна, чтобы `recover(disk) == replay(all ops)` (§10.5)
    /// сравнивал *состояние*, а не только байты файла.
    pub fn check_invariants(&self) -> Result<(), String> {
        for (c, list) in self.lists.iter().enumerate() {
            for w in list.windows(2) {
                if w[0] >= w[1] {
                    return Err(format!("список {c} не отсортирован по slot: {w:?}"));
                }
            }
            for &slot in list {
                if !self.is_live(slot) {
                    return Err(format!("мёртвый slot {slot} в списке {c}"));
                }
                if self.entries[slot as usize].cluster_id as usize != c {
                    return Err(format!("slot {slot} лежит в списке {c} не своего кластера"));
                }
            }
        }
        let mut counted = 0usize;
        for s in 0..self.next_slot() {
            if self.is_live(s) {
                counted += 1;
                let owner = self.entries[s as usize].owner_ed25519;
                if self.owner_slot(&owner) != Some(s) {
                    return Err(format!("dedup потерял slot {s}"));
                }
            }
        }
        if counted != self.live {
            return Err(format!("поле live={} насчитали {counted}", self.live));
        }
        if self.owners.len() != self.live {
            return Err(format!("в таблице {} записей против {} живых", self.owners.len(), self.live));
        }
        // Подсказка аллокатора обязана быть exactly наименьшей дырой, а не «примерно где-то
        // снизу»: на ней держится совпадение slot'ов между primary и репликой. Проверка полная
        // и дорогая — но `check_invariants` вызывается из тестов, а не из пути применения.
        let truth = (0..self.next_slot()).find(|s| !self.is_live(*s));
        if self.min_dead != truth {
            return Err(format!("min_dead={:?}, наименьшая дыра {:?}", self.min_dead, truth));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vecdht_wire::constants::CLUSTERS_PER_SHARD;

    fn entry(owner: u8, cluster: u16, published: u32, ttl: u16) -> IndexEntry {
        IndexEntry {
            owner_ed25519: [owner; 32],
            vec_q: [(owner as i8).wrapping_mul(3); DIM],
            cluster_id: cluster,
            published_bucket: published,
            ttl_buckets: ttl,
        }
    }

    fn idx() -> IvfIndex {
        IvfIndex::new(0)
    }

    /// Разный owner для пары «владелец, кластер» — чтобы тест бюджета мерил живые записи, а не
    /// перепубликации одного и того же ключа дедупликации.
    fn owner_of(owner: u8, cluster: u16) -> [u8; 32] {
        let mut o = [owner; 32];
        o[1] = cluster as u8;
        o[2] = (cluster >> 8) as u8;
        o
    }

    #[test]
    fn live_slots_never_move_but_dead_ones_are_reused_from_the_bottom() {
        let mut ix = idx();
        let a = ix.insert(entry(1, 3, 0, 100)).unwrap().slot;
        let b = ix.insert(entry(2, 4, 0, 100)).unwrap().slot;
        let c = ix.insert(entry(3, 5, 0, 100)).unwrap().slot;
        assert_eq!((a, b, c), (0, 1, 2));
        ix.mark_dead(b);
        let d = ix.insert(entry(4, 3, 0, 100)).unwrap().slot;
        assert_eq!(d, 1, "дыра переиспользуется раньше, чем арена растёт (§8.3, память плоская)");
        assert_eq!(ix.next_slot(), 3, "подрезанный хвост не вырос новой дырой");
        assert_eq!(ix.entry(a).unwrap().owner_ed25519, [1u8; 32]);
        assert_eq!(ix.entry(c).unwrap().owner_ed25519, [3u8; 32]);
        // Бывший владелец дыры ушёл, а живой slot'ы остались на своих местах: ровно то, что
        // запрещает любой `CompactOp` с перенумерацией (§8.3).
        assert_eq!(ix.owner_slot(&[2u8; 32]), None);
        ix.check_invariants().unwrap();
        // Дыра кончилась ⇒ аллокатор возвращается к хвосту.
        let e = ix.insert(entry(5, 3, 0, 100)).unwrap().slot;
        assert_eq!(e, 3);
        ix.check_invariants().unwrap();
    }

    #[test]
    fn trimming_the_tail_does_not_change_future_slot_numbers() {
        // Тот поток опсов на подрезанной и неподрезанной арене обязан дать одинаковые slot'ы:
        // иначе «recover(disk) == replay(all ops)» (§10.5) зависит от момента снапшота.
        let mut keep = idx();
        let mut cut = idx();
        for ix in [&mut keep, &mut cut] {
            for o in 1..6u8 {
                ix.insert(entry(o, o as u16 % 4, 0, 100)).unwrap();
            }
        }
        // В обеих снимаем 4 и 5 (верхние) — дыры в хвосте.
        for ix in [&mut keep, &mut cut] {
            ix.mark_dead(3);
            ix.mark_dead(4);
        }
        cut.truncate_holes();
        assert_eq!(keep.next_slot(), 5);
        assert_eq!(cut.next_slot(), 3, "хвост из двух дыр убран");
        for ix in [&mut keep, &mut cut] {
            ix.insert(entry(9, 1, 0, 100)).unwrap();
            ix.insert(entry(10, 2, 0, 100)).unwrap();
        }
        assert_eq!(
            keep.live_slots().map(|(s, e)| (s, e.owner_ed25519)).collect::<Vec<_>>(),
            cut.live_slots().map(|(s, e)| (s, e.owner_ed25519)).collect::<Vec<_>>()
        );
        keep.check_invariants().unwrap();
        cut.check_invariants().unwrap();
    }

    #[test]
    fn republish_replaces_in_place() {
        let mut ix = idx();
        let first = ix.insert(entry(9, 1, 10, 100)).unwrap();
        assert!(!first.replaced);
        let again = ix.insert(entry(9, 1, 20, 100)).unwrap();
        assert!(again.replaced, "перепубликация того же owner — замена");
        assert_eq!(again.slot, first.slot, "замена обязана быть на месте");
        assert_eq!(ix.live, 1);
        assert_eq!(ix.cluster_len(1), 1, "дублей в списке нет");
        assert_eq!(ix.entry(first.slot).unwrap().published_bucket, 20);
        ix.check_invariants().unwrap();
    }

    #[test]
    fn republish_into_another_cluster_moves_list_membership_only() {
        let mut ix = idx();
        let s = ix.insert(entry(9, 0, 10, 100)).unwrap().slot;
        let r = ix.insert(entry(9, 2, 11, 100)).unwrap();
        assert_eq!(r.slot, s);
        assert_eq!(ix.cluster_len(0), 0);
        assert_eq!(ix.cluster_len(2), 1);
        assert_eq!(ix.entry(s).unwrap().cluster_id, 2);
        ix.check_invariants().unwrap();
    }

    #[test]
    fn lists_stay_sorted_under_interleaved_lifecycle() {
        let mut ix = idx();
        let mut slots = Vec::new();
        for o in 0..40u8 {
            slots.push(ix.insert(entry(o, 0, 0, 1000)).unwrap().slot);
        }
        for &s in &slots[10..30] {
            ix.mark_dead(s);
        }
        for o in 40..60u8 {
            ix.insert(entry(o, 0, 0, 1000)).unwrap();
        }
        let list = ix.cluster_slots(0);
        assert!(list.windows(2).all(|w| w[0] < w[1]), "{list:?}");
        assert_eq!(list.len(), ix.live);
        ix.check_invariants().unwrap();
    }

    #[test]
    fn expire_uses_only_the_bucket() {
        let mut ix = idx();
        let a = ix.insert(entry(1, 0, 100, 10)).unwrap().slot;
        let b = ix.insert(entry(2, 0, 100, 11)).unwrap().slot;
        assert_eq!(ix.expire(109), vec![]);
        assert_eq!(ix.expire(110), vec![a], "expire ⇔ published+ttl ≤ bucket (§9.6)");
        assert_eq!(ix.expire(111), vec![b]);
        assert_eq!(ix.live, 0);
        assert_eq!(ix.tombstones(), 2);
    }

    #[test]
    fn search_contract_is_d2_then_slot() {
        let mut ix = idx();
        // Три записи с одинаковым vec_q ⇒ одинаковый l2_sq ⇒ порядок задаёт slot.
        for o in 0..3u8 {
            let mut e = entry(o, 0, 0, 1000);
            e.vec_q = [5i8; DIM];
            ix.insert(e).unwrap();
        }
        let hits = ix.search(&[0i8; DIM], &[0], 10, 0);
        assert_eq!(hits.iter().map(|h| h.1).collect::<Vec<u32>>(), vec![0, 1, 2]);
        assert!(hits.iter().all(|h| h.0 == hits[0].0));
        assert_eq!(hits, ix.search(&[0i8; DIM], &[0], 10, 0), "контракт детерминирован");
    }

    #[test]
    fn search_orders_by_distance_then_slot() {
        let mut ix = idx();
        for (o, v) in [(1u8, 3i8), (2, 1), (3, 2)] {
            let mut e = entry(o, 0, 0, 1000);
            e.vec_q = [v; DIM];
            ix.insert(e).unwrap();
        }
        let hits = ix.search(&[0i8; DIM], &[0], 10, 0);
        assert_eq!(hits.iter().map(|h| (h.0, h.1)).collect::<Vec<(u32, u32)>>(), {
            // `vec_q = v·1` ⇒ l2_sq = 384·v². Slot'ы 0,1,2 в порядке вставки: v=3 → slot 0,
            // v=1 → slot 1, v=2 → slot 2. Порядок выдачи — по расстоянию, а не по slot'у.
            vec![(384, 1), (1536, 2), (3456, 0)]
        });
    }

    #[test]
    fn search_skips_expired_without_a_gc_tick() {
        let mut ix = idx();
        let live = ix.insert(entry(1, 0, 0, 100)).unwrap().slot;
        let dead = ix.insert(entry(2, 0, 0, 10)).unwrap().slot;
        let hits = ix.search(&[0i8; DIM], &[0], 10, 50);
        assert_eq!(hits.iter().map(|h| h.1).collect::<Vec<u32>>(), vec![live]);
        assert!(!hits.iter().any(|h| h.1 == dead));
        assert_eq!(ix.live, 2, "поиск не обязан чистить индекс");
    }

    #[test]
    fn search_top_k_and_unknown_clusters() {
        let mut ix = idx();
        for o in 0..10u8 {
            ix.insert(entry(o, 0, 0, 1000)).unwrap();
        }
        assert_eq!(ix.search(&[0i8; DIM], &[0], 4, 0).len(), 4);
        assert_eq!(ix.search(&[0i8; DIM], &[NLIST - 1], 4, 0).len(), 0);
        assert_eq!(ix.search(&[0i8; DIM], &[9999], 4, 0).len(), 0, "чужой кластер — не паника");
        assert_eq!(ix.search(&[0i8; DIM], &[], 4, 0).len(), 0);
        assert_eq!(ix.search(&[0i8; DIM], &[0], 0, 0).len(), 0);
    }

    #[test]
    fn foreign_cluster_is_refused() {
        let mut ix = IvfIndex::new(1);
        let mut e = entry(1, 0, 0, 100);
        e.cluster_id = 0;
        assert_eq!(ix.insert(e), Err(IndexError::ShardMismatch { cluster: 0, shard: 1, want: 0 }));
        e.cluster_id = CLUSTERS_PER_SHARD;
        assert!(ix.insert(e).is_ok());
        e.cluster_id = NLIST;
        assert_eq!(ix.insert(e), Err(IndexError::ClusterOutOfRange(NLIST)));
    }

    #[test]
    fn mem_budget_matches_the_spec_table() {
        // §8.2: 424 + 4 + ~20 + 1 ≈ 449 Б/запись. Стартовые ёмкости (4096 арены, 1024 корзин
        // таблицы, 1024 Vec'а списков) при 4080 записях ещё заметны — поэтому верхняя граница
        // 470, а точный бюджет на 1M меряется в tests/memory_budget.rs.
        let mut ix = idx();
        for o in 0..255u8 {
            for c in 0..CLUSTERS_PER_SHARD {
                // Владелец обязан быть разным: дедупликация идёт по `owner`, и 16 перепубликаций
                // одного владельца дали бы одну живую запись, а не шестнадцать (§8.3).
                let mut e = entry(o, c, 0, 1000);
                e.owner_ed25519 = owner_of(o, c);
                ix.insert(e).unwrap();
            }
        }
        let m = ix.mem_bytes();
        let per = m.per_entry(ix.live);
        assert_eq!(ix.live, 255 * CLUSTERS_PER_SHARD as usize);
        assert!(per < 470.0, "{m:?} по {per:.1} Б/запись на {} живых", ix.live);
        assert!(m.lists > 0 && m.owners > 0 && m.bitmap > 0, "{m:?}");
    }

    #[test]
    fn matches_carry_owner_and_cluster() {
        let mut ix = idx();
        let mut e = entry(11, 0, 3, 1000);
        e.vec_q = [1i8; DIM];
        ix.insert(e).unwrap();
        let hits = ix.search(&[0i8; DIM], &[0], 1, 3);
        let ms = ix.matches(&hits);
        assert_eq!(ms.len(), 1);
        assert_eq!(ms[0].owner_ed25519, [11u8; 32]);
        assert_eq!(ms[0].cluster_id, 0);
        assert_eq!(ms[0].slot, hits[0].1);
        assert_eq!(ms[0].d2, hits[0].0);
        // Контракт сортировки проверяется самим wire-типом перед подписанием (§8.4).
        vecdht_wire::messages::MatchResult {
            shard: 0,
            epoch: 1,
            query_id: 7,
            responder_ed25519: [0u8; 32],
            matches: ms,
        }
        .check_sort_contract()
        .unwrap();
    }

    #[test]
    fn remove_owner_is_idempotent_and_frees_dedup() {
        let mut ix = idx();
        let slot = ix.insert(entry(5, 0, 0, 1000)).unwrap().slot;
        assert_eq!(ix.remove_owner(&[5u8; 32]), Some(slot));
        assert_eq!(ix.remove_owner(&[5u8; 32]), None, "повторное delete — no-op");
        assert_eq!(ix.live, 0);
        let again = ix.insert(entry(5, 0, 1, 1000)).unwrap();
        assert!(!again.replaced, "после delete owner свободен ⇒ это новая запись, а не замена");
        assert_eq!(again.slot, slot, "дыра переиспользуется вместо роста арены (§8.3 recycling)");
        assert_eq!(ix.next_slot(), 1, "переиспользованная дыра не добавила slot");
        ix.check_invariants().unwrap();
    }

    #[test]
    fn live_slots_iterates_ascending_and_skips_holes() {
        let mut ix = idx();
        for o in 0..6u8 {
            ix.insert(entry(o, 0, 0, 1000)).unwrap();
        }
        ix.mark_dead(1);
        ix.mark_dead(4);
        let seen: Vec<u32> = ix.live_slots().map(|(s, _)| s).collect();
        assert_eq!(seen, vec![0, 2, 3, 5]);
    }

    #[test]
    fn invariants_catch_a_broken_list() {
        let mut ix = idx();
        for o in 0..4u8 {
            ix.insert(entry(o, 0, 0, 1000)).unwrap();
        }
        ix.lists[0].push(2);
        assert!(ix.check_invariants().unwrap_err().contains("не отсортирован"));
        ix.lists[0].pop();
        ix.live_words[0] = 0;
        assert!(ix.check_invariants().unwrap_err().contains("мёртвый slot"));
    }
}
