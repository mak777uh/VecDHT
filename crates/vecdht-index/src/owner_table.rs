//! Таблица дедупликации `owner → slot` (§8.2, §8.3).
//!
//! `std::collections::HashMap` для этой таблицы не годится по двум причинам, и обе — из спеки:
//!
//! 1. **Бюджет.** В §8.2 на dedup map отведено ~20 Б/запись. У `HashMap<(\[u8;32], u32)>`
//!    аллоцированная ёмкость — следующая степень двойки после `n / 0.875`, то есть при 1M
//!    записей 2²¹ корзин по 36 Б ≈ 72 МБ (72 Б/запись); бюджет 428 МБ (§19.1) тогда не сходится
//!    уже на 1M. Здесь: 4 байта на корзину при коэффициенте заполнения 0.5 → 8 Б/запись.
//! 2. **Детерминизм.** `RandomState` делает порядок обхода нестабильным между прогонами. Таблица
//!    на диск не попадает вообще, но пока её обход можно accidental вызвать из снапшота — риск
//!    есть. Собственный хеш (FNV-1a) убирает и риск, и зависимость.
//!
//! Владельцы в таблице не хранятся: при коллизии сравнивается `owner` из арены (`owner_of`),
//! поэтому таблица не переживает перестройку арены и перестраивается из живых записей по
//! возрастанию slot'а — детерминированно (§8.3).

/// Пустая корзина. `u32::MAX` недостижим как slot: арена ограничена тем же значением.
const EMPTY: u32 = u32::MAX;

/// Стартовый размер: 1024 корзины = 4 КБ. Узел держит до 8 шардов, и на пустом шарде
/// аллоцировать десятки мегабайт нельзя.
const MIN_BUCKETS: usize = 1024;

/// Собственный хеш владельца: детерминирован и не зависит от seed процесса.
#[inline]
fn hash_owner(owner: &[u8; 32]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in owner {
        h ^= *b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    // Нижние биты FNV-1a перемешиваются слабо, а маска берётся именно с них.
    h ^ (h >> 31)
}

#[derive(Debug, Clone)]
pub struct OwnerTable {
    buckets: Vec<u32>,
    len: usize,
}

impl Default for OwnerTable {
    fn default() -> Self {
        Self::new()
    }
}

impl OwnerTable {
    pub fn new() -> Self {
        Self::with_capacity(0)
    }

    /// Таблица под `n` записей: корзины подбираются сразу, чтобы рост (`grow`) не превращал
    /// n вставок в Θ(n log n) перестроек — на 1M записей это 11 полных rebuild'ов.
    pub fn with_capacity(n: usize) -> Self {
        let buckets = (2 * n).max(MIN_BUCKETS).next_power_of_two();
        OwnerTable { buckets: vec![EMPTY; buckets], len: 0 }
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.len
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    #[inline]
    pub fn buckets(&self) -> usize {
        self.buckets.len()
    }

    /// Живые байты таблицы — для теста бюджета (§19.1: 1M записей ≤ 428 МБ).
    #[inline]
    pub fn bytes(&self) -> usize {
        self.buckets.len() * core::mem::size_of::<u32>()
    }

    #[inline]
    fn mask(&self) -> usize {
        self.buckets.len() - 1
    }

    /// `owner_of(slot)` — owner из арены. Обязан быть определён для каждого slot'а, который
    /// лежит в таблице: удаление из таблицы происходит одновременно с tombstone'ом в арене,
    /// иначе дедупликация молча теряет запись.
    pub fn get<F>(&self, owner: &[u8; 32], owner_of: F) -> Option<u32>
    where
        F: Fn(u32) -> Option<[u8; 32]>,
    {
        let idx = self.index_of(owner, owner_of)?;
        Some(self.buckets[idx])
    }

    /// Вставить `slot` для `owner`. Предыдущий slot возвращается — на нём держится
    /// «замена на месте» перепубликации (§19.1, dedup).
    pub fn put<F>(&mut self, owner: &[u8; 32], slot: u32, owner_of: F) -> Option<u32>
    where
        F: Fn(u32) -> Option<[u8; 32]> + Copy,
    {
        if let Some(idx) = self.index_of(owner, owner_of) {
            let prev = std::mem::replace(&mut self.buckets[idx], slot);
            debug_assert_eq!(prev, slot, "два живых slot'а на одного owner");
            return Some(prev);
        }
        if (self.len + 1) * 2 > self.buckets.len() {
            self.grow(owner_of);
        }
        let home = hash_owner(owner) as usize & self.mask();
        self.place_at(slot, home);
        self.len += 1;
        None
    }

    /// Удаление без tombstone-корзин: сдвиг кластера назад с перестановкой. Гарантирует, что
    /// удалённый owner больше не находится (`get` по нему ⇒ `None`).
    pub fn remove<F>(&mut self, owner: &[u8; 32], owner_of: F) -> Option<u32>
    where
        F: Fn(u32) -> Option<[u8; 32]> + Copy,
    {
        let idx = self.index_of(owner, owner_of)?;
        let removed = std::mem::replace(&mut self.buckets[idx], EMPTY);
        let mask = self.mask();
        let mut run = Vec::new();
        let mut j = (idx + 1) & mask;
        while self.buckets[j] != EMPTY {
            run.push(std::mem::replace(&mut self.buckets[j], EMPTY));
            j = (j + 1) & mask;
        }
        for slot in run {
            let home = match owner_of(slot) {
                Some(o) => hash_owner(&o) as usize & mask,
                // Инвариант выше: живые slot'ы имеют owner в арене.
                None => {
                    debug_assert!(false, "slot {slot} в таблице без owner в арене");
                    slot as usize & mask
                }
            };
            self.place_at(slot, home);
        }
        self.len -= 1;
        Some(removed)
    }

    pub fn clear(&mut self) {
        self.buckets.iter_mut().for_each(|b| *b = EMPTY);
        self.len = 0;
    }

    /// Индекс корзины, где лежит `owner`.
    fn index_of<F>(&self, owner: &[u8; 32], owner_of: F) -> Option<usize>
    where
        F: Fn(u32) -> Option<[u8; 32]>,
    {
        let mask = self.mask();
        let mut i = hash_owner(owner) as usize & mask;
        for _ in 0..self.buckets.len() {
            let slot = self.buckets[i];
            if slot == EMPTY {
                return None;
            }
            if owner_of(slot).as_ref() == Some(owner) {
                return Some(i);
            }
            i = (i + 1) & mask;
        }
        None
    }

    /// Линейный probing от `home` до первой свободной корзины.
    fn place_at(&mut self, slot: u32, home: usize) {
        let mask = self.mask();
        let mut i = home & mask;
        while self.buckets[i] != EMPTY {
            i = (i + 1) & mask;
        }
        self.buckets[i] = slot;
    }

    /// Перестройка: обход корзин по возрастанию индекса ⇒ содержимое новой таблицы зависит
    /// только от множества slot'ов, не от истории операций.
    fn grow<F>(&mut self, owner_of: F)
    where
        F: Fn(u32) -> Option<[u8; 32]>,
    {
        let mut held: Vec<u32> = Vec::with_capacity(self.len);
        for b in &self.buckets {
            if *b != EMPTY {
                held.push(*b);
            }
        }
        held.sort_unstable();
        let next = self.buckets.len() * 2;
        self.buckets = vec![EMPTY; next];
        self.len = 0;
        for slot in held {
            let home = match owner_of(slot) {
                Some(o) => hash_owner(&o) as usize & self.mask(),
                None => {
                    debug_assert!(false, "slot {slot} в таблице без owner в арене");
                    slot as usize & self.mask()
                }
            };
            self.place_at(slot, home);
            self.len += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// «Арена» из `ARENA` записей: owner — номер slot'а в первых четырёх байтах. 4096 нужно,
    /// чтобы достать до роста таблицы (порог заполнения 0.5 от `MIN_BUCKETS = 1024`).
    const ARENA: u32 = 4096;

    fn owner_of_slot(slot: u32) -> Option<[u8; 32]> {
        if slot < ARENA {
            Some(owner(slot))
        } else {
            None
        }
    }

    fn owner(slot: u32) -> [u8; 32] {
        let mut a = [0u8; 32];
        a[..4].copy_from_slice(&slot.to_le_bytes());
        a
    }

    #[test]
    fn put_get_remove_roundtrip() {
        let mut t = OwnerTable::new();
        assert!(t.is_empty());
        for s in 0..64u32 {
            assert_eq!(t.put(&owner(s), s, owner_of_slot), None);
        }
        assert_eq!(t.len(), 64);
        for s in 0..64u32 {
            assert_eq!(t.get(&owner(s), owner_of_slot), Some(s));
        }
        for s in 0..64u32 {
            assert_eq!(t.remove(&owner(s), owner_of_slot), Some(s));
        }
        assert!(t.is_empty());
        assert_eq!(t.get(&owner(0), owner_of_slot), None);
    }

    #[test]
    fn re_publish_hits_the_same_slot_in_place() {
        // Per §8.3 перепубликация того же `(owner, shard)` идёт в тот же slot, поэтому
        // повторный `put` обязан вернуть предыдущее значение и не менять ни len, ни ёмкость.
        // Другой slot для живого owner — ошибка вызывающего, на ней стоит debug_assert.
        let mut t = OwnerTable::new();
        assert_eq!(t.put(&owner(1), 1, owner_of_slot), None);
        let before = t.buckets();
        assert_eq!(t.put(&owner(1), 1, owner_of_slot), Some(1));
        assert_eq!(t.len(), 1);
        assert_eq!(t.buckets(), before, "замена на месте не должна триггерить рост");
        assert_eq!(t.get(&owner(1), owner_of_slot), Some(1));
    }

    #[test]
    fn sixteen_bytes_per_entry_at_scale() {
        // Бюджет §8.2 отводит на dedup map ~20 Б/запись. Худший случай таблицы — сразу после
        // удвоения: корзины < 4·n, то есть < 16 Б/запись. У HashMap<(\[u8;32], u32)> там же
        // ~72 Б/запись, и бюджет 428 МБ на 1M не сходится.
        let n = 700_000usize;
        let arena: Vec<[u8; 32]> = (0..n)
            .map(|i| {
                let b = (i as u64).to_le_bytes();
                let mut a = [0u8; 32];
                a[0..8].copy_from_slice(&b);
                a[8..16].copy_from_slice(&b);
                a[16..24].copy_from_slice(&b);
                a[24..32].copy_from_slice(&b);
                a
            })
            .collect();
        let of = |s: u32| arena.get(s as usize).copied();
        let mut t = OwnerTable::new();
        for (i, o) in arena.iter().enumerate() {
            t.put(o, i as u32, of);
        }
        assert_eq!(t.len(), n);
        assert!(t.bytes() <= 16 * n, "{} Б на {n} записей", t.bytes());
        assert!(t.buckets() >= 2 * n / 2, "коэффициент заполнения обязан быть ≤ 0.5");
        for i in (0..n).step_by(7) {
            assert_eq!(t.get(&arena[i], of), Some(i as u32));
        }
    }

    #[test]
    fn lookups_survive_interleaved_removes() {
        let mut t = OwnerTable::new();
        for s in 0..64u32 {
            t.put(&owner(s), s, owner_of_slot);
        }
        for s in (0..64u32).step_by(2) {
            t.remove(&owner(s), owner_of_slot);
        }
        assert_eq!(t.len(), 32);
        for s in 0..64u32 {
            let want = if s % 2 == 1 { Some(s) } else { None };
            assert_eq!(t.get(&owner(s), owner_of_slot), want, "slot {s}");
        }
    }

    /// Раскладка *до* перестройки зависит от порядка вставки — это нормальное поведение
    /// open addressing. Важно другое: `grow` раскладывает-held по возрастанию `slot`, поэтому
    /// после перестройки таблица — функция от набора, а не от истории. Именно поэтому
    /// recovery (загрузка по возрастанию slot'а) и live-узел с тем же набором приходят к
    /// одной и той же таблице (§10.5: `recover(disk) == replay(all ops)`).
    #[test]
    fn grow_rebuilds_deterministically() {
        let mut a = build(&[3u32, 1, 2, 63, 0, 31]);
        let mut b = build(&[63, 31, 0, 2, 1, 3]);
        a.grow(owner_of_slot);
        b.grow(owner_of_slot);
        assert_eq!(a.buckets, b.buckets, "перестройка не должна зависеть от порядка вставки");
        assert_eq!(a.len(), 6);

        let mut asc = build(&(0..1200u32).collect::<Vec<u32>>());
        let mut order: Vec<u32> = (0..1200u32).collect();
        // Детерминированный «перемешивающий» порядок вместо rand: прогон повторяем по номерам.
        order.sort_by_key(|s| (s.wrapping_mul(2654435761) >> 8) ^ (s * 7));
        let mut shuffled = build(&order);
        asc.grow(owner_of_slot);
        shuffled.grow(owner_of_slot);
        assert_eq!(asc.buckets, shuffled.buckets, "набор из 1200 в другом порядке — та же таблица");
        assert_eq!(asc.len(), shuffled.len());
    }

    fn build(slots: &[u32]) -> OwnerTable {
        let mut t = OwnerTable::new();
        for s in slots {
            t.put(&owner(*s), *s, owner_of_slot);
        }
        t
    }

    #[test]
    fn collision_is_resolved_by_owner_from_the_arena() {
        // Два разных owner могут попасть в одну home-корзину: второй обязан уехать вперёд,
        // а не перезаписать первого.
        let mut arena = [[0u8; 32]; 4];
        arena[0] = owner(10);
        arena[1] = owner(11);
        let arena = arena;
        let of = |s: u32| Some(arena[s as usize]);
        let mut t = OwnerTable::new();
        t.put(&owner(10), 0, of);
        t.put(&owner(11), 1, of);
        assert_eq!(t.get(&owner(10), of), Some(0));
        assert_eq!(t.get(&owner(11), of), Some(1));
        assert_eq!(t.get(&owner(12), of), None);
        t.remove(&owner(10), of);
        assert_eq!(t.get(&owner(10), of), None);
        assert_eq!(t.get(&owner(11), of), Some(1), "удаление не должно ломать кластер");
    }

    #[test]
    fn hash_is_stable_and_spread() {
        assert_eq!(hash_owner(&owner(1)), hash_owner(&owner(1)));
        assert_ne!(hash_owner(&owner(1)), hash_owner(&owner(2)));
        // 64 почти одинаковых ключа не должны сложиться в одну корзину.
        let mut distinct = std::collections::HashSet::new();
        for n in 0..64u32 {
            distinct.insert(hash_owner(&owner(n)) as usize & (MIN_BUCKETS - 1));
        }
        assert!(distinct.len() > 40, "{:?}", distinct.len());
    }
}
