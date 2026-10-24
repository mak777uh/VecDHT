//! Гейт §19.1 по памяти: 1M записей в бюджете 428 МБ (±5%), §8.2.
//!
//! Отдельный test-таргет, потому что `#[global_allocator]` считает аллокации **всего процесса**,
//! а тесты внутри одного бинаря идут параллельно: один тест в одном бинаре — и цифра относится к
//! индексу, а не к соседним сценариям.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicIsize, Ordering};

use vecdht_index::entry::{IndexEntry, INDEX_ENTRY_BYTES};
use vecdht_index::ivf::IvfIndex;
use vecdht_wire::codec::DIM;

const MIB: usize = 1024 * 1024;
/// Таблица §8.2: ≈450 Б/запись (424 арена + 4 список + ~20 dedup + 1 bitmap + 1 байт объявления),
/// 1M записей ⇒ ≈429 МБ.
const BUDGET: usize = 428 * MIB;
/// Допуск гейта (§19.1) — ±5%.
const TOL_PCT: usize = 5;
const N: usize = 1_000_000;

static LIVE: AtomicIsize = AtomicIsize::new(0);

struct Counting;

impl Counting {
    #[inline]
    fn add(&self, delta: isize) {
        LIVE.fetch_add(delta, Ordering::Relaxed);
    }
}

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        let p = unsafe { System.alloc(l) };
        if !p.is_null() {
            self.add(l.size() as isize);
        }
        p
    }

    unsafe fn alloc_zeroed(&self, l: Layout) -> *mut u8 {
        let p = unsafe { System.alloc_zeroed(l) };
        if !p.is_null() {
            self.add(l.size() as isize);
        }
        p
    }

    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        self.add(-(l.size() as isize));
        unsafe { System.dealloc(p, l) }
    }

    unsafe fn realloc(&self, p: *mut u8, l: Layout, new_size: usize) -> *mut u8 {
        let q = unsafe { System.realloc(p, l, new_size) };
        if !q.is_null() {
            // Учитывается дельта: `realloc` — это те же байты, а не новые.
            self.add(new_size as isize - l.size() as isize);
        }
        q
    }
}

#[global_allocator]
static ALLOC: Counting = Counting;

fn live_bytes() -> isize {
    LIVE.load(Ordering::Relaxed)
}

/// Запись шарда 0: владельцы уникальны (иначе дедупликация схлопнула бы 1M в 16 записей и
/// бюджет стал бы фиктивным), вектор заполнен детерминированно.
fn entry(i: u64) -> IndexEntry {
    let mut owner = [0u8; 32];
    owner[..8].copy_from_slice(&i.to_le_bytes());
    owner[8] = 0xa7;
    IndexEntry {
        owner_ed25519: owner,
        vec_q: [(i.rem_euclid(7)) as i8; DIM],
        cluster_id: (i % 16) as u16,
        published_bucket: 1_000,
        ttl_buckets: 5_400,
    }
}

#[test]
fn one_million_entries_fit_the_budget() {
    let lower = BUDGET * (100 - TOL_PCT) / 100;
    let upper = BUDGET * (100 + TOL_PCT) / 100;
    let before = live_bytes();

    // `with_capacity`, а не рост блоками: иначе измеряли бы время memcpy, а не раскладку (§8.2).
    let mut index = IvfIndex::with_capacity(0, N);
    for i in 0..N as u64 {
        index.insert(entry(i)).unwrap();
    }
    assert_eq!(index.live, N);
    index.check_invariants().unwrap();

    let used = (live_bytes() - before) as usize;
    let mem = index.mem_bytes();
    let mib = |b: usize| format!("{:.1} МиБ", b as f64 / MIB as f64);
    println!(
        "1M записей: арена {}, списки {}, dedup {}, bitmap {}, объявления {}, итого {} (учтено аллокатором {})",
        mib(mem.arena),
        mib(mem.lists),
        mib(mem.owners),
        mib(mem.bitmap),
        mib(mem.slot_attr),
        mib(mem.total()),
        mib(used),
    );

    // Разбивка по строкам таблицы §8.2.
    assert_eq!(mem.arena, N * INDEX_ENTRY_BYTES, "арена = 424 Б × N");
    assert_eq!(INDEX_ENTRY_BYTES, 424, "раскладка записи поехала");
    assert!(mem.lists <= 8 * MIB, "inverted lists: {} — ожидаемо ~4 МиБ", mib(mem.lists));
    assert!(mem.owners <= 16 * MIB, "dedup: {} — ожидаемо ~8 МиБ", mib(mem.owners));
    assert!(mem.bitmap <= 2 * MIB, "bitmap: {}", mib(mem.bitmap));
    assert_eq!(mem.slot_attr, N, "байт объявления = 1 Б × N (§5.5)");

    // Гейт: и по учёту самого индекса, и по факту аллокаций процесса.
    assert!(mem.total() <= upper, "{} > {}, §8.2 не сходится", mib(mem.total()), mib(upper));
    assert!(used <= upper, "аллоцировано {} > {}", mib(used), mib(upper));
    assert!(
        mem.total() >= lower,
        "подозрительно мало: {} < {} — считать нечего?",
        mib(mem.total()),
        mib(lower)
    );

    // Байт на живую запись против ≈450 Б из таблицы §8.2 (прогноз `E-0100`: 444,6 Б).
    let per = mem.per_entry(index.live);
    assert!(per <= 450.0 * 1.05, "{per:.1} Б/запись против 450 Б (§8.2)");
    println!("на живую запись: {per:.1} Б (предел таблицы 450 Б)");
    // Печатные факты для `lab/expectations/e0100.tsv`: сверка идёт по ним, а не по прозе.
    println!("MEM_SLOT_ATTR_BYTES={}", mem.slot_attr);
    println!("MEM_INDEX_ENTRY_BYTES={INDEX_ENTRY_BYTES}");
    println!("MEM_PER_ENTRY_TENTHS={}", (per * 10.0).round() as usize);
    println!(
        "MEM_PER_ENTRY_AT_MOST_PREDICTED_4446={}",
        u8::from(per <= 444.6)
    );
    println!("MEM_TOTAL_MIB={}", mem.total() / MIB);

    drop(index);
    let leaked = live_bytes() - before;
    assert!(leaked.abs() < 64 * MIB as isize, "индекс не вернул память: {leaked} Б");
}
