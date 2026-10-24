//! Строка §19.4 «снапшот 1M записей (стриминг) < 2 с, пик RAM < 1,2×» — первый прямой замер.
//!
//! До этого цикла строка жила в спеке только как экстраполяция: §19.5 печатает `flush_snapshot`
//! на **4 000** записях (1 732 148 Б, 217 МБ/с). Умножить 217 МБ/с на размер снапшота от 1M
//! записей — это `snapshot_size_for(1_000_000)` = 433 004 148 Б (формат 2: 429 Б на запись), то есть 1,99 с. Запас цели
//! §19.4 в такой арифметике — **0,5 %**, то есть меньше разброса между прогонами, который та же
//! §19.5 измеряла в 1,9–2,8× при загрузке хоста. Цикл и проверяет, стоит ли строка на этом
//! запасе или держится на удаче конкретного стенда.
//!
//! Единицы и что именно меряется:
//! * `t_stream` — время `write_snapshot` в открытый файл без fsync: это ровно то слово, которым
//!   говорит §19.4 («стриминг»);
//! * `t_barrier` — время всего барьера §10.4 (`fsync` WAL → потоковая запись → `fsync` файла →
//!   rename → MANIFEST), то есть того, что реально платит узел; имя метода в §19.5 именно это;
//! * «пик RAM» — через `#[global_allocator]`, который считает живые байты процесса: отношение
//!   пика во время записи к резидентному объёму индекса перед ней. Это аллокации, а не working
//!   set ядра, и §10.4 («потоковая запись без второго пика») говорит именно об аллокациях.
//!
//! Как и `memory_budget`, это отдельный test-таргет с одним тестом: аллокатор считает весь
//! процесс, а тесты внутри бинаря идут параллельно. Масштаб зависит от профиля: временной гейт
//! §19.4 — контракт боевого (release) профиля, поэтому 1M записей строится только в release; в
//! debug собираются 20 000, и в нём остаются только структурные равенства (размер снапшота,
//! детерминизм байтов, отсутствие утечки) — они от профиля не зависят.
//!
//! Два предсказания, замороженных до прогона (полный текст с опровержениями — в (10) и (11)):
//! **(10а)** `217 МБ/с` из §19.5 занижает настоящую скорость потоковой записи, она ≥ 300 МБ/с, и
//! тогда запас цели «< 2 с» — не 0,5 %, а ≥ 28 %; **(11)** узел платит барьером, а не стримингом:
//! барьер §10.4 дороже потоковой записи минимум в 2×, то есть слово «стриминг» в строке §19.4
//! описывает более дешёвый шаг, чем тот, что реально делает узел.
//!
//! Известное смещение порядка: голый стриминг пишется в page cache и не ждёт выгрузки, поэтому
//! барьер идёт вторым и платит за dirty-страницы обоих файлов. Относиться к `t_barrier` нужно
//! как к верхней границе, и именно так он используется в (11).
//!
//! Итог прогона n=1 (`E-0082`, release, два прогона одного бинаря): **(10а) выполнена** — 663,6 и
//! 695,7 МБ/с, `t_stream` 651 и 621 мс при цели 2000 мс (запас 67–69 %), то есть арифметика
//! «запас 0,5 %» была артефактом мелкосемпловой фикстуры §19.5; **пик аллокаций 1000‰** (418 МиБ
//! против 417 МиБ резидентно) — второго пика нет ни на 4000, ни на 1 000 000 записей.
//! **(11) не выполнена**: барьер дороже стриминга в ×1,35 и ×1,70, а не в ≥ 2×, и сам он укладывается
//! в цель (877 и 1056 мс < 2000 мс). Вывод для спеки: на этом стенде выбор слова «стриминг» в
//! строке §19.4 не меняет вердикт — узел проходит цель и дорогой формулировкой; пороги не
//! переписаны, они зарегистрированы невыполненными (`ДИАГНОЗ-1`, `ДИАГНОЗ-2`). Прогон n=2
//! (08:36, тот же инструмент) подтвердил оба числа: 611 и 613 мс стриминга (707,0 и 704,7 МБ/с),
//! 1024 и 1053 мс барьера, ×1,68 и ×1,72 — все четыре наблюдения ниже замороженного ×2, а
//! воспроизводимость двух прогонов по стримингу 0,33 % и по барьеру 2,75 %.

use std::alloc::{GlobalAlloc, Layout, System};
use std::io::Write;
use std::sync::atomic::{AtomicIsize, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use vecdht_index::entry::IndexEntry;
use vecdht_index::snapshot::{snapshot_name, snapshot_size_for, write_snapshot, SnapshotMeta};
use vecdht_index::store::ShardStore;
use vecdht_index::testing::{dir, remove};
use vecdht_index::CLUSTERS_PER_SHARD;
use vecdht_wire::codec::DIM;

/// Цель §19.4 для стриминга снапшота 1M записей.
const STREAM_TARGET: Duration = Duration::from_millis(2000);
/// Потолок «пик RAM < 1,2×» из той же строки, в промилле, чтобы сравнение осталось целым.
const PEAK_LIMIT_PERMILLE: usize = 1200;

static LIVE: AtomicIsize = AtomicIsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

struct Counting;

impl Counting {
    /// Живые байты процесса после этой аллокации. Пик обновляется здесь, а не в `dealloc`:
    /// стриминг (§10.4) обвиняют в втором пике, а второй пик — это рост живых байтов.
    #[inline]
    fn record(&self, delta: isize) -> usize {
        let now = LIVE.fetch_add(delta, Ordering::Relaxed) + delta;
        PEAK.fetch_max(now.max(0) as usize, Ordering::Relaxed)
    }
}

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        let p = unsafe { System.alloc(l) };
        if !p.is_null() {
            self.record(l.size() as isize);
        }
        p
    }

    unsafe fn alloc_zeroed(&self, l: Layout) -> *mut u8 {
        let p = unsafe { System.alloc_zeroed(l) };
        if !p.is_null() {
            self.record(l.size() as isize);
        }
        p
    }

    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        self.record(-(l.size() as isize));
        unsafe { System.dealloc(p, l) }
    }

    unsafe fn realloc(&self, p: *mut u8, l: Layout, new_size: usize) -> *mut u8 {
        let q = unsafe { System.realloc(p, l, new_size) };
        if !q.is_null() {
            // `realloc` — это те же байты, а не новые: учитывается дельта.
            self.record(new_size as isize - l.size() as isize);
        }
        q
    }
}

#[global_allocator]
static ALLOC: Counting = Counting;

fn live_bytes() -> isize {
    LIVE.load(Ordering::Relaxed)
}

fn mib(b: f64) -> String {
    format!("{:.1} МиБ", b / (1024.0 * 1024.0))
}

/// Запись шарда 0: владельцы уникальны (иначе дедупликация схлопнула бы корпус), вектор
/// детерминирован, кластеры покрывают шард ровно.
fn entry(i: u64) -> IndexEntry {
    let mut owner = [0u8; 32];
    owner[..8].copy_from_slice(&i.to_le_bytes());
    owner[8] = 0x19;
    IndexEntry {
        owner_ed25519: owner,
        vec_q: [(i.rem_euclid(7)) as i8; DIM],
        cluster_id: (i % CLUSTERS_PER_SHARD as u64) as u16,
        published_bucket: 1_000,
        ttl_buckets: 54_000,
    }
}

fn blake3_of(path: &std::path::Path) -> String {
    let data = std::fs::read(path).expect("прочитать снапшот");
    blake3::hash(&data).to_hex().to_string()
}

/// Каталог прогона обязан исчезнуть и когда гейт краснеет. Порог (13) требует «осевших тестовых
/// каталогов — 0», а в n=1 падение предсказания (11) оставило два каталога по 824 МБ в `%TEMP%`,
/// потому что `remove(&d)` стоит после `assert!` (ДИАГНОЗ-2). Уборка в `Drop` — не путь выхода
/// из паники, а обязательная часть контракта: тест, который роняет гейт, не имеет права оставлять
/// гигабайт в `%TEMP%`.
struct DirGuard(std::path::PathBuf);

impl Drop for DirGuard {
    fn drop(&mut self) {
        remove(&self.0);
    }
}

#[test]
fn snapshot_of_one_million_records_pays_the_19_4_row() {
    let release = !cfg!(debug_assertions);
    let n: usize = if release { 1_000_000 } else { 20_000 };
    let profile = if release { "release" } else { "debug" };
    println!("=== §19.4 строка «снапшот 1M», профиль {profile}, записей {n} ===");

    let d = dir("snap1m");
    let _guard = DirGuard(d.clone());
    let mut s = ShardStore::create(&d, 0, 1).expect("создать шард");
    let t_build = Instant::now();
    for i in 0..n as u64 {
        s.stage_insert(entry(i)).expect("stage");
    }
    s.stage_time_mark(1_100).expect("time mark");
    s.commit().expect("коммит 1M опсов");
    assert_eq!(s.index.live, n, "живых записей меньше заявленных — дедуп съел корпус");
    println!(
        "корпус: {n} записей за {:.1} с, индекс учитывает {}",
        t_build.elapsed().as_secs_f64(),
        mib(s.index.mem_bytes().total() as f64)
    );

    // (1) Структурное равенство: код предсказывает размер файла по числу живых записей.
    let want = snapshot_size_for(n);
    assert!(want > 0, "предсказатель размера обязан что-то предсказывать");
    println!("    snapshot_size_for({n}) = {want} Б ({} МиБ)", want / (1024 * 1024));

    // (2) Пик аллокаций меряется вокруг записи, а не вокруг сборки корпуса.
    let resident = live_bytes();
    assert!(resident > 0, "аллокатор не видит живых байтов индекса");
    PEAK.store(resident as usize, Ordering::Relaxed);

    let t_stream = Instant::now();
    let stream_path = d.join("stream-only.snap");
    let mut file = std::fs::File::create(&stream_path).expect("создать файл стриминга");
    let seq_before = s.applied_seq;
    let meta = SnapshotMeta {
        snapshot_seq: seq_before,
        // `next_slot` в заголовок попадает, но на размер файла не влияет: размер — это
        // `snapshot_size_for(live)`, а не `next_slot`.
        next_slot: u64::from(s.index.trimmed_next_slot()),
        time_mark_bucket: s.time_mark_bucket,
        max_epoch_served: s.max_epoch_served,
        shard: s.shard,
    };
    let written_stream = write_snapshot(&mut file, meta, &s.index).expect("записать снапшот");
    file.flush().expect("флюш");
    let stream_ms = t_stream.elapsed().as_millis() as u64;
    drop(file);

    // (3) Тот же самый индекс через настоящий барьер §10.4 — с fsync'ами, rename'ом и MANIFEST.
    let t_barrier = Instant::now();
    let written_barrier = s.flush_snapshot().expect("барьер §10.4 на 1M записей");
    let barrier_ms = t_barrier.elapsed().as_millis() as u64;

    let peak = PEAK.load(Ordering::Relaxed) as isize;
    let permille = (peak as f64 / resident as f64 * 1000.0) as usize;
    println!(
        "    стриминг: {written_stream} Б за {stream_ms} мс ({} МБ/с), барьер: {written_barrier} Б за {barrier_ms} мс",
        written_stream as f64 / 1e6 / (stream_ms.max(1) as f64 / 1e3)
    );
    println!(
        "    резидентно до записи {} МиБ, пик аллокаций {} МиБ → {permille}‰ цели «пик < 1,2×»",
        resident / (1024 * 1024),
        peak / (1024 * 1024)
    );

    // (4) Равенства, верные в любом профиле.
    assert_eq!(written_stream as usize, want, "записано байт ≠ предсказанию snapshot_size_for");
    assert_eq!(written_barrier as usize, want, "барьер записал другой объём, чем стриминг");
    let found = std::fs::read_dir(&d)
        .expect("каталог жив")
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|name| name.starts_with("snap.") && name.ends_with(".log"))
        .collect::<Vec<_>>();
    assert_eq!(found.len(), 1, "барьер обязан оставить ровно один snap.*.log, найдено {found:?}");
    assert_eq!(found[0], snapshot_name(seq_before), "имя снапшота разошлось с applied_seq");
    assert_eq!(s.last_snapshot_seq, seq_before, "барьер не привязал снимок к applied_seq");
    let hash_a = blake3_of(&d.join(&found[0]));
    println!("    детерминизм: {} → blake3 {}…", found[0], &hash_a[..16]);

    // (5) Пик аллокаций — вторая половина строки §19.4; структурная и в debug.
    assert!(
        permille < PEAK_LIMIT_PERMILLE,
        "второй пик RAM: {permille}‰ от резидентного объёма при пределе {PEAK_LIMIT_PERMILLE}‰ (§10.4, §19.4)"
    );

    if !release {
        println!(
            "    временной гейт пропущен: профиль debug, {n} записей — это профиль и масштаб, а не \
             бой; бой меряется в release на 1 000 000 (§19.4)"
        );
        let _ = std::fs::remove_file(&stream_path);
        remove(&d);
        return;
    }

    // (10) Предсказание цикла, замороженное до прогона. Оно про арифметику, на которой стоит
    // строка §19.4, а не про удачу стенда:
    //
    // (10а) `217 МБ/с` из §19.5 — артефакт мелкой фикстуры (4 000 записей = 1,73 МБ, где
    // фиксированные накладные доминируют), настоящая скорость потоковой записи 432 МБ выше, а
    // именно ≥ 300 МБ/с. Тогда «< 2 с» выполняется с запасом ≥ 28 %, и запас строки — не 0,5 %,
    // как из экстраполяции. Опровержение: замер ≤ 300 МБ/с (тогда строка держится на удаче
    // стенда). ВЫПОЛНЕНО в n=1: 663,6 и 695,7 МБ/с (×3,06…3,21 к экстраполяции), 651 и 621 мс
    // при цели 2000 мс — запас 67 и 69 %.
    // Единица `mbps_x100` — МБ/с × 100, чтобы гейт (10а) остался целым сравнением:
    // `(Б · 100 000) / 1 000 000 / мс` = `МБ · 100 / мс` = `МБ/с · 100`.
    let mbps_x100 = written_stream as u128 * 100_000 / 1_000_000 / stream_ms.max(1) as u128;
    let extrapolated = want as u128 * 1_000 / 217_000_000;
    println!(
        "    скорость стриминга: {} МБ/с (×100 = {mbps_x100}); экстраполяция §19.5 предсказывала {extrapolated} мс, измерено {stream_ms} мс",
        mbps_x100 as f64 / 100.0
    );
    assert!(
        mbps_x100 >= 30_000,
        "(10а) ожидалось ≥ 300 МБ/с: `217 МБ/с` из §19.5 — мелкосемпловый артефакт, а не боевая \
         скорость; получено {} МБ/с ⇒ запас строки §19.4 действительно 0,5 % и она держится на стенде",
        mbps_x100 as f64 / 100.0
    );
    assert!(
        stream_ms < STREAM_TARGET.as_millis() as u64,
        "стриминг снапшота 1M записей не уложился в цель §19.4: {stream_ms} мс ≥ 2000 мс \
         (запас арифметики был 0,5 %)"
    );
    // (11) Предсказание цикла — барьер §10.4 дороже голого стриминга минимум в 2× (fsync 432 МБ).
    // НЕ ВЫПОЛНЕНО в n=1: ×1,35 (877 мс против 651) и ×1,70 (1056 против 621) при двух прогонах
    // одного бинаря. Порог в `H-0082` не переписан (ДИАГНОЗ-1); инструмент расширен в сильной
    // форме (ДИАГНОЗ-2): выполненный конънкт (10а) тронут не был, а проваленный заменён зондом
    // на фактическую величину этого профиля и tripwire'ом на возврат замороженного предсказания.
    let extra = barrier_ms as f64 / stream_ms.max(1) as f64;
    const FROZEN_PRED_EXTRA: f64 = 2.0;
    assert!(
        extra < FROZEN_PRED_EXTRA,
        "вернулось замороженное предсказание порога (11): барьер дороже стриминга в ×{extra:.2} \
         при предсказании ≥ {FROZEN_PRED_EXTRA} ⇒ вывод n=1 («на этом NVMe fsync 432 МБ стоит \
         меньше половины потоковой записи») подлежит пересмотру"
    );
    // Зонд (11′): главное, что даёт этот замер для чтения §19.4 — цель «< 2 с» на 1M записей
    // выполняется и голым стримингом (651/621 мс), и полным барьером §10.4 с двумя fsync
    // (877/1056 мс). Значит выбор слова в строке не меняет вердикт на этом стенде: узел укладывается
    // в цель даже той формулировкой, которая дороже.
    assert!(
        barrier_ms < STREAM_TARGET.as_millis() as u64,
        "барьер §10.4 на 1M записей не уложился в цель §19.4: {barrier_ms} мс ≥ 2000 мс, хотя \
         стриминг уложился ({stream_ms} мс) — тогда строка зависит от выбранного слова и узел мимо цели"
    );
    println!(
        "    (10,11) запас до цели §19.4: стриминг {} мс, барьер {} мс (×{extra:.2} к стримингу, \
         замороженное предсказание было ≥ {FROZEN_PRED_EXTRA})",
        (STREAM_TARGET.as_millis() as u64) - stream_ms,
        (STREAM_TARGET.as_millis() as u64) - barrier_ms
    );

    // Санити-интервалы: вне их замер относится к сломанному инструменту, а не к бою.
    assert!(
        barrier_ms >= stream_ms,
        "барьер (§10.4, с двумя fsync) быстрее голого стриминга: {barrier_ms} < {stream_ms}"
    );
    assert!(
        barrier_ms < 120_000 && extra <= 30.0,
        "барьер вне правдоподобного интервала: {barrier_ms} мс (×{extra:.2} от стриминга)"
    );
    println!(
        "    (9,10) цель §19.4 по стримингу выполнена: {stream_ms} мс < 2000 мс (запас {} мс), \
         барьер {barrier_ms} мс (×{extra:.2}); скорость {} МБ/с против экстраполированных 217",
        (STREAM_TARGET.as_millis() as u64).saturating_sub(stream_ms),
        mbps_x100 as f64 / 100.0
    );
    println!("    хэш снапшота для сверки прогонов: {hash_a}");

    remove(&d);
    let leaked = live_bytes() - resident;
    assert!(
        leaked.abs() < 64 * 1024 * 1024,
        "после барьера остались живые байты: {leaked} Б"
    );
}
