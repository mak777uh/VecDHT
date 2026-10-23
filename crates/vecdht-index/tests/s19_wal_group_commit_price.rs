//! §19.4, строка «WAL append, group commit ≤32 опсов на fsync | ≥ 6 400 ops/s (=32/0.005); при
//! окне 1 мс — до 32k». Прямого замера именно этой строки в lab-циклах не было: §19.5 печатает
//! «fsync на каждый опс 815 опсов/с (1,23 мс)» и «group commit 21 200 опсов/с (47 мкс/опс, ×26)»,
//! но обе строки снимались в бенч-харнесе (`benches/src/bench/index.rs:164…212`), а не на продуктовом
//! пути.
//!
//! Главная проверяемая вещь найдена в коде ДО замера и от профиля не зависит. Групповой коммит в
//! коде существует как **предикат**, а не как механизм. `ShardStore::should_group_commit()`
//! (`store.rs:367`) вызывается из двух мест — из `benches/src/bench/index.rs:188` и из модульных
//! тестов `store.rs:667`/`store.rs:676`. В продуктовом пути (`crates/vecdht-node/src/node.rs`) у
//! него нет ни одного вызова: publish — это `stage_insert` (+ возможно `stage_delete` того же
//! publish) и `commit` на 810/826, то есть **один fsync на publish**. `GROUP_COMMIT_MS = 5`
//! (`wal.rs:30`) не читается вообще нигде, кроме assert'а константы в `lib.rs:163`: временного
//! окна, о котором говорит строка («при окне 1 мс — до 32k») и §10.2 («задержка ACK до 5 мс»), в
//! коде нет ни в каком виде.
//! Значит «≥ 6 400 ops/s» — свойство харнеса, а не свойство узла, и спрашивать надо не «выполнена ли
//! строка», а «чем она выполняется: арифметикой fsync или тем, что вызывающий позвал `commit` не на
//! каждый опс». Отсюда два отношения, а не одно абсолютное число (правило 7 в `lab/PLAN.md`):
//! `цена publish / цена одного fsync` — если продуктовый путь группировал бы, отношение было бы
//! заметно меньше единицы; и `запас до 6 400 / внутренний разброс` — если запас уже разброса, строку
//! на этом стенде фиксировать нельзя.
//!
//! Профиль — часть заморозки (правило 6): временные гейты только в release, границы заморожены из
//! арифметики строки (`32·1000/5 = 6400`) и из §19.5; в debug идут только структурные гейты и
//! арифметика.
//!
//! Печать — парами `МЕРЕНО ключ=число` с единицей в имени ключа (ascii), чтобы экстракторы
//! helper'а не зависели от номера awk-поля (урок ДИАГНОЗ-4 из `E-0082`).

use std::hint::black_box;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use vecdht_index::entry::{IndexEntry, INDEX_ENTRY_BYTES};
use vecdht_index::store::ShardStore;
use vecdht_index::wal::{WalFrame, WalWriter, GROUP_COMMIT_MAX, GROUP_COMMIT_MS, SEGMENT_MAX_OPS};
use vecdht_index::{SNAPSHOT_OPS, testing};
use vecdht_wire::codec::DIM;
use vecdht_wire::messages::OpKind;

/// Строка §19.4: «≥ 6 400 ops/s» для группового коммита ≤32 опсов на fsync.
const ROW_OPS_PER_SEC: f64 = 6_400.0;
/// §19.5 на этом же стенде: fsync на каждый опс.
const SPEC195_SOLO_OPS: f64 = 815.0;
/// §19.5 на этом же стенде: group commit.
const SPEC195_GROUP_OPS: f64 = 21_200.0;
/// Объём тела фрейма — продуктовый `InsertOp`/`IndexEntry` (424 Б), чтобы цена fsync относилась
/// к боевой записи, а не к произвольному телу.
const BODY_BYTES: usize = INDEX_ENTRY_BYTES;
/// Размер фрейма на диске: crc4 + seq8 + kind1 + len4 + тело.
const FRAME_BYTES: usize = 4 + 8 + 1 + 4 + BODY_BYTES;

/// Каталог, который удаляется даже при панике внутри тест-функции (урок ДИАГНОЗ-3 из `E-0082`:
/// `remove(&d)` после `assert!` оставлял сотни мегабайт в `%TEMP%`).
struct DirGuard(PathBuf);

impl DirGuard {
    fn new(tag: &str) -> Self {
        Self(testing::dir(tag))
    }
    fn path(&self) -> &std::path::Path {
        &self.0
    }
}

impl Drop for DirGuard {
    fn drop(&mut self) {
        testing::remove(&self.0);
    }
}

fn entry(i: u64) -> IndexEntry {
    let mut owner = [0u8; 32];
    owner[..8].copy_from_slice(&i.to_le_bytes());
    owner[8] = 0x5b;
    let mut v = [0i8; DIM];
    for (lane, b) in v.iter_mut().enumerate() {
        let x = ((i as usize) * 7 + lane * 11) % 251;
        *b = (x as i32 - 125) as i8;
    }
    IndexEntry {
        owner_ed25519: owner,
        vec_q: v,
        cluster_id: (i % 16) as u16,
        published_bucket: 1_000,
        ttl_buckets: 54_000,
    }
}

fn frame(seq: u64) -> WalFrame {
    WalFrame::new(seq, OpKind::Insert, entry(seq).to_insert().body_bytes())
}

fn median(v: &[Duration]) -> Duration {
    assert!(!v.is_empty(), "медиана по пустой выборке");
    let mut s = v.to_vec();
    s.sort_unstable();
    s[s.len() / 2]
}

fn split_medians(v: &[Duration]) -> (Duration, Duration) {
    let a: Vec<Duration> = v.iter().step_by(2).copied().collect();
    let b: Vec<Duration> = v.iter().skip(1).step_by(2).copied().collect();
    (median(&a), median(&b))
}

fn us(d: Duration) -> f64 {
    d.as_secs_f64() * 1e6
}

/// Внутренний разброс инструмента, ‰: две чередующиеся половины одной выборки.
fn spread_pmk(v: &[Duration]) -> f64 {
    let (a, b) = split_medians(v);
    let m = us_median(v).max(1e-9);
    (us(a) - us(b)).abs() / m * 1000.0
}

fn us_median(v: &[Duration]) -> f64 {
    us(median(v))
}

/// Медиана цены одной операции по массиву замеров «на опс».
fn per_op_us(total: Duration, ops: usize) -> f64 {
    total.as_secs_f64() * 1e6 / ops as f64
}

/// Целочисленная и профиле-независимая половина строки §19.4 плюс её содержательная половина:
/// групповой коммит в коде — предикат вызывающего, а не механизм узла.
#[test]
fn wal_row_arithmetic_and_group_commit_is_only_a_predicate() {
    // (1) Константы строки живут в коде ровно в тех значениях, из которых выводится 6 400.
    assert_eq!(GROUP_COMMIT_MAX, 32, "GROUP_COMMIT_MAX уехал из строки §19.4");
    assert_eq!(GROUP_COMMIT_MS, 5, "GROUP_COMMIT_MS уехал из §10.2");
    assert_eq!(
        GROUP_COMMIT_MAX as u64 * 1_000 / GROUP_COMMIT_MS,
        6_400,
        "арифметика строки: 32 опса за окно 5 мс = 6 400 опсов/с"
    );
    // Контрфактуал строки «при окне 1 мс — до 32k» — тоже чистая арифметика того же кода.
    assert_eq!(GROUP_COMMIT_MAX as u64 * 1_000, 32_000, "контрфактуал «окно 1 мс» = 32 000 опсов/с");
    // И наоборот: 6 400 опсов/с при 32 опсах на fsync означает ровно 5 мс на fsync.
    assert_eq!(
        GROUP_COMMIT_MAX as f64 * 1_000.0 / ROW_OPS_PER_SEC,
        GROUP_COMMIT_MS as f64,
        "строка «≥6 400» означает fsync за 5 мс — то есть окно, а не пропускную способность диска"
    );

    // (2) Предикат вместо механизма: группировка обязана быть решением вызывающего. До commit'а
    //     опсы на диске (append делает write+flush), но не применены; `should_group_commit`
    //     включается ровно на 32-м опсе.
    let guard = DirGuard::new("s19-wal-pred");
    let mut s = ShardStore::create(guard.path(), 0, 1).expect("создать шард");
    assert_eq!(s.staged_len(), 0);
    for i in 0..(GROUP_COMMIT_MAX as u64 - 1) {
        s.stage_insert(entry(i)).expect("stage");
    }
    assert_eq!(s.staged_len(), 31, "счётчик staged съехал");
    assert!(!s.should_group_commit(), "предикат сработал раньше 32-го опса");
    assert_eq!(s.applied_seq, 0, "без commit память обязана остаться чистой");
    assert_eq!(s.wal.ops(), 31, "append обязан дойти до диска до commit'а");
    s.stage_insert(entry(31)).expect("stage 32-го");
    assert!(s.should_group_commit(), "предикат не сработал на 32-м опсе");
    let n = s.commit().expect("commit");
    assert_eq!(n, GROUP_COMMIT_MAX, "commit применил не всю группу");
    assert_eq!(s.applied_seq, 32);
    assert_eq!(s.staged_len(), 0, "после commit хвост обязан быть пуст");

    // (3) Один fsync на publish — наблюдаемый след продуктового пути: после `publish` staged пуст,
    //     а WAL вырос ровно на один фрейм. Это и есть «fsync на каждый опс» в поведении, а не в
    //     grep'е.
    let before_wal_ops = s.wal.ops();
    let before_applied = s.applied_seq;
    s.publish(entry(100)).expect("publish");
    assert_eq!(s.staged_len(), 0, "publish не обязан оставлять staged");
    assert_eq!(s.wal.ops(), before_wal_ops + 1, "publish пишет ровно один фрейм");
    assert_eq!(s.applied_seq, before_applied + 1);
    assert!(!s.should_group_commit(), "после publish предикат группировки заведомо ложен");

    // (4) Барьер durability — это fsync, а не видимость: незакоммиченные, но записанные фреймы
    //     читаются при повторном открытии и применяются replay'ем.
    let guard2 = DirGuard::new("s19-wal-reopen");
    {
        let mut t = ShardStore::create(guard2.path(), 0, 1).expect("создать шард 2");
        for i in 0..8 {
            t.stage_insert(entry(i)).expect("stage без commit");
        }
        assert_eq!(t.applied_seq, 0);
        assert_eq!(t.wal.ops(), 8);
        black_box(&t);
    }
    let reopened = ShardStore::open(guard2.path(), 0).expect("переоткрыть");
    assert_eq!(reopened.replayed, 8, "replay обязан подобрать незакоммиченный хвост");
    assert_eq!(reopened.len(), 8);
    assert_eq!(reopened.applied_seq, 8);

    // (5) Раскладка фрейма: 441 Б на опс, и ни один из пределов сегмента не задет малыми замерами.
    assert_eq!(FRAME_BYTES, 441, "раскладка фрейма уехала — цена fsync относится не к тому объёму");
    println!(
        "МЕРЕНО wal_arith_ok=1 ops_per_fsync={GROUP_COMMIT_MAX} window_ms={GROUP_COMMIT_MS} \
         row_ops_per_s={ROW_OPS_PER_SEC} window_1ms_ops_per_s=32000 frame_bytes={FRAME_BYTES} \
         snapshot_ops={SNAPSHOT_OPS} segment_max_ops={SEGMENT_MAX_OPS}"
    );
}

/// Боевая половина: цена fsync, цена publish, цена группового коммита и два отношения строки.
#[test]
fn wal_row_price_in_release() {
    let release = !cfg!(debug_assertions);
    let profile = if release { "release" } else { "debug" };
    let n_solo: usize = if release { 600 } else { 60 };
    let n_group_batches: usize = if release { 20 } else { 4 };
    let n_append: usize = if release { 20_000 } else { 2_000 };
    println!("=== §19.4 строка «WAL append, group commit», профиль {profile} ===");

    // (6) Голый append без fsync: цена записи 441 байт в сегмент.
    let guard = DirGuard::new("s19-wal-append");
    let mut w = WalWriter::open(guard.path(), 1).expect("открыть писатель");
    for i in 0..256 {
        w.append(&frame(i)).expect("warmup append");
    }
    let warm_bytes = w.bytes();
    let t = Instant::now();
    for i in 0..n_append {
        w.append(&frame(i as u64)).expect("append");
    }
    let append_total = t.elapsed();
    let append_per_op = per_op_us(append_total, n_append);
    assert_eq!(w.ops(), 256 + n_append as u64);
    println!(
        "МЕРЕНО wal_append_per_op_us={append_per_op:.3} wal_append_bytes={}",
        w.bytes() - warm_bytes
    );

    // (7) Один fsync на опс, по отдельности (warm'ом идёт тот же путь, что и в замере).
    let mut solo_times: Vec<Duration> = Vec::with_capacity(n_solo);
    for i in 0..n_solo {
        let t = Instant::now();
        w.append(&frame(1000 + i as u64)).expect("append solo");
        w.fsync().expect("fsync solo");
        solo_times.push(t.elapsed());
    }
    let solo_p50 = median(&solo_times);
    let solo_ops = 1e6 / us(solo_p50);
    let group = GROUP_COMMIT_MAX;
    println!(
        "МЕРЕНО wal_solo_per_op_us={:.3} solo_ops_per_s={:.0} solo_spread_promil={:.1} \
         solo_ratio_to_195_x={:.3}",
        us(solo_p50),
        solo_ops,
        spread_pmk(&solo_times),
        solo_ops / SPEC195_SOLO_OPS
    );

    // (8) Групповой коммит в харнесовом стиле: `group` аппендов + один fsync.
    let mut group_times: Vec<Duration> = Vec::with_capacity(n_group_batches);
    for b in 0..n_group_batches {
        let t = Instant::now();
        for i in 0..group {
            w.append(&frame(100_000 + (b * group + i) as u64)).expect("append group");
        }
        w.fsync().expect("fsync group");
        group_times.push(t.elapsed());
    }
    let group_p50 = median(&group_times);
    let group_per_op = us(group_p50) / group as f64;
    let group_ops = 1e6 / group_per_op;
    let speedup = us(solo_p50) / group_per_op;
    println!(
        "МЕРЕНО wal_group_per_op_us={group_per_op:.3} group_ops_per_s={group_ops:.0} \
         group_spread_promil={:.1} speedup_vs_solo_x={speedup:.2} group_ratio_to_195_x={:.3}",
        spread_pmk(&group_times),
        group_ops / SPEC195_GROUP_OPS
    );

    // (9) Продуктовый путь: `ShardStore::publish` — stage + commit, то есть append + fsync + apply.
    let guard2 = DirGuard::new("s19-wal-publish");
    let mut store = ShardStore::create(guard2.path(), 0, 1).expect("создать шард");
    for i in 0..32 {
        store.publish(entry(i)).expect("warmup publish");
    }
    let mut pub_times: Vec<Duration> = Vec::with_capacity(n_solo);
    for i in 0..n_solo {
        let t = Instant::now();
        store.publish(entry(1_000 + i as u64)).expect("publish");
        pub_times.push(t.elapsed());
    }
    let pub_p50 = median(&pub_times);
    let publish_ratio_to_solo = us(pub_p50) / us(solo_p50);
    let publish_ops = 1e6 / us(pub_p50);
    println!(
        "МЕРЕНО wal_publish_per_op_us={:.3} publish_ops_per_s={:.0} \
         publish_to_solo_x={publish_ratio_to_solo:.3} publish_spread_promil={:.1}",
        us(pub_p50),
        publish_ops,
        spread_pmk(&pub_times)
    );

    // (10) Тот же путь, но сгруппированный вызывающим: stage ×32 + один commit. Отношение к (9) —
    //      и есть «что даёт строка §19.4: механизм узла или решение вызывающего».
    let guard3 = DirGuard::new("s19-wal-productgroup");
    let mut store3 = ShardStore::create(guard3.path(), 0, 1).expect("создать шард 3");
    let mut pg_times: Vec<Duration> = Vec::with_capacity(n_group_batches);
    let mut seq = 0u64;
    for _ in 0..n_group_batches {
        let t = Instant::now();
        for _ in 0..group {
            store3.stage_insert(entry(seq)).expect("stage");
            seq += 1;
        }
        assert!(store3.should_group_commit());
        store3.commit().expect("group commit");
        pg_times.push(t.elapsed());
    }
    let pg_p50 = median(&pg_times);
    let pg_per_op = us(pg_p50) / group as f64;
    let product_group_ratio = us(pub_p50) / pg_per_op;
    println!(
        "МЕРЕНО wal_productgroup_per_op_us={pg_per_op:.3} productgroup_ops_per_s={:.0} \
         publish_to_productgroup_x={product_group_ratio:.2} productgroup_spread_promil={:.1}",
        1e6 / pg_per_op,
        spread_pmk(&pg_times)
    );
    assert_eq!(store3.len(), n_group_batches * group);
    assert_eq!(store3.last_snapshot_seq, 0, "замер не обязан задевать барьер снапшота");
    assert_eq!(store.applied_seq, 32 + n_solo as u64, "publish применены не все");

    if release {
        // (12) Санити: solo-цена fsync обязана лежать в правдоподобном интервале опсов/с, а не на
        //      порядках мимо — иначе вердикт (11) относится к сломанному инструменту.
        assert!(
            solo_ops > 100.0 && solo_ops < 20_000.0,
            "цена solo fsync вне правдоподобного интервала опсов/с: {solo_ops:.0}"
        );
        // (11) ГЛАВНЫЙ ГЕЙТ: продуктовый путь платит fsync на каждый опс. Если бы узел группировал,
        //      отношение publish/solo было бы заметно меньше единицы. Заморожено как [0,8; 3,0].
        assert!(
            (0.8..3.0).contains(&publish_ratio_to_solo),
            "продуктовый publish НЕ платит один fsync на опс: publish/solo = {publish_ratio_to_solo:.3} \
             при замороженном [0,8; 3,0] — вывод «группировки в проде нет» опровергнут"
        );
        // (12) Отношение «соло к групповому» обязано быть того же порядка, что 32 (≤32, потому что
        //      apply и write не исчезают). Заморожено как [8; 40] — §19.5 печатает ×26.
        assert!(
            (8.0..40.0).contains(&speedup),
            "ускорение группового коммита вне замороженного окна [8; 40]: {speedup:.2}×"
        );
        // (12) Путь вызывающего обязан быть дороже группового хотя бы вчетверо — иначе
        //      «группировка» ничего не даёт и разговор про предикат бессодержателен.
        assert!(
            product_group_ratio >= 4.0,
            "publish против stage×32+commit: {product_group_ratio:.2}× при замороженном ≥ 4×"
        );
        // (13) Строка «≥ 6 400» выполнима групповым путём на этом диске — И запас обязан быть шире
        //      внутреннего разброса (правило 7). Иначе строка на этом стенде не фиксируется.
        let margin = group_ops / ROW_OPS_PER_SEC - 1.0;
        let rel_spread = spread_pmk(&group_times) / 1000.0;
        let gate7 = if margin >= 2.0 * rel_spread { 1 } else { 0 };
        println!(
            "МЕРЕНО row_margin_x={margin:.3} wal_rel_spread_x={rel_spread:.4} wal_gate7_ok={gate7}"
        );
        assert!(
            margin >= 2.0 * rel_spread,
            "правило 7: запас до 6 400 опсов/с ({margin:.3}) уже разброса инструмента ({:.3})",
            2.0 * rel_spread
        );
        assert!(
            group_ops > ROW_OPS_PER_SEC,
            "групповой путь не тянет 6 400 опсов/с: {group_ops:.0} — строка §19.4 нарушена на этом диске"
        );
        // (14) Сопоставимость с §19.5: цикл обязан мерить то же явление, что сноска. Оба отношения
        //      заморожены окном [0,5; 2,0]; выход за него означает, что числа §19.5 снимались на
        //      другом диске/другом теле фрейма/другом профиле, и переносить их в спеку нельзя.
        let solo_to_195 = solo_ops / SPEC195_SOLO_OPS;
        let group_to_195 = group_ops / SPEC195_GROUP_OPS;
        assert!(
            (0.5..=2.0).contains(&solo_to_195),
            "solo-цена не сопоставима с §19.5: {solo_ops:.0} / 815 = {solo_to_195:.3} при окне [0,5; 2,0]"
        );
        assert!(
            (0.5..=2.0).contains(&group_to_195),
            "групповая цена не сопоставима с §19.5: {group_ops:.0} / 21 200 = {group_to_195:.3} при окне [0,5; 2,0]"
        );
        println!("МЕРЕНО wal_release_gates=ok");
    } else {
        println!(
            "debug: временные гейты (11)…(14) пропущены по профилю; проверка — \
             cargo test --release -p vecdht-index --test s19_wal_group_commit_price"
        );
    }
    // (15) Чистота: каталоги замера обязаны сняться вместе с тестом. Порядок обратный
    //      объявлениям: писатель и сторы закрывают дескрипторы раньше, чем их каталоги удаляются
    //      (на Windows `remove_dir_all` не проходит при открытом файле — это и есть проверка,
    //      а не формальность).
    let paths = [
        guard.path().to_path_buf(),
        guard2.path().to_path_buf(),
        guard3.path().to_path_buf(),
    ];
    drop(store3);
    drop(store);
    drop(w);
    drop(guard3);
    drop(guard2);
    drop(guard);
    for p in &paths {
        assert!(!p.exists(), "каталог замера обязан удалиться по Drop: {p:?}");
    }
}
