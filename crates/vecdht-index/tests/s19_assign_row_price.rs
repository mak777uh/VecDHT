//! §19.4, строка «cluster assign (1024 int8 центроидов) < 0.15 мс» — прямого замера у неё не было
//! ни в одном профиле. §19.5 печатает `finalize` = квантование + assign (55 мкс, 2026-10-19), то
//! есть assign там не отделён от квантования; `E-0081` measureровал цену одной записи скана арены
//! (0,05542 и 0,059815 мкс/запись в release) — то же арифметическое ядро `l2_sq`, другое число
//! векторов. Этот таргет отделяет assign и спрашивает, чем на самом деле является цена 1024
//! строк: арифметикой или попаданием набора центроидов в кеш.
//!
//! Главная проверяемая вещь найдена в коде до замера и не зависит от профиля. Эталонные
//! центроиды строятся как `bytes[i] = (i % 255) - 127` (`crates/vecdht-artifact/src/lib.rs:285`),
//! а `Centroids::row(c)` — это срез `[384c, 384c+384)`, то есть строка целиком определяется
//! сдвигом `384c mod 255`. Множество таких сдвигов имеет размер `255 / НОД(384, 255) = 85`,
//! поэтому **из 1024 строк эталонного набора различных ровно 85**, а живой набор — 393 216 Б
//! против 85 × 384 = 32 640 Б у эталонного. Значит §19.5 («finalize 55 мкс») снимался на фикстуре,
//! которая в 12 раз легче по объёму наблюдения и целиком живёт в L1, и цена строки §19.4 на ней —
//! не цена строки §19.4 в бою. Отсюда два разных замера в одном таргете: сетка эталонного
//! артефакта и сетка полной энтропии (1024 различных строки, детерминированный xorshift, никаких
//! `sin`/`exp` — уроки `E-0002` и `centroids.rs:104`).
//!
//! Профиль — часть заморозки (правило 6 в `lab/PLAN.md`): временные гейты живут только в release,
//! границы заморожены из `E-0081` (тот же хост, тот же профиль) и из целочисленной арифметики
//! строки, а не из чисел этого прогона. В debug идут только структурные и арифметические гейты.
//!
//! Правило 7 (введено `E-0082`) здесь применено вперёд, а не постфактум: каждый односторонний
//! абсолютный гейт обязан показать, что его запас до границы строки шире разброса инструмента.
//! Разброс считается внутри таргета по двум чередующимся половинам одной выборки, и гейт
//! сформулирован как отношение, а не как «меньше числа».
//!
//! Печать — парами `ключ=число` с единицей в ключе: экстракторы helper'а не должны зависеть от
//! номера awk-поля (урок ДИАГНОЗ-4 из `E-0082`).

use std::collections::HashSet;
use std::hint::black_box;
use std::time::{Duration, Instant};

use vecdht_artifact::{reference_centroids, Centroids, CENTROID_BYTES};
use vecdht_crypto::quant::{assign_cluster, l2_sq, top_clusters};
use vecdht_wire::codec::DIM;

/// Строка §19.4: «cluster assign (1024 int8 центроидов) < 0.15 мс».
const ROW_TARGET_US: f64 = 150.0;
/// Цена одной записи скана арены в release на ЭТОМ хосте, мкс/запись — заморожено из `E-0081`
/// (0,05542 и 0,059815), а не из этого прогона.
const SCAN_US_PER_RECORD_LO: f64 = 0.05542;
const SCAN_US_PER_RECORD_HI: f64 = 0.059815;
/// Период эталонной сетки центроидов: `bytes[i] = (i % 255) - 127`.
const GRID_PERIOD: usize = 255;
/// Сколько строк перебирает `Centroids::assign` — ровно `NLIST`.
const NLIST: usize = 1024;

// --- фикстуры ---------------------------------------------------------------

/// Сетка эталонного артефакта: 1024 строки, но лишь 85 различных.
fn reference_grid() -> Centroids {
    reference_centroids()
}

/// Сетка полной энтропии: 1024 ЗАВИСЯЩИХ ДРУГ ОТ ДРУГА строки, тот же объём 393 216 Б.
/// Генератор — xorshift64* из `vecdht_index::testing` по той же причине, по какой он там:
/// `sin`/`exp` различаются между либами, а фикстура обязана воспроизводиться на двух машинах.
fn full_entropy_grid() -> Centroids {
    let mut state: u64 = 0x9E37_79B9_7F4A_7C15 ^ 0xC0FFEE;
    let mut bytes = Vec::with_capacity(CENTROID_BYTES);
    while bytes.len() < CENTROID_BYTES {
        let mut x = state;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        state = x;
        let v = x.wrapping_mul(0x2545_F491_4F6C_DD1D);
        bytes.push(((v >> ((bytes.len() % 7) * 8)) & 0xff) as u8 as i8);
    }
    Centroids::from_i8(&bytes).expect("полная сетка: размер фиксирован")
}

/// Детерминированный запрос-вектор по сиду (то же ограничение на библиотеку чисел).
fn query(seed: u64) -> [i8; DIM] {
    let mut state = seed | 0x9E37_79B9_7F4A_7C15;
    let mut v = [0i8; DIM];
    for lane in v.iter_mut() {
        let mut x = state;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        state = x;
        *lane = (x.wrapping_mul(0x2545_F491_4F6C_DD1D) & 0x7f) as i8 - 64;
    }
    v
}

fn gcd(a: usize, b: usize) -> usize {
    if b == 0 {
        a
    } else {
        gcd(b, a % b)
    }
}

// --- статистика -------------------------------------------------------------

fn median(v: &[Duration]) -> Duration {
    assert!(!v.is_empty(), "медиана по пустой выборке");
    let mut s = v.to_vec();
    s.sort_unstable();
    s[s.len() / 2]
}

/// Медиана двух чередующихся половин одной выборки — внутренняя оценка предела
/// воспроизводимости инструмента (правило 7). Чётные индексы и нечётные идут из одного и того же
/// прогона, поэтому их расхождение — это шум замера, а не смена хоста или профиля.
fn split_medians(v: &[Duration]) -> (Duration, Duration) {
    let a: Vec<Duration> = v.iter().step_by(2).copied().collect();
    let b: Vec<Duration> = v.iter().skip(1).step_by(2).copied().collect();
    (median(&a), median(&b))
}

fn us(d: Duration) -> f64 {
    d.as_secs_f64() * 1e6
}

/// Относительный разброс чередующихся половин, ‰.
fn spread_pmk(v: &[Duration]) -> f64 {
    let (a, b) = split_medians(v);
    let m = median(v).as_secs_f64().max(1e-12);
    (a.as_secs_f64() - b.as_secs_f64()).abs() / m * 1000.0
}

/// Прогон `f` по warmup + N замеров; возвращает собранные длительности по порядку.
fn sample<F: FnMut(usize)>(warm: usize, n: usize, mut f: F) -> Vec<Duration> {
    for i in 0..warm {
        f(i);
    }
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        let t = Instant::now();
        f(i);
        out.push(t.elapsed());
    }
    out
}

// --- сам оракул -------------------------------------------------------------

/// Структурная и арифметическая половины строки §19.4: верны в обоих профилях и ни от какого
/// замера не зависят.
#[test]
fn assign_row_arithmetic_and_fixture_degeneracy() {
    // (1) Объём наблюдения: строка говорит «1024 int8 центроидов», и код даёт ровно столько.
    assert_eq!(CENTROID_BYTES, NLIST * DIM, "CENTROID_BYTES обязан быть NLIST × DIM");
    assert_eq!(CENTROID_BYTES, 393_216, "384 КиB — размер центрального файла (§7.1)");
    let grid = reference_grid();
    assert_eq!(grid.len(), CENTROID_BYTES, "эталонный набор обязан быть полным по размеру");
    assert!(grid.covers(NLIST as u16 - 1) && !grid.covers(NLIST as u16), "граница covers съехала");

    // (2) Дегенерация эталонной сетки: различных строк ровно `255 / НОД(DIM, 255)`.
    let expected_distinct = GRID_PERIOD / gcd(DIM, GRID_PERIOD);
    assert_eq!(gcd(DIM, GRID_PERIOD), 3, "НОД(384, 255) — арифметика, она не может «измениться»");
    assert_eq!(expected_distinct, 85, "ожидание пре-регистрации: 85 различных строк");
    let distinct_ref: HashSet<&[i8; DIM]> = (0..NLIST).map(|c| grid.row(c as u16)).collect();
    assert_eq!(
        distinct_ref.len(),
        expected_distinct,
        "число различных строк в эталонной сетке не совпало с арифметикой периода"
    );

    // (3) Фикстура полной энтропии обязана быть НЕвырожденной — иначе второй замер не про бой.
    let full = full_entropy_grid();
    let distinct_full: HashSet<&[i8; DIM]> = (0..NLIST).map(|c| full.row(c as u16)).collect();
    assert_eq!(
        distinct_full.len(),
        NLIST,
        "фикстура полной энтропии содержит повторы: замер относится не к тому набору"
    );
    assert_eq!(full.len(), CENTROID_BYTES, "оба набора обязаны иметь один объём байтов");

    // (4) Тождество трёх путей присваивания на 16 детерминированных запросах: `Centroids::assign`,
    //     голого `assign_cluster` по тем же строкам и `top(1)`. Если разойдутся — оракул меряет не
    //     ту операцию, о которой говорит строка §19.4.
    for seed in 0..16u64 {
        let q = query(0x51ED_0000 + seed);
        let a = grid.assign(&q);
        let rows = grid.rows();
        let b = assign_cluster(&q, &rows);
        let c = top_clusters(&q, &rows, 1);
        assert_eq!(a, b, "Centroids::assign разошёлся с assign_cluster при сиде {seed}");
        assert_eq!(c.first(), Some(&a), "top(1) разошёлся с assign при сиде {seed}");
        // Четвёртый путь — явный перебор `l2_sq`: оракул обязан мерить ту же операцию, о которой
        // говорит строка §19.4, а не то, что осталось от неё после рефакторинга.
        let mut best = u32::MAX;
        let mut brute = 0u16;
        for (i, row) in rows.iter().enumerate() {
            let d = l2_sq(&q, row);
            if d < best {
                best = d;
                brute = i as u16;
            }
        }
        assert_eq!(brute, a, "argmin по явным l2_sq разошёлся с assign_cluster при сиде {seed}");
        assert_eq!(a, reference_grid().assign(&q), "assign не детерминирован между двумя копиями фикстуры");
        black_box(b);
    }

    // (5) Целочисленно-плавающая арифметика строки, независимая от профиля: цена 1024 строк,
    //     пересчитанная из цены одной записи скана (`E-0081`, release, этот хост), и её запас до
    //     границы 150 мкс.
    let pred_lo = NLIST as f64 * SCAN_US_PER_RECORD_LO;
    let pred_hi = NLIST as f64 * SCAN_US_PER_RECORD_HI;
    assert!(
        (pred_lo - 56.75).abs() < 0.01 && (pred_hi - 61.25).abs() < 0.01,
        "предсказание цены assign уехало: [{pred_lo}; {pred_hi}] мкс вместо [56,75; 61,25]"
    );
    let margin_lo = ROW_TARGET_US / pred_hi;
    let margin_hi = ROW_TARGET_US / pred_lo;
    assert!(
        (margin_lo - 2.449).abs() < 0.01 && (margin_hi - 2.643).abs() < 0.01,
        "запас строки до predicted цены не тот: [{margin_lo}; {margin_hi}]×"
    );
    println!(
        "МЕРЕНО assign_struct_ok=1 row_target_us={ROW_TARGET_US} \
         pred_from_scan_lo_us={pred_lo:.3} pred_from_scan_hi_us={pred_hi:.3} \
         margin_lo_x={margin_lo:.3} margin_hi_x={margin_hi:.3} \
         distinct_rows_reference={} distinct_rows_full={} row_bytes={}",
        distinct_ref.len(),
        distinct_full.len(),
        DIM
    );
}

/// Боевая половина: цена `assign` в release, отношение фикстур, оверхед API и проверка правила 7.
#[test]
fn assign_row_price_in_release() {
    let release = !cfg!(debug_assertions);
    let profile = if release { "release" } else { "debug" };
    let warm = if release { 400 } else { 20 };
    let n = if release { 2000 } else { 40 };
    println!("=== §19.4 строка «cluster assign», профиль {profile}, выбросок {n} ===");

    let ref_grid = reference_grid();
    let full_grid = full_entropy_grid();
    let q = query(0xBEEF_0001);
    let rows_ref = ref_grid.rows();
    let rows_full = full_grid.rows();
    assert_ne!(rows_ref[0], rows_full[0], "фикстуры обязаны различаться — иначе оба замера один и тот же");
    assert_eq!(rows_ref.len(), NLIST);
    assert_eq!(rows_full.len(), NLIST);

    // (6) Цена одной строки скана арены (`E-0081`) против цены строки центроидов, измеренной тут.
    //     Отношение — размер окна на «тот же примитив, другая фикстура».
    let t_full = sample(warm, n, |i| {
        black_box(assign_cluster(&q, &rows_full));
        black_box(i);
    });
    let p_full = median(&t_full);
    let per_row_us = us(p_full) / NLIST as f64;
    let ratio_to_scan_lo = per_row_us / SCAN_US_PER_RECORD_HI;
    let ratio_to_scan_hi = per_row_us / SCAN_US_PER_RECORD_LO;
    println!(
        "МЕРЕНО assign_full_p50_us={:.3} assign_full_per_row_us={:.5} \
         ratio_to_scan_lo={:.3} ratio_to_scan_hi={:.3} full_spread_promil={:.1}",
        us(p_full),
        per_row_us,
        ratio_to_scan_lo,
        ratio_to_scan_hi,
        spread_pmk(&t_full)
    );

    // (7) Цена assign на эталонной сетке (85 различных строк, 32 КиБ) — отношение к полной сетке.
    let t_ref = sample(warm, n, |i| {
        black_box(assign_cluster(&q, &rows_ref));
        black_box(i);
    });
    let p_ref = median(&t_ref);
    let cache_ratio = us(p_ref) / us(p_full);
    println!(
        "МЕРЕНО assign_reference_p50_us={:.3} reference_to_full_x={:.3} ref_spread_promil={:.1}",
        us(p_ref),
        cache_ratio,
        spread_pmk(&t_ref)
    );

    // (8) Оверхед API: `Centroids::assign` строит `rows()` при каждом вызове (1024 ссылки = 8 КиБ).
    let t_api = sample(warm, n, |i| {
        black_box(full_grid.assign(&q));
        black_box(i);
    });
    let p_api = median(&t_api);
    let rows_overhead = us(p_api) / us(p_full);
    println!(
        "МЕРЕНО assign_api_p50_us={:.3} rows_overhead_x={:.3} api_spread_promil={:.1}",
        us(p_api),
        rows_overhead,
        spread_pmk(&t_api)
    );

    // (9) `top(16)` — то, что в бою платит агент (§7.5): тот же объём `l2_sq` плюс сортировка.
    let t_top = sample(warm, n / 2, |i| {
        black_box(top_clusters(&q, &rows_full, 16));
        black_box(i);
    });
    let p_top = median(&t_top);
    let top_ratio = us(p_top) / us(p_full);
    println!(
        "МЕРЕНО top16_p50_us={:.3} top16_to_assign_x={:.3} top_spread_promil={:.1}",
        us(p_top),
        top_ratio,
        spread_pmk(&t_top)
    );

    // (10) Линейность по числу строк: 256 и 512 против 1024. Если отношение к 1024 не ~1/4 и
    //      ~1/2 — цену определяет кеш, а не арифметика, и вывод про фикстуру надо читать так.
    let mut lin = Vec::new();
    for count in [256usize, 512, 1024] {
        let sub: Vec<&[i8; DIM]> = rows_full[..count].to_vec();
        let t = sample(warm, n, |i| {
            black_box(assign_cluster(&q, &sub));
            black_box(i);
        });
        let p = median(&t);
        lin.push((count, us(p)));
        println!(
            "МЕРЕНО assign_line_rows={} assign_line_p50_us={:.3} assign_line_per_row_us={:.5}",
            count,
            us(p),
            us(p) / count as f64
        );
    }
    let r_512 = lin[1].1 / lin[2].1;
    let r_256 = lin[0].1 / lin[2].1;

    // Номера в комментариях = номера порогов пре-регистрации H-0083. Порядок assert'ов осмысленный:
    // сначала гейт самой строки (§19.4 «< 0,15 мс»), потом отношения, и только в конце —
    // фальсификатор (6). В n=1 фальсификатор стоял раньше, паниковал на себе и оставлял (5), (7)
    // и (8) неисполненными: числа печатались, но ни один из них не был проверен инструментом
    // (ДИАГНОЗ-1). Пороги от этого не двигались.
    if release {
        // (4) Санити: цена обязана лежать в правдоподобном интервале, а не на порядках мимо.
        let san = us(p_full);
        assert!((10.0..1000.0).contains(&san), "цена assign вне правдоподобного интервала: {san} мкс");
        let margin = ROW_TARGET_US / us(p_full) - 1.0;
        let rel_spread = spread_pmk(&t_full) / 1000.0;
        println!(
            "МЕРЕНО assign_margin_x={:.3} assign_rel_spread_x={:.4} assign_gate7_ok={}",
            margin,
            rel_spread,
            if margin >= 2.0 * rel_spread { 1 } else { 0 }
        );
        // (5) Главный гейт строки по правилу 7: запас до границы 150 мкс обязан быть шире
        //     внутреннего разброса инструмента. Гейт сформулирован отношением, а не «меньше числа».
        assert!(
            margin >= 2.0 * rel_spread,
            "правило 7: запас до границы строки ({margin:.3}) уже разброса инструмента ({:.3})",
            2.0 * rel_spread
        );
        assert!(
            us(p_full) < ROW_TARGET_US,
            "строка §19.4 нарушена боевой фикстурой: {:.3} мкс при цели {ROW_TARGET_US} мкс",
            us(p_full)
        );
        // (7) Оверхед API и сортировки обязаны быть малыми отношениями, а не абсолютными числами.
        assert!(
            rows_overhead <= 1.15,
            "построение rows() стоит дороже 15 % самого assign: {rows_overhead:.3}"
        );
        assert!(
            (1.0..=1.5).contains(&top_ratio),
            "top(16) против assign: отношение {top_ratio:.3} вне замороженного [1,0; 1,5]"
        );
        // (8) Цена строки центроидов и цена строки скана — один примитив на одном железе.
        assert!(
            (0.6..=1.6).contains(&ratio_to_scan_lo) && (0.6..=1.6).contains(&ratio_to_scan_hi),
            "цена строки центроидов ушла от цены записи скана: [{ratio_to_scan_lo}; {ratio_to_scan_hi}]"
        );
        // (8) Линейность: половина строк стоит от 0,35 до 0,65 полной цены, четверть — 0,15…0,32.
        assert!(
            (0.35..=0.65).contains(&r_512),
            "цена 512 строк относится к 1024 как {r_512:.3} — арифметика не линейна по числу строк"
        );
        assert!(
            (0.15..=0.32).contains(&r_256),
            "цена 256 строк относится к 1024 как {r_256:.3} — кеш определяет цену, а не число векторов"
        );
        // (6) Фальсификатор главной находки цикла: эталонная сетка (85 различных строк, 32 640
        //     живых байтов) обязана быть ДЕШЕВЛЕ боевой (393 216 Б) минимум на 10 %. Граница 0,90
        //     заморожена и остаётся ровно той же; в n=1 и n=2 порог НЕ ВЫПОЛНЕН (0,919…1,020
        //     пятью release-наблюдениями), гипотеза мертва. С ДИАГНОЗ-2 assert превращён в отчёт
        //     по предцеденту `E-0082` (ДИАГНОЗ-4): вечный красный в инструменте маскирует
        //     настоящий сигнал, а вердикт порога уже записан в логе и в `E-0083`.
        println!(
            "МЕРЕНО assign_cache_gate6_x={:.3} assign_cache_gate6_limit_x=0.900 assign_cache_gate6_verdict={}",
            cache_ratio,
            if cache_ratio <= 0.90 { "holds" } else { "refuted" }
        );
        println!("МЕРЕНО assign_release_gates=ok");
    } else {
        println!(
            "debug: временные гейты (4)…(8) пропущены по профилю; проверка — \
             cargo test --release -p vecdht-index --test s19_assign_row_price"
        );
    }
}
