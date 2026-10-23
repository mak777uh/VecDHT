//! Строка §19.4 «PoW: генерация / verify ≈150–350 мс / ≈0,14–0,33 мкс» — цель кода или снимок
//! одного хоста?
//!
//! Это отдельный test-таргет по той же причине, что и `search_latency`: замер в общем процессе
//! глушится соседними тестами, которые аллоцируют арены и пилят диск. Время гейтуется только в
//! релизной сборке (§19.4 — контракт боевого профиля, см. правило «профиль — часть заморозки» в
//! `lab/PLAN.md`), в debug остаются арифметика и инварианты: они от профиля не зависят.
//!
//! Единицы. Вся дробная арифметика сведена к целым сравнениям, чтобы оракул не спорил с
//! округлением IEEE-754. Скорость blake3 на ядро хранится как `r100` = МХеш/с × 100 (7,09 → 709),
//! тогда
//! * `gen_ms(bits, r)  =  2^bits / (10 · r100)` — попыток `2^bits`, по одному хешу на попытку;
//! * `verify_us(r)     =  100 / r100`, а в наносекундах — `verify_ns(r) = 100 000 / r100`.
//!
//! Обе формулы выводятся из одного и того же `r100`, поэтому
//! `gen_ms · 1000 = 2^bits · verify_us` — тождество единиц, а не свойство протокола: обе половины
//! строки §19.4 — это два способа напечатать ОДНУ калибровку.
//!
//! Коридор строки переводится на `r100` без деления:
//! * генерация ∈ [150; 350] мс ⟺ `1500 · r100 ≤ 2^bits ≤ 3500 · r100`;
//! * verify ∈ [0,14; 0,33] мкс ⟺ `140 · r100 ≤ 100 000 ≤ 330 · r100`.
//!
//! Отсюда главный вопрос цикла: коридоры двух половин строки НЕ совпадают (первый — это
//! `r ∈ [2,996; 6,990]` МГц, второй — `r ∈ [3,030; 7,143]`), значит найдётся скорость, которая
//! удовлетворяет половине строки и нарушает другую. Такой скоростью оказывается заголовок самого
//! §19.5 (7,09 МХеш/с) и константа, которую везёт код (`BLAKE3_MHZ_CORE_FALLBACK = 7.0`).
//!
//! Профиль. Живой замер гейтует только релиз (§19.4 — контракт боевого профиля, правило 6
//! «профиль — часть заморозки» в `lab/PLAN.md`). В debug перебор `2^24` попыток стоит ~55 с на
//! отсчёт, поэтому в этом профиле остаётся одна дешёвая точка (`POW_BITS_MIN`) и вся целочисленная
//! арифметика сетки: она от профиля не зависит.

use std::hint::black_box;
use std::time::Instant;

use vecdht_crypto::pow::{
    expected_millis, mine_pow, pow_input, pow_ok, BLAKE3_MHZ_CORE_FALLBACK, POW_BITS_DEFAULT,
    POW_BITS_MAX, POW_BITS_MIN,
};

/// Документированные скорости blake3 на ядро: §19.5 (два прогона 2026-10-19), его же сноска про
/// загруженный хост 2026-10-20 (два края) и константа, зашитая в код (§11.1).
const RATES: [(u64, &str); 5] = [
    (709, "§19.5 pow_ok 2026-10-19, прогон 1"),
    (668, "§19.5 pow_ok 2026-10-19, прогон 2"),
    (373, "§19.5 сноска 2026-10-20, верх"),
    (301, "§19.5 сноска 2026-10-20, низ"),
    (700, "BLAKE3_MHZ_CORE_FALLBACK (§11.1)"),
];

/// Коридор §19.4 в целых единицах: мс для генерации, нс для проверки.
const GEN_LO: u64 = 150;
const GEN_HI: u64 = 350;
const VERIFY_LO_NS: u64 = 140;
const VERIFY_HI_NS: u64 = 330;

/// Детерминированный старт перебора (§11.1): один `start` ⇒ один принятый nonce ⇒ один и тот же
/// объём работы в обоих профилях. Профили обязаны расходиться только часами.
const START: u64 = 0x5EED_1904_0000_0000;

/// Повторов timed-замера на каждый бит: хватает на медиану из трёх и не тонет в 2^24 попытках.
const SAMPLES: usize = 3;

/// Попыток в timed-замере `verify`: 100 000 ≈ 13 мс CPU в бою, пакетов 10 ⇒ медиана по пакетам.
const VERIFY_BATCH: usize = 10_000;
const VERIFY_BATCHES: usize = 10;

fn gen_in_corridor(bits: u32, r100: u64) -> bool {
    let attempts = 1u128 << bits;
    GEN_LO as u128 * 10 * r100 as u128 <= attempts && attempts <= GEN_HI as u128 * 10 * r100 as u128
}

fn verify_in_corridor(r100: u64) -> bool {
    VERIFY_LO_NS as u128 * r100 as u128 <= 100_000 && 100_000 <= VERIFY_HI_NS as u128 * r100 as u128
}

/// Обе половины строки сразу — то, что §19.4 обещает узлу целиком, а не по одному слову.
fn both_in_corridor(bits: u32, r100: u64) -> bool {
    gen_in_corridor(bits, r100) && verify_in_corridor(r100)
}

/// Формула оракула против формулы продукта: `expected_millis` обязана совпадать с целым выводом
/// до последнего бита мантиссы, иначе арифметика цикла относится к другому коду.
fn code_and_model_agree(bits: u32, r100: u64) -> bool {
    let model = (1u128 << bits) as f64 / (10.0 * r100 as f64);
    let code = expected_millis(bits, r100 as f64 / 100.0);
    ((code - model) / model).abs() < 1e-12
}

fn median_ns(samples: &mut [u64]) -> u64 {
    samples.sort_unstable();
    samples[samples.len() / 2]
}

fn input() -> Vec<u8> {
    pow_input(
        &[0x5A; 32],
        7,
        3,
        &[0xB2; 32],
        1234,
    )
}

#[test]
fn pow_row_of_19_4_is_a_host_snapshot_not_a_code_gate() {
    let profile = if cfg!(debug_assertions) { "debug" } else { "release" };
    println!("=== §19.4 строка PoW, профиль {profile} ===");

    // (1) Половины строки — одна калибровка в двух единицах. Проверяется тождество единиц и
    // согласие формулы продукта с моделью оракула.
    for (r100, why) in RATES {
        assert!(code_and_model_agree(POW_BITS_DEFAULT, r100), "формула продукта разошлась с моделью при r100={r100}");
        let gen_us = expected_millis(POW_BITS_DEFAULT, r100 as f64 / 100.0) * 1000.0;
        let want = (1u128 << POW_BITS_DEFAULT) as f64 * (100.0 / r100 as f64);
        assert!(
            ((gen_us - want) / want).abs() < 1e-9,
            "генерация в мкс ≠ 2^bits × verify: {gen_us} vs {want}"
        );
        println!(
            "    r100={r100} ← {why}: ген {:.2} мс, verify {:.1} нс",
            expected_millis(POW_BITS_DEFAULT, r100 as f64 / 100.0),
            100_000.0 / r100 as f64
        );
    }
    println!("(1) тождество `gen_ms · 1000 = 2^bits · verify_us` выполнено для всех {} скоростей", RATES.len());

    // (2) Коридоры двух половин строки различаются: есть скорости, которые проходят verify и не
    // проходят генерацию. Именно они — заголовок §19.5 и константа кода.
    let only_verify: Vec<String> = RATES
        .iter()
        .filter(|(r100, _)| verify_in_corridor(*r100) && !gen_in_corridor(POW_BITS_DEFAULT, *r100))
        .map(|(r100, why)| format!("{} МХеш/с ({why}) → ген {:.1} мс, verify {:.1} нс", *r100 as f64 / 100.0, expected_millis(POW_BITS_DEFAULT, *r100 as f64 / 100.0), 100_000.0 / *r100 as f64))
        .collect();
    println!("(2) скоростей, годных для verify и не годных для генерации: {}", only_verify.len());
    for line in &only_verify {
        println!("    {line}");
    }
    assert!(
        only_verify.iter().any(|l| l.contains("7.09")),
        "ожидалось, что заголовок §19.5 (7,09 МХеш/с) попадает в этот список"
    );
    assert!(
        !gen_in_corridor(POW_BITS_DEFAULT, 700),
        "ожидалось, что константа кода 7,0 МХеш/с даёт генерацию НИЖЕ пола §19.4"
    );
    assert!(verify_in_corridor(700), "при 7,0 МХеш/с verify обязан оставаться в коридоре");
    println!(
        "    код при своей константе: ген {:.2} мс (пол строки {GEN_LO}), verify {:.1} нс (пол {})",
        expected_millis(POW_BITS_DEFAULT, BLAKE3_MHZ_CORE_FALLBACK),
        100_000.0 / 700.0,
        VERIFY_LO_NS
    );

    // (3) Перебор сетки «7 бит × 5 скоростей»: сколько ячеек попадают в коридор генерации, и
    // где лежит default. Утверждение точное до ячейки — его можно опровергнуть одной цифрой.
    let mut cells = 0usize;
    let mut inside_bits: Vec<u32> = Vec::new();
    for bits in POW_BITS_MIN..=POW_BITS_MAX {
        let n = RATES.iter().filter(|(r100, _)| gen_in_corridor(bits, *r100)).count();
        cells += n;
        if n > 0 {
            inside_bits.push(bits);
        }
        println!("    bits={bits}: в коридоре {n} из {} скоростей", RATES.len());
    }
    println!("(3) ячеек в коридоре {cells} из {}", (POW_BITS_MAX - POW_BITS_MIN + 1) as usize * RATES.len());
    // Сверка руками (2^19/3010 = 174,2; 2^20/3010 = 348,4; 2^20/3730 = 281,1;
    // 2^20/6680 = 156,9; 2^21/6680 = 313,9; 2^21/7000 = 299,6; 2^21/7090 = 295,8) — ровно эти
    // семь ячеек попадают в [150; 350] мс.
    assert_eq!(cells, 7, "перебор сетки дал не те 7 ячеек — арифметика цикла поехала");
    assert_eq!(inside_bits, vec![19, 20, 21], "коридор §19.4 накрывает не те биты");
    assert!(
        !RATES.iter().any(|(r100, _)| gen_in_corridor(POW_BITS_MIN, *r100)),
        "низ адаптивности (18 бит = 34–87 мс по §11.2) обязан быть дешевле пола строки при любой скорости"
    );
    assert!(
        !RATES.iter().any(|(r100, _)| gen_in_corridor(POW_BITS_MAX, *r100)),
        "верх адаптивности (24 бита) обязан быть дороже потолка строки при любой скорости"
    );
    let inside_default: Vec<u64> = RATES.iter().filter(|(r100, _)| gen_in_corridor(POW_BITS_DEFAULT, *r100)).map(|(r, _)| *r).collect();
    assert_eq!(inside_default, [668, 373, 301], "default inside коридора обязан быть ровно при 6,68 / 3,73 / 3,01 (в порядке объявления RATES)");
    assert!(
        !gen_in_corridor(POW_BITS_MAX, 709) && !gen_in_corridor(POW_BITS_MAX, 301),
        "верх адаптивности обязан быть выше потолка строки при любой документированной скорости"
    );

    // (3б) Тот же перебор, но для строки ЦЕЛИКОМ — ячейки, где годны обе половины. Пересечение
    // коридоров на целых это [304; 699] (низ — `ceil(100 000/330)`, верх — `floor(2^20/1500)`), и
    // оно уже каждого из двух коридоров по отдельности: 709 и 700 (заголовок §19.5 и константа
    // кода) в него не входят, 301 не входит снизу. Ровно две из пяти документированных скоростей
    // выдерживают строку при default-битах — это и есть ответ на вопрос «при скольких битах и при
    // какой скорости строку надо перечитывать».
    let mut both_cells = 0usize;
    for bits in POW_BITS_MIN..=POW_BITS_MAX {
        let n = RATES.iter().filter(|(r100, _)| both_in_corridor(bits, *r100)).count();
        both_cells += n;
        println!("    bits={bits}: обе половины строки выдерживают {n} из {} скоростей", RATES.len());
    }
    assert_eq!(both_cells, 5, "пересечение половин строки даёт не 5 ячеек из 35 — арифметика поехала");
    let both_default: Vec<u64> = RATES
        .iter()
        .filter(|(r100, _)| both_in_corridor(POW_BITS_DEFAULT, *r100))
        .map(|(r, _)| *r)
        .collect();
    assert_eq!(both_default, [668, 373], "при default-битах строку целиком выдерживают не те скорости");
    assert!(
        both_in_corridor(21, 709) && both_in_corridor(21, 700),
        "7,09 и 7,0 МХеш/с входят в пересечение при 21 бите — иначе вывод был бы «строка недостижима», а не «строка про другие биты»"
    );
    assert!(
        !both_in_corridor(21, 301) && !both_in_corridor(21, 373),
        "нижние скорости при 21 бите обязаны выпадать по генерации"
    );
    println!(
        "(3б) ячеек «обе половины» {} из {}; при default — {both_default:?}; 7,09 и 7,0 входят только при 21 бите",
        both_cells,
        (POW_BITS_MAX - POW_BITS_MIN + 1) as usize * RATES.len()
    );

    // (4) Живой замер. Единицы: §19.4 говорит об ОЖИДАЕМОЙ цене `2^bits` попыток, а
    // детерминированный старт даёт фактический объём работы (при `START` это 1,85× от `2^20`),
    // поэтому сравнение с коридором ведётся по норме «нс на попытку × 2^bits», а не по сырым
    // наносекундам конкретного перебора. Это же исправление ловит и обратную ошибку — старт,
    // который везёт в 0,35× (24 бита ниже).
    let inp = input();
    const GEN_BITS: [u32; 3] = [POW_BITS_MIN, POW_BITS_DEFAULT, POW_BITS_MAX];
    // В debug дорогую точку не снимаем: `2^24` попыток по ~600 нс — это ~55 с на один отсчёт, а
    // вывод цикла про боевую шкалу. Нижняя точка остаётся, чтобы печать (4) была осмысленной и в
    // debug-прогоне воркспейса.
    let bits_list: &[u32] = if cfg!(debug_assertions) { &GEN_BITS[..1] } else { &GEN_BITS };
    let mut rows: Vec<(u32, u64, u64, u64)> = Vec::new();
    let mut est_ms: Vec<(u32, u64)> = Vec::new();
    for &bits in bits_list {
        let mut times: Vec<u64> = Vec::new();
        let mut nonce0 = 0u64;
        for _ in 0..SAMPLES {
            let t = Instant::now();
            let nonce = mine_pow(&inp, bits, START, u64::MAX).expect("перебор обязан найти nonce");
            times.push(t.elapsed().as_nanos() as u64);
            if nonce0 == 0 {
                nonce0 = nonce;
            } else {
                assert_eq!(nonce0, nonce, "детерминированный старт дал разный nonce");
            }
        }
        let attempts = nonce0 - START + 1;
        let med = median_ns(&mut times);
        let ns_per_attempt = med / attempts;
        let expected = 1u128 << bits;
        let est = expected as u64 * ns_per_attempt;
        est_ms.push((bits, est / 1_000_000));
        rows.push((bits, nonce0, attempts, ns_per_attempt));
        println!(
            "    gen bits={bits}: nonce {nonce0}, попыток {attempts} ({:.2}× от ожидаемых), \
             медиана {:.1} мс, {ns_per_attempt} нс/попытка → ожидаемая цена {:.1} мс, \
             фактическая скорость {:.2} МХеш/с",
            attempts as f64 / expected as f64,
            med as f64 / 1e6,
            est as f64 / 1e6,
            attempts as f64 / (med as f64 / 1e9) / 1e6
        );
    }
    let est_at = |bits: u32| -> u64 {
        *est_ms
            .iter()
            .find(|(b, _)| *b == bits)
            .map(|(_, v)| v)
            .unwrap_or_else(|| panic!("нет замера при {bits} битах"))
    };
    let ns_at = |bits: u32| -> u64 {
        rows.iter()
            .find(|(b, ..)| *b == bits)
            .map(|(_, _, _, ns)| *ns)
            .unwrap_or_else(|| panic!("нет замера при {bits} битах"))
    };

    // (5) verify в бою: тот же примитив, чем гейтуется приём кадра (§11.3), но на 100 000 попыток
    // и с прогревом — иначе цифра относится к разгону частоты (§19.5, сноска о методе).
    for _ in 0..100 {
        for k in 0..VERIFY_BATCH as u64 {
            black_box(pow_ok(&inp, START.wrapping_add(k), POW_BITS_DEFAULT));
        }
    }
    let mut batch_ns: Vec<u64> = Vec::new();
    for b in 0..VERIFY_BATCHES {
        let t = Instant::now();
        for k in 0..VERIFY_BATCH as u64 {
            black_box(pow_ok(&inp, START.wrapping_add(b as u64 * VERIFY_BATCH as u64 + k), POW_BITS_DEFAULT));
        }
        batch_ns.push(t.elapsed().as_nanos() as u64 / VERIFY_BATCH as u64);
    }
    let verify_med = median_ns(&mut batch_ns);
    println!("    verify: медиана {verify_med} нс/вызов → скорость {:.2} МХеш/с", 1000.0 / verify_med as f64);

    if cfg!(debug_assertions) {
        println!(
            "(6) временные гейты пропущены: профиль debug, {} нс/попытка — это профиль, а не бой \
             (ср. `E-0079` против `E-0081`).",
            verify_med
        );
        assert!(verify_med > 0);
        return;
    }

    // (6) Предсказание цикла: на этом хосте обе половины строки §19.4 лежат НИЖЕ своих полов,
    // а концы адаптивного диапазона — снаружи коридора с обеих сторон. Величины нормированы к
    // ожидаемому объёму работы `2^bits` (см. (4)); числовые границы заморожены из `E-0081`
    // (release: 130,4 и 124,5 нс/попытка ⇒ 136,7 и 130,5 мс при 2^20), а не из этого прогона.
    let est20 = est_at(POW_BITS_DEFAULT);
    let est18 = est_at(POW_BITS_MIN);
    let est24 = est_at(POW_BITS_MAX);
    assert!(est20 < GEN_LO, "ожидалось, что ожидаемая цена генерации при default дешевле пола §19.4, получено {est20} мс");
    assert!(est18 < GEN_LO, "низ адаптивности ({} бит) обязан быть дешевле пола строки", POW_BITS_MIN);
    assert!(est24 > GEN_HI, "верх адаптивности ({} бит) обязан быть дороже потолка строки", POW_BITS_MAX);
    assert!(verify_med < VERIFY_LO_NS, "ожидалось, что verify дешевле пола строки на этом хосте, получено {verify_med} нс");

    // (6б) Скорость хоста, выраженная той же единицей, что и вся строка: `r100 = 100 000 / нс`.
    // Замороженное ожидание: боевой профиль выносит хост ЗА верхний край всей строки
    // (`r100 > 714` — из `E-0081`: 124,5…130,4 нс/попытка ⇒ `r100` = 767…803), то есть §19.4
    // описывает хост 2026-10-19 в профиле, которого у кода больше нет.
    let meas_r100 = 100_000 / verify_med;
    assert!(
        meas_r100 > 714,
        "ожидалось, что release-скорость этого хоста выше потолка всей строки (r100 > 714), получено {meas_r100} (verify {verify_med} нс)"
    );
    assert!(
        !both_in_corridor(POW_BITS_DEFAULT, meas_r100),
        "при измеренной скорости строка обязана не выполняться целиком"
    );

    // Санити-интервалы: вне их замер относится к сломанному инструменту, а не к бою.
    assert!((80u64..400).contains(&est20), "ожидаемая цена default вне правдоподобного интервала: {est20} мс");
    assert!((20u64..100).contains(&est18), "18 бит вне интервала: {est18} мс");
    assert!((1_500u64..5_000).contains(&est24), "24 бита вне интервала: {est24} мс");
    assert!((40..600).contains(&verify_med), "verify вне интервала: {verify_med} нс");

    // (7) Два разных сэмплера мерят одну и ту же стоимость `pow_ok`: полный перебор против
    // пакетного цикла. Расхождение больше 10 % значит, что один из них платит за что-то ещё
    // (прогрев кеша, аллокацию входа, шум планировщика) — и тогда сравнение с §19.4 нечестно.
    let mine_ns = ns_at(POW_BITS_DEFAULT);
    let drift = (mine_ns as f64 / verify_med as f64 - 1.0).abs();
    assert!(drift < 0.10, "сэмплеры разошлись: {mine_ns} нс/попытка против {verify_med} нс/вызов ({:.1} %)", drift * 100.0);
    println!(
        "(6,7) гейты release зелёные: ожидаемая цена default = {est20} мс < пол {GEN_LO}, \
         низ адаптивности {est18} мс, верх {est24} мс (при потолке строки {GEN_HI}); verify = {verify_med} нс \
         < пол {VERIFY_LO_NS}; скорость хоста r100 = {meas_r100} > 714 (за всей строкой); \
         два сэмплера сходятся с разбросом {:.1} %",
        drift * 100.0
    );

    println!("печать (bits, nonce, попыток, нс/попытка) для сверки профилей: {rows:?}");
}
