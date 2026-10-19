//! Замеры wire-слоя: скорость кодека, реальная цена publish-PoW (§11.1–11.2) и проверки подписи.
//!
//! Главный продукт этого прогона — не «быстро/медленно», а число `blake3`-хешей короткого входа за
//! секунду на одно ядро. Именно оно кладётся в артефакт как `power.blake3_mhz_core`, и именно оно
//! определяет, сколько стоит publish. Спека в §11.1 обещала «≈84 мс» на 2²⁴ попытках, и это
//! обещание надо либо подтвердить замером, либо исправить в спеке — третьего варианта нет.
//!
//! Что показал прогон (release, x86_64-windows-gnu, одно ядро): `pow_ok` = 7.0 МХеш/с 2026-10-19 и
//! 3.7 МХеш/с на следующий день на том же стенде, ed25519 `verify_body` ≈ 19 000/с. По первому
//! числу пересняты `POW_BITS_*` и `BLAKE3_MHZ_CORE_FALLBACK` в `vecdht-crypto::pow` и §11.1 спеки;
//! второе — прямое доказательство, что это калибровочное число принадлежит стенду, а не протоколу,
//! и что артефакт обязан калиброваться прогоном оператора (§15.1), а не этим стендом.
//! Предположение «200 МХеш/с» относилось к скорости blake3 на потоковых больших входах, а PoW
//! хешает ~100-байтный вход, где цену даёт фиксированная стоимость вызова и двух компрессий.

use std::time::Instant;

use vecdht_crypto::pow::{
    BLAKE3_MHZ_CORE_FALLBACK, POW_BITS_DEFAULT, POW_BITS_MAX, expected_millis, pow_input, pow_ok,
};
use vecdht_crypto::sig::{Identity, verify_body};
use vecdht_wire::messages::{Codec, Find, Publish};
use vecdht_wire::{DIM, Kind};

use vecdht_benches::{Sink, header, rate, scale, value};

/// Вариантов входа на каждый вид кадра. Нужно, чтобы измеряемый цикл не оказался loop-invariant:
/// с одним и тем же байтовым буфером внутри цикла LLVM выносит декод за его пределы, и печать
/// показала бы «150 млн кадров/с» — измерение оптимизатора, а не кодека.
const VARIANTS: usize = 16;

/// Методика: перед таймером делается прогретый проход той же работы — четверть измеряемого объёма.
/// Короткий прогон (масштаб по умолчанию) без прогрева печатал 5.6 МХеш/с там, где длинный даёт
/// 7.0, — разница про состояние стенда, а не про код, и в спеку такое число переносить нельзя.
const WARMUP_DIV: usize = 4;

/// Нижняя граница цикла, из которого берётся калибровочное число. Прогрев достаточно длинный, но
/// сам измеряемый проход коротким быть не может: на этом же стенде 200 000 попыток давали
/// 1,1–1,8 МХеш/с, а 2 000 000 — 3,7 при том же коде и том же диске. Разница — разгон частоты и
/// прогретый кеш, а не скорость кода, и по такому заниженному числу оператор выставил бы publish
/// в 3–4 раза дороже, чем задумано. Поэтому калибровка меряется на насыщении, а короткий прогон
/// печатается рядом — чтобы этот эффект был виден в выводе, а не только в комментарии.
const CALIBRATION_MIN: usize = 2_000_000;

fn main() {
    let k = scale();
    header("wire", "кодек кадров, цена publish-PoW (§11.2) и проверки подписи (§4.3)");

    // 1. blake3 на входах PoW. `pow_ok` — это ровно то, что делает переборщик на каждую попытку,
    //    поэтому мерим её, а не «голый» blake3: в цену входит и сравнение с целью.
    let input = pow_input(&[0xA1; 32], 7, 3, &[0xB2; 32], 1_234);
    let mut sink = Sink::default();
    for n in 0..(CALIBRATION_MIN / WARMUP_DIV) as u64 {
        sink.add(u64::from(pow_ok(&input, n, POW_BITS_MAX)));
    }
    // Две длины одного цикла: масштабом управляемая (её число — не калибровка) и насыщенная.
    // При крупном масштабе они совпадают, и тогда второй прогон не запускается — мерить одно и то
    // же дважды смысла нет, а вот сравнить короткий с насыщенным надо.
    let short_hashes = 100_000 * k;
    let long_hashes = CALIBRATION_MIN.max(short_hashes);
    let mut passes = vec![short_hashes];
    if long_hashes != short_hashes {
        passes.push(long_hashes);
    }
    let mut mhz = 0.0;
    let mut short_mhz = 0.0;
    let mut short_elapsed = std::time::Duration::ZERO;
    for (i, &hashes) in passes.iter().enumerate() {
        let start = Instant::now();
        for n in 0..hashes as u64 {
            sink.add(u64::from(pow_ok(&input, n, POW_BITS_MAX)));
        }
        let elapsed = start.elapsed();
        let v = hashes as f64 / elapsed.as_secs_f64() / 1e6;
        rate("pow_ok (один blake3 на попытку)", hashes, elapsed);
        if i + 1 == passes.len() {
            mhz = v;
        } else {
            (short_mhz, short_elapsed) = (v, elapsed);
        }
    }
    if short_mhz > 0.0 {
        println!(
            "прогрев: короткий прогон {} попыток за {:.0} мс даёт {short_mhz:.2}, насыщенный — {mhz:.2} МХеш/с (в {:.2}× быстрее); калибровочное число берётся с насыщения (§15.1)",
            short_hashes,
            short_elapsed.as_secs_f64() * 1e3,
            mhz / short_mhz
        );
    }
    value("скорость для §11.2 (калibr., насыщенный цикл)", mhz, "МХеш/с на ядро");
    // Фолбэк-константа crate'а — это тоже измерение, но снятое в другом прогоне. Расхождение в
    // десятки процентов — норма разных дисков/CPU; расхождение в порядок значит, что калибровать
    // артефакт обязан прогон оператора (§15.1), а не этот стенд.
    let ratio = (BLAKE3_MHZ_CORE_FALLBACK / mhz.max(1e-9)).max(mhz.max(1e-9) / BLAKE3_MHZ_CORE_FALLBACK);
    println!(
        "BLAKE3_MHZ_CORE_FALLBACK = {BLAKE3_MHZ_CORE_FALLBACK:.1}, измерено сейчас {mhz:.1} → \
         расходимость оценки стоимости publish в {ratio:.2}×"
    );
    for bits in [POW_BITS_DEFAULT, POW_BITS_DEFAULT + 2, POW_BITS_MAX] {
        println!(
            "bits {bits}: ожидание по константе {:.0} мс, по текущему замеру {:.0} мс",
            expected_millis(bits, BLAKE3_MHZ_CORE_FALLBACK),
            expected_millis(bits, mhz)
        );
    }
    sink.commit("pow");
    // Отдельно про ноль в этой контрольной сумме: при цели 2²⁴ даже миллионы подряд идущих nonce
    // не дают ни одного попадания в принципе, так что ноль — следствие выбранных бит, а не признак
    // вырезанного цикла. Вырезать его нельзя: результат идёт единственному потребителю —
    // аккумулятору.

    // 2. Кодек целиком: `X::decode` = сверка заголовка и версии + границы + тело. Узел на каждом
    //    принятом кадре зовёт именно его (§5.3), а не «голый» `decode_frame`. `Publish` — самый
    //    частый кадр записи, `Find` — самый частый кадр запроса.
    let publish = Publish {
        preprocessing_version: 1,
        cluster_id: 777,
        vec_q: [3i8; DIM],
        owner_ed25519: [0xA1; 32],
        ttl_buckets: 225,
        published_bucket: 1_000_000,
        pow_bits: POW_BITS_DEFAULT as u8,
        pow_nonce: 42,
        intent_id: [0xB2; 32],
        tlv: vec![],
    };
    let find = Find {
        preprocessing_version: 1,
        query_vector: [7i8; DIM],
        clusters: (0..16).collect(),
        top_k: 32,
        query_id: 1,
        requester_ed25519: [0xC3; 32],
        tlv: vec![],
    };
    let publish_frames: Vec<Vec<u8>> = (0..VARIANTS)
        .map(|i| {
            let mut p = publish.clone();
            p.cluster_id = 777 + i as u16;
            p.ttl_buckets = 225 + i as u16;
            p.pow_nonce = i as u64;
            p.encode_unsigned()
        })
        .collect();
    let find_frames: Vec<Vec<u8>> = (0..VARIANTS)
        .map(|i| {
            let mut f = find.clone();
            f.query_id = i as u64;
            f.top_k = 1 + i as u16;
            f.encode_unsigned()
        })
        .collect();

    // Аккумулятор смешивает распарсенные поля, а не длины. Если складывать только `bytes.len()` и
    // `body.len()`, компилятор выводит результат из длины входа и тело не парсится вовсе —
    // прогон печатал бы 149 млн кадров/с.
    let frames = 20_000usize * k;
    let mut s = Sink::default();
    for i in 0..frames / WARMUP_DIV {
        let p = Publish::decode(&publish_frames[i % VARIANTS]).expect("кадр обязан декодироваться");
        s.add(u64::from(p.cluster_id) ^ p.pow_nonce);
    }
    let t = Instant::now();
    for i in 0..frames {
        let p = Publish::decode(&publish_frames[i % VARIANTS]).expect("кадр обязан декодироваться");
        s.add(u64::from(p.cluster_id));
        s.add(p.pow_nonce);
        s.add(u64::from(p.ttl_buckets));
        // Сумма по всему вектору: читать только `vec_q[0]` — значит разрешить компилятору не
        // копировать остальные 383 байта, а копирование входа и есть основная работа декодера
        // (§5.3). Свёртка по массиву дешевле парсинга, поэтому число остаётся консервативным.
        s.add(p.vec_q.iter().fold(0u64, |a, b| a.wrapping_add(u64::from(*b as u8))));
    }
    rate(&format!("Publish::decode ({} байт)", publish_frames[0].len()), frames, t.elapsed());
    s.commit("publish-decode");

    let mut s2 = Sink::default();
    for i in 0..frames / WARMUP_DIV {
        let f = Find::decode(&find_frames[i % VARIANTS]).expect("кадр обязан декодироваться");
        s2.add(f.query_id ^ u64::from(f.top_k));
    }
    let t = Instant::now();
    for i in 0..frames {
        let f = Find::decode(&find_frames[i % VARIANTS]).expect("кадр обязан декодироваться");
        s2.add(f.query_id);
        s2.add(u64::from(f.top_k));
        s2.add(f.clusters.len() as u64);
        s2.add(f.clusters[0] as u64);
        s2.add(f.query_vector.iter().fold(0u64, |a, b| a.wrapping_add(u64::from(*b as u8))));
    }
    rate(&format!("Find::decode ({} байт)", find_frames[0].len()), frames, t.elapsed());
    s2.commit("find-decode");

    // 3. Проверка подписи: её делает каждый приёмник на каждом подписанном кадре, и узел — на
    //    членстве и снапшотах. Это нижняя граница стоимости приёма (§13, квота 100 опсов/с).
    let id = Identity::from_seed([0x5A; 32]);
    let payload = publish.body_bytes();
    let sig = id.sign_body(Publish::DOMAIN, Kind::Publish, &payload);
    let checks = 2_000usize * k;
    let mut ok = 0usize;
    let t = Instant::now();
    for _ in 0..checks {
        if verify_body(&id.pubkey(), Publish::DOMAIN, Kind::Publish, &payload, &sig).unwrap_or(false)
        {
            ok += 1;
        }
    }
    rate("проверка ed25519-подписи кадра Publish", checks, t.elapsed());
    println!("принято {ok} из {checks} — все, иначе замер не о чём");
}
