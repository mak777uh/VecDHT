//! E-0146 — цена фильтра §12.7: recall@10 под `OnlyPaid` на разреженном корпусе.
//!
//! Спека (§12.7) называет вопрос неотвеченным прямым текстом: «числа recall при `OnlyPaid` или при
//! `dir=buy` не существует — подвыборка в несколько процентов живых записей при том же `nprobe` даёт
//! другую полноту, и это отдельный замер». Этот прибор и есть такой замер.
//!
//! Что считается независимо от продукта: предикат класса и расстояние. Оракул сам перебирает записи
//! шарда, сам применяет `OnlyPaid` к байту объявления и сам считает `l2_sq` в `i64`; в индексе он не
//! спрашивает ничего, кроме входных данных. Списки зондирования, наоборот, берутся у продукта
//! (`Centroids::top`), потому что вопрос про цену фильтра осмыслен только при том зондировании,
//! какое получает шард.
//!
//! Три плотности и три размера списка зондирования:
//!
//! * `p = 100 %` — контроль: фильтр не может ничего отбросить по построению;
//! * `p = 10 %` — средняя разреженность;
//! * `p = 2 %` — «подвыборка в несколько процентов», буквально случай спеки.
//!
//! `nprobe = 16` — все кластеры шарда: здесь фильтрованная выдача обязана совпасть с оракулом
//! (иначе разошлось не зондирование, а предикат). `nprobe = 4` и `1` — рабочие размеры списка шарда.
//!
//! Отрицательный контроль: «сначала `top_k`, потом фильтр» — реализация, которую §8.4/§12.7
//! запрещают. Она считается из того же ответа без фильтра (годное из его десяти) и обязана дать
//! заметно меньшую полноту; иначе прибор не видит дефекта, ради которого написан.
//!
//! Печатается `МЕРЕНО <ключ>=<значение>`; `lab/e0146-run.sh` снимает эти строки.

use vecdht_artifact::reference_centroids;
use vecdht_crypto::quant::clusters_of_shard;
use vecdht_index::{IndexEntry, IvfIndex};
use vecdht_wire::codec::DIM;
use vecdht_wire::messages::{ClassFilter, DirFilter, SLOT_ATTR_PAID};

const PER_CLUSTER: usize = 128;
const QUERIES_PER_CLUSTER: usize = 3;
const TOP_K: usize = 10;
const SHARD: u16 = 0;
const NPROBES: [usize; 3] = [16, 4, 1];

/// Детерминированный шум без libm: xorshift64, затем в `-6..=6`.
fn jitter(seed: u64) -> i32 {
    let mut x = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ (seed >> 29);
    x ^= x >> 31;
    x = x.wrapping_mul(0xBF58_476D_1CE4_E5B9);
    x ^= x >> 27;
    (x % 13) as i32 - 6
}

fn vec_near(row: &[i8; DIM], seed: u64) -> [i8; DIM] {
    let mut v = *row;
    for d in 0..DIM {
        let x = i32::from(v[d]) + jitter(seed.wrapping_add((d as u64).wrapping_mul(1_000_003)));
        v[d] = x.clamp(-127, 127) as i8;
    }
    v
}

/// Целочисленный L2² по определению §8.4 — своя реализация, не вызов продукта.
fn d2(a: &[i8; DIM], b: &[i8; DIM]) -> u64 {
    let mut s: u64 = 0;
    for d in 0..DIM {
        let x = i64::from(a[d]) - i64::from(b[d]);
        s += (x * x) as u64;
    }
    s
}

fn owner_of(slot: u32) -> [u8; 32] {
    let mut o = [0u8; 32];
    o[..4].copy_from_slice(&slot.to_le_bytes());
    o
}

fn is_paid(attr: u8) -> bool {
    attr & SLOT_ATTR_PAID != 0
}

/// Плотность платных задаётся слотом детерминированно (§-независимо от кластера — «смешанный
/// корпус» спеки: класс не коррелирует с геометрией).
fn paid_at(slot: u32) -> usize {
    let x = (u64::from(slot).wrapping_mul(0x9E37_79B9_7F4A_7C15) >> 17) % 100;
    x as usize
}

fn dir_bits(slot: u32) -> u8 {
    ((u64::from(slot).wrapping_mul(7)) % 3) as u8
}

/// Оракул: перебор записей шарда, предикат §12.7 по настоящему байту объявления и компаратор §8.4
/// `(l2_sq ASC, slot ASC)`.
fn oracle_top(
    entries: &[IndexEntry],
    attrs: &[u8],
    q: &[i8; DIM],
    clusters: &[u16],
    class: ClassFilter,
) -> Vec<(u64, u32)> {
    let mut hits: Vec<(u64, u32)> = entries
        .iter()
        .enumerate()
        .filter(|(i, e)| clusters.contains(&e.cluster_id) && !class.rejects(is_paid(attrs[*i])))
        .map(|(i, e)| (d2(q, &e.vec_q), i as u32))
        .collect();
    hits.sort_unstable();
    hits.truncate(TOP_K);
    hits
}

fn build(pct: usize) -> (IvfIndex, Vec<IndexEntry>, Vec<u8>) {
    let centroids = reference_centroids();
    let mut ix = IvfIndex::new(SHARD);
    let n = PER_CLUSTER * 16;
    let mut entries = Vec::with_capacity(n);
    let mut attrs = Vec::with_capacity(n);
    for c in 0..16u16 {
        let row = centroids.row(c);
        for i in 0..PER_CLUSTER {
            let slot = (usize::from(c) * PER_CLUSTER + i) as u32;
            let paid = paid_at(slot) < pct;
            let attr = dir_bits(slot) | if paid { SLOT_ATTR_PAID } else { 0 };
            let e = IndexEntry {
                owner_ed25519: owner_of(slot),
                vec_q: vec_near(row, u64::from(slot) + 1),
                cluster_id: c,
                published_bucket: 0,
                ttl_buckets: 1000,
            };
            ix.insert_with_attr(e, attr).expect("вставка записи в IVF");
            entries.push(e);
            attrs.push(attr);
        }
    }
    (ix, entries, attrs)
}

/// Сколько из `hits` нашлось в оракуле — числитель recall.
fn matched(hits: &[(u32, u32)], oracle: &[(u64, u32)]) -> u64 {
    oracle.iter().filter(|(_, s)| hits.iter().any(|(_, h)| h == s)).count() as u64
}

fn pm(num: u64, den: u64) -> u64 {
    if den == 0 {
        0
    } else {
        num * 1000 / den
    }
}

fn print(key: impl std::fmt::Display, value: impl std::fmt::Display) {
    println!("МЕРЕНО {key}={value}");
}

#[test]
fn recall_under_class_filter_on_a_sparse_corpus() {
    let centroids = reference_centroids();
    let all = clusters_of_shard(SHARD);
    assert_eq!(all.len(), 16, "шард — 16 кластеров");

    let mut queries: Vec<[i8; DIM]> = Vec::new();
    for c in 0..16u16 {
        let row = centroids.row(c);
        for k in 0..QUERIES_PER_CLUSTER {
            queries.push(vec_near(row, (u64::from(c) << 8) | (k as u64) | 0xA5A5_0000));
        }
    }
    print("CORPUS_CLUSTERS", all.len());
    print("CORPUS_ENTRIES", PER_CLUSTER * 16);
    print("QUERIES", queries.len());
    print("TOP_K", TOP_K);

    let mut identity_mismatches = 0u64;
    let mut added_misses = 0u64;
    let mut empty_with_oracle = 0u64;
    let mut probes_empty = 0u64;
    let mut paid_total: Vec<(String, u64)> = Vec::new();
    let mut recall: Vec<(String, u64, u64)> = Vec::new(); // ключ, числитель, знаменатель
    let mut ceiling: Vec<(String, u64, u64)> = Vec::new(); // потолок покрытия тем же списком
    let mut post_trunc = (0u64, 0u64);

    for (pct, label) in [(100usize, "100"), (10, "10"), (2, "2"), (1, "1")] {
        let (ix, entries, attrs) = build(pct);
        paid_total.push((
            label.to_string(),
            attrs.iter().filter(|a| is_paid(**a)).count() as u64,
        ));
        let mut num = [0u64; 3];
        let mut den = [0u64; 3];
        let mut ceil = [0u64; 3];

        for q in &queries {
            let mut probed = centroids.top(q, 1024);
            probed.retain(|c| all.contains(c));

            // Идеальный ответ: полный скан шарда с тем же фильтром. Это знаменатель всех
            // полнот ниже — «что было бы видно, если бы зондирование ничего не стоило».
            let oracle_full = oracle_top(&entries, &attrs, q, &all, ClassFilter::OnlyPaid);
            // Тождество: все кластеры шарда — это и есть полный скан.
            let hits_full =
                ix.search_filtered(q, &all, TOP_K, 0, ClassFilter::OnlyPaid, DirFilter::Any);
            let same = oracle_full.len() == hits_full.len()
                && oracle_full
                    .iter()
                    .zip(hits_full.iter())
                    .all(|(o, h)| o.1 == h.1 && o.0 as u32 == h.0);
            if !same {
                identity_mismatches += 1;
            }

            for (i, np) in NPROBES.iter().copied().enumerate() {
                let probe: Vec<u16> = probed.iter().copied().take(np).collect();
                if np == 4 && probe.is_empty() {
                    probes_empty += 1;
                }
                let hits =
                    ix.search_filtered(q, &probe, TOP_K, 0, ClassFilter::OnlyPaid, DirFilter::Any);
                num[i] += matched(&hits, &oracle_full);
                den[i] += oracle_full.len() as u64;
                // Потолок: сколько идеального ответа вообще лежит в этих кластерах. Любая честная
                // реализация, сканирующая ровно этот список, не может найти больше.
                let in_probe: Vec<(u64, u32)> = oracle_full
                    .iter()
                    .copied()
                    .filter(|(_, s)| probe.contains(&entries[*s as usize].cluster_id))
                    .collect();
                ceil[i] += in_probe.len() as u64;
                if np != 4 {
                    continue;
                }
                if hits.is_empty() && !oracle_full.is_empty() {
                    empty_with_oracle += 1;
                }
                // Тот же список зондирования без фильтра. Его годные попадания — ровно то, что
                // вернула бы запрещённая реализация «сначала top_k, потом фильтр».
                let any = ix.search_filtered(q, &probe, TOP_K, 0, ClassFilter::Any, DirFilter::Any);
                let eligible: Vec<(u32, u32)> = any
                    .iter()
                    .copied()
                    .filter(|(_, s)| is_paid(attrs[*s as usize]))
                    .collect();
                let hit_slots: Vec<u32> = hits.iter().map(|(_, s)| *s).collect();
                added_misses += eligible
                    .iter()
                    .filter(|(_, s)| !hit_slots.contains(s))
                    .count() as u64;
                let m = matched(&eligible, &oracle_full);
                // Контроль принадлежит только p = 2 %: у него в имени эта плотность, и складывать
                // его между плотностями значило бы печатать чужое число.
                if pct == 2 {
                    post_trunc.0 += m;
                    post_trunc.1 += oracle_full.len() as u64;
                }
            }
        }

        for (i, np) in NPROBES.iter().enumerate() {
            recall.push((format!("RECALL_PAID_{label}_NP{np}_PM"), num[i], den[i]));
            ceiling.push((format!("COVERAGE_PAID_{label}_NP{np}_PM"), ceil[i], den[i]));
            // Полнота не может превысить покрытие: иначе «идеальный ответ» собран неверно.
            assert!(num[i] <= ceil[i], "полнота выше покрытия при p={label}, nprobe={np}");
            // Внутри просканированного списка предикат и отсечение ничего не теряют: полнота
            // равна покрытию — это и есть «фильтр стоит ноль, стоит зондирование».
            assert_eq!(num[i], ceil[i], "фильтр потерял годное внутри просканированных кластеров (p={label}, nprobe={np})");
        }
        // `nprobe = 16` — полный скан: покрытие там обязано быть полным.
        assert_eq!(ceil[0], den[0], "nprobe=16 обязан покрыть весь идеальный ответ при p={label}");
    }

    for (label, total) in &paid_total {
        print(format!("PAID_TOTAL_{label}"), total);
    }
    for ((key, num, den), (ckey, cnum, cden)) in recall.iter().zip(ceiling.iter()) {
        print(key, pm(*num, *den));
        print(format!("{key}_OF"), format!("{num}/{den}"));
        print(ckey, pm(*cnum, *cden));
        print(format!("{ckey}_OF"), format!("{cnum}/{cden}"));
    }
    print("CTRL_POST_TRUNC_2_NP4_PM", pm(post_trunc.0, post_trunc.1));
    print("CTRL_POST_TRUNC_2_NP4_OF", format!("{}/{}", post_trunc.0, post_trunc.1));
    print("IDENTITY_MISMATCHES", identity_mismatches);
    print("FILTER_ADDS_MISSES", added_misses);
    print("EMPTY_WITH_ORACLE_2_NP4", empty_with_oracle);
    print("PROBES_EMPTY_2_NP4", probes_empty);

    assert_eq!(identity_mismatches, 0, "при всех кластерах выдача обязана совпасть с оракулом");
    assert_eq!(added_misses, 0, "фильтр не может терять годное, что нашёл бы тот же список без него");
    assert_eq!(empty_with_oracle, 0, "пустой ответ при непустом оракуле — потеря, а не «нет объявлений»");
    assert_eq!(probes_empty, 0, "список зондирования шарда непуст: иначе делятся не те числа");
    // Нижняя граница: исправный фильтрованный ответ не беднее того, что вернула бы запрещённая
    // реализация. Индекс 7 — это `p = 2 %`, `nprobe = 4`: четыре плотности по три списка.
    let (fn_, fd) = {
        let (_, n4, d4) = &recall[7];
        (*n4, *d4)
    };
    assert!(
        fn_ * post_trunc.1 >= post_trunc.0 * fd,
        "фильтрованная полнота ниже контроля «фильтр после усечения» — предикат не там"
    );
    // Контроль обязан быть видимо хуже: число 300 — не порог продукта, а требование к прибору.
    assert!(
        pm(post_trunc.0, post_trunc.1) < 300,
        "контроль «фильтр после усечения» не отличим от исправного пути — прибор слеп"
    );
}
