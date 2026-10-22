//! E-0040, пороги (2)(3)(4): потолок per-key таблицы §11.3.1 мягкий, а забытая строка
//! неотличима от новой ни одним вердиктом квоты.
//!
//! Таблица строится напрямую через `Admission::with_limits` — без узла: объект политики и есть
//! предмет измерения, узел лишь передаёт ему кадры (стык проверен в `find_node_budget.rs`),
//! а потолок подменён на 3 по той же причине, что у конструктора (`admission.rs:233`):
//! переполнение 65 536 строк меряло бы память, а не правило.

use vecdht_node::{testing, Addr, Admission, Verdict};

const LIMIT: usize = 3;

fn k(i: u8) -> Addr {
    [i; 32]
}

/// Сжигает весь burst publish (20 токенов) и убеждается, что 21-й отвергнут: строка становится
/// не-idle ровно на 20 секунд (refill 1/с) — окно, за которое prune обязан её не трогать.
fn drain_publish(a: &mut Admission, key: &Addr, now: u64) {
    for i in 0..20 {
        assert!(a.check_publish(key, key, now).is_allow(), "токен №{i} burst");
    }
    assert_eq!(
        a.check_publish(key, key, now),
        Verdict::PublishQuota { retry_after_ms: 1000 },
        "burst исчерпан ⇒ ровно 1 токен/с"
    );
}

/// Полная секвенция find-квоты: 5 токенов burst + отказ с `retry_after_ms`.
fn find_burst(a: &mut Admission, key: &Addr, now: u64) -> Vec<Verdict> {
    let mut v: Vec<Verdict> = (0..5).map(|_| a.check_find(key, now)).collect();
    v.push(a.check_find(key, now));
    v
}

#[test]
fn the_peer_table_holds_active_keys_over_the_limit_and_forgets_nothing() {
    let mut a = Admission::with_limits(&testing::params(8), LIMIT, 1);
    for i in 1..=7u8 {
        drain_publish(&mut a, &k(i), 0);
    }
    // Порог (2): все семь строк не-idle (пустой publish-бакет досчитается только к t=20) —
    // таблица держится выше потолка, forgotten не двигался ни разу.
    assert_eq!(a.tracked_peers(), 7, "потолок мягкий: 7 активных строк при потолке {LIMIT}");
    assert_eq!(a.stats.forgotten_peers, 0, "забывать нечего: idle-строк нет");
}

#[test]
fn idle_surge_forgets_exactly_over_rows_and_the_forgotten_key_returns_fresh() {
    let mut a = Admission::with_limits(&testing::params(8), LIMIT, 1);
    for i in 1..=7u8 {
        drain_publish(&mut a, &k(i), 0);
    }
    // t=20: все publish-бакеты досчитались (0 + 20×1 = 20 = capacity) ⇒ семь idle-строк.
    // Восьмая входит через find и списывает токен — сама она не-idle, pending посчитан.
    assert!(a.check_find(&k(8), 20).is_allow(), "восьмая строка: over = 7 + 1 − 3 = 5");
    // Порог (3): забыто ровно 5, под потолком осталось {6, 7, 8}.
    assert_eq!(a.tracked_peers(), 3);
    assert_eq!(a.stats.forgotten_peers, 5);

    // Порог (4): забытый ключ и выжившая idle-строка отвечают одинаково — и тот, и другая
    // начинаются с полного burst. Проба забытого 0x01 сама вставляет строку и вытесняет
    // следующего idle-кандидата (0x06) — это +1 к forgotten_peers, учтено ниже.
    let expected = vec![
        Verdict::Allow,
        Verdict::Allow,
        Verdict::Allow,
        Verdict::Allow,
        Verdict::Allow,
        Verdict::FindQuota { retry_after_ms: 200 },
    ];
    let forgotten_seq = find_burst(&mut a, &k(1), 20);
    let survivor_seq = find_burst(&mut a, &k(7), 20);
    assert_eq!(forgotten_seq, expected, "забытый ключ обязан начать с полного burst");
    assert_eq!(survivor_seq, expected, "живая idle-строка неотличима от новой");
    assert_eq!(a.stats.forgotten_peers, 6, "проба забытого ключа вытеснила 0x06");
    assert_eq!(a.tracked_peers(), 3, "финал: строки 8, 1 и 7");
}
