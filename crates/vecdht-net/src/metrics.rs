//! Снимок наблюдения транспорта (Приложение C): конечный набор имён и закрытые метки двери.
//!
//! Две части, и они разные по природе:
//!
//! * **фиксированные имена** — [`FIXED`]: таблица провайдеров шарда (§7.4) и собственный
//!   сертификат (§4.2). Их число не зависит ни от трафика, ни от числа отказов;
//! * **метки двери** — `door_refusal.<имя>`, где `<имя>` берётся из `DoorReason::ALL` (22
//!   значения, `E-0095`). В снимок попадают только ненулевые, как и в самом журнале: «причина
//!   не наблюдалась» и «причина наблюдалась ноль раз» — разные утверждения, и второе не нужно.
//!   Число записей при этом ограничено сверху: 22, а не числом отказов.
//!
//! Свободного текста здесь нет: `errors` сервиса — журнал последних ошибок для глаза, а не
//! метрика, и в снимок не входит. Цена интента не входит тем более: узел её не хранит (§5.5),
//! а метка с числом цены была бы утечкой объявления в слой наблюдения.

use crate::door::DoorReason;
use crate::service::NetService;

/// Префикс метки двери. Вынесен в константу, чтобы потребитель не собирал строку сам.
pub const DOOR_LABEL_PREFIX: &str = "door_refusal.";

/// Имена фиксированной части в порядке печати.
pub const FIXED: [&str; 7] = [
    "provider_announcements",
    "provider_cache_len",
    "provider_pruned_dead",
    "provider_expired",
    "provider_evicted",
    "own_cert_expired_refusals",
    "door_refusals_total",
];

/// Снимок транспорта. `door` — только ненулевые причины, в порядке имён `DoorReason::ALL`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetMetrics {
    fixed: [(&'static str, u64); FIXED.len()],
    door: Vec<(&'static str, u64)>,
}

impl NetMetrics {
    /// Снять снимок с живого сервиса.
    pub fn of(service: &NetService) -> Self {
        let (pruned_dead, expired, evicted) = service.provider_cache_stats();
        Self::from_parts(
            service.provider_announcements,
            service.provider_cache_len() as u64,
            (pruned_dead, expired, evicted),
            service.own_cert_expired_refusals(),
            service.door_refusals(),
        )
    }

    /// Сборка из уже снятых значений. Отдельно от [`of`], чтобы оракул мог проверить проекцию
    /// без живого сокета, а форма имён не зависела от libp2p.
    pub fn from_parts(
        announcements: u64,
        cache_len: u64,
        cache: (u64, u64, u64),
        own_cert_expired: u64,
        refusals: Vec<(&'static str, u64)>,
    ) -> Self {
        let mut door: Vec<(&'static str, u64)> =
            refusals.into_iter().filter(|(_, n)| *n > 0).collect();
        // `DoorLedger::refusals` уже отдаёт BTreeMap-порядок, но снимок — контракт для двух
        // прогонов стенда, и порядок не должен зависеть от того, кто собрал вход.
        door.sort_by_key(|(name, _)| *name);
        // Замкнутость метки проверяется здесь: имя вне `ALL` — это свободная строка, которая
        // прошла бы в наблюдение и открыла кардинальность ровно там, где `E-0095` её закрыл.
        let known: Vec<&'static str> = DoorReason::ALL.iter().map(|r| r.name()).collect();
        for (name, _) in &door {
            debug_assert!(known.contains(name), "метка двери вне ALL: {name}");
        }
        let fixed = [
            ("provider_announcements", announcements),
            ("provider_cache_len", cache_len),
            ("provider_pruned_dead", cache.0),
            ("provider_expired", cache.1),
            ("provider_evicted", cache.2),
            ("own_cert_expired_refusals", own_cert_expired),
            ("door_refusals_total", door.iter().map(|(_, n)| *n).sum()),
        ];
        Self { fixed, door }
    }

    pub fn fixed(&self) -> &[(&'static str, u64)] {
        &self.fixed
    }

    pub fn door(&self) -> &[(&'static str, u64)] {
        &self.door
    }

    /// Значение по имени. Метка двери ищется полным именем `door_refusal.<имя>` — так снимок
    /// читает CLI и так же его читает тест, не зная, какие причины наблюдались.
    pub fn get(&self, name: &str) -> Option<u64> {
        if let Some((_, v)) = self.fixed.iter().find(|(n, _)| *n == name) {
            return Some(*v);
        }
        let reason = name.strip_prefix(DOOR_LABEL_PREFIX)?;
        self.door.iter().find(|(n, _)| *n == reason).map(|(_, v)| *v)
    }

    /// Стабильный текст: фиксированные имена, затем метки двери в порядке имён.
    pub fn render(&self) -> String {
        let mut out = String::with_capacity((self.fixed.len() + self.door.len()) * 36);
        for (name, value) in &self.fixed {
            out.push_str(name);
            out.push('=');
            out.push_str(&value.to_string());
            out.push('\n');
        }
        for (name, value) in &self.door {
            out.push_str(DOOR_LABEL_PREFIX);
            out.push_str(name);
            out.push('=');
            out.push_str(&value.to_string());
            out.push('\n');
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_names_are_unique_ascii_and_without_price() {
        let mut seen = std::collections::BTreeSet::new();
        for n in FIXED {
            assert!(seen.insert(n), "имя повторено: {n}");
            assert!(n.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'), "имя вне [a-z_]: {n}");
            for bad in ["price", "cost", "amount", "unit"] {
                assert!(!n.contains(bad), "метрика `{n}` содержит `{bad}`");
            }
        }
        assert!(!DOOR_LABEL_PREFIX.is_empty());
        assert_eq!(DOOR_LABEL_PREFIX.chars().filter(|c| *c == '.').count(), 1);
    }

    #[test]
    fn only_nonzero_door_reasons_are_printed_and_order_is_stable() {
        let a = DoorReason::ALL[0].name();
        let b = DoorReason::ALL[5].name();
        let m = NetMetrics::from_parts(3, 0, (1, 2, 0), 4, vec![(b, 7), (a, 0), (a, 1)]);
        // Ноль отброшен, но суммарное число отказов — сумма ненулевых.
        assert_eq!(m.door().len(), 2);
        assert_eq!(m.get("door_refusals_total"), Some(8));
        assert_eq!(m.get(&format!("{DOOR_LABEL_PREFIX}{a}")), Some(1));
        assert_eq!(m.get(&format!("{DOOR_LABEL_PREFIX}{b}")), Some(7));
        let order: Vec<&str> = m.door().iter().map(|(n, _)| *n).collect();
        let mut sorted = order.clone();
        sorted.sort_unstable();
        assert_eq!(order, sorted, "порядок меток двери не стабилен");
    }
}
