//! Кеш embedding'ов по `blake3(intent_text)` с TTL (§6.1, §12.1).
//!
//! Зачем он часть контракта, а не деталь агента: инференс — доминирующая стоимость пути
//! (0.3–1.0 с на ядро против 0.1–0.3 мс на поиск, §6.1), а перепубликация идёт фоновая, раз в
//! TTL/2 (§12.1). Без кеша агент с одним интентом платит за модель дважды в минуту; с кешем —
//! один раз на TTL.
//!
//! Ключ — `intent_text_hash` (доменный blake3, §6.5), а не сама строка: 32 байта против до 1000,
//! и коллизия домена исключает ситуацию «текст запроса совпал с текстом интента и вернула чужой
//! вектор».
//!
//! Время входит параметром в бакетах (§9.6), часы здесь не читаются: иначе TTL-тесты стали бы
//! гонкой, а кеш — местом, где wall-clock просочился в поведение.

use std::collections::HashMap;

use vecdht_crypto::ids::intent_text_hash;

use crate::model::Encoded;

/// Ключ кеша: доменный хеш канонического текста (§6.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CacheKey([u8; 32]);

impl CacheKey {
    /// Из **канонической** формы текста. Вызывающий код обязан сначала пройти
    /// [`crate::text::normalize_text`]: ключ по сырому тексту означал бы, что «текст A и текст A
    /// с двумя пробелами» — разные записи, и кеш промахивался бы ровно на самых частых повторных
    /// publish'ах.
    pub fn from_canonical_text(canonical: &str) -> Self {
        Self(intent_text_hash(canonical.as_bytes()))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Значение: готовая квантованная запись плюс бакет, после которого она протухла.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Entry {
    encoded: Encoded,
    expires_bucket: u32,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct CacheStats {
    pub hits: u64,
    pub misses: u64,
    /// Попадания, которые отдал бы кеш, но записью уже истекла. Отдельно от `misses`: рост этой
    /// доли при фиксированном TTL означает, что агент переживает TTL чаще, чем считается (§12.1).
    pub expired: u64,
    pub evictions: u64,
    pub live: usize,
}

/// Кеш ограниченного размера. Не потокобезопасен намеренно: в v1 агент — один процесс с одним
/// путём publish, а `Mutex<HashMap>` создал бы иллюзию шаринга между сессиями, где её нечего
/// искать (§12.1 — кеш агента, не узла).
pub struct EmbedCache {
    map: HashMap<CacheKey, Entry>,
    limit: usize,
    stats: CacheStats,
}

impl EmbedCache {
    /// `limit` — максимум живых записей; 0 означает «кеш выключен», и это легальная конфигурация
    /// лёгкого клиента, а не ошибка.
    pub fn new(limit: usize) -> Self {
        Self { map: HashMap::with_capacity(limit.min(4096)), limit, stats: CacheStats::default() }
    }

    pub fn limit(&self) -> usize {
        self.limit
    }

    pub fn stats(&self) -> CacheStats {
        CacheStats { live: self.map.len(), ..self.stats }
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Popadaние по каноническому тексту. `now_bucket` — последний применённый бакет времени
    /// вызывающего кода, не `unix_time()` (§9.6).
    pub fn get(&mut self, canonical: &str, now_bucket: u32) -> Option<Encoded> {
        if self.limit == 0 {
            self.stats.misses += 1;
            return None;
        }
        let key = CacheKey::from_canonical_text(canonical);
        match self.map.get(&key) {
            Some(e) if e.expires_bucket > now_bucket => {
                self.stats.hits += 1;
                Some(e.encoded)
            }
            Some(_) => {
                // Запись есть, но она мертва: снять её с места, чтобы следующий `put` не
                // переполнял кеш из-за фантомов.
                self.stats.expired += 1;
                self.stats.misses += 1;
                self.map.remove(&key);
                self.stats.live = self.map.len();
                None
            }
            None => {
                self.stats.misses += 1;
                None
            }
        }
    }

    /// Сохранить результат инференса. TTL считается в бакетах по 16 с: `ttl_buckets = 6` — это
    /// 96 с, а не 90 — потому что округление вверх (§9.4) не позволяет продлевать чаще, чем
    /// обещает манифест.
    pub fn put(&mut self, canonical: &str, encoded: &Encoded, ttl_buckets: u32, now_bucket: u32) {
        if self.limit == 0 || ttl_buckets == 0 {
            return;
        }
        let key = CacheKey::from_canonical_text(canonical);
        let expires = now_bucket.saturating_add(ttl_buckets);
        self.map.insert(key, Entry { encoded: *encoded, expires_bucket: expires });
        if self.map.len() > self.limit {
            self.evict(now_bucket);
        }
        self.stats.live = self.map.len();
    }

    /// Вытеснение: сначала истёкшие, потом самые ранние по `expires_bucket`, а внутри — по ключу.
    ///
    /// Порядок обязан быть детерминированным. `HashMap` итерируется в произвольном порядке
    /// (просолённый SipHash), поэтому «удали любую» превратило бы размер кеша в источник
    /// платформенной недетерминированности — а тесты §19.1 требуют, чтобы поведение агента
    /// воспроизводилось побайтово.
    fn evict(&mut self, now_bucket: u32) {
        let dead: Vec<CacheKey> = self
            .map
            .iter()
            .filter(|(_, e)| e.expires_bucket <= now_bucket)
            .map(|(k, _)| *k)
            .collect();
        for k in dead {
            if self.map.remove(&k).is_some() {
                self.stats.evictions += 1;
            }
        }
        if self.map.len() <= self.limit {
            return;
        }
        // Мёртвых не хватило (или их не было): выгружаем лишнее по дедлайну, затем по байтам
        // ключа — полный порядок, никакой зависимости от внутреннего состояния хеш-таблицы.
        let mut by_deadline: Vec<(u32, CacheKey)> =
            self.map.iter().map(|(k, e)| (e.expires_bucket, *k)).collect();
        by_deadline.sort_unstable_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.0.cmp(&b.1.0)));
        let overflow = by_deadline.len() - self.limit;
        for (_, k) in by_deadline.into_iter().take(overflow) {
            if self.map.remove(&k).is_some() {
                self.stats.evictions += 1;
            }
        }
    }

    /// Явно снять запись (например, при republish с другим текстом).
    pub fn remove(&mut self, canonical: &str) -> Option<Encoded> {
        self.map.remove(&CacheKey::from_canonical_text(canonical)).map(|e| e.encoded)
    }

    pub fn clear(&mut self) {
        self.map.clear();
        self.stats.live = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::HashModel;
    use crate::Encoder;
    use vecdht_artifact::reference_artifact;

    fn encoded_for(text: &str) -> Encoded {
        let a = reference_artifact();
        let enc = Encoder::from_artifact(&a).unwrap();
        enc.encode_intent(&HashModel::new(), text).unwrap().encoded
    }

    #[test]
    fn hit_only_within_ttl_and_by_canonical_text() {
        let mut c = EmbedCache::new(8);
        let e = encoded_for("ищу партнёра");
        c.put("ищу партнёра", &e, 6, 100);
        assert_eq!(c.get("ищу партнёра", 105).unwrap(), e);
        // Ровно на границе: `expires_bucket > now_bucket`, поэтому 106 уже промах.
        assert_eq!(c.get("ищу партнёра", 106), None);
        let s = c.stats();
        assert_eq!((s.hits, s.misses, s.expired), (1, 1, 1));
    }

    #[test]
    fn key_ignores_noncanonical_whitespace_only_after_normalization() {
        // Ключ строится по канонической форме: вызывающий код обязан нормализовать текст до
        // обращения к кешу. Здесь проверяется, что разные *сырые* формы после normalize_text
        // дают один ключ — то есть кеш реально ловит повторный publish того же интента.
        use crate::text::normalize_text;
        let a = normalize_text("ищу   партнёра").unwrap();
        let b = normalize_text("  ищу партнёра\u{a0}").unwrap();
        assert_eq!(a, b);
        let mut c = EmbedCache::new(4);
        let e = encoded_for(&a);
        c.put(&a, &e, 6, 0);
        assert_eq!(c.get(&b, 3).unwrap(), e);
    }

    #[test]
    fn zero_ttl_and_zero_limit_disable_the_cache_without_panicking() {
        let e = encoded_for("текст");
        let mut c = EmbedCache::new(4);
        c.put("текст", &e, 0, 0);
        assert_eq!(c.len(), 0, "TTL 0 означает «не кешировать», а не «истекло в будущем»");
        let mut off = EmbedCache::new(0);
        off.put("текст", &e, 6, 0);
        assert_eq!(off.get("текст", 1), None);
        assert_eq!(off.stats().misses, 1);
    }

    #[test]
    fn eviction_is_deterministic_under_overflow() {
        // Один и тот же набор вставок при одинаковом лимите обязан вытеснять один и тот же ключ,
        // сколько бы раз мы ни пересобирали кеш: `HashMap` внутри — с просолём, и без явного
        // порядка вытеснения этот тест падал бы только на некоторых машинах.
        let e = encoded_for("текст");
        let run = |seed_shift: u32| -> Vec<[u8; 32]> {
            let mut c = EmbedCache::new(3);
            for i in 0..6u32 {
                let text = format!("текст {i}");
                c.put(&text, &e, 10, seed_shift);
            }
            let mut keys: Vec<[u8; 32]> = c.map.keys().map(|k| k.0).collect();
            keys.sort_unstable();
            keys
        };
        assert_eq!(run(0), run(0));
        assert_eq!(run(0).len(), 3);
        // При другом бакете вытеснение может выбрать других — но всегда ровно `limit` записей.
        assert_eq!(run(5).len(), 3);
    }

    #[test]
    fn expired_entries_are_dropped_from_the_map() {
        let e = encoded_for("текст");
        let mut c = EmbedCache::new(2);
        c.put("текст", &e, 1, 0);
        assert_eq!(c.get("текст", 7), None);
        assert_eq!(c.len(), 0, "истёкшая запись не должна занимать место в кеше");
        assert_eq!(c.stats().expired, 1);
    }

    #[test]
    fn remove_returns_the_stored_value() {
        let e = encoded_for("текст");
        let mut c = EmbedCache::new(2);
        c.put("текст", &e, 6, 0);
        assert_eq!(c.remove("текст").unwrap(), e);
        assert_eq!(c.remove("текст"), None);
        assert!(c.is_empty());
    }

    #[test]
    fn stats_live_follows_the_map() {
        let e = encoded_for("текст");
        let mut c = EmbedCache::new(4);
        c.put("а", &e, 6, 0);
        c.put("б", &e, 6, 0);
        assert_eq!(c.stats().live, 2);
        c.clear();
        assert_eq!(c.stats().live, 0);
    }
}
