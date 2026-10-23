//! Конечная таблица провайдеров шарда (§7.4, §P5; `ADR-0044` «конечность кэшей», `E-0091`).
//!
//! До `E-0091` это был `BTreeMap<u16, BTreeSet<PeerId>>` прямо в `NetService`: пополнение в одном
//! месте (`service.rs:677`), удалений — ни одного. `E-0085` гейт (в) измерил следствие на отзыве,
//! `E-0086` перенёс его в спеку (§4.2 `:185…190`: «запись … монотонна и переживает отзыв того, кто
//! её внёс»). Монотонный кэш — не «неудобство», а дыра двух родов:
//!
//! * память. Стоимость новой записи для атакующего равна стоимости генерации ключевой пары, а §11.4
//!   констатирует, что идентичность в v8 бесплатна. `start_providing` на kad-уровне нашу дверь §5.3
//!   не проходит, поэтому «подождать, пока мёртвый выпадет сам» — не защита;
//! * кандидатуры. `Agent::candidates` (`agent.rs:1102…1108`) для каждого провайдера, которого нет в
//!   таблице аутентифицированных, зовёт `dial_peer`: мёртвая запись превращается в попытку соединения
//!   с трупом на каждый резолв шарда, а цену discovery-помпы измерил `E-0084` (74…81 % времени `find`
//!   против ≤ 3,3 % на сам `search`).
//!
//! Числа взяты из спеки, а не выбраны циклом:
//!
//! * [`PROVIDER_RECORD_TTL_SECS`] = 420 с — `provider_record_ttl` из §7.4 (`:541`). Число было в
//!   спеке и до этого цикла, но в коде его не было вовсе (`NetConfig` знал только
//!   `provider_republish = 180 с`);
//! * [`PROVIDER_CACHE_MAX_PER_SHARD`] = 20 — `max_providers_per_key = K_VALUE = 20` из эталонного
//!   `MemoryStore`, зафиксированный в приложении спеки (`:1883`) как лимит, в который мы себя
//!   лимитируем ради `max_provided_keys = 1024`.
//!
//! Форма «дедлайн записи выводится из частоты реанонса, а не из того, когда её переспросили» взята
//! из эталона (`L-0006`: validity 48 ч против republish 22 ч, кеш адресов — отдельным сроком).
//! Оговорка переносимости: у эталона TTL — свойство *хранилища* record'ов, у нас — свойство
//! *акселератора поиска*, и у нас есть то, чего у эталона нет: §9.8 доказывает смерть пира событием
//! транспорта, поэтому [`ProviderCache::forget_peer`] точнее любого дедлайна, а
//! [`ProviderCache::expire`] остаётся подстраховкой для записей, с которыми мы никогда не соединялись.
//!
//! Числа — константы модуля, а не поля `NetConfig`: восемь существующих литералов конфига (два в
//! `src`, шесть в тестах) пришлось бы править ради двух значений, а порог (0) цикла предписывает
//! правку в трёх файлах (`E-0091`).

use std::collections::{BTreeMap, BTreeSet};

use libp2p::PeerId;
use vecdht_wire::constants::SHARDS;

/// `provider_record_ttl` из §7.4 (`:541`). Запись кэша, которую не подтверждали этим дольше,
/// снимается на тике.
pub const PROVIDER_RECORD_TTL_SECS: u64 = 420;

/// Эталонный `max_providers_per_key` (спека `:1883`): сколько провайдеров одного ключа мы храним.
pub const PROVIDER_CACHE_MAX_PER_SHARD: usize = 20;

/// Суммарный размер таблицы обязан влезать в гейт §18.2 («суммарно < 5k provider-записей в сети»)
/// при полном заполнении всех `S = 64` ключей (§P5). Это тот же класс проверки, что статический
/// ассерт формы капа в `E-0088`: число предела без связи с бюджетом — просто литерал.
const _: () = assert!(PROVIDER_CACHE_MAX_PER_SHARD * (SHARDS as usize) < 5_000);

/// Отчёт об одном пополнении: сколько записей вставилось впервые, сколько снято пределом и
/// сколько не принято из-за окна недоверия.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SeeReport {
    pub inserted: usize,
    pub evicted: usize,
    pub skipped_dead: usize,
}

/// Таблица «шард → провайдер → когда в последний раз подтверждена» (`seen_sec`) плюс окно
/// недоверия к пиру, чью смерть доказал транспорт.
pub struct ProviderCache {
    map: BTreeMap<u16, BTreeMap<PeerId, u64>>,
    /// `peer → когда доказана смерть` (§9.8). Пока запись жива, ответ DHT об этом пире не
    /// принимается: переспрос возвращает мёртвого из чужого хранилища (`E-0091`, превью-прогон —
    /// `g3_has_dead_at_death=0` при `g3_has_dead_after=1`), и без этого окно дыра лечилась бы
    /// ровно до следующего `find_providers`.
    dead: BTreeMap<PeerId, u64>,
    per_shard_max: usize,
    /// Предел окна недоверия: **не новое число**, а собственный bound таблицы
    /// (`per_shard_max × SHARDS`), уже связанный статическим ассертом с гейтом §18.2.
    dead_max: usize,
    ttl_secs: u64,
    /// Снято записей по событию транспорта или отзыва ([`Self::forget_peer`]).
    pub pruned_dead: u64,
    /// Снято записей по дедлайну ([`Self::expire`]).
    pub expired: u64,
    /// Снято записей пределом на шард ([`Self::see`]).
    pub evicted: u64,
    /// Отказано в приёме пира из ответа DHT, потому что он в окне недоверия ([`Self::see`]).
    pub skipped_dead: u64,
    /// Окно снято досрочно: handshake доказал, что пир снова жив (§9.8, [`Self::prove_alive`]).
    pub released_alive: u64,
}

impl ProviderCache {
    /// Лимиты берутся аргументами, чтобы юнит-тесты формы не зависели от product-констант.
    /// Нулевой предел означал бы «таблица всегда пуста», то есть выключенный поиск, а не предел,
    /// поэтому он поднимаётся до единицы.
    pub fn new(per_shard_max: usize, ttl_secs: u64) -> Self {
        let per_shard_max = per_shard_max.max(1);
        Self {
            map: BTreeMap::new(),
            dead: BTreeMap::new(),
            dead_max: per_shard_max.saturating_mul(SHARDS as usize),
            per_shard_max,
            ttl_secs: ttl_secs.max(1),
            pruned_dead: 0,
            expired: 0,
            evicted: 0,
            skipped_dead: 0,
            released_alive: 0,
        }
    }

    /// Product-конструктор: числа из спеки (§7.4 `:541` и приложение `:1883`).
    ///
    /// Инвариант `ttl ≥ republish`: иначе провайдер, честно реанонсящий каждые `republish` секунд,
    /// вымирал бы из кэша между анонсами, и фикс сделал бы резолв дороже дыры. Инвариант закрывает
    /// функция, а не `const`-ассерт, потому что `provider_republish` — поле конфига: `NetConfig` с
    /// републикацией 10 000 с обязан дать кэш с дедлайном 10 000 с, а не с 420.
    pub fn product(provider_republish_secs: u64) -> Self {
        Self::new(
            PROVIDER_CACHE_MAX_PER_SHARD,
            PROVIDER_RECORD_TTL_SECS.max(provider_republish_secs),
        )
    }

    /// Записать результат `GetProviders`: у всех названных провайдеров обновляется дата
    /// подтверждения, новая запись вставляется. Пир, чью смерть доказал транспорт и чьё окно
    /// недоверия ещё не истекло, **не принимается** — иначе переспрос DHT возвращает труп
    /// (`E-0091`, см. шапку модуля). При переборе предела снимаются **старые** записи: пока в
    /// ячейке есть запись из прошлого ответа, новичок не вытесняется (по смыслу §11.3.3 — дороже
    /// принятого не вытеснять). Свежие между собой вытесняются только в одном случае: когда сам
    /// ответ длиннее предела и старых не осталось, иначе лимит не был бы лимитом.
    pub fn see(
        &mut self,
        shard: u16,
        peers: impl IntoIterator<Item = PeerId>,
        now_sec: u64,
    ) -> SeeReport {
        let per = self.per_shard_max;
        let ttl = self.ttl_secs;
        let asked: Vec<PeerId> = peers.into_iter().collect();
        let accepted: Vec<PeerId> = asked
            .iter()
            .copied()
            .filter(|p| !self.distrusted(*p, now_sec, ttl))
            .collect();
        let skipped = asked.len() - accepted.len();
        let (mut inserted, mut evicted) = (0usize, 0usize);
        {
            let cell = self.map.entry(shard).or_default();
            let mut fresh: BTreeSet<PeerId> = BTreeSet::new();
            for p in accepted {
                if !cell.contains_key(&p) {
                    inserted += 1;
                }
                cell.insert(p, now_sec);
                fresh.insert(p);
            }
            while cell.len() > per {
                // Жертва ищется в два прохода: сначала старая запись, и лишь если несвежих не
                // осталось — любая. Второй проход нужен ровно одному случаю: ответ `GET_PROVIDERS`
                // длиннее предела пришёл бы целиком «свежим», и фильтр по несвежим оставил бы
                // ячейку больше предела, то есть дыру вместо лимита. `min_by_key` по BTreeMap
                // детерминирован: при равных датах снимается минимальный `PeerId`.
                let victim = cell
                    .iter()
                    .filter(|(p, _)| !fresh.contains(*p))
                    .min_by_key(|(_, seen)| **seen)
                    .or_else(|| cell.iter().min_by_key(|(_, seen)| **seen))
                    .map(|(p, _)| *p);
                let Some(victim) = victim else { break };
                cell.remove(&victim);
                evicted += 1;
            }
        }
        // Пустая ячейка обязана уйти из карты: иначе число ключей росло бы как ещё один кэш.
        if self.map.get(&shard).is_some_and(|c| c.is_empty()) {
            self.map.remove(&shard);
        }
        self.evicted += evicted as u64;
        self.skipped_dead += skipped as u64;
        SeeReport {
            inserted,
            evicted,
            skipped_dead: skipped,
        }
    }

    /// Жива ли для этого пира запись смерти и не истекло ли её окно.
    fn distrusted(&self, peer: PeerId, now_sec: u64, ttl: u64) -> bool {
        match self.dead.get(&peer) {
            Some(&proved) => now_sec.saturating_sub(proved) < ttl,
            None => false,
        }
    }

    /// Контр-доказательство §9.8: транспорт снова соединился и прошёл handshake — окно снимается
    /// досрочно, и ответ DHT об этом пире принимается как раньше. Возвращает true, если окно
    /// действительно сбрасывалось (число таких снятий — счётчик `released_alive`).
    pub fn prove_alive(&mut self, peer: &PeerId) -> bool {
        let had = self.dead.remove(peer).is_some();
        if had {
            self.released_alive += 1;
        }
        had
    }

    /// Снять пира со **всех** шардов и открыть ему окно недоверия: событие транспорта (§9.8) или
    /// отзыв (§4.2) доказывает, что провайдер мёртв, а мёртв он одинаково для любого ключа.
    /// Возвращает число снятых записей.
    pub fn forget_peer(&mut self, peer: &PeerId, now_sec: u64) -> usize {
        let mut removed = 0usize;
        let mut empty: Vec<u16> = Vec::new();
        for (shard, cell) in self.map.iter_mut() {
            if cell.remove(peer).is_some() {
                removed += 1;
                if cell.is_empty() {
                    empty.push(*shard);
                }
            }
        }
        for shard in empty {
            self.map.remove(&shard);
        }
        self.dead.insert(*peer, now_sec);
        // Окно обязано быть конечным так же, как таблица: предел — собственный bound кэша
        // (`per_shard_max × SHARDS`), снимается самая старая запись смерти, а свежая не вытесняется
        // (тот же порядок цен, что у `see`).
        let max = self.dead_max;
        while self.dead.len() > max {
            let victim = self
                .dead
                .iter()
                .filter(|(p, _)| **p != *peer)
                .min_by_key(|(_, proved)| **proved)
                .or_else(|| self.dead.iter().min_by_key(|(_, proved)| **proved))
                .map(|(p, _)| *p);
            let Some(victim) = victim else { break };
            self.dead.remove(&victim);
        }
        self.pruned_dead += removed as u64;
        removed
    }

    /// Снять всё, что не подтверждали дольше дедлайна. Цена — один проход по таблице раз в секунду
    /// при Lim ≤ `per_shard_max × S` = 1280 записей, то есть порядок тысячи сравнений в секунду
    /// против узлового бюджета §12.6.
    pub fn expire(&mut self, now_sec: u64) -> usize {
        let ttl = self.ttl_secs;
        let mut removed = 0usize;
        for cell in self.map.values_mut() {
            let stale: Vec<PeerId> = cell
                .iter()
                .filter(|(_, seen)| now_sec.saturating_sub(**seen) >= ttl)
                .map(|(p, _)| *p)
                .collect();
            for p in stale {
                cell.remove(&p);
                removed += 1;
            }
        }
        self.map.retain(|_, cell| !cell.is_empty());
        // Окно недоверия живёт ровно `ttl` — тот же срок, что назначен жизни самой
        // провайдер-записи (§7.4). После него мы снова верим ответу DHT: пир мог перезапуститься,
        // а evidence «жив» у нас появляется только из handshake.
        self.dead.retain(|_, proved| now_sec.saturating_sub(*proved) < ttl);
        self.expired += removed as u64;
        removed
    }

    /// Провайдеры шарда в стабильном порядке (по `PeerId`), как до правки.
    pub fn peers(&self, shard: u16) -> Vec<PeerId> {
        self.map
            .get(&shard)
            .map(|c| c.keys().copied().collect())
            .unwrap_or_default()
    }

    pub fn len(&self) -> usize {
        self.map.values().map(|c| c.len()).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    #[cfg(test)]
    pub(crate) fn seen_of(&self, shard: u16, peer: &PeerId) -> Option<u64> {
        self.map.get(&shard).and_then(|c| c.get(peer).copied())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Детерминированный `PeerId`: `PeerId::random()` дал бы разные множества порядка на каждом
    /// прогоне, а tie-break предела (минимальный `PeerId` при равных датах) тесты обязаны наблюдать
    /// одинаково. Формула — существующая `keys::peer_id` над `Identity::from_seed`: тот же вывод
    /// адреса из ключа, что в продукте, а не собственная деривация (§4.1).
    fn peer(n: u8) -> PeerId {
        let mut seed = [0u8; 32];
        seed[0] = n;
        crate::keys::peer_id(&vecdht_crypto::Identity::from_seed(seed))
    }

    /// (1) Числа обязаны быть названными в спеке, а не выбранными циклом, и инвариант
    /// `ttl ≥ republish` обязан держаться при любом конфиге (`L-0006`: record обязан пережить один
    /// пропущенный реанонс).
    #[test]
    fn the_two_numbers_are_the_ones_the_spec_names() {
        assert_eq!(PROVIDER_RECORD_TTL_SECS, 420, "§7.4 :541 provider_record_ttl");
        assert_eq!(PROVIDER_CACHE_MAX_PER_SHARD, 20, "спека :1883 max_providers_per_key");
        // Полная таблица (все 64 ключа по пределу) обязана влезать в гейт §18.2.
        assert!(PROVIDER_CACHE_MAX_PER_SHARD * (SHARDS as usize) < 5_000);
        let c = ProviderCache::product(10_000);
        assert_eq!(c.ttl_secs, 10_000, "clamp: дедлайн не короче републикации");
        let c = ProviderCache::product(180);
        assert_eq!(c.ttl_secs, PROVIDER_RECORD_TTL_SECS, "дефолт спеки: 420 с");
        // Дефолт конфига продукта, а не только литерал теста: `NetConfig::default()` обязан быть
        // в рамках инварианта, иначе кэш съедал бы записи легитимно анонсирующего узла.
        assert!(
            crate::service::NetConfig::default()
                .provider_republish
                .as_secs()
                <= PROVIDER_RECORD_TTL_SECS,
            "републикация по дефолту длиннее дедлайна записи"
        );
    }

    /// (7) Предел на шард: 5 старых + 20 свежих при лимите 20 ⇒ 20 записей, `evicted = 5`, сняты
    /// именно пять старых, а только что принятые выжили.
    #[test]
    fn the_limit_drops_the_oldest_and_never_the_newcomer() {
        let mut c = ProviderCache::new(20, 420);
        for i in 0..5u8 {
            c.see(7, [peer(i)], 1_000);
        }
        let fresh: Vec<PeerId> = (5..25u8).map(peer).collect();
        let report = c.see(7, fresh.iter().copied(), 1_100);
        assert_eq!(report.inserted, 20, "двадцать свежих — все новые ключи");
        assert_eq!(report.evicted, 5, "предел обязан снять ровно переполнение");
        assert_eq!(c.len(), 20);
        for i in 0..5u8 {
            assert!(!c.peers(7).contains(&peer(i)), "старый провайдер {i} выжил");
        }
        for p in &fresh {
            assert!(c.peers(7).contains(p), "только что принятый провайдер вытеснен");
        }
    }

    /// (3) Смерть пира снимает его со всех шардов: одно событие транспорта — сколько угодно записей.
    #[test]
    fn one_death_clears_the_peer_from_every_shard() {
        let mut c = ProviderCache::new(20, 420);
        let dead = peer(1);
        let live = peer(2);
        for shard in [7u16, 9, 11] {
            c.see(shard, [dead, live], 1_000);
        }
        assert_eq!(c.len(), 6);
        assert_eq!(c.forget_peer(&dead, 2_000), 3, "смерть обязана снять запись на каждом шарде");
        assert_eq!(c.pruned_dead, 3);
        assert_eq!(c.len(), 3);
        for shard in [7u16, 9, 11] {
            assert_eq!(c.peers(shard), vec![live], "живой провайдер пострадал");
        }
        assert_eq!(c.forget_peer(&live, 2_001), 3);
        assert!(c.is_empty(), "пустые ячейки не должны оставаться в карте");
    }

    /// (8) Дедлайн: старше `ttl` — снято, в пределах — нет; счётчик обязан совпасть с числом снятий
    /// и не смешиваться со счётчиком смерти.
    #[test]
    fn expiry_takes_only_what_is_older_than_the_deadline() {
        let mut c = ProviderCache::new(20, 420);
        let old = peer(1);
        let young = peer(2);
        c.see(7, [old], 1_000);
        c.see(7, [young], 1_001);
        assert_eq!(c.expire(1_419), 0, "419 с — ещё не дедлайн");
        assert_eq!(c.expire(1_420), 1, "420 с — ровно граница §7.4, запись обязана уйти");
        assert_eq!(c.expired, 1);
        assert_eq!(c.peers(7), vec![young], "живая в пределах дедлайна запись потеряна");
        assert_eq!(c.pruned_dead, 0, "истечение — не смерть: счётчики не смешиваются");
    }

    /// (8а) Легитимный реанонс не стареет: `see` обновляет `seen_sec`, поэтому провайдер, анонсирующий
    /// шард каждые 180 с, живёт в кэше вечно — это и есть цена, которую §7.4 назначил за конечность.
    #[test]
    fn a_republishing_provider_never_expires() {
        let mut c = ProviderCache::product(180);
        let p = peer(3);
        for k in 0..5u64 {
            let now = 1_000 + k * 180;
            c.see(7, [p], now);
            assert_eq!(c.expire(now), 0, "реанонс на шаге {k} потерял провайдера");
            assert_eq!(c.peers(7), vec![p]);
        }
        assert_eq!(c.seen_of(7, &p), Some(1_000 + 4 * 180), "дата обязана обновляться");
        assert_eq!(c.expired, 0);
    }

    /// (6) Превью-прогон цикла измерил: снятие по событию транспорта работает
    /// (`g3_has_dead_at_death=0`), но переспрос DHT возвращает мёртвого обратно
    /// (`g3_has_dead_after=1`), и следом идёт `g5_dial_errors=1`. Механизм, закрывающий это, — окно
    /// недоверия. Оба его числа заимствованы: длительность = `provider_record_ttl` (§7.4), предел =
    /// собственный bound таблицы (`per_shard_max × SHARDS`); новых чисел цикл не изобретает.
    #[test]
    fn a_peer_proved_dead_is_not_taken_back_from_the_dht() {
        let mut c = ProviderCache::new(20, 420);
        let dead = peer(1);
        let live = peer(2);
        c.see(7, [dead, live], 1_000);
        assert_eq!(c.forget_peer(&dead, 1_010), 1);
        let report = c.see(7, [dead, live], 1_020);
        assert_eq!(report.skipped_dead, 1, "мёртвый провайдер принят обратно из DHT");
        assert_eq!(report.inserted, 0);
        assert_eq!(c.peers(7), vec![live], "окно тронуло живого провайдера");
        assert_eq!(c.skipped_dead, 1, "отказ обязан быть числом, а не обещанием");
        // (а) контр-доказательство §9.8: handshake снимает окно досрочно.
        assert!(c.prove_alive(&dead), "окно не снялось успешным handshake");
        assert_eq!(c.released_alive, 1);
        assert_eq!(c.see(7, [dead], 1_030).inserted, 1, "живой пир не вернулся в таблицу");
        // (б) окно конечно само: тем же ttl, что и запись о провайдере.
        c.forget_peer(&dead, 2_000);
        assert_eq!(c.see(7, [dead], 2_419).skipped_dead, 1, "419 с — окно ещё живое");
        assert_eq!(c.see(7, [dead], 2_420).inserted, 1, "420 с — окно обязано истечь");
        // (в) предел окна: bound таблицы, снимается старая запись смерти, свежая остаётся.
        let mut c = ProviderCache::new(2, 420);
        assert_eq!(
            c.dead_max,
            2 * (SHARDS as usize),
            "предел окна обязан быть bound таблицы, а не новым числом"
        );
        for i in 0..130u8 {
            c.forget_peer(&peer(i), 3_000 + i as u64);
        }
        assert_eq!(c.dead.len(), c.dead_max, "окно выросло за собственный bound");
        assert!(!c.dead.contains_key(&peer(0)), "из окна не снята самая старая запись смерти");
        assert!(c.dead.contains_key(&peer(129)), "свежая запись смерти вытеснена");
    }
}
