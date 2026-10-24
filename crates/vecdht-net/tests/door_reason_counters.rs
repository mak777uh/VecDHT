//! H-0095 / E-0095 · оракул 2/2: причина отказа двери названа локально и конечна.
//!
//! Файл пришёл вместе с фиксом и не обязан компилироваться на дереве до правки: его ключи `dc_*` —
//! контракт
//! на правку, замороженный в `lab/expectations/e0095.tsv` до замера (правило (к) п. 8в). Свидетель
//! дыры (`door_reason_observable.rs`) остаётся зелёным на этом же дереве и есть гейт (8)
//! «ничего не изменилось».
//!
//! Предмет: релиз-блокер (4) часть B (`ADR-0044`). Обещано Приложением C:1947
//! (`admit_drops_total{reason}`), §4.2:181 (узел обязан различать отзыв и просрочку действиями) и
//! §14.4 (ii) (подотчётность). Измеряется, что из этого стало наблюдаемо после `ADR-0051`:
//! конечный список имён причин, журнал на двери, провод — прежний.
//!
//! Честная граница доказательства (пятый вопрос Lean, «модель или код»): здесь доказательство
//! идёт про КОД, а не про модель. Соответствие таксономии настоящим `enum`'ам держится на двух
//! опорах: полный `match` в `door.rs` не собирается при новом арма, а юнит-таблица
//! `taxonomy_covers_every_handshake_error_variant` сверяет числа. Lean в этом цикле не применён:
//! предмет гейта — наблюдаемость веток продукта, а не свойство, выводимое из алгебры.
//!
//! Факты — только имена, счётчики, булевы выводы и одна побайтовая свёртка корпуса. Времени и
//! счётчиков шагов нет ни в одном гейте (правило 7 (е)): `dr_g2_steps` на одном дереве дал 3 и 5.

#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};

use vecdht_net::door::DoorReason;
use vecdht_net::service::NetService;
use vecdht_node::testing;
use vecdht_wire::messages::Role;

#[path = "door_corpus/mod.rs"]
mod door_corpus;
use door_corpus::*;

/// Снимок журнала как словарь «имя → счётчик»: дельты считать по нему, а не по тексту записей.
fn ledger(node: &NetService) -> BTreeMap<&'static str, u64> {
    node.door_refusals().into_iter().collect()
}

/// Дельта журнала между двумя снимками: (изменённые имена, сумма приростов).
fn delta(before: &BTreeMap<&'static str, u64>, after: &BTreeMap<&'static str, u64>) -> (Vec<String>, u64) {
    let mut changed = Vec::new();
    let mut sum = 0u64;
    for (name, v) in after {
        let d = *v - before.get(name).copied().unwrap_or(0);
        if d > 0 {
            changed.push(format!("{name}+{d}"));
            sum += d;
        }
    }
    (changed, sum)
}

/// DC_G4 · таксономия конечна и полна как тип, а не как обещание: 22 имени, все различны,
/// наибольшие — 24 символа. Ни одна проба не обязана попадать в `unspecified`.
#[test]
fn taxonomy_is_finite_and_named() {
    let all: Vec<&'static str> = DoorReason::ALL.iter().map(|r| r.name()).collect();
    let set: BTreeSet<&str> = all.iter().copied().collect();
    let mut sorted = all.clone();
    sorted.sort();
    sorted.dedup();
    let longest = all.iter().map(|n| n.len()).max().unwrap_or(0);
    println!("МЕРЕНО dc_names_total={} dc_names_distinct={} dc_names_sorted_unique={}", all.len(), set.len(), sorted.len());
    println!("МЕРЕНО dc_max_name_len={longest}");
    assert_eq!(all.len(), 22, "DC_G4: DoorReason::ALL разошёлся с числом 22");
    assert_eq!(set.len(), 22, "DC_G4: два разных DoorReason дали одно имя: {all:?}");
    assert_eq!(longest, 24, "DC_G4: длина наибольшего имени изменилась — носитель причины поехал");
    for r in DoorReason::ALL {
        assert!(!r.name().is_empty(), "DC_G4: пустое имя у {r:?}");
    }
}

/// DC_G5…DC_G9 · живая дверь на корпусе: счётчик считает ЭТУ пробу, имена не текут наружу,
/// столкновения видны, журнал конечен.
#[test]
fn ledger_names_the_cause_of_every_refusal() {
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(async {
        let d = TmpDir::new("counters");
        let mut node = index_service(primary_seed(SHARD), SHARD, d.path(), quic_addr());
        let mut agent = agent_service(PEER_SEED, quic_addr());
        let addr = wait_listen(&mut node).await;
        let _ = wait_listen(&mut agent).await;
        agent.dial(addr).expect("dial узла");
        let (np, ap) = (node.peer_id(), agent.peer_id());
        pump_until(&mut node, &mut agent, |x, y| {
            x.is_authenticated(&ap) && y.is_authenticated(&np)
        })
        .await;

        // Журнал того обмена, которым стороны уже соединились: агент проходит дверь без кредашиала,
        // отказа быть не должно, и это первый контроль прибора — счётчик не набит до корпуса.
        println!(
            "МЕРЕНО dc_before_corpus_total={} dc_before_corpus_entries={}",
            node.door_refusal_total(),
            node.door_refusals().len()
        );
        assert_eq!(node.door_refusal_total(), 0, "DC_G5: до корпуса на двери уже есть отказы — стенд меряет не то");

        let probes = probe_corpus(ap);
        let mut rows: Vec<String> = Vec::new();
        let mut codes: BTreeSet<String> = BTreeSet::new();
        let mut responder_records = 0usize;
        let mut delta_ok = 1usize;
        let mut bad_probes: Vec<String> = Vec::new();
        for (label, frame) in &probes {
            let before = ledger(&node);
            let r = ask_error(&mut node, &mut agent, np, frame.clone(), label).await;
            responder_records += node.take_errors().len();
            let after = ledger(&node);
            let (changed, sum) = delta(&before, &after);
            let want = probe_reason_name(label);
            // Гейт (3): дельта обязана быть ровно на ОДНОМ имени — имени этой пробы. Иначе счётчик
            // либо считает чужие отказы, либо молчит там, где отказ был.
            let ok = match (&r, want) {
                (None, None) => changed.is_empty() && sum == 0,
                (Some(_), Some(w)) => changed.len() == 1 && changed[0] == format!("{w}+1") && sum == 1,
                _ => false,
            };
            if !ok {
                delta_ok = 0;
                bad_probes.push(format!("{label}: ответ={r:?} ждали={want:?} дельта={changed:?} сумма={sum}"));
            }
            match r {
                Some((c, retry, sh, raw)) => {
                    codes.insert(c.clone());
                    rows.push(refusal_row(label, &c, retry, sh, &raw));
                }
                None => rows.push(silent_row(label)),
            }
        }
        for line in &bad_probes {
            println!("МЕРЕНО dc_probe_delta_bad={line}");
        }
        let l = ledger(&node);
        let refusals = node.door_refusal_total();
        let entries = l.len();
        let unspecified = node.door_refusal_count(DoorReason::Unspecified);
        // Мера схлопывания внутри самого журнала: сколько проб названы одним именем `cert_undecodable`
        // потому что их отбивает `NodeCert::decode` раньше верификатора (`cert.rs:78…80`, `:86…88`,
        // `:102…104`, `:110…112`). Это новая дыра, а не старая: имя есть, поле — нет.
        let absorbed = probes
            .iter()
            .filter(|(l, _)| probe_reason_name(l) == Some(DoorReason::CertUndecodable.name()))
            .count();
        let zero_names = DoorReason::ALL.iter().filter(|r| !l.contains_key(r.name())).count();
        println!("МЕРЕНО dc_probe_delta_ok={delta_ok}");
        println!("МЕРЕНО dc_corpus_refusals={refusals} dc_corpus_entries={entries}");
        println!("МЕРЕНО dc_sum_equals_refusals={}", (refusals == 19) as usize);
        println!("МЕРЕНО dc_unspecified_hits={unspecified} dc_zero_names={zero_names}");
        println!("МЕРЕНО dc_decoder_absorbed_probes={absorbed}");
        println!(
            "МЕРЕНО dc_self_cert_revoked_hits={} dc_shard_not_covered_hits={} dc_transport_no_owner_hits={}",
            node.door_refusal_count(DoorReason::SelfCertRevoked),
            node.door_refusal_count(DoorReason::CertShardNotCovered),
            node.door_refusal_count(DoorReason::TransportNoOwner),
        );
        println!(
            "МЕРЕНО dc_collision_sigs_over_name={} dc_collision_time_order_name={}",
            probe_reason_name("cert_sigs_over").unwrap_or("нет-имени"),
            probe_reason_name("cert_from_after_until").unwrap_or("нет-имени"),
        );
        println!(
            "МЕРЕНО dc_below_threshold_count={} dc_not_yet_valid_count={}",
            node.door_refusal_count(DoorReason::CertBelowThreshold),
            node.door_refusal_count(DoorReason::CertNotYetValid),
        );
        println!("МЕРЕНО dc_wire_codes={}", codes.len());
        println!("МЕРЕНО dc_responder_errors_empty={}", (responder_records == 0) as usize);
        println!("МЕРЕНО dc_frame_digest={}", digest(&rows));

        assert_eq!(delta_ok, 1, "DC_G5: дельта журнала не совпала с отказом пробы: {bad_probes:?}");
        assert_eq!(refusals, 19, "DC_G5: журнал записал не 19 отказов: {l:?}");
        // 15, а не замороженные 17: четыре пробы, которые первая редакция таблицы приписала
        // верификатору, отбивает декодер кредашиала, и они называются одним именем. Порог (6)
        // замёрз другим числом и остался НЕ ВЫПОЛНЕННЫМ — это ДИАГНОЗ цикла, а не повод править
        // `lab/expectations/e0095.tsv` внутри замера.
        assert_eq!(entries, 15, "DC_G6: наблюдаемых имён на корпусе не 15: {l:?}");
        assert_eq!(unspecified, 0, "DC_G6: безымянная ветка осталась — дыра переехала, а не закрыта");
        assert_eq!(zero_names, 7, "DC_G6: имён, которых на этой двери не бывает, не семь: {l:?}");
        assert_eq!(absorbed, 5, "DC_G7: имя `cert_undecodable` собрано не из пяти проб: {l:?}");
        assert_eq!(
            node.door_refusal_count(DoorReason::SelfCertRevoked),
            0,
            "DC_G6: ветка :643 сработала на стенде, где её ждать нечего"
        );
        assert_eq!(
            node.door_refusal_count(DoorReason::CertShardNotCovered),
            0,
            "DC_G6: verify_index_cert стал вызываться из vecdht-net — этот факт вне замера"
        );
        assert_eq!(
            node.door_refusal_count(DoorReason::TransportNoOwner),
            0,
            "DC_G6: NoOwner оказался достижим над QUIC — перепроверить ветку"
        );
        assert_eq!(codes.len(), 2, "DC_G9: набор кодов на проводе изменился: {codes:?}");
        assert_eq!(responder_records, 0, "DC_G9: на дверь утекли записи с текстом — тесты E-0085/E-0087/E-0094 поедут");
        assert_eq!(
            digest(&rows),
            "3fad1a705c2b7db33352d72e3dd44a77620232e911a8d3338080f163b8e87f25",
            "DC_G9: корпус дал другую свёртку — либо правка тронула провод, либо корпуса разъехались"
        );

        // Гейт (7): журнал остаётся числом имён, сколько бы отказов ни произошло.
        for _ in 1..4 {
            for (label, frame) in &probes {
                let _ = ask_error(&mut node, &mut agent, np, frame.clone(), label).await;
                let _ = node.take_errors();
            }
        }
        println!(
            "МЕРЕНО dc_after_repeats_entries={} dc_after_repeats_total={}",
            node.door_refusals().len(),
            node.door_refusal_total()
        );
        assert!(
            node.door_refusals().len() <= DoorReason::ALL.len(),
            "DC_G7: записей больше, чем имён: журнал вырос вместе с отказами"
        );
        assert_eq!(
            node.door_refusals().len(),
            15,
            "DC_G7: после повторов наблюдаемых имён стало не 15 — журнал растёт не по имени"
        );
        assert_eq!(node.door_refusal_total(), 76, "DC_G7: счётчик схлопнулся в булевы флаги вместо 19×4");

        // Гейт (6) на счётчике: «отзовут» и «истёк» — разные имена при одном кадре на проводе.
        let victim = base_cert(agent.peer_id());
        let nonce = victim.nonce;
        let revoke = revoke_for(nonce);
        let mut steps = 0usize;
        while node.revocation_count() == 0 {
            assert!(steps < 6_000, "DC_G8: отзыв не дошёл до двери за 6000 шагов (цена = {steps})");
            let _ = agent.publish_revoke(&revoke);
            node.step().await;
            agent.step().await;
            steps += 1;
        }
        let before = ledger(&node);
        let rv = ask_error(&mut node, &mut agent, np, good_greeting(Role::IndexNode, Some(&victim)), "revoked").await;
        let after_rv = ledger(&node);
        let (rv_changed, rv_sum) = delta(&before, &after_rv);
        let now = now_sec() as u32;
        let expired_cert = testing::node_cert(
            PEER_SEED,
            agent.peer_id().to_bytes(),
            vec![SHARD],
            Role::IndexNode,
            0,
            now - 1,
        );
        let ex = ask_error(&mut node, &mut agent, np, good_greeting(Role::IndexNode, Some(&expired_cert)), "expired").await;
        let after_ex = ledger(&node);
        let (ex_changed, ex_sum) = delta(&after_rv, &after_ex);
        let revoked_name = rv_changed.first().map(|s| s.split('+').next().unwrap().to_string()).unwrap_or_default();
        let expired_name = ex_changed.first().map(|s| s.split('+').next().unwrap().to_string()).unwrap_or_default();
        let three: BTreeSet<&str> = [
            DoorReason::CertRevoked.name(),
            DoorReason::CertExpired.name(),
            DoorReason::CertBelowThreshold.name(),
        ]
        .into_iter()
        .collect();
        println!("МЕРЕНО dc_revoke_steps={steps} dc_revoked_delivered={}", (rv.is_some()) as usize);
        println!("МЕРЕНО dc_expired_delivered={}", (ex.is_some()) as usize);
        println!("МЕРЕНО dc_revoked_name={revoked_name} dc_expired_name={expired_name}");
        println!("МЕРЕНО dc_revoked_counter={rv_sum} dc_expired_counter={ex_sum}");
        println!("МЕРЕНО dc_three_actions_distinct={}", three.len());
        assert_eq!(rv_sum, 1, "DC_G8: отзыв посчитан не ровно один раз: {rv_changed:?}");
        assert!(rv.is_some() && ex.is_some(), "DC_G8: сцена отзыва не дала двух отказов");
        assert_eq!(ex_sum, 1, "DC_G8: просрочка посчитана не ровно один раз: {ex_changed:?}");
        assert_eq!(revoked_name, "cert_revoked", "DC_G8: отказ по отзыву назван как {revoked_name}");
        assert_eq!(expired_name, "cert_expired", "DC_G8: отказ по просрочке назван как {expired_name}");
        assert_eq!(three.len(), 3, "DC_G8: три разных действия схлопнулись в одно имя");
        // Имена, которых на этой двери не было ни разу за весь цикл: корпус, четыре повтора и сцена
        // отзыва. Список, а не число: «недостижимо» и «не случилось» — разные утверждения, и их
        // различие как раз видно по именам (`cert_revoked` из списка исчезает именно в сцене отзыва).
        let final_ledger = ledger(&node);
        let never: Vec<&str> = DoorReason::ALL
            .iter()
            .map(|r| r.name())
            .filter(|n| !final_ledger.contains_key(n))
            .collect();
        println!("МЕРЕНО dc_unreachable_names={}", never.join(","));
        println!("МЕРЕНО dc_counters=ok");
    });
}
