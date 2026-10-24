//! H-0095 / E-0095 · оракул 1/2: причина отказа двери не наблюдаема ни одной из сторон.
//!
//! Предмет — релиз-блокер (4) часть B (`ADR-0044`), голова очереди после `E-0094`. Обещано:
//! Приложение C:1947 называет метрику `admit_drops_total{reason}` — счётчик отказов с разметкой
//! ПРИЧИНЫ (плюс `sig_failures`, `model_mismatch_total`, `cert_revoke_seen`); §4.2:181 обязывает
//! узел различать отзыв, потому что действия у «отзовали» и «истёк» разные; §14.4 (ii):1250 делает
//! узел подотчётным. Здесь измеряется, доходит ли из этого хоть что-то до наблюдателя на живой двери.
//!
//! Файл намеренно не зовёт ничего, чего в дереве до фикса нет: он обязан компилироваться и
//! исполняться на PRE_FIX, иначе отказ неотличим от опечатки (урок `E-0094`). Гейты, которым нужен
//! счётчик причин, живут в `door_reason_counters.rs` и приходят вместе с фиксом. Именно поэтому
//! этот файл обязан остаться зелёным И ПОСЛЕ правки: он и есть гейт (8) «ничего не изменилось» —
//! провод не тронут, а `take_errors()` отказавшей стороны на всём корпусе остаётся пустым.
//!
//! Стенд: один процесс, настоящий QUIC на loopback, `current_thread`. Харнес и корпус проб вынесены
//! в `tests/door_corpus/mod.rs` и общие с файлом счётчиков: два скопированных корпуса неминуемо
//! разъезжаются, и «тот же корпус, что на PRE_FIX» перестало бы что-то значить; разъезд виден по
//! свёртке — `dr_frame_digest` этого файла обязан совпасть с `dc_frame_digest` того.
//!
//! Факты — только коды, длины, побайтовые свёртки кадров и булевы решения двери: ни одного
//! временнóго предсказания, поэтому правило 7 пункт (е) выполнено по построению.

#![allow(dead_code)]

use std::collections::BTreeSet;
use std::time::Duration;

use vecdht_net::keys;
use vecdht_node::testing;
use vecdht_wire::frame::{decode_frame, Kind};
use vecdht_wire::messages::Role;

#[path = "door_corpus/mod.rs"]
mod door_corpus;
use door_corpus::*;

/// DR_G1 · двадцать проб к живой двери: девятнадцать отказов двумя кадрами (восемнадцать
/// одинаковых `CERT_INVALID` и один `BAD_ENUM`), одна проба вообще без ответа, и ни одна сторона не
/// называет причину.
///
/// Корпус: двенадцать кредашиальных причин (из них две пары заведомо дают одну и ту же ветку кода —
/// см. `PROBE_CAUSES`), четыре причины заголовка, роль и комплект («агент с кредашиалом», «узлу
/// кредашиала не досталось»), один кадр с незнакомым видом (`BAD_ENUM`) — итого девятнадцать
/// отказов; двадцатая проба «мусор вместо кадра» отказа на проводе не получает вообще, ей отвечает
/// молчание: её отбивает `FrameCodec::read_request` ещё до `on_request`. Контроль годности прибора —
/// корректное приветствие, которому дверь обязана радоваться: без него «один код» неотличим от
/// стенда, который отказывает всегда.
#[test]
fn door_refusals_collapse_to_one_code_and_leave_no_names() {
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(async {
        let d = TmpDir::new("codes");
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

        let probes = probe_corpus(ap);

        // Контроль годности прибора: корректное приветствие отказа не даёт. Без этого строка
        // «восемнадцать отказов, один код» была бы неотличима от стенда, который отказывает всегда.
        let control = ask_error(
            &mut node,
            &mut agent,
            np,
            good_greeting(Role::Agent, None),
            "control_agent_greeting",
        )
        .await;
        println!("МЕРЕНО dr_control_refused={}", control.is_some() as usize);
        assert!(control.is_none(), "DR_G1: контроль отказал — корректное приветствие двери не принято");
        assert!(node.is_authenticated(&ap), "DR_G1: после контроля дверь разжала аутентификацию");

        let mut codes: BTreeSet<String> = BTreeSet::new();
        let mut frames: BTreeSet<String> = BTreeSet::new();
        let mut refused = 0usize;
        let mut silent = 0usize;
        let mut responder_named = 0usize;
        let mut initiator_named = 0usize;
        let mut named_over = 0usize;
        let mut rows: Vec<String> = Vec::new();
        for (label, frame) in &probes {
            let r = ask_error(&mut node, &mut agent, np, frame.clone(), label).await;
            // Дреним записи обеих сторон по каждой пробе: счётчик обязан считать причину этой
            // пробы, а не накопленный за предыдущие пробы текст.
            let rr = node.take_errors();
            let ir = agent.take_errors();
            let cause = probe_cause(label);
            if let Some(cause) = cause {
                named_over += 1;
                if names_cause(&rr, cause) {
                    responder_named += 1;
                    rows.push(format!("{label}=НАЗВАНО_ОТВЕТЧИКОМ:{cause}"));
                }
                if names_cause(&ir, cause) {
                    initiator_named += 1;
                    rows.push(format!("{label}=НАЗВАНО_ИНИЦИАТОРОМ:{cause}"));
                }
            }
            match r {
                Some((c, retry, s, raw)) => {
                    refused += 1;
                    codes.insert(c.clone());
                    frames.insert(hex::encode(&raw));
                    rows.push(format!("{label}={c}:{retry}:{s}:{}", hex::encode(&raw)));
                    println!("МЕРЕНО dr_probe_{label}_code={c} dr_probe_{label}_len={}", raw.len());
                    println!(
                        "МЕРЕНО dr_probe_{label}_responder_records={} dr_probe_{label}_responder_named={} dr_probe_{label}_initiator_records={} dr_probe_{label}_initiator_named={}",
                        rr.len(),
                        // «none», а не 0: у двух проб ожидаемой причины нет вовсе, и печатать для
                        // них «не названо» было бы правкой утверждения о другом факте.
                        cause.map_or_else(|| "none".to_string(), |x| (names_cause(&rr, x) as usize).to_string()),
                        ir.len(),
                        cause.map_or_else(|| "none".to_string(), |x| (names_cause(&ir, x) as usize).to_string()),
                    );
                }
                None => {
                    silent += 1;
                    rows.push(format!("{label}=без-ответа"));
                    println!("МЕРЕНО dr_probe_{label}_code=без-ответа dr_probe_{label}_len=0");
                }
            }
        }
        let responder_total = cause_records(&node.take_errors());
        let ci = rows.iter().filter(|r| r.contains("=CERT_INVALID:")).count();
        println!("МЕРЕНО dr_probes={} dr_refused={refused} dr_silent={silent}", probes.len());
        println!("МЕРЕНО dr_distinct_codes={}", codes.len());
        println!("МЕРЕНО dr_distinct_refusal_frames={}", frames.len());
        println!("МЕРЕНО dr_certinvalid_family={ci}");
        println!("МЕРЕНО dr_probes_with_named_cause={named_over}");
        println!("МЕРЕНО dr_responder_named={responder_named} dr_initiator_named={initiator_named}");
        println!("МЕРЕНО dr_responder_tail_named={responder_total}");
        println!("МЕРЕНО dr_frame_digest={}", digest(&rows));

        assert_eq!(refused, 19, "DR_G1: отказов на проводе не 19: {rows:?}");
        assert_eq!(silent, 1, "DR_G1: молчаливых проб не одна: {rows:?}");
        assert_eq!(codes.len(), 2, "DR_G1: набор кодов на проводе изменился: {codes:?}");
        assert_eq!(ci, 18, "DR_G1: в семью CERT_INVALID попало не 18 проб: {rows:?}");
        assert_eq!(
            frames.len(),
            2,
            "DR_G1: различных байтовых кадров отказа не два (CERT_INVALID + BAD_ENUM) — провод изменился"
        );
        assert_eq!(named_over, 18, "DR_G1: проб с именуемой причиной не 18");
        assert_eq!(responder_named, 0, "DR_G1: отказавшая сторона уже называет причину");
        assert_eq!(initiator_named, 0, "DR_G1: инициирующая сторона уже называет причину отказа двери");
        assert_eq!(responder_total, 0, "DR_G1: в хвосте записей двери появились имена причин");
        println!("МЕРЕНО dr_g1=ok");
    });
}

/// DR_G2 · «истёк» и «отзовут» дают один и тот же кадр, а §4.2:181 требует различать их действиями.
///
/// Отзыв рассылает сам носитель (агент): `control_topic` подписана в `NetService::new`
/// (`service.rs:282`), а кадры отзыва под фильтр двери не попадают (§4.2, ADR-0043 — «кадры
/// членства и отзыва обязаны доходить даже от пира, с которым двери ещё не было»). Второй узел
/// для рассылки не нужен, и это не мелочь: второй узел из ростера `[1,2,3]` совпадает по сидам с
/// primary шарда 7, а dial самого себя транспорт отбивает error'ом — стенд молчал бы по причине
/// нумерации сидов, а не по причине, которую измеряет гейт (так и вышло на первой сборке).
#[test]
fn expiry_and_revocation_are_the_same_bytes() {
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(async {
        let d = TmpDir::new("pair");
        let mut door = index_service(primary_seed(SHARD), SHARD, d.path(), quic_addr());
        let mut carrier = agent_service(PEER_SEED, quic_addr());
        let door_addr = wait_listen(&mut door).await;
        let _ = wait_listen(&mut carrier).await;
        carrier.dial(door_addr).expect("dial двери носителем");
        let dp = door.peer_id();
        pump_until(&mut door, &mut carrier, |a, b| {
            a.is_authenticated(&b.peer_id()) && b.is_authenticated(&a.peer_id())
        })
        .await;

        let victim = base_cert(carrier.peer_id());
        let nonce = victim.nonce;
        let revoke = revoke_for(nonce);
        let mut steps = 0usize;
        while door.revocation_count() == 0 {
            assert!(steps < 6_000, "DR_G2: отзыв не дошёл до двери за 6000 шагов");
            let _ = carrier.publish_revoke(&revoke);
            door.step().await;
            carrier.step().await;
            steps += 1;
        }
        println!(
            "МЕРЕНО dr_g2_revoke_delivered=1 dr_g2_steps={steps} dr_g2_revocation_count={} dr_g2_knows={}",
            door.revocation_count(),
            door.is_revoked_nonce(&nonce) as usize
        );

        let now = now_sec() as u32;
        let expired_cert = testing::node_cert(
            PEER_SEED,
            carrier.peer_id().to_bytes(),
            vec![SHARD],
            Role::IndexNode,
            0,
            now - 1,
        );
        let a = ask_error(&mut door, &mut carrier, dp, good_greeting(Role::IndexNode, Some(&victim)), "revoked")
            .await;
        let b = ask_error(
            &mut door,
            &mut carrier,
            dp,
            good_greeting(Role::IndexNode, Some(&expired_cert)),
            "expired",
        )
        .await;
        let (ra, rb) = (a.expect("отзыв не дал отказа"), b.expect("просрочка не дала отказа"));
        let door_records = door.take_errors();
        let revoked_named = names_cause(&door_records, "cert is revoked by nonce") as usize;
        let expired_named = names_cause(&door_records, "expired: now=") as usize;
        let named = cause_records(&door_records);
        println!("МЕРЕНО dr_g2_revoked_code={} dr_g2_expired_code={}", ra.0, rb.0);
        println!("МЕРЕНО dr_g2_bytes_equal={}", (ra.3 == rb.3) as usize);
        println!("МЕРЕНО dr_g2_frame_len={}", ra.3.len());
        println!("МЕРЕНО dr_g2_responder_records={}", door_records.len());
        println!("МЕРЕНО dr_g2_responder_named={named} dr_g2_revoked_named={revoked_named} dr_g2_expired_named={expired_named}");
        assert_eq!(ra.0, "CERT_INVALID", "DR_G2: отказ по отзыву именуется кодом {}", ra.0);
        assert_eq!(rb.0, "CERT_INVALID", "DR_G2: отказ по просрочке именуется кодом {}", rb.0);
        assert_eq!(ra.3, rb.3, "DR_G2: байты отказа для разных причин различаются — провод сломан");
        assert_eq!(named, 0, "DR_G2: причина уже наблюдаема локально — дыра иная: {door_records:?}");
        assert_eq!(revoked_named, 0, "DR_G2: отзыв назван на двери без счётчика причин");
        assert_eq!(expired_named, 0, "DR_G2: просрочка названа на двери без счётчика причин");
    });
}

/// DR_G3 · узел с просроченным собственным кредашиалом стучится, не получает ответа, на который
/// умеет смотреть, и не знает ни причины, ни того, что пора остановиться.
///
/// Три факта, каждый годен и до, и после счётчика причин: (`а`) кадр отказа не попадает в inbox
/// приложения — ответ на handshake маршрутизируется через `on_response`/`Pending::Handshake`
/// (`service.rs:696…717`) и тонет там, не дойдя до `route_inbound`; (`б`) узел не считает себя
/// отозванным и не имеет предиката «мой кредашиал истёк» — `is_self_revoked` про отзыв, а
/// `valid_until` своего сертификата сервис не читает; (`в`) единственная запись, которую узел
/// делает, — жалоба на СОБСТВЕННЫЙ неразбор ответа двери, а не имя причины отказа. Именно (`в`)
/// делает дыру наблюдаемой: текст «кредашиал не разобран» в записях есть, а строки «expired: now=»
/// — нет.
#[test]
fn expired_self_node_keeps_knocking_and_learns_nothing() {
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(async {
        let d = TmpDir::new("selfhealthy");
        let now = now_sec() as u32;
        let mut door = index_service(primary_seed(SHARD), SHARD, d.path(), quic_addr());
        let door_addr = wait_listen(&mut door).await;

        let bad_peer = keys::peer_id(&testing::identity(PEER_SEED));
        let expired_cert = testing::node_cert(
            PEER_SEED,
            bad_peer.to_bytes(),
            vec![SHARD_B],
            Role::IndexNode,
            0,
            now - 1,
        );
        let mut expired = raw_cert_service(PEER_SEED, quic_addr(), expired_cert);
        let _ = wait_listen(&mut expired).await;
        expired.dial(door_addr.clone()).expect("dial двери просроченным узлом");
        let ep = expired.peer_id();

        let mut error_frames = 0usize;
        let mut inbox_frames = 0usize;
        for _ in 0..800 {
            expired.step().await;
            door.step().await;
            for (_, f) in expired.take_inbox() {
                inbox_frames += 1;
                if decode_frame(&f).is_ok_and(|k| k.header.kind == Kind::Error) {
                    error_frames += 1;
                }
            }
        }
        let expired_records = expired.take_errors();
        let any_cause = cause_records(&expired_records);
        let own_parse =
            expired_records.iter().filter(|r| r.contains("кредашиал не разобран:")).count();
        let names_expiry = names_cause(&expired_records, "expired: now=") as usize;
        println!("МЕРЕНО dr_g3_inbox_frames={inbox_frames} dr_g3_error_frames={error_frames}");
        println!("МЕРЕНО dr_g3_door_authenticated={}", door.is_authenticated(&ep) as usize);
        println!("МЕРЕНО dr_g3_self_revoked={}", expired.is_self_revoked() as usize);
        println!("МЕРЕНО dr_g3_records={} dr_g3_records_any_cause={any_cause} dr_g3_records_own_parse={own_parse}", expired_records.len());
        // Число записей — производная расписания шагов (узел стучится, пока дверь не ответит), а
        // не свойство кода, поэтому в вектор воспроизводимости и в таблицу ожиданий идёт только
        // булев вывод «хотя бы одна запись про собственный разбор есть» (правило 7 пункт (е)).
        println!("МЕРЕНО dr_g3_has_own_parse={}", (own_parse >= 1) as usize);
        println!("МЕРЕНО dr_g3_names_expiry={names_expiry}");
        println!("МЕРЕНО dr_g3_record_tail={:?}", expired_records.last());
        assert_eq!(error_frames, 0, "DR_G3: кадр отказа стал виден приложению — провод изменился");
        assert!(!door.is_authenticated(&ep), "DR_G3: дверь пустила просроченный ключ");
        assert!(!expired.is_self_revoked(), "DR_G3: узел считает себя отозванным, хотя просрочен");
        assert_eq!(names_expiry, 0, "DR_G3: узел называет причину отказа двери: {expired_records:?}");
        assert!(
            !expired_records.is_empty(),
            "DR_G3: узел вообще не делает записей — стенд молчит, и проверять нечего"
        );
        assert!(
            own_parse >= 1,
            "DR_G3: ни одна запись узла не про его собственный разбор ответа — стенд ловит не то: {expired_records:?}"
        );

        // Контроль годности замера: действующий кредашиал двери проходит. Транспорт — ДРУГОЙ сид:
        // тот же PeerId, что у просроченного узла, заставил бы дверь спорить с самим собой.
        let good_peer = keys::peer_id(&testing::identity(HEALTHY_SEED));
        let good_cert = testing::node_cert(
            HEALTHY_SEED,
            good_peer.to_bytes(),
            vec![SHARD_B],
            Role::IndexNode,
            0,
            now + 3_600,
        );
        let mut healthy = raw_cert_service(HEALTHY_SEED, quic_addr(), good_cert);
        let _ = wait_listen(&mut healthy).await;
        healthy.dial(door_addr).expect("dial двери здоровым узлом");
        let hp = healthy.peer_id();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        while !door.is_authenticated(&hp) && tokio::time::Instant::now() < deadline {
            door.step().await;
            healthy.step().await;
        }
        println!("МЕРЕНО dr_g3_healthy_control={}", door.is_authenticated(&hp) as usize);
        assert!(door.is_authenticated(&hp), "DR_G3: контроль не прошёл — стенд меряет отсутствие сети");
    });
}
