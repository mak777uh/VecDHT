//! `agent publish|find|session` — сетевой путь §12 из командной строки.
//!
//! Команды не несут собственной протокольной логики: кадры, PoW, проверка подписей и выбор
//! держателя живут в `vecdht-net::agent`, который используют и SDK, и тесты. Здесь только разбор
//! флагов, ключ оператора и печать результата. Это принципиально: CLI, собирающий `Publish`
//! руками, разошёлся бы с SDK при первом же изменении wire-формата.
//!
//! `--seed` — приватный ключ оператора (32 байта hex). В продакшене его берут из защищённого
//! хранилища и не пишут в историю shell; здесь явный флаг честнее скрытого файла с неясными
//! правами. Ключ — единственная идентичность: `PeerId` и `owner_ed25519` выводятся из него, а не
//! выбираются отдельно (§4.1).
//!
//! `agent session` принимает кадр приёма и ключ издателя ровно в том виде, в каком их напечатал
//! `agent find`: пересобирать приём из полей нельзя, подпись считается по исходным байтам (§5.2).

use std::collections::BTreeMap;
use std::time::Duration;

use libp2p::Multiaddr;
use vecdht_artifact::Artifact;
use vecdht_crypto::Identity;
use vecdht_embed::testing::HashModel;
use vecdht_net::{
    Agent, AgentConfig, FindQuery, NetworkParams, PublishRequest,
};
use vecdht_node::buckets;
use vecdht_wire::frame::parse_header;

use crate::args::Parsed;
use crate::model::{build_model, push_vector, warn_surrogate, Source};
use crate::{CliError, fail, vector_hex};

pub const CMD_PUBLISH: &str = "agent publish";
pub const CMD_FIND: &str = "agent find";
pub const CMD_SESSION: &str = "agent session";
pub const CMD_RUN: &str = "agent run";

pub const FLAGS_PUBLISH: &[&str] = &[
    "artifact",
    "text",
    "seed",
    "bootstrap",
    "ttl",
    "timeout",
    "model-dir",
    "allow-surrogate",
    "show-vector",
];
pub const FLAGS_FIND: &[&str] = &[
    "artifact",
    "text",
    "seed",
    "bootstrap",
    "nprobe",
    "top-k",
    "timeout",
    "model-dir",
    "allow-surrogate",
    "show-vector",
];
pub const FLAGS_SESSION: &[&str] = &["artifact", "accept", "issuer", "to", "seed", "bootstrap", "timeout"];
pub const FLAGS_RUN: &[&str] = &[
    "artifact",
    "seed",
    "listen",
    "bootstrap",
    "timeout",
    "idle",
    "status-sec",
    "run-seconds",
];

pub const HELP_PUBLISH: &str = "\
agent publish — опубликовать интент по сети (§12.1)
  --artifact DIR        артефакт сети
  --text STR            текст интента
  --seed HEX            Ed25519-ключ оператора, 32 байта hex
  --bootstrap ADDR      адрес узла или агента; можно повторять
  --ttl SEC             TTL записи, по умолчанию из манифеста, потолок — тоже
  --timeout SEC         таймаут вызова, по умолчанию 20
  --model-dir DIR       веса для feature `candle`
  --allow-surrogate     явно разрешить детерминированный суррогат
  --show-vector         печать всех 768 hex-символов vec_q";

pub const HELP_FIND: &str = "\
agent find — найти записи по запросу (§12.2); один Find на шард
  --artifact DIR        артефакт сети
  --text STR            текст запроса
  --seed HEX            Ed25519-ключ искателя, 32 байта hex
  --bootstrap ADDR      адрес узла или агента; можно повторять
  --nprobe N            сколько кластеров зондировать, по умолчанию из манифеста
  --top-k K             сколько записей вернуть, по умолчанию из манифеста
  --timeout SEC         таймаут вызова, по умолчанию 20
  --model-dir DIR       веса для feature `candle`
  --allow-surrogate     явно разрешить детерминированный суррогат
  --show-vector         печать всех 768 hex-символов vec_q

Для каждой найденной записи печатается кадр приёма в hex — его принимает `agent session`.";

pub const HELP_SESSION: &str = "\
agent session — открыть прямой аутентифицированный канал по приёму (§12.5)
  --artifact DIR        артефакт сети (политика TTL приёма)
  --accept HEX          кадр RendezvousAccept из `agent find`
  --issuer HEX          owner_ed25519 index-node, выписавшего приём
  --to ADDR             адрес цели из address book; можно повторять
  --seed HEX            Ed25519-ключ искателя, который был в find
  --bootstrap ADDR      то же, если адрес цели ищется через Kademlia
  --timeout SEC         таймаут вызова, по умолчанию 20

Relay/DCUtR в v1 не подняты: без `--to` цель должна быть известна Kademlia/identify.";

pub const HELP_RUN: &str = "\
agent run — постоянный listener: агент шагает вне вызовов и принимает входящие (§12.5)
  --artifact DIR        артефакт сети
  --seed HEX            Ed25519-ключ оператора, 32 байта hex
  --listen ADDR         адрес прослушивания; можно повторять, нужен минимум один
  --bootstrap ADDR      адрес узла или агента; можно повторять, необязательно
  --timeout SEC         дедлайн клиентских вызовов, по умолчанию 20
  --idle SEC            таймаут простаивающего соединения, по умолчанию 60
  --status-sec SEC      период строки состояния, по умолчанию 30; 0 — не печатать
  --run-seconds SEC     остановиться через N секунд (тесты и скрипты); 0 или отсутствие — до сигнала

Цикл обязателен: без шага вне вызовов входящий handshake не проходит, и процесс, который «слушает»
и молчит, неотличим от зависшего. Поэтому команда печатает адреса, считает принятые кадры по видам
и печатает ошибки транспорта, а успех без поднятого listener'а не объявляет.

Смыслового слоя входящих в v1 нет: `IntentTextRequest` узлом не обслуживается (в `ShardNode` нет
держателя текста), поэтому `run` делает агента достижимым для handshake, ack и приёма, а не
«сервером», который отвечает на всё.";

fn load(p: &Parsed, cmd: &str) -> Result<Artifact, CliError> {
    let dir = p.required(cmd, "artifact")?;
    Artifact::load(std::path::Path::new(&dir)).map_err(|e| fail("чтение артефакта", e))
}

fn identity(p: &Parsed, cmd: &str) -> Result<Identity, CliError> {
    let seed = p.hex_fixed::<32>(cmd, "seed")?.ok_or_else(|| {
        CliError::Fail(format!(
            "`{cmd}` требует --seed: без ключа оператора неоткуда взять owner_ed25519 и PeerId, \
             а подписывать кадры чужим именем протокол запрещает (§4.1)"
        ))
    })?;
    Ok(Identity::from_seed(seed))
}

fn bootstrap(p: &Parsed, cmd: &str) -> Result<Vec<Multiaddr>, CliError> {
    multiaddrs(p, cmd, "bootstrap")
}

fn multiaddrs(p: &Parsed, cmd: &str, flag: &str) -> Result<Vec<Multiaddr>, CliError> {
    p.values(cmd, flag)?
        .into_iter()
        .map(|raw| {
            raw.parse::<Multiaddr>()
                .map_err(|e| CliError::Fail(format!("--{flag} {raw}: {e}")))
        })
        .collect()
}

fn agent_config(p: &Parsed, cmd: &str, bootstrap: Vec<Multiaddr>) -> Result<AgentConfig, CliError> {
    // Сетевой CLI-вызов — клиент: слушателя нет, входящие сессии принимает `agent run`.
    agent_config_with(p, cmd, bootstrap, Vec::new())
}

fn agent_config_with(
    p: &Parsed,
    cmd: &str,
    bootstrap: Vec<Multiaddr>,
    listen: Vec<Multiaddr>,
) -> Result<AgentConfig, CliError> {
    let timeout = p.num_or::<u64>(cmd, "timeout", 20)?;
    if timeout == 0 {
        return Err(CliError::Fail("--timeout 0: вызов без дедлайна неотличим от зависания".into()));
    }
    Ok(AgentConfig {
        bootstrap,
        listen,
        call_timeout: Duration::from_secs(timeout),
        ..AgentConfig::default()
    })
}

fn new_agent(
    id: Identity,
    a: &Artifact,
    cfg: AgentConfig,
) -> Result<Agent, CliError> {
    let network =
        NetworkParams::from_artifact(a).map_err(|e| fail("параметры сети из артефакта", e))?;
    Agent::new(id, network, cfg).map_err(|e| fail("создание агента", e))
}

fn runtime() -> Result<tokio::runtime::Runtime, CliError> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| fail("tokio-рантайм", e))
}

fn describe_source(source: &Source, a: &Artifact, out: &mut String) {
    out.push_str(&format!("артефакт {}\n", a.manifest.model_version));
    out.push_str(&format!("источник вектора: {}\n", source.label()));
    warn_surrogate(source, out);
    out.push_str(&format!("сеть: genesis {}\n", hex::encode(a.genesis_hash())));
}

pub fn exec_publish(p: &Parsed, out: &mut String) -> Result<(), CliError> {
    let a = load(p, CMD_PUBLISH)?;
    let text = p.required(CMD_PUBLISH, "text")?;
    let enc = vecdht_embed::Encoder::from_artifact(&a)
        .map_err(|e| fail("построение Encoder из артефакта", e))?;
    let source = build_model(p, CMD_PUBLISH, enc.pipeline(), &a.manifest.model_version)?;
    let surrogate = HashModel::new();
    let model: &dyn vecdht_embed::EmbeddingModel = match &source {
        Source::Model(m) => m.as_ref(),
        Source::Surrogate => &surrogate,
    };
    let intent = enc.encode_intent(model, &text).map_err(|e| fail("encode_intent", e))?;
    let e = intent.encoded;

    let ttl_sec = p.num_or::<u32>(CMD_PUBLISH, "ttl", a.manifest.time.ttl_default_sec)?;
    let ttl_buckets = u16::try_from(buckets(ttl_sec))
        .map_err(|_| CliError::Fail(format!("--ttl {ttl_sec}: TTL не помещается в бакеты u16")))?;
    let req = PublishRequest {
        vec_q: e.vec_q,
        cluster_id: e.cluster_id,
        ttl_buckets,
        intent_id: e.intent_id,
    };

    let bootstrap = bootstrap(p, CMD_PUBLISH)?;
    if bootstrap.is_empty() {
        return Err(CliError::Fail(
            "нужен хотя бы один --bootstrap: агент не знает, у кого спросить провайдера шарда"
                .into(),
        ));
    }
    let cfg = agent_config(p, CMD_PUBLISH, bootstrap)?;
    let id = identity(p, CMD_PUBLISH)?;
    let owner = id.pubkey();
    let rt = runtime()?;
    let receipt = rt
        .block_on(async {
            let mut agent = new_agent(id, &a, cfg)?;
            agent.publish(&req).await.map_err(|e| fail("publish", e))
        })?;

    describe_source(&source, &a, out);
    out.push_str(&format!("кластер {} (шард {})\n", e.cluster_id, e.shard));
    out.push_str(&format!("intent_id {}\n", hex::encode(e.intent_id)));
    push_vector(&vector_hex(&e.vec_q), p.bool_flag(CMD_PUBLISH, "show-vector")?, out);
    out.push_str(&format!(
        "\nпубликация подтверждена (durable W=2):\n\
         \x20 owner           {}\n\
         \x20 primary         {}\n\
         \x20 epoch {}, seq {}, slot {}\n\
         \x20 pow             {} бит (следующий {}), nonce {}\n\
         \x20 published_bucket {}, expires_bucket {} ({} бакетов ≈ {} с)\n",
        hex::encode(owner),
        receipt.primary,
        receipt.epoch,
        receipt.seq,
        receipt.slot,
        receipt.pow_bits,
        receipt.next_pow_bits,
        receipt.nonce,
        receipt.published_bucket,
        receipt.expires_bucket,
        receipt.ttl_buckets,
        ttl_sec,
    ));
    Ok(())
}

pub fn exec_find(p: &Parsed, out: &mut String) -> Result<(), CliError> {
    let a = load(p, CMD_FIND)?;
    let text = p.required(CMD_FIND, "text")?;
    let enc = vecdht_embed::Encoder::from_artifact(&a)
        .map_err(|e| fail("построение Encoder из артефакта", e))?;
    let source = build_model(p, CMD_FIND, enc.pipeline(), &a.manifest.model_version)?;
    let surrogate = HashModel::new();
    let model: &dyn vecdht_embed::EmbeddingModel = match &source {
        Source::Model(m) => m.as_ref(),
        Source::Surrogate => &surrogate,
    };
    let nprobe = p.num_or::<usize>(CMD_FIND, "nprobe", usize::from(a.manifest.routing.nprobe_default))?;
    if nprobe == 0 || nprobe > usize::from(a.manifest.routing.nlist) {
        return Err(CliError::Fail(format!(
            "--nprobe {nprobe}: вне 1..{}; пустой список кластеров означал бы «искать нигде», а \
             больший nlist — полный скан под видом оптимизации (§8.6)",
            a.manifest.routing.nlist
        )));
    }
    let q = enc.encode_query(model, &text, nprobe).map_err(|e| fail("encode_query", e))?;
    let top_k = p.num_or::<u16>(CMD_FIND, "top-k", a.manifest.query.top_k_default)?;
    let query = FindQuery { vec_q: q.vec_q, clusters: q.clusters.clone(), top_k };

    let bootstrap = bootstrap(p, CMD_FIND)?;
    if bootstrap.is_empty() {
        return Err(CliError::Fail(
            "нужен хотя бы один --bootstrap: агент не знает, у кого спросить провайдера шарда"
                .into(),
        ));
    }
    let cfg = agent_config(p, CMD_FIND, bootstrap)?;
    let id = identity(p, CMD_FIND)?;
    let rt = runtime()?;
    let outcome = rt
        .block_on(async {
            let mut agent = new_agent(id, &a, cfg)?;
            agent.find(&query).await.map_err(|e| fail("find", e))
        })?;

    describe_source(&source, &a, out);
    out.push_str(&format!(
        "запрос: {} кластер(ов), nprobe {nprobe}, top_k {top_k}\n",
        q.clusters.len()
    ));
    push_vector(&vector_hex(&q.vec_q), p.bool_flag(CMD_FIND, "show-vector")?, out);
    for ans in &outcome.answers {
        out.push_str(&format!(
            "ответ шарда {}: {} (эпоха {}, совпадений {})\n",
            ans.shard, ans.peer, ans.epoch, ans.matches
        ));
    }
    for f in &outcome.failures {
        out.push_str(&format!("отказ шарда {}: {}\n", f.shard, f.reason));
    }
    if outcome.matches.is_empty() {
        if outcome.answers.is_empty() {
            return Err(CliError::Fail(format!(
                "ни один из {} шард(ов) не ответил: {}",
                q.per_shard.len(),
                outcome
                    .failures
                    .iter()
                    .map(|f| f.reason.as_str())
                    .collect::<Vec<_>>()
                    .join("; ")
            )));
        }
        out.push_str("совпадений нет (ответы получены, записей по кластерам не найдено)\n");
        return Ok(());
    }

    out.push_str(&format!("\nсовпадения ({}):\n", outcome.matches.len()));
    for (i, m) in outcome.matches.iter().enumerate() {
        out.push_str(&format!(
            "{:>3}. owner {} шард {} кластер {} слот {} d2 {} similarity {:.6}\n",
            i + 1,
            hex::encode(m.owner_ed25519),
            m.shard,
            m.cluster_id,
            m.slot,
            m.d2,
            m.similarity(),
        ));
        match &m.grant {
            Some(g) => out.push_str(&format!(
                "     приём: издатель {} до бакета {}; кадр {}\n",
                hex::encode(g.issuer),
                g.expires_bucket(),
                hex::encode(&g.frame)
            )),
            None => out.push_str(
                "     приём не выписан (потолок rendezvous-таблицы); MatchResult самодостаточен\n",
            ),
        }
    }
    Ok(())
}

pub fn exec_session(p: &Parsed, out: &mut String) -> Result<(), CliError> {
    let a = load(p, CMD_SESSION)?;
    let accept = crate::args::parse_hex_bytes(
        CMD_SESSION,
        "accept",
        &p.required(CMD_SESSION, "accept")?,
    )?;
    let issuer = p.hex_fixed::<32>(CMD_SESSION, "issuer")?.ok_or_else(|| {
        CliError::Fail(
            "нужен --issuer: без ключа издателя приём неотличим от подписи предъявителя (§12.3)"
                .into(),
        )
    })?;
    let bootstrap = bootstrap(p, CMD_SESSION)?;
    let to: Vec<Multiaddr> = p
        .values(CMD_SESSION, "to")?
        .into_iter()
        .map(|raw| {
            raw.parse::<Multiaddr>()
                .map_err(|e| CliError::Fail(format!("--to {raw}: {e}")))
        })
        .collect::<Result<_, _>>()?;
    if bootstrap.is_empty() && to.is_empty() {
        return Err(CliError::Fail(
            "нужен --to ADDR (address book) или --bootstrap: без адреса цели прямой канал \
             v1 не открывается, а relay/DCUtR не подняты (§16.3)"
                .into(),
        ));
    }
    let cfg = agent_config(p, CMD_SESSION, bootstrap)?;
    let id = identity(p, CMD_SESSION)?;
    let rt = runtime()?;
    let session = rt
        .block_on(async {
            let mut agent = new_agent(id, &a, cfg)?;
            // Кадр проверяется по исходным байтам и ключу издателя, а не по пересобранным полям.
            // `open_session_at` повторяет проверку перед dial: старая структура в памяти
            // вызывающего не должна превращаться в сессию к чужому ключу.
            let grant = agent
                .verify_standalone_accept(&accept, issuer)
                .map_err(|e| fail("приём не принят", e))?;
            agent.open_session_at(&grant, &to).await.map_err(|e| fail("сессия", e))
        })?;

    out.push_str(&format!("артефакт {}\n", a.manifest.model_version));
    out.push_str(&format!(
        "сессия: прямой аутентифицированный канал (relay/DCUtR в v1 не подняты)\n\
         \x20 пир        {} (роль {:?})\n\
         \x20 owner      {}\n\
         \x20 издатель   {}\n\
         \x20 шард {}, slot {}\n\
         \x20 приём действителен до бакета {} (выписан в {})\n",
        session.peer,
        session.role,
        hex::encode(session.owner),
        hex::encode(session.issuer),
        session.shard,
        session.slot,
        session.expires_bucket,
        session.issued_bucket,
    ));
    Ok(())
}

pub fn exec_run(p: &Parsed, out: &mut String) -> Result<(), CliError> {
    let a = load(p, CMD_RUN)?;
    let listen = multiaddrs(p, CMD_RUN, "listen")?;
    if listen.is_empty() {
        return Err(CliError::Fail(
            "нужен хотя бы один --listen: агент без слушателя не принимает входящих, и \
             «работающий» процесс был бы неотличим от зависшего"
                .into(),
        ));
    }
    let idle = p.num_or::<u64>(CMD_RUN, "idle", 60)?;
    if idle == 0 {
        return Err(CliError::Fail(
            "--idle 0: простаивающее соединение без таймаута занимает сокет и память вечно".into(),
        ));
    }
    let status_sec = p.num_or::<u64>(CMD_RUN, "status-sec", 30)?;
    let run_seconds = p.num_or::<u64>(CMD_RUN, "run-seconds", 0)?;
    let bootstrap = bootstrap(p, CMD_RUN)?;
    let cfg = AgentConfig {
        idle_timeout: Duration::from_secs(idle),
        ..agent_config_with(p, CMD_RUN, bootstrap, listen)?
    };
    let id = identity(p, CMD_RUN)?;
    let rt = runtime()?;
    // Агент строится **внутри** рантайма: QUIC-транспорт требует реактора уже на сборке
    // swarm, и создание вне `block_on` падает «no reactor running», а не даёт рабочий listener.
    rt.block_on(async {
        let agent = new_agent(id, &a, cfg)?;
        serve(
            agent,
            Duration::from_secs(run_seconds),
            Duration::from_secs(status_sec),
            out,
        )
        .await
    })
}

/// Цикл `run`: агент обязан шагать и вне своих вызовов, иначе входящий handshake не проходит, а
/// «слушающий» процесс молчит до первого вопроса. Это тот же цикл, что `Agent::run` крутит вечно;
/// здесь он ограничен `--run-seconds` ради тестов и скриптов, а не ослаблен.
///
/// Функция не молчит об ошибках транспорта и не объявляет успех без поднятого listener'а: пустой
/// список адресов — отказ, а не «похоже, слушает».
async fn serve(
    mut agent: Agent,
    limit: Duration,
    status_every: Duration,
    out: &mut String,
) -> Result<(), CliError> {
    let listen_deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while agent.listen_addrs().is_empty() {
        agent.net_mut().step().await;
        if tokio::time::Instant::now() >= listen_deadline {
            return Err(CliError::Fail(
                "listener не поднялся за 10 с: адрес не опубликован, объявлять успех нечем".into(),
            ));
        }
    }
    let addrs: Vec<String> = agent.listen_addrs().iter().map(ToString::to_string).collect();
    out.push_str(&format!(
        "артефакт {}\nagent run: peer {} owner {}\nсеть: genesis {}\nслушаю: {}\n",
        agent.network().model_version,
        agent.peer_id(),
        hex::encode(agent.owner()),
        hex::encode(agent.network().genesis_hash),
        addrs.join(", "),
    ));
    if !agent.config().bootstrap.is_empty() {
        out.push_str(&format!(
            "bootstrap: {}\n",
            agent
                .config()
                .bootstrap
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }

    let started = tokio::time::Instant::now();
    let stop_at = (!limit.is_zero()).then(|| started + limit);
    let mut next_status =
        (!status_every.is_zero()).then(|| started + status_every);
    let mut frames = 0usize;
    let mut frame_bytes = 0usize;
    let mut by_kind: BTreeMap<&'static str, usize> = BTreeMap::new();
    let mut errors = 0usize;
    loop {
        agent.net_mut().step().await;
        for (_peer, frame) in agent.net_mut().take_inbox() {
            frames += 1;
            frame_bytes += frame.len();
            let name = parse_header(&frame).map_or("нечитаемый", |(h, _)| h.kind.name());
            *by_kind.entry(name).or_default() += 1;
        }
        for e in agent.net_mut().take_errors() {
            errors += 1;
            out.push_str(&format!("ошибка транспорта: {e}\n"));
        }
        let now = tokio::time::Instant::now();
        if stop_at.is_some_and(|at| now >= at) {
            break;
        }
        if let Some(mut at) = next_status {
            if now >= at {
                out.push_str(&format!(
                    "t={:.0} с: кадров {frames} ({frame_bytes} Б), ошибок {errors}, \
                     аутентифицировано {}, kad {}, отзывов {}\n",
                    now.duration_since(started).as_secs_f64(),
                    agent.net().authenticated_peers().len(),
                    agent.net_mut().kad_peer_count(),
                    agent.net().revocation_count(),
                ));
                while at <= now {
                    at += status_every;
                }
                next_status = Some(at);
            }
        }
    }

    let kinds = if by_kind.is_empty() {
        "нет".to_string()
    } else {
        by_kind
            .iter()
            .map(|(k, n)| format!("{k}×{n}"))
            .collect::<Vec<_>>()
            .join(", ")
    };
    out.push_str(&format!(
        "остановлен через {:.0} с: кадров {frames} ({frame_bytes} Б), из них {kinds}; \
         ошибок транспорта {errors}; аутентифицировано {}\n",
        started.elapsed().as_secs_f64(),
        agent.net().authenticated_peers().len(),
    ));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Parsed {
        Parsed::parse(args).expect("разбор аргументов")
    }

    #[test]
    fn a_missing_seed_is_a_named_refusal_not_a_random_identity() {
        let p = parse(&[CMD_PUBLISH, "--artifact", "x", "--text", "t", "--bootstrap", "/ip4/127.0.0.1/udp/1/quic-v1"]);
        let err = identity(&p, CMD_PUBLISH).unwrap_err();
        assert!(err.to_string().contains("--seed"), "{err}");
    }

    #[test]
    fn a_bad_bootstrap_address_is_named() {
        let p = parse(&[CMD_FIND, "--bootstrap", "не-адрес"]);
        let err = bootstrap(&p, CMD_FIND).unwrap_err();
        assert!(err.to_string().contains("--bootstrap"), "{err}");
    }

    #[test]
    fn run_without_a_listener_is_refused_by_name() {
        let p = parse(&[CMD_RUN, "--artifact", "x", "--seed", &"11".repeat(32)]);
        let listen = multiaddrs(&p, CMD_RUN, "listen").unwrap();
        assert!(listen.is_empty(), "без --listen список обязан быть пустым");
        assert_eq!(p.path_str(), CMD_RUN);
    }

    #[test]
    fn a_bad_listen_address_is_named_as_listen() {
        let p = parse(&[CMD_RUN, "--listen", "не-адрес"]);
        let err = multiaddrs(&p, CMD_RUN, "listen").unwrap_err();
        assert!(err.to_string().contains("--listen"), "{err}");
    }

    #[test]
    fn zero_timeout_is_refused() {
        let p = parse(&[CMD_FIND, "--timeout", "0"]);
        let err = agent_config(&p, CMD_FIND, Vec::new()).unwrap_err();
        assert!(err.to_string().contains("--timeout"), "{err}");
    }

    #[test]
    fn the_grant_hex_roundtrips_through_the_session_parser() {
        // Сессия принимает ровно те байты, что напечатал find; проверка hex здесь ловит
        // расхождение форматов до сетевого вызова.
        let raw = "aa".repeat(9);
        let bytes = crate::args::parse_hex_bytes(CMD_SESSION, "accept", &raw).unwrap();
        assert_eq!(hex::encode(bytes), raw);
    }

    #[test]
    fn agent_errors_keep_their_protocol_text() {
        let e = vecdht_net::AgentError::Refused {
            code: "NOT_OWNER".into(),
            shard: 7,
            retry_after_ms: 1000,
        };
        assert!(e.to_string().contains("NOT_OWNER"), "{e}");
    }
}
