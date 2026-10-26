//! `node run` — шард-узел из командной строки: сертификат и genesis из файлов, индекс на диске.
//!
//! До этой команды узел можно было поднять только тестовым кодом: `ShardNode::open` +
//! `NetService::new` живут в интеграционных тестах, а оператор, у которого `NodeCert` и genesis
//! уже собраны `cert issue`/`genesis build` (A0), не имел способа их предъявить. Карточка A1
//! дорожки A (`docs/PLAN-v1.md`) закрывает ровно этот разрыв.
//!
//! # Что команда проверяет до старта, а не после
//!
//! * **Кредашиал** — тем же `verify_cert`, что и встречная дверь (§4.2): окно, подпись порога,
//!   genesis, роль. Дополнительно: владелец и `dht_peer_id` совпадают с ключом из `--seed`, а
//!   `--shard` входит в покрытие. Кредашиал «на другого» узел поднял бы, но приняли бы его
//!   только до первого кадра, поэтому отказ — здесь.
//! * **Genesis** — `Chain::validate(None, …)`, то есть тот же путь, которым узел принимает
//!   первый переход (§9.2). Файл обязан быть кадром `MembershipUpdate` с подписью кадра
//!   (`genesis build` пишет именно его).
//! * **Своё место в составе** — §7.3: индексный узел, которого нет в genesis, не обслуживает
//!   шард; принимать кадры он мог бы, но ответов по шарду не давал бы «по праву».
//! * **Центроиды** — `centroid.bin` из `--artifact` обязателен: без него узел принимал бы
//!   `cluster_id` издателя (fail-open, `c103`), поэтому отсутствие файла — отказ старта, а
//!   принятый артефакт отдаётся узлу через `with_centroids` (§7.3).
//!
//! # Откуда берётся отправитель кадра genesis
//!
//! Файл кадра не несёт отдельного поля «кто подписал кадр». У genesis `sigs` — подписи
//! авторитетов над телом, и индекс в паре `(idx, sig)` — позиция ключа в `AuthoritySet.keys`
//! (`genesis build` кладёт её именно так). `Chain::validate` проверяет порог; подпись самого
//! кадра — это `sigs[0]`, поэтому отправитель для `on_frame` — `authorities.keys[sigs[0].0]`.
//! Перебор ключей не нужен и был бы второй копией проверки: неверный индекс отверг бы
//! `Chain::validate` ещё до этого шага.
//!
//! # Почему статус пишется в stdout напрямую
//!
//! `run(&[…]) -> Outcome` буферизует вывод, а `main` печатает его один раз при выходе. Для
//! команды, которая живёт часами, это означало бы «ничего не видно, пока не остановишь».
//! Поэтому `node run` печатает строки состояния сам и сразу (`NODE_READY`, `NODE_STATUS`), а
//! `Outcome.stdout` остаётся пустым — иначе `main` напечатал бы их второй раз.
//!
//! # Чего команда не делает
//!
//! * не выпускает отзыв и не банит сама: производитель отзыва — команда `revoke` (A3), а узел
//!   лишь применяет разосланное; `--dir` уже отдан и `revocation.bin` (ADR-0050), и
//!   `denylist.bin` (ADR-0047), поэтому записанное переживает рестарт — это измерено
//!   `E-0092`/`E-0094`/`E-0120`, здесь проверяется, что CLI передаёт тот же каталог;
//! * не обслуживает `IntentTextRequest`: держателя текста в `ShardNode` нет (§12.5, честная
//!   граница v1);
//! * не поднимает relay/DCUtR: прямой QUIC и Kademlia.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use libp2p::Multiaddr;
use vecdht_artifact::Artifact;
use vecdht_crypto::cert::verify_cert;
use vecdht_crypto::sig::Identity;
use vecdht_net::keys;
use vecdht_net::{NetConfig, NetService};
use vecdht_node::candidates::Holder;
use vecdht_node::config::Params;
use vecdht_node::membership::Chain;
use vecdht_node::{Clock, ShardNode};
use vecdht_wire::cert::NodeCert;
use vecdht_wire::messages::{Codec, MembershipUpdate, Role};
use vecdht_wire::SHARDS;

use crate::args::Parsed;
use crate::{fail, CliError};

pub const CMD_RUN: &str = "node run";

pub const FLAGS_RUN: &[&str] = &[
    "artifact",
    "dir",
    "shard",
    "seed",
    "cert",
    "genesis",
    "listen",
    "bootstrap",
    "timeout",
    "idle",
    "status-sec",
    "run-seconds",
];

pub const HELP_RUN: &str = "\
node run — поднять шард-узел: индекс на диске, членство из genesis, сеть по QUIC (§9, §12)
  --artifact DIR       артефакт сети: genesis_hash, набор авторитетов и параметры
  --dir DIR            каталог узла: индекс шарда, `denylist.bin`, `revocation.bin`
  --shard N            шард 0..63, который держит этот узел
  --seed HEX           32 байта Ed25519-ключа узла; owner и PeerId выводятся из него
  --cert FILE          файл `NodeCert` от `cert issue`
  --genesis FILE       файл кадра `MembershipUpdate` от `genesis build` (шард совпадает)
  --listen ADDR        адрес прослушивания; можно повторять, нужен минимум один
  --bootstrap ADDR     адрес соседа; можно повторять, необязательно
  --timeout SEC        дедлайн клиентских вызовов, по умолчанию 20
  --idle SEC           таймаут простаивающего соединения, по умолчанию 60
  --status-sec SEC     период строки NODE_STATUS, по умолчанию 30; 0 — не печатать
  --run-seconds SEC    остановиться через N секунд (тесты и скрипты); 0 — до сигнала

Первая строка `NODE_READY listen=…` печатается, когда слушатель поднят: до неё узел нельзя
считать работающим, а после неё адрес можно давать агентам. Строки статуса идут в stdout сразу,
не в конце процесса. Отказ (код 2) означает, что кредашиал, genesis или их согласие с ключом и
шардом не прошли проверку того же кода, что у двери узла.";

pub fn exec_run(p: &Parsed, _out: &mut String) -> Result<(), CliError> {
    let artifact_dir = p.required(CMD_RUN, "artifact")?;
    let a = Artifact::load(Path::new(&artifact_dir))
        .map_err(|e| fail(format!("чтение артефакта из `{artifact_dir}`"), e))?;
    let dir = PathBuf::from(p.required(CMD_RUN, "dir")?);
    let shard = p
        .num::<u16>(CMD_RUN, "shard")?
        .ok_or_else(|| missing("shard"))?;
    if shard >= SHARDS {
        return Err(CliError::Fail(format!(
            "--shard {shard}: шардов всего {SHARDS}; такого шарда у сети нет (§7.4)"
        )));
    }
    let seed = p.hex_fixed::<32>(CMD_RUN, "seed")?.ok_or_else(|| {
        CliError::Fail(
            "`node run` требует --seed: без ключа узла неоткуда взять owner_ed25519 и PeerId, а \
             кредашиал на другое имя узел всё равно не примет (§4.1)"
                .into(),
        )
    })?;
    let id = Identity::from_seed(seed);
    let owner = id.pubkey();
    let peer = keys::peer_id(&id);

    let listen = multiaddrs(p, "listen")?;
    if listen.is_empty() {
        return Err(CliError::Fail(
            "нужен хотя бы один --listen: узел без слушателя не принимает ни кадра, и \
             «работающий» процесс был бы неотличим от зависшего"
                .into(),
        ));
    }
    let bootstrap = multiaddrs(p, "bootstrap")?;

    let authorities = a.authorities();
    let cert_path = PathBuf::from(p.required(CMD_RUN, "cert")?);
    let cert_bytes = std::fs::read(&cert_path)
        .map_err(|e| fail(format!("чтение кредашиала из `{}`", cert_path.display()), e))?;
    let cert = NodeCert::decode(&cert_bytes)
        .map_err(|e| fail(format!("разбор кредашиала из `{}`", cert_path.display()), e))?;

    // Дверь проверяет кредашиал встречной стороны теми же правилами; узел обязан предъявить
    // такой же себе, иначе первый же кадр уйдёт с кредашиалом, который никто не примет.
    let now = now_sec();
    let now32 = now.min(u64::from(u32::MAX)) as u32;
    verify_cert(&cert, &authorities, &a.genesis_hash(), now32, |_| false)
        .map_err(|e| fail("кредашиал не прошёл проверку двери", e))?;
    if cert.role != Role::IndexNode {
        return Err(CliError::Fail(format!(
            "кредашиал роли {:?}: `node run` поднимает индексный узел, и агентский кредашиал \
             двери соседей для обслуживания шарда не годится (§4.2)",
            cert.role
        )));
    }
    if cert.owner_ed25519 != owner {
        return Err(CliError::Fail(format!(
            "кредашиал выписан владельцу {}, а --seed даёт {}: подписывать кадры чужим именем \
             протокол запрещает (§4.1)",
            hex::encode(cert.owner_ed25519),
            hex::encode(owner)
        )));
    }
    if cert.dht_peer_id != peer.to_bytes() {
        return Err(CliError::Fail(format!(
            "кредашиал привязан к PeerId {}, а --seed даёт {}: адрес и ключ разошлись (§4.2)",
            hex::encode(&cert.dht_peer_id),
            hex::encode(peer.to_bytes())
        )));
    }
    if !cert.covers_shard(shard) {
        return Err(CliError::Fail(format!(
            "кредашиал не покрывает шард {shard}: `NetService::new` отверг бы такой узел, и \
             отказ лучше показать до открытия порта (§4.2)"
        )));
    }

    let params = Params::from_manifest(&a.manifest)
        .map_err(|e| fail("параметры репликации из манифеста", e))?;
    let genesis_path = PathBuf::from(p.required(CMD_RUN, "genesis")?);
    let genesis_bytes = std::fs::read(&genesis_path)
        .map_err(|e| fail(format!("чтение genesis из `{}`", genesis_path.display()), e))?;
    let upd = MembershipUpdate::decode(&genesis_bytes)
        .map_err(|e| fail(format!("разбор genesis из `{}`", genesis_path.display()), e))?;
    let chain = Chain { shard, params, authorities: authorities.clone() };
    // `prev = None` — ровно путь первого перехода: состав ещё не принят, принимается genesis.
    chain
        .validate(None, &upd)
        .map_err(|e| fail("genesis не прошёл проверку цепочки", e))?;

    let own_member = upd
        .members
        .iter()
        .find(|m| m.owner_ed25519 == owner && m.dht_peer_id == peer.to_bytes());
    if own_member.is_none() {
        return Err(CliError::Fail(format!(
            "узел {} ({}) не входит в genesis шарда {shard}: обслуживать шард, куда его не \
             назначили, — не членство, а самоназначение (§7.3, §9.2)",
            hex::encode(owner),
            hex::encode(peer.to_bytes())
        )));
    }
    // Отправитель кадра genesis: индекс `sigs[0]` — позиция ключа авторитета (см. модульный
    // комментарий). `Chain::validate` уже проверил и порог, и сами подписи.
    let signer_idx = upd
        .sigs
        .first()
        .map(|(idx, _)| usize::from(*idx))
        .ok_or_else(|| CliError::Fail("genesis без подписей: цепочку нечем проверить".into()))?;
    let signer = *authorities.keys.get(signer_idx).ok_or_else(|| {
        CliError::Fail(format!(
            "индекс подписи кадра {signer_idx} вне набора авторитетов ({} ключей): genesis собран \
             не тем набором, что в артефакте",
            authorities.keys.len()
        ))
    })?;

    let roster: Vec<Holder> = upd
        .members
        .iter()
        .map(|m| Holder {
            owner_ed25519: m.owner_ed25519,
            dht_peer_id: m.dht_peer_id.clone(),
            capacity_entries: m.capacity_entries,
        })
        .collect();

    let mut node = ShardNode::open(&dir, shard, id.clone(), peer.to_bytes(), params, authorities.clone(), roster)
        .map_err(|e| fail(format!("открытие шарда {shard} в `{}`", dir.display()), e))?;
    node.on_frame(signer, &genesis_bytes, Clock::at(now))
        .map_err(|e| fail("genesis не принят узлом", e))?;
    // §7.3: с центроидами артефакта узел пересчитывает присваивание по `vec_q`, а не верит
    // `cluster_id` издателя. Без этого вызова продуктовая команда попадала бы в fail-open-ветку,
    // которую `c103` измеряет как `cluster_unverified`, — «узел принимает чужой кластер».
    let node = node.with_centroids(Arc::new(a.centroids.clone()));

    let timeout = p.num_or::<u64>(CMD_RUN, "timeout", 20)?;
    if timeout == 0 {
        return Err(CliError::Fail("--timeout 0: вызов без дедлайна неотличим от зависания".into()));
    }
    let idle = p.num_or::<u64>(CMD_RUN, "idle", 60)?;
    if idle == 0 {
        return Err(CliError::Fail(
            "--idle 0: простаивающее соединение без таймаута занимает сокет и память вечно".into(),
        ));
    }
    let status_sec = p.num_or::<u64>(CMD_RUN, "status-sec", 30)?;
    let run_seconds = p.num_or::<u64>(CMD_RUN, "run-seconds", 0)?;

    let cfg = NetConfig {
        listen,
        bootstrap,
        genesis_hash: a.genesis_hash(),
        model_version: a.manifest.model_version.clone(),
        preprocessing_version: a.manifest.preprocessing_version,
        request_timeout: Duration::from_secs(timeout),
        idle_timeout: Duration::from_secs(idle),
        // ADR-0050: отзыв переживает рестарт; ADR-0047: `denylist.bin` поднимает сам
        // `ShardNode::open`. Оба живут в каталоге узла, а не в памяти процесса.
        revoked_dir: Some(dir.clone()),
        ..NetConfig::default()
    };

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| fail("tokio-рантайм", e))?;
    rt.block_on(async move {
        let service = NetService::new(id, Role::IndexNode, Some(cert), vec![node], authorities, cfg)
            .map_err(|e| fail("сборка сервиса узла", e))?;
        serve(service, owner, shard, Duration::from_secs(run_seconds), Duration::from_secs(status_sec))
            .await
    })
}

async fn serve(
    mut service: NetService,
    owner: [u8; 32],
    shard: u16,
    limit: Duration,
    status_every: Duration,
) -> Result<(), CliError> {
    let listen_deadline = Instant::now() + Duration::from_secs(10);
    while service.listen_addrs().is_empty() {
        service.step().await;
        if Instant::now() >= listen_deadline {
            return Err(CliError::Fail(
                "listener не поднялся за 10 с: адрес не опубликован, объявлять узел работающим \
                 нечем"
                    .into(),
            ));
        }
    }
    let addrs = service
        .listen_addrs()
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(",");
    emit(&format!(
        "NODE_READY listen={addrs} peer={} owner={} shard={shard}",
        service.peer_id(),
        hex::encode(owner)
    ))?;

    let started = Instant::now();
    let stop_at = (!limit.is_zero()).then(|| started + limit);
    let mut next_status = (!status_every.is_zero()).then(|| started + status_every);
    loop {
        service.step().await;
        for e in service.take_errors() {
            emit(&format!("NODE_ERROR {e}"))?;
        }
        let now = Instant::now();
        if stop_at.is_some_and(|at| now >= at) {
            break;
        }
        if let Some(mut at) = next_status {
            if now >= at {
                // Наблюдаемость §7.3: без этих двух счётчиков «узел пересчитывает присваивание»
                // и «узел верит подсказке издателя» неотличимы снаружи.
                let (cluster_reassigned, cluster_unverified) = service
                    .node(shard)
                    .map(|n| {
                        let s = n.admission.borrow().stats;
                        (s.cluster_reassigned, s.cluster_unverified)
                    })
                    .unwrap_or((0, 0));
                // Наблюдаемость §9.8 (`ADR-0065`): без этих полей «узел стоит без гранта» и
                // «узел обслуживает эпоху E» снаружи не различимы — агент в обоих случаях
                // видит только таймаут. Значения берутся из того же `serving_epoch`, которым
                // пользуется дверь записи, а не из отдельной счётовой ветки.
                let (lease_field, serving_field) = service
                    .node(shard)
                    .map(|n| {
                        let bucket = Clock::at(now_sec()).bucket;
                        let lease = match n.lease {
                            Some(l) => format!("{}/{}", l.epoch, l.expires_at_bucket),
                            None => "none".to_string(),
                        };
                        let serving = match n.serving_epoch(bucket) {
                            Some(e) => e.to_string(),
                            None => "none".to_string(),
                        };
                        (lease, serving)
                    })
                    .unwrap_or(("none".to_string(), "none".to_string()));
                emit(&format!(
                    "NODE_STATUS t={:.0} peers={} kad={} revocations={} door_refusals={} shard={shard} \
                     cluster_reassigned={cluster_reassigned} cluster_unverified={cluster_unverified} \
                     lease={lease_field} serving_epoch={serving_field}",
                    now.duration_since(started).as_secs_f64(),
                    service.authenticated_peers().len(),
                    service.kad_peer_count(),
                    service.revocation_count(),
                    service.door_refusal_total(),
                ))?;
                while at <= now {
                    at += status_every;
                }
                next_status = Some(at);
            }
        }
    }
    emit(&format!("NODE_STOP t={:.0}", started.elapsed().as_secs_f64()))?;
    Ok(())
}

/// Строка состояния — сразу в stdout. Буфер `Outcome` печатается только на выходе, а процесс
/// узла живёт часами: статус в буфере был бы скрыт ровно тогда, когда он нужен.
fn emit(line: &str) -> Result<(), CliError> {
    let mut out = std::io::stdout();
    writeln!(out, "{line}")
        .and_then(|()| out.flush())
        .map_err(|e| fail("вывод строки состояния", e))
}

fn multiaddrs(p: &Parsed, flag: &str) -> Result<Vec<Multiaddr>, CliError> {
    p.values(CMD_RUN, flag)?
        .into_iter()
        .map(|raw| {
            raw.parse::<Multiaddr>()
                .map_err(|e| CliError::Fail(format!("--{flag} {raw}: {e}")))
        })
        .collect()
}

fn missing(flag: &str) -> CliError {
    // Тот же класс, что у `Parsed::required`: отсутствие флага — ошибка разбора (код 1), а не
    // «команда не могла быть выполнена» (код 2). Иначе `--shard` выпадал бы из общего правила.
    CliError::Arg(crate::args::ArgError::Missing { flag: format!("{CMD_RUN} --{flag}") })
}

fn now_sec() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
