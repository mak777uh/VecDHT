//! `revoke` — производитель отзыва кредашиала: пороговая подпись авторитетов и рассылка по
//! control-теме (§4.2, §15.2; карточка A3 `docs/PLAN-v1.md`).
//!
//! До этой команды отзыв собирался только тестовым кодом: `build_revoke`/`verify_revoke` лежали в
//! `vecdht-crypto`, `publish_revoke` — в `vecdht-net`, а у оператора не было способа ни собрать
//! документ, ни отдать его сети. `revocation.bin` (`ADR-0050`) и дверь (`E-0094`, `E-0095`) при
//! этом уже умели применять отзыв — не хватало производителя, то есть половины механизма.
//!
//! # Почему рассылка, а не запись в чужой каталог
//!
//! Живой узел узнаёт об отзыве только из control-темы: `apply_revoke` вызывается из
//! `on_control_message`, а файл `revocation.bin` читается лишь при старте (`Revocations::open`).
//! Записать байты в каталог соседа значило бы потребовать рестарта, доступа к его диску и доверия
//! к тому, кто пишет. Поэтому `--to` — сетевой путь, а `--out` — архив того же документа.
//!
//! # Три правила
//!
//! 1. **Подписывают только авторитеты, и ключи приходят файлами** (`--key-file`), как в
//!    `cert issue`/`genesis build`. `--dev-keys N --seed HEX64` — названный dev-режим.
//! 2. **Порог проверяется до записи**: `verify_revoke` — тот же код, что у получателя. Отзыв с
//!    двумя подписями при пороге три не должен выглядеть готовым документом.
//! 3. **Молчаливый успех запрещён**: если `--to` назван, но ни один пир не ответил на handshake
//!    или рассылка gossipsub не приняла ни одного кадра, команда завершается кодом 2. Иначе
//!    оператор считал бы отзыв разосланным, а сеть о нём не знала бы.
//!
//! # Чего команда не делает
//!
//! * не проверяет срок и подпись **отзываемого** кредашиала: отозвать ключ — значит объявить его
//!   недействительным, а не подтвердить, что он был выписан этим артефактом. Сверка ограничена
//!   разбором: `--cert` может быть и просрочен, и выпущен до отзыва;
//! * не подписывает кадр отзыва собственной подписью: авторитетность `CertRevoke` — порог
//!   внутри тела, подпись отправителя в нём ничего не значит (`service.rs`, `publish_revoke`);
//! * не переписывает `revocation.bin` у себя: рассылка идёт от эфемерного агента, у которого нет
//!   каталога узла. Записывает получатель — и только он.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use libp2p::Multiaddr;
use vecdht_artifact::Artifact;
use vecdht_crypto::cert::{sign_revoke_identity, verify_revoke};
use vecdht_crypto::sig::Identity;
use vecdht_net::{NetConfig, NetService};
use vecdht_wire::cert::NodeCert;
use vecdht_wire::messages::{CertRevoke, Codec, Role};

use crate::args::Parsed;
use crate::bootstrap_cmd::load_signers;
use crate::{fail, CliError};

pub const CMD_REVOKE: &str = "revoke";

pub const FLAGS_REVOKE: &[&str] = &[
    "artifact",
    "cert",
    "nonce",
    "reason",
    "revoked-at",
    "out",
    "to",
    "id-seed",
    "timeout",
    "wait-sec",
    "key-file",
    "dev-keys",
    "seed",
];

pub const HELP_REVOKE: &str = "\
revoke — отозвать кредашиал: подпись порога авторитетов и рассылка по control-теме (§4.2)

  --artifact DIR       артефакт сети: набор авторитетов и genesis_hash
  --cert FILE          файл `NodeCert`; отзывается его nonce
  --nonce HEX32        nonce прямо, если файла кредашиала под рукой нет (взаимоисключимо с --cert)
  --reason TEXT        причина отзыва; попадает в тело и в подпись
  --revoked-at N       unix-секунды отзыва; по умолчанию — текущее время
  --out FILE           куда записать байты отзыва (кадр `CertRevoke`)
  --to ADDR            адрес узла для рассылки; можно повторять
  --id-seed HEX        ключ эфемерного агента, который рассылает; нужен вместе с --to
  --timeout SEC        дедлайн дозвона и клиентских вызовов, по умолчанию 20
  --wait-sec SEC       сколько секунд держать рассылку, по умолчанию 6
  --key-file FILE      файл с 32-байтовым seed авторитета; повторять можно
  --dev-keys N         dev-режим: вывести N ключей из --seed (как `cert issue`)
  --seed HEX           seed dev-ключей; обязателен вместе с --dev-keys

Нужен хотя бы один из `--out` и `--to`. `--out` пишется после самопроверки порога; `--to`
рассылает тот же документ и печатает `REVOKE_PUBLISHED 1` только если gossipsub принял кадр
хотя бы раз. Отзыв идемпотентен по nonce: повторная рассылка не меняет ни множество, ни файл.";

pub fn exec_revoke(p: &Parsed, out: &mut String) -> Result<(), CliError> {
    let artifact_dir = p.required(CMD_REVOKE, "artifact")?;
    let a = Artifact::load(Path::new(&artifact_dir))
        .map_err(|e| fail(format!("чтение артефакта из `{artifact_dir}`"), e))?;
    let authorities = a.authorities();

    let nonce = target_nonce(p)?;
    let revoked_at = match p.num::<u32>(CMD_REVOKE, "revoked-at")? {
        Some(t) => t,
        None => now_sec().min(u64::from(u32::MAX)) as u32,
    };
    let reason = p
        .value(CMD_REVOKE, "reason")?
        .unwrap_or_else(|| "operator revoke".to_string());
    if reason.is_empty() {
        return Err(CliError::Fail(
            "--reason пуст: причина лежит в теле и входит в подпись порога, а пустая строка \
             сделала бы два разных отзыва неотличимыми по смыслу"
                .into(),
        ));
    }

    // Подписанты — тот же загрузчик, что у `cert issue`/`genesis build`: смешивать файлы и
    // dev-вывод нельзя, иначе непонятно, из чего собран порог.
    let signers = load_signers(p, CMD_REVOKE)?;
    let mut revoke = CertRevoke { nonce, revoked_at, reason, authority_sigs: Vec::new() };
    let mut distinct: Vec<[u8; 32]> = Vec::with_capacity(signers.len());
    for (id, file) in &signers {
        let key = id.pubkey();
        if !authorities.keys.contains(&key) {
            return Err(CliError::Fail(format!(
                "ключ из {file} не входит в набор авторитетов артефакта: его подпись не посчитается \
                 в порог, и отзыв выглядел бы подписанным, не будучи им (§15.2)"
            )));
        }
        if distinct.contains(&key) {
            return Err(CliError::Fail(
                "один и тот же ключ подался дважды: порог считается по разным ключам, повтор его не \
                 приближает (§15.2)"
                    .into(),
            ));
        }
        distinct.push(key);
        revoke = sign_revoke_identity(&revoke, id);
    }
    if distinct.len() < authorities.threshold {
        return Err(CliError::Fail(format!(
            "подписей {} при пороге {}: столько же скажет `verify_revoke`, и запись такого файла \
             оставила бы оператору отзыв, который никто не применит",
            distinct.len(),
            authorities.threshold
        )));
    }
    // Самопроверка тем же кодом, что у получателя: `on_control_message` применяет отзыв только
    // после `verify_revoke`.
    verify_revoke(&revoke, &authorities)
        .map_err(|e| fail("свежесобранный отзыв не прошёл собственную проверку", e))?;

    let out_path = p.value(CMD_REVOKE, "out")?;
    let to = multiaddrs(p, "to")?;
    if out_path.is_none() && to.is_empty() {
        return Err(CliError::Fail(
            "некуда девать отзыв: нужен --out FILE (архив) и/или --to ADDR (рассылка). Подписанный \
             документ без адресата — это файл, о котором сеть не узнает"
                .into(),
        ));
    }

    let bytes = revoke.encode_unsigned();
    if let Some(path) = &out_path {
        let path = PathBuf::from(path);
        std::fs::write(&path, &bytes)
            .map_err(|e| fail(format!("запись отзыва в `{}`", path.display()), e))?;
        out.push_str(&format!("{CMD_REVOKE}: отзыв записан в {}\n", path.display()));
    }
    out.push_str(&format!("  nonce            {}\n", hex::encode(revoke.nonce)));
    out.push_str(&format!("  revoked_at       {revoked_at}\n"));
    out.push_str(&format!("  reason           {}\n", revoke.reason));
    out.push_str(&format!(
        "  signatures       {} при пороге {}\n",
        revoke.authority_sigs.len(),
        authorities.threshold
    ));
    out.push_str(&format!("  REVOKE_NONCE     {}\n", hex::encode(revoke.nonce)));
    out.push_str(&format!("  REVOKE_SIGS      {}\n", revoke.authority_sigs.len()));
    out.push_str(&format!("  REVOKE_THRESHOLD {}\n", authorities.threshold));
    out.push_str(&format!("  REVOKE_BYTES     {}\n", bytes.len()));
    out.push_str(&format!("  REVOKE_SHA256    {}\n", hex::encode(blake3::hash(&bytes).as_bytes())));

    if !to.is_empty() {
        let id_seed = p.hex_fixed::<32>(CMD_REVOKE, "id-seed")?.ok_or_else(|| {
            CliError::Fail(
                "`revoke --to` требует --id-seed: рассылающему нужен свой PeerId, а брать его из \
                 ключа авторитета значило бы светить подписанта в транспорте"
                    .into(),
            )
        })?;
        let timeout = p.num_or::<u64>(CMD_REVOKE, "timeout", 20)?;
        if timeout == 0 {
            return Err(CliError::Fail(
                "--timeout 0: дозвон без дедлайна неотличим от зависания".into(),
            ));
        }
        let wait = p.num_or::<u64>(CMD_REVOKE, "wait-sec", 6)?;
        if wait == 0 {
            return Err(CliError::Fail(
                "--wait-sec 0: рассылка, которая не ждёт ни одного шага сети, не может быть \
                 доставлена; минимум — один heartbeat gossipsub"
                    .into(),
            ));
        }
        let report = publish(
            &a,
            Identity::from_seed(id_seed),
            &revoke,
            to,
            Duration::from_secs(timeout),
            Duration::from_secs(wait),
        )?;
        for e in &report.errors {
            out.push_str(&format!("  REVOKE_TRANSPORT {e}\n"));
        }
        out.push_str(&format!("  REVOKE_PEERS     {}\n", report.peers));
        out.push_str(&format!("  REVOKE_SENT      {}\n", report.sent));
        out.push_str(&format!("  REVOKE_MS        {}\n", report.elapsed_ms));
        out.push_str("  REVOKE_PUBLISHED 1\n");
    }
    Ok(())
}

struct Report {
    peers: usize,
    sent: u32,
    elapsed_ms: u128,
    errors: Vec<String>,
}

/// Эфемерный агент: дозвониться, дождаться обмена подписками и повторять рассылку в течение
/// `wait`. Получатель идемпотентен по `nonce` (`RevocationInsert::Duplicate`), поэтому повторы —
/// это доставка, а не второй отзыв.
fn publish(
    a: &Artifact,
    id: Identity,
    revoke: &CertRevoke,
    to: Vec<Multiaddr>,
    timeout: Duration,
    wait: Duration,
) -> Result<Report, CliError> {
    let cfg = NetConfig {
        genesis_hash: a.genesis_hash(),
        model_version: a.manifest.model_version.clone(),
        preprocessing_version: a.manifest.preprocessing_version,
        request_timeout: timeout,
        ..NetConfig::default()
    };
    let auth = a.authorities();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| fail("tokio-рантайм", e))?;
    rt.block_on(async move {
        let started = Instant::now();
        let mut net = NetService::new(id, Role::Agent, None, Vec::new(), auth, cfg)
            .map_err(|e| fail("сборка сервиса рассылки", e))?;
        for addr in to {
            net.dial(addr).map_err(|e| fail("дозвон до узла", e))?;
        }
        let connect_deadline = Instant::now() + timeout.min(Duration::from_secs(15));
        while net.authenticated_peers().is_empty() {
            net.step().await;
            if Instant::now() >= connect_deadline {
                let seen: Vec<String> = net.take_errors();
                return Err(CliError::Fail(format!(
                    "за {} с ни один пир не прошёл handshake: отзыв некуда рассылать (transport: {})",
                    started.elapsed().as_secs(),
                    if seen.is_empty() { "ошибок нет".to_string() } else { seen.join("; ") }
                )));
            }
        }
        let peers = net.authenticated_peers().len();
        // Подписки gossipsub расходятся на heartbeat (≈1 с). Публикация в тот же тик, что и
        // handshake, могла бы уйти в пустой fanout, и «разослано» стало бы неправдой.
        let warm = Instant::now();
        while warm.elapsed() < Duration::from_secs(2) {
            net.step().await;
        }
        let mut sent = 0u32;
        let mut last: Option<String> = None;
        while started.elapsed() < wait + Duration::from_secs(2) {
            match net.publish_revoke(revoke) {
                Ok(()) => sent += 1,
                Err(e) => last = Some(e.to_string()),
            }
            let until = Instant::now() + Duration::from_secs(1);
            while Instant::now() < until {
                net.step().await;
            }
            if sent > 0 && started.elapsed() >= wait {
                break;
            }
        }
        let errors = net.take_errors();
        if sent == 0 {
            return Err(CliError::Fail(format!(
                "gossipsub не принял ни одного кадра отзыва за {} с: {}",
                wait.as_secs(),
                last.unwrap_or_else(|| "причина не названа".to_string())
            )));
        }
        Ok(Report { peers, sent, elapsed_ms: started.elapsed().as_millis(), errors })
    })
}

/// Что отзываем: `--cert FILE` — nonce из файла, `--nonce HEX32` — прямо. Ровно один источник:
/// два разных nonce в одной команде означали бы «отозвать два ключа одним отзывом», чего в
/// формате `CertRevoke` нет.
fn target_nonce(p: &Parsed) -> Result<[u8; 16], CliError> {
    let cert_path = p.value(CMD_REVOKE, "cert")?;
    let nonce_flag = p.hex_fixed::<16>(CMD_REVOKE, "nonce")?;
    match (cert_path, nonce_flag) {
        (Some(_), Some(_)) => Err(CliError::Fail(
            "--cert и --nonce вместе: отзыв называет один nonce, и два источника делают выбор \
             неоднозначным"
                .into(),
        )),
        (None, Some(n)) => Ok(n),
        (Some(path), None) => {
            let bytes = std::fs::read(&path)
                .map_err(|e| fail(format!("чтение кредашиала из `{path}`"), e))?;
            // Разбор, но не проверка: отзывают в том числе просроченный и выпущенный до
            // смены эпохи кредашиал, а `verify_cert` отверг бы и то, и другое.
            let cert = NodeCert::decode(&bytes)
                .map_err(|e| fail(format!("разбор кредашиала из `{path}`"), e))?;
            Ok(cert.nonce)
        }
        (None, None) => Err(CliError::Arg(crate::args::ArgError::Missing {
            flag: format!("{CMD_REVOKE} --cert|--nonce"),
        })),
    }
}

fn multiaddrs(p: &Parsed, flag: &str) -> Result<Vec<Multiaddr>, CliError> {
    p.values(CMD_REVOKE, flag)?
        .into_iter()
        .map(|raw| {
            raw.parse::<Multiaddr>()
                .map_err(|e| CliError::Fail(format!("--{flag} {raw}: {e}")))
        })
        .collect()
}

fn now_sec() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
