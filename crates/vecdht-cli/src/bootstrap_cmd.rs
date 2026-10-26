//! `cert issue` и `genesis build` — церемония запуска сети без ключей в репозитории (§4.2, §9.2,
//! §15.2).
//!
//! Без этих двух команд узел не собрать: `NodeCert` требует подписи порога авторитетов, а genesis
//! `MembershipUpdate` — подписей 3-of-5 по тому же порогу. До появления команд оба документа
//! умел собирать только тестовый код (`vecdht-node/src/testing.rs`), то есть оператор публичной
//! сети мог получить их лишь правкой Rust-исходников. Это и есть дыра, которую закрывает модуль.
//!
//! Три правила, из которых всё остальное следует.
//!
//! 1. **Ключи приходят из файлов, а не из флагов.** `--key-file` читает 32-байтовый seed в hex;
//!    seed на командной строке остался бы в истории оболочки и в списке процессов. Исключение —
//!    dev-режим (`--dev-keys N --seed HEX64`), и он назван явно: те же ключи выводит
//!    `artifact init --dev-keys`, а предупреждение того артефакта уже говорит, что публичная сеть
//!    на таких ключах работать не обязана.
//! 2. **Подпись, которая не посчитается, — отказ до записи.** Каждый ключ обязан лежать в
//!    `artifact.authority.keys`, иначе его подпись не войдёт в порог, а документ будет выглядеть
//!    подписанным. То же для genesis: индекс подписи — позиция ключа в наборе авторитетов, а не
//!    «сколько ключей дали».
//! 3. **Самопроверка до записи.** Собранный документ проверяется тем же кодом, что и у узла
//!    (`verify_cert`, `Chain::validate`), и только потом попадает на диск. Артефакт, который
//!    лежит и выглядит готовым, но который узел отвергнет, хуже отсутствующего (§14.5).

use std::path::{Path, PathBuf};

use vecdht_artifact::Artifact;
use vecdht_crypto::cert::{sign_cert_identity, verify_cert};
use vecdht_crypto::sig::Identity;
use vecdht_node::candidates::{self, MemberList};
use vecdht_node::config::Params;
use vecdht_node::membership::{self, Chain, GENESIS_EPOCH};
use vecdht_wire::cert::{NodeCert, CERT_VERSION};
use vecdht_wire::messages::{Codec, Role};
use vecdht_wire::SHARDS;

use crate::args::{self, Parsed};
use crate::artifact_cmd::dev_key_seed;
use crate::{fail, CliError};

pub const CMD_CERT: &str = "cert issue";
pub const CMD_GENESIS: &str = "genesis build";

pub const FLAGS_CERT: &[&str] = &[
    "artifact", "out", "owner", "peer-id", "role", "shard", "capacity", "valid-from",
    "valid-until", "nonce", "key-file", "dev-keys", "seed",
];
pub const FLAGS_GENESIS: &[&str] =
    &["artifact", "out", "members", "shard", "generated-at", "key-file", "dev-keys", "seed"];

pub const HELP_CERT: &str = "\
cert issue — выпустить NodeCert, подписанный порогом авторитетов (§4.2)

  --artifact DIR       каталог артефакта: из него берутся genesis_hash и набор авторитетов
  --out FILE           куда записать байты кредашиала (канонический `NodeCert::encode`)
  --owner HEX64        публичный ключ владельца роли
  --peer-id HEX        сериализованный libp2p PeerId; байты как их отдаёт libp2p
  --role index|agent   роль кредашиала (по умолчанию index)
  --shard N            покрытый шард 0..63; повторять можно; отсутствие всех — wildcard
  --capacity N         ёмкость в записях, больше нуля
  --valid-from N       начало действия, unix-секунды
  --valid-until N      конец действия, unix-секунды (строго позже начала)
  --nonce HEX32        16 байт nonce: по нему отзывают кредашиал
  --key-file FILE      файл с 32-байтовым seed подписанта (64 строчных hex); повторять можно
  --dev-keys N         dev-режим: вывести N ключей из --seed (как `artifact init --dev-keys`)
  --seed HEX64         seed dev-ключей; обязателен вместе с --dev-keys

  Каждый ключ обязан быть в наборе авторитетов артефакта, а разных ключей — не меньше порога:
  подпись «мимо набора» порог не увеличивает, и такой кредашиал не должен выглядеть готовым.";

pub const HELP_GENESIS: &str = "\
genesis build — собрать genesis `MembershipUpdate` шарда, подписанный порогом авторитетов (§9.2)

  --artifact DIR       каталог артефакта: genesis_hash, пороги и потолок R
  --out FILE           куда записать кадр `MembershipUpdate` (TLV с подписью кадра)
  --members FILE       состав: строки `<owner HEX64> <peer-id HEX> <capacity>`; `#` — комментарий
  --shard N            шард 0..63
  --generated-at N     unix-секунды, с которых действует состав (входит в подпись)
  --key-file FILE      файл с seed подписанта; повторять можно
  --dev-keys N         dev-режим: вывести N ключей из --seed
  --seed HEX64         seed dev-ключей; обязателен вместе с --dev-keys

  Состав пересортировывается в детерминированный порядок §9.3 (`candidates::ordered`), поэтому
  порядок строк файла ни на что не влияет. Дубликат владельца — отказ, а не тихая склейка.
  Подпись кладётся с индексом ключа в наборе авторитетов, а не с номером по порядку подачи.";

pub fn exec_cert(p: &Parsed, out: &mut String) -> Result<(), CliError> {
    let a = load_artifact(p.required(CMD_CERT, "artifact")?)?;
    let authorities = a.authorities();
    let owner = required_hex32(p, CMD_CERT, "owner")?;
    let peer_raw = p.required(CMD_CERT, "peer-id")?;
    let peer_id = args::parse_hex_bytes(CMD_CERT, "peer-id", &peer_raw)
        .map_err(CliError::Arg)?;
    if peer_id.is_empty() || peer_id.len() > 128 {
        return Err(CliError::Fail(format!(
            "--peer-id {}: длина {} байт; пустой PeerId не адресует никого, а длиннее 128 байт \
             протокол не переносит",
            peer_raw,
            peer_id.len()
        )));
    }
    let role = match p.value(CMD_CERT, "role")?.unwrap_or_else(|| "index".to_string()).as_str() {
        "index" => Role::IndexNode,
        "agent" => Role::Agent,
        "relay" => Role::Relay,
        other => {
            return Err(CliError::Fail(format!(
                "--role {other}: известны `index`, `agent` и `relay`; другой роли в §4.2 нет"
            )))
        }
    };
    let shards = parse_shards(p, CMD_CERT)?;
    let capacity = p
        .num::<u32>(CMD_CERT, "capacity")?
        .ok_or_else(|| missing(CMD_CERT, "capacity"))?;
    if capacity == 0 {
        return Err(CliError::Fail(
            "ёмкость 0 записей: `verify_cert` отвергнет такой кредашиал до подписи (§4.2)".into(),
        ));
    }
    let valid_from = p
        .num::<u32>(CMD_CERT, "valid-from")?
        .ok_or_else(|| missing(CMD_CERT, "valid-from"))?;
    let valid_until = p
        .num::<u32>(CMD_CERT, "valid-until")?
        .ok_or_else(|| missing(CMD_CERT, "valid-until"))?;
    if valid_until <= valid_from {
        return Err(CliError::Fail(format!(
            "окно [{valid_from}; {valid_until}) пусто: `NodeCert::decode` отвергает такой кредашиал \
             ещё до проверки подписи"
        )));
    }
    let nonce = required_hex::<16>(p, CMD_CERT, "nonce")?;
    let signers = load_signers(p, CMD_CERT)?;

    let mut cert = NodeCert {
        version: CERT_VERSION,
        genesis_hash: a.genesis_hash(),
        role,
        owner_ed25519: owner,
        dht_peer_id: peer_id,
        shards,
        capacity_entries: capacity,
        valid_from,
        valid_until,
        nonce,
        authority_sigs: Vec::new(),
    };
    for (id, file) in &signers {
        if !authorities.keys.contains(&id.pubkey()) {
            return Err(CliError::Fail(format!(
                "ключ из {file} не входит в набор авторитетов артефакта: его подпись не посчитается \
                 в порог, и кредашиал выглядел бы подписанным, не будучи им (§15.2)"
            )));
        }
        cert = sign_cert_identity(&cert, id);
    }
    let mut distinct: Vec<[u8; 32]> = Vec::with_capacity(signers.len());
    for (id, _) in &signers {
        let key = id.pubkey();
        if distinct.contains(&key) {
            return Err(CliError::Fail(
                "один и тот же ключ подался дважды: порог считается по разным ключам, повтор его не \
                 приближает (§15.2)"
                    .into(),
            ));
        }
        distinct.push(key);
    }
    if distinct.len() < authorities.threshold {
        return Err(CliError::Fail(format!(
            "подписей {} при пороге {}: столько же скажет `verify_cert`, и запись такого файла \
             оставила бы оператору кредашиал, который никто не примет",
            distinct.len(),
            authorities.threshold
        )));
    }
    // Самопроверка тем же кодом, что у узла: `now = valid_from` — единственная точка окна, в
    // которой кредашиал обязан быть валиден независимо от часов хоста.
    verify_cert(&cert, &authorities, &a.genesis_hash(), valid_from, |_| false)
        .map_err(|e| fail("свежесобранный кредашиал не прошёл собственную проверку", e))?;

    let path = PathBuf::from(p.required(CMD_CERT, "out")?);
    let bytes = cert.encode();
    std::fs::write(&path, &bytes)
        .map_err(|e| fail(format!("запись кредашиала в `{}`", path.display()), e))?;

    out.push_str(&format!("{CMD_CERT}: кредашиал записан в {}\n", path.display()));
    out.push_str(&format!("  role             {}\n", role_name(cert.role)));
    out.push_str(&format!("  owner            {}\n", hex::encode(cert.owner_ed25519)));
    out.push_str(&format!(
        "  shards           {}\n",
        if cert.shards.is_empty() {
            "wildcard".to_string()
        } else {
            cert.shards.iter().map(|s| s.to_string()).collect::<Vec<_>>().join(",")
        }
    ));
    out.push_str(&format!("  capacity         {}\n", cert.capacity_entries));
    out.push_str(&format!("  window           {valid_from}..{valid_until}\n"));
    out.push_str(&format!("  genesis_hash     {}\n", hex::encode(cert.genesis_hash)));
    out.push_str(&format!(
        "  signatures       {} при пороге {}\n",
        cert.authority_sigs.len(),
        authorities.threshold
    ));
    out.push_str(&format!("  CERT_SIGS        {}\n", cert.authority_sigs.len()));
    out.push_str(&format!("  CERT_THRESHOLD   {}\n", authorities.threshold));
    out.push_str(&format!("  CERT_BYTES       {}\n", bytes.len()));
    out.push_str(&format!("  CERT_SHA256      {}\n", hex::encode(blake3::hash(&bytes).as_bytes())));
    Ok(())
}

pub fn exec_genesis(p: &Parsed, out: &mut String) -> Result<(), CliError> {
    let a = load_artifact(p.required(CMD_GENESIS, "artifact")?)?;
    let authorities = a.authorities();
    let params = Params::from_manifest(&a.manifest)
        .map_err(|e| fail("пороги артефакта не годятся для узла", e))?;
    let shard = p
        .num::<u16>(CMD_GENESIS, "shard")?
        .ok_or_else(|| missing(CMD_GENESIS, "shard"))?;
    if shard >= SHARDS {
        return Err(CliError::Fail(format!(
            "--shard {shard}: шардов в сети {SHARDS} (0..{})",
            SHARDS - 1
        )));
    }
    let generated_at = p
        .num::<u32>(CMD_GENESIS, "generated-at")?
        .ok_or_else(|| missing(CMD_GENESIS, "generated-at"))?;
    let members_path = PathBuf::from(p.required(CMD_GENESIS, "members")?);
    let holders = read_members(&members_path)?;
    // §9.3: состав — детерминированный выбор, поэтому порядок файла ни на что не влияет, а
    // дубликат владельца отвергается здесь, до сортировки: `ordered` схлопнул бы его молча.
    let ordered = candidates::ordered(GENESIS_EPOCH, shard, &holders);
    if ordered.len() != holders.len() {
        return Err(CliError::Fail(format!(
            "в составе {} строк, а разных владельцев {}: дубликат схлопнулся бы в один голос, и \
             кворум выглядел бы шире, чем есть (§9.3)",
            holders.len(),
            ordered.len()
        )));
    }
    if ordered.len() < 2 {
        return Err(CliError::Fail(format!(
            "genesis из {} член(ов): W ≥ 2 и R ≥ 2 (ADR-0044) — шард с одним держателем не переживёт \
             его уход, и узел такую сеть не поднимет",
            ordered.len()
        )));
    }
    if ordered.len() > params.r {
        return Err(CliError::Fail(format!(
            "в составе {} членов при R={}: `Chain::validate` отвергнет переход как MembersOutOfOrder",
            ordered.len(),
            params.r
        )));
    }
    let list = MemberList {
        epoch: GENESIS_EPOCH,
        shard,
        members: ordered.iter().map(|h| h.as_member()).collect(),
        generated_at,
    };
    let unsigned = membership::build_update(&list, Vec::new());
    let payload = unsigned.unsigned_body();
    let signers = load_signers(p, CMD_GENESIS)?;
    let mut sigs: Vec<(u8, [u8; 64])> = Vec::with_capacity(signers.len());
    for (id, file) in &signers {
        let Some(idx) = authorities.keys.iter().position(|k| *k == id.pubkey()) else {
            return Err(CliError::Fail(format!(
                "ключ из {file} не входит в набор авторитетов артефакта: подпись с чужим индексом \
                 `check_authorities` отвергнет, а не посчитает (§15.2)"
            )));
        };
        if sigs.iter().any(|(i, _)| *i as usize == idx) {
            return Err(CliError::Fail(
                "один и тот же ключ подался дважды: порог считается по разным ключам (§15.2)".into(),
            ));
        }
        let sig = id.sign_domain(vecdht_wire::messages::domain::MEMBER, &payload);
        sigs.push((idx as u8, sig));
    }
    if sigs.len() < params.authority_threshold {
        return Err(CliError::Fail(format!(
            "подписей {} при пороге авторитета {}: genesis, не собравший порог, не примет ни один \
             узел (§9.2)",
            sigs.len(),
            params.authority_threshold
        )));
    }
    let upd = membership::build_update(&list, sigs);
    // Самопроверка: `prev = None` — ровно тот путь, которым узел принимает genesis первым.
    let chain = Chain { shard, params, authorities };
    chain
        .validate(None, &upd)
        .map_err(|e| fail("свежесобранный genesis не прошёл проверку узла", e))?;

    let path = PathBuf::from(p.required(CMD_GENESIS, "out")?);
    let frame = match upd.sigs.first() {
        // Кадр несёт подпись транспорта; список подписей перехода лежит в теле.
        Some((_, sig)) => upd.encode_signed(sig),
        None => upd.encode_unsigned(),
    };
    std::fs::write(&path, &frame)
        .map_err(|e| fail(format!("запись genesis в `{}`", path.display()), e))?;

    out.push_str(&format!("{CMD_GENESIS}: genesis записан в {}\n", path.display()));
    out.push_str(&format!("  epoch            {GENESIS_EPOCH}\n"));
    out.push_str(&format!("  shard            {shard}\n"));
    out.push_str(&format!("  members          {}\n", upd.members.len()));
    out.push_str(&format!("  primary          {}\n", hex::encode(upd.members[0].owner_ed25519)));
    out.push_str(&format!(
        "  signatures       {} при пороге {}\n",
        upd.sigs.len(),
        params.authority_threshold
    ));
    for (idx, m) in upd.members.iter().enumerate() {
        out.push_str(&format!(
            "    [{idx}] {} peer {} записей {}\n",
            hex::encode(m.owner_ed25519),
            hex::encode(&m.dht_peer_id),
            m.capacity_entries
        ));
    }
    out.push_str(&format!("  GENESIS_EPOCH    {GENESIS_EPOCH}\n"));
    out.push_str(&format!("  GENESIS_SHARD    {shard}\n"));
    out.push_str(&format!("  GENESIS_MEMBERS  {}\n", upd.members.len()));
    out.push_str(&format!("  GENESIS_SIGS     {}\n", upd.sigs.len()));
    out.push_str(&format!("  GENESIS_THRESHOLD {}\n", params.authority_threshold));
    out.push_str(&format!("  GENESIS_BYTES    {}\n", frame.len()));
    out.push_str(&format!("  GENESIS_SHA256   {}\n", hex::encode(blake3::hash(&frame).as_bytes())));
    Ok(())
}

/// Подписанты: либо файлы ключей, либо dev-вывод из seed. Смешивать нельзя — оператор, у
/// которого часть ключей в файлах, а часть «вывелась», не увидел бы, какой именно порог собран.
///
/// `pub(crate)`: тот же загрузчик нужен производителю отзыва (`revoke_cmd`), и второй его
/// экземпляр означал бы, что два места по-разному решают, что такое «порог из файлов».
pub(crate) fn load_signers(p: &Parsed, cmd: &str) -> Result<Vec<(Identity, String)>, CliError> {
    let files = p.values(cmd, "key-file")?;
    let dev = p.num::<usize>(cmd, "dev-keys")?;
    let seed = p.hex_fixed::<32>(cmd, "seed")?;
    match (files.is_empty(), dev) {
        (false, Some(_)) => Err(CliError::Fail(
            "--key-file и --dev-keys вместе: непонятно, из чего собран порог; выберите один режим"
                .into(),
        )),
        (true, None) => Err(CliError::Fail(format!(
            "{cmd} без подписантов: нужен хотя бы один --key-file (или --dev-keys N --seed HEX64)"
        ))),
        (true, Some(0)) => Err(CliError::Fail("--dev-keys 0: подписывать некому".into())),
        (true, Some(n)) if n > 16 => Err(CliError::Fail(format!(
            "--dev-keys {n}: больше 16 подписей кредашиал не переносит (MAX_AUTHORITY_SIGS)"
        ))),
        (true, Some(n)) => {
            let Some(seed) = seed else {
                return Err(CliError::Fail(
                    "--dev-keys без --seed: dev-ключи выводятся из seed, а не из воздуха".into(),
                ));
            };
            Ok((0..n)
                .map(|i| {
                    let d = dev_key_seed(&seed, i as u16);
                    (Identity::from_seed(d), format!("dev[{i}]"))
                })
                .collect())
        }
        (false, None) => {
            if seed.is_some() {
                return Err(CliError::Fail(
                    "--seed без --dev-keys ни на что не влияет: seed подписанта читается из --key-file"
                        .into(),
                ));
            }
            let mut out = Vec::with_capacity(files.len());
            for file in files {
                let raw = std::fs::read_to_string(&file)
                    .map_err(|e| fail(format!("чтение ключа `{file}`"), e))?;
                let text = raw.trim();
                let seed = args::parse_hex::<32>(cmd, "key-file", text).map_err(|e| {
                    CliError::Fail(format!("`{file}`: {e}"))
                })?;
                out.push((Identity::from_seed(seed), file));
            }
            Ok(out)
        }
    }
}

fn read_members(path: &Path) -> Result<Vec<candidates::Holder>, CliError> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| fail(format!("чтение состава `{}`", path.display()), e))?;
    let mut out = Vec::new();
    for (lineno, line) in text.lines().enumerate() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() != 3 {
            return Err(CliError::Fail(format!(
                "{}:{}: ждём `<owner HEX64> <peer-id HEX> <capacity>`, а полей {}",
                path.display(),
                lineno + 1,
                fields.len()
            )));
        }
        let owner = args::parse_hex::<32>(CMD_GENESIS, "members", fields[0])
            .map_err(|e| CliError::Fail(format!("{}:{}: {e}", path.display(), lineno + 1)))?;
        let peer = args::parse_hex_bytes(CMD_GENESIS, "members", fields[1])
            .map_err(|e| CliError::Fail(format!("{}:{}: {e}", path.display(), lineno + 1)))?;
        if peer.is_empty() {
            return Err(CliError::Fail(format!(
                "{}:{}: пустой PeerId не адресует никого",
                path.display(),
                lineno + 1
            )));
        }
        let capacity = fields[2].parse::<u64>().map_err(|e| {
            CliError::Arg(args::ArgError::BadNumber {
                flag: format!("{}:{} capacity", path.display(), lineno + 1),
                value: fields[2].to_string(),
                detail: e.to_string(),
            })
        })?;
        if capacity == 0 {
            return Err(CliError::Fail(format!(
                "{}:{}: ёмкость 0 — член, который не может принять ни одной записи",
                path.display(),
                lineno + 1
            )));
        }
        out.push(candidates::Holder {
            owner_ed25519: owner,
            dht_peer_id: peer,
            capacity_entries: capacity,
        });
    }
    Ok(out)
}

fn parse_shards(p: &Parsed, cmd: &str) -> Result<Vec<u16>, CliError> {
    let mut out: Vec<u16> = Vec::new();
    for raw in p.values(cmd, "shard")? {
        let shard = args::parse_num::<u16>(cmd, "shard", &raw).map_err(CliError::Arg)?;
        if shard >= SHARDS {
            return Err(CliError::Fail(format!(
                "--shard {shard}: шардов в сети {SHARDS} (0..{})",
                SHARDS - 1
            )));
        }
        out.push(shard);
    }
    // Каноническая форма списка — возрастающая без повторов: два кредашиала с одним набором
    // шардов обязаны совпадать байтами, иначе «тот же» документ подписывался бы по-разному.
    out.sort_unstable();
    out.dedup();
    Ok(out)
}

fn load_artifact(dir: String) -> Result<Artifact, CliError> {
    Artifact::load(Path::new(&dir)).map_err(|e| fail(format!("чтение артефакта из `{dir}`"), e))
}

fn required_hex32(p: &Parsed, cmd: &str, name: &str) -> Result<[u8; 32], CliError> {
    p.hex_fixed::<32>(cmd, name)?.ok_or_else(|| missing(cmd, name))
}

fn required_hex<const N: usize>(p: &Parsed, cmd: &str, name: &str) -> Result<[u8; N], CliError> {
    p.hex_fixed::<N>(cmd, name)?.ok_or_else(|| missing(cmd, name))
}

fn missing(cmd: &str, name: &str) -> CliError {
    CliError::Arg(args::ArgError::Missing { flag: format!("{cmd} --{name}") })
}

fn role_name(role: Role) -> &'static str {
    match role {
        Role::IndexNode => "index",
        Role::Agent => "agent",
        Role::Relay => "relay",
    }
}
