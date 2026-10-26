//! `key show` — что сеть называет именем узла: `owner_ed25519` и libp2p `PeerId` из seed.
//!
//! Команда существует ради церемонии: `cert issue` и файл `--members` адресуют узел публичным
//! ключом и PeerId, а `node run` и `agent publish|find` принимают seed. Без вывода seed →
//! (owner, PeerId) оператор, поднимающий узел по этой инструкции, обязан вычислить пару чем-то
//! ещё — и чужое имя в `members` обнаруживается только отказом узла на двери.
//!
//! Здесь нет новой криптографии: обе величины выводятся тем же кодом, что и в `node run`
//! (`Identity::from_seed`, `keys::peer_id`), поэтому расхождение с узлом невозможно по построению.

use vecdht_crypto::sig::Identity;
use vecdht_net::keys;

use crate::args::Parsed;
use crate::CliError;

pub const CMD: &str = "key show";
pub const FLAGS: &[&str] = &["seed"];
pub const HELP: &str = "\
key show — вывести owner_ed25519 и PeerId из 32-байтового seed узла (§4.1)

  --seed HEX64         seed Ed25519-ключа, 32 байта hex

Печатает ровно те две строки, которые нужны церемонии узла:
  owner    HEX64       публичный ключ для `cert issue --owner` и файла `--members`
  peer_id  HEX          сериализованный PeerId для `cert issue --peer-id` и файла `--members`

Приватный ключ не печатается никогда: seed уже находится у оператора, а вывод команды
попадает в историю оболочки и лог.";

pub fn exec(p: &Parsed, out: &mut String) -> Result<(), CliError> {
    let seed = p.hex_fixed::<32>(CMD, "seed")?.ok_or_else(|| {
        CliError::Fail(
            "`key show` требует --seed: owner и PeerId — это и есть вывод из ключа, другого \
             источника имён у сети нет (§4.1)"
                .into(),
        )
    })?;
    let id = Identity::from_seed(seed);
    out.push_str(&format!("owner {}\n", hex::encode(id.pubkey())));
    out.push_str(&format!("peer_id {}\n", hex::encode(keys::peer_id(&id).to_bytes())));
    Ok(())
}
