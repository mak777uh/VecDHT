//! VecDHT v8 — подписанный model artifact (спека §15, §14.5, §15.3).
//!
//! Артефакт — это две вещи и одно обещание: `manifest.json` (параметры сети), `centroid.bin`
//! (1024 замороженных центроида) и `artifact_hash`, по которому узел узнаёт, что сидит на той же
//! сети, что и собеседник. Всё остальное (веса модели, tokenizer) в `manifest` только пиновится
//! хешем: они нужны для вывода эмбеддингов, а не для совпадения байтов протокола.
//!
//! `artifact_hash` = `blake3(канонические байты манифеста без подписей ‖ байты centroid.bin)`
//! (§7.1 + §15.3). Он же `genesis_hash` в `NodeCert`: кредашиал обязан покрывать именно эту сеть,
//! иначе подпись авторитета из другой genesis переносится сюда (§4.2). Подписывается, соответственно,
//! `unsigned_json`, а не хеш целиком: подпись над хешем не отличала бы «манифест + другие
//! центроиды» от «другой манифест + те же центроиды».
//!
//! Crate не знает про HTTP, IPFS и скачивание весов — только разбор, сверка и подпись.

#![forbid(unsafe_code)]

pub mod centroids;
pub mod json;
pub mod manifest;

use std::path::Path;

use ed25519_dalek::SigningKey;
use vecdht_crypto::cert::AuthoritySet;
use vecdht_crypto::ids::content_hash;
use vecdht_crypto::sig::sign_domain;
use vecdht_crypto::Identity;
use vecdht_wire::messages::{ArtifactAnnounce, MAX_INTENT_TEXT_BYTES};

pub use centroids::{CentroidError, Centroids, CENTROID_BYTES};
pub use json::{Json, JsonError};
pub use manifest::{
    Admission, Authority, IndexParams, Manifest, ManifestError, Pooling, Power, QueryParams, Quant,
    Replication, Routing, Time, DOMAIN_ARTIFACT, MANIFEST_SCHEMA,
};

/// Предел числа подписей авторитета в манифесте. Тот же, что у кредашиалов (§4.2): больше —
/// не помещается в канонический материал и только раздувает handshake.
pub const MAX_ARTIFACT_SIGS: usize = 16;

/// Имена файлов внутри каталога артефакта (§15.1).
pub const MANIFEST_FILE: &str = "manifest.json";
pub const CENTROID_FILE: &str = "centroid.bin";

#[derive(Debug, thiserror::Error)]
pub enum ArtifactError {
    #[error(transparent)]
    Manifest(#[from] ManifestError),
    #[error(transparent)]
    Centroids(#[from] CentroidError),
    #[error("артефакт: файл `{file}` не читается: {detail}")]
    Io { file: &'static str, detail: String },
    #[error("артефакт: centroid_blake3 манифеста {expected}, а файл даёт {actual}")]
    CentroidHashMismatch { expected: String, actual: String },
    #[error("артефакт: ожидался хеш {expected}, файл артефакта даёт {actual}")]
    HashMismatch { expected: String, actual: String },
    #[error("артефакт: подписей авторитета {have} при пороге {need}")]
    BelowThreshold { have: usize, need: usize },
    #[error("артефакт: preprocessing_version клиента {client}, сеть на {artifact}")]
    ModelMismatch { client: u16, artifact: u16 },
}

/// Манифест вместе с центроидами, которым он управляет.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Artifact {
    pub manifest: Manifest,
    pub centroids: Centroids,
}

impl Artifact {
    /// Сборка с проверкой того, что манифест действительно описывает переданные центроиды.
    pub fn assemble(manifest: Manifest, centroids: Centroids) -> Result<Self, ArtifactError> {
        manifest.check()?;
        let actual = content_hash(&centroids.as_bytes());
        if actual != manifest.centroid_blake3 {
            return Err(ArtifactError::CentroidHashMismatch {
                expected: hex::encode(manifest.centroid_blake3),
                actual: hex::encode(actual),
            });
        }
        Ok(Self { manifest, centroids })
    }

    /// Байты, которые подписывает авторитет: манифест без ключа `signatures`.
    pub fn signing_material(&self) -> Vec<u8> {
        self.manifest.unsigned_json()
    }

    /// `artifact_hash` — он же `genesis_hash` для кредашиалов и `Handshake` (§4.2, §15.3).
    pub fn artifact_hash(&self) -> [u8; 32] {
        let mut buf = self.signing_material();
        buf.extend_from_slice(&self.centroids.as_bytes());
        content_hash(&buf)
    }

    pub fn genesis_hash(&self) -> [u8; 32] {
        self.artifact_hash()
    }

    /// Множество авторитетов из манифеста — те же ключи и тот же порог, что проверяются в
    /// `verify_cert` для кредашиалов (§15.2).
    pub fn authorities(&self) -> AuthoritySet {
        AuthoritySet::new(self.manifest.authority.keys.clone(), self.manifest.authority.threshold as usize)
    }

    /// Подписать артефакт ключом авторитета. Возвращает число подписей после добавления;
    /// повторный вызов тем же ключом добавляет вторую подпись — дубликаты при проверке
    /// считаются один раз (`AuthoritySet::count_valid`), так что это безопасно, но бессмысленно.
    pub fn sign(&mut self, signing_key: &SigningKey) -> usize {
        let sig = sign_domain(signing_key, DOMAIN_ARTIFACT, &self.signing_material());
        self.manifest.signatures.push(sig);
        self.manifest.signatures.len()
    }

    /// Полная проверка перед использованием: центроиды ↔ манифест, хеш ↔ pinned значение,
    /// порог подписей 3-of-5 (§14.5). Возвращает число валидных подписей.
    pub fn verify(&self, pinned_hash: Option<[u8; 32]>) -> Result<usize, ArtifactError> {
        self.manifest.check()?;
        let actual_centroids = content_hash(&self.centroids.as_bytes());
        if actual_centroids != self.manifest.centroid_blake3 {
            return Err(ArtifactError::CentroidHashMismatch {
                expected: hex::encode(self.manifest.centroid_blake3),
                actual: hex::encode(actual_centroids),
            });
        }
        if let Some(want) = pinned_hash {
            let got = self.artifact_hash();
            if got != want {
                return Err(ArtifactError::HashMismatch {
                    expected: hex::encode(want),
                    actual: hex::encode(got),
                });
            }
        }
        if self.manifest.signatures.len() > MAX_ARTIFACT_SIGS {
            return Err(ArtifactError::BelowThreshold { have: 0, need: self.manifest.authority.threshold as usize });
        }
        let set = self.authorities();
        let have = set.count_valid(&self.signing_material(), DOMAIN_ARTIFACT, &self.manifest.signatures);
        if have >= self.manifest.authority.threshold as usize {
            Ok(have)
        } else {
            Err(ArtifactError::BelowThreshold { have, need: self.manifest.authority.threshold as usize })
        }
    }

    /// Сверка `preprocessing_version` из `Handshake` (§6.7): несоответствие — это
    /// `Error{code:"MODEL_MISMATCH"}` и закрытие соединения, а не попытка искать вслепую.
    pub fn check_preprocessing(&self, preprocessing_version: u16) -> Result<(), ArtifactError> {
        if preprocessing_version == self.manifest.preprocessing_version {
            Ok(())
        } else {
            Err(ArtifactError::ModelMismatch {
                client: preprocessing_version,
                artifact: self.manifest.preprocessing_version,
            })
        }
    }

    /// `ArtifactAnnounce` (§5, §7.7) — то, что узел говорит соседям об этом артефакте.
    pub fn announce(&self, issued_at_bucket: u32) -> ArtifactAnnounce {
        ArtifactAnnounce {
            artifact_hash: self.artifact_hash(),
            model_version: self.manifest.model_version.clone(),
            preprocessing_version: self.manifest.preprocessing_version,
            nlist: self.manifest.routing.nlist,
            clusters_per_shard: self.manifest.routing.clusters_per_shard,
            issued_at: issued_at_bucket,
        }
    }

    /// Прочитать каталог артефакта. Проверка подписи здесь не вызывается: ей нужен доверенный
    /// набор ключей, а он — часть вызывающего кода (bootstrap из §15.2).
    pub fn load(dir: &Path) -> Result<Self, ArtifactError> {
        let manifest_bytes = read(dir, MANIFEST_FILE)?;
        let centroid_bytes = read(dir, CENTROID_FILE)?;
        let manifest = Manifest::decode(&manifest_bytes)?;
        let centroids = Centroids::from_u8(&centroid_bytes)?;
        Ok(Self { manifest, centroids })
    }

    /// Записать каталог: сначала `centroid.bin`, потом `manifest.json`. Манифест последний, потому
    /// что именно он пинит хеш центроидов: обрыв между файлами читается как «артефакта нет»,
    /// а не как «артефакт с чужими центроидами».
    pub fn save(&self, dir: &Path) -> Result<(), ArtifactError> {
        std::fs::create_dir_all(dir).map_err(|e| ArtifactError::Io {
            file: MANIFEST_FILE,
            detail: e.to_string(),
        })?;
        write(dir, CENTROID_FILE, &self.centroids.as_bytes())?;
        write(dir, MANIFEST_FILE, &self.manifest.to_json_bytes())
    }
}

fn read(dir: &Path, file: &'static str) -> Result<Vec<u8>, ArtifactError> {
    std::fs::read(dir.join(file)).map_err(|e| ArtifactError::Io { file, detail: e.to_string() })
}

fn write(dir: &Path, file: &'static str, bytes: &[u8]) -> Result<(), ArtifactError> {
    std::fs::write(dir.join(file), bytes).map_err(|e| ArtifactError::Io { file, detail: e.to_string() })
}

/// Манифест со значениями из приложения B спеки. Это эталон для тестов и калибровки: хеши модели,
/// tokenizer'а и центроидов заполняются нулями и обязаны быть перезаписаны при сборке настоящего
/// артефакта на P0 — подпись под нулевыми пинами технически возможна, но сеть на неё не смотрит,
/// потому что `verify` сравнивает `artifact_hash` с pinned значением из доверенного источника.
pub fn reference_manifest() -> Manifest {
    Manifest {
        schema: MANIFEST_SCHEMA,
        model_version: "granite-embedding-97m-v2".into(),
        preprocessing_version: 1,
        model_blake3: [0u8; 32],
        tokenizer_blake3: [0u8; 32],
        tokenizer_revision: "unpinned-p0".into(),
        centroid_blake3: [0u8; 32],
        pooling: Pooling::Cls,
        max_length: 256,
        add_special_tokens: true,
        intent_prefix: String::new(),
        query_prefix: String::new(),
        quant: Quant { dim: 384, grid: "i8/127".into(), rounding: "half_away".into(), max_d2: 65_536 },
        routing: Routing {
            nlist: 1024,
            clusters_per_shard: 16,
            shards: 64,
            nprobe_default: 16,
            nprobe_allowed: vec![4, 16, 32],
        },
        time: Time { bucket_sec: 16, time_mark_every: 512, ttl_default_sec: 3600, ttl_max_sec: 86_400 },
        power: Power { pow_bits_default: 24, pow_bits_min: 24, pow_bits_max: 28, blake3_mhz_core: 200 },
        admission: Admission {
            max_live_per_shard: 2_000_000,
            per_peer_publish_rps: 1,
            per_peer_publish_burst: 20,
            per_peer_find_rps: 5,
            node_admits_per_s: 100,
        },
        replication: Replication {
            r: 3,
            w: 2,
            membership_threshold: 2,
            lease_sec: 90,
            renew_sec: 30,
            election_timeout_sec: 60,
            provider_record_ttl_sec: 420,
            provider_republish_sec: 180,
        },
        index: IndexParams {
            snapshot_ops: 50_000,
            wal_segment_bytes: 64 * 1024 * 1024,
            wal_group_commit_ms: 5,
            wal_group_commit_ops: 32,
        },
        query: QueryParams {
            top_k_default: 32,
            top_k_max: 64,
            intent_text_max_bytes: MAX_INTENT_TEXT_BYTES as u32,
            rendezvous_ttl_sec: 300,
            timestamp_window_sec: 30,
        },
        authority: Authority {
            // Настоящие публичные ключи пяти тестовых авторитетов: пины `[i; 32]` были бы
            // невалидными ключами Ed25519, и порог на них собрать нельзя было бы даже в тестах.
            keys: (1u8..=5)
                .map(|i| Identity::from_seed([i; 32]).pubkey())
                .collect(),
            threshold: 3,
        },
        signatures: Vec::new(),
    }
}

/// Детерминированные центроиды для тестов и golden-векторов: сетка значений зависит только от
/// номера кластера и координаты, ни от одного `sin`/`exp` (их libm различается между платформами,
/// а хеш артефакта обязан совпадать на двух машинах).
pub fn reference_centroids() -> Centroids {
    let bytes: Vec<i8> = (0..CENTROID_BYTES).map(|i| ((i % 255) as i32 - 127) as i8).collect();
    Centroids::from_i8(&bytes).expect("reference_centroids: размер фиксирован")
}

/// Эталонный артефакт: манифест, запинивающий именно эти центроиды.
pub fn reference_artifact() -> Artifact {
    let centroids = reference_centroids();
    let mut manifest = reference_manifest();
    manifest.centroid_blake3 = content_hash(&centroids.as_bytes());
    Artifact::assemble(manifest, centroids).expect("эталонный артефакт не собирается")
}

#[cfg(test)]
mod tests {
    use super::*;
    use vecdht_wire::cert::{NodeCert, CERT_VERSION};
    use vecdht_wire::messages::Role;

    fn authority(i: usize) -> SigningKey {
        SigningKey::from_bytes(&vecdht_crypto::Identity::from_seed([i as u8; 32]).seed())
    }

    #[test]
    fn reference_artifact_hashes_are_stable() {
        let a = reference_artifact();
        // Два независимых вызова обязаны дать один байт: иначе подпись и pinned хеш разъедутся.
        assert_eq!(a.artifact_hash(), reference_artifact().artifact_hash());
        assert_eq!(a.genesis_hash(), a.artifact_hash());
        assert_eq!(a.manifest.centroid_blake3, content_hash(&a.centroids.as_bytes()));
    }

    #[test]
    fn threshold_signature_round_trip() {
        let mut a = reference_artifact();
        // Две подписи — ещё не порог (3-of-5).
        a.sign(&authority(1));
        a.sign(&authority(2));
        assert!(matches!(
            a.verify(None),
            Err(ArtifactError::BelowThreshold { have: 2, need: 3 })
        ));
        a.sign(&authority(3));
        assert_eq!(a.verify(None).unwrap(), 3);
        // Одна и та же подпись дважды не помогает: порог — про разные ключи.
        let mut dup = reference_artifact();
        let sk = authority(1);
        dup.sign(&sk);
        dup.sign(&sk);
        assert!(matches!(dup.verify(None), Err(ArtifactError::BelowThreshold { have: 1, .. })));
    }

    #[test]
    fn foreign_authority_key_does_not_count() {
        let mut a = reference_artifact();
        // Ключ, которого нет в манифесте (seed 9), даже в трёх экземплярах — не порог.
        let sk = authority(9);
        for _ in 0..3 {
            a.sign(&sk);
        }
        assert!(matches!(a.verify(None), Err(ArtifactError::BelowThreshold { have: 0, need: 3 })));
    }

    #[test]
    fn tampering_with_centroids_breaks_both_hashes() {
        let mut a = reference_artifact();
        let mut bytes = a.centroids.as_bytes();
        bytes[0] ^= 1;
        a.centroids = Centroids::from_u8(&bytes).unwrap();
        // Манифест пинит старый хеш центроидов — это ловится до всякой подписи.
        assert!(matches!(a.verify(None), Err(ArtifactError::CentroidHashMismatch { .. })));
        // И pinned хеш артефакта больше не сходится.
        let pinned = reference_artifact().artifact_hash();
        assert!(matches!(
            a.verify(Some(pinned)),
            Err(ArtifactError::CentroidHashMismatch { .. })
        ));
    }

    #[test]
    fn tampering_with_manifest_breaks_signature_and_pinned_hash() {
        let mut a = reference_artifact();
        let sk = authority(1);
        a.sign(&sk);
        a.sign(&authority(2));
        a.sign(&authority(3));
        let pinned = a.artifact_hash();
        assert_eq!(a.verify(Some(pinned)).unwrap(), 3);
        // Перевод манифеста на другой TTL меняет подписываемые байты → порог не собран.
        // Значение кратное `bucket_sec` (16), иначе `check()` отсекает его раньше подписи.
        a.manifest.time.ttl_default_sec = 7200;
        assert!(matches!(a.verify(None), Err(ArtifactError::BelowThreshold { have: 0, need: 3 })));
    }

    #[test]
    fn wrong_pinned_hash_is_refused() {
        let mut a = reference_artifact();
        a.sign(&authority(1));
        a.sign(&authority(2));
        a.sign(&authority(3));
        assert!(matches!(
            a.verify(Some([0xAA; 32])),
            Err(ArtifactError::HashMismatch { .. })
        ));
    }

    #[test]
    fn preprocessing_mismatch_reports_model_mismatch() {
        let a = reference_artifact();
        assert!(a.check_preprocessing(a.manifest.preprocessing_version).is_ok());
        assert!(matches!(
            a.check_preprocessing(2),
            Err(ArtifactError::ModelMismatch { client: 2, artifact: 1 })
        ));
    }

    #[test]
    fn announce_carries_the_same_numbers_as_the_manifest() {
        let a = reference_artifact();
        let msg = a.announce(42);
        assert_eq!(msg.artifact_hash, a.artifact_hash());
        assert_eq!(msg.nlist, a.manifest.routing.nlist);
        assert_eq!(msg.clusters_per_shard, a.manifest.routing.clusters_per_shard);
        assert_eq!(msg.preprocessing_version, a.manifest.preprocessing_version);
        assert_eq!(msg.issued_at, 42);
    }

    #[test]
    fn genesis_hash_is_what_certs_bind_to() {
        // Интеграция с §4.2: кредашиал, подписанный под другой genesis, не принимается сетью.
        let a = reference_artifact();
        let set = a.authorities();
        let base = NodeCert {
            version: CERT_VERSION,
            genesis_hash: a.genesis_hash(),
            role: Role::IndexNode,
            owner_ed25519: [0x10; 32],
            dht_peer_id: vec![0x00, 0x24, 0x00],
            shards: vec![0, 63],
            capacity_entries: 1000,
            valid_from: 0,
            valid_until: u32::MAX,
            nonce: [1; 16],
            authority_sigs: Vec::new(),
        };
        let mut cert = vecdht_crypto::cert::sign_cert(&base, &authority(1));
        cert = vecdht_crypto::cert::sign_cert(&cert, &authority(2));
        cert = vecdht_crypto::cert::sign_cert(&cert, &authority(3));
        assert_eq!(
            vecdht_crypto::cert::verify_cert(&cert, &set, &a.genesis_hash(), 10, |_| false),
            Ok(())
        );
        let other = a.genesis_hash();
        let mut other2 = other;
        other2[0] ^= 1;
        assert!(vecdht_crypto::cert::verify_cert(&cert, &set, &other2, 10, |_| false).is_err());
    }

    #[test]
    fn save_and_load_round_trip_is_byte_exact() {
        let mut a = reference_artifact();
        a.sign(&authority(1));
        a.sign(&authority(2));
        a.sign(&authority(3));
        let dir = std::env::temp_dir().join(format!(
            "vecdht-artifact-{}-{}",
            std::process::id(),
            content_hash(a.artifact_hash().as_slice())[0] as usize
        ));
        a.save(&dir).expect("запись эталонного артефакта");
        let back = Artifact::load(&dir).expect("чтение эталонного артефакта");
        assert_eq!(back, a, "round-trip изменил артефакт");
        assert_eq!(back.artifact_hash(), a.artifact_hash());
        assert_eq!(back.verify(Some(a.artifact_hash())).unwrap(), 3);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_of_missing_directory_is_io_error() {
        let dir = std::env::temp_dir().join("vecdht-artifact-netu-takogo");
        assert!(matches!(
            Artifact::load(&dir),
            Err(ArtifactError::Io { file: MANIFEST_FILE, .. })
        ));
    }

    #[test]
    fn assemble_refuses_centroids_the_manifest_does_not_pin() {
        let m = reference_manifest(); // centroid_blake3 = нули
        let c = reference_centroids();
        assert!(matches!(
            Artifact::assemble(m, c),
            Err(ArtifactError::CentroidHashMismatch { .. })
        ));
    }

    #[test]
    fn signing_material_excludes_signatures_and_is_canonical() {
        let mut a = reference_artifact();
        let unsigned = a.signing_material();
        assert!(!String::from_utf8(unsigned.clone()).unwrap().contains("\"signatures\""));
        a.sign(&authority(1));
        // Байты подписи не влияют на материал: иначе подпись зависела бы от предыдущих подписей.
        assert_eq!(a.signing_material(), unsigned);
        assert!(a.manifest.to_json_bytes().len() > unsigned.len());
    }
}
