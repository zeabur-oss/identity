//! Persistence of signing keys.
//!
//! The storage format is versioned and independent of the backend. Private keys are stored as
//! PKCS #8 v1 DER. This crate ships only [`MemoryKeyStore`]; the production store keeps the
//! keyset in a Kubernetes Secret (in `zeabur-identity-k8s`), using the Secret's `resourceVersion`
//! as the [`Revision`].
//!
//! Decoding is strict: an unknown schema version, unknown fields, bad base64, a key that does not
//! parse for its algorithm, or an RSA key under 2048 bits ([RFC 7518] §3.3) all fail. This limits
//! what someone with write access to storage can install, and it makes the manager stop rather
//! than overwrite keys it does not understand.
//!
//! [RFC 7518]: https://www.rfc-editor.org/rfc/rfc7518

use std::future::{self, Future};
use std::sync::{Arc, Mutex, PoisonError};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeabur_identity_core::clock::UnixTime;
pub use zeabur_identity_core::store::StoreError;

use super::Algorithm;
use super::rotation::{KeyRecord, KeyRing};
use super::signing::{KeyError, SigningKey};

/// The current storage schema version.
pub const SCHEMA_VERSION: u32 = 1;

/// The keys of every algorithm in storage form.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredKeyset {
    /// Schema version; see [`SCHEMA_VERSION`].
    pub version: u32,
    /// All keys, any algorithm.
    pub keys: Vec<StoredKey>,
}

/// One key in storage form.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredKey {
    /// Algorithm.
    pub alg: Algorithm,
    /// When the key was generated.
    pub created_at: UnixTime,
    /// When the key starts signing.
    pub activates_at: UnixTime,
    /// PKCS #8 v1 DER, base64 (standard alphabet).
    pub pkcs8: String,
}

impl std::fmt::Debug for StoredKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StoredKey")
            .field("alg", &self.alg)
            .field("created_at", &self.created_at)
            .field("activates_at", &self.activates_at)
            .finish_non_exhaustive()
    }
}

/// Why stored keys could not be used.
#[derive(Debug, Error)]
pub enum DecodeError {
    /// The stored schema is newer or older than this binary understands.
    #[error("unsupported key storage schema version {0}")]
    Version(u32),
    /// The key material is not valid base64.
    #[error("stored key is not valid base64")]
    Base64(#[source] base64::DecodeError),
    /// The key material is not a valid key.
    #[error(transparent)]
    Key(#[from] KeyError),
}

/// Converts rings to storage form.
///
/// # Errors
///
/// Returns [`KeyError::Export`] if a key cannot be exported.
pub fn encode(rings: &[KeyRing]) -> Result<StoredKeyset, KeyError> {
    use base64::Engine as _;
    let keys = rings
        .iter()
        .flat_map(|ring| {
            ring.published().iter().map(|record| {
                Ok(StoredKey {
                    alg: ring.alg(),
                    created_at: record.created_at,
                    activates_at: record.activates_at,
                    pkcs8: base64::engine::general_purpose::STANDARD.encode(record.key.to_pkcs8()?),
                })
            })
        })
        .collect::<Result<Vec<_>, KeyError>>()?;
    Ok(StoredKeyset {
        version: SCHEMA_VERSION,
        keys,
    })
}

/// Converts storage form back to one ring per algorithm in [`Algorithm::ALL`].
///
/// # Errors
///
/// Returns [`DecodeError`] if the schema version is unknown or any key is invalid. A keyset
/// that cannot be fully decoded is never partially used: overwriting it could destroy keys
/// that still verify live tokens.
pub fn decode(stored: &StoredKeyset) -> Result<Vec<KeyRing>, DecodeError> {
    use base64::Engine as _;
    if stored.version != SCHEMA_VERSION {
        return Err(DecodeError::Version(stored.version));
    }
    let mut rings = Vec::new();
    for alg in Algorithm::ALL {
        let mut records = Vec::new();
        for key in stored.keys.iter().filter(|key| key.alg == alg) {
            let der = base64::engine::general_purpose::STANDARD
                .decode(&key.pkcs8)
                .map_err(DecodeError::Base64)?;
            records.push(KeyRecord {
                key: Arc::new(SigningKey::from_pkcs8(alg, &der)?),
                created_at: key.created_at,
                activates_at: key.activates_at,
            });
        }
        rings.push(KeyRing::from_records(alg, records));
    }
    Ok(rings)
}

/// An opaque version of the stored keyset, used for compare-and-swap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Revision(pub String);

/// A keyset read from storage.
#[derive(Debug, Clone)]
pub struct Loaded {
    /// The keys.
    pub keyset: StoredKeyset,
    /// The version to pass back to [`KeyStore::save`].
    pub revision: Revision,
}

/// Where signing keys are kept.
pub trait KeyStore: Send + Sync + 'static {
    /// Reads the keyset, or `None` if none has been stored yet.
    fn load(&self) -> impl Future<Output = Result<Option<Loaded>, StoreError>> + Send;

    /// Writes the keyset if the stored revision is still `expected` (`None`: nothing stored
    /// yet), and returns the new revision.
    fn save(
        &self,
        keyset: &StoredKeyset,
        expected: Option<&Revision>,
    ) -> impl Future<Output = Result<Revision, StoreError>> + Send;
}

/// Keeps keys in process memory. Keys do not survive a restart: after a restart every
/// outstanding token fails verification. For development and tests only.
#[derive(Debug, Default)]
pub struct MemoryKeyStore {
    state: Mutex<Option<(StoredKeyset, u64)>>,
}

impl MemoryKeyStore {
    fn load_now(&self) -> Option<Loaded> {
        let state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        state.as_ref().map(|(keyset, revision)| Loaded {
            keyset: keyset.clone(),
            revision: Revision(revision.to_string()),
        })
    }

    fn save_now(
        &self,
        keyset: &StoredKeyset,
        expected: Option<&Revision>,
    ) -> Result<Revision, StoreError> {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let current = state
            .as_ref()
            .map(|(_, revision)| Revision(revision.to_string()));
        if current.as_ref() != expected {
            return Err(StoreError::Conflict);
        }
        let next = state.as_ref().map_or(1, |(_, revision)| revision + 1);
        *state = Some((keyset.clone(), next));
        drop(state);
        Ok(Revision(next.to_string()))
    }
}

impl KeyStore for MemoryKeyStore {
    fn load(&self) -> impl Future<Output = Result<Option<Loaded>, StoreError>> + Send {
        future::ready(Ok(self.load_now()))
    }

    fn save(
        &self,
        keyset: &StoredKeyset,
        expected: Option<&Revision>,
    ) -> impl Future<Output = Result<Revision, StoreError>> + Send {
        future::ready(self.save_now(keyset, expected))
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::rotation::RotationPolicy;

    fn rings() -> Vec<KeyRing> {
        Algorithm::ALL
            .iter()
            .map(|&alg| {
                let mut ring = KeyRing::new(alg);
                ring.tick(
                    UnixTime::from_secs(10),
                    &RotationPolicy::DEFAULT,
                    SigningKey::generate,
                )
                .unwrap();
                ring
            })
            .collect()
    }

    #[test]
    fn encode_decode_round_trip() {
        let rings = rings();
        let stored = encode(&rings).unwrap();
        let json = serde_json::to_string(&stored).unwrap();
        let decoded = decode(&serde_json::from_str(&json).unwrap()).unwrap();
        for (a, b) in rings.iter().zip(&decoded) {
            assert_eq!(a.alg(), b.alg());
            let kids = |r: &KeyRing| {
                r.published()
                    .iter()
                    .map(|k| k.key.kid().to_owned())
                    .collect::<Vec<_>>()
            };
            assert_eq!(kids(a), kids(b));
        }
    }

    #[test]
    fn refuses_unknown_versions_and_bad_keys() {
        let mut stored = encode(&rings()).unwrap();
        stored.version = 2;
        assert!(matches!(
            decode(&stored).unwrap_err(),
            DecodeError::Version(2)
        ));

        let mut stored = encode(&rings()).unwrap();
        stored.keys[0].pkcs8 = "not base64!".into();
        assert!(matches!(
            decode(&stored).unwrap_err(),
            DecodeError::Base64(_)
        ));

        let mut stored = encode(&rings()).unwrap();
        stored.keys[0].pkcs8 = "AAAA".into();
        assert!(matches!(decode(&stored).unwrap_err(), DecodeError::Key(_)));

        assert!(
            serde_json::from_value::<StoredKeyset>(json!({
                "version": 1,
                "keys": [],
                "extra": true,
            }))
            .is_err(),
            "unknown fields rejected"
        );
    }

    #[test]
    fn stored_key_debug_hides_material() {
        let stored = encode(&rings()).unwrap();
        let debug = format!("{stored:?}");
        assert!(!debug.contains(&stored.keys[0].pkcs8));
    }

    #[tokio::test]
    async fn memory_store_compare_and_swap() {
        let store = MemoryKeyStore::default();
        assert!(store.load().await.unwrap().is_none());
        let keyset = encode(&rings()).unwrap();

        let first = store.save(&keyset, None).await.unwrap();
        assert_eq!(store.save(&keyset, None).await, Err(StoreError::Conflict));
        let second = store.save(&keyset, Some(&first)).await.unwrap();
        assert_eq!(
            store.save(&keyset, Some(&first)).await,
            Err(StoreError::Conflict)
        );
        assert_eq!(store.load().await.unwrap().unwrap().revision, second);
    }
}
