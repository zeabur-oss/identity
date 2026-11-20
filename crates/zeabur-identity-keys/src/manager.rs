//! Keeps the signing keys current and publishes them.
//!
//! [`KeyManager::reconcile`] reads the stored keys, advances every [`KeyRing`] to the current
//! time, writes the result back with compare-and-swap, and only then publishes it. A key is
//! never used for signing before it has been stored, so a restart cannot lose a key that signed
//! live tokens, and two writers (for example two replicas) cannot both install different
//! successors. After a conflict nothing new is published; the next interval retries.
//!
//! Each [`Published`] snapshot is immutable and carries the pre-serialized JWK set, so request
//! handlers serve bytes without locking or serializing. If reconciliation keeps failing, the last
//! published keys stay in use and the active key keeps signing past its period; it is still
//! published, so its tokens still verify.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use thiserror::Error;
use tokio::sync::watch;
use tokio::time::MissedTickBehavior;
use zeabur_identity_core::clock::{Clock, UnixTime};

use super::Algorithm;
use super::jwk::JwkSet;
use super::rotation::{KeyRing, RotationPolicy};
use super::signing::{KeyError, SigningKey};
use super::store::{self, DecodeError, KeyStore, StoreError};
use super::verify::VerificationKey;

/// Why a reconciliation failed. The previously published keys stay in use.
#[derive(Debug, Error)]
pub enum ManagerError {
    /// Storage failed or another writer won the race.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// The stored keys cannot be used. They are left untouched.
    #[error(transparent)]
    Decode(#[from] DecodeError),
    /// Key generation or export failed.
    #[error(transparent)]
    Key(#[from] KeyError),
    /// The JWK set could not be serialized.
    #[error("serializing the JWK set failed")]
    Serialize(#[source] serde_json::Error),
}

/// A consistent snapshot of the published keys.
#[derive(Debug)]
pub struct Published {
    rings: Vec<KeyRing>,
    jwks: Bytes,
}

impl Published {
    /// The serialized JWK set.
    #[must_use]
    pub fn jwks(&self) -> Bytes {
        self.jwks.clone()
    }

    /// The key that signs with `alg` at `now`.
    #[must_use]
    pub fn signer(&self, alg: Algorithm, now: UnixTime) -> Option<Arc<SigningKey>> {
        self.rings
            .iter()
            .find(|ring| ring.alg() == alg)
            .and_then(|ring| ring.active(now))
            .map(|record| Arc::clone(&record.key))
    }

    /// Every published key, for verifying tokens this issuer signed.
    #[must_use]
    pub fn verification_keys(&self) -> Vec<VerificationKey> {
        self.rings
            .iter()
            .flat_map(KeyRing::published)
            .map(|record| VerificationKey {
                kid: Some(record.key.kid().to_owned()),
                alg: record.key.alg(),
                key: record.key.public().clone(),
            })
            .collect()
    }

    fn new(rings: Vec<KeyRing>) -> Result<Self, ManagerError> {
        let keys = rings
            .iter()
            .flat_map(KeyRing::published)
            .map(|record| record.key.jwk())
            .collect();
        let jwks = serde_json::to_vec(&JwkSet { keys }).map_err(ManagerError::Serialize)?;
        Ok(Self {
            rings,
            jwks: Bytes::from(jwks),
        })
    }
}

/// Receives the latest [`Published`] snapshot; `None` until the first successful reconcile.
pub type PublishedKeys = watch::Receiver<Option<Arc<Published>>>;

/// Owns key rotation for one issuer.
#[derive(Debug)]
pub struct KeyManager<S, C> {
    store: S,
    clock: C,
    policy: RotationPolicy,
    sender: watch::Sender<Option<Arc<Published>>>,
}

impl<S: KeyStore, C: Clock> KeyManager<S, C> {
    /// Creates a manager. Nothing is published until [`Self::reconcile`] succeeds.
    pub fn new(store: S, clock: C, policy: RotationPolicy) -> Self {
        let (sender, _) = watch::channel(None);
        Self {
            store,
            clock,
            policy,
            sender,
        }
    }

    /// Subscribes to published snapshots.
    #[must_use]
    pub fn subscribe(&self) -> PublishedKeys {
        self.sender.subscribe()
    }

    /// Loads, advances, stores and publishes the keys once.
    ///
    /// # Errors
    ///
    /// Returns [`ManagerError`] if storage, decoding or key generation fails, or if another
    /// writer changed the keys concurrently. Nothing new is published in that case.
    pub async fn reconcile(&self) -> Result<(), ManagerError> {
        let loaded = self.store.load().await?;
        let (mut rings, revision) = match loaded {
            Some(loaded) => (store::decode(&loaded.keyset)?, Some(loaded.revision)),
            None => (Algorithm::ALL.map(KeyRing::new).to_vec(), None),
        };

        let now = self.clock.now();
        let mut changed = false;
        for ring in &mut rings {
            changed |= ring.tick(now, &self.policy, SigningKey::generate)?;
        }
        if changed {
            self.store
                .save(&store::encode(&rings)?, revision.as_ref())
                .await?;
            for ring in &rings {
                for record in ring.published() {
                    tracing::debug!(
                        alg = ring.alg().as_str(),
                        kid = record.key.kid(),
                        activates_at = record.activates_at.as_secs(),
                        "published signing key"
                    );
                }
            }
            tracing::info!(
                keys = rings.iter().map(|r| r.published().len()).sum::<usize>(),
                "signing keys updated"
            );
        }

        let published = Arc::new(Published::new(rings)?);
        self.sender.send_replace(Some(published));
        Ok(())
    }

    /// Reconciles every `interval` until `shutdown` changes. Failures are logged and retried at
    /// the next interval; the last published keys stay in use meanwhile.
    pub async fn run(&self, interval: Duration, mut shutdown: watch::Receiver<bool>) {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    if let Err(error) = self.reconcile().await {
                        tracing::warn!(%error, reason = "key_reconciliation_failed", "signing key reconciliation failed; will retry");
                    }
                }
                _ = shutdown.changed() => break,
            }
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::future::Future;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;
    use crate::store::{Loaded, MemoryKeyStore, Revision, StoredKeyset};

    /// A clock tests move by hand.
    #[derive(Debug, Default)]
    pub(crate) struct TestClock(pub(crate) AtomicU64);

    impl Clock for TestClock {
        fn now(&self) -> UnixTime {
            UnixTime::from_secs(self.0.load(Ordering::SeqCst))
        }
    }

    fn kids(published: &Published) -> Vec<String> {
        #[derive(serde::Deserialize)]
        struct Key {
            kid: String,
        }
        #[derive(serde::Deserialize)]
        struct Set {
            keys: Vec<Key>,
        }
        let set: Set = serde_json::from_slice(&published.jwks()).unwrap();
        set.keys.into_iter().map(|key| key.kid).collect()
    }

    #[tokio::test]
    async fn publishes_after_first_reconcile_and_survives_reload() {
        let clock = Arc::new(TestClock::default());
        clock.0.store(1_000_000, Ordering::SeqCst);
        let manager = KeyManager::new(
            MemoryKeyStore::default(),
            Arc::clone(&clock),
            RotationPolicy::DEFAULT,
        );
        let mut published = manager.subscribe();
        assert!(published.borrow().is_none());

        manager.reconcile().await.unwrap();
        assert!(published.has_changed().unwrap());
        let first = published.borrow_and_update().clone().unwrap();
        let signer = first.signer(Algorithm::Es256, clock.now()).unwrap();
        assert!(kids(&first).contains(&signer.kid().to_owned()));

        // Reconciling again without time passing keeps the same keys.
        manager.reconcile().await.unwrap();
        let again = published.borrow().clone().unwrap();
        assert_eq!(kids(&again), kids(&first));
        assert_eq!(
            again.signer(Algorithm::Es256, clock.now()).unwrap().kid(),
            signer.kid()
        );
    }

    #[tokio::test]
    async fn rotation_publishes_the_next_key_before_using_it() {
        let clock = Arc::new(TestClock::default());
        let manager = KeyManager::new(
            MemoryKeyStore::default(),
            Arc::clone(&clock),
            RotationPolicy::DEFAULT,
        );
        let published = manager.subscribe();
        manager.reconcile().await.unwrap();
        let old = published
            .borrow()
            .clone()
            .unwrap()
            .signer(Algorithm::Es256, clock.now())
            .unwrap();

        clock.0.store(6 * 86_400, Ordering::SeqCst);
        manager.reconcile().await.unwrap();
        let snapshot = published.borrow().clone().unwrap();
        assert_eq!(
            snapshot
                .signer(Algorithm::Es256, clock.now())
                .unwrap()
                .kid(),
            old.kid()
        );
        let successor = snapshot
            .signer(Algorithm::Es256, UnixTime::from_secs(7 * 86_400))
            .unwrap();
        assert_ne!(
            successor.kid(),
            old.kid(),
            "the published successor takes over on schedule, even before the next reconcile"
        );
        assert!(
            kids(&snapshot).contains(&successor.kid().to_owned()),
            "the successor is published before it signs"
        );
    }

    /// A store that always reports a concurrent write.
    #[derive(Debug, Default)]
    struct ConflictingStore;

    impl KeyStore for ConflictingStore {
        fn load(&self) -> impl Future<Output = Result<Option<Loaded>, StoreError>> + Send {
            std::future::ready(Ok(None))
        }

        fn save(
            &self,
            _: &StoredKeyset,
            _: Option<&Revision>,
        ) -> impl Future<Output = Result<Revision, StoreError>> + Send {
            std::future::ready(Err(StoreError::Conflict))
        }
    }

    #[tokio::test]
    async fn never_publishes_keys_it_could_not_store() {
        let manager = KeyManager::new(
            ConflictingStore,
            SystemClockForTest,
            RotationPolicy::DEFAULT,
        );
        let published = manager.subscribe();
        assert!(matches!(
            manager.reconcile().await,
            Err(ManagerError::Store(StoreError::Conflict))
        ));
        assert!(published.borrow().is_none());
    }

    #[derive(Debug)]
    struct SystemClockForTest;
    impl Clock for SystemClockForTest {
        fn now(&self) -> UnixTime {
            UnixTime::from_secs(42)
        }
    }

    #[tokio::test]
    async fn refuses_to_overwrite_undecodable_keys() {
        let store = MemoryKeyStore::default();
        let bad = StoredKeyset {
            version: 99,
            keys: Vec::new(),
        };
        store.save(&bad, None).await.unwrap();
        let manager = KeyManager::new(store, SystemClockForTest, RotationPolicy::DEFAULT);
        assert!(matches!(
            manager.reconcile().await,
            Err(ManagerError::Decode(DecodeError::Version(99)))
        ));
        assert_eq!(
            manager.store.load().await.unwrap().unwrap().keyset,
            bad,
            "left untouched"
        );
    }
}
