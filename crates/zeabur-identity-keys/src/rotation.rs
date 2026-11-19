//! The signing-key schedule.
//!
//! Each algorithm has a [`KeyRing`]. A key moves through three phases that derive from two
//! timestamps. No phase is stored.
//!
//! - **Pending:** published in the JWK set but not yet signing (`now < activates_at`).
//! - **Active:** the newest key with `activates_at <= now`. It signs everything.
//! - **Retired:** a newer key has become active. The key stays published until `retain_after` has
//!   passed since it stopped signing, so tokens it signed keep verifying.
//!
//! A published successor takes over on schedule even if the reconcile loop runs late.
//! [`KeyRing::tick`] is a pure function of the ring, the time and the policy (plus a key
//! generator), so tests need no clock or storage.
//!
//! # Why keys are published ahead
//!
//! Verifiers cache the JWK set. kube-apiserver 1.34 to 1.36 use go-oidc v2. It re-fetches the set
//! on an unknown `kid` only after the cached copy's `Cache-Control` lifetime (plus 30 s) has
//! expired ([kube-apiserver OIDC], [go-oidc v2]). An issuer that signs with a new key at once
//! therefore breaks kube-apiserver for up to that lifetime. Zeabur Identity publishes each key
//! [`RotationPolicy::publish_ahead`] (24 h) before it signs, far longer than the JWK set's
//! `max-age` (5 min). The server refuses to start unless `max-age` is shorter. A verifier that
//! caches the JWK set for longer than the publish-ahead time fails after a rotation.
//!
//! Retired keys stay published for [`RotationPolicy::retain_after`], as [OIDC Core] §10.1.1
//! recommends ("retain recently decommissioned signing keys for a reasonable period of time").
//!
//! With the default policy the JWK set holds one or two keys per algorithm. A third key appears
//! only if `retain_after` exceeds `rotation_period - publish_ahead`.
//!
//! # Clock errors
//!
//! A clock that jumps forward advances the schedule. This is safe because keys are published ahead.
//! A clock that jumps backwards can leave no active key. [`KeyRing::tick`] then creates a key that
//! is active at once, which a verifier may not have cached yet. Hosts must run NTP.
//!
//! [kube-apiserver OIDC]: https://github.com/kubernetes/kubernetes/blob/master/staging/src/k8s.io/apiserver/plugin/pkg/authenticator/token/oidc/oidc.go
//! [go-oidc v2]: https://github.com/coreos/go-oidc/blob/v2.5.0/jwks.go
//! [OIDC Core]: https://openid.net/specs/openid-connect-core-1_0.html

use std::sync::Arc;
use std::time::Duration;

use zeabur_identity_core::clock::UnixTime;
use zeabur_identity_core::config::ConfigError;

use super::Algorithm;
use super::signing::{KeyError, SigningKey};

/// Rotation timings.
///
/// [`Self::validate`] checks the constraints between these values. Two more are checked by the
/// server at startup because they involve other settings: the JWK set `max-age` must be shorter
/// than `publish_ahead`, and `retain_after` must be at least the longest token lifetime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RotationPolicy {
    /// How long each key is the active signing key.
    pub rotation_period: Duration,
    /// How long a new key is published before it signs anything. Must exceed every verifier's
    /// JWK set cache lifetime (kube-apiserver re-fetches only after `Cache-Control` expiry).
    pub publish_ahead: Duration,
    /// How long a key stays published after it stops signing. Must exceed the longest lifetime
    /// of any token it signed.
    pub retain_after: Duration,
}

impl RotationPolicy {
    /// Seven-day rotation, 24 h publish-ahead and 24 h retention.
    ///
    /// 24 h of publish-ahead covers kube-apiserver and clients that cache the JWK set for up to a
    /// day; 24 h of retention covers every token lifetime Zeabur Identity issues by default.
    pub const DEFAULT: Self = Self {
        rotation_period: Duration::from_hours(7 * 24),
        publish_ahead: Duration::from_hours(24),
        retain_after: Duration::from_hours(24),
    };

    /// Checks that the timings are usable.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::BadRotationPolicy`] if a value is below one minute or the
    /// publish-ahead time is not shorter than the rotation period.
    pub fn validate(&self) -> Result<(), ConfigError> {
        let minute = Duration::from_mins(1);
        if self.rotation_period < minute
            || self.publish_ahead < minute
            || self.retain_after < minute
        {
            return Err(ConfigError::BadRotationPolicy(
                "every timing must be at least one minute",
            ));
        }
        if self.publish_ahead >= self.rotation_period {
            return Err(ConfigError::BadRotationPolicy(
                "the publish-ahead time must be shorter than the rotation period",
            ));
        }
        Ok(())
    }
}

/// One key and its schedule.
#[derive(Debug, Clone)]
pub struct KeyRecord {
    /// The key.
    pub key: Arc<SigningKey>,
    /// When the key was generated and first published.
    pub created_at: UnixTime,
    /// When the key starts signing.
    pub activates_at: UnixTime,
}

/// All keys of one algorithm.
#[derive(Debug, Clone)]
pub struct KeyRing {
    alg: Algorithm,
    keys: Vec<KeyRecord>,
}

impl KeyRing {
    /// An empty ring.
    #[must_use]
    pub const fn new(alg: Algorithm) -> Self {
        Self {
            alg,
            keys: Vec::new(),
        }
    }

    /// A ring holding `keys`, which must all be keys for `alg`.
    #[must_use]
    pub fn from_records(alg: Algorithm, mut keys: Vec<KeyRecord>) -> Self {
        keys.retain(|record| record.key.alg() == alg);
        keys.sort_by_key(|record| record.activates_at);
        Self { alg, keys }
    }

    /// The algorithm.
    #[must_use]
    pub const fn alg(&self) -> Algorithm {
        self.alg
    }

    /// Every key that must be published: pending, active and retained keys, oldest first.
    #[must_use]
    pub fn published(&self) -> &[KeyRecord] {
        &self.keys
    }

    /// The key that signs at `now`, if any.
    #[must_use]
    pub fn active(&self, now: UnixTime) -> Option<&KeyRecord> {
        self.keys
            .iter()
            .rev()
            .find(|record| record.activates_at <= now)
    }

    /// Brings the ring up to date at `now`: bootstraps the first key, schedules the next key
    /// early enough, and drops keys that no verifier needs any more. Returns whether anything
    /// changed.
    ///
    /// # Errors
    ///
    /// Returns an error from `generate`; the ring is then unchanged.
    pub fn tick(
        &mut self,
        now: UnixTime,
        policy: &RotationPolicy,
        mut generate: impl FnMut(Algorithm) -> Result<SigningKey, KeyError>,
    ) -> Result<bool, KeyError> {
        let mut changed = false;

        let Some(active) = self.active(now) else {
            // No usable key. Either the ring is empty (first start: no token has been issued, so
            // nothing can fail verification) or every key is still pending (only possible if the
            // clock moved backwards). Sign immediately with a new key.
            self.push(generate(self.alg)?, now, now);
            return Ok(true);
        };
        let active_since = active.activates_at;

        // Schedule a successor once the active key's period minus the publish-ahead time has
        // elapsed. If we are late (the service was down), the successor still gets the full
        // publish-ahead time and the current key signs a little longer.
        let has_pending = self.keys.iter().any(|record| record.activates_at > now);
        let rotate_at = active_since.saturating_add(policy.rotation_period);
        if !has_pending && now.saturating_add(policy.publish_ahead) >= rotate_at {
            let activates_at = rotate_at.max(now.saturating_add(policy.publish_ahead));
            self.push(generate(self.alg)?, now, activates_at);
            changed = true;
        }

        // A key stopped signing when the next key became active. Drop it once `retain_after`
        // has passed since then. The active key and pending keys have no active successor.
        let before = self.keys.len();
        let activations: Vec<UnixTime> = self.keys.iter().map(|r| r.activates_at).collect();
        let mut index = 0;
        self.keys.retain(|_| {
            let stopped_signing = activations.get(index + 1).copied();
            index += 1;
            stopped_signing.is_none_or(|stopped| {
                stopped > now || stopped.saturating_add(policy.retain_after) > now
            })
        });
        changed |= self.keys.len() != before;

        Ok(changed)
    }

    fn push(&mut self, key: SigningKey, created_at: UnixTime, activates_at: UnixTime) {
        self.keys.push(KeyRecord {
            key: Arc::new(key),
            created_at,
            activates_at,
        });
        self.keys.sort_by_key(|record| record.activates_at);
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, HashSet};

    use proptest::prelude::*;

    use super::*;

    const HOUR: u64 = 3_600;
    const DAY: u64 = 86_400;

    fn policy() -> RotationPolicy {
        RotationPolicy::DEFAULT
    }

    /// Generating real keys in property tests is slow; P-256 generation is cheap enough.
    fn generate(_: Algorithm) -> Result<SigningKey, KeyError> {
        SigningKey::generate(Algorithm::Es256)
    }

    fn at(secs: u64) -> UnixTime {
        UnixTime::from_secs(secs)
    }

    #[test]
    fn bootstraps_with_an_immediately_active_key() {
        let mut ring = KeyRing::new(Algorithm::Es256);
        assert!(ring.tick(at(1_000), &policy(), generate).unwrap());
        assert_eq!(ring.active(at(1_000)).unwrap().activates_at, at(1_000));
        assert!(
            !ring.tick(at(1_001), &policy(), generate).unwrap(),
            "idempotent"
        );
    }

    #[test]
    fn follows_the_schedule() {
        let p = policy();
        let mut ring = KeyRing::new(Algorithm::Es256);
        ring.tick(at(0), &p, generate).unwrap();
        let first = ring.active(at(0)).unwrap().key.kid().to_owned();

        // Six days in: successor published, activating at day 7.
        ring.tick(at(6 * DAY), &p, generate).unwrap();
        let next = ring.published().last().unwrap();
        assert_ne!(next.key.kid(), first);
        assert_eq!(next.activates_at, at(7 * DAY));
        assert_eq!(ring.active(at(7 * DAY - 1)).unwrap().key.kid(), first);
        assert_ne!(ring.active(at(7 * DAY)).unwrap().key.kid(), first);

        // The first key stays published for a day after it stopped signing.
        ring.tick(at(8 * DAY - 1), &p, generate).unwrap();
        assert!(ring.published().iter().any(|r| r.key.kid() == first));
        ring.tick(at(8 * DAY), &p, generate).unwrap();
        assert!(ring.published().iter().all(|r| r.key.kid() != first));
    }

    #[test]
    fn late_rotation_still_publishes_ahead() {
        let p = policy();
        let mut ring = KeyRing::new(Algorithm::Es256);
        ring.tick(at(0), &p, generate).unwrap();
        // Down for 30 days, then back.
        ring.tick(at(30 * DAY), &p, generate).unwrap();
        let next = ring.published().last().unwrap();
        assert_eq!(next.activates_at, at(31 * DAY));
        assert_eq!(ring.active(at(30 * DAY)).unwrap().activates_at, at(0));
    }

    #[test]
    fn generator_failure_leaves_ring_unchanged() {
        let mut ring = KeyRing::new(Algorithm::Es256);
        let error = ring
            .tick(at(0), &policy(), |_| {
                Err(KeyError::Generate(aws_lc_rs::error::Unspecified))
            })
            .unwrap_err();
        assert!(matches!(error, KeyError::Generate(_)));
        assert!(ring.published().is_empty());
    }

    #[test]
    fn rejects_bad_policies() {
        let mut p = policy();
        p.publish_ahead = p.rotation_period;
        assert!(p.validate().is_err());
        let mut p = policy();
        p.retain_after = Duration::from_secs(1);
        assert!(p.validate().is_err());
        assert!(policy().validate().is_ok());
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        /// Simulates the service ticking at arbitrary, increasing times (including long
        /// outages) and checks the invariants verifiers depend on.
        #[test]
        fn schedule_invariants(
            gaps in proptest::collection::vec(1_u64..=10 * DAY, 1..80),
            rotation_days in 1_u64..=30,
            ahead_hours in 1_u64..=23,
            retain_hours in 1_u64..=72,
        ) {
            let p = RotationPolicy {
                rotation_period: Duration::from_secs(rotation_days * DAY),
                publish_ahead: Duration::from_secs(ahead_hours * HOUR),
                retain_after: Duration::from_secs(retain_hours * HOUR),
            };
            prop_assume!(p.validate().is_ok());

            let mut ring = KeyRing::new(Algorithm::Es256);
            let mut now = 1_000_000_u64;
            let mut first_seen: HashMap<String, u64> = HashMap::new();
            // kid -> last time it was the active key.
            let mut last_signed: HashMap<String, u64> = HashMap::new();
            let mut bootstrap_kid: Option<String> = None;

            for gap in gaps {
                ring.tick(at(now), &p, generate).unwrap();

                let kids: Vec<&str> = ring.published().iter().map(|r| r.key.kid()).collect();
                let unique: HashSet<&str> = kids.iter().copied().collect();
                prop_assert_eq!(unique.len(), kids.len(), "kids are unique");
                // Pending + active + retired keys; more than one retired key only when keys are
                // retained longer than a rotation period.
                let bound = 3 + usize::try_from(retain_hours / (rotation_days * 24)).unwrap();
                prop_assert!(ring.published().len() <= bound, "ring stays small: {}", ring.published().len());

                for record in ring.published() {
                    first_seen.entry(record.key.kid().to_owned()).or_insert(now);
                }

                let active = ring.active(at(now));
                prop_assert!(active.is_some(), "a key is always active");
                let active = active.unwrap();
                let kid = active.key.kid().to_owned();
                if bootstrap_kid.is_none() {
                    bootstrap_kid = Some(kid.clone());
                }
                // Published ahead: every key except the bootstrap key was visible in the JWK set
                // for at least `publish_ahead` before it became active.
                if Some(&kid) != bootstrap_kid.as_ref() {
                    let seen = first_seen[&kid];
                    prop_assert!(active.activates_at.as_secs() >= seen + p.publish_ahead.as_secs());
                }
                last_signed.insert(kid, now);

                // Retained: a key that signed within `retain_after` of now is still published.
                for (signed_kid, signed_at) in &last_signed {
                    if now < signed_at + p.retain_after.as_secs() {
                        prop_assert!(
                            ring.published().iter().any(|r| r.key.kid() == signed_kid),
                            "key that signed at {} dropped at {}", signed_at, now
                        );
                    }
                }

                now += gap;
            }
        }
    }
}
