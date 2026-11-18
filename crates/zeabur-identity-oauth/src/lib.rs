#![doc = include_str!("../README.md")]

pub mod authorize;
pub mod client_auth;
pub mod code;
pub mod discovery;
pub mod endpoints;
pub mod error;
pub mod metadata;
pub mod params;
pub mod pkce;
pub mod refresh;
pub mod tokens;
pub mod userinfo;

use std::collections::HashMap;
use std::sync::{Mutex, PoisonError};
use std::time::Duration;

use zeabur_identity_core::account::{AccountType, Settings};
use zeabur_identity_core::clock::{Clock, UnixTime};
use zeabur_identity_core::config::BaseUrl;
use zeabur_identity_core::crypto::Sealer;
use zeabur_identity_keys::manager::PublishedKeys;
use zeabur_identity_store::{Directory, GrantStore};

/// Lifetimes of everything the authorization server issues.
///
/// Access and ID tokens are short because kube-apiserver verifies them offline and caches the
/// result: nothing issued can be revoked, so the token lifetime is the revocation latency.
/// Long sessions come from refresh tokens instead, which can be revoked. Token and refresh
/// lifetimes depend on the account type: see [`Lifetimes::for_account`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Lifetimes {
    /// Pending sign-in (the sealed authorization request).
    pub flow: Duration,
    /// Authorization code. RFC 6749 §4.1.2 recommends at most 10 minutes.
    pub code: Duration,
    /// PAR `request_uri` (RFC 9126 §2.2 suggests 5 to 600 seconds).
    pub par: Duration,
    /// Access and ID tokens of a regular account.
    pub access_token: Duration,
    /// A refresh-token family dies if unused this long.
    pub refresh_idle: Duration,
    /// A refresh-token family dies this long after sign-in, regardless of use.
    pub refresh_absolute: Duration,
    /// Access and ID tokens of an admin account. They carry `cluster-admin`, so they are
    /// shorter.
    pub admin_access_token: Duration,
    /// The idle limit of an admin family if [`Settings::short_admin_idle`] is true.
    pub admin_refresh_idle: Duration,
}

/// The lifetimes that apply to one account: see [`Lifetimes::for_account`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TokenLifetimes {
    /// Access and ID tokens.
    pub access_token: Duration,
    /// Idle limit of the refresh-token family.
    pub refresh_idle: Duration,
    /// Absolute limit of the refresh-token family, from sign-in.
    pub refresh_absolute: Duration,
}

impl Lifetimes {
    /// The defaults: codes and PAR request URIs 60 s, pending sign-ins 10 min. Regular accounts:
    /// tokens 10 min, refresh families 1 h idle. Admin accounts: tokens 5 min, refresh families
    /// 15 min idle if several teams share the cluster or admins need a device-bound passkey, else 1
    /// h. Every family ends 12 h after sign-in.
    ///
    /// NIST SP 800-63B-4 sets the AAL2 reauthentication limits at 1 h idle and 24 h overall,
    /// and the AAL3 limits at 15 min idle and 12 h overall ([sp800-63b]).
    ///
    /// [sp800-63b]: https://pages.nist.gov/800-63-4/sp800-63b.html
    pub const DEFAULT: Self = Self {
        flow: Duration::from_mins(10),
        code: Duration::from_mins(1),
        par: Duration::from_mins(1),
        access_token: Duration::from_mins(10),
        refresh_idle: Duration::from_hours(1),
        refresh_absolute: Duration::from_hours(12),
        admin_access_token: Duration::from_mins(5),
        admin_refresh_idle: Duration::from_mins(15),
    };

    /// The lifetimes for an account of type `account` under `settings`.
    #[must_use]
    pub const fn for_account(&self, account: AccountType, settings: Settings) -> TokenLifetimes {
        let (access_token, refresh_idle) = match account {
            AccountType::Regular => (self.access_token, self.refresh_idle),
            AccountType::Admin if settings.short_admin_idle() => {
                (self.admin_access_token, self.admin_refresh_idle)
            }
            AccountType::Admin => (self.admin_access_token, self.refresh_idle),
        };
        TokenLifetimes {
            access_token,
            refresh_idle,
            refresh_absolute: self.refresh_absolute,
        }
    }

    /// The longest lifetime of any signed token, which signing keys must outlive.
    #[must_use]
    pub fn longest_signed_token(&self) -> Duration {
        self.access_token.max(self.admin_access_token)
    }
}

/// Everything the endpoints share.
#[derive(Debug)]
pub struct AuthorizationServer<D, G, C> {
    /// Issuer identifier.
    pub issuer: BaseUrl,
    /// Lifetimes.
    pub lifetimes: Lifetimes,
    /// Clients and users.
    pub directory: D,
    /// Refresh-token families.
    pub grants: G,
    /// Time source.
    pub clock: C,
    /// Signing keys.
    pub keys: PublishedKeys,
    /// Seals flows, codes and PAR request URIs. Its key exists only in this process, so a restart
    /// invalidates everything in flight (fail closed).
    pub sealer: Sealer,
    /// Codes redeemed so far, until they expire. Sealed codes are self-contained, so this set
    /// is what makes them single-use (RFC 6749 §4.1.2).
    pub used_codes: OneTimeIds,
    /// PAR request URIs used so far, until they expire (one-time use, RFC 9126 §4).
    pub used_request_uris: OneTimeIds,
}

impl<D: Directory, G: GrantStore, C: Clock> AuthorizationServer<D, G, C> {
    /// The current time.
    pub fn now(&self) -> UnixTime {
        self.clock.now()
    }
}

/// Outcome of [`OneTimeIds::first_use`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Use {
    /// The identifier had not been seen.
    First,
    /// The identifier was used before; carries what was recorded at first use.
    Again(String),
}

/// A set of single-use identifiers that remembers each one until it expires.
///
/// Used for sealed codes and request URIs: the sealing key is per-process, so this in-memory set
/// is complete for everything this process can open. Memory is bounded by the number of
/// successful redemptions within one code lifetime, and nothing is written to storage.
#[derive(Debug, Default)]
pub struct OneTimeIds {
    seen: Mutex<HashMap<String, (UnixTime, String)>>,
}

impl OneTimeIds {
    /// Records `id` with `note` unless already present. Entries past `expires_at` are dropped
    /// first; they can no longer be presented because the sealed value has expired too.
    pub fn first_use(&self, id: &str, expires_at: UnixTime, note: &str, now: UnixTime) -> Use {
        let mut seen = self.seen.lock().unwrap_or_else(PoisonError::into_inner);
        seen.retain(|_, (expiry, _)| *expiry > now);
        if let Some((_, recorded)) = seen.get(id) {
            return Use::Again(recorded.clone());
        }
        seen.insert(id.to_owned(), (expires_at, note.to_owned()));
        Use::First
    }
}

#[cfg(test)]
mod tests {
    use zeabur_identity_core::account::{AdminSignIn, Teams};

    use super::*;

    #[test]
    fn lifetimes_per_account_type() {
        let mins = Duration::from_mins;
        let single = Settings::default();
        let multiple = Settings {
            teams: Teams::Multiple,
            admin_sign_in: AdminSignIn::default(),
        };
        let device_bound = Settings {
            teams: Teams::Single,
            admin_sign_in: AdminSignIn::DeviceBoundPasskey,
        };
        let cases = [
            ("regular", AccountType::Regular, single, mins(10), mins(60)),
            (
                "regular, several teams",
                AccountType::Regular,
                multiple,
                mins(10),
                mins(60),
            ),
            (
                "regular, device-bound passkey",
                AccountType::Regular,
                device_bound,
                mins(10),
                mins(60),
            ),
            (
                "admin, one team",
                AccountType::Admin,
                single,
                mins(5),
                mins(60),
            ),
            (
                "admin, several teams",
                AccountType::Admin,
                multiple,
                mins(5),
                mins(15),
            ),
            (
                "admin, device-bound passkey",
                AccountType::Admin,
                device_bound,
                mins(5),
                mins(15),
            ),
        ];
        for (name, account, settings, access, idle) in cases {
            let got = Lifetimes::DEFAULT.for_account(account, settings);
            assert_eq!(got.access_token, access, "{name}");
            assert_eq!(got.refresh_idle, idle, "{name}");
            assert_eq!(got.refresh_absolute, Duration::from_hours(12), "{name}");
        }
    }

    #[test]
    fn one_time_ids() {
        let ids = OneTimeIds::default();
        let t = UnixTime::from_secs;
        assert_eq!(ids.first_use("a", t(100), "grant-a", t(0)), Use::First);
        assert_eq!(
            ids.first_use("a", t(100), "other", t(50)),
            Use::Again("grant-a".into())
        );
        assert_eq!(ids.first_use("b", t(100), "", t(50)), Use::First);
        // After expiry the entry is forgotten; the sealed value it guarded has expired as well.
        assert_eq!(ids.first_use("a", t(200), "", t(100)), Use::First);
    }
}
