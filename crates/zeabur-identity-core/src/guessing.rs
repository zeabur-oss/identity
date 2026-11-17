//! Limits on password guessing that cannot lock the owner out.
//!
//! Failures are counted per browser, with device cookies ([owasp]). A browser that signed in as
//! the user before carries a device cookie and has its own count. Every other browser shares one
//! count for the user. Past [`LIMIT`] failures in [`WINDOW`], that count's browsers are held back
//! for [`HOLD`]. Nothing is held back for good, and only password sign-in is held back, so the
//! owner can still sign in from a known browser, with a passkey or upstream account, or with a
//! setup link.
//!
//! [owasp]: https://community.owasp.org/Slow_Down_Online_Guessing_Attacks_with_Device_Cookies

use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::clock::UnixTime;
use crate::crypto::{CryptoError, ct_eq, hex, hmac_sha256, random, sha256};

/// Failures allowed in one [`WINDOW`].
pub const LIMIT: u32 = 10;
/// How long failures are counted together.
pub const WINDOW: Duration = Duration::from_hours(1);
/// How long a count past [`LIMIT`] holds its browsers back.
pub const HOLD: Duration = Duration::from_hours(1);
/// The most known browsers counted per user. The oldest count is dropped first.
pub const MAX_KNOWN: usize = 16;

/// One count of failures.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Count {
    /// When the current window started.
    pub since: UnixTime,
    /// Failures in the current window.
    pub failures: u32,
    /// Until when its browsers are held back.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub held_until: Option<UnixTime>,
}

impl Count {
    /// Whether its browsers are held back at `now`.
    #[must_use]
    pub fn held(&self, now: UnixTime) -> bool {
        self.held_until.is_some_and(|until| now < until)
    }

    /// Records one failure at `now`.
    pub fn fail(&mut self, now: UnixTime) {
        if self.since.saturating_add(WINDOW) <= now {
            *self = Self {
                since: now,
                failures: 0,
                held_until: None,
            };
        }
        self.failures = self.failures.saturating_add(1);
        if self.failures > LIMIT {
            self.held_until = Some(now.saturating_add(HOLD));
        }
    }
}

/// The counts for one user's password.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Counts {
    /// Every browser without a valid device cookie for the user.
    #[serde(default)]
    pub unknown: Count,
    /// Known browsers, by the SHA-256 hex of their device cookie's nonce.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub known: Vec<Known>,
}

/// The count of one known browser.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Known {
    /// SHA-256 hex of the device cookie's nonce.
    pub device: String,
    /// Its failures.
    #[serde(flatten)]
    pub count: Count,
}

impl Counts {
    /// Until when `device` (or an unknown browser, for `None`) is held back, if it is at `now`.
    #[must_use]
    pub fn held(&self, device: Option<&str>, now: UnixTime) -> Option<UnixTime> {
        let count = device.map_or(Some(&self.unknown), |device| {
            self.known
                .iter()
                .find(|k| k.device == device)
                .map(|k| &k.count)
        })?;
        count.held(now).then_some(count.held_until).flatten()
    }

    /// Records one failure from `device` (or an unknown browser) at `now`.
    pub fn fail(&mut self, device: Option<&str>, now: UnixTime) {
        let Some(device) = device else {
            self.unknown.fail(now);
            return;
        };
        if let Some(known) = self.known.iter_mut().find(|k| k.device == device) {
            known.count.fail(now);
            return;
        }
        if self.known.len() >= MAX_KNOWN
            && let Some(oldest) = self
                .known
                .iter()
                .enumerate()
                .min_by_key(|(_, k)| k.count.since)
                .map(|(i, _)| i)
        {
            self.known.swap_remove(oldest);
        }
        let mut count = Count::default();
        count.fail(now);
        self.known.push(Known {
            device: device.to_owned(),
            count,
        });
    }

    /// Clears the count of the browser that signed in. A success from an unknown browser clears
    /// the shared count, as NIST SP 800-63B-4 §3.2.2 asks.
    pub fn succeed(&mut self, device: Option<&str>) {
        match device {
            None => self.unknown = Count::default(),
            Some(device) => self.known.retain(|k| k.device != device),
        }
    }
}

/// Issues and checks device cookie entries. An entry is `<subject>.<nonce>.<mac>`: the user's
/// subject, a random nonce, and an HMAC over both with the server's device key.
pub struct DeviceKey([u8; 32]);

impl std::fmt::Debug for DeviceKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DeviceKey(..)")
    }
}

impl DeviceKey {
    /// A device key.
    #[must_use]
    pub const fn new(key: [u8; 32]) -> Self {
        Self(key)
    }

    fn mac(&self, subject: &str, nonce: &str) -> String {
        let data = format!("zeabur-identity/device/v1\0{subject}\0{nonce}");
        hex(&hmac_sha256(&self.0, data.as_bytes()))
    }

    /// A new entry for `subject`.
    ///
    /// # Errors
    ///
    /// [`CryptoError`] if the RNG fails.
    pub fn issue(&self, subject: &str) -> Result<String, CryptoError> {
        let nonce = hex(&random::<16>()?);
        let mac = self.mac(subject, &nonce);
        Ok(format!("{subject}.{nonce}.{mac}"))
    }

    /// The device of `entry` (the SHA-256 hex of its nonce) if the entry is valid for `subject`.
    #[must_use]
    pub fn check(&self, entry: &str, subject: &str) -> Option<String> {
        let mut parts = entry.split('.');
        let (Some(owner), Some(nonce), Some(mac), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return None;
        };
        (owner == subject && ct_eq(self.mac(subject, nonce).as_bytes(), mac.as_bytes()))
            .then(|| hex(&sha256(nonce.as_bytes())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const T0: UnixTime = UnixTime::from_secs(1_000_000);

    fn at(secs: u64) -> UnixTime {
        UnixTime::from_secs(T0.as_secs() + secs)
    }

    #[test]
    fn unknown_browsers_are_held_after_the_limit_and_released_later() {
        let mut counts = Counts::default();
        for i in 0..LIMIT {
            counts.fail(None, at(u64::from(i)));
        }
        assert!(counts.held(None, at(20)).is_none());
        counts.fail(None, at(21));
        assert!(counts.held(None, at(22)).is_some());
        assert!(counts.held(None, at(21 + HOLD.as_secs() - 1)).is_some());
        assert!(counts.held(None, at(21 + HOLD.as_secs())).is_none());
    }

    #[test]
    fn a_held_unknown_count_leaves_known_browsers_alone() {
        let mut counts = Counts::default();
        for _ in 0..=LIMIT {
            counts.fail(None, T0);
        }
        assert!(counts.held(None, T0).is_some());
        assert!(counts.held(Some("owner"), T0).is_none());
        counts.fail(Some("owner"), T0);
        assert!(counts.held(Some("owner"), T0).is_none());
    }

    #[test]
    fn failures_spread_over_windows_never_hold() {
        let mut counts = Counts::default();
        for hour in 0..48 {
            for _ in 0..LIMIT {
                counts.fail(None, at(hour * WINDOW.as_secs()));
            }
        }
        assert!(counts.held(None, at(48 * WINDOW.as_secs())).is_none());
    }

    #[test]
    fn known_counts_stay_bounded() {
        let mut counts = Counts::default();
        for i in 0..(MAX_KNOWN as u64 + 5) {
            counts.fail(Some(&format!("d{i}")), at(i));
        }
        assert_eq!(counts.known.len(), MAX_KNOWN);
        assert!(counts.known.iter().all(|k| k.device != "d0"));
    }

    #[test]
    fn device_entries_are_bound_to_the_key_and_the_subject() {
        let key = DeviceKey::new([7; 32]);
        let entry = key.issue("alice").unwrap();
        let device = key.check(&entry, "alice").unwrap();
        assert_eq!(device.len(), 64);
        assert_eq!(key.check(&entry, "bob"), None);
        assert_eq!(DeviceKey::new([8; 32]).check(&entry, "alice"), None);
        let forged = entry.replace("alice.", "bob.");
        assert_eq!(key.check(&forged, "bob"), None);
    }

    #[test]
    fn success_clears_only_that_browser() {
        let mut counts = Counts::default();
        counts.fail(None, T0);
        counts.fail(Some("a"), T0);
        counts.fail(Some("b"), T0);
        counts.succeed(Some("a"));
        assert_eq!(counts.unknown.failures, 1);
        assert_eq!(counts.known.len(), 1);
        counts.succeed(None);
        assert_eq!(counts.unknown.failures, 0);
    }
}
