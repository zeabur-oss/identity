//! TOTP codes ([RFC 6238]) as the second factor after a password, and one-time recovery codes.
//!
//! The parameters are the ones every common authenticator app reads from a QR code: HMAC-SHA-1,
//! 6 digits, 30-second steps. A code is accepted from one step before to one step after the
//! current one, for clock drift (RFC 6238 §5.2), and only for a step later than the last one
//! accepted, so each code works once (§5.2: "the verifier MUST NOT accept the second attempt of
//! the same OTP"). A 6-digit code is guessable, so the caller limits failures
//! (NIST SP 800-63B-4 §3.1.4.2).
//!
//! A recovery code takes the place of one TOTP code when the authenticator is lost. Each holds 60
//! random bits and is stored only as a keyed hash.
//!
//! [RFC 6238]: https://www.rfc-editor.org/rfc/rfc6238

use aws_lc_rs::hmac;

use crate::clock::UnixTime;
use crate::crypto::{CryptoError, ct_eq, hex, hmac_sha256, random};

/// Seconds per step (RFC 6238 §4.1, X = 30).
pub const STEP: u64 = 30;
/// Digits in a code.
pub const DIGITS: usize = 6;
/// Recovery codes given at enrolment.
pub const RECOVERY_CODES: usize = 10;
/// Secret length: 160 bits, the length RFC 4226 §4 R6 recommends.
const SECRET_LEN: usize = 20;
/// Base32 characters in a recovery code: 12 × 5 = 60 bits.
const RECOVERY_LEN: usize = 12;
/// RFC 4648 §6.
const BASE32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// A TOTP secret.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret([u8; SECRET_LEN]);

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret(..)")
    }
}

impl Secret {
    /// A new random secret.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError`] if the RNG fails.
    pub fn generate() -> Result<Self, CryptoError> {
        random().map(Self)
    }

    /// A secret from its stored bytes.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        bytes.try_into().ok().map(Self)
    }

    /// The raw bytes, for sealing.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// The secret in base32 without padding, as authenticator apps take it.
    #[must_use]
    pub fn base32(&self) -> String {
        base32(&self.0)
    }

    /// The `otpauth://` URI that a QR code carries.
    ///
    /// The format is the de facto Key URI Format: `otpauth://totp/<issuer>:<account>` with the
    /// secret, the issuer again, and the parameters as query values.
    #[must_use]
    pub fn uri(&self, issuer: &str, account: &str) -> String {
        format!(
            "otpauth://totp/{}:{}?secret={}&issuer={}&algorithm=SHA1&digits={DIGITS}&period={STEP}",
            encode(issuer),
            encode(account),
            self.base32(),
            encode(issuer),
        )
    }

    /// The code for `step` (RFC 4226 §5.3 dynamic truncation).
    fn code(&self, step: u64) -> u32 {
        let key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, &self.0);
        let tag = hmac::sign(&key, &step.to_be_bytes());
        let mac = tag.as_ref();
        let offset = usize::from(mac.last().copied().unwrap_or_default() & 0x0F);
        let word = mac
            .get(offset..offset + 4)
            .and_then(|bytes| <[u8; 4]>::try_from(bytes).ok())
            .map_or(0, u32::from_be_bytes);
        (word & 0x7FFF_FFFF) % 1_000_000
    }

    /// The code an authenticator app shows at `now`.
    #[must_use]
    pub fn code_at(&self, now: UnixTime) -> String {
        format!(
            "{:0width$}",
            self.code(now.as_secs() / STEP),
            width = DIGITS
        )
    }

    /// The step at which `entered` is this secret's code, if it is one within one step of `now`
    /// and later than `last_step`.
    #[must_use]
    pub fn check(&self, entered: &str, now: UnixTime, last_step: Option<u64>) -> Option<u64> {
        let entered = entered.trim();
        if entered.len() != DIGITS || !entered.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let current = now.as_secs() / STEP;
        let mut accepted = None;
        // Every candidate is computed, so the time taken does not tell which step matched.
        for step in current.saturating_sub(1)..=current.saturating_add(1) {
            let code = format!("{:0width$}", self.code(step), width = DIGITS);
            let fresh = last_step.is_none_or(|last| step > last);
            if ct_eq(code.as_bytes(), entered.as_bytes()) && fresh && accepted.is_none() {
                accepted = Some(step);
            }
        }
        accepted
    }
}

/// Keyed hashes of recovery codes. The key is derived from the server's password key, so the
/// stored hashes alone cannot be checked offline.
pub struct RecoveryKey([u8; 32]);

impl std::fmt::Debug for RecoveryKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RecoveryKey(..)")
    }
}

impl RecoveryKey {
    /// A key for recovery codes.
    #[must_use]
    pub const fn new(key: [u8; 32]) -> Self {
        Self(key)
    }

    /// New recovery codes, as shown to the user, and their hashes, as stored.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError`] if the RNG fails.
    pub fn generate(&self) -> Result<(Vec<String>, Vec<String>), CryptoError> {
        let mut shown = Vec::with_capacity(RECOVERY_CODES);
        let mut stored = Vec::with_capacity(RECOVERY_CODES);
        for _ in 0..RECOVERY_CODES {
            let bytes: [u8; 8] = random()?;
            let code: String = base32(&bytes).chars().take(RECOVERY_LEN).collect();
            stored.push(self.hash(&code));
            let (a, rest) = code.split_at(4);
            let (b, c) = rest.split_at(4);
            shown.push(format!("{a}-{b}-{c}").to_ascii_lowercase());
        }
        Ok((shown, stored))
    }

    /// The index in `stored` of the recovery code `entered`, if it is one and not in `used`.
    #[must_use]
    pub fn check(&self, entered: &str, stored: &[String], used: &[usize]) -> Option<usize> {
        let code: String = entered
            .chars()
            .filter(|c| !matches!(c, '-' | ' '))
            .map(|c| c.to_ascii_uppercase())
            .collect();
        if code.len() != RECOVERY_LEN || !code.bytes().all(|b| BASE32.contains(&b)) {
            return None;
        }
        let hash = self.hash(&code);
        let mut found = None;
        // Every stored hash is compared, so the time taken does not tell which one matched.
        for (index, candidate) in stored.iter().enumerate() {
            if ct_eq(candidate.as_bytes(), hash.as_bytes()) && found.is_none() {
                found = Some(index);
            }
        }
        found.filter(|index| !used.contains(index))
    }

    fn hash(&self, code: &str) -> String {
        hex(&hmac_sha256(&self.0, code.as_bytes()))
    }
}

/// RFC 4648 base32 without padding.
fn base32(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(5) * 8);
    let (mut buffer, mut bits) = (0_u32, 0_u32);
    for &byte in bytes {
        buffer = (buffer << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.extend(symbol(buffer >> bits));
        }
    }
    if bits > 0 {
        out.extend(symbol(buffer << (5 - bits)));
    }
    out
}

/// The base32 character of the low 5 bits of `bits`.
fn symbol(bits: u32) -> Option<char> {
    BASE32.get((bits & 31) as usize).copied().map(char::from)
}

/// Percent-encodes everything but RFC 3986 unreserved characters.
fn encode(text: &str) -> String {
    use std::fmt::Write as _;
    text.bytes().fold(String::new(), |mut out, byte| {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(byte));
        } else if write!(out, "%{byte:02X}").is_err() {
            out.clear();
        }
        out
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The SHA-1 seed of RFC 6238 Appendix B: "12345678901234567890" in ASCII.
    fn rfc_secret() -> Secret {
        Secret::from_bytes(b"12345678901234567890").unwrap()
    }

    #[test]
    fn codes_match_the_rfc_6238_test_vectors() {
        // Appendix B gives 8 digits; the 6-digit code is its last 6 digits.
        let vectors = [
            (59, "287082"),
            (1_111_111_109, "081804"),
            (1_111_111_111, "050471"),
            (1_234_567_890, "005924"),
            (2_000_000_000, "279037"),
        ];
        for (time, code) in vectors {
            let now = UnixTime::from_secs(time);
            assert_eq!(rfc_secret().check(code, now, None), Some(time / STEP));
        }
    }

    #[test]
    fn a_code_works_within_one_step_and_only_once() {
        let secret = rfc_secret();
        let step = 1_234_567_890 / STEP;
        let code = "005924";
        for near in [step - 1, step + 1] {
            let now = UnixTime::from_secs(near * STEP + 5);
            assert_eq!(secret.check(code, now, None), Some(step), "step {near}");
        }
        let two_steps = UnixTime::from_secs((step + 2) * STEP);
        assert_eq!(secret.check(code, two_steps, None), None);
        let now = UnixTime::from_secs(step * STEP);
        assert_eq!(secret.check(code, now, Some(step)), None, "replayed");
        assert_eq!(secret.check(code, now, Some(step - 1)), Some(step));
        assert_eq!(secret.check("05924", now, None), None);
        assert_eq!(secret.check("00592a", now, None), None);
    }

    #[test]
    fn the_uri_carries_the_secret_and_the_encoded_names() {
        let uri = rfc_secret().uri("identity.example.com", "alice smith");
        assert_eq!(
            uri,
            "otpauth://totp/identity.example.com:alice%20smith?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=identity.example.com&algorithm=SHA1&digits=6&period=30"
        );
    }

    #[test]
    fn recovery_codes_work_once_and_ignore_case_and_dashes() {
        let key = RecoveryKey::new([3; 32]);
        let (shown, stored) = key.generate().unwrap();
        assert_eq!(
            (shown.len(), stored.len()),
            (RECOVERY_CODES, RECOVERY_CODES)
        );
        let first = &shown[0];
        assert_eq!(first.len(), RECOVERY_LEN + 2);
        assert!(
            !stored
                .iter()
                .any(|hash| hash.contains(&first.replace('-', "")))
        );
        assert_eq!(key.check(first, &stored, &[]), Some(0));
        let typed = first.replace('-', " ").to_ascii_uppercase();
        assert_eq!(key.check(&typed, &stored, &[]), Some(0));
        assert_eq!(key.check(first, &stored, &[0]), None, "used");
        assert_eq!(key.check(&shown[9], &stored, &[0]), Some(9));
        assert_eq!(RecoveryKey::new([4; 32]).check(first, &stored, &[]), None);
        assert_eq!(key.check("123456", &stored, &[]), None);
    }
}
