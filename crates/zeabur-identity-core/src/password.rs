//! Passwords: the rules a new password must meet, and how passwords are stored.
//!
//! The rules follow NIST SP 800-63B-4 §3.1.1.2 for a password that is the only factor: at least
//! 15 characters, at least 64 accepted, every printing character and Unicode accepted and
//! counted by code point after NFC, no composition rules, and a check of the whole password
//! against common and context-specific values ([sp800-63b]).
//!
//! Storage is PBKDF2-HMAC-SHA256 with a random 128-bit salt, then HMAC-SHA256 with a server key
//! kept apart from the hashes (the "additional iteration of a keyed hashing" of §3.1.1.2).
//! PBKDF2 is the scheme of SP 800-132, and aws-lc-rs is the only cryptographic library Zeabur
//! Identity calls. The iteration count is the OWASP Password Storage Cheat Sheet's for
//! PBKDF2-HMAC-SHA256 ([owasp]).
//!
//! [sp800-63b]: https://pages.nist.gov/800-63-4/sp800-63b.html
//! [owasp]: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html

use std::num::NonZeroU32;

use aws_lc_rs::hmac;
use aws_lc_rs::pbkdf2::{self, PBKDF2_HMAC_SHA256};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use icu_normalizer::ComposingNormalizerBorrowed;

use crate::crypto::{CryptoError, ct_eq, random};

/// The fewest characters a password may have.
pub const MIN_CHARS: usize = 15;
/// The most characters a password may have.
pub const MAX_CHARS: usize = 256;
/// The most bytes read from a submitted password. Longer input is refused before any hashing.
pub const MAX_BYTES: usize = 1024;
/// PBKDF2 iterations for new hashes.
pub const ITERATIONS: u32 = 600_000;

const SALT_LEN: usize = 16;
const OUT_LEN: usize = 32;
const SCHEME: &str = "zid-pbkdf2-sha256-hmac";

/// Common passwords of 15 characters or more, lower-cased, sorted by bytes. From the
/// `SecLists` file `Pwdb_top-1000000.txt` (MIT, see `data/common-passwords.LICENSE`).
static COMMON: [&str; line_count(COMMON_TEXT)] = lines(COMMON_TEXT);

const COMMON_TEXT: &str = include_str!("../data/common-passwords.txt");

/// Why a new password is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Weakness {
    /// Fewer than [`MIN_CHARS`] characters.
    TooShort,
    /// More than [`MAX_CHARS`] characters or [`MAX_BYTES`] bytes.
    TooLong,
    /// A common password, or too few different characters.
    Common,
    /// Contains a word from the context: the username, the service name or the host.
    Context,
}

/// A password after NFC normalization.
#[derive(Clone, PartialEq, Eq)]
pub struct Normalized(String);

impl std::fmt::Debug for Normalized {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Normalized(..)")
    }
}

impl Normalized {
    /// Normalizes a submitted password to NFC. `None` if it is longer than [`MAX_BYTES`].
    #[must_use]
    pub fn new(raw: &str) -> Option<Self> {
        if raw.len() > MAX_BYTES {
            return None;
        }
        Some(Self(
            ComposingNormalizerBorrowed::new_nfc()
                .normalize(raw)
                .into_owned(),
        ))
    }

    const fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

/// Checks a new password against the rules. `context` holds words a password must not contain,
/// such as the username; words shorter than 4 characters are ignored.
///
/// # Errors
///
/// The first [`Weakness`] found.
pub fn check(password: &Normalized, context: &[&str]) -> Result<(), Weakness> {
    let chars = password.0.chars().count();
    if chars < MIN_CHARS {
        return Err(Weakness::TooShort);
    }
    if chars > MAX_CHARS {
        return Err(Weakness::TooLong);
    }
    let lower = password.0.to_ascii_lowercase();
    let mut distinct: Vec<char> = lower.chars().collect();
    distinct.sort_unstable();
    distinct.dedup();
    if distinct.len() < 5 || is_common(&lower) {
        return Err(Weakness::Common);
    }
    let in_context = context
        .iter()
        .map(|word| word.to_ascii_lowercase())
        .filter(|word| word.chars().count() >= 4)
        .any(|word| lower.contains(&word));
    if in_context {
        return Err(Weakness::Context);
    }
    Ok(())
}

fn is_common(lower: &str) -> bool {
    COMMON.binary_search(&lower).is_ok()
}

/// The number of lines in `text`, each ended by `\n`.
const fn line_count(text: &str) -> usize {
    let mut bytes = text.as_bytes();
    let mut count = 0;
    while let [byte, rest @ ..] = bytes {
        if *byte == b'\n' {
            count += 1;
        }
        bytes = rest;
    }
    count
}

/// The length of the first line of `bytes`, without its `\n`.
const fn line_len(mut bytes: &[u8]) -> usize {
    let mut len = 0;
    while let [byte, rest @ ..] = bytes {
        if *byte == b'\n' {
            break;
        }
        len += 1;
        bytes = rest;
    }
    len
}

/// Splits `text` into its `N` lines, each ended by `\n`, at compile time.
const fn lines<const N: usize>(mut text: &str) -> [&str; N] {
    let mut out = [""; N];
    let mut slots: &mut [&str] = &mut out;
    while let [slot, more @ ..] = slots {
        let (line, rest) = text.split_at(line_len(text.as_bytes()));
        *slot = line;
        text = rest.split_at(1).1;
        slots = more;
    }
    out
}

/// What a stored hash says about a submitted password.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// The password matches. `rehash` is true when the hash uses older parameters.
    Match {
        /// Store a new hash with the current parameters.
        rehash: bool,
    },
    /// The password does not match, or the stored hash cannot be read.
    Mismatch,
}

/// Hashes and verifies passwords with a server key.
pub struct Hasher {
    key: hmac::Key,
    iterations: NonZeroU32,
}

impl std::fmt::Debug for Hasher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Hasher")
            .field("iterations", &self.iterations)
            .finish_non_exhaustive()
    }
}

impl Hasher {
    /// A hasher with the server key and [`ITERATIONS`].
    #[must_use]
    pub fn new(key: &[u8]) -> Self {
        Self::with_iterations(key, ITERATIONS)
    }

    /// A hasher with a chosen iteration count, for tests.
    #[must_use]
    pub fn with_iterations(key: &[u8], iterations: u32) -> Self {
        Self {
            key: hmac::Key::new(hmac::HMAC_SHA256, key),
            iterations: NonZeroU32::new(iterations).unwrap_or(NonZeroU32::MIN),
        }
    }

    fn derive(&self, password: &Normalized, salt: &[u8], iterations: NonZeroU32) -> [u8; OUT_LEN] {
        let mut derived = [0_u8; OUT_LEN];
        pbkdf2::derive(
            PBKDF2_HMAC_SHA256,
            iterations,
            salt,
            password.as_bytes(),
            &mut derived,
        );
        let mut out = [0_u8; OUT_LEN];
        out.copy_from_slice(hmac::sign(&self.key, &derived).as_ref());
        out
    }

    /// A new hash: `$zid-pbkdf2-sha256-hmac$i=<iterations>$<salt>$<hash>`, base64 without
    /// padding.
    ///
    /// # Errors
    ///
    /// [`CryptoError`] if the RNG fails.
    pub fn hash(&self, password: &Normalized) -> Result<String, CryptoError> {
        let salt = random::<SALT_LEN>()?;
        let out = self.derive(password, &salt, self.iterations);
        Ok(format!(
            "${SCHEME}$i={}${}${}",
            self.iterations,
            STANDARD_NO_PAD.encode(salt),
            STANDARD_NO_PAD.encode(out)
        ))
    }

    /// Checks `password` against a stored hash.
    #[must_use]
    pub fn verify(&self, password: &Normalized, stored: &str) -> Verdict {
        let Some((iterations, salt, expected)) = parse(stored) else {
            return Verdict::Mismatch;
        };
        let out = self.derive(password, &salt, iterations);
        if ct_eq(&out, &expected) {
            Verdict::Match {
                rehash: iterations != self.iterations,
            }
        } else {
            Verdict::Mismatch
        }
    }

    /// Spends the time of one [`Hasher::verify`], for a username with no password, so the
    /// response time does not tell which usernames exist.
    pub fn verify_nothing(&self, password: &Normalized) {
        let _discarded = self.derive(password, &[0_u8; SALT_LEN], self.iterations);
    }
}

fn parse(stored: &str) -> Option<(NonZeroU32, Vec<u8>, Vec<u8>)> {
    let mut parts = stored.strip_prefix('$')?.split('$');
    if parts.next()? != SCHEME {
        return None;
    }
    let iterations: NonZeroU32 = parts.next()?.strip_prefix("i=")?.parse().ok()?;
    let salt = STANDARD_NO_PAD.decode(parts.next()?).ok()?;
    let hash = STANDARD_NO_PAD.decode(parts.next()?).ok()?;
    (parts.next().is_none() && hash.len() == OUT_LEN).then_some((iterations, salt, hash))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pw(s: &str) -> Normalized {
        Normalized::new(s).unwrap()
    }

    #[test]
    fn rules_follow_length_list_and_context() {
        assert_eq!(check(&pw("short one"), &[]), Err(Weakness::TooShort));
        assert_eq!(check(&pw(&"ab1".repeat(90)), &[]), Err(Weakness::TooLong));
        assert_eq!(
            check(&pw("aaaaaaaaaaaaaaaaaaaa"), &[]),
            Err(Weakness::Common)
        );
        assert_eq!(check(&pw("1234567890123456"), &[]), Err(Weakness::Common));
        assert_eq!(
            check(&pw("Zeabur rocks on my server"), &["zeabur"]),
            Err(Weakness::Context)
        );
        assert_eq!(
            check(&pw("alice keeps a tidy garden"), &["Alice"]),
            Err(Weakness::Context)
        );
        assert_eq!(check(&pw("correct horse battery"), &["al"]), Ok(()));
    }

    #[test]
    fn every_listed_password_is_long_and_sorted() {
        assert!(COMMON.windows(2).all(|w| w[0] < w[1]));
        assert!(COMMON.iter().all(|p| p.chars().count() >= MIN_CHARS));
    }

    #[test]
    fn length_counts_code_points_after_nfc() {
        // "é" as e + U+0301 composes to one code point.
        let decomposed = "e\u{301}".repeat(15);
        assert_eq!(pw(&decomposed), pw(&"\u{e9}".repeat(15)));
        assert!(Normalized::new(&"x".repeat(MAX_BYTES + 1)).is_none());
    }

    #[test]
    fn hashes_verify_and_report_old_parameters() {
        let hasher = Hasher::with_iterations(b"server key", 2);
        let stored = hasher.hash(&pw("correct horse battery")).unwrap();
        assert_eq!(
            hasher.verify(&pw("correct horse battery"), &stored),
            Verdict::Match { rehash: false }
        );
        assert_eq!(
            hasher.verify(&pw("correct horse batterY"), &stored),
            Verdict::Mismatch
        );
        let stronger = Hasher::with_iterations(b"server key", 3);
        assert_eq!(
            stronger.verify(&pw("correct horse battery"), &stored),
            Verdict::Match { rehash: true }
        );
        let other_key = Hasher::with_iterations(b"another key", 2);
        assert_eq!(
            other_key.verify(&pw("correct horse battery"), &stored),
            Verdict::Mismatch
        );
        assert_eq!(
            hasher.verify(&pw("x"), "$bcrypt$whatever"),
            Verdict::Mismatch
        );
    }

    #[test]
    fn same_password_gets_a_new_salt() {
        let hasher = Hasher::with_iterations(b"k", 1);
        assert_ne!(
            hasher.hash(&pw("correct horse battery")).unwrap(),
            hasher.hash(&pw("correct horse battery")).unwrap()
        );
    }
}
