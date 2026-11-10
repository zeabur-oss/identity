//! Small, audited wrappers over aws-lc-rs: randomness, hashing, constant-time comparison, and
//! sealing (authenticated encryption) of self-contained protocol state.
//!
//! aws-lc-rs is the only cryptographic library Zeabur Identity's own code calls; the crate-level
//! documentation explains why. Errors from it carry no detail, so [`CryptoError`] carries none
//! either.

use aws_lc_rs::aead::{AES_256_GCM_SIV, Aad, NONCE_LEN, Nonce, RandomizedNonceKey};
use aws_lc_rs::constant_time::verify_slices_are_equal;
use aws_lc_rs::digest::{SHA256, digest};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use thiserror::Error;

/// The cryptographic library failed. It reports no detail.
#[derive(Debug, Error, PartialEq, Eq)]
#[error("cryptographic operation failed")]
pub struct CryptoError;

/// Returns `N` bytes from the system CSPRNG.
///
/// # Errors
///
/// Returns [`CryptoError`] if the RNG fails.
pub fn random<const N: usize>() -> Result<[u8; N], CryptoError> {
    let mut bytes = [0_u8; N];
    aws_lc_rs::rand::fill(&mut bytes).map_err(|_unspecified| CryptoError)?;
    Ok(bytes)
}

/// SHA-256.
#[must_use]
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut out = [0_u8; 32];
    out.copy_from_slice(digest(&SHA256, data).as_ref());
    out
}

/// Lower-case hex.
#[must_use]
pub fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut out, byte| {
            // Writing to a String cannot fail.
            if write!(out, "{byte:02x}").is_err() {
                out.clear();
            }
            out
        })
}

/// Constant-time equality.
#[must_use]
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    verify_slices_are_equal(a, b).is_ok()
}

/// Seals and opens self-contained state with AES-256-GCM-SIV.
///
/// GCM-SIV is nonce-misuse resistant: an accidental repeat of a random 96-bit nonce does not
/// have the catastrophic consequences it has for AES-GCM. That covers the nonce-collision
/// concern that would otherwise call for XChaCha20-Poly1305, which aws-lc-rs does not expose.
///
/// The `purpose` is authenticated as associated data, so a value sealed for one purpose (say, an
/// authorization code) cannot be replayed as another (say, a PAR request URI).
pub struct Sealer {
    key: RandomizedNonceKey,
}

impl std::fmt::Debug for Sealer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Sealer")
    }
}

impl Sealer {
    /// A sealer with a fresh random key that exists only in this process.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError`] if key generation fails.
    pub fn ephemeral() -> Result<Self, CryptoError> {
        Self::from_key(&random::<32>()?)
    }

    /// A sealer with the given 256-bit key.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError`] if the key is rejected.
    pub fn from_key(key: &[u8; 32]) -> Result<Self, CryptoError> {
        Ok(Self {
            key: RandomizedNonceKey::new(&AES_256_GCM_SIV, key)
                .map_err(|_unspecified| CryptoError)?,
        })
    }

    /// Seals `plaintext` for `purpose` and returns `base64url(nonce || ciphertext || tag)`.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError`] if encryption fails.
    pub fn seal(&self, purpose: &str, plaintext: &[u8]) -> Result<String, CryptoError> {
        let mut buffer = plaintext.to_vec();
        let nonce = self
            .key
            .seal_in_place_append_tag(Aad::from(purpose.as_bytes()), &mut buffer)
            .map_err(|_unspecified| CryptoError)?;
        let mut out = nonce.as_ref().to_vec();
        out.extend_from_slice(&buffer);
        Ok(URL_SAFE_NO_PAD.encode(out))
    }

    /// Opens a value sealed for `purpose`. Returns `None` for anything not produced by
    /// [`Self::seal`] with this key and purpose.
    #[must_use]
    pub fn open(&self, purpose: &str, sealed: &str) -> Option<Vec<u8>> {
        // Sealed values are small; refuse to decode anything large.
        if sealed.len() > 16 * 1024 {
            return None;
        }
        let bytes = URL_SAFE_NO_PAD.decode(sealed).ok()?;
        let (nonce, ciphertext) = bytes.split_at_checked(NONCE_LEN)?;
        let nonce = Nonce::try_assume_unique_for_key(nonce).ok()?;
        let mut buffer = ciphertext.to_vec();
        let plaintext = self
            .key
            .open_in_place(nonce, Aad::from(purpose.as_bytes()), &mut buffer)
            .ok()?;
        Some(plaintext.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    #[test]
    fn constant_time_comparison() {
        assert!(ct_eq(b"same", b"same"));
        assert!(!ct_eq(b"same", b"diff"));
        assert!(!ct_eq(b"short", b"longer"));
    }

    #[test]
    fn seal_is_bound_to_key_and_purpose() {
        let sealer = Sealer::ephemeral().unwrap();
        let token = sealer.seal("code", b"payload").unwrap();
        assert_eq!(
            sealer.open("code", &token).as_deref(),
            Some(&b"payload"[..])
        );
        assert_eq!(sealer.open("par", &token), None, "other purpose");
        assert_eq!(
            Sealer::ephemeral().unwrap().open("code", &token),
            None,
            "other key"
        );
        assert_ne!(
            sealer.seal("code", b"payload").unwrap(),
            token,
            "randomized"
        );
    }

    proptest! {
        #[test]
        fn sealed_values_round_trip(payload in proptest::collection::vec(any::<u8>(), 0..512)) {
            let sealer = Sealer::from_key(&[7; 32]).unwrap();
            let sealed = sealer.seal("p", &payload).unwrap();
            prop_assert_eq!(sealer.open("p", &sealed), Some(payload));
        }

        #[test]
        fn tampering_is_detected(payload in proptest::collection::vec(any::<u8>(), 1..64), flip in 0_usize..1000) {
            let sealer = Sealer::from_key(&[7; 32]).unwrap();
            let mut bytes = URL_SAFE_NO_PAD.decode(sealer.seal("p", &payload).unwrap()).unwrap();
            let index = flip % bytes.len();
            bytes[index] ^= 0x01;
            prop_assert_eq!(sealer.open("p", &URL_SAFE_NO_PAD.encode(bytes)), None);
        }

        #[test]
        fn open_never_panics(input in "\\PC{0,200}") {
            let sealer = Sealer::from_key(&[7; 32]).unwrap();
            drop(sealer.open("p", &input));
        }
    }
}
