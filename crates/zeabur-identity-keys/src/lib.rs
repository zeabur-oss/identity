#![doc = include_str!("../README.md")]

pub mod jwk;
pub mod jws;
pub mod manager;
pub mod rotation;
pub mod signing;
pub mod store;
pub mod verify;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
pub use zeabur_identity_api::client::Algorithm;

/// Encodes bytes as unpadded base64url (RFC 7515 §2).
#[must_use]
pub fn base64url(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}
