//! Verifying JWS Compact Serialization (RFC 7515 §5.2): Zeabur Identity's own access tokens at the
//! UserInfo endpoint, and ID tokens from upstream OpenID providers.
//!
//! Only RS256 and ES256 are accepted, each key is used with its own algorithm only, and a token
//! that names a critical header extension is refused because none is understood
//! (RFC 7515 §4.1.11; RFC 8725 §3.1). The caller validates the claims.
//!
//! This is not `jsonwebtoken`: version 11 accepts any `crit` header and binds no key to an
//! algorithm. The tests use it as an independent check.

use aws_lc_rs::signature::{
    ECDSA_P256_SHA256_FIXED, RSA_PKCS1_2048_8192_SHA256, RsaPublicKeyComponents, UnparsedPublicKey,
};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Deserialize;
use thiserror::Error;

use super::Algorithm;
use super::jwk::PublicKey;

/// A key a token may be verified with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationKey {
    /// Key ID, if the key set gives one.
    pub kid: Option<String>,
    /// The only algorithm the key is used with.
    pub alg: Algorithm,
    /// The public key.
    pub key: PublicKey,
}

/// The JOSE header members verification looks at.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct Header {
    /// Algorithm.
    pub alg: String,
    /// Key ID.
    #[serde(default)]
    pub kid: Option<String>,
    /// Media type of the token (RFC 8725 §3.11).
    #[serde(default)]
    pub typ: Option<String>,
    /// Critical extension names (RFC 7515 §4.1.11); verification fails if present.
    #[serde(default)]
    pub crit: Option<Vec<String>>,
}

/// Why a token did not verify.
#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
pub enum VerifyError {
    /// Not three base64url parts with a JSON header.
    #[error("malformed token")]
    Malformed,
    /// The algorithm is not allowed, or the header has critical extensions.
    #[error("algorithm or header not accepted")]
    Header,
    /// No key matches the header.
    #[error("unknown signing key")]
    UnknownKey,
    /// The signature is wrong.
    #[error("bad signature")]
    Signature,
}

fn decode(part: &str) -> Result<Vec<u8>, VerifyError> {
    URL_SAFE_NO_PAD
        .decode(part)
        .map_err(|_base64| VerifyError::Malformed)
}

/// Verifies `token` with one of `keys` and returns its header and payload.
///
/// # Errors
///
/// Returns [`VerifyError`] unless the token is a well-formed compact JWS, signed with an algorithm
/// in `allowed` by a key in `keys` that is bound to that algorithm.
pub fn verify_compact(
    token: &str,
    keys: &[VerificationKey],
    allowed: &[Algorithm],
) -> Result<(Header, Vec<u8>), VerifyError> {
    let mut parts = token.split('.');
    let (Some(header_b64), Some(payload_b64), Some(signature_b64), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(VerifyError::Malformed);
    };
    let header: Header =
        serde_json::from_slice(&decode(header_b64)?).map_err(|_json| VerifyError::Malformed)?;
    let alg = allowed
        .iter()
        .copied()
        .find(|alg| alg.as_str() == header.alg)
        .ok_or(VerifyError::Header)?;
    if header.crit.is_some() {
        return Err(VerifyError::Header);
    }
    let mut candidates = keys
        .iter()
        .filter(|key| key.alg == alg)
        .filter(|key| header.kid.is_none() || key.kid == header.kid);
    // Without a `kid`, more than one candidate is ambiguous.
    let ((Some(key), None, _) | (Some(key), Some(_), Some(_))) =
        (candidates.next(), candidates.next(), &header.kid)
    else {
        return Err(VerifyError::UnknownKey);
    };
    let signature = decode(signature_b64)?;
    let message = format!("{header_b64}.{payload_b64}");
    let verified = match &key.key {
        PublicKey::Ec { x, y } if alg == Algorithm::Es256 => {
            let mut point = Vec::with_capacity(65);
            point.push(0x04);
            point.extend_from_slice(x);
            point.extend_from_slice(y);
            UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, point)
                .verify(message.as_bytes(), &signature)
                .is_ok()
        }
        PublicKey::Rsa { n, e } if alg == Algorithm::Rs256 => RsaPublicKeyComponents { n, e }
            .verify(&RSA_PKCS1_2048_8192_SHA256, message.as_bytes(), &signature)
            .is_ok(),
        PublicKey::Ec { .. } | PublicKey::Rsa { .. } => false,
    };
    if !verified {
        return Err(VerifyError::Signature);
    }
    Ok((header, decode(payload_b64)?))
}

#[derive(Deserialize)]
struct RawJwk {
    kty: String,
    #[serde(default)]
    kid: Option<String>,
    #[serde(default)]
    alg: Option<String>,
    #[serde(default, rename = "use")]
    usage: Option<String>,
    #[serde(default)]
    crv: Option<String>,
    #[serde(default)]
    x: Option<String>,
    #[serde(default)]
    y: Option<String>,
    #[serde(default)]
    n: Option<String>,
    #[serde(default)]
    e: Option<String>,
}

#[derive(Deserialize)]
struct RawJwkSet {
    keys: Vec<RawJwk>,
}

fn convert(raw: RawJwk) -> Option<VerificationKey> {
    if raw.usage.as_deref().is_some_and(|u| u != "sig") {
        return None;
    }
    let bytes = |value: Option<String>| URL_SAFE_NO_PAD.decode(value?).ok();
    let (alg, key) = match raw.kty.as_str() {
        "RSA" => (
            Algorithm::Rs256,
            PublicKey::Rsa {
                n: bytes(raw.n)?,
                e: bytes(raw.e)?,
            },
        ),
        "EC" if raw.crv.as_deref() == Some("P-256") => (
            Algorithm::Es256,
            PublicKey::Ec {
                x: bytes(raw.x)?.try_into().ok()?,
                y: bytes(raw.y)?.try_into().ok()?,
            },
        ),
        _ => return None,
    };
    // A key that names another algorithm is not used with this one.
    if raw.alg.as_deref().is_some_and(|a| a != alg.as_str()) {
        return None;
    }
    Some(VerificationKey {
        kid: raw.kid,
        alg,
        key,
    })
}

/// Parses a JWK set (RFC 7517 §5), keeping the RSA and P-256 signing keys and skipping others.
///
/// # Errors
///
/// Returns [`VerifyError::Malformed`] if the document is not a JWK set.
pub fn parse_jwk_set(json: &[u8]) -> Result<Vec<VerificationKey>, VerifyError> {
    let set: RawJwkSet = serde_json::from_slice(json).map_err(|_json| VerifyError::Malformed)?;
    Ok(set.keys.into_iter().filter_map(convert).collect())
}

#[cfg(test)]
mod tests {
    use serde::{Deserialize, Serialize};

    use super::*;
    use crate::jws::sign_compact;
    use crate::signing::SigningKey;

    /// The payload the tests sign.
    #[derive(Serialize, Deserialize)]
    struct Subject<'a> {
        sub: &'a str,
    }

    /// A JWK set entry: one of ours, or a key a verifier must skip.
    #[derive(Serialize)]
    #[serde(untagged)]
    enum Entry<'a> {
        Ours(&'a crate::jwk::Jwk),
        Foreign(ForeignJwk),
    }

    #[derive(Serialize)]
    struct ForeignJwk {
        kty: &'static str,
        #[serde(rename = "use", skip_serializing_if = "Option::is_none")]
        usage: Option<&'static str>,
        #[serde(skip_serializing_if = "Option::is_none")]
        crv: Option<&'static str>,
        #[serde(skip_serializing_if = "Option::is_none")]
        x: Option<&'static str>,
        #[serde(skip_serializing_if = "Option::is_none")]
        y: Option<&'static str>,
        #[serde(skip_serializing_if = "Option::is_none")]
        n: Option<&'static str>,
        #[serde(skip_serializing_if = "Option::is_none")]
        e: Option<&'static str>,
    }

    #[derive(Serialize)]
    struct Set<'a> {
        keys: Vec<Entry<'a>>,
    }

    fn key(alg: Algorithm) -> (SigningKey, VerificationKey) {
        let signing = SigningKey::generate(alg).unwrap();
        let verification = VerificationKey {
            kid: Some(signing.kid().to_owned()),
            alg,
            key: signing.public().clone(),
        };
        (signing, verification)
    }

    #[test]
    fn verifies_both_algorithms_and_returns_the_payload() {
        for alg in Algorithm::ALL {
            let (signing, verification) = key(alg);
            let token = sign_compact(&signing, "at+jwt", &Subject { sub: "a" }).unwrap();
            let (header, payload) =
                verify_compact(&token, &[verification], &Algorithm::ALL).unwrap();
            assert_eq!(header.typ.as_deref(), Some("at+jwt"));
            let claims: Subject<'_> = serde_json::from_slice(&payload).unwrap();
            assert_eq!(claims.sub, "a");
        }
    }

    #[test]
    fn rejects_tampering_wrong_keys_and_algorithms() {
        let (signing, verification) = key(Algorithm::Es256);
        let (_, other) = key(Algorithm::Es256);
        let token = sign_compact(&signing, "JWT", &Subject { sub: "a" }).unwrap();

        let mut parts: Vec<&str> = token.split('.').collect();
        let forged = URL_SAFE_NO_PAD.encode(br#"{"sub":"b"}"#);
        parts[1] = &forged;
        assert_eq!(
            verify_compact(
                &parts.join("."),
                std::slice::from_ref(&verification),
                &Algorithm::ALL
            ),
            Err(VerifyError::Signature)
        );
        assert_eq!(
            verify_compact(&token, &[other], &Algorithm::ALL),
            Err(VerifyError::UnknownKey)
        );
        assert_eq!(
            verify_compact(
                &token,
                std::slice::from_ref(&verification),
                &[Algorithm::Rs256]
            ),
            Err(VerifyError::Header)
        );

        // `alg: none` and critical extensions are refused.
        let body = URL_SAFE_NO_PAD.encode(br#"{"sub":"a"}"#);
        for header in [r#"{"alg":"none"}"#, r#"{"alg":"ES256","crit":["exp"]}"#] {
            let token = format!("{}.{body}.", URL_SAFE_NO_PAD.encode(header));
            assert_eq!(
                verify_compact(&token, std::slice::from_ref(&verification), &Algorithm::ALL),
                Err(VerifyError::Header)
            );
        }
        for malformed in ["", "a.b", "a.b.c.d", "!!.!!.!!"] {
            assert!(
                verify_compact(
                    malformed,
                    std::slice::from_ref(&verification),
                    &Algorithm::ALL
                )
                .is_err()
            );
        }
    }

    #[test]
    fn an_rsa_key_never_verifies_an_es256_header() {
        let (rsa, rsa_verification) = key(Algorithm::Rs256);
        let token = sign_compact(
            &rsa,
            "JWT",
            &std::collections::BTreeMap::<String, String>::new(),
        )
        .unwrap();
        // Same key material advertised for ES256: the algorithm binding rejects it.
        let mismatched = VerificationKey {
            alg: Algorithm::Es256,
            ..rsa_verification
        };
        assert!(verify_compact(&token, &[mismatched], &Algorithm::ALL).is_err());
    }

    #[test]
    fn parses_a_jwk_set_and_skips_what_it_cannot_use() {
        let (es, es_v) = key(Algorithm::Es256);
        let (rs, rs_v) = key(Algorithm::Rs256);
        let (es_jwk, rs_jwk) = (es.jwk(), rs.jwk());
        let set = Set {
            keys: vec![
                Entry::Ours(&es_jwk),
                Entry::Ours(&rs_jwk),
                Entry::Foreign(ForeignJwk {
                    kty: "OKP",
                    usage: None,
                    crv: Some("Ed25519"),
                    x: Some("AA"),
                    y: None,
                    n: None,
                    e: None,
                }),
                Entry::Foreign(ForeignJwk {
                    kty: "RSA",
                    usage: Some("enc"),
                    crv: None,
                    x: None,
                    y: None,
                    n: Some("AQAB"),
                    e: Some("AQAB"),
                }),
                Entry::Foreign(ForeignJwk {
                    kty: "EC",
                    usage: None,
                    crv: Some("P-384"),
                    x: Some("AA"),
                    y: Some("AA"),
                    n: None,
                    e: None,
                }),
            ],
        };
        let keys = parse_jwk_set(&serde_json::to_vec(&set).unwrap()).unwrap();
        assert_eq!(keys, vec![es_v, rs_v]);
        assert!(parse_jwk_set(b"[]").is_err());
    }
}
