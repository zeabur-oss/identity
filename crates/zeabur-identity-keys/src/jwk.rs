//! JSON Web Keys ([RFC 7517]) for publication, and their [RFC 7638] thumbprints.
//!
//! The `kid` of every key is its RFC 7638 SHA-256 thumbprint. It is deterministic, so the same
//! key always has the same ID and a `kid` can never point at the wrong key; it is unique per key,
//! as RFC 7517 §4.5 asks ("SHOULD use distinct "kid" values"); and it reveals nothing about when
//! the key was created. A fixed `kid` shared by successive keys would let a verifier pair a cached
//! old key with a new signature.
//!
//! [RFC 7517]: https://www.rfc-editor.org/rfc/rfc7517
//! [RFC 7638]: https://www.rfc-editor.org/rfc/rfc7638

use aws_lc_rs::digest::{SHA256, digest};
use serde::Serialize;

use super::{Algorithm, base64url};

/// The public half of a signing key.
#[derive(Clone, PartialEq, Eq)]
pub enum PublicKey {
    /// A P-256 point (RFC 7518 §6.2.1), affine coordinates as 32-byte big-endian integers.
    Ec {
        /// The x coordinate.
        x: [u8; 32],
        /// The y coordinate.
        y: [u8; 32],
    },
    /// An RSA public key (RFC 7518 §6.3.1), big-endian without leading zeros.
    Rsa {
        /// The modulus.
        n: Vec<u8>,
        /// The public exponent.
        e: Vec<u8>,
    },
}

impl std::fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.thumbprint_input())
    }
}

impl PublicKey {
    /// The RFC 7638 §3.2 JSON object: the required members in lexicographic order, without
    /// whitespace. base64url output never needs JSON escaping, so plain formatting is exact.
    fn thumbprint_input(&self) -> String {
        match self {
            Self::Ec { x, y } => format!(
                r#"{{"crv":"P-256","kty":"EC","x":"{}","y":"{}"}}"#,
                base64url(x),
                base64url(y)
            ),
            Self::Rsa { n, e } => {
                format!(
                    r#"{{"e":"{}","kty":"RSA","n":"{}"}}"#,
                    base64url(e),
                    base64url(n)
                )
            }
        }
    }

    /// The RFC 7638 JWK SHA-256 thumbprint, base64url-encoded. Used as the `kid`.
    #[must_use]
    pub fn thumbprint(&self) -> String {
        base64url(digest(&SHA256, self.thumbprint_input().as_bytes()).as_ref())
    }

    /// The JWK to publish for this key.
    #[must_use]
    pub fn to_jwk(&self, alg: Algorithm) -> Jwk {
        let (kty, params) = match self {
            Self::Ec { x, y } => (
                "EC",
                JwkParams::Ec {
                    crv: "P-256",
                    x: base64url(x),
                    y: base64url(y),
                },
            ),
            Self::Rsa { n, e } => (
                "RSA",
                JwkParams::Rsa {
                    n: base64url(n),
                    e: base64url(e),
                },
            ),
        };
        Jwk {
            kty,
            usage: "sig",
            alg,
            kid: self.thumbprint(),
            params,
        }
    }
}

/// A public JWK as published in the JWK set.
///
/// It carries `use` and `alg` but not `key_ops` (RFC 7517 §4.3: they SHOULD NOT be used together),
/// and `alg` pins the key to one algorithm (RFC 8725 §3.1).
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Jwk {
    /// Key type.
    pub kty: &'static str,
    /// Intended use: always `sig`.
    #[serde(rename = "use")]
    pub usage: &'static str,
    /// The only algorithm this key is used with.
    pub alg: Algorithm,
    /// Key ID: the RFC 7638 thumbprint.
    pub kid: String,
    /// Type-specific members.
    #[serde(flatten)]
    pub params: JwkParams,
}

/// The key-type-specific JWK members.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum JwkParams {
    /// RFC 7518 §6.2.1.
    Ec {
        /// Curve.
        crv: &'static str,
        /// x coordinate.
        x: String,
        /// y coordinate.
        y: String,
    },
    /// RFC 7518 §6.3.1.
    Rsa {
        /// Modulus.
        n: String,
        /// Exponent.
        e: String,
    },
}

/// A JWK set (RFC 7517 §5).
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct JwkSet {
    /// The keys.
    pub keys: Vec<Jwk>,
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    use super::*;

    /// The members an EC public JWK may carry.
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct PublicJwk {
        kty: String,
        #[serde(rename = "use")]
        usage: String,
        alg: String,
        kid: String,
        crv: String,
        x: String,
        y: String,
    }

    /// RFC 7638 §3.1.
    #[test]
    fn rfc7638_example_thumbprint() {
        let n = "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw";
        let key = PublicKey::Rsa {
            n: URL_SAFE_NO_PAD.decode(n).unwrap(),
            e: URL_SAFE_NO_PAD.decode("AQAB").unwrap(),
        };
        assert_eq!(
            key.thumbprint(),
            "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
        );
    }

    /// RFC 7638 has no EC example; compare with an independent implementation.
    #[test]
    fn ec_thumbprint_matches_an_independent_implementation() {
        let key = PublicKey::Ec {
            x: [1; 32],
            y: [2; 32],
        };
        let jwk: jsonwebtoken::jwk::Jwk =
            serde_json::from_slice(&serde_json::to_vec(&key.to_jwk(Algorithm::Es256)).unwrap())
                .unwrap();
        assert_eq!(
            key.thumbprint(),
            jwk.thumbprint(jsonwebtoken::jwk::ThumbprintHash::SHA256)
                .unwrap()
        );
    }

    #[test]
    fn jwk_serialisation() {
        let jwk = PublicKey::Ec {
            x: [1; 32],
            y: [2; 32],
        }
        .to_jwk(Algorithm::Es256);
        // A private member (`d`) or `key_ops` in the output fails the parse.
        let value: PublicJwk = serde_json::from_slice(&serde_json::to_vec(&jwk).unwrap()).unwrap();
        assert_eq!(value.kty, "EC");
        assert_eq!(value.usage, "sig");
        assert_eq!(value.alg, "ES256");
        assert_eq!(value.crv, "P-256");
        assert_eq!(value.kid, jwk.kid);
        assert_eq!(value.x, base64url(&[1; 32]));
        assert_eq!(value.y, base64url(&[2; 32]));
    }
}
