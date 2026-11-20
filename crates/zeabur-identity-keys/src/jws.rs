//! JWS Compact Serialization (RFC 7515 §7.1) for tokens this issuer signs.

use serde::Serialize;

use super::base64url;
use super::signing::{KeyError, SigningKey};

#[derive(Serialize)]
struct Header<'a> {
    alg: &'static str,
    kid: &'a str,
    typ: &'a str,
}

/// Signs `claims` with `key` and returns the compact serialization.
///
/// The protected header carries `alg`, `kid` and `typ` (explicit typing, RFC 8725 §3.11), and
/// nothing else, in particular no `jku`, `jwk` or `x5u` (RFC 8725 §3.10).
///
/// # Errors
///
/// Returns [`KeyError::Serialize`] if `claims` cannot be serialized, or [`KeyError::Sign`] if
/// signing fails.
pub fn sign_compact<T: Serialize>(
    key: &SigningKey,
    typ: &str,
    claims: &T,
) -> Result<String, KeyError> {
    let header = Header {
        alg: key.alg().as_str(),
        kid: key.kid(),
        typ,
    };
    let header = serde_json::to_vec(&header).map_err(KeyError::Serialize)?;
    let payload = serde_json::to_vec(claims).map_err(KeyError::Serialize)?;
    let signing_input = format!("{}.{}", base64url(&header), base64url(&payload));
    let signature = key.sign(signing_input.as_bytes())?;
    Ok(format!("{signing_input}.{}", base64url(&signature)))
}

#[cfg(test)]
mod tests {
    use jsonwebtoken::jwk::Jwk as ExternalJwk;
    use jsonwebtoken::{DecodingKey, Validation, decode, decode_header};
    use serde::Deserialize;

    use super::*;
    use crate::Algorithm;

    #[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
    struct Claims {
        iss: String,
        aud: String,
        exp: u64,
    }

    /// An independent JOSE implementation must verify our tokens using only the published JWK.
    #[test]
    fn independent_library_verifies_with_published_jwk() {
        for alg in Algorithm::ALL {
            let key = SigningKey::generate(alg).unwrap();
            let claims = Claims {
                iss: "https://issuer.example".into(),
                aud: "kubernetes".into(),
                exp: 4_102_444_800,
            };
            let token = sign_compact(&key, "JWT", &claims).unwrap();

            let header = decode_header(&token).unwrap();
            assert_eq!(header.kid.as_deref(), Some(key.kid()));
            assert_eq!(header.typ.as_deref(), Some("JWT"));

            let published: ExternalJwk =
                serde_json::from_slice(&serde_json::to_vec(&key.jwk()).unwrap()).unwrap();
            let decoding = DecodingKey::from_jwk(&published).unwrap();
            let expected = match alg {
                Algorithm::Es256 => jsonwebtoken::Algorithm::ES256,
                Algorithm::Rs256 => jsonwebtoken::Algorithm::RS256,
            };
            let mut validation = Validation::new(expected);
            validation.set_audience(&["kubernetes"]);
            validation.set_issuer(&["https://issuer.example"]);
            let decoded = decode::<Claims>(&token, &decoding, &validation).unwrap();
            assert_eq!(decoded.claims, claims);
        }
    }
}
