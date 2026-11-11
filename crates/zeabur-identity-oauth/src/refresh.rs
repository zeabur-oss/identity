//! Refresh tokens: `<grant name>.<256-bit secret>`. Only the secret's hash is stored.
//!
//! Each authorization creates one `Grant` (a refresh-token family) holding the hashes of the
//! current and previous secret. Every refresh rotates the secret with one compare-and-swap, and
//! the family is classified by [`zeabur_identity_store::classify`]:
//!
//! - the current secret rotates;
//! - the previous secret is a replay: someone used a rotated token, so the whole family is revoked
//!   (RFC 9700 §4.14.2, and §2.2.2 for public clients). The thief and the victim share a lineage,
//!   so the first of them to refresh makes the other's next refresh end it;
//! - anything else is `invalid_grant` without revoking, so a cluster reader who knows a grant name
//!   cannot end someone's session by guessing.
//!
//! A losing concurrent rotation is a replay too. There is no grace window: kubelogin serialises
//! refreshes of one token cache with a file lock ([kubelogin]), so legitimate use does not race
//! itself. Every refresh also checks that the presenting client owns the family (otherwise it is
//! revoked only with proof of the current or previous secret), that the user still exists and is
//! enabled, and that the scope only narrows ([RFC 6749 §6]).
//!
//! Revocation and wrong-client refresh compare the presented secret hash in constant time against
//! both retained hashes before deleting a family. The grant name is only a lookup key, not a
//! credential. An unknown secret cannot terminate a session, even when the requester knows its
//! grant name. The owning client can revoke with either retained secret; invalid revocation
//! tokens still receive HTTP 200 ([RFC 7009 §2.1 and §2.2]).
//!
//! [RFC 6749 §6]: https://www.rfc-editor.org/rfc/rfc6749#section-6
//! [RFC 7009 §2.1 and §2.2]: https://www.rfc-editor.org/rfc/rfc7009#section-2.1
//!
//! One small record per family follows Kanidm, and revoking the family on reuse with no grace
//! period follows Hydra's default ([Kanidm], [Hydra]). Pinniped and Rauthy delete the old token on
//! rotation, so a replay looks like an unknown token and the family survives; Dex rejects reuse
//! but keeps the family and stores refresh tokens in plain text ([Pinniped], [Rauthy], [Dex]).
//!
//! [kubelogin]: https://github.com/int128/kubelogin
//! [Kanidm]: https://github.com/kanidm/kanidm/tree/3331b8ed7f1541901ffe0c722f2a04c82897809c
//! [Hydra]: https://github.com/ory/hydra/tree/4174065ffb052799890f7480f5360a877a67ffc1
//! [Pinniped]: https://github.com/vmware/pinniped/tree/e635a39cf793b5b915220a846de91e089ab431c9
//! [Rauthy]: https://github.com/sebadob/rauthy/tree/abd24b6d189b473178c7797787d6cbddd65df3d3
//! [Dex]: https://github.com/dexidp/dex/tree/05a275057112ba93e17db21f600b756f000f1c21

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use zeabur_identity_api::token_hash;
use zeabur_identity_core::crypto::{CryptoError, ct_eq, random};
use zeabur_identity_store::Grant;

/// A parsed refresh token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefreshToken {
    /// The family (`Grant` object name).
    grant: String,
    /// The secret part, base64url: 256 random bits, beyond the 2^-160 guessing probability that
    /// RFC 6749 §10.10 recommends.
    secret: String,
}

impl RefreshToken {
    /// A new token for `grant`.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError`] if randomness fails.
    pub fn generate(grant: &str) -> Result<Self, CryptoError> {
        Ok(Self {
            grant: grant.to_owned(),
            secret: URL_SAFE_NO_PAD.encode(random::<32>()?),
        })
    }

    /// Parses a presented token. Anything malformed is `None`.
    #[must_use]
    pub fn parse(token: &str) -> Option<Self> {
        let (grant, secret) = token.split_once('.')?;
        let valid_grant = grant.len() == 66
            && grant.starts_with("g-")
            && grant
                .bytes()
                .skip(2)
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
        let valid_secret =
            secret.len() == 43 && URL_SAFE_NO_PAD.decode(secret).is_ok_and(|s| s.len() == 32);
        (valid_grant && valid_secret).then(|| Self {
            grant: grant.to_owned(),
            secret: secret.to_owned(),
        })
    }

    /// The family (`Grant` object name).
    #[must_use]
    pub fn grant(&self) -> &str {
        &self.grant
    }

    /// The stored form of the secret.
    #[must_use]
    pub fn hash(&self) -> String {
        token_hash(self.secret.as_bytes())
    }

    /// Proves possession of a current or previous family secret, independently of expiry.
    ///
    /// Both retained hashes are compared in constant time; a grant name alone cannot authorize
    /// deletion. Previous secrets remain proof for family revocation, not valid refresh tokens.
    #[must_use]
    pub fn proves_possession(&self, grant: &Grant) -> bool {
        let hash = self.hash();
        let current = ct_eq(hash.as_bytes(), grant.current_hash.as_bytes());
        let previous = grant
            .previous_hash
            .as_ref()
            .is_some_and(|previous| ct_eq(hash.as_bytes(), previous.as_bytes()));
        current | previous
    }

    /// The token as sent to the client.
    #[must_use]
    pub fn encode(&self) -> String {
        format!("{}.{}", self.grant, self.secret)
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;
    use crate::code::grant_name;

    #[test]
    fn round_trip() {
        let token = RefreshToken::generate(&grant_name("abc")).unwrap();
        let parsed = RefreshToken::parse(&token.encode()).unwrap();
        assert_eq!(parsed, token);
        assert_eq!(parsed.hash(), token.hash());
        assert_ne!(
            RefreshToken::generate(&grant_name("abc")).unwrap().hash(),
            token.hash()
        );
    }

    proptest! {
        #[test]
        fn parse_never_panics(input in "\\PC{0,200}") {
            drop(RefreshToken::parse(&input));
        }
    }
}
