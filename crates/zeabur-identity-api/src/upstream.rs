//! Values of upstream sign-in: the issuer, the subject, the account key they form, and the
//! provider ID.
//!
//! Each constructor checks the syntax and keeps the input bytes as they are. Nothing is
//! normalised, because [`ExternalId`] is the key of a stored `Credential`, and a changed byte
//! would make a linked account unknown. Deserializing runs the same checks.
//!
//! # References
//!
//! - [OIDC Core] N. Sakimura, J. Bradley, M. Jones, B. de Medeiros, and C. Mortimore, "OpenID
//!   Connect Core 1.0 incorporating errata set 2," OpenID Foundation, Dec. 2023, §2 (`iss`, `sub`).
//!
//! [OIDC Core]: https://openid.net/specs/openid-connect-core-1_0.html#IDToken

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Longest [`Issuer`], in bytes. The `Credential` schema allows the same length.
pub const MAX_ISSUER: usize = 256;
/// Longest [`Subject`], in bytes: OIDC Core §2 limits `sub` to 255 ASCII characters.
pub const MAX_SUBJECT: usize = 255;
/// Longest [`ProviderId`], in bytes.
pub const MAX_PROVIDER_ID: usize = 63;

/// A value that a constructor or deserializer of this module refused. The message does not
/// contain the value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("invalid {what}: {reason}")]
pub struct InvalidValue {
    what: &'static str,
    reason: &'static str,
}

const fn invalid(what: &'static str, reason: &'static str) -> InvalidValue {
    InvalidValue { what, reason }
}

/// Visible ASCII: no space, no control character, nothing outside ASCII.
fn is_visible_ascii(value: &str) -> bool {
    value.bytes().all(|byte| byte.is_ascii_graphic())
}

/// The issuer identifier of an upstream provider, compared byte for byte.
///
/// Syntax (OIDC Core §2, `iss`): `https://`, a host that may have a port, an optional path, no
/// query and no fragment. At most [`MAX_ISSUER`] bytes of visible ASCII. No user information.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Issuer(String);

impl Issuer {
    /// Checks `value` and keeps it as it is.
    ///
    /// # Errors
    ///
    /// [`InvalidValue`] if `value` is not an issuer as described on [`Issuer`].
    pub fn new(value: impl Into<String>) -> Result<Self, InvalidValue> {
        const WHAT: &str = "issuer";
        let value = value.into();
        if value.is_empty() || value.len() > MAX_ISSUER {
            return Err(invalid(WHAT, "length"));
        }
        if !is_visible_ascii(&value) {
            return Err(invalid(WHAT, "not visible ASCII"));
        }
        let Some(rest) = value.strip_prefix("https://") else {
            return Err(invalid(WHAT, "not https"));
        };
        if rest.contains(['?', '#']) {
            return Err(invalid(WHAT, "query or fragment"));
        }
        let authority = rest.split('/').next().unwrap_or_default();
        if authority.is_empty() || authority.starts_with(':') {
            return Err(invalid(WHAT, "no host"));
        }
        if authority.contains('@') {
            return Err(invalid(WHAT, "user information"));
        }
        Ok(Self(value))
    }

    /// The issuer as given.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for Issuer {
    type Error = InvalidValue;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<Issuer> for String {
    fn from(value: Issuer) -> Self {
        value.0
    }
}

/// The stable identifier of an account at its issuer (`sub`, or GitHub's numeric user ID).
///
/// Opaque: not a URL and not always a number. Case matters. Syntax: 1 to [`MAX_SUBJECT`] bytes of
/// visible ASCII. The syntax cannot show that a provider sends a stable ID and not an email
/// address; that is a property of the provider.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Subject(String);

impl Subject {
    /// Checks `value` and keeps it as it is.
    ///
    /// # Errors
    ///
    /// [`InvalidValue`] if `value` is empty, longer than [`MAX_SUBJECT`] bytes, or has a byte
    /// that is not visible ASCII.
    pub fn new(value: impl Into<String>) -> Result<Self, InvalidValue> {
        const WHAT: &str = "subject";
        let value = value.into();
        if value.is_empty() || value.len() > MAX_SUBJECT {
            return Err(invalid(WHAT, "length"));
        }
        if !is_visible_ascii(&value) {
            return Err(invalid(WHAT, "not visible ASCII"));
        }
        Ok(Self(value))
    }

    /// The subject as given.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for Subject {
    type Error = InvalidValue;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<Subject> for String {
    fn from(value: Subject) -> Self {
        value.0
    }
}

/// A linked account at an upstream provider.
///
/// The issuer and the subject together identify the account. The two fields have different
/// types, so they cannot change places:
///
/// ```
/// use zeabur_identity_api::upstream::{ExternalId, Issuer, Subject};
///
/// let issuer = Issuer::new("https://github.com")?;
/// let subject = Subject::new("583231")?;
/// let id = ExternalId { issuer, subject };
/// # Ok::<(), zeabur_identity_api::upstream::InvalidValue>(())
/// ```
///
/// ```compile_fail,E0308
/// use zeabur_identity_api::upstream::{ExternalId, Issuer, Subject};
///
/// let issuer = Issuer::new("https://github.com")?;
/// let subject = Subject::new("583231")?;
/// let id = ExternalId { issuer: subject, subject: issuer };
/// # Ok::<(), zeabur_identity_api::upstream::InvalidValue>(())
/// ```
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ExternalId {
    /// Upstream issuer.
    #[schemars(with = "String", length(min = 1, max = 256))]
    pub issuer: Issuer,
    /// Upstream subject: the stable account ID, never an email address.
    #[schemars(with = "String", length(min = 1, max = 256))]
    pub subject: Subject,
}

/// The ID of an upstream provider: its path segment in `/upstream/<id>/callback`.
///
/// Syntax: 1 to [`MAX_PROVIDER_ID`] bytes of `a-z`, `0-9` and `-`, with a letter or digit first
/// and last.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ProviderId(String);

impl ProviderId {
    /// Checks `value` and keeps it as it is.
    ///
    /// # Errors
    ///
    /// [`InvalidValue`] if `value` is not a provider ID as described on [`ProviderId`].
    pub fn new(value: impl Into<String>) -> Result<Self, InvalidValue> {
        const WHAT: &str = "provider ID";
        let value = value.into();
        if value.is_empty() || value.len() > MAX_PROVIDER_ID {
            return Err(invalid(WHAT, "length"));
        }
        let allowed = |byte: u8| byte.is_ascii_lowercase() || byte.is_ascii_digit();
        if !value.bytes().all(|byte| allowed(byte) || byte == b'-')
            || value.starts_with('-')
            || value.ends_with('-')
        {
            return Err(invalid(WHAT, "characters"));
        }
        Ok(Self(value))
    }

    /// The ID as given.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for ProviderId {
    type Error = InvalidValue;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<ProviderId> for String {
    fn from(value: ProviderId) -> Self {
        value.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issuers() {
        let accepted = [
            "https://github.com",
            "https://accounts.google.com",
            "https://login.example.com:8443/realms/zeabur",
            "https://login.example.com/",
            "https://Login.Example.com",
        ];
        for value in accepted {
            assert_eq!(Issuer::new(value).unwrap().as_str(), value);
        }
        let longest = format!("https://{}", "a".repeat(MAX_ISSUER - 8));
        assert!(Issuer::new(longest.clone()).is_ok());
        let refused = [
            String::new(),
            format!("{longest}a"),
            "http://github.com".to_owned(),
            "accounts.google.com".to_owned(),
            "https://".to_owned(),
            "https:///path".to_owned(),
            "https://:443".to_owned(),
            "https://user@github.com".to_owned(),
            "https://github.com?x=1".to_owned(),
            "https://github.com#x".to_owned(),
            "https://github.com/ a".to_owned(),
            " https://github.com".to_owned(),
            "https://github.com\n".to_owned(),
            "https://gíthub.com".to_owned(),
            "583231".to_owned(),
        ];
        for value in refused {
            assert!(Issuer::new(value.clone()).is_err(), "{value:?}");
        }
    }

    #[test]
    fn subjects() {
        let longest = "9".repeat(MAX_SUBJECT);
        let accepted = [
            "583231",
            "110169484474386276334",
            "f:1a2b3c4d-0000-4000-8000-000000000000:alice",
            "auth0|5f7c8ec7c33c6c004bbafe82",
            "AbC",
            "alice@example.com",
            longest.as_str(),
        ];
        for value in accepted {
            assert_eq!(Subject::new(value).unwrap().as_str(), value);
        }
        let refused = [
            String::new(),
            format!("{longest}9"),
            "a b".to_owned(),
            "a\tb".to_owned(),
            "abc\0".to_owned(),
            "ü".to_owned(),
        ];
        for value in refused {
            assert!(Subject::new(value.clone()).is_err(), "{value:?}");
        }
    }

    #[test]
    fn provider_ids() {
        let longest = "a".repeat(MAX_PROVIDER_ID);
        for value in ["github", "google", "keycloak-2", "0", longest.as_str()] {
            assert_eq!(ProviderId::new(value).unwrap().as_str(), value);
        }
        let refused = [
            String::new(),
            format!("{longest}a"),
            "GitHub".to_owned(),
            "-github".to_owned(),
            "github-".to_owned(),
            "git_hub".to_owned(),
            "git.hub".to_owned(),
            "git/hub".to_owned(),
        ];
        for value in refused {
            assert!(ProviderId::new(value.clone()).is_err(), "{value:?}");
        }
    }

    #[test]
    fn deserializing_checks_the_same_rules() {
        let id: ExternalId = serde_json::from_str(
            r#"{"issuer":"https://accounts.google.com","subject":"110169484474386276334"}"#,
        )
        .unwrap();
        assert_eq!(id.issuer.as_str(), "https://accounts.google.com");
        assert_eq!(id.subject.as_str(), "110169484474386276334");

        let refused = [
            r#"{"issuer":"accounts.google.com","subject":"1"}"#,
            r#"{"issuer":"https://github.com","subject":""}"#,
            r#"{"issuer":"https://github.com","subject":"a b"}"#,
        ];
        for json in refused {
            assert!(serde_json::from_str::<ExternalId>(json).is_err(), "{json}");
        }
        assert!(serde_json::from_str::<ProviderId>(r#""GitHub""#).is_err());
        assert_eq!(
            serde_json::from_str::<ProviderId>(r#""github""#).unwrap(),
            ProviderId::new("github").unwrap()
        );
    }
}
