//! Validated runtime configuration.

use std::fmt;
use std::time::Duration;

use http::Uri;
use http::uri::InvalidUri;
use thiserror::Error;

/// A configuration value that failed validation.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ConfigError {
    /// The value is not a valid URL.
    #[error("{field}: not a valid URL: {reason}")]
    InvalidUrl {
        /// The configuration field.
        field: &'static str,
        /// Why parsing failed.
        reason: String,
    },
    /// The URL breaks a rule for issuer-style base URLs.
    #[error("{field}: {reason}")]
    BadBaseUrl {
        /// The configuration field.
        field: &'static str,
        /// The rule that was broken.
        reason: BaseUrlRule,
    },
    /// The value is not a valid duration.
    #[error(
        "invalid duration {0:?}: use a whole number with a unit, for example 300s, 5m, 24h, or 7d"
    )]
    InvalidDuration(String),
    /// Options that only work together were given alone.
    #[error("{0}")]
    Incomplete(&'static str),
    /// The key rotation timings are inconsistent.
    #[error("key rotation: {0}")]
    BadRotationPolicy(&'static str),
}

/// A rule for issuer-style base URLs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BaseUrlRule {
    /// No fragment.
    Fragment,
    /// The `https` scheme.
    Scheme,
    /// No credentials.
    Credentials,
    /// No query.
    Query,
    /// No path.
    Path,
    /// No trailing slash.
    TrailingSlash,
    /// A host.
    Host,
    /// Lower-case scheme and host, no default port.
    Normalised,
}

impl fmt::Display for BaseUrlRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Fragment => "must not contain a fragment",
            Self::Scheme => "must use the https scheme",
            Self::Credentials => "must not contain credentials",
            Self::Query => "must not contain a query",
            Self::Path => "must not contain a path",
            Self::TrailingSlash => "must not end with a slash",
            Self::Host => "must have a host",
            Self::Normalised => {
                "must be in normalised form (lower-case scheme and host, no default port)"
            }
        })
    }
}

/// An `https` URL with a host and no path, query, fragment or credentials, written without a
/// trailing slash.
///
/// The issuer identifier has this form so that OpenID Connect Discovery (which appends
/// `/.well-known/openid-configuration` to the issuer, [OIDC Discovery] §4) and RFC 8414 (which
/// inserts the well-known segment between host and path, [RFC 8414] §3) yield the same location.
/// With a path the two locations differ, which is easy to get wrong.
///
/// Only the normal form is accepted because verifiers compare the issuer as a string:
/// OIDC Discovery §4.3 requires the `issuer` in the metadata to be identical to the URL it was
/// fetched under and to `iss` in ID tokens, and kube-apiserver requires the fetched `issuer` to
/// match its configured `issuer.url` ([KEP-3331]).
///
/// [OIDC Discovery]: https://openid.net/specs/openid-connect-discovery-1_0.html
/// [RFC 8414]: https://www.rfc-editor.org/rfc/rfc8414
/// [KEP-3331]: https://github.com/kubernetes/enhancements/tree/master/keps/sig-auth/3331-structured-authentication-configuration
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BaseUrl(String);

impl BaseUrl {
    /// Validates `input` for the configuration field `field`.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] if `input` is not an absolute `https` URL with a host, or if it
    /// has a path, query, fragment, credentials or trailing slash.
    pub fn parse(field: &'static str, input: &str) -> Result<Self, ConfigError> {
        let bad = |reason| ConfigError::BadBaseUrl { field, reason };
        if input.contains('#') {
            return Err(bad(BaseUrlRule::Fragment));
        }
        let uri: Uri = input
            .parse()
            .map_err(|e: InvalidUri| ConfigError::InvalidUrl {
                field,
                reason: e.to_string(),
            })?;
        let (Some(scheme), Some(authority)) = (uri.scheme_str(), uri.authority()) else {
            return Err(ConfigError::InvalidUrl {
                field,
                reason: "not an absolute URL".to_owned(),
            });
        };
        if scheme != "https" {
            return Err(bad(BaseUrlRule::Scheme));
        }
        if authority.as_str().contains('@') {
            return Err(bad(BaseUrlRule::Credentials));
        }
        if uri.query().is_some() {
            return Err(bad(BaseUrlRule::Query));
        }
        if !matches!(uri.path(), "" | "/") {
            return Err(bad(BaseUrlRule::Path));
        }
        if input.ends_with('/') {
            return Err(bad(BaseUrlRule::TrailingSlash));
        }
        let host = authority.host();
        if host.is_empty() {
            return Err(bad(BaseUrlRule::Host));
        }
        // The identifier must be exactly what verifiers compare against, so only the normal
        // form is accepted: lower-case ASCII scheme and host (internationalised names in their
        // A-label form), and no explicit default port.
        if !input.starts_with("https://")
            || !host.is_ascii()
            || host.bytes().any(|b| b.is_ascii_uppercase())
            || authority.port_u16() == Some(443)
        {
            return Err(bad(BaseUrlRule::Normalised));
        }
        Ok(Self(input.to_owned()))
    }

    /// Returns the URL without a trailing slash.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns the absolute URL of `path`, which must start with `/`.
    #[must_use]
    pub fn join(&self, path: &str) -> String {
        debug_assert!(path.starts_with('/'), "path must be absolute");
        format!("{}{path}", self.0)
    }
}

impl fmt::Display for BaseUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Parses durations written as a whole number and a unit: `s`, `m`, `h` or `d`.
///
/// # Errors
///
/// Returns [`ConfigError::InvalidDuration`] for any other form, for zero, or on overflow.
pub fn parse_duration(input: &str) -> Result<Duration, ConfigError> {
    let invalid = || ConfigError::InvalidDuration(input.to_owned());
    let split = input
        .find(|c: char| !c.is_ascii_digit())
        .ok_or_else(invalid)?;
    let (digits, unit) = input.split_at(split);
    let Ok(value) = digits.parse::<u64>() else {
        return Err(invalid());
    };
    let unit_secs = match unit {
        "s" => 1,
        "m" => 60,
        "h" => 3_600,
        "d" => 86_400,
        _ => return Err(invalid()),
    };
    match value.checked_mul(unit_secs) {
        Some(0) | None => Err(invalid()),
        Some(secs) => Ok(Duration::from_secs(secs)),
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    #[test]
    fn accepts_plain_https_origins() {
        for ok in [
            "https://login.example.com",
            "https://10.43.0.53:8443",
            "https://[::1]:9443",
        ] {
            let url = BaseUrl::parse("issuer", ok).unwrap();
            assert_eq!(url.as_str(), ok);
            assert_eq!(url.join("/jwks"), format!("{ok}/jwks"));
        }
    }

    #[test]
    fn rejects_everything_else() {
        let cases = [
            ("http://login.example.com", BaseUrlRule::Scheme),
            ("https://login.example.com/", BaseUrlRule::TrailingSlash),
            ("https://login.example.com/auth", BaseUrlRule::Path),
            ("https://login.example.com?a=b", BaseUrlRule::Query),
            ("https://login.example.com#x", BaseUrlRule::Fragment),
            ("https://u:p@login.example.com", BaseUrlRule::Credentials),
            ("https://Login.Example.com", BaseUrlRule::Normalised),
            ("https://login.example.com:443", BaseUrlRule::Normalised),
        ];
        for (input, reason) in cases {
            assert_eq!(
                BaseUrl::parse("issuer", input),
                Err(ConfigError::BadBaseUrl {
                    field: "issuer",
                    reason
                }),
                "{input}"
            );
        }
        for invalid in ["login.example.com", "https://", "https://exa mple.com", ""] {
            assert!(
                matches!(
                    BaseUrl::parse("issuer", invalid),
                    Err(ConfigError::InvalidUrl { .. })
                ),
                "{invalid}"
            );
        }
        // Internationalised names must be given in A-label (punycode) form.
        assert!(BaseUrl::parse("issuer", "https://exämple.com").is_err());
        assert!(BaseUrl::parse("issuer", "https://xn--exmple-cua.com").is_ok());
    }

    #[test]
    fn parses_durations() {
        assert_eq!(parse_duration("300s"), Ok(Duration::from_secs(300)));
        assert_eq!(parse_duration("5m"), Ok(Duration::from_secs(300)));
        assert_eq!(parse_duration("24h"), Ok(Duration::from_hours(24)));
        assert_eq!(parse_duration("7d"), Ok(Duration::from_hours(7 * 24)));
        for bad in [
            "",
            "7",
            "d",
            "0s",
            "1.5h",
            "-1s",
            "7 d",
            "1w",
            "99999999999999999999d",
        ] {
            assert!(parse_duration(bad).is_err(), "{bad}");
        }
    }

    proptest! {
        #[test]
        fn duration_round_trips(secs in 1_u64..=10_000_000) {
            prop_assert_eq!(parse_duration(&format!("{secs}s")), Ok(Duration::from_secs(secs)));
        }

        #[test]
        fn parse_duration_never_panics(input in "\\PC*") {
            drop(parse_duration(&input));
        }

        #[test]
        fn base_url_never_panics(input in "\\PC*") {
            drop(BaseUrl::parse("issuer", &input));
        }
    }
}
