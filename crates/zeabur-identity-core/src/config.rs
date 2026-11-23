//! Validated runtime configuration.

use std::fmt;
use std::time::Duration;

use http::Uri;
use http::uri::InvalidUri;
use jiff::{Span, SpanRelativeTo};
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
    /// The duration breaks a rule for duration flags.
    #[error("{field}: {reason}")]
    BadDuration {
        /// The configuration field.
        field: &'static str,
        /// The rule that was broken.
        reason: DurationRule,
    },
    /// Options that only work together were given alone.
    #[error("{0}")]
    Incomplete(&'static str),
    /// The key rotation timings are inconsistent.
    #[error("key rotation: {0}")]
    BadRotationPolicy(&'static str),
}

/// A rule for duration flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DurationRule {
    /// Longer than zero.
    Positive,
    /// Weeks or smaller units: a month or a year has no fixed length.
    FixedLength,
}

impl fmt::Display for DurationRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Positive => "must be longer than zero",
            Self::FixedLength => "must use weeks, days or smaller units",
        })
    }
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
/// Verifiers compare the issuer as a string ([OIDC Discovery] §4.3, [KEP-3331]). With a path,
/// OpenID Connect Discovery and [RFC 8414] §3 yield different well-known locations.
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

/// The length of the duration flag `field`, a [`Span`] in jiff's friendly format (`10m`, `7d`,
/// `1h30m`) or ISO 8601 (`PT10M`). A day is 24 hours.
///
/// # Errors
///
/// Returns [`ConfigError::BadDuration`] for months or years, and for zero or a negative span.
pub fn duration(field: &'static str, span: Span) -> Result<Duration, ConfigError> {
    let bad = |reason| ConfigError::BadDuration { field, reason };
    let signed = span
        .to_duration(SpanRelativeTo::days_are_24_hours())
        .map_err(|_calendar| bad(DurationRule::FixedLength))?;
    Duration::try_from(signed)
        .ok()
        .filter(|length| !length.is_zero())
        .ok_or_else(|| bad(DurationRule::Positive))
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

    /// Parses `input` as clap does (jiff's `FromStr`), then applies [`duration`].
    fn parse(field: &'static str, input: &str) -> Result<Duration, ConfigError> {
        let span: Span = input.parse().unwrap_or_else(|e| panic!("{input}: {e}"));
        duration(field, span)
    }

    /// Every form accepted before jiff (a whole number and `s`, `m`, `h` or `d`)
    /// keeps its value.
    #[test]
    fn accepts_the_old_forms() {
        assert_eq!(parse("f", "300s"), Ok(Duration::from_secs(300)));
        assert_eq!(parse("f", "5m"), Ok(Duration::from_secs(300)));
        assert_eq!(parse("f", "60m"), Ok(Duration::from_hours(1)));
        assert_eq!(parse("f", "24h"), Ok(Duration::from_hours(24)));
        assert_eq!(parse("f", "7d"), Ok(Duration::from_hours(7 * 24)));
        assert_eq!(parse("f", "007d"), Ok(Duration::from_hours(7 * 24)));
    }

    #[test]
    fn refuses_empty_and_unbounded_lengths() {
        let refused = |input: &str, reason| {
            assert_eq!(
                parse("--valid-for", input),
                Err(ConfigError::BadDuration {
                    field: "--valid-for",
                    reason
                }),
                "{input}"
            );
        };
        refused("0s", DurationRule::Positive);
        refused("-1s", DurationRule::Positive);
        refused("1mo", DurationRule::FixedLength);
        refused("1y", DurationRule::FixedLength);
        for bad in ["", "7", "d", "7 x", "5M", "99999999999999999999d"] {
            assert!(bad.parse::<Span>().is_err(), "{bad}");
        }
    }

    proptest! {
        /// A whole number and a unit keep the old value, up to the largest span jiff holds
        /// (about 20,000 years).
        #[test]
        fn old_forms_keep_their_value(
            (unit, secs, count) in prop_oneof![
                (1_u64..=631_107_417_600).prop_map(|n| ("s", 1_u64, n)),
                (1_u64..=10_518_456_960).prop_map(|n| ("m", 60, n)),
                (1_u64..=175_307_616).prop_map(|n| ("h", 3_600, n)),
                (1_u64..=7_304_484).prop_map(|n| ("d", 86_400, n)),
            ]
        ) {
            prop_assert_eq!(
                parse("f", &format!("{count}{unit}")),
                Ok(Duration::from_secs(count * secs))
            );
        }

        #[test]
        fn duration_never_panics(input in "\\PC*") {
            if let Ok(span) = input.parse::<Span>() {
                drop(duration("f", span));
            }
        }

        #[test]
        fn base_url_never_panics(input in "\\PC*") {
            drop(BaseUrl::parse("issuer", &input));
        }
    }
}
