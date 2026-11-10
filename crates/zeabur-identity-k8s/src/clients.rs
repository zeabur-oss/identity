//! Client registration: the admin's side (`zeabur-identityctl client create`).
//!
//! A confidential client's secret is stored as an unsalted SHA-256 hash
//! ([`zeabur_identity_core::crypto::hash_secret`]), which anyone with `get` on `OAuthClient`
//! objects, or with the GitOps repository, can read. That is safe only for a high-entropy secret: a
//! fast, unsalted hash of a password falls to an offline dictionary attack, and the server cannot
//! tell, because it only ever sees the hash. So the secret is generated here, never chosen by a
//! person: 256 bits from the system CSPRNG, the same strength as every other secret Zeabur Identity
//! hashes.
//!
//! The rules the `OAuthClient` schema enforces at admission are checked here too, so a mistake
//! fails before `kubectl apply`, with a message that names the bad value.

use kube::api::ObjectMeta;
use thiserror::Error;
use zeabur_identity_api::client::{
    ClientType, MAX_AUDIENCE, MAX_AUDIENCES, MAX_DISPLAY_NAME, MAX_REDIRECT_URI, MAX_REDIRECT_URIS,
    OAuthClient, OAuthClientSpec,
};
use zeabur_identity_core::crypto::{hash_secret, hex, random};
use zeabur_identity_keys::Algorithm;

/// Longest client ID. The client ID is the `OAuthClient` object name and also the
/// `identity.zeabur.com/client` label value on grants, which Kubernetes caps at 63 characters.
pub const MAX_CLIENT_ID: usize = 63;

/// Bytes of entropy in a generated client secret.
pub const SECRET_BYTES: usize = 32;

/// Why a client could not be registered.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ClientError {
    /// The client ID is not a lowercase DNS subdomain of at most 63 characters.
    #[error(
        "client ID {0:?} must be a lowercase DNS subdomain (a-z, 0-9, '-', '.') of at most {MAX_CLIENT_ID} characters"
    )]
    InvalidClientId(String),
    /// The display name is too long.
    #[error("display name must be at most {MAX_DISPLAY_NAME} characters")]
    DisplayNameTooLong,
    /// No redirect URI, or too many.
    #[error("provide 1 to {MAX_REDIRECT_URIS} redirect URIs")]
    RedirectUriCount,
    /// A redirect URI that RFC 9700 §2.1 or RFC 8252 §7.3 forbids.
    #[error(
        "redirect URI {0:?} must be https:// with a host, or http://127.0.0.1 or http://[::1] with a path, written as a browser normalizes it (lowercase, no default port, at least a / path, non-ASCII percent-encoded, every % followed by two hex digits), with no fragment or user information, at most {MAX_REDIRECT_URI} characters"
    )]
    InvalidRedirectUri(String),
    /// Too many audiences.
    #[error("provide at most {MAX_AUDIENCES} audiences")]
    AudienceCount,
    /// An empty or overlong audience.
    #[error("audience {0:?} must be between 1 and {MAX_AUDIENCE} characters")]
    InvalidAudience(String),
    /// A home URL that is not `https://` with a host, as a browser writes it.
    #[error(
        "home URL {0:?} must be https:// with a host, written as a browser normalizes it, with no fragment or user information, at most {MAX_REDIRECT_URI} characters"
    )]
    InvalidHomeUrl(String),
    /// Randomness failed.
    #[error("unable to generate the client secret")]
    Crypto,
}

/// The client to register.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewClient {
    /// The client ID; also the object name.
    pub client_id: String,
    /// Whether the client can keep a secret.
    pub kind: ClientType,
    /// Name shown on the sign-in pages.
    pub display_name: Option<String>,
    /// Redirect URIs, compared by exact match (any port for loopback URIs).
    pub redirect_uris: Vec<String>,
    /// Audiences the client may request tokens for.
    pub audiences: Vec<String>,
    /// ID token signing algorithm, if not the default.
    pub id_token_signing_alg: Option<Algorithm>,
    /// Where people open the application; the sign-in page links to it.
    pub home_url: Option<String>,
}

/// A registered client, ready for `kubectl apply`.
#[derive(Debug)]
pub struct Registration {
    /// The object; a confidential client's carries only the secret's hash.
    pub client: OAuthClient,
    /// A confidential client's secret: 64 lowercase hex digits. Shown once; it cannot be
    /// recovered from the object.
    pub secret: Option<String>,
}

/// Validates `new` and builds its `OAuthClient` in `namespace`, generating a secret for a
/// confidential client.
///
/// # Errors
///
/// Returns [`ClientError`] for a value the `OAuthClient` schema would reject, or when randomness
/// fails.
pub fn register(new: NewClient, namespace: &str) -> Result<Registration, ClientError> {
    validate(&new)?;
    let secret = match new.kind {
        ClientType::Public => None,
        ClientType::Confidential => Some(hex(
            &random::<SECRET_BYTES>().map_err(|_crypto| ClientError::Crypto)?
        )),
    };
    let client = OAuthClient {
        metadata: ObjectMeta {
            name: Some(new.client_id),
            namespace: Some(namespace.to_owned()),
            ..ObjectMeta::default()
        },
        spec: OAuthClientSpec {
            display_name: new.display_name,
            kind: new.kind,
            redirect_uris: new.redirect_uris,
            audiences: new.audiences,
            secret_hash: secret
                .as_deref()
                .map(|secret| hash_secret(secret.as_bytes())),
            id_token_signing_alg: new.id_token_signing_alg,
            home_url: new.home_url,
        },
    };
    Ok(Registration { client, secret })
}

fn validate(new: &NewClient) -> Result<(), ClientError> {
    if !is_client_id(&new.client_id) {
        return Err(ClientError::InvalidClientId(new.client_id.clone()));
    }
    if new
        .display_name
        .as_ref()
        .is_some_and(|name| name.chars().count() > MAX_DISPLAY_NAME)
    {
        return Err(ClientError::DisplayNameTooLong);
    }
    if new.redirect_uris.is_empty() || new.redirect_uris.len() > MAX_REDIRECT_URIS {
        return Err(ClientError::RedirectUriCount);
    }
    if let Some(uri) = new
        .redirect_uris
        .iter()
        .find(|uri| !redirect_uri_allowed(uri))
    {
        return Err(ClientError::InvalidRedirectUri(uri.clone()));
    }
    if new.audiences.len() > MAX_AUDIENCES {
        return Err(ClientError::AudienceCount);
    }
    if let Some(audience) = new
        .audiences
        .iter()
        .find(|audience| audience.is_empty() || audience.chars().count() > MAX_AUDIENCE)
    {
        return Err(ClientError::InvalidAudience(audience.clone()));
    }
    if let Some(url) = new
        .home_url
        .as_ref()
        .filter(|url| !url.starts_with("https://") || !redirect_uri_allowed(url))
    {
        return Err(ClientError::InvalidHomeUrl(url.clone()));
    }
    Ok(())
}

/// A lowercase RFC 1123 DNS subdomain of at most [`MAX_CLIENT_ID`] characters: dot-separated
/// labels of `a-z`, `0-9` and `-` that start and end with a letter or digit.
fn is_client_id(id: &str) -> bool {
    id.len() <= MAX_CLIENT_ID
        && id.split('.').all(|label| {
            let alphanumeric = |c: char| c.is_ascii_lowercase() || c.is_ascii_digit();
            label.starts_with(alphanumeric)
                && label.ends_with(alphanumeric)
                && label.chars().all(|c| alphanumeric(c) || c == '-')
        })
}

/// Whether `uri` is a redirect URI a browser can follow and the `OAuthClient` schema accepts.
///
/// [`REDIRECT_URI_RULE`](zeabur_identity_api::client::REDIRECT_URI_RULE) is the floor: `https://` with a
/// host, or `http://127.0.0.1` / `http://[::1]` with a path (RFC 9700 §2.1, RFC 8252 §7.3), no
/// fragment (RFC 6749 §3.1.2) and no user information. On top of it, `uri` must parse as a URL
/// the way a browser parses it (the WHATWG URL Standard, which the `url` crate implements) and be
/// written exactly as that parse serializes it. So an address the browser rejects (`999.1.1.1`,
/// `[:::]`, port 99999) fails here rather than at login, and the string registered for exact
/// matching is the one the browser will use: lowercase scheme and host, no default port, and a
/// `/` path at least. Every `%` must start a percent-encoded octet (RFC 3986 §2.1): a browser
/// leaves a stray `%` alone, but Go's parser, and so admission, rejects it.
#[must_use]
pub fn redirect_uri_allowed(uri: &str) -> bool {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use url::{Host, Url};

    if uri.len() > MAX_REDIRECT_URI {
        return false;
    }
    let Ok(url) = Url::parse(uri) else {
        return false;
    };
    let origin_allowed = match (url.scheme(), url.host()) {
        ("https", Some(_)) => true,
        ("http", Some(Host::Ipv4(ip))) => ip == Ipv4Addr::LOCALHOST,
        ("http", Some(Host::Ipv6(ip))) => ip == Ipv6Addr::LOCALHOST,
        _ => false,
    };
    origin_allowed
        && url.as_str() == uri
        && percent_encoding_well_formed(uri)
        && url.fragment().is_none()
        && url.username().is_empty()
        && url.password().is_none()
}

/// Whether every `%` is followed by two hex digits.
fn percent_encoding_well_formed(uri: &str) -> bool {
    uri.split('%').skip(1).all(|after| {
        after
            .as_bytes()
            .get(..2)
            .is_some_and(|digits| digits.iter().all(u8::is_ascii_hexdigit))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn new_client(kind: ClientType) -> NewClient {
        NewClient {
            client_id: "dashboard".into(),
            kind,
            display_name: Some("Dashboard".into()),
            redirect_uris: vec!["https://dash.example.com/callback".into()],
            audiences: vec!["kubernetes".into()],
            id_token_signing_alg: None,
            home_url: None,
        }
    }

    #[test]
    fn confidential_clients_get_a_fresh_random_secret_and_only_its_hash() {
        let first = register(new_client(ClientType::Confidential), "zeabur-identity").unwrap();
        let second = register(new_client(ClientType::Confidential), "zeabur-identity").unwrap();
        let secret = first.secret.unwrap();
        assert_eq!(secret.len(), SECRET_BYTES * 2);
        assert!(secret.bytes().all(|b| b.is_ascii_hexdigit()));
        assert_ne!(Some(&secret), second.secret.as_ref());
        assert_eq!(
            first.client.spec.secret_hash,
            Some(hash_secret(secret.as_bytes()))
        );
        let json = serde_json::to_string(&first.client).unwrap();
        assert!(!json.contains(&secret));
    }

    #[test]
    fn emitted_objects_satisfy_the_schema_rules() {
        let confidential = register(new_client(ClientType::Confidential), "ns").unwrap();
        let value = serde_json::to_value(&confidential.client).unwrap();
        assert_eq!(value["apiVersion"], "identity.zeabur.com/v1alpha1");
        assert_eq!(value["kind"], "OAuthClient");
        assert_eq!(value["metadata"]["name"], "dashboard");
        assert_eq!(value["metadata"]["namespace"], "ns");
        assert_eq!(value["spec"]["type"], "Confidential");
        let hash = value["spec"]["secretHash"].as_str().unwrap();
        let digits = hash.strip_prefix("sha256:").unwrap();
        assert_eq!(digits.len(), 64);
        assert!(
            digits
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        );

        let public = register(new_client(ClientType::Public), "ns").unwrap();
        assert!(public.secret.is_none());
        let value = serde_json::to_value(&public.client).unwrap();
        assert_eq!(value["spec"]["type"], "Public");
        assert!(value["spec"].get("secretHash").is_none());
    }

    /// The policy, by example. `tests/redirect_uris.rs` checks generated candidates against
    /// every parser on the way to the browser, and the cluster tests against admission.
    #[test]
    fn redirect_uris_are_https_or_loopback_in_the_form_a_browser_uses() {
        for allowed in [
            "https://dash.example.com/callback",
            "https://[2001:db8::1]:8443/cb?x=1",
            "http://127.0.0.1:8000/",
            "http://[::1]/cb",
        ] {
            assert!(redirect_uri_allowed(allowed), "{allowed}");
        }
        for forbidden in [
            // Not https or loopback (RFC 9700 §2.1, RFC 8252 §7.3).
            "http://localhost:8000/",
            // A fragment or user information.
            "https://dash.example.com/cb#fragment",
            "https://user@dash.example.com/",
            // Not a URL to a browser.
            "https://[:::]/callback",
            "https://999.999.999.999/callback",
            "https://dash.example.com:99999/callback",
            // A URL, but not as the browser writes it, so an exact match would miss.
            "https://dash.example.com",
            "https:///callback",
            "http://127.0.0.1:8000",
            // A stray `%`, which a browser keeps but Go's parser (admission) rejects.
            "http://127.0.0.1:8000/c%",
            "https://dash.example.com/%zz",
        ] {
            assert!(!redirect_uri_allowed(forbidden), "{forbidden}");
        }
        assert!(!redirect_uri_allowed(&format!(
            "https://e.com/{}",
            "a".repeat(MAX_REDIRECT_URI)
        )));
    }

    #[test]
    fn invalid_registrations_are_rejected_with_the_offending_value() {
        let with = |change: fn(&mut NewClient)| {
            let mut new = new_client(ClientType::Public);
            change(&mut new);
            register(new, "ns").unwrap_err()
        };
        assert_eq!(
            with(|new| new.redirect_uris = vec!["http://example.com/".into()]),
            ClientError::InvalidRedirectUri("http://example.com/".into())
        );
        assert_eq!(
            with(|new| new.redirect_uris = vec![]),
            ClientError::RedirectUriCount
        );
        assert_eq!(
            with(|new| new.redirect_uris = vec!["https://e.com/".into(); MAX_REDIRECT_URIS + 1]),
            ClientError::RedirectUriCount
        );
        assert_eq!(
            with(|new| new.audiences = vec![String::new()]),
            ClientError::InvalidAudience(String::new())
        );
        assert_eq!(
            with(|new| new.audiences = vec!["k".into(); MAX_AUDIENCES + 1]),
            ClientError::AudienceCount
        );
        assert_eq!(
            with(|new| new.display_name = Some("x".repeat(MAX_DISPLAY_NAME + 1))),
            ClientError::DisplayNameTooLong
        );
        assert_eq!(
            with(|new| new.home_url = Some("http://127.0.0.1/".into())),
            ClientError::InvalidHomeUrl("http://127.0.0.1/".into())
        );
        assert_eq!(
            with(|new| new.home_url = Some("https://Zeabur.example.com".into())),
            ClientError::InvalidHomeUrl("https://Zeabur.example.com".into())
        );
        let mut new = new_client(ClientType::Public);
        new.home_url = Some("https://zeabur.example.com/".into());
        assert!(register(new, "ns").is_ok());
        for id in [
            "",
            "Dashboard",
            "-dash",
            "dash-",
            "dash..board",
            "dash_board",
        ] {
            let mut new = new_client(ClientType::Public);
            new.client_id = id.into();
            assert_eq!(
                register(new, "ns").unwrap_err(),
                ClientError::InvalidClientId(id.into())
            );
        }
        let mut new = new_client(ClientType::Public);
        new.client_id = "a".repeat(MAX_CLIENT_ID + 1);
        assert!(register(new, "ns").is_err());
    }
}
