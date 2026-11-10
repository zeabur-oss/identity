//! Minting access tokens (RFC 9068) and ID tokens (OIDC Core §2).
//!
//! The two kinds can be told apart from their claims alone, because kube-apiserver does not check
//! the `typ` header and its CEL claim rules see only claims:
//!
//! - access tokens: `typ: at+jwt`, always ES256, `aud` is the requested resource (one value), carry
//!   `client_id` (RFC 9068 §2.2), and always `preferred_username` and `groups`, which
//!   kube-apiserver maps to a user;
//! - ID tokens: `typ: JWT`, the client's algorithm (ES256, or RS256 for clients that need the OIDC
//!   mandatory algorithm), `aud` is the client, carry `azp` but never `client_id`.
//!
//! The kube-apiserver configuration therefore requires `has(claims.client_id)`, so an ID token
//! is never a Kubernetes credential and the rules for the two kinds stay mutually exclusive
//! (RFC 8725 §3.12).
//!
//! `groups` comes from [`User::token_groups`]: only admin accounts carry
//! [`ADMIN_GROUP`](zeabur_identity_api::ADMIN_GROUP).

use serde::Serialize;
use zeabur_identity_core::clock::UnixTime;
use zeabur_identity_core::crypto::{hex, random};
use zeabur_identity_keys::Algorithm;
use zeabur_identity_keys::jws::sign_compact;
use zeabur_identity_keys::manager::Published;
use zeabur_identity_store::{Client, User};

use super::error::OAuthError;

/// What a token describes.
#[derive(Debug, Clone)]
pub struct Subject<'a> {
    /// Issuer identifier.
    pub issuer: &'a str,
    /// The user.
    pub user: &'a User,
    /// The client.
    pub client: &'a Client,
    /// Access-token audience.
    pub audience: &'a str,
    /// Granted scopes.
    pub scopes: &'a [String],
    /// When the user authenticated.
    pub auth_time: UnixTime,
    /// Authentication methods.
    pub amr: &'a [String],
}

impl Subject<'_> {
    fn has_scope(&self, scope: &str) -> bool {
        self.scopes.iter().any(|s| s == scope)
    }
}

/// RFC 9068 §2.2 claims, plus what kube-apiserver maps to a user.
#[derive(Debug, Serialize)]
struct AccessTokenClaims<'a> {
    iss: &'a str,
    sub: &'a str,
    aud: &'a str,
    exp: u64,
    iat: u64,
    jti: String,
    client_id: &'a str,
    #[serde(skip_serializing_if = "String::is_empty")]
    scope: String,
    auth_time: u64,
    #[serde(skip_serializing_if = "<[String]>::is_empty")]
    amr: &'a [String],
    preferred_username: &'a str,
    groups: &'a [String],
}

/// OIDC Core §2 claims.
#[derive(Debug, Serialize)]
struct IdTokenClaims<'a> {
    iss: &'a str,
    sub: &'a str,
    aud: &'a str,
    azp: &'a str,
    exp: u64,
    iat: u64,
    auth_time: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    nonce: Option<&'a str>,
    #[serde(skip_serializing_if = "<[String]>::is_empty")]
    amr: &'a [String],
    #[serde(skip_serializing_if = "Option::is_none")]
    preferred_username: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    groups: Option<&'a [String]>,
}

fn signer(
    keys: &Published,
    alg: Algorithm,
    now: UnixTime,
) -> Result<std::sync::Arc<zeabur_identity_keys::signing::SigningKey>, OAuthError> {
    keys.signer(alg, now).ok_or_else(|| {
        tracing::error!(
            reason = "no_active_signer",
            alg = alg.as_str(),
            "no active signing key"
        );
        OAuthError::server()
    })
}

/// Signs an access token, `typ: at+jwt` (RFC 9068 §2.1), always ES256.
///
/// # Errors
///
/// `server_error` if no key is active or signing fails.
pub fn access_token(
    keys: &Published,
    subject: &Subject<'_>,
    now: UnixTime,
    expires_at: UnixTime,
) -> Result<String, OAuthError> {
    let groups = subject.user.token_groups();
    let claims = AccessTokenClaims {
        iss: subject.issuer,
        sub: &subject.user.subject,
        aud: subject.audience,
        exp: expires_at.as_secs(),
        iat: now.as_secs(),
        jti: hex(&random::<16>().map_err(|_crypto| OAuthError::server())?),
        client_id: &subject.client.id,
        scope: subject.scopes.join(" "),
        auth_time: subject.auth_time.as_secs(),
        amr: subject.amr,
        preferred_username: &subject.user.username,
        groups: &groups,
    };
    let key = signer(keys, Algorithm::Es256, now)?;
    sign_compact(&key, "at+jwt", &claims).map_err(|error| {
        tracing::error!(
            %error,
            reason = "signing_failed",
            "signing an access token failed"
        );
        OAuthError::server()
    })
}

/// Signs an ID token with the client's algorithm. Profile claims require the `profile` scope;
/// groups require `groups`.
///
/// # Errors
///
/// `server_error` if no key is active or signing fails.
pub fn id_token(
    keys: &Published,
    subject: &Subject<'_>,
    nonce: Option<&str>,
    now: UnixTime,
    expires_at: UnixTime,
) -> Result<String, OAuthError> {
    let profile = subject.has_scope("profile");
    let groups = subject.user.token_groups();
    let claims = IdTokenClaims {
        iss: subject.issuer,
        sub: &subject.user.subject,
        aud: &subject.client.id,
        azp: &subject.client.id,
        exp: expires_at.as_secs(),
        iat: now.as_secs(),
        auth_time: subject.auth_time.as_secs(),
        nonce,
        amr: subject.amr,
        preferred_username: profile.then_some(subject.user.username.as_str()),
        name: if profile {
            subject.user.display_name.as_deref()
        } else {
            None
        },
        groups: subject.has_scope("groups").then_some(groups.as_slice()),
    };
    let key = signer(keys, subject.client.id_token_alg, now)?;
    sign_compact(&key, "JWT", &claims).map_err(|error| {
        tracing::error!(%error, reason = "signing_failed", "signing an ID token failed");
        OAuthError::server()
    })
}
