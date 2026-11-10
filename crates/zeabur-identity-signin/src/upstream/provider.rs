//! GitHub (OAuth 2.0) and Google (OpenID Connect) as upstream identity providers.
//!
//! Each yields one thing: the provider's stable identifier for the account (GitHub's numeric user
//! ID, Google's `sub`), never a login name or email address, which can change hands.
//!
//! Google's ID token is validated as OpenID Connect Core 1.0 §3.1.3.7 requires of a client:
//! signature with a key from Google's published JWK set, `iss` one of Google's issuer strings,
//! `aud` exactly the client ID (no other audience is trusted) and `azp`, if present, equal to it,
//! not expired, and `nonce` equal to the one sent. Codes are exchanged with PKCE (RFC 7636) for
//! both providers, and the client authenticates with `client_secret_post` (RFC 6749 §2.3.1).

use std::sync::Mutex;
use std::time::Duration;

use axum::body::Bytes;
use axum::http::{Method, Request, StatusCode, header};
use serde::Deserialize;
use thiserror::Error;
use zeabur_identity_api::credential::CredentialType;
use zeabur_identity_core::clock::UnixTime;
use zeabur_identity_keys::Algorithm;
use zeabur_identity_keys::verify::{VerificationKey, parse_jwk_set, verify_compact};
use zeabur_identity_ui::pages::ProviderButton;

use super::http::{HttpClient, HttpError};

/// How long Google's JWK set is reused before it is fetched again.
const JWKS_MAX_AGE: Duration = Duration::from_hours(1);
/// An unknown `kid` refetches the set, but not more often than this.
const JWKS_MIN_REFRESH: Duration = Duration::from_mins(1);
/// Clock skew tolerated on `exp` and `iat`.
const LEEWAY: u64 = 60;

/// A supported provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Kind {
    /// GitHub.
    GitHub,
    /// Google.
    Google,
}

impl Kind {
    /// The path segment and CLI name.
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::GitHub => "github",
            Self::Google => "google",
        }
    }

    /// Parses [`Kind::id`].
    #[must_use]
    pub fn from_id(id: &str) -> Option<Self> {
        match id {
            "github" => Some(Self::GitHub),
            "google" => Some(Self::Google),
            _ => None,
        }
    }

    /// The name shown on buttons.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::GitHub => "GitHub",
            Self::Google => "Google",
        }
    }

    /// The icon on its button.
    #[must_use]
    pub const fn icon(self) -> &'static str {
        match self {
            Self::GitHub => "GithubLogo",
            Self::Google => "GoogleLogo",
        }
    }

    /// Its button on the sign-in pages.
    #[must_use]
    pub const fn button(self) -> ProviderButton {
        ProviderButton {
            id: self.id(),
            label: self.label(),
            icon: self.icon(),
        }
    }

    /// The `Credential` type of a linked account.
    #[must_use]
    pub const fn credential_type(self) -> CredentialType {
        match self {
            Self::GitHub => CredentialType::GitHub,
            Self::Google => CredentialType::Google,
        }
    }

    /// The provider of a linked account's `Credential` type. `None` for a passkey.
    #[must_use]
    pub const fn from_credential_type(kind: CredentialType) -> Option<Self> {
        match kind {
            CredentialType::GitHub => Some(Self::GitHub),
            CredentialType::Google => Some(Self::Google),
            CredentialType::Passkey => None,
        }
    }

    /// The issuer recorded with a linked account.
    #[must_use]
    pub const fn issuer(self) -> &'static str {
        match self {
            Self::GitHub => "https://github.com",
            Self::Google => "https://accounts.google.com",
        }
    }
}

/// Where a provider's endpoints are. Fixed for the real providers; tests point them elsewhere.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoints {
    /// Authorization endpoint.
    pub authorize: String,
    /// Token endpoint.
    pub token: String,
    /// GitHub: the authenticated-user endpoint.
    pub user: Option<String>,
    /// Google: the JWK set.
    pub jwks: Option<String>,
    /// Google: accepted `iss` values.
    pub issuers: Vec<String>,
}

impl Endpoints {
    /// GitHub's OAuth app endpoints.
    #[must_use]
    pub fn github() -> Self {
        Self {
            authorize: "https://github.com/login/oauth/authorize".to_owned(),
            token: "https://github.com/login/oauth/access_token".to_owned(),
            user: Some("https://api.github.com/user".to_owned()),
            jwks: None,
            issuers: Vec::new(),
        }
    }

    /// Google's OpenID Connect endpoints, from its discovery document.
    #[must_use]
    pub fn google() -> Self {
        Self {
            authorize: "https://accounts.google.com/o/oauth2/v2/auth".to_owned(),
            token: "https://oauth2.googleapis.com/token".to_owned(),
            user: None,
            jwks: Some("https://www.googleapis.com/oauth2/v3/certs".to_owned()),
            // Google's documentation lists both forms of its issuer.
            issuers: vec![
                "https://accounts.google.com".to_owned(),
                "accounts.google.com".to_owned(),
            ],
        }
    }
}

/// A configured provider.
pub struct Provider {
    kind: Kind,
    client_id: String,
    client_secret: String,
    endpoints: Endpoints,
    jwks: Mutex<Option<(UnixTime, Vec<VerificationKey>)>>,
}

impl std::fmt::Debug for Provider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Provider")
            .field("kind", &self.kind)
            .field("client_id", &self.client_id)
            .finish_non_exhaustive()
    }
}

/// Why an upstream sign-in failed.
#[derive(Debug, Error)]
pub enum UpstreamError {
    /// The provider could not be reached or answered with an error.
    #[error(transparent)]
    Http(#[from] HttpError),
    /// The provider's answer was not what the protocol says.
    #[error("unexpected answer from the provider: {0}")]
    Protocol(&'static str),
    /// The ID token is not valid.
    #[error("the provider's ID token is not valid: {0}")]
    IdToken(&'static str),
}

#[derive(Deserialize)]
struct TokenResponse {
    #[serde(default)]
    access_token: Option<String>,
    #[serde(default)]
    id_token: Option<String>,
}

#[derive(Deserialize)]
struct GitHubUser {
    id: u64,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum Audience {
    One(String),
    Many(Vec<String>),
}

#[derive(Deserialize)]
struct IdClaims {
    iss: String,
    sub: String,
    aud: Audience,
    exp: u64,
    #[serde(default)]
    iat: Option<u64>,
    #[serde(default)]
    azp: Option<String>,
    #[serde(default)]
    nonce: Option<String>,
}

/// What [`Provider::identify`] needs from the authorization response and the sealed state.
#[derive(Debug, Clone, Copy)]
pub struct Exchange<'a> {
    /// The code from the callback.
    pub code: &'a str,
    /// The PKCE verifier sent with the code's request.
    pub verifier: &'a str,
    /// The redirect URI the code was issued for.
    pub redirect_uri: &'a str,
    /// The nonce sent (Google).
    pub nonce: &'a str,
}

impl Provider {
    /// A provider with its client registration.
    #[must_use]
    pub const fn new(
        kind: Kind,
        client_id: String,
        client_secret: String,
        endpoints: Endpoints,
    ) -> Self {
        Self {
            kind,
            client_id,
            client_secret,
            endpoints,
            jwks: Mutex::new(None),
        }
    }

    /// Which provider.
    #[must_use]
    pub const fn kind(&self) -> Kind {
        self.kind
    }

    /// The authorization request URL.
    #[must_use]
    pub fn authorize_url(
        &self,
        redirect_uri: &str,
        state: &str,
        nonce: &str,
        challenge: &str,
    ) -> String {
        let mut query = form_urlencoded::Serializer::new(String::new());
        query
            .append_pair("client_id", &self.client_id)
            .append_pair("redirect_uri", redirect_uri)
            .append_pair("response_type", "code")
            .append_pair("state", state)
            .append_pair("code_challenge", challenge)
            .append_pair("code_challenge_method", "S256");
        match self.kind {
            // No scope: only the public profile (and with it the numeric ID) is needed.
            Kind::GitHub => {
                query.append_pair("allow_signup", "false");
            }
            Kind::Google => {
                query
                    .append_pair("scope", "openid")
                    .append_pair("nonce", nonce)
                    .append_pair("prompt", "select_account");
            }
        }
        let separator = if self.endpoints.authorize.contains('?') {
            '&'
        } else {
            '?'
        };
        format!("{}{separator}{}", self.endpoints.authorize, query.finish())
    }

    /// Exchanges the code and returns the account's stable identifier.
    ///
    /// # Errors
    ///
    /// [`UpstreamError`] if the provider fails or its answer does not check out.
    pub async fn identify<H: HttpClient>(
        &self,
        http: &H,
        exchange: Exchange<'_>,
        now: UnixTime,
    ) -> Result<String, UpstreamError> {
        let form = form_urlencoded::Serializer::new(String::new())
            .append_pair("grant_type", "authorization_code")
            .append_pair("code", exchange.code)
            .append_pair("redirect_uri", exchange.redirect_uri)
            .append_pair("code_verifier", exchange.verifier)
            .append_pair("client_id", &self.client_id)
            .append_pair("client_secret", &self.client_secret)
            .finish();
        let request = Request::builder()
            .method(Method::POST)
            .uri(&self.endpoints.token)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(header::ACCEPT, "application/json")
            .body(Bytes::from(form))
            .map_err(|_request| UpstreamError::Protocol("token endpoint URL"))?;
        let response = http.send(request).await?;
        if response.status() != StatusCode::OK {
            return Err(UpstreamError::Protocol("the token request was refused"));
        }
        let tokens: TokenResponse = serde_json::from_slice(response.body())
            .map_err(|_json| UpstreamError::Protocol("token response"))?;
        match self.kind {
            Kind::GitHub => {
                let access = tokens
                    .access_token
                    .ok_or(UpstreamError::Protocol("no access token"))?;
                self.github_user(http, &access).await
            }
            Kind::Google => {
                let id_token = tokens
                    .id_token
                    .ok_or(UpstreamError::Protocol("no ID token"))?;
                self.google_subject(http, &id_token, exchange.nonce, now)
                    .await
            }
        }
    }

    async fn github_user<H: HttpClient>(
        &self,
        http: &H,
        access_token: &str,
    ) -> Result<String, UpstreamError> {
        let url = self
            .endpoints
            .user
            .as_deref()
            .ok_or(UpstreamError::Protocol("no user endpoint"))?;
        let request = Request::builder()
            .uri(url)
            .header(header::AUTHORIZATION, format!("Bearer {access_token}"))
            .header(header::ACCEPT, "application/vnd.github+json")
            // GitHub's REST API refuses requests without a User-Agent.
            .header(header::USER_AGENT, "zeabur-identity")
            .header("x-github-api-version", "2022-11-28")
            .body(Bytes::new())
            .map_err(|_request| UpstreamError::Protocol("user endpoint URL"))?;
        let response = http.send(request).await?;
        if response.status() != StatusCode::OK {
            return Err(UpstreamError::Protocol("the user request was refused"));
        }
        let user: GitHubUser = serde_json::from_slice(response.body())
            .map_err(|_json| UpstreamError::Protocol("user response"))?;
        Ok(user.id.to_string())
    }

    async fn keys<H: HttpClient>(
        &self,
        http: &H,
        now: UnixTime,
        refresh: bool,
    ) -> Result<Vec<VerificationKey>, UpstreamError> {
        let cached = self
            .jwks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        if let Some((fetched, keys)) = &cached {
            let age = now.as_secs().saturating_sub(fetched.as_secs());
            let fresh = age < JWKS_MAX_AGE.as_secs();
            let recently = age < JWKS_MIN_REFRESH.as_secs();
            if (fresh && !refresh) || recently {
                return Ok(keys.clone());
            }
        }
        let url = self
            .endpoints
            .jwks
            .as_deref()
            .ok_or(UpstreamError::Protocol("no JWK set"))?;
        let request = Request::builder()
            .uri(url)
            .body(Bytes::new())
            .map_err(|_request| UpstreamError::Protocol("JWK set URL"))?;
        let response = http.send(request).await?;
        if response.status() != StatusCode::OK {
            return Err(UpstreamError::Protocol("the JWK set request was refused"));
        }
        let keys =
            parse_jwk_set(response.body()).map_err(|_jwks| UpstreamError::Protocol("JWK set"))?;
        *self
            .jwks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some((now, keys.clone()));
        Ok(keys)
    }

    async fn google_subject<H: HttpClient>(
        &self,
        http: &H,
        id_token: &str,
        nonce: &str,
        now: UnixTime,
    ) -> Result<String, UpstreamError> {
        const ALGORITHMS: [Algorithm; 2] = [Algorithm::Rs256, Algorithm::Es256];
        let keys = self.keys(http, now, false).await?;
        let verified = match verify_compact(id_token, &keys, &ALGORITHMS) {
            Err(zeabur_identity_keys::verify::VerifyError::UnknownKey) => {
                // Keys rotate: fetch again once.
                let keys = self.keys(http, now, true).await?;
                verify_compact(id_token, &keys, &ALGORITHMS)
            }
            other => other,
        };
        let (_header, payload) =
            verified.map_err(|_invalid| UpstreamError::IdToken("signature"))?;
        let claims: IdClaims =
            serde_json::from_slice(&payload).map_err(|_json| UpstreamError::IdToken("claims"))?;
        if !self.endpoints.issuers.contains(&claims.iss) {
            return Err(UpstreamError::IdToken("issuer"));
        }
        // This client trusts no other audience, so the only acceptable `aud` is its own client ID
        // (§3.1.3.7 step 3), and an `azp` naming another party is refused (step 5).
        let audience_ok = match &claims.aud {
            Audience::One(aud) => *aud == self.client_id,
            Audience::Many(auds) => matches!(auds.as_slice(), [aud] if *aud == self.client_id),
        };
        if !audience_ok
            || claims
                .azp
                .as_deref()
                .is_some_and(|azp| azp != self.client_id)
        {
            return Err(UpstreamError::IdToken("audience"));
        }
        if claims.exp.saturating_add(LEEWAY) <= now.as_secs() {
            return Err(UpstreamError::IdToken("expired"));
        }
        if claims
            .iat
            .is_some_and(|iat| iat > now.as_secs().saturating_add(LEEWAY))
        {
            return Err(UpstreamError::IdToken("issued in the future"));
        }
        if claims.nonce.as_deref() != Some(nonce) {
            return Err(UpstreamError::IdToken("nonce"));
        }
        if claims.sub.is_empty() || claims.sub.len() > 255 {
            return Err(UpstreamError::IdToken("subject"));
        }
        Ok(claims.sub)
    }
}
