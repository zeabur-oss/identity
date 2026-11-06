//! Upstream identity providers, each an `UpstreamProvider` object: GitHub (OAuth 2.0), Google,
//! or any OpenID Connect provider.
//!
//! Each yields one thing: the provider's stable identifier for the account (GitHub's numeric user
//! ID, the `sub` of an OpenID Connect provider), never a login name or email address, which can
//! change hands. A linked account is keyed by the issuer and that identifier.
//!
//! An ID token is validated as OpenID Connect Core 1.0 §3.1.3.7 requires of a client: signature
//! with a key from the provider's published JWK set, `iss` the provider's issuer, `aud` exactly
//! the client ID (no other audience is trusted) and `azp`, if present, equal to it, not expired,
//! and `nonce` equal to the one sent. Codes are exchanged with PKCE (RFC 7636).
//!
//! A configured OpenID Connect provider's endpoints come from its discovery document
//! ([OpenID Connect Discovery 1.0] §4), whose `issuer` must equal the configured issuer exactly
//! (§4.3), so a document cannot point sign-in at another issuer's tokens. The client
//! authenticates with `client_secret_basic`, which every authorization server supports
//! (RFC 6749 §2.3.1), unless the document lists only `client_secret_post`. GitHub and Google take
//! `client_secret_post`.
//!
//! [OpenID Connect Discovery 1.0]: https://openid.net/specs/openid-connect-discovery-1_0.html

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use axum::body::Bytes;
use axum::http::{HeaderValue, Method, Request, StatusCode, header};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde::Deserialize;
use thiserror::Error;
use zeabur_identity_core::clock::UnixTime;
use zeabur_identity_keys::Algorithm;
use zeabur_identity_keys::verify::{VerificationKey, parse_jwk_set, verify_compact};
use zeabur_identity_store::CredentialType;
use zeabur_identity_ui::pages::ProviderButton;

use super::http::{HttpClient, HttpError};

/// How long a discovery document is reused before it is fetched again.
const DISCOVERY_MAX_AGE: Duration = Duration::from_hours(1);
/// How long a JWK set is reused before it is fetched again.
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
    /// An OpenID Connect provider configured by an admin.
    Oidc,
}

impl Kind {
    /// The icon on its button.
    #[must_use]
    pub const fn icon(self) -> &'static str {
        match self {
            Self::GitHub => "GithubLogo",
            Self::Google => "GoogleLogo",
            Self::Oidc => "IdentificationBadge",
        }
    }

    /// The `Credential` type of a linked account.
    #[must_use]
    pub const fn credential_type(self) -> CredentialType {
        match self {
            Self::GitHub => CredentialType::GitHub,
            Self::Google => CredentialType::Google,
            Self::Oidc => CredentialType::Oidc,
        }
    }
}

/// How the client authenticates at the token endpoint (RFC 6749 §2.3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenAuth {
    /// `client_secret_basic`: HTTP Basic.
    Basic,
    /// `client_secret_post`: in the form body.
    Post,
}

/// Where a provider's endpoints are. Fixed for GitHub and Google, discovered for configured
/// providers; tests point them elsewhere.
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
    /// Accepted `iss` values.
    pub issuers: Vec<String>,
    /// Client authentication at the token endpoint.
    pub token_auth: TokenAuth,
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
            token_auth: TokenAuth::Post,
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
            token_auth: TokenAuth::Post,
        }
    }
}

/// A future yielding a client secret, or why it could not be read.
pub type SecretFuture = Pin<Box<dyn Future<Output = Result<String, String>> + Send>>;

/// Where a provider's client secret comes from.
#[derive(Clone)]
pub enum ClientSecret {
    /// Read once at startup.
    Fixed(String),
    /// Read at each code exchange, so a rotated secret applies without a restart.
    Fetch(Arc<dyn Fn() -> SecretFuture + Send + Sync>),
}

impl From<String> for ClientSecret {
    fn from(secret: String) -> Self {
        Self::Fixed(secret)
    }
}

impl std::fmt::Debug for ClientSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Fixed(_) => "ClientSecret::Fixed",
            Self::Fetch(_) => "ClientSecret::Fetch",
        })
    }
}

impl ClientSecret {
    async fn read(&self) -> Result<String, UpstreamError> {
        match self {
            Self::Fixed(secret) => Ok(secret.clone()),
            Self::Fetch(fetch) => fetch().await.map_err(|error| {
                tracing::error!(reason = "client_secret_unavailable", %error, "reading the upstream client secret failed");
                UpstreamError::Protocol("client secret unavailable")
            }),
        }
    }
}

/// Where a provider's endpoints come from.
#[derive(Debug)]
enum Source {
    Fixed(Endpoints),
    Discovered(Mutex<Option<(UnixTime, Endpoints)>>),
}

/// A configured provider.
pub struct Provider {
    id: String,
    label: String,
    kind: Kind,
    issuer: String,
    client_id: String,
    client_secret: ClientSecret,
    endpoints: Source,
    jwks: Mutex<Option<(UnixTime, Vec<VerificationKey>)>>,
}

impl std::fmt::Debug for Provider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Provider")
            .field("id", &self.id)
            .field("issuer", &self.issuer)
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

/// The fields of a discovery document this client uses ([OpenID Connect Discovery 1.0] §3).
///
/// [OpenID Connect Discovery 1.0]: https://openid.net/specs/openid-connect-discovery-1_0.html
#[derive(Deserialize)]
struct Discovery {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    jwks_uri: String,
    #[serde(default)]
    token_endpoint_auth_methods_supported: Option<Vec<String>>,
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
    /// The nonce sent (OpenID Connect).
    pub nonce: &'a str,
}

impl Provider {
    /// GitHub, with its OAuth app, as `github`. `endpoints` are [`Endpoints::github`] outside
    /// tests.
    #[must_use]
    pub fn github(
        client_id: String,
        client_secret: impl Into<ClientSecret>,
        endpoints: Endpoints,
    ) -> Self {
        Self::fixed(
            Kind::GitHub,
            "GitHub",
            "https://github.com",
            client_id,
            client_secret,
            endpoints,
        )
    }

    /// Google, with its OAuth client, as `google`. `endpoints` are [`Endpoints::google`] outside
    /// tests.
    #[must_use]
    pub fn google(
        client_id: String,
        client_secret: impl Into<ClientSecret>,
        endpoints: Endpoints,
    ) -> Self {
        Self::fixed(
            Kind::Google,
            "Google",
            "https://accounts.google.com",
            client_id,
            client_secret,
            endpoints,
        )
    }

    fn fixed(
        kind: Kind,
        label: &str,
        issuer: &str,
        client_id: String,
        client_secret: impl Into<ClientSecret>,
        endpoints: Endpoints,
    ) -> Self {
        Self {
            id: label.to_ascii_lowercase(),
            label: label.to_owned(),
            kind,
            issuer: issuer.to_owned(),
            client_id,
            client_secret: client_secret.into(),
            endpoints: Source::Fixed(endpoints),
            jwks: Mutex::new(None),
        }
    }

    /// An OpenID Connect provider whose endpoints are discovered from `issuer`.
    #[must_use]
    pub const fn oidc(
        id: String,
        label: String,
        issuer: String,
        client_id: String,
        client_secret: ClientSecret,
    ) -> Self {
        Self {
            id,
            label,
            kind: Kind::Oidc,
            issuer,
            client_id,
            client_secret,
            endpoints: Source::Discovered(Mutex::new(None)),
            jwks: Mutex::new(None),
        }
    }

    /// The same provider under another ID and button name.
    #[must_use]
    pub fn named(mut self, id: String, label: String) -> Self {
        self.id = id;
        self.label = label;
        self
    }

    /// Which kind of provider.
    #[must_use]
    pub const fn kind(&self) -> Kind {
        self.kind
    }

    /// The path segment of its routes.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// The name shown on buttons.
    #[must_use]
    pub fn label(&self) -> &str {
        &self.label
    }

    /// The issuer recorded with a linked account.
    #[must_use]
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// The client ID registered at the provider.
    #[must_use]
    pub fn client_id(&self) -> &str {
        &self.client_id
    }

    /// Its button on the sign-in pages.
    #[must_use]
    pub fn button(&self) -> ProviderButton<'_> {
        ProviderButton {
            id: &self.id,
            label: &self.label,
            icon: self.kind.icon(),
        }
    }

    /// The provider's endpoints: fixed, or from its discovery document.
    ///
    /// # Errors
    ///
    /// [`UpstreamError`] if the discovery document cannot be read or names another issuer.
    pub async fn endpoints<H: HttpClient>(
        &self,
        http: &H,
        now: UnixTime,
    ) -> Result<Endpoints, UpstreamError> {
        let cache = match &self.endpoints {
            Source::Fixed(endpoints) => return Ok(endpoints.clone()),
            Source::Discovered(cache) => cache,
        };
        let cached = cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        if let Some((fetched, endpoints)) = cached
            && now.as_secs().saturating_sub(fetched.as_secs()) < DISCOVERY_MAX_AGE.as_secs()
        {
            return Ok(endpoints);
        }
        let url = format!(
            "{}/.well-known/openid-configuration",
            self.issuer.trim_end_matches('/')
        );
        let request = Request::builder()
            .uri(&url)
            .header(header::ACCEPT, "application/json")
            .body(Bytes::new())
            .map_err(|_request| UpstreamError::Protocol("discovery URL"))?;
        let response = http.send(request).await?;
        if response.status() != StatusCode::OK {
            return Err(UpstreamError::Protocol("the discovery request was refused"));
        }
        let endpoints = self.discovered(response.body())?;
        *cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some((now, endpoints.clone()));
        Ok(endpoints)
    }

    /// Checks a discovery document and takes its endpoints.
    fn discovered(&self, body: &[u8]) -> Result<Endpoints, UpstreamError> {
        let document: Discovery = serde_json::from_slice(body)
            .map_err(|_json| UpstreamError::Protocol("discovery document"))?;
        // §4.3: "MUST be identical to the Issuer URL that was used as the prefix".
        if document.issuer != self.issuer {
            return Err(UpstreamError::Protocol(
                "the discovery document names another issuer",
            ));
        }
        let token_auth = match document.token_endpoint_auth_methods_supported.as_deref() {
            Some(methods)
                if !methods.iter().any(|m| m == "client_secret_basic")
                    && methods.iter().any(|m| m == "client_secret_post") =>
            {
                TokenAuth::Post
            }
            _ => TokenAuth::Basic,
        };
        Ok(Endpoints {
            authorize: document.authorization_endpoint,
            token: document.token_endpoint,
            user: None,
            jwks: Some(document.jwks_uri),
            issuers: vec![document.issuer],
            token_auth,
        })
    }

    /// The authorization request URL.
    #[must_use]
    pub fn authorize_url(
        &self,
        endpoints: &Endpoints,
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
            Kind::Oidc => {
                query
                    .append_pair("scope", "openid")
                    .append_pair("nonce", nonce);
            }
        }
        let separator = if endpoints.authorize.contains('?') {
            '&'
        } else {
            '?'
        };
        format!("{}{separator}{}", endpoints.authorize, query.finish())
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
        let endpoints = self.endpoints(http, now).await?;
        let secret = self.client_secret.read().await?;
        let request = self.token_request(&endpoints, exchange, &secret)?;
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
                self.github_user(http, &endpoints, &access).await
            }
            Kind::Google | Kind::Oidc => {
                let id_token = tokens
                    .id_token
                    .ok_or(UpstreamError::Protocol("no ID token"))?;
                self.id_token_subject(http, &endpoints, &id_token, exchange.nonce, now)
                    .await
            }
        }
    }

    /// The token request for `exchange`, with the client's credentials.
    fn token_request(
        &self,
        endpoints: &Endpoints,
        exchange: Exchange<'_>,
        secret: &str,
    ) -> Result<Request<Bytes>, UpstreamError> {
        let mut form = form_urlencoded::Serializer::new(String::new());
        form.append_pair("grant_type", "authorization_code")
            .append_pair("code", exchange.code)
            .append_pair("redirect_uri", exchange.redirect_uri)
            .append_pair("code_verifier", exchange.verifier);
        let mut request = Request::builder()
            .method(Method::POST)
            .uri(&endpoints.token)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(header::ACCEPT, "application/json");
        match endpoints.token_auth {
            TokenAuth::Post => {
                form.append_pair("client_id", &self.client_id)
                    .append_pair("client_secret", secret);
            }
            TokenAuth::Basic => {
                request = request.header(
                    header::AUTHORIZATION,
                    basic_authorization(&self.client_id, secret)?,
                );
            }
        }
        request
            .body(Bytes::from(form.finish()))
            .map_err(|_request| UpstreamError::Protocol("token endpoint URL"))
    }

    async fn github_user<H: HttpClient>(
        &self,
        http: &H,
        endpoints: &Endpoints,
        access_token: &str,
    ) -> Result<String, UpstreamError> {
        let url = endpoints
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
        endpoints: &Endpoints,
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
        let url = endpoints
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

    async fn id_token_subject<H: HttpClient>(
        &self,
        http: &H,
        endpoints: &Endpoints,
        id_token: &str,
        nonce: &str,
        now: UnixTime,
    ) -> Result<String, UpstreamError> {
        const ALGORITHMS: [Algorithm; 2] = [Algorithm::Rs256, Algorithm::Es256];
        let keys = self.keys(http, endpoints, now, false).await?;
        let verified = match verify_compact(id_token, &keys, &ALGORITHMS) {
            Err(zeabur_identity_keys::verify::VerifyError::UnknownKey) => {
                // Keys rotate: fetch again once.
                let keys = self.keys(http, endpoints, now, true).await?;
                verify_compact(id_token, &keys, &ALGORITHMS)
            }
            other => other,
        };
        let (_header, payload) =
            verified.map_err(|_invalid| UpstreamError::IdToken("signature"))?;
        let claims: IdClaims =
            serde_json::from_slice(&payload).map_err(|_json| UpstreamError::IdToken("claims"))?;
        if !endpoints.issuers.contains(&claims.iss) {
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

/// `Authorization: Basic` for `client_secret_basic`: each part form-urlencoded first
/// (RFC 6749 §2.3.1).
fn basic_authorization(client_id: &str, secret: &str) -> Result<HeaderValue, UpstreamError> {
    let encode = |part: &str| form_urlencoded::byte_serialize(part.as_bytes()).collect::<String>();
    let credentials = format!("{}:{}", encode(client_id), encode(secret));
    HeaderValue::try_from(format!("Basic {}", STANDARD.encode(credentials)))
        .map_err(|_header| UpstreamError::Protocol("client credentials"))
}

/// The enabled providers, the `UpstreamProvider` objects, which change while the server runs.
#[derive(Debug, Default)]
pub struct Providers {
    configured: RwLock<Vec<Arc<Provider>>>,
}

impl Providers {
    /// These providers, until [`Providers::set_configured`] replaces them.
    #[must_use]
    pub fn new(providers: Vec<Provider>) -> Self {
        Self {
            configured: RwLock::new(providers.into_iter().map(Arc::new).collect()),
        }
    }

    /// Replaces the providers.
    pub fn set_configured(&self, providers: Vec<Arc<Provider>>) {
        *self
            .configured
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = providers;
    }

    /// Every enabled provider, in a stable order.
    #[must_use]
    pub fn all(&self) -> Vec<Arc<Provider>> {
        self.configured
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// The provider with this ID.
    #[must_use]
    pub fn find(&self, id: &str) -> Option<Arc<Provider>> {
        self.all().into_iter().find(|provider| provider.id() == id)
    }

    /// The provider a linked account came from, by its `Credential` type and issuer.
    #[must_use]
    pub fn for_credential(&self, kind: CredentialType, issuer: &str) -> Option<Arc<Provider>> {
        self.all().into_iter().find(|provider| {
            provider.kind().credential_type() == kind
                && (kind != CredentialType::Oidc || provider.issuer() == issuer)
        })
    }
}
