//! GitHub (OAuth 2.0) and OpenID Connect providers, such as Google, as upstream identity
//! providers.
//!
//! Each yields one thing: the provider's stable identifier for the account (GitHub's numeric user
//! ID, the OpenID `sub`), never a login name or email address, which can change hands.
//!
//! An OpenID provider is known by its issuer only. Its endpoints come from its discovery document
//! ([OIDC Discovery] §4), which must name the same issuer (§4.3) and https endpoints (§3). If the
//! document cannot be read or does not check out, the sign-in fails. There are no fixed endpoints
//! to fall back to.
//!
//! The ID token is validated as [OIDC Core] §3.1.3.7 requires of a client: signature with a key
//! from the JWK set that discovery names, `iss` equal to the issuer, `aud` exactly the client ID
//! (no other audience is trusted) and `azp`, if present, equal to it, not expired, and `nonce`
//! equal to the one sent. Codes are exchanged with PKCE ([RFC 7636]) for every provider, and the
//! client authenticates with `client_secret_post` ([RFC 6749] §2.3.1).
//!
//! # References
//!
//! - [OIDC Discovery] N. Sakimura, J. Bradley, M. Jones, and E. Jay, "OpenID Connect Discovery 1.0
//!   incorporating errata set 2," OpenID Foundation, Dec. 2023.
//! - [OIDC Core] N. Sakimura, J. Bradley, M. Jones, B. de Medeiros, and C. Mortimore, "OpenID
//!   Connect Core 1.0 incorporating errata set 2," OpenID Foundation, Dec. 2023.
//! - [RFC 7636] N. Sakimura, J. Bradley, and N. Agarwal, "Proof Key for Code Exchange by OAuth
//!   Public Clients," RFC 7636, Sep. 2015.
//! - [RFC 6749] D. Hardt, Ed., "The OAuth 2.0 Authorization Framework," RFC 6749, Oct. 2012.
//!
//! [OIDC Discovery]: https://openid.net/specs/openid-connect-discovery-1_0.html
//! [OIDC Core]: https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation
//! [RFC 7636]: https://www.rfc-editor.org/rfc/rfc7636.html
//! [RFC 6749]: https://www.rfc-editor.org/rfc/rfc6749.html

use std::sync::Mutex;
use std::time::Duration;

use axum::body::Bytes;
use axum::http::{Method, Request, StatusCode, header};
use serde::Deserialize;
use thiserror::Error;
use zeabur_identity_api::credential::CredentialType;
use zeabur_identity_api::upstream::{ExternalId, InvalidValue, Issuer, ProviderId, Subject};
use zeabur_identity_core::clock::UnixTime;
use zeabur_identity_keys::Algorithm;
use zeabur_identity_keys::verify::{VerificationKey, VerifyError, parse_jwk_set, verify_compact};
use zeabur_identity_ui::pages::ProviderButton;

use super::http::{HttpClient, HttpError};

/// How long a discovery document is reused before it is fetched again.
const METADATA_MAX_AGE: Duration = Duration::from_hours(1);
/// How long a JWK set is reused before it is fetched again.
const JWKS_MAX_AGE: Duration = Duration::from_hours(1);
/// An unknown `kid` refetches the set, but not more often than this.
const JWKS_MIN_REFRESH: Duration = Duration::from_mins(1);
/// Clock skew tolerated on `exp` and `iat`.
const LEEWAY: u64 = 60;
/// Google's issuer.
pub const GOOGLE_ISSUER: &str = "https://accounts.google.com";

/// A supported provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Kind {
    /// GitHub.
    GitHub,
    /// Google.
    Google,
}

impl Kind {
    /// The path segment and CLI name: the default [`Provider::id`].
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
    pub const fn button(self) -> ProviderButton<'static> {
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

    /// The issuer of the public service: GitHub's, and Google's default for `--google-issuer`.
    #[must_use]
    pub const fn issuer(self) -> &'static str {
        match self {
            Self::GitHub => "https://github.com",
            Self::Google => GOOGLE_ISSUER,
        }
    }
}

/// An upstream provider that the account page offers to link: its ID, the name it is shown with
/// and its icon. A provider list gives one for each provider that a user can link now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Descriptor {
    /// The provider's ID. The account page sends it to `POST /account/links/start`.
    pub id: ProviderId,
    /// The name shown on its button.
    pub label: String,
    /// The icon on its button (see `zeabur-identity-ui`'s `templates/icons.html`).
    pub icon: &'static str,
}

impl Descriptor {
    /// Its button.
    #[must_use]
    pub fn button(&self) -> ProviderButton<'_> {
        ProviderButton {
            id: self.id.as_str(),
            label: &self.label,
            icon: self.icon,
        }
    }
}

/// Where GitHub's endpoints are. GitHub has no discovery document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitHubEndpoints {
    /// Authorization endpoint.
    pub authorize: String,
    /// Token endpoint.
    pub token: String,
    /// The authenticated-user endpoint.
    pub user: String,
}

impl GitHubEndpoints {
    /// The endpoints of github.com.
    #[must_use]
    pub fn github_com() -> Self {
        Self {
            authorize: "https://github.com/login/oauth/authorize".to_owned(),
            token: "https://github.com/login/oauth/access_token".to_owned(),
            user: "https://api.github.com/user".to_owned(),
        }
    }
}

/// The members of a discovery document that a client needs ([OIDC Discovery] §3).
///
/// [OIDC Discovery]: https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
#[derive(Debug, Clone, Deserialize)]
struct Metadata {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    jwks_uri: String,
}

/// Fetched values of an OpenID provider, each with the time it was fetched.
#[derive(Debug, Default)]
struct OpenIdCache {
    metadata: Mutex<Option<(UnixTime, Metadata)>>,
    /// The JWK set, with the `jwks_uri` it came from.
    jwks: Mutex<Option<(UnixTime, String, Vec<VerificationKey>)>>,
}

#[derive(Debug)]
enum Protocol {
    GitHub(GitHubEndpoints),
    OpenId(OpenIdCache),
}

/// A configured provider.
pub struct Provider {
    kind: Kind,
    id: ProviderId,
    issuer: Issuer,
    client_id: String,
    client_secret: String,
    protocol: Protocol,
}

impl std::fmt::Debug for Provider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Provider")
            .field("kind", &self.kind)
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
    /// The provider's discovery document could not be read or does not check out.
    #[error("the provider's discovery document is not usable: {0}")]
    Discovery(&'static str),
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

/// The values of one authorization request that [`Provider::authorize_url`] puts in the URL.
#[derive(Debug, Clone, Copy)]
pub struct Authorization<'a> {
    /// Where the provider sends the browser back.
    pub redirect_uri: &'a str,
    /// The `state` value.
    pub state: &'a str,
    /// The `nonce` value (OpenID).
    pub nonce: &'a str,
    /// The PKCE `S256` challenge.
    pub challenge: &'a str,
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
    /// The nonce sent (OpenID).
    pub nonce: &'a str,
}

/// The URL of the discovery document of `issuer`: the issuer without a final `/`, then
/// `/.well-known/openid-configuration` ([OIDC Discovery] §4.1).
///
/// [OIDC Discovery]: https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationRequest
fn discovery_url(issuer: &Issuer) -> String {
    format!(
        "{}/.well-known/openid-configuration",
        issuer.as_str().trim_end_matches('/')
    )
}

/// Whether `value` is an absolute https URL with a host. [OIDC Discovery] §3 requires https for
/// the authorization endpoint and the JWK set. The token endpoint receives the client secret, so
/// it needs https too.
///
/// [OIDC Discovery]: https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
fn is_https_url(value: &str) -> bool {
    url::Url::parse(value).is_ok_and(|url| url.scheme() == "https" && url.host().is_some())
}

impl Provider {
    /// GitHub, at [`Kind::id`] and with [`Kind::issuer`].
    ///
    /// # Errors
    ///
    /// [`InvalidValue`] if the ID or the issuer is malformed.
    pub fn github(
        client_id: String,
        client_secret: String,
        endpoints: GitHubEndpoints,
    ) -> Result<Self, InvalidValue> {
        Ok(Self {
            kind: Kind::GitHub,
            id: ProviderId::new(Kind::GitHub.id())?,
            issuer: Issuer::new(Kind::GitHub.issuer())?,
            client_id,
            client_secret,
            protocol: Protocol::GitHub(endpoints),
        })
    }

    /// The OpenID provider at `issuer`, shown as Google. Its endpoints come from the discovery
    /// document of `issuer`.
    ///
    /// # Errors
    ///
    /// [`InvalidValue`] if the ID is malformed.
    pub fn google(
        issuer: Issuer,
        client_id: String,
        client_secret: String,
    ) -> Result<Self, InvalidValue> {
        Ok(Self {
            kind: Kind::Google,
            id: ProviderId::new(Kind::Google.id())?,
            issuer,
            client_id,
            client_secret,
            protocol: Protocol::OpenId(OpenIdCache::default()),
        })
    }

    /// Which provider.
    #[must_use]
    pub const fn kind(&self) -> Kind {
        self.kind
    }

    /// How the account page offers it.
    #[must_use]
    pub fn descriptor(&self) -> Descriptor {
        Descriptor {
            id: self.id.clone(),
            label: self.kind.label().to_owned(),
            icon: self.kind.icon(),
        }
    }

    /// The path segment of its routes.
    #[must_use]
    pub const fn id(&self) -> &ProviderId {
        &self.id
    }

    /// The issuer of its accounts.
    #[must_use]
    pub const fn issuer(&self) -> &Issuer {
        &self.issuer
    }

    /// The authorization request URL. An OpenID provider's authorization endpoint comes from its
    /// discovery document.
    ///
    /// # Errors
    ///
    /// [`UpstreamError`] if the discovery document cannot be read or does not check out.
    pub async fn authorize_url<H: HttpClient>(
        &self,
        http: &H,
        now: UnixTime,
        request: Authorization<'_>,
    ) -> Result<String, UpstreamError> {
        let endpoint = match &self.protocol {
            Protocol::GitHub(endpoints) => endpoints.authorize.clone(),
            Protocol::OpenId(cache) => {
                self.metadata(cache, http, now)
                    .await?
                    .authorization_endpoint
            }
        };
        let mut query = form_urlencoded::Serializer::new(String::new());
        query
            .append_pair("client_id", &self.client_id)
            .append_pair("redirect_uri", request.redirect_uri)
            .append_pair("response_type", "code")
            .append_pair("state", request.state)
            .append_pair("code_challenge", request.challenge)
            .append_pair("code_challenge_method", "S256");
        match self.protocol {
            // No scope: only the public profile (and with it the numeric ID) is needed.
            Protocol::GitHub(_) => {
                query.append_pair("allow_signup", "false");
            }
            Protocol::OpenId(_) => {
                query
                    .append_pair("scope", "openid")
                    .append_pair("nonce", request.nonce)
                    .append_pair("prompt", "select_account");
            }
        }
        let separator = if endpoint.contains('?') { '&' } else { '?' };
        Ok(format!("{endpoint}{separator}{}", query.finish()))
    }

    /// Exchanges the code and returns the account: this provider's issuer and the account's stable
    /// identifier.
    ///
    /// # Errors
    ///
    /// [`UpstreamError`] if the provider fails or its answer does not check out.
    pub async fn identify<H: HttpClient>(
        &self,
        http: &H,
        exchange: Exchange<'_>,
        now: UnixTime,
    ) -> Result<ExternalId, UpstreamError> {
        let subject = match &self.protocol {
            Protocol::GitHub(endpoints) => {
                let tokens = self.redeem(http, &endpoints.token, exchange).await?;
                let access = tokens
                    .access_token
                    .ok_or(UpstreamError::Protocol("no access token"))?;
                github_user(http, &endpoints.user, &access).await?
            }
            Protocol::OpenId(cache) => {
                let metadata = self.metadata(cache, http, now).await?;
                let tokens = self
                    .redeem(http, &metadata.token_endpoint, exchange)
                    .await?;
                let id_token = tokens
                    .id_token
                    .ok_or(UpstreamError::Protocol("no ID token"))?;
                self.openid_subject(
                    cache,
                    http,
                    &metadata.jwks_uri,
                    &id_token,
                    exchange.nonce,
                    now,
                )
                .await?
            }
        };
        Ok(ExternalId {
            issuer: self.issuer.clone(),
            subject,
        })
    }

    /// Sends the token request for `exchange`.
    async fn redeem<H: HttpClient>(
        &self,
        http: &H,
        token_endpoint: &str,
        exchange: Exchange<'_>,
    ) -> Result<TokenResponse, UpstreamError> {
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
            .uri(token_endpoint)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(header::ACCEPT, "application/json")
            .body(Bytes::from(form))
            .map_err(|_request| UpstreamError::Protocol("token endpoint URL"))?;
        let response = http.send(request).await?;
        if response.status() != StatusCode::OK {
            return Err(UpstreamError::Protocol("the token request was refused"));
        }
        serde_json::from_slice(response.body())
            .map_err(|_json| UpstreamError::Protocol("token response"))
    }

    /// The discovery document of this provider's issuer, fetched again after
    /// [`METADATA_MAX_AGE`].
    ///
    /// The document's `issuer` must be identical to the configured issuer ([OIDC Discovery]
    /// §4.3), and its endpoints must be https URLs (§3).
    ///
    /// [OIDC Discovery]: https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationValidation
    async fn metadata<H: HttpClient>(
        &self,
        cache: &OpenIdCache,
        http: &H,
        now: UnixTime,
    ) -> Result<Metadata, UpstreamError> {
        let cached = cache
            .metadata
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        if let Some((fetched, metadata)) = cached
            && now.as_secs().saturating_sub(fetched.as_secs()) < METADATA_MAX_AGE.as_secs()
        {
            return Ok(metadata);
        }
        let request = Request::builder()
            .uri(discovery_url(&self.issuer))
            .header(header::ACCEPT, "application/json")
            .body(Bytes::new())
            .map_err(|_request| UpstreamError::Discovery("URL"))?;
        let response = http.send(request).await?;
        if response.status() != StatusCode::OK {
            return Err(UpstreamError::Discovery("the request was refused"));
        }
        let metadata: Metadata = serde_json::from_slice(response.body())
            .map_err(|_json| UpstreamError::Discovery("not a discovery document"))?;
        if metadata.issuer != self.issuer.as_str() {
            return Err(UpstreamError::Discovery("issuer"));
        }
        if ![
            &metadata.authorization_endpoint,
            &metadata.token_endpoint,
            &metadata.jwks_uri,
        ]
        .into_iter()
        .all(|endpoint| is_https_url(endpoint))
        {
            return Err(UpstreamError::Discovery("endpoint not https"));
        }
        *cache
            .metadata
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some((now, metadata.clone()));
        Ok(metadata)
    }

    /// Whether `iss` names this provider's issuer ([OIDC Core] §3.1.3.7 step 2: "MUST exactly
    /// match").
    ///
    /// Google's documentation lists two forms of its issuer, so Google's ID tokens may also carry
    /// `accounts.google.com`. The account keeps the configured issuer either way.
    ///
    /// [OIDC Core]: https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation
    fn accepts_issuer(&self, iss: &str) -> bool {
        iss == self.issuer.as_str()
            || (self.issuer.as_str() == GOOGLE_ISSUER && iss == "accounts.google.com")
    }

    async fn openid_subject<H: HttpClient>(
        &self,
        cache: &OpenIdCache,
        http: &H,
        jwks_uri: &str,
        id_token: &str,
        nonce: &str,
        now: UnixTime,
    ) -> Result<Subject, UpstreamError> {
        const ALGORITHMS: [Algorithm; 2] = [Algorithm::Rs256, Algorithm::Es256];
        let keys = jwk_set(cache, http, jwks_uri, now, false).await?;
        let verified = match verify_compact(id_token, &keys, &ALGORITHMS) {
            Err(VerifyError::UnknownKey) => {
                // Keys rotate: fetch again once.
                let keys = jwk_set(cache, http, jwks_uri, now, true).await?;
                verify_compact(id_token, &keys, &ALGORITHMS)
            }
            other => other,
        };
        let (_header, payload) =
            verified.map_err(|_invalid| UpstreamError::IdToken("signature"))?;
        let claims: IdClaims =
            serde_json::from_slice(&payload).map_err(|_json| UpstreamError::IdToken("claims"))?;
        if !self.accepts_issuer(&claims.iss) {
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
        Subject::new(claims.sub).map_err(|_invalid| UpstreamError::IdToken("subject"))
    }
}

async fn github_user<H: HttpClient>(
    http: &H,
    url: &str,
    access_token: &str,
) -> Result<Subject, UpstreamError> {
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
    Subject::new(user.id.to_string()).map_err(|_invalid| UpstreamError::Protocol("user ID"))
}

/// The JWK set at `uri`. A set from another `uri` is not reused.
async fn jwk_set<H: HttpClient>(
    cache: &OpenIdCache,
    http: &H,
    uri: &str,
    now: UnixTime,
    refresh: bool,
) -> Result<Vec<VerificationKey>, UpstreamError> {
    let cached = cache
        .jwks
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    if let Some((fetched, from, keys)) = &cached
        && from == uri
    {
        let age = now.as_secs().saturating_sub(fetched.as_secs());
        let fresh = age < JWKS_MAX_AGE.as_secs();
        let recently = age < JWKS_MIN_REFRESH.as_secs();
        if (fresh && !refresh) || recently {
            return Ok(keys.clone());
        }
    }
    let request = Request::builder()
        .uri(uri)
        .body(Bytes::new())
        .map_err(|_request| UpstreamError::Protocol("JWK set URL"))?;
    let response = http.send(request).await?;
    if response.status() != StatusCode::OK {
        return Err(UpstreamError::Protocol("the JWK set request was refused"));
    }
    let keys =
        parse_jwk_set(response.body()).map_err(|_jwks| UpstreamError::Protocol("JWK set"))?;
    *cache
        .jwks
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) =
        Some((now, uri.to_owned(), keys.clone()));
    Ok(keys)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_discovery_url_drops_a_final_slash_of_the_issuer() {
        for (issuer, url) in [
            (
                "https://accounts.google.com",
                "https://accounts.google.com/.well-known/openid-configuration",
            ),
            (
                "https://idp.example/realms/dev/",
                "https://idp.example/realms/dev/.well-known/openid-configuration",
            ),
        ] {
            assert_eq!(discovery_url(&Issuer::new(issuer).unwrap()), url);
        }
    }

    #[test]
    fn only_google_accepts_the_issuer_without_a_scheme() {
        let google =
            Provider::google(Issuer::new(GOOGLE_ISSUER).unwrap(), "c".into(), "s".into()).unwrap();
        let other = Provider::google(
            Issuer::new("https://idp.example").unwrap(),
            "c".into(),
            "s".into(),
        )
        .unwrap();
        assert!(google.accepts_issuer("https://accounts.google.com"));
        assert!(google.accepts_issuer("accounts.google.com"));
        assert!(!google.accepts_issuer("https://accounts.google.com/"));
        assert!(other.accepts_issuer("https://idp.example"));
        assert!(!other.accepts_issuer("idp.example"));
        assert!(!other.accepts_issuer("accounts.google.com"));
        assert!(!other.accepts_issuer("https://idp.example/"));
    }
}
