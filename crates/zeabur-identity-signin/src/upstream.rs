//! Signing in with an upstream identity provider (GitHub, an OpenID provider such as Google), and
//! linking such an account to a user with an enrolment link or from the account page.
//!
//! | Route | Purpose |
//! |---|---|
//! | `POST /upstream/{provider}/start` | JSON: begin sign-in, or linking with `token` |
//! | `POST /account/links/start` | JSON: begin linking to the signed-in user |
//! | `GET /upstream/{provider}/callback` | the provider's redirect: finish |
//!
//! An account signs in as a user only if it was linked to that user: by redeeming an
//! invitation or setup link with it, by the user on the account page, or by an admin creating
//! the `Credential`. Nothing is created on first sign-in.
//!
//! Linking from the account page gives control of the account to whoever controls the upstream
//! account, so it has the same gate as adding a passkey:
//!
//! 1. The start needs the account session, its CSRF token and a user-verified passkey confirmation
//!    from the last [`REAUTH_WINDOW`](crate::account::REAUTH_WINDOW). Under the `admin-aal3`
//!    setting, only a device-bound passkey confirms an admin account.
//! 2. The pending request names the session, the user and the user's UID. The callback finishes
//!    only if the browser still sends that session. RFC 6749 §10.12 asks for this binding of
//!    `state` to "the user-agent's authenticated state". A provider answer thus cannot link an
//!    account to another session.
//! 3. An account linked to anyone already, this user included, is refused. Admin accounts are
//!    refused at the start and again at the callback.
//! 4. The link names the user's UID, as an enrolment link does. The change is logged and recorded
//!    as an `AccountLinked` event on the user.
//!
//! Upstream sign-ins carry no `amr` value (RFC 8176 defines none for federation). Admin accounts
//! sign in with a passkey only, so they can neither sign in nor link an account here.
//!
//! A link names its `User` by UID as well as by name. After a delete, a new object can have the
//! same name, but every object gets a distinct UID ([Object Names and IDs]). Thus a link left
//! over from a removed person does not sign in as a new person with the same username.
//!
//! The pending request (`state`, `nonce`, PKCE verifier and purpose) is sealed into a `__Host-`
//! cookie with `SameSite=Lax`, the strictest setting that still accompanies the provider's
//! top-level redirect back. `state` is compared in constant time and accepted once
//! (RFC 6749 §10.12, RFC 9700 §2.1). The callback answers with HTML; errors never echo the
//! provider's text.
//!
//! [Object Names and IDs]: https://kubernetes.io/docs/concepts/overview/working-with-objects/names/

pub mod http;
pub mod provider;

use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::body::Bytes;
use axum::extract::{Path, RawQuery, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};
use zeabur_identity_api::upstream::ProviderId;
use zeabur_identity_core::account::Method;
use zeabur_identity_core::clock::{Clock, UnixTime};
use zeabur_identity_core::crypto::{ct_eq, hex, random, sha256};
use zeabur_identity_oauth::authorize::Authentication;
use zeabur_identity_oauth::endpoints::{FLOW_COOKIE, complete_authorization, open_flow};
use zeabur_identity_oauth::{OneTimeIds, Use};
use zeabur_identity_store::{
    Consume, CreateCredential, CredentialStore, Directory, GrantStore, NewExternal, SetupStore,
    User, external_credential_name,
};
use zeabur_identity_ui::i18n::Lang;
use zeabur_identity_ui::pages::{ErrorReason, accept_language, error_page, notice_page};

use self::http::HttpClient;
use self::provider::{Authorization, Exchange, Kind, Provider, UpstreamError};
use crate::account::{Account, Audit, current, log_outcome, record, require_fresh, signed_in};
use crate::device::Requester;
use crate::problem::Problem;
use crate::{
    NO_REQUEST, SignIn, check_account, check_request, clear_cookie, cookie, internal, json, parse,
    redeemed, valid_setup_token,
};

/// Cookie holding the sealed pending upstream request.
pub const UPSTREAM_COOKIE: &str = "__Host-zeabur-identity-upstream";
const PURPOSE: &str = "zeabur-identity/upstream/v1";
/// How long the user may spend at the provider.
const LIFETIME: Duration = Duration::from_mins(10);

const UNKNOWN_PROVIDER: Problem = Problem::new(
    StatusCode::NOT_FOUND,
    "unknown-provider",
    "This sign-in provider isn't enabled.",
);
const PROVIDER_UNAVAILABLE: Problem = Problem::new(
    StatusCode::BAD_GATEWAY,
    "provider-unavailable",
    "This sign-in provider is unavailable. Try again later.",
);

/// Upstream sign-in state shared by the handlers.
pub struct Upstream<D, G, C, K, S, H> {
    /// Passkey sign-in (its authorization server, credentials and enrolment tokens).
    pub sign_in: Arc<SignIn<D, G, C, K, S>>,
    /// The enabled providers.
    pub providers: Vec<Provider>,
    /// Outgoing HTTPS.
    pub http: H,
    /// `state` values already returned by a provider.
    pub used_states: OneTimeIds,
}

impl<D, G, C, K, S, H> std::fmt::Debug for Upstream<D, G, C, K, S, H> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Upstream")
            .field("providers", &self.providers)
            .finish_non_exhaustive()
    }
}

impl<D, G, C, K, S, H> Upstream<D, G, C, K, S, H> {
    /// The enabled provider with this [`Provider::id`].
    fn provider(&self, id: &str) -> Option<&Provider> {
        self.providers.iter().find(|p| p.id().as_str() == id)
    }
}

type Shared<D, G, C, K, S, H> = Arc<Upstream<D, G, C, K, S, H>>;

/// The upstream routes.
pub fn router<D, G, C, K, S, H>(service: Shared<D, G, C, K, S, H>) -> Router
where
    D: Directory,
    G: GrantStore,
    C: Clock,
    K: CredentialStore,
    S: SetupStore,
    H: HttpClient,
{
    Router::new()
        .route(
            "/upstream/{provider}/start",
            post(start::<D, G, C, K, S, H>),
        )
        .route(
            "/upstream/{provider}/callback",
            get(callback::<D, G, C, K, S, H>),
        )
        .route(
            "/account/links/start",
            post(account_start::<D, G, C, K, S, H>),
        )
        .with_state(service)
}

/// Sealed into [`UPSTREAM_COOKIE`].
#[derive(Debug, Serialize, Deserialize)]
struct Pending {
    id: String,
    provider: ProviderId,
    state: String,
    nonce: String,
    verifier: String,
    /// The enrolment token, when linking with one.
    link: Option<String>,
    /// The account session, when linking from the account page.
    #[serde(default)]
    account: Option<Bound>,
    expires_at: UnixTime,
}

/// The account session and user that a link from the account page is for.
#[derive(Debug, Serialize, Deserialize)]
struct Bound {
    /// The `Grant` name of the session.
    session: String,
    user: String,
    /// The user's UID.
    subject: String,
}

impl Bound {
    fn matches(&self, account: &Account) -> bool {
        account.token.name() == self.session
            && account.user.name == self.user
            && account.user.subject == self.subject
    }
}

#[derive(Debug, Deserialize)]
struct StartRequest {
    #[serde(default)]
    token: Option<String>,
}

#[derive(Debug, Serialize)]
struct StartResponse {
    redirect_to: String,
}

fn redirect_uri(issuer: &str, provider: &ProviderId) -> String {
    format!("{issuer}/upstream/{}/callback", provider.as_str())
}

fn random_text<const N: usize>() -> Result<String, Problem> {
    Ok(URL_SAFE_NO_PAD.encode(random::<N>().map_err(internal)?))
}

async fn start<D, G, C, K, S, H>(
    State(service): State<Shared<D, G, C, K, S, H>>,
    Path(provider): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response
where
    D: Directory,
    G: GrantStore,
    C: Clock,
    K: CredentialStore,
    S: SetupStore,
    H: HttpClient,
{
    let normalized_provider = Kind::from_id(&provider).map(Kind::id);
    let result: Result<Response, Problem> = async {
        let sign_in = &service.sign_in;
        check_request(&headers, sign_in.oauth.issuer.as_str())?;
        let provider = service.provider(&provider).ok_or(UNKNOWN_PROVIDER)?;
        let request: StartRequest = parse(&body)?;
        let now = sign_in.oauth.now();
        if let Some(token) = &request.token {
            // Linking: check the link and the account type now, so they fail before the user
            // leaves.
            let (_, user) =
                valid_setup_token(&sign_in.setup, &sign_in.oauth.directory, token, now).await?;
            check_account(&sign_in.oauth.directory, &user, Method::Upstream).await?;
        } else {
            // Signing in: there must be a pending request.
            cookie(&headers, FLOW_COOKIE)
                .and_then(|sealed| open_flow(&sign_in.oauth, sealed))
                .ok_or(NO_REQUEST)?;
        }
        begin(&service, provider, request.token, None, now).await
    }
    .await;
    match &result {
        Ok(_) => {
            tracing::info!(target: "zeabur_identity::audit", event = "auth.upstream_start", outcome = "success", method = "upstream", provider = normalized_provider, "upstream request started");
        }
        Err(problem) => {
            tracing::warn!(target: "zeabur_identity::audit", event = "auth.upstream_start", outcome = "failure", method = "upstream", provider = normalized_provider, reason = problem.kind, "upstream request failed");
        }
    }
    result.unwrap_or_else(IntoResponse::into_response)
}

/// Seals a new pending request into [`UPSTREAM_COOKIE`] and answers with the provider's
/// authorization URL.
async fn begin<D, G, C, K, S, H>(
    service: &Upstream<D, G, C, K, S, H>,
    provider: &Provider,
    link: Option<String>,
    account: Option<Bound>,
    now: UnixTime,
) -> Result<Response, Problem>
where
    D: Directory,
    G: GrantStore,
    C: Clock,
    K: CredentialStore,
    S: SetupStore,
    H: HttpClient,
{
    let sign_in = &service.sign_in;
    let pending = Pending {
        id: hex(&random::<16>().map_err(internal)?),
        provider: provider.id().clone(),
        state: random_text::<32>()?,
        nonce: random_text::<32>()?,
        verifier: random_text::<32>()?,
        link,
        account,
        expires_at: now.saturating_add(LIFETIME),
    };
    let challenge = URL_SAFE_NO_PAD.encode(sha256(pending.verifier.as_bytes()));
    let request = Authorization {
        redirect_uri: &redirect_uri(sign_in.oauth.issuer.as_str(), provider.id()),
        state: &pending.state,
        nonce: &pending.nonce,
        challenge: &challenge,
    };
    let url = provider
        .authorize_url(&service.http, now, request)
        .await
        .map_err(|error| {
            tracing::warn!(reason = "provider_unavailable", %error, "upstream provider unavailable");
            PROVIDER_UNAVAILABLE
        })?;
    let sealed = serde_json::to_vec(&pending)
        .map_err(internal)
        .and_then(|json| sign_in.oauth.sealer.seal(PURPOSE, &json).map_err(internal))?;
    let mut response = json(StatusCode::OK, &StartResponse { redirect_to: url });
    let cookie = format!(
        "{UPSTREAM_COOKIE}={sealed}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age={}",
        LIFETIME.as_secs()
    );
    if let Ok(value) = HeaderValue::try_from(cookie) {
        response.headers_mut().append(header::SET_COOKIE, value);
    }
    Ok(response)
}

#[derive(Debug, Deserialize)]
struct AccountStartRequest {
    csrf: String,
    provider: String,
}

/// `POST /account/links/start`: begins linking an upstream account to the signed-in user.
async fn account_start<D, G, C, K, S, H>(
    State(service): State<Shared<D, G, C, K, S, H>>,
    requester: Requester,
    headers: HeaderMap,
    body: Bytes,
) -> Response
where
    D: Directory,
    G: GrantStore,
    C: Clock,
    K: CredentialStore,
    S: SetupStore,
    H: HttpClient,
{
    let sign_in = &service.sign_in;
    let now = sign_in.oauth.now();
    let mut user = None;
    let mut audit = Audit {
        requester: Some(&requester),
        ..Audit::default()
    };
    let result: Result<Response, Problem> = async {
        let request: AccountStartRequest = parse(&body)?;
        let account = signed_in(sign_in, &headers, &request.csrf, now).await?;
        audit.session = Some(account.token.name().to_owned());
        user = Some(account.user.clone());
        let provider = service
            .provider(&request.provider)
            .ok_or(UNKNOWN_PROVIDER)?;
        require_fresh(&account, now)?;
        check_account(&sign_in.oauth.directory, &account.user, Method::Upstream).await?;
        let bound = Bound {
            session: account.token.name().to_owned(),
            user: account.user.name.clone(),
            subject: account.user.subject.clone(),
        };
        begin(&service, provider, None, Some(bound), now).await
    }
    .await;
    log_outcome(
        "account.upstream_link_started",
        user.as_ref(),
        &audit,
        &result,
    );
    result.unwrap_or_else(IntoResponse::into_response)
}

/// Links the verified upstream account to the account session's user, then returns to the
/// account page.
async fn finish_account_link<D, G, C, K, S>(
    sign_in: &SignIn<D, G, C, K, S>,
    account: &Account,
    external: NewExternal,
    already_linked: bool,
    requester: &Requester,
    now: UnixTime,
) -> Result<Response, Failure>
where
    D: Directory,
    G: GrantStore,
    C: Clock,
    K: CredentialStore,
    S: SetupStore,
{
    if already_linked {
        return Err((
            "account_already_linked",
            ErrorReason::AccountAlreadyLinked,
            None,
        ));
    }
    refuse_admin(&sign_in.oauth.directory, &account.user).await?;
    match sign_in.credentials.link(&external).await {
        Ok(CreateCredential::Created) => {}
        Ok(CreateCredential::AlreadyExists) => {
            return Err((
                "account_already_linked",
                ErrorReason::AccountAlreadyLinked,
                None,
            ));
        }
        Err(error) => {
            tracing::error!(reason = "credential_link_failed", %error, "linking the account failed");
            return Err(("credential_link_failed", ErrorReason::ServerError, None));
        }
    }
    let audit = Audit {
        credential: Some(external.name()),
        session: Some(account.token.name().to_owned()),
        requester: Some(requester),
        ..Audit::default()
    };
    record(sign_in, &account.user, "AccountLinked", &audit, now).await;
    let issuer = sign_in.oauth.issuer.as_str().trim_end_matches('/');
    let mut response = StatusCode::SEE_OTHER.into_response();
    if let Ok(value) = HeaderValue::try_from(format!("{issuer}/account#notice=linked")) {
        response.headers_mut().insert(header::LOCATION, value);
    }
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    clear_cookie(&mut response, UPSTREAM_COOKIE, "Lax");
    Ok(response)
}

/// A failed callback: an HTML page in the user's language, never the provider's text. The
/// detail names the audit log's `reason`, so an administrator can find the matching entry.
fn failure(lang: Lang, reason: ErrorReason, detail: &str) -> Response {
    let mut response = error_page(lang, reason, detail);
    clear_cookie(&mut response, UPSTREAM_COOKIE, "Lax");
    response
}

/// Why a callback failed: the audit `reason`, what the page says, and a note for the details.
type Failure = (&'static str, ErrorReason, Option<String>);

/// Refuses an admin account: it signs in with a passkey only.
async fn refuse_admin<D: Directory>(directory: &D, user: &User) -> Result<(), Failure> {
    check_account(directory, user, Method::Upstream)
        .await
        .map_err(|problem| match problem.kind {
            "admin-needs-passkey" => ("admin_needs_passkey", ErrorReason::AdminNeedsPasskey, None),
            _ => ("account_check_failed", ErrorReason::ServerError, None),
        })
}

/// A provider answer that did not verify. An ID token outside its validity window usually means
/// this server's clock is off. HTTP errors are not shown: they can carry the provider's text.
fn verification_failure(error: &UpstreamError) -> Failure {
    let reason = "provider_verification_failed";
    match error {
        UpstreamError::IdToken("expired" | "issued in the future") => {
            (reason, ErrorReason::ClockSkew, Some(error.to_string()))
        }
        UpstreamError::IdToken(_) | UpstreamError::Protocol(_) | UpstreamError::Discovery(_) => {
            (reason, ErrorReason::ProviderFailed, Some(error.to_string()))
        }
        UpstreamError::Http(_) => (reason, ErrorReason::ProviderFailed, None),
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "the callback's checks run in protocol order; splitting them would hide the order"
)]
async fn callback<D, G, C, K, S, H>(
    State(service): State<Shared<D, G, C, K, S, H>>,
    Path(provider): Path<String>,
    RawQuery(query): RawQuery,
    headers: HeaderMap,
    requester: Requester,
) -> Response
where
    D: Directory,
    G: GrantStore,
    C: Clock,
    K: CredentialStore,
    S: SetupStore,
    H: HttpClient,
{
    let lang = Lang::negotiate(None, accept_language(&headers));
    let m = lang.messages();
    let sign_in = &service.sign_in;
    let oauth = &sign_in.oauth;
    let now = oauth.now();
    let normalized_provider = Kind::from_id(&provider).map(Kind::id);
    let mut event = "auth.upstream_callback";
    let mut identity = None;
    let mut link_user = None;
    // Keep the protocol checks in order, but emit only after the complete operation has a result.
    // The error carries a controlled reason and the existing localized browser response.
    let result: Result<Response, Failure> = async {
        let params: Vec<(String, String)> =
            form_urlencoded::parse(query.unwrap_or_default().as_bytes())
                .into_owned()
                .collect();
        let param = |name: &str| {
            params
                .iter()
                .find(|(k, _)| k == name)
                .map(|(_, v)| v.as_str())
        };
        let pending: Option<Pending> = cookie(&headers, UPSTREAM_COOKIE)
            .and_then(|sealed| oauth.sealer.open(PURPOSE, sealed))
            .and_then(|json| serde_json::from_slice(&json).ok());
        let pending = pending
            .filter(|p| p.expires_at > now && p.provider.as_str() == provider)
            .ok_or(("invalid_pending", ErrorReason::StateMismatch, None))?;
        event = match (&pending.account, &pending.link) {
            (Some(_), _) => "account.upstream_linked",
            (None, Some(_)) => "auth.account_link",
            (None, None) => "auth.sign_in",
        };
        let provider = service
            .provider(pending.provider.as_str())
            .ok_or(("provider_unavailable", ErrorReason::ProviderFailed, None))?;
        // The provider refused, or the user cancelled (RFC 6749 §4.1.2.1).
        let (Some(code), Some(state)) = (param("code"), param("state")) else {
            return Err(("provider_denied", ErrorReason::ProviderDenied, None));
        };
        if !ct_eq(state.as_bytes(), pending.state.as_bytes())
            || service
                .used_states
                .first_use(&pending.id, pending.expires_at, "", now)
                != Use::First
        {
            return Err(("invalid_state", ErrorReason::StateMismatch, None));
        }
        // Linking from the account page: the session that started must still be signed in.
        let account = match &pending.account {
            Some(bound) => {
                let account = current(sign_in, &headers, now)
                    .await
                    .map_err(|_problem| ("session_lookup_failed", ErrorReason::ServerError, None))?
                    .filter(|account| bound.matches(account))
                    .ok_or(("session_mismatch", ErrorReason::AccountSessionEnded, None))?;
                identity = Some(account.user.clone());
                Some(account)
            }
            None => None,
        };
        let exchange = Exchange {
            code,
            verifier: &pending.verifier,
            redirect_uri: &redirect_uri(oauth.issuer.as_str(), provider.id()),
            nonce: &pending.nonce,
        };
        let id = provider
            .identify(&service.http, exchange, now)
            .await
            .map_err(|error| {
                tracing::warn!(reason = "provider_verification_failed", %error, "upstream provider verification failed");
                verification_failure(&error)
            })?;
        let name = external_credential_name(&id);
        let linked = sign_in
            .credentials
            .linked_account(&name)
            .await
            .map_err(|error| {
                tracing::error!(
                    reason = "credential_lookup_failed",
                    %error,
                    "credential lookup failed"
                );
                ("credential_lookup_failed", ErrorReason::ServerError, None)
            })?;
        if let Some(account) = account {
            let external = NewExternal {
                id,
                user: account.user.name.clone(),
                kind: provider.kind().credential_type(),
                user_subject: account.user.subject.clone(),
            };
            return finish_account_link(sign_in, &account, external, linked.is_some(), &requester, now)
                .await;
        }
        let Some(token) = pending.link else {
            let linked = linked.ok_or(("account_unlinked", ErrorReason::AccountNotLinked, None))?;
            identity = oauth
                .directory
                .user(&linked.user)
                .await
                .map_err(|error| {
                    tracing::warn!(reason = "user_lookup_failed", %error, "upstream user lookup failed");
                    ("user_lookup_failed", ErrorReason::ServerError, None)
                })?;
            let user = identity
                .as_ref()
                .ok_or(("user_unavailable", ErrorReason::UserUnavailable, None))?;
            // A link left over from a deleted User must not sign in as a new User with that name.
            if !linked.signs_in_as(user) {
                return Err(("account_unlinked", ErrorReason::AccountNotLinked, None));
            }
            if user.disabled {
                return Err(("user_unavailable", ErrorReason::UserUnavailable, None));
            }
            refuse_admin(&oauth.directory, user).await?;
            let flow = cookie(&headers, FLOW_COOKIE).ok_or(("missing_flow", ErrorReason::RequestExpired, None))?;
            let authentication = Authentication {
                user: user.name.clone(),
                subject: user.subject.clone(),
                auth_time: now,
                amr: Vec::new(),
                credential: Some(name.clone()),
                user_verified: false,
                device_bound: false,
            };
            let location = complete_authorization(oauth, flow, authentication)
                .map_err(|error| {
                    tracing::warn!(reason = "authorization_failed", ?error, "upstream authorization failed");
                    ("authorization_failed", ErrorReason::RequestExpired, None)
                })?;
            let mut response = StatusCode::SEE_OTHER.into_response();
            if let Ok(value) = HeaderValue::try_from(location) {
                response.headers_mut().insert(header::LOCATION, value);
            }
            response
                .headers_mut()
                .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            clear_cookie(&mut response, UPSTREAM_COOKIE, "Lax");
            clear_cookie(&mut response, FLOW_COOKIE, "Lax");
            return Ok(response);
        };
        // Linking with an enrolment link: same single-use gate as enrolling a passkey.
        if linked.is_some() {
            return Err(("account_already_linked", ErrorReason::AccountAlreadyLinked, None));
        }
        let (stored, user) = valid_setup_token(&sign_in.setup, &oauth.directory, &token, now)
            .await
            .map_err(|_problem| ("invalid_setup", ErrorReason::SetupLinkInvalid, None))?;
        link_user = Some(stored.user.clone());
        refuse_admin(&oauth.directory, &user).await?;
        let user_subject = user.subject.clone();
        match sign_in.setup.consume(&stored).await {
            Ok(Consume::Consumed) => {}
            Ok(Consume::AlreadyUsed) => {
                return Err(("setup_already_used", ErrorReason::SetupLinkInvalid, None));
            }
            Err(error) => {
                tracing::error!(
                    reason = "setup_consume_failed",
                    %error,
                    "consuming the enrolment token failed"
                );
                return Err(("setup_consume_failed", ErrorReason::ServerError, None));
            }
        }
        let external = NewExternal {
            id,
            user: stored.user,
            kind: provider.kind().credential_type(),
            user_subject,
        };
        match sign_in.credentials.link(&external).await {
            Ok(CreateCredential::Created) => {
                let audit = Audit {
                    credential: Some(name),
                    requester: Some(&requester),
                    ..Audit::default()
                };
                record(sign_in, &user, redeemed(&token), &audit, now).await;
                let apps = oauth.directory.apps();
                let mut response = notice_page(
                    lang,
                    m.upstream_linked_title,
                    m.upstream_linked_body,
                    &crate::pages::links(&apps),
                );
                clear_cookie(&mut response, UPSTREAM_COOKIE, "Lax");
                Ok(response)
            }
            Ok(CreateCredential::AlreadyExists) => {
                Err(("account_already_linked", ErrorReason::AccountAlreadyLinked, None))
            }
            Err(error) => {
                tracing::error!(
                    reason = "credential_link_failed",
                    %error,
                    "linking the account failed"
                );
                Err(("credential_link_failed", ErrorReason::ServerError, None))
            }
        }
    }
    .await;
    let user = identity
        .as_ref()
        .map(|u| u.name.as_str())
        .or(link_user.as_deref());
    let subject = identity.as_ref().map(|u| u.subject.as_str());
    match result {
        Ok(response) => {
            tracing::info!(target: "zeabur_identity::audit", event, outcome = "success", method = "upstream", provider = normalized_provider, user, subject, "upstream operation completed");
            response
        }
        Err((reason, kind, note)) => {
            tracing::warn!(target: "zeabur_identity::audit", event, outcome = "failure", method = "upstream", provider = normalized_provider, reason, user, subject, "upstream operation failed");
            let provider = normalized_provider.unwrap_or("unknown");
            let mut detail = format!("{reason} ({provider})");
            if let Some(note) = note {
                detail = format!("{detail}: {note}");
            }
            failure(lang, kind, &detail)
        }
    }
}
