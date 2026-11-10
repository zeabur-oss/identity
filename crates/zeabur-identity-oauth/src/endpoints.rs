//! HTTP handlers: `/authorize`, `/token`, `/par`, `/revoke` (and `/userinfo`, see
//! [`crate::userinfo`]).
//!
//! Storage writes per event: none for `/authorize`, `/par` and failed token requests; one
//! `Grant` create per code redemption; one compare-and-swap per refresh; one delete per
//! revocation or detected reuse. Storage errors become `server_error`, never a token. Every
//! token, PAR, revocation and error response carries `Cache-Control: no-store`
//! (RFC 6749 §5.1), and error descriptions are fixed strings that never echo input.
//!
//! # Account types
//!
//! Each `User` is an admin or a regular account ([`account::AccountType`]). Only admin accounts
//! carry [`ADMIN_GROUP`](zeabur_identity_api::ADMIN_GROUP), which RBAC binds to
//! `cluster-admin`. The token endpoint applies the account policy ([`account::allows`]) at code
//! redemption and again at each refresh, so changing a user to admin ends their GitHub or Google
//! sessions, and turning on AAL3 ends admin sessions that started with a synced passkey. The
//! sign-in methods refuse earlier with a message for the person; this check is the backstop.
//!
//! Token and refresh lifetimes come from [`Lifetimes::for_account`](crate::Lifetimes::for_account)
//! with the user's current type and the current settings. A family always ends
//! [`Lifetimes::refresh_absolute`](crate::Lifetimes::refresh_absolute) after `auth_time`.
//!
//! The token response adds `refresh_expires_in`: the seconds until the refresh token dies if it is
//! not used. Keycloak returns the same field. Zeabur uses it to end an idle browser session at the
//! same limit.

use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::body::Bytes;
use axum::extract::{RawQuery, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use serde::{Deserialize, Serialize};
use zeabur_identity_core::account::{self, Method, Settings};
use zeabur_identity_core::clock::{Clock, UnixTime};
use zeabur_identity_store::{
    Client, CreateGrant, Directory, Grant, GrantStore, NewGrant, Rotation, User,
};
use zeabur_identity_ui::i18n::Lang;
use zeabur_identity_ui::pages::{ErrorReason, accept_language, error_page};

use super::authorize::{self, Authentication, Flow, Rejection, response_location};
use super::client_auth::{AuthFailure, authenticate};
use super::code::{self, CodeClaims};
use super::error::{ErrorCode, OAuthError, no_store};
use super::params::Params;
use super::refresh::RefreshToken;
use super::tokens::{self, Subject};
use super::{AuthorizationServer, Use};
use crate::discovery::{AUTHORIZATION_PATH, PAR_PATH, REVOCATION_PATH, TOKEN_PATH, USERINFO_PATH};

/// Cookie holding the sealed pending sign-in. `__Host-` pins it to this origin, path `/`, Secure.
/// It is `SameSite=Lax` because the client sends the browser here with a cross-site top-level
/// navigation.
pub const FLOW_COOKIE: &str = "__Host-zeabur-identity-flow";
/// Associated data for sealed flows.
pub const FLOW_PURPOSE: &str = "zeabur-identity/flow/v1";
/// Associated data for sealed PAR requests.
pub const PAR_PURPOSE: &str = "zeabur-identity/par/v1";
/// RFC 9126 §2.2 request URI prefix.
pub const REQUEST_URI_PREFIX: &str = "urn:ietf:params:oauth:request_uri:";
/// Where the user signs in.
pub const LOGIN_PATH: &str = "/login";

type Shared<D, G, C> = Arc<AuthorizationServer<D, G, C>>;

/// The authorization server's routes.
pub fn router<D: Directory, G: GrantStore, C: Clock>(server: Shared<D, G, C>) -> Router {
    Router::new()
        .route(
            AUTHORIZATION_PATH,
            get(authorize_get::<D, G, C>).post(authorize_post::<D, G, C>),
        )
        .route(TOKEN_PATH, post(token::<D, G, C>))
        .route(PAR_PATH, post(par::<D, G, C>))
        .route(REVOCATION_PATH, post(revoke::<D, G, C>))
        .route(
            USERINFO_PATH,
            get(super::userinfo::userinfo::<D, G, C>).post(super::userinfo::userinfo::<D, G, C>),
        )
        .with_state(server)
}

fn redirect(location: &str) -> Response {
    let mut response = StatusCode::SEE_OTHER.into_response();
    if let Ok(value) = HeaderValue::try_from(location) {
        response.headers_mut().insert(header::LOCATION, value);
    }
    no_store(&mut response);
    response
}

/// The error page for requests whose client or redirect URI cannot be trusted
/// (RFC 6749 §4.1.2.1): shown to the user, never redirected.
fn local_error(lang: Lang, reason: ErrorReason, error: &OAuthError) -> Response {
    let detail = format!("{}: {}", error.error.as_str(), error.error_description);
    error_page(lang, reason, &detail)
}

fn is_form(headers: &HeaderMap) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(';').next())
        .is_some_and(|v| {
            v.trim()
                .eq_ignore_ascii_case("application/x-www-form-urlencoded")
        })
}

const NOT_FORM: OAuthError = OAuthError::new(
    ErrorCode::InvalidRequest,
    "Send the request body as application/x-www-form-urlencoded.",
);

async fn authorize_get<D: Directory, G: GrantStore, C: Clock>(
    State(server): State<Shared<D, G, C>>,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
) -> Response {
    let lang = Lang::negotiate(None, accept_language(&headers));
    authorize(&server, lang, query.unwrap_or_default().as_bytes()).await
}

async fn authorize_post<D: Directory, G: GrantStore, C: Clock>(
    State(server): State<Shared<D, G, C>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let lang = Lang::negotiate(None, accept_language(&headers));
    if !is_form(&headers) {
        return local_error(lang, ErrorReason::MalformedRequest, &NOT_FORM);
    }
    authorize(&server, lang, &body).await
}

/// A pushed authorization request, sealed into its request URI.
#[derive(Debug, Serialize, Deserialize)]
struct Pushed {
    id: String,
    client_id: String,
    query: String,
    expires_at: UnixTime,
}

async fn authorize<D: Directory, G: GrantStore, C: Clock>(
    server: &AuthorizationServer<D, G, C>,
    lang: Lang,
    input: &[u8],
) -> Response {
    let params = match Params::parse(input) {
        Ok(params) => params,
        Err(error) => return local_error(lang, ErrorReason::MalformedRequest, &error),
    };
    // OIDC Core §3.1.2.1 `ui_locales`: the client's preference wins over the browser's.
    let lang = params
        .get("ui_locales")
        .and_then(|locales| locales.split(' ').find_map(Lang::from_range))
        .unwrap_or(lang);
    let params = match params.get("request_uri") {
        None => params,
        Some(uri) => match resolve_pushed(server, &params, uri) {
            Ok(params) => params,
            Err(error) => return local_error(lang, ErrorReason::RequestExpired, &error),
        },
    };
    let client = match params.get("client_id") {
        None => None,
        Some(id) => match server.directory.client(id).await {
            Ok(client) => client,
            Err(error) => {
                tracing::error!(%error, reason = "storage_failed", "client lookup failed");
                return local_error(lang, ErrorReason::ServerError, &OAuthError::server());
            }
        },
    };
    let request = match authorize::validate(&params, client.as_ref()) {
        Ok(request) => request,
        Err(Rejection::Local(error)) => {
            let reason = if client.is_some() {
                ErrorReason::RedirectUri
            } else {
                ErrorReason::UnknownClient
            };
            return local_error(lang, reason, &error);
        }
        Err(Rejection::Redirect {
            redirect_uri,
            state,
            error,
        }) => {
            let location = response_location(
                &redirect_uri,
                &[
                    ("error", error.error.as_str()),
                    ("error_description", error.error_description),
                ],
                state.as_deref(),
                server.issuer.as_str(),
            );
            return redirect(&location);
        }
    };

    let now = server.now();
    let flow = Flow {
        request,
        expires_at: now.saturating_add(server.lifetimes.flow),
    };
    let sealed = serde_json::to_vec(&flow)
        .ok()
        .and_then(|json| server.sealer.seal(FLOW_PURPOSE, &json).ok());
    let Some(sealed) = sealed else {
        return local_error(lang, ErrorReason::ServerError, &OAuthError::server());
    };
    let mut response = redirect(LOGIN_PATH);
    let cookie = format!(
        "{FLOW_COOKIE}={sealed}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age={}",
        server.lifetimes.flow.as_secs()
    );
    if let Ok(value) = HeaderValue::try_from(cookie) {
        response.headers_mut().append(header::SET_COOKIE, value);
    }
    response
}

fn resolve_pushed<D: Directory, G: GrantStore, C: Clock>(
    server: &AuthorizationServer<D, G, C>,
    outer: &Params,
    uri: &str,
) -> Result<Params, OAuthError> {
    let invalid = OAuthError::new(
        ErrorCode::InvalidRequestUri,
        "The request_uri is invalid, expired, or already used. Start the sign-in again.",
    );
    let pushed: Pushed = uri
        .strip_prefix(REQUEST_URI_PREFIX)
        .and_then(|sealed| server.sealer.open(PAR_PURPOSE, sealed))
        .and_then(|json| serde_json::from_slice(&json).ok())
        .ok_or(invalid)?;
    let now = server.now();
    // RFC 9126 §4: client_id must be sent and match; expired URIs are invalid; one-time use.
    if outer.get("client_id") != Some(pushed.client_id.as_str()) || pushed.expires_at <= now {
        return Err(invalid);
    }
    if server
        .used_request_uris
        .first_use(&pushed.id, pushed.expires_at, "", now)
        != Use::First
    {
        return Err(invalid);
    }
    Params::parse(pushed.query.as_bytes())
}

/// Opens a pending sign-in from its cookie value, if it is genuine and not expired. Used by the
/// sign-in page to show which application the user is signing in to.
#[must_use]
pub fn open_flow<D: Directory, G: GrantStore, C: Clock>(
    server: &AuthorizationServer<D, G, C>,
    sealed_flow: &str,
) -> Option<Flow> {
    let flow: Flow = server
        .sealer
        .open(FLOW_PURPOSE, sealed_flow)
        .and_then(|json| serde_json::from_slice(&json).ok())?;
    (flow.expires_at > server.now()).then_some(flow)
}

/// Finishes a sign-in: called by a sign-in method once the user has authenticated. Returns where
/// to send the browser (the client's redirect URI with `code`, `state` and `iss`).
///
/// # Errors
///
/// `invalid_request` if the flow is missing, forged or expired.
pub fn complete_authorization<D: Directory, G: GrantStore, C: Clock>(
    server: &AuthorizationServer<D, G, C>,
    sealed_flow: &str,
    authentication: Authentication,
) -> Result<String, OAuthError> {
    let flow: Flow = server
        .sealer
        .open(FLOW_PURPOSE, sealed_flow)
        .and_then(|json| serde_json::from_slice(&json).ok())
        .ok_or(OAuthError::new(
            ErrorCode::InvalidRequest,
            "No valid sign-in request was found. Start again from the app.",
        ))?;
    let now = server.now();
    if flow.expires_at <= now {
        return Err(OAuthError::new(
            ErrorCode::InvalidRequest,
            "The sign-in request expired. Start again from the app.",
        ));
    }
    let (redirect_uri, state) = (
        flow.request.redirect_uri.clone(),
        flow.request.state.clone(),
    );
    let code = code::issue(
        &server.sealer,
        flow.request,
        authentication,
        now.saturating_add(server.lifetimes.code),
    )
    .map_err(|_crypto| OAuthError::server())?;
    Ok(response_location(
        &redirect_uri,
        &[("code", &code)],
        state.as_deref(),
        server.issuer.as_str(),
    ))
}

/// RFC 6749 §5.1 token response.
#[derive(Debug, Serialize)]
struct TokenResponse {
    access_token: String,
    token_type: &'static str,
    expires_in: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    refresh_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    refresh_expires_in: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    id_token: Option<String>,
    #[serde(skip_serializing_if = "String::is_empty")]
    scope: String,
}

fn auth_failure(failure: AuthFailure) -> Response {
    let mut response = failure.error.into_response();
    if failure.basic && failure.error.error == ErrorCode::InvalidClient {
        response.headers_mut().insert(
            header::WWW_AUTHENTICATE,
            HeaderValue::from_static(r#"Basic realm="zeabur-identity""#),
        );
    }
    response
}

async fn token<D: Directory, G: GrantStore, C: Clock>(
    State(server): State<Shared<D, G, C>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let mut event = "oauth.token_request";
    let mut client = None;
    let not_form = !is_form(&headers);
    let result = async {
        if not_form {
            return Err(AuthFailure {
                error: NOT_FORM,
                basic: false,
            });
        }
        let params = Params::parse(&body).map_err(|error| AuthFailure {
            error,
            basic: false,
        })?;
        event = match params.get("grant_type") {
            Some("authorization_code") => "oauth.code_exchange",
            Some("refresh_token") => "oauth.refresh",
            Some(_) | None => "oauth.token_request",
        };
        let authenticated = authenticate(&server.directory, &headers, &params).await?;
        let client = client.insert(authenticated);
        match params.get("grant_type") {
            Some("authorization_code") => exchange_code(&server, client, &params).await,
            Some("refresh_token") => refresh(&server, client, &params).await,
            Some(_) => Err(OAuthError::new(
                ErrorCode::UnsupportedGrantType,
                "This grant_type is not supported. Use authorization_code or refresh_token.",
            )),
            None => Err(OAuthError::new(
                ErrorCode::InvalidRequest,
                "The grant_type parameter is missing.",
            )),
        }
        .map_err(|error| AuthFailure {
            error,
            basic: false,
        })
    }
    .await;
    match result {
        Ok(tokens) => {
            let mut response = axum::Json(tokens).into_response();
            no_store(&mut response);
            response
        }
        Err(failure) => {
            tracing::warn!(
                target: "zeabur_identity::audit",
                event,
                outcome = "failure",
                reason = if not_form { "not_form" } else { failure.error.error.as_str() },
                client = client.as_ref().map(|client| client.id.as_str()),
                "token request failed"
            );
            auth_failure(failure)
        }
    }
}

const INVALID_GRANT: OAuthError = OAuthError::new(
    ErrorCode::InvalidGrant,
    "The grant is invalid, expired, revoked, or was issued to another client.",
);

fn store_error(error: impl std::fmt::Display) -> OAuthError {
    tracing::error!(%error, reason = "storage_failed", "storage failed");
    OAuthError::server()
}

#[expect(
    clippy::too_many_lines,
    reason = "keep code consumption, issuance and its final audit outcome in protocol order"
)]
async fn exchange_code<D: Directory, G: GrantStore, C: Clock>(
    server: &AuthorizationServer<D, G, C>,
    client: &Client,
    params: &Params,
) -> Result<TokenResponse, OAuthError> {
    let now = server.now();
    let code = params.get("code").ok_or(OAuthError::new(
        ErrorCode::InvalidRequest,
        "The code parameter is missing.",
    ))?;
    let claims: CodeClaims = code::open(&server.sealer, code).ok_or(INVALID_GRANT)?;
    // RFC 6749 §4.1.3: the code was issued to this client; redirect_uri, if sent, is identical.
    if claims.expires_at <= now {
        return Err(INVALID_GRANT);
    }
    if claims.request.client_id != client.id {
        tracing::warn!(
            target: "zeabur_identity::audit",
            event = "oauth.client_binding",
            outcome = "failure",
            reason = "client_mismatch",
            client = %client.id,
            "authorization code client mismatch detected"
        );
        return Err(INVALID_GRANT);
    }
    if params
        .get("redirect_uri")
        .is_some_and(|uri| uri != claims.request.redirect_uri)
    {
        return Err(INVALID_GRANT);
    }
    // RFC 7636 §4.6. Checked before the single-use gate, so someone holding a stolen code without
    // the verifier cannot burn it for the legitimate client. A missing verifier is refused, so a
    // request cannot downgrade out of PKCE (RFC 9700 §2.1.1).
    let verifier = params.get("code_verifier").ok_or(INVALID_GRANT)?;
    if !super::pkce::verify(verifier, &claims.request.code_challenge) {
        return Err(INVALID_GRANT);
    }

    let grant_name = code::grant_name(&claims.id);
    if let Use::Again(issued) =
        server
            .used_codes
            .first_use(&claims.id, claims.expires_at, &grant_name, now)
    {
        // RFC 6749 §4.1.2: deny, and revoke what the first redemption produced.
        tracing::warn!(
            target: "zeabur_identity::audit",
            event = "oauth.replay",
            outcome = "failure",
            reason = "code_reused",
            client = %client.id,
            "authorization code reuse detected"
        );
        server.grants.revoke(&issued).await.map_err(store_error)?;
        return Err(INVALID_GRANT);
    }

    let user = active_user(server, &claims.user)
        .await?
        .filter(|user| user.subject == claims.subject)
        .ok_or(INVALID_GRANT)?;
    let settings = server.directory.settings().await.map_err(store_error)?;
    check_policy(settings, &user, &claims.amr, claims.device_bound)?;
    let lifetimes = server.lifetimes.for_account(user.account_type, settings);
    let refresh_token =
        RefreshToken::generate(&grant_name).map_err(|_crypto| OAuthError::server())?;
    let absolute = claims.auth_time.saturating_add(lifetimes.refresh_absolute);
    let grant = NewGrant {
        name: grant_name,
        user: user.name.clone(),
        client: client.id.clone(),
        audience: claims.request.audience.clone(),
        scopes: claims.request.scopes.clone(),
        auth_time: claims.auth_time,
        amr: claims.amr.clone(),
        expires_at: absolute,
        initial_hash: refresh_token.hash(),
        subject: Some(user.subject.clone()),
        credential: claims.credential.clone(),
        user_verified: claims.user_verified,
        device_bound: claims.device_bound,
    };
    let idle = now.saturating_add(lifetimes.refresh_idle).min(absolute);
    match server
        .grants
        .create(&grant, idle)
        .await
        .map_err(store_error)?
    {
        CreateGrant::Created => {}
        // Another process redeemed the same code first.
        CreateGrant::AlreadyExists => {
            tracing::warn!(
                target: "zeabur_identity::audit",
                event = "oauth.replay",
                outcome = "failure",
                reason = "code_reused",
                client = %client.id,
                "authorization code reuse detected"
            );
            server
                .grants
                .revoke(&grant.name)
                .await
                .map_err(store_error)?;
            return Err(INVALID_GRANT);
        }
    }
    let tokens = issue_tokens(
        server,
        client,
        &user,
        &grant,
        claims.request.nonce.as_deref(),
        Some((&refresh_token, idle)),
        lifetimes.access_token,
        now,
    )?;
    tracing::info!(
        target: "zeabur_identity::audit",
        event = "oauth.code_exchange",
        outcome = "success",
        user = %user.name,
        subject = %user.subject,
        client = %client.id,
        "authorization code exchanged"
    );
    Ok(tokens)
}

/// Refuses a user whose account type no longer allows how they signed in (see
/// [`account::allows`]). `amr` contains `swk` only after a passkey sign-in.
fn check_policy(
    settings: Settings,
    user: &User,
    amr: &[String],
    device_bound: bool,
) -> Result<(), OAuthError> {
    let method = if amr.iter().any(|m| m == "swk") {
        Method::Passkey { device_bound }
    } else {
        Method::Upstream
    };
    account::allows(user.account_type, settings, method).map_err(|refusal| {
        tracing::warn!(
            target: "zeabur_identity::audit",
            event = "oauth.account_policy",
            outcome = "failure",
            reason = ?refusal,
            user = %user.name,
            "the account type does not allow this sign-in method"
        );
        INVALID_GRANT
    })
}

async fn active_user<D: Directory, G: GrantStore, C: Clock>(
    server: &AuthorizationServer<D, G, C>,
    name: &str,
) -> Result<Option<User>, OAuthError> {
    let user = server.directory.user(name).await.map_err(store_error)?;
    Ok(user.filter(|user| !user.disabled))
}

#[expect(
    clippy::too_many_arguments,
    reason = "every argument is a distinct input of the token response"
)]
fn issue_tokens<D: Directory, G: GrantStore, C: Clock>(
    server: &AuthorizationServer<D, G, C>,
    client: &Client,
    user: &User,
    grant: &NewGrant,
    nonce: Option<&str>,
    refresh_token: Option<(&RefreshToken, UnixTime)>,
    lifetime: Duration,
    now: UnixTime,
) -> Result<TokenResponse, OAuthError> {
    let keys = server.keys.borrow().clone().ok_or_else(|| {
        tracing::error!(
            reason = "keys_unavailable",
            "token requested before signing keys were published"
        );
        OAuthError::new(
            ErrorCode::TemporarilyUnavailable,
            "Signing keys are not ready yet. Try again in a few seconds.",
        )
    })?;
    let subject = Subject {
        issuer: server.issuer.as_str(),
        user,
        client,
        audience: &grant.audience,
        scopes: &grant.scopes,
        auth_time: grant.auth_time,
        amr: &grant.amr,
    };
    let access_token = tokens::access_token(&keys, &subject, now, now.saturating_add(lifetime))?;
    let id_token = if grant.scopes.iter().any(|s| s == "openid") {
        let expires = now.saturating_add(lifetime);
        Some(tokens::id_token(&keys, &subject, nonce, now, expires)?)
    } else {
        None
    };
    Ok(TokenResponse {
        access_token,
        token_type: "Bearer",
        expires_in: lifetime.as_secs(),
        refresh_token: refresh_token.map(|(token, _)| token.encode()),
        refresh_expires_in: refresh_token
            .map(|(_, idle)| idle.as_secs().saturating_sub(now.as_secs())),
        id_token,
        scope: grant.scopes.join(" "),
    })
}

/// Enforces client binding without letting a known grant name authorize family deletion.
async fn check_refresh_client<D: Directory, G: GrantStore, C: Clock>(
    server: &AuthorizationServer<D, G, C>,
    client: &Client,
    presented: &RefreshToken,
    stored: &Grant,
) -> Result<(), OAuthError> {
    if stored.spec.client == client.id {
        return Ok(());
    }
    tracing::warn!(
        target: "zeabur_identity::audit",
        event = "oauth.client_binding",
        outcome = "failure",
        reason = "client_mismatch",
        client = %client.id,
        "refresh token client mismatch detected"
    );
    if presented.proves_possession(stored) {
        server
            .grants
            .revoke(presented.grant())
            .await
            .map_err(store_error)?;
    }
    Err(INVALID_GRANT)
}

#[expect(
    clippy::too_many_lines,
    reason = "keep rotation, user recheck and final issuance outcome in protocol order"
)]
async fn refresh<D: Directory, G: GrantStore, C: Clock>(
    server: &AuthorizationServer<D, G, C>,
    client: &Client,
    params: &Params,
) -> Result<TokenResponse, OAuthError> {
    let now = server.now();
    let presented = params.get("refresh_token").ok_or(OAuthError::new(
        ErrorCode::InvalidRequest,
        "The refresh_token parameter is missing.",
    ))?;
    let presented = RefreshToken::parse(presented).ok_or(INVALID_GRANT)?;
    let stored = server
        .grants
        .get(presented.grant())
        .await
        .map_err(store_error)?
        .ok_or(INVALID_GRANT)?;
    check_refresh_client(server, client, &presented, &stored).await?;
    let scopes = match params.get("scope") {
        None => stored.spec.scopes.clone(),
        Some(requested) => {
            let requested: Vec<String> = requested
                .split(' ')
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
                .collect();
            if !requested.iter().all(|s| stored.spec.scopes.contains(s)) {
                return Err(OAuthError::new(
                    ErrorCode::InvalidScope,
                    "A refresh can only narrow the granted scope, not add to it.",
                ));
            }
            requested
        }
    };

    // Re-check the user before rotation: disabled or deleted users get nothing more, and the
    // account type and groups come from the user as it is now. A new user with the name of a
    // deleted one has a new UID and does not get the deleted user's sessions. Only a holder of
    // the current or previous token may end the family here.
    let settings = server.directory.settings().await.map_err(store_error)?;
    let user = active_user(server, &stored.spec.user)
        .await?
        .filter(|user| stored.belongs_to(user))
        .ok_or(INVALID_GRANT);
    let user = match user.and_then(|user| {
        check_policy(settings, &user, &stored.spec.amr, stored.spec.device_bound).map(|()| user)
    }) {
        Ok(user) => user,
        Err(error) => {
            if presented.proves_possession(&stored) {
                server
                    .grants
                    .revoke(presented.grant())
                    .await
                    .map_err(store_error)?;
            }
            return Err(error);
        }
    };
    let lifetimes = server.lifetimes.for_account(user.account_type, settings);
    let absolute = stored.spec.expires_at.min(
        stored
            .spec
            .auth_time
            .saturating_add(lifetimes.refresh_absolute),
    );
    let next = RefreshToken::generate(presented.grant()).map_err(|_crypto| OAuthError::server())?;
    let idle = now.saturating_add(lifetimes.refresh_idle).min(absolute);
    let rotated = server
        .grants
        .rotate(
            presented.grant(),
            &presented.hash(),
            &next.hash(),
            now,
            idle,
        )
        .await
        .map_err(store_error)?;
    let grant = match rotated {
        Rotation::Rotated(grant) => grant,
        Rotation::Replay => {
            // RFC 9700 §4.14.2: a rotated token was used again; revoke the whole family.
            tracing::warn!(
                target: "zeabur_identity::audit",
                event = "oauth.replay",
                outcome = "failure",
                reason = "refresh_reused",
                client = %client.id,
                "refresh token reuse detected"
            );
            server
                .grants
                .revoke(presented.grant())
                .await
                .map_err(store_error)?;
            return Err(INVALID_GRANT);
        }
        // The idle or absolute lifetime has passed; delete the family now rather than waiting
        // for garbage collection.
        Rotation::Expired => {
            server
                .grants
                .revoke(presented.grant())
                .await
                .map_err(store_error)?;
            return Err(INVALID_GRANT);
        }
        // Unknown secret: refuse without revoking, or anyone who can read grant names could end
        // other users' sessions.
        Rotation::Invalid | Rotation::NotFound => return Err(INVALID_GRANT),
    };
    let narrowed = NewGrant {
        scopes,
        ..grant.spec
    };
    let tokens = issue_tokens(
        server,
        client,
        &user,
        &narrowed,
        None,
        Some((&next, idle)),
        lifetimes.access_token,
        now,
    )?;
    tracing::info!(
        target: "zeabur_identity::audit",
        event = "oauth.refresh",
        outcome = "success",
        user = %user.name,
        subject = %user.subject,
        client = %client.id,
        "refresh token exchanged"
    );
    Ok(tokens)
}

/// RFC 9126 §2.2 response. The `request_uri` is the sealed request itself, so pushing writes
/// nothing; it is bound to the client, expires after [`crate::Lifetimes::par`] and is single-use
/// (RFC 9126 §4).
#[derive(Debug, Serialize)]
struct PushedResponse {
    request_uri: String,
    expires_in: u64,
}

async fn par<D: Directory, G: GrantStore, C: Clock>(
    State(server): State<Shared<D, G, C>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if !is_form(&headers) {
        return NOT_FORM.into_response();
    }
    let params = match Params::parse(&body) {
        Ok(params) => params,
        Err(error) => return error.into_response(),
    };
    // RFC 9126 §2.1: authenticate the client as at the token endpoint, then validate exactly as
    // `/authorize` would.
    let client = match authenticate(&server.directory, &headers, &params).await {
        Ok(client) => client,
        Err(failure) => return auth_failure(failure),
    };
    if params.get("request_uri").is_some() {
        return OAuthError::new(
            ErrorCode::InvalidRequest,
            "A pushed authorization request cannot contain request_uri.",
        )
        .into_response();
    }
    if let Err(rejection) = authorize::validate(&params, Some(&client)) {
        let error = match rejection {
            Rejection::Local(error) | Rejection::Redirect { error, .. } => error,
        };
        return error.into_response();
    }
    // Keep the authorization parameters, never the client's credentials.
    let query = form_urlencoded::Serializer::new(String::new())
        .extend_pairs(form_urlencoded::parse(&body).filter(|(k, _)| k != "client_secret"))
        .finish();
    let now = server.now();
    let lifetime = server.lifetimes.par;
    let sealed = zeabur_identity_core::crypto::random::<16>()
        .ok()
        .and_then(|id| {
            let pushed = Pushed {
                id: zeabur_identity_core::crypto::hex(&id),
                client_id: client.id.clone(),
                query,
                expires_at: now.saturating_add(lifetime),
            };
            serde_json::to_vec(&pushed)
                .ok()
                .and_then(|json| server.sealer.seal(PAR_PURPOSE, &json).ok())
        });
    let Some(sealed) = sealed else {
        return OAuthError::server().into_response();
    };
    let mut response = (
        StatusCode::CREATED,
        axum::Json(PushedResponse {
            request_uri: format!("{REQUEST_URI_PREFIX}{sealed}"),
            expires_in: lifetime.as_secs(),
        }),
    )
        .into_response();
    no_store(&mut response);
    response
}

async fn revoke<D: Directory, G: GrantStore, C: Clock>(
    State(server): State<Shared<D, G, C>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let mut client = None;
    let not_form = !is_form(&headers);
    let result = async {
        if not_form {
            return Err(AuthFailure {
                error: NOT_FORM,
                basic: false,
            });
        }
        let params = Params::parse(&body).map_err(|error| AuthFailure {
            error,
            basic: false,
        })?;
        let authenticated = authenticate(&server.directory, &headers, &params).await?;
        let client = client.insert(authenticated);
        let token = params.get("token").ok_or(AuthFailure {
            error: OAuthError::new(ErrorCode::InvalidRequest, "The token parameter is missing."),
            basic: false,
        })?;
        if let Some(refresh) = RefreshToken::parse(token) {
            let grant = server
                .grants
                .get(refresh.grant())
                .await
                .map_err(|error| AuthFailure {
                    error: store_error(error),
                    basic: false,
                })?;
            // RFC 7009 §2.1: verify both the owning client and possession of its token.
            if grant.is_some_and(|grant| {
                grant.spec.client == client.id && refresh.proves_possession(&grant)
            }) {
                server
                    .grants
                    .revoke(refresh.grant())
                    .await
                    .map_err(|error| AuthFailure {
                        error: store_error(error),
                        basic: false,
                    })?;
            }
        } else if token.split('.').count() == 3 {
            // Access and ID tokens are verified offline (kube-apiserver among others) and cannot
            // be revoked; say so instead of pretending (RFC 7009 §2.2.1).
            return Err(AuthFailure {
                error: OAuthError::new(
                    ErrorCode::UnsupportedTokenType,
                    "Access tokens cannot be revoked; they expire within minutes. Revoke the refresh token instead.",
                ),
                basic: false,
            });
        }
        Ok(())
    }
    .await;
    match result {
        Ok(()) => {
            tracing::info!(
                target: "zeabur_identity::audit",
                event = "oauth.revocation_request",
                outcome = "success",
                reason = "accepted",
                client = client.as_ref().map(|client| client.id.as_str()),
                "revocation request accepted"
            );
            // RFC 7009 §2.2: 200 for revoked and for invalid tokens alike.
            let mut response = StatusCode::OK.into_response();
            no_store(&mut response);
            response
        }
        Err(failure) => {
            tracing::warn!(
                target: "zeabur_identity::audit",
                event = "oauth.revocation_request",
                outcome = "failure",
                reason = if not_form { "not_form" } else { failure.error.error.as_str() },
                client = client.as_ref().map(|client| client.id.as_str()),
                "revocation request failed"
            );
            auth_failure(failure)
        }
    }
}
