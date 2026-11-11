//! `/account`: where a signed-in user sees and changes their own passkeys and sessions.
//!
//! Signing in here creates an account session, stored as a `Grant` named `s-…` with client
//! [`ACCOUNT_CLIENT`]: one write, revoked like any grant (by the user, by an admin deleting it,
//! by a reset) and collected when it expires. The browser holds `<name>.<secret>` in an
//! `HttpOnly` cookie; only the secret's hash is stored. Every request reads the session and its
//! user again, and the session must name the user's current UID, so a deleted and recreated
//! user of the same name does not inherit it.
//!
//! Every change is one write to the user's own objects, which the stores find by the session's
//! user and UID, never by a name from the request. Changes need the session cookie, the
//! same-origin and JSON checks of the other endpoints (`check_request`). Adding or
//! removing a passkey also needs a user-verified passkey assertion from the last
//! [`REAUTH_WINDOW`], made with one of the user's own passkeys and recorded on the session.
//! Removing a passkey revokes every session and grant that signed in or re-authenticated with
//! it, and the last passkey cannot be removed (see `CredentialStore::remove`).
//!
//! Linking an upstream account starts here and finishes at the provider's callback (see
//! [`crate::upstream`]). The start needs the same fresh confirmation as adding a passkey.
//! Unlinking needs it too. It revokes every session and grant that signed in with the account,
//! and the user's last credential cannot be unlinked (see `CredentialStore::unlink`).

use std::time::Duration;

use axum::Router;
use axum::body::Bytes;
use axum::extract::{RawQuery, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};
use webauthn_rs::prelude::{
    DiscoverableAuthentication, PasskeyRegistration, PublicKeyCredential,
    RegisterPublicKeyCredential, Uuid,
};
use zeabur_identity_api::token_hash;
use zeabur_identity_core::account::{AccountType, Method};
use zeabur_identity_core::clock::{Clock, UnixTime};
use zeabur_identity_core::crypto::{CryptoError, hex, random};
use zeabur_identity_oauth::Use;
use zeabur_identity_store::{
    AccountEvent, Classification, CreateCredential, CreateGrant, CredentialStore, Directory, Grant,
    GrantStore, LinkedSummary, NewGrant, PasskeySummary, Removal, Rename, SetupStore, Unlink, User,
    Verification, classify,
};
use zeabur_identity_ui::pages::{
    AccountView, ErrorReason, LinkedRow, PasskeyRow, ProviderButton, SessionRow, Storage,
    account_page, error_page, page_lang,
};

use crate::device::Requester;
use crate::passkeys::{authenticator, backup_flags};
use crate::problem::Problem;
use crate::upstream::provider::{Descriptor, GITHUB_ISSUER, GOOGLE_ISSUER};
use crate::{
    Accepted, BAD_REQUEST, CEREMONY_COOKIE, CEREMONY_EXPIRED, CEREMONY_LIFETIME, Ceremony,
    PASSKEY_AMR, PASSKEY_FAILED, Refused, SignIn, Verified, accepted, check_account, check_request,
    clean_label, clear_cookie, cookie, internal, json, new_passkey, open, parse, seal, set_cookie,
    set_cookie_with, touch, verify_assertion,
};

/// Cookie holding the account session, `<grant name>.<secret>` (`SameSite=Lax`, so a link to
/// `/account` from another site still shows the signed-in page; changes are refused unless
/// same-origin).
pub const SESSION_COOKIE: &str = "__Host-zeabur-identity-session";
/// `spec.client` of account sessions. Not a valid object name, so no `OAuthClient` has it.
pub const ACCOUNT_CLIENT: &str = "zeabur_identity";
/// How long an account session lasts. It is not extended.
pub const SESSION_LIFETIME: Duration = Duration::from_hours(1);
/// How recent a passkey confirmation must be to add or remove a passkey.
pub const REAUTH_WINDOW: Duration = Duration::from_mins(5);

const SIGN_IN_PURPOSE: &str = "zeabur-identity/account-sign-in/v1";
const REAUTH_PURPOSE: &str = "zeabur-identity/reauth/v1";
const REGISTRATION_PURPOSE: &str = "zeabur-identity/account-registration/v1";

const SIGNED_OUT: Problem = Problem::new(
    StatusCode::UNAUTHORIZED,
    "signed-out",
    "Your session ended. Sign in again.",
);
const REAUTH_REQUIRED: Problem = Problem::new(
    StatusCode::FORBIDDEN,
    "reauth-required",
    "Confirm with a passkey first.",
);
const NOT_FOUND: Problem = Problem::new(
    StatusCode::NOT_FOUND,
    "not-found",
    "No such passkey or session.",
);
const LAST_PASSKEY: Problem = Problem::new(
    StatusCode::CONFLICT,
    "last-passkey",
    "This is your only passkey. Add another before removing it.",
);
const CONFLICT: Problem = Problem::new(
    StatusCode::CONFLICT,
    "conflict",
    "Your passkeys changed meanwhile. Reload and try again.",
);
const PASSKEY_EXISTS: Problem = Problem::new(
    StatusCode::CONFLICT,
    "passkey-exists",
    "This passkey is already registered.",
);
const LAST_CREDENTIAL: Problem = Problem::new(
    StatusCode::CONFLICT,
    "last-credential",
    "This is your only way to sign in. Add a passkey before unlinking it.",
);

type Shared<D, G, C, K, S> = std::sync::Arc<SignIn<D, G, C, K, S>>;

/// The account routes and `/.well-known/passkey-endpoints`.
pub(crate) fn routes<D, G, C, K, S>() -> Router<Shared<D, G, C, K, S>>
where
    D: Directory,
    G: GrantStore,
    C: Clock,
    K: CredentialStore,
    S: SetupStore,
{
    Router::new()
        .route("/account", get(page::<D, G, C, K, S>))
        .route(
            "/.well-known/passkey-endpoints",
            get(passkey_endpoints::<D, G, C, K, S>),
        )
        .route(
            "/account/session/options",
            post(session_options::<D, G, C, K, S>),
        )
        .route("/account/session", post(session_create::<D, G, C, K, S>))
        .route("/account/sign-out", post(sign_out::<D, G, C, K, S>))
        .route(
            "/account/reauth/options",
            post(reauth_options::<D, G, C, K, S>),
        )
        .route("/account/reauth", post(reauth::<D, G, C, K, S>))
        .route(
            "/account/passkeys/options",
            post(add_options::<D, G, C, K, S>),
        )
        .route("/account/passkeys", post(add::<D, G, C, K, S>))
        .route("/account/passkeys/rename", post(rename::<D, G, C, K, S>))
        .route("/account/passkeys/remove", post(remove::<D, G, C, K, S>))
        .route("/account/sessions/revoke", post(revoke::<D, G, C, K, S>))
        .route(
            "/account/sessions/revoke-others",
            post(revoke_others::<D, G, C, K, S>),
        )
        .route("/account/links/remove", post(unlink::<D, G, C, K, S>))
}

/// The account session cookie: `s-<64 hex>.<256-bit secret, base64url>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionToken {
    name: String,
    secret: String,
}

impl SessionToken {
    /// A new session.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError`] if randomness fails.
    pub fn generate() -> Result<Self, CryptoError> {
        Ok(Self {
            name: format!("s-{}", hex(&random::<32>()?)),
            secret: URL_SAFE_NO_PAD.encode(random::<32>()?),
        })
    }

    /// Parses a cookie value. Anything malformed is `None`.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        let (name, secret) = value.split_once('.')?;
        let valid_name = name.len() == 66
            && name.starts_with("s-")
            && name
                .bytes()
                .skip(2)
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
        let valid_secret =
            secret.len() == 43 && URL_SAFE_NO_PAD.decode(secret).is_ok_and(|s| s.len() == 32);
        (valid_name && valid_secret).then(|| Self {
            name: name.to_owned(),
            secret: secret.to_owned(),
        })
    }

    /// The `Grant` object name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The cookie value.
    #[must_use]
    pub fn encode(&self) -> String {
        format!("{}.{}", self.name, self.secret)
    }

    /// The stored form of the secret.
    #[must_use]
    pub fn hash(&self) -> String {
        token_hash(self.secret.as_bytes())
    }
}

/// A signed-in request.
pub(crate) struct Account {
    pub(crate) user: User,
    pub(crate) session: Grant,
    pub(crate) token: SessionToken,
}

/// The account session the request carries, if it is valid: current secret, not expired, an
/// account session, and its user enabled with the UID recorded at sign-in.
pub(crate) async fn current<D, G, C, K, S>(
    service: &SignIn<D, G, C, K, S>,
    headers: &HeaderMap,
    now: UnixTime,
) -> Result<Option<Account>, Problem>
where
    D: Directory,
    G: GrantStore,
    C: Clock,
    K: CredentialStore,
    S: SetupStore,
{
    let Some(token) = cookie(headers, SESSION_COOKIE).and_then(SessionToken::parse) else {
        return Ok(None);
    };
    let Some(session) = service
        .oauth
        .grants
        .get(&token.name)
        .await
        .map_err(internal)?
    else {
        return Ok(None);
    };
    match classify(&session, &token.hash(), now) {
        Classification::Current => {}
        Classification::Expired | Classification::Previous | Classification::Unknown => {
            return Ok(None);
        }
    }
    if session.spec.client != ACCOUNT_CLIENT {
        return Ok(None);
    }
    let Some(user) = service
        .oauth
        .directory
        .user(&session.spec.user)
        .await
        .map_err(internal)?
    else {
        return Ok(None);
    };
    if user.disabled || !session.belongs_to(&user) {
        return Ok(None);
    }
    Ok(Some(Account {
        user,
        session,
        token,
    }))
}

/// A change request: same origin, JSON and a valid session.
pub(crate) async fn signed_in<D, G, C, K, S>(
    service: &SignIn<D, G, C, K, S>,
    headers: &HeaderMap,
    now: UnixTime,
) -> Result<Account, Problem>
where
    D: Directory,
    G: GrantStore,
    C: Clock,
    K: CredentialStore,
    S: SetupStore,
{
    check_request(headers, service.oauth.issuer.as_str())?;
    current(service, headers, now).await?.ok_or(SIGNED_OUT)
}

/// Whether the session's latest authentication verified the user within [`REAUTH_WINDOW`].
#[must_use]
pub fn is_fresh(session: &Grant, now: UnixTime) -> bool {
    let verification = session.verification();
    verification.user_verified
        && verification.at <= now
        && now < verification.at.saturating_add(REAUTH_WINDOW)
}

pub(crate) fn require_fresh(account: &Account, now: UnixTime) -> Result<(), Problem> {
    if is_fresh(&account.session, now) {
        Ok(())
    } else {
        Err(REAUTH_REQUIRED)
    }
}

/// What the audit log and the `Event` record about a change.
#[derive(Default)]
pub(crate) struct Audit<'a> {
    pub(crate) credential: Option<String>,
    pub(crate) aaguid: Option<String>,
    pub(crate) session: Option<String>,
    pub(crate) revoked: usize,
    pub(crate) requester: Option<&'a Requester>,
}

pub(crate) fn log_outcome<T>(
    event: &'static str,
    user: Option<&User>,
    audit: &Audit<'_>,
    result: &Result<T, Problem>,
) {
    let requester = audit.requester;
    let ip = requester.and_then(|r| r.ip).map(|ip| ip.to_string());
    let peer = requester.and_then(|r| r.peer).map(|ip| ip.to_string());
    let user_agent = requester.and_then(|r| r.user_agent.as_deref());
    let (actor, subject) = (
        user.map(|u| u.name.as_str()),
        user.map(|u| u.subject.as_str()),
    );
    match result {
        Ok(_) => tracing::info!(
            target: "zeabur_identity::audit",
            event,
            outcome = "success",
            actor,
            subject,
            credential = audit.credential.as_deref(),
            aaguid = audit.aaguid.as_deref(),
            session = audit.session.as_deref(),
            revoked = audit.revoked,
            client_ip = ip.as_deref(),
            peer = peer.as_deref(),
            user_agent,
            "account changed"
        ),
        Err(problem) => tracing::warn!(
            target: "zeabur_identity::audit",
            event,
            outcome = "failure",
            reason = problem.kind,
            actor,
            subject,
            credential = audit.credential.as_deref(),
            session = audit.session.as_deref(),
            client_ip = ip.as_deref(),
            peer = peer.as_deref(),
            user_agent,
            "account change failed"
        ),
    }
}

/// Records an `Event` on the user. Best effort: the change is done, so a failure is logged.
pub(crate) async fn record<D, G, C, K, S>(
    service: &SignIn<D, G, C, K, S>,
    user: &User,
    reason: &'static str,
    audit: &Audit<'_>,
    now: UnixTime,
) where
    D: Directory,
    G: GrantStore,
    C: Clock,
    K: CredentialStore,
    S: SetupStore,
{
    let requester = audit.requester.cloned().unwrap_or_default();
    let mut note = format!("actor={}", user.name);
    let fields = [
        ("credential", audit.credential.clone()),
        ("aaguid", audit.aaguid.clone()),
        ("session", audit.session.clone()),
        (
            "revoked",
            (audit.revoked > 0).then(|| audit.revoked.to_string()),
        ),
        ("client_ip", requester.ip.map(|ip| ip.to_string())),
        (
            "user_agent",
            requester.user_agent.map(|ua| format!("{ua:?}")),
        ),
    ];
    for (key, value) in fields {
        if let Some(value) = value {
            note.extend([" ", key, "=", &value]);
        }
    }
    let event = AccountEvent {
        user: user.name.clone(),
        subject: user.subject.clone(),
        reason,
        at: now,
        note,
    };
    if let Err(error) = service.credentials.record(&event).await {
        tracing::warn!(reason = "event_failed", %error, "recording an account event failed");
    }
}

fn with_cookie(mut response: Response, token: &SessionToken) -> Response {
    set_cookie_with(
        &mut response,
        SESSION_COOKIE,
        &token.encode(),
        SESSION_LIFETIME.as_secs(),
        "Lax",
    );
    response
}

#[derive(Serialize)]
struct Done {
    /// The session viewing the page was signed out by this change.
    signed_out: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    accepted: Option<Accepted>,
}

fn done(signed_out: bool, accepted: Option<Accepted>) -> Response {
    let mut response = json(
        StatusCode::OK,
        &Done {
            signed_out,
            accepted,
        },
    );
    if signed_out {
        clear_cookie(&mut response, SESSION_COOKIE, "Lax");
    }
    response
}

#[derive(Deserialize)]
struct AssertionRequest {
    credential: PublicKeyCredential,
}

#[derive(Deserialize)]
struct AddRequest {
    credential: RegisterPublicKeyCredential,
    #[serde(default)]
    label: Option<String>,
}

#[derive(Deserialize)]
struct NameRequest {
    name: String,
}

#[derive(Deserialize)]
struct RenameRequest {
    name: String,
    label: String,
}

/// `GET /.well-known/passkey-endpoints` (W3C, "A Well-Known URL for Relying Party Passkey
/// Endpoints"): where a password manager sends people to add or manage passkeys. Served
/// directly, never redirected.
async fn passkey_endpoints<D, G, C, K, S>(State(service): State<Shared<D, G, C, K, S>>) -> Response
where
    D: Directory,
    G: GrantStore,
    C: Clock,
    K: CredentialStore,
    S: SetupStore,
{
    let issuer = service.oauth.issuer.as_str().trim_end_matches('/');
    let body = serde_json::json!({
        "enroll": format!("{issuer}/account#add"),
        "manage": format!("{issuer}/account"),
    });
    let mut response = (StatusCode::OK, axum::Json(body)).into_response();
    let headers = response.headers_mut();
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=3600"),
    );
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_ORIGIN,
        HeaderValue::from_static("*"),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    response
}

/// How a linked account's provider is shown: the provider it was linked through. If that
/// provider is gone, a provider with the same issuer, which signs the account in, or else GitHub,
/// Google or the issuer's host. The user can unlink the account either way.
fn shown_provider(account: &LinkedSummary, providers: &[Descriptor]) -> (String, &'static str) {
    let current = account
        .provider
        .as_ref()
        .and_then(|id| providers.iter().find(|p| p.id == *id))
        .or_else(|| providers.iter().find(|p| p.issuer == account.issuer));
    match current {
        Some(descriptor) => (descriptor.label.clone(), descriptor.icon),
        None if account.issuer.as_str() == GITHUB_ISSUER => ("GitHub".to_owned(), "GithubLogo"),
        None if account.issuer.as_str() == GOOGLE_ISSUER => ("Google".to_owned(), "GoogleLogo"),
        None => (issuer_label(account.issuer.as_str()), "SignIn"),
    }
}

fn linked_rows<'a>(
    linked: &'a [LinkedSummary],
    shown: &'a [(String, &'static str)],
) -> Vec<LinkedRow<'a>> {
    let mut rows = Vec::new();
    for (account, (label, icon)) in linked.iter().zip(shown) {
        rows.push(LinkedRow {
            name: &account.name,
            provider: ProviderButton {
                id: "",
                label,
                icon,
            },
            linked: account.created_at.map(UnixTime::as_secs),
        });
    }
    rows
}

/// The host of an issuer, or the issuer itself if it has none.
fn issuer_label(issuer: &str) -> String {
    url::Url::parse(issuer)
        .ok()
        .and_then(|url| url.host_str().map(str::to_owned))
        .unwrap_or_else(|| issuer.to_owned())
}

async fn page<D, G, C, K, S>(
    State(service): State<Shared<D, G, C, K, S>>,
    RawQuery(query): RawQuery,
    headers: HeaderMap,
) -> Response
where
    D: Directory,
    G: GrantStore,
    C: Clock,
    K: CredentialStore,
    S: SetupStore,
{
    let lang = page_lang(query.as_deref(), &headers);
    let now = service.oauth.now();
    let loaded = async {
        let Some(account) = current(&service, &headers, now).await? else {
            return Ok::<_, Problem>(None);
        };
        let passkeys = service
            .credentials
            .passkeys(&account.user)
            .await
            .map_err(internal)?;
        let linked = service
            .credentials
            .linked_accounts(&account.user)
            .await
            .map_err(internal)?;
        let mut sessions: Vec<Grant> = service
            .oauth
            .grants
            .list(&account.user)
            .await
            .map_err(internal)?
            .into_iter()
            .filter(|grant| now < grant.spec.expires_at && now < grant.idle_expires_at)
            .collect();
        sessions.sort_by(|a, b| {
            let current = |g: &Grant| g.spec.name != account.session.spec.name;
            current(a)
                .cmp(&current(b))
                .then(b.spec.auth_time.cmp(&a.spec.auth_time))
        });
        let mut apps = Vec::new();
        for client in sessions.iter().map(|g| g.spec.client.as_str()) {
            if client == ACCOUNT_CLIENT || apps.iter().any(|(id, _)| id == client) {
                continue;
            }
            let name = service
                .oauth
                .directory
                .client_name(client)
                .unwrap_or_else(|| client.to_owned());
            apps.push((client.to_owned(), name));
        }
        Ok(Some((account, passkeys, linked, sessions, apps)))
    }
    .await;
    match loaded {
        Ok(None) => account_page(lang, None),
        Ok(Some((account, passkeys, linked, sessions, apps))) => {
            let this_device = account.session.verification().credential;
            let label = |name: &str| {
                passkeys
                    .iter()
                    .find(|p| p.name == name)
                    .and_then(|p| p.label.as_deref())
            };
            let rows: Vec<PasskeyRow<'_>> = passkeys
                .iter()
                .map(|p| passkey_row(p, this_device.as_deref()))
                .collect();
            let session_rows: Vec<SessionRow<'_>> = sessions
                .iter()
                .map(|grant| SessionRow {
                    name: &grant.spec.name,
                    app: apps
                        .iter()
                        .find(|(id, _)| *id == grant.spec.client)
                        .map(|(_, name)| name.as_str()),
                    signed_in: grant.spec.auth_time.as_secs(),
                    credential: grant.spec.credential.as_deref().and_then(label),
                    current: grant.spec.name == account.session.spec.name,
                })
                .collect();
            let descriptors = service.providers.descriptors();
            let shown: Vec<_> = linked
                .iter()
                .map(|account| shown_provider(account, &descriptors))
                .collect();
            let linked_rows = linked_rows(&linked, &shown);
            let providers: Vec<ProviderButton<'_>> =
                descriptors.iter().map(Descriptor::button).collect();
            account_page(
                lang,
                Some(AccountView {
                    username: &account.user.username,
                    passkeys: &rows,
                    linked: &linked_rows,
                    providers: &providers,
                    admin: account.user.account_type == AccountType::Admin,
                    sessions: &session_rows,
                }),
            )
        }
        Err(_) => error_page(lang, ErrorReason::ServerError, ""),
    }
}

fn passkey_row<'a>(passkey: &'a PasskeySummary, this_device: Option<&str>) -> PasskeyRow<'a> {
    let storage = match backup_flags(&passkey.record) {
        (_, true) => Storage::Synced,
        (false, false) => Storage::OneDevice,
        (true, false) => Storage::Unknown,
    };
    PasskeyRow {
        name: &passkey.name,
        label: passkey.label.as_deref(),
        added: passkey.created_at.map(UnixTime::as_secs),
        last_used: passkey.last_used_at.map(UnixTime::as_secs),
        storage,
        this_device: this_device == Some(passkey.name.as_str()),
    }
}

/// Starts a discoverable assertion bound to `purpose` and, for re-authentication, the session.
fn assertion_options<D, G, C, K, S>(
    service: &SignIn<D, G, C, K, S>,
    purpose: &str,
    session: Option<String>,
    now: UnixTime,
) -> Result<Response, Problem>
where
    D: Directory,
    G: GrantStore,
    C: Clock,
    K: CredentialStore,
    S: SetupStore,
{
    let (options, state) = service.passkeys.begin_sign_in().map_err(internal)?;
    let sealed =
        seal::<DiscoverableAuthentication, _, _, _>(&service.oauth, purpose, state, session, now)?;
    let mut response = json(StatusCode::OK, &options);
    set_cookie(
        &mut response,
        CEREMONY_COOKIE,
        &sealed,
        CEREMONY_LIFETIME.as_secs(),
    );
    Ok(response)
}

/// Verifies an assertion against a ceremony started for `purpose`, then spends the ceremony.
async fn finish_assertion<D, G, C, K, S>(
    service: &SignIn<D, G, C, K, S>,
    headers: &HeaderMap,
    purpose: &str,
    session: Option<&str>,
    credential: &PublicKeyCredential,
    now: UnixTime,
) -> Result<Verified, Refused>
where
    D: Directory,
    G: GrantStore,
    C: Clock,
    K: CredentialStore,
    S: SetupStore,
{
    let ceremony: Ceremony<DiscoverableAuthentication> =
        open(&service.oauth, headers, purpose, now)?;
    if ceremony.user.as_deref() != session {
        return Err(CEREMONY_EXPIRED.into());
    }
    let verified = verify_assertion(service, credential, ceremony.state).await?;
    if service
        .used_ceremonies
        .first_use(&ceremony.id, ceremony.expires_at, "", now)
        != Use::First
    {
        return Err(CEREMONY_EXPIRED.into());
    }
    Ok(verified)
}

async fn session_options<D, G, C, K, S>(
    State(service): State<Shared<D, G, C, K, S>>,
    headers: HeaderMap,
) -> Response
where
    D: Directory,
    G: GrantStore,
    C: Clock,
    K: CredentialStore,
    S: SetupStore,
{
    let result = check_request(&headers, service.oauth.issuer.as_str())
        .and_then(|()| assertion_options(&service, SIGN_IN_PURPOSE, None, service.oauth.now()));
    result.unwrap_or_else(IntoResponse::into_response)
}

#[derive(Serialize)]
struct SignedIn {
    #[serde(skip_serializing_if = "Option::is_none")]
    accepted: Option<Accepted>,
}

async fn session_create<D, G, C, K, S>(
    State(service): State<Shared<D, G, C, K, S>>,
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
{
    let now = service.oauth.now();
    let mut user = None;
    let mut audit = Audit {
        requester: Some(&requester),
        ..Audit::default()
    };
    let result: Result<Response, Refused> = async {
        check_request(&headers, service.oauth.issuer.as_str())?;
        let request: AssertionRequest = parse(&body)?;
        let verified = finish_assertion(
            &service,
            &headers,
            SIGN_IN_PURPOSE,
            None,
            &request.credential,
            now,
        )
        .await?;
        audit.credential = Some(verified.credential.clone());
        let token = SessionToken::generate().map_err(internal)?;
        audit.session = Some(token.name.clone());
        let expires_at = now.saturating_add(SESSION_LIFETIME);
        let grant = NewGrant {
            name: token.name.clone(),
            user: verified.user.name.clone(),
            client: ACCOUNT_CLIENT.to_owned(),
            audience: service.oauth.issuer.as_str().to_owned(),
            scopes: Vec::new(),
            auth_time: now,
            amr: PASSKEY_AMR.iter().map(|m| (*m).to_owned()).collect(),
            expires_at,
            initial_hash: token.hash(),
            subject: Some(verified.user.subject.clone()),
            credential: Some(verified.credential.clone()),
            user_verified: true,
            device_bound: verified.device_bound,
        };
        match service
            .oauth
            .grants
            .create(&grant, expires_at)
            .await
            .map_err(internal)?
        {
            CreateGrant::Created => {}
            CreateGrant::AlreadyExists => return Err(internal("session name collision").into()),
        }
        touch(&service, &verified, now).await;
        let signal = accepted(&service, &verified.user).await;
        user = Some(verified.user);
        let mut response = json(StatusCode::OK, &SignedIn { accepted: signal });
        clear_cookie(&mut response, CEREMONY_COOKIE, "Strict");
        Ok(with_cookie(response, &token))
    }
    .await;
    let logged = result.as_ref().map(|_| ()).map_err(|r| r.problem);
    log_outcome("account.sign_in", user.as_ref(), &audit, &logged);
    result.unwrap_or_else(|refused| refused.respond(service.passkeys.rp_id()))
}

async fn sign_out<D, G, C, K, S>(
    State(service): State<Shared<D, G, C, K, S>>,
    requester: Requester,
    headers: HeaderMap,
) -> Response
where
    D: Directory,
    G: GrantStore,
    C: Clock,
    K: CredentialStore,
    S: SetupStore,
{
    let now = service.oauth.now();
    let mut user = None;
    let mut audit = Audit {
        requester: Some(&requester),
        ..Audit::default()
    };
    let result: Result<Response, Problem> = async {
        let account = signed_in(&service, &headers, now).await?;
        audit.session = Some(account.token.name.clone());
        service
            .oauth
            .grants
            .revoke(&account.token.name)
            .await
            .map_err(internal)?;
        user = Some(account.user);
        Ok(done(true, None))
    }
    .await;
    log_outcome("account.sign_out", user.as_ref(), &audit, &result);
    result.unwrap_or_else(IntoResponse::into_response)
}

async fn reauth_options<D, G, C, K, S>(
    State(service): State<Shared<D, G, C, K, S>>,
    headers: HeaderMap,
) -> Response
where
    D: Directory,
    G: GrantStore,
    C: Clock,
    K: CredentialStore,
    S: SetupStore,
{
    let now = service.oauth.now();
    let result: Result<Response, Problem> = async {
        let account = signed_in(&service, &headers, now).await?;
        assertion_options(&service, REAUTH_PURPOSE, Some(account.token.name), now)
    }
    .await;
    result.unwrap_or_else(IntoResponse::into_response)
}

async fn reauth<D, G, C, K, S>(
    State(service): State<Shared<D, G, C, K, S>>,
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
{
    let now = service.oauth.now();
    let mut user = None;
    let mut audit = Audit {
        requester: Some(&requester),
        ..Audit::default()
    };
    let result: Result<Response, Refused> = async {
        let request: AssertionRequest = parse(&body)?;
        let account = signed_in(&service, &headers, now).await?;
        audit.session = Some(account.token.name.clone());
        let verified = finish_assertion(
            &service,
            &headers,
            REAUTH_PURPOSE,
            Some(&account.token.name),
            &request.credential,
            now,
        )
        .await?;
        audit.credential = Some(verified.credential.clone());
        // The assertion's user handle names the credential's owner; it must be this session's.
        if verified.user.name != account.user.name || verified.user.subject != account.user.subject
        {
            return Err(PASSKEY_FAILED.into());
        }
        let verification = Verification {
            at: now,
            credential: Some(verified.credential.clone()),
            user_verified: true,
        };
        let recorded = service
            .oauth
            .grants
            .reauthenticate(&account.token.name, &account.token.hash(), &verification)
            .await
            .map_err(internal)?;
        if !recorded {
            return Err(SIGNED_OUT.into());
        }
        touch(&service, &verified, now).await;
        user = Some(account.user);
        let mut response = done(false, None);
        clear_cookie(&mut response, CEREMONY_COOKIE, "Strict");
        Ok(response)
    }
    .await;
    let logged = result.as_ref().map(|_| ()).map_err(|r| r.problem);
    log_outcome("account.reauth", user.as_ref(), &audit, &logged);
    result.unwrap_or_else(|refused| refused.respond(service.passkeys.rp_id()))
}

async fn add_options<D, G, C, K, S>(
    State(service): State<Shared<D, G, C, K, S>>,
    headers: HeaderMap,
) -> Response
where
    D: Directory,
    G: GrantStore,
    C: Clock,
    K: CredentialStore,
    S: SetupStore,
{
    let now = service.oauth.now();
    let result: Result<Response, Problem> = async {
        let account = signed_in(&service, &headers, now).await?;
        require_fresh(&account, now)?;
        let exclude = service
            .credentials
            .passkeys(&account.user)
            .await
            .map_err(internal)?
            .iter()
            .filter_map(|p| URL_SAFE_NO_PAD.decode(&p.credential_id).ok())
            .collect();
        let user = &account.user;
        let handle = Uuid::parse_str(&user.subject).map_err(internal)?;
        let display = user.display_name.as_deref().unwrap_or(&user.username);
        let (options, state) = service
            .passkeys
            .begin_registration(handle, &user.username, display, exclude)
            .map_err(internal)?;
        let sealed = seal::<PasskeyRegistration, _, _, _>(
            &service.oauth,
            REGISTRATION_PURPOSE,
            state,
            Some(account.token.name.clone()),
            now,
        )?;
        let mut response = json(StatusCode::OK, &options);
        set_cookie(
            &mut response,
            CEREMONY_COOKIE,
            &sealed,
            CEREMONY_LIFETIME.as_secs(),
        );
        Ok(response)
    }
    .await;
    result.unwrap_or_else(IntoResponse::into_response)
}

async fn add<D, G, C, K, S>(
    State(service): State<Shared<D, G, C, K, S>>,
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
{
    let now = service.oauth.now();
    let mut user = None;
    let mut audit = Audit {
        requester: Some(&requester),
        ..Audit::default()
    };
    let result: Result<Response, Problem> = async {
        let request: AddRequest = parse(&body)?;
        let account = signed_in(&service, &headers, now).await?;
        audit.session = Some(account.token.name.clone());
        require_fresh(&account, now)?;
        let ceremony: Ceremony<PasskeyRegistration> =
            open(&service.oauth, &headers, REGISTRATION_PURPOSE, now)?;
        if ceremony.user.as_deref() != Some(account.token.name.as_str()) {
            return Err(CEREMONY_EXPIRED);
        }
        let passkey = service
            .passkeys
            .finish_registration(&request.credential, &ceremony.state)
            .map_err(|error| {
                tracing::warn!(reason = PASSKEY_FAILED.kind, %error, "passkey registration verification failed");
                PASSKEY_FAILED
            })?;
        let device_bound = !authenticator(&request.credential).backup_eligible;
        check_account(
            &service.oauth.directory,
            &account.user,
            Method::Passkey { device_bound },
        )
        .await?;
        if service
            .used_ceremonies
            .first_use(&ceremony.id, ceremony.expires_at, "", now)
            != Use::First
        {
            return Err(CEREMONY_EXPIRED);
        }
        let stored = new_passkey(
            &passkey,
            &account.user.name,
            &request.credential,
            request.label.as_deref(),
            now,
        )?;
        audit.credential = Some(stored.name.clone());
        audit.aaguid.clone_from(&stored.aaguid);
        match service
            .credentials
            .create(&stored)
            .await
            .map_err(internal)?
        {
            CreateCredential::Created => {}
            CreateCredential::AlreadyExists => return Err(PASSKEY_EXISTS),
        }
        record(&service, &account.user, "PasskeyAdded", &audit, now).await;
        let mut response = done(false, accepted(&service, &account.user).await);
        clear_cookie(&mut response, CEREMONY_COOKIE, "Strict");
        user = Some(account.user);
        Ok(response)
    }
    .await;
    log_outcome("account.passkey_added", user.as_ref(), &audit, &result);
    result.unwrap_or_else(IntoResponse::into_response)
}

async fn rename<D, G, C, K, S>(
    State(service): State<Shared<D, G, C, K, S>>,
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
{
    let now = service.oauth.now();
    let mut user = None;
    let mut audit = Audit {
        requester: Some(&requester),
        ..Audit::default()
    };
    let result: Result<Response, Problem> = async {
        let request: RenameRequest = parse(&body)?;
        let account = signed_in(&service, &headers, now).await?;
        audit.session = Some(account.token.name.clone());
        let label = clean_label(Some(&request.label)).ok_or(BAD_REQUEST)?;
        let passkeys = service
            .credentials
            .passkeys(&account.user)
            .await
            .map_err(internal)?;
        let target = passkeys
            .iter()
            .find(|p| p.name == request.name)
            .ok_or(NOT_FOUND)?;
        audit.credential = Some(target.name.clone());
        audit.aaguid.clone_from(&target.aaguid);
        match service
            .credentials
            .rename(&account.user, &target.name, &label)
            .await
            .map_err(internal)?
        {
            Rename::Renamed => {}
            Rename::NotFound => return Err(NOT_FOUND),
        }
        record(&service, &account.user, "PasskeyRenamed", &audit, now).await;
        user = Some(account.user);
        Ok(done(false, None))
    }
    .await;
    log_outcome("account.passkey_renamed", user.as_ref(), &audit, &result);
    result.unwrap_or_else(IntoResponse::into_response)
}

/// Revokes the user's sessions and grants that signed in, or last re-authenticated, with
/// `credential`. Returns how many, and whether `current` was one of them.
pub(crate) async fn revoke_by_credential<D, G, C, K, S>(
    service: &SignIn<D, G, C, K, S>,
    user: &User,
    credential: &str,
    current: &str,
) -> Result<(usize, bool), Problem>
where
    D: Directory,
    G: GrantStore,
    C: Clock,
    K: CredentialStore,
    S: SetupStore,
{
    let grants = service.oauth.grants.list(user).await.map_err(internal)?;
    let mut revoked = 0;
    let mut signed_out = false;
    for grant in grants {
        let signed_in_with = grant.spec.credential.as_deref() == Some(credential)
            || grant
                .reauth
                .as_ref()
                .is_some_and(|r| r.credential.as_deref() == Some(credential));
        if signed_in_with {
            service
                .oauth
                .grants
                .revoke(&grant.spec.name)
                .await
                .map_err(internal)?;
            revoked += 1;
            signed_out |= grant.spec.name == current;
        }
    }
    Ok((revoked, signed_out))
}

async fn remove<D, G, C, K, S>(
    State(service): State<Shared<D, G, C, K, S>>,
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
{
    let now = service.oauth.now();
    let mut user = None;
    let mut audit = Audit {
        requester: Some(&requester),
        ..Audit::default()
    };
    let result: Result<Response, Problem> = async {
        let request: NameRequest = parse(&body)?;
        let account = signed_in(&service, &headers, now).await?;
        audit.session = Some(account.token.name.clone());
        require_fresh(&account, now)?;
        let passkeys = service
            .credentials
            .passkeys(&account.user)
            .await
            .map_err(internal)?;
        let target = passkeys
            .iter()
            .find(|p| p.name == request.name)
            .ok_or(NOT_FOUND)?;
        audit.credential = Some(target.name.clone());
        audit.aaguid.clone_from(&target.aaguid);
        match service
            .credentials
            .remove(&account.user, &target.name)
            .await
            .map_err(internal)?
        {
            Removal::Removed => {}
            Removal::LastPasskey => return Err(LAST_PASSKEY),
            Removal::NotFound => return Err(NOT_FOUND),
            Removal::Conflict => return Err(CONFLICT),
        }
        let (revoked, signed_out) =
            revoke_by_credential(&service, &account.user, &target.name, &account.token.name)
                .await?;
        audit.revoked = revoked;
        record(&service, &account.user, "PasskeyRemoved", &audit, now).await;
        let signal = accepted(&service, &account.user).await;
        user = Some(account.user);
        Ok(done(signed_out, signal))
    }
    .await;
    log_outcome("account.passkey_removed", user.as_ref(), &audit, &result);
    result.unwrap_or_else(IntoResponse::into_response)
}

async fn unlink<D, G, C, K, S>(
    State(service): State<Shared<D, G, C, K, S>>,
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
{
    let now = service.oauth.now();
    let mut user = None;
    let mut audit = Audit {
        requester: Some(&requester),
        ..Audit::default()
    };
    let result: Result<Response, Problem> = async {
        let request: NameRequest = parse(&body)?;
        let account = signed_in(&service, &headers, now).await?;
        audit.session = Some(account.token.name.clone());
        require_fresh(&account, now)?;
        let linked = service
            .credentials
            .linked_accounts(&account.user)
            .await
            .map_err(internal)?;
        let target = linked
            .iter()
            .find(|l| l.name == request.name)
            .ok_or(NOT_FOUND)?;
        audit.credential = Some(target.name.clone());
        match service
            .credentials
            .unlink(&account.user, &target.name)
            .await
            .map_err(internal)?
        {
            Unlink::Unlinked => {}
            Unlink::LastCredential => return Err(LAST_CREDENTIAL),
            Unlink::NotFound => return Err(NOT_FOUND),
            Unlink::Conflict => return Err(CONFLICT),
        }
        let (revoked, signed_out) =
            revoke_by_credential(&service, &account.user, &target.name, &account.token.name)
                .await?;
        audit.revoked = revoked;
        record(&service, &account.user, "AccountUnlinked", &audit, now).await;
        user = Some(account.user);
        Ok(done(signed_out, None))
    }
    .await;
    log_outcome("account.upstream_unlinked", user.as_ref(), &audit, &result);
    result.unwrap_or_else(IntoResponse::into_response)
}

async fn revoke<D, G, C, K, S>(
    State(service): State<Shared<D, G, C, K, S>>,
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
{
    let now = service.oauth.now();
    let mut user = None;
    let mut audit = Audit {
        requester: Some(&requester),
        ..Audit::default()
    };
    let result: Result<Response, Problem> = async {
        let request: NameRequest = parse(&body)?;
        let account = signed_in(&service, &headers, now).await?;
        let grants = service
            .oauth
            .grants
            .list(&account.user)
            .await
            .map_err(internal)?;
        let target = grants
            .iter()
            .find(|g| g.spec.name == request.name)
            .ok_or(NOT_FOUND)?;
        audit.session = Some(target.spec.name.clone());
        audit.credential.clone_from(&target.spec.credential);
        service
            .oauth
            .grants
            .revoke(&target.spec.name)
            .await
            .map_err(internal)?;
        audit.revoked = 1;
        record(&service, &account.user, "SessionRevoked", &audit, now).await;
        let signed_out = target.spec.name == account.token.name;
        user = Some(account.user);
        Ok(done(signed_out, None))
    }
    .await;
    log_outcome("account.session_revoked", user.as_ref(), &audit, &result);
    result.unwrap_or_else(IntoResponse::into_response)
}

async fn revoke_others<D, G, C, K, S>(
    State(service): State<Shared<D, G, C, K, S>>,
    requester: Requester,
    headers: HeaderMap,
) -> Response
where
    D: Directory,
    G: GrantStore,
    C: Clock,
    K: CredentialStore,
    S: SetupStore,
{
    let now = service.oauth.now();
    let mut user = None;
    let mut audit = Audit {
        requester: Some(&requester),
        ..Audit::default()
    };
    let result: Result<Response, Problem> = async {
        let account = signed_in(&service, &headers, now).await?;
        let grants = service
            .oauth
            .grants
            .list(&account.user)
            .await
            .map_err(internal)?;
        for grant in grants.iter().filter(|g| g.spec.name != account.token.name) {
            service
                .oauth
                .grants
                .revoke(&grant.spec.name)
                .await
                .map_err(internal)?;
            audit.revoked += 1;
        }
        record(&service, &account.user, "SessionRevoked", &audit, now).await;
        user = Some(account.user);
        Ok(done(false, None))
    }
    .await;
    log_outcome("account.sessions_revoked", user.as_ref(), &audit, &result);
    result.unwrap_or_else(IntoResponse::into_response)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_tokens_round_trip_and_reject_refresh_tokens() {
        let token = SessionToken::generate().unwrap();
        assert_eq!(SessionToken::parse(&token.encode()), Some(token.clone()));
        assert!(token.name().starts_with("s-") && token.name().len() == 66);
        let refresh = token.encode().replacen("s-", "g-", 1);
        assert_eq!(SessionToken::parse(&refresh), None);
        assert_eq!(SessionToken::parse(token.name()), None);
    }
}
