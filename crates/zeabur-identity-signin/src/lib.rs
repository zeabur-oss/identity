#![doc = include_str!("../README.md")]

pub mod account;
mod audit;
pub mod device;
mod method;
pub mod pages;
pub mod passkeys;
pub mod password;
pub mod problem;
mod request;
pub mod upstream;

#[cfg(test)]
mod contract;

use std::sync::Arc;

use axum::Router;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use schemars::JsonSchema;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use webauthn_rs::prelude::{
    DiscoverableAuthentication, Passkey, PasskeyRegistration, PublicKeyCredential,
    RegisterPublicKeyCredential, Uuid,
};
use zeabur_identity_api::credential::MAX_LABEL;
use zeabur_identity_api::token_hash;
use zeabur_identity_core::account::{Method, Refusal, allows};
use zeabur_identity_core::clock::{Clock, UnixTime};
use zeabur_identity_core::crypto::{ct_eq, hex, random};
use zeabur_identity_core::protocol::SETUP_PATH;
use zeabur_identity_oauth::endpoints::FLOW_COOKIE;
use zeabur_identity_oauth::{AuthorizationServer, OneTimeIds, Use};
use zeabur_identity_store::{
    Consume, CreateCredential, CredentialStore, Directory, GrantStore, NewPasskey, SetupStore,
    User, invitation_name,
};

use crate::account::{Audit, record};
use crate::audit::Record;
use crate::device::Requester;
use crate::method::{SignInMethod, finish};
use crate::passkeys::{Passkeys, aaguid, backup_flags, credential_name};
use crate::password::Passwords;
use crate::problem::{Extensions, Problem, Step, UnknownCredential};
use crate::request::{Body, SameOrigin};
use crate::upstream::provider::Providers;

/// Cookie holding the sealed WebAuthn ceremony state (`SameSite=Strict`).
///
/// webauthn-rs expects relying parties to keep ceremony state on the server. Sealing it with a
/// key that exists only in this process, bound to a purpose and an expiry, and recording each
/// ceremony ID once it has verified ([`SignIn::used_ceremonies`]) gives the same protection
/// against replay without a storage write before authentication.
pub const CEREMONY_COOKIE: &str = "__Host-zeabur-identity-webauthn";
const REGISTRATION_PURPOSE: &str = "zeabur-identity/registration/v1";
const SIGN_IN_PURPOSE: &str = "zeabur-identity/sign-in/v1";
/// How long a ceremony may take (WebAuthn Level 3 recommends 300 s for UV-required ceremonies).
pub(crate) const CEREMONY_LIFETIME: std::time::Duration = std::time::Duration::from_mins(5);

/// The stores and clock the sign-in routes use.
pub trait Backend: Send + Sync + 'static {
    /// Users, clients and settings.
    type Directory: Directory;
    /// Grants: OAuth refresh token families and account sessions.
    type Grants: GrantStore;
    /// The clock.
    type Clock: Clock;
    /// Passkeys, passwords and linked upstream accounts.
    type Credentials: CredentialStore;
    /// Setup links and invitations.
    type Setup: SetupStore;
}

/// Sign-in state shared by the handlers.
pub struct SignIn<B: Backend> {
    /// The authorization server whose pending requests sign-ins complete.
    pub oauth: Arc<AuthorizationServer<B::Directory, B::Grants, B::Clock>>,
    /// The relying party.
    pub passkeys: Passkeys,
    /// Stored passkeys.
    pub credentials: B::Credentials,
    /// The setup token.
    pub setup: B::Setup,
    /// Ceremony identifiers already used.
    pub used_ceremonies: OneTimeIds,
    /// The upstream providers, shared with the sign-in pages and the upstream routes.
    pub providers: Arc<Providers>,
    /// Password hashing and device cookies.
    pub passwords: Passwords,
}

impl<B: Backend> std::fmt::Debug for SignIn<B> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignIn")
            .field("passkeys", &self.passkeys)
            .field("providers", &self.providers)
            .finish_non_exhaustive()
    }
}

pub(crate) type Shared<B> = Arc<SignIn<B>>;

/// A webauthn-rs value in its JSON form, which has no schema: the options the browser's
/// credential calls take, and the credentials they return. The pages convert them with the
/// helpers in `ui/src/webauthn.ts`.
pub(crate) struct WebAuthnJson;

impl JsonSchema for WebAuthnJson {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "WebAuthnJson".into()
    }

    fn json_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({
            "description": "A webauthn-rs value in its JSON form; `ui/src/webauthn.ts` converts it.",
            "type": "object",
        })
    }
}

impl<B: Backend> request::State for Shared<B> {
    type Backend = B;

    fn sign_in(&self) -> &SignIn<B> {
        self
    }
}

/// The sign-in routes.
pub fn router<B: Backend>(service: Shared<B>) -> Router {
    Router::new()
        .route("/setup/options", post(setup_options::<B>))
        .route(SETUP_PATH, post(setup_finish::<B>))
        .route("/login/options", post(login_options::<B>))
        .route("/login", post(login_finish::<B>))
        .route("/login/password", post(password::sign_in::<B>))
        .route("/setup/password", post(password::set_up::<B>))
        .route(
            "/setup/password/options",
            post(password::set_up_options::<B>),
        )
        .merge(account::routes::<B>())
        .layer(request::no_store())
        .merge(account::passkey_endpoints::<B>())
        .layer(axum::middleware::from_fn(problem::localize))
        .with_state(service)
}

pub(crate) const BAD_REQUEST: Problem = Problem::new(
    StatusCode::BAD_REQUEST,
    "bad-request",
    "Unable to read the request body. Send the JSON this endpoint expects.",
);
pub(crate) const SETUP_INVALID: Problem = Problem::new(
    StatusCode::UNAUTHORIZED,
    "setup-invalid",
    "This setup link is invalid, already used, or expired. Ask your cluster administrator for a new link.",
).detail(|m| m.setup_invalid).next(Step::NewLink);
pub(crate) const ACCOUNT_DISABLED: Problem = Problem::new(
    StatusCode::FORBIDDEN,
    "account-disabled",
    "This account is disabled, so the link does not work. Ask your cluster administrator to enable it.",
).detail(|m| m.account_disabled);
pub(crate) const CEREMONY_EXPIRED: Problem = Problem::new(
    StatusCode::BAD_REQUEST,
    "ceremony-expired",
    "The passkey prompt expired. Start again.",
)
.detail(|m| m.ceremony_expired);
pub(crate) const PASSKEY_FAILED: Problem = Problem::new(
    StatusCode::UNAUTHORIZED,
    "passkey-failed",
    "Unable to verify the passkey.",
)
.detail(|m| m.passkey_failed);
pub(crate) const ADMIN_NEEDS_PASSKEY: Problem = Problem::new(
    StatusCode::FORBIDDEN,
    "admin-needs-passkey",
    "Admin accounts sign in with a passkey only.",
)
.detail(|m| m.admin_passkey_only);
pub(crate) const DEVICE_PASSKEY_NEEDED: Problem = Problem::new(
    StatusCode::FORBIDDEN,
    "device-passkey-needed",
    "Admin accounts need a security key or a passkey that stays on one device.",
)
.detail(|m| m.device_passkey_needed);
pub(crate) const ADMIN_NEEDS_TWO_FACTOR: Problem = Problem::new(
    StatusCode::FORBIDDEN,
    "admin-needs-two-factor",
    "Admin accounts sign in with a passkey, or a password and an authenticator code.",
)
.detail(|m| m.admin_two_factor);
pub(crate) const NO_REQUEST: Problem = Problem::new(
    StatusCode::BAD_REQUEST,
    "no-request",
    "No sign-in is in progress. Go back to the app and start again.",
)
.next(Step::Ended);

/// Reads a cookie by name from the request.
#[must_use]
pub fn cookie<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .find(|(key, _)| *key == name)
        .map(|(_, value)| value)
}

pub(crate) fn set_cookie(response: &mut Response, name: &str, value: &str, max_age: u64) {
    set_cookie_with(response, name, value, max_age, "Strict");
}

pub(crate) fn set_cookie_with(
    response: &mut Response,
    name: &str,
    value: &str,
    max_age: u64,
    same_site: &str,
) {
    let cookie = format!(
        "{name}={value}; Path=/; Secure; HttpOnly; SameSite={same_site}; Max-Age={max_age}"
    );
    if let Ok(value) = HeaderValue::try_from(cookie) {
        response.headers_mut().append(header::SET_COOKIE, value);
    }
}

pub(crate) fn clear_cookie(response: &mut Response, name: &str, same_site: &str) {
    let cookie = format!("{name}=; Path=/; Secure; HttpOnly; SameSite={same_site}; Max-Age=0");
    if let Ok(value) = HeaderValue::try_from(cookie) {
        response.headers_mut().append(header::SET_COOKIE, value);
    }
}

pub(crate) fn json<T: Serialize>(status: StatusCode, body: &T) -> Response {
    (status, axum::Json(body)).into_response()
}

/// Sealed ceremony state.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct Ceremony<T> {
    pub(crate) id: String,
    pub(crate) state: T,
    /// What the ceremony is bound to: the user a setup token was for, or the account session.
    pub(crate) user: Option<String>,
    pub(crate) expires_at: UnixTime,
}

pub(crate) fn seal<T: Serialize, D, G, C>(
    oauth: &AuthorizationServer<D, G, C>,
    purpose: &str,
    state: T,
    user: Option<String>,
    now: UnixTime,
) -> Result<String, Problem> {
    let ceremony = Ceremony {
        id: hex(&random::<16>().map_err(Problem::internal)?),
        state,
        user,
        expires_at: now.saturating_add(CEREMONY_LIFETIME),
    };
    let json = serde_json::to_vec(&ceremony).map_err(Problem::internal)?;
    oauth.sealer.seal(purpose, &json).map_err(Problem::internal)
}

pub(crate) fn open<T: DeserializeOwned, D, G, C>(
    oauth: &AuthorizationServer<D, G, C>,
    headers: &HeaderMap,
    purpose: &str,
    now: UnixTime,
) -> Result<Ceremony<T>, Problem> {
    let sealed = cookie(headers, CEREMONY_COOKIE).ok_or(CEREMONY_EXPIRED)?;
    let ceremony: Ceremony<T> = oauth
        .sealer
        .open(purpose, sealed)
        .and_then(|json| serde_json::from_slice(&json).ok())
        .ok_or(CEREMONY_EXPIRED)?;
    if ceremony.expires_at <= now {
        Err(CEREMONY_EXPIRED)
    } else {
        Ok(ceremony)
    }
}

/// A label as given, trimmed and shortened, or `None` if empty.
pub(crate) fn clean_label(label: Option<&str>) -> Option<String> {
    let label: String = label?.trim().chars().take(MAX_LABEL).collect();
    let label = label.trim_end().to_owned();
    (!label.is_empty()).then_some(label)
}

/// The record to store for a newly registered passkey. The label is the one the user typed, if
/// any. The account page shows a passkey without a label by its creation date.
pub(crate) fn new_passkey(
    passkey: &Passkey,
    user: &str,
    response: &RegisterPublicKeyCredential,
    label: Option<&str>,
    now: UnixTime,
) -> Result<NewPasskey, Problem> {
    let credential_id: Vec<u8> = AsRef::<[u8]>::as_ref(passkey.cred_id()).to_vec();
    Ok(NewPasskey {
        name: credential_name(&credential_id),
        user: user.to_owned(),
        credential_id: URL_SAFE_NO_PAD.encode(&credential_id),
        record: serde_json::to_string(passkey).map_err(Problem::internal)?,
        label: clean_label(label),
        aaguid: aaguid(response),
        backup_eligible: backup_flags(passkey).eligible,
        created_at: now,
    })
}

/// Refuses `user` if their account type does not allow `method` under the current settings (see
/// [`allows`]).
pub(crate) async fn check_account<D: Directory>(
    directory: &D,
    user: &User,
    method: Method,
) -> Result<(), Problem> {
    let settings = directory.settings().await.map_err(Problem::internal)?;
    allows(user.account_type, settings, method).map_err(|refusal| refused(user, refusal))
}

/// The answer to a sign-in method the account type does not allow.
pub(crate) fn refused(user: &User, refusal: Refusal) -> Problem {
    tracing::warn!(reason = ?refusal, user = %user.name, "the account type does not allow this sign-in method");
    match refusal {
        Refusal::Passkey => ADMIN_NEEDS_PASSKEY,
        Refusal::DeviceBoundPasskey => DEVICE_PASSKEY_NEEDED,
        Refusal::TwoFactor => ADMIN_NEEDS_TWO_FACTOR,
    }
}

/// A verified assertion.
pub(crate) struct Verified {
    pub(crate) user: User,
    /// `Credential` object name.
    pub(crate) credential: String,
    pub(crate) last_used_at: Option<UnixTime>,
    /// The authenticator reported BE unset at registration.
    pub(crate) device_bound: bool,
}

/// A refused assertion, with the credential ID when it is not registered here.
pub(crate) struct Refused {
    pub(crate) problem: Problem,
    pub(crate) unknown: Option<Vec<u8>>,
}

impl From<Problem> for Refused {
    fn from(problem: Problem) -> Self {
        Self {
            problem,
            unknown: None,
        }
    }
}

/// Verifies a discoverable assertion against the stored credential it names. Every failure
/// gives the same answer, so responses do not reveal which users or credentials exist; only an
/// unregistered credential ID is passed back, for `signalUnknownCredential`.
pub(crate) async fn verify_assertion<B: Backend>(
    service: &SignIn<B>,
    response: &PublicKeyCredential,
    state: DiscoverableAuthentication,
) -> Result<Verified, Refused> {
    let (handle, credential_id) = service.passkeys.identify(response).map_err(|error| {
        tracing::warn!(reason = PASSKEY_FAILED.kind, %error, "passkey identification failed");
        PASSKEY_FAILED
    })?;
    let credential = credential_name(&credential_id);
    let Some(stored) = service
        .credentials
        .get(&credential)
        .await
        .map_err(Problem::internal)?
    else {
        return Err(Refused {
            problem: PASSKEY_FAILED,
            unknown: Some(credential_id),
        });
    };
    let user = service
        .oauth
        .directory
        .user(&stored.user)
        .await
        .map_err(Problem::internal)?
        .ok_or(PASSKEY_FAILED)?;
    // The user handle in the assertion must be the credential owner's (WebAuthn Level 3 §7.2).
    if user.disabled || user.subject != handle.to_string() {
        return Err(PASSKEY_FAILED.into());
    }
    let passkey: Passkey = serde_json::from_str(&stored.record).map_err(Problem::internal)?;
    let result = service
        .passkeys
        .finish_sign_in(response, state, &passkey)
        .map_err(|error| {
            tracing::warn!(reason = PASSKEY_FAILED.kind, %error, "passkey sign-in verification failed");
            PASSKEY_FAILED
        })?;
    // Checked after the assertion verifies, so the answer says nothing about unproven keys.
    // A credential can become eligible for backup after enrolment, so both must say no.
    let device_bound = !backup_flags(&passkey).eligible && !result.backup_eligible();
    check_account(
        &service.oauth.directory,
        &user,
        Method::Passkey { device_bound },
    )
    .await?;
    Ok(Verified {
        user,
        credential,
        last_used_at: stored.last_used_at,
        device_bound,
    })
}

impl Refused {
    /// The response, with `unknownCredential` for an unregistered credential.
    pub(crate) fn respond(self, rp_id: &str) -> Response {
        match self.unknown {
            Some(id) => self.problem.with(Extensions {
                unknown_credential: Some(UnknownCredential {
                    rp_id: rp_id.to_owned(),
                    credential_id: URL_SAFE_NO_PAD.encode(id),
                }),
                ..Extensions::default()
            }),
            None => self.problem.into_response(),
        }
    }
}

/// Records when a passkey signed in, at most once a minute. Failures are only logged.
pub(crate) async fn touch<B: Backend>(service: &SignIn<B>, verified: &Verified, now: UnixTime) {
    let recent = verified
        .last_used_at
        .is_some_and(|last| now.as_secs().saturating_sub(last.as_secs()) < 60);
    if recent {
        return;
    }
    if let Err(error) = service.credentials.touch(&verified.credential, now).await {
        tracing::warn!(reason = "touch_failed", %error, "recording passkey use failed");
    }
}

/// The user's registered credentials, for `signalAllAcceptedCredentials` (WebAuthn Level 3
/// §5.1.10.2). Only a complete list read from storage is sent; an empty one never is, so a
/// failed or partial read cannot make a provider hide working passkeys.
#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Accepted {
    rp_id: String,
    user_id: String,
    all_accepted_credential_ids: Vec<String>,
}

pub(crate) async fn accepted<B: Backend>(service: &SignIn<B>, user: &User) -> Option<Accepted> {
    let passkeys = match service.credentials.passkeys(user).await {
        Ok(passkeys) => passkeys,
        Err(error) => {
            tracing::warn!(reason = "passkey_list_failed", %error, "listing passkeys failed");
            return None;
        }
    };
    let handle = Uuid::parse_str(&user.subject).ok()?;
    (!passkeys.is_empty()).then(|| Accepted {
        rp_id: service.passkeys.rp_id().to_owned(),
        user_id: URL_SAFE_NO_PAD.encode(handle.as_bytes()),
        all_accepted_credential_ids: passkeys.into_iter().map(|p| p.credential_id).collect(),
    })
}

#[derive(Deserialize, JsonSchema)]
#[schemars(rename = "PasskeySetupOptionsRequest")]
pub(crate) struct SetupOptionsRequest {
    token: String,
}

#[derive(Deserialize, JsonSchema)]
#[schemars(rename = "PasskeySetupRequest")]
pub(crate) struct SetupRequest {
    token: String,
    /// The new credential, in the webauthn-rs `RegisterPublicKeyCredential` form.
    #[schemars(with = "WebAuthnJson")]
    credential: RegisterPublicKeyCredential,
    #[serde(default)]
    label: Option<String>,
}

#[derive(Serialize, JsonSchema)]
#[schemars(rename = "PasskeySetUp")]
pub(crate) struct SetupResponse<'a> {
    username: &'a str,
}

/// The `Event` reason for a redeemed setup link or invitation.
pub(crate) fn redeemed(token: &str) -> &'static str {
    if invitation_name(token).is_some() {
        "InvitationRedeemed"
    } else {
        "SetupLinkRedeemed"
    }
}

/// Checks a presented setup token against the stored one. Returns the stored token and its
/// current `User`.
///
/// The `User` must have the UID the token was issued for. A token left over from a deleted
/// `User` thus does not enrol a new `User` with the same name. A disabled `User` cannot redeem
/// a token: otherwise a suspended person could add a passkey that works when the account is
/// enabled again.
pub(crate) async fn valid_setup_token<S: SetupStore, D: Directory>(
    setup: &S,
    directory: &D,
    presented: &str,
    now: UnixTime,
) -> Result<(zeabur_identity_store::SetupToken, User), Problem> {
    let stored = setup
        .load(presented)
        .await
        .map_err(Problem::internal)?
        .ok_or(SETUP_INVALID)?;
    let matches = ct_eq(
        token_hash(presented.as_bytes()).as_bytes(),
        stored.token_hash.as_bytes(),
    );
    if !matches || stored.expires_at <= now {
        return Err(SETUP_INVALID);
    }
    let user = directory
        .user(&stored.user)
        .await
        .map_err(Problem::internal)?
        .ok_or_else(|| {
            tracing::error!(
                reason = "user_unavailable",
                "the setup token names a user that does not exist"
            );
            SETUP_INVALID
        })?;
    if !stored.is_for(&user) {
        tracing::warn!(
            reason = "user_replaced",
            "the setup token was issued for an earlier user of this name"
        );
        return Err(SETUP_INVALID);
    }
    if user.disabled {
        return Err(ACCOUNT_DISABLED);
    }
    Ok((stored, user))
}

async fn setup_options<B: Backend>(
    State(service): State<Shared<B>>,
    request: Result<Body<SameOrigin, SetupOptionsRequest>, Problem>,
) -> Response {
    let mut identity = None;
    let result: Result<Response, Problem> = async {
        let Body(SameOrigin, request) = request?;
        let now = service.oauth.now();
        let (_, user) = valid_setup_token(
            &service.setup,
            &service.oauth.directory,
            &request.token,
            now,
        )
        .await?;
        identity = Some(user);
        let user = identity.as_ref().ok_or(SETUP_INVALID)?;
        let handle = Uuid::parse_str(&user.subject).map_err(Problem::internal)?;
        let display = user.display_name.as_deref().unwrap_or(&user.username);
        let (options, state) = service
            .passkeys
            .begin_registration(handle, &user.username, display, Vec::new())
            .map_err(Problem::internal)?;
        let sealed = seal::<PasskeyRegistration, _, _, _>(
            &service.oauth,
            REGISTRATION_PURPOSE,
            state,
            Some(user.name.clone()),
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
    let record = Record {
        event: "auth.passkey_enrollment",
        messages: ["passkey enrollment started", "passkey enrollment failed"],
        phase: Some("start"),
        method: Some("passkey"),
        user: identity.as_ref().map(|u| u.name.as_str()),
        subject: identity.as_ref().map(|u| u.subject.as_str()),
        ..Record::default()
    };
    record.log(result.as_ref().err().map(|p| p.kind));
    result.unwrap_or_else(IntoResponse::into_response)
}

async fn setup_finish<B: Backend>(
    State(service): State<Shared<B>>,
    headers: HeaderMap,
    requester: Requester,
    request: Result<Body<SameOrigin, SetupRequest>, Problem>,
) -> Response {
    let mut user = None;
    let result: Result<Response, Problem> = async {
        let Body(SameOrigin, request) = request?;
        let now = service.oauth.now();
        let ceremony: Ceremony<PasskeyRegistration> =
            open(&service.oauth, &headers, REGISTRATION_PURPOSE, now)?;
        let (token, owner) = valid_setup_token(
            &service.setup,
            &service.oauth.directory,
            &request.token,
            now,
        )
        .await?;
        user = Some(token.user.clone());
        // The ceremony must have been started with this token's user.
        if ceremony.user.as_deref() != Some(token.user.as_str()) {
            return Err(SETUP_INVALID);
        }
        let passkey: Passkey = service
            .passkeys
            .finish_registration(&request.credential, &ceremony.state)
            .map_err(|error| {
                tracing::warn!(reason = PASSKEY_FAILED.kind, %error, "passkey registration verification failed");
                PASSKEY_FAILED
            })?;
        // Refused before the token is used, so the person can try again with another passkey.
        let device_bound = !backup_flags(&passkey).eligible;
        check_account(&service.oauth.directory, &owner, Method::Passkey { device_bound }).await?;
        if service
            .used_ceremonies
            .first_use(&ceremony.id, ceremony.expires_at, "", now)
            != Use::First
        {
            return Err(CEREMONY_EXPIRED);
        }
        // Consume the token before storing the passkey: if two registrations race, only the one
        // that consumed the token may add a credential.
        if service.setup.consume(&token).await.map_err(Problem::internal)? == Consume::AlreadyUsed {
            return Err(SETUP_INVALID);
        }
        let stored = new_passkey(
            &passkey,
            &token.user,
            &request.credential,
            request.label.as_deref(),
            now,
        )?;
        match service
            .credentials
            .create(&stored)
            .await
            .map_err(Problem::internal)?
        {
            CreateCredential::Created => {}
            CreateCredential::AlreadyExists => {
                return Err(Problem::new(
                    StatusCode::CONFLICT,
                    "passkey-exists",
                    "This passkey is already registered. Sign in with it instead.",
                )
                .detail(|m| m.setup_passkey_exists));
            }
        }
        let audit = Audit {
            credential: Some(stored.name.clone()),
            aaguid: stored.aaguid.clone(),
            requester: Some(&requester),
            ..Audit::default()
        };
        record(&service, &owner, redeemed(&request.token), &audit, now).await;
        let mut response = json(
            StatusCode::CREATED,
            &SetupResponse {
                username: &token.user,
            },
        );
        clear_cookie(&mut response, CEREMONY_COOKIE, "Strict");
        Ok(response)
    }
    .await;
    let record = Record {
        event: "auth.passkey_enrollment",
        messages: ["passkey enrolled", "passkey enrollment failed"],
        phase: Some("finish"),
        method: Some("passkey"),
        user: user.as_deref(),
        ..Record::default()
    };
    record.log(result.as_ref().err().map(|p| p.kind));
    result.unwrap_or_else(IntoResponse::into_response)
}

#[derive(Deserialize, JsonSchema)]
#[schemars(rename = "PasskeySignInRequest")]
pub(crate) struct SignInRequest {
    /// The assertion, in the webauthn-rs `PublicKeyCredential` form.
    #[schemars(with = "WebAuthnJson")]
    credential: PublicKeyCredential,
}

async fn login_options<B: Backend>(
    State(service): State<Shared<B>>,
    origin: Result<SameOrigin, Problem>,
) -> Response {
    let result: Result<Response, Problem> = (|| {
        let SameOrigin = origin?;
        let now = service.oauth.now();
        let (options, state) = service
            .passkeys
            .begin_sign_in()
            .map_err(Problem::internal)?;
        let sealed = seal::<DiscoverableAuthentication, _, _, _>(
            &service.oauth,
            SIGN_IN_PURPOSE,
            state,
            None,
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
    })();
    let record = Record {
        event: "auth.passkey_options",
        messages: ["passkey options accepted", "passkey options failed"],
        method: Some("passkey"),
        ..Record::default()
    };
    record.log(result.as_ref().err().map(|p| p.kind));
    result.unwrap_or_else(IntoResponse::into_response)
}

#[derive(Serialize, JsonSchema)]
#[schemars(rename = "PasskeySignedIn")]
pub(crate) struct SignInResponse {
    redirect_to: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    accepted: Option<Accepted>,
}

async fn login_finish<B: Backend>(
    State(service): State<Shared<B>>,
    headers: HeaderMap,
    request: Result<Body<SameOrigin, SignInRequest>, Problem>,
) -> Response {
    let mut identity = None;
    let result: Result<Response, Refused> = async {
        let Body(SameOrigin, request) = request?;
        let now = service.oauth.now();
        let flow = cookie(&headers, FLOW_COOKIE).ok_or(NO_REQUEST)?.to_owned();
        let ceremony: Ceremony<DiscoverableAuthentication> =
            open(&service.oauth, &headers, SIGN_IN_PURPOSE, now)?;
        let verified = verify_assertion(&service, &request.credential, ceremony.state).await?;
        // A credential lookup alone does not authenticate the submitted assertion.
        let user = identity.insert(verified.user.clone());
        // The challenge is single-use once it has produced a successful assertion.
        if service
            .used_ceremonies
            .first_use(&ceremony.id, ceremony.expires_at, "", now)
            != Use::First
        {
            return Err(CEREMONY_EXPIRED.into());
        }

        let method = SignInMethod::Passkey {
            device_bound: verified.device_bound,
        };
        let authentication = method.authentication(user, verified.credential.clone(), now);
        let location = finish(&service.oauth, &flow, authentication).ok_or(NO_REQUEST)?;
        touch(&service, &verified, now).await;
        let mut response = json(
            StatusCode::OK,
            &SignInResponse {
                redirect_to: location,
                accepted: accepted(&service, user).await,
            },
        );
        service
            .passwords
            .remember(&mut response, &headers, &user.subject);
        clear_cookie(&mut response, CEREMONY_COOKIE, "Strict");
        clear_cookie(&mut response, FLOW_COOKIE, "Lax");
        Ok(response)
    }
    .await;
    let record = Record {
        event: "auth.sign_in",
        messages: ["signed in with a passkey", "passkey sign-in failed"],
        method: Some("passkey"),
        user: identity.as_ref().map(|u| u.name.as_str()),
        subject: identity.as_ref().map(|u| u.subject.as_str()),
        ..Record::default()
    };
    record.log(result.as_ref().err().map(|r| r.problem.kind));
    result.unwrap_or_else(|refused| refused.respond(service.passkeys.rp_id()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&'static str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.append(*name, HeaderValue::from_str(value).unwrap());
        }
        map
    }

    #[test]
    fn reads_cookies() {
        let h = headers(&[
            ("cookie", "a=1; __Host-zeabur-identity-flow=xyz"),
            ("cookie", "b=2"),
        ]);
        assert_eq!(cookie(&h, FLOW_COOKIE), Some("xyz"));
        assert_eq!(cookie(&h, "b"), Some("2"));
        assert_eq!(cookie(&h, "c"), None);
    }
}
