#![doc = include_str!("../README.md")]

pub mod account;
pub mod device;
pub mod pages;
pub mod passkeys;
pub mod problem;
pub mod upstream;

use std::sync::Arc;

use axum::Router;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use webauthn_rs::prelude::{
    DiscoverableAuthentication, Passkey, PasskeyRegistration, PublicKeyCredential,
    RegisterPublicKeyCredential, Uuid,
};
use zeabur_identity_api::token_hash;
use zeabur_identity_core::account::{Method, Refusal, allows};
use zeabur_identity_core::clock::{Clock, UnixTime};
use zeabur_identity_core::crypto::{ct_eq, hex, random};
use zeabur_identity_oauth::authorize::Authentication;
use zeabur_identity_oauth::endpoints::{FLOW_COOKIE, complete_authorization};
use zeabur_identity_oauth::{AuthorizationServer, OneTimeIds, Use};
use zeabur_identity_store::{
    Consume, CreateCredential, CredentialStore, Directory, GrantStore, NewPasskey, SetupStore,
    User, invitation_name,
};

use crate::account::{Audit, record};
use crate::device::Requester;
use crate::passkeys::{Passkeys, authenticator, backup_flags, credential_name};
use crate::problem::Problem;
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
/// Authentication methods asserted by a passkey sign-in (RFC 8176).
///
/// `swk`: proof of possession of a key. Attestation is `none`, so a hardware-backed key cannot be
/// claimed and `hwk` is not used. `mfa`: the authenticator verified the user with a PIN or
/// biometric in addition to possession, a multi-factor cryptographic authenticator in NIST SP
/// 800-63B-4 terms.
pub const PASSKEY_AMR: [&str; 2] = ["swk", "mfa"];

/// Sign-in state shared by the handlers.
#[derive(Debug)]
pub struct SignIn<D, G, C, K, S> {
    /// The authorization server whose pending requests sign-ins complete.
    pub oauth: Arc<AuthorizationServer<D, G, C>>,
    /// The relying party.
    pub passkeys: Passkeys,
    /// Stored passkeys.
    pub credentials: K,
    /// The setup token.
    pub setup: S,
    /// Ceremony identifiers already used.
    pub used_ceremonies: OneTimeIds,
    /// The upstream providers, shared with the sign-in pages and the upstream routes.
    pub providers: Arc<Providers>,
}

type Shared<D, G, C, K, S> = Arc<SignIn<D, G, C, K, S>>;

/// The sign-in routes.
pub fn router<D, G, C, K, S>(service: Shared<D, G, C, K, S>) -> Router
where
    D: Directory,
    G: GrantStore,
    C: Clock,
    K: CredentialStore,
    S: SetupStore,
{
    Router::new()
        .route("/setup/options", post(setup_options::<D, G, C, K, S>))
        .route("/setup", post(setup_finish::<D, G, C, K, S>))
        .route("/login/options", post(login_options::<D, G, C, K, S>))
        .route("/login", post(login_finish::<D, G, C, K, S>))
        .merge(account::routes::<D, G, C, K, S>())
        .with_state(service)
}

const CROSS_SITE: Problem = Problem::new(
    StatusCode::FORBIDDEN,
    "cross-site",
    "Send this request from the sign-in page.",
);
const NOT_JSON: Problem = Problem::new(
    StatusCode::UNSUPPORTED_MEDIA_TYPE,
    "not-json",
    "Send the request body as JSON.",
);
pub(crate) const BAD_REQUEST: Problem = Problem::new(
    StatusCode::BAD_REQUEST,
    "bad-request",
    "Unable to read the request body. Send the JSON this endpoint expects.",
);
pub(crate) const SETUP_INVALID: Problem = Problem::new(
    StatusCode::UNAUTHORIZED,
    "setup-invalid",
    "This setup link is invalid, already used, or expired. Ask your cluster administrator for a new link.",
);
pub(crate) const ACCOUNT_DISABLED: Problem = Problem::new(
    StatusCode::FORBIDDEN,
    "account-disabled",
    "This account is disabled, so the link does not work. Ask your cluster administrator to enable it.",
);
pub(crate) const CEREMONY_EXPIRED: Problem = Problem::new(
    StatusCode::BAD_REQUEST,
    "ceremony-expired",
    "The passkey prompt expired. Start again.",
);
pub(crate) const PASSKEY_FAILED: Problem = Problem::new(
    StatusCode::UNAUTHORIZED,
    "passkey-failed",
    "Unable to verify the passkey.",
);
pub(crate) const ADMIN_NEEDS_PASSKEY: Problem = Problem::new(
    StatusCode::FORBIDDEN,
    "admin-needs-passkey",
    "Admin accounts sign in with a passkey only.",
);
pub(crate) const DEVICE_PASSKEY_NEEDED: Problem = Problem::new(
    StatusCode::FORBIDDEN,
    "device-passkey-needed",
    "Admin accounts need a security key or a passkey that stays on one device.",
);
pub(crate) const NO_REQUEST: Problem = Problem::new(
    StatusCode::BAD_REQUEST,
    "no-request",
    "No sign-in is in progress. Go back to the app and start again.",
);

/// Cross-site request protection for the JSON endpoints: `Sec-Fetch-Site: same-origin`, or, for
/// browsers that do not send Fetch Metadata, an `Origin` equal to the issuer. Requests with
/// neither are refused. The JSON content type adds a CORS preflight for any cross-origin caller.
pub(crate) fn check_request(headers: &HeaderMap, issuer: &str) -> Result<(), Problem> {
    let header = |name| {
        headers
            .get(name)
            .and_then(|v: &HeaderValue| v.to_str().ok())
    };
    let allowed = match (header("sec-fetch-site"), header(header::ORIGIN.as_str())) {
        (Some(site), _) => site == "same-origin",
        (None, Some(origin)) => origin == issuer,
        (None, None) => false,
    };
    if !allowed {
        return Err(CROSS_SITE);
    }
    let json = header(header::CONTENT_TYPE.as_str())
        .and_then(|v| v.split(';').next())
        .is_some_and(|v| v.trim().eq_ignore_ascii_case("application/json"));
    if json { Ok(()) } else { Err(NOT_JSON) }
}

pub(crate) fn parse<T: DeserializeOwned>(body: &[u8]) -> Result<T, Problem> {
    serde_json::from_slice(body).map_err(|_malformed| BAD_REQUEST)
}

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
    let mut response = (status, axum::Json(body)).into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

pub(crate) fn internal(error: impl std::fmt::Display) -> Problem {
    tracing::error!(reason = "internal_error", %error, "sign-in failed");
    Problem::internal()
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
        id: hex(&random::<16>().map_err(internal)?),
        state,
        user,
        expires_at: now.saturating_add(CEREMONY_LIFETIME),
    };
    let json = serde_json::to_vec(&ceremony).map_err(internal)?;
    oauth.sealer.seal(purpose, &json).map_err(internal)
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

/// The longest passkey label.
pub(crate) const LABEL_MAX: usize = 64;

/// A label as given, trimmed and shortened, or `None` if empty.
pub(crate) fn clean_label(label: Option<&str>) -> Option<String> {
    let label: String = label?.trim().chars().take(LABEL_MAX).collect();
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
    let found = authenticator(response);
    Ok(NewPasskey {
        name: credential_name(&credential_id),
        user: user.to_owned(),
        credential_id: URL_SAFE_NO_PAD.encode(&credential_id),
        record: serde_json::to_string(passkey).map_err(internal)?,
        label: clean_label(label),
        aaguid: found.aaguid,
        backup_eligible: found.backup_eligible,
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
    let settings = directory.settings().await.map_err(internal)?;
    allows(user.account_type, settings, method).map_err(|refusal| {
        tracing::warn!(reason = ?refusal, user = %user.name, "the account type does not allow this sign-in method");
        match refusal {
            Refusal::AdminNeedsPasskey => ADMIN_NEEDS_PASSKEY,
            Refusal::AdminNeedsDeviceBoundPasskey => DEVICE_PASSKEY_NEEDED,
        }
    })
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
pub(crate) async fn verify_assertion<D, G, C, K, S>(
    service: &SignIn<D, G, C, K, S>,
    response: &PublicKeyCredential,
    state: DiscoverableAuthentication,
) -> Result<Verified, Refused>
where
    D: Directory,
    G: GrantStore,
    C: Clock,
    K: CredentialStore,
    S: SetupStore,
{
    let (handle, credential_id) = service.passkeys.identify(response).map_err(|error| {
        tracing::warn!(reason = PASSKEY_FAILED.kind, %error, "passkey identification failed");
        PASSKEY_FAILED
    })?;
    let credential = credential_name(&credential_id);
    let Some(stored) = service
        .credentials
        .get(&credential)
        .await
        .map_err(internal)?
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
        .map_err(internal)?
        .ok_or(PASSKEY_FAILED)?;
    // The user handle in the assertion must be the credential owner's (WebAuthn Level 3 §7.2).
    if user.disabled || user.subject != handle.to_string() {
        return Err(PASSKEY_FAILED.into());
    }
    let passkey: Passkey = serde_json::from_str(&stored.record).map_err(internal)?;
    service
        .passkeys
        .finish_sign_in(response, state, &passkey)
        .map_err(|error| {
            tracing::warn!(reason = PASSKEY_FAILED.kind, %error, "passkey sign-in verification failed");
            PASSKEY_FAILED
        })?;
    // Checked after the assertion verifies, so the answer says nothing about unproven keys.
    // A credential can become eligible for backup after enrolment, so both must say no.
    let device_bound =
        !backup_flags(&stored.record).0 && !passkeys::assertion_backup_eligible(response);
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
            Some(id) => self.problem.with(
                "unknownCredential",
                serde_json::json!({ "rpId": rp_id, "credentialId": URL_SAFE_NO_PAD.encode(id) }),
            ),
            None => self.problem.into_response(),
        }
    }
}

/// Records when a passkey signed in, at most once a minute. Failures are only logged.
pub(crate) async fn touch<D, G, C, K, S>(
    service: &SignIn<D, G, C, K, S>,
    verified: &Verified,
    now: UnixTime,
) where
    D: Directory,
    G: GrantStore,
    C: Clock,
    K: CredentialStore,
    S: SetupStore,
{
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
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Accepted {
    rp_id: String,
    user_id: String,
    all_accepted_credential_ids: Vec<String>,
}

pub(crate) async fn accepted<D, G, C, K, S>(
    service: &SignIn<D, G, C, K, S>,
    user: &User,
) -> Option<Accepted>
where
    D: Directory,
    G: GrantStore,
    C: Clock,
    K: CredentialStore,
    S: SetupStore,
{
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

#[derive(Deserialize)]
struct SetupOptionsRequest {
    token: String,
}

#[derive(Deserialize)]
struct SetupRequest {
    token: String,
    credential: RegisterPublicKeyCredential,
    #[serde(default)]
    label: Option<String>,
}

#[derive(Serialize)]
struct SetupResponse<'a> {
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
        .map_err(internal)?
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
        .map_err(internal)?
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

async fn setup_options<D, G, C, K, S>(
    State(service): State<Shared<D, G, C, K, S>>,
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
    let mut identity = None;
    let result: Result<Response, Problem> = async {
        check_request(&headers, service.oauth.issuer.as_str())?;
        let request: SetupOptionsRequest = parse(&body)?;
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
        let handle = Uuid::parse_str(&user.subject).map_err(internal)?;
        let display = user.display_name.as_deref().unwrap_or(&user.username);
        let (options, state) = service
            .passkeys
            .begin_registration(handle, &user.username, display, Vec::new())
            .map_err(internal)?;
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
    match &result {
        Ok(_) => {
            tracing::info!(target: "zeabur_identity::audit", event = "auth.passkey_enrollment", phase = "start", outcome = "success", method = "passkey", user = identity.as_ref().map(|u| u.name.as_str()), subject = identity.as_ref().map(|u| u.subject.as_str()), "passkey enrollment started");
        }
        Err(problem) => {
            tracing::warn!(target: "zeabur_identity::audit", event = "auth.passkey_enrollment", phase = "start", outcome = "failure", method = "passkey", reason = problem.kind, user = identity.as_ref().map(|u| u.name.as_str()), subject = identity.as_ref().map(|u| u.subject.as_str()), "passkey enrollment failed");
        }
    }
    result.unwrap_or_else(IntoResponse::into_response)
}

async fn setup_finish<D, G, C, K, S>(
    State(service): State<Shared<D, G, C, K, S>>,
    headers: HeaderMap,
    requester: Requester,
    body: Bytes,
) -> Response
where
    D: Directory,
    G: GrantStore,
    C: Clock,
    K: CredentialStore,
    S: SetupStore,
{
    let mut user = None;
    let result: Result<Response, Problem> = async {
        check_request(&headers, service.oauth.issuer.as_str())?;
        let request: SetupRequest = parse(&body)?;
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
        let device_bound = !authenticator(&request.credential).backup_eligible;
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
        if service.setup.consume(&token).await.map_err(internal)? == Consume::AlreadyUsed {
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
            .map_err(internal)?
        {
            CreateCredential::Created => {}
            CreateCredential::AlreadyExists => {
                return Err(Problem::new(
                    StatusCode::CONFLICT,
                    "passkey-exists",
                    "This passkey is already registered. Sign in with it instead.",
                ));
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
    match &result {
        Ok(_) => {
            tracing::info!(target: "zeabur_identity::audit", event = "auth.passkey_enrollment", phase = "finish", outcome = "success", method = "passkey", user = user.as_deref(), "passkey enrolled");
        }
        Err(problem) => {
            tracing::warn!(target: "zeabur_identity::audit", event = "auth.passkey_enrollment", phase = "finish", outcome = "failure", method = "passkey", reason = problem.kind, user = user.as_deref(), "passkey enrollment failed");
        }
    }
    result.unwrap_or_else(IntoResponse::into_response)
}

#[derive(Deserialize)]
struct SignInRequest {
    credential: PublicKeyCredential,
}

async fn login_options<D, G, C, K, S>(
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
    let result: Result<Response, Problem> = (|| {
        check_request(&headers, service.oauth.issuer.as_str())?;
        let now = service.oauth.now();
        let (options, state) = service.passkeys.begin_sign_in().map_err(internal)?;
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
    match &result {
        Ok(_) => {
            tracing::info!(target: "zeabur_identity::audit", event = "auth.passkey_options", outcome = "success", method = "passkey", "passkey options accepted");
        }
        Err(problem) => {
            tracing::warn!(target: "zeabur_identity::audit", event = "auth.passkey_options", outcome = "failure", method = "passkey", reason = problem.kind, "passkey options failed");
        }
    }
    result.unwrap_or_else(IntoResponse::into_response)
}

#[derive(Serialize)]
struct SignInResponse {
    redirect_to: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    accepted: Option<Accepted>,
}

async fn login_finish<D, G, C, K, S>(
    State(service): State<Shared<D, G, C, K, S>>,
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
    let mut identity = None;
    let result: Result<Response, Refused> = async {
        check_request(&headers, service.oauth.issuer.as_str())?;
        let request: SignInRequest = parse(&body)?;
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

        let authentication = Authentication {
            user: user.name.clone(),
            subject: user.subject.clone(),
            auth_time: now,
            amr: PASSKEY_AMR.iter().map(|m| (*m).to_owned()).collect(),
            credential: Some(verified.credential.clone()),
            user_verified: true,
            device_bound: verified.device_bound,
        };
        let location =
            complete_authorization(&service.oauth, &flow, authentication).map_err(|error| {
                tracing::warn!(
                    reason = NO_REQUEST.kind,
                    ?error,
                    "passkey authorization failed"
                );
                NO_REQUEST
            })?;
        touch(&service, &verified, now).await;
        let mut response = json(
            StatusCode::OK,
            &SignInResponse {
                redirect_to: location,
                accepted: accepted(&service, user).await,
            },
        );
        clear_cookie(&mut response, CEREMONY_COOKIE, "Strict");
        clear_cookie(&mut response, FLOW_COOKIE, "Lax");
        Ok(response)
    }
    .await;
    match &result {
        Ok(_) => {
            tracing::info!(target: "zeabur_identity::audit", event = "auth.sign_in", outcome = "success", method = "passkey", user = identity.as_ref().map(|u| u.name.as_str()), subject = identity.as_ref().map(|u| u.subject.as_str()), "signed in with a passkey");
        }
        Err(refused) => {
            tracing::warn!(target: "zeabur_identity::audit", event = "auth.sign_in", outcome = "failure", method = "passkey", reason = refused.problem.kind, user = identity.as_ref().map(|u| u.name.as_str()), subject = identity.as_ref().map(|u| u.subject.as_str()), "passkey sign-in failed");
        }
    }
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
    fn same_origin_checks() {
        let issuer = "https://login.example.com";
        let json = ("content-type", "application/json; charset=utf-8");
        assert!(
            check_request(&headers(&[("sec-fetch-site", "same-origin"), json]), issuer).is_ok()
        );
        assert!(check_request(&headers(&[("origin", issuer), json]), issuer).is_ok());
        assert_eq!(
            check_request(
                &headers(&[("sec-fetch-site", "cross-site"), ("origin", issuer), json]),
                issuer
            ),
            Err(CROSS_SITE)
        );
        assert_eq!(
            check_request(&headers(&[("sec-fetch-site", "same-site"), json]), issuer),
            Err(CROSS_SITE)
        );
        assert_eq!(
            check_request(
                &headers(&[("origin", "https://evil.example"), json]),
                issuer
            ),
            Err(CROSS_SITE)
        );
        assert_eq!(check_request(&headers(&[json]), issuer), Err(CROSS_SITE));
        assert_eq!(
            check_request(
                &headers(&[
                    ("sec-fetch-site", "same-origin"),
                    ("content-type", "text/plain")
                ]),
                issuer
            ),
            Err(NOT_JSON)
        );
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
