//! Password sign-in, and setting a password with a setup link.
//!
//! Every failed sign-in gives the same answer, and a username without a password spends the same
//! hashing time, so answers do not tell which usernames exist. Failures are limited per browser
//! with device cookies (see [`zeabur_identity_core::guessing`]): a browser that signed in as the
//! user before keeps its own count, so guesses from elsewhere cannot lock the owner out.
//!
//! A user with a TOTP authenticator also enters a code, or a recovery code, after the password
//! (see [`zeabur_identity_core::totp`]). A wrong code counts as a failed sign-in. The setup link
//! asks for an authenticator when the account settings need a second factor for the user.
//!
//! On the account page, a signed-in user changes or removes their password with the current one,
//! checked and counted as at sign-in. A change keeps the authenticator, and the codes already used
//! stay used. A removal deletes the authenticator with the password.

use std::num::NonZeroUsize;
use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use tokio::sync::Semaphore;
use zeabur_identity_core::account::{Method, allows};
use zeabur_identity_core::clock::{Clock, UnixTime};
use zeabur_identity_core::crypto::{CryptoError, Sealer, hmac_sha256};
use zeabur_identity_core::guessing::DeviceKey;
use zeabur_identity_core::password::{self, Hasher, ITERATIONS, Normalized, Verdict, Weakness};
use zeabur_identity_core::totp::{RecoveryKey, Secret};
use zeabur_identity_oauth::authorize::Authentication;
use zeabur_identity_oauth::endpoints::{FLOW_COOKIE, complete_authorization};
use zeabur_identity_store::{
    Consume, CredentialStore, Directory, GrantStore, PasswordRemoval, PasswordState, Saved,
    SetupStore, StoredPassword, StoredTotp, User,
};

use crate::account::{
    Audit, LAST_CREDENTIAL, done, log_outcome, record, revoke_all_but, signed_in, start_session,
    with_cookie,
};
use crate::device::Requester;
use crate::problem::{Extensions, Problem};
use crate::{
    NO_REQUEST, SETUP_INVALID, Shared, SignIn, check_account, check_request, cookie, internal,
    json, parse, redeemed, refused, set_cookie_with, valid_setup_token,
};

/// Cookie holding the browser's device entries, one per user who signed in here.
pub const DEVICE_COOKIE: &str = "__Host-zeabur-identity-device";
/// Joins the entries in the device cookie. Cookie values cannot hold `,`, `;` or spaces
/// (RFC 6265 §4.1.1), and each entry already uses `.` between its parts.
const ENTRY_SEPARATOR: &str = "~";
/// The most users a browser remembers. The oldest entry is dropped first.
///
/// Each entry protects one user, so a browser shared by a few accounts (a personal and an admin
/// account, or a family computer) keeps all of them. Four is a judgement, not a limit of the
/// cookie: four entries take about 540 bytes of the 4096 that RFC 6265 §6.1 asks browsers to keep.
const DEVICE_ENTRIES: usize = 4;
/// 400 days, the longest lifetime browsers keep (RFC 6265bis §5.5).
const DEVICE_MAX_AGE: u64 = 400 * 24 * 60 * 60;
/// Authentication methods asserted by a password sign-in (RFC 8176).
pub const PASSWORD_AMR: [&str; 1] = ["pwd"];
/// A password, then a TOTP code.
pub const TOTP_AMR: [&str; 3] = ["pwd", "otp", "mfa"];
/// A password, then a recovery code.
pub const RECOVERY_AMR: [&str; 2] = ["pwd", "mfa"];
/// How many times a guess count is read again when another sign-in changed it first.
const SAVE_ATTEMPTS: usize = 5;

pub(crate) const PASSWORD_FAILED: Problem = Problem::new(
    StatusCode::UNAUTHORIZED,
    "password-failed",
    "Unable to sign in with this username and password.",
);
const PASSWORD_HELD: Problem = Problem::new(
    StatusCode::TOO_MANY_REQUESTS,
    "password-held",
    "Too many failed attempts from this browser. Try again later, or sign in another way.",
);
const PASSWORD_WEAK: Problem = Problem::new(
    StatusCode::UNPROCESSABLE_ENTITY,
    "password-weak",
    "Choose another password.",
);
const CODE_NEEDED: Problem = Problem::new(
    StatusCode::UNAUTHORIZED,
    "code-needed",
    "Enter the code from your authenticator app.",
);
const CODE_FAILED: Problem = Problem::new(
    StatusCode::UNAUTHORIZED,
    "code-failed",
    "This code does not work. Enter the current code, or a recovery code.",
);
const ENROL_CODE_FAILED: Problem = Problem::new(
    StatusCode::UNPROCESSABLE_ENTITY,
    "code-failed",
    "This code does not match. Enter the current code from your authenticator app.",
);
const CURRENT_WRONG: Problem = Problem::new(
    StatusCode::FORBIDDEN,
    "current-password-wrong",
    "This is not your current password.",
);
const NO_PASSWORD: Problem =
    Problem::new(StatusCode::NOT_FOUND, "not-found", "You have no password.");
const PASSWORD_CONFLICT: Problem = Problem::new(
    StatusCode::CONFLICT,
    "password-conflict",
    "Your password changed in the meantime. Reload and try again.",
);
const BUSY: Problem = Problem::new(
    StatusCode::SERVICE_UNAVAILABLE,
    "busy",
    "Too many sign-ins at once. Try again in a moment.",
);

/// The password hasher, the device key, the TOTP keys, and a cap on hashes running at once.
pub struct Passwords {
    hasher: Arc<Hasher>,
    devices: DeviceKey,
    totp: Sealer,
    recovery: RecoveryKey,
    permits: Arc<Semaphore>,
}

impl std::fmt::Debug for Passwords {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Passwords")
            .field("hasher", &self.hasher)
            .finish_non_exhaustive()
    }
}

impl Passwords {
    /// Passwords keyed by the server's password key.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError`] if the TOTP key is rejected.
    pub fn new(secret: &[u8; 32]) -> Result<Self, CryptoError> {
        Self::with_iterations(secret, ITERATIONS)
    }

    /// Passwords with a chosen PBKDF2 iteration count, for tests.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError`] if the TOTP key is rejected.
    pub fn with_iterations(secret: &[u8; 32], iterations: u32) -> Result<Self, CryptoError> {
        let pepper = hmac_sha256(secret, b"zeabur-identity/password/pepper/v1");
        let device = hmac_sha256(secret, b"zeabur-identity/device/v1");
        let totp = hmac_sha256(secret, b"zeabur-identity/totp/v1");
        let recovery = hmac_sha256(secret, b"zeabur-identity/recovery/v1");
        // One hash at a time per core: more only queues work and slows every sign-in.
        let cores = std::thread::available_parallelism().map_or(2, NonZeroUsize::get);
        Ok(Self {
            hasher: Arc::new(Hasher::with_iterations(&pepper, iterations)),
            devices: DeviceKey::new(device),
            totp: Sealer::from_key(&totp)?,
            recovery: RecoveryKey::new(recovery),
            permits: Arc::new(Semaphore::new(cores)),
        })
    }

    /// The secret offered for setup token `token`, and the step of its code, if the code is right.
    fn enrol(
        &self,
        token: &str,
        request: &TotpRequest,
        now: UnixTime,
    ) -> Result<(Secret, u64), Problem> {
        let secret = self
            .totp
            .open(&enrol_purpose(token), &request.sealed)
            .and_then(|bytes| Secret::from_bytes(&bytes))
            .ok_or(NO_REQUEST)?;
        let step = secret
            .check(&request.code, now, None)
            .ok_or(ENROL_CODE_FAILED)?;
        Ok((secret, step))
    }

    /// `secret` sealed for `subject` with new recovery codes, and the codes to show.
    fn store(
        &self,
        subject: &str,
        secret: &Secret,
        enrolled_step: u64,
    ) -> Result<(StoredTotp, Vec<String>), Problem> {
        let (shown, recovery) = self.recovery.generate().map_err(internal)?;
        let secret = self
            .totp
            .seal(&stored_purpose(subject), secret.as_bytes())
            .map_err(internal)?;
        Ok((
            StoredTotp {
                secret,
                recovery,
                enrolled_step,
            },
            shown,
        ))
    }

    /// Which second factor `code` is for `subject`, if it is one that was not used before.
    fn second_factor(
        &self,
        subject: &str,
        totp: &StoredTotp,
        state: &PasswordState,
        code: &str,
        now: UnixTime,
    ) -> Option<SecondFactor> {
        let step = self
            .totp
            .open(&stored_purpose(subject), &totp.secret)
            .and_then(|bytes| Secret::from_bytes(&bytes))
            .and_then(|secret| {
                let last = state.totp_last_step.max(Some(totp.enrolled_step));
                secret.check(code, now, last)
            });
        step.map(SecondFactor::Totp).or_else(|| {
            self.recovery
                .check(code, &totp.recovery, &state.recovery_used)
                .map(SecondFactor::Recovery)
        })
    }

    /// Runs `work` on the blocking pool, or refuses when every core is already hashing.
    async fn run<T: Send + 'static>(
        &self,
        work: impl FnOnce(&Hasher) -> T + Send + 'static,
    ) -> Result<T, Failure> {
        let permit = Arc::clone(&self.permits)
            .try_acquire_owned()
            .map_err(|_full| Failure::Retry(BUSY, 1))?;
        let hasher = Arc::clone(&self.hasher);
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            work(&hasher)
        })
        .await
        .map_err(|error| Failure::Problem(internal(error)))
    }

    /// The device this browser has for `subject`, if its cookie holds a valid entry.
    fn device(&self, headers: &HeaderMap, subject: &str) -> Option<String> {
        cookie(headers, DEVICE_COOKIE)?
            .split(ENTRY_SEPARATOR)
            .find_map(|entry| self.devices.check(entry, subject))
    }

    /// Adds an entry for `subject` to this browser's device cookie, or keeps the one it has.
    pub(crate) fn remember(&self, response: &mut Response, headers: &HeaderMap, subject: &str) {
        let mut entries: Vec<&str> = cookie(headers, DEVICE_COOKIE)
            .unwrap_or_default()
            .split(ENTRY_SEPARATOR)
            .filter(|entry| {
                entry
                    .split_once('.')
                    .is_some_and(|(owner, _)| self.devices.check(entry, owner).is_some())
            })
            .collect();
        let new;
        if let Some(at) = entries
            .iter()
            .position(|entry| self.devices.check(entry, subject).is_some())
        {
            let kept = entries.remove(at);
            entries.push(kept);
        } else {
            match self.devices.issue(subject) {
                Ok(entry) => {
                    new = entry;
                    entries.push(&new);
                }
                Err(error) => {
                    tracing::warn!(reason = "device_cookie_failed", %error, "issuing a device cookie failed");
                    return;
                }
            }
        }
        let skip = entries.len().saturating_sub(DEVICE_ENTRIES);
        let value = entries.split_off(skip).join(ENTRY_SEPARATOR);
        // Lax, so the cookie also reaches the upstream callback, a cross-site navigation.
        set_cookie_with(response, DEVICE_COOKIE, &value, DEVICE_MAX_AGE, "Lax");
    }
}

/// What the purpose of a sealed TOTP secret binds it to: the user it is stored for.
fn stored_purpose(subject: &str) -> String {
    format!("totp\0{subject}")
}

/// The purpose of a TOTP secret offered during setup: the setup token it was offered for.
fn enrol_purpose(token: &str) -> String {
    format!("totp-enrol\0{token}")
}

/// A second factor that was accepted.
#[derive(Clone, Copy)]
enum SecondFactor {
    /// A TOTP code of this step.
    Totp(u64),
    /// The recovery code at this index.
    Recovery(usize),
}

impl SecondFactor {
    /// Marks it used in `state`, unless another sign-in used it first.
    fn spend(self, state: &mut PasswordState) -> bool {
        match self {
            Self::Totp(step) => {
                let fresh = state.totp_last_step.is_none_or(|last| step > last);
                if fresh {
                    state.totp_last_step = Some(step);
                }
                fresh
            }
            Self::Recovery(index) => {
                let fresh = !state.recovery_used.contains(&index);
                if fresh {
                    state.recovery_used.push(index);
                }
                fresh
            }
        }
    }

    const fn amr(self) -> &'static [&'static str] {
        match self {
            Self::Totp(_) => &TOTP_AMR,
            Self::Recovery(_) => &RECOVERY_AMR,
        }
    }
}

/// Why a request was refused.
enum Failure {
    Problem(Problem),
    /// Refused; the client may try again after this many seconds.
    Retry(Problem, u64),
    Weak(Weakness),
}

impl From<Problem> for Failure {
    fn from(problem: Problem) -> Self {
        Self::Problem(problem)
    }
}

impl Failure {
    const fn problem(&self) -> Problem {
        match self {
            Self::Problem(problem) | Self::Retry(problem, _) => *problem,
            Self::Weak(_) => PASSWORD_WEAK,
        }
    }

    const fn kind(&self) -> &'static str {
        self.problem().kind
    }

    fn respond(self) -> Response {
        match self {
            Self::Problem(problem) => problem.into_response(),
            Self::Retry(problem, seconds) => {
                let mut response = problem.into_response();
                response
                    .headers_mut()
                    .insert(header::RETRY_AFTER, HeaderValue::from(seconds));
                response
            }
            Self::Weak(weakness) => PASSWORD_WEAK.with(Extensions {
                weakness: Some(weakness),
                ..Extensions::default()
            }),
        }
    }
}

/// The result of [`update_state`].
#[derive(PartialEq, Eq)]
enum Update {
    Saved,
    /// `change` refused the current state, or the password was replaced.
    Refused,
    /// The store failed; it is logged.
    Failed,
}

/// Reads the password state again and applies `change` until the write is not beaten by another
/// sign-in. `change` returns false to refuse the state it is given.
async fn update_state<K: CredentialStore>(
    credentials: &K,
    user: &User,
    mut stored: StoredPassword,
    change: impl Fn(&mut PasswordState) -> bool,
) -> Update {
    let (hash, totp) = (stored.hash.clone(), stored.totp.clone());
    for _ in 0..SAVE_ATTEMPTS {
        if stored.hash != hash || stored.totp != totp {
            return Update::Refused;
        }
        let mut state = stored.state.clone();
        if !change(&mut state) {
            return Update::Refused;
        }
        if state == stored.state {
            return Update::Saved;
        }
        match credentials.save_state(&stored, &state).await {
            Ok(Saved::Saved) => return Update::Saved,
            Ok(Saved::Conflict) => {}
            Err(error) => {
                tracing::warn!(reason = "password_state_unsaved", %error, "saving the password state failed");
                return Update::Failed;
            }
        }
        match credentials.password(user).await {
            Ok(Some(again)) => stored = again,
            Ok(None) => return Update::Refused,
            Err(error) => {
                tracing::warn!(reason = "password_state_unsaved", %error, "reading the password state failed");
                return Update::Failed;
            }
        }
    }
    tracing::warn!(
        reason = "password_state_unsaved",
        "saving the password state kept conflicting"
    );
    Update::Failed
}

#[derive(Deserialize)]
pub(crate) struct SignInRequest {
    username: String,
    password: String,
    /// A TOTP or recovery code, after a `code-needed` answer.
    #[serde(default)]
    code: Option<String>,
}

#[derive(Serialize, JsonSchema)]
#[schemars(rename = "PasswordSignedIn")]
pub(crate) struct SignedIn {
    redirect_to: String,
}

/// `POST /login/password`: signs in with a username and password.
pub(crate) async fn sign_in<D, G, C, K, S>(
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
    let result = sign_in_with(&service, &headers, &body, &mut identity).await;
    let (user, subject) = (
        identity.as_ref().map(|u: &User| u.name.as_str()),
        identity.as_ref().map(|u| u.subject.as_str()),
    );
    match &result {
        Ok(_) => {
            tracing::info!(target: "zeabur_identity::audit", event = "auth.sign_in", outcome = "success", method = "password", user, subject, "signed in with a password");
        }
        Err(failure) => {
            tracing::warn!(target: "zeabur_identity::audit", event = "auth.sign_in", outcome = "failure", method = "password", reason = failure.kind(), user, subject, "password sign-in failed");
        }
    }
    result.unwrap_or_else(Failure::respond)
}

async fn sign_in_with<D, G, C, K, S>(
    service: &SignIn<D, G, C, K, S>,
    headers: &HeaderMap,
    body: &[u8],
    identity: &mut Option<User>,
) -> Result<Response, Failure>
where
    D: Directory,
    G: GrantStore,
    C: Clock,
    K: CredentialStore,
    S: SetupStore,
{
    check_request(headers, service.oauth.issuer.as_str())?;
    let request: SignInRequest = parse(body)?;
    let flow = cookie(headers, FLOW_COOKIE).ok_or(NO_REQUEST)?;
    let authentication = authenticate(service, headers, &request, identity).await?;
    let subject = authentication.subject.clone();
    let location =
        complete_authorization(&service.oauth, flow, authentication).map_err(|error| {
            tracing::warn!(
                reason = NO_REQUEST.kind,
                ?error,
                "password authorization failed"
            );
            NO_REQUEST
        })?;
    let mut response = json(
        StatusCode::OK,
        &SignedIn {
            redirect_to: location,
        },
    );
    service.passwords.remember(&mut response, headers, &subject);
    crate::clear_cookie(&mut response, FLOW_COOKIE, "Lax");
    Ok(response)
}

/// Checks a username, a password and, for a user with an authenticator, a code. Every password
/// sign-in uses it: an unknown user and a held browser get the answer of a wrong password, and a
/// wrong password or code counts against this browser.
async fn authenticate<D, G, C, K, S>(
    service: &SignIn<D, G, C, K, S>,
    headers: &HeaderMap,
    request: &SignInRequest,
    identity: &mut Option<User>,
) -> Result<Authentication, Failure>
where
    D: Directory,
    G: GrantStore,
    C: Clock,
    K: CredentialStore,
    S: SetupStore,
{
    let entered = Normalized::new(&request.password).ok_or(PASSWORD_FAILED)?;
    let now = service.oauth.now();
    let passwords = &service.passwords;
    // The username is the `User` object name; a `User` whose username differs is not matched.
    let user = service
        .oauth
        .directory
        .user(&request.username)
        .await
        .map_err(internal)?
        .filter(|user| user.username == request.username && !user.disabled);
    let stored = match &user {
        Some(user) => service.credentials.password(user).await.map_err(internal)?,
        None => None,
    };
    let (Some(user), Some(stored)) = (user, stored) else {
        passwords
            .run(move |hasher| hasher.verify_nothing(&entered))
            .await?;
        return Err(PASSWORD_FAILED.into());
    };
    let user = identity.insert(user);
    let device = passwords.device(headers, &user.subject);
    if let Some(until) = stored.state.guesses.held(device.as_deref(), now) {
        if device.is_none() {
            // A browser this user never signed in with gets the answer of a wrong password, so a
            // hold does not show that the account exists.
            passwords
                .run(move |hasher| hasher.verify_nothing(&entered))
                .await?;
            return Err(PASSWORD_FAILED.into());
        }
        let seconds = until.as_secs().saturating_sub(now.as_secs()).max(1);
        return Err(Failure::Retry(PASSWORD_HELD, seconds));
    }
    let hash = stored.hash.clone();
    let (verdict, rehashed) = passwords
        .run(move |hasher| {
            let verdict = hasher.verify(&entered, &hash);
            let rehashed = matches!(verdict, Verdict::Match { rehash: true })
                .then(|| hasher.hash(&entered).ok())
                .flatten();
            (verdict, rehashed)
        })
        .await?;
    let device = device.as_deref();
    if verdict == Verdict::Mismatch {
        update_state(&service.credentials, user, stored, |state| {
            state.guesses.fail(device, now);
            true
        })
        .await;
        return Err(PASSWORD_FAILED.into());
    }
    let code = request.code.as_deref();
    let second = check_second_factor(service, user, &stored, code, device, now).await?;
    // Checked after the password matches, so the answer says nothing about unproven guesses.
    let method = Method::Password {
        second_factor: second.is_some(),
    };
    check_account(&service.oauth.directory, user, method).await?;
    let name = stored.name.clone();
    record_success(service, user, stored, rehashed, device, second).await?;
    let amr = second.map_or(&PASSWORD_AMR[..], SecondFactor::amr);
    Ok(Authentication {
        user: user.name.clone(),
        subject: user.subject.clone(),
        auth_time: now,
        amr: amr.iter().map(|m| (*m).to_owned()).collect(),
        credential: Some(name),
        user_verified: false,
        device_bound: false,
    })
}

/// `POST /account/session/password`: signs in to the account page with a username and password.
/// The session is not user-verified, so changes that need a fresh passkey still ask for one.
pub(crate) async fn account_session<D, G, C, K, S>(
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
    let mut identity = None;
    let mut audit = Audit {
        requester: Some(&requester),
        ..Audit::default()
    };
    let result: Result<Response, Failure> = async {
        check_request(&headers, service.oauth.issuer.as_str())?;
        let request: SignInRequest = parse(&body)?;
        let authentication = authenticate(&service, &headers, &request, &mut identity).await?;
        audit.credential.clone_from(&authentication.credential);
        let token = start_session(&service, &authentication).await?;
        audit.session = Some(token.name().to_owned());
        let mut response = json(StatusCode::OK, &crate::account::SignedIn { accepted: None });
        service
            .passwords
            .remember(&mut response, &headers, &authentication.subject);
        Ok(with_cookie(response, &token))
    }
    .await;
    let logged = result.as_ref().map(|_| ()).map_err(Failure::problem);
    log_outcome("account.sign_in", identity.as_ref(), &audit, &logged);
    result.unwrap_or_else(Failure::respond)
}

/// Clears this browser's count, marks the second factor used, and stores a stronger hash.
async fn record_success<D, G, C, K, S>(
    service: &SignIn<D, G, C, K, S>,
    user: &User,
    stored: StoredPassword,
    rehashed: Option<String>,
    device: Option<&str>,
    second: Option<SecondFactor>,
) -> Result<(), Failure>
where
    D: Directory,
    G: GrantStore,
    C: Clock,
    K: CredentialStore,
    S: SetupStore,
{
    // Replacing the credential starts a new state, which would let used codes work again. A user
    // with an authenticator keeps the old hash until the password is set again.
    if let Some(hash) = rehashed
        && stored.totp.is_none()
        && let Err(error) = service
            .credentials
            .set_password(user, &hash, None, Some(&stored))
            .await
    {
        tracing::warn!(reason = "rehash_failed", %error, "storing a stronger password hash failed");
    }
    let succeed = |state: &mut PasswordState| {
        state.guesses.succeed(device);
        second.is_none_or(|second| second.spend(state))
    };
    match (
        update_state(&service.credentials, user, stored, succeed).await,
        second,
    ) {
        (Update::Saved, _) | (_, None) => {}
        // Another sign-in used the code first.
        (Update::Refused, Some(_)) => return Err(CODE_FAILED.into()),
        (Update::Failed, Some(_)) => {
            return Err(internal("the use of a second factor could not be recorded").into());
        }
    }
    Ok(())
}

/// The second factor `code` gives, for a user with an authenticator. A missing code is asked
/// for and changes no count, since the password was right; a wrong one counts as a failure.
async fn check_second_factor<D, G, C, K, S>(
    service: &SignIn<D, G, C, K, S>,
    user: &User,
    stored: &StoredPassword,
    code: Option<&str>,
    device: Option<&str>,
    now: UnixTime,
) -> Result<Option<SecondFactor>, Failure>
where
    D: Directory,
    G: GrantStore,
    C: Clock,
    K: CredentialStore,
    S: SetupStore,
{
    let Some(totp) = &stored.totp else {
        return Ok(None);
    };
    let code = code
        .filter(|code| !code.trim().is_empty())
        .ok_or(CODE_NEEDED)?;
    let second = service
        .passwords
        .second_factor(&user.subject, totp, &stored.state, code, now);
    if second.is_none() {
        update_state(&service.credentials, user, stored.clone(), |state| {
            state.guesses.fail(device, now);
            true
        })
        .await;
        return Err(CODE_FAILED.into());
    }
    Ok(second)
}

#[derive(Deserialize)]
pub(crate) struct SetupRequest {
    token: String,
    password: String,
    /// The authenticator, when the options asked for one.
    #[serde(default)]
    totp: Option<TotpRequest>,
}

#[derive(Deserialize)]
struct TotpRequest {
    /// `sealed` from the options.
    sealed: String,
    /// The current code from the authenticator app.
    code: String,
}

#[derive(Serialize, JsonSchema)]
#[schemars(rename = "PasswordSetUp")]
pub(crate) struct SetUp<'a> {
    username: &'a str,
    /// Shown once; only their hashes are stored.
    #[serde(skip_serializing_if = "Option::is_none")]
    recovery_codes: Option<Vec<String>>,
}

#[derive(Deserialize)]
pub(crate) struct OptionsRequest {
    token: String,
}

#[derive(Serialize, JsonSchema)]
#[schemars(rename = "PasswordSetupOptions")]
pub(crate) struct SetupOptions {
    /// An authenticator to add, when the settings need a second factor for this user.
    totp: Option<Enrolment>,
}

#[derive(Serialize, JsonSchema)]
#[schemars(rename = "TotpEnrolment")]
struct Enrolment {
    /// The secret in base32, for typing into the app.
    secret: String,
    /// The `otpauth://` URI the QR code holds.
    uri: String,
    qr: Qr,
    /// The secret sealed to the setup token, sent back with the password.
    sealed: String,
}

/// A QR code as one SVG path in a `size` × `size` box, quiet zone included.
#[derive(Serialize, JsonSchema)]
struct Qr {
    size: usize,
    path: String,
}

/// The QR code of `text`: each run of dark modules in a row is one `h` segment.
fn qr(text: &str) -> Result<Qr, Problem> {
    use std::fmt::Write as _;
    const QUIET: usize = 4;
    let code = qrcode::QrCode::new(text.as_bytes()).map_err(internal)?;
    let width = code.width();
    let colors = code.to_colors();
    let mut path = String::new();
    for (y, row) in colors.chunks(width).enumerate() {
        let mut x = 0;
        while x < width {
            let run = row
                .iter()
                .skip(x)
                .take_while(|c| **c == qrcode::Color::Dark)
                .count();
            if run > 0 {
                // Writing to a String cannot fail.
                if write!(path, "M{} {}h{run}v1h-{run}z", x + QUIET, y + QUIET).is_err() {
                    path.clear();
                }
                x += run;
            } else {
                x += 1;
            }
        }
    }
    Ok(Qr {
        size: width + 2 * QUIET,
        path,
    })
}

/// Whether the settings need a second factor after a password for `owner`.
async fn needs_second_factor<D: Directory>(directory: &D, owner: &User) -> Result<bool, Problem> {
    let settings = directory.settings().await.map_err(internal)?;
    let without = Method::Password {
        second_factor: false,
    };
    let with = Method::Password {
        second_factor: true,
    };
    if allows(owner.account_type, settings, without).is_ok() {
        return Ok(false);
    }
    allows(owner.account_type, settings, with)
        .map(|()| true)
        .map_err(|refusal| refused(owner, refusal))
}

/// The host of the issuer, for password context and the authenticator's label.
fn issuer_host(issuer: &str) -> String {
    url::Url::parse(issuer)
        .ok()
        .and_then(|url| url.host_str().map(str::to_owned))
        .unwrap_or_default()
}

/// `entered` as a new password for `owner`, if it is long enough and not easy to guess: not common,
/// and without the username, the display name or the issuer's host.
fn strong(entered: &str, owner: &User, issuer: &str) -> Result<Normalized, Failure> {
    let entered = Normalized::new(entered).ok_or(Failure::Weak(Weakness::TooLong))?;
    let host = issuer_host(issuer);
    let mut context: Vec<&str> = vec![&owner.username, "zeabur"];
    context.extend(owner.display_name.as_deref());
    context.extend(host.split('.'));
    password::check(&entered, &context).map_err(Failure::Weak)?;
    Ok(entered)
}

/// `POST /setup/password/options`: what setting a password with this setup link asks for.
pub(crate) async fn set_up_options<D, G, C, K, S>(
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
    options_with(&service, &headers, &body)
        .await
        .unwrap_or_else(IntoResponse::into_response)
}

async fn options_with<D, G, C, K, S>(
    service: &SignIn<D, G, C, K, S>,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<Response, Problem>
where
    D: Directory,
    G: GrantStore,
    C: Clock,
    K: CredentialStore,
    S: SetupStore,
{
    check_request(headers, service.oauth.issuer.as_str())?;
    let request: OptionsRequest = parse(body)?;
    let now = service.oauth.now();
    let directory = &service.oauth.directory;
    let (_, owner) = valid_setup_token(&service.setup, directory, &request.token, now).await?;
    if !needs_second_factor(directory, &owner).await? {
        return Ok(json(StatusCode::OK, &SetupOptions { totp: None }));
    }
    let secret = Secret::generate().map_err(internal)?;
    let host = issuer_host(service.oauth.issuer.as_str());
    let uri = secret.uri(&host, &owner.username);
    let sealed = service
        .passwords
        .totp
        .seal(&enrol_purpose(&request.token), secret.as_bytes())
        .map_err(internal)?;
    let enrolment = Enrolment {
        secret: secret.base32(),
        qr: qr(&uri)?,
        uri,
        sealed,
    };
    let mut response = json(
        StatusCode::OK,
        &SetupOptions {
            totp: Some(enrolment),
        },
    );
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(response)
}

/// `POST /setup/password`: sets the password of the user a setup link is for.
pub(crate) async fn set_up<D, G, C, K, S>(
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
    let result = set_up_with(&service, &headers, &requester, &body, &mut user).await;
    match &result {
        Ok(_) => {
            tracing::info!(target: "zeabur_identity::audit", event = "auth.password_enrollment", outcome = "success", method = "password", user = user.as_deref(), "password set");
        }
        Err(failure) => {
            tracing::warn!(target: "zeabur_identity::audit", event = "auth.password_enrollment", outcome = "failure", method = "password", reason = failure.kind(), user = user.as_deref(), "setting a password failed");
        }
    }
    result.unwrap_or_else(Failure::respond)
}

async fn set_up_with<D, G, C, K, S>(
    service: &SignIn<D, G, C, K, S>,
    headers: &HeaderMap,
    requester: &Requester,
    body: &[u8],
    user: &mut Option<String>,
) -> Result<Response, Failure>
where
    D: Directory,
    G: GrantStore,
    C: Clock,
    K: CredentialStore,
    S: SetupStore,
{
    check_request(headers, service.oauth.issuer.as_str())?;
    let request: SetupRequest = parse(body)?;
    let now = service.oauth.now();
    let (token, owner) = valid_setup_token(
        &service.setup,
        &service.oauth.directory,
        &request.token,
        now,
    )
    .await?;
    *user = Some(token.user.clone());
    let passwords = &service.passwords;
    let enrolled = match &request.totp {
        Some(totp) => Some(passwords.enrol(&request.token, totp, now)?),
        None => None,
    };
    let method = Method::Password {
        second_factor: enrolled.is_some(),
    };
    check_account(&service.oauth.directory, &owner, method).await?;
    let entered = strong(&request.password, &owner, service.oauth.issuer.as_str())?;
    let hash = passwords
        .run(move |hasher| hasher.hash(&entered))
        .await?
        .map_err(internal)?;
    let (totp, recovery_codes) = match &enrolled {
        Some((secret, step)) => {
            let (totp, shown) = passwords.store(&owner.subject, secret, *step)?;
            (Some(totp), Some(shown))
        }
        None => (None, None),
    };
    // Consume the token before storing the password, as for a passkey.
    if service.setup.consume(&token).await.map_err(internal)? == Consume::AlreadyUsed {
        return Err(SETUP_INVALID.into());
    }
    // Another setup of this user can write between the read and the write; the later one wins.
    let mut saved = Saved::Conflict;
    for _ in 0..3 {
        saved = service
            .credentials
            .set_password(&owner, &hash, totp.as_ref(), None)
            .await
            .map_err(internal)?;
        if saved == Saved::Saved {
            break;
        }
    }
    if saved == Saved::Conflict {
        return Err(internal("the password credential kept changing during setup").into());
    }
    let audit = Audit {
        credential: Some(zeabur_identity_store::password_credential_name(
            &owner.subject,
        )),
        requester: Some(requester),
        ..Audit::default()
    };
    record(service, &owner, redeemed(&request.token), &audit, now).await;
    let mut response = json(
        StatusCode::CREATED,
        &SetUp {
            username: &token.user,
            recovery_codes,
        },
    );
    if enrolled.is_some() {
        response
            .headers_mut()
            .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    }
    passwords.remember(&mut response, headers, &owner.subject);
    Ok(response)
}

#[derive(Deserialize)]
struct ChangeRequest {
    current: String,
    new: String,
}

#[derive(Deserialize)]
struct RemoveRequest {
    current: String,
}

/// The stored password of `user`, if `entered` is it. As at sign-in, a held browser is refused
/// and a wrong password counts against this browser.
async fn check_current<D, G, C, K, S>(
    service: &SignIn<D, G, C, K, S>,
    headers: &HeaderMap,
    user: &User,
    entered: &str,
    now: UnixTime,
) -> Result<StoredPassword, Failure>
where
    D: Directory,
    G: GrantStore,
    C: Clock,
    K: CredentialStore,
    S: SetupStore,
{
    let stored = service
        .credentials
        .password(user)
        .await
        .map_err(internal)?
        .ok_or(NO_PASSWORD)?;
    let passwords = &service.passwords;
    let device = passwords.device(headers, &user.subject);
    let device = device.as_deref();
    if let Some(until) = stored.state.guesses.held(device, now) {
        let seconds = until.as_secs().saturating_sub(now.as_secs()).max(1);
        return Err(Failure::Retry(PASSWORD_HELD, seconds));
    }
    let entered = Normalized::new(entered).ok_or(CURRENT_WRONG)?;
    let hash = stored.hash.clone();
    let verdict = passwords
        .run(move |hasher| hasher.verify(&entered, &hash))
        .await?;
    if verdict == Verdict::Mismatch {
        update_state(&service.credentials, user, stored, |state| {
            state.guesses.fail(device, now);
            true
        })
        .await;
        return Err(CURRENT_WRONG.into());
    }
    Ok(stored)
}

/// The authenticator of `stored` for a new password, whose state starts empty: the recovery codes
/// not used yet, and no TOTP step up to the last one used.
fn carried(totp: &StoredTotp, state: &PasswordState) -> StoredTotp {
    StoredTotp {
        secret: totp.secret.clone(),
        recovery: totp
            .recovery
            .iter()
            .enumerate()
            .filter(|(index, _)| !state.recovery_used.contains(index))
            .map(|(_, hash)| hash.clone())
            .collect(),
        enrolled_step: state
            .totp_last_step
            .map_or(totp.enrolled_step, |last| last.max(totp.enrolled_step)),
    }
}

/// `POST /account/password`: replaces the signed-in user's password.
pub(crate) async fn change<D, G, C, K, S>(
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
    let result: Result<Response, Failure> = async {
        let request: ChangeRequest = parse(&body)?;
        let account = signed_in(&service, &headers, now).await?;
        audit.session = Some(account.token.name().to_owned());
        let owner = user.insert(account.user);
        let stored = check_current(&service, &headers, owner, &request.current, now).await?;
        audit.credential = Some(stored.name.clone());
        let entered = strong(&request.new, owner, service.oauth.issuer.as_str())?;
        let hash = service
            .passwords
            .run(move |hasher| hasher.hash(&entered))
            .await?
            .map_err(internal)?;
        let totp = stored.totp.as_ref().map(|t| carried(t, &stored.state));
        match service
            .credentials
            .set_password(owner, &hash, totp.as_ref(), Some(&stored))
            .await
            .map_err(internal)?
        {
            Saved::Saved => {}
            Saved::Conflict => return Err(PASSWORD_CONFLICT.into()),
        }
        audit.revoked = revoke_all_but(&service, owner, account.token.name()).await?;
        record(&service, owner, "PasswordChanged", &audit, now).await;
        let mut response = done(false, None);
        service
            .passwords
            .remember(&mut response, &headers, &owner.subject);
        Ok(response)
    }
    .await;
    let logged = result.as_ref().map(|_| ()).map_err(Failure::problem);
    log_outcome("account.password_changed", user.as_ref(), &audit, &logged);
    result.unwrap_or_else(Failure::respond)
}

/// `POST /account/password/remove`: deletes the signed-in user's password and authenticator.
pub(crate) async fn remove<D, G, C, K, S>(
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
    let result: Result<Response, Failure> = async {
        let request: RemoveRequest = parse(&body)?;
        let account = signed_in(&service, &headers, now).await?;
        audit.session = Some(account.token.name().to_owned());
        let owner = user.insert(account.user);
        let stored = check_current(&service, &headers, owner, &request.current, now).await?;
        audit.credential = Some(stored.name.clone());
        match service
            .credentials
            .remove_password(owner, &stored)
            .await
            .map_err(internal)?
        {
            PasswordRemoval::Removed => {}
            PasswordRemoval::LastCredential => return Err(LAST_CREDENTIAL.into()),
            PasswordRemoval::Conflict => return Err(PASSWORD_CONFLICT.into()),
        }
        audit.revoked = revoke_all_but(&service, owner, account.token.name()).await?;
        record(&service, owner, "PasswordRemoved", &audit, now).await;
        Ok(done(false, None))
    }
    .await;
    let logged = result.as_ref().map(|_| ()).map_err(Failure::problem);
    log_outcome("account.password_removed", user.as_ref(), &audit, &logged);
    result.unwrap_or_else(Failure::respond)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with_cookie(value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        let pair = format!("{DEVICE_COOKIE}={value}");
        headers.insert(header::COOKIE, HeaderValue::from_str(&pair).unwrap());
        headers
    }

    fn set_value(response: &Response) -> String {
        let set = response.headers()[header::SET_COOKIE].to_str().unwrap();
        let pair = set.split(';').next().unwrap();
        pair.split_once('=').unwrap().1.to_owned()
    }

    #[test]
    fn a_browser_keeps_one_entry_per_user_and_the_newest_four() {
        let passwords = Passwords::with_iterations(&[1; 32], 1).unwrap();
        let mut value = String::new();
        for subject in ["a", "b", "c", "d", "e", "b"] {
            let mut response = Response::default();
            passwords.remember(&mut response, &with_cookie(&value), subject);
            value = set_value(&response);
        }
        let headers = with_cookie(&value);
        assert_eq!(value.split(ENTRY_SEPARATOR).count(), DEVICE_ENTRIES);
        assert!(passwords.device(&headers, "a").is_none());
        let b = passwords.device(&headers, "b").unwrap();
        let mut response = Response::default();
        passwords.remember(&mut response, &headers, "b");
        assert_eq!(
            passwords.device(&with_cookie(&set_value(&response)), "b"),
            Some(b)
        );
    }

    #[test]
    fn entries_from_another_key_are_dropped() {
        let ours = Passwords::with_iterations(&[1; 32], 1).unwrap();
        let theirs = Passwords::with_iterations(&[2; 32], 1).unwrap();
        let mut response = Response::default();
        theirs.remember(&mut response, &HeaderMap::new(), "a");
        let foreign = set_value(&response);
        assert!(ours.device(&with_cookie(&foreign), "a").is_none());
        let mut response = Response::default();
        ours.remember(&mut response, &with_cookie(&foreign), "b");
        assert_eq!(set_value(&response).split(ENTRY_SEPARATOR).count(), 1);
    }
}
