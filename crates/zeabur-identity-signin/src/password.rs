//! Password sign-in, and adding a password and an authenticator with a setup link or on the
//! account page.
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
//! The setup page and the account page add a password with the same code: [`offer`] gives the
//! authenticator for a user who needs one, and [`new_password`] checks the password and the code.
//! The account page adds a password after a recent passkey confirmation, and only when the user has
//! none.
//!
//! On the account page, a signed-in user changes or removes their password with the current one,
//! checked and counted as at sign-in. A change keeps the authenticator, and the codes already used
//! stay used. A removal deletes the authenticator with the password. Replacing the authenticator
//! or its recovery codes needs the current password and a code, checked, counted and spent as at
//! sign-in, or a recent passkey confirmation. Every change on the account page ends the user's
//! other sessions.

use std::num::NonZeroUsize;
use std::sync::Arc;

use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use tokio::sync::Semaphore;
use zeabur_identity_core::account::{Method, allows};
use zeabur_identity_core::clock::UnixTime;
use zeabur_identity_core::crypto::{CryptoError, Sealer, hmac_sha256};
use zeabur_identity_core::guessing::DeviceKey;
use zeabur_identity_core::password::{self, Hasher, ITERATIONS, Normalized, Verdict, Weakness};
use zeabur_identity_core::totp::{RecoveryKey, Secret};
use zeabur_identity_oauth::authorize::Authentication;
use zeabur_identity_oauth::endpoints::FLOW_COOKIE;
use zeabur_identity_store::{
    Consume, CredentialStore, Directory, PasswordRemoval, PasswordState, PasswordWrite, Saved,
    SetupStore, StoreError, StoredPassword, StoredTotp, User, password_credential_name,
    retry_on_conflict,
};

use crate::account::{
    Account, Audit, LAST_CREDENTIAL, done, record, require_fresh, revoke_all_but, start_session,
    with_cookie,
};
use crate::audit::Record;
use crate::device::Requester;
use crate::method::{SignInMethod, finish};
use crate::problem::{Extensions, Problem, Step};
use crate::request::{Body, SameOrigin};
use crate::{
    Backend, NO_REQUEST, SETUP_INVALID, Shared, SignIn, check_account, cookie, json, redeemed,
    refused, set_cookie_with, valid_setup_token,
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

pub(crate) const PASSWORD_FAILED: Problem = Problem::new(
    StatusCode::UNAUTHORIZED,
    "password-failed",
    "Unable to sign in with this username and password.",
)
.detail(|m| m.password_failed);
const PASSWORD_HELD: Problem = Problem::new(
    StatusCode::TOO_MANY_REQUESTS,
    "password-held",
    "Too many failed attempts from this browser. Try again later, or sign in another way.",
)
.detail(|m| m.password_held);
/// The same hold, where signing in another way is no way out: changing or removing the password.
const PASSWORD_HELD_HERE: Problem = PASSWORD_HELD.detail(|m| m.password_held_here);
const PASSWORD_WEAK: Problem = Problem::new(
    StatusCode::UNPROCESSABLE_ENTITY,
    "password-weak",
    "Choose another password.",
);
const CODE_NEEDED: Problem = Problem::new(
    StatusCode::UNAUTHORIZED,
    "code-needed",
    "Enter the code from your authenticator app.",
)
.next(Step::Code);
const CODE_FAILED: Problem = Problem::new(
    StatusCode::UNAUTHORIZED,
    "code-failed",
    "This code does not work. Enter the current code, or a recovery code.",
)
.detail(|m| m.code_failed);
const ENROL_CODE_FAILED: Problem = Problem::new(
    StatusCode::UNPROCESSABLE_ENTITY,
    "code-failed",
    "This code does not match. Enter the current code from your authenticator app.",
)
.detail(|m| m.setup_code_failed);
const CURRENT_WRONG: Problem = Problem::new(
    StatusCode::FORBIDDEN,
    "current-password-wrong",
    "This is not your current password.",
)
.detail(|m| m.password_wrong);
const NO_PASSWORD: Problem =
    Problem::new(StatusCode::NOT_FOUND, "not-found", "You have no password.").refresh();
const PASSWORD_CONFLICT: Problem = Problem::new(
    StatusCode::CONFLICT,
    "password-conflict",
    "Your password changed in the meantime. Reload and try again.",
)
.detail(|m| m.password_conflict)
.refresh();
const PASSWORD_EXISTS: Problem = Problem::new(
    StatusCode::CONFLICT,
    "password-exists",
    "You already have a password.",
)
.detail(|m| m.password_exists)
.refresh();
const NO_AUTHENTICATOR: Problem = Problem::new(
    StatusCode::NOT_FOUND,
    "not-found",
    "You have no authenticator app.",
)
.detail(|m| m.authenticator_gone)
.refresh();
const BUSY: Problem = Problem::new(
    StatusCode::SERVICE_UNAVAILABLE,
    "busy",
    "Too many sign-ins at once. Try again in a moment.",
)
.detail(|m| m.busy);

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

    /// The secret offered with `offer`, and the step of its code, if the code is right.
    fn enrol(
        &self,
        offer: Offer<'_>,
        request: &TotpRequest,
        now: UnixTime,
    ) -> Result<(Secret, u64), Problem> {
        let secret = self
            .totp
            .open(&offer.purpose(), &request.sealed)
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
        let (shown, recovery) = self.recovery_codes()?;
        let secret = self
            .totp
            .seal(&stored_purpose(subject), secret.as_bytes())
            .map_err(Problem::internal)?;
        Ok((
            StoredTotp {
                secret,
                recovery,
                enrolled_step,
            },
            shown,
        ))
    }

    /// New recovery codes: the codes to show, and their hashes to store.
    fn recovery_codes(&self) -> Result<(Vec<String>, Vec<String>), Problem> {
        self.recovery.generate().map_err(Problem::internal)
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
        .map_err(|error| Failure::Problem(Problem::internal(error)))
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

/// What a TOTP secret offered for enrolment is sealed to, so it is accepted only there.
#[derive(Clone, Copy)]
enum Offer<'a> {
    /// The setup token it was offered with.
    Setup(&'a str),
    /// The name of the account session it was offered to.
    Session(&'a str),
}

impl Offer<'_> {
    fn purpose(self) -> String {
        match self {
            Self::Setup(token) => format!("totp-enrol\0{token}"),
            Self::Session(session) => format!("totp-enrol-session\0{session}"),
        }
    }
}

/// A second factor that was accepted.
#[derive(Clone, Copy)]
pub(crate) enum SecondFactor {
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
    stored: StoredPassword,
    change: impl Fn(&mut PasswordState) -> bool,
) -> Update {
    let (hash, totp) = (stored.hash.clone(), stored.totp.clone());
    let (hash, totp, change) = (&hash, &totp, &change);
    let mut first = Some(stored);
    let saved = retry_on_conflict(|| {
        let first = first.take();
        async move {
            let stored = match first {
                Some(stored) => stored,
                None => match credentials.password(user).await? {
                    Some(again) => again,
                    None => return Ok(Some(Update::Refused)),
                },
            };
            if stored.hash != *hash || stored.totp != *totp {
                return Ok(Some(Update::Refused));
            }
            let mut state = stored.state.clone();
            if !change(&mut state) {
                return Ok(Some(Update::Refused));
            }
            if state == stored.state {
                return Ok(Some(Update::Saved));
            }
            Ok(match credentials.save_state(&stored, &state).await? {
                Saved::Saved => Some(Update::Saved),
                Saved::Conflict => None,
            })
        }
    })
    .await;
    saved.unwrap_or_else(|error: StoreError| {
        tracing::warn!(reason = "password_state_unsaved", %error, "saving the password state failed");
        Update::Failed
    })
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
pub(crate) async fn sign_in<B: Backend>(
    State(service): State<Shared<B>>,
    headers: HeaderMap,
    request: Result<Body<SameOrigin, SignInRequest>, Problem>,
) -> Response {
    let mut identity = None;
    let result = sign_in_with(&service, &headers, request, &mut identity).await;
    let (user, subject) = (
        identity.as_ref().map(|u: &User| u.name.as_str()),
        identity.as_ref().map(|u| u.subject.as_str()),
    );
    let record = Record {
        event: "auth.sign_in",
        messages: ["signed in with a password", "password sign-in failed"],
        method: Some("password"),
        user,
        subject,
        ..Record::default()
    };
    record.log(result.as_ref().err().map(Failure::kind));
    result.unwrap_or_else(Failure::respond)
}

async fn sign_in_with<B: Backend>(
    service: &SignIn<B>,
    headers: &HeaderMap,
    request: Result<Body<SameOrigin, SignInRequest>, Problem>,
    identity: &mut Option<User>,
) -> Result<Response, Failure> {
    let Body(SameOrigin, request) = request?;
    let flow = cookie(headers, FLOW_COOKIE).ok_or(NO_REQUEST)?;
    let authentication = authenticate(service, headers, &request, identity).await?;
    let subject = authentication.subject.clone();
    let location = finish(&service.oauth, flow, authentication).ok_or(NO_REQUEST)?;
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
async fn authenticate<B: Backend>(
    service: &SignIn<B>,
    headers: &HeaderMap,
    request: &SignInRequest,
    identity: &mut Option<User>,
) -> Result<Authentication, Failure> {
    let entered = Normalized::new(&request.password).ok_or(PASSWORD_FAILED)?;
    let now = service.oauth.now();
    let passwords = &service.passwords;
    // The username is the `User` object name; a `User` whose username differs is not matched.
    let user = service
        .oauth
        .directory
        .user(&request.username)
        .await
        .map_err(Problem::internal)?
        .filter(|user| user.username == request.username && !user.disabled);
    let stored = match &user {
        Some(user) => service
            .credentials
            .password(user)
            .await
            .map_err(Problem::internal)?,
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
    let method = SignInMethod::Password(second);
    check_account(&service.oauth.directory, user, method.policy()).await?;
    let name = stored.name.clone();
    record_success(service, user, stored, rehashed, device, second).await?;
    Ok(method.authentication(user, name, now))
}

/// `POST /account/session/password`: signs in to the account page with a username and password.
/// The session is not user-verified, so changes that need a fresh passkey still ask for one.
pub(crate) async fn account_session<B: Backend>(
    State(service): State<Shared<B>>,
    requester: Requester,
    headers: HeaderMap,
    request: Result<Body<SameOrigin, SignInRequest>, Problem>,
) -> Response {
    let mut identity = None;
    let mut audit = Audit {
        requester: Some(&requester),
        ..Audit::default()
    };
    let result: Result<Response, Failure> = async {
        let Body(SameOrigin, request) = request?;
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
    let record = Record::account("account.sign_in", identity.as_ref(), &audit);
    record.log(result.as_ref().err().map(Failure::kind));
    result.unwrap_or_else(Failure::respond)
}

/// Clears this browser's count, marks the second factor used, and stores a stronger hash.
async fn record_success<B: Backend>(
    service: &SignIn<B>,
    user: &User,
    stored: StoredPassword,
    rehashed: Option<String>,
    device: Option<&str>,
    second: Option<SecondFactor>,
) -> Result<(), Failure> {
    // Replacing the credential starts a new state, which would let used codes work again. A user
    // with an authenticator keeps the old hash until the password is set again.
    if let Some(hash) = rehashed
        && stored.totp.is_none()
        && let Err(error) = service
            .credentials
            .set_password(user, &hash, None, PasswordWrite::Replace(&stored))
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
            return Err(
                Problem::internal("the use of a second factor could not be recorded").into(),
            );
        }
    }
    Ok(())
}

/// The second factor `code` gives, for a user with an authenticator. A missing code is asked
/// for and changes no count, since the password was right; a wrong one counts as a failure.
async fn check_second_factor<B: Backend>(
    service: &SignIn<B>,
    user: &User,
    stored: &StoredPassword,
    code: Option<&str>,
    device: Option<&str>,
    now: UnixTime,
) -> Result<Option<SecondFactor>, Failure> {
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
pub(crate) struct Enrolment {
    /// The secret in base32, for typing into the app.
    secret: String,
    /// The same secret in groups of four, as the page shows it.
    secret_display: String,
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
    let code = qrcode::QrCode::new(text.as_bytes()).map_err(Problem::internal)?;
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
    let settings = directory.settings().await.map_err(Problem::internal)?;
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

/// The authenticator a new password of `owner` needs, if the settings need a second factor for
/// them, sealed to `offer`.
async fn offer<B: Backend>(
    service: &SignIn<B>,
    owner: &User,
    offer: Offer<'_>,
) -> Result<SetupOptions, Problem> {
    if !needs_second_factor(&service.oauth.directory, owner).await? {
        return Ok(SetupOptions { totp: None });
    }
    Ok(SetupOptions {
        totp: Some(enrolment(service, owner, offer)?),
    })
}

/// A new TOTP secret for `owner`, sealed to `offer`.
fn enrolment<B: Backend>(
    service: &SignIn<B>,
    owner: &User,
    offer: Offer<'_>,
) -> Result<Enrolment, Problem> {
    let secret = Secret::generate().map_err(Problem::internal)?;
    let host = issuer_host(service.oauth.issuer.as_str());
    let uri = secret.uri(&host, &owner.username);
    let sealed = service
        .passwords
        .totp
        .seal(&offer.purpose(), secret.as_bytes())
        .map_err(Problem::internal)?;
    Ok(Enrolment {
        secret: secret.base32(),
        secret_display: secret.grouped(),
        qr: qr(&uri)?,
        uri,
        sealed,
    })
}

/// A password, and an authenticator, ready to store.
struct NewPassword {
    hash: String,
    totp: Option<StoredTotp>,
    /// The recovery codes of `totp`, to show once.
    recovery_codes: Option<Vec<String>>,
}

/// Checks a new password of `owner`, and the code of the authenticator offered with `offer`, then
/// hashes the password. The account settings decide whether an authenticator is needed.
async fn new_password<B: Backend>(
    service: &SignIn<B>,
    owner: &User,
    password: &str,
    totp: Option<&TotpRequest>,
    offer: Offer<'_>,
    now: UnixTime,
) -> Result<NewPassword, Failure> {
    let passwords = &service.passwords;
    let enrolled = totp
        .map(|totp| passwords.enrol(offer, totp, now))
        .transpose()?;
    let method = Method::Password {
        second_factor: enrolled.is_some(),
    };
    check_account(&service.oauth.directory, owner, method).await?;
    let entered = strong(password, owner, service.oauth.issuer.as_str())?;
    let hash = passwords
        .run(move |hasher| hasher.hash(&entered))
        .await?
        .map_err(Problem::internal)?;
    let (totp, recovery_codes) = match &enrolled {
        Some((secret, step)) => {
            let (totp, shown) = passwords.store(&owner.subject, secret, *step)?;
            (Some(totp), Some(shown))
        }
        None => (None, None),
    };
    Ok(NewPassword {
        hash,
        totp,
        recovery_codes,
    })
}

/// `POST /setup/password/options`: what setting a password with this setup link asks for.
pub(crate) async fn set_up_options<B: Backend>(
    State(service): State<Shared<B>>,
    request: Result<Body<SameOrigin, OptionsRequest>, Problem>,
) -> Response {
    let result: Result<Response, Problem> = async {
        let Body(SameOrigin, request) = request?;
        let now = service.oauth.now();
        let directory = &service.oauth.directory;
        let (_, owner) = valid_setup_token(&service.setup, directory, &request.token, now).await?;
        let options = offer(&service, &owner, Offer::Setup(&request.token)).await?;
        Ok(json(StatusCode::OK, &options))
    }
    .await;
    result.unwrap_or_else(IntoResponse::into_response)
}

/// `POST /setup/password`: sets the password of the user a setup link is for.
pub(crate) async fn set_up<B: Backend>(
    State(service): State<Shared<B>>,
    headers: HeaderMap,
    requester: Requester,
    request: Result<Body<SameOrigin, SetupRequest>, Problem>,
) -> Response {
    let mut user = None;
    let result = set_up_with(&service, &headers, &requester, request, &mut user).await;
    let record = Record {
        event: "auth.password_enrollment",
        messages: ["password set", "setting a password failed"],
        method: Some("password"),
        user: user.as_deref(),
        ..Record::default()
    };
    record.log(result.as_ref().err().map(Failure::kind));
    result.unwrap_or_else(Failure::respond)
}

async fn set_up_with<B: Backend>(
    service: &SignIn<B>,
    headers: &HeaderMap,
    requester: &Requester,
    request: Result<Body<SameOrigin, SetupRequest>, Problem>,
    user: &mut Option<String>,
) -> Result<Response, Failure> {
    let Body(SameOrigin, request) = request?;
    let now = service.oauth.now();
    let (token, owner) = valid_setup_token(
        &service.setup,
        &service.oauth.directory,
        &request.token,
        now,
    )
    .await?;
    *user = Some(token.user.clone());
    let offered = Offer::Setup(&request.token);
    let new = new_password(
        service,
        &owner,
        &request.password,
        request.totp.as_ref(),
        offered,
        now,
    )
    .await?;
    // Consume the token before storing the password, as for a passkey.
    if service
        .setup
        .consume(&token)
        .await
        .map_err(Problem::internal)?
        == Consume::AlreadyUsed
    {
        return Err(SETUP_INVALID.into());
    }
    // Another setup of this user can write between the read and the write; the later one wins.
    {
        let (owner, hash, totp) = (&owner, &new.hash, new.totp.as_ref());
        retry_on_conflict(|| async move {
            let saved = service
                .credentials
                .set_password(owner, hash, totp, PasswordWrite::Overwrite)
                .await?;
            Ok::<_, StoreError>((saved == Saved::Saved).then_some(()))
        })
        .await
        .map_err(Problem::internal)?;
    }
    let audit = Audit {
        credential: Some(password_credential_name(&owner.subject)),
        requester: Some(requester),
        ..Audit::default()
    };
    record(service, &owner, redeemed(&request.token), &audit, now).await;
    let mut response = json(
        StatusCode::CREATED,
        &SetUp {
            username: &token.user,
            recovery_codes: new.recovery_codes,
        },
    );
    service
        .passwords
        .remember(&mut response, headers, &owner.subject);
    Ok(response)
}

#[derive(Deserialize)]
pub(crate) struct ChangeRequest {
    current: String,
    new: String,
}

#[derive(Deserialize)]
pub(crate) struct RemoveRequest {
    current: String,
}

/// The stored password of `user`, if `entered` is it. As at sign-in, a held browser is refused
/// and a wrong password counts against this browser.
async fn check_current<B: Backend>(
    service: &SignIn<B>,
    headers: &HeaderMap,
    user: &User,
    entered: &str,
    now: UnixTime,
) -> Result<StoredPassword, Failure> {
    let stored = service
        .credentials
        .password(user)
        .await
        .map_err(Problem::internal)?
        .ok_or(NO_PASSWORD)?;
    let passwords = &service.passwords;
    let device = passwords.device(headers, &user.subject);
    let device = device.as_deref();
    if let Some(until) = stored.state.guesses.held(device, now) {
        let seconds = until.as_secs().saturating_sub(now.as_secs()).max(1);
        return Err(Failure::Retry(PASSWORD_HELD_HERE, seconds));
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

/// Stores `hash` and `totp` as the signed-in user's password, over what `write` allows, then ends
/// the user's other sessions and records `reason`. Every change on the account page that stores a
/// password ends here.
async fn save<B: Backend>(
    service: &SignIn<B>,
    account: &Account,
    hash: &str,
    totp: Option<&StoredTotp>,
    write: PasswordWrite<'_>,
    reason: &'static str,
    audit: &mut Audit<'_>,
) -> Result<(), Failure> {
    let owner = &account.user;
    audit.credential = Some(password_credential_name(&owner.subject));
    let saved = service
        .credentials
        .set_password(owner, hash, totp, write)
        .await
        .map_err(Problem::internal)?;
    if saved == Saved::Conflict {
        let problem = match write {
            PasswordWrite::Add => PASSWORD_EXISTS,
            PasswordWrite::Replace(_) | PasswordWrite::Overwrite => PASSWORD_CONFLICT,
        };
        return Err(problem.into());
    }
    audit.revoked = revoke_all_but(service, owner, account.token.name()).await?;
    record(service, owner, reason, audit, service.oauth.now()).await;
    Ok(())
}

/// The reply to a change on the account page that makes recovery codes.
#[derive(Serialize, JsonSchema)]
#[schemars(rename = "AccountRecoveryCodes")]
pub(crate) struct Codes {
    /// Shown once; only their hashes are stored.
    #[serde(skip_serializing_if = "Option::is_none")]
    recovery_codes: Option<Vec<String>>,
}

/// `json` of the recovery codes, with the browser's device cookie for `subject`.
fn codes<B: Backend>(
    service: &SignIn<B>,
    headers: &HeaderMap,
    subject: &str,
    recovery_codes: Option<Vec<String>>,
) -> Response {
    let mut response = json(StatusCode::OK, &Codes { recovery_codes });
    service.passwords.remember(&mut response, headers, subject);
    response
}

/// `POST /account/password`: replaces the signed-in user's password.
pub(crate) async fn change<B: Backend>(
    State(service): State<Shared<B>>,
    requester: Requester,
    headers: HeaderMap,
    request: Result<Body<Account, ChangeRequest>, Problem>,
) -> Response {
    let now = service.oauth.now();
    let mut user = None;
    let mut audit = Audit {
        requester: Some(&requester),
        ..Audit::default()
    };
    let result: Result<Response, Failure> = async {
        let Body(account, request) = request?;
        audit.session = Some(account.token.name().to_owned());
        let owner = user.insert(account.user.clone());
        let stored = check_current(&service, &headers, owner, &request.current, now).await?;
        audit.credential = Some(stored.name.clone());
        let entered = strong(&request.new, owner, service.oauth.issuer.as_str())?;
        let hash = service
            .passwords
            .run(move |hasher| hasher.hash(&entered))
            .await?
            .map_err(Problem::internal)?;
        let totp = stored.totp.as_ref().map(|t| carried(t, &stored.state));
        let write = PasswordWrite::Replace(&stored);
        let reason = "PasswordChanged";
        save(
            &service,
            &account,
            &hash,
            totp.as_ref(),
            write,
            reason,
            &mut audit,
        )
        .await?;
        let mut response = done(false, None);
        service
            .passwords
            .remember(&mut response, &headers, &owner.subject);
        Ok(response)
    }
    .await;
    let record = Record::account("account.password_changed", user.as_ref(), &audit);
    record.log(result.as_ref().err().map(Failure::kind));
    result.unwrap_or_else(Failure::respond)
}

/// `POST /account/password/options`: what adding a password asks for. Needs a recent passkey
/// confirmation.
pub(crate) async fn add_options<B: Backend>(
    State(service): State<Shared<B>>,
    account: Result<Account, Problem>,
) -> Response {
    let now = service.oauth.now();
    let result: Result<Response, Problem> = async {
        let account = account?;
        require_fresh(&account, now)?;
        let owner = &account.user;
        let stored = service
            .credentials
            .password(owner)
            .await
            .map_err(Problem::internal)?;
        if stored.is_some() {
            return Err(PASSWORD_EXISTS);
        }
        let options = offer(&service, owner, Offer::Session(account.token.name())).await?;
        Ok(json(StatusCode::OK, &options))
    }
    .await;
    result.unwrap_or_else(IntoResponse::into_response)
}

#[derive(Deserialize)]
pub(crate) struct AddRequest {
    password: String,
    /// The authenticator, when the options asked for one.
    #[serde(default)]
    totp: Option<TotpRequest>,
}

/// `POST /account/password/add`: adds a password, and an authenticator when the settings need
/// one, for a signed-in user without a password. Needs a recent passkey confirmation.
pub(crate) async fn add<B: Backend>(
    State(service): State<Shared<B>>,
    requester: Requester,
    headers: HeaderMap,
    request: Result<Body<Account, AddRequest>, Problem>,
) -> Response {
    let now = service.oauth.now();
    let mut user = None;
    let mut audit = Audit {
        requester: Some(&requester),
        ..Audit::default()
    };
    let result: Result<Response, Failure> = async {
        let Body(account, request) = request?;
        audit.session = Some(account.token.name().to_owned());
        user = Some(account.user.clone());
        require_fresh(&account, now)?;
        let offered = Offer::Session(account.token.name());
        let totp = request.totp.as_ref();
        let new = new_password(
            &service,
            &account.user,
            &request.password,
            totp,
            offered,
            now,
        )
        .await?;
        let write = PasswordWrite::Add;
        let reason = "PasswordAdded";
        save(
            &service,
            &account,
            &new.hash,
            new.totp.as_ref(),
            write,
            reason,
            &mut audit,
        )
        .await?;
        let subject = &account.user.subject;
        Ok(codes(&service, &headers, subject, new.recovery_codes))
    }
    .await;
    let record = Record::account("account.password_added", user.as_ref(), &audit);
    record.log(result.as_ref().err().map(Failure::kind));
    result.unwrap_or_else(Failure::respond)
}

#[derive(Deserialize)]
pub(crate) struct ConfirmRequest {
    /// The current password. Without it, the change needs a recent passkey confirmation.
    #[serde(default)]
    current: Option<String>,
    /// A code from the current authenticator, or a recovery code, with `current`.
    #[serde(default)]
    code: Option<String>,
}

#[derive(Deserialize)]
pub(crate) struct ReplaceRequest {
    #[serde(flatten)]
    confirm: ConfirmRequest,
    /// The new authenticator: `sealed` from its options, and its current code.
    totp: TotpRequest,
}

/// The signed-in user's password, once a change to its authenticator is confirmed: with the
/// current password and a code, checked, counted and spent as at sign-in, or, without a password,
/// with a recent passkey confirmation.
async fn confirm_authenticator<B: Backend>(
    service: &SignIn<B>,
    headers: &HeaderMap,
    account: &Account,
    request: &ConfirmRequest,
    now: UnixTime,
) -> Result<StoredPassword, Failure> {
    let owner = &account.user;
    let Some(current) = request.current.as_deref().filter(|c| !c.is_empty()) else {
        require_fresh(account, now)?;
        let stored = service
            .credentials
            .password(owner)
            .await
            .map_err(Problem::internal)?
            .ok_or(NO_PASSWORD)?;
        return match stored.totp {
            Some(_) => Ok(stored),
            None => Err(NO_AUTHENTICATOR.into()),
        };
    };
    let code = request
        .code
        .as_deref()
        .filter(|code| !code.trim().is_empty())
        .ok_or(CODE_FAILED)?;
    let stored = check_current(service, headers, owner, current, now).await?;
    if stored.totp.is_none() {
        return Err(NO_AUTHENTICATOR.into());
    }
    let device = service.passwords.device(headers, &owner.subject);
    let device = device.as_deref();
    let second = check_second_factor(service, owner, &stored, Some(code), device, now).await?;
    let (hash, totp) = (stored.hash.clone(), stored.totp.clone());
    record_success(service, owner, stored, None, device, second).await?;
    // Spending the code stored a new version, which the change replaces.
    let again = service
        .credentials
        .password(owner)
        .await
        .map_err(Problem::internal)?;
    again
        .filter(|again| again.hash == hash && again.totp == totp)
        .ok_or_else(|| PASSWORD_CONFLICT.into())
}

/// `POST /account/authenticator/options`: a new authenticator for the signed-in user, who has one.
pub(crate) async fn authenticator_options<B: Backend>(
    State(service): State<Shared<B>>,
    account: Result<Account, Problem>,
) -> Response {
    let result: Result<Response, Problem> = async {
        let account = account?;
        let stored = service
            .credentials
            .password(&account.user)
            .await
            .map_err(Problem::internal)?;
        if stored.and_then(|stored| stored.totp).is_none() {
            return Err(NO_AUTHENTICATOR);
        }
        let offered = Offer::Session(account.token.name());
        let enrolment = enrolment(&service, &account.user, offered)?;
        Ok(json(StatusCode::OK, &enrolment))
    }
    .await;
    result.unwrap_or_else(IntoResponse::into_response)
}

/// `POST /account/authenticator`: replaces the signed-in user's authenticator and its recovery
/// codes. The old secret and codes stop working.
pub(crate) async fn replace_authenticator<B: Backend>(
    State(service): State<Shared<B>>,
    requester: Requester,
    headers: HeaderMap,
    request: Result<Body<Account, ReplaceRequest>, Problem>,
) -> Response {
    let now = service.oauth.now();
    let mut user = None;
    let mut audit = Audit {
        requester: Some(&requester),
        ..Audit::default()
    };
    let result: Result<Response, Failure> = async {
        let Body(account, request) = request?;
        audit.session = Some(account.token.name().to_owned());
        user = Some(account.user.clone());
        // The new code first, so a mistyped one spends nothing.
        let offered = Offer::Session(account.token.name());
        let (secret, step) = service.passwords.enrol(offered, &request.totp, now)?;
        let stored =
            confirm_authenticator(&service, &headers, &account, &request.confirm, now).await?;
        let subject = &account.user.subject;
        let (totp, shown) = service.passwords.store(subject, &secret, step)?;
        let write = PasswordWrite::Replace(&stored);
        let reason = "AuthenticatorReplaced";
        save(
            &service,
            &account,
            &stored.hash,
            Some(&totp),
            write,
            reason,
            &mut audit,
        )
        .await?;
        Ok(codes(&service, &headers, subject, Some(shown)))
    }
    .await;
    let record = Record::account("account.authenticator_replaced", user.as_ref(), &audit);
    record.log(result.as_ref().err().map(Failure::kind));
    result.unwrap_or_else(Failure::respond)
}

/// `POST /account/recovery-codes`: replaces the signed-in user's recovery codes. The old codes
/// stop working; the authenticator stays, and its codes already used stay used.
pub(crate) async fn regenerate<B: Backend>(
    State(service): State<Shared<B>>,
    requester: Requester,
    headers: HeaderMap,
    request: Result<Body<Account, ConfirmRequest>, Problem>,
) -> Response {
    let now = service.oauth.now();
    let mut user = None;
    let mut audit = Audit {
        requester: Some(&requester),
        ..Audit::default()
    };
    let result: Result<Response, Failure> = async {
        let Body(account, request) = request?;
        audit.session = Some(account.token.name().to_owned());
        user = Some(account.user.clone());
        let stored = confirm_authenticator(&service, &headers, &account, &request, now).await?;
        let kept = stored.totp.as_ref().ok_or(NO_AUTHENTICATOR)?;
        let (shown, recovery) = service.passwords.recovery_codes()?;
        let totp = StoredTotp {
            recovery,
            ..carried(kept, &stored.state)
        };
        let write = PasswordWrite::Replace(&stored);
        let reason = "RecoveryCodesRegenerated";
        save(
            &service,
            &account,
            &stored.hash,
            Some(&totp),
            write,
            reason,
            &mut audit,
        )
        .await?;
        let subject = &account.user.subject;
        Ok(codes(&service, &headers, subject, Some(shown)))
    }
    .await;
    let record = Record::account("account.recovery_codes_regenerated", user.as_ref(), &audit);
    record.log(result.as_ref().err().map(Failure::kind));
    result.unwrap_or_else(Failure::respond)
}

/// `POST /account/password/remove`: deletes the signed-in user's password and authenticator.
pub(crate) async fn remove<B: Backend>(
    State(service): State<Shared<B>>,
    requester: Requester,
    headers: HeaderMap,
    request: Result<Body<Account, RemoveRequest>, Problem>,
) -> Response {
    let now = service.oauth.now();
    let mut user = None;
    let mut audit = Audit {
        requester: Some(&requester),
        ..Audit::default()
    };
    let result: Result<Response, Failure> = async {
        let Body(account, request) = request?;
        audit.session = Some(account.token.name().to_owned());
        let owner = user.insert(account.user);
        let stored = check_current(&service, &headers, owner, &request.current, now).await?;
        audit.credential = Some(stored.name.clone());
        match service
            .credentials
            .remove_password(owner, &stored)
            .await
            .map_err(Problem::internal)?
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
    let record = Record::account("account.password_removed", user.as_ref(), &audit);
    record.log(result.as_ref().err().map(Failure::kind));
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
