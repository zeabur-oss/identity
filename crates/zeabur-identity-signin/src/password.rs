//! Password sign-in, and setting a password with a setup link.
//!
//! Every failed sign-in gives the same answer, and a username without a password spends the same
//! hashing time, so answers do not tell which usernames exist. Failures are limited per browser
//! with device cookies (see [`zeabur_identity_core::guessing`]): a browser that signed in as the
//! user before keeps its own count, so guesses from elsewhere cannot lock the owner out.

use std::num::NonZeroUsize;
use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use tokio::sync::Semaphore;
use zeabur_identity_core::account::Method;
use zeabur_identity_core::clock::Clock;
use zeabur_identity_core::crypto::hmac_sha256;
use zeabur_identity_core::guessing::{Counts, DeviceKey};
use zeabur_identity_core::password::{self, Hasher, ITERATIONS, Normalized, Verdict, Weakness};
use zeabur_identity_oauth::authorize::Authentication;
use zeabur_identity_oauth::endpoints::{FLOW_COOKIE, complete_authorization};
use zeabur_identity_store::{
    Consume, CredentialStore, Directory, GrantStore, Saved, SetupStore, StoredPassword, User,
};

use crate::account::{Audit, record};
use crate::device::Requester;
use crate::problem::Problem;
use crate::{
    NO_REQUEST, SETUP_INVALID, Shared, SignIn, check_account, check_request, cookie, internal,
    json, parse, redeemed, set_cookie_with, valid_setup_token,
};

/// Cookie holding the browser's device entries, one per user who signed in here.
pub const DEVICE_COOKIE: &str = "__Host-zeabur-identity-device";
/// Joins the entries in the device cookie. Cookie values cannot hold `,`, `;` or spaces
/// (RFC 6265 §4.1.1), and each entry already uses `.` between its parts.
const ENTRY_SEPARATOR: &str = "~";
/// The most users a browser remembers. The oldest entry is dropped first.
const DEVICE_ENTRIES: usize = 4;
/// 400 days, the longest lifetime browsers keep (RFC 6265bis §5.5).
const DEVICE_MAX_AGE: u64 = 400 * 24 * 60 * 60;
/// Authentication methods asserted by a password sign-in (RFC 8176).
pub const PASSWORD_AMR: [&str; 1] = ["pwd"];
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
const BUSY: Problem = Problem::new(
    StatusCode::SERVICE_UNAVAILABLE,
    "busy",
    "Too many sign-ins at once. Try again in a moment.",
);

/// The password hasher, the device key, and a cap on hashes running at once.
pub struct Passwords {
    hasher: Arc<Hasher>,
    devices: DeviceKey,
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
    #[must_use]
    pub fn new(secret: &[u8; 32]) -> Self {
        Self::with_iterations(secret, ITERATIONS)
    }

    /// Passwords with a chosen PBKDF2 iteration count, for tests.
    #[must_use]
    pub fn with_iterations(secret: &[u8; 32], iterations: u32) -> Self {
        let pepper = hmac_sha256(secret, b"zeabur-identity/password/pepper/v1");
        let device = hmac_sha256(secret, b"zeabur-identity/device/v1");
        // One hash at a time per core: more only queues work and slows every sign-in.
        let cores = std::thread::available_parallelism().map_or(2, NonZeroUsize::get);
        Self {
            hasher: Arc::new(Hasher::with_iterations(&pepper, iterations)),
            devices: DeviceKey::new(device),
            permits: Arc::new(Semaphore::new(cores)),
        }
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
    const fn kind(&self) -> &'static str {
        match self {
            Self::Problem(problem) | Self::Retry(problem, _) => problem.kind,
            Self::Weak(_) => PASSWORD_WEAK.kind,
        }
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
            Self::Weak(weakness) => {
                let name = match weakness {
                    Weakness::TooShort => "too-short",
                    Weakness::TooLong => "too-long",
                    Weakness::Common => "common",
                    Weakness::Context => "context",
                };
                PASSWORD_WEAK.with("weakness", serde_json::Value::from(name))
            }
        }
    }
}

/// Reads the guess counts again and applies `change` until the write is not beaten by another
/// sign-in. Failures are logged: the answer to the browser does not depend on them.
async fn update_guesses<K: CredentialStore>(
    credentials: &K,
    user: &User,
    mut stored: StoredPassword,
    change: impl Fn(&mut Counts),
) {
    for _ in 0..SAVE_ATTEMPTS {
        let mut counts = stored.guesses.clone();
        change(&mut counts);
        if counts == stored.guesses {
            return;
        }
        match credentials.save_guesses(&stored, &counts).await {
            Ok(Saved::Saved) => return,
            Ok(Saved::Conflict) => {}
            Err(error) => {
                tracing::warn!(reason = "guesses_unsaved", %error, "saving password guesses failed");
                return;
            }
        }
        match credentials.password(user).await {
            Ok(Some(again)) => stored = again,
            Ok(None) => return,
            Err(error) => {
                tracing::warn!(reason = "guesses_unsaved", %error, "reading password guesses failed");
                return;
            }
        }
    }
    tracing::warn!(
        reason = "guesses_unsaved",
        "saving password guesses kept conflicting"
    );
}

#[derive(Deserialize)]
pub(crate) struct SignInRequest {
    username: String,
    password: String,
}

#[derive(Serialize)]
struct SignedIn {
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
    if let Some(until) = stored.guesses.held(device.as_deref(), now) {
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
    if verdict == Verdict::Mismatch {
        update_guesses(&service.credentials, user, stored, |counts| {
            counts.fail(device.as_deref(), now);
        })
        .await;
        return Err(PASSWORD_FAILED.into());
    }
    // Checked after the password matches, so the answer says nothing about unproven guesses.
    check_account(&service.oauth.directory, user, Method::Password).await?;
    let name = stored.name.clone();
    if let Some(hash) = rehashed
        && let Err(error) = service
            .credentials
            .set_password(user, &hash, Some(&stored))
            .await
    {
        tracing::warn!(reason = "rehash_failed", %error, "storing a stronger password hash failed");
    }
    update_guesses(&service.credentials, user, stored, |counts| {
        counts.succeed(device.as_deref());
    })
    .await;
    let authentication = Authentication {
        user: user.name.clone(),
        subject: user.subject.clone(),
        auth_time: now,
        amr: PASSWORD_AMR.iter().map(|m| (*m).to_owned()).collect(),
        credential: Some(name),
        user_verified: false,
        device_bound: false,
    };
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
    passwords.remember(&mut response, headers, &user.subject);
    crate::clear_cookie(&mut response, FLOW_COOKIE, "Lax");
    Ok(response)
}

#[derive(Deserialize)]
pub(crate) struct SetupRequest {
    token: String,
    password: String,
}

#[derive(Serialize)]
struct SetUp<'a> {
    username: &'a str,
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
    check_account(&service.oauth.directory, &owner, Method::Password).await?;
    let entered = Normalized::new(&request.password).ok_or(Failure::Weak(Weakness::TooLong))?;
    let host = url::Url::parse(service.oauth.issuer.as_str())
        .ok()
        .and_then(|url| url.host_str().map(str::to_owned))
        .unwrap_or_default();
    let mut context: Vec<&str> = vec![&owner.username, "zeabur"];
    context.extend(owner.display_name.as_deref());
    context.extend(host.split('.'));
    password::check(&entered, &context).map_err(Failure::Weak)?;
    let hash = service
        .passwords
        .run(move |hasher| hasher.hash(&entered))
        .await?
        .map_err(internal)?;
    // Consume the token before storing the password, as for a passkey.
    if service.setup.consume(&token).await.map_err(internal)? == Consume::AlreadyUsed {
        return Err(SETUP_INVALID.into());
    }
    service
        .credentials
        .set_password(&owner, &hash, None)
        .await
        .map_err(internal)?;
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
        },
    );
    service
        .passwords
        .remember(&mut response, headers, &owner.subject);
    Ok(response)
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
        let passwords = Passwords::with_iterations(&[1; 32], 1);
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
        let ours = Passwords::with_iterations(&[1; 32], 1);
        let theirs = Passwords::with_iterations(&[2; 32], 1);
        let mut response = Response::default();
        theirs.remember(&mut response, &HeaderMap::new(), "a");
        let foreign = set_value(&response);
        assert!(ours.device(&with_cookie(&foreign), "a").is_none());
        let mut response = Response::default();
        ours.remember(&mut response, &with_cookie(&foreign), "b");
        assert_eq!(set_value(&response).split(ENTRY_SEPARATOR).count(), 1);
    }
}
