#![doc = include_str!("../README.md")]

use std::collections::HashMap;
use std::future::{self, Future};
use std::sync::{Mutex, PoisonError};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeabur_identity_core::account::{AccountType, Settings};
use zeabur_identity_core::clock::UnixTime;
use zeabur_identity_core::crypto::ct_eq;
use zeabur_identity_core::protocol::ADMIN_GROUP;

/// Client type (RFC 6749 §2.1).
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, JsonSchema)]
pub enum ClientType {
    /// Cannot keep a secret; identifies itself with `client_id` only. Like every client, it
    /// must use PKCE.
    Public,
    /// Authenticates at the token endpoint.
    Confidential,
}

/// Kind of credential.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, JsonSchema)]
pub enum CredentialType {
    /// A WebAuthn discoverable credential.
    Passkey,
    /// A GitHub account.
    GitHub,
    /// A Google account.
    Google,
}

/// A storage backend failed or answered ambiguously.
///
/// Callers fail closed: they answer `server_error` and never treat an error as success. A lost race
/// is not an error; it is an outcome such as [`CreateGrant::AlreadyExists`] or
/// [`Rotation::Replay`].
#[derive(Debug, Error, PartialEq, Eq)]
#[error("storage failed: {0}")]
pub struct StoreError(pub String);

/// A registered client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Client {
    /// `client_id` (the `OAuthClient` object name).
    pub id: String,
    /// Shown on the login page.
    pub display_name: Option<String>,
    /// Public or confidential.
    pub kind: ClientType,
    /// Registered redirect URIs.
    pub redirect_uris: Vec<String>,
    /// Audiences the client may request.
    pub audiences: Vec<String>,
    /// `sha256:<hex>` of the secret, for confidential clients. The secret itself is never
    /// stored.
    pub secret_hash: Option<String>,
    /// Algorithm for this client's ID tokens.
    pub id_token_alg: zeabur_identity_keys::Algorithm,
    /// Where people open the application. The sign-in page links to it.
    pub home_url: Option<String>,
}

impl Client {
    /// The name people see: the display name, or the `client_id` without one.
    #[must_use]
    pub fn name(&self) -> &str {
        self.display_name
            .as_deref()
            .filter(|name| !name.trim().is_empty())
            .unwrap_or(&self.id)
    }
}

/// An application the sign-in page offers to open: a client with a home URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct App {
    /// [`Client::name`].
    pub name: String,
    /// [`Client::home_url`].
    pub url: String,
}

/// At most this many applications are listed.
pub const MAX_APPS: usize = 8;

/// The clients with a home URL as [`App`]s, sorted by name, at most [`MAX_APPS`].
#[must_use]
pub fn apps<'a>(clients: impl IntoIterator<Item = &'a Client>) -> Vec<App> {
    let mut apps: Vec<App> = clients
        .into_iter()
        .filter_map(|client| {
            client.home_url.as_ref().map(|url| App {
                name: client.name().to_owned(),
                url: url.clone(),
            })
        })
        .collect();
    apps.sort_by(|a, b| a.name.cmp(&b.name).then_with(|| a.url.cmp(&b.url)));
    apps.truncate(MAX_APPS);
    apps
}

/// A user, as needed to issue tokens.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct User {
    /// The `User` object name.
    pub name: String,
    /// Stable subject identifier: the object UID. Unique within the issuer (RFC 7519 §4.1.2),
    /// never reassigned, and never an email address.
    pub subject: String,
    /// Login name.
    pub username: String,
    /// Display name.
    pub display_name: Option<String>,
    /// Base groups: in every access token, and in ID tokens granted the `groups` scope.
    pub groups: Vec<String>,
    /// Disabled users get no tokens.
    pub disabled: bool,
    /// Admin or regular. It decides how the user may sign in, how long tokens last, and whether
    /// tokens carry [`ADMIN_GROUP`].
    pub account_type: AccountType,
}

impl User {
    /// The groups tokens carry: [`User::groups`] without
    /// [`ADMIN_GROUP`], then that group if the user
    /// is an admin account. Only the account type decides who holds `cluster-admin`.
    #[must_use]
    pub fn token_groups(&self) -> Vec<String> {
        let mut groups: Vec<String> = self
            .groups
            .iter()
            .filter(|group| *group != ADMIN_GROUP)
            .cloned()
            .collect();
        match self.account_type {
            AccountType::Admin => groups.push(ADMIN_GROUP.to_owned()),
            AccountType::Regular => {}
        }
        groups
    }
}

/// Read access to clients and users.
pub trait Directory: Send + Sync + 'static {
    /// Looks up a client by `client_id`.
    fn client(&self, id: &str) -> impl Future<Output = Result<Option<Client>, StoreError>> + Send;
    /// The [`Client::name`] of a client, from a local index. Pages call it for each row, so it
    /// reads no backend. The answer can lag. Do not use it for authorization.
    fn client_name(&self, id: &str) -> Option<String>;
    /// Looks up a user by object name.
    fn user(&self, name: &str) -> impl Future<Output = Result<Option<User>, StoreError>> + Send;
    /// Looks up a user by immutable subject (the object UID), with current authorization data.
    ///
    /// Adapters may use a metadata index to locate the object, but must verify the UID of the
    /// directly read user. Ambiguous subjects fail closed.
    fn user_by_subject(
        &self,
        subject: &str,
    ) -> impl Future<Output = Result<Option<User>, StoreError>> + Send;
    /// The applications the sign-in page offers to open (see [`apps`]), from a local index.
    /// Anyone can load the page, so it reads no backend. Nothing here is authorization data.
    fn apps(&self) -> Vec<App>;
    /// The install-wide account settings, read from storage on each call. They decide who may
    /// sign in, so a cache could keep a revoked method working.
    fn settings(&self) -> impl Future<Output = Result<Settings, StoreError>> + Send;
}

/// A refresh-token family to create.
///
/// One record per family, not per token: each rotation changes only the hashes in [`Grant`],
/// which makes reuse detection one compare-and-swap, as in Kanidm's per-session record
/// ([Kanidm]). Creating it is the first storage write of a sign-in.
///
/// [Kanidm]: https://github.com/kanidm/kanidm/tree/3331b8ed7f1541901ffe0c722f2a04c82897809c
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewGrant {
    /// Object name, derived from the authorization code so a code can create at most one grant.
    pub name: String,
    /// User object name.
    pub user: String,
    /// `client_id`.
    pub client: String,
    /// Access-token audience.
    pub audience: String,
    /// Granted scopes.
    pub scopes: Vec<String>,
    /// OIDC `auth_time`.
    pub auth_time: UnixTime,
    /// Authentication methods.
    pub amr: Vec<String>,
    /// Absolute expiry, after which the family is dead however often it was used.
    pub expires_at: UnixTime,
    /// `sha256:<hex>` of the first refresh token.
    pub initial_hash: String,
    /// UID of the `User` at sign-in. A grant without one belongs to no one.
    pub subject: Option<String>,
    /// `Credential` object name the user signed in with.
    pub credential: Option<String>,
    /// Whether the authenticator verified the user (WebAuthn UV) at sign-in.
    pub user_verified: bool,
    /// Whether the user signed in with a passkey whose authenticator reported BE unset. A
    /// refresh checks it again when AAL3 is on for admin accounts.
    pub device_bound: bool,
}

/// One authentication of a session: at sign-in, or a later re-authentication.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verification {
    /// When it happened.
    pub at: UnixTime,
    /// `Credential` object name used.
    pub credential: Option<String>,
    /// Whether the authenticator verified the user.
    pub user_verified: bool,
}

/// A stored refresh-token family.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grant {
    /// The family as created.
    pub spec: NewGrant,
    /// Rotations so far.
    pub rotation: u64,
    /// Hash of the valid refresh token.
    pub current_hash: String,
    /// Hash of the previous token, kept so that its reuse is recognised as a replay rather than
    /// as an unknown token. Deleting old tokens instead makes a replay indistinguishable from an
    /// unknown token, as in Pinniped and Rauthy ([Pinniped], [Rauthy]).
    ///
    /// [Pinniped]: https://github.com/vmware/pinniped/tree/e635a39cf793b5b915220a846de91e089ab431c9
    /// [Rauthy]: https://github.com/sebadob/rauthy/tree/abd24b6d189b473178c7797787d6cbddd65df3d3
    pub previous_hash: Option<String>,
    /// Idle expiry: a family unused this long dies. Enforced when the family is read
    /// ([`classify`]); deleting it is only reclaiming space.
    pub idle_expires_at: UnixTime,
    /// The latest re-authentication, if any (account sessions only).
    pub reauth: Option<Verification>,
}

impl Grant {
    /// The latest authentication: the re-authentication if there was one, else the sign-in.
    #[must_use]
    pub fn verification(&self) -> Verification {
        self.reauth.clone().unwrap_or_else(|| Verification {
            at: self.spec.auth_time,
            credential: self.spec.credential.clone(),
            user_verified: self.spec.user_verified,
        })
    }

    /// Whether the grant belongs to `user`: the same object name and the same UID. A grant
    /// without a recorded UID belongs to no one.
    #[must_use]
    pub fn belongs_to(&self, user: &User) -> bool {
        self.spec.user == user.name && self.spec.subject.as_deref() == Some(user.subject.as_str())
    }
}

/// Outcome of [`GrantStore::create`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CreateGrant {
    /// Created.
    Created,
    /// A grant with that name exists: the code was already redeemed.
    AlreadyExists,
}

/// Outcome of [`GrantStore::rotate`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rotation {
    /// The presented token was current; it is now replaced.
    Rotated(Box<Grant>),
    /// The presented token was the previous one: someone used a rotated token. The caller must
    /// revoke the family (RFC 9700 §4.14.2).
    Replay,
    /// The token does not belong to this family. The caller must not revoke: a guess at a
    /// known grant name would otherwise end someone else's session.
    Invalid,
    /// The family expired.
    Expired,
    /// No such family.
    NotFound,
}

/// Refresh-token families.
pub trait GrantStore: Send + Sync + 'static {
    /// Creates a family unless one with that name exists. The name derives from the
    /// authorization code, so [`CreateGrant::AlreadyExists`] means the code was redeemed twice,
    /// possibly by another process.
    fn create(
        &self,
        grant: &NewGrant,
        idle_expires_at: UnixTime,
    ) -> impl Future<Output = Result<CreateGrant, StoreError>> + Send;

    /// Reads a family.
    fn get(&self, name: &str) -> impl Future<Output = Result<Option<Grant>, StoreError>> + Send;

    /// Replaces the current token hash with `next_hash` if `presented_hash` is current, as one
    /// compare-and-swap. A concurrent rotation that wins first turns this call into
    /// [`Rotation::Replay`]: an adapter whose swap loses re-reads the family and classifies the
    /// presented hash again, and it is now the previous one.
    fn rotate(
        &self,
        name: &str,
        presented_hash: &str,
        next_hash: &str,
        now: UnixTime,
        idle_expires_at: UnixTime,
    ) -> impl Future<Output = Result<Rotation, StoreError>> + Send;

    /// Deletes a family. Deleting a missing family succeeds.
    fn revoke(&self, name: &str) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// The families of `user` (see [`Grant::belongs_to`]), read from storage, not a cache.
    fn list(&self, user: &User) -> impl Future<Output = Result<Vec<Grant>, StoreError>> + Send;

    /// Records a re-authentication on the family `name` if `current_hash` is still its current
    /// token, as one compare-and-swap. `false` if the family is gone or its token changed.
    fn reauthenticate(
        &self,
        name: &str,
        current_hash: &str,
        verification: &Verification,
    ) -> impl Future<Output = Result<bool, StoreError>> + Send;
}

/// Classifies a presented hash against a stored family. Shared by every backend so the security
/// outcome is identical. Hashes are compared in constant time.
#[must_use]
pub fn classify(grant: &Grant, presented_hash: &str, now: UnixTime) -> Classification {
    if now >= grant.spec.expires_at || now >= grant.idle_expires_at {
        Classification::Expired
    } else if ct_eq(presented_hash.as_bytes(), grant.current_hash.as_bytes()) {
        Classification::Current
    } else if grant
        .previous_hash
        .as_ref()
        .is_some_and(|previous| ct_eq(presented_hash.as_bytes(), previous.as_bytes()))
    {
        Classification::Previous
    } else {
        Classification::Unknown
    }
}

/// Result of [`classify`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Classification {
    /// The family has expired.
    Expired,
    /// The presented token is the valid one.
    Current,
    /// The presented token was valid before the last rotation.
    Previous,
    /// The presented token is not from this family.
    Unknown,
}

/// The state after a successful rotation.
#[must_use]
pub fn rotated(grant: &Grant, next_hash: &str, idle_expires_at: UnixTime) -> Grant {
    Grant {
        spec: grant.spec.clone(),
        rotation: grant.rotation + 1,
        previous_hash: Some(grant.current_hash.clone()),
        current_hash: next_hash.to_owned(),
        idle_expires_at,
        reauth: grant.reauth.clone(),
    }
}

/// In-memory directory, for tests.
#[derive(Debug, Default)]
pub struct MemoryDirectory {
    clients: Mutex<HashMap<String, Client>>,
    users: Mutex<HashMap<String, User>>,
    settings: Mutex<Settings>,
}

impl MemoryDirectory {
    /// Adds or replaces a client.
    pub fn put_client(&self, client: Client) {
        let mut clients = self.clients.lock().unwrap_or_else(PoisonError::into_inner);
        clients.insert(client.id.clone(), client);
    }

    /// Adds or replaces a user.
    pub fn put_user(&self, user: User) {
        let mut users = self.users.lock().unwrap_or_else(PoisonError::into_inner);
        users.insert(user.name.clone(), user);
    }

    /// Replaces the account settings.
    pub fn put_settings(&self, settings: Settings) {
        *self.settings.lock().unwrap_or_else(PoisonError::into_inner) = settings;
    }

    /// Removes a user.
    pub fn remove_user(&self, name: &str) {
        let mut users = self.users.lock().unwrap_or_else(PoisonError::into_inner);
        users.remove(name);
    }
}

impl Directory for MemoryDirectory {
    fn client(&self, id: &str) -> impl Future<Output = Result<Option<Client>, StoreError>> + Send {
        let clients = self.clients.lock().unwrap_or_else(PoisonError::into_inner);
        future::ready(Ok(clients.get(id).cloned()))
    }

    fn client_name(&self, id: &str) -> Option<String> {
        let clients = self.clients.lock().unwrap_or_else(PoisonError::into_inner);
        clients.get(id).map(|client| client.name().to_owned())
    }

    fn user(&self, name: &str) -> impl Future<Output = Result<Option<User>, StoreError>> + Send {
        let users = self.users.lock().unwrap_or_else(PoisonError::into_inner);
        future::ready(Ok(users.get(name).cloned()))
    }

    fn user_by_subject(
        &self,
        subject: &str,
    ) -> impl Future<Output = Result<Option<User>, StoreError>> + Send {
        let users = self.users.lock().unwrap_or_else(PoisonError::into_inner);
        let mut matches = users.values().filter(|user| user.subject == subject);
        let user = matches.next().cloned();
        let result = if matches.next().is_some() {
            Err(StoreError("ambiguous user subject".to_owned()))
        } else {
            Ok(user)
        };
        drop(users);
        future::ready(result)
    }

    fn apps(&self) -> Vec<App> {
        let clients = self.clients.lock().unwrap_or_else(PoisonError::into_inner);
        apps(clients.values())
    }

    fn settings(&self) -> impl Future<Output = Result<Settings, StoreError>> + Send {
        future::ready(Ok(*self
            .settings
            .lock()
            .unwrap_or_else(PoisonError::into_inner)))
    }
}

/// In-memory grant store, for tests.
#[derive(Debug, Default)]
pub struct MemoryGrantStore {
    grants: Mutex<HashMap<String, Grant>>,
}

impl MemoryGrantStore {
    fn create_now(&self, grant: &NewGrant, idle_expires_at: UnixTime) -> CreateGrant {
        let mut grants = self.grants.lock().unwrap_or_else(PoisonError::into_inner);
        if grants.contains_key(&grant.name) {
            return CreateGrant::AlreadyExists;
        }
        grants.insert(
            grant.name.clone(),
            Grant {
                spec: grant.clone(),
                rotation: 0,
                current_hash: grant.initial_hash.clone(),
                previous_hash: None,
                idle_expires_at,
                reauth: None,
            },
        );
        CreateGrant::Created
    }

    fn rotate_now(
        &self,
        name: &str,
        presented_hash: &str,
        next_hash: &str,
        now: UnixTime,
        idle_expires_at: UnixTime,
    ) -> Rotation {
        let mut grants = self.grants.lock().unwrap_or_else(PoisonError::into_inner);
        let outcome = match grants
            .get(name)
            .map(|g| (classify(g, presented_hash, now), g.clone()))
        {
            None => Rotation::NotFound,
            Some((Classification::Expired, _)) => Rotation::Expired,
            Some((Classification::Previous, _)) => Rotation::Replay,
            Some((Classification::Unknown, _)) => Rotation::Invalid,
            Some((Classification::Current, grant)) => {
                let next = rotated(&grant, next_hash, idle_expires_at);
                grants.insert(name.to_owned(), next.clone());
                Rotation::Rotated(Box::new(next))
            }
        };
        drop(grants);
        outcome
    }
}

impl GrantStore for MemoryGrantStore {
    fn create(
        &self,
        grant: &NewGrant,
        idle_expires_at: UnixTime,
    ) -> impl Future<Output = Result<CreateGrant, StoreError>> + Send {
        future::ready(Ok(self.create_now(grant, idle_expires_at)))
    }

    fn get(&self, name: &str) -> impl Future<Output = Result<Option<Grant>, StoreError>> + Send {
        let grants = self.grants.lock().unwrap_or_else(PoisonError::into_inner);
        future::ready(Ok(grants.get(name).cloned()))
    }

    fn rotate(
        &self,
        name: &str,
        presented_hash: &str,
        next_hash: &str,
        now: UnixTime,
        idle_expires_at: UnixTime,
    ) -> impl Future<Output = Result<Rotation, StoreError>> + Send {
        future::ready(Ok(self.rotate_now(
            name,
            presented_hash,
            next_hash,
            now,
            idle_expires_at,
        )))
    }

    fn revoke(&self, name: &str) -> impl Future<Output = Result<(), StoreError>> + Send {
        self.grants
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(name);
        future::ready(Ok(()))
    }

    fn list(&self, user: &User) -> impl Future<Output = Result<Vec<Grant>, StoreError>> + Send {
        let grants = self.grants.lock().unwrap_or_else(PoisonError::into_inner);
        let mut list: Vec<Grant> = grants
            .values()
            .filter(|grant| grant.belongs_to(user))
            .cloned()
            .collect();
        drop(grants);
        list.sort_by(|a, b| a.spec.name.cmp(&b.spec.name));
        future::ready(Ok(list))
    }

    fn reauthenticate(
        &self,
        name: &str,
        current_hash: &str,
        verification: &Verification,
    ) -> impl Future<Output = Result<bool, StoreError>> + Send {
        let mut grants = self.grants.lock().unwrap_or_else(PoisonError::into_inner);
        let recorded = match grants.get_mut(name) {
            Some(grant) if ct_eq(grant.current_hash.as_bytes(), current_hash.as_bytes()) => {
                grant.reauth = Some(verification.clone());
                true
            }
            Some(_) | None => false,
        };
        drop(grants);
        future::ready(Ok(recorded))
    }
}

/// A passkey to store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewPasskey {
    /// Object name (see [`passkey_credential_name`]).
    pub name: String,
    /// `User` object name.
    pub user: String,
    /// Credential ID, base64url.
    pub credential_id: String,
    /// The serialized relying-party credential record (public key and flags).
    pub record: String,
    /// User-chosen label.
    pub label: Option<String>,
    /// Authenticator model (AAGUID, lowercase hyphenated), when the authenticator reports one.
    pub aaguid: Option<String>,
    /// Whether the credential may be synced to other devices (WebAuthn BE flag).
    pub backup_eligible: bool,
    /// When it was registered. Adapters with their own timestamps may ignore it.
    pub created_at: UnixTime,
}

/// A passkey as the account page lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasskeySummary {
    /// `Credential` object name.
    pub name: String,
    /// Credential ID, base64url.
    pub credential_id: String,
    /// The serialized credential record.
    pub record: String,
    /// The label: the latest rename, else the one given at registration.
    pub label: Option<String>,
    /// Authenticator model (AAGUID).
    pub aaguid: Option<String>,
    /// When it was registered.
    pub created_at: Option<UnixTime>,
    /// When it last signed in, roughly (see [`CredentialStore::touch`]).
    pub last_used_at: Option<UnixTime>,
}

/// Outcome of [`CredentialStore::rename`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rename {
    /// Renamed.
    Renamed,
    /// The user has no such passkey.
    NotFound,
}

/// Outcome of [`CredentialStore::remove`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Removal {
    /// Deleted.
    Removed,
    /// It is the user's only passkey, so it stays.
    LastPasskey,
    /// The user has no such passkey.
    NotFound,
    /// The user's passkeys changed while checking; nothing was deleted. Retrying is safe.
    Conflict,
}

/// Outcome of [`CredentialStore::unlink`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unlink {
    /// Deleted.
    Unlinked,
    /// It is the user's only credential, so it stays.
    LastCredential,
    /// The user has no such linked account.
    NotFound,
    /// The user's credentials changed while checking. Nothing was deleted. Retrying is safe.
    Conflict,
}

/// A linked upstream account as the account page lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkedSummary {
    /// `Credential` object name.
    pub name: String,
    /// The provider.
    pub kind: CredentialType,
    /// When it was linked, if the backend records it.
    pub created_at: Option<UnixTime>,
}

/// Something a user did to their own account, recorded for administrators.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountEvent {
    /// `User` object name.
    pub user: String,
    /// The `User` UID.
    pub subject: String,
    /// Short `UpperCamelCase` reason, for example `PasskeyAdded`.
    pub reason: &'static str,
    /// When it happened.
    pub at: UnixTime,
    /// What happened, without personal data beyond the actor, credential, address and browser.
    pub note: String,
}

/// An upstream account to link to a user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewExternal {
    /// Object name (see [`external_credential_name`]).
    pub name: String,
    /// `User` object name.
    pub user: String,
    /// The provider.
    pub kind: CredentialType,
    /// Upstream issuer.
    pub issuer: String,
    /// Upstream subject: the stable account ID.
    pub subject: String,
    /// The [`User::subject`] (UID) of the user the account signs in as.
    pub user_subject: String,
}

/// The user an upstream account is linked to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkedAccount {
    /// `User` object name.
    pub user: String,
    /// The UID of the `User` the account was linked to. `None` if storage holds no single UID.
    pub user_subject: Option<String>,
}

impl LinkedAccount {
    /// Whether the account signs in as `user`.
    ///
    /// A new `User` with the name of a deleted one has a new UID. Thus a link left over from the
    /// deleted user does not sign in as the new user. A link with no UID signs in as no one.
    #[must_use]
    pub fn signs_in_as(&self, user: &User) -> bool {
        self.user == user.name && self.user_subject.as_deref() == Some(user.subject.as_str())
    }
}

/// The `Credential` name for a passkey credential ID.
///
/// Deterministic, so a duplicate registration fails with `AlreadyExists`, even across replicas:
/// WebAuthn Level 3 §7.1 says that if the credential ID "is already known then the Relying Party
/// SHOULD fail this registration ceremony".
#[must_use]
pub fn passkey_credential_name(credential_id: &[u8]) -> String {
    let mut input = b"zeabur-identity/passkey/v1/".to_vec();
    input.extend_from_slice(credential_id);
    format!(
        "c-{}",
        zeabur_identity_core::crypto::hex(&zeabur_identity_core::crypto::sha256(&input))
    )
}

/// The `Credential` name for an upstream account. Derived from the issuer and subject, so finding
/// the user is a single read and linking one account twice fails with `AlreadyExists`.
#[must_use]
pub fn external_credential_name(issuer: &str, subject: &str) -> String {
    let mut input = b"zeabur-identity/external/v1/".to_vec();
    input.extend_from_slice(issuer.as_bytes());
    input.push(0);
    input.extend_from_slice(subject.as_bytes());
    format!(
        "c-{}",
        zeabur_identity_core::crypto::hex(&zeabur_identity_core::crypto::sha256(&input))
    )
}

/// A stored passkey.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredPasskey {
    /// `User` object name.
    pub user: String,
    /// The serialized credential record.
    pub record: String,
    /// When it last signed in, roughly.
    pub last_used_at: Option<UnixTime>,
}

/// Outcome of [`CredentialStore::create`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CreateCredential {
    /// Stored.
    Created,
    /// The credential ID is already registered (WebAuthn Level 3 §7.1).
    AlreadyExists,
}

/// Passkeys and linked identities.
pub trait CredentialStore: Send + Sync + 'static {
    /// Stores a passkey unless its credential ID is already registered.
    fn create(
        &self,
        passkey: &NewPasskey,
    ) -> impl Future<Output = Result<CreateCredential, StoreError>> + Send;
    /// Reads a passkey by object name.
    fn get(
        &self,
        name: &str,
    ) -> impl Future<Output = Result<Option<StoredPasskey>, StoreError>> + Send;
    /// Links an upstream account unless it is linked already (to anyone).
    fn link(
        &self,
        external: &NewExternal,
    ) -> impl Future<Output = Result<CreateCredential, StoreError>> + Send;
    /// The user an upstream account (by credential name) is linked to. Callers check
    /// [`LinkedAccount::signs_in_as`] before they sign anyone in.
    fn linked_account(
        &self,
        name: &str,
    ) -> impl Future<Output = Result<Option<LinkedAccount>, StoreError>> + Send;

    /// The passkeys of `user`, read from storage, not a cache. Adapters that know a credential's
    /// owning `User` UID leave out credentials owned by another UID.
    fn passkeys(
        &self,
        user: &User,
    ) -> impl Future<Output = Result<Vec<PasskeySummary>, StoreError>> + Send;

    /// Relabels one of `user`'s passkeys, as one write.
    fn rename(
        &self,
        user: &User,
        name: &str,
        label: &str,
    ) -> impl Future<Output = Result<Rename, StoreError>> + Send;

    /// Deletes one of `user`'s passkeys unless it is their last. Two concurrent removals of
    /// different passkeys must never both succeed when only two exist.
    fn remove(
        &self,
        user: &User,
        name: &str,
    ) -> impl Future<Output = Result<Removal, StoreError>> + Send;

    /// The upstream accounts that sign in as `user`, read from storage: linked to the user's
    /// name and UID.
    fn linked_accounts(
        &self,
        user: &User,
    ) -> impl Future<Output = Result<Vec<LinkedSummary>, StoreError>> + Send;

    /// Deletes one of `user`'s linked accounts if the user keeps another credential (a passkey
    /// or another linked account). Two concurrent unlinks must never both succeed when they
    /// would leave the user with no credential.
    fn unlink(
        &self,
        user: &User,
        name: &str,
    ) -> impl Future<Output = Result<Unlink, StoreError>> + Send;

    /// Records that the passkey `name` signed in at `now`. Best effort: callers skip it when
    /// the stored time is recent and only log a failure.
    fn touch(
        &self,
        name: &str,
        now: UnixTime,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// Records an [`AccountEvent`] where administrators look for it.
    fn record(&self, event: &AccountEvent) -> impl Future<Output = Result<(), StoreError>> + Send;
}

/// The pending setup token: who it is for, its hash and expiry, and the stored version that a
/// redemption must consume.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetupToken {
    /// `User` object name the token enrols a passkey for.
    pub user: String,
    /// The UID of the `User` the token was issued for. `None` if storage holds no single UID.
    /// The token enrols only a `User` with this UID (see [`SetupToken::is_for`]).
    pub user_subject: Option<String>,
    /// `sha256:<hex>` of the token.
    pub token_hash: String,
    /// Expiry.
    pub expires_at: UnixTime,
    /// Opaque version, consumed atomically.
    pub version: String,
}

impl SetupToken {
    /// Whether the token may enrol a passkey or link an account for `user`.
    ///
    /// A new `User` with the name of a deleted one has a new UID. Thus a token left over from
    /// the deleted user does not enrol the new user. A token with no UID enrols no one.
    #[must_use]
    pub fn is_for(&self, user: &User) -> bool {
        self.user == user.name && self.user_subject.as_deref() == Some(user.subject.as_str())
    }
}

/// Outcome of [`SetupStore::consume`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Consume {
    /// This call consumed the token.
    Consumed,
    /// The token was consumed or replaced by someone else.
    AlreadyUsed,
}

/// One-time enrolment tokens: the cluster admin's setup token, and invitations.
///
/// A presented token `<name>.<secret>` refers to the invitation `<name>`; any other token refers
/// to the setup token. Base64url setup tokens never contain a dot.
pub trait SetupStore: Send + Sync + 'static {
    /// Reads the stored token that `presented` refers to, if any. The caller compares hashes.
    fn load(
        &self,
        presented: &str,
    ) -> impl Future<Output = Result<Option<SetupToken>, StoreError>> + Send;
    /// Consumes `token` if it is still the stored version. Exactly one concurrent caller wins,
    /// so two simultaneous redemptions cannot both enrol a passkey. Pocket ID once let
    /// concurrent setup requests create several administrators (GHSA-x6w5-6mr5-mxrx).
    fn consume(
        &self,
        token: &SetupToken,
    ) -> impl Future<Output = Result<Consume, StoreError>> + Send;
}

/// In-memory credentials, for tests.
#[derive(Debug, Default)]
pub struct MemoryCredentialStore {
    passkeys: Mutex<HashMap<String, MemoryPasskey>>,
    externals: Mutex<HashMap<String, (LinkedAccount, CredentialType)>>,
    events: Mutex<Vec<AccountEvent>>,
}

#[derive(Debug, Clone)]
struct MemoryPasskey {
    passkey: NewPasskey,
    label: Option<String>,
    last_used_at: Option<UnixTime>,
}

impl MemoryCredentialStore {
    /// The events recorded so far.
    #[must_use]
    pub fn events(&self) -> Vec<AccountEvent> {
        self.events
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Deletes a passkey as an administrator would, without the last-passkey check.
    pub fn delete(&self, name: &str) {
        self.passkeys
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(name);
    }
}

impl CredentialStore for MemoryCredentialStore {
    fn create(
        &self,
        passkey: &NewPasskey,
    ) -> impl Future<Output = Result<CreateCredential, StoreError>> + Send {
        let mut passkeys = self.passkeys.lock().unwrap_or_else(PoisonError::into_inner);
        let outcome = if passkeys.contains_key(&passkey.name) {
            CreateCredential::AlreadyExists
        } else {
            passkeys.insert(
                passkey.name.clone(),
                MemoryPasskey {
                    passkey: passkey.clone(),
                    label: passkey.label.clone(),
                    last_used_at: None,
                },
            );
            CreateCredential::Created
        };
        drop(passkeys);
        future::ready(Ok(outcome))
    }

    fn get(
        &self,
        name: &str,
    ) -> impl Future<Output = Result<Option<StoredPasskey>, StoreError>> + Send {
        let passkeys = self.passkeys.lock().unwrap_or_else(PoisonError::into_inner);
        future::ready(Ok(passkeys.get(name).map(|stored| StoredPasskey {
            user: stored.passkey.user.clone(),
            record: stored.passkey.record.clone(),
            last_used_at: stored.last_used_at,
        })))
    }

    fn link(
        &self,
        external: &NewExternal,
    ) -> impl Future<Output = Result<CreateCredential, StoreError>> + Send {
        let mut externals = self
            .externals
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let outcome = if externals.contains_key(&external.name) {
            CreateCredential::AlreadyExists
        } else {
            externals.insert(
                external.name.clone(),
                (
                    LinkedAccount {
                        user: external.user.clone(),
                        user_subject: Some(external.user_subject.clone()),
                    },
                    external.kind,
                ),
            );
            CreateCredential::Created
        };
        drop(externals);
        future::ready(Ok(outcome))
    }

    fn linked_account(
        &self,
        name: &str,
    ) -> impl Future<Output = Result<Option<LinkedAccount>, StoreError>> + Send {
        let externals = self
            .externals
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        future::ready(Ok(externals.get(name).map(|(linked, _)| linked.clone())))
    }

    fn passkeys(
        &self,
        user: &User,
    ) -> impl Future<Output = Result<Vec<PasskeySummary>, StoreError>> + Send {
        let passkeys = self.passkeys.lock().unwrap_or_else(PoisonError::into_inner);
        let mut list: Vec<PasskeySummary> = passkeys
            .values()
            .filter(|stored| stored.passkey.user == user.name)
            .map(|stored| PasskeySummary {
                name: stored.passkey.name.clone(),
                credential_id: stored.passkey.credential_id.clone(),
                record: stored.passkey.record.clone(),
                label: stored.label.clone(),
                aaguid: stored.passkey.aaguid.clone(),
                created_at: Some(stored.passkey.created_at),
                last_used_at: stored.last_used_at,
            })
            .collect();
        drop(passkeys);
        list.sort_by(|a, b| a.created_at.cmp(&b.created_at).then(a.name.cmp(&b.name)));
        future::ready(Ok(list))
    }

    fn rename(
        &self,
        user: &User,
        name: &str,
        label: &str,
    ) -> impl Future<Output = Result<Rename, StoreError>> + Send {
        let mut passkeys = self.passkeys.lock().unwrap_or_else(PoisonError::into_inner);
        let outcome = match passkeys.get_mut(name) {
            Some(stored) if stored.passkey.user == user.name => {
                stored.label = Some(label.to_owned());
                Rename::Renamed
            }
            Some(_) | None => Rename::NotFound,
        };
        drop(passkeys);
        future::ready(Ok(outcome))
    }

    fn remove(
        &self,
        user: &User,
        name: &str,
    ) -> impl Future<Output = Result<Removal, StoreError>> + Send {
        let mut passkeys = self.passkeys.lock().unwrap_or_else(PoisonError::into_inner);
        let owned = passkeys
            .values()
            .filter(|stored| stored.passkey.user == user.name)
            .count();
        let target = passkeys
            .get(name)
            .is_some_and(|stored| stored.passkey.user == user.name);
        let outcome = if !target {
            Removal::NotFound
        } else if owned < 2 {
            Removal::LastPasskey
        } else {
            passkeys.remove(name);
            Removal::Removed
        };
        drop(passkeys);
        future::ready(Ok(outcome))
    }

    fn linked_accounts(
        &self,
        user: &User,
    ) -> impl Future<Output = Result<Vec<LinkedSummary>, StoreError>> + Send {
        let externals = self
            .externals
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let mut list: Vec<LinkedSummary> = externals
            .iter()
            .filter(|(_, (linked, _))| linked.signs_in_as(user))
            .map(|(name, (_, kind))| LinkedSummary {
                name: name.clone(),
                kind: *kind,
                created_at: None,
            })
            .collect();
        drop(externals);
        list.sort_by(|a, b| a.name.cmp(&b.name));
        future::ready(Ok(list))
    }

    fn unlink(
        &self,
        user: &User,
        name: &str,
    ) -> impl Future<Output = Result<Unlink, StoreError>> + Send {
        let passkeys = self.passkeys.lock().unwrap_or_else(PoisonError::into_inner);
        let mut externals = self
            .externals
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let owned = |linked: &LinkedAccount| linked.signs_in_as(user);
        let others = passkeys
            .values()
            .filter(|stored| stored.passkey.user == user.name)
            .count()
            + externals
                .iter()
                .filter(|(other, (linked, _))| other.as_str() != name && owned(linked))
                .count();
        let outcome = if !externals.get(name).is_some_and(|(linked, _)| owned(linked)) {
            Unlink::NotFound
        } else if others == 0 {
            Unlink::LastCredential
        } else {
            externals.remove(name);
            Unlink::Unlinked
        };
        drop(externals);
        drop(passkeys);
        future::ready(Ok(outcome))
    }

    fn touch(
        &self,
        name: &str,
        now: UnixTime,
    ) -> impl Future<Output = Result<(), StoreError>> + Send {
        if let Some(stored) = self
            .passkeys
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get_mut(name)
        {
            stored.last_used_at = Some(now);
        }
        future::ready(Ok(()))
    }

    fn record(&self, event: &AccountEvent) -> impl Future<Output = Result<(), StoreError>> + Send {
        self.events
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(event.clone());
        future::ready(Ok(()))
    }
}

/// The invitation name in a presented `<name>.<secret>` token, if it is one.
#[must_use]
pub fn invitation_name(presented: &str) -> Option<&str> {
    let (name, secret) = presented.split_once('.')?;
    let label = !name.is_empty()
        && name.len() <= 63
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
    (label && !secret.is_empty()).then_some(name)
}

/// In-memory setup token and invitations, for tests.
#[derive(Debug, Default)]
pub struct MemorySetupStore {
    token: Mutex<Option<SetupToken>>,
    invitations: Mutex<HashMap<String, SetupToken>>,
}

impl MemorySetupStore {
    /// Adds an invitation, as `zeabur-identityctl invite` would.
    pub fn put_invitation(&self, name: &str, user: &User, token_hash: &str, expires_at: UnixTime) {
        let token = SetupToken {
            user: user.name.clone(),
            user_subject: Some(user.subject.clone()),
            token_hash: token_hash.to_owned(),
            expires_at,
            version: format!("invitation/{name}"),
        };
        self.invitations
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(name.to_owned(), token);
    }

    /// Replaces the token, as the admin CLI would.
    pub fn put(&self, user: &User, token_hash: &str, expires_at: UnixTime) {
        let mut slot = self.token.lock().unwrap_or_else(PoisonError::into_inner);
        let version = slot
            .as_ref()
            .map_or(1, |t| t.version.parse::<u64>().unwrap_or(0) + 1);
        *slot = Some(SetupToken {
            user: user.name.clone(),
            user_subject: Some(user.subject.clone()),
            token_hash: token_hash.to_owned(),
            expires_at,
            version: version.to_string(),
        });
    }
}

impl SetupStore for MemorySetupStore {
    fn load(
        &self,
        presented: &str,
    ) -> impl Future<Output = Result<Option<SetupToken>, StoreError>> + Send {
        if let Some(name) = invitation_name(presented) {
            let invitations = self
                .invitations
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            return future::ready(Ok(invitations.get(name).cloned()));
        }
        let slot = self.token.lock().unwrap_or_else(PoisonError::into_inner);
        future::ready(Ok(slot.clone()))
    }

    fn consume(
        &self,
        token: &SetupToken,
    ) -> impl Future<Output = Result<Consume, StoreError>> + Send {
        if let Some(name) = token.version.strip_prefix("invitation/") {
            let mut invitations = self
                .invitations
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            let outcome = if invitations.remove(name).is_some() {
                Consume::Consumed
            } else {
                Consume::AlreadyUsed
            };
            drop(invitations);
            return future::ready(Ok(outcome));
        }
        let mut slot = self.token.lock().unwrap_or_else(PoisonError::into_inner);
        let outcome = if slot.as_ref().is_some_and(|t| t.version == token.version) {
            *slot = None;
            Consume::Consumed
        } else {
            Consume::AlreadyUsed
        };
        drop(slot);
        future::ready(Ok(outcome))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client(id: &str, display_name: Option<&str>, home_url: Option<&str>) -> Client {
        Client {
            id: id.into(),
            display_name: display_name.map(Into::into),
            kind: ClientType::Public,
            redirect_uris: vec![],
            audiences: vec![],
            secret_hash: None,
            id_token_alg: zeabur_identity_keys::Algorithm::Es256,
            home_url: home_url.map(Into::into),
        }
    }

    #[test]
    fn only_admin_accounts_carry_the_admin_group() {
        let user = |account_type| User {
            groups: vec!["dev".into(), ADMIN_GROUP.into()],
            account_type,
            ..User::default()
        };
        assert_eq!(user(AccountType::Regular).token_groups(), ["dev"]);
        assert_eq!(
            user(AccountType::Admin).token_groups(),
            ["dev", ADMIN_GROUP]
        );
    }

    #[test]
    fn apps_are_clients_with_a_home_url_by_name() {
        let clients = [
            client("kubectl", None, None),
            client(
                "zeabur",
                Some("Zeabur"),
                Some("https://zeabur.example.com/"),
            ),
            client("argocd", Some(" "), Some("https://argocd.example.com/")),
        ];
        assert_eq!(
            apps(&clients),
            [
                App {
                    name: "Zeabur".into(),
                    url: "https://zeabur.example.com/".into()
                },
                App {
                    name: "argocd".into(),
                    url: "https://argocd.example.com/".into()
                },
            ]
        );
        let many: Vec<Client> = (0..20)
            .map(|i| client(&format!("app{i:02}"), None, Some("https://e.com/")))
            .collect();
        assert_eq!(apps(&many).len(), MAX_APPS);
    }
}
