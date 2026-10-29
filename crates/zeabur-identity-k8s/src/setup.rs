//! The one-time setup token in a Secret, and the cluster admin's side of issuing it.
//!
//! The cluster admin runs `zeabur-identityctl setup-link` with their own kubeconfig. It creates the
//! `User` as an admin account (`accountType: Admin`), optionally removes the user's pending
//! invitations, old passkeys and sessions (`--reset`), and
//! writes the Secret `zeabur-identity-setup` holding only the SHA-256 of a fresh 256-bit token.
//! Zeabur Identity's service account can only `get` and `delete` that Secret, so it can redeem a
//! token but never create one, and it never needs RBAC rights: the `zeabur:admins` binding is
//! created at install.
//!
//! The Secret and each invitation carry an owner reference with the UID of their `User`. A token
//! enrols only a `User` with that UID: see [`SetupToken::is_for`]. Thus a token left over from a
//! deleted `User` does not enrol a new `User` with the same name.
//!
//! Redeeming is a delete with `uid` and `resourceVersion` preconditions, so exactly one of any
//! number of concurrent redemptions succeeds, and issuing a new link (which replaces the Secret)
//! invalidates every earlier one. The token travels in the URL fragment, which browsers do not
//! send to servers or proxies. A user who already has passkeys or linked accounts gets a setup
//! link or an invitation only with `--reset`, which also deletes the user's credentials and
//! grants: otherwise the link's holder could add a passkey to an account that someone else
//! controls. A credential owned by an earlier `User` of the same name does not count: it does not
//! sign in as this `User`, and garbage collection deletes it.
//!
//! A link stays valid for at most [`MAX_VALID_FOR`]: the lifetime of an invitation from Zeabur and
//! the default of `invite`. A link sent through chat or email can leak, so its lifetime has a cap.
//!
//! Each issued link is recorded as an `Event` on the `User`, and Zeabur Identity records each
//! redemption the same way. If the `Event` fails, the command does not show the link.
//!
//! Reset deletes the user's invitations first, then credentials, then grants. Invitations go
//! first because each one can enrol another passkey: one left behind would let whoever holds it
//! back into the recovered account. Reset always deletes all three collections, even when they
//! look empty: a failed later deletion may follow a successful earlier one, so a retry cannot use
//! a count as evidence that the rest are gone. No setup Secret is written until every deletion
//! succeeds. An enrolment that redeemed its link before the reset but stores its passkey after
//! the credentials are deleted survives it; that window is one request long, and
//! `kubectl get zbcred -l identity.zeabur.com/user=<name>` after the reset shows it. This
//! implements Zeabur Identity's account-recovery policy using the security-event refresh-token
//! revocation permitted by [RFC 9700 §4.14.2].
//!
//! [RFC 9700 §4.14.2]: https://www.rfc-editor.org/rfc/rfc9700.html#section-4.14.2

use std::collections::BTreeMap;
use std::future::Future;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use k8s_openapi::ByteString;
use k8s_openapi::api::core::v1::Secret;
use kube::api::{Api, DeleteParams, ListParams, ObjectMeta, PostParams};
use kube::{Client, Resource as _, ResourceExt as _};
use thiserror::Error;
use zeabur_identity_core::clock::UnixTime;
use zeabur_identity_core::config::BaseUrl;
use zeabur_identity_core::crypto::{hash_secret, random};
use zeabur_identity_store::{
    AccountEvent, Consume, CredentialStore as _, SetupStore, SetupToken, StoreError,
    invitation_name,
};

use super::MANAGED_BY;
use super::credentials::KubeCredentialStore;
use super::objects::{DeleteOutcome, delete_if_unchanged};
use super::users::{owned_by_another, user_owner_uid};
use crate::crd::credential::Credential;
use crate::crd::grant::Grant;
use crate::crd::invitation::Invitation;
use crate::crd::user::{AccountType, User, UserSpec};
use crate::crd::{EXPIRES_AT_ANNOTATION, USER_LABEL};

/// Name of the setup Secret.
pub const SETUP_SECRET: &str = "zeabur-identity-setup";
/// Its `type`.
pub const SECRET_TYPE: &str = "identity.zeabur.com/setup";
pub use zeabur_identity_core::protocol::ADMIN_GROUP;

/// The longest a setup link or an invitation stays valid.
pub const MAX_VALID_FOR: Duration = Duration::from_hours(7 * 24);

const USER_KEY: &str = "user";
const HASH_KEY: &str = "token-hash";

/// Reads and consumes the setup token and, when enabled, invitations.
#[derive(Clone)]
pub struct KubeSetupStore {
    api: Api<Secret>,
    invitations: Option<Api<Invitation>>,
}

impl std::fmt::Debug for KubeSetupStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("KubeSetupStore")
    }
}

impl KubeSetupStore {
    /// Uses the given (namespaced) API.
    #[must_use]
    pub const fn new(api: Api<Secret>) -> Self {
        Self {
            api,
            invitations: None,
        }
    }

    /// Also redeems invitations from the given (namespaced) API.
    #[must_use]
    pub fn with_invitations(mut self, invitations: Api<Invitation>) -> Self {
        self.invitations = Some(invitations);
        self
    }
}

fn backend(error: &kube::Error) -> StoreError {
    StoreError(error.to_string())
}

fn data(secret: &Secret, key: &str) -> Option<String> {
    let bytes = secret.data.as_ref()?.get(key)?;
    String::from_utf8(bytes.0.clone()).ok()
}

async fn load_setup(api: &Api<Secret>) -> Result<Option<SetupToken>, StoreError> {
    let Some(secret) = api.get_opt(SETUP_SECRET).await.map_err(|e| backend(&e))? else {
        return Ok(None);
    };
    if secret.type_.as_deref() != Some(SECRET_TYPE) {
        return Err(StoreError(format!(
            "Secret {SETUP_SECRET} has the wrong type"
        )));
    }
    let expires_at = secret
        .annotations()
        .get(EXPIRES_AT_ANNOTATION)
        .and_then(|v| v.parse::<u64>().ok())
        .map(UnixTime::from_secs);
    let (Some(user), Some(token_hash), Some(expires_at), Some(uid), Some(rv)) = (
        data(&secret, USER_KEY),
        data(&secret, HASH_KEY),
        expires_at,
        secret.uid(),
        secret.resource_version(),
    ) else {
        return Err(StoreError(format!("Secret {SETUP_SECRET} is malformed")));
    };
    Ok(Some(SetupToken {
        user,
        user_subject: user_owner_uid(&secret.metadata).map(str::to_owned),
        token_hash,
        expires_at,
        version: format!("{SETUP_SECRET}/{uid}/{rv}"),
    }))
}

async fn load_invitation(
    api: &Api<Invitation>,
    name: &str,
) -> Result<Option<SetupToken>, StoreError> {
    let Some(invitation) = api.get_opt(name).await.map_err(|e| backend(&e))? else {
        return Ok(None);
    };
    let (Some(uid), Some(rv)) = (invitation.uid(), invitation.resource_version()) else {
        return Ok(None);
    };
    Ok(Some(SetupToken {
        user: invitation.spec.user.clone(),
        user_subject: user_owner_uid(&invitation.metadata).map(str::to_owned),
        token_hash: invitation.spec.token_hash.clone(),
        expires_at: UnixTime::from_secs(u64::try_from(invitation.spec.expires_at).unwrap_or(0)),
        version: format!("{INVITATION_VERSION}{name}/{uid}/{rv}"),
    }))
}

/// Prefix of an invitation token's version.
const INVITATION_VERSION: &str = "invitation:";

impl SetupStore for KubeSetupStore {
    fn load(
        &self,
        presented: &str,
    ) -> impl Future<Output = Result<Option<SetupToken>, StoreError>> + Send {
        let api = self.api.clone();
        let invitations = self.invitations.clone();
        let invitation = invitation_name(presented).map(str::to_owned);
        async move {
            match (invitation, invitations) {
                (Some(name), Some(invitations)) => load_invitation(&invitations, &name).await,
                // Invitations are disabled: such a token refers to nothing.
                (Some(_), None) => Ok(None),
                (None, _) => load_setup(&api).await,
            }
        }
    }

    fn consume(
        &self,
        token: &SetupToken,
    ) -> impl Future<Output = Result<Consume, StoreError>> + Send {
        let api = self.api.clone();
        let invitations = self.invitations.clone();
        let version = token.version.clone();
        async move {
            let malformed = || StoreError("malformed enrolment token version".to_owned());
            let (name, rest) = version.split_once('/').ok_or_else(malformed)?;
            let (uid, rv) = rest.split_once('/').ok_or_else(malformed)?;
            // The delete is the single-use gate: with uid and resourceVersion preconditions,
            // exactly one concurrent redemption succeeds, and a regenerated token is never
            // consumed by a redemption that read the old one.
            let outcome = match name.strip_prefix(INVITATION_VERSION) {
                Some(invitation) => {
                    let api = invitations.ok_or_else(malformed)?;
                    delete_if_unchanged(&api, invitation, uid, rv).await
                }
                None if name == SETUP_SECRET => {
                    delete_if_unchanged(&api, SETUP_SECRET, uid, rv).await
                }
                None => return Err(malformed()),
            };
            match outcome.map_err(|e| backend(&e))? {
                DeleteOutcome::Deleted => Ok(Consume::Consumed),
                DeleteOutcome::Changed | DeleteOutcome::NotFound => Ok(Consume::AlreadyUsed),
            }
        }
    }
}

/// Why a setup link or an invitation could not be issued.
#[derive(Debug, Error)]
pub enum LinkError {
    /// The Kubernetes API failed (often: the kubeconfig lacks the rights).
    #[error("Kubernetes API request failed: {0}")]
    Kubernetes(#[from] kube::Error),
    /// The user can already sign in; a link would let its holder add another passkey.
    #[error(
        "user {user} can already sign in (passkeys and linked accounts: {count}); pass --reset to remove them, their sessions, and pending invitations"
    )]
    HasCredentials {
        /// User object name.
        user: String,
        /// How many credentials exist.
        count: usize,
    },
    /// The requested lifetime is longer than [`MAX_VALID_FOR`].
    #[error(
        "a link stays valid for at most {} days; pass a shorter --valid-for",
        MAX_VALID_FOR.as_secs() / 86_400
    )]
    TooLong,
    /// Randomness failed.
    #[error("unable to generate the token")]
    Crypto,
    /// The link exists, but the `Event` on the `User` failed, so the link is not shown.
    #[error("unable to record the link as an Event on the user, so the link is not shown: {0}")]
    Event(StoreError),
}

/// Refuses a lifetime longer than [`MAX_VALID_FOR`].
pub(crate) fn check_valid_for(valid_for: Duration) -> Result<(), LinkError> {
    if valid_for > MAX_VALID_FOR {
        return Err(LinkError::TooLong);
    }
    Ok(())
}

/// Records an issued link as an `Event` on `user`. A link without its `Event` is not shown.
pub(crate) async fn record_issued(
    client: &Client,
    namespace: &str,
    user: &User,
    reason: &'static str,
    note: String,
    now: UnixTime,
) -> Result<(), LinkError> {
    let store = KubeCredentialStore::new(Api::namespaced(client.clone(), namespace));
    let event = AccountEvent {
        user: user.name_any(),
        subject: user.uid().unwrap_or_default(),
        reason,
        at: now,
        note,
    };
    store.record(&event).await.map_err(LinkError::Event)
}

/// The `Event` note for an issued link.
pub(crate) fn issued_note(link: Option<&str>, expires_at: UnixTime, reset: bool) -> String {
    let invitation = link.map_or_else(String::new, |name| format!("invitation={name} "));
    let reset = if reset { " reset=true" } else { "" };
    format!("{invitation}expires_at={}{reset}", expires_at.as_secs())
}

/// Refuses a link for `user` if the user can already sign in, unless `reset` is true. With
/// `reset`, deletes the user's invitations, then credentials, then grants.
pub(crate) async fn prepare_enrolment(
    client: &Client,
    namespace: &str,
    user: &User,
    reset: bool,
) -> Result<(), LinkError> {
    let username = user.name_any();
    let subject = user.uid().unwrap_or_default();
    let selector = ListParams::default().labels(&format!("{USER_LABEL}={username}"));
    let credentials: Api<Credential> = Api::namespaced(client.clone(), namespace);
    let existing = credentials
        .list(&selector)
        .await?
        .items
        .iter()
        .filter(|credential| !owned_by_another(&credential.metadata, &subject))
        .count();
    if existing > 0 && !reset {
        return Err(LinkError::HasCredentials {
            user: username,
            count: existing,
        });
    }
    if reset {
        // Pending invitations first: each could enrol a passkey into the recovered account.
        let invitations: Api<Invitation> = Api::namespaced(client.clone(), namespace);
        invitations
            .delete_collection(&DeleteParams::default(), &selector)
            .await?;
        credentials
            .delete_collection(&DeleteParams::default(), &selector)
            .await?;
        // End the user's refresh-token families too: whoever held the old passkeys is out.
        let grants: Api<Grant> = Api::namespaced(client.clone(), namespace);
        grants
            .delete_collection(&DeleteParams::default(), &selector)
            .await?;
    }
    Ok(())
}

/// A freshly issued setup link.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetupLink {
    /// `https://<issuer>/setup#token=<token>`. The token is in the fragment, so it never reaches
    /// server or proxy logs.
    pub url: String,
    /// When the link stops working.
    pub expires_at: UnixTime,
}

/// Issues a setup link for `username` using the caller's (cluster admin's) credentials.
///
/// # Errors
///
/// [`LinkError`] if `valid_for` is longer than [`MAX_VALID_FOR`], the API calls fail, or the user
/// already has passkeys or linked accounts and `reset` is false. Records a `SetupLinkIssued`
/// `Event` on the `User`.
pub async fn issue_setup_link(
    client: Client,
    namespace: &str,
    issuer: &BaseUrl,
    username: &str,
    valid_for: Duration,
    reset: bool,
    now: UnixTime,
) -> Result<SetupLink, LinkError> {
    check_valid_for(valid_for)?;
    let pp = PostParams::default();
    let users: Api<User> = Api::namespaced(client.clone(), namespace);
    let user = if let Some(user) = users.get_opt(username).await? {
        user
    } else {
        let user = User::new(
            username,
            UserSpec {
                username: username.to_owned(),
                display_name: None,
                groups: Vec::new(),
                disabled: false,
                account_type: AccountType::Admin,
            },
        );
        users.create(&pp, &user).await?
    };

    prepare_enrolment(&client, namespace, &user, reset).await?;

    let token = URL_SAFE_NO_PAD.encode(random::<32>().map_err(|_crypto| LinkError::Crypto)?);
    let expires_at = now.saturating_add(valid_for);
    let secrets: Api<Secret> = Api::namespaced(client.clone(), namespace);
    let mut secret = Secret {
        metadata: ObjectMeta {
            name: Some(SETUP_SECRET.to_owned()),
            owner_references: user.owner_ref(&()).map(|owner| vec![owner]),
            labels: Some(BTreeMap::from([(
                MANAGED_BY.0.to_owned(),
                MANAGED_BY.1.to_owned(),
            )])),
            annotations: Some(BTreeMap::from([(
                EXPIRES_AT_ANNOTATION.to_owned(),
                expires_at.as_secs().to_string(),
            )])),
            ..ObjectMeta::default()
        },
        type_: Some(SECRET_TYPE.to_owned()),
        data: Some(BTreeMap::from([
            (
                USER_KEY.to_owned(),
                ByteString(username.as_bytes().to_vec()),
            ),
            (
                HASH_KEY.to_owned(),
                ByteString(hash_secret(token.as_bytes()).into_bytes()),
            ),
        ])),
        ..Secret::default()
    };
    // Replacing the Secret changes its UID or resourceVersion, which invalidates any earlier link.
    match secrets.get_opt(SETUP_SECRET).await? {
        Some(current) => {
            secret.metadata.resource_version = current.resource_version();
            secrets.replace(SETUP_SECRET, &pp, &secret).await?;
        }
        None => {
            secrets.create(&pp, &secret).await?;
        }
    }
    let note = issued_note(None, expires_at, reset);
    record_issued(&client, namespace, &user, "SetupLinkIssued", note, now).await?;
    Ok(SetupLink {
        url: format!("{}#token={token}", issuer.join("/setup")),
        expires_at,
    })
}
