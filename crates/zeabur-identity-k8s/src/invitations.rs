//! Invitations: the admin's side (`zeabur-identityctl invite`).

use std::collections::BTreeMap;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use kube::api::{Api, ObjectMeta, PostParams};
use kube::{Client, Resource as _, ResourceExt as _};
use zeabur_identity_api::invitation::{Invitation, InvitationSpec};
use zeabur_identity_api::user::{AccountType, User, UserSpec};
use zeabur_identity_api::{EXPIRES_AT_ANNOTATION, EXPIRY_BUCKET_LABEL, USER_LABEL, token_hash};
use zeabur_identity_core::clock::UnixTime;
use zeabur_identity_core::config::BaseUrl;
use zeabur_identity_core::crypto::{hex, random};

use super::MANAGED_BY;
use super::setup::{LinkError, check_valid_for, issued_note, prepare_enrolment, record_issued};

/// Path of the enrolment page; the token goes in the fragment.
pub const ENROL_PATH: &str = "/setup";

/// Who to invite.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invitee {
    /// Login name; also the `User` object name.
    pub username: String,
    /// Display name, for a new user.
    pub display_name: Option<String>,
    /// Groups, for a new user.
    pub groups: Vec<String>,
    /// Account type, for a new user.
    pub account_type: AccountType,
}

/// What was created.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invited {
    /// The `Invitation` object name.
    pub name: String,
    /// The link.
    pub url: String,
    /// Whether the `User` was created now.
    pub created_user: bool,
    /// When the link stops working.
    pub expires_at: UnixTime,
}

/// A fresh `<name>.<secret>` token.
///
/// # Errors
///
/// Returns [`LinkError::Crypto`] if randomness fails.
pub fn new_token(name: &str) -> Result<String, LinkError> {
    let secret = random::<32>().map_err(|_crypto| LinkError::Crypto)?;
    Ok(format!("{name}.{}", URL_SAFE_NO_PAD.encode(secret)))
}

/// The enrolment link for `token`.
#[must_use]
pub fn link(issuer: &BaseUrl, token: &str) -> String {
    format!("{}#token={token}", issuer.join(ENROL_PATH))
}

/// Creates the user (if missing) and an invitation, with the caller's (admin's) credentials.
///
/// A user who already has passkeys or linked accounts gets an invitation only with `reset`, which
/// first deletes the user's invitations, credentials and grants, as for a setup link (see
/// [`crate::setup`]).
///
/// # Errors
///
/// [`LinkError`] if `valid_for` is longer than [`MAX_VALID_FOR`](crate::setup::MAX_VALID_FOR), an
/// API call fails, or the user already has credentials and `reset` is false. Records an
/// `InvitationIssued` `Event` on the `User`.
pub async fn invite(
    client: Client,
    namespace: &str,
    issuer: &BaseUrl,
    invitee: &Invitee,
    valid_for: Duration,
    reset: bool,
    now: UnixTime,
) -> Result<Invited, LinkError> {
    check_valid_for(valid_for)?;
    let pp = PostParams::default();
    let users: Api<User> = Api::namespaced(client.clone(), namespace);
    let (user, created_user) = if let Some(user) = users.get_opt(&invitee.username).await? {
        (user, false)
    } else {
        let user = User::new(
            &invitee.username,
            UserSpec {
                username: invitee.username.clone(),
                display_name: invitee.display_name.clone(),
                groups: invitee.groups.clone(),
                account_type: invitee.account_type,
                ..UserSpec::default()
            },
        );
        (users.create(&pp, &user).await?, true)
    };
    prepare_enrolment(&client, namespace, &user, reset).await?;

    let name = format!(
        "inv-{}",
        hex(&random::<8>().map_err(|_crypto| LinkError::Crypto)?)
    );
    let expires_at = now.saturating_add(valid_for);
    let token = new_token(&name)?;
    let invitation = Invitation {
        metadata: ObjectMeta {
            name: Some(name.clone()),
            namespace: Some(namespace.to_owned()),
            owner_references: user.owner_ref(&()).map(|owner| vec![owner]),
            labels: Some(BTreeMap::from([
                (MANAGED_BY.0.to_owned(), MANAGED_BY.1.to_owned()),
                (USER_LABEL.to_owned(), invitee.username.clone()),
                (
                    EXPIRY_BUCKET_LABEL.to_owned(),
                    (expires_at.as_secs() / 3600).to_string(),
                ),
            ])),
            annotations: Some(BTreeMap::from([(
                EXPIRES_AT_ANNOTATION.to_owned(),
                expires_at.as_secs().to_string(),
            )])),
            ..ObjectMeta::default()
        },
        spec: InvitationSpec {
            user: invitee.username.clone(),
            token_hash: token_hash(token.as_bytes()),
            expires_at: i64::try_from(expires_at.as_secs()).unwrap_or(i64::MAX),
        },
    };
    let invitations: Api<Invitation> = Api::namespaced(client.clone(), namespace);
    let created = invitations.create(&pp, &invitation).await?;
    let note = issued_note(Some(&name), expires_at, reset);
    record_issued(&client, namespace, &user, "InvitationIssued", note, now).await?;
    Ok(Invited {
        name: created.name_any(),
        url: link(issuer, &token),
        created_user,
        expires_at,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_name_their_invitation() {
        let token = new_token("inv-abc").unwrap();
        let (name, secret) = token.split_once('.').unwrap();
        assert_eq!(name, "inv-abc");
        assert_eq!(secret.len(), 43);
        assert_eq!(
            zeabur_identity_store::invitation_name(&token),
            Some("inv-abc")
        );
    }
}
