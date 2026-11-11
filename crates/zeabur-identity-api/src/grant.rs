//! `Grant`: a refresh-token family.

#![expect(
    unreachable_pub,
    reason = "the KubeSchema derive re-emits these types inside a private module"
)]

use kube::{CustomResource, KubeSchema};
use serde::{Deserialize, Serialize};

/// One login's refresh-token family.
///
/// Created when an authorization code is redeemed; every refresh rotates the token with one
/// compare-and-swap on `status`; reuse of an old token deletes the object, which revokes the
/// whole family. Deleting it by hand is how an admin revokes a session
/// (`kubectl delete grant`, or `-l identity.zeabur.com/user=<user>` for all of a user's).
/// Only hashes are stored.
///
/// Signing in to the account page creates one too: named `s-…`, with client `zeabur_identity`
/// (never a valid `OAuthClient` name), and no refresh token.
#[expect(
    clippy::duplicated_attributes,
    reason = "repeated printcolumn arguments such as `type_ = \"string\"` are distinct columns"
)]
#[derive(CustomResource, KubeSchema, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[kube(
    group = "identity.zeabur.com",
    version = "v1alpha1",
    kind = "Grant",
    namespaced,
    status = "GrantStatus",
    shortname = "zbgrant",
    category = "zeabur-identity",
    selectable = ".spec.user",
    printcolumn(name = "User", type_ = "string", json_path = ".spec.user"),
    printcolumn(name = "Client", type_ = "string", json_path = ".spec.client"),
    printcolumn(name = "Rotations", type_ = "integer", json_path = ".status.rotation"),
    printcolumn(
        name = "Age",
        type_ = "date",
        json_path = ".metadata.creationTimestamp"
    ),
    doc = "A refresh-token family issued by Zeabur Identity."
)]
#[x_kube(validation = Rule::new("self == oldSelf").message("a grant's spec is immutable"))]
#[serde(rename_all = "camelCase")]
pub struct GrantSpec {
    /// Name of the `User` object.
    #[schemars(length(min = 1, max = 253))]
    pub user: String,
    /// Name of the `OAuthClient` object (the `client_id`).
    #[schemars(length(min = 1, max = 253))]
    pub client: String,
    /// Audience of the tokens issued from this grant.
    #[schemars(length(min = 1, max = 256))]
    pub audience: String,
    /// When the user authenticated, in Unix seconds (OIDC `auth_time`).
    #[schemars(range(min = 0))]
    pub auth_time: i64,
    /// Granted scopes.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[schemars(length(max = 16), inner(length(min = 1, max = 64)))]
    pub scopes: Vec<String>,
    /// Authentication methods (RFC 8176 values).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[schemars(length(max = 8), inner(length(min = 1, max = 32)))]
    pub amr: Vec<String>,
    /// Absolute expiry, in Unix seconds. The family cannot be refreshed after this.
    #[schemars(range(min = 0))]
    pub expires_at: i64,
    /// Idle expiry until the first rotation writes `status`, in Unix seconds.
    #[schemars(range(min = 0))]
    pub initial_idle_expires_at: i64,
    /// `sha256:<hex>` of the first refresh token. Valid until the first rotation writes `status`,
    /// so creating a family is one write.
    #[schemars(regex(pattern = r"^sha256:[0-9a-f]{64}$"))]
    pub initial_hash: String,
    /// UID of the `User` at sign-in.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(length(min = 1, max = 128))]
    pub subject: Option<String>,
    /// Name of the `Credential` the user signed in with. Removing that credential revokes the
    /// grant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(length(min = 1, max = 253))]
    pub credential: Option<String>,
    /// Whether the authenticator verified the user at sign-in.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub user_verified: bool,
    /// Whether the user signed in with a device-bound passkey (BE unset).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub device_bound: bool,
}

/// Rotation state, changed only through compare-and-swap.
#[derive(KubeSchema, Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct GrantStatus {
    /// Number of rotations so far.
    #[serde(default)]
    #[schemars(range(min = 0))]
    pub rotation: i64,
    /// `sha256:<hex>` of the refresh token that is currently valid.
    #[schemars(regex(pattern = r"^sha256:[0-9a-f]{64}$"))]
    pub current_hash: String,
    /// `sha256:<hex>` of the previous token, kept to tell a replay from a forgery.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(regex(pattern = r"^sha256:[0-9a-f]{64}$"))]
    pub previous_hash: Option<String>,
    /// Idle expiry, in Unix seconds; pushed forward by each rotation.
    #[serde(default)]
    #[schemars(range(min = 0))]
    pub idle_expires_at: i64,
    /// The latest re-authentication, for account sessions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reauth: Option<GrantReauth>,
}

/// A re-authentication within an account session.
#[derive(KubeSchema, Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct GrantReauth {
    /// When, in Unix seconds.
    #[schemars(range(min = 0))]
    pub auth_time: i64,
    /// Name of the `Credential` used.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(length(min = 1, max = 253))]
    pub credential: Option<String>,
    /// Whether the authenticator verified the user.
    #[serde(default)]
    pub user_verified: bool,
}
