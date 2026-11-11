//! `Invitation`: a one-time link that lets a person enrol a passkey.

#![expect(
    unreachable_pub,
    reason = "the KubeSchema derive re-emits these types inside a private module"
)]

use kube::{CustomResource, KubeSchema};
use serde::{Deserialize, Serialize};

/// A one-time enrolment link for a `User`, created by an admin (`zeabur-identityctl invite`).
///
/// The link carries `<invitation name>.<secret>`; only the SHA-256 of that token is stored. It
/// works once: redeeming deletes the object with UID and resourceVersion preconditions before
/// the passkey is stored, so exactly one of any number of concurrent redemptions succeeds. The
/// admin's CLI generates the token, records its hash in `spec` and prints the link; delivering it
/// is up to the admin. Expired invitations are deleted by the garbage collector.
#[derive(CustomResource, KubeSchema, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[kube(
    group = "identity.zeabur.com",
    version = "v1alpha1",
    kind = "Invitation",
    namespaced,
    shortname = "zbinvite",
    category = "zeabur-identity",
    selectable = ".spec.user",
    printcolumn(name = "User", type_ = "string", json_path = ".spec.user"),
    printcolumn(
        name = "Age",
        type_ = "date",
        json_path = ".metadata.creationTimestamp"
    ),
    doc = "A one-time passkey enrolment link for a Zeabur Identity user."
)]
#[x_kube(
    validation = Rule::new("self == oldSelf").message("an invitation's spec is immutable")
)]
#[serde(rename_all = "camelCase")]
pub struct InvitationSpec {
    /// Name of the `User` object the invitation enrols a passkey for.
    #[schemars(length(min = 1, max = 253))]
    pub user: String,
    /// `sha256:<hex>` of the token in the link.
    #[schemars(regex(pattern = r"^sha256:[0-9a-f]{64}$"))]
    pub token_hash: String,
    /// When the link stops working, in Unix seconds.
    #[schemars(range(min = 0))]
    pub expires_at: i64,
}
