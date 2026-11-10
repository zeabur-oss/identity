//! `User`: a person who can sign in.

#![expect(
    unreachable_pub,
    reason = "the KubeSchema derive re-emits these types inside a private module"
)]

use kube::{CustomResource, KubeSchema};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// A person who can sign in. The admin (or GitOps) owns `spec`; Zeabur Identity only reads it.
///
/// Kubernetes sees the user as `zeabur:<username>` with groups `zeabur:<group>`, plus
/// `zeabur:admins` for an admin account.
#[expect(
    clippy::duplicated_attributes,
    reason = "repeated printcolumn arguments such as `type_ = \"string\"` are distinct columns"
)]
#[derive(
    CustomResource, KubeSchema, Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq,
)]
#[kube(
    group = "identity.zeabur.com",
    version = "v1alpha1",
    kind = "User",
    namespaced,
    shortname = "zbuser",
    category = "zeabur-identity",
    selectable = ".spec.username",
    printcolumn(name = "Username", type_ = "string", json_path = ".spec.username"),
    printcolumn(name = "Type", type_ = "string", json_path = ".spec.accountType"),
    printcolumn(name = "Disabled", type_ = "boolean", json_path = ".spec.disabled"),
    printcolumn(
        name = "Age",
        type_ = "date",
        json_path = ".metadata.creationTimestamp"
    ),
    doc = "A person who can sign in to Zeabur Identity."
)]
#[serde(rename_all = "camelCase")]
pub struct UserSpec {
    /// Login name: a lowercase DNS subdomain of at most 63 characters. Kubernetes sees
    /// `zeabur:<username>`. The length limit keeps the username usable as the
    /// `identity.zeabur.com/user` label value on invitations, credentials and grants.
    /// Use the username as the object name so object-name uniqueness also prevents duplicate
    /// usernames. Immutable because RBAC bindings and audit logs refer to it.
    #[schemars(
        length(min = 1, max = 63),
        regex(pattern = r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$")
    )]
    #[x_kube(validation = Rule::new("self == oldSelf").message("username is immutable"))]
    pub username: String,

    /// Name shown in the UI.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(length(max = 128))]
    pub display_name: Option<String>,

    /// Groups. Kubernetes sees each as `zeabur:<group>`. The characters exclude ':', so a group
    /// can never spell a reserved name. `admins` is refused: set `accountType: Admin` instead.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[schemars(
        length(max = 64),
        inner(
            length(min = 1, max = 128),
            regex(pattern = r"^[a-z0-9]([-a-z0-9._/]{0,126}[a-z0-9])?$")
        )
    )]
    #[x_kube(validation = Rule::new("!self.exists(g, g == 'admins')").message(
        "the admins group comes from accountType: Admin; remove it from groups"
    ))]
    pub groups: Vec<String>,

    /// A disabled user cannot sign in, and refresh tokens stop working at their next use.
    #[serde(default)]
    pub disabled: bool,

    /// `Admin` or `Regular` (the default). An admin account signs in only with a passkey, gets
    /// shorter sessions, and its tokens carry the group `zeabur:admins`, which is bound to
    /// `cluster-admin`.
    #[serde(default)]
    pub account_type: AccountType,
}

/// What kind of account a `User` is. See
/// [`zeabur_identity_core::account::AccountType`].
#[derive(Serialize, Deserialize, JsonSchema, Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum AccountType {
    /// Day-to-day work.
    #[default]
    Regular,
    /// Administers the cluster.
    Admin,
}

impl From<AccountType> for zeabur_identity_core::account::AccountType {
    fn from(value: AccountType) -> Self {
        match value {
            AccountType::Regular => Self::Regular,
            AccountType::Admin => Self::Admin,
        }
    }
}
