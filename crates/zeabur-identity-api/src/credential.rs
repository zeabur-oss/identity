//! `Credential`: a passkey or a linked upstream identity.

#![expect(
    unreachable_pub,
    reason = "the KubeSchema derive re-emits these types inside a private module"
)]

use kube::{CustomResource, KubeSchema};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
pub use zeabur_identity_store::CredentialType;

/// A way for a `User` to sign in.
///
/// The object name is derived from the credential's unique key (`c-` + hex SHA-256 of the
/// passkey credential ID, or of the upstream issuer and subject), so creating a duplicate fails
/// with `409 AlreadyExists`. That is the uniqueness check WebAuthn Level 3 §7.1 asks for, and
/// it holds across replicas. The spec is immutable; revoking is deleting. `status` holds what
/// the user may change (the label) and when the credential was last used.
#[expect(
    clippy::duplicated_attributes,
    reason = "repeated printcolumn arguments such as `type_ = \"string\"` are distinct columns"
)]
#[derive(CustomResource, KubeSchema, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[kube(
    group = "identity.zeabur.com",
    version = "v1alpha1",
    kind = "Credential",
    namespaced,
    status = "CredentialStatus",
    shortname = "zbcred",
    category = "zeabur-identity",
    selectable = ".spec.user",
    printcolumn(name = "User", type_ = "string", json_path = ".spec.user"),
    printcolumn(name = "Type", type_ = "string", json_path = ".spec.type"),
    printcolumn(
        name = "Age",
        type_ = "date",
        json_path = ".metadata.creationTimestamp"
    ),
    doc = "A passkey or linked upstream identity of a Zeabur Identity user."
)]
#[x_kube(
    validation = Rule::new("self == oldSelf").message("credentials are immutable; delete and re-enrol instead"),
    validation = Rule::new("(self.type == 'Passkey') == has(self.passkey)").message("passkey is set exactly when type is Passkey"),
    validation = Rule::new("(self.type != 'Passkey') == has(self.external)").message("external is set exactly when type is GitHub or Google")
)]
#[serde(rename_all = "camelCase")]
pub struct CredentialSpec {
    /// Name of the `User` object.
    #[schemars(length(min = 1, max = 253))]
    pub user: String,
    /// Kind of credential.
    #[serde(rename = "type")]
    pub kind: CredentialType,
    /// Passkey details, when `type` is `Passkey`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub passkey: Option<Passkey>,
    /// Upstream identity, when `type` is `GitHub` or `Google`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external: Option<ExternalIdentity>,
}

/// The public part of a WebAuthn credential. Nothing here is secret.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Passkey {
    /// Credential ID, base64url.
    #[schemars(length(min = 1, max = 1366), regex(pattern = r"^[A-Za-z0-9_-]+$"))]
    pub credential_id: String,
    /// The relying party's stored credential record, as serialized by the WebAuthn library
    /// (public key, algorithm, flags). Opaque to Kubernetes.
    #[schemars(length(min = 1, max = 16384))]
    pub record: String,
    /// Whether the credential may be synced to other devices (BE flag).
    #[serde(default)]
    pub backup_eligible: bool,
    /// Authenticator model (AAGUID), when the authenticator reports one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(regex(
        pattern = r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
    ))]
    pub aaguid: Option<String>,
    /// User-chosen label, for example "MacBook".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(length(max = 64))]
    pub label: Option<String>,
}

/// A linked account at an upstream provider.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ExternalIdentity {
    /// Upstream issuer.
    #[schemars(length(min = 1, max = 256))]
    pub issuer: String,
    /// Upstream subject: the stable account ID, never an email address.
    #[schemars(length(min = 1, max = 256))]
    pub subject: String,
}

/// What changes after enrolment. Written by Zeabur Identity only.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct CredentialStatus {
    /// The label the user gave it last; takes the place of `spec.passkey.label`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(length(max = 64))]
    pub label: Option<String>,
    /// When it last signed in, in Unix seconds. Updated at most once a minute.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(range(min = 0))]
    pub last_used_at: Option<i64>,
    /// Bumped by every account change that must not race a removal (see
    /// `KubeCredentialStore::remove`).
    #[serde(default)]
    #[schemars(range(min = 0))]
    pub revision: i64,
}
