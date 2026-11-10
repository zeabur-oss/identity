//! `Credential`: a passkey or a linked upstream identity.

#![expect(
    unreachable_pub,
    reason = "the KubeSchema derive re-emits these types inside a private module"
)]

use kube::{CustomResource, KubeSchema};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::upstream::{ExternalId, ProviderId};

/// Kind of credential.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, JsonSchema)]
pub enum CredentialType {
    /// A WebAuthn discoverable credential.
    Passkey,
    /// An account at an upstream provider (`UpstreamProvider`).
    Upstream,
}

/// The admission rule that keeps the spec unchanged, with one exception.
///
/// A linked account of type `GitHub` or `Google` may become type `Upstream` with provider `github`
/// or `google`. Zeabur Identity makes that change when it starts (`zeabur_identity_k8s::migrate`).
pub const IMMUTABLE_RULE: &str = concat!(
    "self == oldSelf || (oldSelf.type in ['GitHub', 'Google'] && self.type == 'Upstream'",
    " && self.user == oldSelf.user && !has(self.passkey) && has(self.external)",
    " && has(oldSelf.external) && self.external == oldSelf.external && has(self.provider)",
    " && self.provider == (oldSelf.type == 'GitHub' ? 'github' : 'google'))",
);

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
    validation = Rule::new(IMMUTABLE_RULE).message("credentials are immutable; delete and re-enrol instead"),
    validation = Rule::new("(self.type == 'Passkey') == has(self.passkey)").message("passkey is set exactly when type is Passkey"),
    validation = Rule::new("(self.type != 'Passkey') == has(self.external)").message("external is set exactly when type is Upstream"),
    validation = Rule::new("(self.type == 'Upstream') == has(self.provider)").message("provider is set exactly when type is Upstream")
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
    /// Upstream identity, when `type` is `Upstream`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external: Option<ExternalId>,
    /// The `UpstreamProvider` that linked the account, when `type` is `Upstream`. Sign-in does not
    /// read it: any provider with the same issuer signs the account in.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(
        with = "String",
        length(min = 1, max = 63),
        regex(pattern = r"^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$")
    )]
    pub provider: Option<ProviderId>,
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

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::upstream::{Issuer, Subject};

    #[test]
    fn a_stored_linked_account_reads_back_to_the_same_typed_values() {
        let stored = json!({
            "apiVersion": "identity.zeabur.com/v1alpha1",
            "kind": "Credential",
            "metadata": {
                "name": "c-7de39252447e608075f56f721487e3974c942e34378410bbe7ab9e5edf75c0fc"
            },
            "spec": {
                "user": "alice",
                "type": "Upstream",
                "external": {"issuer": "https://github.com", "subject": "583231"},
                "provider": "github"
            }
        });
        let credential: Credential = serde_json::from_value(stored.clone()).unwrap();
        let expected = ExternalId {
            issuer: Issuer::new("https://github.com").unwrap(),
            subject: Subject::new("583231").unwrap(),
        };
        assert_eq!(credential.spec.external, Some(expected));
        assert_eq!(
            serde_json::to_value(&credential).unwrap()["spec"],
            stored["spec"]
        );
    }

    #[test]
    fn a_stored_credential_with_a_malformed_subject_is_refused() {
        let stored = json!({
            "apiVersion": "identity.zeabur.com/v1alpha1",
            "kind": "Credential",
            "metadata": {"name": "c-0"},
            "spec": {
                "user": "alice",
                "type": "Upstream",
                "external": {"issuer": "https://github.com", "subject": "alice smith"},
                "provider": "github"
            }
        });
        assert!(serde_json::from_value::<Credential>(stored).is_err());
    }
}
