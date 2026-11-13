//! `Credential`: a passkey or a linked upstream identity.

#![expect(
    unreachable_pub,
    reason = "the KubeSchema derive re-emits these types inside a private module"
)]

use kube::{CustomResource, KubeSchema};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::upstream::ExternalId;

/// A way for a `User` to sign in.
///
/// The object name is derived from the credential's unique key (`c-` + hex SHA-256 of the
/// passkey credential ID, or of the upstream issuer and subject), so creating a duplicate fails
/// with `409 AlreadyExists`. That is the uniqueness check WebAuthn Level 3 §7.1 asks for, and
/// it holds across replicas. The spec is immutable; revoking is deleting. `status` holds what
/// the user may change (the label) and when the credential was last used.
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
    printcolumn(
        name = "Age",
        type_ = "date",
        json_path = ".metadata.creationTimestamp"
    ),
    doc = "A passkey or linked upstream identity of a Zeabur Identity user."
)]
#[x_kube(
    validation = Rule::new("self == oldSelf").message("credentials are immutable; delete and re-enrol instead")
)]
#[serde(rename_all = "camelCase")]
pub struct CredentialSpec {
    /// Name of the `User` object.
    #[schemars(length(min = 1, max = 253))]
    pub user: String,
    /// What signs in: a passkey or an upstream account.
    #[serde(flatten)]
    pub kind: CredentialKind,
}

/// What a `Credential` signs in with. The field that is set names the kind.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum CredentialKind {
    /// A WebAuthn discoverable credential.
    Passkey(Passkey),
    /// An account at an upstream provider, which any `UpstreamProvider` with its issuer signs in.
    External(ExternalId),
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
    use serde_json::{Value, json};

    use super::*;
    use crate::upstream::{Issuer, Subject};

    fn stored(spec: &Value) -> Value {
        json!({
            "apiVersion": "identity.zeabur.com/v1alpha1",
            "kind": "Credential",
            "metadata": {
                "name": "c-7de39252447e608075f56f721487e3974c942e34378410bbe7ab9e5edf75c0fc"
            },
            "spec": spec
        })
    }

    fn github_account() -> ExternalId {
        ExternalId {
            issuer: Issuer::new("https://github.com").unwrap(),
            subject: Subject::new("583231").unwrap(),
        }
    }

    #[test]
    fn a_linked_account_reads_back_to_the_same_typed_values() {
        let object = stored(&json!({
            "user": "alice",
            "external": {"issuer": "https://github.com", "subject": "583231"}
        }));
        let credential: Credential = serde_json::from_value(object.clone()).unwrap();
        assert_eq!(
            credential.spec.kind,
            CredentialKind::External(github_account())
        );
        assert_eq!(serde_json::to_value(&credential).unwrap(), object);
    }

    #[test]
    fn credentials_stored_by_earlier_versions_read_by_their_field() {
        let passkey = json!({"credentialId": "AAEC", "record": "{}", "backupEligible": true});
        let external = json!({"issuer": "https://github.com", "subject": "583231"});
        let earlier = [
            json!({"user": "alice", "type": "Passkey", "passkey": passkey}),
            json!({"user": "alice", "type": "GitHub", "external": external}),
            json!({"user": "alice", "type": "Upstream", "external": external, "provider": "github"}),
        ];
        let [passkey, github, upstream] =
            earlier.map(|spec| serde_json::from_value::<Credential>(stored(&spec)).unwrap());
        assert!(matches!(passkey.spec.kind, CredentialKind::Passkey(_)));
        assert_eq!(github.spec.kind, CredentialKind::External(github_account()));
        assert_eq!(upstream.spec, github.spec);
    }

    #[test]
    fn a_credential_without_a_kind_is_refused() {
        let object = stored(&json!({"user": "alice", "type": "Passkey"}));
        assert!(serde_json::from_value::<Credential>(object).is_err());
    }

    #[test]
    fn a_stored_credential_with_a_malformed_subject_is_refused() {
        let object = stored(&json!({
            "user": "alice",
            "external": {"issuer": "https://github.com", "subject": "alice smith"}
        }));
        assert!(serde_json::from_value::<Credential>(object).is_err());
    }
}
