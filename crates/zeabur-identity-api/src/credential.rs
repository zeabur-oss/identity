//! `Credential`: a passkey, a linked upstream identity, or a password.

#![expect(
    unreachable_pub,
    reason = "the KubeSchema derive re-emits these types inside a private module"
)]

use kube::{CustomResource, KubeSchema};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::upstream::ExternalId;

/// Longest passkey label, in characters.
pub const MAX_LABEL: usize = 64;

/// A way for a `User` to sign in.
///
/// The object name is derived from the credential's unique key (`c-` + hex SHA-256 of the
/// passkey credential ID, of the upstream issuer and subject, or of the user's UID for a
/// password), so creating a duplicate fails with `409 AlreadyExists`. That is the uniqueness
/// check WebAuthn Level 3 §7.1 asks for, and it holds across replicas. The spec is immutable;
/// revoking is deleting. `status` holds what the user may change (the label) and when the
/// credential was last used.
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
    doc = "A passkey, linked upstream identity or password of a Zeabur Identity user."
)]
#[x_kube(
    validation = Rule::new("self == oldSelf").message("credentials are immutable; delete and re-enrol instead")
)]
#[serde(rename_all = "camelCase")]
pub struct CredentialSpec {
    /// Name of the `User` object.
    #[schemars(length(min = 1, max = 253))]
    pub user: String,
    /// What signs in: a passkey, an upstream account or a password.
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
    /// A password hash. A user has at most one; its object name is derived from the user.
    Password(Password),
}

/// A password hash: salted PBKDF2, then keyed with a server key kept in another Secret, so the
/// hash alone cannot be attacked offline.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Password {
    /// `$<scheme>$i=<iterations>$<salt>$<hash>`.
    #[schemars(length(min = 1, max = 256))]
    pub hash: String,
    /// The second factor asked for after the password, if the user enrolled one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub totp: Option<Totp>,
}

/// A TOTP authenticator and its recovery codes.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Totp {
    /// The TOTP secret, sealed with a key derived from the password key and bound to the user.
    #[schemars(length(min = 1, max = 256))]
    pub secret: String,
    /// Keyed hashes of the one-time recovery codes, hex.
    #[schemars(length(max = 16))]
    pub recovery: Vec<RecoveryHash>,
    /// The TOTP time step of the code entered at setup. Codes of this step or before do not
    /// sign in, so the setup code cannot be used again.
    #[schemars(range(min = 0))]
    pub enrolled_step: i64,
}

/// A keyed hash of one recovery code: HMAC-SHA256, hex.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, JsonSchema)]
#[serde(transparent)]
pub struct RecoveryHash(#[schemars(regex(pattern = r"^[0-9a-f]{64}$"))] pub String);

impl std::fmt::Debug for Password {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Password(..)")
    }
}

impl std::fmt::Debug for Totp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Totp(..)")
    }
}

impl std::fmt::Debug for RecoveryHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RecoveryHash(..)")
    }
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
    #[schemars(length(max = MAX_LABEL))]
    pub label: Option<String>,
}

/// What changes after enrolment. Written by Zeabur Identity only.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct CredentialStatus {
    /// The label the user gave it last; takes the place of `spec.passkey.label`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(length(max = MAX_LABEL))]
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
    /// Failed password sign-ins, for a password credential.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guesses: Option<Guesses>,
    /// The last TOTP step accepted, so each code works once.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(range(min = 0))]
    pub totp_last_step: Option<i64>,
    /// Indexes into `spec.password.totp.recovery` of the recovery codes already used.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[schemars(length(max = 16))]
    pub recovery_used: Vec<i64>,
}

/// Failed password sign-ins, counted per browser.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Guesses {
    /// Every browser without a device cookie for the user.
    #[serde(default)]
    pub unknown: GuessCount,
    /// Browsers that signed in as the user before. Always written, so a merge patch replaces the
    /// whole list.
    #[serde(default)]
    #[schemars(length(max = 16))]
    pub known: Vec<KnownGuessCount>,
}

/// One count of failed password sign-ins.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, Default, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct GuessCount {
    /// When the count started, in Unix seconds.
    #[serde(default)]
    #[schemars(range(min = 0))]
    pub since: i64,
    /// Failures since then.
    #[serde(default)]
    #[schemars(range(min = 0))]
    pub failures: i64,
    /// Until when password sign-in from these browsers is held back, in Unix seconds; 0 when it
    /// is not. Always written, so a merge patch clears an earlier value.
    #[serde(default)]
    #[schemars(range(min = 0))]
    pub held_until: i64,
}

/// The count of one known browser.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct KnownGuessCount {
    /// SHA-256 hex of the browser's device cookie nonce.
    #[schemars(regex(pattern = r"^[0-9a-f]{64}$"))]
    pub device: String,
    /// Its failures.
    #[serde(flatten)]
    pub count: GuessCount,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::upstream::{Issuer, Subject};

    /// The stored object around `spec`, as the API server returns it.
    fn stored(spec: &str) -> String {
        format!(
            r#"{{"apiVersion":"identity.zeabur.com/v1alpha1","kind":"Credential","metadata":{{"name":"c-7de39252447e608075f56f721487e3974c942e34378410bbe7ab9e5edf75c0fc"}},"spec":{spec}}}"#
        )
    }

    fn github_account() -> ExternalId {
        ExternalId {
            issuer: Issuer::new("https://github.com").unwrap(),
            subject: Subject::new("583231").unwrap(),
        }
    }

    #[test]
    fn a_linked_account_reads_back_to_the_same_typed_values() {
        let object = stored(
            r#"{"user":"alice","external":{"issuer":"https://github.com","subject":"583231"}}"#,
        );
        let credential: Credential = serde_json::from_str(&object).unwrap();
        assert_eq!(
            credential.spec.kind,
            CredentialKind::External(github_account())
        );
        assert_eq!(serde_json::to_string(&credential).unwrap(), object);
    }

    #[test]
    fn credentials_stored_by_earlier_versions_read_by_their_field() {
        let passkey = r#"{"credentialId":"AAEC","record":"{}","backupEligible":true}"#;
        let external = r#"{"issuer":"https://github.com","subject":"583231"}"#;
        let earlier = [
            format!(r#"{{"user":"alice","type":"Passkey","passkey":{passkey}}}"#),
            format!(r#"{{"user":"alice","type":"GitHub","external":{external}}}"#),
            format!(
                r#"{{"user":"alice","type":"Upstream","external":{external},"provider":"github"}}"#
            ),
        ];
        let [passkey, github, upstream] =
            earlier.map(|spec| serde_json::from_str::<Credential>(&stored(&spec)).unwrap());
        assert!(matches!(passkey.spec.kind, CredentialKind::Passkey(_)));
        assert_eq!(github.spec.kind, CredentialKind::External(github_account()));
        assert_eq!(upstream.spec, github.spec);
    }

    #[test]
    fn a_password_reads_back_and_never_prints_its_hash() {
        let object = stored(r#"{"user":"alice","password":{"hash":"$s$i=1$AA$BB"}}"#);
        let credential: Credential = serde_json::from_str(&object).unwrap();
        assert!(matches!(credential.spec.kind, CredentialKind::Password(_)));
        assert_eq!(serde_json::to_string(&credential).unwrap(), object);
        assert!(!format!("{credential:?}").contains("$s$i=1"));
    }

    #[test]
    fn a_credential_without_a_kind_is_refused() {
        let object = stored(r#"{"user":"alice","type":"Passkey"}"#);
        assert!(serde_json::from_str::<Credential>(&object).is_err());
    }

    #[test]
    fn a_stored_credential_with_a_malformed_subject_is_refused() {
        let object = stored(
            r#"{"user":"alice","external":{"issuer":"https://github.com","subject":"alice smith"}}"#,
        );
        assert!(serde_json::from_str::<Credential>(&object).is_err());
    }
}
