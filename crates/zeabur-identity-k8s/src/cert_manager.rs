//! The fields of cert-manager's `cert-manager.io/v1` `Issuer` and `Certificate` that Zeabur
//! Identity sets or reads ([API reference](https://cert-manager.io/docs/reference/api-docs/)).
//! cert-manager publishes no Rust crate, so these are small local views.

use std::collections::BTreeMap;

use kube::CustomResource;
use serde::{Deserialize, Serialize};

/// `Issuer.spec`: exactly one of the issuer kinds.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq)]
#[kube(
    group = "cert-manager.io",
    version = "v1",
    kind = "Issuer",
    namespaced,
    schema = "disabled"
)]
#[serde(rename_all = "camelCase")]
pub struct IssuerSpec {
    /// Issues self-signed certificates.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub self_signed: Option<SelfSignedIssuer>,
    /// Signs with the CA in a Secret.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ca: Option<CaIssuer>,
}

/// `Issuer.spec.selfSigned`; no fields are set.
#[expect(
    clippy::empty_structs_with_brackets,
    reason = "a unit struct serialises as null; cert-manager needs {}"
)]
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq)]
pub struct SelfSignedIssuer {}

/// `Issuer.spec.ca`.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CaIssuer {
    /// The Secret with the CA certificate and key.
    pub secret_name: String,
}

/// `Certificate.spec`.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq)]
#[kube(
    group = "cert-manager.io",
    version = "v1",
    kind = "Certificate",
    namespaced,
    status = "CertificateStatus",
    schema = "disabled"
)]
#[serde(rename_all = "camelCase")]
pub struct CertificateSpec {
    /// The Secret cert-manager writes the pair to.
    pub secret_name: String,
    /// Labels and annotations cert-manager copies to the Secret.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret_template: Option<SecretTemplate>,
    /// Whether the certificate is a CA.
    #[serde(rename = "isCA", skip_serializing_if = "Option::is_none")]
    pub is_ca: Option<bool>,
    /// The subject common name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub common_name: Option<String>,
    /// Validity, as a Go duration (`87600h`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration: Option<String>,
    /// IP address subject alternative names.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ip_addresses: Vec<String>,
    /// DNS subject alternative names.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dns_names: Vec<String>,
    /// Key usages, such as `server auth`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub usages: Vec<String>,
    /// The private key.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub private_key: Option<PrivateKey>,
    /// The Issuer that signs it.
    pub issuer_ref: IssuerRef,
}

/// `Certificate.spec.secretTemplate`.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq)]
pub struct SecretTemplate {
    /// Labels on the Secret.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub labels: BTreeMap<String, String>,
    /// Annotations on the Secret.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub annotations: BTreeMap<String, String>,
}

/// `Certificate.spec.privateKey`.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PrivateKey {
    /// `RSA`, `ECDSA` or `Ed25519`.
    pub algorithm: String,
    /// Key size in bits, or the curve size for ECDSA.
    pub size: u32,
    /// `Never` keeps the key on renewal; `Always` makes a new one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rotation_policy: Option<String>,
}

/// `Certificate.spec.issuerRef`.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq)]
pub struct IssuerRef {
    /// Name of the issuer.
    pub name: String,
    /// `Issuer` or `ClusterIssuer`.
    pub kind: String,
    /// API group of the issuer.
    pub group: String,
}

/// `Certificate.status`.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq)]
pub struct CertificateStatus {
    /// The conditions, of which Zeabur Identity reads `Ready`.
    #[serde(default)]
    pub conditions: Vec<CertificateCondition>,
}

/// One entry of `Certificate.status.conditions`.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CertificateCondition {
    /// `Ready` or `Issuing`.
    #[serde(rename = "type")]
    pub type_: String,
    /// `True`, `False` or `Unknown`.
    pub status: String,
    /// The `metadata.generation` the condition was set for.
    #[serde(default)]
    pub observed_generation: Option<i64>,
}

impl Certificate {
    /// Whether cert-manager reports the Certificate `Ready` for its current spec.
    #[must_use]
    pub fn is_ready(&self) -> bool {
        let generation = self.metadata.generation;
        self.status.iter().flat_map(|s| &s.conditions).any(|c| {
            c.type_ == "Ready" && c.status == "True" && c.observed_generation == generation
        })
    }
}
