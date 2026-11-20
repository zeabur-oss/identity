//! The certificate of the in-cluster discovery listener.
//!
//! kube-apiserver fetches discovery and keys over `https` only, and does not resolve cluster DNS
//! names. It reaches Zeabur Identity at its Service's ClusterIP with a certificate for that IP.
//! cert-manager issues and renews that certificate ([cert-manager Certificate]).
//! `zeabur-identityctl kube-config`, run with the cluster admin's credentials, applies [`objects`]
//! in Zeabur Identity's namespace:
//!
//! 1. A `SelfSigned` Issuer issues a root CA, valid for [`CA_DURATION`], into the Secret
//!    [`CA_SECRET`] ([cert-manager SelfSigned]).
//! 2. A `CA` Issuer signs with that root ([cert-manager CA]).
//! 3. A Certificate for the ClusterIP and the Service's DNS names goes into the `kubernetes.io/tls`
//!    Secret [`SECRET`], with cert-manager's default duration and renewal.
//!
//! kube-apiserver trusts the root CA (`issuer.certificateAuthority`), not the serving certificate.
//! A renewed serving certificate needs no change to kube-apiserver's configuration. The running
//! server reads [`SECRET`] again within a minute. The root CA keeps its key when cert-manager
//! renews it (`rotationPolicy: Never`), so the CA certificate that kube-apiserver holds stays valid
//! until it expires.
//!
//! The chain ends in a certificate with `CA:TRUE`, because Go's TLS stack requires it even for a
//! self-signed setup ([Authenticating]).
//!
//! The CA's private key is in [`CA_SECRET`]. Anyone who can read that Secret can issue a
//! certificate for the internal address. To impersonate Zeabur Identity, they must also answer at
//! the ClusterIP. Zeabur Identity's service account can only `get` [`SECRET`], not the CA.
//!
//! # References
//!
//! - [Authenticating] The Kubernetes Authors, "Authenticating: Using authentication configuration,"
//!   Kubernetes documentation.
//! - [cert-manager Certificate] The cert-manager Authors, "Certificate resource," cert-manager
//!   documentation.
//! - [cert-manager SelfSigned] The cert-manager Authors, "`SelfSigned`: Bootstrapping CA Issuers,"
//!   cert-manager documentation.
//! - [cert-manager CA] The cert-manager Authors, "CA," cert-manager documentation.
//!
//! [Authenticating]: https://kubernetes.io/docs/reference/access-authn-authz/authentication/
//! [cert-manager Certificate]: https://cert-manager.io/docs/usage/certificate/
//! [cert-manager SelfSigned]: https://cert-manager.io/docs/configuration/selfsigned/#bootstrapping-ca-issuers
//! [cert-manager CA]: https://cert-manager.io/docs/configuration/ca/

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::Arc;

use k8s_openapi::api::core::v1::Secret;
use kube::api::ObjectMeta;
use rustls::sign::CertifiedKey;
use thiserror::Error;
use zeabur_identity_core::config::{BaseUrl, ConfigError};
use zeabur_identity_tls::certificate::{CertificateError, certified_key};

use super::MANAGED_BY;
use crate::cert_manager::{
    CaIssuer, Certificate, CertificateSpec, Issuer, IssuerRef, IssuerSpec, PrivateKey,
    SecretTemplate, SelfSignedIssuer,
};

/// Name of the Certificate and the Secret holding the serving certificate.
pub const SECRET: &str = "zeabur-identity-internal-tls";
/// Name of the Certificate and the Secret holding the root CA and its private key.
pub const CA_SECRET: &str = "zeabur-identity-internal-ca";
/// Name of the `SelfSigned` Issuer that issues the root CA.
pub const ROOT_ISSUER: &str = "zeabur-identity-internal-root";
/// Name of the `CA` Issuer that signs the serving certificate.
pub const CA_ISSUER: &str = "zeabur-identity-internal-ca";
/// Validity of the root CA (10 years).
pub const CA_DURATION: &str = "87600h";
/// Annotation: the `https` base URL kube-apiserver uses to reach the internal listener.
pub const URL_ANNOTATION: &str = "identity.zeabur.com/internal-url";

const CERT_KEY: &str = "tls.crt";
const KEY_KEY: &str = "tls.key";

/// Why the certificate Secret could not be used.
#[derive(Debug, Error)]
pub enum TlsError {
    /// Loading the certificate failed.
    #[error(transparent)]
    Certificate(#[from] CertificateError),
    /// A required field is missing from the Secret.
    #[error("the Secret has no {0}")]
    Missing(&'static str),
    /// The URL annotation is not an `https` base URL.
    #[error(transparent)]
    Url(#[from] ConfigError),
}

/// The cert-manager objects that issue the root CA and the serving certificate.
#[derive(Debug, Clone)]
pub struct Objects {
    /// The `SelfSigned` Issuer of the root CA.
    pub root_issuer: Issuer,
    /// The root CA.
    pub ca: Certificate,
    /// The `CA` Issuer that signs with the root CA.
    pub ca_issuer: Issuer,
    /// The serving certificate.
    pub serving: Certificate,
}

/// The cert-manager objects that issue the root CA and the serving certificate for `ip` and
/// `dns_names`.
#[must_use]
pub fn objects(namespace: &str, ip: IpAddr, dns_names: &[String]) -> Objects {
    let labels = BTreeMap::from([(MANAGED_BY.0.to_owned(), MANAGED_BY.1.to_owned())]);
    let metadata = |name: &str| ObjectMeta {
        name: Some(name.to_owned()),
        namespace: Some(namespace.to_owned()),
        labels: Some(labels.clone()),
        ..ObjectMeta::default()
    };
    let issuer_ref = |name: &str| IssuerRef {
        name: name.to_owned(),
        kind: "Issuer".to_owned(),
        group: "cert-manager.io".to_owned(),
    };
    let ecdsa = |rotation_policy: Option<&str>| PrivateKey {
        algorithm: "ECDSA".to_owned(),
        size: 256,
        rotation_policy: rotation_policy.map(str::to_owned),
    };
    let annotations = internal_url(ip).map_or_else(
        |_never| BTreeMap::new(),
        |url| BTreeMap::from([(URL_ANNOTATION.to_owned(), url.as_str().to_owned())]),
    );
    Objects {
        root_issuer: Issuer {
            metadata: metadata(ROOT_ISSUER),
            spec: IssuerSpec {
                self_signed: Some(SelfSignedIssuer {}),
                ca: None,
            },
        },
        ca: Certificate {
            metadata: metadata(CA_SECRET),
            spec: CertificateSpec {
                is_ca: Some(true),
                common_name: Some("Zeabur Identity internal CA".to_owned()),
                secret_name: CA_SECRET.to_owned(),
                duration: Some(CA_DURATION.to_owned()),
                private_key: Some(ecdsa(Some("Never"))),
                issuer_ref: issuer_ref(ROOT_ISSUER),
                ..CertificateSpec::default()
            },
            status: None,
        },
        ca_issuer: Issuer {
            metadata: metadata(CA_ISSUER),
            spec: IssuerSpec {
                self_signed: None,
                ca: Some(CaIssuer {
                    secret_name: CA_SECRET.to_owned(),
                }),
            },
        },
        serving: Certificate {
            metadata: metadata(SECRET),
            spec: CertificateSpec {
                secret_name: SECRET.to_owned(),
                secret_template: Some(SecretTemplate {
                    labels: labels.clone(),
                    annotations,
                }),
                ip_addresses: vec![ip.to_string()],
                dns_names: dns_names.to_vec(),
                usages: vec!["server auth".to_owned(), "digital signature".to_owned()],
                private_key: Some(ecdsa(None)),
                issuer_ref: issuer_ref(CA_ISSUER),
                ..CertificateSpec::default()
            },
            status: None,
        },
    }
}

/// The `https` base URL for an address inside the cluster.
///
/// # Errors
///
/// Never for an IP address; the result type follows [`BaseUrl::parse`].
pub fn internal_url(ip: IpAddr) -> Result<BaseUrl, ConfigError> {
    match ip {
        IpAddr::V4(ip) => BaseUrl::parse("internal URL", &format!("https://{ip}")),
        IpAddr::V6(ip) => BaseUrl::parse("internal URL", &format!("https://[{ip}]")),
    }
}

/// What the internal listener needs from the Secret.
#[derive(Debug, Clone)]
pub struct Material {
    /// Certificate chain and key, ready for rustls.
    pub key: Arc<CertifiedKey>,
    /// Where kube-apiserver reaches the listener (the annotation), if recorded.
    pub url: Option<BaseUrl>,
}

/// The value of `key` in `secret`, or [`TlsError::Missing`].
///
/// # Errors
///
/// Returns [`TlsError::Missing`] if the Secret has no such key.
pub fn field<'a>(secret: &'a Secret, key: &'static str) -> Result<&'a [u8], TlsError> {
    secret
        .data
        .as_ref()
        .and_then(|data| data.get(key))
        .map(|bytes| bytes.0.as_slice())
        .ok_or(TlsError::Missing(key))
}

/// Reads a `kubernetes.io/tls` Secret.
///
/// # Errors
///
/// Returns [`TlsError`] if the certificate or key is missing or unusable, or the URL annotation
/// is not an `https` base URL.
pub fn parse(secret: &Secret) -> Result<Material, TlsError> {
    let key = certified_key(field(secret, CERT_KEY)?, field(secret, KEY_KEY)?)?;
    let url = secret
        .metadata
        .annotations
        .as_ref()
        .and_then(|a| a.get(URL_ANNOTATION))
        .map(|url| BaseUrl::parse("internal URL", url))
        .transpose()?;
    Ok(Material { key, url })
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use k8s_openapi::ByteString;
    use zeabur_identity_test_support::certificate::Ca;

    use super::*;

    /// A Secret as cert-manager writes it for `certificate`: the issued pair, plus the labels and
    /// annotations of `secretTemplate`.
    fn issued_secret(certificate: &Certificate, cert_pem: &str, key_pem: &str) -> Secret {
        let template = certificate.spec.secret_template.clone().unwrap();
        Secret {
            metadata: ObjectMeta {
                name: Some(certificate.spec.secret_name.clone()),
                labels: Some(template.labels),
                annotations: Some(template.annotations),
                ..ObjectMeta::default()
            },
            type_: Some("kubernetes.io/tls".to_owned()),
            data: Some(BTreeMap::from([
                (
                    "tls.crt".to_owned(),
                    ByteString(cert_pem.as_bytes().to_vec()),
                ),
                (
                    "tls.key".to_owned(),
                    ByteString(key_pem.as_bytes().to_vec()),
                ),
            ])),
            ..Secret::default()
        }
    }

    #[test]
    fn issued_secret_tells_the_listener_where_kube_apiserver_reaches_it() {
        let ip = IpAddr::V4(Ipv4Addr::new(10, 43, 0, 53));
        let serving = objects(
            "zeabur-identity",
            ip,
            &["zeabur-identity.zeabur-identity.svc".to_owned()],
        )
        .serving;
        assert_eq!(serving.spec.secret_name, SECRET);
        assert_eq!(serving.spec.ip_addresses, ["10.43.0.53"]);
        let issued = Ca::new().unwrap().issue(&["10.43.0.53"]).unwrap();

        let material = parse(&issued_secret(&serving, &issued.cert_pem, &issued.key_pem)).unwrap();
        assert_eq!(material.url, Some(internal_url(ip).unwrap()));
    }

    #[test]
    fn serving_certificate_chains_to_the_root_that_kube_apiserver_trusts() {
        let objects = objects("ns", IpAddr::V4(Ipv4Addr::LOCALHOST), &[]);
        assert_eq!(
            objects.serving.spec.issuer_ref.name,
            objects.ca_issuer.metadata.name.unwrap()
        );
        assert_eq!(
            objects.ca_issuer.spec.ca.unwrap().secret_name,
            objects.ca.spec.secret_name
        );
        assert_eq!(objects.ca.spec.is_ca, Some(true));
        // A new root key would invalidate the CA in kube-apiserver's configuration.
        assert_eq!(
            objects
                .ca
                .spec
                .private_key
                .unwrap()
                .rotation_policy
                .as_deref(),
            Some("Never")
        );
        assert_eq!(
            objects.ca.spec.issuer_ref.name,
            objects.root_issuer.metadata.name.unwrap()
        );
        assert!(objects.root_issuer.spec.self_signed.is_some());
    }

    #[test]
    fn objects_serialise_as_cert_manager_reads_them() {
        let objects = objects("ns", IpAddr::V4(Ipv4Addr::LOCALHOST), &[]);
        assert_eq!(
            serde_json::to_string(&objects.root_issuer).unwrap(),
            format!(
                r#"{{"apiVersion":"cert-manager.io/v1","kind":"Issuer","metadata":{{"labels":{{"app.kubernetes.io/managed-by":"zeabur-identity"}},"name":"{ROOT_ISSUER}","namespace":"ns"}},"spec":{{"selfSigned":{{}}}}}}"#
            )
        );
        let ca = serde_json::to_string(&objects.ca).unwrap();
        let expected = format!(
            r#""spec":{{"secretName":"{CA_SECRET}","isCA":true,"commonName":"Zeabur Identity internal CA","duration":"{CA_DURATION}","privateKey":{{"algorithm":"ECDSA","size":256,"rotationPolicy":"Never"}},"issuerRef":{{"name":"{ROOT_ISSUER}","kind":"Issuer","group":"cert-manager.io"}}}}"#
        );
        assert!(ca.ends_with(&format!("{expected}}}")), "{ca}");
        assert!(!ca.contains(r#""status""#));
    }

    #[test]
    fn ipv6_urls_use_brackets() {
        let url = internal_url("fd00::53".parse().unwrap()).unwrap();
        assert_eq!(url.as_str(), "https://[fd00::53]");
    }

    #[test]
    fn rejects_incomplete_secrets() {
        let mut secret = Secret::default();
        assert!(matches!(parse(&secret), Err(TlsError::Missing("tls.crt"))));
        secret.data = Some(BTreeMap::from([
            ("tls.crt".to_owned(), ByteString(b"not pem".to_vec())),
            ("tls.key".to_owned(), ByteString(b"not pem".to_vec())),
        ]));
        assert!(matches!(
            parse(&secret),
            Err(TlsError::Certificate(CertificateError::Pem(_)))
        ));
    }
}
