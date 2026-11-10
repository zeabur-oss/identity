//! `zeabur-identityctl kube-config`: the kube-apiserver side of the integration.
//!
//! Run by the cluster admin with their own kubeconfig. It finds Zeabur Identity's Service, has
//! cert-manager issue a certificate for the Service's ClusterIP ([`crate::internal_tls`]), and
//! prints the `AuthenticationConfiguration` for the chosen distribution together with how to
//! install it there. The configuration names the root CA, which stays the same when cert-manager
//! renews the serving certificate. The output therefore changes only if the ClusterIP or the root
//! CA changes.
//!
//! The file is a structured `AuthenticationConfiguration` (`apiserver.config.k8s.io/v1`, GA in
//! Kubernetes 1.34, [KEP-3331]). kube-apiserver re-reads it about once a minute, so only the
//! flag that names it needs a restart. It cannot be combined with `--oidc-*` flags.
//!
//! # Discovery from inside the cluster
//!
//! With [`DiscoveryMode::Internal`] (the default), the control plane does not depend on public
//! DNS, the ingress or a publicly trusted certificate. kube-apiserver redirects only the
//! discovery request to `discoveryURL`; the document it gets there must still name the public
//! issuer, and the JWK set is fetched from the document's `jwks_uri` ([oidc.go]). Zeabur Identity's
//! internal listener therefore serves a copy of the metadata that differs only in `jwks_uri`.
//! kube-apiserver resolves names with the host's resolver, so cluster DNS names do not resolve
//! ([DNS]); it uses the Service's ClusterIP, over `https` (required by [validation.go]), with
//! Zeabur Identity's own CA as `certificateAuthority` ([`crate::internal_tls`]). kube-apiserver
//! starts even while Zeabur Identity is down and retries discovery every 10 s; it fetches discovery
//! once, when the authenticator starts. A static JWK set is not an option: KEP-3331 lists other key
//! discovery methods as a non-goal. `egressSelectorType` is never set: K3s/RKE2 dial a host name
//! through it as a node name, so the authenticator would fail.
//!
//! # Rules kube-apiserver enforces
//!
//! - `has(claims.client_id)`: kube-apiserver does not look at the JWT `typ`, so this accepts access
//!   tokens, which carry `client_id` ([RFC 9068] §2.2), and rejects ID tokens, which are meant for
//!   the client.
//! - `exp - iat` is bounded, because kube-apiserver cannot revoke a token before it expires.
//! - Usernames and groups get the `zeabur:` prefix, which already rules out `system:`. Structured
//!   configuration has no built-in rejection of `system:`, so `userValidationRules` reject it as
//!   well, in case the mapping changes.
//! - `client_id`, `amr` and `jti` are mapped into `extra` under `identity.zeabur.com/`, so `kubectl
//!   auth whoami` and audit events tie a request to one token issuance.
//!
//! # Distributions
//!
//! | `--distro` | `anonymous` section | Internal discovery |
//! |---|---|---|
//! | `k3s` (K3s/RKE2) | `enabled: false` | With the agent on the server |
//! | `generic` | omitted | Depends on the cluster |
//!
//! - **K3s/RKE2** normally pass `--anonymous-auth=false` but drop it when they see an
//!   authentication configuration file, so the file restores it. Internal discovery needs
//!   kube-proxy on the server, which the K3s flag `--disable-agent` removes.
//! - **RKE2** runs kube-apiserver as a static pod. The directory, not the file, is mounted into the
//!   pod with `kube-apiserver-extra-mount`: a single-file bind mount would keep showing the old
//!   file after an atomic replace.
//!
//! Installation follows the documented mechanism of K3s and RKE2 ([K3s], [RKE2]); see
//! [`instructions`]. The RKE2 steps write the same files, flags and mount as the Zeabur installer,
//! which runs `zeabur-identityctl kube-config --distro k3s` on RKE2 (see "installer" below).
//!
//! # References
//!
//! - [KEP-3331] The Kubernetes Authors, "KEP-3331: Structured Authentication Configuration,"
//!   kubernetes/enhancements.
//! - [oidc.go] The Kubernetes Authors,
//!   `staging/src/k8s.io/apiserver/plugin/pkg/authenticator/token/oidc/oidc.go`.
//! - [validation.go] The Kubernetes Authors,
//!   `staging/src/k8s.io/apiserver/pkg/apis/apiserver/validation/validation.go`, v1.37.1.
//! - [DNS] The Kubernetes Authors, "DNS for Services and Pods," Kubernetes documentation.
//! - [RFC 9068] V. Bertocci, "JSON Web Token (JWT) Profile for OAuth 2.0 Access Tokens," RFC 9068,
//!   IETF, Oct. 2021.
//! - [K3s] K3s project, K3s documentation, `k3s server` command reference.
//! - [RKE2] RKE2 project, RKE2 documentation, server configuration reference.
//! - installer: Zeabur repository, `zeabur-installer-plan/src/rke2.rs` and
//!   `zeabur-installer/src/apply.rs`.
//!
//! [KEP-3331]: https://github.com/kubernetes/enhancements/tree/master/keps/sig-auth/3331-structured-authentication-configuration
//! [oidc.go]: https://github.com/kubernetes/kubernetes/blob/master/staging/src/k8s.io/apiserver/plugin/pkg/authenticator/token/oidc/oidc.go
//! [validation.go]: https://github.com/kubernetes/kubernetes/blob/v1.37.1/staging/src/k8s.io/apiserver/pkg/apis/apiserver/validation/validation.go
//! [DNS]: https://kubernetes.io/docs/concepts/services-networking/dns-pod-service/
//! [RFC 9068]: https://www.rfc-editor.org/rfc/rfc9068
//! [K3s]: https://docs.k3s.io/cli/server
//! [RKE2]: https://docs.rke2.io/reference/server_config

use std::net::IpAddr;
use std::time::Duration;

use clap::ValueEnum;
use k8s_openapi::api::core::v1::{Secret, Service};
use kube::Client;
use kube::api::{Api, ApiResource, DynamicObject, GroupVersionKind, Patch, PatchParams};
use serde_json::Value;
use thiserror::Error;
use zeabur_identity_api::IDENTITY_PREFIX;
use zeabur_identity_core::config::{BaseUrl, ConfigError};
use zeabur_identity_core::protocol::OPENID_CONFIGURATION_PATH;

use crate::internal_tls::{self, TlsError};
use crate::rbac::NAME;

/// Prefix of the `extra` keys Zeabur Identity maps into Kubernetes user info.
pub const EXTRA_PREFIX: &str = "identity.zeabur.com/";

/// Field manager of the cert-manager objects.
const FIELD_MANAGER: &str = "zeabur-identityctl";
/// How long to wait for cert-manager to issue the certificates.
const ISSUE_TIMEOUT: Duration = Duration::from_mins(2);

/// Where kube-apiserver runs; decides the `anonymous` section and the install instructions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Distro {
    /// K3s/RKE2.
    K3s,
    /// Any other distribution: the configuration file only.
    Generic,
}

/// How kube-apiserver reaches discovery and the JWK set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum DiscoveryMode {
    /// Through the Service's ClusterIP, with Zeabur Identity's own certificate (no dependency on
    /// public DNS, ingress or a public certificate).
    Internal,
    /// Through the public issuer URL, which the control-plane nodes must reach and trust.
    Public,
}

/// Internal discovery: where, and the CA that vouches for it.
#[derive(Debug, Clone)]
pub struct InternalDiscovery {
    /// Base URL of the internal listener (`https://<ClusterIP>`).
    pub url: BaseUrl,
    /// PEM of the CA kube-apiserver trusts for that URL.
    pub ca_pem: String,
}

/// Everything the generated `AuthenticationConfiguration` depends on.
#[derive(Debug, Clone)]
pub struct ApiserverOptions {
    /// The distribution.
    pub distro: Distro,
    /// The issuer identifier.
    pub issuer: BaseUrl,
    /// Internal discovery, or `None` for the public URL.
    pub internal: Option<InternalDiscovery>,
    /// Accepted token audiences.
    pub audiences: Vec<String>,
    /// Longest accepted token lifetime (`exp - iat`).
    pub max_token_lifetime: Duration,
}

/// Why `kube-config` failed.
#[derive(Debug, Error)]
pub enum KubeConfigError {
    /// The Kubernetes API failed.
    #[error("Kubernetes API request failed: {0}")]
    Kubernetes(#[from] kube::Error),
    /// Zeabur Identity's Service is missing or has no ClusterIP.
    #[error(
        "Service {namespace}/{name} has no ClusterIP; install Zeabur Identity first (`zeabur-identityctl manifests`)"
    )]
    NoService {
        /// Namespace searched.
        namespace: String,
        /// Service name.
        name: &'static str,
    },
    /// The ClusterIP is not an IP address.
    #[error("Service ClusterIP {0:?} is not an IP address")]
    BadClusterIp(String),
    /// Reading the certificate failed.
    #[error("internal certificate: {0}")]
    Tls(#[from] TlsError),
    /// cert-manager's resources do not exist in the cluster.
    #[error(
        "cert-manager is not installed: internal discovery needs it to issue Zeabur Identity's certificate; install cert-manager, or use --discovery public"
    )]
    NoCertManager,
    /// cert-manager did not issue a certificate in time.
    #[error(
        "cert-manager did not issue Certificate {namespace}/{name} within 2 minutes; see `kubectl -n {namespace} describe certificate {name}`"
    )]
    NotIssued {
        /// Namespace of the Certificate.
        namespace: String,
        /// Name of the Certificate.
        name: &'static str,
    },
    /// An option is invalid.
    #[error(transparent)]
    Config(#[from] ConfigError),
    /// An audience cannot be used.
    #[error("audience {0:?} must be non-empty printable ASCII without spaces")]
    BadAudience(String),
}

/// A YAML double-quoted scalar (JSON string syntax is valid YAML).
fn quoted(value: &str) -> String {
    Value::String(value.to_owned()).to_string()
}

/// The first line of the generated file.
const HEADER: &str = "# kube-apiserver AuthenticationConfiguration for Zeabur Identity, from `zeabur-identityctl kube-config`.";

/// Why an ID token is refused, as kube-apiserver reports it.
const ID_TOKEN_MESSAGE: &str = "    message: \"only Zeabur Identity access tokens are accepted (ID tokens carry no client_id)\"";

/// Renders the `AuthenticationConfiguration` (YAML).
///
/// # Errors
///
/// Returns [`KubeConfigError::BadAudience`] for an empty or unusual audience.
pub fn authentication_configuration(options: &ApiserverOptions) -> Result<String, KubeConfigError> {
    if let Some(bad) = options
        .audiences
        .iter()
        .find(|a| a.is_empty() || !a.bytes().all(|b| b.is_ascii_graphic()))
    {
        return Err(KubeConfigError::BadAudience(bad.clone()));
    }
    let mut out = String::new();
    let mut line = |text: &str| {
        out.push_str(text);
        out.push('\n');
    };
    line(HEADER);
    line("apiVersion: apiserver.config.k8s.io/v1");
    line("kind: AuthenticationConfiguration");
    match options.distro {
        // K3s/RKE2 drop their own --anonymous-auth=false when they see this file; restore it.
        Distro::K3s => {
            line("anonymous:");
            line("  enabled: false");
        }
        Distro::Generic => {}
    }
    line("jwt:");
    line("- issuer:");
    line(&format!("    url: {}", quoted(options.issuer.as_str())));
    if let Some(internal) = &options.internal {
        line(&format!(
            "    discoveryURL: {}",
            quoted(&internal.url.join(OPENID_CONFIGURATION_PATH))
        ));
        line("    certificateAuthority: |");
        for pem in internal.ca_pem.lines().filter(|l| !l.trim().is_empty()) {
            line(&format!("      {}", pem.trim_end()));
        }
    }
    line("    audiences:");
    for audience in &options.audiences {
        line(&format!("    - {}", quoted(audience)));
    }
    line("    audienceMatchPolicy: MatchAny");
    line("  claimValidationRules:");
    line("  - expression: \"has(claims.client_id)\"");
    line(ID_TOKEN_MESSAGE);
    let lifetime = options.max_token_lifetime.as_secs();
    line(&format!(
        "  - expression: \"claims.exp - claims.iat <= {lifetime}\""
    ));
    line(&format!(
        "    message: \"token lifetime must not exceed {lifetime} seconds\""
    ));
    line("  claimMappings:");
    line("    username:");
    line("      claim: preferred_username");
    line(&format!("      prefix: {}", quoted(IDENTITY_PREFIX)));
    line("    groups:");
    line("      claim: groups");
    line(&format!("      prefix: {}", quoted(IDENTITY_PREFIX)));
    line("    uid:");
    line("      claim: sub");
    line("    extra:");
    line(&format!(
        "    - key: {}",
        quoted(&format!("{EXTRA_PREFIX}client-id"))
    ));
    line("      valueExpression: \"claims.client_id\"");
    line(&format!(
        "    - key: {}",
        quoted(&format!("{EXTRA_PREFIX}amr"))
    ));
    line("      valueExpression: \"has(claims.amr) ? claims.amr : []\"");
    line(&format!(
        "    - key: {}",
        quoted(&format!("{EXTRA_PREFIX}jti"))
    ));
    line("      valueExpression: \"claims.jti\"");
    line("  userValidationRules:");
    line("  - expression: \"!user.username.startsWith('system:')\"");
    line("    message: \"the system: prefix is reserved\"");
    line("  - expression: \"user.groups.all(g, !g.startsWith('system:'))\"");
    line("    message: \"the system: prefix is reserved\"");
    Ok(out)
}

/// How to install the file on `distro`, for the cluster admin (plain text).
#[must_use]
pub fn instructions(distro: Distro, discovery: DiscoveryMode) -> String {
    let (path, steps): (&str, &[&str]) = match distro {
        Distro::K3s => (
            "/etc/rancher/k3s/zeabur-identity/authn.yaml on K3s, /etc/rancher/rke2/zeabur-identity/authn.yaml on RKE2",
            &[
                "On every server node, save the configuration above as authn.yaml in /etc/rancher/k3s/zeabur-identity/ (K3s) or /etc/rancher/rke2/zeabur-identity/ (RKE2).",
                "On K3s, add /etc/rancher/k3s/config.yaml.d/50-zeabur-identity.yaml containing:",
                "    kube-apiserver-arg:",
                "      - \"authentication-config=/etc/rancher/k3s/zeabur-identity/authn.yaml\"",
                "On RKE2, add /etc/rancher/rke2/config.yaml.d/50-zeabur-identity.yaml containing:",
                "    kube-apiserver-arg:",
                "      - \"authentication-config=/etc/rancher/rke2/zeabur-identity/authn.yaml\"",
                "    kube-apiserver-extra-mount:",
                "      - \"/etc/rancher/rke2/zeabur-identity:/etc/rancher/rke2/zeabur-identity:ro\"",
                "Run `systemctl restart k3s` (K3s) or `systemctl restart rke2-server` (RKE2) once. kube-apiserver reloads later changes to authn.yaml within about a minute.",
                "On K3s, internal discovery needs the node's embedded agent (it does not work with --disable-agent).",
            ],
        ),
        Distro::Generic => (
            "authn.yaml",
            &[
                "Save the configuration above where kube-apiserver can read it and start kube-apiserver with --authentication-config=<path>.",
                "Remove any --oidc-* flags; they cannot be combined with --authentication-config.",
                "Check how your distribution handles --anonymous-auth: the file may need an `anonymous` section.",
            ],
        ),
    };
    let mut lines = vec![format!("Install ({path}):")];
    lines.extend(steps.iter().map(|step| format!("  {step}")));
    if discovery == DiscoveryMode::Public {
        lines.push(
            "  Public discovery: every control-plane node must resolve the issuer and trust its certificate."
                .to_owned(),
        );
    }
    lines.push(format!(
        "Check: `kubectl --token=<access token> auth whoami` shows a user named {IDENTITY_PREFIX}<username>."
    ));
    lines.join("\n")
}

/// Inputs of [`prepare`].
#[derive(Debug, Clone)]
pub struct Request {
    /// Zeabur Identity's namespace.
    pub namespace: String,
    /// What to generate.
    pub distro: Distro,
    /// The issuer identifier.
    pub issuer: BaseUrl,
    /// How kube-apiserver reaches discovery.
    pub discovery: DiscoveryMode,
    /// Accepted audiences.
    pub audiences: Vec<String>,
    /// Longest accepted token lifetime.
    pub max_token_lifetime: Duration,
}

/// Prepares the cluster for internal discovery (if chosen) and renders the
/// `AuthenticationConfiguration` (YAML).
///
/// # Errors
///
/// Returns [`KubeConfigError`] if Zeabur Identity's Service is missing, cert-manager is missing
/// or does not issue the certificates, an audience is invalid, or the API refuses a request.
pub async fn prepare(client: Client, request: &Request) -> Result<String, KubeConfigError> {
    let internal = match request.discovery {
        DiscoveryMode::Public => None,
        DiscoveryMode::Internal => Some(ensure_certificate(client, &request.namespace).await?),
    };
    authentication_configuration(&ApiserverOptions {
        distro: request.distro,
        issuer: request.issuer.clone(),
        internal,
        audiences: request.audiences.clone(),
        max_token_lifetime: request.max_token_lifetime,
    })
}

async fn ensure_certificate(
    client: Client,
    namespace: &str,
) -> Result<InternalDiscovery, KubeConfigError> {
    let services: Api<Service> = Api::namespaced(client.clone(), namespace);
    let no_service = || KubeConfigError::NoService {
        namespace: namespace.to_owned(),
        name: NAME,
    };
    let cluster_ip = services
        .get_opt(NAME)
        .await?
        .and_then(|s| s.spec)
        .and_then(|spec| spec.cluster_ip)
        .filter(|ip| !ip.is_empty() && ip != "None")
        .ok_or_else(no_service)?;
    let ip: IpAddr = cluster_ip
        .parse()
        .map_err(|_parse| KubeConfigError::BadClusterIp(cluster_ip.clone()))?;
    let url = internal_tls::internal_url(ip)?;

    let secrets: Api<Secret> = Api::namespaced(client.clone(), namespace);
    let dns_names = [
        format!("{NAME}.{namespace}.svc"),
        format!("{NAME}.{namespace}.svc.cluster.local"),
    ];
    let params = PatchParams::apply(FIELD_MANAGER).force();
    for object in internal_tls::objects(namespace, ip, &dns_names) {
        let text = |pointer: &str| object.pointer(pointer).and_then(Value::as_str);
        let (Some(kind), Some(name)) = (text("/kind"), text("/metadata/name")) else {
            continue;
        };
        let resource = ApiResource::from_gvk_with_plural(
            &GroupVersionKind::gvk("cert-manager.io", "v1", kind),
            &format!("{}s", kind.to_ascii_lowercase()),
        );
        let api: Api<DynamicObject> = Api::namespaced_with(client.clone(), namespace, &resource);
        match api.patch(name, &params, &Patch::Apply(&object)).await {
            Ok(_) => {}
            Err(kube::Error::Api(status)) if status.code == 404 => {
                return Err(KubeConfigError::NoCertManager);
            }
            Err(error) => return Err(error.into()),
        }
    }

    let certificates: Api<DynamicObject> = Api::namespaced_with(
        client,
        namespace,
        &ApiResource::from_gvk_with_plural(
            &GroupVersionKind::gvk("cert-manager.io", "v1", "Certificate"),
            "certificates",
        ),
    );
    for name in [internal_tls::CA_SECRET, internal_tls::SECRET] {
        wait_until_ready(&certificates, namespace, name).await?;
    }
    let ca = secrets.get(internal_tls::CA_SECRET).await?;
    let ca_pem = String::from_utf8(internal_tls::field(&ca, "tls.crt")?.to_vec())
        .map_err(|_utf8| TlsError::Missing("tls.crt"))?;
    Ok(InternalDiscovery { url, ca_pem })
}

/// Whether cert-manager reports the Certificate `Ready` for its current spec.
fn ready(certificate: &DynamicObject) -> bool {
    let generation = certificate.metadata.generation;
    certificate
        .data
        .pointer("/status/conditions")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .any(|condition| {
            condition.get("type").and_then(Value::as_str) == Some("Ready")
                && condition.get("status").and_then(Value::as_str) == Some("True")
                && condition.get("observedGeneration").and_then(Value::as_i64) == generation
        })
}

async fn wait_until_ready(
    certificates: &Api<DynamicObject>,
    namespace: &str,
    name: &'static str,
) -> Result<(), KubeConfigError> {
    let deadline = tokio::time::Instant::now() + ISSUE_TIMEOUT;
    loop {
        if certificates
            .get_opt(name)
            .await?
            .as_ref()
            .is_some_and(ready)
        {
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(KubeConfigError::NotIssued {
                namespace: namespace.to_owned(),
                name,
            });
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn options(distro: Distro, internal: bool) -> ApiserverOptions {
        ApiserverOptions {
            distro,
            issuer: BaseUrl::parse("issuer", "https://login.example.com").unwrap(),
            internal: internal.then(|| InternalDiscovery {
                url: BaseUrl::parse("internal", "https://10.43.0.53").unwrap(),
                ca_pem: "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n".into(),
            }),
            audiences: vec!["kubernetes".into()],
            max_token_lifetime: Duration::from_hours(1),
        }
    }

    #[test]
    fn k3s_internal_configuration() {
        let yaml = authentication_configuration(&options(Distro::K3s, true)).unwrap();
        let expected = r#"# kube-apiserver AuthenticationConfiguration for Zeabur Identity, from `zeabur-identityctl kube-config`.
apiVersion: apiserver.config.k8s.io/v1
kind: AuthenticationConfiguration
anonymous:
  enabled: false
jwt:
- issuer:
    url: "https://login.example.com"
    discoveryURL: "https://10.43.0.53/.well-known/openid-configuration"
    certificateAuthority: |
      -----BEGIN CERTIFICATE-----
      AAAA
      -----END CERTIFICATE-----
    audiences:
    - "kubernetes"
    audienceMatchPolicy: MatchAny
  claimValidationRules:
  - expression: "has(claims.client_id)"
    message: "only Zeabur Identity access tokens are accepted (ID tokens carry no client_id)"
  - expression: "claims.exp - claims.iat <= 3600"
    message: "token lifetime must not exceed 3600 seconds"
  claimMappings:
    username:
      claim: preferred_username
      prefix: "zeabur:"
    groups:
      claim: groups
      prefix: "zeabur:"
    uid:
      claim: sub
    extra:
    - key: "identity.zeabur.com/client-id"
      valueExpression: "claims.client_id"
    - key: "identity.zeabur.com/amr"
      valueExpression: "has(claims.amr) ? claims.amr : []"
    - key: "identity.zeabur.com/jti"
      valueExpression: "claims.jti"
  userValidationRules:
  - expression: "!user.username.startsWith('system:')"
    message: "the system: prefix is reserved"
  - expression: "user.groups.all(g, !g.startsWith('system:'))"
    message: "the system: prefix is reserved"
"#;
        assert_eq!(yaml, expected);
    }

    #[test]
    fn generic_configuration_has_no_anonymous_section() {
        let yaml = authentication_configuration(&options(Distro::Generic, true)).unwrap();
        assert!(!yaml.contains("anonymous"));
    }

    #[test]
    fn public_discovery_has_no_discovery_url_or_ca() {
        let yaml = authentication_configuration(&options(Distro::K3s, false)).unwrap();
        assert!(!yaml.contains("discoveryURL") && !yaml.contains("certificateAuthority"));
    }

    #[test]
    fn audiences_are_validated() {
        for bad in ["", "two words", "tab\t"] {
            let mut o = options(Distro::K3s, false);
            o.audiences = vec![bad.into()];
            assert!(matches!(
                authentication_configuration(&o),
                Err(KubeConfigError::BadAudience(_))
            ));
        }
    }

    #[test]
    fn instructions_name_the_file_and_the_restart() {
        let k3s = instructions(Distro::K3s, DiscoveryMode::Internal);
        for expected in [
            "authentication-config=/etc/rancher/k3s/zeabur-identity/authn.yaml",
            "systemctl restart k3s",
            "authentication-config=/etc/rancher/rke2/zeabur-identity/authn.yaml",
            "/etc/rancher/rke2/zeabur-identity:/etc/rancher/rke2/zeabur-identity:ro",
            "systemctl restart rke2-server",
        ] {
            assert!(k3s.contains(expected), "{expected}");
        }
        let generic = instructions(Distro::Generic, DiscoveryMode::Public);
        assert!(
            generic.contains("--authentication-config") && generic.contains("Public discovery")
        );
    }
}
