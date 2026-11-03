//! Zeabur Identity's Service and Deployment.
//!
//! One replica: authorization codes, PAR request URIs and ceremonies are single-use through
//! in-process state, and flows are sealed with a per-process key. The `Recreate` strategy keeps
//! two pods from serving at once during an update.
//!
//! `Recreate` does not promise "at most one pod" in every case (a pod deleted by hand is replaced
//! while it is still terminating). A brief second pod is still safe: anything sealed by one
//! process fails to open in the other, so nothing can be redeemed twice and at worst a sign-in is
//! retried, and long-lived state is written with compare-and-swap. A `StatefulSet` would give the
//! stronger guarantee, but a lost node would then block the pod until someone force-deletes it.
//! There is no leader election: an elector renewing a lease every few seconds would be the largest
//! source of writes in the system.
//!
//! The pod runs as a non-root user with a read-only root file system, no capabilities, no
//! privilege escalation and the runtime's default seccomp profile. The Service exposes the public
//! listener (`http`, behind the ingress, which terminates TLS) and the internal TLS listener that
//! kube-apiserver reaches at the Service's ClusterIP ([`crate::kube_config`]).

use std::collections::BTreeMap;

use k8s_openapi::api::apps::v1::{Deployment, DeploymentSpec, DeploymentStrategy};
use k8s_openapi::api::core::v1::{
    Capabilities, Container, ContainerPort, EnvVar, EnvVarSource, HTTPGetAction,
    ObjectFieldSelector, PodSecurityContext, PodSpec, PodTemplateSpec, Probe, ResourceRequirements,
    SeccompProfile, SecretVolumeSource, SecurityContext, Service, ServicePort, ServiceSpec, Volume,
    VolumeMount,
};
use k8s_openapi::apimachinery::pkg::api::resource::Quantity;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::LabelSelector;
use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;
use kube::api::ObjectMeta;
use serde_json::Value;
use zeabur_identity_core::config::BaseUrl;

use super::MANAGED_BY;
use super::rbac::NAME;

/// Port of the public HTTP listener (TLS is terminated in front of it).
pub const HTTP_PORT: i32 = 8080;
/// Port of the internal TLS listener kube-apiserver uses.
pub const INTERNAL_PORT: i32 = 8443;
/// Non-root user and group the container runs as.
pub const RUN_AS: i64 = 65532;

fn labels() -> BTreeMap<String, String> {
    BTreeMap::from([
        ("app.kubernetes.io/name".to_owned(), NAME.to_owned()),
        (MANAGED_BY.0.to_owned(), MANAGED_BY.1.to_owned()),
    ])
}

fn selector() -> BTreeMap<String, String> {
    BTreeMap::from([("app.kubernetes.io/name".to_owned(), NAME.to_owned())])
}

fn meta(namespace: &str) -> ObjectMeta {
    ObjectMeta {
        name: Some(NAME.to_owned()),
        namespace: Some(namespace.to_owned()),
        labels: Some(labels()),
        ..ObjectMeta::default()
    }
}

fn quantity(value: &str) -> Quantity {
    Quantity(value.to_owned())
}

/// The Service: `http` (80) for the ingress, `internal` (443) for kube-apiserver.
#[must_use]
pub fn service(namespace: &str) -> Service {
    let port = |name: &str, port, target| ServicePort {
        name: Some(name.to_owned()),
        port,
        target_port: Some(IntOrString::String(target)),
        protocol: Some("TCP".to_owned()),
        ..ServicePort::default()
    };
    Service {
        metadata: meta(namespace),
        spec: Some(ServiceSpec {
            type_: Some("ClusterIP".to_owned()),
            selector: Some(selector()),
            ports: Some(vec![
                port("http", 80, "http".to_owned()),
                port("internal", 443, "internal".to_owned()),
            ]),
            ..ServiceSpec::default()
        }),
        ..Service::default()
    }
}

/// What the Deployment runs.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Options {
    /// Container image.
    pub image: String,
    /// Arguments for `zeabur-identity`.
    pub serve_args: Vec<String>,
    /// Secret mounted read-only at [`CONFIG_DIR`].
    pub config_secret: Option<String>,
}

/// Where `config_secret` is mounted.
pub const CONFIG_DIR: &str = "/etc/zeabur-identity";

fn container(issuer: &BaseUrl, options: &Options) -> Container {
    let env = vec![
        EnvVar {
            name: "ZEABUR_IDENTITY_ISSUER".to_owned(),
            value: Some(issuer.as_str().to_owned()),
            ..EnvVar::default()
        },
        EnvVar {
            name: "ZEABUR_IDENTITY_NAMESPACE".to_owned(),
            value_from: Some(EnvVarSource {
                field_ref: Some(ObjectFieldSelector {
                    field_path: "metadata.namespace".to_owned(),
                    ..ObjectFieldSelector::default()
                }),
                ..EnvVarSource::default()
            }),
            ..EnvVar::default()
        },
    ];
    let probe = |path: &str| Probe {
        http_get: Some(HTTPGetAction {
            path: Some(path.to_owned()),
            port: IntOrString::String("http".to_owned()),
            ..HTTPGetAction::default()
        }),
        period_seconds: Some(10),
        ..Probe::default()
    };
    let port = |name: &str, port| ContainerPort {
        name: Some(name.to_owned()),
        container_port: port,
        protocol: Some("TCP".to_owned()),
        ..ContainerPort::default()
    };
    Container {
        name: NAME.to_owned(),
        image: Some(options.image.clone()),
        args: (!options.serve_args.is_empty()).then(|| options.serve_args.clone()),
        volume_mounts: options.config_secret.as_ref().map(|_| {
            vec![VolumeMount {
                name: "config".to_owned(),
                mount_path: CONFIG_DIR.to_owned(),
                read_only: Some(true),
                ..VolumeMount::default()
            }]
        }),
        env: Some(env),
        ports: Some(vec![
            port("http", HTTP_PORT),
            port("internal", INTERNAL_PORT),
        ]),
        // Startup probes suspend liveness/readiness until initialization succeeds. Allow two
        // minutes for the bounded metadata sync plus key preparation before normal probes start.
        // https://kubernetes.io/docs/tasks/configure-pod-container/configure-liveness-readiness-startup-probes/#define-startup-probes
        startup_probe: Some(Probe {
            failure_threshold: Some(12),
            ..probe("/healthz")
        }),
        readiness_probe: Some(probe("/readyz")),
        liveness_probe: Some(probe("/healthz")),
        resources: Some(ResourceRequirements {
            requests: Some(BTreeMap::from([
                ("cpu".to_owned(), quantity("10m")),
                ("memory".to_owned(), quantity("24Mi")),
            ])),
            limits: Some(BTreeMap::from([("memory".to_owned(), quantity("128Mi"))])),
            ..ResourceRequirements::default()
        }),
        security_context: Some(SecurityContext {
            allow_privilege_escalation: Some(false),
            read_only_root_filesystem: Some(true),
            run_as_non_root: Some(true),
            capabilities: Some(Capabilities {
                drop: Some(vec!["ALL".to_owned()]),
                ..Capabilities::default()
            }),
            ..SecurityContext::default()
        }),
        ..Container::default()
    }
}

/// The Deployment running `zeabur-identity` from `image`.
#[must_use]
pub fn deployment(namespace: &str, issuer: &BaseUrl, options: &Options) -> Deployment {
    Deployment {
        metadata: meta(namespace),
        spec: Some(DeploymentSpec {
            replicas: Some(1),
            strategy: Some(DeploymentStrategy {
                type_: Some("Recreate".to_owned()),
                ..DeploymentStrategy::default()
            }),
            selector: LabelSelector {
                match_labels: Some(selector()),
                ..LabelSelector::default()
            },
            template: PodTemplateSpec {
                metadata: Some(ObjectMeta {
                    labels: Some(labels()),
                    ..ObjectMeta::default()
                }),
                spec: Some(PodSpec {
                    service_account_name: Some(NAME.to_owned()),
                    containers: vec![container(issuer, options)],
                    volumes: options.config_secret.as_ref().map(|secret| {
                        vec![Volume {
                            name: "config".to_owned(),
                            secret: Some(SecretVolumeSource {
                                secret_name: Some(secret.clone()),
                                default_mode: Some(0o440),
                                ..SecretVolumeSource::default()
                            }),
                            ..Volume::default()
                        }]
                    }),
                    security_context: Some(PodSecurityContext {
                        run_as_user: Some(RUN_AS),
                        run_as_group: Some(RUN_AS),
                        // Secret volume files belong to root; without `fsGroup` the 0440 config
                        // files are unreadable to this group. The kubelet gives them this group.
                        fs_group: Some(RUN_AS),
                        run_as_non_root: Some(true),
                        seccomp_profile: Some(SeccompProfile {
                            type_: "RuntimeDefault".to_owned(),
                            ..SeccompProfile::default()
                        }),
                        ..PodSecurityContext::default()
                    }),
                    ..PodSpec::default()
                }),
            },
            ..DeploymentSpec::default()
        }),
        ..Deployment::default()
    }
}

/// Everything to install, in apply order: the RBAC objects ([`super::rbac::manifests`]), the
/// Service and the Deployment.
///
/// # Errors
///
/// Returns an error if serialization fails.
pub fn manifests(
    namespace: &str,
    issuer: &BaseUrl,
    options: &Options,
) -> serde_json::Result<Vec<Value>> {
    let mut items = super::rbac::manifests(namespace)?;
    items.push(serde_json::to_value(service(namespace))?);
    items.push(serde_json::to_value(deployment(
        namespace, issuer, options,
    ))?);
    Ok(items)
}

/// Renders [`manifests`] as a Kubernetes `List`.
///
/// # Errors
///
/// Returns an error if serialization fails.
pub fn manifests_json(
    namespace: &str,
    issuer: &BaseUrl,
    options: &Options,
) -> serde_json::Result<String> {
    serde_json::to_string_pretty(&serde_json::json!({
        "apiVersion": "v1",
        "kind": "List",
        "items": manifests(namespace, issuer, options)?,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deployment_is_locked_down() {
        let issuer = BaseUrl::parse("issuer", "https://login.example.com").unwrap();
        let options = Options {
            image: "zeabur-identity:test".into(),
            serve_args: vec!["--invitations".into()],
            config_secret: Some("zeabur-identity-config".into()),
        };
        let deployment = serde_json::to_value(deployment("ns", &issuer, &options)).unwrap();
        let spec = &deployment["spec"];
        assert_eq!(spec["replicas"], 1);
        assert_eq!(spec["strategy"]["type"], "Recreate");
        let pod = &spec["template"]["spec"];
        assert_eq!(pod["serviceAccountName"], NAME);
        assert_eq!(pod["securityContext"]["runAsNonRoot"], true);
        assert_eq!(
            pod["securityContext"]["seccompProfile"]["type"],
            "RuntimeDefault"
        );
        let container = &pod["containers"][0];
        assert_eq!(container["securityContext"]["readOnlyRootFilesystem"], true);
        assert_eq!(
            container["securityContext"]["allowPrivilegeEscalation"],
            false
        );
        assert_eq!(
            container["securityContext"]["capabilities"]["drop"][0],
            "ALL"
        );
        assert_eq!(container["env"][0]["value"], "https://login.example.com");
        assert_eq!(container["args"], serde_json::json!(["--invitations"]));
        assert_eq!(container["volumeMounts"][0]["mountPath"], CONFIG_DIR);
        assert_eq!(container["volumeMounts"][0]["readOnly"], true);
        assert_eq!(
            pod["volumes"][0]["secret"]["secretName"],
            "zeabur-identity-config"
        );
        // The 0440 config files must be readable by the container's group.
        assert_eq!(pod["volumes"][0]["secret"]["defaultMode"], 0o440);
        assert_eq!(pod["securityContext"]["fsGroup"], RUN_AS);
        assert_eq!(
            container["env"][1]["valueFrom"]["fieldRef"]["fieldPath"],
            "metadata.namespace"
        );
    }

    #[test]
    fn startup_cannot_restart_before_directory_sync_deadline() {
        let issuer = BaseUrl::parse("issuer", "https://login.example.com").unwrap();
        let container = container(&issuer, &Options::default());
        let startup = container.startup_probe.unwrap();
        // A kubelet may probe immediately. Even if every probe fails instantly, the last
        // allowed failure must occur after the initialization deadline, not at/before it.
        // Kubernetes defaults are included so omitting a field cannot silently weaken the guard.
        let failures = u64::try_from(startup.failure_threshold.unwrap_or(3)).unwrap();
        let period = u64::try_from(startup.period_seconds.unwrap_or(10)).unwrap();
        let delay = u64::try_from(startup.initial_delay_seconds.unwrap_or(0)).unwrap();
        let earliest_restart =
            std::time::Duration::from_secs(delay + failures.saturating_sub(1) * period);
        assert!(
            earliest_restart > crate::directory::INITIAL_SYNC_TIMEOUT,
            "startup may restart at {earliest_restart:?}, before metadata initialization finishes"
        );
    }

    #[test]
    fn service_exposes_both_listeners() {
        let service = serde_json::to_value(service("ns")).unwrap();
        let ports: Vec<_> = service["spec"]["ports"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| {
                (
                    p["name"].as_str(),
                    p["port"].as_u64(),
                    p["targetPort"].as_str(),
                )
            })
            .collect();
        assert_eq!(
            ports,
            [
                (Some("http"), Some(80), Some("http")),
                (Some("internal"), Some(443), Some("internal")),
            ]
        );
    }
}
