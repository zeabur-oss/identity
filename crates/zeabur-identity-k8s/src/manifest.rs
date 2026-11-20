//! The objects of an installation, as typed Kubernetes objects.

use k8s_openapi::api::apps::v1::Deployment;
use k8s_openapi::api::core::v1::{Namespace, Secret, Service, ServiceAccount};
use k8s_openapi::api::rbac::v1::{ClusterRoleBinding, Role, RoleBinding};
use serde::{Deserialize, Serialize};

/// One object of an installation. Each variant serialises with its own `apiVersion` and `kind`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Manifest {
    /// The namespace.
    Namespace(Box<Namespace>),
    /// The service account Zeabur Identity runs as.
    ServiceAccount(Box<ServiceAccount>),
    /// The Role of that service account.
    Role(Box<Role>),
    /// The binding of that Role.
    RoleBinding(Box<RoleBinding>),
    /// The binding of the cluster admin group.
    ClusterRoleBinding(Box<ClusterRoleBinding>),
    /// A Secret that the installer creates empty.
    Secret(Box<Secret>),
    /// The Service in front of the Deployment.
    Service(Box<Service>),
    /// The Deployment.
    Deployment(Box<Deployment>),
}

/// A Kubernetes `List` of [`Manifest`]s.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ManifestList {
    /// Always `v1`.
    pub api_version: String,
    /// Always `List`.
    pub kind: String,
    /// The objects, in apply order.
    pub items: Vec<Manifest>,
}

impl ManifestList {
    /// Wraps `items` as a `v1` `List`.
    #[must_use]
    pub fn new(items: Vec<Manifest>) -> Self {
        Self {
            api_version: "v1".to_owned(),
            kind: "List".to_owned(),
            items,
        }
    }
}
