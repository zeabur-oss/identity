//! The namespace-scoped objects Zeabur Identity needs: its namespace, service account,
//! least-privilege Role, and the empty signing-key Secret.
//!
//! Generated from code so the deployment manifest and the integration tests use the same rules;
//! the tests act as the service account through impersonation and show that it cannot list
//! Secrets, read or create other Secrets, bind `cluster-admin`, create `User`s, or read grants in
//! another namespace.
//!
//! - **Secrets by name only.** `get`/`update` on the signing keys, `get`/`delete` on the setup
//!   token (redeeming is deleting), `get` on the internal certificate and on the upstream client
//!   secrets ([`upstream_provider::SECRET`]). RBAC cannot limit `create` or `deletecollection` to a
//!   name, and `list` or `watch` on Secrets reveals their contents ([RBAC], [RBAC good practices]),
//!   so Zeabur Identity has none of these on Secrets: the installer creates the empty key Secret
//!   and the cluster admin's `zeabur-identityctl` writes the other two.
//! - **Configuration is read-only.** Users, credentials, clients and upstream providers are written
//!   by admins or GitOps; Zeabur Identity reads them and creates or deletes credentials when a
//!   passkey is enrolled, removed or an account is linked. On credentials it writes `status` (the
//!   label a user gives a passkey, and when it was last used). It has no write access to users or
//!   upstream providers.
//! - **Account settings.** It reads one `ConfigMap`, [`SETTINGS_CONFIG_MAP`], by name. Admins write
//!   it.
//! - **Account events.** It creates core `Event`s about users who change their own passkeys or
//!   sessions or redeem a setup link or invitation, and cannot read, change or delete events.
//! - **Runtime state is Zeabur Identity's.** Full access to grants; invitations it can read and
//!   redeem (`delete`), but not create.
//! - **Nothing else.** No cluster-scoped rights, nothing in other namespaces, no RBAC objects, no
//!   `impersonate`. The admin binding ([`ADMINS_BINDING`]) is applied at install with the cluster
//!   admin's rights; Zeabur Identity cannot change them.
//!
//! # References
//!
//! - [RBAC] The Kubernetes Authors, "Using RBAC Authorization: Referring to resources," Kubernetes
//!   documentation.
//! - [RBAC good practices] The Kubernetes Authors, "Role Based Access Control Good Practices,"
//!   Kubernetes documentation.
//!
//! [RBAC]: https://kubernetes.io/docs/reference/access-authn-authz/rbac/
//! [RBAC good practices]: https://kubernetes.io/docs/concepts/security/rbac-good-practices/

use std::collections::BTreeMap;

use k8s_openapi::api::core::v1::{Namespace, Secret, ServiceAccount};
use k8s_openapi::api::rbac::v1::{
    ClusterRoleBinding, PolicyRule, Role, RoleBinding, RoleRef, Subject,
};
use kube::api::ObjectMeta;
use serde_json::Value;
use zeabur_identity_api::{ADMIN_GROUP, GROUP, IDENTITY_PREFIX, upstream_provider};
use zeabur_identity_core::account::SETTINGS_CONFIG_MAP;

use super::keys::SECRET_TYPE;
use super::setup::SETUP_SECRET;
use super::{KEY_SECRET, MANAGED_BY, internal_tls};

/// Name of the service account, `Role` and `RoleBinding`.
pub const NAME: &str = "zeabur-identity";

/// Name of the `ClusterRoleBinding` that binds `zeabur:admins` (the admin accounts) to
/// `cluster-admin`.
pub const ADMINS_BINDING: &str = "zeabur-identity-cluster-admins";

/// Default namespace.
pub const DEFAULT_NAMESPACE: &str = "zeabur-identity";

fn rule(groups: &[&str], resources: &[&str], names: &[&str], verbs: &[&str]) -> PolicyRule {
    let strings = |items: &[&str]| items.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
    PolicyRule {
        api_groups: Some(strings(groups)),
        resources: Some(strings(resources)),
        resource_names: (!names.is_empty()).then(|| strings(names)),
        verbs: strings(verbs),
        ..PolicyRule::default()
    }
}

/// The rules of Zeabur Identity's Role. There is no `list`, `watch` or `create` on Secrets, and
/// nothing outside the namespace.
#[must_use]
pub fn rules() -> Vec<PolicyRule> {
    vec![
        // Signing keys: read and compare-and-swap one Secret.
        rule(&[""], &["secrets"], &[KEY_SECRET], &["get", "update"]),
        // Setup token: read and consume (delete) one Secret; only the cluster admin creates it.
        rule(&[""], &["secrets"], &[SETUP_SECRET], &["get", "delete"]),
        // Internal listener certificate: read one Secret; the cluster admin writes it.
        rule(&[""], &["secrets"], &[internal_tls::SECRET], &["get"]),
        // Upstream client secrets: read one Secret at each use; the cluster admin writes it.
        rule(&[""], &["secrets"], &[upstream_provider::SECRET], &["get"]),
        // Configuration and identities, written by admins or GitOps.
        rule(
            &[GROUP],
            &["users", "credentials", "oauthclients", "upstreamproviders"],
            &[],
            &["get", "list", "watch"],
        ),
        // Runtime state Zeabur Identity owns.
        rule(&[GROUP], &["credentials"], &[], &["create", "delete"]),
        rule(&[GROUP], &["credentials/status"], &[], &["update", "patch"]),
        rule(
            &[GROUP],
            &["grants"],
            &[],
            &[
                "get",
                "list",
                "watch",
                "create",
                "update",
                "delete",
                "deletecollection",
            ],
        ),
        rule(&[GROUP], &["grants/status"], &[], &["update"]),
        // Invitations: the admin creates them; Zeabur Identity redeems (deletes) and collects
        // expired ones.
        rule(
            &[GROUP],
            &["invitations"],
            &[],
            &["get", "list", "watch", "delete"],
        ),
        // Account settings, written by admins.
        rule(&[""], &["configmaps"], &[SETTINGS_CONFIG_MAP], &["get"]),
        // Account changes users make themselves and redeemed links, as events on the User.
        rule(&[""], &["events"], &[], &["create"]),
    ]
}

/// Binds the `ClusterRole` `role` to the Kubernetes group `zeabur:<group>`.
fn group_binding(name: &str, role: &str, group: &str) -> ClusterRoleBinding {
    ClusterRoleBinding {
        metadata: meta(name, None),
        role_ref: RoleRef {
            api_group: "rbac.authorization.k8s.io".to_owned(),
            kind: "ClusterRole".to_owned(),
            name: role.to_owned(),
        },
        subjects: Some(vec![Subject {
            api_group: Some("rbac.authorization.k8s.io".to_owned()),
            kind: "Group".to_owned(),
            name: format!("{IDENTITY_PREFIX}{group}"),
            ..Subject::default()
        }]),
    }
}

fn meta(name: &str, namespace: Option<&str>) -> ObjectMeta {
    ObjectMeta {
        name: Some(name.to_owned()),
        namespace: namespace.map(str::to_owned),
        labels: Some(BTreeMap::from([(
            MANAGED_BY.0.to_owned(),
            MANAGED_BY.1.to_owned(),
        )])),
        ..ObjectMeta::default()
    }
}

/// The objects to install in `namespace`, in apply order.
///
/// # Errors
///
/// Returns an error if serialization fails.
pub fn manifests(namespace: &str) -> serde_json::Result<Vec<Value>> {
    let ns = Some(namespace);
    Ok(vec![
        serde_json::to_value(Namespace {
            metadata: meta(namespace, None),
            ..Namespace::default()
        })?,
        serde_json::to_value(ServiceAccount {
            metadata: meta(NAME, ns),
            automount_service_account_token: Some(true),
            ..ServiceAccount::default()
        })?,
        serde_json::to_value(Role {
            metadata: meta(NAME, ns),
            rules: Some(rules()),
        })?,
        serde_json::to_value(RoleBinding {
            metadata: meta(NAME, ns),
            role_ref: RoleRef {
                api_group: "rbac.authorization.k8s.io".to_owned(),
                kind: "Role".to_owned(),
                name: NAME.to_owned(),
            },
            subjects: Some(vec![Subject {
                kind: "ServiceAccount".to_owned(),
                name: NAME.to_owned(),
                namespace: Some(namespace.to_owned()),
                ..Subject::default()
            }]),
        })?,
        // Only admin accounts carry `zeabur:admins`, and they sign in with a passkey only. Applied
        // by the installer with the cluster admin's own rights; Zeabur Identity's service account
        // cannot create bindings.
        serde_json::to_value(group_binding(ADMINS_BINDING, "cluster-admin", ADMIN_GROUP))?,
        // Created empty by the installer; Zeabur Identity fills it.
        serde_json::to_value(Secret {
            metadata: meta(KEY_SECRET, ns),
            type_: Some(SECRET_TYPE.to_owned()),
            ..Secret::default()
        })?,
    ])
}

/// Renders [`manifests`] as a Kubernetes `List` without a trailing newline.
///
/// # Errors
///
/// Returns an error if serialization fails.
pub fn manifests_json(namespace: &str) -> serde_json::Result<String> {
    serde_json::to_string_pretty(&serde_json::json!({
        "apiVersion": "v1",
        "kind": "List",
        "items": manifests(namespace)?,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regenerate with `cargo run -q -- rbac > deploy/rbac.json`.
    #[test]
    fn committed_manifest_is_current() {
        let committed = include_str!("../../../deploy/rbac.json");
        // Compare parsed JSON: test builds may enable serde_json features (such as
        // `preserve_order`, through dev-dependencies) that change key order but not
        // content.
        let parse = |s: &str| serde_json::from_str::<Value>(s).unwrap();
        assert!(
            committed.ends_with('\n')
                && parse(committed) == parse(&manifests_json(DEFAULT_NAMESPACE).unwrap()),
            "deploy/rbac.json is stale: run `cargo run -q -- rbac > deploy/rbac.json`"
        );
    }

    #[test]
    fn secrets_are_reachable_only_by_name() {
        for rule in rules() {
            if rule
                .resources
                .as_deref()
                .is_some_and(|r| r.iter().any(|r| r == "secrets"))
            {
                let names = rule.resource_names.clone().unwrap_or_default();
                assert!(
                    names == [KEY_SECRET]
                        || names == [SETUP_SECRET]
                        || names == [internal_tls::SECRET]
                        || names == [upstream_provider::SECRET],
                    "{names:?}"
                );
                assert!(
                    rule.verbs
                        .iter()
                        .all(|v| ["get", "update", "delete"].contains(&v.as_str())),
                    "{:?}",
                    rule.verbs
                );
            }
        }
    }

    #[test]
    fn no_privilege_escalation_verbs() {
        for rule in rules() {
            for verb in &rule.verbs {
                assert!(!["*", "bind", "escalate", "impersonate"].contains(&verb.as_str()));
            }
            assert!(
                rule.api_groups
                    .iter()
                    .flatten()
                    .all(|g| g != "rbac.authorization.k8s.io")
            );
        }
    }
}
