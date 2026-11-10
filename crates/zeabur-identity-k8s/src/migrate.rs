//! Turns linked accounts from before `UpstreamProvider` into `Upstream` credentials.
//!
//! Before `UpstreamProvider`, a linked account was a `Credential` of type `GitHub` or `Google`.
//! Now it is of type `Upstream` and names its provider in `spec.provider`. The `Credential` spec
//! is immutable, except for this one step, which its CRD allows (`IMMUTABLE_RULE`):
//!
//! - `type: GitHub` becomes `type: Upstream` with `provider: github`.
//! - `type: Google` becomes `type: Upstream` with `provider: google`.
//!
//! The patch changes nothing else: the object name (from the issuer and subject), its UID, its
//! owner reference to the `User`, its labels and `spec.external` stay. An `UpstreamProvider`
//! named `github` or `google` with the old issuer then signs these accounts in, links and
//! unlinks them as before.
//!
//! The typed [`Credential`] has no `GitHub` or `Google` type, so this module reads the objects
//! with only the fields it needs.

use kube::api::{Api, ListParams, Patch, PatchParams};
use kube::core::{ApiResource, NotUsed, Object};
use kube::{Resource as _, ResourceExt as _};
use serde::{Deserialize, Serialize};
use zeabur_identity_api::credential::Credential;

use super::objects::list_all;

/// How many times one object is patched again after it changed underneath.
const MAX_ATTEMPTS: usize = 4;

/// The part of a `Credential` spec the migration reads.
#[derive(Deserialize, Serialize, Clone, Debug)]
struct TypeOnly {
    #[serde(rename = "type")]
    kind: String,
}

type Stored = Object<TypeOnly, NotUsed>;

#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
struct MigratePatch<'a> {
    metadata: Version<'a>,
    spec: MigrateSpec,
}

#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
struct Version<'a> {
    resource_version: &'a str,
}

#[derive(Serialize, Debug)]
struct MigrateSpec {
    #[serde(rename = "type")]
    kind: &'static str,
    provider: &'static str,
}

/// The provider ID a legacy type becomes, or `None` if the type is not a legacy one.
fn provider_for(kind: &str) -> Option<&'static str> {
    match kind {
        "GitHub" => Some("github"),
        "Google" => Some("google"),
        _ => None,
    }
}

/// Migrates every `GitHub` and `Google` credential in `namespace`. Returns how many it changed.
///
/// Each patch carries the `resourceVersion` it read, so it never overwrites a change made in
/// between; on a conflict it reads the object again.
///
/// # Errors
///
/// A failed list or patch, including a `422` when the installed `Credential` CRD is older than
/// this server and does not allow `type: Upstream`.
pub async fn linked_accounts(client: kube::Client, namespace: &str) -> Result<usize, kube::Error> {
    linked_accounts_at(client, namespace, &ApiResource::erase::<Credential>(&())).await
}

/// [`linked_accounts`] for `Credential` objects served as `resource`, such as a copy of the CRD
/// under another group that still accepts the old types, as the cluster tests use.
///
/// # Errors
///
/// As [`linked_accounts`].
pub async fn linked_accounts_at(
    client: kube::Client,
    namespace: &str,
    resource: &ApiResource,
) -> Result<usize, kube::Error> {
    let api: Api<Stored> = Api::namespaced_with(client, namespace, resource);
    let mut changed = 0;
    for object in list_all(&api, ListParams::default()).await? {
        if provider_for(&object.spec.kind).is_some() && migrate_one(&api, object).await? {
            changed += 1;
        }
    }
    Ok(changed)
}

async fn migrate_one(api: &Api<Stored>, mut object: Stored) -> Result<bool, kube::Error> {
    let name = object.name_any();
    for _ in 0..MAX_ATTEMPTS {
        let Some(provider) = provider_for(&object.spec.kind) else {
            return Ok(false);
        };
        let Some(version) = object.meta().resource_version.as_deref() else {
            return Ok(false);
        };
        let patch = MigratePatch {
            metadata: Version {
                resource_version: version,
            },
            spec: MigrateSpec {
                kind: "Upstream",
                provider,
            },
        };
        match api
            .patch(&name, &PatchParams::default(), &Patch::Merge(&patch))
            .await
        {
            Ok(_) => return Ok(true),
            Err(kube::Error::Api(status)) if status.code == 404 => return Ok(false),
            Err(kube::Error::Api(status)) if status.code == 409 => {
                match api.get_opt(&name).await? {
                    Some(fresh) => object = fresh,
                    None => return Ok(false),
                }
            }
            Err(error) => return Err(error),
        }
    }
    Err(kube::Error::Api(
        kube::core::Status::failure(
            &format!("credential {name} kept changing during migration"),
            "Conflict",
        )
        .with_code(409)
        .boxed(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_legacy_types_migrate() {
        assert_eq!(provider_for("GitHub"), Some("github"));
        assert_eq!(provider_for("Google"), Some("google"));
        assert_eq!(provider_for("Passkey"), None);
        assert_eq!(provider_for("Upstream"), None);
        assert_eq!(provider_for("github"), None);
    }

    #[test]
    fn patch_changes_only_type_and_provider_under_a_precondition() {
        let patch = MigratePatch {
            metadata: Version {
                resource_version: "7",
            },
            spec: MigrateSpec {
                kind: "Upstream",
                provider: "github",
            },
        };
        assert_eq!(
            serde_json::to_value(&patch).unwrap(),
            serde_json::json!({
                "metadata": {"resourceVersion": "7"},
                "spec": {"type": "Upstream", "provider": "github"},
            })
        );
    }
}
