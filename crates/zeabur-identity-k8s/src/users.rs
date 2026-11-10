//! Account types, and owner references from a `User`'s dependents (credentials, grants,
//! invitations) to the `User`.

use k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference;
use kube::Resource;
use kube::api::{Api, ObjectMeta, Patch, PatchParams};
use zeabur_identity_api::user::{AccountType, User};
use zeabur_identity_store::StoreError;

fn backend(error: &kube::Error) -> StoreError {
    StoreError(error.to_string())
}

/// An `ownerReference` to the current `User` named `name`, so that Kubernetes' garbage
/// collector deletes the dependent with that User ([Owners and Dependents]).
///
/// The reference carries the User's UID: a same-named User created later does not adopt the
/// dependent, and one deleted before the dependent is created leaves it to the collector.
/// It is not a controller reference and does not set `blockOwnerDeletion`, which would need
/// `delete` on Users. Collection is eventual and skipped by orphan deletion, so it is cleanup,
/// not revocation. Reads that sign someone in or enrol a passkey compare the owner's UID with the
/// `User` (see [`user_owner_uid`]).
///
/// Like `Resource::owner_ref`, returns `None` for a User without a UID; API-server responses
/// always have one. Requires a namespaced API to keep owner and dependent in the same namespace.
///
/// [Owners and Dependents]: https://kubernetes.io/docs/concepts/overview/working-with-objects/owners-dependents/
pub(crate) async fn user_owner<K>(
    api: &Api<K>,
    name: &str,
) -> Result<Option<OwnerReference>, StoreError>
where
    K: Resource + Clone,
{
    let namespace = api
        .namespace()
        .ok_or_else(|| StoreError("User dependents require a namespaced API".to_owned()))?;
    let users: Api<User> = Api::namespaced(api.clone().into_client(), namespace);
    let user = users.get(name).await.map_err(|error| backend(&error))?;
    Ok(user.owner_ref(&()))
}

/// Whether `meta` names a `User` owner other than the one with UID `subject`. A dependent with
/// no `User` owner (created while the User was missing) is not excluded.
pub(crate) fn owned_by_another(meta: &ObjectMeta, subject: &str) -> bool {
    meta.owner_references
        .iter()
        .flatten()
        .any(|owner| owner.kind == "User" && owner.uid != subject)
}

/// The UID of the one `User` that owns `meta`. `None` if no `User` owns it, or if two `User`
/// owners have different UIDs.
pub(crate) fn user_owner_uid(meta: &ObjectMeta) -> Option<&str> {
    let mut uids = meta
        .owner_references
        .iter()
        .flatten()
        .filter(|owner| owner.kind == "User")
        .map(|owner| owner.uid.as_str());
    let first = uids.next()?;
    uids.all(|uid| uid == first).then_some(first)
}

/// Sets the account type of the `User` named `name`, with the caller's credentials.
///
/// This is the same as
/// `kubectl patch user <name> --type merge -p '{"spec":{"accountType":"Admin"}}'`. The next
/// sign-in or refresh uses the new type; access tokens already issued stay valid until they
/// expire.
///
/// # Errors
///
/// The Kubernetes error if the User cannot be read or patched.
pub async fn set_account_type(
    client: kube::Client,
    namespace: &str,
    name: &str,
    account_type: AccountType,
) -> Result<User, kube::Error> {
    let users: Api<User> = Api::namespaced(client, namespace);
    let patch = serde_json::json!({ "spec": { "accountType": account_type } });
    users
        .patch(name, &PatchParams::default(), &Patch::Merge(patch))
        .await
}
