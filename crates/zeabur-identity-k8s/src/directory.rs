//! [`Directory`] backed by `User` and `OAuthClient` objects.
//!
//! Watches index clients and user UIDs; arbitrary unknown client names and subjects never cause
//! per-request API reads. The user index holds metadata only. The client index also holds the
//! display name and home URL. The sign-in page and the account page read them from the index.
//! The initial snapshots must complete before any lookup. Relists replace each index atomically,
//! and watch errors retry with backoff without falling back to per-identifier reads for indexed
//! lookups.
//! Before reflection, discard annotations, labels, managed fields, owner references and
//! finalizers: this locator uses none of them. In particular, GitOps annotations and server-side
//! apply history can dwarf the name/namespace/UID needed for lookup. Also discard the secret hash,
//! redirect URIs and audiences of each client. Projecting before the reflector also avoids cloning
//! those allocations into its initial and relist snapshots.
//!
//! An index is only a locator and a source of display names, never authorization data: known
//! clients and users are read directly on every request. Watch lag may temporarily deny a new
//! object, but cannot retain a revoked permission or client secret. Subject lookups also compare
//! the fetched UID, because Kubernetes permits a deleted object's name to be reused but assigns
//! every new object a distinct [UID]. Ambiguous subjects fail closed.
//! Name-based user lookups always GET directly after initial synchronization, including absent
//! names. Setup, sign-in and refresh therefore do not wait for individual user watch events.
//!
//! The account settings are a `ConfigMap` read directly on every call, in the namespace of the
//! `User`s. A missing `ConfigMap` gives the defaults.
//!
//! [UID]: https://kubernetes.io/docs/concepts/overview/working-with-objects/names/#uids

use std::borrow::Cow;
use std::fmt::Debug;
use std::sync::Arc;
use std::time::Duration;

use futures_util::StreamExt as _;
use k8s_openapi::api::core::v1::ConfigMap;
use kube::api::Api;
use kube::core::{NamespaceResourceScope, PartialObjectMeta};
use kube::runtime::reflector::store::Writer;
use kube::runtime::reflector::{self, ObjectRef, Store};
use kube::runtime::{WatchStreamExt as _, watcher};
use kube::{Resource, ResourceExt as _};
use serde::de::DeserializeOwned;
use tokio::task::JoinHandle;
use zeabur_identity_api::client::OAuthClient;
use zeabur_identity_api::user::{AccountType as ApiAccountType, User as UserObject};
use zeabur_identity_core::account::{AccountType, SETTINGS_CONFIG_MAP, Settings};
use zeabur_identity_keys::Algorithm;
use zeabur_identity_store::{App, Client, Directory, StoreError, User};

use crate::watch::relisting_watcher;

/// Maximum startup wait for complete directory metadata snapshots.
///
/// Deployment startup protection must outlast this deadline before liveness may restart a pod.
pub const INITIAL_SYNC_TIMEOUT: Duration = Duration::from_secs(30);

/// Locates clients and user subjects through watched indexes, then reads current API objects.
#[derive(Clone)]
pub struct KubeDirectory {
    clients: Api<OAuthClient>,
    users: Api<UserObject>,
    client_index: Store<OAuthClient>,
    user_index: Store<PartialObjectMeta<UserObject>>,
    _watcher: Arc<WatchTask>,
}

impl Debug for KubeDirectory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("KubeDirectory")
    }
}

/// The last directory clone owns cancellation; construction failure also drops this guard.
struct WatchTask(JoinHandle<()>);

impl Drop for WatchTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}

impl KubeDirectory {
    fn config_maps(&self) -> Api<ConfigMap> {
        let client = self.users.clone().into_client();
        match self.users.namespace() {
            Some(namespace) => Api::namespaced(client, namespace),
            None => Api::default_namespaced(client),
        }
    }

    /// Returns a directory only after both metadata snapshots initialize.
    ///
    /// Watches use the supplied API namespaces and stop when the last directory clone drops.
    ///
    /// # Errors
    ///
    /// Returns an error if initial synchronization fails or exceeds [`INITIAL_SYNC_TIMEOUT`].
    /// Cancelling construction also stops its watchers.
    pub async fn new(
        clients: Api<OAuthClient>,
        users: Api<UserObject>,
    ) -> Result<Self, StoreError> {
        let (client_index, client_writer) = reflector::store();
        let (user_index, user_writer) = reflector::store();
        let client_api = clients.clone();
        let user_metadata = metadata_api(&users);
        let watcher = Arc::new(WatchTask(tokio::spawn(async move {
            tokio::join!(
                run_index(client_api, client_writer, "client", |client| {
                    client.spec.secret_hash = None;
                    client.spec.redirect_uris = Vec::new();
                    client.spec.audiences = Vec::new();
                }),
                run_index(user_metadata, user_writer, "user", |_| {}),
            );
        })));
        tokio::time::timeout(INITIAL_SYNC_TIMEOUT, async {
            tokio::try_join!(
                client_index.wait_until_ready(),
                user_index.wait_until_ready(),
            )
        })
        .await
        .map_err(|_elapsed| {
            StoreError("directory metadata initial synchronization timed out".into())
        })?
        .map_err(|error| {
            StoreError(format!(
                "directory metadata index did not initialize: {error}"
            ))
        })?;
        Ok(Self {
            clients,
            users,
            client_index,
            user_index,
            _watcher: watcher,
        })
    }

    async fn read_user(api: &Api<UserObject>, name: &str) -> Result<Option<User>, StoreError> {
        Ok(api
            .get_opt(name)
            .await
            .map_err(|e| backend(&e))?
            .and_then(convert))
    }

    fn indexed_client(&self, id: &str) -> Option<Arc<OAuthClient>> {
        self.clients.namespace().map_or_else(
            // A name shared across namespaces is not an unambiguous client identifier.
            || {
                let mut matches = self
                    .client_index
                    .state_filter(|object| object.metadata.name.as_deref() == Some(id));
                if matches.len() == 1 {
                    matches.pop()
                } else {
                    None
                }
            },
            |namespace| self.client_index.get(&ObjectRef::new(id).within(namespace)),
        )
    }
}

fn metadata_api<K>(api: &Api<K>) -> Api<PartialObjectMeta<K>>
where
    K: Resource<Scope = NamespaceResourceScope, DynamicType = ()> + Clone,
{
    let client = api.clone().into_client();
    match api.namespace() {
        Some(namespace) => Api::namespaced(client, namespace),
        None => Api::all(client),
    }
}

/// All-namespaces watches still require a namespace for an individual object GET.
fn indexed_api<'a, K, I>(api: &'a Api<K>, indexed: &I) -> Option<Cow<'a, Api<K>>>
where
    K: Resource<Scope = NamespaceResourceScope, DynamicType = ()> + Clone,
    I: Resource,
{
    if api.namespace().is_some() {
        Some(Cow::Borrowed(api))
    } else {
        Some(Cow::Owned(Api::namespaced(
            api.clone().into_client(),
            indexed.meta().namespace.as_deref()?,
        )))
    }
}

/// The watcher pages its `LIST` (500 objects for each page) and follows `continue`.
async fn run_index<K>(
    api: Api<K>,
    writer: Writer<K>,
    resource: &'static str,
    project: impl Fn(&mut K) + Send + 'static,
) where
    K: Resource<DynamicType = ()> + Clone + DeserializeOwned + Debug + Send + Sync + 'static,
{
    let events = relisting_watcher(api, watcher::Config::default()).modify(move |object| {
        let metadata = object.meta_mut();
        metadata.annotations = None;
        metadata.labels = None;
        metadata.managed_fields = None;
        metadata.owner_references = None;
        metadata.finalizers = None;
        project(object);
    });
    reflector::reflector(writer, events)
        .default_backoff()
        .for_each(|event| async move {
            if let Err(error) = event {
                tracing::warn!(
                    event = "kubernetes_directory_watch",
                    resource,
                    reason = "watch_failed",
                    %error,
                    "directory metadata watch error; retrying with backoff"
                );
            }
        })
        .await;
}

fn backend(error: &kube::Error) -> StoreError {
    StoreError(error.to_string())
}

impl Directory for KubeDirectory {
    async fn settings(&self) -> Result<Settings, StoreError> {
        let object = self
            .config_maps()
            .get_opt(SETTINGS_CONFIG_MAP)
            .await
            .map_err(|e| backend(&e))?;
        let data = object.and_then(|object| object.data).unwrap_or_default();
        let (settings, bad) = Settings::from_data(&data);
        if !bad.is_empty() {
            tracing::warn!(
                event = "account_settings",
                reason = "invalid_value",
                keys = ?bad,
                "a value in the account settings is not understood; the stricter setting applies"
            );
        }
        Ok(settings)
    }

    async fn client(&self, id: &str) -> Result<Option<Client>, StoreError> {
        let Some(indexed) = self.indexed_client(id) else {
            return Ok(None);
        };
        let Some(api) = indexed_api(&self.clients, indexed.as_ref()) else {
            return Ok(None);
        };
        let result = api.get_opt(id).await;
        Ok(result.map_err(|e| backend(&e))?.map(client))
    }

    fn client_name(&self, id: &str) -> Option<String> {
        let indexed = self.indexed_client(id)?;
        Some(client(OAuthClient::clone(&indexed)).name().to_owned())
    }

    async fn user(&self, name: &str) -> Result<Option<User>, StoreError> {
        Self::read_user(&self.users, name).await
    }

    fn apps(&self) -> Vec<App> {
        let clients: Vec<Client> = self
            .client_index
            .state_filter(|object| object.spec.home_url.is_some())
            .iter()
            .map(|object| client(OAuthClient::clone(object)))
            .collect();
        zeabur_identity_store::apps(&clients)
    }

    async fn user_by_subject(&self, subject: &str) -> Result<Option<User>, StoreError> {
        // Filter under one store read lock so an ambiguous snapshot never picks an arbitrary user.
        // Only matching metadata is cloned, not a full snapshot of every user.
        let matches = self
            .user_index
            .state_filter(|object| object.metadata.uid.as_deref() == Some(subject));
        let [metadata] = matches.as_slice() else {
            return Ok(None);
        };
        let Some(name) = metadata.metadata.name.as_deref() else {
            return Ok(None);
        };
        let Some(api) = indexed_api(&self.users, metadata.as_ref()) else {
            return Ok(None);
        };
        Ok(Self::read_user(&api, name)
            .await?
            .filter(|user| user.subject == subject))
    }
}

fn client(object: OAuthClient) -> Client {
    let id = object.name_any();
    let spec = object.spec;
    Client {
        id,
        display_name: spec.display_name,
        kind: spec.kind,
        redirect_uris: spec.redirect_uris,
        audiences: spec.audiences,
        secret_hash: spec.secret_hash,
        id_token_alg: spec.id_token_signing_alg.unwrap_or(Algorithm::Es256),
        home_url: spec.home_url,
    }
}

/// An object without a UID was never stored; it is treated as absent.
fn convert(object: UserObject) -> Option<User> {
    let subject = object.uid()?;
    Some(User {
        name: object.name_any(),
        subject,
        username: object.spec.username,
        display_name: object.spec.display_name,
        groups: object.spec.groups,
        disabled: object.spec.disabled,
        account_type: match object.spec.account_type {
            ApiAccountType::Regular => AccountType::Regular,
            ApiAccountType::Admin => AccountType::Admin,
        },
    })
}

#[cfg(test)]
#[path = "directory_watch_tests.rs"]
mod tests;
