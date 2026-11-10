//! `UpstreamProvider` objects, watched, and their client secrets in the Secret [`SECRET`], read
//! by name at each use.
//!
//! Reading the Secret at each use makes a rotated secret take effect at the next sign-in, with no
//! watch on Secrets: Zeabur Identity's Role cannot list or watch Secrets (see [`crate::rbac`]).

use futures_util::StreamExt as _;
use k8s_openapi::api::core::v1::Secret;
use kube::api::Api;
use kube::runtime::WatchStreamExt as _;
use kube::runtime::reflector::{self, reflector};
use kube::runtime::watcher::{self, Event};
pub use zeabur_identity_api::upstream_provider::SECRET;
use zeabur_identity_api::upstream_provider::UpstreamProvider;

use crate::watch::relisting_watcher;

/// Watches `UpstreamProvider` objects and calls `publish` with all of them, sorted by name.
///
/// It publishes after the initial list and after every change. Errors are logged and retried
/// with backoff; it returns only if the watch stream ends.
pub async fn watch(api: Api<UpstreamProvider>, mut publish: impl FnMut(Vec<UpstreamProvider>)) {
    let (store, writer) = reflector::store();
    let events = relisting_watcher(api, watcher::Config::default());
    let mut events = reflector(writer, events).default_backoff().boxed();
    while let Some(event) = events.next().await {
        match event {
            Ok(Event::Init | Event::InitApply(_)) => {}
            Ok(Event::InitDone | Event::Apply(_) | Event::Delete(_)) => {
                let mut providers: Vec<UpstreamProvider> =
                    store.state().iter().map(|p| (**p).clone()).collect();
                providers.sort_by(|a, b| a.metadata.name.cmp(&b.metadata.name));
                publish(providers);
            }
            Err(error) => {
                tracing::warn!(
                    reason = "upstream_provider_watch_failed",
                    %error,
                    "upstream provider watch error; retrying with backoff"
                );
            }
        }
    }
}

/// The client secret under `key` in [`SECRET`], without surrounding whitespace.
///
/// # Errors
///
/// A message naming what is missing or unusable, without the secret.
pub async fn client_secret(api: &Api<Secret>, key: &str) -> Result<String, String> {
    let secret = api
        .get_opt(SECRET)
        .await
        .map_err(|error| format!("reading Secret {SECRET}: {error}"))?
        .ok_or_else(|| format!("Secret {SECRET} does not exist"))?;
    let value = secret
        .data
        .and_then(|mut data| data.remove(key))
        .ok_or_else(|| format!("Secret {SECRET} has no key {key}"))?;
    let text = String::from_utf8(value.0)
        .map_err(|_utf8| format!("Secret {SECRET} key {key} is not UTF-8"))?;
    let text = text.trim();
    if text.is_empty() {
        return Err(format!("Secret {SECRET} key {key} is empty"));
    }
    Ok(text.to_owned())
}
