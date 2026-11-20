//! Single-use and compare-and-swap primitives on Kubernetes objects.
//!
//! Each function is one API request whose outcome is decided atomically by the API server and its
//! storage (etcd, or kine on k3s):
//!
//! - [`create_once`]: a deterministic name turns `create` into insert-if-absent; the losers of a
//!   race get `409 AlreadyExists`.
//! - [`replace_status_if_unchanged`]: `resourceVersion` makes an update a compare-and-swap; the
//!   losers get `409 Conflict`.
//! - [`delete_if_unchanged`]: delete preconditions on `uid` and `resourceVersion`; exactly one of
//!   many concurrent deletes succeeds.
//!
//! The guarantees come from the API server ([API concepts], [DeleteOptions]): a create of an
//! existing name fails, an update carrying a stale `resourceVersion` fails, and a delete checks
//! its preconditions and then deletes only if the stored revision is unchanged (a transaction in
//! etcd; a unique index on the previous revision in kine). Gates therefore always talk to the API
//! server directly, never to a watch cache. A name derived from a hash of the identifier (as
//! [Pinniped] does) keeps raw identifiers out of object names.
//!
//! Security-relevant races are returned as outcomes, not errors; only infrastructure failures
//! are `Err`, and callers fail closed on them: an error is never treated as success. This
//! matters on k3s, where kine on SQLite has answered the losing side of a concurrent delete with
//! `500 unexpected end of JSON input` instead of `404` or `409`; the winner still got `200`.
//!
//! # References
//!
//! - [API concepts] The Kubernetes Authors, "Kubernetes API Concepts: Resource versions,"
//!   Kubernetes documentation.
//! - [DeleteOptions] The Kubernetes Authors, "`DeleteOptions`," Kubernetes API reference.
//! - [Pinniped] Pinniped project, `internal/crud/crud.go`, commit e635a39.
//!
//! [API concepts]: https://kubernetes.io/docs/reference/using-api/api-concepts/
//! [DeleteOptions]: https://kubernetes.io/docs/reference/kubernetes-api/common-definitions/delete-options/
//! [Pinniped]: https://github.com/vmware/pinniped/tree/e635a39cf793b5b915220a846de91e089ab431c9

use std::fmt::Debug;

use kube::api::{Api, DeleteParams, ListParams, PostParams, Preconditions};
use kube::core::NamespaceResourceScope;
use kube::{Resource, ResourceExt as _};
use serde::Serialize;
use serde::de::DeserializeOwned;

/// Objects for each `LIST` page.
const PAGE_SIZE: u32 = 500;

/// Lists every object that matches `params`, following `continue` tokens.
///
/// # Errors
///
/// Any failed page, including an expired `continue` token.
pub async fn list_all<K>(api: &Api<K>, params: ListParams) -> Result<Vec<K>, kube::Error>
where
    K: Clone + DeserializeOwned + Debug,
{
    let mut params = params.limit(PAGE_SIZE);
    let mut items = Vec::new();
    loop {
        let page = api.list(&params).await?;
        items.extend(page.items);
        match page.metadata.continue_.filter(|token| !token.is_empty()) {
            Some(token) => params.continue_token = Some(token),
            None => return Ok(items),
        }
    }
}

/// Outcome of [`create_once`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CreateOutcome<K> {
    /// This call created the object.
    Created(K),
    /// An object with that name already exists.
    AlreadyExists,
}

/// Outcome of [`replace_status_if_unchanged`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplaceOutcome<K> {
    /// The update was applied.
    Replaced(K),
    /// The object changed since it was read.
    Conflict,
    /// The object no longer exists.
    NotFound,
}

/// Outcome of [`delete_if_unchanged`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeleteOutcome {
    /// This call deleted the object.
    Deleted,
    /// The object changed (or was replaced by a new one with the same name) since it was read.
    Changed,
    /// The object no longer exists.
    NotFound,
}

/// The HTTP status code of an API server refusal; `None` for other failures.
#[must_use]
pub const fn status_code(error: &kube::Error) -> Option<u16> {
    if let kube::Error::Api(status) = error {
        Some(status.code)
    } else {
        None
    }
}

/// Creates `object` unless an object with its name exists.
///
/// # Errors
///
/// Returns the API error for anything other than `409 AlreadyExists`.
pub async fn create_once<K>(api: &Api<K>, object: &K) -> Result<CreateOutcome<K>, kube::Error>
where
    K: Resource<Scope = NamespaceResourceScope>
        + Clone
        + Serialize
        + DeserializeOwned
        + Debug
        + Send
        + Sync,
{
    match api.create(&PostParams::default(), object).await {
        Ok(created) => Ok(CreateOutcome::Created(created)),
        Err(error) if status_code(&error) == Some(409) => Ok(CreateOutcome::AlreadyExists),
        Err(error) => Err(error),
    }
}

/// Writes `object`'s status if the stored object still has `object`'s `resourceVersion`.
///
/// # Errors
///
/// Returns the API error for anything other than `409 Conflict` or `404 Not Found`. An object
/// without a `resourceVersion` is rejected by the server as invalid, never written blindly.
pub async fn replace_status_if_unchanged<K>(
    api: &Api<K>,
    object: &K,
) -> Result<ReplaceOutcome<K>, kube::Error>
where
    K: Resource<Scope = NamespaceResourceScope>
        + Clone
        + Serialize
        + DeserializeOwned
        + Debug
        + Send
        + Sync,
{
    match api
        .replace_status(&object.name_any(), &PostParams::default(), object)
        .await
    {
        Ok(replaced) => Ok(ReplaceOutcome::Replaced(replaced)),
        Err(error) => match status_code(&error) {
            Some(409) => Ok(ReplaceOutcome::Conflict),
            Some(404) => Ok(ReplaceOutcome::NotFound),
            _ => Err(error),
        },
    }
}

/// Deletes the object `name` if it still has `uid` and `resource_version`.
///
/// # Errors
///
/// Returns the API error for anything other than `409 Conflict` (failed precondition) or
/// `404 Not Found`.
pub async fn delete_if_unchanged<K>(
    api: &Api<K>,
    name: &str,
    uid: &str,
    resource_version: &str,
) -> Result<DeleteOutcome, kube::Error>
where
    K: Resource<Scope = NamespaceResourceScope> + Clone + DeserializeOwned + Debug + Send + Sync,
{
    let params = DeleteParams {
        preconditions: Some(Preconditions {
            uid: Some(uid.to_owned()),
            resource_version: Some(resource_version.to_owned()),
        }),
        ..DeleteParams::background()
    };
    match api.delete(name, &params).await {
        Ok(_) => Ok(DeleteOutcome::Deleted),
        Err(error) => match status_code(&error) {
            Some(409) => Ok(DeleteOutcome::Changed),
            Some(404) => Ok(DeleteOutcome::NotFound),
            _ => Err(error),
        },
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use axum::Router;
    use axum::body::Body;
    use axum::extract::State;
    use axum::http::Request;
    use axum::response::{IntoResponse as _, Response};
    use k8s_openapi::api::core::v1::ConfigMap;
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::ListMeta;
    use kube::api::ObjectMeta;

    use super::*;

    type Queries = Arc<Mutex<Vec<String>>>;

    async fn api_server(State(queries): State<Queries>, request: Request<Body>) -> Response {
        let query = request.uri().query().unwrap_or_default().to_owned();
        let params: Vec<(String, String)> = form_urlencoded::parse(query.as_bytes())
            .into_owned()
            .collect();
        queries.lock().unwrap().push(query);
        let token = params
            .iter()
            .find(|(key, _)| key == "continue")
            .map(|(_, value)| value.as_str());
        let (name, next) = match token {
            None => ("a", "page-2"),
            Some("page-2") => ("b", "page-3"),
            Some(_) => ("c", ""),
        };
        axum::Json(k8s_openapi::List {
            metadata: ListMeta {
                resource_version: Some("1".to_owned()),
                continue_: Some(next.to_owned()),
                ..ListMeta::default()
            },
            items: vec![ConfigMap {
                metadata: ObjectMeta {
                    name: Some(name.to_owned()),
                    namespace: Some("test".to_owned()),
                    ..ObjectMeta::default()
                },
                ..ConfigMap::default()
            }],
        })
        .into_response()
    }

    #[tokio::test]
    async fn list_all_follows_continue_tokens() {
        let queries = Queries::default();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let app = Router::new()
            .fallback(api_server)
            .with_state(Arc::clone(&queries));
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let client = kube::Client::try_from(kube::Config::new(
            format!("http://{address}").parse().unwrap(),
        ))
        .unwrap();
        let api: Api<ConfigMap> = Api::namespaced(client, "test");

        let items = list_all(&api, ListParams::default().labels("a=b"))
            .await
            .unwrap();
        server.abort();

        let names: Vec<_> = items.iter().map(kube::ResourceExt::name_any).collect();
        assert_eq!(names, ["a", "b", "c"]);
        let all_paged = queries
            .lock()
            .unwrap()
            .iter()
            .all(|query| query.contains("limit=500") && query.contains("labelSelector=a%3Db"));
        assert!(all_paged);
    }
}
