//! HTTP-level regression tests using real `kube::Api` list/watch streams.

use std::collections::HashMap;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use axum::body::{Body, Bytes};
use axum::extract::State;
use axum::http::{Method, Request, StatusCode};
use axum::response::{IntoResponse as _, Response};
use axum::{Json, Router};
use futures_util::stream;
use serde_json::{Value, json};
use tokio::sync::{Mutex, mpsc};

use super::{Api, Directory as _, KubeDirectory};

const CLIENTS: &str = "oauthclients";
const USERS: &str = "users";

type StreamSender = mpsc::UnboundedSender<Bytes>;

enum BackendRequest {
    List(&'static str, StreamSender),
    Watch(&'static str, StreamSender),
}

struct Backend {
    objects: HashMap<&'static str, HashMap<String, Value>>,
    gets: HashMap<String, usize>,
    lists: HashMap<&'static str, usize>,
    fail_gets: bool,
    requests: mpsc::UnboundedSender<BackendRequest>,
}

async fn kubernetes(
    State(backend): State<Arc<Mutex<Backend>>>,
    request: Request<Body>,
) -> Response {
    let (request, _) = request.into_parts();
    assert_eq!(request.method, Method::GET);
    let path = request.uri.path();
    let collection = path
        .strip_prefix("/apis/identity.zeabur.com/v1alpha1/")
        .unwrap();
    let namespaced = collection.strip_prefix("namespaces/test/");
    let resource = namespaced.unwrap_or(collection);
    let mut backend = backend.lock().await;
    if let Some((kind, name)) = resource.split_once('/') {
        assert!(
            namespaced.is_some(),
            "namespaced resources require a scoped GET"
        );
        *backend.gets.entry(resource.to_owned()).or_default() += 1;
        if backend.fail_gets {
            return status(StatusCode::INTERNAL_SERVER_ERROR, "InternalError");
        }
        return backend
            .objects
            .get(kind)
            .and_then(|objects| objects.get(name))
            .cloned()
            .map_or_else(
                || status(StatusCode::NOT_FOUND, "NotFound"),
                |object| Json(object).into_response(),
            );
    }
    let resource = match resource {
        CLIENTS => CLIENTS,
        USERS => USERS,
        other => panic!("unexpected collection: {other}"),
    };
    // The user index must negotiate metadata, not download full specs.
    let metadata_only = request.headers.get("accept").is_some_and(|accept| {
        accept
            .to_str()
            .unwrap()
            .contains("as=PartialObjectMetadata")
    });
    assert_eq!(metadata_only, resource == USERS);
    let is_watch = form_urlencoded::parse(request.uri.query().unwrap_or_default().as_bytes())
        .any(|(key, value)| key == "watch" && value == "true");
    let (sender, receiver) = mpsc::unbounded_channel();
    let request = if is_watch {
        BackendRequest::Watch(resource, sender)
    } else {
        *backend.lists.entry(resource).or_default() += 1;
        BackendRequest::List(resource, sender)
    };
    backend.requests.send(request).unwrap();
    drop(backend);
    let chunks = stream::unfold(receiver, |mut receiver| async move {
        receiver
            .recv()
            .await
            .map(|bytes| (Ok::<_, std::convert::Infallible>(bytes), receiver))
    });
    Response::builder()
        .header("content-type", "application/json")
        .body(Body::from_stream(chunks))
        .unwrap()
}

fn status(code: StatusCode, reason: &str) -> Response {
    (
        code,
        Json(
            json!({"apiVersion":"v1", "kind":"Status", "status":"Failure",
            "code":code.as_u16(), "reason":reason, "message":reason}),
        ),
    )
        .into_response()
}

fn client(name: &str) -> Value {
    json!({"apiVersion":"identity.zeabur.com/v1alpha1", "kind":"OAuthClient",
        "metadata":{"name":name, "namespace":"test", "uid":format!("uid-{name}"), "resourceVersion":"101"},
        "spec":{"type":"Public", "displayName":"Original", "redirectUris":["https://example.com/callback"]}})
}

fn user(name: &str, uid: &str) -> Value {
    json!({"apiVersion":"identity.zeabur.com/v1alpha1", "kind":"User",
        "metadata":{"name":name, "namespace":"test", "uid":uid, "resourceVersion":"101"},
        "spec":{"username":name, "accountType":"Admin", "disabled":false}})
}

fn with_unused_metadata(mut object: Value) -> Value {
    object["metadata"]["annotations"] =
        json!({"gitops.example/config": "retained only by the API"});
    object["metadata"]["labels"] = json!({"app.kubernetes.io/managed-by": "projection-test"});
    object["metadata"]["managedFields"] = json!([{
        "manager": "projection-test",
        "operation": "Apply",
        "apiVersion": "identity.zeabur.com/v1alpha1",
        "fieldsType": "FieldsV1",
        "fieldsV1": {"f:metadata": {"f:annotations": {"f:gitops.example/config": {}}}}
    }]);
    object["metadata"]["ownerReferences"] = json!([{
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "name": "owner",
        "uid": "uid-owner",
        "controller": false,
        "blockOwnerDeletion": false
    }]);
    object["metadata"]["finalizers"] = json!(["identity.zeabur.com/projection-test"]);
    object
}

fn metadata(object: &Value) -> Value {
    json!({"apiVersion":"meta.k8s.io/v1", "kind":"PartialObjectMetadata",
        "metadata":object["metadata"]})
}

/// The object as its index watch receives it.
fn watched(resource: &str, object: &Value) -> Value {
    if resource == CLIENTS {
        object.clone()
    } else {
        metadata(object)
    }
}

fn reply_list(reply: StreamSender, items: &[Value]) {
    reply
        .send(Bytes::from(
            json!({"apiVersion":"v1", "kind":"List",
                "metadata":{"resourceVersion":"100"}, "items":items})
            .to_string(),
        ))
        .unwrap();
    // Finish this HTTP response; watch streams deliberately keep their sender alive instead.
    drop(reply);
}

async fn bounded<F: Future>(future: F) -> F::Output {
    tokio::time::timeout(Duration::from_secs(10), future)
        .await
        .expect("stream gate or index did not advance")
}

async fn wait_for(predicate: impl Fn() -> bool) {
    bounded(async {
        while !predicate() {
            tokio::task::yield_now().await;
        }
    })
    .await;
}

fn assert_pending<F: Future>(future: Pin<&mut F>) {
    assert!(matches!(
        future.poll(&mut Context::from_waker(Waker::noop())),
        Poll::Pending
    ));
}

struct Mock {
    backend: Arc<Mutex<Backend>>,
    requests: mpsc::UnboundedReceiver<BackendRequest>,
    pending_lists: HashMap<&'static str, StreamSender>,
    streams: HashMap<&'static str, StreamSender>,
    server: tokio::task::JoinHandle<()>,
}

impl Mock {
    async fn start(clients: Vec<Value>, users: Vec<Value>) -> (Self, kube::Client) {
        let (requests, receiver) = mpsc::unbounded_channel();
        let collect = |objects: Vec<Value>| {
            objects
                .into_iter()
                .map(|object| {
                    (
                        object["metadata"]["name"].as_str().unwrap().to_owned(),
                        object,
                    )
                })
                .collect()
        };
        let backend = Arc::new(Mutex::new(Backend {
            objects: HashMap::from([(CLIENTS, collect(clients)), (USERS, collect(users))]),
            gets: HashMap::new(),
            lists: HashMap::new(),
            fail_gets: false,
            requests,
        }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let app = Router::new()
            .fallback(kubernetes)
            .with_state(Arc::clone(&backend));
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let client = kube::Client::try_from(kube::Config::new(
            format!("http://{address}").parse().unwrap(),
        ))
        .unwrap();
        (
            Self {
                backend,
                requests: receiver,
                pending_lists: HashMap::new(),
                streams: HashMap::new(),
                server,
            },
            client,
        )
    }

    async fn new(clients: Vec<Value>, users: Vec<Value>) -> (Self, KubeDirectory) {
        let (mut mock, client) = Self::start(clients, users).await;
        let mut construction = std::pin::pin!(KubeDirectory::new(
            Api::namespaced(client.clone(), "test"),
            Api::namespaced(client, "test"),
        ));
        assert_pending(construction.as_mut());
        for resource in [CLIENTS, USERS] {
            let reply = mock.take_list(resource).await;
            reply_list(reply, &mock.snapshot(resource).await);
        }
        let directory = bounded(construction).await.unwrap();
        mock.connect_watch(CLIENTS).await;
        mock.connect_watch(USERS).await;
        (mock, directory)
    }

    async fn receive(&mut self) {
        match bounded(self.requests.recv()).await.unwrap() {
            BackendRequest::List(resource, reply) => {
                assert!(self.pending_lists.insert(resource, reply).is_none());
            }
            BackendRequest::Watch(resource, sender) => {
                assert!(self.streams.insert(resource, sender).is_none());
            }
        }
    }

    async fn take_list(&mut self, resource: &'static str) -> StreamSender {
        loop {
            if let Some(reply) = self.pending_lists.remove(resource) {
                return reply;
            }
            self.receive().await;
        }
    }

    async fn connect_watch(&mut self, resource: &'static str) {
        while !self.streams.contains_key(resource) {
            self.receive().await;
        }
    }

    async fn snapshot(&self, resource: &str) -> Vec<Value> {
        self.backend.lock().await.objects[resource]
            .values()
            .map(|object| watched(resource, object))
            .collect()
    }

    async fn put(&self, resource: &'static str, object: Value) {
        let name = object["metadata"]["name"].as_str().unwrap().to_owned();
        self.backend
            .lock()
            .await
            .objects
            .get_mut(resource)
            .unwrap()
            .insert(name, object);
    }

    fn event(&self, resource: &str, event: &str, object: &Value) {
        let object = if event == "ERROR" {
            object.clone()
        } else {
            watched(resource, object)
        };
        self.streams[resource]
            .send(Bytes::from(format!(
                "{}\n",
                json!({"type":event, "object":object})
            )))
            .unwrap();
    }

    async fn gets(&self, resource: &str) -> usize {
        self.backend
            .lock()
            .await
            .gets
            .get(resource)
            .copied()
            .unwrap_or_default()
    }
}

impl Drop for Mock {
    fn drop(&mut self) {
        self.server.abort();
    }
}

fn has_client(directory: &KubeDirectory, name: &str) -> bool {
    directory
        .client_index
        .find(|object| object.metadata.name.as_deref() == Some(name))
        .is_some()
}

fn assert_projected_indexes(directory: &KubeDirectory, client: &Value, user: &Value) {
    assert_eq!(directory.client_index.len(), 1);
    assert_eq!(directory.user_index.len(), 1);
    let cached_client = directory.client_index.find(|_| true).unwrap();
    let cached_user = directory.user_index.find(|_| true).unwrap();
    for (cached, expected) in [
        (&cached_client.metadata, &client["metadata"]),
        (&cached_user.metadata, &user["metadata"]),
    ] {
        assert_eq!(cached.name.as_deref(), expected["name"].as_str());
        assert_eq!(cached.namespace.as_deref(), expected["namespace"].as_str());
        assert_eq!(cached.uid.as_deref(), expected["uid"].as_str());
        assert_eq!(
            cached.resource_version.as_deref(),
            expected["resourceVersion"].as_str()
        );
        assert!(cached.annotations.is_none());
        assert!(cached.labels.is_none());
        assert!(cached.managed_fields.is_none());
        assert!(cached.owner_references.is_none());
        assert!(cached.finalizers.is_none());
    }
}

#[tokio::test]
async fn constructor_waits_for_both_initial_snapshots() {
    for first in [CLIENTS, USERS] {
        let known = client("known");
        let alice = user("alice", "uid-alice");
        let (mut mock, client) = Mock::start(vec![known], vec![alice]).await;
        let mut construction = std::pin::pin!(KubeDirectory::new(
            Api::namespaced(client.clone(), "test"),
            Api::namespaced(client, "test"),
        ));
        assert_pending(construction.as_mut());
        let clients = mock.take_list(CLIENTS).await;
        let users = mock.take_list(USERS).await;
        let (first_reply, second_reply, second) = if first == CLIENTS {
            (clients, users, USERS)
        } else {
            (users, clients, CLIENTS)
        };
        reply_list(first_reply, &mock.snapshot(first).await);
        mock.connect_watch(first).await;
        assert_pending(construction.as_mut());
        assert!(mock.backend.lock().await.gets.is_empty());
        reply_list(second_reply, &mock.snapshot(second).await);
        let directory = bounded(construction).await.unwrap();
        assert!(directory.client("known").await.unwrap().is_some());
        assert!(directory.user("alice").await.unwrap().is_some());
        assert!(
            directory
                .user_by_subject("uid-alice")
                .await
                .unwrap()
                .is_some()
        );
    }
}

#[tokio::test]
async fn list_watch_and_relist_project_metadata_without_losing_locator_identity() {
    let known = with_unused_metadata(client("known"));
    let alice = with_unused_metadata(user("alice", "uid-alice"));
    let (mut mock, directory) = Mock::new(vec![known.clone()], vec![alice.clone()]).await;
    let indexes_at_version = |version: &str| {
        directory
            .client_index
            .find(|object| object.metadata.resource_version.as_deref() == Some(version))
            .is_some()
            && directory
                .user_index
                .find(|object| object.metadata.resource_version.as_deref() == Some(version))
                .is_some()
    };
    assert_projected_indexes(&directory, &known, &alice);

    let mut modified_client = known;
    modified_client["metadata"]["resourceVersion"] = json!("102");
    let mut modified_user = alice;
    modified_user["metadata"]["resourceVersion"] = json!("102");
    modified_user["spec"]["groups"] = json!(["modified"]);
    mock.put(CLIENTS, modified_client.clone()).await;
    mock.put(USERS, modified_user.clone()).await;
    // Subject lookups still read current specs before watch delivery.
    assert_eq!(
        directory
            .user_by_subject("uid-alice")
            .await
            .unwrap()
            .unwrap()
            .groups,
        ["modified"]
    );
    mock.event(CLIENTS, "MODIFIED", &modified_client);
    mock.event(USERS, "MODIFIED", &modified_user);
    wait_for(|| indexes_at_version("102")).await;
    assert_projected_indexes(&directory, &modified_client, &modified_user);

    let mut relisted_client = with_unused_metadata(client("relisted-client"));
    relisted_client["metadata"]["resourceVersion"] = json!("104");
    relisted_client["spec"]["displayName"] = json!("Relisted");
    let mut relisted_user = with_unused_metadata(user("relisted-user", "uid-relisted-user"));
    relisted_user["metadata"]["resourceVersion"] = json!("104");
    relisted_user["spec"]["groups"] = json!(["relisted"]);
    {
        let mut backend = mock.backend.lock().await;
        backend.objects.get_mut(CLIENTS).unwrap().clear();
        backend.objects.get_mut(USERS).unwrap().clear();
    }
    mock.put(CLIENTS, relisted_client.clone()).await;
    mock.put(USERS, relisted_user.clone()).await;
    let expired = json!({
        "apiVersion": "v1",
        "kind": "Status",
        "status": "Failure",
        "code": 410,
        "reason": "Expired",
        "message": "resource version expired"
    });
    for resource in [CLIENTS, USERS] {
        mock.event(resource, "ERROR", &expired);
        drop(mock.streams.remove(resource).unwrap());
    }
    for resource in [CLIENTS, USERS] {
        let reply = mock.take_list(resource).await;
        reply_list(reply, &mock.snapshot(resource).await);
    }
    mock.connect_watch(CLIENTS).await;
    mock.connect_watch(USERS).await;
    wait_for(|| indexes_at_version("104")).await;
    assert_projected_indexes(&directory, &relisted_client, &relisted_user);
    assert!(directory.client("known").await.unwrap().is_none());
    assert!(
        directory
            .user_by_subject("uid-alice")
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        directory
            .client("relisted-client")
            .await
            .unwrap()
            .unwrap()
            .display_name
            .as_deref(),
        Some("Relisted")
    );
    assert_eq!(
        directory
            .user_by_subject("uid-relisted-user")
            .await
            .unwrap()
            .unwrap()
            .groups,
        ["relisted"]
    );
}

#[tokio::test]
async fn unique_unknown_identifiers_never_read_resources() {
    let (mock, directory) = Mock::new(vec![], vec![]).await;
    for number in 0..4096 {
        let unknown = format!("unknown-{number}");
        assert!(directory.client(&unknown).await.unwrap().is_none());
        assert!(directory.user_by_subject(&unknown).await.unwrap().is_none());
    }
    let backend = mock.backend.lock().await;
    assert!(backend.gets.is_empty());
    assert_eq!(backend.lists[CLIENTS], 1);
    assert_eq!(backend.lists[USERS], 1);
}

#[tokio::test]
async fn client_create_delete_events_update_existence_index() {
    let (mock, directory) = Mock::new(vec![], vec![]).await;
    let mut created = client("created");
    created["spec"]["type"] = json!("Confidential");
    created["spec"]["secretHash"] = json!(format!("sha256:{}", "ab".repeat(32)));
    created["spec"]["audiences"] = json!(["kubernetes"]);
    created["spec"]["homeUrl"] = json!("https://created.example/");
    mock.put(CLIENTS, created.clone()).await;
    assert!(directory.client("created").await.unwrap().is_none());
    assert_eq!(mock.gets("oauthclients/created").await, 0);
    mock.event(CLIENTS, "ADDED", &created);
    wait_for(|| has_client(&directory, "created")).await;
    assert!(directory.client("created").await.unwrap().is_some());
    let cached = directory.client_index.find(|_| true).unwrap();
    assert_eq!(cached.spec.secret_hash, None);
    assert_eq!(cached.spec.redirect_uris, Vec::<String>::new());
    assert_eq!(cached.spec.audiences, Vec::<String>::new());
    // Pages read names and home URLs from the index, not from the API server.
    assert_eq!(
        directory.client_name("created").as_deref(),
        Some("Original")
    );
    assert_eq!(
        directory.apps(),
        [zeabur_identity_store::App {
            name: "Original".into(),
            url: "https://created.example/".into(),
        }]
    );
    assert_eq!(mock.backend.lock().await.lists[CLIENTS], 1);
    mock.backend
        .lock()
        .await
        .objects
        .get_mut(CLIENTS)
        .unwrap()
        .remove("created");
    // Stale existence metadata never authorizes an object deleted before its watch event.
    assert!(directory.client("created").await.unwrap().is_none());
    mock.event(CLIENTS, "DELETED", &created);
    wait_for(|| !has_client(&directory, "created")).await;
    assert!(directory.client("created").await.unwrap().is_none());
    assert_eq!(mock.gets("oauthclients/created").await, 2);
}

#[tokio::test]
async fn known_clients_read_latest_authorization_during_watch_interruption() {
    let (mut mock, directory) = Mock::new(vec![client("known")], vec![]).await;
    assert_eq!(
        directory
            .client("known")
            .await
            .unwrap()
            .unwrap()
            .display_name
            .as_deref(),
        Some("Original")
    );
    drop(mock.streams.remove(CLIENTS).unwrap());
    let mut updated = client("known");
    updated["spec"]["displayName"] = json!("Updated");
    updated["spec"]["type"] = json!("Confidential");
    updated["spec"]["secretHash"] = json!(format!("sha256:{}", "ab".repeat(32)));
    updated["spec"]["redirectUris"] = json!(["https://changed.example/callback"]);
    updated["spec"]["audiences"] = json!(["changed-audience"]);
    mock.put(CLIENTS, updated).await;
    let current = directory.client("known").await.unwrap().unwrap();
    assert_eq!(current.display_name.as_deref(), Some("Updated"));
    assert_eq!(
        current.kind,
        zeabur_identity_api::client::ClientType::Confidential
    );
    assert_eq!(
        current.secret_hash,
        Some(format!("sha256:{}", "ab".repeat(32)))
    );
    assert_eq!(current.redirect_uris, ["https://changed.example/callback"]);
    assert_eq!(current.audiences, ["changed-audience"]);
    mock.backend.lock().await.fail_gets = true;
    assert!(directory.client("known").await.is_err());
    mock.backend.lock().await.fail_gets = false;
    assert!(directory.client("known").await.unwrap().is_some());
    assert_eq!(mock.gets("oauthclients/known").await, 4);
}

#[tokio::test]
async fn subject_lookup_reads_current_authorization_without_per_request_lists() {
    let original = user("alice", "uid-alice");
    let (mock, directory) = Mock::new(vec![], vec![original.clone()]).await;
    assert!(
        !directory
            .user_by_subject("uid-alice")
            .await
            .unwrap()
            .unwrap()
            .disabled
    );
    let mut disabled = original;
    disabled["spec"]["disabled"] = json!(true);
    disabled["spec"]["groups"] = json!([]);
    mock.put(USERS, disabled).await;
    let current = directory
        .user_by_subject("uid-alice")
        .await
        .unwrap()
        .unwrap();
    assert!(current.disabled);
    assert_eq!(current.groups, Vec::<String>::new());
    assert!(directory.user("alice").await.unwrap().unwrap().disabled);
    assert!(directory.user("absent").await.unwrap().is_none());
    assert!(directory.user("absent").await.unwrap().is_none());
    assert_eq!(mock.gets("users/alice").await, 3);
    assert_eq!(mock.gets("users/absent").await, 2);
    assert_eq!(mock.backend.lock().await.lists[USERS], 1);
    let cached = directory.user_index.find(|_| true).unwrap();
    assert!(
        serde_json::to_value(cached.as_ref())
            .unwrap()
            .get("spec")
            .is_none()
    );
}

#[tokio::test]
async fn deleted_recreated_user_never_substitutes_subject() {
    let original = user("alice", "old-uid");
    let (mock, directory) = Mock::new(vec![], vec![original.clone()]).await;
    assert!(
        directory
            .user_by_subject("old-uid")
            .await
            .unwrap()
            .is_some()
    );
    mock.backend
        .lock()
        .await
        .objects
        .get_mut(USERS)
        .unwrap()
        .remove("alice");
    assert!(
        directory
            .user_by_subject("old-uid")
            .await
            .unwrap()
            .is_none()
    );
    let recreated = user("alice", "new-uid");
    mock.put(USERS, recreated.clone()).await;
    assert!(
        directory
            .user_by_subject("old-uid")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        directory
            .user_by_subject("new-uid")
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(mock.gets("users/alice").await, 3);
    mock.event(USERS, "DELETED", &original);
    mock.event(USERS, "ADDED", &recreated);
    wait_for(|| {
        directory
            .user_index
            .find(|object| object.metadata.uid.as_deref() == Some("new-uid"))
            .is_some()
    })
    .await;
    assert!(
        directory
            .user_by_subject("old-uid")
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        directory
            .user_by_subject("new-uid")
            .await
            .unwrap()
            .unwrap()
            .subject,
        "new-uid"
    );
    assert_eq!(mock.gets("users/alice").await, 4);
}

#[tokio::test]
async fn ambiguous_subjects_fail_closed_without_resource_reads() {
    let (mock, directory) = Mock::new(
        vec![],
        vec![user("alice", "duplicate"), user("bob", "duplicate")],
    )
    .await;
    assert!(
        directory
            .user_by_subject("duplicate")
            .await
            .unwrap()
            .is_none()
    );
    assert!(directory.user_by_subject("absent").await.unwrap().is_none());
    assert!(mock.backend.lock().await.gets.is_empty());
}

#[tokio::test]
async fn cancelling_constructor_closes_both_initial_list_streams() {
    let (mut mock, client) = Mock::start(vec![], vec![]).await;
    let (clients, users) = {
        let mut construction = std::pin::pin!(KubeDirectory::new(
            Api::namespaced(client.clone(), "test"),
            Api::namespaced(client, "test"),
        ));
        assert_pending(construction.as_mut());
        let clients = mock.take_list(CLIENTS).await;
        let users = mock.take_list(USERS).await;
        assert!(!clients.is_closed());
        assert!(!users.is_closed());
        assert_pending(construction.as_mut());
        (clients, users)
    };
    bounded(async {
        tokio::join!(clients.closed(), users.closed());
    })
    .await;
    assert!(mock.backend.lock().await.gets.is_empty());
}

#[tokio::test]
async fn clones_keep_watchers_alive_until_last_directory_drops() {
    let (mock, directory) = Mock::new(vec![], vec![]).await;
    let KubeDirectory { _watcher: task, .. } = &directory;
    let watcher = task.0.abort_handle();
    let clone = directory.clone();
    drop(directory);
    let created = client("created");
    mock.put(CLIENTS, created.clone()).await;
    mock.event(CLIENTS, "ADDED", &created);
    wait_for(|| has_client(&clone, "created")).await;
    assert!(clone.client("created").await.unwrap().is_some());
    assert!(!watcher.is_finished());
    drop(clone);
    wait_for(|| watcher.is_finished()).await;
}

#[tokio::test]
async fn all_namespace_indexes_read_objects_in_their_metadata_namespace() {
    let (mut mock, client) =
        Mock::start(vec![client("known")], vec![user("alice", "uid-alice")]).await;
    let mut construction = std::pin::pin!(KubeDirectory::new(
        Api::all(client.clone()),
        Api::all(client),
    ));
    assert_pending(construction.as_mut());
    for resource in [CLIENTS, USERS] {
        let reply = mock.take_list(resource).await;
        reply_list(reply, &mock.snapshot(resource).await);
    }
    let directory = bounded(construction).await.unwrap();
    assert_eq!(
        directory
            .user_by_subject("uid-alice")
            .await
            .unwrap()
            .unwrap()
            .name,
        "alice"
    );
    assert_eq!(
        directory.client("known").await.unwrap().unwrap().id,
        "known"
    );
    mock.connect_watch(CLIENTS).await;
    let mut duplicate = mock.backend.lock().await.objects[CLIENTS]["known"].clone();
    duplicate["metadata"]["namespace"] = json!("other");
    duplicate["metadata"]["uid"] = json!("other-client");
    mock.event(CLIENTS, "ADDED", &duplicate);
    wait_for(|| directory.client_index.len() == 2).await;
    assert!(directory.client("known").await.unwrap().is_none());
    let gets = &mock.backend.lock().await.gets;
    assert_eq!(gets.get("users/alice"), Some(&1));
    assert_eq!(gets.get("oauthclients/known"), Some(&1));
}
