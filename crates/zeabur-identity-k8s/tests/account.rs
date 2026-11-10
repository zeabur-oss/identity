//! The account page's stores against a Kubernetes API that enforces `resourceVersion`
//! preconditions: filtering to the user, concurrent passkey removals and unlinks,
//! re-authentication.

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::Arc;

    use axum::body::Body;
    use axum::extract::State;
    use axum::http::{Method, Request, StatusCode};
    use axum::{Json, Router};
    use http_body_util::BodyExt as _;
    use kube::api::Api;
    use serde_json::{Value, json};
    use tokio::sync::{Barrier, Mutex};
    use zeabur_identity_api::credential::CredentialType;
    use zeabur_identity_api::upstream::{ExternalId, Issuer, Subject};
    use zeabur_identity_core::clock::UnixTime;
    use zeabur_identity_k8s::credentials::KubeCredentialStore;
    use zeabur_identity_k8s::grants::KubeGrantStore;
    use zeabur_identity_k8s::setup::KubeSetupStore;
    use zeabur_identity_store::{
        AccountEvent, CredentialStore as _, GrantStore as _, NewExternal, Removal, Rename,
        SetupStore as _, Unlink, User, Verification,
    };

    const ALICE_UID: &str = "uid-alice";

    #[derive(Default)]
    struct Backend {
        objects: BTreeMap<(String, String), Value>,
        version: u64,
        events: Vec<Value>,
        /// Credential status writes that wait at the barrier before being applied.
        held: usize,
        barrier: Option<Arc<Barrier>>,
    }

    impl Backend {
        fn next_version(&mut self) -> String {
            self.version += 1;
            self.version.to_string()
        }

        fn insert(&mut self, collection: &str, mut object: Value) {
            let name = object["metadata"]["name"].as_str().unwrap().to_owned();
            object["metadata"]["resourceVersion"] = json!(self.next_version());
            object["metadata"]["uid"] = json!(format!("uid-{name}"));
            self.objects.insert((collection.to_owned(), name), object);
        }

        fn names(&self, collection: &str) -> Vec<String> {
            self.objects
                .keys()
                .filter(|(c, _)| c == collection)
                .map(|(_, name)| name.clone())
                .collect()
        }
    }

    fn status(code: StatusCode, reason: &str) -> (StatusCode, Json<Value>) {
        (
            code,
            Json(
                json!({"apiVersion":"v1", "kind":"Status", "status":"Failure",
                "code":code.as_u16(), "reason":reason, "message":reason}),
            ),
        )
    }

    async fn kubernetes(
        State(state): State<Arc<Mutex<Backend>>>,
        request: Request<Body>,
    ) -> (StatusCode, Json<Value>) {
        let method = request.method().clone();
        let path = request.uri().path().to_owned();
        let query = request.uri().query().unwrap_or_default().to_owned();
        let bytes = request.into_body().collect().await.unwrap().to_bytes();
        let body: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        let segments: Vec<&str> = path.trim_start_matches('/').split('/').collect();
        if method == Method::POST && path == "/api/v1/namespaces/test/events" {
            state.lock().await.events.push(body.clone());
            return (StatusCode::CREATED, Json(body));
        }
        let [
            "apis",
            "identity.zeabur.com",
            "v1alpha1",
            "namespaces",
            "test",
            collection,
            rest @ ..,
        ] = segments.as_slice()
        else {
            panic!("unexpected Kubernetes request: {method} {path}");
        };
        let collection = (*collection).to_owned();
        let barrier = {
            let mut backend = state.lock().await;
            let is_status_put = method == Method::PUT && rest.get(1) == Some(&"status");
            (is_status_put && collection == "credentials" && backend.held > 0)
                .then(|| {
                    backend.held -= 1;
                    backend.barrier.clone()
                })
                .flatten()
        };
        if let Some(barrier) = barrier {
            barrier.wait().await;
        }
        apply(
            &mut *state.lock().await,
            &method,
            &collection,
            rest,
            &query,
            &body,
        )
    }

    fn apply(
        backend: &mut Backend,
        method: &Method,
        collection: &str,
        rest: &[&str],
        query: &str,
        body: &Value,
    ) -> (StatusCode, Json<Value>) {
        let collection = collection.to_owned();
        match (method.clone(), rest) {
            (Method::GET, []) => {
                let selector = form_urlencoded::parse(query.as_bytes())
                    .find(|(k, _)| k == "labelSelector")
                    .map(|(_, v)| v.into_owned())
                    .unwrap();
                let (key, value) = selector.split_once('=').unwrap();
                let items: Vec<Value> = backend
                    .objects
                    .iter()
                    .filter(|((c, _), o)| *c == collection && o["metadata"]["labels"][key] == value)
                    .map(|(_, o)| o.clone())
                    .collect();
                (
                    StatusCode::OK,
                    Json(json!({"apiVersion":"identity.zeabur.com/v1alpha1",
                        "kind":"List", "metadata":{"resourceVersion":backend.version.to_string()},
                        "items":items})),
                )
            }
            (Method::GET, [name]) => backend
                .objects
                .get(&(collection, (*name).to_owned()))
                .map_or_else(
                    || status(StatusCode::NOT_FOUND, "NotFound"),
                    |o| (StatusCode::OK, Json(o.clone())),
                ),
            (Method::PUT, [name, "status"]) => {
                let key = (collection, (*name).to_owned());
                let Some(current) = backend.objects.get(&key).cloned() else {
                    return status(StatusCode::NOT_FOUND, "NotFound");
                };
                if body["metadata"]["resourceVersion"] != current["metadata"]["resourceVersion"] {
                    return status(StatusCode::CONFLICT, "Conflict");
                }
                let mut updated = current;
                updated["status"] = body["status"].clone();
                updated["metadata"]["resourceVersion"] = json!(backend.next_version());
                backend.objects.insert(key, updated.clone());
                (StatusCode::OK, Json(updated))
            }
            (Method::PATCH, [name, "status"]) => {
                let key = (collection, (*name).to_owned());
                let Some(mut updated) = backend.objects.get(&key).cloned() else {
                    return status(StatusCode::NOT_FOUND, "NotFound");
                };
                if !updated["status"].is_object() {
                    updated["status"] = json!({});
                }
                for (field, value) in body["status"].as_object().unwrap() {
                    updated["status"][field] = value.clone();
                }
                updated["metadata"]["resourceVersion"] = json!(backend.next_version());
                backend.objects.insert(key, updated.clone());
                (StatusCode::OK, Json(updated))
            }
            (Method::DELETE, [name]) => {
                let key = (collection, (*name).to_owned());
                let Some(current) = backend.objects.get(&key) else {
                    return status(StatusCode::NOT_FOUND, "NotFound");
                };
                let preconditions = &body["preconditions"];
                assert!(preconditions.is_object(), "delete without preconditions");
                if preconditions["uid"] != current["metadata"]["uid"]
                    || preconditions["resourceVersion"] != current["metadata"]["resourceVersion"]
                {
                    return status(StatusCode::CONFLICT, "Conflict");
                }
                let removed = backend.objects.remove(&key).unwrap();
                (StatusCode::OK, Json(removed))
            }
            (method, rest) => {
                panic!("unexpected Kubernetes request: {method} {collection} {rest:?}")
            }
        }
    }

    fn alice() -> User {
        User {
            name: "alice".into(),
            subject: ALICE_UID.into(),
            username: "alice".into(),
            ..User::default()
        }
    }

    fn passkey(name: &str, user: &str, owner: Option<&str>) -> Value {
        let mut object = json!({"apiVersion":"identity.zeabur.com/v1alpha1","kind":"Credential",
            "metadata":{"name":name,"labels":{"identity.zeabur.com/user":"alice"},
                "creationTimestamp":"2026-10-01T00:00:00Z"},
            "spec":{"user":user,"type":"Passkey",
                "passkey":{"credentialId":name,"record":"{}","backupEligible":true,
                    "label":"Laptop","aaguid":"fbfc3007-154e-4ecc-8c0b-6e020557d7bd"}}});
        if let Some(uid) = owner {
            object["metadata"]["ownerReferences"] = json!([{"apiVersion":"identity.zeabur.com/v1alpha1",
                "kind":"User","name":"alice","uid":uid}]);
        }
        object
    }

    fn github(name: &str, owners: &[&str]) -> Value {
        let owners: Vec<Value> = owners
            .iter()
            .map(|uid| {
                json!({"apiVersion":"identity.zeabur.com/v1alpha1",
                "kind":"User","name":"alice","uid":uid})
            })
            .collect();
        json!({"apiVersion":"identity.zeabur.com/v1alpha1","kind":"Credential",
            "metadata":{"name":name,"labels":{"identity.zeabur.com/user":"alice"},
                "ownerReferences":owners},
            "spec":{"user":"alice","type":"GitHub",
                "external":{"issuer":"https://github.com","subject":name}}})
    }

    fn grant(name: &str, subject: Option<&str>) -> Value {
        json!({"apiVersion":"identity.zeabur.com/v1alpha1","kind":"Grant",
            "metadata":{"name":name,"labels":{"identity.zeabur.com/user":"alice"}},
            "spec":{"user":"alice","client":"zeabur_identity","audience":"https://login.example.com",
                "authTime":1_800_000_000,"scopes":[],"amr":["hwk","user"],
                "expiresAt":1_800_003_600,"initialIdleExpiresAt":1_800_003_600,
                "initialHash":"hash-1","subject":subject,"credential":"a","userVerified":true}})
    }

    struct Mock {
        state: Arc<Mutex<Backend>>,
        client: kube::Client,
        task: tokio::task::JoinHandle<()>,
    }

    impl Drop for Mock {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    async fn mock(backend: Backend) -> Mock {
        let state = Arc::new(Mutex::new(backend));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let app = Router::new()
            .fallback(kubernetes)
            .with_state(Arc::clone(&state));
        let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let client = kube::Client::try_from(kube::Config::new(
            format!("http://{address}").parse().unwrap(),
        ))
        .unwrap();
        Mock {
            state,
            client,
            task,
        }
    }

    fn credentials(mock: &Mock) -> KubeCredentialStore {
        KubeCredentialStore::new(Api::namespaced(mock.client.clone(), "test"))
    }

    #[tokio::test]
    async fn only_the_users_own_passkeys_are_listed_or_changed() {
        let mut backend = Backend::default();
        backend.insert("credentials", passkey("a", "alice", Some(ALICE_UID)));
        backend.insert("credentials", passkey("b", "alice", None));
        // Labelled for alice but naming someone else, or owned by an earlier alice.
        backend.insert("credentials", passkey("c", "mallory", None));
        backend.insert("credentials", passkey("d", "alice", Some("uid-old-alice")));
        let mock = mock(backend).await;
        let store = credentials(&mock);
        let listed: Vec<String> = store
            .passkeys(&alice())
            .await
            .unwrap()
            .into_iter()
            .map(|p| p.name)
            .collect();
        assert_eq!(listed, ["a", "b"]);
        for foreign in ["c", "d"] {
            assert!(matches!(
                store.rename(&alice(), foreign, "Mine").await.unwrap(),
                Rename::NotFound
            ));
            assert!(matches!(
                store.remove(&alice(), foreign).await.unwrap(),
                Removal::NotFound
            ));
        }
        assert_eq!(
            mock.state.lock().await.names("credentials"),
            ["a", "b", "c", "d"]
        );

        assert!(matches!(
            store.rename(&alice(), "a", "Phone").await.unwrap(),
            Rename::Renamed
        ));
        store
            .touch("a", UnixTime::from_secs(1_800_000_100))
            .await
            .unwrap();
        store
            .touch("gone", UnixTime::from_secs(1_800_000_100))
            .await
            .unwrap();
        let a = store
            .passkeys(&alice())
            .await
            .unwrap()
            .into_iter()
            .find(|p| p.name == "a")
            .unwrap();
        assert_eq!(a.label.as_deref(), Some("Phone"));
        assert_eq!(a.last_used_at, Some(UnixTime::from_secs(1_800_000_100)));
        assert_eq!(
            a.aaguid.as_deref(),
            Some("fbfc3007-154e-4ecc-8c0b-6e020557d7bd")
        );

        store
            .record(&AccountEvent {
                user: "alice".into(),
                subject: ALICE_UID.into(),
                reason: "PasskeyRenamed",
                at: UnixTime::from_secs(1_800_000_100),
                note: "actor=alice credential=a".into(),
            })
            .await
            .unwrap();
        let event = mock.state.lock().await.events[0].clone();
        assert_eq!(event["involvedObject"]["kind"], "User");
        assert_eq!(event["involvedObject"]["uid"], ALICE_UID);
        assert_eq!(event["reason"], "PasskeyRenamed");
        assert_eq!(event["metadata"]["generateName"], "alice.");
    }

    #[tokio::test]
    async fn a_linked_account_signs_in_only_as_the_user_that_owns_it() {
        let mut backend = Backend::default();
        let cases = [
            ("current", vec![ALICE_UID], true),
            ("earlier-alice", vec!["uid-old-alice"], false),
            ("no-owner", vec![], false),
            ("two-owners", vec![ALICE_UID, "uid-old-alice"], false),
        ];
        for (name, owners, _) in &cases {
            backend.insert("credentials", github(name, owners));
        }
        backend.insert(
            "users",
            json!({"apiVersion":"identity.zeabur.com/v1alpha1","kind":"User",
                "metadata":{"name":"alice"},"spec":{"username":"alice"}}),
        );
        let mock = mock(backend).await;
        let store = credentials(&mock);
        for (name, _, signs_in) in cases {
            let linked = store.linked_account(name).await.unwrap().unwrap();
            assert_eq!(linked.signs_in_as(&alice()), signs_in, "{name}");
        }

        // A link for a User that was replaced after the caller read it.
        let stale = NewExternal {
            id: ExternalId {
                issuer: Issuer::new("https://github.com").unwrap(),
                subject: Subject::new("new").unwrap(),
            },
            user: "alice".into(),
            kind: CredentialType::GitHub,
            user_subject: "uid-old-alice".into(),
        };
        assert!(store.link(&stale).await.is_err());
        assert!(
            !mock
                .state
                .lock()
                .await
                .names("credentials")
                .contains(&stale.name())
        );
    }

    #[tokio::test]
    async fn an_invitation_enrols_only_the_user_that_owns_it() {
        let mut backend = Backend::default();
        let cases = [
            ("inv-current", vec![ALICE_UID], true),
            ("inv-earlier-alice", vec!["uid-old-alice"], false),
            ("inv-no-owner", vec![], false),
        ];
        for (name, owners, _) in &cases {
            let owners: Vec<Value> = owners
                .iter()
                .map(|uid| {
                    json!({"apiVersion":"identity.zeabur.com/v1alpha1",
                    "kind":"User","name":"alice","uid":uid})
                })
                .collect();
            backend.insert(
                "invitations",
                json!({"apiVersion":"identity.zeabur.com/v1alpha1","kind":"Invitation",
                    "metadata":{"name":name,"ownerReferences":owners},
                    "spec":{"user":"alice","tokenHash":"sha256:00","expiresAt":1_800_003_600}}),
            );
        }
        let mock = mock(backend).await;
        let store = KubeSetupStore::new(Api::namespaced(mock.client.clone(), "test"))
            .with_invitations(Api::namespaced(mock.client.clone(), "test"));
        for (name, _, enrols) in cases {
            let token = store
                .load(&format!("{name}.secret"))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(token.is_for(&alice()), enrols, "{name}");
        }
    }

    #[tokio::test]
    async fn the_last_passkey_is_never_removed() {
        let mut backend = Backend::default();
        backend.insert("credentials", passkey("a", "alice", None));
        let mock = mock(backend).await;
        assert!(matches!(
            credentials(&mock).remove(&alice(), "a").await.unwrap(),
            Removal::LastPasskey
        ));
        assert_eq!(mock.state.lock().await.names("credentials"), ["a"]);
    }

    /// Two removals that both list before either writes: neither may leave the user with none.
    #[tokio::test]
    async fn interleaved_removals_keep_a_passkey() {
        for passkeys in [2, 3] {
            let mut backend = Backend::default();
            for name in ["a", "b", "c"].into_iter().take(passkeys) {
                backend.insert("credentials", passkey(name, "alice", None));
            }
            // Each removal's first status write waits for the other's.
            backend.held = 2;
            backend.barrier = Some(Arc::new(Barrier::new(2)));
            let mock = mock(backend).await;
            let store = credentials(&mock);
            let (user_a, user_b) = (alice(), alice());
            let (first, second) =
                tokio::join!(store.remove(&user_a, "a"), store.remove(&user_b, "b"));
            let outcomes = [first.unwrap(), second.unwrap()];
            let removed = outcomes
                .iter()
                .filter(|o| matches!(o, Removal::Removed))
                .count();
            assert!(removed < 2, "{outcomes:?}");
            let left = mock.state.lock().await.names("credentials");
            assert_eq!(left.len(), passkeys - removed);
        }
    }

    #[tokio::test]
    async fn sequential_removals_stop_at_the_last_passkey() {
        let mut backend = Backend::default();
        for name in ["a", "b", "c"] {
            backend.insert("credentials", passkey(name, "alice", None));
        }
        let mock = mock(backend).await;
        let store = credentials(&mock);
        assert!(matches!(
            store.remove(&alice(), "a").await.unwrap(),
            Removal::Removed
        ));
        assert!(matches!(
            store.remove(&alice(), "b").await.unwrap(),
            Removal::Removed
        ));
        assert!(matches!(
            store.remove(&alice(), "c").await.unwrap(),
            Removal::LastPasskey
        ));
        assert_eq!(mock.state.lock().await.names("credentials"), ["c"]);
    }

    #[tokio::test]
    async fn only_linked_accounts_the_user_owns_are_listed_or_unlinked() {
        let mut backend = Backend::default();
        backend.insert("credentials", github("g-own", &[ALICE_UID]));
        backend.insert("credentials", github("g-old", &["uid-old-alice"]));
        backend.insert("credentials", github("g-none", &[]));
        backend.insert("credentials", passkey("a", "alice", Some(ALICE_UID)));
        let mock = mock(backend).await;
        let store = credentials(&mock);
        let listed: Vec<String> = store
            .linked_accounts(&alice())
            .await
            .unwrap()
            .into_iter()
            .map(|linked| linked.name)
            .collect();
        assert_eq!(listed, ["g-own"]);
        for name in ["g-old", "g-none", "a"] {
            assert!(matches!(
                store.unlink(&alice(), name).await.unwrap(),
                Unlink::NotFound
            ));
        }
        assert!(matches!(
            store.unlink(&alice(), "g-own").await.unwrap(),
            Unlink::Unlinked
        ));
        assert_eq!(
            mock.state.lock().await.names("credentials"),
            ["a", "g-none", "g-old"]
        );
    }

    #[tokio::test]
    async fn the_last_credential_is_never_unlinked() {
        let mut backend = Backend::default();
        backend.insert("credentials", github("g", &[ALICE_UID]));
        let mock = mock(backend).await;
        assert!(matches!(
            credentials(&mock).unlink(&alice(), "g").await.unwrap(),
            Unlink::LastCredential
        ));
        assert_eq!(mock.state.lock().await.names("credentials"), ["g"]);
    }

    /// Two unlinks that both list before either writes: neither may leave the user with nothing.
    #[tokio::test]
    async fn interleaved_unlinks_keep_a_credential() {
        let mut backend = Backend::default();
        backend.insert("credentials", github("g1", &[ALICE_UID]));
        backend.insert("credentials", github("g2", &[ALICE_UID]));
        backend.held = 2;
        backend.barrier = Some(Arc::new(Barrier::new(2)));
        let mock = mock(backend).await;
        let store = credentials(&mock);
        let (user_a, user_b) = (alice(), alice());
        let (first, second) =
            tokio::join!(store.unlink(&user_a, "g1"), store.unlink(&user_b, "g2"));
        let outcomes = [first.unwrap(), second.unwrap()];
        assert!(
            !outcomes.iter().all(|o| matches!(o, Unlink::Unlinked)),
            "{outcomes:?}"
        );
        let left = mock.state.lock().await.names("credentials");
        assert!(matches!(left.as_slice(), [_, ..]), "{left:?}");
    }

    #[tokio::test]
    async fn grants_are_listed_by_uid_and_reauthenticated_by_secret() {
        let mut backend = Backend::default();
        backend.insert("grants", grant("s-1", Some(ALICE_UID)));
        // A grant without a recorded UID belongs to no one.
        backend.insert("grants", grant("g-legacy", None));
        backend.insert("grants", grant("s-old", Some("uid-old-alice")));
        let mock = mock(backend).await;
        let store = KubeGrantStore::new(Api::namespaced(mock.client.clone(), "test"));
        let names: Vec<String> = store
            .list(&alice())
            .await
            .unwrap()
            .into_iter()
            .map(|g| g.spec.name)
            .collect();
        assert_eq!(names, ["s-1"]);

        let verification = Verification {
            at: UnixTime::from_secs(1_800_000_200),
            credential: Some("b".into()),
            user_verified: true,
        };
        assert!(
            !store
                .reauthenticate("s-1", "wrong-hash", &verification)
                .await
                .unwrap()
        );
        assert!(
            !store
                .reauthenticate("s-missing", "hash-1", &verification)
                .await
                .unwrap()
        );
        assert!(
            store
                .reauthenticate("s-1", "hash-1", &verification)
                .await
                .unwrap()
        );
        let session = store.get("s-1").await.unwrap().unwrap();
        assert_eq!(session.verification(), verification);
        assert_eq!(session.spec.credential.as_deref(), Some("a"));
    }
}
