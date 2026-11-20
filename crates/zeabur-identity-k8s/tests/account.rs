//! The account page's stores against a Kubernetes API that enforces `resourceVersion`
//! preconditions: filtering to the user, concurrent passkey removals, unlinks and password
//! removals, re-authentication.

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::Arc;

    use axum::body::Body;
    use axum::extract::State;
    use axum::http::{Method, Request, StatusCode};
    use axum::response::{IntoResponse as _, Response};
    use axum::{Json, Router};
    use http_body_util::BodyExt as _;
    use k8s_openapi::api::core::v1::Event;
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::{ListMeta, OwnerReference, Time};
    use kube::api::Api;
    use kube::core::{ObjectList, Status, TypeMeta};
    use kube::{Resource, ResourceExt as _};
    use serde::de::DeserializeOwned;
    use serde::{Deserialize, Serialize};
    use tokio::sync::{Barrier, Mutex};
    use zeabur_identity_api::USER_LABEL;
    use zeabur_identity_api::credential::{
        Credential, CredentialKind, CredentialSpec, CredentialStatus, Guesses, Passkey, Password,
        RecoveryHash, Totp,
    };
    use zeabur_identity_api::grant::{Grant, GrantSpec};
    use zeabur_identity_api::invitation::{Invitation, InvitationSpec};
    use zeabur_identity_api::upstream::{ExternalId, Issuer, Subject};
    use zeabur_identity_api::user::{User as UserObject, UserSpec};
    use zeabur_identity_core::clock::UnixTime;
    use zeabur_identity_k8s::credentials::KubeCredentialStore;
    use zeabur_identity_k8s::grants::KubeGrantStore;
    use zeabur_identity_k8s::setup::KubeSetupStore;
    use zeabur_identity_store::{
        AccountEvent, CredentialStore as _, GrantStore as _, NewExternal, PasswordRemoval,
        PasswordState, Removal, Rename, Saved, SetupStore as _, Unlink, User, Verification,
        password_credential_name,
    };

    const ALICE_UID: &str = "uid-alice";

    #[derive(Default)]
    struct Backend {
        credentials: BTreeMap<String, Credential>,
        grants: BTreeMap<String, Grant>,
        users: BTreeMap<String, UserObject>,
        invitations: BTreeMap<String, Invitation>,
        version: u64,
        events: Vec<Event>,
        /// Credential status writes that wait at the barrier before being applied.
        held: usize,
        barrier: Option<Arc<Barrier>>,
    }

    /// A kind that the fake API server stores.
    trait Stored: Resource<DynamicType = ()> + Clone + Serialize + DeserializeOwned {
        fn objects(backend: &mut Backend) -> &mut BTreeMap<String, Self>;

        /// What a `PUT` of the status subresource keeps of `sent`.
        fn replace_status(&mut self, _sent: &Self) {
            panic!("{} has no status", Self::kind(&()));
        }

        /// What a merge `PATCH` of the status subresource does with `body`.
        fn patch_status(&mut self, _body: &[u8]) {
            panic!("{} takes no status patch", Self::kind(&()));
        }
    }

    impl Stored for Credential {
        fn objects(backend: &mut Backend) -> &mut BTreeMap<String, Self> {
            &mut backend.credentials
        }

        fn replace_status(&mut self, sent: &Self) {
            self.status.clone_from(&sent.status);
        }

        fn patch_status(&mut self, body: &[u8]) {
            /// The two merge patches that Zeabur Identity sends: `touch`, and `save_state`, which
            /// always sends all three of its members.
            #[derive(Deserialize)]
            struct Patch {
                status: Fields,
            }
            #[derive(Deserialize)]
            #[serde(rename_all = "camelCase")]
            struct Fields {
                last_used_at: Option<i64>,
                guesses: Option<Guesses>,
                totp_last_step: Option<i64>,
                recovery_used: Option<Vec<i64>>,
            }
            let Patch { status: fields } = serde_json::from_slice(body).unwrap();
            let status = self.status.get_or_insert_with(CredentialStatus::default);
            if fields.last_used_at.is_some() {
                status.last_used_at = fields.last_used_at;
            } else {
                status.guesses = fields.guesses;
                status.totp_last_step = fields.totp_last_step;
                status.recovery_used = fields.recovery_used.unwrap();
            }
        }
    }

    impl Stored for Grant {
        fn objects(backend: &mut Backend) -> &mut BTreeMap<String, Self> {
            &mut backend.grants
        }

        fn replace_status(&mut self, sent: &Self) {
            self.status.clone_from(&sent.status);
        }
    }

    impl Stored for UserObject {
        fn objects(backend: &mut Backend) -> &mut BTreeMap<String, Self> {
            &mut backend.users
        }
    }

    impl Stored for Invitation {
        fn objects(backend: &mut Backend) -> &mut BTreeMap<String, Self> {
            &mut backend.invitations
        }
    }

    impl Backend {
        fn next_version(&mut self) -> String {
            self.version += 1;
            self.version.to_string()
        }

        fn insert<T: Stored>(&mut self, mut object: T) {
            let name = object.name_any();
            object.meta_mut().resource_version = Some(self.next_version());
            object.meta_mut().uid = Some(format!("uid-{name}"));
            T::objects(self).insert(name, object);
        }

        fn names(&self) -> Vec<String> {
            self.credentials.keys().cloned().collect()
        }
    }

    /// A `Status` with the `kind` that clients look for.
    #[derive(Serialize)]
    struct StatusBody {
        #[serde(flatten)]
        types: TypeMeta,
        #[serde(flatten)]
        status: Status,
    }

    fn status(code: StatusCode, reason: &str) -> Response {
        let status = Status::failure(reason, reason).with_code(code.as_u16());
        let body = StatusBody {
            types: TypeMeta {
                api_version: "v1".into(),
                kind: "Status".into(),
            },
            status,
        };
        (code, Json(body)).into_response()
    }

    async fn kubernetes(
        State(state): State<Arc<Mutex<Backend>>>,
        request: Request<Body>,
    ) -> Response {
        let method = request.method().clone();
        let path = request.uri().path().to_owned();
        let query = request.uri().query().unwrap_or_default().to_owned();
        let bytes = request.into_body().collect().await.unwrap().to_bytes();
        let segments: Vec<&str> = path.trim_start_matches('/').split('/').collect();
        if method == Method::POST && path == "/api/v1/namespaces/test/events" {
            state
                .lock()
                .await
                .events
                .push(serde_json::from_slice(&bytes).unwrap());
            return (
                StatusCode::CREATED,
                [(axum::http::header::CONTENT_TYPE, "application/json")],
                bytes,
            )
                .into_response();
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
        let barrier = {
            let mut backend = state.lock().await;
            let is_status_put = method == Method::PUT && rest.get(1) == Some(&"status");
            (is_status_put && *collection == "credentials" && backend.held > 0)
                .then(|| {
                    backend.held -= 1;
                    backend.barrier.clone()
                })
                .flatten()
        };
        if let Some(barrier) = barrier {
            barrier.wait().await;
        }
        let backend = &mut *state.lock().await;
        let request = Call {
            method: &method,
            rest,
            query: &query,
            body: &bytes,
        };
        match *collection {
            "credentials" => apply::<Credential>(backend, &request),
            "grants" => apply::<Grant>(backend, &request),
            "users" => apply::<UserObject>(backend, &request),
            "invitations" => apply::<Invitation>(backend, &request),
            other => panic!("unexpected collection: {other}"),
        }
    }

    struct Call<'a> {
        method: &'a Method,
        rest: &'a [&'a str],
        query: &'a str,
        body: &'a [u8],
    }

    /// The `DELETE` options that the stores send.
    #[derive(Deserialize)]
    struct DeleteBody {
        preconditions: Option<Preconditions>,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Preconditions {
        uid: Option<String>,
        resource_version: Option<String>,
    }

    fn apply<T: Stored>(backend: &mut Backend, call: &Call<'_>) -> Response {
        match (call.method.clone(), call.rest) {
            (Method::GET, []) => {
                let selector = form_urlencoded::parse(call.query.as_bytes())
                    .find(|(k, _)| k == "labelSelector")
                    .map(|(_, v)| v.into_owned())
                    .unwrap();
                let (key, value) = selector.split_once('=').unwrap();
                let items: Vec<T> = T::objects(backend)
                    .values()
                    .filter(|o| o.labels().get(key).is_some_and(|v| v == value))
                    .cloned()
                    .collect();
                let list = ObjectList {
                    types: TypeMeta {
                        api_version: "identity.zeabur.com/v1alpha1".into(),
                        kind: "List".into(),
                    },
                    metadata: ListMeta {
                        resource_version: Some(backend.version.to_string()),
                        ..ListMeta::default()
                    },
                    items,
                };
                (StatusCode::OK, Json(list)).into_response()
            }
            (Method::GET, [name]) => T::objects(backend).get(*name).map_or_else(
                || status(StatusCode::NOT_FOUND, "NotFound"),
                |o| (StatusCode::OK, Json(o)).into_response(),
            ),
            (Method::PUT, [name, "status"]) => {
                let sent: T = serde_json::from_slice(call.body).unwrap();
                let version = backend.next_version();
                let Some(current) = T::objects(backend).get_mut(*name) else {
                    return status(StatusCode::NOT_FOUND, "NotFound");
                };
                if sent.meta().resource_version != current.meta().resource_version {
                    backend.version -= 1;
                    return status(StatusCode::CONFLICT, "Conflict");
                }
                current.replace_status(&sent);
                current.meta_mut().resource_version = Some(version);
                (StatusCode::OK, Json(&*current)).into_response()
            }
            (Method::PATCH, [name, "status"]) => {
                let version = backend.next_version();
                let Some(current) = T::objects(backend).get_mut(*name) else {
                    return status(StatusCode::NOT_FOUND, "NotFound");
                };
                current.patch_status(call.body);
                current.meta_mut().resource_version = Some(version);
                (StatusCode::OK, Json(&*current)).into_response()
            }
            (Method::POST, []) => {
                let object: T = serde_json::from_slice(call.body).unwrap();
                let name = object.name_any();
                if T::objects(backend).contains_key(&name) {
                    return status(StatusCode::CONFLICT, "AlreadyExists");
                }
                backend.insert(object);
                (StatusCode::CREATED, Json(&T::objects(backend)[&name])).into_response()
            }
            (Method::DELETE, [name]) => {
                let Some(current) = T::objects(backend).get(*name) else {
                    return status(StatusCode::NOT_FOUND, "NotFound");
                };
                let options: DeleteBody = serde_json::from_slice(call.body).unwrap();
                let preconditions = options.preconditions.expect("delete without preconditions");
                if preconditions.uid != current.meta().uid
                    || preconditions.resource_version != current.meta().resource_version
                {
                    return status(StatusCode::CONFLICT, "Conflict");
                }
                let removed = T::objects(backend).remove(*name).unwrap();
                (StatusCode::OK, Json(removed)).into_response()
            }
            (method, rest) => {
                panic!("unexpected Kubernetes request: {method} {rest:?}")
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

    fn alice_object() -> UserObject {
        UserObject::new(
            "alice",
            UserSpec {
                username: "alice".into(),
                ..UserSpec::default()
            },
        )
    }

    fn owner(uid: &str) -> OwnerReference {
        OwnerReference {
            api_version: "identity.zeabur.com/v1alpha1".into(),
            kind: "User".into(),
            name: "alice".into(),
            uid: uid.into(),
            controller: None,
            block_owner_deletion: None,
        }
    }

    fn credential(name: &str, owners: &[&str], kind: CredentialKind) -> Credential {
        let mut object = Credential::new(
            name,
            CredentialSpec {
                user: "alice".into(),
                kind,
            },
        );
        object.metadata.labels = Some(BTreeMap::from([(
            USER_LABEL.to_owned(),
            "alice".to_owned(),
        )]));
        object.metadata.owner_references = Some(owners.iter().map(|uid| owner(uid)).collect());
        object
    }

    fn passkey(name: &str, user: &str, owner: Option<&str>) -> Credential {
        let mut object = credential(
            name,
            owner.as_slice(),
            CredentialKind::Passkey(Passkey {
                credential_id: name.into(),
                record: "{}".into(),
                backup_eligible: true,
                aaguid: Some("fbfc3007-154e-4ecc-8c0b-6e020557d7bd".into()),
                label: Some("Laptop".into()),
            }),
        );
        object.spec.user = user.into();
        object.metadata.creation_timestamp =
            Some(serde_json::from_str::<Time>("\"2026-10-01T00:00:00Z\"").unwrap());
        if owner.is_none() {
            object.metadata.owner_references = None;
        }
        object
    }

    fn github(name: &str, owners: &[&str]) -> Credential {
        credential(
            name,
            owners,
            CredentialKind::External(ExternalId {
                issuer: Issuer::new("https://github.com").unwrap(),
                subject: Subject::new(name).unwrap(),
            }),
        )
    }

    fn password() -> Credential {
        credential(
            &password_credential_name(ALICE_UID),
            &[ALICE_UID],
            CredentialKind::Password(Password {
                hash: "$pbkdf2-sha256$i=1$c2FsdA$aGFzaA".into(),
                totp: Some(Totp {
                    secret: "sealed".into(),
                    recovery: vec![RecoveryHash("00".into())],
                    enrolled_step: 1,
                }),
            }),
        )
    }

    fn invitation(name: &str, owners: &[&str]) -> Invitation {
        let mut object = Invitation::new(
            name,
            InvitationSpec {
                user: "alice".into(),
                token_hash: "sha256:00".into(),
                expires_at: 1_800_003_600,
            },
        );
        object.metadata.owner_references = Some(owners.iter().map(|uid| owner(uid)).collect());
        object
    }

    fn grant(name: &str, subject: Option<&str>) -> Grant {
        let mut object = Grant::new(
            name,
            GrantSpec {
                user: "alice".into(),
                client: "zeabur_identity".into(),
                audience: "https://login.example.com".into(),
                auth_time: 1_800_000_000,
                scopes: Vec::new(),
                amr: vec!["hwk".into(), "user".into()],
                expires_at: 1_800_003_600,
                initial_idle_expires_at: 1_800_003_600,
                initial_hash: "hash-1".into(),
                subject: subject.map(Into::into),
                credential: Some("a".into()),
                user_verified: true,
                device_bound: false,
            },
        );
        object.metadata.labels = Some(BTreeMap::from([(
            USER_LABEL.to_owned(),
            "alice".to_owned(),
        )]));
        object
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
        backend.insert(passkey("a", "alice", Some(ALICE_UID)));
        backend.insert(passkey("b", "alice", None));
        // Labelled for alice but naming someone else, or owned by an earlier alice.
        backend.insert(passkey("c", "mallory", None));
        backend.insert(passkey("d", "alice", Some("uid-old-alice")));
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
        assert_eq!(mock.state.lock().await.names(), ["a", "b", "c", "d"]);

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
        assert_eq!(event.involved_object.kind.as_deref(), Some("User"));
        assert_eq!(event.involved_object.uid.as_deref(), Some(ALICE_UID));
        assert_eq!(event.reason.as_deref(), Some("PasskeyRenamed"));
        assert_eq!(event.metadata.generate_name.as_deref(), Some("alice."));
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
            backend.insert(github(name, owners));
        }
        backend.insert(alice_object());
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
            user_subject: "uid-old-alice".into(),
        };
        assert!(store.link(&stale).await.is_err());
        assert!(!mock.state.lock().await.names().contains(&stale.name()));
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
            backend.insert(invitation(name, owners));
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
        backend.insert(passkey("a", "alice", None));
        let mock = mock(backend).await;
        assert!(matches!(
            credentials(&mock).remove(&alice(), "a").await.unwrap(),
            Removal::LastPasskey
        ));
        assert_eq!(mock.state.lock().await.names(), ["a"]);
    }

    /// Two removals that both list before either writes: neither may leave the user with none.
    #[tokio::test]
    async fn interleaved_removals_keep_a_passkey() {
        for passkeys in [2, 3] {
            let mut backend = Backend::default();
            for name in ["a", "b", "c"].into_iter().take(passkeys) {
                backend.insert(passkey(name, "alice", None));
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
            let left = mock.state.lock().await.names();
            assert_eq!(left.len(), passkeys - removed);
        }
    }

    #[tokio::test]
    async fn sequential_removals_stop_at_the_last_passkey() {
        let mut backend = Backend::default();
        for name in ["a", "b", "c"] {
            backend.insert(passkey(name, "alice", None));
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
        assert_eq!(mock.state.lock().await.names(), ["c"]);
    }

    #[tokio::test]
    async fn only_linked_accounts_the_user_owns_are_listed_or_unlinked() {
        let mut backend = Backend::default();
        backend.insert(github("g-own", &[ALICE_UID]));
        backend.insert(github("g-old", &["uid-old-alice"]));
        backend.insert(github("g-none", &[]));
        backend.insert(passkey("a", "alice", Some(ALICE_UID)));
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
        assert_eq!(mock.state.lock().await.names(), ["a", "g-none", "g-old"]);
    }

    #[tokio::test]
    async fn the_last_credential_is_never_unlinked() {
        let mut backend = Backend::default();
        backend.insert(github("g", &[ALICE_UID]));
        let mock = mock(backend).await;
        assert!(matches!(
            credentials(&mock).unlink(&alice(), "g").await.unwrap(),
            Unlink::LastCredential
        ));
        assert_eq!(mock.state.lock().await.names(), ["g"]);
    }

    /// Two unlinks that both list before either writes: neither may leave the user with nothing.
    #[tokio::test]
    async fn interleaved_unlinks_keep_a_credential() {
        let mut backend = Backend::default();
        backend.insert(github("g1", &[ALICE_UID]));
        backend.insert(github("g2", &[ALICE_UID]));
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
        let left = mock.state.lock().await.names();
        assert!(matches!(left.as_slice(), [_, ..]), "{left:?}");
    }

    #[tokio::test]
    async fn a_password_is_removed_only_while_the_user_keeps_another_way_in() {
        let mut backend = Backend::default();
        backend.insert(password());
        let mock = mock(backend).await;
        let store = credentials(&mock);
        let stored = store.password(&alice()).await.unwrap().unwrap();
        assert!(matches!(
            store.remove_password(&alice(), &stored).await.unwrap(),
            PasswordRemoval::LastCredential
        ));

        mock.state.lock().await.insert(github("g", &[ALICE_UID]));
        // A version read before a sign-in changed the password's state.
        let state = PasswordState {
            totp_last_step: Some(2),
            ..PasswordState::default()
        };
        store.save_state(&stored, &state).await.unwrap();
        assert!(matches!(
            store.remove_password(&alice(), &stored).await.unwrap(),
            PasswordRemoval::Conflict
        ));
        let stored = store.password(&alice()).await.unwrap().unwrap();
        assert!(matches!(
            store.remove_password(&alice(), &stored).await.unwrap(),
            PasswordRemoval::Removed
        ));
        assert!(store.password(&alice()).await.unwrap().is_none());
        assert_eq!(mock.state.lock().await.names(), ["g"]);
    }

    /// A password removal and an unlink that both list before either writes: neither may leave
    /// the user with nothing.
    #[tokio::test]
    async fn a_password_change_from_a_stale_read_is_refused() {
        let mut backend = Backend::default();
        backend.insert(password());
        backend.insert(alice_object());
        let mock = mock(backend).await;
        let store = credentials(&mock);
        let read = store.password(&alice()).await.unwrap().unwrap();
        assert!(matches!(
            store
                .set_password(&alice(), "first", None, Some(&read))
                .await
                .unwrap(),
            Saved::Saved
        ));
        assert!(matches!(
            store
                .set_password(&alice(), "second", None, Some(&read))
                .await
                .unwrap(),
            Saved::Conflict
        ));
        let kept = store.password(&alice()).await.unwrap().unwrap();
        assert_eq!(kept.hash, "first");
    }

    #[tokio::test]
    async fn a_password_removal_racing_an_unlink_keeps_a_credential() {
        let mut backend = Backend::default();
        backend.insert(password());
        backend.insert(github("g", &[ALICE_UID]));
        backend.held = 2;
        backend.barrier = Some(Arc::new(Barrier::new(2)));
        let mock = mock(backend).await;
        let store = credentials(&mock);
        let stored = store.password(&alice()).await.unwrap().unwrap();
        let (user_a, user_b) = (alice(), alice());
        let (removal, unlink) = tokio::join!(
            store.remove_password(&user_a, &stored),
            store.unlink(&user_b, "g")
        );
        let (removal, unlink) = (removal.unwrap(), unlink.unwrap());
        assert!(
            !matches!(
                (removal, unlink),
                (PasswordRemoval::Removed, Unlink::Unlinked)
            ),
            "{removal:?} {unlink:?}"
        );
        let left = mock.state.lock().await.names();
        assert!(matches!(left.as_slice(), [_, ..]), "{left:?}");
    }

    #[tokio::test]
    async fn grants_are_listed_by_uid_and_reauthenticated_by_secret() {
        let mut backend = Backend::default();
        backend.insert(grant("s-1", Some(ALICE_UID)));
        // A grant without a recorded UID belongs to no one.
        backend.insert(grant("g-legacy", None));
        backend.insert(grant("s-old", Some("uid-old-alice")));
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
