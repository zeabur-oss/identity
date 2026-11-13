//! Setup reset retries through the Kubernetes HTTP API and the real OAuth token endpoint.

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use axum::body::Body;
    use axum::extract::State;
    use axum::http::{Method, Request, StatusCode};
    use axum::{Json, Router};
    use http_body_util::BodyExt as _;
    use kube::api::Api;
    use serde_json::{Value, json};
    use tokio::sync::Mutex;
    use tower::ServiceExt as _;
    use zeabur_identity_api::client::ClientType;
    use zeabur_identity_core::account::AccountType;
    use zeabur_identity_core::clock::{Clock as _, SystemClock};
    use zeabur_identity_core::config::BaseUrl;
    use zeabur_identity_core::crypto::Sealer;
    use zeabur_identity_k8s::grants::KubeGrantStore;
    use zeabur_identity_k8s::setup::issue_setup_link;
    use zeabur_identity_keys::Algorithm;
    use zeabur_identity_keys::manager::KeyManager;
    use zeabur_identity_keys::rotation::RotationPolicy;
    use zeabur_identity_keys::store::MemoryKeyStore;
    use zeabur_identity_oauth::endpoints::router;
    use zeabur_identity_oauth::refresh::RefreshToken;
    use zeabur_identity_oauth::{AuthorizationServer, Lifetimes, OneTimeIds};
    use zeabur_identity_store::{Client, MemoryDirectory, User};

    struct Backend {
        credentials: bool,
        invitations: bool,
        grant: Option<Value>,
        /// The collection whose next deletion fails once.
        fail: Option<&'static str>,
        /// Collections deleted, in order.
        deletes: Vec<&'static str>,
        secret_writes: usize,
        secret: Value,
    }

    async fn kubernetes(
        State(state): State<Arc<Mutex<Backend>>>,
        request: Request<Body>,
    ) -> (StatusCode, Json<Value>) {
        let method = request.method().clone();
        let path = request.uri().path().to_owned();
        let query = request.uri().query().unwrap_or_default().to_owned();
        let bytes = request.into_body().collect().await.unwrap().to_bytes();
        let mut state = state.lock().await;
        let ok = |value| (StatusCode::OK, Json(value));
        let status = |code: StatusCode, reason: &str| {
            (
                code,
                Json(
                    json!({"apiVersion":"v1", "kind":"Status", "status":"Failure",
            "code":code.as_u16(), "reason":reason, "message":reason}),
                ),
            )
        };
        match (method, path.rsplit('/').next().unwrap()) {
            (Method::GET, "alice") => ok(json!({"apiVersion":"identity.zeabur.com/v1alpha1",
            "kind":"User", "metadata":{"name":"alice","uid":"uid-alice"},
            "spec":{"username":"alice","accountType":"Admin","disabled":false}})),
            (Method::GET, "credentials") => ok(json!({"apiVersion":"identity.zeabur.com/v1alpha1",
            "kind":"CredentialList", "metadata":{}, "items":if state.credentials {
                vec![json!({"metadata":{"name":"old"},"spec":{"user":"alice",
                    "passkey":{"credentialId":"YWJj","record":"{}","backupEligible":false}}})]
            } else { vec![] }})),
            (Method::DELETE, collection @ ("invitations" | "credentials" | "grants")) => {
                assert!(query.contains("labelSelector=identity.zeabur.com%2Fuser%3Dalice"));
                let collection = match collection {
                    "invitations" => "invitations",
                    "credentials" => "credentials",
                    _ => "grants",
                };
                state.deletes.push(collection);
                if state.fail == Some(collection) {
                    state.fail = None;
                    return status(StatusCode::INTERNAL_SERVER_ERROR, "InternalError");
                }
                match collection {
                    "invitations" => state.invitations = false,
                    "credentials" => state.credentials = false,
                    _ => state.grant = None,
                }
                ok(json!({"apiVersion":"v1","kind":"Status","status":"Success"}))
            }
            (Method::GET, "zeabur-identity-setup") => ok(state.secret.clone()),
            (Method::PUT, "zeabur-identity-setup") => {
                state.secret_writes += 1;
                state.secret = serde_json::from_slice(&bytes).unwrap();
                ok(state.secret.clone())
            }
            (Method::POST, "events") => (
                StatusCode::CREATED,
                Json(serde_json::from_slice(&bytes).unwrap()),
            ),
            (Method::PUT, "status") if path.contains("/grants/") => {
                let mut grant: Value = serde_json::from_slice(&bytes).unwrap();
                grant["metadata"]["resourceVersion"] = json!("2");
                state.grant = Some(grant.clone());
                ok(grant)
            }
            (Method::GET, _) if path.contains("/grants/") => state.grant.as_ref().map_or_else(
                || status(StatusCode::NOT_FOUND, "NotFound"),
                |grant| ok(grant.clone()),
            ),
            unexpected => panic!("unexpected Kubernetes request: {unexpected:?} {path}"),
        }
    }

    async fn refresh(app: &Router, token: &str) -> (StatusCode, Value) {
        let form = form_urlencoded::Serializer::new(String::new())
            .extend_pairs([
                ("grant_type", "refresh_token"),
                ("client_id", "kubectl"),
                ("refresh_token", token),
            ])
            .finish();
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/token")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(form))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        (status, serde_json::from_slice(&bytes).unwrap())
    }

    async fn oauth_app(client: kube::Client, issuer: BaseUrl) -> Router {
        let directory = MemoryDirectory::default();
        directory.put_client(Client {
            id: "kubectl".into(),
            display_name: None,
            kind: ClientType::Public,
            redirect_uris: vec![],
            audiences: vec!["kubernetes".into()],
            secret_hash: None,
            id_token_alg: Algorithm::Es256,
            home_url: None,
        });
        directory.put_user(User {
            name: "alice".into(),
            subject: "uid-alice".into(),
            username: "alice".into(),
            display_name: None,
            groups: vec![],
            disabled: false,
            account_type: AccountType::Admin,
        });
        let keys = KeyManager::new(
            MemoryKeyStore::default(),
            SystemClock,
            RotationPolicy::DEFAULT,
        );
        keys.reconcile().await.unwrap();
        router(Arc::new(AuthorizationServer {
            issuer,
            lifetimes: Lifetimes::DEFAULT,
            directory,
            grants: KubeGrantStore::new(Api::namespaced(client, "test")),
            clock: SystemClock,
            keys: keys.subscribe(),
            sealer: Sealer::ephemeral().unwrap(),
            used_codes: OneTimeIds::default(),
            used_request_uris: OneTimeIds::default(),
        }))
    }

    async fn reset_case(credentials: bool, fail: Option<&'static str>) {
        let now = SystemClock.now();
        let name = format!("g-{}", "a".repeat(64));
        let token = RefreshToken::generate(&name).unwrap();
        let original_secret = json!({"apiVersion":"v1","kind":"Secret",
        "metadata":{"name":"zeabur-identity-setup","resourceVersion":"1"},"data":{"old":"b2xk"}});
        let state = Arc::new(Mutex::new(Backend {
            credentials,
            invitations: true,
            fail,
            deletes: Vec::new(),
            secret_writes: 0,
            secret: original_secret.clone(),
            grant: Some(
                json!({"apiVersion":"identity.zeabur.com/v1alpha1","kind":"Grant",
            "metadata":{"name":name,"resourceVersion":"1"},
            "spec":{"user":"alice","client":"kubectl","audience":"kubernetes",
                "authTime":now.as_secs(),"scopes":["openid"],"amr":["swk"],
                "expiresAt":now.as_secs()+3600,"initialIdleExpiresAt":now.as_secs()+3600,
                "initialHash":token.hash(),"subject":"uid-alice"}}),
            ),
        }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let mock = Router::new()
            .fallback(kubernetes)
            .with_state(Arc::clone(&state));
        let task = tokio::spawn(async move { axum::serve(listener, mock).await.unwrap() });
        let client = kube::Client::try_from(kube::Config::new(
            format!("http://{address}").parse().unwrap(),
        ))
        .unwrap();
        let issuer = BaseUrl::parse("issuer", "https://login.example.com").unwrap();
        let app = oauth_app(client.clone(), issuer.clone()).await;
        let (status, body) = refresh(&app, &token.encode()).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let current = body["refresh_token"].as_str().unwrap();
        if let Some(failing) = fail {
            assert!(
                issue_setup_link(
                    client.clone(),
                    "test",
                    &issuer,
                    "alice",
                    Duration::from_secs(600),
                    true,
                    now
                )
                .await
                .is_err()
            );
            let backend = state.lock().await;
            // Nothing after the failing collection is touched, and no link is written.
            let order = ["invitations", "credentials", "grants"];
            let reached = order.iter().position(|c| *c == failing).unwrap() + 1;
            assert_eq!(backend.deletes, order[..reached]);
            assert_eq!(backend.credentials, failing != "grants" && credentials);
            assert_eq!(backend.secret_writes, 0);
            assert_eq!(backend.secret, original_secret);
        }
        let link = issue_setup_link(
            client,
            "test",
            &issuer,
            "alice",
            Duration::from_secs(600),
            true,
            now,
        )
        .await
        .unwrap();
        assert!(
            link.url
                .starts_with("https://login.example.com/setup#token=")
        );
        let (status, body) = refresh(&app, current).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], "invalid_grant");
        let backend = state.lock().await;
        // Invitations go first, so none survives to enrol a passkey after the reset; a retry
        // deletes every collection again.
        let order = ["invitations", "credentials", "grants"];
        let first = fail.map_or(0, |failing| {
            order.iter().position(|c| *c == failing).unwrap() + 1
        });
        assert_eq!(backend.deletes[..first], order[..first]);
        assert_eq!(backend.deletes[first..], order);
        assert!(!backend.invitations && !backend.credentials);
        assert_eq!(backend.secret_writes, 1);
        task.abort();
    }

    #[tokio::test]
    async fn reset_retries_grant_deletion_after_credentials_are_gone() {
        reset_case(true, Some("grants")).await;
    }

    #[tokio::test]
    async fn reset_revokes_old_grants_without_credentials() {
        reset_case(false, None).await;
    }

    #[tokio::test]
    async fn reset_revokes_invitations_before_anything_else() {
        reset_case(true, Some("invitations")).await;
    }
}
