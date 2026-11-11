//! End-to-end tests of the authorization server through its HTTP router, with in-memory storage
//! and a controllable clock.

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

    use axum::Router;
    use axum::body::Body;
    use axum::http::{HeaderMap, Method, Request, StatusCode, header};
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;
    use http_body_util::BodyExt as _;
    use jsonwebtoken::jwk::JwkSet;
    use jsonwebtoken::{DecodingKey, Validation, decode, decode_header};
    use serde_json::Value;
    use tokio::sync::Barrier;
    use tower::ServiceExt as _;
    use tracing::instrument::WithSubscriber as _;
    use zeabur_identity_api::client::ClientType;
    use zeabur_identity_api::{ADMIN_GROUP, token_hash};
    use zeabur_identity_core::account::{AccountType, Settings, Teams};
    use zeabur_identity_core::clock::{Clock, UnixTime};
    use zeabur_identity_core::config::BaseUrl;
    use zeabur_identity_core::crypto::Sealer;
    use zeabur_identity_keys::Algorithm;
    use zeabur_identity_keys::manager::{KeyManager, Published};
    use zeabur_identity_keys::rotation::RotationPolicy;
    use zeabur_identity_keys::store::MemoryKeyStore;
    use zeabur_identity_oauth::authorize::Authentication;
    use zeabur_identity_oauth::endpoints::{FLOW_COOKIE, complete_authorization, router};
    use zeabur_identity_oauth::{AuthorizationServer, Lifetimes, OneTimeIds};
    use zeabur_identity_store::{
        Client, CreateGrant, Directory as _, Grant, GrantStore, MemoryDirectory, MemoryGrantStore,
        NewGrant, Rotation, StoreError, User, Verification,
    };
    use zeabur_identity_test_support::logging::Capture;

    const ISSUER: &str = "https://login.example.com";
    const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    const KUBECTL_REDIRECT: &str = "http://127.0.0.1:8000/callback";
    const WEB_SECRET: &str = "a-long-random-client-secret-for-tests-only";
    const START: u64 = 1_800_000_000;

    #[derive(Debug, Clone, Default)]
    struct TestClock(Arc<AtomicU64>);

    impl Clock for TestClock {
        fn now(&self) -> UnixTime {
            UnixTime::from_secs(self.0.load(Ordering::SeqCst))
        }
    }

    impl TestClock {
        fn advance(&self, secs: u64) {
            self.0.fetch_add(secs, Ordering::SeqCst);
        }
    }

    #[derive(Default)]
    struct TestGrantStore {
        memory: MemoryGrantStore,
        fail_revoke: AtomicBool,
    }

    impl GrantStore for TestGrantStore {
        async fn create(
            &self,
            grant: &NewGrant,
            idle: UnixTime,
        ) -> Result<CreateGrant, StoreError> {
            self.memory.create(grant, idle).await
        }

        async fn get(&self, name: &str) -> Result<Option<Grant>, StoreError> {
            self.memory.get(name).await
        }

        async fn rotate(
            &self,
            name: &str,
            presented: &str,
            next: &str,
            now: UnixTime,
            idle: UnixTime,
        ) -> Result<Rotation, StoreError> {
            self.memory.rotate(name, presented, next, now, idle).await
        }

        async fn revoke(&self, name: &str) -> Result<(), StoreError> {
            if self.fail_revoke.load(Ordering::SeqCst) {
                Err(StoreError("oauth-storage-secret-sentinel".into()))
            } else {
                self.memory.revoke(name).await
            }
        }

        async fn list(&self, user: &User) -> Result<Vec<Grant>, StoreError> {
            self.memory.list(user).await
        }

        async fn reauthenticate(
            &self,
            name: &str,
            current_hash: &str,
            verification: &Verification,
        ) -> Result<bool, StoreError> {
            self.memory
                .reauthenticate(name, current_hash, verification)
                .await
        }
    }

    type Server = AuthorizationServer<MemoryDirectory, TestGrantStore, TestClock>;

    struct Harness {
        server: Arc<Server>,
        app: Router,
        clock: TestClock,
        jwks: JwkSet,
        capture: Capture,
        keys_sender: tokio::sync::watch::Sender<Option<Arc<Published>>>,
    }

    async fn harness() -> Harness {
        harness_with(Lifetimes::DEFAULT).await
    }

    async fn harness_with(lifetimes: Lifetimes) -> Harness {
        let clock = TestClock::default();
        clock.0.store(START, Ordering::SeqCst);
        let manager = KeyManager::new(
            MemoryKeyStore::default(),
            clock.clone(),
            RotationPolicy::DEFAULT,
        );
        manager.reconcile().await.unwrap();
        let keys = manager.subscribe();
        let jwks: JwkSet = serde_json::from_slice(&keys.borrow().clone().unwrap().jwks()).unwrap();
        let (keys_sender, keys) = tokio::sync::watch::channel(keys.borrow().clone());

        let directory = MemoryDirectory::default();
        directory.put_client(Client {
            id: "kubectl".into(),
            display_name: None,
            kind: ClientType::Public,
            redirect_uris: vec![KUBECTL_REDIRECT.into()],
            audiences: vec!["kubernetes".into()],
            secret_hash: None,
            id_token_alg: Algorithm::Es256,
            home_url: None,
        });
        directory.put_client(Client {
            id: "web".into(),
            display_name: Some("Web".into()),
            kind: ClientType::Confidential,
            redirect_uris: vec!["https://app.example.com/cb".into()],
            audiences: vec![],
            secret_hash: Some(token_hash(WEB_SECRET.as_bytes())),
            id_token_alg: Algorithm::Rs256,
            home_url: None,
        });
        for (name, disabled, account_type) in [
            ("alice", false, AccountType::Regular),
            ("bob", true, AccountType::Regular),
            ("carol", false, AccountType::Admin),
        ] {
            directory.put_user(User {
                name: name.into(),
                subject: format!("uid-{name}"),
                username: name.into(),
                display_name: Some(format!("{name} example")),
                groups: vec!["developers".into()],
                disabled,
                account_type,
            });
        }
        let server = Arc::new(AuthorizationServer {
            issuer: BaseUrl::parse("issuer", ISSUER).unwrap(),
            lifetimes,
            directory,
            grants: TestGrantStore::default(),
            clock: clock.clone(),
            keys,
            sealer: Sealer::ephemeral().unwrap(),
            used_codes: OneTimeIds::default(),
            used_request_uris: OneTimeIds::default(),
        });
        let capture = Capture::new();
        let dispatch = capture.dispatch();
        let app = router(Arc::clone(&server)).layer(axum::middleware::from_fn(
            move |request: Request<Body>, next: axum::middleware::Next| {
                next.run(request).with_subscriber(dispatch.clone())
            },
        ));
        Harness {
            server,
            app,
            clock,
            jwks,
            capture,
            keys_sender,
        }
    }

    struct Reply {
        status: StatusCode,
        headers: HeaderMap,
        body: Vec<u8>,
    }

    impl Reply {
        fn json(&self) -> Value {
            serde_json::from_slice(&self.body).unwrap()
        }
        fn location(&self) -> String {
            self.headers[header::LOCATION].to_str().unwrap().to_owned()
        }
        fn error(&self) -> String {
            self.json()["error"].as_str().unwrap().to_owned()
        }
    }

    async fn send(app: &Router, request: Request<Body>) -> Reply {
        let response = app.clone().oneshot(request).await.unwrap();
        let (parts, body) = response.into_parts();
        Reply {
            status: parts.status,
            headers: parts.headers,
            body: body.collect().await.unwrap().to_bytes().to_vec(),
        }
    }

    async fn get(app: &Router, uri: &str) -> Reply {
        send(
            app,
            Request::builder().uri(uri).body(Body::empty()).unwrap(),
        )
        .await
    }

    async fn post(
        app: &Router,
        path: &str,
        form: &[(&str, &str)],
        basic: Option<(&str, &str)>,
    ) -> Reply {
        let body = form_urlencoded::Serializer::new(String::new())
            .extend_pairs(form)
            .finish();
        let mut request = Request::builder()
            .method(Method::POST)
            .uri(path)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
        if let Some((id, secret)) = basic {
            request = request.header(
                header::AUTHORIZATION,
                format!("Basic {}", STANDARD.encode(format!("{id}:{secret}"))),
            );
        }
        send(app, request.body(Body::from(body)).unwrap()).await
    }

    fn query(pairs: &[(&str, &str)]) -> String {
        form_urlencoded::Serializer::new(String::new())
            .extend_pairs(pairs)
            .finish()
    }

    fn kubectl_authorize(extra: &[(&str, &str)]) -> String {
        let mut pairs = vec![
            ("client_id", "kubectl"),
            ("redirect_uri", KUBECTL_REDIRECT),
            ("response_type", "code"),
            ("scope", "openid profile groups"),
            ("state", "state-1"),
            ("nonce", "nonce-1"),
            ("code_challenge", CHALLENGE),
            ("code_challenge_method", "S256"),
        ];
        pairs.extend_from_slice(extra);
        format!("/authorize?{}", query(&pairs))
    }

    fn flow_cookie(reply: &Reply) -> String {
        let cookie = reply.headers[header::SET_COOKIE].to_str().unwrap();
        cookie
            .strip_prefix(&format!("{FLOW_COOKIE}="))
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned()
    }

    fn param(location: &str, name: &str) -> Option<String> {
        let (_, query) = location.split_once('?')?;
        form_urlencoded::parse(query.as_bytes())
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.into_owned())
    }

    /// Runs `/authorize` and the sign-in for `user`, and returns the code.
    async fn sign_in(h: &Harness, user: &str, authorize_uri: &str) -> String {
        sign_in_with(h, user, authorize_uri, &["hwk", "user"]).await
    }

    /// [`sign_in`] with the given authentication methods.
    async fn sign_in_with(h: &Harness, user: &str, authorize_uri: &str, amr: &[&str]) -> String {
        sign_in_as(h, user, authorize_uri, amr, false).await
    }

    /// [`sign_in_with`], with a device-bound passkey if `device_bound`.
    async fn sign_in_as(
        h: &Harness,
        user: &str,
        authorize_uri: &str,
        amr: &[&str],
        device_bound: bool,
    ) -> String {
        let reply = get(&h.app, authorize_uri).await;
        assert_eq!(
            reply.status,
            StatusCode::SEE_OTHER,
            "{}",
            String::from_utf8_lossy(&reply.body)
        );
        let auth = Authentication {
            user: user.into(),
            subject: format!("uid-{user}"),
            auth_time: h.clock.now(),
            amr: amr.iter().map(|m| (*m).to_owned()).collect(),
            credential: None,
            user_verified: false,
            device_bound,
        };
        let location = complete_authorization(&h.server, &flow_cookie(&reply), auth).unwrap();
        param(&location, "code").unwrap()
    }

    async fn exchange(h: &Harness, code: &str) -> Reply {
        post(
            &h.app,
            "/token",
            &[
                ("grant_type", "authorization_code"),
                ("code", code),
                ("redirect_uri", KUBECTL_REDIRECT),
                ("code_verifier", VERIFIER),
                ("client_id", "kubectl"),
            ],
            None,
        )
        .await
    }

    async fn refresh(h: &Harness, token: &str) -> Reply {
        post(
            &h.app,
            "/token",
            &[
                ("grant_type", "refresh_token"),
                ("refresh_token", token),
                ("client_id", "kubectl"),
            ],
            None,
        )
        .await
    }

    fn verify(h: &Harness, token: &str, audience: &str) -> (jsonwebtoken::Header, Value) {
        let header = decode_header(token).unwrap();
        let jwk = h.jwks.find(header.kid.as_deref().unwrap()).unwrap();
        let mut validation = Validation::new(header.alg);
        validation.set_audience(&[audience]);
        validation.set_issuer(&[ISSUER]);
        validation.validate_exp = false;
        let data =
            decode::<Value>(token, &DecodingKey::from_jwk(jwk).unwrap(), &validation).unwrap();
        (header, data.claims)
    }

    fn audit_outcomes(h: &Harness, event: &str, outcomes: &[&str]) -> Vec<Value> {
        let records: Vec<_> = h
            .capture
            .records()
            .into_iter()
            .filter(|record| {
                record["target"] == "zeabur_identity::audit" && record["fields"]["event"] == event
            })
            .collect();
        assert_eq!(records.len(), outcomes.len(), "{records:#?}");
        for (record, outcome) in records.iter().zip(outcomes) {
            assert_eq!(record["fields"]["outcome"], *outcome, "{record:#?}");
            if *outcome == "success" && matches!(event, "oauth.code_exchange" | "oauth.refresh") {
                assert_eq!(record["fields"]["user"], "alice");
                assert_eq!(record["fields"]["subject"], "uid-alice");
                assert_eq!(record["fields"]["client"], "kubectl");
            }
        }
        assert!(
            h.capture
                .records()
                .iter()
                .all(|record| { record["fields"]["event"] != "auth.sign_in" }),
            "OAuth operations are not fresh sign-ins"
        );
        records
    }

    fn assert_no_secrets(h: &Harness, secrets: &[&str]) {
        let audit: Vec<_> = h
            .capture
            .records()
            .into_iter()
            .filter(|record| record["target"] == "zeabur_identity::audit")
            .collect();
        assert!(
            !audit.is_empty(),
            "secret exclusion requires captured audit records"
        );
        for record in &audit {
            assert!(record.get("span").is_none());
            assert!(record.get("spans").is_none());
        }
        let serialized = serde_json::to_string(&audit).unwrap();
        for secret in secrets.iter().copied().chain([
            VERIFIER,
            CHALLENGE,
            WEB_SECRET,
            "state-1",
            "nonce-1",
            "oauth-storage-secret-sentinel",
        ]) {
            assert!(
                !serialized.contains(secret),
                "audit records contain secret: {secret}"
            );
        }
        assert!(!serialized.contains(&STANDARD.encode(format!("web:{WEB_SECRET}"))));
    }

    #[tokio::test]
    async fn code_flow_issues_tokens_kubernetes_can_use() {
        let h = harness().await;
        let reply = get(&h.app, &kubectl_authorize(&[])).await;
        assert_eq!(reply.status, StatusCode::SEE_OTHER);
        assert_eq!(reply.location(), "/login");
        let cookie = reply.headers[header::SET_COOKIE].to_str().unwrap();
        for attribute in ["Path=/", "Secure", "HttpOnly", "SameSite=Lax"] {
            assert!(cookie.contains(attribute), "{cookie}");
        }

        let auth = Authentication {
            user: "alice".into(),
            subject: "uid-alice".into(),
            auth_time: h.clock.now(),
            amr: vec!["hwk".into(), "user".into()],
            credential: None,
            user_verified: false,
            device_bound: false,
        };
        let location = complete_authorization(&h.server, &flow_cookie(&reply), auth).unwrap();
        assert!(location.starts_with(KUBECTL_REDIRECT));
        assert_eq!(param(&location, "state").as_deref(), Some("state-1"));
        assert_eq!(param(&location, "iss").as_deref(), Some(ISSUER), "RFC 9207");
        let code = param(&location, "code").unwrap();
        let flow = flow_cookie(&reply);

        let reply = exchange(&h, &code).await;
        assert_eq!(reply.status, StatusCode::OK);
        assert_eq!(reply.headers[header::CACHE_CONTROL], "no-store");
        let body = reply.json();
        assert_eq!(body["token_type"], "Bearer");
        assert_eq!(body["expires_in"], 600);
        assert_eq!(body["scope"], "openid profile groups");

        let (header, at) = verify(&h, body["access_token"].as_str().unwrap(), "kubernetes");
        assert_eq!(header.typ.as_deref(), Some("at+jwt"));
        assert_eq!(header.alg, jsonwebtoken::Algorithm::ES256);
        assert_eq!(at["client_id"], "kubectl");
        assert_eq!(at["sub"], "uid-alice");
        assert_eq!(at["preferred_username"], "alice");
        assert_eq!(at["groups"], serde_json::json!(["developers"]));
        assert_eq!(
            at["exp"].as_u64().unwrap() - at["iat"].as_u64().unwrap(),
            600
        );
        assert!(at.get("azp").is_none() && at.get("nonce").is_none());

        let (header, id) = verify(&h, body["id_token"].as_str().unwrap(), "kubectl");
        assert_eq!(header.typ.as_deref(), Some("JWT"));
        assert_eq!(id["azp"], "kubectl");
        assert_eq!(id["nonce"], "nonce-1");
        assert_eq!(id["auth_time"], START);
        assert_eq!(id["name"], "alice example");
        assert!(
            id.get("client_id").is_none(),
            "ID tokens never look like access tokens"
        );
        audit_outcomes(&h, "oauth.code_exchange", &["success"]);
        assert_no_secrets(
            &h,
            &[
                &code,
                &flow,
                body["access_token"].as_str().unwrap(),
                body["id_token"].as_str().unwrap(),
                body["refresh_token"].as_str().unwrap(),
            ],
        );
    }

    #[expect(
        clippy::too_many_lines,
        reason = "exercise both client authentication methods, challenges and secret exclusion in one scenario"
    )]
    #[tokio::test]
    async fn confidential_client_gets_rs256_id_tokens_and_must_authenticate() {
        let h = harness().await;
        let authorize = format!(
            "/authorize?{}",
            query(&[
                ("client_id", "web"),
                ("redirect_uri", "https://app.example.com/cb"),
                ("response_type", "code"),
                ("scope", "openid"),
                ("code_challenge", CHALLENGE),
                ("code_challenge_method", "S256"),
            ])
        );
        let form = |code: &str| {
            vec![
                ("grant_type", "authorization_code".to_owned()),
                ("code", code.to_owned()),
                ("code_verifier", VERIFIER.to_owned()),
            ]
        };
        let as_refs = |pairs: &[(&'static str, String)]| {
            pairs
                .iter()
                .map(|(k, v)| (*k, v.clone()))
                .collect::<Vec<_>>()
        };

        // Wrong secret over Basic: 401 with a Basic challenge.
        let code = sign_in(&h, "alice", &authorize).await;
        let pairs = as_refs(&form(&code));
        let first_code = code.clone();
        let pairs: Vec<(&str, &str)> = pairs.iter().map(|(k, v)| (*k, v.as_str())).collect();
        let reply = post(&h.app, "/token", &pairs, Some(("web", "wrong"))).await;
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
        assert_eq!(reply.error(), "invalid_client");
        assert!(
            reply.headers[header::WWW_AUTHENTICATE]
                .to_str()
                .unwrap()
                .starts_with("Basic")
        );

        // Two methods at once.
        let mut both = pairs.clone();
        both.push(("client_secret", WEB_SECRET));
        let reply = post(&h.app, "/token", &both, Some(("web", WEB_SECRET))).await;
        assert_eq!(reply.error(), "invalid_request");

        // No credentials at all for a confidential client.
        let mut none = pairs.clone();
        none.push(("client_id", "web"));
        assert_eq!(
            post(&h.app, "/token", &none, None).await.error(),
            "invalid_client"
        );

        // client_secret_basic works; the ID token is RS256 as registered.
        let reply = post(&h.app, "/token", &pairs, Some(("web", WEB_SECRET))).await;
        assert_eq!(reply.status, StatusCode::OK);
        let basic_tokens = reply.json();
        let (header, id) = verify(&h, reply.json()["id_token"].as_str().unwrap(), "web");
        assert_eq!(header.alg, jsonwebtoken::Algorithm::RS256);
        assert!(
            id.get("name").is_none(),
            "no profile scope, no profile claims"
        );
        let (_, at) = verify(&h, reply.json()["access_token"].as_str().unwrap(), "web");
        assert_eq!(
            at["aud"], "web",
            "a client without audiences gets itself as audience"
        );

        // client_secret_post works too.
        let code = sign_in(&h, "alice", &authorize).await;
        let pairs = as_refs(&form(&code));
        let mut pairs: Vec<(&str, &str)> = pairs.iter().map(|(k, v)| (*k, v.as_str())).collect();
        pairs.extend([("client_id", "web"), ("client_secret", WEB_SECRET)]);
        let reply = post(&h.app, "/token", &pairs, None).await;
        assert_eq!(reply.status, StatusCode::OK);
        let post_tokens = reply.json();

        // A public client must not send a secret; unknown clients are rejected.
        let reply = post(
            &h.app,
            "/token",
            &[("grant_type", "refresh_token"), ("refresh_token", "x")],
            Some(("kubectl", "s")),
        )
        .await;
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
        let reply = post(
            &h.app,
            "/token",
            &[("grant_type", "refresh_token"), ("client_id", "nobody")],
            None,
        )
        .await;
        assert_eq!(reply.error(), "invalid_client");
        let events: Vec<_> = h
            .capture
            .records()
            .into_iter()
            .filter(|record| {
                record["target"] == "zeabur_identity::audit"
                    && record["fields"]["event"] == "oauth.code_exchange"
            })
            .collect();
        assert_eq!(events.len(), 5);
        for (event, outcome) in events
            .iter()
            .zip(["failure", "failure", "failure", "success", "success"])
        {
            assert_eq!(event["fields"]["outcome"], outcome);
            if outcome == "success" {
                assert_eq!(event["fields"]["client"], "web");
                assert_eq!(event["fields"]["user"], "alice");
                assert_eq!(event["fields"]["subject"], "uid-alice");
            } else {
                for identity in ["client", "user", "subject"] {
                    assert!(event["fields"].get(identity).is_none());
                }
            }
        }
        let failed_refresh = audit_outcomes(&h, "oauth.refresh", &["failure", "failure"]);
        assert!(
            failed_refresh
                .iter()
                .all(|record| record["fields"].get("client").is_none())
        );
        assert_no_secrets(
            &h,
            &[
                &first_code,
                &code,
                &STANDARD.encode("web:wrong"),
                "nobody",
                basic_tokens["access_token"].as_str().unwrap(),
                basic_tokens["id_token"].as_str().unwrap(),
                basic_tokens["refresh_token"].as_str().unwrap(),
                post_tokens["access_token"].as_str().unwrap(),
                post_tokens["id_token"].as_str().unwrap(),
                post_tokens["refresh_token"].as_str().unwrap(),
            ],
        );
    }

    #[tokio::test]
    async fn code_is_single_use_and_reuse_revokes_what_it_issued() {
        let h = harness().await;
        let code = sign_in(&h, "alice", &kubectl_authorize(&[])).await;
        let first = exchange(&h, &code).await;
        assert_eq!(first.status, StatusCode::OK);
        let refresh_token = first.json()["refresh_token"].as_str().unwrap().to_owned();

        let second = exchange(&h, &code).await;
        assert_eq!(second.status, StatusCode::BAD_REQUEST);
        assert_eq!(second.error(), "invalid_grant");
        // RFC 6749 §4.1.2: tokens issued from the reused code are revoked.
        assert_eq!(refresh(&h, &refresh_token).await.error(), "invalid_grant");
        audit_outcomes(&h, "oauth.code_exchange", &["success", "failure"]);
        audit_outcomes(&h, "oauth.refresh", &["failure"]);
        let replay = audit_outcomes(&h, "oauth.replay", &["failure"]);
        assert_eq!(replay[0]["fields"]["reason"], "code_reused");
        assert_eq!(replay[0]["fields"]["client"], "kubectl");
        assert!(replay[0]["fields"].get("user").is_none());
        assert_no_secrets(
            &h,
            &[
                &code,
                &refresh_token,
                first.json()["access_token"].as_str().unwrap(),
                first.json()["id_token"].as_str().unwrap(),
            ],
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn exactly_one_concurrent_redemption_succeeds() {
        let h = Arc::new(harness().await);
        let code = sign_in(&h, "alice", &kubectl_authorize(&[])).await;
        let barrier = Arc::new(Barrier::new(64));
        let tasks: Vec<_> = (0..64)
            .map(|_| {
                let (h, code, barrier) = (Arc::clone(&h), code.clone(), Arc::clone(&barrier));
                tokio::spawn(async move {
                    barrier.wait().await;
                    exchange(&h, &code).await.status
                })
            })
            .collect();
        let mut ok = 0;
        for task in tasks {
            if task.await.unwrap() == StatusCode::OK {
                ok += 1;
            }
        }
        assert_eq!(ok, 1);
    }

    #[tokio::test]
    async fn pkce_and_code_binding_are_enforced() {
        let h = harness().await;
        let code = sign_in(&h, "alice", &kubectl_authorize(&[])).await;
        let base = [
            ("grant_type", "authorization_code"),
            ("code", code.as_str()),
            ("client_id", "kubectl"),
        ];

        let wrong = [
            &base[..],
            &[(
                "code_verifier",
                "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXl",
            )],
        ]
        .concat();
        assert_eq!(
            post(&h.app, "/token", &wrong, None).await.error(),
            "invalid_grant"
        );
        assert_eq!(
            post(&h.app, "/token", &base, None).await.error(),
            "invalid_grant",
            "verifier required"
        );
        let other_redirect = [
            &base[..],
            &[
                ("code_verifier", VERIFIER),
                ("redirect_uri", "http://127.0.0.1:9/x"),
            ],
        ]
        .concat();
        assert_eq!(
            post(&h.app, "/token", &other_redirect, None).await.error(),
            "invalid_grant"
        );

        // Failed attempts did not consume the code: the legitimate client still succeeds.
        assert_eq!(exchange(&h, &code).await.status, StatusCode::OK);

        // Codes expire after 60 seconds.
        let late = sign_in(&h, "alice", &kubectl_authorize(&[])).await;
        h.clock.advance(61);
        assert_eq!(exchange(&h, &late).await.error(), "invalid_grant");

        // A code issued to one client is useless to another.
        let code = sign_in(&h, "alice", &kubectl_authorize(&[])).await;
        let reply = post(
            &h.app,
            "/token",
            &[
                ("grant_type", "authorization_code"),
                ("code", &code),
                ("code_verifier", VERIFIER),
            ],
            Some(("web", WEB_SECRET)),
        )
        .await;
        assert_eq!(reply.error(), "invalid_grant");
        assert_eq!(exchange(&h, "not-a-code").await.error(), "invalid_grant");
        let events = audit_outcomes(
            &h,
            "oauth.code_exchange",
            &[
                "failure", "failure", "failure", "success", "failure", "failure", "failure",
            ],
        );
        assert_eq!(events[5]["fields"]["client"], "web");
        let binding = audit_outcomes(&h, "oauth.client_binding", &["failure"]);
        assert_eq!(binding[0]["fields"]["reason"], "client_mismatch");
        assert_eq!(binding[0]["fields"]["client"], "web");
        assert!(binding[0]["fields"].get("user").is_none());
        assert_no_secrets(&h, &[&code, &late]);
    }

    #[tokio::test]
    async fn refresh_rotates_and_reuse_revokes_the_family() {
        let h = harness().await;
        let code = sign_in(&h, "alice", &kubectl_authorize(&[])).await;
        let issued = exchange(&h, &code).await.json();
        let first = issued["refresh_token"].as_str().unwrap().to_owned();

        h.clock.advance(300);
        let reply = refresh(&h, &first).await;
        assert_eq!(reply.status, StatusCode::OK);
        assert_eq!(reply.headers[header::CACHE_CONTROL], "no-store");
        let second = reply.json()["refresh_token"].as_str().unwrap().to_owned();
        assert_ne!(first, second);
        let (_, id) = verify(&h, reply.json()["id_token"].as_str().unwrap(), "kubectl");
        assert_eq!(id["auth_time"], START, "auth_time is the original sign-in");
        assert!(id.get("nonce").is_none());

        let rotated = refresh(&h, &second).await.json();
        let third = rotated["refresh_token"].as_str().unwrap().to_owned();
        // Someone replays the second token (already rotated): the whole family dies.
        assert_eq!(refresh(&h, &second).await.error(), "invalid_grant");
        assert_eq!(refresh(&h, &third).await.error(), "invalid_grant");
        audit_outcomes(&h, "oauth.code_exchange", &["success"]);
        audit_outcomes(
            &h,
            "oauth.refresh",
            &["success", "success", "failure", "failure"],
        );
        let detection = audit_outcomes(&h, "oauth.replay", &["failure"]);
        assert_eq!(detection[0]["fields"]["reason"], "refresh_reused");
        assert_eq!(detection[0]["fields"]["client"], "kubectl");
        assert_no_secrets(
            &h,
            &[
                &code,
                &first,
                &second,
                &third,
                reply.json()["access_token"].as_str().unwrap(),
                reply.json()["id_token"].as_str().unwrap(),
                issued["access_token"].as_str().unwrap(),
                issued["id_token"].as_str().unwrap(),
                rotated["access_token"].as_str().unwrap(),
                rotated["id_token"].as_str().unwrap(),
            ],
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn concurrent_reuse_of_a_refresh_token_revokes_the_family() {
        let h = Arc::new(harness().await);
        let code = sign_in(&h, "alice", &kubectl_authorize(&[])).await;
        let token = exchange(&h, &code).await.json()["refresh_token"]
            .as_str()
            .unwrap()
            .to_owned();
        let barrier = Arc::new(Barrier::new(64));
        let tasks: Vec<_> = (0..64)
            .map(|_| {
                let (h, token, barrier) = (Arc::clone(&h), token.clone(), Arc::clone(&barrier));
                tokio::spawn(async move {
                    barrier.wait().await;
                    let reply = refresh(&h, &token).await;
                    (reply.status == StatusCode::OK)
                        .then(|| reply.json()["refresh_token"].as_str().unwrap().to_owned())
                })
            })
            .collect();
        let mut winners = Vec::new();
        for task in tasks {
            winners.extend(task.await.unwrap());
        }
        assert!(winners.len() <= 1, "at most one rotation succeeds");
        // The losers presented an already-rotated token, which revokes the family, including the
        // winner's new token.
        for winner in winners {
            assert_eq!(refresh(&h, &winner).await.error(), "invalid_grant");
        }
    }

    #[tokio::test]
    async fn refresh_rechecks_user_scope_and_lifetime() {
        let h = harness().await;
        let token = exchange(&h, &sign_in(&h, "alice", &kubectl_authorize(&[])).await)
            .await
            .json()["refresh_token"]
            .as_str()
            .unwrap()
            .to_owned();

        let reply = post(
            &h.app,
            "/token",
            &[
                ("grant_type", "refresh_token"),
                ("refresh_token", &token),
                ("client_id", "kubectl"),
                ("scope", "openid offline_access"),
            ],
            None,
        )
        .await;
        assert_eq!(
            reply.error(),
            "invalid_scope",
            "refresh cannot widen the scope"
        );
        let reply = post(
            &h.app,
            "/token",
            &[
                ("grant_type", "refresh_token"),
                ("refresh_token", &token),
                ("client_id", "kubectl"),
                ("scope", "openid"),
            ],
            None,
        )
        .await;
        assert_eq!(reply.status, StatusCode::OK);
        assert_eq!(reply.json()["scope"], "openid");
        let token = reply.json()["refresh_token"].as_str().unwrap().to_owned();

        // Another client presenting it kills the family.
        let reply = post(
            &h.app,
            "/token",
            &[("grant_type", "refresh_token"), ("refresh_token", &token)],
            Some(("web", WEB_SECRET)),
        )
        .await;
        assert_eq!(reply.error(), "invalid_grant");
        assert_eq!(refresh(&h, &token).await.error(), "invalid_grant");

        // A deleted user gets nothing more.
        let token = exchange(&h, &sign_in(&h, "alice", &kubectl_authorize(&[])).await)
            .await
            .json()["refresh_token"]
            .as_str()
            .unwrap()
            .to_owned();
        h.server.directory.remove_user("alice");
        assert_eq!(refresh(&h, &token).await.error(), "invalid_grant");

        // A disabled user cannot redeem a code.
        let code = sign_in(&h, "bob", &kubectl_authorize(&[])).await;
        assert_eq!(exchange(&h, &code).await.error(), "invalid_grant");
    }

    #[tokio::test]
    async fn refresh_families_expire() {
        let h = harness().await;
        let token = exchange(&h, &sign_in(&h, "alice", &kubectl_authorize(&[])).await)
            .await
            .json()["refresh_token"]
            .as_str()
            .unwrap()
            .to_owned();
        h.clock.advance(3600);
        assert_eq!(
            refresh(&h, &token).await.error(),
            "invalid_grant",
            "idle lifetime"
        );

        // Even an active family ends at the absolute lifetime.
        let mut token = exchange(&h, &sign_in(&h, "alice", &kubectl_authorize(&[])).await)
            .await
            .json()["refresh_token"]
            .as_str()
            .unwrap()
            .to_owned();
        for _ in 0..14 {
            h.clock.advance(50 * 60);
            let reply = refresh(&h, &token).await;
            assert_eq!(reply.status, StatusCode::OK);
            token = reply.json()["refresh_token"].as_str().unwrap().to_owned();
        }
        h.clock.advance(50 * 60);
        assert_eq!(
            refresh(&h, &token).await.error(),
            "invalid_grant",
            "absolute lifetime"
        );
    }

    #[tokio::test]
    async fn authorization_endpoint_errors() {
        let h = harness().await;
        // Untrusted client or redirect URI: never redirected.
        let reply = get(
            &h.app,
            &format!(
                "/authorize?{}",
                query(&[("client_id", "nobody"), ("redirect_uri", KUBECTL_REDIRECT)])
            ),
        )
        .await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST);
        let reply = get(
            &h.app,
            &format!(
                "/authorize?{}",
                query(&[
                    ("client_id", "kubectl"),
                    ("redirect_uri", "https://evil.example/")
                ])
            ),
        )
        .await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST);
        assert!(reply.headers.get(header::LOCATION).is_none());
        // Repeated parameters.
        assert_eq!(
            get(&h.app, &format!("{}&state=again", kubectl_authorize(&[])))
                .await
                .status,
            StatusCode::BAD_REQUEST
        );

        // Other errors go back to the client with state and iss.
        let reply = get(&h.app, &kubectl_authorize(&[("prompt", "none")])).await;
        assert_eq!(reply.status, StatusCode::SEE_OTHER);
        let location = reply.location();
        assert!(location.starts_with(KUBECTL_REDIRECT));
        assert_eq!(param(&location, "error").as_deref(), Some("login_required"));
        assert_eq!(param(&location, "state").as_deref(), Some("state-1"));
        assert_eq!(param(&location, "iss").as_deref(), Some(ISSUER));
        let reply = get(
            &h.app,
            &kubectl_authorize(&[("resource", "https://other.example")]),
        )
        .await;
        assert_eq!(
            param(&reply.location(), "error").as_deref(),
            Some("invalid_target")
        );

        // A forged or expired flow cannot be completed.
        let auth = Authentication {
            user: "alice".into(),
            subject: "uid-alice".into(),
            auth_time: h.clock.now(),
            amr: vec![],
            credential: None,
            user_verified: false,
            device_bound: false,
        };
        assert!(complete_authorization(&h.server, "forged", auth.clone()).is_err());
        let reply = get(&h.app, &kubectl_authorize(&[])).await;
        h.clock.advance(601);
        assert!(complete_authorization(&h.server, &flow_cookie(&reply), auth).is_err());
    }

    #[tokio::test]
    async fn authorization_endpoint_accepts_post() {
        let h = harness().await;
        let form = kubectl_authorize(&[]);
        let form = form.strip_prefix("/authorize?").unwrap();
        let pairs: Vec<(String, String)> = form_urlencoded::parse(form.as_bytes())
            .into_owned()
            .collect();
        let pairs: Vec<(&str, &str)> = pairs
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        let reply = post(&h.app, "/authorize", &pairs, None).await;
        assert_eq!(reply.status, StatusCode::SEE_OTHER);
        assert_eq!(reply.location(), "/login");
    }

    #[tokio::test]
    async fn pushed_authorization_requests() {
        let h = harness().await;
        let pushed = [
            ("client_id", "kubectl"),
            ("redirect_uri", KUBECTL_REDIRECT),
            ("response_type", "code"),
            ("scope", "openid"),
            ("state", "pushed"),
            ("code_challenge", CHALLENGE),
            ("code_challenge_method", "S256"),
        ];
        let reply = post(&h.app, "/par", &pushed, None).await;
        assert_eq!(reply.status, StatusCode::CREATED);
        assert_eq!(reply.headers[header::CACHE_CONTROL], "no-store");
        let request_uri = reply.json()["request_uri"].as_str().unwrap().to_owned();
        assert!(request_uri.starts_with("urn:ietf:params:oauth:request_uri:"));
        assert_eq!(reply.json()["expires_in"], 60);

        let authorize = |client: &str| {
            format!(
                "/authorize?{}",
                query(&[("client_id", client), ("request_uri", &request_uri)])
            )
        };
        assert_eq!(
            get(&h.app, &authorize("web")).await.status,
            StatusCode::BAD_REQUEST,
            "bound to the client"
        );
        let reply = get(&h.app, &authorize("kubectl")).await;
        assert_eq!(reply.status, StatusCode::SEE_OTHER);
        let auth = Authentication {
            user: "alice".into(),
            subject: "uid-alice".into(),
            auth_time: h.clock.now(),
            amr: vec![],
            credential: None,
            user_verified: false,
            device_bound: false,
        };
        let location = complete_authorization(&h.server, &flow_cookie(&reply), auth).unwrap();
        assert_eq!(param(&location, "state").as_deref(), Some("pushed"));
        assert_eq!(
            get(&h.app, &authorize("kubectl")).await.status,
            StatusCode::BAD_REQUEST,
            "one-time use"
        );

        // Expiry, and invalid pushed requests.
        let request_uri = post(&h.app, "/par", &pushed, None).await.json()["request_uri"]
            .as_str()
            .unwrap()
            .to_owned();
        h.clock.advance(61);
        let reply = get(
            &h.app,
            &format!(
                "/authorize?{}",
                query(&[("client_id", "kubectl"), ("request_uri", &request_uri)])
            ),
        )
        .await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST);
        let reply = post(
            &h.app,
            "/par",
            &[
                ("client_id", "kubectl"),
                ("redirect_uri", "https://evil.example/"),
            ],
            None,
        )
        .await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST);
        let reply = post(
            &h.app,
            "/par",
            &[("client_id", "web"), ("client_secret", "wrong")],
            None,
        )
        .await;
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn guessed_refresh_secrets_cannot_revoke_a_known_grant() {
        for wrong_client in [false, true] {
            for rotated in [false, true] {
                let h = harness().await;
                let first = exchange(&h, &sign_in(&h, "alice", &kubectl_authorize(&[])).await)
                    .await
                    .json()["refresh_token"]
                    .as_str()
                    .unwrap()
                    .to_owned();
                let current = if rotated {
                    refresh(&h, &first).await.json()["refresh_token"]
                        .as_str()
                        .unwrap()
                        .to_owned()
                } else {
                    first.clone()
                };
                let (grant, _) = first.split_once('.').unwrap();
                let guessed = format!("{grant}.{}", "A".repeat(43));
                assert_ne!(guessed, first);
                assert_ne!(guessed, current);
                let reply = if wrong_client {
                    post(
                        &h.app,
                        "/token",
                        &[("grant_type", "refresh_token"), ("refresh_token", &guessed)],
                        Some(("web", WEB_SECRET)),
                    )
                    .await
                } else {
                    post(
                        &h.app,
                        "/revoke",
                        &[("token", &guessed), ("client_id", "kubectl")],
                        None,
                    )
                    .await
                };
                if wrong_client {
                    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
                    assert_eq!(reply.error(), "invalid_grant");
                } else {
                    assert_eq!(reply.status, StatusCode::OK);
                    assert_eq!(reply.headers[header::CACHE_CONTROL], "no-store");
                }
                assert_eq!(refresh(&h, &current).await.status, StatusCode::OK);
            }
        }
    }

    #[tokio::test]
    async fn current_and_previous_refresh_secrets_authorize_family_revocation() {
        for wrong_client in [false, true] {
            for previous in [false, true] {
                let h = harness().await;
                let first = exchange(&h, &sign_in(&h, "alice", &kubectl_authorize(&[])).await)
                    .await
                    .json()["refresh_token"]
                    .as_str()
                    .unwrap()
                    .to_owned();
                let current = refresh(&h, &first).await.json()["refresh_token"]
                    .as_str()
                    .unwrap()
                    .to_owned();
                let presented = if previous { &first } else { &current };
                let reply = if wrong_client {
                    post(
                        &h.app,
                        "/token",
                        &[
                            ("grant_type", "refresh_token"),
                            ("refresh_token", presented),
                        ],
                        Some(("web", WEB_SECRET)),
                    )
                    .await
                } else {
                    post(
                        &h.app,
                        "/revoke",
                        &[("token", presented), ("client_id", "kubectl")],
                        None,
                    )
                    .await
                };
                if wrong_client {
                    assert_eq!(reply.error(), "invalid_grant");
                } else {
                    assert_eq!(reply.status, StatusCode::OK);
                }
                assert_eq!(refresh(&h, &current).await.error(), "invalid_grant");
                if wrong_client {
                    let binding = audit_outcomes(&h, "oauth.client_binding", &["failure"]);
                    assert_eq!(binding[0]["fields"]["reason"], "client_mismatch");
                    assert_eq!(binding[0]["fields"]["client"], "web");
                    audit_outcomes(&h, "oauth.refresh", &["success", "failure", "failure"]);
                } else {
                    let revocation = audit_outcomes(&h, "oauth.revocation_request", &["success"]);
                    assert_eq!(revocation[0]["fields"]["reason"], "accepted");
                    assert_eq!(revocation[0]["fields"]["client"], "kubectl");
                    audit_outcomes(&h, "oauth.refresh", &["success", "failure"]);
                }
                assert_no_secrets(&h, &[&first, &current]);
            }
        }
    }

    #[tokio::test]
    async fn revocation() {
        let h = harness().await;
        let body = exchange(&h, &sign_in(&h, "alice", &kubectl_authorize(&[])).await)
            .await
            .json();
        let token = body["refresh_token"].as_str().unwrap();

        // Another client cannot revoke it (but gets 200, RFC 7009 §2.2).
        let reply = post(
            &h.app,
            "/revoke",
            &[("token", token)],
            Some(("web", WEB_SECRET)),
        )
        .await;
        assert_eq!(reply.status, StatusCode::OK);
        let rotated = refresh(&h, token).await.json();
        let token = rotated["refresh_token"].as_str().unwrap().to_owned();

        let reply = post(
            &h.app,
            "/revoke",
            &[("token", &token), ("client_id", "kubectl")],
            None,
        )
        .await;
        assert_eq!(reply.status, StatusCode::OK);
        assert_eq!(refresh(&h, &token).await.error(), "invalid_grant");

        let reply = post(
            &h.app,
            "/revoke",
            &[
                ("token", body["access_token"].as_str().unwrap()),
                ("client_id", "kubectl"),
            ],
            None,
        )
        .await;
        assert_eq!(reply.error(), "unsupported_token_type");
        let reply = post(
            &h.app,
            "/revoke",
            &[("token", "garbage"), ("client_id", "kubectl")],
            None,
        )
        .await;
        assert_eq!(reply.status, StatusCode::OK);
        let events = audit_outcomes(
            &h,
            "oauth.revocation_request",
            &["success", "success", "failure", "success"],
        );
        assert_eq!(events[0]["fields"]["client"], "web");
        for index in [0, 1, 3] {
            assert_eq!(events[index]["fields"]["reason"], "accepted");
            assert!(events[index]["fields"].get("user").is_none());
            assert!(events[index]["fields"].get("subject").is_none());
        }
        assert_eq!(events[2]["fields"]["reason"], "unsupported_token_type");
        assert_no_secrets(
            &h,
            &[
                &token,
                body["access_token"].as_str().unwrap(),
                body["id_token"].as_str().unwrap(),
                body["refresh_token"].as_str().unwrap(),
                rotated["access_token"].as_str().unwrap(),
                rotated["id_token"].as_str().unwrap(),
            ],
        );
    }

    const PASSKEY: &[&str] = &["swk", "mfa"];

    fn tokens_of(reply: &Reply) -> Value {
        assert_eq!(reply.status, StatusCode::OK, "{}", reply.json());
        reply.json()
    }

    fn lifetime(h: &Harness, token: &str, audience: &str) -> u64 {
        let (_, claims) = verify(h, token, audience);
        claims["exp"].as_u64().unwrap() - claims["iat"].as_u64().unwrap()
    }

    async fn stored_user(h: &Harness, name: &str) -> User {
        h.server.directory.user(name).await.unwrap().unwrap()
    }

    async fn set_account_type(h: &Harness, name: &str, account_type: AccountType) {
        let mut user = stored_user(h, name).await;
        user.account_type = account_type;
        h.server.directory.put_user(user);
    }

    async fn sign_in_tokens(h: &Harness, user: &str, amr: &[&str], device_bound: bool) -> Value {
        let code = sign_in_as(h, user, &kubectl_authorize(&[]), amr, device_bound).await;
        tokens_of(&exchange(h, &code).await)
    }

    fn refresh_token(tokens: &Value) -> &str {
        tokens["refresh_token"].as_str().unwrap()
    }

    #[tokio::test]
    async fn a_code_for_a_removed_user_is_not_redeemed_for_a_new_user_of_that_name() {
        let h = harness().await;
        let code = sign_in_with(&h, "alice", &kubectl_authorize(&[]), PASSKEY).await;
        // Remove alice after sign-in, then give the name to a new person.
        h.server.directory.remove_user("alice");
        let newcomer = User {
            name: "alice".into(),
            subject: "uid-recreated".into(),
            username: "alice".into(),
            account_type: AccountType::Admin,
            ..User::default()
        };
        h.server.directory.put_user(newcomer.clone());
        assert_eq!(exchange(&h, &code).await.error(), "invalid_grant");
        assert_eq!(h.server.grants.list(&newcomer).await.unwrap(), []);
    }

    #[tokio::test]
    async fn only_admin_accounts_carry_the_admin_group_and_their_tokens_are_shorter() {
        let h = harness().await;
        // A regular account never carries the admin group, even if its groups list it.
        let mut alice = stored_user(&h, "alice").await;
        alice.groups.push(ADMIN_GROUP.into());
        h.server.directory.put_user(alice);
        let regular = sign_in_tokens(&h, "alice", PASSKEY, false).await;
        let admin = sign_in_tokens(&h, "carol", PASSKEY, false).await;
        for (name, tokens, groups, seconds) in [
            ("regular", &regular, serde_json::json!(["developers"]), 600),
            (
                "admin",
                &admin,
                serde_json::json!(["developers", ADMIN_GROUP]),
                300,
            ),
        ] {
            let access = tokens["access_token"].as_str().unwrap();
            let (_, claims) = verify(&h, access, "kubernetes");
            assert_eq!(claims["groups"], groups, "{name}");
            assert_eq!(tokens["expires_in"], seconds, "{name}");
            assert_eq!(lifetime(&h, access, "kubernetes"), seconds, "{name}");
            let id = tokens["id_token"].as_str().unwrap();
            assert_eq!(lifetime(&h, id, "kubectl"), seconds, "{name}: ID token");
            let info = userinfo(&h, Some(access)).await.json();
            assert_eq!(info["groups"], groups, "{name}: UserInfo");
        }

        // A refresh uses the account type as it is now.
        set_account_type(&h, "carol", AccountType::Regular).await;
        let refreshed = tokens_of(&refresh(&h, refresh_token(&admin)).await);
        let (_, claims) = verify(
            &h,
            refreshed["access_token"].as_str().unwrap(),
            "kubernetes",
        );
        assert_eq!(claims["groups"], serde_json::json!(["developers"]));
        assert_eq!(refreshed["expires_in"], 600);
    }

    #[tokio::test]
    async fn admin_accounts_need_a_passkey_and_with_aal3_a_device_bound_one() {
        let h = harness().await;
        // A regular account may use GitHub or Google; an admin account may not.
        let upstream = sign_in_tokens(&h, "alice", &[], false).await;
        let code = sign_in_with(&h, "carol", &kubectl_authorize(&[]), &[]).await;
        assert_eq!(exchange(&h, &code).await.error(), "invalid_grant");
        let events = audit_outcomes(&h, "oauth.account_policy", &["failure"]);
        assert_eq!(events[0]["fields"]["reason"], "AdminNeedsPasskey");

        // An upstream session ends when its account becomes an admin account.
        set_account_type(&h, "alice", AccountType::Admin).await;
        assert_eq!(
            refresh(&h, refresh_token(&upstream)).await.error(),
            "invalid_grant"
        );
        set_account_type(&h, "alice", AccountType::Regular).await;
        assert_eq!(
            refresh(&h, refresh_token(&upstream)).await.error(),
            "invalid_grant",
            "the family was revoked"
        );

        // A synced passkey is enough until AAL3 is on. Then only a device-bound one is.
        let synced = sign_in_tokens(&h, "carol", PASSKEY, false).await;
        let bound = sign_in_tokens(&h, "carol", PASSKEY, true).await;
        h.server.directory.put_settings(Settings {
            admin_aal3: true,
            ..Settings::default()
        });
        let code = sign_in_with(&h, "carol", &kubectl_authorize(&[]), PASSKEY).await;
        assert_eq!(exchange(&h, &code).await.error(), "invalid_grant");
        assert_eq!(
            refresh(&h, refresh_token(&synced)).await.error(),
            "invalid_grant"
        );
        tokens_of(&refresh(&h, refresh_token(&bound)).await);
        sign_in_tokens(&h, "carol", PASSKEY, true).await;
        // AAL3 does not change regular accounts.
        sign_in_tokens(&h, "alice", PASSKEY, false).await;
    }

    #[tokio::test]
    async fn refresh_idle_follows_the_account_type_and_the_settings() {
        let multiple = Settings {
            teams: Teams::Multiple,
            admin_aal3: false,
        };
        let aal3 = Settings {
            teams: Teams::Single,
            admin_aal3: true,
        };
        for (name, user, settings, idle) in [
            ("regular", "alice", Settings::default(), 3600),
            ("regular, several teams", "alice", multiple, 3600),
            ("admin, one team", "carol", Settings::default(), 3600),
            ("admin, several teams", "carol", multiple, 900),
            ("admin, AAL3", "carol", aal3, 900),
        ] {
            let h = harness().await;
            h.server.directory.put_settings(settings);
            let tokens = sign_in_tokens(&h, user, PASSKEY, true).await;
            assert_eq!(tokens["refresh_expires_in"], idle, "{name}");
            // Used just before the idle limit, the family lives on.
            h.clock.advance(idle - 1);
            let tokens = tokens_of(&refresh(&h, refresh_token(&tokens)).await);
            assert_eq!(tokens["refresh_expires_in"], idle, "{name}");
            h.clock.advance(idle);
            assert_eq!(
                refresh(&h, refresh_token(&tokens)).await.error(),
                "invalid_grant",
                "{name}"
            );
        }
    }

    #[tokio::test]
    async fn auth_time_is_the_sign_in_and_survives_refresh() {
        let h = harness().await;
        let tokens = sign_in_tokens(&h, "alice", PASSKEY, false).await;
        h.clock.advance(30 * 60);
        let refreshed = tokens_of(&refresh(&h, refresh_token(&tokens)).await);
        let (_, id) = verify(&h, refreshed["id_token"].as_str().unwrap(), "kubectl");
        let (_, access) = verify(
            &h,
            refreshed["access_token"].as_str().unwrap(),
            "kubernetes",
        );
        assert_eq!(id["auth_time"], START);
        assert_eq!(access["auth_time"], START);

        // There is no single sign-on session. A request with max_age always goes to the sign-in
        // page, so its tokens carry the new auth_time.
        let uri = kubectl_authorize(&[("max_age", "600")]);
        assert_eq!(get(&h.app, &uri).await.location(), "/login");
        let fresh = tokens_of(&exchange(&h, &sign_in(&h, "alice", &uri).await).await);
        let (_, id) = verify(&h, fresh["id_token"].as_str().unwrap(), "kubectl");
        assert_eq!(id["auth_time"], START + 30 * 60);
    }

    async fn userinfo(h: &Harness, token: Option<&str>) -> Reply {
        let mut request = Request::builder().uri("/userinfo");
        if let Some(token) = token {
            request = request.header(header::AUTHORIZATION, format!("Bearer {token}"));
        }
        send(&h.app, request.body(Body::empty()).unwrap()).await
    }

    #[tokio::test]
    async fn userinfo_returns_current_claims_for_access_tokens_only() {
        let h = harness().await;
        let code = sign_in(&h, "alice", &kubectl_authorize(&[])).await;
        let tokens = exchange(&h, &code).await.json();
        let access = tokens["access_token"].as_str().unwrap();

        let reply = userinfo(&h, Some(access)).await;
        assert_eq!(reply.status, StatusCode::OK);
        assert_eq!(reply.headers[header::CACHE_CONTROL], "no-store");
        let claims = reply.json();
        assert_eq!(claims["sub"], "uid-alice");
        assert_eq!(claims["preferred_username"], "alice");
        assert_eq!(claims["name"], "alice example");
        assert_eq!(claims["groups"], serde_json::json!(["developers"]));

        // RFC 6750 §3: no token → a bare challenge; a bad one → invalid_token.
        let reply = userinfo(&h, None).await;
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
        assert_eq!(
            reply.headers[header::WWW_AUTHENTICATE],
            r#"Bearer realm="zeabur-identity""#
        );
        let id_token = tokens["id_token"].as_str().unwrap();
        for bad in [id_token, "not-a-token", &format!("{access}x")] {
            let reply = userinfo(&h, Some(bad)).await;
            assert_eq!(reply.status, StatusCode::UNAUTHORIZED, "{bad}");
            assert!(
                reply.headers[header::WWW_AUTHENTICATE]
                    .to_str()
                    .unwrap()
                    .contains(r#"error="invalid_token""#)
            );
        }

        // Without `profile` and `groups`, only `sub`.
        let code = sign_in(
            &h,
            "alice",
            &kubectl_authorize(&[]).replace("scope=openid+profile+groups", "scope=openid"),
        )
        .await;
        let narrow = exchange(&h, &code).await.json();
        let claims = userinfo(&h, narrow["access_token"].as_str()).await.json();
        assert_eq!(claims, serde_json::json!({ "sub": "uid-alice" }));

        // Without `openid`, UserInfo is out of scope.
        let code = sign_in(
            &h,
            "alice",
            &kubectl_authorize(&[]).replace("scope=openid+profile+groups", "scope=groups"),
        )
        .await;
        let plain = exchange(&h, &code).await.json();
        let reply = userinfo(&h, plain["access_token"].as_str()).await;
        assert_eq!(reply.status, StatusCode::FORBIDDEN);

        // A user disabled after issuance, and an expired token, get nothing.
        h.server.directory.put_user(User {
            name: "alice".into(),
            subject: "uid-alice".into(),
            username: "alice".into(),
            disabled: true,
            ..User::default()
        });
        assert_eq!(
            userinfo(&h, Some(access)).await.status,
            StatusCode::UNAUTHORIZED
        );
        h.clock.advance(3600);
        assert_eq!(
            userinfo(&h, Some(access)).await.status,
            StatusCode::UNAUTHORIZED
        );
    }

    #[tokio::test]
    async fn userinfo_rejects_deleted_and_recreated_users() {
        let h = harness().await;
        let code = sign_in(&h, "alice", &kubectl_authorize(&[])).await;
        let tokens = exchange(&h, &code).await.json();
        let access = tokens["access_token"].as_str().unwrap();
        assert_eq!(userinfo(&h, Some(access)).await.status, StatusCode::OK);

        h.server.directory.remove_user("alice");
        assert_eq!(
            userinfo(&h, Some(access)).await.status,
            StatusCode::UNAUTHORIZED
        );

        // Reusing the original name for a different UID must not expose its claims.
        h.server.directory.put_user(User {
            name: "alice".into(),
            subject: "uid-recreated".into(),
            username: "replacement".into(),
            ..User::default()
        });
        let reply = userinfo(&h, Some(access)).await;
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
        assert_eq!(reply.body.as_slice(), b"");
    }

    #[tokio::test]
    async fn a_session_left_from_a_removed_user_does_not_refresh_as_a_new_user_of_that_name() {
        let h = harness().await;
        let token = exchange(&h, &sign_in(&h, "alice", &kubectl_authorize(&[])).await)
            .await
            .json()["refresh_token"]
            .as_str()
            .unwrap()
            .to_owned();
        // Remove alice but not her session, then give the name to a new person.
        h.server.directory.remove_user("alice");
        h.server.directory.put_user(User {
            name: "alice".into(),
            subject: "uid-recreated".into(),
            username: "alice".into(),
            ..User::default()
        });
        assert_eq!(refresh(&h, &token).await.error(), "invalid_grant");
    }

    #[tokio::test]
    async fn userinfo_rejects_unknown_and_ambiguous_subjects() {
        let h = harness().await;
        let code = sign_in(&h, "alice", &kubectl_authorize(&[])).await;
        let tokens = exchange(&h, &code).await.json();
        let access = tokens["access_token"].as_str().unwrap();
        let (_, mut claims) = verify(&h, access, "kubernetes");
        let keys = h.server.keys.borrow().clone().unwrap();
        let key = keys.signer(Algorithm::Es256, h.clock.now()).unwrap();

        // An otherwise valid signed token for an absent subject never yields claims.
        claims["sub"] = serde_json::json!("uid-unknown");
        let unknown = zeabur_identity_keys::jws::sign_compact(&key, "at+jwt", &claims).unwrap();
        let reply = userinfo(&h, Some(&unknown)).await;
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
        assert_eq!(reply.body.as_slice(), b"");

        // Ambiguous backend answers fail closed rather than choosing an arbitrary user.
        h.server.directory.put_user(User {
            name: "duplicate".into(),
            subject: "uid-alice".into(),
            username: "private-duplicate-username".into(),
            ..User::default()
        });
        let reply = userinfo(&h, Some(access)).await;
        assert_eq!(reply.status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(reply.body.as_slice(), b"");
    }

    #[tokio::test]
    async fn signing_failures_never_report_issuance_success() {
        // Both missing key publication and a clock before signer activation fail code issuance.
        for user in ["alice", "carol"] {
            for missing in [false, true] {
                let h = harness().await;
                if missing {
                    h.keys_sender.send(None).unwrap();
                } else {
                    h.clock.0.store(START - 1, Ordering::SeqCst);
                }
                let code = sign_in_with(&h, user, &kubectl_authorize(&[]), PASSKEY).await;
                let reply = exchange(&h, &code).await;
                let reason = if missing {
                    "temporarily_unavailable"
                } else {
                    "server_error"
                };
                assert_eq!(reply.error(), reason);
                let events = audit_outcomes(&h, "oauth.code_exchange", &["failure"]);
                assert_eq!(events[0]["fields"]["reason"], reason);
                assert_eq!(events[0]["fields"]["client"], "kubectl");
                assert!(events[0]["fields"].get("user").is_none());
                let operational = if missing {
                    "keys_unavailable"
                } else {
                    "no_active_signer"
                };
                assert!(h.capture.records().iter().any(|record| {
                    matches!(
                        record["target"].as_str(),
                        Some("zeabur_identity_oauth::endpoints" | "zeabur_identity_oauth::tokens")
                    ) && record["fields"]["reason"] == operational
                }));
                assert_no_secrets(&h, &[&code]);
            }
        }

        // Rotation still happens before signing; restoring keys cannot reuse the old token.
        let h = harness().await;
        let code = sign_in(&h, "alice", &kubectl_authorize(&[])).await;
        let issued = exchange(&h, &code).await.json();
        let token = issued["refresh_token"].as_str().unwrap();
        let keys = h.server.keys.borrow().clone();
        h.keys_sender.send(None).unwrap();
        assert_eq!(refresh(&h, token).await.error(), "temporarily_unavailable");
        h.keys_sender.send(keys).unwrap();
        assert_eq!(refresh(&h, token).await.error(), "invalid_grant");
        let events = audit_outcomes(&h, "oauth.refresh", &["failure", "failure"]);
        assert_eq!(events[0]["fields"]["reason"], "temporarily_unavailable");
        let replay = audit_outcomes(&h, "oauth.replay", &["failure"]);
        assert_eq!(replay[0]["fields"]["reason"], "refresh_reused");
        assert_no_secrets(
            &h,
            &[
                &code,
                token,
                issued["access_token"].as_str().unwrap(),
                issued["id_token"].as_str().unwrap(),
            ],
        );
    }

    #[tokio::test]
    async fn detection_and_revocation_failures_do_not_claim_deletion() {
        for detection in ["code", "refresh", "binding", "revoke"] {
            let h = harness().await;
            let code = sign_in(&h, "alice", &kubectl_authorize(&[])).await;
            let issued = exchange(&h, &code).await.json();
            let token = issued["refresh_token"].as_str().unwrap();
            let mut secrets = vec![code.clone(), token.to_owned()];
            h.server.grants.fail_revoke.store(true, Ordering::SeqCst);
            let (reply, operation, client) = match detection {
                "code" => (exchange(&h, &code).await, "oauth.code_exchange", "kubectl"),
                "refresh" => {
                    let rotated = refresh(&h, token).await.json();
                    for field in ["refresh_token", "access_token", "id_token"] {
                        secrets.push(rotated[field].as_str().unwrap().to_owned());
                    }
                    (refresh(&h, token).await, "oauth.refresh", "kubectl")
                }
                "binding" => (
                    post(
                        &h.app,
                        "/token",
                        &[("grant_type", "refresh_token"), ("refresh_token", token)],
                        Some(("web", WEB_SECRET)),
                    )
                    .await,
                    "oauth.refresh",
                    "web",
                ),
                "revoke" => (
                    post(
                        &h.app,
                        "/revoke",
                        &[("token", token), ("client_id", "kubectl")],
                        None,
                    )
                    .await,
                    "oauth.revocation_request",
                    "kubectl",
                ),
                _ => unreachable!(),
            };
            assert_eq!(reply.error(), "server_error");
            let expected = if matches!(detection, "code" | "refresh") {
                vec!["success", "failure"]
            } else {
                vec!["failure"]
            };
            let events = audit_outcomes(&h, operation, &expected);
            let failed = events.last().unwrap();
            assert_eq!(failed["fields"]["reason"], "server_error");
            assert_eq!(failed["fields"]["client"], client);
            assert!(h.capture.records().iter().any(|record| {
                record["target"] == "zeabur_identity_oauth::endpoints"
                    && record["fields"]["reason"] == "storage_failed"
            }));
            if detection != "revoke" {
                let (event, reason) = match detection {
                    "code" => ("oauth.replay", "code_reused"),
                    "refresh" => ("oauth.replay", "refresh_reused"),
                    "binding" => ("oauth.client_binding", "client_mismatch"),
                    _ => unreachable!(),
                };
                let detected = audit_outcomes(&h, event, &["failure"]);
                assert_eq!(detected[0]["fields"]["reason"], reason);
                assert_eq!(detected[0]["fields"]["client"], client);
                assert!(detected[0]["fields"].get("user").is_none());
            }
            assert_no_secrets(&h, &secrets.iter().map(String::as_str).collect::<Vec<_>>());
            let family = zeabur_identity_oauth::refresh::RefreshToken::parse(token).unwrap();
            assert!(
                h.server.grants.get(family.grant()).await.unwrap().is_some(),
                "failed deletion must leave the family in storage"
            );
            assert_no_secrets(
                &h,
                &[
                    issued["access_token"].as_str().unwrap(),
                    issued["id_token"].as_str().unwrap(),
                ],
            );
        }
    }

    #[tokio::test]
    async fn token_and_revoke_failures_preserve_basic_challenges_and_unknown_identity() {
        for path in ["/token", "/revoke"] {
            let h = harness().await;
            let reply = post(
                &h.app,
                path,
                &[
                    ("grant_type", "authorization_code"),
                    ("code", "unverified-code-sentinel"),
                    ("token", "unverified-token-sentinel"),
                ],
                Some(("web", "wrong-client-secret-sentinel")),
            )
            .await;
            assert_eq!(reply.error(), "invalid_client");
            assert_eq!(
                reply.headers[header::WWW_AUTHENTICATE],
                r#"Basic realm="zeabur-identity""#
            );
            let event = if path == "/token" {
                "oauth.code_exchange"
            } else {
                "oauth.revocation_request"
            };
            let events = audit_outcomes(&h, event, &["failure"]);
            assert_eq!(events[0]["fields"]["reason"], "invalid_client");
            for identity in ["client", "user", "subject"] {
                assert!(events[0]["fields"].get(identity).is_none());
            }
            assert_no_secrets(
                &h,
                &[
                    "unverified-code-sentinel",
                    "unverified-token-sentinel",
                    "wrong-client-secret-sentinel",
                    &STANDARD.encode("web:wrong-client-secret-sentinel"),
                ],
            );
        }
    }

    #[tokio::test]
    async fn revocation_failures_cover_form_parsing_and_missing_token() {
        let h = harness().await;
        let request = Request::builder()
            .method(Method::POST)
            .uri("/revoke")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(r#"{"token":"non-form-token-sentinel"}"#))
            .unwrap();
        assert_eq!(send(&h.app, request).await.error(), "invalid_request");
        let duplicate = post(
            &h.app,
            "/revoke",
            &[
                ("token", "first-token-sentinel"),
                ("token", "second-token-sentinel"),
                ("client_id", "kubectl"),
            ],
            None,
        )
        .await;
        assert_eq!(duplicate.error(), "invalid_request");
        assert_eq!(
            post(&h.app, "/revoke", &[("client_id", "kubectl")], None)
                .await
                .error(),
            "invalid_request"
        );
        let events = audit_outcomes(
            &h,
            "oauth.revocation_request",
            &["failure", "failure", "failure"],
        );
        assert_eq!(events[0]["fields"]["reason"], "not_form");
        assert_eq!(events[1]["fields"]["reason"], "invalid_request");
        assert_eq!(events[2]["fields"]["reason"], "invalid_request");
        assert!(events[0]["fields"].get("client").is_none());
        assert!(events[1]["fields"].get("client").is_none());
        assert_eq!(events[2]["fields"]["client"], "kubectl");
        assert_no_secrets(
            &h,
            &[
                "non-form-token-sentinel",
                "first-token-sentinel",
                "second-token-sentinel",
            ],
        );
    }

    #[tokio::test]
    async fn token_endpoint_rejects_malformed_requests() {
        let h = harness().await;
        let reply = post(
            &h.app,
            "/token",
            &[("grant_type", "password"), ("client_id", "kubectl")],
            None,
        )
        .await;
        assert_eq!(reply.error(), "unsupported_grant_type");
        let reply = post(&h.app, "/token", &[("client_id", "kubectl")], None).await;
        assert_eq!(reply.error(), "invalid_request");
        let request = Request::builder()
            .method(Method::POST)
            .uri("/token")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from("{}"))
            .unwrap();
        assert_eq!(send(&h.app, request).await.status, StatusCode::BAD_REQUEST);
        let duplicate = post(
            &h.app,
            "/token",
            &[
                ("grant_type", "authorization_code"),
                ("grant_type", "refresh_token"),
                ("code", "duplicate-form-code-sentinel"),
                ("client_id", "kubectl"),
            ],
            None,
        )
        .await;
        assert_eq!(duplicate.error(), "invalid_request");
        let events = audit_outcomes(
            &h,
            "oauth.token_request",
            &["failure", "failure", "failure", "failure"],
        );
        assert_eq!(events[0]["fields"]["reason"], "unsupported_grant_type");
        assert_eq!(events[0]["fields"]["client"], "kubectl");
        assert_eq!(events[1]["fields"]["reason"], "invalid_request");
        assert_eq!(events[2]["fields"]["reason"], "not_form");
        assert!(events[2]["fields"].get("client").is_none());
        assert!(events[3]["fields"].get("client").is_none());
        assert_no_secrets(&h, &["password", "duplicate-form-code-sentinel"]);
    }
}
