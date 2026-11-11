//! Upstream sign-in and account linking against fake GitHub and OpenID providers that answer in
//! process: PKCE is checked against the challenge sent, the OpenID provider's discovery document
//! names test endpoints, and its ID token is signed with a test key published in a test JWK set.

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::fmt::Write as _;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};

    use axum::Router;
    use axum::body::{Body, Bytes};
    use axum::http::{HeaderMap, Method, Request, Response, StatusCode, header};
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use http_body_util::BodyExt as _;
    use serde_json::{Value, json};
    use tower::ServiceExt as _;
    use tracing::instrument::WithSubscriber as _;
    use zeabur_identity_api::client::ClientType;
    use zeabur_identity_api::token_hash;
    use zeabur_identity_api::upstream::{ExternalId, Issuer, ProviderId, Subject};
    use zeabur_identity_core::account::AccountType;
    use zeabur_identity_core::clock::{Clock, SystemClock};
    use zeabur_identity_core::config::BaseUrl;
    use zeabur_identity_core::crypto::{Sealer, random, sha256};
    use zeabur_identity_keys::Algorithm;
    use zeabur_identity_keys::jwk::JwkSet;
    use zeabur_identity_keys::jws::sign_compact;
    use zeabur_identity_keys::manager::KeyManager;
    use zeabur_identity_keys::rotation::RotationPolicy;
    use zeabur_identity_keys::signing::SigningKey;
    use zeabur_identity_keys::store::MemoryKeyStore;
    use zeabur_identity_oauth::endpoints::{self, FLOW_COOKIE};
    use zeabur_identity_oauth::{AuthorizationServer, Lifetimes, OneTimeIds};
    use zeabur_identity_signin::SignIn;
    use zeabur_identity_signin::account::{ACCOUNT_CLIENT, SESSION_COOKIE, SessionToken};
    use zeabur_identity_signin::passkeys::Passkeys;
    use zeabur_identity_signin::upstream::http::{HttpClient, HttpError};
    use zeabur_identity_signin::upstream::provider::{
        ClientSecret, Exchange, GITHUB_ISSUER, GOOGLE_ISSUER, GitHubEndpoints, Provider, Providers,
    };
    use zeabur_identity_signin::upstream::{self, UPSTREAM_COOKIE, Upstream};
    use zeabur_identity_store::{
        Client, CredentialStore as _, Directory as _, GrantStore as _, MemoryCredentialStore,
        MemoryDirectory, MemoryGrantStore, MemorySetupStore, NewExternal, NewGrant,
        SetupStore as _, User, external_credential_name,
    };
    use zeabur_identity_test_support::logging::Capture;
    use zeabur_identity_ui::i18n::Lang;

    const ISSUER: &str = "https://login.example.com";
    const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    const GITHUB_ID: u64 = 583_231;
    const GOOGLE_SUB: &str = "110169484474386276334";
    const INVITATION: &str = "inv-1.invitation-secret-with-plenty-of-entropy";

    const SECRET_ERROR: &str = "secret-bearing-upstream-http-error-sentinel";
    /// What the fake providers know about the current attempt.
    #[derive(Default)]
    struct Fake {
        /// code → (PKCE challenge, nonce) the code was issued for.
        codes: Mutex<HashMap<String, (String, String)>>,
        /// Signs Google's ID tokens.
        google_key: Mutex<Option<Arc<SigningKey>>>,
        /// Published in Google's JWK set.
        published_key: Mutex<Option<Arc<SigningKey>>>,
        /// Overrides for Google's ID token claims.
        id_token_overrides: Mutex<Value>,
        fail_http: AtomicBool,
        secrets: Mutex<Vec<String>>,
        /// The OpenID provider's issuer: its discovery document is at this issuer.
        issuer: String,
        /// Overrides for the discovery document; `null` makes it answer `500`.
        discovery_overrides: Mutex<Value>,
        /// The URL of every request the providers received.
        requests: Mutex<Vec<String>>,
    }

    #[derive(Clone)]
    struct FakeHttp(Arc<Fake>);

    fn reply(status: StatusCode, body: &Value) -> Response<Bytes> {
        Response::builder()
            .status(status)
            .body(Bytes::from(body.to_string()))
            .unwrap()
    }

    /// Google's token response: an ID token with the fake's claims and overrides.
    fn google_token(fake: &Fake, nonce: &str) -> Response<Bytes> {
        let now = SystemClock.now().as_secs();
        let mut claims = json!({
            "iss": fake.issuer,
            "sub": GOOGLE_SUB,
            "aud": "google-client",
            "exp": now + 300,
            "iat": now,
            "nonce": nonce,
        });
        let overrides = fake.id_token_overrides.lock().unwrap().clone();
        if let Value::Object(map) = overrides {
            for (k, v) in map {
                claims[k] = v;
            }
        }
        let key = fake.google_key.lock().unwrap().clone().unwrap();
        let id_token = sign_compact(&key, "JWT", &claims).unwrap();
        fake.secrets
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(id_token.clone());
        reply(
            StatusCode::OK,
            &json!({ "access_token": "g", "id_token": id_token }),
        )
    }

    /// Google's JWK set: the published key only.
    fn google_jwks(fake: &Fake) -> Response<Bytes> {
        let key = fake.published_key.lock().unwrap().clone().unwrap();
        let set = JwkSet {
            keys: vec![key.jwk()],
        };
        reply(StatusCode::OK, &serde_json::to_value(set).unwrap())
    }

    /// The OpenID provider's discovery document, pointing at the test endpoints.
    fn discovery(fake: &Fake) -> Response<Bytes> {
        let overrides = fake.discovery_overrides.lock().unwrap().clone();
        if overrides.is_null() {
            return reply(StatusCode::INTERNAL_SERVER_ERROR, &json!({}));
        }
        let mut document = json!({
            "issuer": fake.issuer,
            "authorization_endpoint": "https://google.test/authorize",
            "token_endpoint": "https://google.test/token",
            "jwks_uri": "https://google.test/jwks",
            "response_types_supported": ["code"],
        });
        if let Value::Object(map) = overrides {
            for (k, v) in map {
                if v.is_null() {
                    document.as_object_mut().unwrap().remove(&k);
                } else {
                    document[k] = v;
                }
            }
        }
        reply(StatusCode::OK, &document)
    }

    impl HttpClient for FakeHttp {
        fn send(
            &self,
            request: Request<Bytes>,
        ) -> impl Future<Output = Result<Response<Bytes>, HttpError>> + Send {
            std::future::ready(if self.0.fail_http.load(Ordering::SeqCst) {
                Err(HttpError(SECRET_ERROR.into()))
            } else {
                self.answer(&request)
                    .ok_or_else(|| HttpError(SECRET_ERROR.into()))
            })
        }
    }

    impl FakeHttp {
        fn answer(&self, request: &Request<Bytes>) -> Option<Response<Bytes>> {
            let fake = &self.0;
            let uri = request.uri().to_string();
            fake.requests.lock().unwrap().push(uri.clone());
            let discovery_url = format!(
                "{}/.well-known/openid-configuration",
                fake.issuer.trim_end_matches('/')
            );
            if uri == discovery_url {
                return Some(discovery(fake));
            }
            let form: HashMap<String, String> = form_urlencoded::parse(request.body())
                .into_owned()
                .collect();
            let redeem = |form: &HashMap<String, String>| {
                let code = form.get("code")?;
                let (challenge, nonce) = fake.codes.lock().unwrap().remove(code)?;
                let verifier = form.get("code_verifier")?;
                (URL_SAFE_NO_PAD.encode(sha256(verifier.as_bytes())) == challenge).then_some(nonce)
            };
            Some(match uri.as_str() {
                "https://github.test/token" => match redeem(&form) {
                    Some(_)
                        if form.get("client_secret").map(String::as_str) == Some("gh-secret") =>
                    {
                        reply(StatusCode::OK, &json!({ "access_token": "gh-access" }))
                    }
                    _ => reply(
                        StatusCode::BAD_REQUEST,
                        &json!({ "error": "bad_verification_code" }),
                    ),
                },
                "https://api.github.test/user" => {
                    let authorized = request.headers()[header::AUTHORIZATION] == "Bearer gh-access"
                        && request.headers().contains_key(header::USER_AGENT);
                    if authorized {
                        reply(
                            StatusCode::OK,
                            &json!({ "id": GITHUB_ID, "login": "octocat" }),
                        )
                    } else {
                        reply(StatusCode::UNAUTHORIZED, &json!({}))
                    }
                }
                "https://google.test/token" => redeem(&form).map_or_else(
                    || {
                        reply(
                            StatusCode::BAD_REQUEST,
                            &json!({ "error": "invalid_grant" }),
                        )
                    },
                    |nonce| google_token(fake, &nonce),
                ),
                "https://google.test/jwks" => google_jwks(fake),
                _ => return None,
            })
        }
    }

    struct Harness {
        app: Router,
        fake: Arc<Fake>,
        service: Arc<
            Upstream<
                MemoryDirectory,
                MemoryGrantStore,
                SystemClock,
                MemoryCredentialStore,
                MemorySetupStore,
                FakeHttp,
            >,
        >,
    }

    async fn harness() -> Harness {
        harness_at(GOOGLE_ISSUER).await
    }

    /// The harness, with the OpenID provider shown as Google at `issuer`.
    async fn harness_at(google_issuer: &str) -> Harness {
        harness_with(google_issuer, &["github", "google"]).await
    }

    /// The harness with only the providers named in `configured`, in that order.
    async fn harness_with(google_issuer: &str, configured: &[&str]) -> Harness {
        let manager = KeyManager::new(
            MemoryKeyStore::default(),
            SystemClock,
            RotationPolicy::DEFAULT,
        );
        manager.reconcile().await.unwrap();
        let directory = MemoryDirectory::default();
        directory.put_client(Client {
            id: "kubectl".into(),
            display_name: None,
            kind: ClientType::Public,
            redirect_uris: vec!["http://127.0.0.1:8000/".into()],
            audiences: vec!["kubernetes".into()],
            secret_hash: None,
            id_token_alg: Algorithm::Es256,
            home_url: None,
        });
        for (name, disabled) in [("alice", false), ("dana", false), ("zed", true)] {
            directory.put_user(User {
                name: name.into(),
                subject: format!("uid-{name}"),
                username: name.into(),
                groups: vec!["dev".into()],
                disabled,
                ..User::default()
            });
        }
        let issuer = BaseUrl::parse("issuer", ISSUER).unwrap();
        let oauth = Arc::new(AuthorizationServer {
            issuer: issuer.clone(),
            lifetimes: Lifetimes::DEFAULT,
            directory,
            grants: MemoryGrantStore::default(),
            clock: SystemClock,
            keys: manager.subscribe(),
            sealer: Sealer::ephemeral().unwrap(),
            used_codes: OneTimeIds::default(),
            used_request_uris: OneTimeIds::default(),
        });
        let setup = MemorySetupStore::default();
        let dana = oauth.directory.user("dana").await.unwrap().unwrap();
        setup.put_invitation(
            "inv-1",
            &dana,
            &token_hash(INVITATION.as_bytes()),
            zeabur_identity_core::clock::UnixTime::from_secs(SystemClock.now().as_secs() + 3600),
        );
        let mut providers = Vec::new();
        for id in configured {
            let provider = match *id {
                "github" => github_provider(ClientSecret::Fixed("gh-secret".into())),
                "google" => google_provider(google_issuer),
                other => panic!("no provider {other} in the harness"),
            };
            providers.push(Arc::new(provider));
        }
        let sign_in = Arc::new(SignIn {
            oauth: Arc::clone(&oauth),
            passkeys: Passkeys::new(&issuer).unwrap(),
            credentials: MemoryCredentialStore::default(),
            setup,
            used_ceremonies: OneTimeIds::default(),
            providers: Arc::new(Providers::new(providers)),
        });
        let fake = Arc::new(Fake {
            issuer: google_issuer.to_owned(),
            discovery_overrides: Mutex::new(json!({})),
            ..Fake::default()
        });
        let google_key = Arc::new(SigningKey::generate(Algorithm::Rs256).unwrap());
        *fake.google_key.lock().unwrap() = Some(Arc::clone(&google_key));
        *fake.published_key.lock().unwrap() = Some(google_key);
        let service = Arc::new(Upstream {
            sign_in: Arc::clone(&sign_in),
            http: FakeHttp(Arc::clone(&fake)),
            used_states: OneTimeIds::default(),
        });
        let app = endpoints::router(oauth)
            .merge(zeabur_identity_signin::router(sign_in))
            .merge(upstream::router(Arc::clone(&service)));
        Harness { app, fake, service }
    }

    fn github_provider(secret: ClientSecret) -> Provider {
        Provider::github(
            ProviderId::new("github").unwrap(),
            "gh-client".into(),
            secret,
            GitHubEndpoints {
                authorize: "https://github.test/authorize".into(),
                token: "https://github.test/token".into(),
                user: "https://api.github.test/user".into(),
            },
        )
        .unwrap()
    }

    fn google_provider(issuer: &str) -> Provider {
        openid_provider(
            "google",
            issuer,
            ClientSecret::Fixed("google-secret".into()),
        )
    }

    fn openid_provider(id: &str, issuer: &str, secret: ClientSecret) -> Provider {
        Provider::openid(
            ProviderId::new(id).unwrap(),
            "Google".into(),
            Issuer::new(issuer).unwrap(),
            Vec::new(),
            "google-client".into(),
            secret,
        )
    }

    /// The two providers the harness configures, by their default IDs.
    #[derive(Clone, Copy, Debug)]
    enum Kind {
        GitHub,
        Google,
    }

    impl Kind {
        fn from_id(id: &str) -> Option<Self> {
            match id {
                "github" => Some(Self::GitHub),
                "google" => Some(Self::Google),
                _ => None,
            }
        }

        fn id(self) -> ProviderId {
            ProviderId::new(match self {
                Self::GitHub => "github",
                Self::Google => "google",
            })
            .unwrap()
        }

        fn issuer(self) -> &'static str {
            match self {
                Self::GitHub => GITHUB_ISSUER,
                Self::Google => GOOGLE_ISSUER,
            }
        }
    }

    struct Reply {
        status: StatusCode,
        headers: HeaderMap,
        body: String,
        audit: Option<Value>,
        logs: String,
    }

    impl Reply {
        fn json(&self) -> Value {
            serde_json::from_str(&self.body).unwrap_or(Value::Null)
        }
        fn cookie(&self, name: &str) -> String {
            self.headers
                .get_all(header::SET_COOKIE)
                .iter()
                .find_map(|v| {
                    let v = v.to_str().ok()?.strip_prefix(&format!("{name}="))?;
                    Some(v.split(';').next()?.to_owned())
                })
                .unwrap_or_else(|| panic!("no {name} cookie"))
        }
    }

    #[expect(
        clippy::too_many_lines,
        reason = "the test request boundary keeps protocol, audit and generated-secret assertions together"
    )]
    async fn call(app: &Router, request: Request<Body>) -> Reply {
        let capture = Capture::new();
        let path = request.uri().path().to_owned();
        let provider = path.split('/').nth(2).map(str::to_owned);
        let cookies = request
            .headers()
            .get(header::COOKIE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_owned();
        let query_secrets: Vec<_> =
            form_urlencoded::parse(request.uri().query().unwrap_or_default().as_bytes())
                .filter(|(key, _)| matches!(key.as_ref(), "code" | "state"))
                .map(|(_, value)| value.into_owned())
                .collect();
        let (request_parts, body) = request.into_parts();
        let body = body.collect().await.unwrap().to_bytes();
        let submitted: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
        let response = app
            .clone()
            .oneshot(Request::from_parts(request_parts, Body::from(body)))
            .with_subscriber(capture.dispatch())
            .await
            .unwrap();
        let (parts, body) = response.into_parts();
        let response_body =
            String::from_utf8_lossy(&body.collect().await.unwrap().to_bytes()).into_owned();
        let records = capture.records();
        let audits: Vec<_> = records
            .iter()
            .filter(|r| r["target"] == "zeabur_identity::audit")
            .collect();
        if path.starts_with("/upstream/") {
            assert_eq!(audits.len(), 1, "{records:?}");
            let fields = &audits[0]["fields"];
            assert_eq!(fields["method"], "upstream");
            assert_eq!(
                fields["outcome"],
                if parts.status.is_success() || parts.status == StatusCode::SEE_OTHER {
                    "success"
                } else {
                    "failure"
                }
            );
            if path.ends_with("/start") {
                assert_eq!(fields["event"], "auth.upstream_start");
                if !parts.status.is_success() {
                    let problem: Value = serde_json::from_str(&response_body).unwrap();
                    assert_eq!(
                        fields["reason"],
                        problem["type"]
                            .as_str()
                            .unwrap()
                            .strip_prefix("urn:zeabur-identity:problem:")
                            .unwrap()
                    );
                }
            } else {
                assert!(matches!(
                    fields["event"].as_str(),
                    Some(
                        "auth.upstream_callback"
                            | "auth.sign_in"
                            | "auth.account_link"
                            | "account.upstream_linked"
                    )
                ));
                if parts.status == StatusCode::BAD_REQUEST {
                    assert!(fields["reason"].as_str().is_some());
                }
            }
            // A logged provider is the one the path names. Only a configured provider is logged
            // (see `callback_classification_requires_verified_unexpired_pending`).
            if let Some(logged) = fields.get("provider") {
                assert_eq!(logged.as_str(), provider.as_deref());
            }
            assert!(fields.get("client").is_none());
        }
        let serialized = serde_json::to_string(&audits).unwrap();
        for secret in query_secrets.iter().map(String::as_str).chain(
            cookies
                .split(';')
                .filter_map(|p| p.trim().split_once('=').map(|(_, v)| v)),
        ) {
            if !secret.is_empty() {
                assert!(!serialized.contains(secret), "callback secret leaked");
            }
        }
        for secret in [
            SECRET_ERROR,
            GOOGLE_SUB,
            "gh-secret",
            "google-secret",
            "gh-access",
            INVITATION,
            &GITHUB_ID.to_string(),
        ] {
            assert!(
                !serialized.contains(secret),
                "upstream secret or subject leaked"
            );
        }
        if let Some(token) = submitted["token"].as_str() {
            assert!(!serialized.contains(token), "enrollment token leaked");
        }
        for value in parts.headers.get_all(header::SET_COOKIE) {
            let value = value
                .to_str()
                .unwrap()
                .split(';')
                .next()
                .unwrap()
                .split_once('=')
                .unwrap()
                .1;
            if !value.is_empty() {
                assert!(!serialized.contains(value), "generated cookie leaked");
            }
        }
        let redirect = parts
            .headers
            .get(header::LOCATION)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned)
            .or_else(|| {
                serde_json::from_str::<Value>(&response_body)
                    .ok()
                    .and_then(|v| v["redirect_to"].as_str().map(str::to_owned))
            });
        if let Some(url) = redirect {
            for (key, secret) in
                form_urlencoded::parse(url.split_once('?').map_or("", |(_, q)| q).as_bytes())
            {
                if matches!(key.as_ref(), "code" | "state" | "nonce" | "code_challenge") {
                    assert!(
                        !serialized.contains(secret.as_ref()),
                        "generated redirect secret leaked"
                    );
                }
            }
        }
        if let Ok(tokens) = serde_json::from_str::<Value>(&response_body) {
            for key in ["access_token", "id_token", "refresh_token"] {
                if let Some(token) = tokens[key].as_str() {
                    assert!(!serialized.contains(token), "issued token leaked");
                }
            }
        }
        Reply {
            status: parts.status,
            headers: parts.headers,
            body: response_body,
            audit: audits.first().map(|r| (*r).clone()),
            logs: serde_json::to_string(&records).unwrap(),
        }
    }

    fn assert_audit(
        reply: &Reply,
        event: &str,
        reason: Option<&str>,
        user: Option<&str>,
        subject: Option<&str>,
    ) {
        let fields = &reply.audit.as_ref().unwrap()["fields"];
        assert_eq!(fields["event"], event);
        assert_eq!(fields.get("reason").and_then(Value::as_str), reason);
        assert_eq!(fields.get("user").and_then(Value::as_str), user);
        assert_eq!(fields.get("subject").and_then(Value::as_str), subject);
    }

    async fn authorize(h: &Harness, scope: &str) -> String {
        let uri = format!(
            "/authorize?client_id=kubectl&redirect_uri=http%3A%2F%2F127.0.0.1%3A8000%2F&response_type=code&scope={scope}&code_challenge={CHALLENGE}&code_challenge_method=S256&state=oauth-state-secret-sentinel"
        );
        let reply = call(&h.app, Request::get(uri).body(Body::empty()).unwrap()).await;
        reply.cookie(FLOW_COOKIE)
    }

    async fn start(h: &Harness, provider: &str, body: &Value, cookies: &str) -> Reply {
        let mut request = Request::builder()
            .method(Method::POST)
            .uri(format!("/upstream/{provider}/start"))
            .header(header::ORIGIN, ISSUER)
            .header(header::CONTENT_TYPE, "application/json");
        if !cookies.is_empty() {
            request = request.header(header::COOKIE, cookies);
        }
        call(&h.app, request.body(Body::from(body.to_string())).unwrap()).await
    }

    /// Plays the provider: reads the authorization URL, issues `code` for its challenge and
    /// nonce, and returns the callback query with the given state.
    fn provider_issues_code(h: &Harness, authorize_url: &str, code: &str) -> String {
        let query: HashMap<String, String> =
            form_urlencoded::parse(authorize_url.split_once('?').unwrap().1.as_bytes())
                .into_owned()
                .collect();
        assert_eq!(query["code_challenge_method"], "S256");
        h.fake.codes.lock().unwrap().insert(
            code.to_owned(),
            (
                query["code_challenge"].clone(),
                query.get("nonce").cloned().unwrap_or_default(),
            ),
        );
        format!("code={code}&state={}", query["state"])
    }

    async fn callback(h: &Harness, provider: &str, query: &str, cookies: &str) -> Reply {
        let reply = call(
            &h.app,
            Request::get(format!("/upstream/{provider}/callback?{query}"))
                .header(header::COOKIE, cookies)
                .header(header::ACCEPT_LANGUAGE, "en")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        for token in h
            .fake
            .secrets
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
        {
            assert!(
                !reply.logs.contains(token),
                "generated provider ID token leaked"
            );
        }
        for pair in cookies.split(';') {
            if let Some((UPSTREAM_COOKIE, sealed)) = pair.trim().split_once('=')
                && let Some(pending) = h
                    .service
                    .sign_in
                    .oauth
                    .sealer
                    .open("zeabur-identity/upstream/v1", sealed)
                    .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
            {
                for key in ["state", "nonce", "verifier", "link", "id"] {
                    if let Some(secret) = pending[key].as_str() {
                        assert!(!reply.logs.contains(secret), "sealed pending secret leaked");
                    }
                }
            }
        }
        reply
    }

    /// The account `subject` at `kind`'s issuer.
    fn external(kind: Kind, subject: &str) -> ExternalId {
        ExternalId {
            issuer: Issuer::new(kind.issuer()).unwrap(),
            subject: Subject::new(subject).unwrap(),
        }
    }

    async fn link(h: &Harness, kind: Kind, subject: &str, user: &str) {
        h.service
            .sign_in
            .credentials
            .link(&NewExternal {
                id: external(kind, subject),
                user: user.into(),
                provider: kind.id(),
                user_subject: format!("uid-{user}"),
            })
            .await
            .unwrap();
    }

    /// Runs a sign-in with `provider` up to the callback; returns the callback reply.
    async fn sign_in(h: &Harness, provider: &str, code: &str) -> Reply {
        let flow = authorize(h, "openid").await;
        let started = start(h, provider, &json!({}), &format!("{FLOW_COOKIE}={flow}")).await;
        assert_eq!(started.status, StatusCode::OK, "{}", started.body);
        let url = started.json()["redirect_to"].as_str().unwrap().to_owned();
        let query = provider_issues_code(h, &url, code);
        let cookies = format!(
            "{FLOW_COOKIE}={flow}; {UPSTREAM_COOKIE}={}",
            started.cookie(UPSTREAM_COOKIE)
        );
        callback(h, provider, &query, &cookies).await
    }

    #[tokio::test]
    async fn a_linked_github_account_signs_in_and_gets_a_code() {
        let h = harness().await;
        link(&h, Kind::GitHub, &GITHUB_ID.to_string(), "alice").await;
        let reply = sign_in(&h, "github", "code-1").await;
        assert_eq!(reply.status, StatusCode::SEE_OTHER, "{}", reply.body);
        assert_audit(
            &reply,
            "auth.sign_in",
            None,
            Some("alice"),
            Some("uid-alice"),
        );
        let location = reply.headers[header::LOCATION].to_str().unwrap();
        assert!(
            location.starts_with("http://127.0.0.1:8000/?code="),
            "{location}"
        );

        let tokens = exchange(&h, location).await.json();
        let payload = tokens["access_token"]
            .as_str()
            .unwrap()
            .split('.')
            .nth(1)
            .unwrap();
        let claims: Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).unwrap()).unwrap();
        assert_eq!(claims["sub"], "uid-alice");
        // No passkey: no `amr`.
        assert!(claims.get("amr").is_none(), "{claims}");
    }

    #[tokio::test]
    async fn a_link_left_from_a_removed_user_does_not_sign_in_as_a_new_user_of_that_name() {
        let h = harness().await;
        link(&h, Kind::GitHub, &GITHUB_ID.to_string(), "alice").await;
        // Remove alice but not her link, then give the name to a new person.
        let directory = &h.service.sign_in.oauth.directory;
        directory.remove_user("alice");
        directory.put_user(User {
            name: "alice".into(),
            subject: "uid-alice-new".into(),
            username: "alice".into(),
            groups: vec!["dev".into()],
            ..User::default()
        });
        let reply = sign_in(&h, "github", "code-1").await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{}", reply.body);
        assert!(
            reply.body.contains("account_unlinked (github)"),
            "{}",
            reply.body
        );
        assert!(!reply.headers.contains_key(header::LOCATION));
    }

    #[tokio::test]
    async fn unlinked_disabled_and_replayed_sign_ins_fail() {
        let h = harness().await;
        let reply = sign_in(&h, "github", "code-1").await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST);
        assert_audit(&reply, "auth.sign_in", Some("account_unlinked"), None, None);
        assert!(
            reply.body.contains("account_unlinked (github)"),
            "{}",
            reply.body
        );

        link(&h, Kind::Google, GOOGLE_SUB, "zed").await;
        let reply = sign_in(&h, "google", "code-2").await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "disabled user");
        assert!(
            reply.body.contains("user_unavailable (google)"),
            "{}",
            reply.body
        );
        assert_audit(
            &reply,
            "auth.sign_in",
            Some("user_unavailable"),
            Some("zed"),
            Some("uid-zed"),
        );

        // The same state twice: the second is refused.
        link(&h, Kind::GitHub, &GITHUB_ID.to_string(), "alice").await;
        let flow = authorize(&h, "openid").await;
        let started = start(&h, "github", &json!({}), &format!("{FLOW_COOKIE}={flow}")).await;
        let url = started.json()["redirect_to"].as_str().unwrap().to_owned();
        let query = provider_issues_code(&h, &url, "code-3");
        let cookies = format!(
            "{FLOW_COOKIE}={flow}; {UPSTREAM_COOKIE}={}",
            started.cookie(UPSTREAM_COOKIE)
        );
        let first = callback(&h, "github", &query, &cookies).await;
        assert_eq!(first.status, StatusCode::SEE_OTHER);
        assert_audit(
            &first,
            "auth.sign_in",
            None,
            Some("alice"),
            Some("uid-alice"),
        );
        let second_attempt = callback(&h, "github", &query, &cookies).await;
        assert_eq!(second_attempt.status, StatusCode::BAD_REQUEST);
        assert_audit(
            &second_attempt,
            "auth.sign_in",
            Some("invalid_state"),
            None,
            None,
        );

        // A forged state, or no cookie, is refused.
        let flow = authorize(&h, "openid").await;
        let started = start(&h, "github", &json!({}), &format!("{FLOW_COOKIE}={flow}")).await;
        let url = started.json()["redirect_to"].as_str().unwrap().to_owned();
        provider_issues_code(&h, &url, "code-4");
        let cookies = format!(
            "{FLOW_COOKIE}={flow}; {UPSTREAM_COOKIE}={}",
            started.cookie(UPSTREAM_COOKIE)
        );
        let forged = callback(&h, "github", "code=code-4&state=forged", &cookies).await;
        assert_eq!(forged.status, StatusCode::BAD_REQUEST);
        assert!(forged.body.contains("invalid_state (github)"));
        assert_audit(&forged, "auth.sign_in", Some("invalid_state"), None, None);
        let no_cookie = callback(&h, "github", "code=code-4&state=x", "").await;
        assert_eq!(no_cookie.status, StatusCode::BAD_REQUEST);
        assert_audit(
            &no_cookie,
            "auth.upstream_callback",
            Some("invalid_pending"),
            None,
            None,
        );
    }

    #[tokio::test]
    async fn start_requires_a_pending_request() {
        let h = harness().await;
        let reply = start(&h, "github", &json!({}), "").await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST);
        let reply = start(&h, "gitlab", &json!({}), "").await;
        assert_eq!(reply.status, StatusCode::NOT_FOUND);
        // Cross-site requests are refused before anything else.
        let reply = call(
            &h.app,
            Request::post("/upstream/github/start")
                .header(header::ORIGIN, "https://evil.example")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await;
        assert_eq!(reply.status, StatusCode::FORBIDDEN);
    }

    async fn make_admin(h: &Harness, name: &str) {
        let directory = &h.service.sign_in.oauth.directory;
        let mut user = directory.user(name).await.unwrap().unwrap();
        user.account_type = AccountType::Admin;
        directory.put_user(user);
    }

    #[tokio::test]
    async fn admin_accounts_neither_sign_in_with_nor_link_github_or_google() {
        let h = harness().await;
        link(&h, Kind::GitHub, &GITHUB_ID.to_string(), "alice").await;
        make_admin(&h, "alice").await;
        let reply = sign_in(&h, "github", "code-1").await;
        assert!(reply.status.is_client_error(), "{}", reply.status);
        assert!(reply.body.contains("admin_needs_passkey"), "{}", reply.body);
        assert_audit(
            &reply,
            "auth.sign_in",
            Some("admin_needs_passkey"),
            Some("alice"),
            Some("uid-alice"),
        );

        make_admin(&h, "dana").await;
        let started = start(&h, "google", &json!({ "token": INVITATION }), "").await;
        assert_eq!(started.status, StatusCode::FORBIDDEN, "{}", started.body);
        assert_eq!(
            started.json()["type"],
            "urn:zeabur-identity:problem:admin-needs-passkey"
        );
    }

    #[tokio::test]
    async fn an_invitation_links_an_account_once() {
        let h = harness().await;
        let started = start(&h, "google", &json!({ "token": INVITATION }), "").await;
        assert_eq!(started.status, StatusCode::OK, "{}", started.body);
        let url = started.json()["redirect_to"].as_str().unwrap().to_owned();
        assert!(url.contains("scope=openid") && url.contains("nonce="));
        let query = provider_issues_code(&h, &url, "code-1");
        let cookies = format!("{UPSTREAM_COOKIE}={}", started.cookie(UPSTREAM_COOKIE));
        let reply = callback(&h, "google", &query, &cookies).await;
        assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
        assert!(reply.body.contains("Account linked"));
        assert_audit(&reply, "auth.account_link", None, Some("dana"), None);
        let name = external_credential_name(&external(Kind::Google, GOOGLE_SUB));
        assert_eq!(
            h.service
                .sign_in
                .credentials
                .linked_account(&name)
                .await
                .unwrap()
                .map(|linked| (linked.user, linked.user_subject)),
            Some(("dana".to_owned(), Some("uid-dana".to_owned())))
        );
        let events = h.service.sign_in.credentials.events();
        assert!(
            events
                .iter()
                .any(|event| event.reason == "InvitationRedeemed" && event.user == "dana"),
            "{events:?}"
        );
        // The invitation is used up.
        let again = start(&h, "google", &json!({ "token": INVITATION }), "").await;
        assert_eq!(again.status, StatusCode::UNAUTHORIZED);

        // And the linked account now signs in as dana.
        let reply = sign_in(&h, "google", "code-2").await;
        assert_eq!(reply.status, StatusCode::SEE_OTHER, "{}", reply.body);
        assert_audit(&reply, "auth.sign_in", None, Some("dana"), Some("uid-dana"));
    }

    #[tokio::test]
    async fn google_id_tokens_are_validated() {
        let h = harness().await;
        link(&h, Kind::Google, GOOGLE_SUB, "alice").await;
        let now = SystemClock.now().as_secs();
        for (claim, value) in [
            ("aud", json!("someone-else")),
            ("aud", json!(["google-client", "other"])),
            ("aud", json!([])),
            ("azp", json!("other")),
            ("iss", json!("https://evil.example")),
            ("exp", json!(now - 3600)),
            ("nonce", json!("replayed")),
            ("iat", json!(now + 3600)),
        ] {
            *h.fake.id_token_overrides.lock().unwrap() = json!({ claim: value });
            let reply = sign_in(&h, "google", &format!("code-{claim}")).await;
            assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{claim}={value}");
            // A token outside its validity window points at this server's clock.
            assert_eq!(
                reply
                    .body
                    .contains(Lang::En.messages().err_clock_skew.title),
                matches!(claim, "exp" | "iat"),
                "{claim}={value}"
            );
            assert_audit(
                &reply,
                "auth.sign_in",
                Some("provider_verification_failed"),
                None,
                None,
            );
        }
        // Another audience is refused even when azp names this client (OIDC Core §3.1.3.7 step 3).
        *h.fake.id_token_overrides.lock().unwrap() =
            json!({ "aud": ["google-client", "other"], "azp": "google-client" });
        assert_eq!(
            sign_in(&h, "google", "code-azp-other").await.status,
            StatusCode::BAD_REQUEST
        );
        // Google's documentation lists both spellings of its issuer.
        *h.fake.id_token_overrides.lock().unwrap() = json!({ "iss": "accounts.google.com" });
        let reply = sign_in(&h, "google", "code-iss-short").await;
        assert_eq!(reply.status, StatusCode::SEE_OTHER, "{}", reply.body);
        assert_audit(
            &reply,
            "auth.sign_in",
            None,
            Some("alice"),
            Some("uid-alice"),
        );
        // A one-element array naming this client, with a matching azp, is accepted.
        *h.fake.id_token_overrides.lock().unwrap() =
            json!({ "aud": ["google-client"], "azp": "google-client" });
        assert_eq!(
            sign_in(&h, "google", "code-azp").await.status,
            StatusCode::SEE_OTHER
        );

        // A token signed by a key outside the published set is refused.
        *h.fake.id_token_overrides.lock().unwrap() = json!({});
        let rogue = Arc::new(SigningKey::generate(Algorithm::Rs256).unwrap());
        *h.fake.google_key.lock().unwrap() = Some(rogue);
        let reply = sign_in(&h, "google", "code-rogue").await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST);
        assert_audit(
            &reply,
            "auth.sign_in",
            Some("provider_verification_failed"),
            None,
            None,
        );
    }

    #[tokio::test]
    async fn verified_provider_does_not_succeed_before_local_authorization() {
        for failure in ["invalid_flow", "expired_flow", "missing_flow"] {
            let h = harness().await;
            link(&h, Kind::Google, GOOGLE_SUB, "alice").await;
            let flow = authorize(&h, "openid").await;
            let started = start(&h, "google", &json!({}), &format!("{FLOW_COOKIE}={flow}")).await;
            let query = provider_issues_code(
                &h,
                started.json()["redirect_to"].as_str().unwrap(),
                "secret-code-local-rejection",
            );
            let rejected_flow = match failure {
                "invalid_flow" => "secret-forged-flow".to_owned(),
                "expired_flow" => {
                    let oauth = &h.service.sign_in.oauth;
                    let mut flow: Value = serde_json::from_slice(
                        &oauth.sealer.open(endpoints::FLOW_PURPOSE, &flow).unwrap(),
                    )
                    .unwrap();
                    flow["expires_at"] = json!(0);
                    oauth
                        .sealer
                        .seal(endpoints::FLOW_PURPOSE, &serde_json::to_vec(&flow).unwrap())
                        .unwrap()
                }
                "missing_flow" => String::new(),
                _ => unreachable!(),
            };
            let mut cookies = format!("{UPSTREAM_COOKIE}={}", started.cookie(UPSTREAM_COOKIE));
            if failure != "missing_flow" {
                write!(cookies, "; {FLOW_COOKIE}={rejected_flow}").unwrap();
            }
            let reply = callback(&h, "google", &query, &cookies).await;
            assert_eq!(reply.status, StatusCode::BAD_REQUEST);
            let reason = if failure == "missing_flow" {
                "missing_flow"
            } else {
                "authorization_failed"
            };
            assert_audit(
                &reply,
                "auth.sign_in",
                Some(reason),
                Some("alice"),
                Some("uid-alice"),
            );
            assert_eq!(
                reply.audit.as_ref().unwrap()["fields"]["outcome"],
                "failure"
            );
            assert!(
                h.fake.codes.lock().unwrap().is_empty(),
                "provider code was verified first"
            );
        }
    }

    #[tokio::test]
    async fn callback_classification_requires_verified_unexpired_pending() {
        let h = harness().await;
        let started = start(&h, "google", &json!({ "token": INVITATION }), "").await;
        let oauth = &h.service.sign_in.oauth;
        let mut pending: Value = serde_json::from_slice(
            &oauth
                .sealer
                .open(
                    "zeabur-identity/upstream/v1",
                    &started.cookie(UPSTREAM_COOKIE),
                )
                .unwrap(),
        )
        .unwrap();
        pending["expires_at"] = json!(0);
        let expired = oauth
            .sealer
            .seal(
                "zeabur-identity/upstream/v1",
                &serde_json::to_vec(&pending).unwrap(),
            )
            .unwrap();
        for (provider, cookies) in [
            ("google", format!("{UPSTREAM_COOKIE}={expired}")),
            (
                "google",
                format!("{UPSTREAM_COOKIE}=secret-invalid-pending"),
            ),
            ("unknown-secret-provider", String::new()),
            (
                "github",
                format!("{UPSTREAM_COOKIE}={}", started.cookie(UPSTREAM_COOKIE)),
            ),
        ] {
            let reply = callback(
                &h,
                provider,
                "code=secret-code&state=secret-state",
                &cookies,
            )
            .await;
            assert_eq!(reply.status, StatusCode::BAD_REQUEST);
            assert_audit(
                &reply,
                "auth.upstream_callback",
                Some("invalid_pending"),
                None,
                None,
            );
            assert!(!reply.logs.contains("unknown-secret-provider"));
        }
    }

    #[tokio::test]
    async fn provider_denial_and_secret_bearing_http_failure_have_fixed_reasons() {
        let h = harness().await;
        link(&h, Kind::Google, GOOGLE_SUB, "alice").await;
        let flow = authorize(&h, "openid").await;
        let started = start(&h, "google", &json!({}), &format!("{FLOW_COOKIE}={flow}")).await;
        let cookies = format!("{UPSTREAM_COOKIE}={}", started.cookie(UPSTREAM_COOKIE));
        let denied = callback(&h, "google", "error=secret-provider-error", &cookies).await;
        assert_audit(&denied, "auth.sign_in", Some("provider_denied"), None, None);
        assert!(!denied.logs.contains("secret-provider-error"));
        h.fake.fail_http.store(true, Ordering::SeqCst);
        let failed = sign_in(&h, "google", "secret-code-http-failure").await;
        assert_eq!(failed.status, StatusCode::BAD_REQUEST);
        assert_audit(
            &failed,
            "auth.sign_in",
            Some("provider_verification_failed"),
            None,
            None,
        );
        assert!(!failed.body.contains(SECRET_ERROR));
        let records: Vec<Value> = serde_json::from_str(&failed.logs).unwrap();
        let diagnostic = records
            .iter()
            .find(|record| record["target"] == "zeabur_identity_signin::upstream")
            .unwrap();
        assert_eq!(
            diagnostic["fields"]["reason"],
            "provider_verification_failed"
        );
        // The operator log keeps the detail; the audit record does not.
        assert!(
            diagnostic["fields"]["error"]
                .as_str()
                .unwrap()
                .contains(SECRET_ERROR)
        );
        let audit = failed.audit.as_ref().unwrap();
        assert!(audit["fields"].get("error").is_none());
        assert!(!serde_json::to_string(audit).unwrap().contains(SECRET_ERROR));
    }

    #[tokio::test]
    async fn link_failures_are_not_fresh_sign_ins() {
        for already_linked in [false, true] {
            let h = harness().await;
            let started = start(&h, "google", &json!({ "token": INVITATION }), "").await;
            let query = provider_issues_code(
                &h,
                started.json()["redirect_to"].as_str().unwrap(),
                "secret-code-link-failure",
            );
            if already_linked {
                link(&h, Kind::Google, GOOGLE_SUB, "alice").await;
            } else {
                // The valid invitation was consumed while the user was at the provider.
                let token = h
                    .service
                    .sign_in
                    .setup
                    .load(INVITATION)
                    .await
                    .unwrap()
                    .unwrap();
                h.service.sign_in.setup.consume(&token).await.unwrap();
            }
            let reply = callback(
                &h,
                "google",
                &query,
                &format!("{UPSTREAM_COOKIE}={}", started.cookie(UPSTREAM_COOKIE)),
            )
            .await;
            assert_eq!(reply.status, StatusCode::BAD_REQUEST);
            let reason = if already_linked {
                "account_already_linked"
            } else {
                "invalid_setup"
            };
            assert_audit(&reply, "auth.account_link", Some(reason), None, None);
            assert_eq!(
                reply.audit.as_ref().unwrap()["fields"]["outcome"],
                "failure"
            );
        }
    }

    /// An account-page session for `user`, as a passkey sign-in `age` ago creates it.
    struct Session {
        cookie: String,
        csrf: String,
        name: String,
    }

    async fn account_session(h: &Harness, user: &str, age: u64) -> Session {
        let token = SessionToken::generate().unwrap();
        let now = SystemClock.now().as_secs();
        let at = zeabur_identity_core::clock::UnixTime::from_secs(now - age);
        let expires_at = zeabur_identity_core::clock::UnixTime::from_secs(now + 3600);
        h.service
            .sign_in
            .oauth
            .grants
            .create(
                &NewGrant {
                    name: token.name().to_owned(),
                    user: user.into(),
                    client: ACCOUNT_CLIENT.into(),
                    audience: ISSUER.into(),
                    scopes: vec![],
                    auth_time: at,
                    amr: vec!["swk".into(), "mfa".into()],
                    expires_at,
                    initial_hash: token.hash(),
                    subject: Some(format!("uid-{user}")),
                    credential: Some("c-passkey".into()),
                    user_verified: true,
                    device_bound: false,
                },
                expires_at,
            )
            .await
            .unwrap();
        Session {
            cookie: format!("{SESSION_COOKIE}={}", token.encode()),
            csrf: token.csrf(),
            name: token.name().to_owned(),
        }
    }

    async fn account_post(h: &Harness, path: &str, body: &Value, cookies: &str) -> Reply {
        let mut request = Request::builder()
            .method(Method::POST)
            .uri(path)
            .header(header::ORIGIN, ISSUER)
            .header(header::CONTENT_TYPE, "application/json");
        if !cookies.is_empty() {
            request = request.header(header::COOKIE, cookies);
        }
        call(&h.app, request.body(Body::from(body.to_string())).unwrap()).await
    }

    /// Starts linking `provider` from `session` and plays the provider. Returns the callback
    /// query and the upstream cookie.
    async fn start_account_link(
        h: &Harness,
        session: &Session,
        provider: &str,
        code: &str,
    ) -> (String, String) {
        let started = account_post(
            h,
            "/account/links/start",
            &json!({ "csrf": session.csrf, "provider": provider }),
            &session.cookie,
        )
        .await;
        assert_eq!(started.status, StatusCode::OK, "{}", started.body);
        let url = started.json()["redirect_to"].as_str().unwrap().to_owned();
        let query = provider_issues_code(h, &url, code);
        (
            query,
            format!("{UPSTREAM_COOKIE}={}", started.cookie(UPSTREAM_COOKIE)),
        )
    }

    async fn linked_to(h: &Harness, kind: Kind, subject: &str) -> Option<String> {
        h.service
            .sign_in
            .credentials
            .linked_account(&external_credential_name(&external(kind, subject)))
            .await
            .unwrap()
            .map(|linked| linked.user)
    }

    async fn account_page(h: &Harness, session: &Session) -> String {
        let reply = call(
            &h.app,
            Request::get("/account")
                .header(header::COOKIE, &session.cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(reply.status, StatusCode::OK);
        reply.body
    }

    async fn token(h: &Harness, pairs: &[(&str, &str)]) -> Reply {
        let form = form_urlencoded::Serializer::new(String::new())
            .extend_pairs(pairs)
            .finish();
        call(
            &h.app,
            Request::post("/token")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(form))
                .unwrap(),
        )
        .await
    }

    /// Exchanges the code in the redirect to `location` for kubectl's tokens.
    async fn exchange(h: &Harness, location: &str) -> Reply {
        let code = form_urlencoded::parse(location.split_once('?').unwrap().1.as_bytes())
            .find(|(k, _)| k == "code")
            .unwrap()
            .1
            .into_owned();
        token(
            h,
            &[
                ("grant_type", "authorization_code"),
                ("code", code.as_str()),
                ("code_verifier", VERIFIER),
                ("client_id", "kubectl"),
            ],
        )
        .await
    }

    #[tokio::test]
    async fn a_signed_in_user_links_an_account_on_the_account_page() {
        let h = harness().await;
        let session = account_session(&h, "alice", 0).await;
        let page = account_page(&h, &session).await;
        assert!(page.contains(r#"data-link="github""#));
        assert!(page.contains(r#"data-link="google""#));
        assert!(!page.contains("data-linked="));
        let (query, upstream) = start_account_link(&h, &session, "github", "code-1").await;
        let reply = callback(
            &h,
            "github",
            &query,
            &format!("{upstream}; {}", session.cookie),
        )
        .await;
        assert_eq!(reply.status, StatusCode::SEE_OTHER, "{}", reply.body);
        assert_eq!(
            reply.headers[header::LOCATION],
            format!("{ISSUER}/account#notice=linked")
        );
        assert_audit(
            &reply,
            "account.upstream_linked",
            None,
            Some("alice"),
            Some("uid-alice"),
        );
        let name = external_credential_name(&external(Kind::GitHub, &GITHUB_ID.to_string()));
        assert_eq!(
            h.service
                .sign_in
                .credentials
                .linked_account(&name)
                .await
                .unwrap()
                .map(|linked| (linked.user, linked.user_subject)),
            Some(("alice".to_owned(), Some("uid-alice".to_owned())))
        );
        let events = h.service.sign_in.credentials.events();
        assert!(
            events.iter().any(|event| event.reason == "AccountLinked"
                && event.user == "alice"
                && event.note.contains(&name)),
            "{events:?}"
        );
        let page = account_page(&h, &session).await;
        assert!(page.contains(&format!(r#"data-linked="{name}""#)));
        // The account now signs in as alice.
        let reply = sign_in(&h, "github", "code-2").await;
        assert_eq!(reply.status, StatusCode::SEE_OTHER, "{}", reply.body);
        assert_audit(
            &reply,
            "auth.sign_in",
            None,
            Some("alice"),
            Some("uid-alice"),
        );
    }

    /// The link buttons on an account page: each one's provider ID and text, in page order.
    fn link_buttons(page: &str) -> Vec<(String, String)> {
        let mut buttons = Vec::new();
        for rest in page.split(r#"data-link=""#).skip(1) {
            let (id, rest) = rest.split_once('"').unwrap();
            let (inside, _) = rest.split_once("</button>").unwrap();
            let text = inside.rsplit_once('>').unwrap().1;
            buttons.push((id.to_owned(), text.to_owned()));
        }
        buttons
    }

    #[tokio::test]
    async fn the_account_page_offers_exactly_the_configured_providers_and_each_starts_its_own() {
        let authorize = |id: &str| match id {
            "github" => "https://github.test/authorize?",
            "google" => "https://google.test/authorize?",
            other => panic!("no provider {other}"),
        };
        let label = |id: &str| match id {
            "github" => "Link GitHub",
            "google" => "Link Google",
            other => panic!("no provider {other}"),
        };
        let sets: [&[&str]; 4] = [
            &[],
            &["google"],
            &["github", "google"],
            &["google", "github"],
        ];
        for configured in sets {
            let h = harness_with(GOOGLE_ISSUER, configured).await;
            let session = account_session(&h, "alice", 0).await;
            let page = account_page(&h, &session).await;
            let mut expected = Vec::new();
            for id in configured {
                expected.push(((*id).to_owned(), label(id).to_owned()));
            }
            assert_eq!(link_buttons(&page), expected, "{configured:?}");

            for id in configured {
                let started = account_post(
                    &h,
                    "/account/links/start",
                    &json!({ "csrf": session.csrf, "provider": id }),
                    &session.cookie,
                )
                .await;
                assert_eq!(started.status, StatusCode::OK, "{}", started.body);
                let url = started.json()["redirect_to"].as_str().unwrap().to_owned();
                assert!(url.starts_with(authorize(id)), "{id}: {url}");
            }
            for id in ["github", "google"] {
                if configured.contains(&id) {
                    continue;
                }
                let started = account_post(
                    &h,
                    "/account/links/start",
                    &json!({ "csrf": session.csrf, "provider": id }),
                    &session.cookie,
                )
                .await;
                assert_eq!(
                    started.status,
                    StatusCode::NOT_FOUND,
                    "{id} in {configured:?}"
                );
            }
        }
    }

    #[tokio::test]
    async fn linking_needs_a_fresh_confirmation_and_the_session_that_started_it() {
        let h = harness().await;
        let stale = account_session(&h, "alice", 600).await;
        let fresh = account_session(&h, "alice", 0).await;
        let cases = [
            (&stale.cookie, stale.csrf.as_str(), "reauth-required"),
            (&fresh.cookie, stale.csrf.as_str(), "csrf"),
            (&String::new(), fresh.csrf.as_str(), "signed-out"),
        ];
        for (cookie, csrf, kind) in cases {
            let reply = account_post(
                &h,
                "/account/links/start",
                &json!({ "csrf": csrf, "provider": "github" }),
                cookie,
            )
            .await;
            assert_eq!(
                reply.json()["type"],
                format!("urn:zeabur-identity:problem:{kind}"),
                "{}",
                reply.body
            );
            assert!(
                !reply
                    .headers
                    .get_all(header::SET_COOKIE)
                    .iter()
                    .any(|v| v.to_str().unwrap().starts_with(UPSTREAM_COOKIE))
            );
        }
        let reply = account_post(
            &h,
            "/account/links/start",
            &json!({ "csrf": fresh.csrf, "provider": "gitlab" }),
            &fresh.cookie,
        )
        .await;
        assert_eq!(reply.status, StatusCode::NOT_FOUND);

        // The callback must come with the session that started, still signed in.
        let other = account_session(&h, "alice", 0).await;
        let dana = account_session(&h, "dana", 0).await;
        let revoked = account_session(&h, "alice", 0).await;
        for (code, session) in [
            ("code-1", Some(&other)),
            ("code-2", Some(&dana)),
            ("code-3", None),
            ("code-4", Some(&revoked)),
        ] {
            let starter = if code == "code-4" { &revoked } else { &fresh };
            let (query, upstream) = start_account_link(&h, starter, "github", code).await;
            if code == "code-4" {
                h.service
                    .sign_in
                    .oauth
                    .grants
                    .revoke(&revoked.name)
                    .await
                    .unwrap();
            }
            let cookies = session.map_or_else(
                || upstream.clone(),
                |session| format!("{upstream}; {}", session.cookie),
            );
            let reply = callback(&h, "github", &query, &cookies).await;
            assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{code}");
            assert!(reply.body.contains("session_mismatch (github)"), "{code}");
            assert_eq!(
                linked_to(&h, Kind::GitHub, &GITHUB_ID.to_string()).await,
                None
            );
        }

        // A user turned off while at the provider does not get the link.
        let (query, upstream) = start_account_link(&h, &fresh, "github", "code-5").await;
        let directory = &h.service.sign_in.oauth.directory;
        let mut alice = directory.user("alice").await.unwrap().unwrap();
        alice.disabled = true;
        directory.put_user(alice);
        let reply = callback(
            &h,
            "github",
            &query,
            &format!("{upstream}; {}", fresh.cookie),
        )
        .await;
        assert!(reply.body.contains("session_mismatch (github)"));
        assert_eq!(
            linked_to(&h, Kind::GitHub, &GITHUB_ID.to_string()).await,
            None
        );
    }

    #[tokio::test]
    async fn an_account_linked_to_anyone_is_not_linked_again() {
        for owner in ["dana", "alice"] {
            let h = harness().await;
            link(&h, Kind::Google, GOOGLE_SUB, owner).await;
            let session = account_session(&h, "alice", 0).await;
            let (query, upstream) = start_account_link(&h, &session, "google", "code-1").await;
            let reply = callback(
                &h,
                "google",
                &query,
                &format!("{upstream}; {}", session.cookie),
            )
            .await;
            assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{owner}");
            assert_audit(
                &reply,
                "account.upstream_linked",
                Some("account_already_linked"),
                Some("alice"),
                Some("uid-alice"),
            );
            assert_eq!(
                linked_to(&h, Kind::Google, GOOGLE_SUB).await.as_deref(),
                Some(owner)
            );
        }
    }

    #[tokio::test]
    async fn admin_accounts_cannot_link_from_the_account_page() {
        let h = harness().await;
        make_admin(&h, "dana").await;
        let session = account_session(&h, "dana", 0).await;
        let reply = account_post(
            &h,
            "/account/links/start",
            &json!({ "csrf": session.csrf, "provider": "github" }),
            &session.cookie,
        )
        .await;
        assert_eq!(
            reply.json()["type"],
            "urn:zeabur-identity:problem:admin-needs-passkey"
        );
        assert!(!account_page(&h, &session).await.contains("data-link="));

        // Made an admin while at the provider.
        let session = account_session(&h, "alice", 0).await;
        let (query, upstream) = start_account_link(&h, &session, "github", "code-1").await;
        make_admin(&h, "alice").await;
        let reply = callback(
            &h,
            "github",
            &query,
            &format!("{upstream}; {}", session.cookie),
        )
        .await;
        assert!(reply.body.contains("admin_needs_passkey (github)"));
        assert_eq!(
            linked_to(&h, Kind::GitHub, &GITHUB_ID.to_string()).await,
            None
        );
    }

    #[tokio::test]
    async fn unlinking_keeps_a_way_to_sign_in_and_ends_what_the_account_signed_in() {
        let h = harness().await;
        link(&h, Kind::GitHub, &GITHUB_ID.to_string(), "alice").await;
        let github = external_credential_name(&external(Kind::GitHub, &GITHUB_ID.to_string()));
        let stale = account_session(&h, "alice", 600).await;
        let session = account_session(&h, "alice", 0).await;
        let unlink = |session: &Session, name: &str| {
            let body = json!({ "csrf": session.csrf, "name": name });
            let cookie = session.cookie.clone();
            let h = &h;
            async move { account_post(h, "/account/links/remove", &body, &cookie).await }
        };
        let reply = unlink(&stale, &github).await;
        assert_eq!(
            reply.json()["type"],
            "urn:zeabur-identity:problem:reauth-required"
        );
        // GitHub is alice's only credential here.
        let reply = unlink(&session, &github).await;
        assert_eq!(
            reply.json()["type"],
            "urn:zeabur-identity:problem:last-credential"
        );
        assert!(
            linked_to(&h, Kind::GitHub, &GITHUB_ID.to_string())
                .await
                .is_some()
        );
        // Another user's linked account is not found.
        link(&h, Kind::Google, GOOGLE_SUB, "dana").await;
        let google = external_credential_name(&external(Kind::Google, GOOGLE_SUB));
        let reply = unlink(&session, &google).await;
        assert_eq!(reply.status, StatusCode::NOT_FOUND);
        assert_eq!(
            linked_to(&h, Kind::Google, GOOGLE_SUB).await.as_deref(),
            Some("dana")
        );

        // With a second credential, the GitHub account goes, and so does what it signed in.
        h.service
            .sign_in
            .credentials
            .link(&NewExternal {
                id: external(Kind::Google, "second"),
                user: "alice".into(),
                provider: Kind::Google.id(),
                user_subject: "uid-alice".into(),
            })
            .await
            .unwrap();
        let signed_in = sign_in(&h, "github", "code-1").await;
        assert_eq!(signed_in.status, StatusCode::SEE_OTHER);
        let location = signed_in.headers[header::LOCATION].to_str().unwrap();
        let tokens = exchange(&h, location).await.json();
        let refresh = tokens["refresh_token"].as_str().unwrap().to_owned();

        let reply = unlink(&session, &github).await;
        assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
        assert_eq!(reply.json()["signed_out"], false);
        assert_eq!(
            linked_to(&h, Kind::GitHub, &GITHUB_ID.to_string()).await,
            None
        );
        let events = h.service.sign_in.credentials.events();
        assert!(
            events
                .iter()
                .any(|event| event.reason == "AccountUnlinked" && event.note.contains(&github)),
            "{events:?}"
        );
        let renewed = token(
            &h,
            &[
                ("grant_type", "refresh_token"),
                ("refresh_token", refresh.as_str()),
                ("client_id", "kubectl"),
            ],
        )
        .await;
        assert_eq!(renewed.status, StatusCode::BAD_REQUEST, "{}", renewed.body);
        let reply = sign_in(&h, "github", "code-2").await;
        assert!(reply.body.contains("account_unlinked (github)"));
    }

    fn requests(h: &Harness) -> Vec<String> {
        h.fake.requests.lock().unwrap().clone()
    }

    #[tokio::test]
    async fn the_openid_provider_is_reached_at_the_endpoints_its_discovery_document_names() {
        let h = harness().await;
        link(&h, Kind::Google, GOOGLE_SUB, "alice").await;
        let flow = authorize(&h, "openid").await;
        let started = start(&h, "google", &json!({}), &format!("{FLOW_COOKIE}={flow}")).await;
        let url = started.json()["redirect_to"].as_str().unwrap().to_owned();
        assert!(url.starts_with("https://google.test/authorize?"), "{url}");
        let query = provider_issues_code(&h, &url, "code-1");
        let cookies = format!(
            "{FLOW_COOKIE}={flow}; {UPSTREAM_COOKIE}={}",
            started.cookie(UPSTREAM_COOKIE)
        );
        let reply = callback(&h, "google", &query, &cookies).await;
        assert_eq!(reply.status, StatusCode::SEE_OTHER, "{}", reply.body);
        assert_eq!(
            requests(&h),
            [
                "https://accounts.google.com/.well-known/openid-configuration",
                "https://google.test/token",
                "https://google.test/jwks",
            ]
        );
    }

    #[tokio::test]
    async fn another_openid_issuer_signs_in_through_the_same_checks() {
        const IDP: &str = "https://idp.test/realms/dev";
        let h = harness_at(IDP).await;
        h.service
            .sign_in
            .credentials
            .link(&NewExternal {
                id: ExternalId {
                    issuer: Issuer::new(IDP).unwrap(),
                    subject: Subject::new(GOOGLE_SUB).unwrap(),
                },
                user: "alice".into(),
                provider: Kind::Google.id(),
                user_subject: "uid-alice".into(),
            })
            .await
            .unwrap();
        let reply = sign_in(&h, "google", "code-1").await;
        assert_eq!(reply.status, StatusCode::SEE_OTHER, "{}", reply.body);
        assert_audit(
            &reply,
            "auth.sign_in",
            None,
            Some("alice"),
            Some("uid-alice"),
        );
        assert_eq!(
            requests(&h)[0],
            "https://idp.test/realms/dev/.well-known/openid-configuration"
        );
        // Google's second spelling of its issuer is Google's only, and another issuer's tokens
        // are refused like Google's.
        for (case, (claim, value)) in [
            ("iss", json!("accounts.google.com")),
            ("iss", json!(GOOGLE_ISSUER)),
            ("iss", json!("https://idp.test/realms/dev/")),
            ("aud", json!("someone-else")),
            ("nonce", json!("replayed")),
        ]
        .into_iter()
        .enumerate()
        {
            *h.fake.id_token_overrides.lock().unwrap() = json!({ claim: value });
            let reply = sign_in(&h, "google", &format!("code-{case}")).await;
            assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{claim}={value}");
            assert_audit(
                &reply,
                "auth.sign_in",
                Some("provider_verification_failed"),
                None,
                None,
            );
        }
    }

    #[tokio::test]
    async fn an_unusable_discovery_document_ends_the_sign_in_with_no_other_endpoint_tried() {
        for overrides in [
            Value::Null,
            json!({ "issuer": "https://evil.example" }),
            json!({ "issuer": "https://accounts.google.com/" }),
            json!({ "issuer": "accounts.google.com" }),
            json!({ "jwks_uri": null }),
            json!({ "token_endpoint": "http://google.test/token" }),
            json!({ "authorization_endpoint": "/authorize" }),
        ] {
            let h = harness().await;
            *h.fake.discovery_overrides.lock().unwrap() = overrides.clone();
            let flow = authorize(&h, "openid").await;
            let started = start(&h, "google", &json!({}), &format!("{FLOW_COOKIE}={flow}")).await;
            assert_eq!(started.status, StatusCode::BAD_GATEWAY, "{overrides}");
            assert_eq!(
                started.json()["type"],
                "urn:zeabur-identity:problem:provider-unavailable"
            );
            assert!(started.headers.get(header::SET_COOKIE).is_none());
            assert_eq!(
                requests(&h),
                ["https://accounts.google.com/.well-known/openid-configuration"],
                "{overrides}"
            );

            // At the callback, the code is not sent anywhere.
            let fresh = google_provider(GOOGLE_ISSUER);
            let verifier = URL_SAFE_NO_PAD.encode(random::<32>().unwrap());
            let nonce = URL_SAFE_NO_PAD.encode(random::<32>().unwrap());
            let exchange = Exchange {
                code: "code-1",
                verifier: &verifier,
                redirect_uri: "https://login.example.com/upstream/google/callback",
                nonce: &nonce,
            };
            assert!(
                fresh
                    .identify(&FakeHttp(Arc::clone(&h.fake)), exchange, SystemClock.now())
                    .await
                    .is_err()
            );
            assert!(
                requests(&h)
                    .iter()
                    .all(|url| url.ends_with("/.well-known/openid-configuration")),
                "{overrides}"
            );
        }
    }

    /// How a callback is reached.
    #[derive(Clone, Copy, Debug)]
    enum Flow {
        /// Sign-in as alice, whose account is linked first.
        SignIn,
        /// Linking with dana's invitation.
        Invitation,
        /// Linking from alice's account page.
        AccountPage,
    }

    fn subject_at(kind: Kind) -> String {
        match kind {
            Kind::GitHub => GITHUB_ID.to_string(),
            Kind::Google => GOOGLE_SUB.to_owned(),
        }
    }

    /// Runs `flow` with `provider` up to the callback, with `extra` added to the callback query.
    async fn run_flow(h: &Harness, provider: &str, flow: Flow, extra: &str) -> Reply {
        let kind = Kind::from_id(provider).unwrap();
        let (query, cookies) = match flow {
            Flow::SignIn => {
                link(h, kind, &subject_at(kind), "alice").await;
                let flow = authorize(h, "openid").await;
                let started =
                    start(h, provider, &json!({}), &format!("{FLOW_COOKIE}={flow}")).await;
                let url = started.json()["redirect_to"].as_str().unwrap().to_owned();
                (
                    provider_issues_code(h, &url, "code-1"),
                    format!(
                        "{FLOW_COOKIE}={flow}; {UPSTREAM_COOKIE}={}",
                        started.cookie(UPSTREAM_COOKIE)
                    ),
                )
            }
            Flow::Invitation => {
                let started = start(h, provider, &json!({ "token": INVITATION }), "").await;
                let url = started.json()["redirect_to"].as_str().unwrap().to_owned();
                (
                    provider_issues_code(h, &url, "code-1"),
                    format!("{UPSTREAM_COOKIE}={}", started.cookie(UPSTREAM_COOKIE)),
                )
            }
            Flow::AccountPage => {
                let session = account_session(h, "alice", 0).await;
                let (query, upstream) = start_account_link(h, &session, provider, "code-1").await;
                (query, format!("{upstream}; {}", session.cookie))
            }
        };
        callback(h, provider, &format!("{query}{extra}"), &cookies).await
    }

    fn iss_param(value: &str) -> String {
        form_urlencoded::Serializer::new(String::new())
            .append_pair("iss", value)
            .finish()
    }

    fn token_requests(h: &Harness) -> usize {
        requests(h)
            .iter()
            .filter(|url| url.ends_with("/token"))
            .count()
    }

    #[tokio::test]
    async fn a_callback_with_another_empty_or_repeated_iss_is_refused_before_the_code_is_sent() {
        for provider in ["github", "google"] {
            let issuer = Kind::from_id(provider).unwrap().issuer();
            for extra in [
                format!("&{}", iss_param("https://evil.example")),
                format!("&{}", iss_param("")),
                format!("&{}", iss_param("accounts.google.com")),
                format!("&{}", iss_param(&format!("{issuer}/"))),
                format!("&{0}&{0}", iss_param(issuer)),
            ] {
                for flow in [Flow::SignIn, Flow::Invitation, Flow::AccountPage] {
                    let h = harness().await;
                    let reply = run_flow(&h, provider, flow, &extra).await;
                    let case = format!("{provider} {flow:?} {extra}");
                    assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{case}");
                    let fields = &reply.audit.as_ref().unwrap()["fields"];
                    assert_eq!(fields["reason"], "issuer_mismatch", "{case}");
                    assert_eq!(fields["outcome"], "failure", "{case}");
                    assert!(
                        reply
                            .body
                            .contains(&format!("issuer_mismatch ({provider})")),
                        "{case}"
                    );
                    assert!(!reply.headers.contains_key(header::LOCATION), "{case}");
                    assert_eq!(token_requests(&h), 0, "{case}");
                    let kind = Kind::from_id(provider).unwrap();
                    let owner = linked_to(&h, kind, &subject_at(kind)).await;
                    let expected = matches!(flow, Flow::SignIn).then(|| "alice".to_owned());
                    assert_eq!(owner, expected, "{case}");
                }
            }
        }
    }

    #[tokio::test]
    async fn a_callback_with_the_matching_or_no_iss_completes() {
        for provider in ["github", "google"] {
            let issuer = Kind::from_id(provider).unwrap().issuer();
            for extra in [String::new(), format!("&{}", iss_param(issuer))] {
                for flow in [Flow::SignIn, Flow::Invitation, Flow::AccountPage] {
                    let h = harness().await;
                    let reply = run_flow(&h, provider, flow, &extra).await;
                    let case = format!("{provider} {flow:?} {extra}");
                    let expected = match flow {
                        Flow::Invitation => StatusCode::OK,
                        Flow::SignIn | Flow::AccountPage => StatusCode::SEE_OTHER,
                    };
                    assert_eq!(reply.status, expected, "{case}: {}", reply.body);
                    assert_eq!(
                        reply.audit.as_ref().unwrap()["fields"]["outcome"],
                        "success",
                        "{case}"
                    );
                    let kind = Kind::from_id(provider).unwrap();
                    let owner = linked_to(&h, kind, &subject_at(kind)).await;
                    let user = if matches!(flow, Flow::Invitation) {
                        "dana"
                    } else {
                        "alice"
                    };
                    assert_eq!(owner.as_deref(), Some(user), "{case}");
                }
            }
        }
    }

    #[tokio::test]
    async fn a_pending_request_without_its_issuer_or_with_another_is_refused() {
        for (change, reason) in [
            (Value::Null, "invalid_pending"),
            (json!("https://idp.example"), "provider_changed"),
        ] {
            let h = harness().await;
            link(&h, Kind::Google, GOOGLE_SUB, "alice").await;
            let flow = authorize(&h, "openid").await;
            let started = start(&h, "google", &json!({}), &format!("{FLOW_COOKIE}={flow}")).await;
            let url = started.json()["redirect_to"].as_str().unwrap().to_owned();
            let query = provider_issues_code(&h, &url, "code-1");
            let sealer = &h.service.sign_in.oauth.sealer;
            let mut pending: Value = serde_json::from_slice(
                &sealer
                    .open(
                        "zeabur-identity/upstream/v1",
                        &started.cookie(UPSTREAM_COOKIE),
                    )
                    .unwrap(),
            )
            .unwrap();
            assert_eq!(pending["issuer"], GOOGLE_ISSUER);
            if change.is_null() {
                pending.as_object_mut().unwrap().remove("issuer");
            } else {
                pending["issuer"] = change;
            }
            let resealed = sealer
                .seal(
                    "zeabur-identity/upstream/v1",
                    &serde_json::to_vec(&pending).unwrap(),
                )
                .unwrap();
            let cookies = format!("{FLOW_COOKIE}={flow}; {UPSTREAM_COOKIE}={resealed}");
            let reply = callback(&h, "google", &query, &cookies).await;
            assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{reason}");
            assert_eq!(reply.audit.as_ref().unwrap()["fields"]["reason"], reason);
            assert!(!reply.headers.contains_key(header::LOCATION));
            assert_eq!(token_requests(&h), 0, "{reason}");
        }
    }

    fn registry(h: &Harness) -> &Providers {
        &h.service.sign_in.providers
    }

    /// Starts a sign-in as alice with `provider` and returns the callback query and cookies.
    async fn started_sign_in(h: &Harness, provider: &str) -> (String, String) {
        let flow = authorize(h, "openid").await;
        let started = start(h, provider, &json!({}), &format!("{FLOW_COOKIE}={flow}")).await;
        assert_eq!(started.status, StatusCode::OK, "{}", started.body);
        let url = started.json()["redirect_to"].as_str().unwrap().to_owned();
        (
            provider_issues_code(h, &url, "code-1"),
            format!(
                "{FLOW_COOKIE}={flow}; {UPSTREAM_COOKIE}={}",
                started.cookie(UPSTREAM_COOKIE)
            ),
        )
    }

    #[tokio::test]
    async fn an_added_provider_starts_at_the_next_request() {
        let h = harness_with(GOOGLE_ISSUER, &["github"]).await;
        link(&h, Kind::Google, GOOGLE_SUB, "alice").await;
        let flow = authorize(&h, "openid").await;
        let started = start(&h, "google", &json!({}), &format!("{FLOW_COOKIE}={flow}")).await;
        assert_eq!(started.status, StatusCode::NOT_FOUND);

        let mut list = registry(&h).current().to_vec();
        list.push(Arc::new(google_provider(GOOGLE_ISSUER)));
        registry(&h).replace(list);
        let reply = sign_in(&h, "google", "code-1").await;
        assert_eq!(reply.status, StatusCode::SEE_OTHER, "{}", reply.body);
    }

    /// A provider deleted or moved to another issuer while the user is at the provider: the code
    /// is not sent anywhere.
    #[tokio::test]
    async fn a_provider_deleted_or_changed_during_a_sign_in_ends_it_before_the_code_is_sent() {
        for (replacement, reason) in [
            (None, "provider_unavailable"),
            (Some("https://idp.test/realms/dev"), "provider_changed"),
        ] {
            let h = harness().await;
            link(&h, Kind::Google, GOOGLE_SUB, "alice").await;
            let (query, cookies) = started_sign_in(&h, "google").await;
            let mut list: Vec<_> = registry(&h)
                .current()
                .iter()
                .filter(|p| p.id().as_str() != "google")
                .cloned()
                .collect();
            if let Some(issuer) = replacement {
                list.push(Arc::new(google_provider(issuer)));
            }
            registry(&h).replace(list);
            let reply = callback(&h, "google", &query, &cookies).await;
            assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{reason}");
            assert_eq!(reply.audit.as_ref().unwrap()["fields"]["reason"], reason);
            assert!(!reply.headers.contains_key(header::LOCATION));
            assert_eq!(token_requests(&h), 0, "{reason}");
        }
    }

    /// The client secret is read at each exchange: a rotated secret works at the next sign-in, and
    /// an unreadable one ends the sign-in before the code is sent, without naming the Secret.
    #[tokio::test]
    async fn the_client_secret_is_read_at_each_exchange() {
        let h = harness_with(GOOGLE_ISSUER, &[]).await;
        link(&h, Kind::GitHub, &GITHUB_ID.to_string(), "alice").await;
        let current: Arc<Mutex<Result<String, String>>> =
            Arc::new(Mutex::new(Ok("stale-secret".into())));
        let source = Arc::clone(&current);
        let secret = ClientSecret::Fetch(Arc::new(move || {
            let value = source.lock().unwrap().clone();
            Box::pin(async move { value })
        }));
        registry(&h).replace(vec![Arc::new(github_provider(secret))]);

        let refused = sign_in(&h, "github", "code-1").await;
        assert_eq!(refused.status, StatusCode::BAD_REQUEST);

        *current.lock().unwrap() = Ok("gh-secret".into());
        let reply = sign_in(&h, "github", "code-2").await;
        assert_eq!(reply.status, StatusCode::SEE_OTHER, "{}", reply.body);

        *current.lock().unwrap() = Err("Secret zeabur-identity-upstream has no key github".into());
        let before = token_requests(&h);
        let reply = sign_in(&h, "github", "code-3").await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST);
        assert_eq!(
            reply.audit.as_ref().unwrap()["fields"]["reason"],
            "provider_unavailable"
        );
        assert_eq!(token_requests(&h), before);
        assert!(!reply.body.contains("zeabur-identity-upstream"));
    }

    /// Deleting a provider deletes no linked account: the account page still lists it and can
    /// unlink it, and any provider with the same issuer signs it in again.
    #[tokio::test]
    async fn a_deleted_provider_keeps_its_linked_accounts() {
        let h = harness().await;
        link(&h, Kind::Google, GOOGLE_SUB, "alice").await;
        registry(&h).replace(Vec::new());
        assert_eq!(
            linked_to(&h, Kind::Google, GOOGLE_SUB).await.as_deref(),
            Some("alice")
        );
        let session = account_session(&h, "alice", 0).await;
        let page = account_page(&h, &session).await;
        assert!(page.contains("accounts.google.com"), "{page}");

        registry(&h).replace(vec![Arc::new(openid_provider(
            "workspace",
            GOOGLE_ISSUER,
            ClientSecret::Fixed("google-secret".into()),
        ))]);
        let reply = sign_in(&h, "workspace", "code-1").await;
        assert_eq!(reply.status, StatusCode::SEE_OTHER, "{}", reply.body);
        assert_audit(
            &reply,
            "auth.sign_in",
            None,
            Some("alice"),
            Some("uid-alice"),
        );
    }
}
