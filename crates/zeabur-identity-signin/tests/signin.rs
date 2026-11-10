//! End-to-end tests of passkey enrolment and sign-in, with a software authenticator (the
//! `passkey` crates) standing in for the browser and the user's device.

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

    use axum::Router;
    use axum::body::Body;
    use axum::http::{HeaderMap, Method, Request, StatusCode, header};
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use http_body_util::BodyExt as _;
    use passkey::authenticator::{Authenticator, UiHint, UserCheck, UserValidationMethod};
    use passkey::client::{Client as PasskeyClient, DefaultClientData};
    use passkey::types::ctap2::{Aaguid, Ctap2Error};
    use passkey::types::webauthn::{CredentialCreationOptions, CredentialRequestOptions};
    use serde_json::{Value, json};
    use tokio::sync::Barrier;
    use tower::ServiceExt as _;
    use tracing::instrument::WithSubscriber as _;
    use url::Url;
    use zeabur_identity_api::client::ClientType;
    use zeabur_identity_core::account::{AccountType, Settings};
    use zeabur_identity_core::clock::{Clock, UnixTime};
    use zeabur_identity_core::config::BaseUrl;
    use zeabur_identity_core::crypto::{Sealer, hash_secret};
    use zeabur_identity_keys::Algorithm;
    use zeabur_identity_keys::manager::KeyManager;
    use zeabur_identity_keys::rotation::RotationPolicy;
    use zeabur_identity_keys::store::MemoryKeyStore;
    use zeabur_identity_oauth::endpoints::{self, FLOW_COOKIE};
    use zeabur_identity_oauth::{AuthorizationServer, Lifetimes, OneTimeIds};
    use zeabur_identity_signin::passkeys::{PasskeyError, Passkeys};
    use zeabur_identity_signin::{CEREMONY_COOKIE, SignIn};
    use zeabur_identity_store::{
        Client, CredentialStore as _, MemoryCredentialStore, MemoryDirectory, MemoryGrantStore,
        MemorySetupStore, User,
    };
    use zeabur_identity_test_support::logging::Capture;
    use zeabur_identity_test_support::{Device, device};

    const ISSUER: &str = "https://login.example.com";
    const SETUP_TOKEN: &str = "setup-token-with-plenty-of-entropy-for-tests";
    const ADMIN_UID: &str = "5b0c7a7e-3f4b-4c1e-9a52-0d6f4b8a1c11";
    const START: u64 = 1_800_000_000;
    const INVITATION: &str = "inv-1.invitation-secret-with-plenty-of-entropy";
    const DANA_UID: &str = "8d2f1c3a-5b6e-4f70-8a91-b2c3d4e5f607";
    const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    /// A device that only tests presence: no PIN, no biometric.
    struct PresenceOnly;

    #[async_trait::async_trait]
    impl UserValidationMethod for PresenceOnly {
        type PasskeyItem = passkey::types::Passkey;

        async fn check_user<'a>(
            &self,
            _hint: UiHint<'a, Self::PasskeyItem>,
            presence: bool,
            _verification: bool,
        ) -> Result<UserCheck, Ctap2Error> {
            Ok(UserCheck {
                presence,
                verification: false,
            })
        }

        fn is_presence_enabled(&self) -> bool {
            true
        }

        fn is_verification_enabled(&self) -> Option<bool> {
            Some(false)
        }
    }

    #[derive(Debug, Clone, Default)]
    struct TestClock(Arc<AtomicU64>);

    impl Clock for TestClock {
        fn now(&self) -> UnixTime {
            UnixTime::from_secs(self.0.load(Ordering::SeqCst))
        }
    }

    type Server = AuthorizationServer<MemoryDirectory, MemoryGrantStore, TestClock>;
    type Service = SignIn<
        MemoryDirectory,
        MemoryGrantStore,
        TestClock,
        MemoryCredentialStore,
        MemorySetupStore,
    >;

    struct Harness {
        app: Router,
        service: Arc<Service>,
        clock: TestClock,
    }

    async fn harness() -> Harness {
        let clock = TestClock::default();
        clock.0.store(START, Ordering::SeqCst);
        let manager = KeyManager::new(
            MemoryKeyStore::default(),
            clock.clone(),
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
        directory.put_user(User {
            name: "admin".into(),
            subject: ADMIN_UID.into(),
            username: "admin".into(),
            display_name: Some("Cluster admin".into()),
            disabled: false,
            account_type: AccountType::Admin,
            ..User::default()
        });
        directory.put_user(User {
            name: "dana".into(),
            subject: DANA_UID.into(),
            username: "dana".into(),
            groups: vec!["dev".into()],
            ..User::default()
        });
        let issuer = BaseUrl::parse("issuer", ISSUER).unwrap();
        let oauth: Arc<Server> = Arc::new(AuthorizationServer {
            issuer: issuer.clone(),
            lifetimes: Lifetimes::DEFAULT,
            directory,
            grants: MemoryGrantStore::default(),
            clock: clock.clone(),
            keys: manager.subscribe(),
            sealer: Sealer::ephemeral().unwrap(),
            used_codes: OneTimeIds::default(),
            used_request_uris: OneTimeIds::default(),
        });
        let setup = MemorySetupStore::default();
        setup.put_invitation(
            "inv-1",
            &User {
                name: "dana".into(),
                subject: DANA_UID.into(),
                ..User::default()
            },
            &hash_secret(INVITATION.as_bytes()),
            UnixTime::from_secs(START + 3600),
        );
        setup.put(
            &User {
                name: "admin".into(),
                subject: ADMIN_UID.into(),
                ..User::default()
            },
            &hash_secret(SETUP_TOKEN.as_bytes()),
            UnixTime::from_secs(START + 3600),
        );
        let service = Arc::new(SignIn {
            oauth: Arc::clone(&oauth),
            passkeys: Passkeys::new(&issuer).unwrap(),
            credentials: MemoryCredentialStore::default(),
            setup,
            used_ceremonies: OneTimeIds::default(),
            providers: Vec::new(),
        });
        let app =
            endpoints::router(oauth).merge(zeabur_identity_signin::router(Arc::clone(&service)));
        Harness {
            app,
            service,
            clock,
        }
    }

    struct Reply {
        status: StatusCode,
        headers: HeaderMap,
        body: Value,
        audit: Option<Value>,
        diagnostics: Vec<Value>,
    }

    impl Reply {
        fn cookie(&self, name: &str) -> Option<String> {
            self.headers
                .get_all(header::SET_COOKIE)
                .iter()
                .find_map(|v| {
                    let v = v.to_str().ok()?;
                    let value = v.strip_prefix(&format!("{name}="))?.split(';').next()?;
                    (!value.is_empty()).then(|| value.to_owned())
                })
        }
        fn kind(&self) -> String {
            self.body["type"].as_str().unwrap_or_default().to_owned()
        }
    }

    async fn call(
        app: &Router,
        method: Method,
        path: &str,
        body: Option<Value>,
        cookies: &[(&str, &str)],
        origin: Option<&str>,
    ) -> Reply {
        let capture = Capture::new();
        let submitted = body.clone();
        let mut request = Request::builder().method(method).uri(path);
        if let Some(origin) = origin {
            request = request.header(header::ORIGIN, origin);
        }
        if body.is_some() {
            request = request.header(header::CONTENT_TYPE, "application/json");
        }
        if !cookies.is_empty() {
            let cookie = cookies
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect::<Vec<_>>()
                .join("; ");
            request = request.header(header::COOKIE, cookie);
        }
        let body = body.map_or_else(Body::empty, |b| Body::from(b.to_string()));
        let response = app
            .clone()
            .oneshot(request.body(body).unwrap())
            .with_subscriber(capture.dispatch())
            .await
            .unwrap();
        let (parts, body) = response.into_parts();
        let bytes = body.collect().await.unwrap().to_bytes();
        let response_body = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        let records = capture.records();
        let audit: Vec<_> = records
            .iter()
            .filter(|r| r["target"] == "zeabur_identity::audit")
            .collect();
        let operation = match path {
            "/setup/options" => Some(("auth.passkey_enrollment", Some("start"))),
            "/setup" => Some(("auth.passkey_enrollment", Some("finish"))),
            "/login/options" => Some(("auth.passkey_options", None)),
            "/login" => Some(("auth.sign_in", None)),
            _ => None,
        };
        if let Some((event, phase)) = operation {
            assert_eq!(audit.len(), 1, "{records:?}");
            let fields = &audit[0]["fields"];
            assert_eq!(fields["event"], event);
            assert_eq!(fields["method"], "passkey");
            assert_eq!(
                fields["outcome"],
                if parts.status.is_success() {
                    "success"
                } else {
                    "failure"
                }
            );
            if let Some(phase) = phase {
                assert_eq!(fields["phase"], phase);
            }
            if !parts.status.is_success() {
                assert_eq!(
                    fields["reason"],
                    response_body["type"]
                        .as_str()
                        .unwrap()
                        .strip_prefix("urn:zeabur-identity:problem:")
                        .unwrap()
                );
            }
            assert!(fields.get("client").is_none());
        }
        let serialized = serde_json::to_string(&audit).unwrap();
        for (_, secret) in cookies {
            assert!(!serialized.contains(secret), "cookie leaked");
        }
        if let Some(submitted) = &submitted {
            assert_secret_values_absent(&serialized, submitted);
        }
        assert_secret_values_absent(&serialized, &response_body);
        for value in parts.headers.get_all(header::SET_COOKIE) {
            let cookie = value.to_str().unwrap().split(';').next().unwrap();
            let secret = cookie.split_once('=').unwrap().1;
            if !secret.is_empty() {
                assert!(!serialized.contains(secret), "response cookie leaked");
            }
        }
        Reply {
            status: parts.status,
            headers: parts.headers,
            body: response_body,
            audit: audit.first().map(|r| (*r).clone()),
            diagnostics: records
                .into_iter()
                .filter(|record| record["target"] == "zeabur_identity_signin")
                .collect(),
        }
    }

    fn assert_secret_values_absent(records: &str, value: &Value) {
        if let Value::Object(fields) = value {
            for (key, value) in fields {
                if matches!(
                    key.as_str(),
                    "token"
                        | "id"
                        | "rawId"
                        | "clientDataJSON"
                        | "authenticatorData"
                        | "signature"
                        | "attestationObject"
                        | "userHandle"
                        | "challenge"
                        | "access_token"
                        | "id_token"
                        | "refresh_token"
                ) && let Some(secret) = value.as_str().filter(|s| !s.is_empty())
                {
                    assert!(!records.contains(secret), "{key} leaked");
                }
                assert_secret_values_absent(records, value);
            }
        }
        if let Some(location) = value.get("redirect_to").and_then(Value::as_str)
            && let Some((_, query)) = location.split_once('?')
        {
            for (key, secret) in form_urlencoded::parse(query.as_bytes()) {
                if key == "code" {
                    assert!(
                        !records.contains(secret.as_ref()),
                        "authorization code leaked"
                    );
                }
            }
        }
    }

    async fn post(app: &Router, path: &str, body: Value, cookies: &[(&str, &str)]) -> Reply {
        call(app, Method::POST, path, Some(body), cookies, Some(ISSUER)).await
    }

    fn origin() -> Url {
        Url::parse(ISSUER).unwrap()
    }

    /// Starts a registration with the setup token; returns the authenticator's response and the
    /// ceremony cookie.
    async fn start_enrolment(h: &Harness, device: &mut Device, token: &str) -> (Value, String) {
        let reply = post(&h.app, "/setup/options", json!({ "token": token }), &[]).await;
        assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
        let (user, subject) = if token == INVITATION {
            ("dana", DANA_UID)
        } else {
            ("admin", ADMIN_UID)
        };
        assert_eq!(reply.audit.as_ref().unwrap()["fields"]["user"], user);
        assert_eq!(reply.audit.as_ref().unwrap()["fields"]["subject"], subject);
        let options: CredentialCreationOptions =
            serde_json::from_value(reply.body.clone()).unwrap();
        let credential = device
            .register(&origin(), options, DefaultClientData)
            .await
            .unwrap();
        (
            serde_json::to_value(credential).unwrap(),
            reply.cookie(CEREMONY_COOKIE).unwrap(),
        )
    }

    async fn enrol(h: &Harness, device: &mut Device) {
        let (credential, ceremony) = start_enrolment(h, device, SETUP_TOKEN).await;
        let reply = post(
            &h.app,
            "/setup",
            json!({ "token": SETUP_TOKEN, "credential": credential, "label": "Laptop" }),
            &[(CEREMONY_COOKIE, &ceremony)],
        )
        .await;
        assert_eq!(reply.status, StatusCode::CREATED, "{}", reply.body);
        assert_eq!(reply.audit.as_ref().unwrap()["fields"]["user"], "admin");
        assert!(
            reply.audit.as_ref().unwrap()["fields"]
                .get("subject")
                .is_none()
        );
        assert_eq!(reply.body["username"], "admin");
    }

    /// Opens an authorization request and signs in with `device`; returns the reply to `/login`.
    async fn sign_in(h: &Harness, device: &mut Device) -> Reply {
        let authorize = format!(
            "/authorize?client_id=kubectl&redirect_uri=http%3A%2F%2F127.0.0.1%3A8000%2F&response_type=code&scope=openid&code_challenge={CHALLENGE}&code_challenge_method=S256&state=xyz"
        );
        let reply = call(&h.app, Method::GET, &authorize, None, &[], None).await;
        let flow = reply.cookie(FLOW_COOKIE).unwrap();
        let reply = post(&h.app, "/login/options", json!({}), &[]).await;
        assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
        let ceremony = reply.cookie(CEREMONY_COOKIE).unwrap();
        let options: CredentialRequestOptions = serde_json::from_value(reply.body.clone()).unwrap();
        let assertion = device
            .authenticate(&origin(), options, DefaultClientData)
            .await
            .unwrap();
        post(
            &h.app,
            "/login",
            json!({ "credential": assertion }),
            &[(FLOW_COOKIE, &flow), (CEREMONY_COOKIE, &ceremony)],
        )
        .await
    }

    /// Redeems the authorization code in a successful `/login` reply; returns the token response.
    async fn exchange(h: &Harness, reply: &Reply) -> Value {
        let location = reply.body["redirect_to"].as_str().unwrap();
        assert!(location.starts_with("http://127.0.0.1:8000/?code="));
        let code = form_urlencoded::parse(location.split_once('?').unwrap().1.as_bytes())
            .find(|(k, _)| k == "code")
            .unwrap()
            .1
            .into_owned();
        let body = form_urlencoded::Serializer::new(String::new())
            .extend_pairs([
                ("grant_type", "authorization_code"),
                ("code", &code),
                ("code_verifier", VERIFIER),
                ("client_id", "kubectl"),
            ])
            .finish();
        let request = Request::post("/token")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(body))
            .unwrap();
        let response = h.app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap()
    }

    /// The flags byte of an assertion's authenticator data (after the 32-byte RP ID hash).
    fn authenticator_flags(assertion: &Value) -> u8 {
        let data = assertion["response"]["authenticatorData"].as_str().unwrap();
        URL_SAFE_NO_PAD.decode(data).unwrap()[32]
    }

    const FLAG_UP: u8 = 0x01;
    const FLAG_UV: u8 = 0x04;

    /// Opens the authorization request `authorize` and starts one sign-in ceremony. `device`
    /// first answers it without user verification: the client is told UV is `discouraged`
    /// (only the request options change, and they are not signed), so the authenticator signs
    /// authenticator data with UV clear while the challenge, origin, RP ID and signature stay
    /// valid. The server must refuse that, issue nothing, and leave the ceremony and request
    /// usable; the same ceremony answered with UV then completes. Returns the issued tokens.
    async fn refuse_unverified_then_sign_in(h: &Harness, authorize: &str) -> Value {
        let mut device = device();
        enrol(h, &mut device).await;
        let flow = call(&h.app, Method::GET, authorize, None, &[], None)
            .await
            .cookie(FLOW_COOKIE)
            .unwrap();
        let options = post(&h.app, "/login/options", json!({}), &[]).await;
        let ceremony = options.cookie(CEREMONY_COOKIE).unwrap();
        let cookies = [
            (FLOW_COOKIE, flow.as_str()),
            (CEREMONY_COOKIE, ceremony.as_str()),
        ];
        assert_eq!(options.body["publicKey"]["userVerification"], "required");

        let mut discouraged = options.body.clone();
        discouraged["publicKey"]["userVerification"] = json!("discouraged");
        let unverified = serde_json::to_value(
            device
                .authenticate(
                    &origin(),
                    serde_json::from_value::<CredentialRequestOptions>(discouraged).unwrap(),
                    DefaultClientData,
                )
                .await
                .unwrap(),
        )
        .unwrap();
        let flags = authenticator_flags(&unverified);
        assert_eq!(flags & (FLAG_UP | FLAG_UV), FLAG_UP, "UP set, UV clear");
        let rejected = post(
            &h.app,
            "/login",
            json!({ "credential": unverified }),
            &cookies,
        )
        .await;
        assert_eq!(rejected.status, StatusCode::UNAUTHORIZED);
        assert_eq!(
            rejected.kind(),
            "urn:zeabur-identity:problem:passkey-failed"
        );
        assert!(rejected.body.get("redirect_to").is_none());
        let fields = &rejected.audit.as_ref().unwrap()["fields"];
        assert!(fields.get("user").is_none());
        assert!(fields.get("subject").is_none());
        // Refused by the UV check, not by the signature, challenge or origin checks.
        let diagnostic = rejected.diagnostics.first().unwrap();
        assert_eq!(diagnostic["fields"]["reason"], "passkey-failed");
        assert_eq!(
            diagnostic["fields"]["error"],
            PasskeyError::NotUserVerified.to_string(),
            "{diagnostic}"
        );

        let verified = serde_json::to_value(
            device
                .authenticate(
                    &origin(),
                    serde_json::from_value::<CredentialRequestOptions>(options.body).unwrap(),
                    DefaultClientData,
                )
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(authenticator_flags(&verified) & FLAG_UV, FLAG_UV);
        let reply = post(
            &h.app,
            "/login",
            json!({ "credential": verified }),
            &cookies,
        )
        .await;
        assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
        exchange(h, &reply).await
    }

    #[tokio::test]
    async fn setup_link_then_passkey_sign_in_issues_tokens() {
        let h = harness().await;
        let mut device = device();
        enrol(&h, &mut device).await;

        let reply = sign_in(&h, &mut device).await;
        assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
        assert_eq!(reply.audit.as_ref().unwrap()["fields"]["user"], "admin");
        assert_eq!(
            reply.audit.as_ref().unwrap()["fields"]["subject"],
            ADMIN_UID
        );
        assert!(
            reply
                .headers
                .get_all(header::SET_COOKIE)
                .iter()
                .any(|c| c.to_str().unwrap().starts_with(&format!("{FLOW_COOKIE}=;"))),
            "flow cookie cleared"
        );
        let tokens = exchange(&h, &reply).await;
        let payload = tokens["access_token"]
            .as_str()
            .unwrap()
            .split('.')
            .nth(1)
            .unwrap();
        let claims: Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).unwrap()).unwrap();
        assert_eq!(claims["sub"], ADMIN_UID);
        assert_eq!(claims["groups"], json!(["admins"]));
        assert_eq!(claims["amr"], json!(["swk", "mfa"]));
        assert_eq!(claims["auth_time"], START);
    }

    #[tokio::test]
    async fn invitation_enrols_the_invited_user_once() {
        let h = harness().await;
        let mut device = device();
        let (credential, ceremony) = start_enrolment(&h, &mut device, INVITATION).await;
        let reply = post(
            &h.app,
            "/setup",
            json!({ "token": INVITATION, "credential": credential }),
            &[(CEREMONY_COOKIE, &ceremony)],
        )
        .await;
        assert_eq!(reply.status, StatusCode::CREATED, "{}", reply.body);
        assert_eq!(reply.body["username"], "dana");

        // Used up; and the admin's setup token is untouched by it.
        let reply = post(
            &h.app,
            "/setup/options",
            json!({ "token": INVITATION }),
            &[],
        )
        .await;
        assert_eq!(reply.kind(), "urn:zeabur-identity:problem:setup-invalid");
        let reply = post(
            &h.app,
            "/setup/options",
            json!({ "token": SETUP_TOKEN }),
            &[],
        )
        .await;
        assert_eq!(reply.status, StatusCode::OK);

        // Signing in with the new passkey yields dana's identity.
        let reply = sign_in(&h, &mut device).await;
        assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);

        // A guessed secret for a real invitation name is refused.
        let reply = post(
            &h.app,
            "/setup/options",
            json!({ "token": "inv-1.guess" }),
            &[],
        )
        .await;
        assert_eq!(reply.kind(), "urn:zeabur-identity:problem:setup-invalid");
    }

    #[tokio::test]
    async fn a_link_left_from_a_removed_user_does_not_enrol_a_new_user_of_that_name() {
        for (token, name) in [(INVITATION, "dana"), (SETUP_TOKEN, "admin")] {
            let h = harness().await;
            let mut device = device();
            // The ceremony starts for the old user, and the link is still unused.
            let (credential, ceremony) = start_enrolment(&h, &mut device, token).await;
            // Remove the user but not the link, then give the name to a new person.
            let directory = &h.service.oauth.directory;
            directory.remove_user(name);
            let newcomer = User {
                name: name.into(),
                subject: "0e7c5a1b-9d3f-4b2a-8c6e-1f2a3b4c5d6e".into(),
                username: name.into(),
                ..User::default()
            };
            directory.put_user(newcomer.clone());
            let finish = post(
                &h.app,
                "/setup",
                json!({ "token": token, "credential": credential }),
                &[(CEREMONY_COOKIE, &ceremony)],
            )
            .await;
            assert_eq!(
                finish.kind(),
                "urn:zeabur-identity:problem:setup-invalid",
                "{name}"
            );
            let options = post(&h.app, "/setup/options", json!({ "token": token }), &[]).await;
            assert_eq!(
                options.kind(),
                "urn:zeabur-identity:problem:setup-invalid",
                "{name}"
            );
            assert!(
                h.service
                    .credentials
                    .passkeys(&newcomer)
                    .await
                    .unwrap()
                    .is_empty(),
                "{name}"
            );
        }
    }

    #[tokio::test]
    async fn redeeming_a_link_records_an_event_on_the_user() {
        for (token, user, reason) in [
            (SETUP_TOKEN, "admin", "SetupLinkRedeemed"),
            (INVITATION, "dana", "InvitationRedeemed"),
        ] {
            let h = harness().await;
            let mut device = device();
            let (credential, ceremony) = start_enrolment(&h, &mut device, token).await;
            let reply = post(
                &h.app,
                "/setup",
                json!({ "token": token, "credential": credential }),
                &[(CEREMONY_COOKIE, &ceremony)],
            )
            .await;
            assert_eq!(reply.status, StatusCode::CREATED, "{}", reply.body);
            let events = h.service.credentials.events();
            let event = events
                .iter()
                .find(|event| event.reason == reason)
                .unwrap_or_else(|| panic!("no {reason} event in {events:?}"));
            assert_eq!(event.user, user);
            assert!(event.note.contains("credential="), "{}", event.note);
        }
    }

    #[tokio::test]
    async fn a_disabled_user_cannot_redeem_a_link() {
        for (token, name) in [(SETUP_TOKEN, "admin"), (INVITATION, "dana")] {
            let h = harness().await;
            let mut device = device();
            // The ceremony starts while the user is enabled, then an admin disables them.
            let (credential, ceremony) = start_enrolment(&h, &mut device, token).await;
            let directory = &h.service.oauth.directory;
            let mut user = directory.user(name).await.unwrap().unwrap();
            user.disabled = true;
            directory.put_user(user.clone());

            let options = post(&h.app, "/setup/options", json!({ "token": token }), &[]).await;
            assert_eq!(options.status, StatusCode::FORBIDDEN, "{name}");
            assert_eq!(
                options.kind(),
                "urn:zeabur-identity:problem:account-disabled",
                "{name}"
            );
            let finish = post(
                &h.app,
                "/setup",
                json!({ "token": token, "credential": credential }),
                &[(CEREMONY_COOKIE, &ceremony)],
            )
            .await;
            assert_eq!(
                finish.kind(),
                "urn:zeabur-identity:problem:account-disabled",
                "{name}"
            );
            assert!(
                h.service
                    .credentials
                    .passkeys(&user)
                    .await
                    .unwrap()
                    .is_empty(),
                "{name}"
            );

            // The link still works once an admin enables the user again.
            user.disabled = false;
            directory.put_user(user);
            let options = post(&h.app, "/setup/options", json!({ "token": token }), &[]).await;
            assert_eq!(options.status, StatusCode::OK, "{name}");
        }
    }

    #[tokio::test]
    async fn setup_token_is_single_use() {
        let h = harness().await;
        enrol(&h, &mut device()).await;
        let reply = post(
            &h.app,
            "/setup/options",
            json!({ "token": SETUP_TOKEN }),
            &[],
        )
        .await;
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
        assert_eq!(reply.kind(), "urn:zeabur-identity:problem:setup-invalid");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_enrolments_with_one_token_add_one_passkey() {
        let h = Arc::new(harness().await);
        let mut started = Vec::new();
        for _ in 0..8 {
            let mut device = device();
            started.push(start_enrolment(&h, &mut device, SETUP_TOKEN).await);
        }
        let barrier = Arc::new(Barrier::new(started.len()));
        let tasks: Vec<_> = started
            .into_iter()
            .map(|(credential, ceremony)| {
                let (h, barrier) = (Arc::clone(&h), Arc::clone(&barrier));
                tokio::spawn(async move {
                    barrier.wait().await;
                    post(
                        &h.app,
                        "/setup",
                        json!({ "token": SETUP_TOKEN, "credential": credential }),
                        &[(CEREMONY_COOKIE, &ceremony)],
                    )
                    .await
                    .status
                })
            })
            .collect();
        let mut created = 0;
        for task in tasks {
            if task.await.unwrap() == StatusCode::CREATED {
                created += 1;
            }
        }
        assert_eq!(created, 1);
    }

    #[tokio::test]
    async fn setup_token_expires_and_must_match() {
        let h = harness().await;
        let reply = post(&h.app, "/setup/options", json!({ "token": "wrong" }), &[]).await;
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED);

        // Started in time, finished after expiry.
        let mut device = device();
        let (credential, ceremony) = start_enrolment(&h, &mut device, SETUP_TOKEN).await;
        h.clock.0.fetch_add(3600, Ordering::SeqCst);
        let reply = post(
            &h.app,
            "/setup",
            json!({ "token": SETUP_TOKEN, "credential": credential }),
            &[(CEREMONY_COOKIE, &ceremony)],
        )
        .await;
        assert_eq!(
            reply.status,
            StatusCode::BAD_REQUEST,
            "the ceremony expired first: {}",
            reply.body
        );
        let reply = post(
            &h.app,
            "/setup/options",
            json!({ "token": SETUP_TOKEN }),
            &[],
        )
        .await;
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED, "the token expired");
    }

    #[tokio::test]
    async fn regenerating_the_link_invalidates_the_old_one() {
        let h = harness().await;
        let mut device = device();
        let (credential, ceremony) = start_enrolment(&h, &mut device, SETUP_TOKEN).await;
        h.service.setup.put(
            &User {
                name: "admin".into(),
                subject: ADMIN_UID.into(),
                ..User::default()
            },
            &hash_secret(b"a-newer-token"),
            UnixTime::from_secs(START + 3600),
        );
        let reply = post(
            &h.app,
            "/setup",
            json!({ "token": SETUP_TOKEN, "credential": credential }),
            &[(CEREMONY_COOKIE, &ceremony)],
        )
        .await;
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn requests_from_other_sites_are_refused() {
        let h = harness().await;
        let reply = call(
            &h.app,
            Method::POST,
            "/setup/options",
            Some(json!({ "token": SETUP_TOKEN })),
            &[],
            None,
        )
        .await;
        assert_eq!(reply.status, StatusCode::FORBIDDEN);
        let reply = call(
            &h.app,
            Method::POST,
            "/login/options",
            Some(json!({})),
            &[],
            Some("https://evil.example"),
        )
        .await;
        assert_eq!(reply.status, StatusCode::FORBIDDEN);
        assert_eq!(
            reply.headers[header::CONTENT_TYPE],
            "application/problem+json"
        );
    }

    #[tokio::test]
    async fn assertions_cannot_be_replayed() {
        let h = harness().await;
        let mut device = device();
        enrol(&h, &mut device).await;
        let authorize = format!(
            "/authorize?client_id=kubectl&redirect_uri=http%3A%2F%2F127.0.0.1%3A8000%2F&response_type=code&code_challenge={CHALLENGE}&code_challenge_method=S256"
        );
        let flow = call(&h.app, Method::GET, &authorize, None, &[], None)
            .await
            .cookie(FLOW_COOKIE)
            .unwrap();
        let reply = post(&h.app, "/login/options", json!({}), &[]).await;
        let ceremony = reply.cookie(CEREMONY_COOKIE).unwrap();
        let options: CredentialRequestOptions = serde_json::from_value(reply.body).unwrap();
        let assertion = serde_json::to_value(
            device
                .authenticate(&origin(), options, DefaultClientData)
                .await
                .unwrap(),
        )
        .unwrap();
        let cookies = [
            (FLOW_COOKIE, flow.as_str()),
            (CEREMONY_COOKIE, ceremony.as_str()),
        ];
        // Knowing an enrolled credential ID and handle is not proof of possession.
        let mut forged = assertion.clone();
        forged["response"]["signature"] = json!(URL_SAFE_NO_PAD.encode([0_u8; 64]));
        let rejected = post(&h.app, "/login", json!({ "credential": forged }), &cookies).await;
        assert_eq!(rejected.status, StatusCode::UNAUTHORIZED);
        assert_eq!(
            rejected.kind(),
            "urn:zeabur-identity:problem:passkey-failed"
        );
        let fields = &rejected.audit.as_ref().unwrap()["fields"];
        assert!(fields.get("user").is_none());
        assert!(fields.get("subject").is_none());
        assert!(fields.get("error").is_none());
        let diagnostic = rejected.diagnostics.first().unwrap();
        assert_eq!(diagnostic["fields"]["reason"], "passkey-failed");
        // Failed signature verification does not consume the valid ceremony.
        assert_eq!(
            post(
                &h.app,
                "/login",
                json!({ "credential": assertion }),
                &cookies
            )
            .await
            .status,
            StatusCode::OK
        );
        let second = post(
            &h.app,
            "/login",
            json!({ "credential": assertion }),
            &cookies,
        )
        .await;
        assert_eq!(second.status, StatusCode::BAD_REQUEST);
        assert_eq!(
            second.kind(),
            "urn:zeabur-identity:problem:ceremony-expired"
        );
    }

    #[tokio::test]
    async fn unknown_passkeys_and_disabled_users_cannot_sign_in() {
        let h = harness().await;
        // A device whose passkey was never enrolled here (registered against another server).
        let other = harness().await;
        let mut stranger = device();
        enrol(&other, &mut stranger).await;
        let reply = sign_in(&h, &mut stranger).await;
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
        assert_eq!(reply.kind(), "urn:zeabur-identity:problem:passkey-failed");
        assert!(
            reply.audit.as_ref().unwrap()["fields"]
                .get("user")
                .is_none()
        );
        assert!(
            reply.audit.as_ref().unwrap()["fields"]
                .get("subject")
                .is_none()
        );

        let mut device = device();
        enrol(&h, &mut device).await;
        let mut admin = h
            .service
            .oauth
            .directory
            .user("admin")
            .await
            .unwrap()
            .unwrap();
        admin.disabled = true;
        h.service.oauth.directory.put_user(admin);
        let reply = sign_in(&h, &mut device).await;
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
        // Disabled users are rejected before signature verification, so no identity is asserted.
        let fields = &reply.audit.as_ref().unwrap()["fields"];
        assert!(fields.get("user").is_none());
        assert!(fields.get("subject").is_none());
    }

    #[tokio::test]
    async fn sign_in_needs_a_pending_authorization_request() {
        let h = harness().await;
        let mut device = device();
        enrol(&h, &mut device).await;
        let reply = post(&h.app, "/login/options", json!({}), &[]).await;
        let ceremony = reply.cookie(CEREMONY_COOKIE).unwrap();
        let options: CredentialRequestOptions = serde_json::from_value(reply.body).unwrap();
        let assertion = device
            .authenticate(&origin(), options, DefaultClientData)
            .await
            .unwrap();
        let reply = post(
            &h.app,
            "/login",
            json!({ "credential": assertion }),
            &[(CEREMONY_COOKIE, &ceremony)],
        )
        .await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST);
        assert_eq!(reply.kind(), "urn:zeabur-identity:problem:no-request");
    }

    use zeabur_identity_store::Directory as _;

    #[tokio::test]
    async fn passkeys_without_user_verification_are_refused() {
        let h = harness().await;
        let mut device: PasskeyClient<
            Option<passkey::types::Passkey>,
            PresenceOnly,
            passkey::crypto::aws_lc_rs::AwsLcRsBackend,
            public_suffix::PublicSuffixList,
            (),
        > = PasskeyClient::new(Authenticator::new(
            Aaguid::new_empty(),
            None,
            PresenceOnly,
            passkey::crypto::aws_lc_rs::AwsLcRsBackend,
        ));
        let reply = post(
            &h.app,
            "/setup/options",
            json!({ "token": SETUP_TOKEN }),
            &[],
        )
        .await;
        let ceremony = reply.cookie(CEREMONY_COOKIE).unwrap();
        let options: CredentialCreationOptions = serde_json::from_value(reply.body).unwrap();
        // A client honouring `userVerification: required` refuses outright; if one sends a
        // response anyway, the server must reject it. This covers registration from the client
        // side only; `refuse_unverified_then_sign_in` covers signed sign-in assertions.
        if let Ok(credential) = device.register(&origin(), options, DefaultClientData).await {
            let reply = post(
                &h.app,
                "/setup",
                json!({ "token": SETUP_TOKEN, "credential": credential }),
                &[(CEREMONY_COOKIE, &ceremony)],
            )
            .await;
            assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
        }
        // The token was not consumed by the failed attempt.
        let reply = post(
            &h.app,
            "/setup/options",
            json!({ "token": SETUP_TOKEN }),
            &[],
        )
        .await;
        assert_eq!(reply.status, StatusCode::OK);
    }

    #[tokio::test]
    async fn sign_in_without_user_verification_is_refused() {
        let h = harness().await;
        let authorize = format!(
            "/authorize?client_id=kubectl&redirect_uri=http%3A%2F%2F127.0.0.1%3A8000%2F&response_type=code&scope=openid&code_challenge={CHALLENGE}&code_challenge_method=S256"
        );
        let tokens = refuse_unverified_then_sign_in(&h, &authorize).await;
        assert!(tokens["refresh_token"].is_string());
        assert!(tokens["id_token"].is_string());
    }

    /// `credential` (a registration response) with the backup flags (BE, BS) clear, as a
    /// device-bound passkey reports them. The test authenticator sets both, like a synced
    /// passkey. Attestation is `none`, so nothing signs these flags.
    fn as_device_bound(mut credential: Value) -> Value {
        let field = &mut credential["response"]["attestationObject"];
        let mut object = URL_SAFE_NO_PAD.decode(field.as_str().unwrap()).unwrap();
        let key = b"hauthData";
        let at = object.windows(key.len()).position(|w| w == key).unwrap() + key.len();
        // A CBOR byte string head: 0x58 with a one-byte length, or 0x59 with two.
        let data = at + if object[at] == 0x58 { 2 } else { 3 };
        assert_eq!(object[data + 32] & 0x18, 0x18, "BE and BS set");
        object[data + 32] &= !0x18;
        *field = json!(URL_SAFE_NO_PAD.encode(object));
        credential
    }

    fn turn_on_aal3(h: &Harness) {
        h.service.oauth.directory.put_settings(Settings {
            admin_aal3: true,
            ..Settings::default()
        });
    }

    #[tokio::test]
    async fn with_aal3_an_admin_cannot_sign_in_with_a_synced_passkey() {
        let h = harness().await;
        let mut device = device();
        enrol(&h, &mut device).await;
        turn_on_aal3(&h);
        let reply = sign_in(&h, &mut device).await;
        assert_eq!(reply.status, StatusCode::FORBIDDEN, "{}", reply.body);
        assert_eq!(
            reply.kind(),
            "urn:zeabur-identity:problem:device-passkey-needed"
        );
        assert!(reply.body.get("redirect_to").is_none());
    }

    #[tokio::test]
    async fn with_aal3_an_admin_enrols_only_a_device_bound_passkey() {
        let h = harness().await;
        turn_on_aal3(&h);
        let mut device = device();
        let (credential, ceremony) = start_enrolment(&h, &mut device, SETUP_TOKEN).await;
        let refused = post(
            &h.app,
            "/setup",
            json!({ "token": SETUP_TOKEN, "credential": credential.clone() }),
            &[(CEREMONY_COOKIE, &ceremony)],
        )
        .await;
        assert_eq!(refused.status, StatusCode::FORBIDDEN, "{}", refused.body);
        assert_eq!(
            refused.kind(),
            "urn:zeabur-identity:problem:device-passkey-needed"
        );
        // The refusal leaves the link usable.
        let reply = post(
            &h.app,
            "/setup",
            json!({ "token": SETUP_TOKEN, "credential": as_device_bound(credential) }),
            &[(CEREMONY_COOKIE, &ceremony)],
        )
        .await;
        assert_eq!(reply.status, StatusCode::CREATED, "{}", reply.body);
    }

    #[tokio::test]
    async fn verified_passkey_does_not_succeed_with_invalid_or_expired_authorization() {
        for expired in [false, true] {
            let h = harness().await;
            let mut device = device();
            enrol(&h, &mut device).await;
            let authorize = format!(
                "/authorize?client_id=kubectl&redirect_uri=http%3A%2F%2F127.0.0.1%3A8000%2F&response_type=code&code_challenge={CHALLENGE}&code_challenge_method=S256"
            );
            let flow = call(&h.app, Method::GET, &authorize, None, &[], None)
                .await
                .cookie(FLOW_COOKIE)
                .unwrap();
            let rejected_flow = if expired {
                h.clock
                    .0
                    .fetch_add(h.service.oauth.lifetimes.flow.as_secs(), Ordering::SeqCst);
                flow
            } else {
                "secret-forged-authorization-flow".to_owned()
            };
            // Start a fresh ceremony after the flow expires, so the assertion itself verifies.
            let options = post(&h.app, "/login/options", json!({}), &[]).await;
            let ceremony = options.cookie(CEREMONY_COOKIE).unwrap();
            let assertion = device
                .authenticate(
                    &origin(),
                    serde_json::from_value(options.body).unwrap(),
                    DefaultClientData,
                )
                .await
                .unwrap();
            let reply = post(
                &h.app,
                "/login",
                json!({ "credential": assertion }),
                &[(FLOW_COOKIE, &rejected_flow), (CEREMONY_COOKIE, &ceremony)],
            )
            .await;
            assert_eq!(reply.status, StatusCode::BAD_REQUEST);
            assert_eq!(reply.kind(), "urn:zeabur-identity:problem:no-request");
            let fields = &reply.audit.as_ref().unwrap()["fields"];
            assert_eq!(fields["outcome"], "failure");
            assert_eq!(fields["user"], "admin");
            assert_eq!(fields["subject"], ADMIN_UID);
            assert!(fields.get("error").is_none());
            let diagnostic = reply.diagnostics.first().unwrap();
            assert_eq!(diagnostic["fields"]["reason"], "no-request");
            let error = diagnostic["fields"]["error"].as_str().unwrap();
            assert!(!serde_json::to_string(fields).unwrap().contains(error));
            // A rejected authorization still consumed the verified passkey ceremony.
            let second_attempt = post(
                &h.app,
                "/login",
                json!({ "credential": assertion }),
                &[(FLOW_COOKIE, &rejected_flow), (CEREMONY_COOKIE, &ceremony)],
            )
            .await;
            assert_eq!(
                second_attempt.kind(),
                "urn:zeabur-identity:problem:ceremony-expired"
            );
        }
    }

    #[tokio::test]
    async fn missing_setup_user_is_not_an_authenticated_identity() {
        let h = harness().await;
        let token = "secret-setup-for-unknown-local-user";
        h.service.setup.put(
            &User {
                name: "missing-secret-user".into(),
                subject: "uid-missing".into(),
                ..User::default()
            },
            &hash_secret(token.as_bytes()),
            UnixTime::from_secs(START + 3600),
        );
        let reply = post(&h.app, "/setup/options", json!({ "token": token }), &[]).await;
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
        let fields = &reply.audit.as_ref().unwrap()["fields"];
        assert!(fields.get("user").is_none());
        assert!(fields.get("subject").is_none());
    }

    mod account {
        use zeabur_identity_signin::account::{REAUTH_WINDOW, SESSION_COOKIE, SESSION_LIFETIME};
        use zeabur_identity_store::{GrantStore as _, Removal};

        use super::*;

        /// A signed-in browser: the session cookie and the page's CSRF token.
        struct Session {
            cookie: String,
            csrf: String,
        }

        impl Session {
            fn cookies(&self) -> [(&str, &str); 1] {
                [(SESSION_COOKIE, self.cookie.as_str())]
            }
        }

        async fn user(h: &Harness, name: &str) -> User {
            h.service.oauth.directory.user(name).await.unwrap().unwrap()
        }

        async fn passkeys(h: &Harness, name: &str) -> Vec<String> {
            let user = user(h, name).await;
            let mut names: Vec<String> = h
                .service
                .credentials
                .passkeys(&user)
                .await
                .unwrap()
                .into_iter()
                .map(|p| p.name)
                .collect();
            names.sort();
            names
        }

        async fn page(h: &Harness, session: Option<&str>) -> String {
            let mut request = Request::get("/account");
            if let Some(cookie) = session {
                request = request.header(header::COOKIE, format!("{SESSION_COOKIE}={cookie}"));
            }
            let response = h
                .app
                .clone()
                .oneshot(request.body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let headers = response.headers();
            assert_eq!(
                headers[header::CONTENT_SECURITY_POLICY],
                zeabur_identity_ui::CSP
            );
            assert_eq!(headers[header::CACHE_CONTROL], "no-store");
            let bytes = response.into_body().collect().await.unwrap().to_bytes();
            let html = String::from_utf8(bytes.to_vec()).unwrap();
            assert!(!html.contains("<script>") && !html.contains(" style=\""));
            html
        }

        fn csrf_of(html: &str) -> String {
            html.split_once("data-csrf=\"")
                .unwrap()
                .1
                .split('"')
                .next()
                .unwrap()
                .to_owned()
        }

        async fn assertion(device: &mut Device, reply: &Reply) -> (Value, String) {
            assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
            let options: CredentialRequestOptions =
                serde_json::from_value(reply.body.clone()).unwrap();
            let assertion = device
                .authenticate(&origin(), options, DefaultClientData)
                .await
                .unwrap();
            (
                serde_json::to_value(assertion).unwrap(),
                reply.cookie(CEREMONY_COOKIE).unwrap(),
            )
        }

        async fn sign_in_to_account(h: &Harness, device: &mut Device) -> Session {
            let reply = post(&h.app, "/account/session/options", json!({}), &[]).await;
            let (credential, ceremony) = assertion(device, &reply).await;
            let reply = post(
                &h.app,
                "/account/session",
                json!({ "credential": credential }),
                &[(CEREMONY_COOKIE, &ceremony)],
            )
            .await;
            assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
            let accepted = &reply.body["accepted"];
            assert_eq!(accepted["rpId"], "login.example.com");
            assert!(
                accepted["allAcceptedCredentialIds"]
                    .as_array()
                    .is_some_and(|ids| !ids.is_empty())
            );
            let set_cookie = reply
                .headers
                .get_all(header::SET_COOKIE)
                .iter()
                .map(|v| v.to_str().unwrap().to_owned())
                .find(|v| v.starts_with(SESSION_COOKIE))
                .unwrap();
            assert!(set_cookie.contains("HttpOnly") && set_cookie.contains("SameSite=Lax"));
            let cookie = reply.cookie(SESSION_COOKIE).unwrap();
            let csrf = csrf_of(&page(h, Some(&cookie)).await);
            Session { cookie, csrf }
        }

        async fn reauth(h: &Harness, session: &Session, device: &mut Device) -> Reply {
            let reply = post(
                &h.app,
                "/account/reauth/options",
                json!({ "csrf": session.csrf }),
                &session.cookies(),
            )
            .await;
            let (credential, ceremony) = assertion(device, &reply).await;
            post(
                &h.app,
                "/account/reauth",
                json!({ "csrf": session.csrf, "credential": credential }),
                &[
                    (SESSION_COOKIE, &session.cookie),
                    (CEREMONY_COOKIE, &ceremony),
                ],
            )
            .await
        }

        async fn add(h: &Harness, session: &Session, device: &mut Device) -> Reply {
            let reply = post(
                &h.app,
                "/account/passkeys/options",
                json!({ "csrf": session.csrf }),
                &session.cookies(),
            )
            .await;
            if reply.status != StatusCode::OK {
                return reply;
            }
            let options: CredentialCreationOptions =
                serde_json::from_value(reply.body.clone()).unwrap();
            let public_key = &reply.body["publicKey"];
            assert_eq!(
                public_key["authenticatorSelection"]["residentKey"],
                "required"
            );
            assert_eq!(
                public_key["authenticatorSelection"]["userVerification"],
                "required"
            );
            let ceremony = reply.cookie(CEREMONY_COOKIE).unwrap();
            let credential = device
                .register(&origin(), options, DefaultClientData)
                .await
                .unwrap();
            post(
                &h.app,
                "/account/passkeys",
                json!({ "csrf": session.csrf, "credential": credential }),
                &[
                    (SESSION_COOKIE, &session.cookie),
                    (CEREMONY_COOKIE, &ceremony),
                ],
            )
            .await
        }

        async fn remove(h: &Harness, session: &Session, name: &str) -> Reply {
            post(
                &h.app,
                "/account/passkeys/remove",
                json!({ "csrf": session.csrf, "name": name }),
                &session.cookies(),
            )
            .await
        }

        fn advance(h: &Harness, by: std::time::Duration) {
            h.clock.0.fetch_add(by.as_secs(), Ordering::SeqCst);
        }

        /// Admin enrolled with one device and signed in to `/account` with it.
        async fn signed_in() -> (Harness, Device, Session) {
            let h = harness().await;
            let mut first = device();
            enrol(&h, &mut first).await;
            let session = sign_in_to_account(&h, &mut first).await;
            (h, first, session)
        }

        async fn enrol_dana(h: &Harness) -> Device {
            let mut dana = device();
            let (credential, ceremony) = start_enrolment(h, &mut dana, INVITATION).await;
            let reply = post(
                &h.app,
                "/setup",
                json!({ "token": INVITATION, "credential": credential }),
                &[(CEREMONY_COOKIE, &ceremony)],
            )
            .await;
            assert_eq!(reply.status, StatusCode::CREATED, "{}", reply.body);
            dana
        }

        #[tokio::test]
        async fn the_page_lists_only_the_session_users_passkeys() {
            let (h, _first, session) = signed_in().await;
            let _dana = enrol_dana(&h).await;
            let html = page(&h, Some(&session.cookie)).await;
            let [admin] = <[String; 1]>::try_from(passkeys(&h, "admin").await).unwrap();
            let [dana] = <[String; 1]>::try_from(passkeys(&h, "dana").await).unwrap();
            assert!(html.contains(&admin));
            assert!(!html.contains(&dana));
            assert!(html.contains("Laptop"));
            assert!(html.contains("Ask an administrator for a setup link"));

            let signed_out = page(&h, None).await;
            assert!(!signed_out.contains("data-csrf"));
            assert!(!signed_out.contains(&admin));
        }

        #[tokio::test]
        async fn a_passkey_without_a_label_shows_its_creation_date() {
            let h = harness().await;
            let mut dana_device = enrol_dana(&h).await;
            let dana = sign_in_to_account(&h, &mut dana_device).await;
            let stored = h
                .service
                .credentials
                .passkeys(&user(&h, "dana").await)
                .await
                .unwrap();
            assert!(stored.iter().all(|p| p.label.is_none()));
            let html = page(&h, Some(&dana.cookie)).await;
            assert!(html.contains("data-format=\"Passkey added %date%\""));
        }

        #[tokio::test]
        async fn changes_cannot_reach_another_users_objects() {
            let (h, _first, admin) = signed_in().await;
            let mut dana_device = enrol_dana(&h).await;
            let dana = sign_in_to_account(&h, &mut dana_device).await;
            let [admin_passkey] = <[String; 1]>::try_from(passkeys(&h, "admin").await).unwrap();
            let admin_session = admin.cookie.split_once('.').unwrap().0.to_owned();

            let reply = post(
                &h.app,
                "/account/passkeys/rename",
                json!({ "csrf": dana.csrf, "name": admin_passkey, "label": "Mine" }),
                &dana.cookies(),
            )
            .await;
            assert_eq!(reply.status, StatusCode::NOT_FOUND);
            let reply = remove(&h, &dana, &admin_passkey).await;
            assert_eq!(reply.status, StatusCode::NOT_FOUND);
            let reply = post(
                &h.app,
                "/account/sessions/revoke",
                json!({ "csrf": dana.csrf, "name": admin_session }),
                &dana.cookies(),
            )
            .await;
            assert_eq!(reply.status, StatusCode::NOT_FOUND);
            assert_eq!(passkeys(&h, "admin").await, [admin_passkey]);
            assert!(page(&h, Some(&admin.cookie)).await.contains("data-csrf"));

            // Re-authenticating with someone else's passkey does not count.
            let reply = reauth(&h, &admin, &mut dana_device).await;
            assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
            assert_eq!(reply.kind(), "urn:zeabur-identity:problem:passkey-failed");

            // A session is tied to the user's UID: a recreated user of the same name is signed out.
            let mut recreated = user(&h, "admin").await;
            recreated.subject = "0f0e0d0c-0b0a-4908-8706-050403020100".into();
            h.service.oauth.directory.put_user(recreated);
            assert!(!page(&h, Some(&admin.cookie)).await.contains("data-csrf"));
        }

        #[tokio::test]
        async fn adding_and_removing_need_a_recent_verified_passkey() {
            let (h, mut first, session) = signed_in().await;
            advance(&h, REAUTH_WINDOW);
            let mut second = device();
            let reply = add(&h, &session, &mut second).await;
            assert_eq!(reply.status, StatusCode::FORBIDDEN);
            assert_eq!(reply.kind(), "urn:zeabur-identity:problem:reauth-required");
            let [only] = <[String; 1]>::try_from(passkeys(&h, "admin").await).unwrap();
            assert_eq!(
                remove(&h, &session, &only).await.kind(),
                "urn:zeabur-identity:problem:reauth-required"
            );

            let reply = reauth(&h, &session, &mut first).await;
            assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
            let reply = add(&h, &session, &mut second).await;
            assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
            assert_eq!(passkeys(&h, "admin").await.len(), 2);
            let events = h.service.credentials.events();
            let added = events.last().unwrap();
            assert_eq!(added.reason, "PasskeyAdded");
            assert_eq!(added.subject, ADMIN_UID);
            assert!(added.note.contains("actor=admin"));

            // The same authenticator cannot be added twice.
            advance(
                &h,
                REAUTH_WINDOW
                    .checked_sub(std::time::Duration::from_secs(1))
                    .unwrap(),
            );
            let reply = post(
                &h.app,
                "/account/passkeys/options",
                json!({ "csrf": session.csrf }),
                &session.cookies(),
            )
            .await;
            assert_eq!(reply.status, StatusCode::OK);
            assert_eq!(
                reply.body["publicKey"]["excludeCredentials"]
                    .as_array()
                    .unwrap()
                    .len(),
                2
            );
            advance(&h, std::time::Duration::from_secs(1));
            let reply = add(&h, &session, &mut device()).await;
            assert_eq!(reply.kind(), "urn:zeabur-identity:problem:reauth-required");
        }

        #[tokio::test]
        async fn rename_needs_the_csrf_token_and_same_origin() {
            let (h, _first, session) = signed_in().await;
            let [name] = <[String; 1]>::try_from(passkeys(&h, "admin").await).unwrap();
            for csrf in ["", "0000", &"0".repeat(64)] {
                let reply = post(
                    &h.app,
                    "/account/passkeys/rename",
                    json!({ "csrf": csrf, "name": name, "label": "Phone" }),
                    &session.cookies(),
                )
                .await;
                assert_eq!(reply.status, StatusCode::FORBIDDEN);
                assert_eq!(reply.kind(), "urn:zeabur-identity:problem:csrf");
            }
            let reply = call(
                &h.app,
                Method::POST,
                "/account/passkeys/rename",
                Some(json!({ "csrf": session.csrf, "name": name, "label": "Phone" })),
                &session.cookies(),
                Some("https://evil.example"),
            )
            .await;
            assert_eq!(reply.status, StatusCode::FORBIDDEN);
            assert!(!page(&h, Some(&session.cookie)).await.contains("Phone"));

            // Rename needs no recent passkey confirmation.
            advance(&h, REAUTH_WINDOW);
            let reply = post(
                &h.app,
                "/account/passkeys/rename",
                json!({ "csrf": session.csrf, "name": name, "label": "  Phone  " }),
                &session.cookies(),
            )
            .await;
            assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
            assert!(page(&h, Some(&session.cookie)).await.contains("Phone"));
            let fields = &reply.audit.unwrap()["fields"];
            assert_eq!(fields["event"], "account.passkey_renamed");
            assert_eq!(fields["credential"], name.as_str());
            assert_eq!(
                h.service.credentials.events().last().unwrap().reason,
                "PasskeyRenamed"
            );
        }

        #[tokio::test]
        async fn the_last_passkey_cannot_be_removed() {
            let (h, _first, session) = signed_in().await;
            let [only] = <[String; 1]>::try_from(passkeys(&h, "admin").await).unwrap();
            let reply = remove(&h, &session, &only).await;
            assert_eq!(reply.status, StatusCode::CONFLICT);
            assert_eq!(reply.kind(), "urn:zeabur-identity:problem:last-passkey");
            assert_eq!(passkeys(&h, "admin").await, [only]);
        }

        #[tokio::test]
        async fn concurrent_removals_keep_one_passkey() {
            let (h, _laptop, session) = signed_in().await;
            let reply = add(&h, &session, &mut device()).await;
            assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
            let [a, b] = <[String; 2]>::try_from(passkeys(&h, "admin").await).unwrap();
            let (first, second) = tokio::join!(remove(&h, &session, &a), remove(&h, &session, &b));
            let statuses = [first.status, second.status];
            assert_eq!(
                statuses.iter().filter(|s| **s == StatusCode::OK).count(),
                1,
                "{statuses:?}"
            );
            assert_eq!(passkeys(&h, "admin").await.len(), 1);

            // The store itself: of two removals racing, one is refused.
            let (h, _laptop, session) = signed_in().await;
            let reply = add(&h, &session, &mut device()).await;
            assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
            let [a, b] = <[String; 2]>::try_from(passkeys(&h, "admin").await).unwrap();
            let admin = user(&h, "admin").await;
            let store = &h.service.credentials;
            let (first, second) = tokio::join!(store.remove(&admin, &a), store.remove(&admin, &b));
            let mut outcomes = [first.unwrap(), second.unwrap()];
            outcomes.sort_by_key(|o| matches!(o, Removal::LastPasskey));
            assert!(
                matches!(outcomes, [Removal::Removed, Removal::LastPasskey]),
                "{outcomes:?}"
            );
            assert_eq!(passkeys(&h, "admin").await.len(), 1);
        }

        #[tokio::test]
        async fn removing_a_passkey_revokes_what_it_signed_in() {
            let (h, mut first, by_first) = signed_in().await;
            let mut second = device();
            let reply = add(&h, &by_first, &mut second).await;
            assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
            let by_second = sign_in_to_account(&h, &mut second).await;
            // An OAuth grant from the first passkey.
            let tokens = exchange(&h, &sign_in(&h, &mut first).await).await;
            let refresh = tokens["refresh_token"].as_str().unwrap().to_owned();
            let admin = user(&h, "admin").await;
            assert_eq!(h.service.oauth.grants.list(&admin).await.unwrap().len(), 3);

            let first_name = h
                .service
                .credentials
                .passkeys(&admin)
                .await
                .unwrap()
                .into_iter()
                .find(|p| p.label.as_deref() == Some("Laptop"))
                .unwrap()
                .name;
            let reply = remove(&h, &by_second, &first_name).await;
            assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
            assert_eq!(reply.body["signed_out"], false);
            assert_eq!(
                reply.body["accepted"]["allAcceptedCredentialIds"]
                    .as_array()
                    .unwrap()
                    .len(),
                1
            );
            let fields = &reply.audit.unwrap()["fields"];
            assert_eq!(fields["event"], "account.passkey_removed");
            assert_eq!(fields["revoked"], 2);

            let left: Vec<String> = h
                .service
                .oauth
                .grants
                .list(&admin)
                .await
                .unwrap()
                .into_iter()
                .map(|g| g.spec.name)
                .collect();
            assert_eq!(left, [by_second.cookie.split_once('.').unwrap().0]);
            assert!(!page(&h, Some(&by_first.cookie)).await.contains("data-csrf"));
            let request = Request::post("/token")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "grant_type=refresh_token&client_id=kubectl&refresh_token={refresh}"
                )))
                .unwrap();
            let response = h.app.clone().oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            let event = h.service.credentials.events().last().unwrap().clone();
            assert_eq!(event.reason, "PasskeyRemoved");
            assert!(event.note.contains(&first_name));

            // The removed passkey is now unknown, and the browser is told so.
            let reply = post(&h.app, "/account/session/options", json!({}), &[]).await;
            let (credential, ceremony) = assertion(&mut first, &reply).await;
            let reply = post(
                &h.app,
                "/account/session",
                json!({ "credential": credential }),
                &[(CEREMONY_COOKIE, &ceremony)],
            )
            .await;
            assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
            assert_eq!(reply.body["unknownCredential"]["rpId"], "login.example.com");
            assert_eq!(
                reply.body["unknownCredential"]["credentialId"],
                credential["id"]
            );
        }

        #[tokio::test]
        async fn sessions_can_be_revoked() {
            let (h, mut first, this) = signed_in().await;
            let other = sign_in_to_account(&h, &mut first).await;
            let _tokens = exchange(&h, &sign_in(&h, &mut first).await).await;
            let admin = user(&h, "admin").await;
            assert_eq!(h.service.oauth.grants.list(&admin).await.unwrap().len(), 3);

            let reply = post(
                &h.app,
                "/account/sessions/revoke",
                json!({ "csrf": this.csrf, "name": other.cookie.split_once('.').unwrap().0 }),
                &this.cookies(),
            )
            .await;
            assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
            assert!(!page(&h, Some(&other.cookie)).await.contains("data-csrf"));
            assert_eq!(
                h.service.credentials.events().last().unwrap().reason,
                "SessionRevoked"
            );

            let reply = post(
                &h.app,
                "/account/sessions/revoke-others",
                json!({ "csrf": this.csrf }),
                &this.cookies(),
            )
            .await;
            assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
            let left: Vec<String> = h
                .service
                .oauth
                .grants
                .list(&admin)
                .await
                .unwrap()
                .into_iter()
                .map(|g| g.spec.name)
                .collect();
            assert_eq!(left, [this.cookie.split_once('.').unwrap().0]);
            assert!(page(&h, Some(&this.cookie)).await.contains("data-csrf"));

            let reply = post(
                &h.app,
                "/account/sign-out",
                json!({ "csrf": this.csrf }),
                &this.cookies(),
            )
            .await;
            assert_eq!(reply.status, StatusCode::OK);
            let left = h.service.oauth.grants.list(&admin).await.unwrap();
            assert_eq!(left.len(), 0);
        }

        #[tokio::test]
        async fn sessions_end_after_an_hour_and_with_the_user() {
            let (h, _first, session) = signed_in().await;
            advance(&h, SESSION_LIFETIME);
            assert!(!page(&h, Some(&session.cookie)).await.contains("data-csrf"));
            let reply = post(
                &h.app,
                "/account/sessions/revoke-others",
                json!({ "csrf": session.csrf }),
                &session.cookies(),
            )
            .await;
            assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
            assert_eq!(reply.kind(), "urn:zeabur-identity:problem:signed-out");

            let (h, _first, session) = signed_in().await;
            let mut admin = user(&h, "admin").await;
            admin.disabled = true;
            h.service.oauth.directory.put_user(admin);
            assert!(!page(&h, Some(&session.cookie)).await.contains("data-csrf"));
        }

        #[tokio::test]
        async fn passkey_endpoints_are_published() {
            let h = harness().await;
            let response = h
                .app
                .clone()
                .oneshot(
                    Request::get("/.well-known/passkey-endpoints")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(response.headers()[header::CONTENT_TYPE], "application/json");
            let body: Value =
                serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                    .unwrap();
            assert_eq!(
                body,
                json!({
                    "enroll": "https://login.example.com/account#add",
                    "manage": "https://login.example.com/account",
                })
            );
        }
    }
}
