//! End-to-end tests of passkey enrolment and sign-in, with a software authenticator (the
//! `passkey` crates) standing in for the browser and the user's device.

#[cfg(test)]
mod common;

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
    use passkey::types::webauthn::{
        AuthenticatedPublicKeyCredential, CreatedPublicKeyCredential, CredentialCreationOptions,
        CredentialRequestOptions, ResidentKeyRequirement, UserVerificationRequirement,
    };
    use serde::de::DeserializeOwned;
    use serde::{Deserialize, Serialize};
    use tokio::sync::Barrier;
    use tower::ServiceExt as _;
    use tracing::instrument::WithSubscriber as _;
    use url::Url;
    use zeabur_identity_api::client::ClientType;
    use zeabur_identity_api::token_hash;
    use zeabur_identity_core::account::{AccountType, AdminSignIn, Settings};
    use zeabur_identity_core::clock::{Clock, UnixTime};
    use zeabur_identity_core::config::BaseUrl;
    use zeabur_identity_core::crypto::Sealer;
    use zeabur_identity_keys::Algorithm;
    use zeabur_identity_keys::manager::KeyManager;
    use zeabur_identity_keys::rotation::RotationPolicy;
    use zeabur_identity_keys::store::MemoryKeyStore;
    use zeabur_identity_oauth::endpoints::{self, FLOW_COOKIE};
    use zeabur_identity_oauth::{AuthorizationServer, Lifetimes, OneTimeIds};
    use zeabur_identity_signin::passkeys::{PasskeyError, Passkeys};
    use zeabur_identity_signin::{Backend, CEREMONY_COOKIE, SignIn};
    use zeabur_identity_store::{
        Client, CredentialStore as _, MemoryCredentialStore, MemoryDirectory, MemoryGrantStore,
        MemorySetupStore, User,
    };
    use zeabur_identity_test_support::logging::{Capture, FieldValue, Record};
    use zeabur_identity_test_support::{Device, device};
    use zeabur_identity_ui::i18n::Lang;

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
    /// The in-memory stores, on a clock the tests move.
    struct Memory;

    impl Backend for Memory {
        type Directory = MemoryDirectory;
        type Grants = MemoryGrantStore;
        type Clock = TestClock;
        type Credentials = MemoryCredentialStore;
        type Setup = MemorySetupStore;
    }

    type Service = SignIn<Memory>;

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
            &token_hash(INVITATION.as_bytes()),
            UnixTime::from_secs(START + 3600),
        );
        setup.put(
            &User {
                name: "admin".into(),
                subject: ADMIN_UID.into(),
                ..User::default()
            },
            &token_hash(SETUP_TOKEN.as_bytes()),
            UnixTime::from_secs(START + 3600),
        );
        let service = Arc::new(SignIn::<Memory> {
            oauth: Arc::clone(&oauth),
            passkeys: Passkeys::new(&issuer).unwrap(),
            credentials: MemoryCredentialStore::default(),
            setup,
            used_ceremonies: OneTimeIds::default(),
            providers: Arc::default(),
            passwords: zeabur_identity_signin::password::Passwords::with_iterations(&[9; 32], 1)
                .unwrap(),
        });
        let app =
            endpoints::router(oauth).merge(zeabur_identity_signin::router(Arc::clone(&service)));
        Harness {
            app,
            service,
            clock,
        }
    }

    /// An empty JSON object.
    #[derive(Serialize)]
    #[expect(
        clippy::empty_structs_with_brackets,
        reason = "a unit struct serializes as null, not as an empty object"
    )]
    struct Empty {}

    #[derive(Serialize)]
    struct Token<'a> {
        token: &'a str,
    }

    #[derive(Serialize)]
    struct Credential<'a, C> {
        credential: &'a C,
    }

    /// `POST /setup`: a registration response, with the setup token or invitation.
    #[derive(Serialize)]
    struct Enrol<'a, C> {
        token: &'a str,
        credential: &'a C,
        #[serde(skip_serializing_if = "Option::is_none")]
        label: Option<&'a str>,
    }

    #[derive(Serialize)]
    struct Rename<'a> {
        label: &'a str,
    }

    #[derive(Serialize)]
    struct PasswordLogin<'a> {
        username: &'a str,
        password: &'a str,
        #[serde(skip_serializing_if = "Option::is_none")]
        code: Option<&'a str>,
    }

    #[derive(Serialize)]
    struct PasswordSetup<'a> {
        token: &'a str,
        password: &'a str,
        #[serde(skip_serializing_if = "Option::is_none")]
        totp: Option<TotpSetup<'a>>,
    }

    #[derive(Serialize)]
    struct TotpSetup<'a> {
        sealed: &'a str,
        code: &'a str,
    }

    #[derive(Serialize)]
    struct PasswordChange<'a> {
        current: &'a str,
        new: &'a str,
    }

    #[derive(Serialize)]
    struct Current<'a> {
        current: &'a str,
    }

    /// A problem (RFC 9457) of the sign-in API; a member the server does not send fails the parse.
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields, rename_all = "camelCase")]
    struct Problem {
        #[serde(rename = "type")]
        kind: String,
        title: String,
        status: u16,
        detail: String,
        #[serde(default)]
        refresh: bool,
        next: Option<String>,
        weakness: Option<String>,
        unknown_credential: Option<UnknownCredential>,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct UnknownCredential {
        rp_id: String,
        credential_id: String,
    }

    /// `signalAllAcceptedCredentials` data.
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Accepted {
        rp_id: String,
        all_accepted_credential_ids: Vec<String>,
    }

    /// A successful sign-in or session reply; a problem carries none of these members.
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct SignedIn {
        redirect_to: String,
        accepted: Option<Accepted>,
    }

    /// The reply of `/account/session` and `/account/reauth`.
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct AccountSession {
        accepted: Option<Accepted>,
    }

    /// `/.well-known/passkey-endpoints`.
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct PasskeyEndpoints {
        enroll: String,
        manage: String,
    }

    /// The reply of an account change.
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Changed {
        #[serde(default)]
        signed_out: bool,
        accepted: Option<Accepted>,
    }

    #[derive(Deserialize)]
    struct Enrolled {
        username: String,
        recovery_codes: Option<Vec<String>>,
    }

    /// `/setup/password/options`.
    #[derive(Deserialize)]
    struct PasswordOptions {
        totp: Option<Enrolment>,
    }

    #[derive(Deserialize)]
    struct Enrolment {
        secret: String,
        secret_display: String,
        uri: String,
        qr: Qr,
        sealed: String,
    }

    #[derive(Deserialize)]
    struct Qr {
        path: String,
    }

    /// The members of the OAuth token response the tests read.
    #[derive(Deserialize)]
    struct Tokens {
        #[serde(rename = "access_token")]
        access: String,
        #[serde(rename = "id_token")]
        id: Option<String>,
        #[serde(rename = "refresh_token")]
        refresh: Option<String>,
    }

    /// The claims of an access token the tests read.
    #[derive(Deserialize)]
    struct Claims {
        sub: String,
        #[serde(default)]
        groups: Vec<String>,
        amr: Vec<String>,
        auth_time: Option<u64>,
    }

    /// The members of a request or reply body that must not reach the logs.
    #[derive(Default, Deserialize)]
    #[serde(default)]
    struct Secrets {
        token: Option<String>,
        password: Option<String>,
        current: Option<String>,
        new: Option<String>,
        id: Option<String>,
        #[serde(rename = "rawId")]
        raw_id: Option<String>,
        #[serde(rename = "clientDataJSON")]
        client_data_json: Option<String>,
        #[serde(rename = "authenticatorData")]
        authenticator_data: Option<String>,
        signature: Option<String>,
        #[serde(rename = "attestationObject")]
        attestation_object: Option<String>,
        #[serde(rename = "userHandle")]
        user_handle: Option<String>,
        challenge: Option<String>,
        access_token: Option<String>,
        id_token: Option<String>,
        refresh_token: Option<String>,
        redirect_to: Option<String>,
        credential: Option<Box<Self>>,
        response: Option<Box<Self>>,
        #[serde(rename = "publicKey")]
        public_key: Option<PublicKey>,
        user: Option<Box<Self>>,
        rp: Option<Box<Self>>,
    }

    /// `publicKey` is the options object of an options reply and the key text of a registration.
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum PublicKey {
        Options(Box<Secrets>),
        Key(String),
    }

    impl Secrets {
        /// Reads `text` if it is a JSON object; other bodies have no members to check.
        fn read(text: &str) -> Self {
            if text.trim_start().starts_with('{') {
                serde_json::from_str(text).unwrap()
            } else {
                Self::default()
            }
        }

        fn assert_absent_from(&self, records: &str) {
            let named = [
                ("token", &self.token),
                ("password", &self.password),
                ("current", &self.current),
                ("new", &self.new),
                ("id", &self.id),
                ("rawId", &self.raw_id),
                ("clientDataJSON", &self.client_data_json),
                ("authenticatorData", &self.authenticator_data),
                ("signature", &self.signature),
                ("attestationObject", &self.attestation_object),
                ("userHandle", &self.user_handle),
                ("challenge", &self.challenge),
                ("access_token", &self.access_token),
                ("id_token", &self.id_token),
                ("refresh_token", &self.refresh_token),
            ];
            for (key, value) in named {
                if let Some(secret) = value.as_deref().filter(|s| !s.is_empty()) {
                    assert!(!records.contains(secret), "{key} leaked");
                }
            }
            for nested in [&self.credential, &self.response, &self.user, &self.rp]
                .into_iter()
                .flatten()
            {
                nested.assert_absent_from(records);
            }
            match &self.public_key {
                Some(PublicKey::Options(options)) => options.assert_absent_from(records),
                Some(PublicKey::Key(key)) => assert!(!records.contains(key), "publicKey leaked"),
                None => {}
            }
            if let Some(location) = &self.redirect_to
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
    }

    /// A leak check that reads no member of its input passes every log, so each wire name must
    /// be seen: a body carrying only that member, found in a log line, must fail the check.
    #[test]
    fn every_secret_member_is_detected_in_a_log_line() {
        let members = [
            "token",
            "password",
            "current",
            "new",
            "id",
            "rawId",
            "clientDataJSON",
            "authenticatorData",
            "signature",
            "attestationObject",
            "userHandle",
            "challenge",
            "access_token",
            "id_token",
            "refresh_token",
            "publicKey",
        ];
        for member in members {
            let body = format!(r#"{{"{member}":"sentinel-{member}"}}"#);
            let line = format!("INFO sentinel-{member}");
            let leaked =
                std::panic::catch_unwind(|| Secrets::read(&body).assert_absent_from(&line));
            assert!(leaked.is_err(), "a leaked {member} went unnoticed");
            Secrets::read(&body).assert_absent_from("INFO nothing here");
        }
        let body = r#"{"redirect_to":"https://rp.test/cb?code=sentinel-code&state=s"}"#;
        let leaked = std::panic::catch_unwind(|| {
            Secrets::read(body).assert_absent_from("INFO sentinel-code");
        });
        assert!(
            leaked.is_err(),
            "a leaked authorization code went unnoticed"
        );
        for nested in ["credential", "response", "user", "rp"] {
            let body = format!(r#"{{"{nested}":{{"token":"sentinel-{nested}"}}}}"#);
            let leaked = std::panic::catch_unwind(|| {
                Secrets::read(&body).assert_absent_from(&format!("INFO sentinel-{nested}"));
            });
            assert!(leaked.is_err(), "a leaked {nested} member went unnoticed");
        }
    }

    struct Reply {
        status: StatusCode,
        headers: HeaderMap,
        body: String,
        audit: Option<Record>,
        diagnostics: Vec<Record>,
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
        fn parse<T: DeserializeOwned>(&self) -> T {
            serde_json::from_str(&self.body).unwrap_or_else(|e| panic!("{e}: {}", self.body))
        }
        fn problem(&self) -> Problem {
            self.parse()
        }
        fn kind(&self) -> String {
            self.problem().kind
        }
        fn audit(&self) -> &Record {
            self.audit.as_ref().unwrap()
        }
    }

    /// The audit event, phase and method a path logs.
    fn audited(path: &str) -> Option<(&'static str, Option<&'static str>, &'static str)> {
        match path {
            "/setup/options" => Some(("auth.passkey_enrollment", Some("start"), "passkey")),
            "/setup" => Some(("auth.passkey_enrollment", Some("finish"), "passkey")),
            "/login/options" => Some(("auth.passkey_options", None, "passkey")),
            "/login" => Some(("auth.sign_in", None, "passkey")),
            "/login/password" => Some(("auth.sign_in", None, "password")),
            "/setup/password" => Some(("auth.password_enrollment", None, "password")),
            _ => None,
        }
    }

    fn json_text(body: &impl Serialize) -> String {
        serde_json::to_string(body).unwrap()
    }

    async fn call(
        app: &Router,
        method: Method,
        path: &str,
        body: Option<String>,
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
        let body = body.map_or_else(Body::empty, Body::from);
        let response = app
            .clone()
            .oneshot(request.body(body).unwrap())
            .with_subscriber(capture.dispatch())
            .await
            .unwrap();
        let (parts, body) = response.into_parts();
        let bytes = body.collect().await.unwrap().to_bytes();
        let response_body = String::from_utf8(bytes.to_vec()).unwrap();
        let records = capture.records();
        let audit: Vec<&Record> = records
            .iter()
            .filter(|r| r.target == "zeabur_identity::audit")
            .collect();
        for record in &audit {
            super::common::assert_audit_shape(record);
        }
        if let Some((event, phase, method)) = audited(path) {
            assert_eq!(audit.len(), 1, "{records:?}");
            let record = audit[0];
            assert_eq!(record.field("event"), Some(event));
            assert_eq!(record.field("method"), Some(method));
            assert_eq!(
                record.field("outcome"),
                Some(if parts.status.is_success() {
                    "success"
                } else {
                    "failure"
                })
            );
            if let Some(phase) = phase {
                assert_eq!(record.field("phase"), Some(phase));
            }
            if !parts.status.is_success() {
                let problem: Problem = serde_json::from_str(&response_body).unwrap();
                assert_eq!(problem.status, parts.status.as_u16());
                assert_eq!(
                    record.field("reason"),
                    Some(
                        problem
                            .kind
                            .strip_prefix("urn:zeabur-identity:problem:")
                            .unwrap()
                    )
                );
            }
            assert!(!record.fields.contains_key("client"));
        }
        let serialized = audit
            .iter()
            .map(|r| r.text())
            .collect::<Vec<_>>()
            .join("\n");
        for (_, secret) in cookies {
            assert!(!serialized.contains(secret), "cookie leaked");
        }
        if let Some(submitted) = &submitted {
            Secrets::read(submitted).assert_absent_from(&serialized);
        }
        Secrets::read(&response_body).assert_absent_from(&serialized);
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
                .filter(|record| record.target.starts_with("zeabur_identity_signin"))
                .collect(),
        }
    }

    async fn post(
        app: &Router,
        path: &str,
        body: &(impl Serialize + Sync),
        cookies: &[(&str, &str)],
    ) -> Reply {
        call(
            app,
            Method::POST,
            path,
            Some(json_text(body)),
            cookies,
            Some(ISSUER),
        )
        .await
    }

    /// Sends `body` with `method`, as the pages do for a route that changes a resource.
    async fn send(
        app: &Router,
        method: Method,
        path: &str,
        body: &(impl Serialize + Sync),
        cookies: &[(&str, &str)],
    ) -> Reply {
        call(
            app,
            method,
            path,
            Some(json_text(body)),
            cookies,
            Some(ISSUER),
        )
        .await
    }

    /// Sends a `DELETE` without a body. It still names the JSON content type, as every account
    /// route asks for.
    async fn delete(app: &Router, path: &str, cookies: &[(&str, &str)]) -> Reply {
        call(
            app,
            Method::DELETE,
            path,
            Some(String::new()),
            cookies,
            Some(ISSUER),
        )
        .await
    }

    /// The method and path of each route in the committed `ui/src/contract.ts`, the table the
    /// pages call through, with each `{parameter}` filled in as `x`.
    pub(super) fn contract_routes() -> Vec<(Method, String)> {
        let contract = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../ui/src/contract.ts"
        ))
        .unwrap();
        let table = contract
            .split_once("export const routes = {")
            .unwrap()
            .1
            .split_once("} as const")
            .unwrap()
            .0;
        let quoted = |line: &str, key: &str| {
            let rest = line
                .split_once(&format!("{key}: \""))
                .map(|(_, rest)| rest)?;
            rest.split_once('"').map(|(value, _)| value.to_owned())
        };
        let routes: Vec<(Method, String)> = table
            .lines()
            .filter_map(|line| {
                let method = Method::from_bytes(quoted(line, "method")?.as_bytes()).unwrap();
                let path = quoted(line, "path")?
                    .split('/')
                    .map(|segment| {
                        if segment.starts_with('{') {
                            "x"
                        } else {
                            segment
                        }
                    })
                    .collect::<Vec<_>>()
                    .join("/");
                Some((method, path))
            })
            .collect();
        assert!(routes.len() > 20, "{table}");
        routes
    }

    fn origin() -> Url {
        Url::parse(ISSUER).unwrap()
    }

    /// Starts a registration with the setup token; returns the authenticator's response and the
    /// ceremony cookie.
    async fn start_enrolment(
        h: &Harness,
        device: &mut Device,
        token: &str,
    ) -> (CreatedPublicKeyCredential, String) {
        let reply = post(&h.app, "/setup/options", &Token { token }, &[]).await;
        assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
        let (user, subject) = if token == INVITATION {
            ("dana", DANA_UID)
        } else {
            ("admin", ADMIN_UID)
        };
        assert_eq!(reply.audit().fields["user"], user);
        assert_eq!(reply.audit().fields["subject"], subject);
        let options: CredentialCreationOptions = reply.parse();
        let credential = device
            .register(&origin(), options, DefaultClientData)
            .await
            .unwrap();
        (credential, reply.cookie(CEREMONY_COOKIE).unwrap())
    }

    async fn enrol(h: &Harness, device: &mut Device) {
        let (credential, ceremony) = start_enrolment(h, device, SETUP_TOKEN).await;
        let reply = post(
            &h.app,
            "/setup",
            &Enrol {
                token: SETUP_TOKEN,
                credential: &credential,
                label: Some("Laptop"),
            },
            &[(CEREMONY_COOKIE, &ceremony)],
        )
        .await;
        assert_eq!(reply.status, StatusCode::CREATED, "{}", reply.body);
        assert_eq!(reply.audit().fields["user"], "admin");
        assert!(!reply.audit().fields.contains_key("subject"));
        assert_eq!(reply.parse::<Enrolled>().username, "admin");
    }

    /// Opens an authorization request and signs in with `device`; returns the reply to `/login`.
    async fn sign_in(h: &Harness, device: &mut Device) -> Reply {
        let authorize = format!(
            "/authorize?client_id=kubectl&redirect_uri=http%3A%2F%2F127.0.0.1%3A8000%2F&response_type=code&scope=openid&code_challenge={CHALLENGE}&code_challenge_method=S256&state=xyz"
        );
        let reply = call(&h.app, Method::GET, &authorize, None, &[], None).await;
        let flow = reply.cookie(FLOW_COOKIE).unwrap();
        let reply = post(&h.app, "/login/options", &Empty {}, &[]).await;
        assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
        let ceremony = reply.cookie(CEREMONY_COOKIE).unwrap();
        let options: CredentialRequestOptions = reply.parse();
        let assertion = device
            .authenticate(&origin(), options, DefaultClientData)
            .await
            .unwrap();
        post(
            &h.app,
            "/login",
            &Credential {
                credential: &assertion,
            },
            &[(FLOW_COOKIE, &flow), (CEREMONY_COOKIE, &ceremony)],
        )
        .await
    }

    /// Redeems the authorization code in a successful `/login` reply; returns the token response.
    async fn exchange(h: &Harness, reply: &Reply) -> Tokens {
        let location = reply.parse::<SignedIn>().redirect_to;
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
        read_json(response).await
    }

    async fn read_json<T: DeserializeOwned>(response: axum::http::Response<Body>) -> T {
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap()
    }

    impl Tokens {
        /// The claims in the payload of the access token.
        fn claims(&self) -> Claims {
            let payload = self.access.split('.').nth(1).unwrap();
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).unwrap()).unwrap()
        }
    }

    /// The flags byte of an assertion's authenticator data (after the 32-byte RP ID hash).
    fn authenticator_flags(assertion: &AuthenticatedPublicKeyCredential) -> u8 {
        assertion.response.authenticator_data[32]
    }

    const FLAG_UP: u8 = 0x01;
    const FLAG_UV: u8 = 0x04;

    /// Opens the authorization request `authorize` and starts one sign-in ceremony. `device`
    /// first answers it without user verification: the client is told UV is `discouraged`
    /// (only the request options change, and they are not signed), so the authenticator signs
    /// authenticator data with UV clear while the challenge, origin, RP ID and signature stay
    /// valid. The server must refuse that, issue nothing, and leave the ceremony and request
    /// usable; the same ceremony answered with UV then completes. Returns the issued tokens.
    async fn refuse_unverified_then_sign_in(h: &Harness, authorize: &str) -> Tokens {
        let mut device = device();
        enrol(h, &mut device).await;
        let flow = call(&h.app, Method::GET, authorize, None, &[], None)
            .await
            .cookie(FLOW_COOKIE)
            .unwrap();
        let options = post(&h.app, "/login/options", &Empty {}, &[]).await;
        let ceremony = options.cookie(CEREMONY_COOKIE).unwrap();
        let cookies = [
            (FLOW_COOKIE, flow.as_str()),
            (CEREMONY_COOKIE, ceremony.as_str()),
        ];
        let mut discouraged: CredentialRequestOptions = options.parse();
        assert_eq!(
            discouraged.public_key.user_verification,
            UserVerificationRequirement::Required
        );
        discouraged.public_key.user_verification = UserVerificationRequirement::Discouraged;
        let unverified = device
            .authenticate(&origin(), discouraged, DefaultClientData)
            .await
            .unwrap();
        let flags = authenticator_flags(&unverified);
        assert_eq!(flags & (FLAG_UP | FLAG_UV), FLAG_UP, "UP set, UV clear");
        let rejected = post(
            &h.app,
            "/login",
            &Credential {
                credential: &unverified,
            },
            &cookies,
        )
        .await;
        assert_eq!(rejected.status, StatusCode::UNAUTHORIZED);
        assert_eq!(
            rejected.kind(),
            "urn:zeabur-identity:problem:passkey-failed"
        );
        let fields = &rejected.audit().fields;
        assert!(!fields.contains_key("user"));
        assert!(!fields.contains_key("subject"));
        // Refused by the UV check, not by the signature, challenge or origin checks.
        let diagnostic = rejected.diagnostics.first().unwrap();
        assert_eq!(diagnostic.fields["reason"], "passkey-failed");
        assert_eq!(
            diagnostic.field("error"),
            Some(PasskeyError::NotUserVerified.to_string().as_str()),
            "{diagnostic:?}"
        );

        let verified = device
            .authenticate(&origin(), options.parse(), DefaultClientData)
            .await
            .unwrap();
        assert_eq!(authenticator_flags(&verified) & FLAG_UV, FLAG_UV);
        let reply = post(
            &h.app,
            "/login",
            &Credential {
                credential: &verified,
            },
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
        assert_eq!(reply.audit().fields["user"], "admin");
        assert_eq!(reply.audit().fields["subject"], ADMIN_UID);
        assert!(
            reply
                .headers
                .get_all(header::SET_COOKIE)
                .iter()
                .any(|c| c.to_str().unwrap().starts_with(&format!("{FLOW_COOKIE}=;"))),
            "flow cookie cleared"
        );
        let accepted = reply.parse::<SignedIn>().accepted.unwrap();
        assert_eq!(accepted.rp_id, "login.example.com");
        let claims = exchange(&h, &reply).await.claims();
        assert_eq!(claims.sub, ADMIN_UID);
        assert_eq!(claims.groups, ["admins"]);
        assert_eq!(claims.amr, ["swk", "mfa"]);
        assert_eq!(claims.auth_time, Some(START));
    }

    #[tokio::test]
    async fn invitation_enrols_the_invited_user_once() {
        let h = harness().await;
        let mut device = device();
        let (credential, ceremony) = start_enrolment(&h, &mut device, INVITATION).await;
        let reply = post(
            &h.app,
            "/setup",
            &Enrol {
                token: INVITATION,
                credential: &credential,
                label: None,
            },
            &[(CEREMONY_COOKIE, &ceremony)],
        )
        .await;
        assert_eq!(reply.status, StatusCode::CREATED, "{}", reply.body);
        assert_eq!(reply.parse::<Enrolled>().username, "dana");

        // Used up; and the admin's setup token is untouched by it.
        let reply = post(&h.app, "/setup/options", &Token { token: INVITATION }, &[]).await;
        assert_eq!(reply.kind(), "urn:zeabur-identity:problem:setup-invalid");
        let reply = post(&h.app, "/setup/options", &Token { token: SETUP_TOKEN }, &[]).await;
        assert_eq!(reply.status, StatusCode::OK);

        // Signing in with the new passkey yields dana's identity.
        let reply = sign_in(&h, &mut device).await;
        assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);

        // A guessed secret for a real invitation name is refused.
        let reply = post(
            &h.app,
            "/setup/options",
            &Token {
                token: "inv-1.guess",
            },
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
                &Enrol {
                    token,
                    credential: &credential,
                    label: None,
                },
                &[(CEREMONY_COOKIE, &ceremony)],
            )
            .await;
            assert_eq!(
                finish.kind(),
                "urn:zeabur-identity:problem:setup-invalid",
                "{name}"
            );
            let options = post(&h.app, "/setup/options", &Token { token }, &[]).await;
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
                &Enrol {
                    token,
                    credential: &credential,
                    label: None,
                },
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

            let options = post(&h.app, "/setup/options", &Token { token }, &[]).await;
            assert_eq!(options.status, StatusCode::FORBIDDEN, "{name}");
            assert_eq!(
                options.kind(),
                "urn:zeabur-identity:problem:account-disabled",
                "{name}"
            );
            let finish = post(
                &h.app,
                "/setup",
                &Enrol {
                    token,
                    credential: &credential,
                    label: None,
                },
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
            let options = post(&h.app, "/setup/options", &Token { token }, &[]).await;
            assert_eq!(options.status, StatusCode::OK, "{name}");
        }
    }

    #[tokio::test]
    async fn setup_token_is_single_use() {
        let h = harness().await;
        enrol(&h, &mut device()).await;
        let reply = post(&h.app, "/setup/options", &Token { token: SETUP_TOKEN }, &[]).await;
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
                        &Enrol {
                            token: SETUP_TOKEN,
                            credential: &credential,
                            label: None,
                        },
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
        let reply = post(&h.app, "/setup/options", &Token { token: "wrong" }, &[]).await;
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED);

        // Started in time, finished after expiry.
        let mut device = device();
        let (credential, ceremony) = start_enrolment(&h, &mut device, SETUP_TOKEN).await;
        h.clock.0.fetch_add(3600, Ordering::SeqCst);
        let reply = post(
            &h.app,
            "/setup",
            &Enrol {
                token: SETUP_TOKEN,
                credential: &credential,
                label: None,
            },
            &[(CEREMONY_COOKIE, &ceremony)],
        )
        .await;
        assert_eq!(
            reply.status,
            StatusCode::BAD_REQUEST,
            "the ceremony expired first: {}",
            reply.body
        );
        let reply = post(&h.app, "/setup/options", &Token { token: SETUP_TOKEN }, &[]).await;
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
            &token_hash(b"a-newer-token"),
            UnixTime::from_secs(START + 3600),
        );
        let reply = post(
            &h.app,
            "/setup",
            &Enrol {
                token: SETUP_TOKEN,
                credential: &credential,
                label: None,
            },
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
            Some(json_text(&Token { token: SETUP_TOKEN })),
            &[],
            None,
        )
        .await;
        assert_eq!(reply.status, StatusCode::FORBIDDEN);
        let reply = call(
            &h.app,
            Method::POST,
            "/login/options",
            Some(json_text(&Empty {})),
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
        let reply = post(&h.app, "/login/options", &Empty {}, &[]).await;
        let ceremony = reply.cookie(CEREMONY_COOKIE).unwrap();
        let options: CredentialRequestOptions = reply.parse();
        let assertion = device
            .authenticate(&origin(), options, DefaultClientData)
            .await
            .unwrap();
        let cookies = [
            (FLOW_COOKIE, flow.as_str()),
            (CEREMONY_COOKIE, ceremony.as_str()),
        ];
        // Knowing an enrolled credential ID and handle is not proof of possession.
        let mut forged: AuthenticatedPublicKeyCredential =
            serde_json::from_str(&json_text(&assertion)).unwrap();
        forged.response.signature = vec![0_u8; 64].into();
        let rejected = post(
            &h.app,
            "/login",
            &Credential {
                credential: &forged,
            },
            &cookies,
        )
        .await;
        assert_eq!(rejected.status, StatusCode::UNAUTHORIZED);
        assert_eq!(
            rejected.kind(),
            "urn:zeabur-identity:problem:passkey-failed"
        );
        let fields = &rejected.audit().fields;
        assert!(!fields.contains_key("user"));
        assert!(!fields.contains_key("subject"));
        assert!(!fields.contains_key("error"));
        let diagnostic = rejected.diagnostics.first().unwrap();
        assert_eq!(diagnostic.fields["reason"], "passkey-failed");
        // Failed signature verification does not consume the valid ceremony.
        assert_eq!(
            post(
                &h.app,
                "/login",
                &Credential {
                    credential: &assertion
                },
                &cookies
            )
            .await
            .status,
            StatusCode::OK
        );
        let second = post(
            &h.app,
            "/login",
            &Credential {
                credential: &assertion,
            },
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
        assert!(!reply.audit().fields.contains_key("user"));
        assert!(!reply.audit().fields.contains_key("subject"));

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
        let fields = &reply.audit().fields;
        assert!(!fields.contains_key("user"));
        assert!(!fields.contains_key("subject"));
    }

    #[tokio::test]
    async fn sign_in_needs_a_pending_authorization_request() {
        let h = harness().await;
        let mut device = device();
        enrol(&h, &mut device).await;
        let reply = post(&h.app, "/login/options", &Empty {}, &[]).await;
        let ceremony = reply.cookie(CEREMONY_COOKIE).unwrap();
        let options: CredentialRequestOptions = reply.parse();
        let assertion = device
            .authenticate(&origin(), options, DefaultClientData)
            .await
            .unwrap();
        let reply = post(
            &h.app,
            "/login",
            &Credential {
                credential: &assertion,
            },
            &[(CEREMONY_COOKIE, &ceremony)],
        )
        .await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST);
        assert_eq!(reply.kind(), "urn:zeabur-identity:problem:no-request");
    }

    /// A refusal says why in the language the page asks for, and names the step the page moves
    /// to, so the page needs no table of problem codes.
    #[tokio::test]
    async fn a_refusal_says_why_in_the_page_language() {
        let h = harness().await;
        for (lang, messages) in [("zh-TW", Lang::ZhTw), ("en", Lang::En), ("", Lang::En)] {
            let request = Request::post("/setup/options")
                .header(header::ORIGIN, ISSUER)
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ACCEPT_LANGUAGE, lang)
                .body(Body::from(json_text(&Token { token: "wrong" })))
                .unwrap();
            let response = h.app.clone().oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
            let body: Problem = read_json(response).await;
            assert_eq!(body.detail, messages.messages().setup_invalid, "{lang}");
            assert_eq!(body.next.as_deref(), Some("new-link"));
            assert!(!body.refresh);
        }
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
        let reply = post(&h.app, "/setup/options", &Token { token: SETUP_TOKEN }, &[]).await;
        let ceremony = reply.cookie(CEREMONY_COOKIE).unwrap();
        let options: CredentialCreationOptions = reply.parse();
        // A client honouring `userVerification: required` refuses outright; if one sends a
        // response anyway, the server must reject it. This covers registration from the client
        // side only; `refuse_unverified_then_sign_in` covers signed sign-in assertions.
        if let Ok(credential) = device.register(&origin(), options, DefaultClientData).await {
            let reply = post(
                &h.app,
                "/setup",
                &Enrol {
                    token: SETUP_TOKEN,
                    credential: &credential,
                    label: None,
                },
                &[(CEREMONY_COOKIE, &ceremony)],
            )
            .await;
            assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
        }
        // The token was not consumed by the failed attempt.
        let reply = post(&h.app, "/setup/options", &Token { token: SETUP_TOKEN }, &[]).await;
        assert_eq!(reply.status, StatusCode::OK);
    }

    #[tokio::test]
    async fn sign_in_without_user_verification_is_refused() {
        let h = harness().await;
        let authorize = format!(
            "/authorize?client_id=kubectl&redirect_uri=http%3A%2F%2F127.0.0.1%3A8000%2F&response_type=code&scope=openid&code_challenge={CHALLENGE}&code_challenge_method=S256"
        );
        let tokens = refuse_unverified_then_sign_in(&h, &authorize).await;
        assert!(tokens.refresh.is_some());
        assert!(tokens.id.is_some());
    }

    /// `credential` (a registration response) with the backup flags (BE, BS) clear, as a
    /// device-bound passkey reports them. The test authenticator sets both, like a synced
    /// passkey. Attestation is `none`, so nothing signs these flags.
    fn as_device_bound(mut credential: CreatedPublicKeyCredential) -> CreatedPublicKeyCredential {
        let object = &mut credential.response.attestation_object;
        let key = b"hauthData";
        let at = object.windows(key.len()).position(|w| w == key).unwrap() + key.len();
        // A CBOR byte string head: 0x58 with a one-byte length, or 0x59 with two.
        let data = at + if object[at] == 0x58 { 2 } else { 3 };
        assert_eq!(object[data + 32] & 0x18, 0x18, "BE and BS set");
        object[data + 32] &= !0x18;
        credential
    }

    fn require_device_bound_passkeys(h: &Harness) {
        h.service.oauth.directory.put_settings(Settings {
            admin_sign_in: AdminSignIn::DeviceBoundPasskey,
            ..Settings::default()
        });
    }

    #[tokio::test]
    async fn with_device_bound_passkeys_an_admin_cannot_sign_in_with_a_synced_passkey() {
        let h = harness().await;
        let mut device = device();
        enrol(&h, &mut device).await;
        require_device_bound_passkeys(&h);
        let reply = sign_in(&h, &mut device).await;
        assert_eq!(reply.status, StatusCode::FORBIDDEN, "{}", reply.body);
        assert_eq!(
            reply.kind(),
            "urn:zeabur-identity:problem:device-passkey-needed"
        );
    }

    #[tokio::test]
    async fn with_device_bound_passkeys_an_admin_enrols_only_a_device_bound_passkey() {
        let h = harness().await;
        require_device_bound_passkeys(&h);
        let mut device = device();
        let (credential, ceremony) = start_enrolment(&h, &mut device, SETUP_TOKEN).await;
        let refused = post(
            &h.app,
            "/setup",
            &Enrol {
                token: SETUP_TOKEN,
                credential: &credential,
                label: None,
            },
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
            &Enrol {
                token: SETUP_TOKEN,
                credential: &as_device_bound(credential),
                label: None,
            },
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
            let options = post(&h.app, "/login/options", &Empty {}, &[]).await;
            let ceremony = options.cookie(CEREMONY_COOKIE).unwrap();
            let assertion = device
                .authenticate(&origin(), options.parse(), DefaultClientData)
                .await
                .unwrap();
            let reply = post(
                &h.app,
                "/login",
                &Credential {
                    credential: &assertion,
                },
                &[(FLOW_COOKIE, &rejected_flow), (CEREMONY_COOKIE, &ceremony)],
            )
            .await;
            assert_eq!(reply.status, StatusCode::BAD_REQUEST);
            assert_eq!(reply.kind(), "urn:zeabur-identity:problem:no-request");
            let fields = &reply.audit().fields;
            assert_eq!(fields["outcome"], "failure");
            assert_eq!(fields["user"], "admin");
            assert_eq!(fields["subject"], ADMIN_UID);
            assert!(!fields.contains_key("error"));
            let diagnostic = reply.diagnostics.first().unwrap();
            assert_eq!(diagnostic.fields["reason"], "authorization_failed");
            let error = diagnostic.field("error").unwrap();
            assert!(!serde_json::to_string(fields).unwrap().contains(error));
            // A rejected authorization still consumed the verified passkey ceremony.
            let second_attempt = post(
                &h.app,
                "/login",
                &Credential {
                    credential: &assertion,
                },
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
            &token_hash(token.as_bytes()),
            UnixTime::from_secs(START + 3600),
        );
        let reply = post(&h.app, "/setup/options", &Token { token }, &[]).await;
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
        let fields = &reply.audit().fields;
        assert!(!fields.contains_key("user"));
        assert!(!fields.contains_key("subject"));
    }

    mod account {
        use zeabur_identity_signin::account::{
            ACCOUNT_CLIENT, REAUTH_WINDOW, SESSION_COOKIE, SESSION_LIFETIME,
        };
        use zeabur_identity_store::{GrantStore as _, Removal};

        use super::*;

        /// Only the signed-out page has the sign-in button.
        pub(super) const SIGNED_OUT_MARK: &str = "id=\"account-sign-in\"";

        /// A signed-in browser: the session cookie.
        pub(super) struct Session {
            pub(super) cookie: String,
        }

        impl Session {
            pub(super) fn cookies(&self) -> [(&str, &str); 1] {
                [(SESSION_COOKIE, self.cookie.as_str())]
            }
        }

        pub(super) async fn user(h: &Harness, name: &str) -> User {
            h.service.oauth.directory.user(name).await.unwrap().unwrap()
        }

        pub(super) async fn passkeys(h: &Harness, name: &str) -> Vec<String> {
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

        pub(super) async fn page(h: &Harness, session: Option<&str>) -> String {
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

        async fn assertion(
            device: &mut Device,
            reply: &Reply,
        ) -> (AuthenticatedPublicKeyCredential, String) {
            assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
            let options: CredentialRequestOptions = reply.parse();
            let assertion = device
                .authenticate(&origin(), options, DefaultClientData)
                .await
                .unwrap();
            (assertion, reply.cookie(CEREMONY_COOKIE).unwrap())
        }

        pub(super) async fn sign_in_to_account(h: &Harness, device: &mut Device) -> Session {
            let reply = post(&h.app, "/account/session/options", &Empty {}, &[]).await;
            let (credential, ceremony) = assertion(device, &reply).await;
            let reply = post(
                &h.app,
                "/account/session",
                &Credential {
                    credential: &credential,
                },
                &[(CEREMONY_COOKIE, &ceremony)],
            )
            .await;
            assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
            let accepted = reply.parse::<AccountSession>().accepted.unwrap();
            assert_eq!(accepted.rp_id, "login.example.com");
            assert_ne!(accepted.all_accepted_credential_ids, Vec::<String>::new());
            let set_cookie = reply
                .headers
                .get_all(header::SET_COOKIE)
                .iter()
                .map(|v| v.to_str().unwrap().to_owned())
                .find(|v| v.starts_with(SESSION_COOKIE))
                .unwrap();
            assert!(set_cookie.contains("HttpOnly") && set_cookie.contains("SameSite=Lax"));
            let cookie = reply.cookie(SESSION_COOKIE).unwrap();
            Session { cookie }
        }

        pub(super) async fn reauth(h: &Harness, session: &Session, device: &mut Device) -> Reply {
            let reply = post(
                &h.app,
                "/account/reauth/options",
                &Empty {},
                &session.cookies(),
            )
            .await;
            let (credential, ceremony) = assertion(device, &reply).await;
            post(
                &h.app,
                "/account/reauth",
                &Credential {
                    credential: &credential,
                },
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
                &Empty {},
                &session.cookies(),
            )
            .await;
            if reply.status != StatusCode::OK {
                return reply;
            }
            let options: CredentialCreationOptions = reply.parse();
            let selection = options.public_key.authenticator_selection.as_ref().unwrap();
            assert_eq!(
                selection.resident_key,
                Some(ResidentKeyRequirement::Required)
            );
            assert_eq!(
                selection.user_verification,
                UserVerificationRequirement::Required
            );
            let ceremony = reply.cookie(CEREMONY_COOKIE).unwrap();
            let credential = device
                .register(&origin(), options, DefaultClientData)
                .await
                .unwrap();
            post(
                &h.app,
                "/account/passkeys",
                &Credential {
                    credential: &credential,
                },
                &[
                    (SESSION_COOKIE, &session.cookie),
                    (CEREMONY_COOKIE, &ceremony),
                ],
            )
            .await
        }

        async fn remove(h: &Harness, session: &Session, name: &str) -> Reply {
            let path = format!("/account/passkeys/{name}");
            delete(&h.app, &path, &session.cookies()).await
        }

        pub(super) fn advance(h: &Harness, by: std::time::Duration) {
            h.clock.0.fetch_add(by.as_secs(), Ordering::SeqCst);
        }

        /// Admin enrolled with one device and signed in to `/account` with it.
        pub(super) async fn signed_in() -> (Harness, Device, Session) {
            let h = harness().await;
            let mut first = device();
            enrol(&h, &mut first).await;
            let session = sign_in_to_account(&h, &mut first).await;
            (h, first, session)
        }

        /// A passkey account session records what a passkey sign-in asserts (RFC 8176 values in
        /// this order), and that the user was verified.
        #[tokio::test]
        async fn a_passkey_session_records_the_passkey_sign_in() {
            let (h, _device, _session) = signed_in().await;
            let admin = user(&h, "admin").await;
            let grants = h.service.oauth.grants.list(&admin).await.unwrap();
            let [grant] = grants.as_slice() else {
                panic!("{grants:?}")
            };
            assert_eq!(grant.spec.client, ACCOUNT_CLIENT);
            assert_eq!(grant.spec.amr, ["swk", "mfa"]);
            assert!(grant.spec.user_verified);
            assert!(grant.spec.credential.is_some());
        }

        /// Every route in the table the pages call through is served with the method the table
        /// names: a change on either side would leave a control that calls nowhere.
        #[tokio::test]
        async fn each_route_the_contract_names_is_served() {
            let (h, _device, session) = signed_in().await;
            for (method, path) in contract_routes() {
                if path.starts_with("/upstream/") || path == "/account/links/start" {
                    // The upstream router is not part of this harness; `tests/upstream.rs`
                    // calls these two routes.
                    continue;
                }
                let reply = call(
                    &h.app,
                    method.clone(),
                    &path,
                    Some("{}".to_owned()),
                    &session.cookies(),
                    Some(ISSUER),
                )
                .await;
                let routed = !matches!(
                    reply.status,
                    StatusCode::NOT_FOUND | StatusCode::METHOD_NOT_ALLOWED
                ) || reply.headers[header::CONTENT_TYPE] == "application/problem+json";
                assert!(routed, "{method} {path} answered {}", reply.status);
            }
        }

        pub(super) async fn enrol_dana(h: &Harness) -> Device {
            let mut dana = device();
            let (credential, ceremony) = start_enrolment(h, &mut dana, INVITATION).await;
            let reply = post(
                &h.app,
                "/setup",
                &Enrol {
                    token: INVITATION,
                    credential: &credential,
                    label: None,
                },
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
            assert!(signed_out.contains(SIGNED_OUT_MARK));
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
            assert!(html.contains("Passkey added <time datetime=\""));
        }

        #[tokio::test]
        async fn changes_cannot_reach_another_users_objects() {
            let (h, _first, admin) = signed_in().await;
            let mut dana_device = enrol_dana(&h).await;
            let dana = sign_in_to_account(&h, &mut dana_device).await;
            let [admin_passkey] = <[String; 1]>::try_from(passkeys(&h, "admin").await).unwrap();
            let admin_session = admin.cookie.split_once('.').unwrap().0.to_owned();

            let reply = send(
                &h.app,
                Method::PATCH,
                &format!("/account/passkeys/{admin_passkey}"),
                &Rename { label: "Mine" },
                &dana.cookies(),
            )
            .await;
            assert_eq!(reply.status, StatusCode::NOT_FOUND);
            let reply = remove(&h, &dana, &admin_passkey).await;
            assert_eq!(reply.status, StatusCode::NOT_FOUND);
            let path = format!("/account/sessions/{admin_session}");
            let reply = delete(&h.app, &path, &dana.cookies()).await;
            assert_eq!(reply.status, StatusCode::NOT_FOUND);
            assert_eq!(passkeys(&h, "admin").await, [admin_passkey]);
            assert!(
                !page(&h, Some(&admin.cookie))
                    .await
                    .contains(SIGNED_OUT_MARK)
            );

            // Re-authenticating with someone else's passkey does not count.
            let reply = reauth(&h, &admin, &mut dana_device).await;
            assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
            assert_eq!(reply.kind(), "urn:zeabur-identity:problem:passkey-failed");

            // A session is tied to the user's UID: a recreated user of the same name is signed out.
            let mut recreated = user(&h, "admin").await;
            recreated.subject = "0f0e0d0c-0b0a-4908-8706-050403020100".into();
            h.service.oauth.directory.put_user(recreated);
            assert!(
                page(&h, Some(&admin.cookie))
                    .await
                    .contains(SIGNED_OUT_MARK)
            );
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
                &Empty {},
                &session.cookies(),
            )
            .await;
            assert_eq!(reply.status, StatusCode::OK);
            let options: CredentialCreationOptions = reply.parse();
            assert_eq!(options.public_key.exclude_credentials.unwrap().len(), 2);
            advance(&h, std::time::Duration::from_secs(1));
            let reply = add(&h, &session, &mut device()).await;
            assert_eq!(reply.kind(), "urn:zeabur-identity:problem:reauth-required");
        }

        /// A rename with the given browser headers and content type; the label shows whether it
        /// took effect.
        async fn rename_with(
            h: &Harness,
            session: &Session,
            name: &str,
            headers: &[(&str, &str)],
            content_type: &str,
        ) -> StatusCode {
            let mut request = Request::builder()
                .method(Method::PATCH)
                .uri(format!("/account/passkeys/{name}"))
                .header(header::CONTENT_TYPE, content_type)
                .header(
                    header::COOKIE,
                    format!("{SESSION_COOKIE}={}", session.cookie),
                );
            for (key, value) in headers {
                request = request.header(*key, *value);
            }
            let body = json_text(&Rename { label: "Phone" });
            let response = h
                .app
                .clone()
                .oneshot(request.body(Body::from(body)).unwrap())
                .await
                .unwrap();
            response.status()
        }

        /// The bare issuer URL leads to the account page.
        #[tokio::test]
        async fn the_root_redirects_to_the_account_page() {
            let h = harness().await;
            let reply = call(&h.app, Method::GET, "/", None, &[], None).await;
            assert_eq!(reply.status, StatusCode::SEE_OTHER);
            assert_eq!(reply.headers[header::LOCATION], "/account");
        }

        /// A cross-site request is refused for being cross-site before its body is read, so a
        /// body that does not parse still gets 403, and the refusal is not cached. This holds for
        /// every method the route table names, `PATCH` and `DELETE` as well as `POST`.
        #[tokio::test]
        async fn cross_site_requests_are_refused_before_the_body_is_read() {
            let (h, _first, session) = signed_in().await;
            let routes = contract_routes();
            for method in [Method::PATCH, Method::PUT, Method::DELETE] {
                assert!(routes.iter().any(|(m, _)| *m == method), "{method}");
            }
            for (method, path) in routes {
                if path.starts_with("/upstream/") || path == "/account/links/start" {
                    // `cross_site_starts_are_refused_before_the_body_is_read` in
                    // `tests/upstream.rs` covers the upstream routes.
                    continue;
                }
                let reply = call(
                    &h.app,
                    method.clone(),
                    &path,
                    Some("not json".to_owned()),
                    &session.cookies(),
                    Some("https://evil.example"),
                )
                .await;
                assert_eq!(reply.status, StatusCode::FORBIDDEN, "{method} {path}");
                assert_eq!(
                    reply.kind(),
                    "urn:zeabur-identity:problem:cross-site",
                    "{method} {path}"
                );
                assert_eq!(
                    reply.headers[header::CACHE_CONTROL],
                    "no-store",
                    "{method} {path}"
                );
            }
        }

        /// A `PATCH` or `DELETE` that `Sec-Fetch-Site` marks cross-site changes nothing, even
        /// with a valid session cookie and the JSON content type.
        #[tokio::test]
        async fn cross_site_patch_and_delete_change_nothing() {
            let (h, _first, session) = signed_in().await;
            let [name] = <[String; 1]>::try_from(passkeys(&h, "admin").await).unwrap();
            let path = format!("/account/passkeys/{name}");
            for (method, body) in [
                (Method::PATCH, json_text(&Rename { label: "Evil" })),
                (Method::DELETE, String::new()),
            ] {
                let request = Request::builder()
                    .method(method.clone())
                    .uri(&path)
                    .header("sec-fetch-site", "cross-site")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(
                        header::COOKIE,
                        format!("{SESSION_COOKIE}={}", session.cookie),
                    )
                    .body(Body::from(body))
                    .unwrap();
                let response = h.app.clone().oneshot(request).await.unwrap();
                assert_eq!(response.status(), StatusCode::FORBIDDEN, "{method}");
            }
            assert_eq!(passkeys(&h, "admin").await, [name]);
            assert!(!page(&h, Some(&session.cookie)).await.contains("Evil"));
        }

        /// The routes the account page called before they became resources are gone: no
        /// handler answers them.
        #[tokio::test]
        async fn the_old_account_routes_are_gone() {
            let (h, _first, session) = signed_in().await;
            for path in [
                "/account/sign-out",
                "/account/passkeys/rename",
                "/account/passkeys/remove",
                "/account/sessions/revoke",
                "/account/sessions/revoke-others",
                "/account/links/remove",
                "/account/password/add",
                "/account/password/remove",
            ] {
                let reply = post(&h.app, path, &Empty {}, &session.cookies()).await;
                // A path that now matches a resource route answers 405 for `POST`.
                assert!(
                    matches!(
                        reply.status,
                        StatusCode::NOT_FOUND | StatusCode::METHOD_NOT_ALLOWED
                    ),
                    "{path} answered {}",
                    reply.status
                );
                let problem = reply
                    .headers
                    .get(header::CONTENT_TYPE)
                    .is_some_and(|v| v == "application/problem+json");
                assert!(!problem, "{path} reached a handler");
            }
            for (method, path) in [
                (Method::POST, "/account/authenticator"),
                (Method::POST, "/account/sessions"),
            ] {
                let reply = call(
                    &h.app,
                    method,
                    path,
                    Some("{}".to_owned()),
                    &session.cookies(),
                    Some(ISSUER),
                )
                .await;
                assert_eq!(reply.status, StatusCode::METHOD_NOT_ALLOWED, "{path}");
            }
        }

        #[tokio::test]
        async fn changes_need_a_same_origin_json_request() {
            let (h, _first, session) = signed_in().await;
            let [name] = <[String; 1]>::try_from(passkeys(&h, "admin").await).unwrap();
            let json = "application/json";
            let refused = [
                (
                    vec![("sec-fetch-site", "cross-site")],
                    json,
                    StatusCode::FORBIDDEN,
                ),
                (
                    vec![("sec-fetch-site", "same-site")],
                    json,
                    StatusCode::FORBIDDEN,
                ),
                (
                    vec![("origin", "https://evil.example")],
                    json,
                    StatusCode::FORBIDDEN,
                ),
                (vec![], json, StatusCode::FORBIDDEN),
                (
                    vec![("sec-fetch-site", "same-origin")],
                    "text/plain",
                    StatusCode::UNSUPPORTED_MEDIA_TYPE,
                ),
            ];
            for (headers, content_type, expected) in refused {
                let status = rename_with(&h, &session, &name, &headers, content_type).await;
                assert_eq!(status, expected, "{headers:?} {content_type}");
            }
            assert!(!page(&h, Some(&session.cookie)).await.contains("Phone"));

            let status = rename_with(
                &h,
                &session,
                &name,
                &[("sec-fetch-site", "same-origin")],
                json,
            )
            .await;
            assert_eq!(status, StatusCode::OK);
            assert!(page(&h, Some(&session.cookie)).await.contains("Phone"));
            let status = rename_with(&h, &session, &name, &[("origin", ISSUER)], json).await;
            assert_eq!(status, StatusCode::OK);

            // Rename needs no recent passkey confirmation.
            advance(&h, REAUTH_WINDOW);
            let reply = send(
                &h.app,
                Method::PATCH,
                &format!("/account/passkeys/{name}"),
                &Rename { label: "  Phone  " },
                &session.cookies(),
            )
            .await;
            assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
            assert!(page(&h, Some(&session.cookie)).await.contains("Phone"));
            let fields = &reply.audit.unwrap().fields;
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
            let refresh = tokens.refresh.unwrap();
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
            let changed: Changed = reply.parse();
            assert!(!changed.signed_out);
            assert_eq!(
                changed.accepted.unwrap().all_accepted_credential_ids.len(),
                1
            );
            let fields = &reply.audit.unwrap().fields;
            assert_eq!(fields["event"], "account.passkey_removed");
            assert_eq!(fields["revoked"], FieldValue::Count(2));

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
            assert!(
                page(&h, Some(&by_first.cookie))
                    .await
                    .contains(SIGNED_OUT_MARK)
            );
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
            let reply = post(&h.app, "/account/session/options", &Empty {}, &[]).await;
            let (credential, ceremony) = assertion(&mut first, &reply).await;
            let reply = post(
                &h.app,
                "/account/session",
                &Credential {
                    credential: &credential,
                },
                &[(CEREMONY_COOKIE, &ceremony)],
            )
            .await;
            assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
            let unknown = reply.problem().unknown_credential.unwrap();
            assert_eq!(unknown.rp_id, "login.example.com");
            assert_eq!(unknown.credential_id, credential.id);
        }

        #[tokio::test]
        async fn sessions_can_be_revoked() {
            let (h, mut first, this) = signed_in().await;
            let other = sign_in_to_account(&h, &mut first).await;
            let _tokens = exchange(&h, &sign_in(&h, &mut first).await).await;
            let admin = user(&h, "admin").await;
            assert_eq!(h.service.oauth.grants.list(&admin).await.unwrap().len(), 3);

            let other_name = other.cookie.split_once('.').unwrap().0;
            let path = format!("/account/sessions/{other_name}");
            let reply = delete(&h.app, &path, &this.cookies()).await;
            assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
            assert!(
                page(&h, Some(&other.cookie))
                    .await
                    .contains(SIGNED_OUT_MARK)
            );
            assert_eq!(
                h.service.credentials.events().last().unwrap().reason,
                "SessionRevoked"
            );

            let reply = delete(&h.app, "/account/sessions", &this.cookies()).await;
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
            assert!(!page(&h, Some(&this.cookie)).await.contains(SIGNED_OUT_MARK));

            let reply = delete(&h.app, "/account/session", &this.cookies()).await;
            assert_eq!(reply.status, StatusCode::OK);
            let left = h.service.oauth.grants.list(&admin).await.unwrap();
            assert_eq!(left.len(), 0);
        }

        #[tokio::test]
        async fn sessions_end_after_an_hour_and_with_the_user() {
            let (h, _first, session) = signed_in().await;
            advance(&h, SESSION_LIFETIME);
            assert!(
                page(&h, Some(&session.cookie))
                    .await
                    .contains(SIGNED_OUT_MARK)
            );
            let reply = delete(&h.app, "/account/sessions", &session.cookies()).await;
            assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
            assert_eq!(reply.kind(), "urn:zeabur-identity:problem:signed-out");

            let (h, _first, session) = signed_in().await;
            let mut admin = user(&h, "admin").await;
            admin.disabled = true;
            h.service.oauth.directory.put_user(admin);
            assert!(
                page(&h, Some(&session.cookie))
                    .await
                    .contains(SIGNED_OUT_MARK)
            );
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
            let endpoints: PasskeyEndpoints = read_json(response).await;
            assert_eq!(endpoints.enroll, "https://login.example.com/account#add");
            assert_eq!(endpoints.manage, "https://login.example.com/account");
        }
    }

    mod password {
        use zeabur_identity_core::guessing::{HOLD, LIMIT};
        use zeabur_identity_core::totp::{RECOVERY_CODES, STEP, Secret};
        use zeabur_identity_signin::account::{REAUTH_WINDOW, SESSION_COOKIE};
        use zeabur_identity_signin::password::DEVICE_COOKIE;
        use zeabur_identity_store::GrantStore as _;

        use super::account::{self, SIGNED_OUT_MARK, Session, page, sign_in_to_account, signed_in};
        use super::*;

        const GOOD: &str = "violet kettle under the stairs";

        /// Opens an authorization request; returns the flow cookie.
        async fn flow(h: &Harness) -> String {
            let authorize = format!(
                "/authorize?client_id=kubectl&redirect_uri=http%3A%2F%2F127.0.0.1%3A8000%2F&response_type=code&scope=openid&code_challenge={CHALLENGE}&code_challenge_method=S256&state=xyz"
            );
            let reply = call(&h.app, Method::GET, &authorize, None, &[], None).await;
            reply.cookie(FLOW_COOKIE).unwrap()
        }

        async fn set_password(h: &Harness, token: &str, password: &str) -> Reply {
            post(
                &h.app,
                "/setup/password",
                &PasswordSetup {
                    token,
                    password,
                    totp: None,
                },
                &[],
            )
            .await
        }

        async fn sign_in(
            h: &Harness,
            username: &str,
            password: &str,
            device: Option<&str>,
        ) -> Reply {
            let flow = flow(h).await;
            let mut cookies = vec![(FLOW_COOKIE, flow.as_str())];
            cookies.extend(device.map(|d| (DEVICE_COOKIE, d)));
            post(
                &h.app,
                "/login/password",
                &PasswordLogin {
                    username,
                    password,
                    code: None,
                },
                &cookies,
            )
            .await
        }

        /// Sets dana's password with the invitation; returns the device cookie it gave.
        async fn dana_with_password(h: &Harness) -> String {
            let reply = set_password(h, INVITATION, GOOD).await;
            assert_eq!(reply.status, StatusCode::CREATED, "{}", reply.body);
            assert_eq!(reply.parse::<Enrolled>().username, "dana");
            reply.cookie(DEVICE_COOKIE).unwrap()
        }

        #[tokio::test]
        async fn a_password_set_with_an_invitation_signs_in() {
            let h = harness().await;
            let device = dana_with_password(&h).await;
            let reply = sign_in(&h, "dana", GOOD, Some(&device)).await;
            assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
            assert!(reply.cookie(DEVICE_COOKIE).is_some());
            let claims = exchange(&h, &reply).await.claims();
            assert_eq!(claims.sub, DANA_UID);
            assert_eq!(claims.amr, ["pwd"]);
            // The invitation is used up.
            assert_eq!(
                set_password(&h, INVITATION, GOOD).await.status,
                StatusCode::UNAUTHORIZED
            );
        }

        #[tokio::test]
        async fn weak_passwords_are_refused_and_leave_the_link_usable() {
            let h = harness().await;
            for (password, weakness) in [
                ("too short", "too-short"),
                ("passwordpassword", "common"),
                ("dana keeps a tidy garden", "context"),
                ("example rocks on my server", "context"),
            ] {
                let reply = set_password(&h, INVITATION, password).await;
                assert_eq!(reply.status, StatusCode::UNPROCESSABLE_ENTITY, "{password}");
                assert_eq!(
                    reply.problem().weakness.as_deref(),
                    Some(weakness),
                    "{password}"
                );
            }
            dana_with_password(&h).await;
        }

        #[tokio::test]
        async fn an_admin_password_needs_an_authenticator() {
            let h = harness().await;
            let reply = set_password(&h, SETUP_TOKEN, GOOD).await;
            assert_eq!(reply.status, StatusCode::FORBIDDEN);
            assert!(reply.kind().ends_with(":admin-needs-two-factor"));
            // Where admins need a passkey, setup offers no authenticator either.
            h.service.oauth.directory.put_settings(Settings {
                admin_sign_in: AdminSignIn::Passkey,
                ..Settings::default()
            });
            let reply = options(&h, SETUP_TOKEN).await;
            assert!(reply.kind().ends_with(":admin-needs-passkey"));
            let reply = set_password(&h, SETUP_TOKEN, GOOD).await;
            assert!(reply.kind().ends_with(":admin-needs-passkey"));
        }

        #[tokio::test]
        async fn a_regular_password_needs_no_authenticator() {
            let h = harness().await;
            let reply = options(&h, INVITATION).await;
            assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
            assert!(reply.parse::<PasswordOptions>().totp.is_none());
        }

        async fn options(h: &Harness, token: &str) -> Reply {
            post(&h.app, "/setup/password/options", &Token { token }, &[]).await
        }

        /// RFC 4648 base32 without padding.
        fn base32(text: &str) -> Vec<u8> {
            let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
            let (mut out, mut buffer, mut bits) = (Vec::new(), 0_u32, 0);
            for c in text.chars() {
                let value = u32::try_from(alphabet.find(c).unwrap()).unwrap();
                buffer = ((buffer << 5) | value) & 0xFFFF;
                bits += 5;
                if bits >= 8 {
                    bits -= 8;
                    out.push(u8::try_from((buffer >> bits) & 0xFF).unwrap());
                }
            }
            out
        }

        fn now(h: &Harness) -> UnixTime {
            UnixTime::from_secs(h.clock.0.load(Ordering::SeqCst))
        }

        fn next_step(h: &Harness) {
            h.clock.0.fetch_add(STEP, Ordering::SeqCst);
        }

        /// Sets the admin's password with an authenticator; returns its secret, the recovery
        /// codes and the device cookie.
        async fn admin_with_authenticator(h: &Harness) -> (Secret, Vec<String>, String) {
            let offered = options(h, SETUP_TOKEN).await;
            assert_eq!(offered.status, StatusCode::OK, "{}", offered.body);
            let totp = offered.parse::<PasswordOptions>().totp.unwrap();
            assert!(totp.uri.starts_with("otpauth://totp/"));
            assert!(totp.qr.path.starts_with('M'));
            let secret = Secret::from_bytes(&base32(&totp.secret)).unwrap();
            assert_eq!(totp.secret_display.replace(' ', ""), totp.secret);
            let sealed = totp.sealed;
            let setup = |code: String| {
                let body = json_text(&PasswordSetup {
                    token: SETUP_TOKEN,
                    password: GOOD,
                    totp: Some(TotpSetup {
                        sealed: &sealed,
                        code: &code,
                    }),
                });
                async move {
                    call(
                        &h.app,
                        Method::POST,
                        "/setup/password",
                        Some(body),
                        &[],
                        Some(ISSUER),
                    )
                    .await
                }
            };
            // A wrong code leaves the link usable.
            let wrong = setup("000000".to_owned()).await;
            assert_eq!(
                wrong.status,
                StatusCode::UNPROCESSABLE_ENTITY,
                "{}",
                wrong.body
            );
            assert!(wrong.kind().ends_with(":code-failed"));
            let reply = setup(secret.code_at(now(h))).await;
            assert_eq!(reply.status, StatusCode::CREATED, "{}", reply.body);
            let codes = reply.parse::<Enrolled>().recovery_codes.unwrap();
            assert_eq!(codes.len(), RECOVERY_CODES);
            (secret, codes, reply.cookie(DEVICE_COOKIE).unwrap())
        }

        async fn sign_in_with_code(h: &Harness, code: Option<&str>, device: Option<&str>) -> Reply {
            admin_sign_in(h, GOOD, code, device).await
        }

        async fn admin_sign_in(
            h: &Harness,
            password: &str,
            code: Option<&str>,
            device: Option<&str>,
        ) -> Reply {
            let flow = flow(h).await;
            let mut cookies = vec![(FLOW_COOKIE, flow.as_str())];
            cookies.extend(device.map(|d| (DEVICE_COOKIE, d)));
            let body = &PasswordLogin {
                username: "admin",
                password,
                code,
            };
            post(&h.app, "/login/password", body, &cookies).await
        }

        async fn amr(h: &Harness, reply: &Reply) -> Vec<String> {
            exchange(h, reply).await.claims().amr
        }

        #[tokio::test]
        async fn an_admin_signs_in_with_a_password_and_a_code_that_works_once() {
            let h = harness().await;
            let (secret, _, device) = admin_with_authenticator(&h).await;
            let device = Some(device.as_str());
            let reply = sign_in_with_code(&h, None, device).await;
            assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
            assert!(reply.kind().ends_with(":code-needed"));
            // The code entered at setup does not work again.
            let used = secret.code_at(now(&h));
            let reply = sign_in_with_code(&h, Some(&used), device).await;
            assert!(reply.kind().ends_with(":code-failed"), "{}", reply.body);
            next_step(&h);
            let code = secret.code_at(now(&h));
            let reply = sign_in_with_code(&h, Some(&code), device).await;
            assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
            assert_eq!(amr(&h, &reply).await, ["pwd", "otp", "mfa"]);
            let reply = sign_in_with_code(&h, Some(&code), device).await;
            assert!(reply.kind().ends_with(":code-failed"), "replayed");
        }

        #[tokio::test]
        async fn a_recovery_code_works_once_in_place_of_a_code() {
            let h = harness().await;
            let (_, codes, device) = admin_with_authenticator(&h).await;
            let device = Some(device.as_str());
            let typed = codes[3].to_ascii_uppercase();
            let reply = sign_in_with_code(&h, Some(&typed), device).await;
            assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
            assert_eq!(amr(&h, &reply).await, ["pwd", "mfa"]);
            let reply = sign_in_with_code(&h, Some(&codes[3]), device).await;
            assert!(reply.kind().ends_with(":code-failed"));
            let reply = sign_in_with_code(&h, Some(&codes[4]), device).await;
            assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
        }

        #[tokio::test]
        async fn wrong_codes_count_as_failed_sign_ins() {
            let h = harness().await;
            let (secret, _, device) = admin_with_authenticator(&h).await;
            for _ in 0..=LIMIT {
                let reply = sign_in_with_code(&h, Some("123456"), None).await;
                assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
            }
            next_step(&h);
            let code = secret.code_at(now(&h));
            let reply = sign_in_with_code(&h, Some(&code), None).await;
            assert!(reply.kind().ends_with(":password-failed"), "held back");
            let reply = sign_in_with_code(&h, Some(&code), Some(&device)).await;
            assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
        }

        #[tokio::test]
        async fn every_failure_gives_the_same_answer() {
            let h = harness().await;
            dana_with_password(&h).await;
            for (username, password) in [
                ("dana", "not the password at all"),
                ("nobody", GOOD),
                ("admin", GOOD),
                ("dana", ""),
            ] {
                let reply = sign_in(&h, username, password, None).await;
                assert_eq!(reply.status, StatusCode::UNAUTHORIZED, "{username}");
                assert_eq!(
                    reply.problem().title,
                    "Unable to sign in with this username and password."
                );
                assert!(reply.cookie(DEVICE_COOKIE).is_none());
            }
        }

        #[tokio::test]
        async fn a_sign_in_needs_a_request_in_progress() {
            let h = harness().await;
            dana_with_password(&h).await;
            let reply = post(
                &h.app,
                "/login/password",
                &PasswordLogin {
                    username: "dana",
                    password: GOOD,
                    code: None,
                },
                &[],
            )
            .await;
            assert!(reply.kind().ends_with(":no-request"));
        }

        #[tokio::test]
        async fn guesses_from_elsewhere_never_hold_back_a_known_browser() {
            let h = harness().await;
            let device = dana_with_password(&h).await;
            for _ in 0..=LIMIT {
                let reply = sign_in(&h, "dana", "a wrong guess, again and again", None).await;
                assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
            }
            // Held back, even with the right password. The answer is the one an unknown user gets,
            // so a hold does not show that dana exists.
            let reply = sign_in(&h, "dana", GOOD, None).await;
            assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
            assert!(!reply.headers.contains_key(header::RETRY_AFTER));
            let unknown = sign_in(&h, "nobody", GOOD, None).await;
            assert_eq!(reply.body, unknown.body);
            // The browser dana signed in with still works.
            let reply = sign_in(&h, "dana", GOOD, Some(&device)).await;
            assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
            // Other browsers can try again after the hold.
            h.clock.0.fetch_add(HOLD.as_secs(), Ordering::SeqCst);
            let reply = sign_in(&h, "dana", GOOD, None).await;
            assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
        }

        #[tokio::test]
        async fn a_known_browser_is_held_back_by_its_own_guesses() {
            let h = harness().await;
            let device = dana_with_password(&h).await;
            for _ in 0..=LIMIT {
                sign_in(&h, "dana", "a wrong guess, again and again", Some(&device)).await;
            }
            let reply = sign_in(&h, "dana", GOOD, Some(&device)).await;
            assert_eq!(reply.status, StatusCode::TOO_MANY_REQUESTS);
            let reply = sign_in(&h, "dana", GOOD, None).await;
            assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
        }

        #[tokio::test]
        async fn a_hold_in_another_language_still_says_when_to_retry() {
            let h = harness().await;
            let device = dana_with_password(&h).await;
            for _ in 0..=LIMIT {
                sign_in(&h, "dana", "a wrong guess, again and again", Some(&device)).await;
            }
            let flow = flow(&h).await;
            let request = Request::post("/login/password")
                .header(header::ORIGIN, ISSUER)
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ACCEPT_LANGUAGE, "zh-TW")
                .header(
                    header::COOKIE,
                    format!("{FLOW_COOKIE}={flow}; {DEVICE_COOKIE}={device}"),
                )
                .body(Body::from(json_text(&PasswordLogin {
                    username: "dana",
                    password: GOOD,
                    code: None,
                })))
                .unwrap();
            let response = h.app.clone().oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
            assert!(response.headers().contains_key(header::RETRY_AFTER));
            let body: Problem = read_json(response).await;
            assert_eq!(body.detail, Lang::ZhTw.messages().password_held);
        }

        #[tokio::test]
        async fn a_passkey_sign_in_gives_the_browser_a_device_cookie() {
            let h = harness().await;
            let mut device = device();
            enrol(&h, &mut device).await;
            let reply = super::sign_in(&h, &mut device).await;
            assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
            assert!(reply.cookie(DEVICE_COOKIE).unwrap().starts_with(ADMIN_UID));
        }

        const NEW: &str = "copper lantern by the north gate";

        /// The admin signed in to `/account` with a passkey, with a password and an
        /// authenticator too. Returns the harness, the passkey device, the session, the
        /// authenticator secret, the recovery codes and the device cookie.
        async fn account_with_password() -> (Harness, Device, Session, Secret, Vec<String>, String)
        {
            let (h, passkey, session) = signed_in().await;
            assert!(
                !page(&h, Some(&session.cookie))
                    .await
                    .contains(PASSWORD_FORM)
            );
            let admin = account::user(&h, "admin").await;
            h.service.setup.put(
                &admin,
                &token_hash(SETUP_TOKEN.as_bytes()),
                UnixTime::from_secs(START + 3600),
            );
            let (secret, codes, device) = admin_with_authenticator(&h).await;
            (h, passkey, session, secret, codes, device)
        }

        /// Only a user with a password sees the form to change it.
        const PASSWORD_FORM: &str = "id=\"password-change\"";

        async fn change(
            h: &Harness,
            session: &Session,
            device: &str,
            current: &str,
            new: &str,
        ) -> Reply {
            send(
                &h.app,
                Method::PUT,
                "/account/password",
                &PasswordChange { current, new },
                &[(SESSION_COOKIE, &session.cookie), (DEVICE_COOKIE, device)],
            )
            .await
        }

        async fn remove(h: &Harness, session: &Session, device: &str, current: &str) -> Reply {
            send(
                &h.app,
                Method::DELETE,
                "/account/password",
                &Current { current },
                &[(SESSION_COOKIE, &session.cookie), (DEVICE_COOKIE, device)],
            )
            .await
        }

        #[tokio::test]
        async fn a_changed_password_signs_in_and_the_old_one_does_not() {
            let (h, _passkey, session, secret, _, device) = account_with_password().await;
            assert!(
                page(&h, Some(&session.cookie))
                    .await
                    .contains(PASSWORD_FORM)
            );
            let reply = change(&h, &session, &device, GOOD, NEW).await;
            assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
            let audit = &reply.audit().fields;
            assert_eq!(audit["event"], "account.password_changed");
            assert_eq!(audit["outcome"], "success");
            let event = h.service.credentials.events().pop().unwrap();
            assert_eq!(event.reason, "PasswordChanged");
            assert_eq!(event.subject, ADMIN_UID);

            next_step(&h);
            let code = secret.code_at(now(&h));
            let reply = admin_sign_in(&h, GOOD, Some(&code), Some(&device)).await;
            assert!(reply.kind().ends_with(":password-failed"), "{}", reply.body);
            let reply = admin_sign_in(&h, NEW, Some(&code), Some(&device)).await;
            assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
        }

        #[tokio::test]
        async fn a_wrong_current_password_is_refused_and_counted() {
            let (h, mut passkey, session, _, _, device) = account_with_password().await;
            let reply = change(&h, &session, &device, "not my password at all", NEW).await;
            assert_eq!(reply.status, StatusCode::FORBIDDEN);
            assert!(reply.kind().ends_with(":current-password-wrong"));
            let audit = &reply.audit().fields;
            assert_eq!(audit["reason"], "current-password-wrong");
            for _ in 0..LIMIT {
                remove(&h, &session, &device, "not my password at all").await;
            }
            // This browser is held back, even with the right password.
            let reply = change(&h, &session, &device, GOOD, NEW).await;
            assert_eq!(
                reply.status,
                StatusCode::TOO_MANY_REQUESTS,
                "{}",
                reply.body
            );
            assert!(reply.kind().ends_with(":password-held"));
            assert!(reply.headers.contains_key(header::RETRY_AFTER));
            h.clock.0.fetch_add(HOLD.as_secs(), Ordering::SeqCst);
            let session = sign_in_to_account(&h, &mut passkey).await;
            let reply = change(&h, &session, &device, GOOD, NEW).await;
            assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
        }

        #[tokio::test]
        async fn a_weak_new_password_is_refused() {
            let (h, _passkey, session, secret, _, device) = account_with_password().await;
            for (password, weakness) in [
                ("too short", "too-short"),
                ("passwordpassword", "common"),
                ("admin keeps a tidy garden", "context"),
            ] {
                let reply = change(&h, &session, &device, GOOD, password).await;
                assert_eq!(reply.status, StatusCode::UNPROCESSABLE_ENTITY, "{password}");
                assert_eq!(
                    reply.problem().weakness.as_deref(),
                    Some(weakness),
                    "{password}"
                );
            }
            next_step(&h);
            let code = secret.code_at(now(&h));
            let reply = admin_sign_in(&h, GOOD, Some(&code), Some(&device)).await;
            assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
        }

        #[tokio::test]
        async fn used_codes_stay_used_after_a_change() {
            let (h, _passkey, session, secret, codes, device) = account_with_password().await;
            let known = Some(device.as_str());
            next_step(&h);
            let code = secret.code_at(now(&h));
            let reply = sign_in_with_code(&h, Some(&code), known).await;
            assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
            let reply = sign_in_with_code(&h, Some(&codes[0]), known).await;
            assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);

            let reply = change(&h, &session, &device, GOOD, NEW).await;
            assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);

            let reply = admin_sign_in(&h, NEW, Some(&code), known).await;
            assert!(reply.kind().ends_with(":code-failed"), "used step");
            let reply = admin_sign_in(&h, NEW, Some(&codes[0]), known).await;
            assert!(reply.kind().ends_with(":code-failed"), "used recovery code");
            let reply = admin_sign_in(&h, NEW, Some(&codes[1]), known).await;
            assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
            next_step(&h);
            let reply = admin_sign_in(&h, NEW, Some(&secret.code_at(now(&h))), known).await;
            assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
        }

        #[tokio::test]
        async fn the_only_way_in_cannot_be_removed() {
            let (h, _passkey, session, _, _, device) = account_with_password().await;
            for name in account::passkeys(&h, "admin").await {
                h.service.credentials.delete(&name);
            }
            let reply = remove(&h, &session, &device, GOOD).await;
            assert_eq!(reply.status, StatusCode::CONFLICT, "{}", reply.body);
            assert!(reply.kind().ends_with(":last-credential"));
            let admin = account::user(&h, "admin").await;
            assert!(
                h.service
                    .credentials
                    .password(&admin)
                    .await
                    .unwrap()
                    .is_some()
            );
        }

        #[tokio::test]
        async fn removing_the_password_removes_the_authenticator() {
            let (h, _passkey, session, secret, codes, device) = account_with_password().await;
            let reply = remove(&h, &session, &device, GOOD).await;
            assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
            let audit = &reply.audit().fields;
            assert_eq!(audit["event"], "account.password_removed");
            assert_eq!(
                h.service.credentials.events().pop().unwrap().reason,
                "PasswordRemoved"
            );
            let admin = account::user(&h, "admin").await;
            assert!(
                h.service
                    .credentials
                    .password(&admin)
                    .await
                    .unwrap()
                    .is_none()
            );
            assert!(
                !page(&h, Some(&session.cookie))
                    .await
                    .contains(PASSWORD_FORM)
            );
            next_step(&h);
            let known = Some(device.as_str());
            let reply = sign_in_with_code(&h, Some(&secret.code_at(now(&h))), known).await;
            assert!(reply.kind().ends_with(":password-failed"));
            let reply = sign_in_with_code(&h, Some(&codes[2]), known).await;
            assert!(reply.kind().ends_with(":password-failed"));
            // There is nothing left to remove.
            let reply = remove(&h, &session, &device, GOOD).await;
            assert_eq!(reply.status, StatusCode::NOT_FOUND);
        }

        #[tokio::test]
        async fn a_change_or_removal_signs_out_every_other_session() {
            let (h, mut passkey, session, _, _, device) = account_with_password().await;
            let other = sign_in_to_account(&h, &mut passkey).await;
            let reply = change(&h, &session, &device, GOOD, NEW).await;
            assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
            assert_eq!(reply.audit().fields["revoked"], FieldValue::Count(1));
            assert!(
                page(&h, Some(&other.cookie))
                    .await
                    .contains(SIGNED_OUT_MARK)
            );
            assert!(
                !page(&h, Some(&session.cookie))
                    .await
                    .contains(SIGNED_OUT_MARK)
            );

            let other = sign_in_to_account(&h, &mut passkey).await;
            let reply = remove(&h, &session, &device, NEW).await;
            assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
            assert!(
                page(&h, Some(&other.cookie))
                    .await
                    .contains(SIGNED_OUT_MARK)
            );
            assert!(
                !page(&h, Some(&session.cookie))
                    .await
                    .contains(SIGNED_OUT_MARK)
            );
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn concurrent_changes_save_one_and_refuse_the_other() {
            let (h, _passkey, session, secret, _, device) = account_with_password().await;
            let other = "amber window over the old mill";
            let (first, second) = tokio::join!(
                change(&h, &session, &device, GOOD, NEW),
                change(&h, &session, &device, GOOD, other),
            );
            let (saved, refused) = if first.status == StatusCode::OK {
                ((first, NEW), second)
            } else {
                ((second, other), first)
            };
            assert_eq!(saved.0.status, StatusCode::OK, "{}", saved.0.body);
            // Both read the old password and the second save conflicts, or the first saved before
            // the second read, which then finds the current password changed.
            let kind = refused.kind();
            assert!(
                (refused.status == StatusCode::CONFLICT && kind.ends_with(":password-conflict"))
                    || (refused.status == StatusCode::FORBIDDEN
                        && kind.ends_with(":current-password-wrong")),
                "{}",
                refused.body
            );
            next_step(&h);
            let code = secret.code_at(now(&h));
            let reply = admin_sign_in(&h, saved.1, Some(&code), Some(&device)).await;
            assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
        }

        async fn account_sign_in(
            h: &Harness,
            username: &str,
            password: &str,
            code: Option<&str>,
            device: Option<&str>,
        ) -> Reply {
            let cookies: Vec<(&str, &str)> =
                device.map(|d| (DEVICE_COOKIE, d)).into_iter().collect();
            post(
                &h.app,
                "/account/session/password",
                &PasswordLogin {
                    username,
                    password,
                    code,
                },
                &cookies,
            )
            .await
        }

        /// A password account session records what a password sign-in asserts, and that the
        /// user was not verified.
        #[tokio::test]
        async fn a_password_session_records_the_password_sign_in() {
            let h = harness().await;
            let device = dana_with_password(&h).await;
            let reply = account_sign_in(&h, "dana", GOOD, None, Some(&device)).await;
            assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
            let dana = account::user(&h, "dana").await;
            let grants = h.service.oauth.grants.list(&dana).await.unwrap();
            let [grant] = grants.as_slice() else {
                panic!("{grants:?}")
            };
            assert_eq!(grant.spec.amr, ["pwd"]);
            assert!(!grant.spec.user_verified);
            assert!(!grant.spec.device_bound);
            assert!(grant.spec.credential.is_some());
        }

        #[tokio::test]
        async fn a_user_with_only_a_password_signs_in_to_the_account_page_and_changes_it() {
            let h = harness().await;
            let device = dana_with_password(&h).await;
            let reply = account_sign_in(&h, "dana", GOOD, None, Some(&device)).await;
            assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
            let audit = &reply.audit().fields;
            assert_eq!(audit["event"], "account.sign_in");
            assert_eq!(audit["outcome"], "success");
            let session = Session {
                cookie: reply.cookie(SESSION_COOKIE).unwrap(),
            };
            let html = page(&h, Some(&session.cookie)).await;
            assert!(html.contains(PASSWORD_FORM));
            // Without a passkey, the page offers no passkey or link changes.
            assert!(!html.contains("id=\"add\""));
            assert!(html.contains("needs a sign-in with a passkey"));
            let reply = post(
                &h.app,
                "/account/passkeys/options",
                &Empty {},
                &session.cookies(),
            )
            .await;
            assert!(reply.kind().ends_with(":reauth-required"), "{}", reply.body);

            let reply = change(&h, &session, &device, GOOD, NEW).await;
            assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
            let reply = sign_in(&h, "dana", GOOD, Some(&device)).await;
            assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
            let reply = sign_in(&h, "dana", NEW, Some(&device)).await;
            assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
        }

        #[tokio::test]
        async fn an_admin_signs_in_to_the_account_page_with_a_password_and_a_code() {
            let h = harness().await;
            let (secret, _, device) = admin_with_authenticator(&h).await;
            let reply = account_sign_in(&h, "admin", GOOD, None, Some(&device)).await;
            assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
            assert!(reply.kind().ends_with(":code-needed"));
            assert!(reply.cookie(SESSION_COOKIE).is_none());
            next_step(&h);
            let code = secret.code_at(now(&h));
            let reply = account_sign_in(&h, "admin", GOOD, Some(&code), Some(&device)).await;
            assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
            let cookie = reply.cookie(SESSION_COOKIE).unwrap();
            assert!(!page(&h, Some(&cookie)).await.contains(SIGNED_OUT_MARK));
            // The code works once, here as at the sign-in page.
            let reply = sign_in_with_code(&h, Some(&code), Some(&device)).await;
            assert!(reply.kind().ends_with(":code-failed"));
        }

        #[tokio::test]
        async fn account_sign_ins_count_against_the_sign_in_limits() {
            let h = harness().await;
            let device = dana_with_password(&h).await;
            for _ in 0..=LIMIT {
                let reply = account_sign_in(
                    &h,
                    "dana",
                    "a wrong guess, again and again",
                    None,
                    Some(&device),
                )
                .await;
                assert!(reply.cookie(SESSION_COOKIE).is_none());
            }
            let reply = sign_in(&h, "dana", GOOD, Some(&device)).await;
            assert_eq!(reply.status, StatusCode::TOO_MANY_REQUESTS);
            let reply = account_sign_in(&h, "dana", GOOD, None, Some(&device)).await;
            assert_eq!(reply.status, StatusCode::TOO_MANY_REQUESTS);
            assert!(reply.headers.contains_key(header::RETRY_AFTER));
        }

        #[tokio::test]
        async fn an_unknown_user_gets_the_answer_of_a_wrong_password() {
            let h = harness().await;
            dana_with_password(&h).await;
            let wrong = account_sign_in(&h, "dana", "not the password at all", None, None).await;
            assert_eq!(wrong.status, StatusCode::UNAUTHORIZED);
            for (username, password) in [("nobody", GOOD), ("admin", GOOD), ("dana", "")] {
                let reply = account_sign_in(&h, username, password, None, None).await;
                assert_eq!(reply.status, wrong.status, "{username}");
                assert_eq!(reply.body, wrong.body, "{username}");
                assert!(reply.cookie(SESSION_COOKIE).is_none());
            }
        }

        #[derive(Serialize)]
        struct PasswordAdd<'a> {
            password: &'a str,
            #[serde(skip_serializing_if = "Option::is_none")]
            totp: Option<TotpSetup<'a>>,
        }

        /// The body of `/account/authenticator` and `/account/recovery-codes`.
        #[derive(Serialize, Default)]
        struct Confirm<'a> {
            #[serde(skip_serializing_if = "Option::is_none")]
            current: Option<&'a str>,
            #[serde(skip_serializing_if = "Option::is_none")]
            code: Option<&'a str>,
            #[serde(skip_serializing_if = "Option::is_none")]
            totp: Option<TotpSetup<'a>>,
        }

        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct RecoveryCodes {
            recovery_codes: Option<Vec<String>>,
        }

        /// Only a user who can add a password sees the button for it.
        const ADD_PASSWORD: &str = "data-opens=\"add-password\"";

        async fn add_options(h: &Harness, session: &Session) -> Reply {
            post(
                &h.app,
                "/account/password/options",
                &Empty {},
                &session.cookies(),
            )
            .await
        }

        async fn add_password(
            h: &Harness,
            session: &Session,
            password: &str,
            totp: Option<TotpSetup<'_>>,
        ) -> Reply {
            let body = &PasswordAdd { password, totp };
            post(&h.app, "/account/password", body, &session.cookies()).await
        }

        async fn confirmed(
            h: &Harness,
            (method, path): &(Method, &str),
            session: &Session,
            device: &str,
            body: &Confirm<'_>,
        ) -> Reply {
            let cookies = [
                (SESSION_COOKIE, session.cookie.as_str()),
                (DEVICE_COOKIE, device),
            ];
            send(&h.app, method.clone(), path, body, &cookies).await
        }

        fn shown_codes(reply: &Reply) -> Vec<String> {
            assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
            let codes = reply.parse::<RecoveryCodes>().recovery_codes.unwrap();
            assert_eq!(codes.len(), RECOVERY_CODES);
            codes
        }

        fn secret_of(enrolment: &Enrolment) -> Secret {
            Secret::from_bytes(&base32(&enrolment.secret)).unwrap()
        }

        #[tokio::test]
        async fn a_password_is_added_after_a_passkey_confirmation() {
            let h = harness().await;
            let mut dana = account::enrol_dana(&h).await;
            let session = sign_in_to_account(&h, &mut dana).await;
            let other = sign_in_to_account(&h, &mut dana).await;
            assert!(page(&h, Some(&session.cookie)).await.contains(ADD_PASSWORD));

            account::advance(&h, REAUTH_WINDOW);
            for reply in [
                add_options(&h, &session).await,
                add_password(&h, &session, GOOD, None).await,
            ] {
                assert_eq!(reply.status, StatusCode::FORBIDDEN, "{}", reply.body);
                assert!(reply.kind().ends_with(":reauth-required"));
            }
            assert!(
                sign_in(&h, "dana", GOOD, None)
                    .await
                    .kind()
                    .ends_with(":password-failed")
            );

            let reply = account::reauth(&h, &session, &mut dana).await;
            assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
            let reply = add_options(&h, &session).await;
            assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
            assert!(reply.parse::<PasswordOptions>().totp.is_none());
            let reply = add_password(&h, &session, "too short", None).await;
            assert_eq!(reply.problem().weakness.as_deref(), Some("too-short"));
            let reply = add_password(&h, &session, GOOD, None).await;
            assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
            assert!(reply.parse::<RecoveryCodes>().recovery_codes.is_none());
            assert!(reply.cookie(DEVICE_COOKIE).is_some());
            let audit = &reply.audit().fields;
            assert_eq!(audit["event"], "account.password_added");
            assert_eq!(audit["revoked"], FieldValue::Count(1));
            assert_eq!(
                h.service.credentials.events().pop().unwrap().reason,
                "PasswordAdded"
            );
            assert!(
                page(&h, Some(&other.cookie))
                    .await
                    .contains(SIGNED_OUT_MARK)
            );

            let reply = sign_in(&h, "dana", GOOD, None).await;
            assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
            let html = page(&h, Some(&session.cookie)).await;
            assert!(!html.contains(ADD_PASSWORD));
            for reply in [
                add_options(&h, &session).await,
                add_password(&h, &session, "amber window over the old mill", None).await,
            ] {
                assert_eq!(reply.status, StatusCode::CONFLICT, "{}", reply.body);
                assert!(reply.kind().ends_with(":password-exists"));
            }
        }

        #[tokio::test]
        async fn an_admin_adds_a_password_only_with_an_authenticator() {
            let (h, mut passkey, session) = signed_in().await;
            let reply = add_options(&h, &session).await;
            assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
            let enrolment = reply.parse::<PasswordOptions>().totp.unwrap();
            let secret = secret_of(&enrolment);
            let totp = |code| {
                Some(TotpSetup {
                    sealed: &enrolment.sealed,
                    code,
                })
            };

            let reply = add_password(&h, &session, GOOD, None).await;
            assert_eq!(reply.status, StatusCode::FORBIDDEN, "{}", reply.body);
            assert!(reply.kind().ends_with(":admin-needs-two-factor"));
            let reply = add_password(&h, &session, GOOD, totp("000000")).await;
            assert!(reply.kind().ends_with(":code-failed"), "{}", reply.body);
            // An authenticator offered to another session does not work here.
            let elsewhere = sign_in_to_account(&h, &mut passkey).await;
            let code = secret.code_at(now(&h));
            let reply = add_password(&h, &elsewhere, GOOD, totp(&code)).await;
            assert!(reply.kind().ends_with(":no-request"), "{}", reply.body);
            let admin = account::user(&h, "admin").await;
            assert!(
                h.service
                    .credentials
                    .password(&admin)
                    .await
                    .unwrap()
                    .is_none()
            );

            let reply = add_password(&h, &session, GOOD, totp(&code)).await;
            let codes = shown_codes(&reply);
            next_step(&h);
            let reply = sign_in_with_code(&h, Some(&secret.code_at(now(&h))), None).await;
            assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
            let reply = sign_in_with_code(&h, Some(&codes[0]), None).await;
            assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
        }

        #[tokio::test]
        async fn a_new_authenticator_retires_the_old_secret_and_codes() {
            let (h, mut passkey, session, old, old_codes, device) = account_with_password().await;
            let other = sign_in_to_account(&h, &mut passkey).await;
            let html = page(&h, Some(&session.cookie)).await;
            assert!(html.contains("data-opens=\"authenticator\""));
            assert!(html.contains("data-opens=\"recovery\""));
            let reply = post(
                &h.app,
                "/account/authenticator/options",
                &Empty {},
                &session.cookies(),
            )
            .await;
            assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
            let enrolment: Enrolment = reply.parse();
            let new = secret_of(&enrolment);
            next_step(&h);
            let (confirm, code) = (old.code_at(now(&h)), new.code_at(now(&h)));
            let body = Confirm {
                current: Some(GOOD),
                code: Some(&confirm),
                totp: Some(TotpSetup {
                    sealed: &enrolment.sealed,
                    code: &code,
                }),
            };
            let reply = confirmed(
                &h,
                &(Method::PUT, "/account/authenticator"),
                &session,
                &device,
                &body,
            )
            .await;
            let codes = shown_codes(&reply);
            assert_eq!(
                reply.audit().fields["event"],
                "account.authenticator_replaced"
            );
            let event = h.service.credentials.events().pop().unwrap();
            assert_eq!(event.reason, "AuthenticatorReplaced");
            assert!(
                page(&h, Some(&other.cookie))
                    .await
                    .contains(SIGNED_OUT_MARK)
            );
            assert!(
                !page(&h, Some(&session.cookie))
                    .await
                    .contains(SIGNED_OUT_MARK)
            );

            next_step(&h);
            let known = Some(device.as_str());
            let reply = sign_in_with_code(&h, Some(&old.code_at(now(&h))), known).await;
            assert!(reply.kind().ends_with(":code-failed"), "old secret");
            let reply = sign_in_with_code(&h, Some(&old_codes[5]), known).await;
            assert!(reply.kind().ends_with(":code-failed"), "old recovery code");
            let reply = sign_in_with_code(&h, Some(&new.code_at(now(&h))), known).await;
            assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
            let reply = sign_in_with_code(&h, Some(&codes[0]), known).await;
            assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
        }

        #[tokio::test]
        async fn new_recovery_codes_retire_the_old_ones_and_keep_the_app() {
            let (h, mut passkey, session, secret, old_codes, device) =
                account_with_password().await;
            let path = &(Method::POST, "/account/recovery-codes");
            // Without the current password, the change needs a passkey confirmation.
            account::advance(&h, REAUTH_WINDOW);
            let reply = confirmed(&h, path, &session, &device, &Confirm::default()).await;
            assert!(reply.kind().ends_with(":reauth-required"), "{}", reply.body);
            let other = sign_in_to_account(&h, &mut passkey).await;
            let reply = account::reauth(&h, &session, &mut passkey).await;
            assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
            let reply = confirmed(&h, path, &session, &device, &Confirm::default()).await;
            let codes = shown_codes(&reply);
            assert_ne!(codes, old_codes);
            assert_eq!(
                reply.audit().fields["event"],
                "account.recovery_codes_regenerated"
            );
            let event = h.service.credentials.events().pop().unwrap();
            assert_eq!(event.reason, "RecoveryCodesRegenerated");
            assert!(
                page(&h, Some(&other.cookie))
                    .await
                    .contains(SIGNED_OUT_MARK)
            );

            let known = Some(device.as_str());
            let reply = sign_in_with_code(&h, Some(&old_codes[0]), known).await;
            assert!(reply.kind().ends_with(":code-failed"), "old recovery code");
            let reply = sign_in_with_code(&h, Some(&codes[0]), known).await;
            assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
            next_step(&h);
            let reply = sign_in_with_code(&h, Some(&secret.code_at(now(&h))), known).await;
            assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
        }

        #[tokio::test]
        async fn a_wrong_password_or_code_is_refused_and_counted() {
            let (h, mut passkey, session, secret, codes, device) = account_with_password().await;
            let path = &(Method::POST, "/account/recovery-codes");
            let wrong = Confirm {
                current: Some("not my password at all"),
                code: Some(&codes[0]),
                ..Confirm::default()
            };
            let reply = confirmed(&h, path, &session, &device, &wrong).await;
            assert_eq!(reply.status, StatusCode::FORBIDDEN, "{}", reply.body);
            assert!(reply.kind().ends_with(":current-password-wrong"));
            for code in [None, Some(""), Some("000000")] {
                let body = Confirm {
                    current: Some(GOOD),
                    code,
                    ..Confirm::default()
                };
                let reply = confirmed(&h, path, &session, &device, &body).await;
                assert!(
                    reply.kind().ends_with(":code-failed"),
                    "{code:?}: {}",
                    reply.body
                );
            }
            for _ in 0..LIMIT {
                let body = Confirm {
                    current: Some(GOOD),
                    code: Some("123456"),
                    ..Confirm::default()
                };
                confirmed(&h, path, &session, &device, &body).await;
            }
            // This browser is held back, even with the right password and code.
            next_step(&h);
            let code = secret.code_at(now(&h));
            let right = Confirm {
                current: Some(GOOD),
                code: Some(&code),
                ..Confirm::default()
            };
            let reply = confirmed(&h, path, &session, &device, &right).await;
            assert_eq!(
                reply.status,
                StatusCode::TOO_MANY_REQUESTS,
                "{}",
                reply.body
            );
            assert!(reply.kind().ends_with(":password-held"));
            h.clock.0.fetch_add(HOLD.as_secs(), Ordering::SeqCst);
            let session = sign_in_to_account(&h, &mut passkey).await;
            let code = secret.code_at(now(&h));
            let right = Confirm {
                code: Some(&code),
                ..right
            };
            shown_codes(&confirmed(&h, path, &session, &device, &right).await);
        }
    }
}
