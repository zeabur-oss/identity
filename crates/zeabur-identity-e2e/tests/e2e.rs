//! End to end on a real cluster: Zeabur Identity runs as a pod from its image, `kube-config`
//! prepares kube-apiserver, an admin enrols a passkey from a setup link and signs in, and
//! kube-apiserver accepts the resulting access token (`kubectl auth whoami`). Then cert-manager
//! renews the internal certificate and Zeabur Identity gets a new signing key: kube-apiserver
//! accepts a new token with the configuration it already has.
//!
//! Needs a k3s cluster with cert-manager whose kube-apiserver reads its
//! `AuthenticationConfiguration` from a directory on this machine, and the image loaded into the
//! cluster. CI sets this up (see the
//! `kubernetes` job in `scripts/ci.sh`):
//!
//! - `KUBECONFIG`: the cluster admin;
//! - `ZEABUR_IDENTITY_E2E_IMAGE`: the image name inside the cluster;
//! - `ZEABUR_IDENTITY_E2E_AUTHN_DIR`: the host directory mounted at kube-apiserver's configuration
//!   path.
//!
//! Run: `cargo nextest run --run-ignored only -E 'binary(e2e)'`

#[cfg(test)]
mod tests {
    use std::io::BufRead as _;
    use std::net::IpAddr;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use axum::body::Bytes;
    use axum::http::{HeaderMap, Method, Request, StatusCode, header};
    use http_body_util::{BodyExt as _, Full};
    use hyper_util::rt::TokioIo;
    use k8s_openapi::api::apps::v1::Deployment;
    use k8s_openapi::api::core::v1::{Namespace, Node, Secret, Service, ServicePort, ServiceSpec};
    use kube::api::{
        Api, DeleteParams, DynamicObject, ListParams, ObjectMeta, Patch, PatchParams, PostParams,
    };
    use kube::config::Kubeconfig;
    use kube::core::GroupVersionKind;
    use kube::discovery::{Scope, pinned_kind};
    use kube::{Client, ResourceExt as _};
    use passkey::client::DefaultClientData;
    use passkey::types::webauthn::{CredentialCreationOptions, CredentialRequestOptions};
    use rustls::pki_types::pem::PemObject as _;
    use rustls::pki_types::{CertificateDer, ServerName};
    use serde_json::{Value, json};
    use tokio::net::TcpStream;
    use tokio_rustls::TlsConnector;
    use url::Url;
    use zeabur_identity_core::clock::{Clock as _, SystemClock};
    use zeabur_identity_core::config::BaseUrl;
    use zeabur_identity_k8s::crd::client::{ClientType, OAuthClient, OAuthClientSpec};
    use zeabur_identity_k8s::crd::credential::Credential;
    use zeabur_identity_k8s::crd::user::User;
    use zeabur_identity_k8s::crd::{USER_LABEL, definitions};
    use zeabur_identity_k8s::kube_config::{self, DiscoveryMode, Distro};
    use zeabur_identity_k8s::setup::issue_setup_link;
    use zeabur_identity_k8s::{deployment, internal_tls, rbac};
    use zeabur_identity_oauth::endpoints::FLOW_COOKIE;
    use zeabur_identity_signin::CEREMONY_COOKIE;
    use zeabur_identity_test_support::{Device, device};

    const ISSUER: &str = "https://identity.e2e.invalid";
    const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    const REDIRECT: &str = "http://127.0.0.1:8000/";
    /// kube-apiserver re-reads the file about once a minute and then waits for discovery.
    const APISERVER_PICKUP: Duration = Duration::from_secs(180);
    const EMPTY_AUTHN: &str = "apiVersion: apiserver.config.k8s.io/v1\nkind: AuthenticationConfiguration\nanonymous:\n  enabled: false\njwt: []\n";

    fn env(name: &str) -> String {
        std::env::var(name).unwrap_or_else(|_| panic!("{name} must be set (see tests/e2e.rs)"))
    }

    /// Server-side apply of any object.
    async fn apply(client: &Client, value: Value) {
        let object: DynamicObject = serde_json::from_value(value).unwrap();
        let gvk = GroupVersionKind::try_from(object.types.as_ref().unwrap()).unwrap();
        let (resource, capabilities) = pinned_kind(client, &gvk).await.unwrap();
        let api: Api<DynamicObject> = match capabilities.scope {
            Scope::Namespaced => Api::namespaced_with(
                client.clone(),
                object.namespace().as_deref().unwrap(),
                &resource,
            ),
            Scope::Cluster => Api::all_with(client.clone(), &resource),
        };
        api.patch(
            &object.name_any(),
            &PatchParams::apply("zeabur-identity-e2e").force(),
            &Patch::Apply(&object),
        )
        .await
        .unwrap();
    }

    async fn wait_for<F, Fut>(what: &str, timeout: Duration, mut check: F)
    where
        F: FnMut() -> Fut,
        Fut: Future<Output = bool>,
    {
        let deadline = Instant::now() + timeout;
        while !check().await {
            assert!(Instant::now() < deadline, "timed out waiting for {what}");
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    }

    /// Writes kube-apiserver's configuration atomically (it re-reads the file by path).
    fn write_authn(dir: &Path, contents: &str) {
        let staging = dir.join(".authn.yaml.tmp");
        std::fs::write(&staging, contents).unwrap();
        std::fs::rename(&staging, dir.join("authn.yaml")).unwrap();
    }

    struct Reply {
        status: StatusCode,
        headers: HeaderMap,
        body: Bytes,
    }

    impl Reply {
        fn json(&self) -> Value {
            serde_json::from_slice(&self.body).unwrap_or(Value::Null)
        }
        fn cookie(&self, name: &str) -> String {
            self.headers
                .get_all(header::SET_COOKIE)
                .iter()
                .find_map(|v| {
                    let value = v.to_str().ok()?.strip_prefix(&format!("{name}="))?;
                    Some(value.split(';').next()?.to_owned())
                })
                .unwrap_or_else(|| panic!("no {name} cookie"))
        }
    }

    /// One HTTP/1.1 request to Zeabur Identity's public listener (`address` is the node's IP and
    /// the `NodePort`).
    async fn http(
        address: &str,
        method: Method,
        path: &str,
        headers: &[(&str, &str)],
        body: Option<(&str, String)>,
    ) -> Reply {
        let stream = TcpStream::connect(address).await.unwrap();
        let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
            .await
            .unwrap();
        tokio::spawn(connection);
        let mut request = Request::builder()
            .method(method)
            .uri(path)
            .header(header::HOST, address);
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        let payload = match body {
            Some((content_type, payload)) => {
                request = request.header(header::CONTENT_TYPE, content_type);
                payload
            }
            None => String::new(),
        };
        let response = sender
            .send_request(request.body(Full::new(Bytes::from(payload))).unwrap())
            .await
            .unwrap();
        let (parts, body) = response.into_parts();
        Reply {
            status: parts.status,
            headers: parts.headers,
            body: body.collect().await.unwrap().to_bytes(),
        }
    }

    async fn post_json(address: &str, path: &str, body: &Value, cookies: &str) -> Reply {
        let mut headers = vec![("origin", ISSUER)];
        if !cookies.is_empty() {
            headers.push(("cookie", cookies));
        }
        http(
            address,
            Method::POST,
            path,
            &headers,
            Some(("application/json", body.to_string())),
        )
        .await
    }

    /// A kubeconfig with the cluster from `KUBECONFIG` and only a bearer token: no client
    /// certificate that kube-apiserver could authenticate first.
    fn token_kubeconfig(dir: &Path, label: &str, token: &str) -> PathBuf {
        let admin = Kubeconfig::read().unwrap();
        let context = admin.current_context.clone().unwrap();
        let cluster_name = admin
            .contexts
            .iter()
            .find(|c| c.name == context)
            .and_then(|c| c.context.as_ref())
            .map(|c| c.cluster.clone())
            .unwrap();
        let cluster = admin
            .clusters
            .iter()
            .find(|c| c.name == cluster_name)
            .and_then(|c| c.cluster.clone())
            .unwrap();
        let config = json!({
            "apiVersion": "v1",
            "kind": "Config",
            "clusters": [{ "name": "e2e", "cluster": {
                "server": cluster.server,
                "certificate-authority-data": cluster.certificate_authority_data,
            }}],
            "users": [{ "name": "e2e", "user": { "token": token } }],
            "contexts": [{ "name": "e2e", "context": { "cluster": "e2e", "user": "e2e" } }],
            "current-context": "e2e",
        });
        let path = dir.join(format!(
            "zeabur-identity-e2e-{label}-{}.json",
            std::process::id()
        ));
        std::fs::write(&path, config.to_string()).unwrap();
        path
    }

    fn kubectl(kubeconfig: &Path, args: &[&str]) -> Result<String, String> {
        let output = Command::new("kubectl")
            .arg("--kubeconfig")
            .arg(kubeconfig)
            .args(args)
            .output()
            .map_err(|error| format!("running kubectl: {error}"))?;
        if output.status.success() {
            Ok(String::from_utf8_lossy(&output.stdout).into_owned())
        } else {
            Err(String::from_utf8_lossy(&output.stderr).into_owned())
        }
    }

    /// `kubectl auth can-i`: "yes" or "no" (it exits non-zero for "no").
    fn can_i(kubeconfig: &Path, args: &[&str]) -> String {
        let output = Command::new("kubectl")
            .arg("--kubeconfig")
            .arg(kubeconfig)
            .args(["auth", "can-i"])
            .args(args)
            .output()
            .unwrap();
        String::from_utf8_lossy(&output.stdout).trim().to_owned()
    }

    /// `secret`'s `tls.crt`, as PEM.
    fn leaf_pem(secret: &Secret) -> Vec<u8> {
        secret.data.as_ref().unwrap()["tls.crt"].0.clone()
    }

    /// The first certificate of the PEM chain in `secret`'s `tls.crt`, as DER.
    fn leaf(secret: &Secret) -> Vec<u8> {
        CertificateDer::pem_slice_iter(&leaf_pem(secret))
            .next()
            .unwrap()
            .unwrap()
            .to_vec()
    }

    /// The certificate the internal listener presents, reached with `kubectl port-forward` and
    /// verified against `ca_pem` for the name `ip`, as kube-apiserver does.
    async fn served_certificate(
        namespace: &str,
        ip: IpAddr,
        ca_pem: &str,
    ) -> Result<Vec<u8>, String> {
        let mut forward = Command::new("kubectl")
            .args([
                "-n",
                namespace,
                "port-forward",
                &format!("deployment/{}", rbac::NAME),
                &format!(":{}", deployment::INTERNAL_PORT),
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        // kubectl prints `Forwarding from 127.0.0.1:<port> -> 8443` when it listens. Keep the
        // pipe open: kubectl writes a line for each connection and fails if the pipe is closed.
        let mut output = std::io::BufReader::new(forward.stdout.take().unwrap());
        let mut line = String::new();
        output.read_line(&mut line).unwrap();
        let served = async {
            let port = line
                .split_once("127.0.0.1:")
                .and_then(|(_, rest)| rest.split_whitespace().next())
                .ok_or_else(|| format!("port-forward printed {line:?}"))?;
            let tcp = TcpStream::connect(format!("127.0.0.1:{port}"))
                .await
                .map_err(|error| format!("connect: {error}"))?;
            let mut roots = rustls::RootCertStore::empty();
            for cert in CertificateDer::pem_slice_iter(ca_pem.as_bytes()) {
                let cert = cert.map_err(|error| format!("CA PEM: {error}"))?;
                roots.add(cert).map_err(|error| format!("CA: {error}"))?;
            }
            let config = rustls::ClientConfig::builder_with_provider(Arc::new(
                rustls::crypto::aws_lc_rs::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .map_err(|error| format!("TLS config: {error}"))?
            .with_root_certificates(roots)
            .with_no_client_auth();
            let tls = TlsConnector::from(Arc::new(config))
                .connect(ServerName::IpAddress(ip.into()), tcp)
                .await
                .map_err(|error| format!("handshake: {error}"))?;
            tls.get_ref()
                .1
                .peer_certificates()
                .and_then(|chain| chain.first())
                .map(|cert| cert.to_vec())
                .ok_or_else(|| "no peer certificate".to_owned())
        }
        .await;
        drop(forward.kill());
        drop(forward.wait());
        drop(output);
        served
    }

    /// Asks cert-manager to issue the Certificate again now, as `cmctl renew` does.
    async fn renew(client: &Client, namespace: &str, name: &str) {
        let gvk = GroupVersionKind::gvk("cert-manager.io", "v1", "Certificate");
        let (resource, _) = pinned_kind(client, &gvk).await.unwrap();
        let certificates: Api<DynamicObject> =
            Api::namespaced_with(client.clone(), namespace, &resource);
        let current = certificates.get(name).await.unwrap();
        let mut conditions = current
            .data
            .pointer("/status/conditions")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        conditions.push(json!({
            "type": "Issuing",
            "status": "True",
            "reason": "ManuallyTriggered",
            "message": "Certificate re-issuance manually triggered",
        }));
        certificates
            .patch_status(
                name,
                &PatchParams::default(),
                &Patch::Merge(json!({"status": {"conditions": conditions}})),
            )
            .await
            .unwrap();
    }

    /// Signs in with `device` through Zeabur Identity's public listener, as kubectl's OIDC plugin
    /// would (authorization request, passkey, code, token), and returns the token response.
    async fn sign_in(address: &str, device: &mut Device, scope: &str) -> Value {
        let origin = Url::parse(ISSUER).unwrap();
        let authorize = format!(
            "/authorize?client_id=kubectl&redirect_uri=http%3A%2F%2F127.0.0.1%3A8000%2F&response_type=code&scope={scope}&code_challenge={CHALLENGE}&code_challenge_method=S256&state=e2e"
        );
        let reply = http(address, Method::GET, &authorize, &[], None).await;
        assert_eq!(reply.status, StatusCode::SEE_OTHER);
        let flow = reply.cookie(FLOW_COOKIE);
        let reply = post_json(address, "/login/options", &json!({}), "").await;
        let ceremony = reply.cookie(CEREMONY_COOKIE);
        let options: CredentialRequestOptions = serde_json::from_value(reply.json()).unwrap();
        let assertion = device
            .authenticate(&origin, options, DefaultClientData)
            .await
            .unwrap();
        let reply = post_json(
            address,
            "/login",
            &json!({ "credential": assertion }),
            &format!("{FLOW_COOKIE}={flow}; {CEREMONY_COOKIE}={ceremony}"),
        )
        .await;
        assert_eq!(reply.status, StatusCode::OK, "{:?}", reply.body);
        let location = reply.json()["redirect_to"].as_str().unwrap().to_owned();
        let code = form_urlencoded::parse(location.split_once('?').unwrap().1.as_bytes())
            .find(|(k, _)| k == "code")
            .unwrap()
            .1
            .into_owned();
        let form = form_urlencoded::Serializer::new(String::new())
            .extend_pairs([
                ("grant_type", "authorization_code"),
                ("code", code.as_str()),
                ("code_verifier", VERIFIER),
                ("client_id", "kubectl"),
                ("redirect_uri", REDIRECT),
            ])
            .finish();
        let reply = http(
            address,
            Method::POST,
            "/token",
            &[],
            Some(("application/x-www-form-urlencoded", form)),
        )
        .await;
        assert_eq!(reply.status, StatusCode::OK, "{:?}", reply.body);
        reply.json()
    }

    async fn post_form(address: &str, path: &str, pairs: &[(&str, &str)]) -> Reply {
        let form = form_urlencoded::Serializer::new(String::new())
            .extend_pairs(pairs.iter().copied())
            .finish();
        http(
            address,
            Method::POST,
            path,
            &[],
            Some(("application/x-www-form-urlencoded", form)),
        )
        .await
    }

    async fn refresh(address: &str, token: &str) -> Reply {
        post_form(
            address,
            "/token",
            &[
                ("grant_type", "refresh_token"),
                ("client_id", "kubectl"),
                ("refresh_token", token),
            ],
        )
        .await
    }

    /// Exercises proof-gated deletion through the deployed server and Kubernetes grant store.
    /// Returns the latest rotated token so later reset checks exercise a live family.
    async fn guessed_refresh_secrets_preserve_session(address: &str, issued: &str) -> String {
        let (grant, _) = issued.split_once('.').unwrap();
        let guessed = format!("{grant}.{}", "A".repeat(43));
        assert_ne!(guessed, issued);
        let revoked = post_form(
            address,
            "/revoke",
            &[("token", &guessed), ("client_id", "kubectl")],
        )
        .await;
        assert_eq!(revoked.status, StatusCode::OK);
        let refreshed = post_form(
            address,
            "/token",
            &[
                ("grant_type", "refresh_token"),
                ("refresh_token", issued),
                ("client_id", "kubectl"),
            ],
        )
        .await;
        assert_eq!(refreshed.status, StatusCode::OK);
        let current = refreshed.json()["refresh_token"]
            .as_str()
            .unwrap()
            .to_owned();
        let (grant, _) = current.split_once('.').unwrap();
        let guessed = format!("{grant}.{}", "A".repeat(43));
        assert_ne!(guessed, current);
        let wrong_client = post_form(
            address,
            "/token",
            &[
                ("grant_type", "refresh_token"),
                ("refresh_token", &guessed),
                ("client_id", "other-client"),
            ],
        )
        .await;
        assert_eq!(wrong_client.status, StatusCode::BAD_REQUEST);
        assert_eq!(wrong_client.json()["error"], "invalid_grant");
        let refreshed = post_form(
            address,
            "/token",
            &[
                ("grant_type", "refresh_token"),
                ("refresh_token", &current),
                ("client_id", "kubectl"),
            ],
        )
        .await;
        assert_eq!(refreshed.status, StatusCode::OK);
        refreshed.json()["refresh_token"]
            .as_str()
            .unwrap()
            .to_owned()
    }

    #[tokio::test]
    #[ignore = "needs a prepared k3s cluster and the image (see the file comment)"]
    #[expect(clippy::too_many_lines, reason = "one scenario, read top to bottom")]
    async fn passkey_sign_in_then_kubectl_auth_whoami() {
        let image = env("ZEABUR_IDENTITY_E2E_IMAGE");
        let authn_dir = PathBuf::from(env("ZEABUR_IDENTITY_E2E_AUTHN_DIR"));
        let admin = Client::try_default().await.unwrap();
        let issuer = BaseUrl::parse("issuer", ISSUER).unwrap();
        let namespace = format!("zeabur-identity-e2e-{}", std::process::id());

        // Install: CRDs, then everything `zeabur-identityctl manifests` prints.
        for crd in definitions() {
            apply(&admin, serde_json::to_value(crd).unwrap()).await;
        }
        for object in deployment::manifests(
            &namespace,
            &issuer,
            &deployment::Options {
                image: image.clone(),
                ..deployment::Options::default()
            },
        )
        .unwrap()
        {
            apply(&admin, object).await;
        }
        let deployments: Api<Deployment> = Api::namespaced(admin.clone(), &namespace);
        wait_for(
            "Zeabur Identity to become ready",
            Duration::from_secs(180),
            || async {
                deployments
                    .get(rbac::NAME)
                    .await
                    .ok()
                    .and_then(|d| d.status)
                    .and_then(|s| s.ready_replicas)
                    == Some(1)
            },
        )
        .await;

        // kube-apiserver side, exactly as `zeabur-identityctl kube-config --distro k3s` does it.
        let request = kube_config::Request {
            namespace: namespace.clone(),
            distro: Distro::K3s,
            issuer: issuer.clone(),
            discovery: DiscoveryMode::Internal,
            audiences: vec!["kubernetes".into()],
            max_token_lifetime: Duration::from_hours(1),
        };
        let configuration = kube_config::prepare(admin.clone(), &request).await.unwrap();
        write_authn(&authn_dir, &configuration);

        // The kubectl client, and a setup link for the first admin.
        let clients: Api<OAuthClient> = Api::namespaced(admin.clone(), &namespace);
        for client_id in ["kubectl", "other-client"] {
            clients
                .create(
                    &PostParams::default(),
                    &OAuthClient::new(
                        client_id,
                        OAuthClientSpec {
                            display_name: None,
                            kind: ClientType::Public,
                            redirect_uris: vec![REDIRECT.into()],
                            audiences: vec!["kubernetes".into()],
                            secret_hash: None,
                            id_token_signing_alg: None,
                            home_url: None,
                        },
                    ),
                )
                .await
                .unwrap();
        }
        let link = issue_setup_link(
            admin.clone(),
            &namespace,
            &issuer,
            "admin",
            Duration::from_mins(10),
            false,
            SystemClock.now(),
        )
        .await
        .unwrap();
        let token = link.url.split_once("#token=").unwrap().1.to_owned();

        // Reach the public listener through a NodePort on the node's address.
        let services: Api<Service> = Api::namespaced(admin.clone(), &namespace);
        let node_port = services
            .create(
                &PostParams::default(),
                &Service {
                    metadata: ObjectMeta {
                        name: Some("zeabur-identity-e2e-nodeport".into()),
                        ..ObjectMeta::default()
                    },
                    spec: Some(ServiceSpec {
                        type_: Some("NodePort".into()),
                        selector: Some(
                            [("app.kubernetes.io/name".into(), rbac::NAME.into())].into(),
                        ),
                        ports: Some(vec![ServicePort {
                            port: 80,
                            target_port: Some(
                                k8s_openapi::apimachinery::pkg::util::intstr::IntOrString::Int(
                                    deployment::HTTP_PORT,
                                ),
                            ),
                            ..ServicePort::default()
                        }]),
                        ..ServiceSpec::default()
                    }),
                    ..Service::default()
                },
            )
            .await
            .unwrap()
            .spec
            .unwrap()
            .ports
            .unwrap()[0]
            .node_port
            .unwrap();
        let node = Api::<Node>::all(admin.clone())
            .list(&ListParams::default())
            .await
            .unwrap()
            .items
            .remove(0);
        let node_name = node.name_any();
        let node_ip = node
            .status
            .and_then(|s| s.addresses)
            .unwrap()
            .into_iter()
            .find(|a| a.type_ == "InternalIP")
            .unwrap()
            .address;
        let address = format!("{node_ip}:{node_port}");
        wait_for(
            "the NodePort to accept connections",
            Duration::from_secs(60),
            || {
                let address = address.clone();
                async move { TcpStream::connect(&address).await.is_ok() }
            },
        )
        .await;
        let origin = Url::parse(ISSUER).unwrap();

        // Enrol a passkey from the link.
        let mut device = device();
        let reply = post_json(&address, "/setup/options", &json!({ "token": token }), "").await;
        assert_eq!(reply.status, StatusCode::OK, "{:?}", reply.body);
        let options: CredentialCreationOptions = serde_json::from_value(reply.json()).unwrap();
        let credential = device
            .register(&origin, options, DefaultClientData)
            .await
            .unwrap();
        let ceremony = reply.cookie(CEREMONY_COOKIE);
        let reply = post_json(
            &address,
            "/setup",
            &json!({ "token": token, "credential": credential, "label": "e2e" }),
            &format!("{CEREMONY_COOKIE}={ceremony}"),
        )
        .await;
        assert_eq!(reply.status, StatusCode::CREATED, "{:?}", reply.body);

        // Sign in as kubectl would: authorization request, passkey, code, token.
        let tokens = sign_in(&address, &mut device, "openid").await;
        assert!(tokens["refresh_token"].is_string());
        let latest_refresh = guessed_refresh_secrets_preserve_session(
            &address,
            tokens["refresh_token"].as_str().unwrap(),
        )
        .await;
        let access_token = tokens["access_token"].as_str().unwrap();
        let id_token = tokens["id_token"].as_str().unwrap();

        // UserInfo resolves metadata by UID without changing the token contract, then checks
        // the latest user spec. A disable must take effect without waiting for a watch update.
        let users: Api<User> = Api::namespaced(admin.clone(), &namespace);
        let subject = users.get("admin").await.unwrap().uid().unwrap();
        let authorization = format!("Bearer {access_token}");
        let headers = [("authorization", authorization.as_str())];
        let info = http(&address, Method::GET, "/userinfo", &headers, None).await;
        assert_eq!(info.status, StatusCode::OK);
        assert_eq!(info.json(), json!({"sub": subject}));
        users
            .patch(
                "admin",
                &PatchParams::default(),
                &Patch::Merge(json!({"spec": {"disabled": true}})),
            )
            .await
            .unwrap();
        let disabled = http(&address, Method::GET, "/userinfo", &headers, None).await;
        assert_eq!(disabled.status, StatusCode::UNAUTHORIZED);
        users
            .patch(
                "admin",
                &PatchParams::default(),
                &Patch::Merge(json!({"spec": {"disabled": false}})),
            )
            .await
            .unwrap();

        // kube-apiserver accepts the access token once it has loaded the configuration.
        let scratch = std::env::temp_dir();
        let as_user = token_kubeconfig(&scratch, "access", access_token);
        let mut whoami = String::new();
        wait_for(
            "kube-apiserver to accept the token",
            APISERVER_PICKUP,
            || {
                let result = kubectl(&as_user, &["auth", "whoami", "-o", "json"]);
                if let Ok(output) = &result {
                    whoami.clone_from(output);
                }
                async move { result.is_ok() }
            },
        )
        .await;
        let user = &serde_json::from_str::<Value>(&whoami).unwrap()["status"]["userInfo"];
        assert_eq!(user["username"], "zeabur:admin", "{user}");
        let groups = user["groups"].as_array().unwrap();
        assert!(groups.contains(&json!("zeabur:admins")), "{user}");
        assert!(groups.contains(&json!("system:authenticated")), "{user}");
        assert!(
            !groups
                .iter()
                .any(|g| g.as_str().unwrap().starts_with("system:masters"))
        );
        assert_eq!(
            user["extra"]["identity.zeabur.com/client-id"],
            json!(["kubectl"])
        );
        assert_eq!(
            user["extra"]["identity.zeabur.com/amr"],
            json!(["swk", "mfa"])
        );
        assert!(user["uid"].as_str().is_some_and(|uid| !uid.is_empty()));

        // An admin account acts with full rights, with no second sign-in.
        assert_eq!(can_i(&as_user, &["*", "*", "--all-namespaces"]), "yes");

        // A refresh needs no passkey, as kubelogin uses it. The token follows the account type
        // at each refresh: as a regular account, the admin group and its rights are gone.
        let set_type = |account_type: &'static str| {
            let users = users.clone();
            async move {
                users
                    .patch(
                        "admin",
                        &PatchParams::default(),
                        &Patch::Merge(json!({"spec": {"accountType": account_type}})),
                    )
                    .await
                    .unwrap();
            }
        };
        set_type("Regular").await;
        let regular = refresh(&address, &latest_refresh).await;
        assert_eq!(regular.status, StatusCode::OK, "{:?}", regular.body);
        let regular = regular.json();
        let as_regular = token_kubeconfig(
            &scratch,
            "regular",
            regular["access_token"].as_str().unwrap(),
        );
        assert_eq!(
            can_i(&as_regular, &["list", "pods", "--all-namespaces"]),
            "no"
        );
        set_type("Admin").await;
        let refreshed = refresh(&address, regular["refresh_token"].as_str().unwrap()).await;
        assert_eq!(refreshed.status, StatusCode::OK, "{:?}", refreshed.body);
        let refreshed = refreshed.json();
        let as_admin = token_kubeconfig(
            &scratch,
            "admin",
            refreshed["access_token"].as_str().unwrap(),
        );
        assert_eq!(can_i(&as_admin, &["*", "*", "--all-namespaces"]), "yes");
        let latest_refresh = refreshed["refresh_token"].as_str().unwrap().to_owned();

        // ID tokens are for the client, not for the cluster.
        let as_id_token = token_kubeconfig(&scratch, "id", id_token);
        assert!(kubectl(&as_id_token, &["auth", "whoami"]).is_err());

        // Memory as the kubelet sees it (working set), after a full sign-in. The budget is
        // 30 MiB; the value is also written for CI's job summary.
        let summary: Value = serde_json::from_str(
            &admin
                .request_text(
                    Request::get(format!("/api/v1/nodes/{node_name}/proxy/stats/summary"))
                        .body(Vec::new())
                        .unwrap(),
                )
                .await
                .unwrap(),
        )
        .unwrap();
        let working_set = summary["pods"]
            .as_array()
            .unwrap()
            .iter()
            .find(|pod| pod["podRef"]["namespace"] == namespace.as_str())
            .and_then(|pod| pod["memory"]["workingSetBytes"].as_u64())
            .unwrap();
        if let Ok(path) = std::env::var("ZEABUR_IDENTITY_E2E_MEASUREMENTS") {
            std::fs::write(
                path,
                json!({ "pod_working_set_bytes": working_set }).to_string(),
            )
            .unwrap();
        }
        assert!(
            working_set <= 30 * 1024 * 1024,
            "working set {working_set} bytes exceeds 30 MiB"
        );

        // cert-manager renews the serving certificate. Zeabur Identity serves it without a
        // restart, and kube-apiserver's configuration stays the same.
        let secrets: Api<Secret> = Api::namespaced(admin.clone(), &namespace);
        let cluster_ip: IpAddr = services
            .get(rbac::NAME)
            .await
            .unwrap()
            .spec
            .unwrap()
            .cluster_ip
            .unwrap()
            .parse()
            .unwrap();
        let ca_secret = secrets.get(internal_tls::CA_SECRET).await.unwrap();
        let ca_pem = String::from_utf8(leaf_pem(&ca_secret)).unwrap();
        let first_leaf = leaf(&secrets.get(internal_tls::SECRET).await.unwrap());
        assert_eq!(
            served_certificate(&namespace, cluster_ip, &ca_pem).await,
            Ok(first_leaf.clone())
        );
        renew(&admin, &namespace, internal_tls::SECRET).await;
        wait_for(
            "cert-manager to renew the serving certificate",
            Duration::from_secs(120),
            || {
                let (secrets, first_leaf) = (secrets.clone(), first_leaf.clone());
                async move { leaf(&secrets.get(internal_tls::SECRET).await.unwrap()) != first_leaf }
            },
        )
        .await;
        let renewed_leaf = leaf(&secrets.get(internal_tls::SECRET).await.unwrap());
        wait_for(
            "Zeabur Identity to serve the renewed certificate",
            Duration::from_secs(120),
            || {
                let (namespace, ca_pem, renewed_leaf) =
                    (namespace.clone(), ca_pem.clone(), renewed_leaf.clone());
                async move {
                    served_certificate(&namespace, cluster_ip, &ca_pem).await == Ok(renewed_leaf)
                }
            },
        )
        .await;
        assert_eq!(
            kube_config::prepare(admin.clone(), &request).await.unwrap(),
            configuration
        );

        // Replace the CA by hand, as docs/operations/backup-restore.mdx says: delete the CA
        // Secret, then the leaf Secret, then install the new configuration. kube-apiserver then
        // trusts only the new CA and accepts tokens again.
        for name in [internal_tls::CA_SECRET, internal_tls::SECRET] {
            let old = leaf(&secrets.get(name).await.unwrap());
            secrets
                .delete(name, &DeleteParams::default())
                .await
                .unwrap();
            wait_for(
                &format!("cert-manager to issue {name} again"),
                Duration::from_secs(120),
                || {
                    let (secrets, old) = (secrets.clone(), old.clone());
                    async move {
                        secrets.get_opt(name).await.unwrap().is_some_and(|secret| {
                            !leaf_pem(&secret).is_empty() && leaf(&secret) != old
                        })
                    }
                },
            )
            .await;
        }
        let rotated_configuration = kube_config::prepare(admin.clone(), &request).await.unwrap();
        assert_ne!(rotated_configuration, configuration);
        write_authn(&authn_dir, &rotated_configuration);
        let rotated_ca = String::from_utf8(leaf_pem(
            &secrets.get(internal_tls::CA_SECRET).await.unwrap(),
        ))
        .unwrap();
        let rotated_leaf = leaf(&secrets.get(internal_tls::SECRET).await.unwrap());
        wait_for(
            "Zeabur Identity to serve the leaf from the new CA",
            Duration::from_secs(120),
            || {
                let (namespace, ca, rotated_leaf) =
                    (namespace.clone(), rotated_ca.clone(), rotated_leaf.clone());
                async move {
                    served_certificate(&namespace, cluster_ip, &ca).await == Ok(rotated_leaf)
                }
            },
        )
        .await;
        let rotated = sign_in(&address, &mut device, "openid").await;
        let as_rotated = token_kubeconfig(
            &scratch,
            "rotated",
            rotated["access_token"].as_str().unwrap(),
        );
        wait_for(
            "kube-apiserver to trust the new CA",
            APISERVER_PICKUP,
            || {
                let result = kubectl(&as_rotated, &["auth", "whoami"]);
                async move { result.is_ok() }
            },
        )
        .await;

        // A partial reset can remove credentials while leaving a usable refresh-token family.
        // Prove the family's current token works, then retry reset with no credentials left.
        let refreshed = refresh(&address, &latest_refresh).await;
        assert_eq!(refreshed.status, StatusCode::OK, "{:?}", refreshed.body);
        let refreshed = refreshed.json();
        let current_refresh = refreshed["refresh_token"].as_str().unwrap();
        let credentials: Api<Credential> = Api::namespaced(admin.clone(), &namespace);
        let selector = ListParams::default().labels(&format!("{USER_LABEL}=admin"));
        credentials
            .delete_collection(&DeleteParams::default(), &selector)
            .await
            .unwrap();
        assert!(credentials.list(&selector).await.unwrap().items.is_empty());
        issue_setup_link(
            admin.clone(),
            &namespace,
            &issuer,
            "admin",
            Duration::from_mins(10),
            true,
            SystemClock.now(),
        )
        .await
        .unwrap();
        let denied = refresh(&address, current_refresh).await;
        assert_eq!(denied.status, StatusCode::BAD_REQUEST, "{:?}", denied.body);
        assert_eq!(denied.json()["error"], "invalid_grant");

        // Clean up: forget the issuer, remove the namespace.
        write_authn(&authn_dir, EMPTY_AUTHN);
        for file in [as_user, as_regular, as_admin, as_id_token, as_rotated] {
            drop(std::fs::remove_file(file));
        }
        Api::<Namespace>::all(admin)
            .delete(&namespace, &DeleteParams::background())
            .await
            .unwrap();
    }
}
