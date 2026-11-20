//! End to end on a real cluster: Zeabur Identity runs as a pod from its image, `kube-config`
//! prepares kube-apiserver, an admin enrols a passkey from a setup link and signs in, and
//! kube-apiserver accepts the resulting access token (`kubectl auth whoami`). Then cert-manager
//! renews the internal certificate and Zeabur Identity gets a new signing key: kube-apiserver
//! accepts a new token with the configuration it already has.
//!
//! Needs a k3s cluster with cert-manager whose kube-apiserver reads its
//! `AuthenticationConfiguration` from a directory on this machine, and the image loaded into the
//! cluster. CI sets this up (see the
//! `kubernetes` job, `scripts/ci/kubernetes.sh`):
//!
//! - `KUBECONFIG`: the cluster admin;
//! - `ZEABUR_IDENTITY_E2E_IMAGE`: the image name inside the cluster;
//! - `ZEABUR_IDENTITY_E2E_AUTHN_DIR`: the host directory mounted at kube-apiserver's configuration
//!   path.
//!
//! Run: `cargo nextest run --run-ignored only -E 'binary(e2e) and not test(keycloak)'`. The
//! Keycloak scenario needs Keycloak too: `scripts/keycloak-e2e.sh` runs it.

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
    use k8s_openapi::api::authentication::v1::SelfSubjectReview;
    use k8s_openapi::api::core::v1::{
        ConfigMap, ConfigMapVolumeSource, Container, EnvVar, Namespace, Node, Secret, Service,
        ServicePort, ServiceSpec, Volume, VolumeMount,
    };
    use k8s_openapi::apiextensions_apiserver::pkg::apis::apiextensions::v1::CustomResourceDefinition;
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::Time;
    use k8s_openapi::{ClusterResourceScope, NamespaceResourceScope};
    use kube::api::{Api, DeleteParams, ListParams, ObjectMeta, Patch, PatchParams, PostParams};
    use kube::config::Kubeconfig;
    use kube::core::object::NotUsed;
    use kube::core::{GroupVersionKind, Object};
    use kube::discovery::pinned_kind;
    use kube::runtime::wait::await_condition;
    use kube::{Client, Resource, ResourceExt as _};
    use passkey::client::DefaultClientData;
    use passkey::types::webauthn::{CredentialCreationOptions, CredentialRequestOptions};
    use rustls::pki_types::pem::PemObject as _;
    use rustls::pki_types::{CertificateDer, ServerName};
    use serde::de::DeserializeOwned;
    use serde::{Deserialize, Serialize};
    use tokio::net::TcpStream;
    use tokio_rustls::TlsConnector;
    use url::Url;
    use zeabur_identity_api::client::{ClientType, OAuthClient, OAuthClientSpec};
    use zeabur_identity_api::credential::{Credential, CredentialKind};
    use zeabur_identity_api::upstream_provider::{
        OpenID, UpstreamKind, UpstreamProvider, UpstreamProviderSpec,
    };
    use zeabur_identity_api::user::{AccountType, User};
    use zeabur_identity_api::{USER_LABEL, definitions};
    use zeabur_identity_core::clock::{Clock as _, SystemClock};
    use zeabur_identity_core::config::BaseUrl;
    use zeabur_identity_k8s::kube_config::{self, DiscoveryMode, Distro};
    use zeabur_identity_k8s::manifest::Manifest;
    use zeabur_identity_k8s::setup::issue_setup_link;
    use zeabur_identity_k8s::{deployment, internal_tls, rbac};
    use zeabur_identity_oauth::endpoints::FLOW_COOKIE;
    use zeabur_identity_signin::CEREMONY_COOKIE;
    use zeabur_identity_signin::account::SESSION_COOKIE;
    use zeabur_identity_signin::upstream::UPSTREAM_COOKIE;
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

    /// Server-side apply of `object` through `api`.
    async fn apply_to<K>(api: &Api<K>, object: &K)
    where
        K: Resource + Serialize + DeserializeOwned + Clone + std::fmt::Debug + Sync,
    {
        api.patch(
            &object.name_any(),
            &PatchParams::apply("zeabur-identity-e2e").force(),
            &Patch::Apply(object),
        )
        .await
        .unwrap();
    }

    async fn apply_namespaced<K>(client: &Client, object: &K)
    where
        K: Resource<Scope = NamespaceResourceScope, DynamicType = ()>
            + Serialize
            + DeserializeOwned
            + Clone
            + std::fmt::Debug
            + Sync,
    {
        let api = Api::namespaced(client.clone(), object.namespace().as_deref().unwrap());
        apply_to(&api, object).await;
    }

    async fn apply_cluster<K>(client: &Client, object: &K)
    where
        K: Resource<Scope = ClusterResourceScope, DynamicType = ()>
            + Serialize
            + DeserializeOwned
            + Clone
            + std::fmt::Debug
            + Sync,
    {
        apply_to(&Api::all(client.clone()), object).await;
    }

    /// Server-side apply of one object of an installation.
    async fn apply(client: &Client, manifest: &Manifest) {
        match manifest {
            Manifest::Namespace(object) => apply_cluster(client, &**object).await,
            Manifest::ClusterRoleBinding(object) => apply_cluster(client, &**object).await,
            Manifest::ServiceAccount(object) => apply_namespaced(client, &**object).await,
            Manifest::Role(object) => apply_namespaced(client, &**object).await,
            Manifest::RoleBinding(object) => apply_namespaced(client, &**object).await,
            Manifest::Secret(object) => apply_namespaced(client, &**object).await,
            Manifest::Service(object) => apply_namespaced(client, &**object).await,
            Manifest::Deployment(object) => apply_namespaced(client, &**object).await,
        }
    }

    /// A JSON body with no members.
    type Empty = std::collections::BTreeMap<String, String>;

    #[derive(Serialize)]
    struct TokenBody<'a> {
        token: &'a str,
    }

    #[derive(Serialize)]
    struct SetupBody<'a, C> {
        token: &'a str,
        credential: &'a C,
        label: &'a str,
    }

    #[derive(Serialize)]
    struct CredentialBody<'a, C> {
        credential: &'a C,
    }

    #[derive(Serialize)]
    struct ProviderBody<'a> {
        provider: &'a str,
    }

    #[derive(Serialize)]
    struct NameBody<'a> {
        name: &'a str,
    }

    #[derive(Debug, Deserialize)]
    struct Tokens {
        #[serde(rename = "access_token")]
        access: String,
        #[serde(rename = "refresh_token")]
        refresh: String,
        #[serde(rename = "id_token")]
        id: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    struct OAuthError {
        error: String,
    }

    #[derive(Debug, Deserialize)]
    struct Redirect {
        redirect_to: String,
    }

    #[derive(Debug, Deserialize, PartialEq, Eq)]
    struct UserInfo {
        sub: String,
    }

    /// A merge patch of `spec`.
    #[derive(Debug, Serialize)]
    struct SpecPatch<S> {
        spec: S,
    }

    #[derive(Debug, Serialize)]
    struct DisabledPatch {
        disabled: bool,
    }

    #[derive(Debug, Serialize)]
    #[serde(rename_all = "camelCase")]
    struct AccountTypePatch {
        account_type: AccountType,
    }

    /// The members of kubelet's stats summary that the memory check reads.
    #[derive(Deserialize)]
    struct StatsSummary {
        pods: Vec<PodStats>,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct PodStats {
        pod_ref: PodRef,
        memory: Option<PodMemory>,
    }

    #[derive(Deserialize)]
    struct PodRef {
        namespace: String,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct PodMemory {
        working_set_bytes: Option<u64>,
    }

    #[derive(Serialize)]
    struct Measurement {
        pod_working_set_bytes: u64,
    }

    /// A kubeconfig with one cluster and one bearer token.
    #[derive(Serialize)]
    #[serde(rename_all = "kebab-case")]
    struct TokenConfig {
        api_version: &'static str,
        kind: &'static str,
        clusters: Vec<Named<ClusterEntry>>,
        users: Vec<Named<UserEntry>>,
        contexts: Vec<Named<ContextEntry>>,
        current_context: &'static str,
    }

    #[derive(Serialize)]
    struct Named<T> {
        name: &'static str,
        #[serde(flatten)]
        entry: T,
    }

    #[derive(Serialize)]
    struct ClusterEntry {
        cluster: Cluster,
    }

    #[derive(Serialize)]
    #[serde(rename_all = "kebab-case")]
    struct Cluster {
        server: Option<String>,
        certificate_authority_data: Option<String>,
    }

    #[derive(Serialize)]
    struct UserEntry {
        user: TokenUser,
    }

    #[derive(Serialize)]
    struct TokenUser {
        token: String,
    }

    #[derive(Serialize)]
    struct ContextEntry {
        context: Context,
    }

    #[derive(Serialize)]
    struct Context {
        cluster: &'static str,
        user: &'static str,
    }

    /// A merge patch of a Deployment's pod template.
    #[derive(Debug, Serialize)]
    struct TemplatePatch {
        spec: TemplateSpecPatch,
    }

    #[derive(Debug, Serialize)]
    struct TemplateSpecPatch {
        template: PodPatch,
    }

    #[derive(Debug, Serialize)]
    struct PodPatch {
        spec: PodSpecPatch,
    }

    #[derive(Debug, Serialize)]
    struct PodSpecPatch {
        volumes: Vec<Volume>,
        containers: Vec<Container>,
    }

    /// cert-manager's Certificate, of which the tests read and write only the conditions.
    type Certificate = Object<CertificateSpec, CertificateStatus>;

    #[derive(Clone, Debug, Default, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct CertificateSpec {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        secret_name: Option<String>,
    }

    #[derive(Clone, Debug, Default, Serialize, Deserialize)]
    struct CertificateStatus {
        #[serde(default)]
        conditions: Vec<CertificateCondition>,
    }

    #[derive(Clone, Debug, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct CertificateCondition {
        #[serde(rename = "type")]
        kind: String,
        status: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        message: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        last_transition_time: Option<Time>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        observed_generation: Option<i64>,
    }

    #[derive(Debug, Serialize)]
    struct StatusPatch<S> {
        status: S,
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

    /// Waits until the Deployment's rollout is complete, as `kubectl rollout status` decides: the
    /// controller saw the current generation, and every replica is updated and available.
    async fn rolled_out(deployments: &Api<Deployment>, what: &str) {
        let completed =
            await_condition(deployments.clone(), rbac::NAME, |d: Option<&Deployment>| {
                d.is_some_and(|d| {
                    let want = d.spec.as_ref().and_then(|s| s.replicas).unwrap_or(1);
                    d.status.as_ref().is_some_and(|s| {
                        s.observed_generation >= d.metadata.generation
                            && s.updated_replicas.unwrap_or(0) == want
                            && s.replicas.unwrap_or(0) == want
                            && s.available_replicas.unwrap_or(0) == want
                    })
                })
            });
        tokio::time::timeout(Duration::from_secs(180), completed)
            .await
            .unwrap_or_else(|_| panic!("timed out waiting for {what}"))
            .unwrap();
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
        fn json<T: DeserializeOwned>(&self) -> T {
            serde_json::from_slice(&self.body)
                .unwrap_or_else(|error| panic!("{error}: {:?}", self.body))
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

    async fn post_json(
        address: &str,
        path: &str,
        body: &(impl Serialize + Sync),
        cookies: &str,
    ) -> Reply {
        let mut headers = vec![("origin", ISSUER)];
        if !cookies.is_empty() {
            headers.push(("cookie", cookies));
        }
        http(
            address,
            Method::POST,
            path,
            &headers,
            Some(("application/json", serde_json::to_string(body).unwrap())),
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
        let config = TokenConfig {
            api_version: "v1",
            kind: "Config",
            clusters: vec![Named {
                name: "e2e",
                entry: ClusterEntry {
                    cluster: Cluster {
                        server: cluster.server,
                        certificate_authority_data: cluster.certificate_authority_data,
                    },
                },
            }],
            users: vec![Named {
                name: "e2e",
                entry: UserEntry {
                    user: TokenUser {
                        token: token.to_owned(),
                    },
                },
            }],
            contexts: vec![Named {
                name: "e2e",
                entry: ContextEntry {
                    context: Context {
                        cluster: "e2e",
                        user: "e2e",
                    },
                },
            }],
            current_context: "e2e",
        };
        let path = dir.join(format!(
            "zeabur-identity-e2e-{label}-{}.json",
            std::process::id()
        ));
        std::fs::write(&path, serde_json::to_string(&config).unwrap()).unwrap();
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
        let certificates: Api<Certificate> =
            Api::namespaced_with(client.clone(), namespace, &resource);
        let current = certificates.get(name).await.unwrap();
        let mut status = current.status.unwrap_or_default();
        status.conditions.push(CertificateCondition {
            kind: "Issuing".into(),
            status: "True".into(),
            reason: Some("ManuallyTriggered".into()),
            message: Some("Certificate re-issuance manually triggered".into()),
            last_transition_time: None,
            observed_generation: None,
        });
        certificates
            .patch_status(
                name,
                &PatchParams::default(),
                &Patch::Merge(&StatusPatch { status }),
            )
            .await
            .unwrap();
    }

    /// Installs the CRDs and everything `zeabur-identityctl manifests` prints into `namespace`,
    /// with `image`, and waits until Zeabur Identity is ready.
    async fn install(admin: &Client, namespace: &str, issuer: &BaseUrl, image: &str) {
        for crd in definitions() {
            apply_to(&Api::<CustomResourceDefinition>::all(admin.clone()), &crd).await;
        }
        for object in deployment::manifests(
            namespace,
            issuer,
            &deployment::Options {
                image: image.to_owned(),
                ..deployment::Options::default()
            },
        ) {
            apply(admin, &object).await;
        }
        let deployments: Api<Deployment> = Api::namespaced(admin.clone(), namespace);
        rolled_out(&deployments, "Zeabur Identity to become ready").await;
    }

    /// Reaches the public listener through a `NodePort` on the node's address. Returns the
    /// address and the node's name.
    async fn public_address(admin: &Client, namespace: &str) -> (String, String) {
        let services: Api<Service> = Api::namespaced(admin.clone(), namespace);
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
        (address, node_name)
    }

    /// Signs in with `device` through Zeabur Identity's public listener, as kubectl's OIDC plugin
    /// would (authorization request, passkey, code, token), and returns the token response.
    async fn sign_in(address: &str, device: &mut Device, scope: &str) -> Tokens {
        let origin = Url::parse(ISSUER).unwrap();
        let authorize = format!(
            "/authorize?client_id=kubectl&redirect_uri=http%3A%2F%2F127.0.0.1%3A8000%2F&response_type=code&scope={scope}&code_challenge={CHALLENGE}&code_challenge_method=S256&state=e2e"
        );
        let reply = http(address, Method::GET, &authorize, &[], None).await;
        assert_eq!(reply.status, StatusCode::SEE_OTHER);
        let flow = reply.cookie(FLOW_COOKIE);
        let reply = post_json(address, "/login/options", &Empty::new(), "").await;
        let ceremony = reply.cookie(CEREMONY_COOKIE);
        let options: CredentialRequestOptions = reply.json();
        let assertion = device
            .authenticate(&origin, options, DefaultClientData)
            .await
            .unwrap();
        let reply = post_json(
            address,
            "/login",
            &CredentialBody {
                credential: &assertion,
            },
            &format!("{FLOW_COOKIE}={flow}; {CEREMONY_COOKIE}={ceremony}"),
        )
        .await;
        assert_eq!(reply.status, StatusCode::OK, "{:?}", reply.body);
        let location = reply.json::<Redirect>().redirect_to;
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
        let current = refreshed.json::<Tokens>().refresh;
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
        assert_eq!(wrong_client.json::<OAuthError>().error, "invalid_grant");
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
        refreshed.json::<Tokens>().refresh
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

        install(&admin, &namespace, &issuer, &image).await;

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

        let (address, node_name) = public_address(&admin, &namespace).await;
        let origin = Url::parse(ISSUER).unwrap();

        // Enrol a passkey from the link.
        let mut device = device();
        let reply = post_json(&address, "/setup/options", &TokenBody { token: &token }, "").await;
        assert_eq!(reply.status, StatusCode::OK, "{:?}", reply.body);
        let options: CredentialCreationOptions = reply.json();
        let credential = device
            .register(&origin, options, DefaultClientData)
            .await
            .unwrap();
        let ceremony = reply.cookie(CEREMONY_COOKIE);
        let reply = post_json(
            &address,
            "/setup",
            &SetupBody {
                token: &token,
                credential: &credential,
                label: "e2e",
            },
            &format!("{CEREMONY_COOKIE}={ceremony}"),
        )
        .await;
        assert_eq!(reply.status, StatusCode::CREATED, "{:?}", reply.body);

        // Sign in as kubectl would: authorization request, passkey, code, token.
        let tokens = sign_in(&address, &mut device, "openid").await;
        let latest_refresh =
            guessed_refresh_secrets_preserve_session(&address, &tokens.refresh).await;
        let access_token = tokens.access.as_str();
        let id_token = tokens.id.as_deref().unwrap();

        // UserInfo resolves metadata by UID without changing the token contract, then checks
        // the latest user spec. A disable must take effect without waiting for a watch update.
        let users: Api<User> = Api::namespaced(admin.clone(), &namespace);
        let subject = users.get("admin").await.unwrap().uid().unwrap();
        let authorization = format!("Bearer {access_token}");
        let headers = [("authorization", authorization.as_str())];
        let info = http(&address, Method::GET, "/userinfo", &headers, None).await;
        assert_eq!(info.status, StatusCode::OK);
        assert_eq!(info.json::<UserInfo>(), UserInfo { sub: subject });
        users
            .patch(
                "admin",
                &PatchParams::default(),
                &Patch::Merge(&SpecPatch {
                    spec: DisabledPatch { disabled: true },
                }),
            )
            .await
            .unwrap();
        let disabled = http(&address, Method::GET, "/userinfo", &headers, None).await;
        assert_eq!(disabled.status, StatusCode::UNAUTHORIZED);
        users
            .patch(
                "admin",
                &PatchParams::default(),
                &Patch::Merge(&SpecPatch {
                    spec: DisabledPatch { disabled: false },
                }),
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
        let user = serde_json::from_str::<SelfSubjectReview>(&whoami)
            .unwrap()
            .status
            .unwrap()
            .user_info
            .unwrap();
        assert_eq!(user.username.as_deref(), Some("zeabur:admin"), "{user:?}");
        let groups = user.groups.clone().unwrap_or_default();
        assert!(groups.iter().any(|g| g == "zeabur:admins"), "{user:?}");
        assert!(
            groups.iter().any(|g| g == "system:authenticated"),
            "{user:?}"
        );
        assert!(!groups.iter().any(|g| g.starts_with("system:masters")));
        let extra = user.extra.clone().unwrap_or_default();
        assert_eq!(
            extra.get("identity.zeabur.com/client-id"),
            Some(&vec!["kubectl".to_owned()])
        );
        assert_eq!(
            extra.get("identity.zeabur.com/amr"),
            Some(&vec!["swk".to_owned(), "mfa".to_owned()])
        );
        assert!(user.uid.as_ref().is_some_and(|uid| !uid.is_empty()));

        // An admin account acts with full rights, with no second sign-in.
        assert_eq!(can_i(&as_user, &["*", "*", "--all-namespaces"]), "yes");

        // A refresh needs no passkey, as kubelogin uses it. The token follows the account type
        // at each refresh: as a regular account, the admin group and its rights are gone.
        let set_type = |account_type: AccountType| {
            let users = users.clone();
            async move {
                users
                    .patch(
                        "admin",
                        &PatchParams::default(),
                        &Patch::Merge(&SpecPatch {
                            spec: AccountTypePatch { account_type },
                        }),
                    )
                    .await
                    .unwrap();
            }
        };
        set_type(AccountType::Regular).await;
        let regular = refresh(&address, &latest_refresh).await;
        assert_eq!(regular.status, StatusCode::OK, "{:?}", regular.body);
        let regular = regular.json::<Tokens>();
        let as_regular = token_kubeconfig(&scratch, "regular", &regular.access);
        assert_eq!(
            can_i(&as_regular, &["list", "pods", "--all-namespaces"]),
            "no"
        );
        set_type(AccountType::Admin).await;
        let refreshed = refresh(&address, &regular.refresh).await;
        assert_eq!(refreshed.status, StatusCode::OK, "{:?}", refreshed.body);
        let refreshed = refreshed.json::<Tokens>();
        let as_admin = token_kubeconfig(&scratch, "admin", &refreshed.access);
        assert_eq!(can_i(&as_admin, &["*", "*", "--all-namespaces"]), "yes");
        let latest_refresh = refreshed.refresh;

        // ID tokens are for the client, not for the cluster.
        let as_id_token = token_kubeconfig(&scratch, "id", id_token);
        assert!(kubectl(&as_id_token, &["auth", "whoami"]).is_err());

        // Memory as the kubelet sees it (working set), after a full sign-in. The budget is
        // 30 MiB; the value is also written for CI's job summary.
        let summary: StatsSummary = serde_json::from_str(
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
        let working_set = summary
            .pods
            .iter()
            .find(|pod| pod.pod_ref.namespace == namespace)
            .and_then(|pod| pod.memory.as_ref()?.working_set_bytes)
            .unwrap();
        if let Ok(path) = std::env::var("ZEABUR_IDENTITY_E2E_MEASUREMENTS") {
            std::fs::write(
                path,
                serde_json::to_string(&Measurement {
                    pod_working_set_bytes: working_set,
                })
                .unwrap(),
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
        let services: Api<Service> = Api::namespaced(admin.clone(), &namespace);
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
        let as_rotated = token_kubeconfig(&scratch, "rotated", &rotated.access);
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
        let refreshed = refreshed.json::<Tokens>();
        let current_refresh = refreshed.refresh.as_str();
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
        assert_eq!(denied.json::<OAuthError>().error, "invalid_grant");

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

    /// Keycloak as the browser and the test reach it: TLS to `address`, trusting only the
    /// scenario's CA, for URLs on the issuer's host.
    struct Keycloak {
        issuer: String,
        address: String,
        tls: TlsConnector,
    }

    /// The realm's client secret and test users (`keycloak/realm.json`).
    const KEYCLOAK_SECRET: &str = "e2e-only-client-secret";
    const KC_ALICE: (&str, &str, &str) = (
        "kc-alice",
        "alice-e2e-password",
        "6f1c1d2e-0000-4000-8000-00000000a11c",
    );
    const KC_BOB: (&str, &str, &str) = (
        "kc-bob",
        "bob-e2e-password",
        "6f1c1d2e-0000-4000-8000-000000000b0b",
    );

    /// Every cookie a reply sets, as a `Cookie` header value.
    fn set_cookies(reply: &Reply) -> Vec<String> {
        reply
            .headers
            .get_all(header::SET_COOKIE)
            .iter()
            .filter_map(|v| Some(v.to_str().ok()?.split(';').next()?.to_owned()))
            .collect()
    }

    impl Keycloak {
        fn from_env() -> Self {
            let pem = std::fs::read(env("ZEABUR_IDENTITY_E2E_KEYCLOAK_CA")).unwrap();
            let mut roots = rustls::RootCertStore::empty();
            for cert in CertificateDer::pem_slice_iter(&pem) {
                roots.add(cert.unwrap()).unwrap();
            }
            let config = rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth();
            Self {
                issuer: env("ZEABUR_IDENTITY_E2E_KEYCLOAK_ISSUER"),
                address: env("ZEABUR_IDENTITY_E2E_KEYCLOAK_ADDRESS"),
                tls: TlsConnector::from(Arc::new(config)),
            }
        }

        /// One HTTP/1.1 request over TLS to `url`.
        async fn request(
            &self,
            method: Method,
            url: &Url,
            cookies: &[String],
            form: Option<String>,
        ) -> Reply {
            let host = url.host_str().unwrap().to_owned();
            let stream = TcpStream::connect(&self.address).await.unwrap();
            let stream = self
                .tls
                .connect(ServerName::try_from(host.clone()).unwrap(), stream)
                .await
                .unwrap();
            let (mut sender, connection) =
                hyper::client::conn::http1::handshake(TokioIo::new(stream))
                    .await
                    .unwrap();
            tokio::spawn(connection);
            let path = url[url::Position::BeforePath..url::Position::AfterQuery].to_owned();
            let mut request = Request::builder().method(method).uri(path).header(
                header::HOST,
                format!("{host}:{}", url.port_or_known_default().unwrap()),
            );
            if !cookies.is_empty() {
                request = request.header(header::COOKIE, cookies.join("; "));
            }
            let payload = form.unwrap_or_default();
            if !payload.is_empty() {
                request = request.header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
            }
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

        /// Plays the browser at Keycloak: opens `authorize`, submits the login form as `user`,
        /// and returns where Keycloak sends the browser back to.
        async fn log_in(&self, authorize: &str, (user, password, _): (&str, &str, &str)) -> Url {
            let authorize = Url::parse(authorize).unwrap();
            assert!(authorize.as_str().starts_with(&self.issuer), "{authorize}");
            let page = self.request(Method::GET, &authorize, &[], None).await;
            assert_eq!(page.status, StatusCode::OK, "{:?}", page.body);
            let html = String::from_utf8_lossy(&page.body).into_owned();
            let form = html
                .get(html.find("id=\"kc-form-login\"").unwrap()..)
                .unwrap();
            let action = form.get(form.find("action=\"").unwrap() + 8..).unwrap();
            let action = action
                .get(..action.find('"').unwrap())
                .unwrap()
                .replace("&amp;", "&");
            let body = form_urlencoded::Serializer::new(String::new())
                .extend_pairs([
                    ("username", user),
                    ("password", password),
                    ("credentialId", ""),
                ])
                .finish();
            let reply = self
                .request(
                    Method::POST,
                    &Url::parse(&action).unwrap(),
                    &set_cookies(&page),
                    Some(body),
                )
                .await;
            assert_eq!(reply.status, StatusCode::FOUND, "{:?}", reply.body);
            let location = reply.headers[header::LOCATION].to_str().unwrap();
            Url::parse(location).unwrap()
        }
    }

    /// Follows Keycloak's redirect back to Zeabur Identity's callback with `cookies`.
    async fn callback(address: &str, back: &Url, cookies: &str) -> Reply {
        assert!(
            back.as_str()
                .starts_with(&format!("{ISSUER}/upstream/keycloak/callback?")),
            "{back}"
        );
        // RFC 9207: Keycloak names itself in the response, and Zeabur Identity checks it.
        assert!(back.query_pairs().any(|(k, _)| k == "iss"), "{back}");
        let path = format!("{}?{}", back.path(), back.query().unwrap());
        http(address, Method::GET, &path, &[("cookie", cookies)], None).await
    }

    /// The account session cookie after signing in to the account page with `device`.
    async fn account_session(address: &str, device: &mut Device) -> String {
        let origin = Url::parse(ISSUER).unwrap();
        let reply = post_json(address, "/account/session/options", &Empty::new(), "").await;
        assert_eq!(reply.status, StatusCode::OK, "{:?}", reply.body);
        let ceremony = reply.cookie(CEREMONY_COOKIE);
        let options: CredentialRequestOptions = reply.json();
        let assertion = device
            .authenticate(&origin, options, DefaultClientData)
            .await
            .unwrap();
        let reply = post_json(
            address,
            "/account/session",
            &CredentialBody {
                credential: &assertion,
            },
            &format!("{CEREMONY_COOKIE}={ceremony}"),
        )
        .await;
        assert_eq!(reply.status, StatusCode::OK, "{:?}", reply.body);
        format!("{SESSION_COOKIE}={}", reply.cookie(SESSION_COOKIE))
    }

    /// Links the Keycloak user `kc` from the account page.
    async fn link_from_account(
        address: &str,
        keycloak: &Keycloak,
        session: &str,
        kc: (&str, &str, &str),
    ) {
        let started = post_json(
            address,
            "/account/links/start",
            &ProviderBody {
                provider: "keycloak",
            },
            session,
        )
        .await;
        assert_eq!(started.status, StatusCode::OK, "{:?}", started.body);
        let upstream = started.cookie(UPSTREAM_COOKIE);
        let back = keycloak
            .log_in(&started.json::<Redirect>().redirect_to, kc)
            .await;
        let reply = callback(
            address,
            &back,
            &format!("{session}; {UPSTREAM_COOKIE}={upstream}"),
        )
        .await;
        assert_eq!(reply.status, StatusCode::SEE_OTHER, "{:?}", reply.body);
        assert_eq!(
            reply.headers[header::LOCATION],
            format!("{ISSUER}/account#notice=linked")
        );
    }

    /// Signs in as kubectl would, choosing Keycloak and logging in there as `kc`. Returns the
    /// callback reply.
    async fn keycloak_sign_in(address: &str, keycloak: &Keycloak, kc: (&str, &str, &str)) -> Reply {
        let authorize = format!(
            "/authorize?client_id=kubectl&redirect_uri=http%3A%2F%2F127.0.0.1%3A8000%2F&response_type=code&scope=openid&code_challenge={CHALLENGE}&code_challenge_method=S256&state=e2e"
        );
        let reply = http(address, Method::GET, &authorize, &[], None).await;
        assert_eq!(reply.status, StatusCode::SEE_OTHER);
        let flow = format!("{FLOW_COOKIE}={}", reply.cookie(FLOW_COOKIE));
        let started = post_json(address, "/upstream/keycloak/start", &Empty::new(), &flow).await;
        assert_eq!(started.status, StatusCode::OK, "{:?}", started.body);
        let upstream = started.cookie(UPSTREAM_COOKIE);
        let back = keycloak
            .log_in(&started.json::<Redirect>().redirect_to, kc)
            .await;
        callback(
            address,
            &back,
            &format!("{flow}; {UPSTREAM_COOKIE}={upstream}"),
        )
        .await
    }

    /// The `sub` that `/userinfo` returns for the code in a successful callback.
    async fn signed_in_subject(address: &str, reply: &Reply) -> String {
        assert_eq!(reply.status, StatusCode::SEE_OTHER, "{:?}", reply.body);
        let location = reply.headers[header::LOCATION].to_str().unwrap();
        assert!(location.starts_with(REDIRECT), "{location}");
        let code = form_urlencoded::parse(location.split_once('?').unwrap().1.as_bytes())
            .find(|(k, _)| k == "code")
            .unwrap()
            .1
            .into_owned();
        let tokens = post_form(
            address,
            "/token",
            &[
                ("grant_type", "authorization_code"),
                ("code", code.as_str()),
                ("code_verifier", VERIFIER),
                ("client_id", "kubectl"),
                ("redirect_uri", REDIRECT),
            ],
        )
        .await;
        assert_eq!(tokens.status, StatusCode::OK, "{:?}", tokens.body);
        let authorization = format!("Bearer {}", tokens.json::<Tokens>().access);
        let info = http(
            address,
            Method::GET,
            "/userinfo",
            &[("authorization", &authorization)],
            None,
        )
        .await;
        assert_eq!(info.status, StatusCode::OK);
        info.json::<UserInfo>().sub
    }

    /// The checked-in OpenID scenario against Keycloak, which `scripts/keycloak-e2e.sh` serves
    /// with a CA of its own. Zeabur Identity is told to trust that CA as the "Add an upstream
    /// sign-in" guide says. Then a regular user links one Keycloak account from the account page
    /// and signs in with it as kubectl would, links a second, unlinks it, and that second account
    /// can no longer sign in while the first still can.
    #[tokio::test]
    #[ignore = "needs a prepared k3s cluster, the image and Keycloak (scripts/keycloak-e2e.sh)"]
    #[expect(clippy::too_many_lines, reason = "one scenario, read top to bottom")]
    async fn keycloak_links_signs_in_and_unlinks() {
        let image = env("ZEABUR_IDENTITY_E2E_IMAGE");
        let keycloak = Keycloak::from_env();
        let ca = std::fs::read_to_string(env("ZEABUR_IDENTITY_E2E_KEYCLOAK_CA")).unwrap();
        let admin = Client::try_default().await.unwrap();
        let issuer = BaseUrl::parse("issuer", ISSUER).unwrap();
        let namespace = format!("zeabur-identity-keycloak-{}", std::process::id());
        install(&admin, &namespace, &issuer, &image).await;

        // Trust the provider's CA: a ConfigMap, mounted, and the image's bundle kept.
        apply_namespaced(
            &admin,
            &ConfigMap {
                metadata: ObjectMeta {
                    name: Some("upstream-ca".into()),
                    namespace: Some(namespace.clone()),
                    ..ObjectMeta::default()
                },
                data: Some([("ca.crt".to_owned(), ca)].into()),
                ..ConfigMap::default()
            },
        )
        .await;
        let deployments: Api<Deployment> = Api::namespaced(admin.clone(), &namespace);
        deployments
            .patch(
                rbac::NAME,
                &PatchParams::default(),
                &Patch::Strategic(&TemplatePatch {
                    spec: TemplateSpecPatch {
                        template: PodPatch {
                            spec: PodSpecPatch {
                                volumes: vec![Volume {
                                    name: "upstream-ca".into(),
                                    config_map: Some(ConfigMapVolumeSource {
                                        name: "upstream-ca".into(),
                                        ..ConfigMapVolumeSource::default()
                                    }),
                                    ..Volume::default()
                                }],
                                containers: vec![Container {
                                    name: rbac::NAME.into(),
                                    env: Some(vec![
                                        EnvVar {
                                            name: "SSL_CERT_FILE".into(),
                                            value: Some(
                                                "/etc/ssl/certs/ca-certificates.crt".into(),
                                            ),
                                            ..EnvVar::default()
                                        },
                                        EnvVar {
                                            name: "SSL_CERT_DIR".into(),
                                            value: Some("/etc/zeabur-identity-upstream-ca".into()),
                                            ..EnvVar::default()
                                        },
                                    ]),
                                    volume_mounts: Some(vec![VolumeMount {
                                        name: "upstream-ca".into(),
                                        mount_path: "/etc/zeabur-identity-upstream-ca".into(),
                                        read_only: Some(true),
                                        ..VolumeMount::default()
                                    }]),
                                    ..Container::default()
                                }],
                            },
                        },
                    },
                }),
            )
            .await
            .unwrap();
        rolled_out(&deployments, "the Deployment to roll out with the CA").await;

        // The provider: its client secret, then the object.
        apply_namespaced(
            &admin,
            &Secret {
                metadata: ObjectMeta {
                    name: Some("zeabur-identity-upstream".into()),
                    namespace: Some(namespace.clone()),
                    ..ObjectMeta::default()
                },
                string_data: Some([("keycloak".to_owned(), KEYCLOAK_SECRET.to_owned())].into()),
                ..Secret::default()
            },
        )
        .await;
        let provider_resource = kube::api::ApiResource::erase::<UpstreamProvider>(&());
        let provider = Object::<UpstreamProviderSpec, NotUsed>::new(
            "keycloak",
            &provider_resource,
            UpstreamProviderSpec {
                client_id: "zeabur-identity".into(),
                kind: UpstreamKind::OpenID(OpenID {
                    issuer: keycloak.issuer.clone(),
                    display_name: Some("Keycloak".into()),
                    scopes: None,
                    mfa: zeabur_identity_api::upstream_provider::Mfa::default(),
                }),
            },
        )
        .within(&namespace);
        apply_to(
            &Api::namespaced_with(admin.clone(), &namespace, &provider_resource),
            &provider,
        )
        .await;
        let clients: Api<OAuthClient> = Api::namespaced(admin.clone(), &namespace);
        clients
            .create(
                &PostParams::default(),
                &OAuthClient::new(
                    "kubectl",
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
        let (address, _) = public_address(&admin, &namespace).await;
        wait_for(
            "the sign-in page to offer Keycloak",
            Duration::from_secs(60),
            || {
                let address = address.clone();
                async move {
                    let page = http(&address, Method::GET, "/setup", &[], None).await;
                    String::from_utf8_lossy(&page.body)
                        .contains("data-start=\"/upstream/keycloak/start\"")
                }
            },
        )
        .await;

        // alice: a passkey from a setup link, then a regular account.
        let link = issue_setup_link(
            admin.clone(),
            &namespace,
            &issuer,
            "alice",
            Duration::from_mins(10),
            false,
            SystemClock.now(),
        )
        .await
        .unwrap();
        let token = link.url.split_once("#token=").unwrap().1.to_owned();
        let mut device = device();
        let origin = Url::parse(ISSUER).unwrap();
        let reply = post_json(&address, "/setup/options", &TokenBody { token: &token }, "").await;
        assert_eq!(reply.status, StatusCode::OK, "{:?}", reply.body);
        let options: CredentialCreationOptions = reply.json();
        let credential = device
            .register(&origin, options, DefaultClientData)
            .await
            .unwrap();
        let ceremony = reply.cookie(CEREMONY_COOKIE);
        let reply = post_json(
            &address,
            "/setup",
            &SetupBody {
                token: &token,
                credential: &credential,
                label: "e2e",
            },
            &format!("{CEREMONY_COOKIE}={ceremony}"),
        )
        .await;
        assert_eq!(reply.status, StatusCode::CREATED, "{:?}", reply.body);
        let users: Api<User> = Api::namespaced(admin.clone(), &namespace);
        users
            .patch(
                "alice",
                &PatchParams::default(),
                &Patch::Merge(&SpecPatch {
                    spec: AccountTypePatch {
                        account_type: AccountType::Regular,
                    },
                }),
            )
            .await
            .unwrap();
        let alice = users.get("alice").await.unwrap().uid().unwrap();

        // Before any link, Keycloak's kc-alice is nobody here.
        let reply = keycloak_sign_in(&address, &keycloak, KC_ALICE).await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{:?}", reply.body);
        assert!(String::from_utf8_lossy(&reply.body).contains("account_unlinked (keycloak)"));

        // Link kc-alice from the account page; it signs in as alice.
        let session = account_session(&address, &mut device).await;
        link_from_account(&address, &keycloak, &session, KC_ALICE).await;
        let reply = keycloak_sign_in(&address, &keycloak, KC_ALICE).await;
        assert_eq!(signed_in_subject(&address, &reply).await, alice);

        // A second Keycloak account, linked to alice too, signs in as alice.
        link_from_account(&address, &keycloak, &session, KC_BOB).await;
        let reply = keycloak_sign_in(&address, &keycloak, KC_BOB).await;
        assert_eq!(signed_in_subject(&address, &reply).await, alice);

        // Unlink kc-bob: alice keeps her passkey and kc-alice.
        let credentials: Api<Credential> = Api::namespaced(admin.clone(), &namespace);
        let mine = credentials
            .list(&ListParams::default().labels(&format!("{USER_LABEL}=alice")))
            .await
            .unwrap()
            .items;
        let subject_of = |c: &Credential| match &c.spec.kind {
            CredentialKind::External(e) => Some(e.subject.as_str().to_owned()),
            CredentialKind::Passkey(_) | CredentialKind::Password(_) => None,
        };
        let bob = mine
            .iter()
            .find(|c| subject_of(c).as_deref() == Some(KC_BOB.2))
            .unwrap()
            .name_any();
        let reply = post_json(
            &address,
            "/account/links/remove",
            &NameBody { name: &bob },
            &session,
        )
        .await;
        assert!(reply.status.is_success(), "{:?}", reply.body);
        let left = credentials
            .list(&ListParams::default().labels(&format!("{USER_LABEL}=alice")))
            .await
            .unwrap()
            .items;
        assert!(left.iter().all(|c| c.name_any() != bob));
        assert!(
            left.iter()
                .any(|c| matches!(c.spec.kind, CredentialKind::Passkey(_)))
        );
        assert!(
            left.iter()
                .any(|c| subject_of(c).as_deref() == Some(KC_ALICE.2))
        );

        // kc-bob is nobody here again; kc-alice still signs in as alice.
        let reply = keycloak_sign_in(&address, &keycloak, KC_BOB).await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{:?}", reply.body);
        assert!(String::from_utf8_lossy(&reply.body).contains("account_unlinked (keycloak)"));
        let reply = keycloak_sign_in(&address, &keycloak, KC_ALICE).await;
        assert_eq!(signed_in_subject(&address, &reply).await, alice);

        Api::<Namespace>::all(admin)
            .delete(&namespace, &DeleteParams::background())
            .await
            .unwrap();
    }
}
