//! `zeabur-identity`: wires configuration, storage, keys and HTTP together.
//!
//! Kubernetes mode binds the internal port first, failing immediately if it is unavailable.
//! Startup refuses to bind the public port until directory metadata watches publish their initial
//! snapshots and signing keys are reconciled. Background tasks watch metadata, rotate keys,
//! collect expired grants and invitations, and serve internal TLS.
//! With the Kubernetes store, if the API server becomes unreachable, Zeabur Identity keeps serving
//! the last published keys; logins and refreshes that need a write fail closed, and the background
//! tasks retry.

use std::io;
use std::sync::Arc;
use std::time::Duration;

use axum::serve::Listener as _;
use k8s_openapi::api::core::v1::Secret;
use kube::Client;
use kube::api::Api;
use thiserror::Error;
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use zeabur_identity_core::clock::SystemClock;
use zeabur_identity_core::crypto::Sealer;
use zeabur_identity_k8s::crd::grant::Grant;
use zeabur_identity_k8s::crd::invitation::Invitation;
use zeabur_identity_k8s::credentials::KubeCredentialStore;
use zeabur_identity_k8s::directory::KubeDirectory;
use zeabur_identity_k8s::gc;
use zeabur_identity_k8s::grants::KubeGrantStore;
use zeabur_identity_k8s::keys::SecretKeyStore;
use zeabur_identity_k8s::setup::KubeSetupStore;
use zeabur_identity_keys::manager::{KeyManager, ManagerError};
use zeabur_identity_keys::store::{KeyStore, MemoryKeyStore};
use zeabur_identity_oauth::discovery::ProviderMetadata;
use zeabur_identity_oauth::metadata::{AppState, router};
use zeabur_identity_oauth::{AuthorizationServer, OneTimeIds, endpoints};
use zeabur_identity_signin::passkeys::Passkeys;
use zeabur_identity_signin::upstream::http::HyperClient;
use zeabur_identity_signin::upstream::provider::{Endpoints, Kind, Provider};
use zeabur_identity_signin::upstream::{self, Upstream};
use zeabur_identity_signin::{SignIn, pages};
use zeabur_identity_store::{
    CredentialStore, Directory, GrantStore, MemoryCredentialStore, MemoryDirectory,
    MemoryGrantStore, MemorySetupStore, SetupStore,
};
use zeabur_identity_tls::listener::{Resolver, TlsListener, server_config};

use crate::config::{ServeConfig, Store};
use crate::internal::{self, InternalConfig};

/// How often signing keys are reconciled. Rotation timings are hours to days, so a minute of
/// lateness is irrelevant; the interval mainly bounds how quickly a storage outage recovers.
const RECONCILE_INTERVAL: Duration = Duration::from_mins(1);

/// Maximum request body. Every request this server accepts is a small form.
const MAX_BODY: usize = 16 * 1024;
/// Maximum time to handle one request.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
/// Each business route/method service has its own admission budget.
const ROUTE_CONCURRENT: usize = 64;

/// Why the server stopped with an error.
#[derive(Debug, Error)]
pub enum ServeError {
    /// No Kubernetes client could be configured (no in-cluster service account and no
    /// kubeconfig).
    #[error("connecting to Kubernetes: {0}")]
    Kubernetes(#[from] kube::Error),
    /// Signing keys could not be prepared at startup.
    #[error("preparing signing keys: {0}")]
    Keys(#[from] ManagerError),
    /// Kubernetes directory metadata could not be synchronized at startup.
    #[error("preparing directory metadata: {0}")]
    Directory(#[from] zeabur_identity_store::StoreError),
    /// The process sealing key could not be created.
    #[error("creating the process sealing key failed")]
    Crypto,
    /// The configuration cannot be used (for example as a WebAuthn origin).
    #[error("configuration: {0}")]
    Config(String),
    /// Binding or serving failed.
    #[error("serving HTTP: {0}")]
    Io(#[from] io::Error),
}

/// Runs the server until SIGTERM or SIGINT.
///
/// # Errors
///
/// Returns [`ServeError`] if storage or keys cannot be prepared at startup, or the listener
/// fails.
pub async fn serve(config: ServeConfig) -> Result<(), ServeError> {
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    match &config.store {
        Store::Memory => {
            tracing::warn!(
                "store=memory: keys, clients, users and grants live in process memory and start \
                 empty; use only for development"
            );
            let stores = (
                MemoryKeyStore::default(),
                MemoryDirectory::default(),
                MemoryGrantStore::default(),
                MemoryCredentialStore::default(),
                MemorySetupStore::default(),
            );
            run(&config, stores, Vec::new(), None, shutdown_tx).await
        }
        Store::Kubernetes {
            namespace,
            key_secret,
        } => {
            let internal_listener = TcpListener::bind(config.internal_listen).await?;
            let resolver = Arc::new(Resolver::default());
            let tls = server_config(Arc::clone(&resolver)).map_err(io::Error::other)?;
            let internal_listener = TlsListener::new(internal_listener, tls)?;
            tracing::info!(address = %internal_listener.local_addr()?, "internal listener bound");
            let client = Client::try_default().await?;
            let namespace = namespace
                .clone()
                .unwrap_or_else(|| client.default_namespace().to_owned());
            tracing::info!("using Kubernetes storage");
            let keys = SecretKeyStore::new(
                Api::namespaced(client.clone(), &namespace),
                key_secret.clone(),
            );
            let mut background = Vec::new();
            let directory = KubeDirectory::new(
                Api::namespaced(client.clone(), &namespace),
                Api::namespaced(client.clone(), &namespace),
            )
            .await?;
            let grants = KubeGrantStore::new(Api::namespaced(client.clone(), &namespace));
            let credentials = KubeCredentialStore::new(Api::namespaced(client.clone(), &namespace));
            let mut setup = KubeSetupStore::new(Api::namespaced(client.clone(), &namespace));
            if config.invitations {
                setup = setup.with_invitations(Api::namespaced(client.clone(), &namespace));
                background.push(tokio::spawn({
                    let (client, namespace, shutdown) =
                        (client.clone(), namespace.clone(), shutdown_rx.clone());
                    async move {
                        gc::run::<Invitation, _>(client, &namespace, SystemClock, shutdown).await;
                    }
                }));
            }
            let internal_secrets = Api::namespaced(client.clone(), &namespace);
            let gc = tokio::spawn({
                let shutdown = shutdown_rx.clone();
                async move { gc::run::<Grant, _>(client, &namespace, SystemClock, shutdown).await }
            });
            run(
                &config,
                (keys, directory, grants, credentials, setup),
                background.into_iter().chain([gc]).collect(),
                Some((internal_listener, resolver, internal_secrets)),
                shutdown_tx,
            )
            .await
        }
    }
}

/// The configured upstream providers, with their client secrets read from files.
fn upstream_providers(config: &ServeConfig) -> Result<Vec<Provider>, ServeError> {
    config
        .upstream
        .iter()
        .map(|upstream| {
            let secret = std::fs::read_to_string(&upstream.client_secret_file)
                .map_err(|error| {
                    ServeError::Config(format!(
                        "{}: {error}",
                        upstream.client_secret_file.display()
                    ))
                })?
                .trim()
                .to_owned();
            let endpoints = match upstream.kind {
                Kind::GitHub => Endpoints::github(),
                Kind::Google => Endpoints::google(),
            };
            Ok(Provider::new(
                upstream.kind,
                upstream.client_id.clone(),
                secret,
                endpoints,
            ))
        })
        .collect()
}

/// Maps load shedding to an immediate retryable response; unexpected errors retain diagnostics.
fn admission_error(error: &axum::BoxError) -> axum::response::Response {
    use axum::http::{StatusCode, header};
    use axum::response::IntoResponse as _;

    if error.is::<tower::load_shed::error::Overloaded>() {
        tracing::debug!("request rejected for load");
        (
            StatusCode::SERVICE_UNAVAILABLE,
            [
                (header::RETRY_AFTER, "1"),
                (header::CACHE_CONTROL, "no-store"),
            ],
        )
            .into_response()
    } else {
        tracing::error!(%error, "unexpected request admission error");
        StatusCode::INTERNAL_SERVER_ERROR.into_response()
    }
}

/// Limits each route/method independently, rather than sharing a semaphore across the router.
///
/// Load shedding polls the limiter before calling it, so saturation never queues outside the
/// universal timeout. Permits are released on handler completion, cancellation or timeout.
/// Overload uses `503` with a one-second retry suggestion ([RFC 9110 §15.6.4]).
///
/// [RFC 9110 §15.6.4]: https://www.rfc-editor.org/rfc/rfc9110.html#section-15.6.4
fn business_limits(router: axum::Router) -> axum::Router {
    // Materialize deferred handlers once: otherwise axum can rebuild a per-service semaphore
    // when supplying state at request/connection time instead of sharing it across route clones.
    router.with_state(()).layer(
        tower::ServiceBuilder::new()
            .layer(axum::error_handling::HandleErrorLayer::new(
                |error: axum::BoxError| async move { admission_error(&error) },
            ))
            .load_shed()
            .concurrency_limit(ROUTE_CONCURRENT),
    )
}

/// Body and time limits apply universally, including metadata and probes.
fn limits(router: axum::Router) -> axum::Router {
    router
        .layer(axum::extract::DefaultBodyLimit::max(MAX_BODY))
        .layer(tower_http::timeout::TimeoutLayer::with_status_code(
            axum::http::StatusCode::REQUEST_TIMEOUT,
            REQUEST_TIMEOUT,
        ))
}

async fn run<S: KeyStore, D: Directory, G: GrantStore, K: CredentialStore, T: SetupStore>(
    config: &ServeConfig,
    (keys, directory, grants, credentials, setup): (S, D, G, K, T),
    mut background: Vec<JoinHandle<()>>,
    internal_listener: Option<(TlsListener, Arc<Resolver>, Api<Secret>)>,
    shutdown_tx: watch::Sender<bool>,
) -> Result<(), ServeError> {
    let manager = Arc::new(KeyManager::new(keys, SystemClock, config.rotation));
    // Refuse to start without keys rather than serve an empty JWK set.
    manager.reconcile().await?;

    let rotator = tokio::spawn({
        let manager = Arc::clone(&manager);
        let shutdown = shutdown_tx.subscribe();
        async move { manager.run(RECONCILE_INTERVAL, shutdown).await }
    });

    if let Some((listener, resolver, secrets)) = internal_listener {
        let internal = InternalConfig {
            issuer: config.issuer.clone(),
            url: config.internal_url.clone(),
            max_age: config.metadata_max_age,
        };
        background.push(tokio::spawn(internal::run(
            listener,
            resolver,
            internal,
            secrets,
            manager.subscribe(),
            shutdown_tx.subscribe(),
        )));
    }

    let metadata = ProviderMetadata::new(&config.issuer, &config.issuer).to_bytes();
    let server = Arc::new(AuthorizationServer {
        issuer: config.issuer.clone(),
        lifetimes: config.lifetimes,
        directory,
        grants,
        clock: SystemClock,
        keys: manager.subscribe(),
        sealer: Sealer::ephemeral().map_err(|_crypto| ServeError::Crypto)?,
        used_codes: OneTimeIds::default(),
        used_request_uris: OneTimeIds::default(),
    });
    let providers = upstream_providers(config)?;
    let kinds: Vec<Kind> = providers.iter().map(Provider::kind).collect();
    let sign_in = Arc::new(SignIn {
        oauth: Arc::clone(&server),
        passkeys: Passkeys::new(&config.issuer)
            .map_err(|error| ServeError::Config(error.to_string()))?,
        credentials,
        setup,
        used_ceremonies: OneTimeIds::default(),
        providers: kinds.clone(),
    });
    let mut app = router(AppState::new(
        metadata,
        manager.subscribe(),
        config.metadata_max_age,
    ))
    .merge(business_limits(endpoints::router(Arc::clone(&server))))
    .merge(business_limits(zeabur_identity_signin::router(Arc::clone(
        &sign_in,
    ))))
    .merge(business_limits(pages::router(Arc::clone(&server), &kinds)));
    if !providers.is_empty() {
        let roots = zeabur_identity_tls::trust::roots()
            .map_err(|error| ServeError::Config(error.to_string()))?;
        let http =
            HyperClient::new(roots).map_err(|error| ServeError::Config(error.to_string()))?;
        tracing::info!(providers = ?kinds, "upstream sign-in enabled");
        app = app.merge(business_limits(upstream::router(Arc::new(Upstream {
            sign_in,
            providers,
            http,
            used_states: OneTimeIds::default(),
        }))));
    }
    let app = limits(app);
    let listener = TcpListener::bind(config.listen).await?;
    tracing::info!(address = %listener.local_addr()?, issuer = %config.issuer, "listening");

    let outcome = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await;
    shutdown_tx.send_replace(true);
    for task in background.into_iter().chain([rotator]) {
        if let Err(error) = task.await {
            tracing::error!(%error, reason = "background_task_failed", "background task failed");
        }
    }
    outcome?;
    tracing::info!(event = "server.stopped", "stopped");
    Ok(())
}

async fn shutdown_signal() {
    let interrupt = async {
        if let Err(error) = tokio::signal::ctrl_c().await {
            tracing::error!(
                reason = "sigint_listener_failed",
                %error,
                "cannot listen for SIGINT"
            );
            std::future::pending::<()>().await;
        }
    };
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(error) => {
                tracing::error!(
                    reason = "sigterm_listener_failed",
                    %error,
                    "cannot listen for SIGTERM"
                );
                std::future::pending::<()>().await;
            }
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        () = interrupt => {},
        () = terminate => {},
    }
    tracing::info!("shutting down");
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::{Request, StatusCode, header};
    use axum::routing::get;
    use tokio::sync::Semaphore;
    use tower::ServiceExt as _;

    use super::*;

    fn request(path: &str) -> Request<Body> {
        Request::builder().uri(path).body(Body::empty()).unwrap()
    }

    async fn assert_route_isolation(saturated: &'static str) {
        let entered = Arc::new(Semaphore::new(0));
        let release = Arc::new(Semaphore::new(0));
        let business = axum::Router::new()
            .route(
                saturated,
                get({
                    let entered = Arc::clone(&entered);
                    let release = Arc::clone(&release);
                    move || {
                        let entered = Arc::clone(&entered);
                        let release = Arc::clone(&release);
                        async move {
                            entered.add_permits(1);
                            release.acquire().await.unwrap().forget();
                            StatusCode::OK
                        }
                    }
                })
                .post(|| async { StatusCode::OK }),
            )
            .route("/par", get(|| async { StatusCode::OK }))
            .route("/token", get(|| async { StatusCode::OK }))
            .route("/login/options", get(|| async { StatusCode::OK }));
        let app = limits(
            axum::Router::new()
                .route("/readyz", get(|| async { StatusCode::OK }))
                .route("/healthz", get(|| async { StatusCode::OK }))
                .merge(business_limits(business)),
        );
        let mut tasks = Vec::new();
        for _ in 0..ROUTE_CONCURRENT {
            tasks.push(tokio::spawn(app.clone().oneshot(request(saturated))));
        }
        tokio::time::timeout(
            Duration::from_secs(1),
            entered.acquire_many(u32::try_from(ROUTE_CONCURRENT).unwrap()),
        )
        .await
        .unwrap()
        .unwrap()
        .forget();
        let rejected = tokio::time::timeout(
            Duration::from_secs(1),
            app.clone().oneshot(request(saturated)),
        )
        .await
        .expect("overload must not queue")
        .unwrap();
        assert_eq!(rejected.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(rejected.headers()[header::RETRY_AFTER], "1");
        assert_eq!(rejected.headers()[header::CACHE_CONTROL], "no-store");
        for path in ["/par", "/token", "/login/options", "/readyz", "/healthz"] {
            let response =
                tokio::time::timeout(Duration::from_secs(1), app.clone().oneshot(request(path)))
                    .await
                    .unwrap()
                    .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
        }
        // A different method of the saturated route also has its own budget.
        let post = Request::builder()
            .method("POST")
            .uri(saturated)
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), app.clone().oneshot(post))
                .await
                .unwrap()
                .unwrap()
                .status(),
            StatusCode::OK
        );

        // Cancellation releases one slot, without waiting for the other handlers.
        let cancelled = tasks.pop().unwrap();
        cancelled.abort();
        assert!(cancelled.await.unwrap_err().is_cancelled());
        let replacement = tokio::spawn(app.clone().oneshot(request(saturated)));
        tokio::time::timeout(Duration::from_secs(1), entered.acquire())
            .await
            .unwrap()
            .unwrap()
            .forget();
        release.add_permits(ROUTE_CONCURRENT);
        tasks.push(replacement);
        for task in tasks {
            assert_eq!(task.await.unwrap().unwrap().status(), StatusCode::OK);
        }
        // Completion releases all slots too.
        release.add_permits(1);
        assert_eq!(
            app.oneshot(request(saturated)).await.unwrap().status(),
            StatusCode::OK
        );
    }

    #[tokio::test]
    async fn overloaded_authorization_is_isolated_per_route_and_method() {
        assert_route_isolation("/authorize").await;
    }

    #[tokio::test]
    async fn overloaded_userinfo_backend_does_not_block_probes() {
        assert_route_isolation("/userinfo").await;
    }

    #[test]
    fn unexpected_admission_errors_return_internal_server_error() {
        let response = admission_error(&io::Error::other("unexpected middleware failure").into());
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert!(!response.headers().contains_key(header::RETRY_AFTER));
    }
}
