//! HTTP routes for the public listener: the metadata documents, the JWK set, `/healthz` and
//! `/readyz`.
//!
//! Documents are precomputed and served from memory with `Cache-Control: public, max-age=N`.
//! kube-apiserver's verifier re-fetches keys only after that cache expires, so new keys must be
//! published at least `N` seconds before they sign (the key manager's publish-ahead period).
//! The JWK set answers 503 until keys exist, never an empty set, and `/readyz` follows it.

use std::time::Duration;

use axum::Router;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use tokio::sync::watch;
use zeabur_identity_keys::manager::PublishedKeys;

use crate::discovery::{JWKS_PATH, OAUTH_METADATA_PATH, OPENID_CONFIGURATION_PATH};

/// Shared state of the public listener.
#[derive(Debug, Clone)]
pub struct AppState {
    metadata: watch::Receiver<Bytes>,
    keys: PublishedKeys,
    cache_control: HeaderValue,
}

impl AppState {
    /// `metadata` is the serialized provider metadata; `max_age` bounds how long clients may
    /// cache the metadata and the JWK set.
    #[must_use]
    pub fn new(metadata: Bytes, keys: PublishedKeys, max_age: Duration) -> Self {
        Self::dynamic(watch::channel(metadata).1, keys, max_age)
    }

    /// Like [`AppState::new`], for a metadata document that can change (the internal listener's,
    /// whose `jwks_uri` follows its certificate Secret).
    #[must_use]
    pub fn dynamic(
        metadata: watch::Receiver<Bytes>,
        keys: PublishedKeys,
        max_age: Duration,
    ) -> Self {
        let cache_control = HeaderValue::try_from(format!("public, max-age={}", max_age.as_secs()))
            .unwrap_or_else(|_| HeaderValue::from_static("no-cache"));
        Self {
            metadata,
            keys,
            cache_control,
        }
    }
}

/// Builds the router.
pub fn router(state: AppState) -> Router {
    Router::new()
        .route(OPENID_CONFIGURATION_PATH, get(metadata))
        .route(OAUTH_METADATA_PATH, get(metadata))
        .route(JWKS_PATH, get(jwks))
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .fallback(not_found)
        .with_state(state)
}

/// Headers for public, cacheable JSON. CORS is open because the documents are public and
/// browser-based clients fetch them (no credentials are involved).
fn public_json(state: &AppState) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    headers.insert(header::CACHE_CONTROL, state.cache_control.clone());
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_ORIGIN,
        HeaderValue::from_static("*"),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers
}

async fn metadata(State(state): State<AppState>) -> Response {
    let metadata = state.metadata.borrow().clone();
    (public_json(&state), metadata).into_response()
}

async fn jwks(State(state): State<AppState>) -> Response {
    let published = state.keys.borrow().clone();
    published.map_or_else(unavailable, |published| {
        (public_json(&state), published.jwks()).into_response()
    })
}

async fn healthz() -> &'static str {
    "ok"
}

async fn readyz(State(state): State<AppState>) -> Response {
    if state.keys.borrow().is_some() {
        "ok".into_response()
    } else {
        unavailable()
    }
}

fn unavailable() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        [(header::RETRY_AFTER, HeaderValue::from_static("5"))],
        "Signing keys are not ready yet. Try again in a few seconds.",
    )
        .into_response()
}

/// A plain-text `404`, so a browser shows the answer instead of saving it as a file.
async fn not_found() -> Response {
    (
        StatusCode::NOT_FOUND,
        [(header::X_CONTENT_TYPE_OPTIONS, "nosniff")],
        "Not found.",
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::sync::Arc;

    use axum::body::Body;
    use axum::http::{Method, Request};
    use http_body_util::BodyExt as _;
    use serde::Deserialize;
    use tower::ServiceExt as _;
    use zeabur_identity_core::clock::SystemClock;
    use zeabur_identity_core::config::BaseUrl;
    use zeabur_identity_keys::manager::KeyManager;
    use zeabur_identity_keys::rotation::RotationPolicy;
    use zeabur_identity_keys::store::MemoryKeyStore;

    use super::*;
    use crate::discovery::ProviderMetadata;

    /// The discovery member the test reads.
    #[derive(Deserialize)]
    struct Discovery {
        issuer: String,
    }

    /// A public JWK (RFC 7517 §4, RFC 7518 §6): a private member fails the parse.
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct PublicJwk {
        kty: String,
        #[serde(rename = "use")]
        usage: String,
        alg: String,
        kid: String,
        #[serde(default)]
        crv: Option<String>,
        #[serde(default)]
        x: Option<String>,
        #[serde(default)]
        y: Option<String>,
        #[serde(default)]
        n: Option<String>,
        #[serde(default)]
        e: Option<String>,
    }

    /// A JWK set (RFC 7517 §5).
    #[derive(Deserialize)]
    struct PublicJwkSet {
        keys: Vec<PublicJwk>,
    }

    async fn app(reconciled: bool) -> Router {
        let issuer = BaseUrl::parse("issuer", "https://login.example.com").unwrap();
        let manager = Arc::new(KeyManager::new(
            MemoryKeyStore::default(),
            SystemClock,
            RotationPolicy::DEFAULT,
        ));
        if reconciled {
            manager.reconcile().await.unwrap();
        }
        let metadata = ProviderMetadata::new(&issuer, &issuer).to_bytes();
        router(AppState::new(
            metadata,
            manager.subscribe(),
            Duration::from_secs(300),
        ))
    }

    async fn fetch(app: &Router, path: &str) -> (StatusCode, HeaderMap, Bytes) {
        let request = Request::builder().uri(path).body(Body::empty()).unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        let (parts, body) = response.into_parts();
        (
            parts.status,
            parts.headers,
            body.collect().await.unwrap().to_bytes(),
        )
    }

    #[tokio::test]
    async fn both_metadata_locations_serve_the_same_document() {
        let app = app(true).await;
        let (status, headers, oidc) = fetch(&app, OPENID_CONFIGURATION_PATH).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(headers[header::CONTENT_TYPE], "application/json");
        assert_eq!(headers[header::CACHE_CONTROL], "public, max-age=300");
        let (_, _, oauth) = fetch(&app, OAUTH_METADATA_PATH).await;
        assert_eq!(oidc, oauth);
        let doc: Discovery = serde_json::from_slice(&oidc).unwrap();
        assert_eq!(doc.issuer, "https://login.example.com");
    }

    #[tokio::test]
    async fn jwks_lists_every_published_key_once() {
        let app = app(true).await;
        let (status, headers, body) = fetch(&app, JWKS_PATH).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(headers[header::ACCESS_CONTROL_ALLOW_ORIGIN], "*");
        let set: PublicJwkSet = serde_json::from_slice(&body).unwrap();
        let keys = &set.keys;
        let algs: HashSet<&str> = keys.iter().map(|k| k.alg.as_str()).collect();
        assert_eq!(
            algs,
            HashSet::from(["ES256", "RS256"]),
            "both advertised algorithms"
        );
        let kids: HashSet<&str> = keys.iter().map(|k| k.kid.as_str()).collect();
        assert_eq!(kids.len(), keys.len(), "distinct kids (RFC 7517 §4.5)");
        for key in keys {
            assert_eq!(key.usage, "sig");
            match key.kty.as_str() {
                "EC" => assert!(key.crv.is_some() && key.x.is_some() && key.y.is_some()),
                "RSA" => assert!(key.n.is_some() && key.e.is_some()),
                other => panic!("unexpected key type {other}"),
            }
        }
    }

    #[tokio::test]
    async fn not_ready_until_keys_exist() {
        let ready = app(true).await;
        let app = app(false).await;
        assert_eq!(
            fetch(&app, "/readyz").await.0,
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            fetch(&app, JWKS_PATH).await.0,
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(fetch(&app, "/healthz").await.0, StatusCode::OK);
        assert_eq!(fetch(&ready, "/readyz").await.0, StatusCode::OK);
    }

    #[tokio::test]
    async fn unknown_paths_and_methods() {
        let app = app(true).await;
        let (status, headers, body) = fetch(&app, "/nope").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(headers[header::CONTENT_TYPE], "text/plain; charset=utf-8");
        assert_eq!(headers[header::X_CONTENT_TYPE_OPTIONS], "nosniff");
        assert_eq!(body, "Not found.");
        let post = Request::builder()
            .method(Method::POST)
            .uri(JWKS_PATH)
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(post).await.unwrap();
        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
        // RFC 9110 §15.5.6: a 405 response MUST include Allow.
        assert!(response.headers().get(header::ALLOW).is_some());
    }
}
