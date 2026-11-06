//! `GET /login`, `GET /setup` and the embedded assets: the routes in front of the page rendering
//! in [`zeabur_identity_ui`].

use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::extract::{RawQuery, State};
use axum::http::HeaderMap;
use axum::response::Response;
use axum::routing::get;
use zeabur_identity_core::clock::Clock;
use zeabur_identity_oauth::AuthorizationServer;
use zeabur_identity_oauth::authorize::Flow;
use zeabur_identity_oauth::endpoints::{FLOW_COOKIE, open_flow};
use zeabur_identity_store::{App, Directory, GrantStore};
use zeabur_identity_ui::pages::{AppLink, ProviderButton, login_page, page_lang, setup_page};

use crate::cookie;
use crate::upstream::provider::Providers;

type Shared<D, G, C> = (Arc<AuthorizationServer<D, G, C>>, Arc<Providers>);

/// The page routes and `/assets/{name}`. `providers` are the upstream providers offered.
pub fn router<D: Directory, G: GrantStore, C: Clock>(
    server: Arc<AuthorizationServer<D, G, C>>,
    providers: Arc<Providers>,
) -> Router {
    Router::new()
        .route("/login", get(login::<D, G, C>))
        .route("/setup", get(setup::<D, G, C>))
        .with_state((server, providers))
        .merge(zeabur_identity_ui::assets::router())
}

async fn login<D: Directory, G: GrantStore, C: Clock>(
    State((server, providers)): State<Shared<D, G, C>>,
    RawQuery(query): RawQuery,
    headers: HeaderMap,
) -> Response {
    let lang = page_lang(query.as_deref(), &headers);
    let pending = pending(&server, &headers).await;
    // The page swaps the form for the app links once the request expires.
    let expires_in = pending.as_ref().map(|(flow, _)| {
        Duration::from_secs(
            flow.expires_at
                .as_secs()
                .saturating_sub(server.now().as_secs()),
        )
    });
    let client = pending.as_ref().map(|(_, client)| client.as_str());
    let login_hint = pending
        .as_ref()
        .and_then(|(flow, _)| flow.request.login_hint.as_deref());
    let apps = server.directory.apps();
    let providers = providers.all();
    let buttons: Vec<ProviderButton<'_>> = providers.iter().map(|p| p.button()).collect();
    login_page(
        lang,
        client.zip(expires_in),
        login_hint,
        &buttons,
        &links(&apps),
    )
}

async fn setup<D: Directory, G: GrantStore, C: Clock>(
    State((server, providers)): State<Shared<D, G, C>>,
    RawQuery(query): RawQuery,
    headers: HeaderMap,
) -> Response {
    let pending = pending(&server, &headers).await;
    let apps = server.directory.apps();
    let providers = providers.all();
    let buttons: Vec<ProviderButton<'_>> = providers.iter().map(|p| p.button()).collect();
    setup_page(
        page_lang(query.as_deref(), &headers),
        pending.as_ref().map(|(_, client)| client.as_str()),
        &buttons,
        &links(&apps),
    )
}

/// The sign-in request in progress in this browser and its client's name, if any.
async fn pending<D: Directory, G: GrantStore, C: Clock>(
    server: &AuthorizationServer<D, G, C>,
    headers: &HeaderMap,
) -> Option<(Flow, String)> {
    let flow = cookie(headers, FLOW_COOKIE).and_then(|sealed| open_flow(server, sealed))?;
    match server.directory.client(&flow.request.client_id).await {
        Ok(Some(client)) => {
            let name = client.name().to_owned();
            Some((flow, name))
        }
        Ok(None) => None,
        Err(error) => {
            tracing::error!(reason = "client_lookup_failed", %error, "client lookup failed");
            None
        }
    }
}

/// Links for `apps`; only `https` addresses, whatever the storage holds.
pub(crate) fn links(apps: &[App]) -> Vec<AppLink<'_>> {
    apps.iter()
        .filter(|app| app.url.starts_with("https://"))
        .map(|app| AppLink {
            name: &app.name,
            url: &app.url,
        })
        .collect()
}
