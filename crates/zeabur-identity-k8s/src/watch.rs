//! A kube-runtime [`watcher()`] that relists when the API server answers a watch with `410 Gone`.
//!
//! kube-runtime relists only on a `410 Gone` *watch event*. When the API server answers the watch
//! request itself with `410 Gone` (a `resourceVersion` it no longer has, for example after a
//! restart), kube-client 5 returns `Error::Api` and the watcher reports `WatchStartFailed`, then
//! reconnects with the same stale `resourceVersion` and fails the same way forever. Older
//! kube-client versions read the body as watch events instead, which gives `WatchFailed` with
//! `Error::Api` or, for an indented `Status`, `Error::SerdeError`. This wrapper starts a new
//! watcher, and with it a fresh `LIST`, on any of these errors.
use std::fmt::Debug;

use futures_util::stream::{self, BoxStream};
use futures_util::{Stream, StreamExt as _};
use kube::api::Api;
use kube::runtime::watcher::{self, Event, watcher};
use kube::{Error, Resource};
use serde::de::DeserializeOwned;

/// [`watcher()`] that starts over with a fresh `LIST` after a response it cannot follow.
pub fn relisting_watcher<K>(
    api: Api<K>,
    config: watcher::Config,
) -> impl Stream<Item = watcher::Result<Event<K>>> + Send
where
    K: Resource + Clone + DeserializeOwned + Debug + Send + 'static,
{
    let start = |api: &Api<K>, config: &watcher::Config| -> BoxStream<'static, _> {
        watcher(api.clone(), config.clone()).boxed()
    };
    let events = start(&api, &config);
    stream::unfold(
        (api, config, events),
        move |(api, config, mut events)| async move {
            let event = events.next().await?;
            if let Err(error) = &event
                && must_relist(error)
            {
                events = start(&api, &config);
            }
            Some((event, (api, config, events)))
        },
    )
}

fn must_relist(error: &watcher::Error) -> bool {
    match error {
        watcher::Error::WatchStartFailed(Error::Api(status))
        | watcher::Error::WatchFailed(Error::Api(status)) => status.code == 410,
        watcher::Error::WatchFailed(Error::SerdeError(_)) => true,
        watcher::Error::WatchFailed(_)
        | watcher::Error::InitialListFailed(_)
        | watcher::Error::WatchStartFailed(_)
        | watcher::Error::WatchError(_)
        | watcher::Error::NoResourceVersion => false,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use axum::Router;
    use axum::body::Body;
    use axum::extract::State;
    use axum::http::{Request, StatusCode};
    use axum::response::{IntoResponse as _, Response};
    use k8s_openapi::api::core::v1::ConfigMap;
    use serde_json::json;

    use super::*;

    /// Requests seen by the mock: `None` for a `LIST`, the `resourceVersion` for a watch.
    type Seen = Arc<Mutex<Vec<Option<String>>>>;

    #[derive(Clone)]
    struct Mock {
        seen: Seen,
        gone: Arc<String>,
    }

    async fn api_server(State(mock): State<Mock>, request: Request<Body>) -> Response {
        let query = request.uri().query().unwrap_or_default().to_owned();
        let params: Vec<(String, String)> = form_urlencoded::parse(query.as_bytes())
            .into_owned()
            .collect();
        let param = |name: &str| {
            params
                .iter()
                .find(|(key, _)| key == name)
                .map(|(_, value)| value.clone())
        };
        let watches = {
            let mut seen = mock.seen.lock().unwrap();
            seen.push(
                (param("watch").as_deref() == Some("true"))
                    .then(|| param("resourceVersion").unwrap_or_default()),
            );
            seen.iter().filter(|request| request.is_some()).count()
        };
        if param("watch").is_none() {
            return axum::Json(json!({"apiVersion":"v1", "kind":"ConfigMapList",
                "metadata":{"resourceVersion":"100"},
                "items":[{"metadata":{"name":"a", "namespace":"test", "resourceVersion":"99"}}]}))
            .into_response();
        }
        if watches == 1 {
            return (StatusCode::GONE, mock.gone.as_str().to_owned()).into_response();
        }
        Body::from_stream(stream::pending::<Result<String, std::io::Error>>()).into_response()
    }

    async fn relists_after(gone: String) {
        let seen = Seen::default();
        let mock = Mock {
            seen: Arc::clone(&seen),
            gone: Arc::new(gone),
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let app = Router::new().fallback(api_server).with_state(mock);
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let client = kube::Client::try_from(kube::Config::new(
            format!("http://{address}").parse().unwrap(),
        ))
        .unwrap();
        let api: Api<ConfigMap> = Api::namespaced(client, "test");
        let mut events = relisting_watcher(api, watcher::Config::default()).boxed();
        let mut errors = 0;
        let mut init_done = 0;
        tokio::time::timeout(Duration::from_secs(10), async {
            while init_done < 2 {
                match events.next().await.unwrap() {
                    Ok(Event::InitDone) => init_done += 1,
                    Ok(_) => {}
                    Err(_) => errors += 1,
                }
            }
        })
        .await
        .expect("watcher did not relist");
        server.abort();
        assert_eq!(errors, 1);
        // Without the relist, the watcher reconnects at the stale version instead of listing.
        assert_eq!(
            seen.lock().unwrap()[..3],
            [None, Some("100".to_owned()), None]
        );
    }

    fn gone() -> serde_json::Value {
        json!({"kind":"Status", "apiVersion":"v1", "metadata":{}, "status":"Failure",
            "message":"too old resource version: 100 (200)", "reason":"Expired",
            "details":{"group":"identity.zeabur.com", "kind":"grants"}, "code":410})
    }

    #[tokio::test]
    async fn relists_after_an_indented_status_response() {
        relists_after(serde_json::to_string_pretty(&gone()).unwrap()).await;
    }

    #[tokio::test]
    async fn relists_after_a_gone_status_response() {
        relists_after(gone().to_string()).await;
    }
}
