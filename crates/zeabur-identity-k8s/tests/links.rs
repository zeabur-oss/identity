//! Setup links and invitations through the Kubernetes HTTP API, against a fake API server.

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use axum::body::Body;
    use axum::extract::State;
    use axum::http::{Method, Request, StatusCode};
    use axum::{Json, Router};
    use http_body_util::BodyExt as _;
    use serde_json::{Value, json};
    use zeabur_identity_api::user::AccountType;
    use zeabur_identity_core::clock::UnixTime;
    use zeabur_identity_core::config::BaseUrl;
    use zeabur_identity_k8s::invitations::{Invitee, invite};
    use zeabur_identity_k8s::setup::{LinkError, MAX_VALID_FOR, issue_setup_link};

    const NOW: u64 = 1_800_000_000;

    #[derive(Default)]
    struct Backend {
        /// Credentials of alice, as listed.
        credentials: Vec<Value>,
        /// Writes, as `(method, last path segment)`, in order.
        writes: Vec<(Method, String)>,
        /// Events created.
        events: Vec<Value>,
        /// Refuse to create events.
        refuse_events: bool,
    }

    async fn kubernetes(
        State(state): State<Arc<Mutex<Backend>>>,
        request: Request<Body>,
    ) -> (StatusCode, Json<Value>) {
        let method = request.method().clone();
        let path = request.uri().path().to_owned();
        let bytes = request.into_body().collect().await.unwrap().to_bytes();
        let body: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        let segment = path.rsplit('/').next().unwrap().to_owned();
        if method != Method::GET {
            let write = (method.clone(), segment.clone());
            state.lock().unwrap().writes.push(write);
        }
        let ok = |value| (StatusCode::OK, Json(value));
        let not_found = || {
            (
                StatusCode::NOT_FOUND,
                Json(json!({"apiVersion":"v1","kind":"Status","status":"Failure",
                    "code":404,"reason":"NotFound","message":"not found"})),
            )
        };
        match (method, segment.as_str()) {
            (Method::GET, "alice") => ok(json!({"apiVersion":"identity.zeabur.com/v1alpha1",
                "kind":"User", "metadata":{"name":"alice","uid":"uid-alice"},
                "spec":{"username":"alice","accountType":"Regular","disabled":false}})),
            (Method::GET, "credentials") => ok(json!({"apiVersion":"identity.zeabur.com/v1alpha1",
                "kind":"CredentialList","metadata":{},"items":state.lock().unwrap().credentials})),
            (Method::DELETE, "invitations" | "grants") => {
                ok(json!({"apiVersion":"v1","kind":"Status","status":"Success"}))
            }
            (Method::DELETE, "credentials") => {
                state.lock().unwrap().credentials.clear();
                ok(json!({"apiVersion":"v1","kind":"Status","status":"Success"}))
            }
            (Method::GET, "zeabur-identity-setup") => not_found(),
            (Method::POST, "secrets" | "invitations") => {
                let mut object = body;
                object["metadata"]["uid"] = json!("uid-object");
                object["metadata"]["resourceVersion"] = json!("1");
                (StatusCode::CREATED, Json(object))
            }
            (Method::POST, "events") => {
                let mut state = state.lock().unwrap();
                if state.refuse_events {
                    return (
                        StatusCode::FORBIDDEN,
                        Json(json!({"apiVersion":"v1","kind":"Status","status":"Failure",
                            "code":403,"reason":"Forbidden","message":"forbidden"})),
                    );
                }
                state.events.push(body.clone());
                drop(state);
                (StatusCode::CREATED, Json(body))
            }
            unexpected => panic!("unexpected Kubernetes request: {unexpected:?} {path}"),
        }
    }

    fn credential(owner: &str) -> Value {
        json!({"metadata":{"name":format!("cred-{owner}"),
            "labels":{"identity.zeabur.com/user":"alice"},
            "ownerReferences":[{"apiVersion":"identity.zeabur.com/v1alpha1","kind":"User",
                "name":"alice","uid":owner}]},
            "spec":{"user":"alice","type":"Passkey",
                "passkey":{"credentialId":"YWJj","record":"{}","backupEligible":false}}})
    }

    async fn fake(credentials: Vec<Value>) -> (kube::Client, Arc<Mutex<Backend>>) {
        let state = Arc::new(Mutex::new(Backend {
            credentials,
            ..Backend::default()
        }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let app = Router::new()
            .fallback(kubernetes)
            .with_state(Arc::clone(&state));
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let client = kube::Client::try_from(kube::Config::new(
            format!("http://{address}").parse().unwrap(),
        ))
        .unwrap();
        (client, state)
    }

    fn issuer() -> BaseUrl {
        BaseUrl::parse("issuer", "https://login.example.com").unwrap()
    }

    fn alice() -> Invitee {
        Invitee {
            username: "alice".into(),
            display_name: None,
            groups: vec![],
            account_type: AccountType::Regular,
        }
    }

    #[derive(Clone, Copy, Debug)]
    enum Link {
        Setup,
        Invitation,
    }

    async fn issue(
        client: kube::Client,
        link: Link,
        valid_for: Duration,
        reset: bool,
    ) -> Result<String, LinkError> {
        let now = UnixTime::from_secs(NOW);
        match link {
            Link::Setup => {
                issue_setup_link(client, "test", &issuer(), "alice", valid_for, reset, now)
                    .await
                    .map(|link| link.url)
            }
            Link::Invitation => invite(client, "test", &issuer(), &alice(), valid_for, reset, now)
                .await
                .map(|invited| invited.url),
        }
    }

    fn created(writes: &[(Method, String)], collection: &str) -> bool {
        writes
            .iter()
            .any(|(method, segment)| *method == Method::POST && segment == collection)
    }

    fn stored(link: Link) -> &'static str {
        match link {
            Link::Setup => "secrets",
            Link::Invitation => "invitations",
        }
    }

    #[tokio::test]
    async fn a_user_who_can_sign_in_gets_a_link_only_with_reset() {
        for link in [Link::Setup, Link::Invitation] {
            let (client, state) = fake(vec![credential("uid-alice")]).await;
            let error = issue(client.clone(), link, Duration::from_hours(1), false)
                .await
                .unwrap_err();
            assert!(
                matches!(error, LinkError::HasCredentials { count: 1, .. }),
                "{link:?}: {error}"
            );
            assert!(state.lock().unwrap().writes.is_empty(), "{link:?}");

            let url = issue(client, link, Duration::from_hours(1), true)
                .await
                .unwrap();
            assert!(url.starts_with("https://login.example.com/setup#token="));
            let writes = state.lock().unwrap().writes.clone();
            let deletes: Vec<_> = writes
                .iter()
                .take_while(|(method, _)| *method == Method::DELETE)
                .map(|(_, segment)| segment.as_str())
                .collect();
            assert_eq!(
                deletes,
                ["invitations", "credentials", "grants"],
                "{link:?}"
            );
            assert!(created(&writes, stored(link)), "{link:?}");
        }
    }

    #[tokio::test]
    async fn credentials_of_an_earlier_user_of_that_name_do_not_count() {
        for link in [Link::Setup, Link::Invitation] {
            let (client, state) = fake(vec![credential("uid-old")]).await;
            issue(client, link, Duration::from_hours(1), false)
                .await
                .unwrap();
            assert!(
                created(&state.lock().unwrap().writes, stored(link)),
                "{link:?}"
            );
        }
    }

    #[tokio::test]
    async fn links_stay_valid_for_at_most_seven_days() {
        for link in [Link::Setup, Link::Invitation] {
            let (client, state) = fake(Vec::new()).await;
            let error = issue(
                client.clone(),
                link,
                MAX_VALID_FOR + Duration::from_secs(1),
                false,
            )
            .await
            .unwrap_err();
            assert!(matches!(error, LinkError::TooLong), "{link:?}: {error}");
            assert!(state.lock().unwrap().writes.is_empty(), "{link:?}");

            issue(client, link, Duration::from_hours(7 * 24), false)
                .await
                .unwrap();
            assert!(
                created(&state.lock().unwrap().writes, stored(link)),
                "{link:?}"
            );
        }
    }

    #[tokio::test]
    async fn issuing_a_link_records_an_event_on_the_user() {
        for (link, reason) in [
            (Link::Setup, "SetupLinkIssued"),
            (Link::Invitation, "InvitationIssued"),
        ] {
            let (client, state) = fake(vec![credential("uid-alice")]).await;
            issue(client, link, Duration::from_hours(1), true)
                .await
                .unwrap();
            let events = state.lock().unwrap().events.clone();
            let event = events
                .iter()
                .find(|event| event["reason"] == reason)
                .unwrap_or_else(|| panic!("{link:?}: no {reason} event in {events:?}"));
            let user = &event["involvedObject"];
            assert_eq!(
                (&user["kind"], &user["name"], &user["uid"]),
                (&json!("User"), &json!("alice"), &json!("uid-alice")),
                "{link:?}"
            );
            assert!(
                event["message"].as_str().unwrap().contains("reset=true"),
                "{link:?}: {event}"
            );
        }
    }

    #[tokio::test]
    async fn a_link_whose_event_fails_is_not_shown() {
        for link in [Link::Setup, Link::Invitation] {
            let (client, state) = fake(Vec::new()).await;
            state.lock().unwrap().refuse_events = true;
            let error = issue(client, link, Duration::from_hours(1), false)
                .await
                .unwrap_err();
            assert!(matches!(error, LinkError::Event(_)), "{link:?}: {error}");
        }
    }
}
