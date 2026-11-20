//! Setup links and invitations through the Kubernetes HTTP API, against a fake API server.

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use axum::body::Body;
    use axum::extract::State;
    use axum::http::{Method, Request, StatusCode};
    use axum::response::{IntoResponse as _, Response};
    use axum::{Json, Router};
    use http_body_util::BodyExt as _;
    use k8s_openapi::api::core::v1::{Event, Secret};
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::{ListMeta, OwnerReference};
    use kube::Resource;
    use kube::api::ObjectMeta;
    use kube::core::{ObjectList, Status, TypeMeta};
    use serde::Serialize;
    use serde::de::DeserializeOwned;
    use zeabur_identity_api::USER_LABEL;
    use zeabur_identity_api::credential::{Credential, CredentialKind, CredentialSpec, Passkey};
    use zeabur_identity_api::invitation::Invitation;
    use zeabur_identity_api::user::{AccountType, User as UserObject, UserSpec};
    use zeabur_identity_core::clock::UnixTime;
    use zeabur_identity_core::config::BaseUrl;
    use zeabur_identity_k8s::invitations::{Invitee, invite};
    use zeabur_identity_k8s::setup::{LinkError, MAX_VALID_FOR, issue_setup_link};

    const NOW: u64 = 1_800_000_000;

    #[derive(Default)]
    struct Backend {
        /// Credentials of alice, as listed.
        credentials: Vec<Credential>,
        /// Writes, as `(method, last path segment)`, in order.
        writes: Vec<(Method, String)>,
        /// Events created.
        events: Vec<Event>,
        /// Refuse to create events.
        refuse_events: bool,
    }

    /// A `Status` with the `kind` that clients look for.
    #[derive(Serialize)]
    struct StatusBody {
        #[serde(flatten)]
        types: TypeMeta,
        #[serde(flatten)]
        status: Status,
    }

    fn status(code: StatusCode, status: Status) -> Response {
        (code, Json(status_body(status.with_code(code.as_u16())))).into_response()
    }

    fn status_body(status: Status) -> StatusBody {
        StatusBody {
            types: TypeMeta {
                api_version: "v1".into(),
                kind: "Status".into(),
            },
            status,
        }
    }

    fn ok<T: Serialize>(value: &T) -> Response {
        (StatusCode::OK, Json(value)).into_response()
    }

    /// The object as the API server stores a new one.
    fn store_new<T: Resource + DeserializeOwned + Serialize>(bytes: &[u8]) -> Response {
        let mut object: T = serde_json::from_slice(bytes).unwrap();
        object.meta_mut().uid = Some("uid-object".into());
        object.meta_mut().resource_version = Some("1".into());
        (StatusCode::CREATED, Json(object)).into_response()
    }

    async fn kubernetes(
        State(state): State<Arc<Mutex<Backend>>>,
        request: Request<Body>,
    ) -> Response {
        let method = request.method().clone();
        let path = request.uri().path().to_owned();
        let bytes = request.into_body().collect().await.unwrap().to_bytes();
        let segment = path.rsplit('/').next().unwrap().to_owned();
        if method != Method::GET {
            let write = (method.clone(), segment.clone());
            state.lock().unwrap().writes.push(write);
        }
        let not_found = || {
            status(
                StatusCode::NOT_FOUND,
                Status::failure("not found", "NotFound"),
            )
        };
        match (method, segment.as_str()) {
            (Method::GET, "alice") => {
                let mut user = UserObject::new(
                    "alice",
                    UserSpec {
                        username: "alice".into(),
                        ..UserSpec::default()
                    },
                );
                user.metadata.uid = Some("uid-alice".into());
                ok(&user)
            }
            (Method::GET, "credentials") => ok(&ObjectList {
                types: TypeMeta {
                    api_version: "identity.zeabur.com/v1alpha1".into(),
                    kind: "CredentialList".into(),
                },
                metadata: ListMeta::default(),
                items: state.lock().unwrap().credentials.clone(),
            }),
            (Method::DELETE, "invitations" | "grants") => ok(&status_body(Status::success())),
            (Method::DELETE, "credentials") => {
                state.lock().unwrap().credentials.clear();
                ok(&status_body(Status::success()))
            }
            (Method::GET, "zeabur-identity-setup") => not_found(),
            (Method::POST, "secrets") => store_new::<Secret>(&bytes),
            (Method::POST, "invitations") => store_new::<Invitation>(&bytes),
            (Method::POST, "events") => {
                let mut state = state.lock().unwrap();
                if state.refuse_events {
                    return status(
                        StatusCode::FORBIDDEN,
                        Status::failure("forbidden", "Forbidden"),
                    );
                }
                state.events.push(serde_json::from_slice(&bytes).unwrap());
                drop(state);
                (
                    StatusCode::CREATED,
                    [(axum::http::header::CONTENT_TYPE, "application/json")],
                    bytes,
                )
                    .into_response()
            }
            unexpected => panic!("unexpected Kubernetes request: {unexpected:?} {path}"),
        }
    }

    fn credential(owner: &str) -> Credential {
        let mut object = Credential::new(
            &format!("cred-{owner}"),
            CredentialSpec {
                user: "alice".into(),
                kind: CredentialKind::Passkey(Passkey {
                    credential_id: "YWJj".into(),
                    record: "{}".into(),
                    backup_eligible: false,
                    aaguid: None,
                    label: None,
                }),
            },
        );
        object.metadata = ObjectMeta {
            name: object.metadata.name,
            labels: Some(BTreeMap::from([(
                USER_LABEL.to_owned(),
                "alice".to_owned(),
            )])),
            owner_references: Some(vec![OwnerReference {
                api_version: "identity.zeabur.com/v1alpha1".into(),
                kind: "User".into(),
                name: "alice".into(),
                uid: owner.into(),
                controller: None,
                block_owner_deletion: None,
            }]),
            ..ObjectMeta::default()
        };
        object
    }

    async fn fake(credentials: Vec<Credential>) -> (kube::Client, Arc<Mutex<Backend>>) {
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
                .find(|event| event.reason.as_deref() == Some(reason))
                .unwrap_or_else(|| panic!("{link:?}: no {reason} event in {events:?}"));
            let user = &event.involved_object;
            assert_eq!(
                (
                    user.kind.as_deref(),
                    user.name.as_deref(),
                    user.uid.as_deref()
                ),
                (Some("User"), Some("alice"), Some("uid-alice")),
                "{link:?}"
            );
            assert!(
                event.message.as_deref().unwrap().contains("reset=true"),
                "{link:?}: {event:?}"
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
