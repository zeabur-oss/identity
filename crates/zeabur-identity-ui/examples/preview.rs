//! Serves every page state with made-up data, for looking at the pages in a browser:
//! `cargo run -p zeabur-identity-ui --example preview`, then open <http://localhost:8090/>.
//! Add `?lang=zh-TW` or `?lang=zh-CN` to any page.

use std::time::Duration;

use axum::Router;
use axum::extract::{Path, RawQuery};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use zeabur_identity_ui::pages::{
    AccountView, AppLink, ErrorReason, LinkedRow, PasskeyRow, ProviderButton, SessionRow, Storage,
    account_page, error_page, login_page, notice_page, page_lang, setup_page,
};

const GITHUB: ProviderButton<'static> = ProviderButton {
    id: "github",
    label: "GitHub",
    icon: "GithubLogo",
};
const PROVIDERS: [ProviderButton<'static>; 1] = [GITHUB];
/// Several providers of any kind, one with a display name at the 64-character limit.
const MANY: [ProviderButton<'static>; 4] = [
    ProviderButton {
        id: "keycloak",
        label: "Company SSO",
        icon: "SignIn",
    },
    GITHUB,
    ProviderButton {
        id: "google",
        label: "Google",
        icon: "GoogleLogo",
    },
    ProviderButton {
        id: "partners",
        label: "Partner Directory for Contractors and External Collaborators, EU",
        icon: "SignIn",
    },
];
const LINKED: [LinkedRow<'static>; 1] = [LinkedRow {
    name: "cred-github",
    provider: GITHUB,
    linked: Some(1_791_500_000),
}];
const APPS: [AppLink<'static>; 2] = [
    AppLink {
        name: "Zeabur",
        url: "https://zeabur.example.com/",
    },
    AppLink {
        name: "Grafana",
        url: "https://grafana.example.com/",
    },
];
const REASONS: [(&str, ErrorReason, &str); 16] = [
    (
        "admin-needs-passkey",
        ErrorReason::AdminNeedsPasskey,
        "admin_needs_passkey (github)",
    ),
    (
        "request-expired",
        ErrorReason::RequestExpired,
        "invalid_request_uri: The request_uri is invalid, expired, or already used. Start the sign-in again.",
    ),
    (
        "state-mismatch",
        ErrorReason::StateMismatch,
        "invalid_state (github)",
    ),
    (
        "malformed",
        ErrorReason::MalformedRequest,
        "invalid_request: A parameter appears more than once. Send each parameter once.",
    ),
    (
        "unknown-client",
        ErrorReason::UnknownClient,
        "invalid_request: The client_id is missing or not registered.",
    ),
    (
        "redirect-uri",
        ErrorReason::RedirectUri,
        "invalid_request: This redirect_uri is not registered for the client.",
    ),
    (
        "provider-denied",
        ErrorReason::ProviderDenied,
        "provider_denied (github)",
    ),
    (
        "provider-failed",
        ErrorReason::ProviderFailed,
        "provider_verification_failed (google)",
    ),
    (
        "clock-skew",
        ErrorReason::ClockSkew,
        "provider_verification_failed (google): the provider's ID token is not valid: expired",
    ),
    (
        "not-linked",
        ErrorReason::AccountNotLinked,
        "account_unlinked (github)",
    ),
    (
        "already-linked",
        ErrorReason::AccountAlreadyLinked,
        "account_already_linked (github)",
    ),
    (
        "account-session",
        ErrorReason::AccountSessionEnded,
        "session_mismatch (github)",
    ),
    (
        "user-unavailable",
        ErrorReason::UserUnavailable,
        "user_unavailable (google)",
    ),
    (
        "setup-link",
        ErrorReason::SetupLinkInvalid,
        "setup_already_used (github)",
    ),
    (
        "server",
        ErrorReason::ServerError,
        "server_error: Internal error. Try again.",
    ),
    (
        "other",
        ErrorReason::Other,
        "unsupported_response_type: Only response_type=code is supported.",
    ),
];

fn lang(query: Option<&str>, headers: &HeaderMap) -> zeabur_identity_ui::i18n::Lang {
    page_lang(query, headers)
}

async fn index() -> Html<String> {
    let pages = [
        "/login",
        "/login/apps",
        "/login/request",
        "/login/ending",
        "/login/hint",
        "/login/no-providers",
        "/login/many",
        "/setup",
        "/setup/many",
        "/setup#token=preview",
        "/linked",
        "/account",
        "/account/one",
        "/account/linked",
        "/account/admin",
        "/account/signed-out",
    ]
    .map(String::from);
    let errors = REASONS.iter().map(|(name, ..)| format!("/error/{name}"));
    let mut links = String::new();
    for path in pages.into_iter().chain(errors) {
        for part in ["<li><a href=\"", &path, "\">", &path, "</a></li>"] {
            links.push_str(part);
        }
    }
    Html(format!(
        "<!doctype html><title>Pages</title><ul>{links}</ul>"
    ))
}

const PENDING: Duration = Duration::from_mins(10);

async fn login(Path(state): Path<String>, RawQuery(q): RawQuery, h: HeaderMap) -> Response {
    let lang = lang(q.as_deref(), &h);
    match state.as_str() {
        "apps" => login_page(lang, None, None, &PROVIDERS, &APPS),
        "request" => login_page(lang, Some(("Zeabur", PENDING)), None, &PROVIDERS, &APPS),
        // The request ends a few seconds after the page loads.
        "ending" => login_page(
            lang,
            Some(("Zeabur", Duration::from_secs(5))),
            None,
            &PROVIDERS,
            &APPS,
        ),
        "hint" => login_page(
            lang,
            Some(("Zeabur", PENDING)),
            Some("admin"),
            &PROVIDERS,
            &[],
        ),
        "no-providers" => login_page(lang, Some(("Zeabur", PENDING)), None, &[], &[]),
        "many" => login_page(lang, Some(("Zeabur", PENDING)), None, &MANY, &[]),
        _ => StatusCode::NOT_FOUND.into_response(),
    }
}

const PASSKEYS: [PasskeyRow<'static>; 3] = [
    PasskeyRow {
        name: "cred-1",
        label: Some("Work laptop"),
        added: Some(1_790_000_000),
        last_used: Some(1_792_000_000),
        storage: Storage::Synced,
        this_device: true,
    },
    PasskeyRow {
        name: "cred-2",
        label: Some("YubiKey 5 on the office keyring, the blue one"),
        added: Some(1_780_000_000),
        last_used: None,
        storage: Storage::OneDevice,
        this_device: false,
    },
    PasskeyRow {
        name: "cred-3",
        label: None,
        added: None,
        last_used: None,
        storage: Storage::Unknown,
        this_device: false,
    },
];
const SESSIONS: [SessionRow<'static>; 3] = [
    SessionRow {
        name: "s-1",
        app: None,
        signed_in: 1_792_000_000,
        credential: Some("Apple Passwords"),
        current: true,
    },
    SessionRow {
        name: "g-1",
        app: Some("Grafana"),
        signed_in: 1_791_000_000,
        credential: Some("YubiKey 5 on the office keyring, the blue one"),
        current: false,
    },
    SessionRow {
        name: "g-2",
        app: Some("kubectl"),
        signed_in: 1_790_500_000,
        credential: None,
        current: false,
    },
];

async fn account(Path(state): Path<String>, RawQuery(q): RawQuery, h: HeaderMap) -> Response {
    let lang = lang(q.as_deref(), &h);
    let view = |passkeys, linked, admin| AccountView {
        username: "admin",
        passkeys,
        linked,
        providers: &MANY,
        admin,
        sessions: &SESSIONS,
    };
    match state.as_str() {
        "all" => account_page(lang, Some(view(&PASSKEYS, &[], false))),
        "one" => account_page(lang, Some(view(&PASSKEYS[..1], &[], false))),
        "linked" => account_page(lang, Some(view(&PASSKEYS[..1], &LINKED, false))),
        "admin" => account_page(lang, Some(view(&PASSKEYS[..1], &LINKED, true))),
        "signed-out" => account_page(lang, None),
        _ => StatusCode::NOT_FOUND.into_response(),
    }
}

/// A challenge the browser can wait on for passkey autofill; nothing ever completes it.
async fn login_options() -> Response {
    (
        [(header::CONTENT_TYPE, "application/json")],
        r#"{"publicKey":{"challenge":"AAAAAAAAAAAAAAAAAAAAAA","timeout":600000,"rpId":"localhost","userVerification":"required"}}"#,
    )
        .into_response()
}

async fn setup_options() -> Response {
    (
        StatusCode::BAD_REQUEST,
        [(header::CONTENT_TYPE, "application/problem+json")],
        r#"{"type":"urn:zeabur-identity:problem:setup-invalid","title":"","status":400}"#,
    )
        .into_response()
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let app = Router::new()
        .route("/", get(index))
        .route(
            "/login",
            get(|RawQuery(q): RawQuery, h: HeaderMap| async move {
                login_page(lang(q.as_deref(), &h), None, None, &PROVIDERS, &[])
            }),
        )
        .route("/login/{state}", get(login))
        .route("/login/options", post(login_options))
        .route(
            "/setup",
            get(|RawQuery(q): RawQuery, h: HeaderMap| async move {
                setup_page(lang(q.as_deref(), &h), None, &PROVIDERS, &APPS)
            }),
        )
        .route(
            "/setup/many",
            get(|RawQuery(q): RawQuery, h: HeaderMap| async move {
                setup_page(lang(q.as_deref(), &h), None, &MANY, &APPS)
            }),
        )
        .route("/setup/options", post(setup_options))
        .route(
            "/account",
            get(|q: RawQuery, h: HeaderMap| account(Path("all".to_owned()), q, h)),
        )
        .route("/account/{state}", get(account))
        .route(
            "/linked",
            get(|RawQuery(q): RawQuery, h: HeaderMap| async move {
                let lang = lang(q.as_deref(), &h);
                let m = lang.messages();
                notice_page(lang, m.upstream_linked_title, m.upstream_linked_body, &APPS)
            }),
        )
        .route(
            "/error/{reason}",
            get(
                |Path(name): Path<String>, RawQuery(q): RawQuery, h: HeaderMap| async move {
                    REASONS.iter().find(|(n, ..)| *n == name).map_or_else(
                        || StatusCode::NOT_FOUND.into_response(),
                        |(_, reason, detail)| error_page(lang(q.as_deref(), &h), *reason, detail),
                    )
                },
            ),
        )
        .merge(zeabur_identity_ui::assets::router());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:8090").await?;
    axum::serve(listener, app).await
}
