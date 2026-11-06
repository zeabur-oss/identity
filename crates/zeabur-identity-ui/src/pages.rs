//! Rendering the pages: sign-in, enrolment, errors and notices. Routing and the data behind each
//! page belong to the caller.

use std::time::Duration;

use askama::Template;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{Html, IntoResponse, Response};

use super::assets::{VERSIONS, Versions};
use super::harden;
use super::i18n::{ErrorText, Lang, Messages};

/// A "Continue with …" button for an upstream identity provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProviderButton<'a> {
    /// Path segment of the provider's routes, for example `github`.
    pub id: &'a str,
    /// Name shown on the button.
    pub label: &'a str,
    /// Icon name (see `templates/icons.html`).
    pub icon: &'static str,
}

/// An application the page offers to open, from its client's home URL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AppLink<'a> {
    /// The client's display name.
    pub name: &'a str,
    /// Where it opens.
    pub url: &'a str,
}

/// Commands the pages show. They run with the cluster admin's kubeconfig, on the server for a
/// single-server install, with `ZEABUR_IDENTITY_ISSUER` set as in the getting-started guide.
const SETUP_LINK_COMMAND: &str = "zeabur-identityctl setup-link --username <name>";
const RESET_COMMAND: &str = "zeabur-identityctl setup-link --username <name> --reset";
const INVITE_COMMAND: &str = "zeabur-identityctl invite --username <name>";
const LOGS_COMMAND: &str = "kubectl -n zeabur-identity logs deploy/zeabur-identity --tail=100";
const CLOCK_COMMAND: &str = "timedatectl status";

/// Why a sign-in stopped, as the error page explains it: a title, the cause and the next step,
/// with the raw detail behind a disclosure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorReason {
    /// The pending sign-in or pushed request expired, was used, or belongs to another browser.
    RequestExpired,
    /// An upstream provider's answer does not match this browser's pending request (`state`
    /// or the sealed cookie).
    StateMismatch,
    /// The authorization request cannot be parsed.
    MalformedRequest,
    /// The `client_id` is missing or not registered.
    UnknownClient,
    /// The `redirect_uri` is missing or not registered for the client.
    RedirectUri,
    /// The upstream provider came back without a code (cancelled or denied).
    ProviderDenied,
    /// The upstream provider could not be reached or its answer did not verify.
    ProviderFailed,
    /// The upstream ID token is expired or issued in the future: usually this server's clock.
    ClockSkew,
    /// No user is linked to the upstream account.
    AccountNotLinked,
    /// The upstream account is linked already.
    AccountAlreadyLinked,
    /// The account session that started linking ended, or the browser sent another one.
    AccountSessionEnded,
    /// The linked user is disabled or gone.
    UserUnavailable,
    /// An admin account tried to sign in with, or link, a GitHub or Google account.
    AdminNeedsPasskey,
    /// The enrolment link is invalid, used or expired.
    SetupLinkInvalid,
    /// Storage or another server-side step failed.
    ServerError,
    /// Anything else.
    Other,
}

impl ErrorReason {
    const fn text(self, m: &Messages) -> ErrorText {
        match self {
            Self::RequestExpired => m.err_request_expired,
            Self::StateMismatch => m.err_state_mismatch,
            Self::MalformedRequest => m.err_malformed,
            Self::UnknownClient => m.err_unknown_client,
            Self::RedirectUri => m.err_redirect_uri,
            Self::ProviderDenied => m.err_provider_denied,
            Self::ProviderFailed => m.err_provider_failed,
            Self::ClockSkew => m.err_clock_skew,
            Self::AccountNotLinked => m.err_account_not_linked,
            Self::AccountAlreadyLinked => m.err_account_already_linked,
            Self::AccountSessionEnded => m.err_account_session,
            Self::UserUnavailable => m.err_user_unavailable,
            Self::AdminNeedsPasskey => m.err_admin_passkey,
            Self::SetupLinkInvalid => m.err_setup_link,
            Self::ServerError => m.err_server,
            Self::Other => ErrorText {
                title: m.error_title,
                cause: "",
                next: m.error_body,
            },
        }
    }

    const fn command(self) -> Option<&'static str> {
        match self {
            Self::ProviderFailed | Self::ServerError => Some(LOGS_COMMAND),
            Self::ClockSkew => Some(CLOCK_COMMAND),
            Self::RequestExpired
            | Self::StateMismatch
            | Self::MalformedRequest
            | Self::UnknownClient
            | Self::RedirectUri
            | Self::ProviderDenied
            | Self::AccountNotLinked
            | Self::AccountAlreadyLinked
            | Self::AccountSessionEnded
            | Self::UserUnavailable
            | Self::AdminNeedsPasskey
            | Self::SetupLinkInvalid
            | Self::Other => None,
        }
    }
}

#[derive(Template)]
#[template(path = "login.html")]
struct LoginPage<'a> {
    lang: Lang,
    langs: &'static [Lang],
    m: &'static Messages,
    assets: &'a Versions,
    client: Option<&'a str>,
    /// Seconds left on the pending request.
    expires_in: Option<u64>,
    subtitle: String,
    login_hint: Option<&'a str>,
    providers: &'a [ProviderButton<'a>],
    apps: &'a [AppLink<'a>],
    reset_command: &'static str,
}

#[derive(Template)]
#[template(path = "setup.html")]
struct SetupPage<'a> {
    lang: Lang,
    langs: &'static [Lang],
    m: &'static Messages,
    assets: &'a Versions,
    client: Option<&'a str>,
    providers: &'a [ProviderButton<'a>],
    apps: &'a [AppLink<'a>],
    setup_link_command: &'static str,
    invite_command: &'static str,
}

#[derive(Template)]
#[template(path = "notice.html")]
struct NoticePage<'a> {
    lang: Lang,
    langs: &'static [Lang],
    m: &'static Messages,
    assets: &'a Versions,
    title: &'a str,
    body: &'a str,
    apps: &'a [AppLink<'a>],
}

/// Renders a page that only informs (for example, "account linked"), with a way into `apps`.
#[must_use]
pub fn notice_page(lang: Lang, title: &str, body: &str, apps: &[AppLink<'_>]) -> Response {
    let page = NoticePage {
        lang,
        langs: &Lang::ALL,
        m: lang.messages(),
        assets: &VERSIONS,
        title,
        body,
        apps,
    };
    render(StatusCode::OK, &page)
}

#[derive(Template)]
#[template(path = "error.html")]
struct ErrorPage<'a> {
    lang: Lang,
    langs: &'static [Lang],
    m: &'static Messages,
    assets: &'a Versions,
    text: ErrorText,
    command: Option<&'static str>,
    new_link: bool,
    setup_link_command: &'static str,
    detail: &'a str,
}

/// The page language: `?lang=` (the language switcher), then `Accept-Language`.
#[must_use]
pub fn page_lang(query: Option<&str>, headers: &HeaderMap) -> Lang {
    let explicit = form_urlencoded::parse(query.unwrap_or_default().as_bytes())
        .find(|(key, _)| key == "lang")
        .map(|(_, value)| value.into_owned());
    Lang::negotiate(explicit.as_deref(), accept_language(headers))
}

/// The `Accept-Language` header, if it is text.
#[must_use]
pub fn accept_language(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::ACCEPT_LANGUAGE)
        .and_then(|v| v.to_str().ok())
}

fn render(status: StatusCode, page: &impl Template) -> Response {
    let mut response = match page.render() {
        Ok(html) => (status, Html(html)).into_response(),
        Err(error) => {
            tracing::error!(%error, reason = "page_render_failed", "rendering a page failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    };
    harden(&mut response);
    response
}

/// Renders the error page for an authorization request that cannot be trusted enough to redirect
/// (RFC 6749 §4.1.2.1) or an upstream sign-in that failed.
///
/// It says what happened and what to do for `reason`, then `detail` (for the administrator)
/// behind a collapsed disclosure.
#[must_use]
pub fn error_page(lang: Lang, reason: ErrorReason, detail: &str) -> Response {
    let m = lang.messages();
    let page = ErrorPage {
        lang,
        langs: &Lang::ALL,
        m,
        assets: &VERSIONS,
        text: reason.text(m),
        command: reason.command(),
        new_link: reason == ErrorReason::SetupLinkInvalid,
        setup_link_command: SETUP_LINK_COMMAND,
        detail,
    };
    render(StatusCode::BAD_REQUEST, &page)
}

/// Renders the sign-in page.
///
/// `request` is the pending request's client name and the time left on it. Without one the page
/// explains that there is nothing to sign in to and offers `apps`; with one, it offers them only
/// once the request has ended. `providers` adds "Continue with …" buttons.
#[must_use]
pub fn login_page(
    lang: Lang,
    request: Option<(&str, Duration)>,
    login_hint: Option<&str>,
    providers: &[ProviderButton<'_>],
    apps: &[AppLink<'_>],
) -> Response {
    let m = lang.messages();
    let client = request.map(|(client, _)| client);
    let subtitle = client.map_or_else(
        || m.login_subtitle.to_owned(),
        |c| format!("{} {c}", m.login_continue_to),
    );
    let page = LoginPage {
        lang,
        langs: &Lang::ALL,
        m,
        assets: &VERSIONS,
        client,
        expires_in: request.map(|(_, left)| left.as_secs()),
        subtitle,
        login_hint,
        providers,
        apps,
        reset_command: RESET_COMMAND,
    };
    render(StatusCode::OK, &page)
}

/// Renders the enrolment page, where a setup link or invitation becomes a passkey (or, with
/// `providers`, a linked upstream account).
///
/// Once done, it leads back to the sign-in for `client` when one is pending, otherwise to `apps`,
/// and suggests a backup passkey.
#[must_use]
pub fn setup_page(
    lang: Lang,
    client: Option<&str>,
    providers: &[ProviderButton<'_>],
    apps: &[AppLink<'_>],
) -> Response {
    let page = SetupPage {
        lang,
        langs: &Lang::ALL,
        m: lang.messages(),
        assets: &VERSIONS,
        client,
        providers,
        apps,
        setup_link_command: SETUP_LINK_COMMAND,
        invite_command: INVITE_COMMAND,
    };
    render(StatusCode::OK, &page)
}

/// How a passkey is kept, from its backup flags (WebAuthn BE and BS).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Storage {
    /// Backed up (BS): synced by a passkey provider.
    Synced,
    /// Not backup eligible (BE unset): it lives on one authenticator.
    OneDevice,
    /// Eligible but not backed up yet, or unknown.
    Unknown,
}

/// A passkey on the account page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PasskeyRow<'a> {
    /// `Credential` object name.
    pub name: &'a str,
    /// The label the user gave, or `None` to show a name with the creation date.
    pub label: Option<&'a str>,
    /// When it was added, in Unix seconds.
    pub added: Option<u64>,
    /// When it last signed in, in Unix seconds.
    pub last_used: Option<u64>,
    /// How it is kept.
    pub storage: Storage,
    /// Whether this session signed in, or last confirmed, with it.
    pub this_device: bool,
}

/// A linked upstream account on the account page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinkedRow<'a> {
    /// `Credential` object name.
    pub name: &'a str,
    /// The provider's name and icon.
    pub provider: ProviderButton<'a>,
    /// When it was linked, in Unix seconds.
    pub linked: Option<u64>,
}

/// A session or app grant on the account page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionRow<'a> {
    /// `Grant` object name.
    pub name: &'a str,
    /// The app's name, or `None` for the account page itself.
    pub app: Option<&'a str>,
    /// When the user signed in, in Unix seconds.
    pub signed_in: u64,
    /// The label of the credential used, if known.
    pub credential: Option<&'a str>,
    /// Whether it is the session viewing the page.
    pub current: bool,
}

/// The signed-in user's account.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccountView<'a> {
    /// The username.
    pub username: &'a str,
    /// The session's CSRF token, sent back with every change.
    pub csrf: &'a str,
    /// The user's passkeys.
    pub passkeys: &'a [PasskeyRow<'a>],
    /// The user's linked upstream accounts.
    pub linked: &'a [LinkedRow<'a>],
    /// The upstream providers the user may link.
    pub providers: &'a [ProviderButton<'a>],
    /// An admin account, which cannot link upstream accounts.
    pub admin: bool,
    /// The user's sessions and app grants.
    pub sessions: &'a [SessionRow<'a>],
}

/// A UTC date for a `<time>` element; the script shows it in the reader's locale.
#[derive(Debug, Clone)]
struct Date {
    iso: String,
    text: String,
}

impl Date {
    fn new(secs: u64) -> Self {
        let days = i64::try_from(secs / 86_400).unwrap_or(0);
        let rest = secs % 86_400;
        let (year, month, day) = civil(days);
        Self {
            iso: format!(
                "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
                rest / 3600,
                rest / 60 % 60,
                rest % 60
            ),
            text: format!("{year:04}-{month:02}-{day:02}"),
        }
    }
}

/// Days since 1970-01-01 to a proleptic Gregorian date (Howard Hinnant's `civil_from_days`).
const fn civil(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + if month <= 2 { 1 } else { 0 };
    (year, month, day)
}

struct PasskeyItem<'a> {
    name: &'a str,
    label: Option<&'a str>,
    added: Option<Date>,
    last_used: Option<Date>,
    storage: &'static str,
    this_device: bool,
}

struct LinkedItem<'a> {
    name: &'a str,
    provider: ProviderButton<'a>,
    linked: Option<Date>,
}

struct SessionItem<'a> {
    name: &'a str,
    title: &'a str,
    signed_in: Date,
    credential: Option<&'a str>,
    current: bool,
}

struct AccountItems<'a> {
    username: &'a str,
    csrf: &'a str,
    passkeys: Vec<PasskeyItem<'a>>,
    linked: Vec<LinkedItem<'a>>,
    providers: &'a [ProviderButton<'a>],
    admin: bool,
    sessions: Vec<SessionItem<'a>>,
}

#[derive(Template)]
#[template(path = "account.html")]
struct AccountPage<'a> {
    lang: Lang,
    langs: &'static [Lang],
    m: &'static Messages,
    assets: &'a Versions,
    view: Option<AccountItems<'a>>,
    reset_command: &'static str,
}

/// Renders the account page: a sign-in button without `view`, else the user's passkeys, linked
/// accounts and sessions. The linked accounts show only if the user has one or `providers` offers
/// one.
#[must_use]
pub fn account_page(lang: Lang, view: Option<AccountView<'_>>) -> Response {
    let m = lang.messages();
    let view = view.map(|view| AccountItems {
        username: view.username,
        csrf: view.csrf,
        passkeys: view
            .passkeys
            .iter()
            .map(|p| PasskeyItem {
                name: p.name,
                label: p.label.filter(|l| !l.trim().is_empty()),
                added: p.added.map(Date::new),
                last_used: p.last_used.map(Date::new),
                storage: match p.storage {
                    Storage::Synced => m.passkey_synced,
                    Storage::OneDevice => m.passkey_device_bound,
                    Storage::Unknown => "",
                },
                this_device: p.this_device,
            })
            .collect(),
        linked: view
            .linked
            .iter()
            .map(|l| LinkedItem {
                name: l.name,
                provider: l.provider,
                linked: l.linked.map(Date::new),
            })
            .collect(),
        providers: view.providers,
        admin: view.admin,
        sessions: view
            .sessions
            .iter()
            .map(|s| SessionItem {
                name: s.name,
                title: s.app.unwrap_or(m.session_account),
                signed_in: Date::new(s.signed_in),
                credential: s.credential,
                current: s.current,
            })
            .collect(),
    });
    let page = AccountPage {
        lang,
        langs: &Lang::ALL,
        m,
        assets: &VERSIONS,
        view,
        reset_command: RESET_COMMAND,
    };
    render(StatusCode::OK, &page)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates_are_utc_civil_dates() {
        assert_eq!(Date::new(0).iso, "1970-01-01T00:00:00Z");
        assert_eq!(Date::new(951_782_400).text, "2000-02-29");
        let date = Date::new(1_792_651_380);
        assert_eq!(date.text, "2026-10-22");
        assert_eq!(date.iso, "2026-10-22T06:43:00Z");
    }
}
