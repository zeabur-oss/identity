//! RFC 9457 problem details for Zeabur Identity's own JSON endpoints (not the OAuth endpoints,
//! which use RFC 6749 errors).
//!
//! The server concludes and the page shows: each problem carries its message in the reader's
//! language (`detail`), whether the page shows a stale list (`refresh`), and the step the page
//! moves to (`next`).

use std::borrow::Cow;

use axum::extract::Request;
use axum::http::{HeaderValue, StatusCode, header};
use axum::middleware::Next as Run;
use axum::response::{IntoResponse, Response};
use schemars::JsonSchema;
use serde::Serialize;
use zeabur_identity_core::password::Weakness;
use zeabur_identity_ui::i18n::{Lang, Messages};
use zeabur_identity_ui::pages::accept_language;

/// Picks a problem's message from the messages of one language.
pub type Detail = fn(&'static Messages) -> &'static str;

/// A problem. `kind` is a short stable code that names it in `type`.
#[derive(Debug, Clone, Copy)]
pub struct Problem {
    /// HTTP status.
    pub status: StatusCode,
    /// Stable machine-readable code, also used to build `type`.
    pub kind: &'static str,
    /// Short summary, in English.
    pub title: &'static str,
    /// The message the page shows.
    pub detail: Detail,
    /// The page shows a list that changed in the meantime.
    pub refresh: bool,
    /// The step the page moves to.
    pub next: Option<Step>,
}

impl PartialEq for Problem {
    fn eq(&self, other: &Self) -> bool {
        (self.status, self.kind, self.title) == (other.status, other.kind, other.title)
    }
}

impl Eq for Problem {}

/// The step a page moves to after a problem, in place of showing it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum Step {
    /// Ask for the authenticator code.
    Code,
    /// The sign-in request ended: offer the apps.
    Ended,
    /// The setup link no longer works: show how to get a new one.
    NewLink,
    /// Confirm with a passkey, then send the request again.
    Reauth,
}

/// The JSON body of a problem (RFC 9457 §3), with every extension member (§3.2) any problem
/// carries. Each member is present only on the problems that set it.
#[derive(Debug, Serialize, JsonSchema)]
#[schemars(rename = "Problem")]
pub(crate) struct ProblemBody {
    /// `urn:zeabur-identity:problem:<kind>`.
    #[serde(rename = "type")]
    kind: String,
    title: &'static str,
    status: u16,
    /// The message to show, in the language of the request's `Accept-Language`.
    detail: Cow<'static, str>,
    /// The page shows a list that changed in the meantime: reload it, then show `detail`.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    refresh: bool,
    /// The step the page moves to, in place of showing `detail`.
    #[serde(skip_serializing_if = "Option::is_none")]
    next: Option<Step>,
    #[serde(flatten)]
    extensions: Extensions,
}

/// Extension members of a problem.
#[derive(Debug, Clone, Default, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Extensions {
    /// Why a new password was refused (`password-weak`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub weakness: Option<Weakness>,
    /// The credential the relying party does not know (`passkey-failed`), for
    /// `signalUnknownCredential` (WebAuthn Level 3 §5.1.10.1).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unknown_credential: Option<UnknownCredential>,
}

/// The argument of `PublicKeyCredential.signalUnknownCredential()`.
#[derive(Debug, Clone, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct UnknownCredential {
    /// The relying party ID.
    pub rp_id: String,
    /// The credential ID, base64url.
    pub credential_id: String,
}

impl Problem {
    /// Creates a problem with the generic message.
    #[must_use]
    pub const fn new(status: StatusCode, kind: &'static str, title: &'static str) -> Self {
        Self {
            status,
            kind,
            title,
            detail: |m| m.generic_error,
            refresh: false,
            next: None,
        }
    }

    /// The message the page shows.
    #[must_use]
    pub const fn detail(self, detail: Detail) -> Self {
        Self { detail, ..self }
    }

    /// Tells the page that its list changed in the meantime.
    #[must_use]
    pub const fn refresh(self) -> Self {
        Self {
            refresh: true,
            ..self
        }
    }

    /// Tells the page which step comes next.
    #[must_use]
    pub const fn next(self, step: Step) -> Self {
        Self {
            next: Some(step),
            ..self
        }
    }

    /// An internal error: logs `error` and returns a refusal without details.
    #[must_use]
    pub fn internal(error: impl std::fmt::Display) -> Self {
        tracing::error!(reason = "internal_error", %error, "sign-in failed");
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
            "Unable to complete the request. Try again.",
        )
    }

    /// The response with extension members (RFC 9457 §3.2). Its `detail` is in English until
    /// [`localize`] writes it in the request's language.
    #[must_use]
    pub fn with(self, extensions: Extensions) -> Response {
        let mut response = self.render(extensions.clone(), Lang::En);
        response.extensions_mut().insert(Pending(self, extensions));
        response
    }

    fn render(self, extensions: Extensions, lang: Lang) -> Response {
        let m = lang.messages();
        let detail = extensions.weakness.map_or_else(
            || Cow::Borrowed((self.detail)(m)),
            |weakness| weakness_text(weakness, m),
        );
        let body = ProblemBody {
            // RFC 9457 §3.1.1: a URI reference identifying the problem type.
            kind: format!("urn:zeabur-identity:problem:{}", self.kind),
            title: self.title,
            status: self.status.as_u16(),
            detail,
            refresh: self.refresh,
            next: self.next,
            extensions,
        };
        let mut response = (self.status, axum::Json(body)).into_response();
        let headers = response.headers_mut();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/problem+json"),
        );
        response
    }
}

impl IntoResponse for Problem {
    fn into_response(self) -> Response {
        self.with(Extensions::default())
    }
}

/// A problem response whose `detail` waits for the request's language.
#[derive(Debug, Clone)]
struct Pending(Problem, Extensions);

/// Middleware: writes each problem's `detail` in the language of the request's
/// `Accept-Language` (RFC 9110 §12.5.4), which the pages set to their own language.
pub async fn localize(request: Request, run: Run) -> Response {
    let lang = Lang::negotiate(None, accept_language(request.headers()));
    let mut response = run.run(request).await;
    match response.extensions_mut().remove::<Pending>() {
        // Keep the status and headers the handler added (`Retry-After`, `Set-Cookie`).
        Some(Pending(problem, extensions)) if lang != Lang::En => {
            let (parts, _) = response.into_parts();
            let (_, body) = problem.render(extensions, lang).into_parts();
            Response::from_parts(parts, body)
        }
        Some(_) | None => response,
    }
}

fn weakness_text(weakness: Weakness, m: &'static Messages) -> Cow<'static, str> {
    match weakness {
        Weakness::TooShort => Cow::Owned(m.too_short()),
        Weakness::TooLong => Cow::Borrowed(m.weak_too_long),
        Weakness::Common => Cow::Borrowed(m.weak_common),
        Weakness::Context => Cow::Borrowed(m.weak_context),
    }
}
