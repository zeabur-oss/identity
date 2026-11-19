//! RFC 9457 problem details for Zeabur Identity's own JSON endpoints (not the OAuth endpoints,
//! which use RFC 6749 errors).

use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use schemars::JsonSchema;
use serde::Serialize;
use zeabur_identity_core::password::Weakness;

/// A problem. `kind` is a short stable code the UI can switch on; `detail` is for people.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Problem {
    /// HTTP status.
    pub status: StatusCode,
    /// Stable machine-readable code, also used to build `type`.
    pub kind: &'static str,
    /// Short summary.
    pub title: &'static str,
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
    #[serde(flatten)]
    extensions: Extensions,
}

/// Extension members of a problem.
#[derive(Debug, Default, Serialize, JsonSchema)]
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
#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct UnknownCredential {
    /// The relying party ID.
    pub rp_id: String,
    /// The credential ID, base64url.
    pub credential_id: String,
}

impl Problem {
    /// Creates a problem.
    #[must_use]
    pub const fn new(status: StatusCode, kind: &'static str, title: &'static str) -> Self {
        Self {
            status,
            kind,
            title,
        }
    }

    /// An internal error; details are logged, not returned.
    #[must_use]
    pub const fn internal() -> Self {
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
            "Unable to complete the request. Try again.",
        )
    }

    /// The response with extension members (RFC 9457 §3.2).
    #[must_use]
    pub fn with(self, extensions: Extensions) -> Response {
        let body = ProblemBody {
            // RFC 9457 §3.1.1: a URI reference identifying the problem type.
            kind: format!("urn:zeabur-identity:problem:{}", self.kind),
            title: self.title,
            status: self.status.as_u16(),
            extensions,
        };
        let mut response = (self.status, axum::Json(body)).into_response();
        let headers = response.headers_mut();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/problem+json"),
        );
        headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        response
    }
}

impl IntoResponse for Problem {
    fn into_response(self) -> Response {
        self.with(Extensions::default())
    }
}
