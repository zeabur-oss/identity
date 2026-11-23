//! What the JSON endpoints accept before a handler runs, and the `Cache-Control` they answer with.
//!
//! [`SameOrigin`] and [`Account`] read only the request's head, so axum runs them before the body
//! is read. [`Body`] reads its guard from the head first and parses the body only when the guard
//! accepts it: a cross-site request is refused for being cross-site whatever its body holds.
//! [`check_request`] is private to this module, so no handler can run its checks in another
//! order.

use axum::body::Bytes;
use axum::extract::{FromRequest, FromRequestParts, Request};
use axum::http::request::Parts;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use serde::de::DeserializeOwned;
use tower_http::set_header::SetResponseHeaderLayer;

use crate::account::{Account, SIGNED_OUT, current};
use crate::problem::Problem;
use crate::{BAD_REQUEST, Backend, SignIn};

const CROSS_SITE: Problem = Problem::new(
    StatusCode::FORBIDDEN,
    "cross-site",
    "Send this request from the sign-in page.",
);
const NOT_JSON: Problem = Problem::new(
    StatusCode::UNSUPPORTED_MEDIA_TYPE,
    "not-json",
    "Send the request body as JSON.",
);
const TOO_LARGE: Problem = Problem::new(
    StatusCode::PAYLOAD_TOO_LARGE,
    "too-large",
    "The request body is too large.",
);

/// A router state that holds the sign-in service.
pub(crate) trait State: Send + Sync {
    /// The service's stores.
    type Backend: Backend;
    /// The sign-in service.
    fn sign_in(&self) -> &SignIn<Self::Backend>;
}

/// `Cache-Control: no-store` on every answer of the routes it wraps, errors included: they carry
/// session cookies, ceremony state and account details, which no cache may keep ([RFC 9111
/// §5.2.2.5]).
///
/// [RFC 9111 §5.2.2.5]: https://www.rfc-editor.org/rfc/rfc9111.html#section-5.2.2.5
pub(crate) fn no_store() -> SetResponseHeaderLayer<HeaderValue> {
    SetResponseHeaderLayer::overriding(header::CACHE_CONTROL, HeaderValue::from_static("no-store"))
}

/// Cross-site request protection for the JSON endpoints: `Sec-Fetch-Site: same-origin`, or, for
/// browsers that do not send Fetch Metadata, an `Origin` equal to the issuer. Requests with
/// neither are refused. The JSON content type adds a CORS preflight for any cross-origin caller.
fn check_request(headers: &HeaderMap, issuer: &str) -> Result<(), Problem> {
    let header = |name| {
        headers
            .get(name)
            .and_then(|v: &HeaderValue| v.to_str().ok())
    };
    let allowed = match (header("sec-fetch-site"), header(header::ORIGIN.as_str())) {
        (Some(site), _) => site == "same-origin",
        (None, Some(origin)) => origin == issuer,
        (None, None) => false,
    };
    if !allowed {
        return Err(CROSS_SITE);
    }
    let json = header(header::CONTENT_TYPE.as_str())
        .and_then(|v| v.split(';').next())
        .is_some_and(|v| v.trim().eq_ignore_ascii_case("application/json"));
    if json { Ok(()) } else { Err(NOT_JSON) }
}

/// A same-origin JSON request ([`check_request`]).
pub(crate) struct SameOrigin;

impl<S: State> FromRequestParts<S> for SameOrigin {
    type Rejection = Problem;

    fn from_request_parts(
        parts: &mut Parts,
        state: &S,
    ) -> impl Future<Output = Result<Self, Problem>> + Send {
        std::future::ready(
            check_request(&parts.headers, state.sign_in().oauth.issuer.as_str()).map(|()| Self),
        )
    }
}

/// A same-origin JSON request with a valid account session ([`current`]).
impl<S: State> FromRequestParts<S> for Account {
    type Rejection = Problem;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Problem> {
        let service = state.sign_in();
        check_request(&parts.headers, service.oauth.issuer.as_str())?;
        current(service, &parts.headers, service.oauth.now())
            .await?
            .ok_or(SIGNED_OUT)
    }
}

/// The JSON body `T`, parsed only after the guard `G` accepted the request's head. A body that
/// does not parse is [`BAD_REQUEST`].
pub(crate) struct Body<G, T>(pub(crate) G, pub(crate) T);

impl<S, G, T> FromRequest<S> for Body<G, T>
where
    S: Send + Sync,
    G: FromRequestParts<S, Rejection = Problem> + Send,
    T: DeserializeOwned,
{
    type Rejection = Problem;

    async fn from_request(request: Request, state: &S) -> Result<Self, Problem> {
        let (mut parts, body) = request.into_parts();
        let guard = G::from_request_parts(&mut parts, state).await?;
        let bytes = Bytes::from_request(Request::from_parts(parts, body), state)
            .await
            .map_err(|rejection| {
                if rejection.status() == StatusCode::PAYLOAD_TOO_LARGE {
                    TOO_LARGE
                } else {
                    BAD_REQUEST
                }
            })?;
        let value = serde_json::from_slice(&bytes).map_err(|_malformed| BAD_REQUEST)?;
        Ok(Self(guard, value))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&'static str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.append(*name, HeaderValue::from_str(value).unwrap());
        }
        map
    }

    #[test]
    fn same_origin_checks() {
        let issuer = "https://login.example.com";
        let json = ("content-type", "application/json; charset=utf-8");
        assert!(
            check_request(&headers(&[("sec-fetch-site", "same-origin"), json]), issuer).is_ok()
        );
        assert!(check_request(&headers(&[("origin", issuer), json]), issuer).is_ok());
        assert_eq!(
            check_request(
                &headers(&[("sec-fetch-site", "cross-site"), ("origin", issuer), json]),
                issuer
            ),
            Err(CROSS_SITE)
        );
        assert_eq!(
            check_request(&headers(&[("sec-fetch-site", "same-site"), json]), issuer),
            Err(CROSS_SITE)
        );
        assert_eq!(
            check_request(
                &headers(&[("origin", "https://evil.example"), json]),
                issuer
            ),
            Err(CROSS_SITE)
        );
        assert_eq!(check_request(&headers(&[json]), issuer), Err(CROSS_SITE));
        assert_eq!(
            check_request(
                &headers(&[
                    ("sec-fetch-site", "same-origin"),
                    ("content-type", "text/plain")
                ]),
                issuer
            ),
            Err(NOT_JSON)
        );
    }
}
