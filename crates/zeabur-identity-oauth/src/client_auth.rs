//! Client authentication at the token, PAR and revocation endpoints (RFC 6749 §2.3).
//!
//! Confidential clients use `client_secret_basic` or `client_secret_post`; public clients send
//! only `client_id`. Using two methods at once is an error (RFC 6749 §2.3). Both secret methods
//! exist because the OpenID Foundation's Basic OP certification tests them, and the OAuth 2.1
//! draft requires credentials in the request body to be accepted.
//!
//! Only `sha256:<hex>` hashes of client secrets are stored, and they are compared in constant
//! time (Kanidm once compared client secrets in variable time, GHSA-53hj-r94p-8c8f). An unknown
//! client and a wrong secret get the same `invalid_client`.

use axum::http::{HeaderMap, header};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use zeabur_identity_api::client::ClientType;
use zeabur_identity_api::token_hash;
use zeabur_identity_core::crypto::ct_eq;
use zeabur_identity_store::{Client, Directory};

use super::error::{ErrorCode, OAuthError};
use super::params::Params;

/// A failed client authentication; `basic` says whether the Basic scheme was attempted, in which
/// case the response must carry `WWW-Authenticate` (RFC 6749 §5.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthFailure {
    /// The error.
    pub error: OAuthError,
    /// Whether HTTP Basic was used.
    pub basic: bool,
}

struct Presented {
    id: String,
    secret: Option<String>,
    basic: bool,
}

fn presented(headers: &HeaderMap, params: &Params) -> Result<Presented, AuthFailure> {
    let invalid_request = |d, basic| AuthFailure {
        error: OAuthError::new(ErrorCode::InvalidRequest, d),
        basic,
    };
    if let Some(value) = headers.get(header::AUTHORIZATION) {
        let invalid_client = AuthFailure {
            error: OAuthError::new(
                ErrorCode::InvalidClient,
                "Unable to read the Basic credentials in the Authorization header.",
            ),
            basic: true,
        };
        let encoded = value
            .to_str()
            .ok()
            .and_then(|v| v.strip_prefix("Basic "))
            .ok_or(invalid_client)?;
        let decoded = STANDARD
            .decode(encoded.trim())
            .ok()
            .and_then(|d| String::from_utf8(d).ok())
            .ok_or(invalid_client)?;
        let (id, secret) = decoded.split_once(':').ok_or(invalid_client)?;
        // RFC 6749 §2.3.1: both parts are form-urlencoded before Base64.
        let unescape = |s: &str| -> Option<String> {
            form_urlencoded::parse(format!("v={s}").as_bytes())
                .next()
                .map(|(_, v)| v.into_owned())
        };
        let (id, secret) = (
            unescape(id).ok_or(invalid_client)?,
            unescape(secret).ok_or(invalid_client)?,
        );
        if params.get("client_secret").is_some() {
            return Err(invalid_request(
                "Use one client authentication method, not both Basic and client_secret.",
                true,
            ));
        }
        if params.get("client_id").is_some_and(|form_id| form_id != id) {
            return Err(invalid_request(
                "The client_id does not match the client in the credentials.",
                true,
            ));
        }
        return Ok(Presented {
            id,
            secret: Some(secret),
            basic: true,
        });
    }
    let id = params
        .get("client_id")
        .ok_or_else(|| invalid_request("The client_id parameter is missing.", false))?;
    Ok(Presented {
        id: id.to_owned(),
        secret: params.get("client_secret").map(str::to_owned),
        basic: false,
    })
}

/// Authenticates the client of a request.
///
/// # Errors
///
/// `invalid_client` (401) for unknown clients and wrong or missing credentials; `invalid_request`
/// for malformed requests; `server_error` if the directory fails.
pub async fn authenticate<D: Directory>(
    directory: &D,
    headers: &HeaderMap,
    params: &Params,
) -> Result<Client, AuthFailure> {
    let presented = presented(headers, params)?;
    let basic = presented.basic;
    let fail = |d| AuthFailure {
        error: OAuthError::new(ErrorCode::InvalidClient, d),
        basic,
    };
    let client = directory
        .client(&presented.id)
        .await
        .map_err(|error| {
            tracing::error!(%error, reason = "storage_failed", "client lookup failed");
            AuthFailure {
                error: OAuthError::server(),
                basic,
            }
        })?
        .ok_or_else(|| fail("Client authentication failed. Check the client ID and secret."))?;
    match (client.kind, &client.secret_hash, presented.secret) {
        (ClientType::Public, _, None) => Ok(client),
        (ClientType::Confidential, Some(expected), Some(secret))
            if ct_eq(
                token_hash(secret.as_bytes()).as_bytes(),
                expected.as_bytes(),
            ) =>
        {
            Ok(client)
        }
        _ => Err(fail(
            "Client authentication failed. Check the client ID and secret.",
        )),
    }
}
