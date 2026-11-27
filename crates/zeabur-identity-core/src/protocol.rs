//! Paths that several parts of Zeabur Identity must agree on: the router, the URLs the server
//! builds and the page templates.

/// Path of the authorization endpoint.
pub const AUTHORIZATION_PATH: &str = "/authorize";
/// Path of the token endpoint.
pub const TOKEN_PATH: &str = "/token";
/// Path of the pushed authorization request endpoint (RFC 9126).
pub const PAR_PATH: &str = "/par";
/// Path of the revocation endpoint (RFC 7009).
pub const REVOCATION_PATH: &str = "/revoke";
/// Path of the JWK set.
pub const JWKS_PATH: &str = "/jwks";
/// OpenID Connect Discovery location (Discovery §4).
pub const OPENID_CONFIGURATION_PATH: &str = "/.well-known/openid-configuration";
/// UserInfo endpoint (OIDC Core §5.3).
pub const USERINFO_PATH: &str = "/userinfo";
/// RFC 8414 location for an issuer without a path (RFC 8414 §3).
pub const OAUTH_METADATA_PATH: &str = "/.well-known/oauth-authorization-server";
/// Path of the setup and enrolment page; the token goes in the fragment.
pub const SETUP_PATH: &str = "/setup";
/// Path of the account page.
pub const ACCOUNT_PATH: &str = "/account";
/// The provider ID in an upstream route.
const PROVIDER_PARAMETER: &str = "{provider}";
/// Route of an upstream provider's sign-in start. `{provider}` is the provider ID.
pub const UPSTREAM_START_ROUTE: &str = "/upstream/{provider}/start";
/// Route of an upstream provider's callback. `{provider}` is the provider ID.
pub const UPSTREAM_CALLBACK_ROUTE: &str = "/upstream/{provider}/callback";

/// The path the upstream provider `provider` redirects back to.
#[must_use]
pub fn upstream_callback_path(provider: &str) -> String {
    UPSTREAM_CALLBACK_ROUTE.replace(PROVIDER_PARAMETER, provider)
}
