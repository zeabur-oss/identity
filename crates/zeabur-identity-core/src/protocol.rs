//! Endpoint paths that several parts of Zeabur Identity must agree on.

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
