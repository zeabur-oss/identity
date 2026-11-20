//! Provider metadata: OpenID Connect Discovery 1.0 §3 and RFC 8414 §2.
//!
//! One document is served at both `/.well-known/openid-configuration` and
//! `/.well-known/oauth-authorization-server`, so the two publications are always consistent
//! (RFC 8414 §3, and RFC 9068 §4 for issuers that publish both).
//!
//! Only implemented behaviour is advertised. Optional members whose default would claim
//! something we do not support are set explicitly (for example `request_uri_parameter_supported`
//! defaults to `true` in Discovery §3, and `response_modes_supported` defaults to include
//! `fragment`). ID tokens are offered in ES256 and RS256, since Discovery §3 requires RS256.
//!
//! The issuer is an `https` origin with no path or trailing slash. OpenID Connect appends the
//! well-known suffix to the issuer while RFC 8414 §3 inserts it before the path (RFC 8414 §5), so
//! only a path-less issuer puts both documents where both specifications expect them. The
//! issuer string is used byte for byte everywhere: Discovery §4.3, RFC 8414 §3.3 and
//! kube-apiserver all require it to be identical to `iss`.
//!
//! kube-apiserver may fetch discovery from an in-cluster address instead (`issuer.discoveryURL`,
//! KEP-3331). It requires the fetched `issuer` to equal its configured `issuer.url` and then
//! fetches keys from the document's `jwks_uri`, so the in-cluster document differs from the
//! public one only in `jwks_uri` ([k8s-authn]). kube-apiserver's own service account issuer does
//! the same with `--service-account-jwks-uri`.
//!
//! [k8s-authn]: https://kubernetes.io/docs/reference/access-authn-authz/authentication/

use axum::body::Bytes;
use serde::Serialize;
use zeabur_identity_core::config::BaseUrl;
pub use zeabur_identity_core::protocol::{
    AUTHORIZATION_PATH, JWKS_PATH, OAUTH_METADATA_PATH, OPENID_CONFIGURATION_PATH, PAR_PATH,
    REVOCATION_PATH, TOKEN_PATH, USERINFO_PATH,
};
use zeabur_identity_keys::Algorithm;

use crate::endpoints::GrantType;

/// The metadata document.
#[derive(Debug, Serialize)]
pub struct ProviderMetadata {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    userinfo_endpoint: String,
    jwks_uri: String,
    pushed_authorization_request_endpoint: String,
    revocation_endpoint: String,
    scopes_supported: Vec<&'static str>,
    response_types_supported: &'static [&'static str],
    response_modes_supported: &'static [&'static str],
    grant_types_supported: [&'static str; 2],
    subject_types_supported: &'static [&'static str],
    id_token_signing_alg_values_supported: [&'static str; 2],
    request_uri_parameter_supported: bool,
    require_pushed_authorization_requests: bool,
    code_challenge_methods_supported: &'static [&'static str],
    token_endpoint_auth_methods_supported: &'static [&'static str],
    revocation_endpoint_auth_methods_supported: &'static [&'static str],
    authorization_response_iss_parameter_supported: bool,
    claims_supported: &'static [&'static str],
}

impl ProviderMetadata {
    /// Builds the document for `issuer`. `jwks_base` is the base URL of the JWK set: the
    /// issuer itself for the public document, or the in-cluster address for the document that
    /// kube-apiserver fetches through `issuer.discoveryURL` (the `issuer` member stays the same).
    #[must_use]
    pub fn new(issuer: &BaseUrl, jwks_base: &BaseUrl) -> Self {
        Self {
            issuer: issuer.as_str().to_owned(),
            authorization_endpoint: issuer.join(AUTHORIZATION_PATH),
            token_endpoint: issuer.join(TOKEN_PATH),
            userinfo_endpoint: issuer.join(USERINFO_PATH),
            jwks_uri: jwks_base.join(JWKS_PATH),
            pushed_authorization_request_endpoint: issuer.join(PAR_PATH),
            revocation_endpoint: issuer.join(REVOCATION_PATH),
            scopes_supported: crate::authorize::SUPPORTED_SCOPES.to_vec(),
            response_types_supported: &["code"],
            response_modes_supported: &["query"],
            grant_types_supported: GrantType::SUPPORTED.map(GrantType::as_str),
            subject_types_supported: &["public"],
            id_token_signing_alg_values_supported: Algorithm::ALL.map(Algorithm::as_str),
            // Discovery §3 defaults this to true, meaning OIDC request objects by reference,
            // which are not supported. PAR request URIs are advertised separately.
            request_uri_parameter_supported: false,
            require_pushed_authorization_requests: false,
            code_challenge_methods_supported: &["S256"],
            token_endpoint_auth_methods_supported: &[
                "none",
                "client_secret_basic",
                "client_secret_post",
            ],
            revocation_endpoint_auth_methods_supported: &[
                "none",
                "client_secret_basic",
                "client_secret_post",
            ],
            authorization_response_iss_parameter_supported: true,
            claims_supported: &[
                "iss",
                "sub",
                "aud",
                "exp",
                "iat",
                "auth_time",
                "nonce",
                "amr",
                "azp",
                "preferred_username",
                "name",
                "groups",
            ],
        }
    }

    /// Serializes the document.
    ///
    /// # Panics
    ///
    /// Never: the document contains only strings and booleans, which always serialize.
    #[must_use]
    pub fn to_bytes(&self) -> Bytes {
        #[expect(
            clippy::expect_used,
            reason = "serializing strings and booleans cannot fail"
        )]
        Bytes::from(serde_json::to_vec(self).expect("metadata serializes"))
    }
}

#[cfg(test)]
mod tests {
    use serde_json::Value;

    use super::*;

    fn issuer() -> BaseUrl {
        BaseUrl::parse("issuer", "https://login.example.com").unwrap()
    }

    fn document(jwks_base: &BaseUrl) -> Value {
        serde_json::from_slice(&ProviderMetadata::new(&issuer(), jwks_base).to_bytes()).unwrap()
    }

    #[test]
    fn required_members_are_present() {
        let doc = document(&issuer());
        // Discovery §3 REQUIRED members.
        for member in [
            "issuer",
            "authorization_endpoint",
            "token_endpoint",
            "jwks_uri",
            "response_types_supported",
            "subject_types_supported",
            "id_token_signing_alg_values_supported",
        ] {
            assert!(!doc[member].is_null(), "{member}");
        }
        // Discovery §4.3 / RFC 8414 §3.3: identical to the issuer identifier.
        assert_eq!(doc["issuer"], "https://login.example.com");
        assert_eq!(doc["jwks_uri"], "https://login.example.com/jwks");
        // Discovery §3: "The algorithm RS256 MUST be included."
        let algs = doc["id_token_signing_alg_values_supported"]
            .as_array()
            .unwrap();
        assert!(algs.contains(&Value::from("RS256")));
        assert!(algs.contains(&Value::from("ES256")));
        // Discovery §3: scopes_supported "MUST support the openid scope value".
        assert!(
            doc["scopes_supported"]
                .as_array()
                .unwrap()
                .contains(&Value::from("openid"))
        );
    }

    #[test]
    fn does_not_inherit_misleading_defaults() {
        let doc = document(&issuer());
        assert_eq!(doc["request_uri_parameter_supported"], false);
        assert_eq!(
            doc["response_modes_supported"],
            serde_json::json!(["query"])
        );
        assert_eq!(
            doc["grant_types_supported"],
            serde_json::json!(["authorization_code", "refresh_token"])
        );
        assert_eq!(
            doc["code_challenge_methods_supported"],
            serde_json::json!(["S256"])
        );
        assert_eq!(doc["authorization_response_iss_parameter_supported"], true);
        assert_eq!(doc["response_types_supported"], serde_json::json!(["code"]));
    }

    #[test]
    fn internal_variant_changes_only_the_jwks_uri() {
        let internal = BaseUrl::parse("internal", "https://10.43.0.53:8443").unwrap();
        let mut public = document(&issuer());
        let mut inside = document(&internal);
        assert_eq!(
            inside["issuer"], public["issuer"],
            "kube-apiserver requires the same issuer"
        );
        assert_eq!(inside["jwks_uri"], "https://10.43.0.53:8443/jwks");
        public["jwks_uri"] = Value::Null;
        inside["jwks_uri"] = Value::Null;
        assert_eq!(public, inside);
    }
}
