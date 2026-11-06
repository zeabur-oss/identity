//! `UpstreamProvider`: an OpenID Connect provider people sign in with.

#![expect(
    unreachable_pub,
    reason = "the KubeSchema derive re-emits these types inside a private module"
)]

use kube::{CustomResource, KubeSchema};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// The Secret holding every provider's client secret, one key per provider. A fixed name lets
/// Zeabur Identity's role read this Secret and no other.
pub const SECRET: &str = "zeabur-identity-upstream";
/// Longest display name.
pub const MAX_DISPLAY_NAME: usize = 64;
/// Longest issuer. A linked account's `Credential` stores it, with the same limit.
pub const MAX_ISSUER: usize = 256;
/// Longest client ID.
pub const MAX_CLIENT_ID: usize = 256;
/// The admission rule for the issuer: `https` with a host, printable ASCII, no user information,
/// query or fragment (OpenID Connect Discovery 1.0 §2).
pub const ISSUER_RULE: &str = concat!(
    "self.matches('^[!-~]+$') && isURL(self) && !self.matches('^[^/]*//[^/?]*@')",
    " && !self.contains('?') && !self.contains('#')",
    " && url(self).getScheme() == 'https' && url(self).getHostname() != ''",
);
/// A scope token (RFC 6749 §3.3).
pub const SCOPE_PATTERN: &str = r"^[!#-\[\]-~]+$";
/// A key in a Secret's `data` (Kubernetes allows these characters).
pub const SECRET_KEY_PATTERN: &str = r"^[-._a-zA-Z0-9]+$";

/// An OpenID Connect provider.
///
/// The object name is the provider's ID in Zeabur Identity's URLs: register
/// `<issuer>/upstream/<name>/callback` as the redirect URI at the provider. `github` and `google`
/// are taken by the built-in providers.
#[derive(CustomResource, KubeSchema, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[kube(
    group = "identity.zeabur.com",
    version = "v1alpha1",
    kind = "UpstreamProvider",
    namespaced,
    category = "zeabur-identity",
    printcolumn(name = "Issuer", type_ = "string", json_path = ".spec.issuer"),
    printcolumn(
        name = "Age",
        type_ = "date",
        json_path = ".metadata.creationTimestamp"
    ),
    doc = "An OpenID Connect provider people can sign in to Zeabur Identity with."
)]
#[serde(rename_all = "camelCase")]
pub struct UpstreamProviderSpec {
    /// Name on the "Continue with …" button.
    #[schemars(length(min = 1, max = MAX_DISPLAY_NAME))]
    pub display_name: String,

    /// The provider's issuer URL, exactly as its ID tokens' `iss` claim. Its discovery document is
    /// read from `<issuer>/.well-known/openid-configuration`.
    #[schemars(length(min = 1, max = MAX_ISSUER))]
    #[x_kube(validation = Rule::new(ISSUER_RULE).message(
        "the issuer must be https:// with a host; printable ASCII, no user information, query or fragment"
    ))]
    pub issuer: String,

    /// The client ID registered at the provider.
    #[schemars(length(min = 1, max = MAX_CLIENT_ID), regex(pattern = r"^[!-~]+$"))]
    pub client_id: String,

    /// The key holding the client secret in the Secret `zeabur-identity-upstream`, in the same
    /// namespace.
    #[schemars(length(min = 1, max = 253), regex(pattern = SECRET_KEY_PATTERN))]
    pub client_secret_key: String,

    /// Create a user at an account's first sign-in, when its ID token's `claim` has one of
    /// `values`. Unset, accounts must be linked first.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provisioning: Option<Provisioning>,
}

/// Which accounts get a user at first sign-in.
#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Provisioning {
    /// An ID token claim, such as `hd` or `groups`.
    #[schemars(length(min = 1, max = 64), regex(pattern = r"^[!-~]+$"))]
    pub claim: String,

    /// The values that allow it. The claim must be one of them, or, for a list, contain one.
    #[schemars(length(min = 1, max = 32), inner(length(min = 1, max = 256)))]
    pub values: Vec<String>,

    /// Scopes to ask for besides `openid profile email`, such as one that adds a groups claim.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[schemars(length(max = 8), inner(length(min = 1, max = 64), regex(pattern = SCOPE_PATTERN)))]
    pub scopes: Vec<String>,
}

#[cfg(test)]
mod tests {
    use kube::CustomResourceExt as _;

    use super::UpstreamProvider;

    #[test]
    fn issuer_and_secret_key_are_checked_at_admission() {
        let crd = serde_json::to_value(UpstreamProvider::crd()).unwrap();
        let spec = &crd["spec"]["versions"][0]["schema"]["openAPIV3Schema"]["properties"]["spec"];
        let issuer = &spec["properties"]["issuer"];
        assert_eq!(issuer["maxLength"], 256);
        assert_eq!(
            issuer["x-kubernetes-validations"][0]["rule"],
            super::ISSUER_RULE
        );
        assert_eq!(
            spec["properties"]["clientSecretKey"]["pattern"],
            super::SECRET_KEY_PATTERN
        );
        let mut required: Vec<&str> = spec["required"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        required.sort_unstable();
        assert_eq!(
            required,
            ["clientId", "clientSecretKey", "displayName", "issuer"]
        );
    }
}
