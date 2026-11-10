//! `UpstreamProvider`: a GitHub OAuth app or an OpenID provider that people sign in with.

#![expect(
    unreachable_pub,
    reason = "the KubeSchema derive re-emits these types inside a private module"
)]

use kube::{CustomResource, KubeSchema};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// The Secret that holds the client secret of every provider, one key for each provider.
///
/// It is in the namespace of Zeabur Identity. The name is fixed, so Zeabur Identity's Role can
/// read this Secret by name and no other Secret.
pub const SECRET: &str = "zeabur-identity-upstream";
/// Longest display name.
pub const MAX_DISPLAY_NAME: usize = 64;
/// Longest client ID.
pub const MAX_CLIENT_ID: usize = 256;
/// Most extra scopes.
pub const MAX_SCOPES: usize = 16;
/// Longest scope.
pub const MAX_SCOPE: usize = 128;
/// The admission rule for the object name: a provider ID (`upstream::ProviderId`).
pub const NAME_RULE: &str = "self.metadata.name.matches('^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$')";
/// The admission rule for the issuer: `https` with a host, visible ASCII, no user information,
/// query or fragment. Zeabur Identity checks the issuer again with `upstream::Issuer`.
pub const ISSUER_RULE: &str = concat!(
    "self.matches('^[!-~]+$') && isURL(self) && !self.matches('^[^/]*//[^/?]*@')",
    " && !self.contains('?') && !self.contains('#')",
    " && self.startsWith('https://') && url(self).getHostname() != ''",
);
/// A key of a Secret's `data`: Kubernetes allows these characters.
pub const SECRET_KEY_PATTERN: &str = r"^[-._a-zA-Z0-9]+$";
/// A scope token ([RFC 6749] §3.3: `1*NQCHAR`).
///
/// [RFC 6749]: https://www.rfc-editor.org/rfc/rfc6749.html#section-3.3
pub const SCOPE_PATTERN: &str = r"^[\x21\x23-\x5B\x5D-\x7E]+$";

/// How Zeabur Identity talks to the provider.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, JsonSchema)]
pub enum UpstreamType {
    /// An OpenID provider. Zeabur Identity reads its endpoints from its discovery document and
    /// checks its ID tokens.
    OpenID,
    /// github.com, which has OAuth 2.0 without OpenID. Zeabur Identity reads the numeric user ID
    /// from GitHub's API.
    GitHub,
}

/// A provider that people sign in with, after an administrator links their account at the
/// provider to their `User`.
///
/// The object name is the provider ID: register `<issuer>/upstream/<name>/callback` as the
/// redirect URI at the provider. Accounts are identified by the issuer and the subject, not by the
/// provider ID. Thus two objects with the same issuer sign in the same accounts.
#[derive(CustomResource, KubeSchema, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[kube(
    group = "identity.zeabur.com",
    version = "v1alpha1",
    kind = "UpstreamProvider",
    namespaced,
    shortname = "zbupstream",
    category = "zeabur-identity",
    printcolumn(name = "Type", type_ = "string", json_path = ".spec.type"),
    printcolumn(name = "Issuer", type_ = "string", json_path = ".spec.issuer"),
    printcolumn(
        name = "Age",
        type_ = "date",
        json_path = ".metadata.creationTimestamp"
    ),
    validation = Rule::new(NAME_RULE).message(
        "the name must be 1 to 63 characters of a-z, 0-9 and -, with a letter or digit first and last"
    ),
    doc = "A GitHub OAuth app or an OpenID provider that people sign in to Zeabur Identity with."
)]
#[x_kube(
    validation = Rule::new("(self.type == 'OpenID') == has(self.issuer)")
        .message("issuer is set exactly when type is OpenID"),
    validation = Rule::new("(self.type == 'OpenID') == has(self.displayName)")
        .message("displayName is set exactly when type is OpenID"),
    validation = Rule::new("self.type == 'OpenID' || !has(self.scopes)")
        .message("scopes are set only when type is OpenID")
)]
#[serde(rename_all = "camelCase")]
pub struct UpstreamProviderSpec {
    /// `OpenID` or `GitHub`.
    #[serde(rename = "type")]
    pub kind: UpstreamType,

    /// The client ID registered at the provider.
    #[schemars(length(min = 1, max = MAX_CLIENT_ID), regex(pattern = r"^[!-~]+$"))]
    pub client_id: String,

    /// The key of the client secret in the Secret `zeabur-identity-upstream`.
    #[schemars(length(min = 1, max = 253), regex(pattern = SECRET_KEY_PATTERN))]
    pub client_secret_key: String,

    /// `OpenID` only: the issuer, exactly as in the `iss` claim of its ID tokens. Zeabur Identity
    /// reads `<issuer>/.well-known/openid-configuration`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(length(min = 1, max = 256))]
    #[x_kube(validation = Rule::new(ISSUER_RULE).message(
        "the issuer must be https:// with a host; visible ASCII, no user information, query or fragment"
    ))]
    pub issuer: Option<String>,

    /// `OpenID` only: the name on the sign-in button, for example "Keycloak".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(length(min = 1, max = MAX_DISPLAY_NAME))]
    pub display_name: Option<String>,

    /// `OpenID` only: scopes to request in addition to `openid`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(
        length(max = MAX_SCOPES),
        inner(length(min = 1, max = MAX_SCOPE), regex(pattern = SCOPE_PATTERN))
    )]
    pub scopes: Option<Vec<String>>,
}
