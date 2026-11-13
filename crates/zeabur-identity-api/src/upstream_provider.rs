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
/// A scope token ([RFC 6749] §3.3: `1*NQCHAR`).
///
/// [RFC 6749]: https://www.rfc-editor.org/rfc/rfc6749.html#section-3.3
pub const SCOPE_PATTERN: &str = r"^[\x21\x23-\x5B\x5D-\x7E]+$";

/// A provider that people sign in with, after an administrator links their account at the
/// provider to their `User`.
///
/// The object name is the provider ID: register `<issuer>/upstream/<name>/callback` as the
/// redirect URI at the provider. The client secret is the key with the object name in the Secret
/// `zeabur-identity-upstream`. Accounts are identified by the issuer and the subject, not by the
/// provider ID. Thus two objects with the same issuer sign in the same accounts.
#[derive(CustomResource, KubeSchema, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[kube(
    group = "identity.zeabur.com",
    version = "v1alpha1",
    kind = "UpstreamProvider",
    namespaced,
    shortname = "zbupstream",
    category = "zeabur-identity",
    printcolumn(name = "Issuer", type_ = "string", json_path = ".spec.openid.issuer"),
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
#[serde(rename_all = "camelCase")]
pub struct UpstreamProviderSpec {
    /// The client ID registered at the provider.
    #[schemars(length(min = 1, max = MAX_CLIENT_ID), regex(pattern = r"^[!-~]+$"))]
    pub client_id: String,

    /// How Zeabur Identity talks to the provider.
    #[serde(flatten)]
    pub kind: UpstreamKind,
}

/// How Zeabur Identity talks to the provider. The field that is set names the kind.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum UpstreamKind {
    /// An OpenID provider. Zeabur Identity reads its endpoints from its discovery document and
    /// checks its ID tokens.
    OpenID(OpenID),
    /// github.com, which has OAuth 2.0 without OpenID. Zeabur Identity reads the numeric user ID
    /// from GitHub's API.
    GitHub(GitHub),
}

/// An OpenID provider.
#[derive(KubeSchema, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct OpenID {
    /// The issuer, exactly as in the `iss` claim of its ID tokens. Zeabur Identity reads
    /// `<issuer>/.well-known/openid-configuration`.
    #[schemars(length(min = 1, max = 256))]
    #[x_kube(validation = Rule::new(ISSUER_RULE).message(
        "the issuer must be https:// with a host; visible ASCII, no user information, query or fragment"
    ))]
    pub issuer: String,

    /// The name on the sign-in button, for example "Keycloak". The object name if not set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(length(min = 1, max = MAX_DISPLAY_NAME))]
    pub display_name: Option<String>,

    /// Scopes to request in addition to `openid`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(
        length(max = MAX_SCOPES),
        inner(length(min = 1, max = MAX_SCOPE), regex(pattern = SCOPE_PATTERN))
    )]
    pub scopes: Option<Vec<String>>,
}

/// github.com. It has nothing to set.
#[expect(
    clippy::empty_structs_with_brackets,
    reason = "serde reads `github: {}` into a struct with braces, not into a unit struct"
)]
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq, JsonSchema)]
pub struct GitHub {}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn the_field_that_is_set_names_the_kind() {
        let github: UpstreamProviderSpec =
            serde_json::from_value(json!({"clientId": "Iv1.abc", "github": {}})).unwrap();
        assert_eq!(github.kind, UpstreamKind::GitHub(GitHub {}));
        let openid: UpstreamProviderSpec = serde_json::from_value(
            json!({"clientId": "c", "openid": {"issuer": "https://accounts.google.com"}}),
        )
        .unwrap();
        let UpstreamKind::OpenID(openid) = openid.kind else {
            panic!("{openid:?}");
        };
        assert_eq!(openid.issuer, "https://accounts.google.com");
        assert_eq!(openid.display_name, None);
    }

    #[test]
    fn a_v0_2_0_object_without_a_kind_field_is_refused() {
        let stored = json!({"type": "GitHub", "clientId": "Iv1.abc", "clientSecretKey": "github"});
        assert!(serde_json::from_value::<UpstreamProviderSpec>(stored).is_err());
    }
}
