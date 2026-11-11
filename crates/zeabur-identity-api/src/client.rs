//! `OAuthClient`: a registered relying party.

#![expect(
    unreachable_pub,
    reason = "the KubeSchema derive re-emits these types inside a private module"
)]

use kube::{CustomResource, KubeSchema};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Client type (RFC 6749 §2.1).
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, JsonSchema)]
pub enum ClientType {
    /// Cannot keep a secret; identifies itself with `client_id` only. Like every client, it
    /// must use PKCE.
    Public,
    /// Authenticates at the token endpoint.
    Confidential,
}

/// A JWS signing algorithm this issuer uses.
///
/// kube-apiserver accepts only the RS, ES and PS families ([kube-apiserver OIDC]), so EdDSA is
/// not offered. ES256 is the default for every token: smaller tokens and faster signing than
/// RS256, and [RFC 7518] §3.1 marks it "Recommended+". RS256 exists only because
/// [OIDC Discovery] §3 requires it in `id_token_signing_alg_values_supported`.
///
/// [kube-apiserver OIDC]: https://github.com/kubernetes/kubernetes/blob/master/staging/src/k8s.io/apiserver/plugin/pkg/authenticator/token/oidc/oidc.go
/// [RFC 7518]: https://www.rfc-editor.org/rfc/rfc7518
/// [OIDC Discovery]: https://openid.net/specs/openid-connect-discovery-1_0.html
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
pub enum Algorithm {
    /// ECDSA using P-256 and SHA-256 (RFC 7518 §3.4).
    #[serde(rename = "ES256")]
    Es256,
    /// RSASSA-PKCS1-v1_5 using SHA-256 (RFC 7518 §3.3).
    #[serde(rename = "RS256")]
    Rs256,
}

impl Algorithm {
    /// All algorithms, in the order they are advertised.
    pub const ALL: [Self; 2] = [Self::Es256, Self::Rs256];

    /// The JWA name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Es256 => "ES256",
            Self::Rs256 => "RS256",
        }
    }
}

/// Longest display name.
pub const MAX_DISPLAY_NAME: usize = 128;
/// Most redirect URIs per client.
pub const MAX_REDIRECT_URIS: usize = 16;
/// Longest redirect URI.
pub const MAX_REDIRECT_URI: usize = 2048;
/// Most audiences per client.
pub const MAX_AUDIENCES: usize = 16;
/// Longest audience.
pub const MAX_AUDIENCE: usize = 256;
/// The admission rule for redirect URIs (RFC 9700 §2.1, RFC 8252 §7.3).
///
/// Each is a URL by Kubernetes' CEL `isURL()` (Go's `net/url`), and either `https` with a host or
/// loopback `http` (`127.0.0.1` or `[::1]`) with a path. Printable ASCII only, so the redirect's
/// `Location` header can carry it; no fragment (RFC 6749 §3.1.2) and no user information. This is
/// the floor that keeps a GitOps mistake from reaching the server, not a full URL grammar: Go
/// accepts some hosts and ports that browsers reject.
/// `zeabur_identity_k8s::clients::redirect_uri_allowed` adds a browser's (WHATWG) parse on top, for
/// tools that check before `kubectl apply`.
pub const REDIRECT_URI_RULE: &str = concat!(
    "self.all(u, u.matches('^[!-~]+$') && !u.contains('#') && isURL(u)",
    " && !u.matches('^[^/]*//[^/?]*@')",
    " && (url(u).getScheme() == 'https' ? url(u).getHostname() != ''",
    " : url(u).getScheme() == 'http' && url(u).getHostname() in ['127.0.0.1', '::1']",
    " && url(u).getEscapedPath() != ''))",
);
/// The admission rule for the home URL: `https` with a host, printable ASCII, no user
/// information, as for redirect URIs.
pub const HOME_URL_RULE: &str = concat!(
    "self.matches('^[!-~]+$') && isURL(self) && !self.matches('^[^/]*//[^/?]*@')",
    " && url(self).getScheme() == 'https' && url(self).getHostname() != ''",
);
/// The stored secret: `sha256:` and the lowercase hex SHA-256 of the secret.
pub const SECRET_HASH_PATTERN: &str = r"^sha256:[0-9a-f]{64}$";

/// A registered OAuth 2.0 / OpenID Connect client. The object name is the `client_id`.
///
/// Admission rules reject redirect URIs that RFC 9700 §2.1 and OAuth 2.1 forbid, so a
/// mistake in a GitOps repository fails at `kubectl apply`, not at login.
#[derive(CustomResource, KubeSchema, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[kube(
    group = "identity.zeabur.com",
    version = "v1alpha1",
    kind = "OAuthClient",
    namespaced,
    shortname = "zbclient",
    category = "zeabur-identity",
    printcolumn(name = "Type", type_ = "string", json_path = ".spec.type"),
    printcolumn(
        name = "Age",
        type_ = "date",
        json_path = ".metadata.creationTimestamp"
    ),
    doc = "An OAuth 2.0 / OpenID Connect client registered with Zeabur Identity."
)]
#[x_kube(
    validation = Rule::new("(self.type == 'Confidential') == has(self.secretHash)")
        .message("secretHash is required for confidential clients and forbidden for public clients")
)]
#[serde(rename_all = "camelCase")]
pub struct OAuthClientSpec {
    /// Name shown on the consent and login pages.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(length(max = MAX_DISPLAY_NAME))]
    pub display_name: Option<String>,

    /// Public clients (kubectl, native apps) cannot keep a secret; confidential clients can.
    #[serde(rename = "type")]
    pub kind: ClientType,

    /// Redirect URIs, compared by exact string match. Each is `https://` with a host, or
    /// `http://127.0.0.1` / `http://[::1]` with a path for native apps (RFC 8252 §7.3); ASCII URI
    /// characters only, no fragment.
    #[schemars(
        length(min = 1, max = MAX_REDIRECT_URIS),
        inner(length(max = MAX_REDIRECT_URI))
    )]
    #[x_kube(validation = Rule::new(REDIRECT_URI_RULE).message(
        "each redirect URI must be https:// with a host, or http://127.0.0.1 or http://[::1] with a path; printable ASCII, no fragment or user information"
    ))]
    pub redirect_uris: Vec<String>,

    /// Audiences this client may request tokens for (RFC 8707 resource indicators), for example
    /// the `audiences` entry of the cluster's AuthenticationConfiguration.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[schemars(length(max = MAX_AUDIENCES), inner(length(min = 1, max = MAX_AUDIENCE)))]
    pub audiences: Vec<String>,

    /// SHA-256 of the client secret, as `sha256:<64 hex digits>`. The secret itself is never
    /// stored.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(regex(pattern = SECRET_HASH_PATTERN))]
    pub secret_hash: Option<String>,

    /// Algorithm for ID tokens: `ES256` (default) or `RS256` for clients that need it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id_token_signing_alg: Option<Algorithm>,

    /// Where people open this application, for example `https://zeabur.example.com/`. When set,
    /// the sign-in page links here, labelled with the display name, for anyone who reaches it with
    /// nothing to sign in to, and after someone sets up a passkey.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(length(max = MAX_REDIRECT_URI))]
    #[x_kube(validation = Rule::new(HOME_URL_RULE).message(
        "the home URL must be https:// with a host; printable ASCII, no user information"
    ))]
    pub home_url: Option<String>,
}

/// What `zeabur-identityctl client create --output json` writes to stdout, as one JSON object.
///
/// For a confidential client, `token_hash(secret)` is the manifest's `spec.secretHash`
/// ([`crate::token_hash`]).
#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ClientRegistration {
    /// The `client_id`, also the name of the manifest.
    pub client_id: String,
    /// The plaintext secret of a confidential client: 64 lowercase hex digits. Absent for a
    /// public client. Nothing else holds it, and the manifest holds only its hash.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret: Option<String>,
    /// The `OAuthClient` to apply.
    pub manifest: OAuthClient,
}

impl std::fmt::Debug for ClientRegistration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientRegistration")
            .field("client_id", &self.client_id)
            .field("secret", &self.secret.as_ref().map(|_secret| "<redacted>"))
            .field("manifest", &self.manifest)
            .finish()
    }
}
