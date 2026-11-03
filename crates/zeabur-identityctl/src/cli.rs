//! Command-line interface of `zeabur-identityctl`.

use std::time::Duration;

use clap::{Args, Parser, Subcommand, ValueEnum};
use zeabur_identity_core::config::{BaseUrl, ConfigError, parse_duration};
use zeabur_identity_k8s::kube_config::{DiscoveryMode, Distro};

/// Administer Zeabur Identity with your own kubeconfig: install manifests, configure
/// kube-apiserver, issue setup links and invitations, register clients.
#[derive(Debug, Parser)]
#[command(name = "zeabur-identityctl", version, about)]
pub(crate) struct Cli {
    /// The command to run.
    #[command(subcommand)]
    pub command: Command,
}

/// Subcommands.
#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    /// Print the custom resource definitions as a Kubernetes `List` (JSON), for
    /// `zeabur-identityctl crds | kubectl apply -f -`.
    Crds,
    /// Print a one-time link that enrolls a passkey for a user. Uses your own kubeconfig, which
    /// needs cluster-admin rights; the link works once and expires.
    SetupLink(SetupLinkArgs),
    /// Print the namespace, service account, `Role`, `RoleBinding` and empty key Secret as a
    /// Kubernetes `List` (JSON), for `zeabur-identityctl rbac | kubectl apply -f -`.
    Rbac {
        /// Namespace to install into.
        #[arg(long, default_value = zeabur_identity_k8s::rbac::DEFAULT_NAMESPACE)]
        namespace: String,
    },
    /// Print everything to install (the `rbac` objects, the Service and the Deployment) as a
    /// Kubernetes `List` (JSON), for `zeabur-identityctl manifests … | kubectl apply -f -`.
    Manifests(ManifestsArgs),
    /// Print the total memory request of the pods `manifests` renders with its defaults, as JSON
    /// (`{"requestMemoryMiB": 24}`), so an installer can check a server has room before it
    /// downloads anything.
    Resources,
    /// Prepare kube-apiserver to accept Zeabur Identity's tokens, using your own kubeconfig
    /// (cluster admin): issues the internal listener's certificate if needed, prints the
    /// `AuthenticationConfiguration` (stdout) and how to install it (stderr).
    KubeConfig(KubeConfigArgs),
    /// Invite a user: creates the `User` if it does not exist and prints a one-time enrollment
    /// link for you to send. Uses your own kubeconfig, which needs admin rights.
    Invite(InviteArgs),
    /// Make a user an admin account or a regular account. Uses your own kubeconfig, which needs
    /// admin rights. The same as `kubectl patch user <name> --type merge -p
    /// '{"spec":{"accountType":"Admin"}}'`.
    AccountType(AccountTypeArgs),
    /// Register OAuth clients.
    Client {
        /// The client command to run.
        #[command(subcommand)]
        command: ClientCommand,
    },
}

/// `zeabur-identityctl client` subcommands.
#[derive(Debug, Subcommand)]
pub(crate) enum ClientCommand {
    /// Print an `OAuthClient` (JSON), for `zeabur-identityctl client create … | kubectl apply -f
    /// -`. A confidential client gets a generated secret, printed once on stderr; only its hash
    /// goes into the object.
    Create(ClientCreateArgs),
}

/// Arguments of `zeabur-identityctl client create`.
#[derive(Debug, Args)]
pub(crate) struct ClientCreateArgs {
    /// The client ID, also the object name: a lowercase DNS subdomain of at most 63 characters.
    pub client_id: String,
    /// `public` for clients that cannot keep a secret (kubectl, native and browser apps),
    /// `confidential` for servers.
    #[arg(long = "type", value_enum)]
    pub kind: ClientKind,
    /// Redirect URI (repeatable): `https://` with a host, or `http://127.0.0.1` / `http://[::1]`
    /// with a path for native apps; any port matches for those.
    #[arg(long = "redirect-uri", required = true)]
    pub redirect_uris: Vec<String>,
    /// Audience the client may request tokens for (repeatable), for example `kubernetes`.
    #[arg(long = "audience")]
    pub audiences: Vec<String>,
    /// Name shown on the sign-in pages.
    #[arg(long)]
    pub display_name: Option<String>,
    /// Where people open the application (`https://` only). The sign-in page then links here,
    /// labelled with the display name, for anyone who reaches it with nothing to sign in to.
    #[arg(long)]
    pub home_url: Option<String>,
    /// ID token signing algorithm, for a client that cannot verify `ES256`.
    #[arg(long, value_enum)]
    pub id_token_signing_alg: Option<SigningAlg>,
    /// Namespace Zeabur Identity runs in.
    #[arg(long, env = "ZEABUR_IDENTITY_NAMESPACE", default_value = zeabur_identity_k8s::rbac::DEFAULT_NAMESPACE)]
    pub namespace: String,
}

/// Client type.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub(crate) enum ClientKind {
    /// Identifies itself with its client ID only.
    Public,
    /// Authenticates at the token endpoint with a generated secret.
    Confidential,
}

/// ID token signing algorithm.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub(crate) enum SigningAlg {
    /// ECDSA P-256 (the default).
    #[value(name = "ES256")]
    Es256,
    /// RSA PKCS #1 v1.5.
    #[value(name = "RS256")]
    Rs256,
}

/// Arguments of `zeabur-identityctl invite`.
#[derive(Debug, Args)]
pub(crate) struct InviteArgs {
    /// The issuer identifier (the same as `zeabur-identity --issuer`).
    #[arg(long, env = "ZEABUR_IDENTITY_ISSUER", value_parser = parse_issuer)]
    pub issuer: BaseUrl,
    /// Login name: a lowercase DNS subdomain, at most 63 characters; Kubernetes sees
    /// `zeabur:<username>`.
    #[arg(long)]
    pub username: String,
    /// Display name, for a new user.
    #[arg(long)]
    pub display_name: Option<String>,
    /// Group of a new user (repeatable).
    #[arg(long = "group")]
    pub groups: Vec<String>,
    /// Make a new user an admin account: it signs in with a passkey only, and its tokens carry
    /// the `admins` group.
    #[arg(long)]
    pub admin: bool,
    /// How long the link stays valid, at most 7 days.
    #[arg(long, default_value = "7d", value_parser = parse_duration)]
    pub valid_for: Duration,
    /// Remove the user's pending invitations, passkeys, linked accounts and sessions first
    /// (account recovery). Without it, a user who can already sign in gets no invitation.
    #[arg(long)]
    pub reset: bool,
    /// Namespace Zeabur Identity runs in.
    #[arg(long, env = "ZEABUR_IDENTITY_NAMESPACE", default_value = zeabur_identity_k8s::rbac::DEFAULT_NAMESPACE)]
    pub namespace: String,
}

/// Arguments of `zeabur-identityctl account-type`.
#[derive(Debug, Args)]
pub(crate) struct AccountTypeArgs {
    /// The `User` name.
    pub username: String,
    /// The new account type.
    #[arg(value_enum)]
    pub account_type: AccountTypeArg,
    /// Namespace Zeabur Identity runs in.
    #[arg(long, env = "ZEABUR_IDENTITY_NAMESPACE", default_value = zeabur_identity_k8s::rbac::DEFAULT_NAMESPACE)]
    pub namespace: String,
}

/// Account type.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub(crate) enum AccountTypeArg {
    /// Signs in with a passkey only; tokens carry the `admins` group.
    Admin,
    /// Signs in with every method the server offers.
    Regular,
}

/// Arguments of `zeabur-identityctl manifests`.
#[derive(Debug, Args)]
pub(crate) struct ManifestsArgs {
    /// The issuer identifier.
    #[arg(long, env = "ZEABUR_IDENTITY_ISSUER", value_parser = parse_issuer)]
    pub issuer: BaseUrl,
    /// The container image, preferably by digest.
    #[arg(long)]
    pub image: String,
    /// Namespace to install into.
    #[arg(long, default_value = zeabur_identity_k8s::rbac::DEFAULT_NAMESPACE)]
    pub namespace: String,
    /// An argument for `zeabur-identity` (repeatable), for example `--serve-arg=--invitations`.
    #[arg(long = "serve-arg", allow_hyphen_values = true)]
    pub serve_args: Vec<String>,
    /// A Secret mounted read-only at /etc/zeabur-identity, for files such as client secrets.
    #[arg(long)]
    pub config_secret: Option<String>,
}

/// Arguments of `zeabur-identityctl kube-config`.
#[derive(Debug, Args)]
pub(crate) struct KubeConfigArgs {
    /// The issuer identifier (the same as `zeabur-identity --issuer`).
    #[arg(long, env = "ZEABUR_IDENTITY_ISSUER", value_parser = parse_issuer)]
    pub issuer: BaseUrl,
    /// The Kubernetes distribution kube-apiserver belongs to.
    #[arg(long, value_enum)]
    pub distro: Distro,
    /// Namespace Zeabur Identity runs in.
    #[arg(long, env = "ZEABUR_IDENTITY_NAMESPACE", default_value = zeabur_identity_k8s::rbac::DEFAULT_NAMESPACE)]
    pub namespace: String,
    /// How kube-apiserver fetches discovery and keys.
    #[arg(long, value_enum, default_value_t = DiscoveryMode::Internal)]
    pub discovery: DiscoveryMode,
    /// Token audience kube-apiserver accepts (repeatable).
    #[arg(long = "audience", default_value = "kubernetes")]
    pub audiences: Vec<String>,
    /// Longest token lifetime kube-apiserver accepts.
    #[arg(long, default_value = "1h", value_parser = parse_duration)]
    pub max_token_lifetime: Duration,
}

/// Arguments of `zeabur-identityctl setup-link`.
#[derive(Debug, Args)]
pub(crate) struct SetupLinkArgs {
    /// The issuer identifier (the same as `zeabur-identity --issuer`).
    #[arg(long, env = "ZEABUR_IDENTITY_ISSUER", value_parser = parse_issuer)]
    pub issuer: BaseUrl,
    /// The `User` to enroll a passkey for; created as an admin account if it does not exist.
    /// The username must be a lowercase DNS subdomain of at most 63 characters.
    #[arg(long, default_value = "admin")]
    pub username: String,
    /// Namespace Zeabur Identity runs in.
    #[arg(long, env = "ZEABUR_IDENTITY_NAMESPACE", default_value = zeabur_identity_k8s::rbac::DEFAULT_NAMESPACE)]
    pub namespace: String,
    /// How long the link stays valid, at most 7 days.
    #[arg(long, default_value = "60m", value_parser = parse_duration)]
    pub valid_for: Duration,
    /// Remove the user's pending invitations, passkeys, linked accounts and sessions first
    /// (account recovery).
    #[arg(long)]
    pub reset: bool,
}

fn parse_issuer(input: &str) -> Result<BaseUrl, ConfigError> {
    BaseUrl::parse("issuer", input)
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory as _;

    use super::*;

    #[test]
    fn cli_definition_is_valid() {
        Cli::command().debug_assert();
    }
}
