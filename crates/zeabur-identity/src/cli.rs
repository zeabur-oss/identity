//! Command-line flags of the `zeabur-identity` server.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use clap::{Parser, ValueEnum};
use zeabur_identity_core::config::{BaseUrl, ConfigError, parse_duration};
use zeabur_identity_keys::rotation::RotationPolicy;
use zeabur_identity_signin::upstream::provider::Kind;

use crate::config::{ServeConfig, Store, UpstreamConfig};

/// `Cache-Control: max-age` for discovery documents and the JWK set.
pub const METADATA_MAX_AGE: Duration = Duration::from_mins(5);

/// Tokio worker threads. Two keep idle memory low.
pub const WORKER_THREADS: usize = 2;

/// Log output format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum LogFormat {
    /// One JSON object per line.
    Json,
    /// Human-readable text.
    Text,
}

/// Passkey-first OpenID Connect issuer for Kubernetes. Every flag can also be set through its
/// environment variable.
#[derive(Debug, Parser)]
#[command(name = "zeabur-identity", version, about)]
pub struct ServeArgs {
    /// Issuer identifier: an https URL with no path and no trailing slash. It must match
    /// kube-apiserver's `issuer.url` byte for byte.
    #[arg(long, env = "ZEABUR_IDENTITY_ISSUER", value_parser = parse_issuer)]
    pub issuer: BaseUrl,

    /// Address of the public HTTP listener. TLS is terminated in front of it.
    #[arg(long, env = "ZEABUR_IDENTITY_LISTEN", default_value = "0.0.0.0:8080")]
    pub listen: SocketAddr,

    /// Log format.
    #[arg(long, env = "ZEABUR_IDENTITY_LOG_FORMAT", value_enum, default_value_t = LogFormat::Json)]
    pub log_format: LogFormat,

    /// Where state is kept.
    #[arg(long, env = "ZEABUR_IDENTITY_STORE", value_enum, default_value_t = StoreKind::Kubernetes)]
    pub store: StoreKind,

    /// Kubernetes namespace for state; defaults to the pod's namespace (or the kubeconfig
    /// context's).
    #[arg(long, env = "ZEABUR_IDENTITY_NAMESPACE")]
    pub namespace: Option<String>,

    /// Lifetime of a regular account's access and ID tokens. kube-apiserver cannot revoke them,
    /// so this is also how long a revoked session can still call the cluster.
    #[arg(long, env = "ZEABUR_IDENTITY_TOKEN_LIFETIME", default_value = "10m", value_parser = parse_duration)]
    pub token_lifetime: Duration,

    /// A refresh-token family ends if unused this long.
    #[arg(long, env = "ZEABUR_IDENTITY_REFRESH_IDLE", default_value = "1h", value_parser = parse_duration)]
    pub refresh_idle: Duration,

    /// A refresh-token family ends this long after sign-in.
    #[arg(long, env = "ZEABUR_IDENTITY_REFRESH_ABSOLUTE", default_value = "12h", value_parser = parse_duration)]
    pub refresh_absolute: Duration,

    /// Accept invitations (`zeabur-identityctl invite`) as enrolment links.
    #[arg(long, env = "ZEABUR_IDENTITY_INVITATIONS")]
    pub invitations: bool,

    /// Enable "Continue with GitHub": the OAuth app's client ID. Register
    /// `<issuer>/upstream/github/callback` as its callback URL.
    #[arg(
        long,
        env = "ZEABUR_IDENTITY_GITHUB_CLIENT_ID",
        requires = "github_client_secret_file"
    )]
    pub github_client_id: Option<String>,

    /// File holding the GitHub OAuth app's client secret.
    #[arg(
        long,
        env = "ZEABUR_IDENTITY_GITHUB_CLIENT_SECRET_FILE",
        requires = "github_client_id"
    )]
    pub github_client_secret_file: Option<PathBuf>,

    /// Enable "Continue with Google": the OAuth client ID. Register
    /// `<issuer>/upstream/google/callback` as an authorized redirect URI.
    #[arg(
        long,
        env = "ZEABUR_IDENTITY_GOOGLE_CLIENT_ID",
        requires = "google_client_secret_file"
    )]
    pub google_client_id: Option<String>,

    /// File holding the Google OAuth client secret.
    #[arg(
        long,
        env = "ZEABUR_IDENTITY_GOOGLE_CLIENT_SECRET_FILE",
        requires = "google_client_id"
    )]
    pub google_client_secret_file: Option<PathBuf>,

    /// Lifetime of an admin account's access and ID tokens. They carry `cluster-admin`.
    #[arg(long, env = "ZEABUR_IDENTITY_ADMIN_TOKEN_LIFETIME", default_value = "5m", value_parser = parse_duration)]
    pub admin_token_lifetime: Duration,

    /// An admin account's refresh-token family ends if unused this long, when several teams share
    /// the cluster or AAL3 is on. Otherwise `--refresh-idle` applies.
    #[arg(long, env = "ZEABUR_IDENTITY_ADMIN_REFRESH_IDLE", default_value = "15m", value_parser = parse_duration)]
    pub admin_refresh_idle: Duration,

    /// Address of the internal TLS listener kube-apiserver fetches discovery and keys from.
    /// Binds at startup; TLS handshakes fail until `zeabur-identityctl kube-config` issues its
    /// certificate (Kubernetes store only).
    #[arg(
        long,
        env = "ZEABUR_IDENTITY_INTERNAL_LISTEN",
        default_value = "0.0.0.0:8443"
    )]
    pub internal_listen: SocketAddr,

    /// Base URL kube-apiserver uses for the internal listener; by default the one recorded in
    /// the certificate Secret.
    #[arg(long, env = "ZEABUR_IDENTITY_INTERNAL_URL", value_parser = parse_internal_url)]
    pub internal_url: Option<BaseUrl>,
}

/// Storage backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum StoreKind {
    /// Kubernetes objects.
    Kubernetes,
    /// Process memory (development only).
    Memory,
}

fn parse_issuer(input: &str) -> Result<BaseUrl, ConfigError> {
    BaseUrl::parse("issuer", input)
}

fn parse_internal_url(input: &str) -> Result<BaseUrl, ConfigError> {
    BaseUrl::parse("internal URL", input)
}

impl ServeArgs {
    /// Builds and validates the server configuration.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] if the values are inconsistent.
    pub fn config(&self) -> Result<ServeConfig, ConfigError> {
        let config = ServeConfig {
            issuer: self.issuer.clone(),
            listen: self.listen,
            rotation: RotationPolicy::DEFAULT,
            metadata_max_age: METADATA_MAX_AGE,
            invitations: self.invitations,
            upstream: [
                (
                    Kind::GitHub,
                    &self.github_client_id,
                    &self.github_client_secret_file,
                ),
                (
                    Kind::Google,
                    &self.google_client_id,
                    &self.google_client_secret_file,
                ),
            ]
            .into_iter()
            .filter_map(|(kind, id, secret)| {
                Some(UpstreamConfig {
                    kind,
                    client_id: id.clone()?,
                    client_secret_file: secret.clone()?,
                })
            })
            .collect(),
            internal_listen: self.internal_listen,
            internal_url: self.internal_url.clone(),
            store: match self.store {
                StoreKind::Kubernetes => Store::Kubernetes {
                    namespace: self.namespace.clone(),
                    key_secret: zeabur_identity_k8s::KEY_SECRET.to_owned(),
                },
                StoreKind::Memory => Store::Memory,
            },
            lifetimes: zeabur_identity_oauth::Lifetimes {
                access_token: self.token_lifetime,
                refresh_idle: self.refresh_idle,
                refresh_absolute: self.refresh_absolute,
                admin_access_token: self.admin_token_lifetime,
                admin_refresh_idle: self.admin_refresh_idle,
                ..zeabur_identity_oauth::Lifetimes::DEFAULT
            },
        };
        config.validate()?;
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory as _;

    use super::*;

    fn parse(args: &[&str]) -> Result<ServeArgs, clap::Error> {
        ServeArgs::try_parse_from(std::iter::once("zeabur-identity").chain(args.iter().copied()))
    }

    #[test]
    fn cli_definition_is_valid() {
        ServeArgs::command().debug_assert();
    }

    #[test]
    fn rejects_bad_issuers_and_inconsistent_timings() {
        assert!(parse(&["--issuer", "http://login.example.com"]).is_err());
        let args = parse(&[
            "--issuer",
            "https://login.example.com",
            "--token-lifetime",
            "2h",
        ])
        .unwrap();
        assert!(args.config().is_err());
    }
}
