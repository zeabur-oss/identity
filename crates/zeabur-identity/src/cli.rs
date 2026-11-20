//! Command-line flags of the `zeabur-identity` server.

use std::net::SocketAddr;
use std::time::Duration;

use clap::{Args, Parser, Subcommand, ValueEnum};
use zeabur_identity_core::config::{BaseUrl, ConfigError, parse_duration};
use zeabur_identity_keys::rotation::RotationPolicy;

use crate::config::{ServeConfig, Store};

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
#[command(
    name = "zeabur-identity",
    version,
    about,
    args_conflicts_with_subcommands = true,
    subcommand_negates_reqs = true
)]
pub struct Cli {
    /// Without a command, the server runs.
    #[command(subcommand)]
    pub command: Option<Command>,
    /// The server's flags. None is required here: their environment variables, set in the pod,
    /// would otherwise make clap ask for them under a command too.
    #[command(flatten)]
    pub serve: ServeArgs,
}

/// One-off commands, run with the pod's service account.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Store the setup token whose hash is given, for a token the caller made, such as a Helm
    /// chart that prints the link in its notes. Creates the `User` as an admin account if it does
    /// not exist. Changes nothing when the user can already sign in.
    SetupLink(SetupLinkArgs),
}

/// `zeabur-identity setup-link`.
#[derive(Debug, Args)]
pub struct SetupLinkArgs {
    /// The `User` the token enrols.
    #[arg(long, default_value = "admin")]
    pub user: String,
    /// `sha256:` and the lowercase hex SHA-256 of the token.
    #[arg(long, value_parser = parse_token_hash)]
    pub token_hash: String,
    /// How long the token stays valid, at most 7 days.
    #[arg(long, default_value = "24h", value_parser = parse_duration)]
    pub valid_for: Duration,
    /// Namespace Zeabur Identity runs in.
    #[arg(long, env = "ZEABUR_IDENTITY_NAMESPACE")]
    pub namespace: String,
}

/// The server's flags.
#[derive(Debug, Args)]
pub struct ServeArgs {
    /// Issuer identifier: an https URL with no path and no trailing slash. It must match
    /// kube-apiserver's `issuer.url` byte for byte. Required.
    #[arg(long, env = "ZEABUR_IDENTITY_ISSUER", value_parser = parse_issuer)]
    pub issuer: Option<BaseUrl>,

    /// Address of the public HTTP listener. TLS is terminated in front of it.
    #[arg(long, env = "ZEABUR_IDENTITY_LISTEN", default_value = "0.0.0.0:8080")]
    pub listen: SocketAddr,

    /// Log format.
    #[arg(long, env = "ZEABUR_IDENTITY_LOG_FORMAT", value_enum, default_value_t = LogFormat::Json)]
    pub log_format: LogFormat,

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

    /// Lifetime of an admin account's access and ID tokens. They carry `cluster-admin`.
    #[arg(long, env = "ZEABUR_IDENTITY_ADMIN_TOKEN_LIFETIME", default_value = "5m", value_parser = parse_duration)]
    pub admin_token_lifetime: Duration,

    /// An admin account's refresh-token family ends if unused this long, when several teams share
    /// the cluster or admins need a device-bound passkey. Otherwise `--refresh-idle` applies.
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

fn parse_issuer(input: &str) -> Result<BaseUrl, ConfigError> {
    BaseUrl::parse("issuer", input)
}

fn parse_internal_url(input: &str) -> Result<BaseUrl, ConfigError> {
    BaseUrl::parse("internal URL", input)
}

fn parse_token_hash(input: &str) -> Result<String, String> {
    let hex = input.strip_prefix("sha256:").filter(|hex| {
        hex.len() == 64 && hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    });
    hex.map(|_| input.to_owned())
        .ok_or_else(|| "expected sha256: and 64 lowercase hex digits".to_owned())
}

impl ServeArgs {
    /// Builds and validates the server configuration.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] if the issuer is missing or the values are inconsistent.
    pub fn config(&self) -> Result<ServeConfig, ConfigError> {
        let issuer = self.issuer.clone().ok_or(ConfigError::Incomplete(
            "--issuer (ZEABUR_IDENTITY_ISSUER) is required",
        ))?;
        let config = ServeConfig {
            issuer,
            listen: self.listen,
            rotation: RotationPolicy::DEFAULT,
            metadata_max_age: METADATA_MAX_AGE,
            invitations: self.invitations,
            internal_listen: self.internal_listen,
            internal_url: self.internal_url.clone(),
            store: Store {
                namespace: self.namespace.clone(),
                key_secret: zeabur_identity_k8s::KEY_SECRET.to_owned(),
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

    fn cli(args: &[&str]) -> Result<Cli, clap::Error> {
        Cli::try_parse_from(std::iter::once("zeabur-identity").chain(args.iter().copied()))
    }

    fn parse(args: &[&str]) -> Result<ServeArgs, clap::Error> {
        cli(args).map(|cli| cli.serve)
    }

    #[test]
    fn cli_definition_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn setup_link_needs_no_issuer_and_a_well_formed_hash() {
        let hash = format!("sha256:{}", "0a".repeat(32));
        let parsed = cli(&["setup-link", "--token-hash", &hash, "--namespace", "id"]).unwrap();
        let Some(Command::SetupLink(args)) = parsed.command else {
            panic!("expected setup-link");
        };
        assert_eq!((args.user.as_str(), args.token_hash), ("admin", hash));
        for bad in [
            "0a".repeat(32),
            format!("sha256:{}", "0A".repeat(32)),
            format!("sha256:{}", "0a".repeat(31)),
        ] {
            assert!(cli(&["setup-link", "--token-hash", &bad, "--namespace", "id"]).is_err());
        }
    }

    #[test]
    fn server_flags_do_not_mix_with_a_command() {
        let hash = format!("sha256:{}", "0a".repeat(32));
        let mixed = ["--issuer", "https://login.example.com", "setup-link"];
        assert!(cli(&mixed).is_err());
        assert!(cli(&["--token-hash", &hash]).is_err());
    }

    #[test]
    fn rejects_bad_issuers_and_inconsistent_timings() {
        assert!(parse(&[]).unwrap().config().is_err());
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
