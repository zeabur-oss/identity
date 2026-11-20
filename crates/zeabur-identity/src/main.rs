//! `zeabur-identity`: the passkey-first OpenID Connect issuer for Kubernetes.

#![forbid(unsafe_code)]

use std::process::ExitCode;

use clap::Parser as _;
use tracing_subscriber::filter::Targets;
use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::util::SubscriberInitExt as _;
use zeabur_identity::cli::{Cli, Command, LogFormat, ServeArgs, SetupLinkArgs};
use zeabur_identity::serve::ServeError;
use zeabur_identity_core::clock::Clock as _;
use zeabur_identity_k8s::setup::LinkError;

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    init_logging(match &cli.command {
        Some(Command::SetupLink(_)) => LogFormat::Json,
        None => cli.serve.log_format,
    });
    match &cli.command {
        Some(Command::SetupLink(args)) => setup_link(args).await,
        None => serve(&cli.serve).await,
    }
}

async fn setup_link(args: &SetupLinkArgs) -> ExitCode {
    let result = async {
        let client = kube::Client::try_default().await.map_err(LinkError::from)?;
        let now = zeabur_identity_core::clock::SystemClock.now();
        zeabur_identity_k8s::setup::store_setup_token(
            client,
            &args.namespace,
            &args.user,
            &args.token_hash,
            args.valid_for,
            false,
            now,
        )
        .await
    }
    .await;
    match result {
        Ok(expires_at) => {
            tracing::info!(user = %args.user, expires_at = expires_at.as_secs(), "setup token stored");
            ExitCode::SUCCESS
        }
        Err(LinkError::HasCredentials { .. }) => {
            tracing::info!(user = %args.user, "the user can already sign in; no setup token stored");
            ExitCode::SUCCESS
        }
        Err(error) => {
            tracing::error!(reason = "setup_link_failed", %error, "storing the setup token failed");
            ExitCode::FAILURE
        }
    }
}

async fn serve(args: &ServeArgs) -> ExitCode {
    let config = match args.config() {
        Ok(config) => config,
        Err(error) => {
            tracing::error!(
                event = "server.configuration",
                reason = "invalid_configuration",
                %error,
                "configuration failed"
            );
            return ExitCode::from(2);
        }
    };
    match zeabur_identity::serve::serve(config).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            let reason = match &error {
                ServeError::Kubernetes(_) => "kubernetes_unavailable",
                ServeError::Keys(_) => "signing_keys_failed",
                ServeError::Directory(_) => "directory_unavailable",
                ServeError::Upstream(_) => "upstream_providers_unavailable",
                ServeError::Crypto => "sealing_key_failed",
                ServeError::Config(_) => "invalid_configuration",
                ServeError::Io(_) => "http_failed",
            };
            tracing::error!(reason, %error, "exiting");
            ExitCode::FAILURE
        }
    }
}

/// One mixed stdout stream; `ZEABUR_IDENTITY_LOG` replaces the complete native target filter.
fn init_logging(format: LogFormat) {
    let fallback = || {
        "warn,zeabur-identity=info"
            .parse::<Targets>()
            .unwrap_or_default()
    };
    let (filter, invalid) = match std::env::var("ZEABUR_IDENTITY_LOG") {
        Ok(directives) => match directives.parse::<Targets>() {
            Ok(filter) => (filter, false),
            Err(_error) => (fallback(), true),
        },
        Err(std::env::VarError::NotPresent) => (fallback(), false),
        Err(std::env::VarError::NotUnicode(_value)) => (fallback(), true),
    };
    // The fmt subscriber's own INFO ceiling must not mask explicit DEBUG/TRACE directives.
    let builder = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_ansi(false);
    match format {
        LogFormat::Json => builder
            .json()
            .with_current_span(false)
            .with_span_list(false)
            .finish()
            .with(filter)
            .init(),
        LogFormat::Text => builder.finish().with(filter).init(),
    }
    if invalid {
        tracing::warn!(
            reason = "invalid_filter",
            "ignoring invalid ZEABUR_IDENTITY_LOG"
        );
    }
}
