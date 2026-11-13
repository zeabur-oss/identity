//! `zeabur-identity`: the passkey-first OpenID Connect issuer for Kubernetes.

#![forbid(unsafe_code)]

use std::process::ExitCode;

use clap::Parser as _;
use tracing_subscriber::filter::Targets;
use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::util::SubscriberInitExt as _;
use zeabur_identity::cli::{LogFormat, ServeArgs, WORKER_THREADS};
use zeabur_identity::serve::ServeError;

fn main() -> ExitCode {
    serve(&ServeArgs::parse())
}

fn serve(args: &ServeArgs) -> ExitCode {
    init_logging(args.log_format);
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
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(WORKER_THREADS)
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            tracing::error!(
                reason = "runtime_creation_failed",
                %error,
                "starting the async runtime failed"
            );
            return ExitCode::FAILURE;
        }
    };
    match runtime.block_on(zeabur_identity::serve::serve(config)) {
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
