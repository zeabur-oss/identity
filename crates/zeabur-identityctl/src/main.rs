#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]

mod cli;
mod output;

use std::process::ExitCode;

use clap::Parser as _;
use zeabur_identity_core::clock::Clock as _;
use zeabur_identity_k8s::crd::user::AccountType;

use crate::cli::{
    AccountTypeArg, AccountTypeArgs, Cli, ClientCommand, ClientCreateArgs, ClientKind, Command,
    InviteArgs, KubeConfigArgs, SetupLinkArgs, SigningAlg,
};

fn main() -> ExitCode {
    match Cli::parse().command {
        Command::SetupLink(args) => setup_link(&args),
        Command::Crds => print_json(zeabur_identity_k8s::crd::definitions_json()),
        Command::Rbac { namespace } => {
            print_json(zeabur_identity_k8s::rbac::manifests_json(&namespace))
        }
        Command::Manifests(args) => print_json(zeabur_identity_k8s::deployment::manifests_json(
            &args.namespace,
            &args.issuer,
            &zeabur_identity_k8s::deployment::Options {
                image: args.image.clone(),
                serve_args: args.serve_args.clone(),
                config_secret: args.config_secret.clone(),
            },
        )),
        Command::KubeConfig(args) => kube_config(&args),
        Command::Invite(args) => invite(&args),
        Command::AccountType(args) => account_type(&args),
        Command::Client {
            command: ClientCommand::Create(args),
        } => client_create(args),
    }
}

fn client_create(args: ClientCreateArgs) -> ExitCode {
    use zeabur_identity_k8s::crd::client::ClientType;
    let new = zeabur_identity_k8s::clients::NewClient {
        kind: match args.kind {
            ClientKind::Public => ClientType::Public,
            ClientKind::Confidential => ClientType::Confidential,
        },
        id_token_signing_alg: args.id_token_signing_alg.map(|alg| match alg {
            SigningAlg::Es256 => zeabur_identity_keys::Algorithm::Es256,
            SigningAlg::Rs256 => zeabur_identity_keys::Algorithm::Rs256,
        }),
        client_id: args.client_id,
        display_name: args.display_name,
        redirect_uris: args.redirect_uris,
        audiences: args.audiences,
        home_url: args.home_url,
    };
    let registration = match zeabur_identity_k8s::clients::register(new, &args.namespace) {
        Ok(registration) => registration,
        Err(error) => {
            output::stderr(&format!("error: {error}"));
            return ExitCode::FAILURE;
        }
    };
    let code = print_json(serde_json::to_string_pretty(&registration.client));
    if let Some(secret) = registration.secret {
        output::stderr(
            "Client secret (shown only once; the cluster keeps only its hash, so a lost secret has to be replaced):",
        );
        output::stderr(&secret);
    }
    code
}

fn invite(args: &InviteArgs) -> ExitCode {
    let Some(runtime) = current_thread_runtime() else {
        return ExitCode::FAILURE;
    };
    let invitee = zeabur_identity_k8s::invitations::Invitee {
        username: args.username.clone(),
        display_name: args.display_name.clone(),
        groups: args.groups.clone(),
        account_type: if args.admin {
            AccountType::Admin
        } else {
            AccountType::Regular
        },
    };
    let result = runtime.block_on(async {
        let client = kube::Client::try_default().await?;
        zeabur_identity_k8s::invitations::invite(
            client,
            &args.namespace,
            &args.issuer,
            &invitee,
            args.valid_for,
            args.reset,
            zeabur_identity_core::clock::SystemClock.now(),
        )
        .await
        .map_err(|error| -> Box<dyn std::error::Error> { Box::new(error) })
    });
    match result {
        Ok(created) => {
            if !created.created_user {
                output::stderr(&format!(
                    "User {} already exists; this command left its groups and account type unchanged.",
                    args.username
                ));
            }
            output::stdout(&created.url);
            output::stderr(&format!(
                "Send this link to {}. It works once and expires in {}.",
                args.username,
                span(args.valid_for)
            ));
            ExitCode::SUCCESS
        }
        Err(error) => {
            output::stderr(&format!("error: {error}"));
            ExitCode::FAILURE
        }
    }
}

fn account_type(args: &AccountTypeArgs) -> ExitCode {
    let Some(runtime) = current_thread_runtime() else {
        return ExitCode::FAILURE;
    };
    let account_type = match args.account_type {
        AccountTypeArg::Admin => AccountType::Admin,
        AccountTypeArg::Regular => AccountType::Regular,
    };
    let result = runtime.block_on(async {
        let client = kube::Client::try_default().await?;
        zeabur_identity_k8s::users::set_account_type(
            client,
            &args.namespace,
            &args.username,
            account_type,
        )
        .await
    });
    match result {
        Ok(_) => {
            let note = match account_type {
                AccountType::Admin => {
                    "is now an admin account. It signs in with a passkey only; sessions from GitHub or Google end at their next refresh."
                }
                AccountType::Regular => {
                    "is now a regular account. Its tokens lose the admins group at the next refresh, within 5 minutes."
                }
            };
            output::stderr(&format!("{} {note}", args.username));
            ExitCode::SUCCESS
        }
        Err(error) => {
            output::stderr(&format!("error: {error}"));
            ExitCode::FAILURE
        }
    }
}

fn current_thread_runtime() -> Option<tokio::runtime::Runtime> {
    match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => Some(runtime),
        Err(error) => {
            output::stderr(&format!(
                "error: unable to start the async runtime: {error}"
            ));
            None
        }
    }
}

fn kube_config(args: &KubeConfigArgs) -> ExitCode {
    let Some(runtime) = current_thread_runtime() else {
        return ExitCode::FAILURE;
    };
    let request = zeabur_identity_k8s::kube_config::Request {
        namespace: args.namespace.clone(),
        distro: args.distro,
        issuer: args.issuer.clone(),
        discovery: args.discovery,
        audiences: args.audiences.clone(),
        max_token_lifetime: args.max_token_lifetime,
    };
    let result = runtime.block_on(async {
        let client = kube::Client::try_default().await?;
        zeabur_identity_k8s::kube_config::prepare(client, &request)
            .await
            .map_err(|error| -> Box<dyn std::error::Error> { Box::new(error) })
    });
    match result {
        Ok(configuration) => {
            output::stdout(configuration.trim_end());
            output::stderr(
                zeabur_identity_k8s::kube_config::instructions(args.distro, args.discovery)
                    .trim_end(),
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            output::stderr(&format!("error: {error}"));
            ExitCode::FAILURE
        }
    }
}

fn setup_link(args: &SetupLinkArgs) -> ExitCode {
    let Some(runtime) = current_thread_runtime() else {
        return ExitCode::FAILURE;
    };
    let result = runtime.block_on(async {
        let client = kube::Client::try_default().await?;
        let now = zeabur_identity_core::clock::SystemClock.now();
        zeabur_identity_k8s::setup::issue_setup_link(
            client,
            &args.namespace,
            &args.issuer,
            &args.username,
            args.valid_for,
            args.reset,
            now,
        )
        .await
        .map_err(|error| -> Box<dyn std::error::Error> { Box::new(error) })
    });
    match result {
        Ok(link) => {
            output::stdout(&link.url);
            output::stderr(&format!(
                "Open this link in a browser to enroll a passkey for {}. It works once and expires in {}.",
                args.username,
                span(args.valid_for)
            ));
            ExitCode::SUCCESS
        }
        Err(error) => {
            output::stderr(&format!("error: {error}"));
            ExitCode::FAILURE
        }
    }
}

/// A duration in the largest whole unit that states it exactly: `7 days`, `12 hours`, `90
/// minutes`, `45 seconds`.
fn span(duration: std::time::Duration) -> String {
    let secs = duration.as_secs();
    let (count, unit) = [(86_400, "day"), (3_600, "hour"), (60, "minute")]
        .into_iter()
        .find(|(size, _)| secs >= *size && secs.is_multiple_of(*size))
        .map_or((secs, "second"), |(size, unit)| (secs / size, unit));
    let plural = if count == 1 { "" } else { "s" };
    format!("{count} {unit}{plural}")
}

fn print_json(json: serde_json::Result<String>) -> ExitCode {
    match json {
        Ok(json) => {
            output::stdout(&json);
            ExitCode::SUCCESS
        }
        Err(error) => {
            output::stderr(&format!("error: {error}"));
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::span;

    #[test]
    fn spans_use_the_largest_exact_unit() {
        assert_eq!(span(Duration::from_hours(7 * 24)), "7 days");
        assert_eq!(span(Duration::from_hours(24)), "1 day");
        assert_eq!(span(Duration::from_hours(12)), "12 hours");
        assert_eq!(span(Duration::from_mins(90)), "90 minutes");
        assert_eq!(span(Duration::from_secs(45)), "45 seconds");
        assert_eq!(span(Duration::from_secs(0)), "0 seconds");
    }
}
