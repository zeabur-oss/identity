//! Moves GitHub and Google sign-in from the removed `--github-*` and `--google-*` server options
//! to `UpstreamProvider` objects named `github` and `google`, with their client secrets copied
//! into [`upstream::SECRET`].
//!
//! The names keep the callback URLs registered at GitHub and Google, and the issuers stay the
//! same, so linked accounts keep working.

use std::collections::BTreeMap;

use k8s_openapi::ByteString;
use k8s_openapi::api::apps::v1::Deployment;
use k8s_openapi::api::core::v1::{Container, PodSpec, Secret};
use kube::api::{Api, ObjectMeta, Patch, PatchParams, PostParams};

use crate::crd::upstream::{self, ProviderType, UpstreamProvider, UpstreamProviderSpec};
use crate::rbac::NAME;

/// Server options that no longer exist, for `zeabur-identityctl manifests` to refuse.
pub const REMOVED_OPTIONS: [&str; 4] = [
    "--github-client-id",
    "--github-client-secret-file",
    "--google-client-id",
    "--google-client-secret-file",
];

/// Why migrating failed.
#[derive(Debug, thiserror::Error)]
pub enum MigrateError {
    /// The Kubernetes API failed.
    #[error(transparent)]
    Kube(#[from] kube::Error),
    /// The Deployment or the existing objects do not allow it.
    #[error("{0}")]
    Invalid(String),
}

/// One provider to create.
#[derive(Debug, Clone)]
pub struct Migration {
    /// The `UpstreamProvider`.
    pub provider: UpstreamProvider,
    /// The Secret and key the client secret is copied from.
    pub source: (String, String),
}

/// A removed provider option as the Deployment sets it.
struct Legacy {
    kind: ProviderType,
    /// The object name and secret key, which keep the callback URL.
    name: &'static str,
    display_name: &'static str,
    client_id: String,
    secret_file: String,
}

/// The providers the Deployment `zeabur-identity` in `namespace` enables with the removed
/// options. Empty if it uses none.
///
/// # Errors
///
/// [`MigrateError`] if the Deployment cannot be read, or an option is only half set or reads a
/// file that is not a key of a mounted Secret.
pub async fn plan(client: kube::Client, namespace: &str) -> Result<Vec<Migration>, MigrateError> {
    let deployment = Api::<Deployment>::namespaced(client, namespace)
        .get(NAME)
        .await?;
    let pod = deployment
        .spec
        .and_then(|spec| spec.template.spec)
        .ok_or_else(|| MigrateError::Invalid(format!("Deployment {NAME} has no pod spec")))?;
    let container = pod
        .containers
        .iter()
        .find(|container| container.name == NAME)
        .ok_or_else(|| {
            MigrateError::Invalid(format!("Deployment {NAME} has no container {NAME}"))
        })?;
    let mut migrations = Vec::new();
    for legacy in legacy_options(container)? {
        let source = secret_source(&pod, container, &legacy.secret_file)?;
        let mut provider = UpstreamProvider::new(
            legacy.name,
            UpstreamProviderSpec {
                kind: legacy.kind,
                display_name: legacy.display_name.to_owned(),
                issuer: None,
                client_id: legacy.client_id,
                client_secret_key: legacy.name.to_owned(),
                provisioning: None,
            },
        );
        provider.metadata.namespace = Some(namespace.to_owned());
        migrations.push(Migration { provider, source });
    }
    Ok(migrations)
}

/// Creates the providers and copies their client secrets. Running it again changes nothing.
///
/// # Errors
///
/// [`MigrateError`] if a provider or secret key of the same name already holds something else,
/// or the Kubernetes API fails.
pub async fn apply(
    client: kube::Client,
    namespace: &str,
    migrations: &[Migration],
) -> Result<(), MigrateError> {
    let secrets: Api<Secret> = Api::namespaced(client.clone(), namespace);
    let providers: Api<UpstreamProvider> = Api::namespaced(client, namespace);
    for migration in migrations {
        let name = migration.provider.metadata.name.clone().unwrap_or_default();
        let key = &migration.provider.spec.client_secret_key;
        let (source_name, source_key) = &migration.source;
        let existing = providers.get_opt(&name).await?;
        if existing
            .as_ref()
            .is_some_and(|existing| existing.spec != migration.provider.spec)
        {
            return Err(MigrateError::Invalid(format!(
                "UpstreamProvider {name} already exists with other settings; compare it with the \
                 Deployment's options and remove them by hand"
            )));
        }
        let source = secrets.get(source_name).await?;
        let value = source
            .data
            .and_then(|mut data| data.remove(source_key))
            .ok_or_else(|| {
                MigrateError::Invalid(format!("Secret {source_name} has no key {source_key}"))
            })?;
        copy_secret(&secrets, key, value).await?;
        if existing.is_none() {
            providers
                .create(&PostParams::default(), &migration.provider)
                .await?;
        }
    }
    Ok(())
}

/// Puts `value` under `key` in [`upstream::SECRET`], keeping its other keys.
async fn copy_secret(
    secrets: &Api<Secret>,
    key: &str,
    value: ByteString,
) -> Result<(), MigrateError> {
    let Some(existing) = secrets.get_opt(upstream::SECRET).await? else {
        let secret = Secret {
            metadata: ObjectMeta {
                name: Some(upstream::SECRET.to_owned()),
                ..ObjectMeta::default()
            },
            data: Some(BTreeMap::from([(key.to_owned(), value)])),
            ..Secret::default()
        };
        secrets.create(&PostParams::default(), &secret).await?;
        return Ok(());
    };
    match existing.data.as_ref().and_then(|data| data.get(key)) {
        Some(current) if *current == value => Ok(()),
        Some(_) => Err(MigrateError::Invalid(format!(
            "Secret {} already has another value under {key}",
            upstream::SECRET
        ))),
        None => {
            let patch = serde_json::json!({ "data": { key: value } });
            secrets
                .patch(
                    upstream::SECRET,
                    &PatchParams::default(),
                    &Patch::Merge(&patch),
                )
                .await?;
            Ok(())
        }
    }
}

/// The removed options in the container's arguments and environment.
fn legacy_options(container: &Container) -> Result<Vec<Legacy>, MigrateError> {
    let mut legacy = Vec::new();
    for (kind, name, display_name, env) in [
        (
            ProviderType::GitHub,
            "github",
            "GitHub",
            "ZEABUR_IDENTITY_GITHUB",
        ),
        (
            ProviderType::Google,
            "google",
            "Google",
            "ZEABUR_IDENTITY_GOOGLE",
        ),
    ] {
        let prefix = format!("--{name}");
        let client_id = option(
            container,
            &format!("{prefix}-client-id"),
            &format!("{env}_CLIENT_ID"),
        )?;
        let secret_file = option(
            container,
            &format!("{prefix}-client-secret-file"),
            &format!("{env}_CLIENT_SECRET_FILE"),
        )?;
        match (client_id, secret_file) {
            (None, None) => {}
            (Some(client_id), Some(secret_file)) => legacy.push(Legacy {
                kind,
                name,
                display_name,
                client_id,
                secret_file,
            }),
            _ => {
                return Err(MigrateError::Invalid(format!(
                    "{prefix}-client-id and {prefix}-client-secret-file must be set together"
                )));
            }
        }
    }
    Ok(legacy)
}

/// The value of `--flag=value`, `--flag value` or the environment variable `env`;
/// arguments win over the environment, as in clap.
fn option(container: &Container, flag: &str, env: &str) -> Result<Option<String>, MigrateError> {
    let mut args = container.args.iter().flatten();
    while let Some(arg) = args.next() {
        if let Some(value) = arg
            .strip_prefix(flag)
            .and_then(|rest| rest.strip_prefix('='))
        {
            return Ok(Some(value.to_owned()));
        }
        if arg == flag {
            let value = args
                .next()
                .ok_or_else(|| MigrateError::Invalid(format!("{flag} has no value")))?;
            return Ok(Some(value.clone()));
        }
    }
    for var in container.env.iter().flatten() {
        if var.name == env {
            let value = var.value.clone().ok_or_else(|| {
                MigrateError::Invalid(format!(
                    "{env} is not set to a plain value; create the UpstreamProvider by hand"
                ))
            })?;
            return Ok(Some(value));
        }
    }
    Ok(None)
}

/// The Secret and key mounted at `path` in the container.
fn secret_source(
    pod: &PodSpec,
    container: &Container,
    path: &str,
) -> Result<(String, String), MigrateError> {
    let not_found = || {
        MigrateError::Invalid(format!(
            "{path} is not a key of a Secret mounted in the container; copy the client secret \
             into the Secret {} by hand",
            upstream::SECRET
        ))
    };
    for mount in container.volume_mounts.iter().flatten() {
        if mount.sub_path.is_some() {
            continue;
        }
        let Some(file) = path
            .strip_prefix(mount.mount_path.trim_end_matches('/'))
            .and_then(|rest| rest.strip_prefix('/'))
        else {
            continue;
        };
        let Some(source) = pod
            .volumes
            .iter()
            .flatten()
            .find(|volume| volume.name == mount.name)
            .and_then(|volume| volume.secret.as_ref())
        else {
            continue;
        };
        let secret = source.secret_name.clone().ok_or_else(not_found)?;
        let key = match &source.items {
            Some(items) => items
                .iter()
                .find(|item| item.path == file)
                .map(|item| item.key.clone())
                .ok_or_else(not_found)?,
            None => file.to_owned(),
        };
        return Ok((secret, key));
    }
    Err(not_found())
}

#[cfg(test)]
mod tests {
    use k8s_openapi::api::core::v1::{EnvVar, KeyToPath, SecretVolumeSource, Volume, VolumeMount};

    use super::*;
    use crate::deployment::{self, CONFIG_DIR, Options};

    fn generated(serve_args: &[&str]) -> PodSpec {
        let issuer =
            zeabur_identity_core::config::BaseUrl::parse("issuer", "https://id.example.com")
                .unwrap();
        let options = Options {
            image: "zeabur-identity".into(),
            serve_args: serve_args.iter().map(|s| (*s).to_owned()).collect(),
            config_secret: Some("zeabur-identity-config".into()),
        };
        deployment::deployment("zeabur-identity", &issuer, &options)
            .spec
            .unwrap()
            .template
            .spec
            .unwrap()
    }

    #[test]
    fn reads_the_options_the_installation_guides_set() {
        let pod = generated(&[
            "--invitations",
            "--github-client-id=Ov23li",
            "--github-client-secret-file=/etc/zeabur-identity/github-client-secret",
            "--google-client-id",
            "123.apps.googleusercontent.com",
            "--google-client-secret-file",
            "/etc/zeabur-identity/google-client-secret",
        ]);
        let container = &pod.containers[0];
        let legacy = legacy_options(container).unwrap();
        assert_eq!(legacy.len(), 2);
        assert_eq!(legacy[0].kind, ProviderType::GitHub);
        assert_eq!(legacy[0].client_id, "Ov23li");
        assert_eq!(legacy[1].kind, ProviderType::Google);
        assert_eq!(legacy[1].client_id, "123.apps.googleusercontent.com");
        assert_eq!(
            secret_source(&pod, container, &legacy[0].secret_file).unwrap(),
            (
                "zeabur-identity-config".into(),
                "github-client-secret".into()
            )
        );
        assert_eq!(
            secret_source(&pod, container, &legacy[1].secret_file).unwrap(),
            (
                "zeabur-identity-config".into(),
                "google-client-secret".into()
            )
        );
    }

    #[test]
    fn reads_the_environment_and_secret_items() {
        let mut pod = generated(&[]);
        let container = &mut pod.containers[0];
        container.env.get_or_insert_default().extend([
            EnvVar {
                name: "ZEABUR_IDENTITY_GITHUB_CLIENT_ID".into(),
                value: Some("Ov23li".into()),
                ..EnvVar::default()
            },
            EnvVar {
                name: "ZEABUR_IDENTITY_GITHUB_CLIENT_SECRET_FILE".into(),
                value: Some("/run/github/secret".into()),
                ..EnvVar::default()
            },
        ]);
        container
            .volume_mounts
            .get_or_insert_default()
            .push(VolumeMount {
                name: "github".into(),
                mount_path: "/run/github/".into(),
                ..VolumeMount::default()
            });
        pod.volumes.get_or_insert_default().push(Volume {
            name: "github".into(),
            secret: Some(SecretVolumeSource {
                secret_name: Some("github-oauth".into()),
                items: Some(vec![KeyToPath {
                    key: "client-secret".into(),
                    path: "secret".into(),
                    ..KeyToPath::default()
                }]),
                ..SecretVolumeSource::default()
            }),
            ..Volume::default()
        });
        let container = &pod.containers[0];
        let legacy = legacy_options(container).unwrap();
        assert_eq!(legacy.len(), 1);
        assert_eq!(
            secret_source(&pod, container, &legacy[0].secret_file).unwrap(),
            ("github-oauth".into(), "client-secret".into())
        );
    }

    #[test]
    fn refuses_what_it_cannot_copy() {
        let pod = generated(&["--github-client-id=Ov23li"]);
        assert!(legacy_options(&pod.containers[0]).is_err());

        let pod = generated(&[]);
        let outside = format!("{CONFIG_DIR}-other/github-client-secret");
        assert!(secret_source(&pod, &pod.containers[0], &outside).is_err());
    }

    #[test]
    fn a_deployment_without_the_options_needs_nothing() {
        let pod = generated(&["--invitations"]);
        assert!(legacy_options(&pod.containers[0]).unwrap().is_empty());
    }
}
