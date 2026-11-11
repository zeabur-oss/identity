//! Turns `UpstreamProvider` objects into the providers that sign-in uses, and keeps the shared
//! [`Providers`] registry current as the objects change.
//!
//! - **Add, change, delete.** Each change to the objects replaces the registry, so the next request
//!   sees it. A provider whose spec did not change is kept as it is, with its cached discovery
//!   document and keys.
//! - **Invalid objects.** The CRD rejects most mistakes. An object it lets through but Zeabur
//!   Identity cannot use (for example an issuer that `Issuer` refuses) is left out and logged; the
//!   other providers keep working.
//! - **Client secrets.** Each provider reads its secret from the Secret
//!   [`zeabur_identity_k8s::upstream::SECRET`] at each code exchange. A rotated secret applies at
//!   the next sign-in; a missing one fails that sign-in before the code is sent.

use std::collections::HashMap;
use std::sync::Arc;

use k8s_openapi::api::core::v1::Secret;
use kube::ResourceExt as _;
use kube::api::Api;
use zeabur_identity_api::upstream::{Issuer, ProviderId};
use zeabur_identity_api::upstream_provider::{
    MAX_DISPLAY_NAME, UpstreamProvider, UpstreamProviderSpec, UpstreamType,
};
use zeabur_identity_signin::upstream::provider::{
    ClientSecret, GitHubEndpoints, Provider, Providers,
};

/// Builds providers from objects and publishes them to a registry.
#[derive(Debug)]
pub struct Builder {
    secrets: Api<Secret>,
    registry: Arc<Providers>,
    built: HashMap<String, (UpstreamProviderSpec, Arc<Provider>)>,
}

impl Builder {
    /// Publishes to `registry`; providers read their client secrets through `secrets`.
    #[must_use]
    pub fn new(secrets: Api<Secret>, registry: Arc<Providers>) -> Self {
        Self {
            secrets,
            registry,
            built: HashMap::new(),
        }
    }

    /// Replaces the registry with a provider for each usable object in `objects`, in their order.
    pub fn publish(&mut self, objects: &[UpstreamProvider]) {
        let mut built = HashMap::new();
        let mut list = Vec::new();
        for object in objects {
            let name = object.name_any();
            let provider = match self.built.remove(&name) {
                Some((spec, provider)) if spec == object.spec => provider,
                _ => match build(&name, &object.spec, &self.secrets) {
                    Ok(provider) => Arc::new(provider),
                    Err(error) => {
                        tracing::warn!(
                            reason = "upstream_provider_invalid",
                            provider = %name,
                            %error,
                            "upstream provider left out"
                        );
                        continue;
                    }
                },
            };
            list.push(Arc::clone(&provider));
            built.insert(name, (object.spec.clone(), provider));
        }
        let ids: Vec<&str> = list.iter().map(|p| p.id().as_str()).collect();
        tracing::info!(providers = ?ids, "upstream providers updated");
        self.registry.replace(list);
        self.built = built;
    }
}

/// A scope token ([RFC 6749] §3.3): `1*NQCHAR`, `%x21 / %x23-5B / %x5D-7E`.
///
/// [RFC 6749]: https://www.rfc-editor.org/rfc/rfc6749.html#section-3.3
fn is_scope(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|b| b == 0x21 || (0x23..=0x5B).contains(&b) || (0x5D..=0x7E).contains(&b))
}

fn is_visible_ascii(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|b| b.is_ascii_graphic())
}

/// The provider an object describes. Checks again what the CRD checks, so that an object stored
/// under an older schema cannot reach the protocol code.
fn build(
    name: &str,
    spec: &UpstreamProviderSpec,
    secrets: &Api<Secret>,
) -> Result<Provider, String> {
    let id = ProviderId::new(name).map_err(|error| format!("name: {error}"))?;
    if !is_visible_ascii(&spec.client_id) {
        return Err("clientId must be visible ASCII".to_owned());
    }
    let secret = client_secret(secrets.clone(), spec.client_secret_key.clone());
    match spec.kind {
        UpstreamType::GitHub => Provider::github(
            id,
            spec.client_id.clone(),
            secret,
            GitHubEndpoints::github_com(),
        )
        .map_err(|error| error.to_string()),
        UpstreamType::OpenID => {
            let issuer = spec
                .issuer
                .clone()
                .ok_or("an OpenID provider needs issuer")?;
            let issuer = Issuer::new(issuer).map_err(|error| format!("issuer: {error}"))?;
            let label = spec
                .display_name
                .clone()
                .filter(|label| !label.trim().is_empty())
                .ok_or("an OpenID provider needs displayName")?;
            if label.chars().count() > MAX_DISPLAY_NAME {
                return Err("displayName is too long".to_owned());
            }
            let scopes = spec.scopes.clone().unwrap_or_default();
            if let Some(bad) = scopes.iter().find(|scope| !is_scope(scope)) {
                return Err(format!("scope {bad:?} is not a scope token"));
            }
            Ok(Provider::openid(
                id,
                label,
                issuer,
                scopes,
                spec.client_id.clone(),
                secret,
            ))
        }
    }
}

fn client_secret(secrets: Api<Secret>, key: String) -> ClientSecret {
    ClientSecret::Fetch(Arc::new(move || {
        let (secrets, key) = (secrets.clone(), key.clone());
        Box::pin(async move { zeabur_identity_k8s::upstream::client_secret(&secrets, &key).await })
    }))
}

#[cfg(test)]
mod tests {
    use kube::api::ObjectMeta;

    use super::*;

    /// Never called in these tests: secrets are read only at a code exchange.
    fn secrets() -> Api<Secret> {
        let config = kube::Config::new("https://127.0.0.1:1".parse().unwrap());
        Api::namespaced(kube::Client::try_from(config).unwrap(), "default")
    }

    fn object(name: &str, spec: serde_json::Value) -> UpstreamProvider {
        UpstreamProvider {
            metadata: ObjectMeta {
                name: Some(name.to_owned()),
                ..ObjectMeta::default()
            },
            spec: serde_json::from_value(spec).unwrap(),
        }
    }

    fn keycloak(issuer: &str) -> UpstreamProvider {
        object(
            "keycloak",
            serde_json::json!({
                "type": "OpenID", "issuer": issuer, "displayName": "Keycloak",
                "clientId": "identity", "clientSecretKey": "keycloak",
            }),
        )
    }

    fn github() -> UpstreamProvider {
        object(
            "github",
            serde_json::json!({"type": "GitHub", "clientId": "Iv1.abc", "clientSecretKey": "github"}),
        )
    }

    #[tokio::test]
    async fn usable_objects_are_published_and_unusable_ones_left_out() {
        let registry = Arc::new(Providers::default());
        let mut builder = Builder::new(secrets(), Arc::clone(&registry));
        let bad_issuer = object(
            "bad",
            serde_json::json!({
                "type": "OpenID", "issuer": "http://idp.example", "displayName": "Bad",
                "clientId": "c", "clientSecretKey": "bad",
            }),
        );
        let bad_scope = object(
            "scopes",
            serde_json::json!({
                "type": "OpenID", "issuer": "https://idp.example", "displayName": "Scopes",
                "clientId": "c", "clientSecretKey": "s", "scopes": ["a b"],
            }),
        );
        builder.publish(&[
            bad_issuer,
            github(),
            keycloak("https://sso.example/realms/dev"),
            bad_scope,
        ]);
        let ids: Vec<String> = registry
            .current()
            .iter()
            .map(|p| p.id().as_str().to_owned())
            .collect();
        assert_eq!(ids, ["github", "keycloak"]);
        let keycloak = registry.get("keycloak").unwrap().descriptor();
        assert_eq!(keycloak.label, "Keycloak");
        assert_eq!(keycloak.issuer.as_str(), "https://sso.example/realms/dev");
    }

    #[tokio::test]
    async fn an_unchanged_provider_is_kept_and_a_changed_or_deleted_one_is_not() {
        let registry = Arc::new(Providers::default());
        let mut builder = Builder::new(secrets(), Arc::clone(&registry));
        builder.publish(&[github(), keycloak("https://sso.example/realms/dev")]);
        let github_before = registry.get("github").unwrap();
        let keycloak_before = registry.get("keycloak").unwrap();

        builder.publish(&[github(), keycloak("https://sso.example/realms/prod")]);
        assert!(Arc::ptr_eq(
            &github_before,
            &registry.get("github").unwrap()
        ));
        let keycloak_after = registry.get("keycloak").unwrap();
        assert!(!Arc::ptr_eq(&keycloak_before, &keycloak_after));
        assert_eq!(
            keycloak_after.issuer().as_str(),
            "https://sso.example/realms/prod"
        );

        builder.publish(&[keycloak("https://sso.example/realms/prod")]);
        assert!(registry.get("github").is_none());
        builder.publish(&[github()]);
        assert!(!Arc::ptr_eq(
            &github_before,
            &registry.get("github").unwrap()
        ));
    }

    #[test]
    fn scope_tokens_follow_rfc_6749() {
        for good in ["profile", "email", "groups:read", "https://x.example/a"] {
            assert!(is_scope(good), "{good}");
        }
        for bad in ["", "a b", "a\"b", "a\\b", "é", "a\tb"] {
            assert!(!is_scope(bad), "{bad:?}");
        }
    }
}
