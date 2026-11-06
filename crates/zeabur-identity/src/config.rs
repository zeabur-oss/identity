//! Validated configuration of `zeabur-identity`.

use std::net::SocketAddr;
use std::time::Duration;

use zeabur_identity_core::config::{BaseUrl, ConfigError};
use zeabur_identity_keys::rotation::RotationPolicy;

/// Where long-term state is kept: Kubernetes objects, custom resources and Secrets in one
/// namespace (`zeabur_identity_k8s`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Store {
    /// Namespace; defaults to the client's (in-cluster: the pod's).
    pub namespace: Option<String>,
    /// Name of the signing-key Secret.
    pub key_secret: String,
}

/// Configuration for `zeabur-identity`.
#[derive(Debug, Clone)]
pub struct ServeConfig {
    /// The issuer identifier, also the public base URL.
    pub issuer: BaseUrl,
    /// Where the public HTTP listener binds. TLS is terminated in front of it.
    pub listen: SocketAddr,
    /// Signing-key rotation timings.
    pub rotation: RotationPolicy,
    /// `Cache-Control: max-age` for the discovery documents and the JWK set.
    pub metadata_max_age: Duration,
    /// Whether invitations are accepted.
    pub invitations: bool,
    /// Where the internal TLS listener binds (Kubernetes store only).
    pub internal_listen: SocketAddr,
    /// Overrides the internal base URL recorded in the certificate Secret.
    pub internal_url: Option<BaseUrl>,
    /// Where state is kept.
    pub store: Store,
    /// Token and grant lifetimes.
    pub lifetimes: zeabur_identity_oauth::Lifetimes,
}

impl ServeConfig {
    /// Checks relations between fields.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::BadRotationPolicy`] if verifiers could see a signing key later
    /// than it is used, or stop seeing it before its tokens expire.
    pub fn validate(&self) -> Result<(), ConfigError> {
        self.rotation.validate()?;
        if self.rotation.retain_after < self.lifetimes.longest_signed_token() {
            return Err(ConfigError::BadRotationPolicy(
                "keys must stay published at least as long as the longest token lifetime",
            ));
        }
        let token_lifetimes = [
            self.lifetimes.access_token,
            self.lifetimes.admin_access_token,
        ];
        if token_lifetimes
            .iter()
            .any(|t| *t > Duration::from_hours(1) || *t < Duration::from_mins(1))
        {
            // RFC 6750 §5.3: short-lived bearer tokens, one hour or less.
            return Err(ConfigError::BadRotationPolicy(
                "access token lifetime must be between 1m and 1h",
            ));
        }
        if self.lifetimes.refresh_idle > self.lifetimes.refresh_absolute
            || self.lifetimes.admin_refresh_idle > self.lifetimes.refresh_absolute
        {
            return Err(ConfigError::BadRotationPolicy(
                "refresh idle lifetime cannot exceed the absolute lifetime",
            ));
        }
        if self.metadata_max_age >= self.rotation.publish_ahead {
            return Err(ConfigError::BadRotationPolicy(
                "metadata max-age must be shorter than the publish-ahead time, or verifiers \
                 that cache the JWK set may not see a new key before it signs",
            ));
        }
        Ok(())
    }
}
