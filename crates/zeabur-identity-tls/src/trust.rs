//! Certificate authorities trusted for outgoing TLS (upstream identity providers): the system
//! bundle.
//!
//! Zeabur Identity's image ships a CA bundle; `SSL_CERT_FILE` and `SSL_CERT_DIR` override where it
//! is looked for. No root list is compiled in: `webpki-roots` is licensed CDLA-Permissive-2.0,
//! which is not OSI-approved. Connections to kube-apiserver do not use this: they trust the service
//! account's CA only.

use rustls::RootCertStore;
use thiserror::Error;

/// Why trust roots could not be loaded.
#[derive(Debug, Error)]
pub enum TrustError {
    /// No CA was found at all.
    #[error("no trusted certificate authorities found (set SSL_CERT_FILE or SSL_CERT_DIR)")]
    Empty,
}

/// The system's CAs.
///
/// # Errors
///
/// [`TrustError`] if nothing at all is trusted.
pub fn roots() -> Result<RootCertStore, TrustError> {
    let mut store = RootCertStore::empty();
    let system = rustls_native_certs::load_native_certs();
    for error in &system.errors {
        tracing::debug!(
            reason = "system_ca_unavailable",
            %error,
            "skipping part of the system CA bundle"
        );
    }
    let (_added, _ignored) = store.add_parsable_certificates(system.certs);
    if store.is_empty() {
        return Err(TrustError::Empty);
    }
    Ok(store)
}
