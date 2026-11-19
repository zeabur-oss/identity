//! The server key for password hashes and device cookies, in one Secret.
//!
//! The installer creates the Secret empty, as it does the signing-key Secret, because RBAC cannot
//! limit `create` to a name. The first replica to start fills it with 32 random bytes, with a
//! compare-and-swap on `resourceVersion`; the others read the winner's key. The key stays apart
//! from the password hashes in `Credential` objects, so a copy of those alone cannot be attacked
//! offline (NIST SP 800-63B-4 §3.1.1.2). Replacing the key makes every password and device cookie
//! invalid.

use std::collections::BTreeMap;

use k8s_openapi::ByteString;
use k8s_openapi::api::core::v1::Secret;
use kube::api::{Api, PostParams};
use zeabur_identity_core::crypto::random;
use zeabur_identity_store::{StoreError, retry_on_conflict};

use crate::objects::status_code;

/// Name of the Secret.
pub const SECRET: &str = "zeabur-identity-password-key";
/// The Secret `type`.
pub const SECRET_TYPE: &str = "identity.zeabur.com/password-key";
/// The data key holding the 32-byte key.
pub const DATA_KEY: &str = "key";
/// Length of the key.
pub const KEY_LEN: usize = 32;

/// Reads the key, filling the empty Secret first if no replica has.
///
/// # Errors
///
/// The Secret is missing, has another type or a malformed key, or the API server fails.
pub async fn load_or_init(api: &Api<Secret>) -> Result<[u8; KEY_LEN], StoreError> {
    retry_on_conflict(|| async {
        let mut secret = api
            .get_opt(SECRET)
            .await
            .map_err(StoreError::backend)?
            .ok_or_else(|| {
                StoreError::Backend(format!("Secret {SECRET} does not exist; run the installer"))
            })?;
        if secret.type_.as_deref() != Some(SECRET_TYPE) {
            return Err(StoreError::Backend(format!(
                "Secret {SECRET} has type {:?}, expected {SECRET_TYPE}; refusing to use it",
                secret.type_
            )));
        }
        if let Some(stored) = secret.data.as_ref().and_then(|data| data.get(DATA_KEY)) {
            return <[u8; KEY_LEN]>::try_from(stored.0.as_slice())
                .map(Some)
                .map_err(|_wrong_length| {
                    StoreError::Backend(format!("Secret {SECRET} holds a malformed key"))
                });
        }
        let key = random::<KEY_LEN>().map_err(StoreError::backend)?;
        secret.data = Some(BTreeMap::from([(
            DATA_KEY.to_owned(),
            ByteString(key.to_vec()),
        )]));
        // `replace` sends the read resourceVersion, so only one replica fills the Secret.
        match api.replace(SECRET, &PostParams::default(), &secret).await {
            Ok(_) => Ok(Some(key)),
            Err(error) if status_code(&error) == Some(409) => Ok(None),
            Err(error) => Err(StoreError::backend(error)),
        }
    })
    .await
}
