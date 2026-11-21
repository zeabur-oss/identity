//! Signing keys in a Kubernetes Secret.
//!
//! One Secret holds the whole keyset as JSON. Writes are compare-and-swap on `resourceVersion`,
//! so only one writer can install a new key. The service account needs only `get` and `update`
//! on this one Secret name; the installer creates the (empty) Secret, because RBAC cannot limit
//! `create` to a name. A Secret, not a custom resource, because this is the one piece of private
//! material Zeabur Identity stores, and Secret encryption at rest (where the cluster enables it)
//! covers it.
//!
//! Eight replicas racing to initialise the empty Secret all end up publishing the winner's keys
//! (tested against a real API server); a restart loads them.

use std::collections::BTreeMap;

use k8s_openapi::ByteString;
use k8s_openapi::api::core::v1::Secret;
use kube::api::{Api, ObjectMeta, PostParams};
use zeabur_identity_keys::store::{
    KeyStore, Loaded, Revision, SCHEMA_VERSION, StoreError, StoredKeyset,
};

use super::MANAGED_BY;
use super::objects::status_code;

/// The Secret `type` of the key Secret.
pub const SECRET_TYPE: &str = "identity.zeabur.com/signing-keys";

/// The data key holding the keyset.
pub const DATA_KEY: &str = "keyset.json";

/// A [`KeyStore`] backed by one Secret.
#[derive(Clone)]
pub struct SecretKeyStore {
    api: Api<Secret>,
    name: String,
}

impl std::fmt::Debug for SecretKeyStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretKeyStore")
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

impl SecretKeyStore {
    /// Uses the Secret `name` through `api` (which fixes the namespace).
    #[must_use]
    pub fn new(api: Api<Secret>, name: impl Into<String>) -> Self {
        Self {
            api,
            name: name.into(),
        }
    }

    fn data(keyset: &StoredKeyset) -> Result<BTreeMap<String, ByteString>, StoreError> {
        let json = serde_json::to_vec(keyset).map_err(StoreError::backend)?;
        Ok(BTreeMap::from([(DATA_KEY.to_owned(), ByteString(json))]))
    }
}

impl KeyStore for SecretKeyStore {
    async fn load(&self) -> Result<Option<Loaded>, StoreError> {
        let Some(secret) = self
            .api
            .get_opt(&self.name)
            .await
            .map_err(StoreError::backend)?
        else {
            return Ok(None);
        };
        if secret.type_.as_deref() != Some(SECRET_TYPE) {
            return Err(StoreError::Backend(format!(
                "Secret {} has type {:?}, expected {SECRET_TYPE}; refusing to use it",
                self.name, secret.type_
            )));
        }
        let revision = Revision(secret.metadata.resource_version.clone().unwrap_or_default());
        // An installer-created Secret has no data yet: it is an empty keyset at this revision.
        let keyset = match secret.data.as_ref().and_then(|data| data.get(DATA_KEY)) {
            Some(bytes) => serde_json::from_slice(&bytes.0).map_err(StoreError::backend)?,
            None => StoredKeyset {
                version: SCHEMA_VERSION,
                keys: Vec::new(),
            },
        };
        Ok(Some(Loaded { keyset, revision }))
    }

    async fn save(
        &self,
        keyset: &StoredKeyset,
        expected: Option<&Revision>,
    ) -> Result<Revision, StoreError> {
        let data = Self::data(keyset)?;
        let result = match expected {
            None => {
                let secret = Secret {
                    metadata: ObjectMeta {
                        name: Some(self.name.clone()),
                        labels: Some(BTreeMap::from([(
                            MANAGED_BY.0.to_owned(),
                            MANAGED_BY.1.to_owned(),
                        )])),
                        ..ObjectMeta::default()
                    },
                    type_: Some(SECRET_TYPE.to_owned()),
                    data: Some(data),
                    ..Secret::default()
                };
                self.api.create(&PostParams::default(), &secret).await
            }
            // Only `data` changes: the labels and annotations are the installer's, and a Helm
            // upgrade fails on a label another field manager changed.
            Some(revision) => {
                let Some(mut secret) = self
                    .api
                    .get_opt(&self.name)
                    .await
                    .map_err(StoreError::backend)?
                else {
                    return Err(StoreError::Conflict);
                };
                if secret.metadata.resource_version.as_deref() != Some(revision.0.as_str()) {
                    return Err(StoreError::Conflict);
                }
                secret.data = Some(data);
                self.api
                    .replace(&self.name, &PostParams::default(), &secret)
                    .await
            }
        };
        match result {
            Ok(saved) => Ok(Revision(
                saved.metadata.resource_version.unwrap_or_default(),
            )),
            // 409: someone else wrote first. 404: the Secret was deleted since we read it.
            Err(error) if matches!(status_code(&error), Some(409 | 404)) => {
                Err(StoreError::Conflict)
            }
            Err(error) => Err(StoreError::backend(error)),
        }
    }
}
