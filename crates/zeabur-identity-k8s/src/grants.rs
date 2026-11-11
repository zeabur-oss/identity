//! [`GrantStore`] backed by `Grant` objects.
//!
//! Creating a family is one write (the first token's hash is in `spec`); each rotation is one
//! compare-and-swap on `status`. A rotation that loses a race re-reads the object and is
//! classified again, so a concurrent reuse of the same token is reported as a replay.

use std::collections::BTreeMap;
use std::future::Future;

use kube::ResourceExt as _;
use kube::api::{Api, DeleteParams, ListParams, ObjectMeta};
use zeabur_identity_api::grant::{Grant as GrantObject, GrantReauth, GrantSpec, GrantStatus};
use zeabur_identity_api::{CLIENT_LABEL, EXPIRES_AT_ANNOTATION, EXPIRY_BUCKET_LABEL, USER_LABEL};
use zeabur_identity_core::clock::UnixTime;
use zeabur_identity_core::crypto::ct_eq;
use zeabur_identity_store::{
    Classification, CreateGrant, Grant, GrantStore, NewGrant, Rotation, StoreError, User,
    Verification, classify, rotated,
};

use super::objects::{
    CreateOutcome, ReplaceOutcome, create_once, list_all, replace_status_if_unchanged,
};
use super::users::{owned_by_another, user_owner};

/// How many times a rotation re-reads after losing a compare-and-swap.
const MAX_ATTEMPTS: usize = 4;

/// Refresh-token families as `Grant` objects.
#[derive(Clone)]
pub struct KubeGrantStore {
    api: Api<GrantObject>,
}

impl std::fmt::Debug for KubeGrantStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("KubeGrantStore")
    }
}

impl KubeGrantStore {
    /// Uses the given (namespaced) API.
    #[must_use]
    pub const fn new(api: Api<GrantObject>) -> Self {
        Self { api }
    }
}

fn secs(time: UnixTime) -> i64 {
    i64::try_from(time.as_secs()).unwrap_or(i64::MAX)
}

fn time(secs: i64) -> UnixTime {
    UnixTime::from_secs(u64::try_from(secs).unwrap_or(0))
}

fn backend(error: &kube::Error) -> StoreError {
    StoreError(error.to_string())
}

fn to_object(grant: &NewGrant, idle_expires_at: UnixTime) -> GrantObject {
    let expires = grant.expires_at.as_secs();
    GrantObject {
        metadata: ObjectMeta {
            name: Some(grant.name.clone()),
            labels: Some(BTreeMap::from([
                (USER_LABEL.to_owned(), grant.user.clone()),
                (CLIENT_LABEL.to_owned(), grant.client.clone()),
                (EXPIRY_BUCKET_LABEL.to_owned(), (expires / 3600).to_string()),
                (
                    super::MANAGED_BY.0.to_owned(),
                    super::MANAGED_BY.1.to_owned(),
                ),
            ])),
            // The collector deletes at the absolute expiry; idle expiry is enforced on read.
            annotations: Some(BTreeMap::from([(
                EXPIRES_AT_ANNOTATION.to_owned(),
                expires.to_string(),
            )])),
            ..ObjectMeta::default()
        },
        spec: GrantSpec {
            user: grant.user.clone(),
            client: grant.client.clone(),
            audience: grant.audience.clone(),
            auth_time: secs(grant.auth_time),
            scopes: grant.scopes.clone(),
            amr: grant.amr.clone(),
            expires_at: secs(grant.expires_at),
            initial_idle_expires_at: secs(idle_expires_at),
            initial_hash: grant.initial_hash.clone(),
            subject: grant.subject.clone(),
            credential: grant.credential.clone(),
            user_verified: grant.user_verified,
            device_bound: grant.device_bound,
        },
        status: None,
    }
}

fn status(grant: &Grant) -> GrantStatus {
    GrantStatus {
        rotation: i64::try_from(grant.rotation).unwrap_or(i64::MAX),
        current_hash: grant.current_hash.clone(),
        previous_hash: grant.previous_hash.clone(),
        idle_expires_at: secs(grant.idle_expires_at),
        reauth: grant.reauth.as_ref().map(|reauth| GrantReauth {
            auth_time: secs(reauth.at),
            credential: reauth.credential.clone(),
            user_verified: reauth.user_verified,
        }),
    }
}

fn from_object(object: &GrantObject) -> Grant {
    let spec = &object.spec;
    let new = NewGrant {
        name: object.name_any(),
        user: spec.user.clone(),
        client: spec.client.clone(),
        audience: spec.audience.clone(),
        scopes: spec.scopes.clone(),
        auth_time: time(spec.auth_time),
        amr: spec.amr.clone(),
        expires_at: time(spec.expires_at),
        initial_hash: spec.initial_hash.clone(),
        subject: spec.subject.clone(),
        credential: spec.credential.clone(),
        user_verified: spec.user_verified,
        device_bound: spec.device_bound,
    };
    match &object.status {
        None => Grant {
            current_hash: spec.initial_hash.clone(),
            spec: new,
            rotation: 0,
            previous_hash: None,
            idle_expires_at: time(spec.initial_idle_expires_at),
            reauth: None,
        },
        Some(status) => Grant {
            spec: new,
            rotation: u64::try_from(status.rotation).unwrap_or(0),
            current_hash: status.current_hash.clone(),
            previous_hash: status.previous_hash.clone(),
            idle_expires_at: time(status.idle_expires_at),
            reauth: status.reauth.as_ref().map(|reauth| Verification {
                at: time(reauth.auth_time),
                credential: reauth.credential.clone(),
                user_verified: reauth.user_verified,
            }),
        },
    }
}

impl GrantStore for KubeGrantStore {
    fn create(
        &self,
        grant: &NewGrant,
        idle_expires_at: UnixTime,
    ) -> impl Future<Output = Result<CreateGrant, StoreError>> + Send {
        let api = self.api.clone();
        let mut object = to_object(grant, idle_expires_at);
        async move {
            object.metadata.owner_references = user_owner(&api, &object.spec.user)
                .await?
                .map(|owner| vec![owner]);
            match create_once(&api, &object).await.map_err(|e| backend(&e))? {
                CreateOutcome::Created(_) => Ok(CreateGrant::Created),
                CreateOutcome::AlreadyExists => Ok(CreateGrant::AlreadyExists),
            }
        }
    }

    fn get(&self, name: &str) -> impl Future<Output = Result<Option<Grant>, StoreError>> + Send {
        let api = self.api.clone();
        let name = name.to_owned();
        async move {
            Ok(api
                .get_opt(&name)
                .await
                .map_err(|e| backend(&e))?
                .as_ref()
                .map(from_object))
        }
    }

    fn rotate(
        &self,
        name: &str,
        presented_hash: &str,
        next_hash: &str,
        now: UnixTime,
        idle_expires_at: UnixTime,
    ) -> impl Future<Output = Result<Rotation, StoreError>> + Send {
        let api = self.api.clone();
        let (name, presented, next) = (
            name.to_owned(),
            presented_hash.to_owned(),
            next_hash.to_owned(),
        );
        async move {
            for _ in 0..MAX_ATTEMPTS {
                let Some(mut object) = api.get_opt(&name).await.map_err(|e| backend(&e))? else {
                    return Ok(Rotation::NotFound);
                };
                let current = from_object(&object);
                match classify(&current, &presented, now) {
                    Classification::Expired => return Ok(Rotation::Expired),
                    Classification::Previous => return Ok(Rotation::Replay),
                    Classification::Unknown => return Ok(Rotation::Invalid),
                    Classification::Current => {}
                }
                let after = rotated(&current, &next, idle_expires_at);
                object.status = Some(status(&after));
                match replace_status_if_unchanged(&api, &object)
                    .await
                    .map_err(|e| backend(&e))?
                {
                    ReplaceOutcome::Replaced(_) => return Ok(Rotation::Rotated(Box::new(after))),
                    ReplaceOutcome::NotFound => return Ok(Rotation::NotFound),
                    // Someone rotated first; re-read and classify the presented token again.
                    ReplaceOutcome::Conflict => {}
                }
            }
            Err(StoreError(
                "refresh token rotation kept conflicting".to_owned(),
            ))
        }
    }

    fn revoke(&self, name: &str) -> impl Future<Output = Result<(), StoreError>> + Send {
        let api = self.api.clone();
        let name = name.to_owned();
        async move {
            match api.delete(&name, &DeleteParams::background()).await {
                Ok(_) => Ok(()),
                Err(kube::Error::Api(status)) if status.code == 404 => Ok(()),
                Err(error) => Err(backend(&error)),
            }
        }
    }

    fn list(&self, user: &User) -> impl Future<Output = Result<Vec<Grant>, StoreError>> + Send {
        let api = self.api.clone();
        let user = user.clone();
        async move {
            let params = ListParams::default().labels(&format!("{USER_LABEL}={}", user.name));
            let objects = list_all(&api, params).await.map_err(|e| backend(&e))?;
            let mut grants: Vec<Grant> = objects
                .iter()
                .filter(|object| !owned_by_another(&object.metadata, &user.subject))
                .map(from_object)
                .filter(|grant| grant.belongs_to(&user))
                .collect();
            grants.sort_by(|a, b| a.spec.name.cmp(&b.spec.name));
            Ok(grants)
        }
    }

    fn reauthenticate(
        &self,
        name: &str,
        current_hash: &str,
        verification: &Verification,
    ) -> impl Future<Output = Result<bool, StoreError>> + Send {
        let api = self.api.clone();
        let (name, current_hash, verification) = (
            name.to_owned(),
            current_hash.to_owned(),
            verification.clone(),
        );
        async move {
            for _ in 0..MAX_ATTEMPTS {
                let Some(mut object) = api.get_opt(&name).await.map_err(|e| backend(&e))? else {
                    return Ok(false);
                };
                let mut grant = from_object(&object);
                if !ct_eq(grant.current_hash.as_bytes(), current_hash.as_bytes()) {
                    return Ok(false);
                }
                grant.reauth = Some(verification.clone());
                object.status = Some(status(&grant));
                match replace_status_if_unchanged(&api, &object)
                    .await
                    .map_err(|e| backend(&e))?
                {
                    ReplaceOutcome::Replaced(_) => return Ok(true),
                    ReplaceOutcome::NotFound => return Ok(false),
                    ReplaceOutcome::Conflict => {}
                }
            }
            Err(StoreError("re-authentication kept conflicting".to_owned()))
        }
    }
}
