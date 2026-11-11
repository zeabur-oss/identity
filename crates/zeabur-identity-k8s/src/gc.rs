//! Garbage collection of expired objects.
//!
//! Short-lived objects carry the label [`EXPIRY_BUCKET_LABEL`] and the annotation
//! [`EXPIRES_AT_ANNOTATION`] (Unix seconds). The collector watches only their metadata, keeps an
//! in-memory schedule, and when an object is due deletes it with `uid` and `resourceVersion`
//! preconditions: if the object changed in the meantime (for example, a refresh extended a grant),
//! the delete fails and the next watch event reschedules it.
//!
//! Expiry is always re-checked when an object is read for use; the collector only reclaims space.
//!
//! - **Metadata only.** The watch uses `PartialObjectMeta` ([`metadata_watcher`]-style) with a
//!   label selector, so object bodies (hashes) are never cached and memory grows only with the
//!   number of expiring objects. A periodic `LIST` would also have to follow `continue` tokens:
//!   [Dex]'s collector, which lists 500 objects per kind, never reaches the rest.
//! - **Safe against concurrent use.** The collector can delete only objects of its own kinds that
//!   it last saw as expired, and only if they are unchanged since. A clock running fast deletes
//!   objects early, which ends sessions but cannot extend them. The precondition-guarded delete
//!   follows [Pinniped]'s garbage collector.
//! - **Retries.** Infrastructure errors are retried after 30 s. A relist forgets objects deleted
//!   while the watch was down; [`relisting_watcher`] also relists when the API server rejects a
//!   resumed watch. Sleeps are capped at 5 minutes so that a wall-clock jump is noticed.
//! - **Not a kube-runtime `Controller`.** `Controller::for_stream`, needed for a metadata-only
//!   stream, is behind an unstable feature in kube-runtime 4.2, and this job is a timer queue, not
//!   reconciliation. Several replicas may run it: deletes are idempotent.
//!
//! # References
//!
//! - [Dex] Dex project, `storage/kubernetes/`, commit 05a2750, and issue #4979.
//! - [Pinniped] Pinniped project, `internal/controller/supervisorstorage/garbage_collector.go`,
//!   commit e635a39.
//!
//! [`metadata_watcher`]: https://docs.rs/kube-runtime/latest/kube_runtime/watcher/fn.metadata_watcher.html
//! [Dex]: https://github.com/dexidp/dex/tree/05a275057112ba93e17db21f600b756f000f1c21/storage/kubernetes
//! [Pinniped]: https://github.com/vmware/pinniped/tree/e635a39cf793b5b915220a846de91e089ab431c9

use std::collections::{BTreeSet, HashMap, HashSet};
use std::fmt::Debug;
use std::time::Duration;

use futures_util::StreamExt as _;
use kube::api::{Api, ObjectMeta};
use kube::core::{NamespaceResourceScope, PartialObjectMeta};
use kube::runtime::WatchStreamExt as _;
use kube::runtime::watcher::{self, Event};
use kube::{Client, Resource};
use serde::de::DeserializeOwned;
use tokio::sync::watch;
use zeabur_identity_api::{EXPIRES_AT_ANNOTATION, EXPIRY_BUCKET_LABEL};
use zeabur_identity_core::clock::{Clock, UnixTime};

use super::objects::{DeleteOutcome, delete_if_unchanged};
use crate::watch::relisting_watcher;

/// How long to wait before retrying a delete that failed for an infrastructure reason.
const RETRY_AFTER: Duration = Duration::from_secs(30);

/// Upper bound on one sleep, so a wall-clock jump is noticed within this time.
const MAX_SLEEP: Duration = Duration::from_secs(300);

/// Reads the expiry annotation of an object.
#[must_use]
pub fn expires_at(meta: &ObjectMeta) -> Option<UnixTime> {
    meta.annotations
        .as_ref()?
        .get(EXPIRES_AT_ANNOTATION)?
        .parse::<u64>()
        .ok()
        .map(UnixTime::from_secs)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Entry {
    uid: String,
    resource_version: String,
    due: UnixTime,
}

/// An object that is due for deletion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Due {
    /// Object name.
    pub name: String,
    /// UID precondition.
    pub uid: String,
    /// `resourceVersion` precondition.
    pub resource_version: String,
}

/// The collector's view of which object expires when. Pure: no I/O, no clock.
#[derive(Debug, Default)]
pub struct Schedule {
    entries: HashMap<String, Entry>,
    queue: BTreeSet<(UnixTime, String)>,
    /// Names seen since the last watch (re)start; used to forget objects deleted while the
    /// watch was down.
    relisting: Option<HashSet<String>>,
}

impl Schedule {
    /// Records the latest metadata of an object. Objects without a valid expiry are ignored.
    pub fn apply(&mut self, meta: &ObjectMeta) {
        let Some(name) = meta.name.clone() else {
            return;
        };
        if let Some(seen) = self.relisting.as_mut() {
            seen.insert(name.clone());
        }
        let (Some(due), Some(uid), Some(rv)) =
            (expires_at(meta), &meta.uid, &meta.resource_version)
        else {
            self.remove(&name);
            return;
        };
        let entry = Entry {
            uid: uid.clone(),
            resource_version: rv.clone(),
            due,
        };
        self.remove(&name);
        self.queue.insert((entry.due, name.clone()));
        self.entries.insert(name, entry);
    }

    /// Forgets an object.
    pub fn remove(&mut self, name: &str) {
        if let Some(old) = self.entries.remove(name) {
            self.queue.remove(&(old.due, name.to_owned()));
        }
    }

    /// Marks the start of a full relist.
    pub fn begin_relist(&mut self) {
        self.relisting = Some(HashSet::new());
    }

    /// Ends a relist: forgets objects that were not seen.
    pub fn end_relist(&mut self) {
        if let Some(seen) = self.relisting.take() {
            let gone: Vec<String> = self
                .entries
                .keys()
                .filter(|n| !seen.contains(*n))
                .cloned()
                .collect();
            for name in gone {
                self.remove(&name);
            }
        }
    }

    /// When the next object is due.
    #[must_use]
    pub fn next_due(&self) -> Option<UnixTime> {
        self.queue.first().map(|(due, _)| *due)
    }

    /// Objects due at `now`, earliest first. They stay scheduled until [`Self::remove`] or
    /// [`Self::postpone`].
    #[must_use]
    pub fn due(&self, now: UnixTime) -> Vec<Due> {
        self.queue
            .iter()
            .take_while(|(due, _)| *due <= now)
            .filter_map(|(_, name)| {
                self.entries.get(name).map(|entry| Due {
                    name: name.clone(),
                    uid: entry.uid.clone(),
                    resource_version: entry.resource_version.clone(),
                })
            })
            .collect()
    }

    /// Retries an object later, keeping its preconditions.
    pub fn postpone(&mut self, name: &str, until: UnixTime) {
        if let Some(entry) = self.entries.get_mut(name) {
            self.queue.remove(&(entry.due, name.to_owned()));
            entry.due = until;
            self.queue.insert((until, name.to_owned()));
        }
    }

    /// Number of scheduled objects.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether nothing is scheduled.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Deletes expired objects of kind `K` in `namespace` until `shutdown` changes.
pub async fn run<K, C>(
    client: Client,
    namespace: &str,
    clock: C,
    mut shutdown: watch::Receiver<bool>,
) where
    K: Resource<Scope = NamespaceResourceScope, DynamicType = ()>
        + Clone
        + DeserializeOwned
        + Debug
        + Send
        + Sync
        + 'static,
    C: Clock,
{
    let kind = K::kind(&()).into_owned();
    let config = watcher::Config::default().labels(EXPIRY_BUCKET_LABEL);
    let api: Api<K> = Api::namespaced(client.clone(), namespace);
    // Metadata-only watch: names, versions and annotations, never object bodies.
    let metadata: Api<PartialObjectMeta<K>> = Api::namespaced(client, namespace);
    let mut events = relisting_watcher(metadata, config)
        .default_backoff()
        .boxed();
    let mut schedule = Schedule::default();
    tracing::info!(%kind, "garbage collector started");

    loop {
        let now = clock.now();
        let sleep_for = schedule
            .next_due()
            .map_or(MAX_SLEEP, |due| {
                Duration::from_secs(due.as_secs().saturating_sub(now.as_secs()))
            })
            .min(MAX_SLEEP);

        tokio::select! {
            event = events.next() => match event {
                Some(Ok(Event::Init)) => schedule.begin_relist(),
                Some(Ok(Event::InitApply(object) | Event::Apply(object))) => schedule.apply(&object.metadata),
                Some(Ok(Event::InitDone)) => schedule.end_relist(),
                Some(Ok(Event::Delete(object))) => {
                    if let Some(name) = &object.metadata.name {
                        schedule.remove(name);
                    }
                }
                Some(Err(error)) => tracing::warn!(%kind, %error, reason = "watch_failed", "watch error; retrying with backoff"),
                None => break,
            },
            () = tokio::time::sleep(sleep_for) => {
                collect(&api, &kind, &mut schedule, clock.now()).await;
            }
            _ = shutdown.changed() => break,
        }
    }
    tracing::info!(%kind, "garbage collector stopped");
}

async fn collect<K>(api: &Api<K>, kind: &str, schedule: &mut Schedule, now: UnixTime)
where
    K: Resource<Scope = NamespaceResourceScope> + Clone + DeserializeOwned + Debug + Send + Sync,
{
    for due in schedule.due(now) {
        match delete_if_unchanged(api, &due.name, &due.uid, &due.resource_version).await {
            Ok(DeleteOutcome::Deleted) => {
                tracing::debug!(%kind, "deleted expired object");
                schedule.remove(&due.name);
            }
            Ok(DeleteOutcome::NotFound) => schedule.remove(&due.name),
            // Changed since we saw it; the watch delivers the new version and its expiry.
            Ok(DeleteOutcome::Changed) => {
                schedule.postpone(&due.name, now.saturating_add(RETRY_AFTER));
            }
            Err(error) => {
                tracing::warn!(%kind, %error, reason = "deletion_failed", "deleting expired object failed; will retry");
                schedule.postpone(&due.name, now.saturating_add(RETRY_AFTER));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use proptest::prelude::*;

    use super::*;

    fn meta(name: &str, rv: &str, expires: Option<u64>) -> ObjectMeta {
        ObjectMeta {
            name: Some(name.to_owned()),
            uid: Some(format!("uid-{name}")),
            resource_version: Some(rv.to_owned()),
            annotations: expires
                .map(|e| BTreeMap::from([(EXPIRES_AT_ANNOTATION.to_owned(), e.to_string())])),
            ..ObjectMeta::default()
        }
    }

    fn t(secs: u64) -> UnixTime {
        UnixTime::from_secs(secs)
    }

    fn names(due: &[Due]) -> Vec<&str> {
        due.iter().map(|d| d.name.as_str()).collect()
    }

    #[test]
    fn schedules_by_expiry_and_uses_latest_version() {
        let mut s = Schedule::default();
        s.apply(&meta("a", "1", Some(100)));
        s.apply(&meta("b", "1", Some(50)));
        assert_eq!(s.next_due(), Some(t(50)));
        assert_eq!(s.due(t(49)), []);
        assert_eq!(names(&s.due(t(50))), ["b"]);

        // A refresh extends "b" and changes its resourceVersion.
        s.apply(&meta("b", "2", Some(500)));
        assert_eq!(s.next_due(), Some(t(100)));
        let due = s.due(t(1_000));
        assert_eq!(names(&due), ["a", "b"]);
        assert_eq!(due[1].resource_version, "2");
    }

    #[test]
    fn ignores_objects_without_a_valid_expiry() {
        let mut s = Schedule::default();
        s.apply(&meta("a", "1", None));
        let mut bad = meta("b", "1", None);
        bad.annotations = Some(BTreeMap::from([(
            EXPIRES_AT_ANNOTATION.to_owned(),
            "soon".to_owned(),
        )]));
        s.apply(&bad);
        assert!(s.is_empty());
        // Losing the annotation unschedules an object.
        s.apply(&meta("c", "1", Some(10)));
        s.apply(&meta("c", "2", None));
        assert!(s.is_empty());
    }

    #[test]
    fn relist_forgets_objects_deleted_while_disconnected() {
        let mut s = Schedule::default();
        s.apply(&meta("a", "1", Some(10)));
        s.apply(&meta("b", "1", Some(20)));
        s.begin_relist();
        s.apply(&meta("b", "1", Some(20)));
        s.end_relist();
        assert_eq!(names(&s.due(t(100))), ["b"]);
    }

    #[test]
    fn postpone_and_remove() {
        let mut s = Schedule::default();
        s.apply(&meta("a", "1", Some(10)));
        s.postpone("a", t(40));
        assert_eq!(s.due(t(39)), []);
        assert_eq!(names(&s.due(t(40))), ["a"]);
        s.remove("a");
        assert!(s.is_empty() && s.next_due().is_none());
    }

    #[derive(Debug, Clone)]
    enum Op {
        Apply(u8, u8, Option<u16>),
        Remove(u8),
        Postpone(u8, u16),
    }

    fn op() -> impl Strategy<Value = Op> {
        prop_oneof![
            (0_u8..6, 0_u8..4, proptest::option::of(0_u16..1000))
                .prop_map(|(n, r, e)| Op::Apply(n, r, e)),
            (0_u8..6).prop_map(Op::Remove),
            (0_u8..6, 0_u16..1000).prop_map(|(n, e)| Op::Postpone(n, e)),
        ]
    }

    proptest! {
        /// The queue and the entry map never disagree, and `due` returns exactly the scheduled
        /// objects whose time has come, with the latest preconditions.
        #[test]
        fn queue_and_entries_stay_consistent(ops in proptest::collection::vec(op(), 0..100), now in 0_u64..1000) {
            let mut s = Schedule::default();
            let mut model: HashMap<String, (String, u64)> = HashMap::new();
            for op in ops {
                match op {
                    Op::Apply(n, r, e) => {
                        let name = format!("o{n}");
                        s.apply(&meta(&name, &r.to_string(), e.map(u64::from)));
                        match e {
                            Some(e) => { model.insert(name, (r.to_string(), u64::from(e))); }
                            None => { model.remove(&name); }
                        }
                    }
                    Op::Remove(n) => {
                        let name = format!("o{n}");
                        s.remove(&name);
                        model.remove(&name);
                    }
                    Op::Postpone(n, e) => {
                        let name = format!("o{n}");
                        s.postpone(&name, t(u64::from(e)));
                        if let Some(entry) = model.get_mut(&name) { entry.1 = u64::from(e); }
                    }
                }
                prop_assert_eq!(s.len(), model.len());
                prop_assert_eq!(s.queue.len(), s.entries.len());
            }
            let mut expected: Vec<(String, String)> = model
                .iter()
                .filter(|(_, (_, due))| *due <= now)
                .map(|(n, (rv, _))| (n.clone(), rv.clone()))
                .collect();
            expected.sort();
            let mut got: Vec<(String, String)> = s.due(t(now)).into_iter().map(|d| (d.name, d.resource_version)).collect();
            got.sort();
            prop_assert_eq!(got, expected);
        }
    }
}
