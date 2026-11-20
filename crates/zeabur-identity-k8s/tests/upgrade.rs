//! Credentials stored by released versions, read through this version's CRD.
//!
//! The test replaces the cluster's `Credential` CRD with a released one and back, so it runs
//! alone, after the other cluster tests:
//! `cargo nextest run --run-ignored only -E 'binary(upgrade)'`.

#[cfg(test)]
mod tests {
    use std::io::Write as _;
    use std::process::{Command, Stdio};
    use std::time::Duration;

    use k8s_openapi::apiextensions_apiserver::pkg::apis::apiextensions::v1::CustomResourceDefinition;
    use kube::api::{Api, ApiResource, DeleteParams, PostParams};
    use kube::core::Object;
    use kube::core::object::NotUsed;
    use kube::{Client, Config, Resource as _, ResourceExt as _};
    use serde::{Deserialize, Serialize};
    use zeabur_identity_api::credential::{Credential, CredentialKind, CredentialSpec, Passkey};
    use zeabur_identity_api::upstream::{ExternalId, Issuer, Subject};
    use zeabur_identity_api::user::{User as UserObject, UserSpec};
    use zeabur_identity_api::{USER_LABEL, definitions};
    use zeabur_identity_core::clock::UnixTime;
    use zeabur_identity_k8s::credentials::KubeCredentialStore;
    use zeabur_identity_k8s::rbac;
    use zeabur_identity_store::{
        CredentialStore as _, Rename, Unlink, User, external_credential_name,
        passkey_credential_name,
    };

    const CRD: &str = "crd/credentials.identity.zeabur.com";

    fn kubectl(args: &[&str], stdin: &str) -> String {
        let mut child = Command::new("kubectl")
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("kubectl must be on PATH");
        child
            .stdin
            .take()
            .unwrap()
            .write_all(stdin.as_bytes())
            .unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "kubectl {args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8_lossy(&output.stdout).into_owned()
    }

    fn apply(manifest: &impl Serialize) {
        kubectl(
            &["apply", "--server-side", "--force-conflicts", "-f", "-"],
            &serde_json::to_string(manifest).unwrap(),
        );
    }

    /// A Kubernetes `List`.
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct List<'a, T> {
        api_version: &'static str,
        kind: &'static str,
        items: &'a [T],
    }

    fn apply_crds(items: &[CustomResourceDefinition]) {
        apply(&List {
            api_version: "v1",
            kind: "List",
            items,
        });
        kubectl(&["wait", "--for=condition=Established", CRD], "");
    }

    /// The members of a `Credential` that released versions wrote, which this version's types
    /// no longer have as such.
    #[derive(Clone, Debug, Serialize, Deserialize)]
    struct ReleasedSpec {
        user: String,
        #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
        kind: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        passkey: Option<Passkey>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        external: Option<ExternalId>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        provider: Option<String>,
    }

    type Released = Object<ReleasedSpec, NotUsed>;

    fn current_crds() -> Vec<CustomResourceDefinition> {
        definitions()
    }

    fn external(issuer: &str, subject: &str) -> ExternalId {
        ExternalId {
            issuer: Issuer::new(issuer).unwrap(),
            subject: Subject::new(subject).unwrap(),
        }
    }

    /// Creates `spec` as a `Credential`, retrying until the API server keeps its `type`: right
    /// after a CRD change it can still serve the schema before.
    async fn create_released(api: &Api<Released>, object: &Released) {
        let name = object.name_any();
        for _ in 0..50 {
            if let Ok(created) = api.create(&PostParams::default(), object).await {
                if created.spec.kind.is_some() {
                    return;
                }
                api.delete(&name, &DeleteParams::default()).await.unwrap();
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        panic!("the released CRD did not keep the type of {name}");
    }

    /// Waits until the API server admits a `Credential` without `type`, so it serves this
    /// version's CRD.
    async fn wait_for_current(api: &Api<Credential>, user: &str) {
        let probe = Credential::new(
            "c-probe",
            CredentialSpec {
                user: user.to_owned(),
                kind: CredentialKind::External(external("https://probe.example", "1")),
            },
        );
        for _ in 0..50 {
            if api.create(&PostParams::default(), &probe).await.is_ok() {
                api.delete("c-probe", &DeleteParams::default())
                    .await
                    .unwrap();
                return;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        panic!("the API server did not serve this version's Credential CRD");
    }

    /// Stores a passkey and two linked accounts as `version` wrote them, applies this version's
    /// CRD, and uses them as Zeabur Identity's service account.
    #[expect(clippy::too_many_lines, reason = "one upgrade scenario, top to bottom")]
    async fn check(
        version: &str,
        released_crd: &str,
        linked_spec: fn(&str, ExternalId) -> ReleasedSpec,
    ) {
        let admin = Client::try_default()
            .await
            .expect("KUBECONFIG must point at a test cluster");
        let mut suffix = [0_u8; 4];
        aws_lc_rs::rand::fill(&mut suffix).unwrap();
        let namespace = format!("zeabur-identity-upgrade-{:08x}", u32::from_be_bytes(suffix));
        let mut crds = current_crds();
        crds.retain(|crd| crd.spec.names.kind != "Credential");
        crds.push(serde_json::from_str(released_crd).unwrap());
        apply_crds(&crds);
        for manifest in rbac::manifests(&namespace) {
            apply(&manifest);
        }

        let users: Api<UserObject> = Api::namespaced(admin.clone(), &namespace);
        let alice = users
            .create(
                &PostParams::default(),
                &UserObject::new(
                    "alice",
                    UserSpec {
                        username: "alice".into(),
                        ..UserSpec::default()
                    },
                ),
            )
            .await
            .unwrap();
        let owner = alice.owner_ref(&()).unwrap();
        let user = User {
            name: "alice".into(),
            subject: alice.uid().unwrap(),
            username: "alice".into(),
            display_name: None,
            groups: Vec::new(),
            disabled: false,
            account_type: zeabur_identity_core::account::AccountType::Regular,
        };
        let resource = ApiResource::erase::<Credential>(&());
        let released: Api<Released> = Api::namespaced_with(admin.clone(), &namespace, &resource);
        let object = |name: &str, spec: ReleasedSpec| {
            let mut object = Released::new(name, &resource, spec);
            object.metadata.labels = Some([(USER_LABEL.to_owned(), "alice".to_owned())].into());
            object.metadata.owner_references = Some(vec![owner.clone()]);
            object
        };
        let released_spec = |kind: &str| ReleasedSpec {
            user: "alice".into(),
            kind: Some(kind.to_owned()),
            passkey: None,
            external: None,
            provider: None,
        };
        let passkey = passkey_credential_name(b"passkey");
        let github = external("https://github.com", "583231");
        let google = external("https://accounts.google.com", "1047");
        create_released(
            &released,
            &object(
                &passkey,
                ReleasedSpec {
                    passkey: Some(Passkey {
                        credential_id: "cGFzc2tleQ".into(),
                        record: "{}".into(),
                        backup_eligible: false,
                        aaguid: None,
                        label: None,
                    }),
                    ..released_spec("Passkey")
                },
            ),
        )
        .await;
        for (id, provider) in [(&github, "github"), (&google, "google")] {
            let spec = linked_spec(provider, id.clone());
            create_released(&released, &object(&external_credential_name(id), spec)).await;
        }

        apply_crds(&current_crds());
        let current: Api<Credential> = Api::namespaced(admin.clone(), &namespace);
        wait_for_current(&current, "alice").await;

        let mut config = Config::infer().await.unwrap();
        config.auth_info.impersonate =
            Some(format!("system:serviceaccount:{namespace}:{}", rbac::NAME));
        let store = KubeCredentialStore::new(Api::namespaced(
            Client::try_from(config).unwrap(),
            &namespace,
        ));

        // Read and sign in: the passkey record, each linked account's user, the last use.
        let stored = store.get(&passkey).await.unwrap().expect(version);
        assert_eq!(stored.user, "alice", "{version}");
        for id in [&github, &google] {
            let name = external_credential_name(id);
            let linked = store.linked_account(&name).await.unwrap().expect(version);
            assert!(linked.signs_in_as(&user), "{version}");
            store
                .touch(&name, UnixTime::from_secs(1_800_000_000))
                .await
                .unwrap();
        }
        let listed = store.linked_accounts(&user).await.unwrap();
        let mut issuers: Vec<&str> = listed.iter().map(|l| l.issuer.as_str()).collect();
        issuers.sort_unstable();
        assert_eq!(
            issuers,
            ["https://accounts.google.com", "https://github.com"],
            "{version}"
        );
        assert_eq!(
            store.rename(&user, &passkey, "MacBook").await.unwrap(),
            Rename::Renamed,
            "{version}"
        );
        assert_eq!(
            store.passkeys(&user).await.unwrap()[0].label.as_deref(),
            Some("MacBook"),
            "{version}"
        );

        // Unlink both accounts; the passkey stays.
        for id in [&github, &google] {
            let name = external_credential_name(id);
            assert_eq!(
                store.unlink(&user, &name).await.unwrap(),
                Unlink::Unlinked,
                "{version}"
            );
            assert!(current.get_opt(&name).await.unwrap().is_none(), "{version}");
        }
        assert!(store.get(&passkey).await.unwrap().is_some(), "{version}");

        kubectl(&["delete", "namespace", &namespace, "--wait=false"], "");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "needs a Kubernetes cluster (KUBECONFIG); replaces the Credential CRD"]
    async fn credentials_stored_by_released_versions_sign_in_and_unlink() {
        check(
            "v0.1.2",
            include_str!("upgrade/credential-crd-v0.1.2.json"),
            |provider, external| ReleasedSpec {
                user: "alice".into(),
                kind: Some(
                    if provider == "github" {
                        "GitHub"
                    } else {
                        "Google"
                    }
                    .to_owned(),
                ),
                passkey: None,
                external: Some(external),
                provider: None,
            },
        )
        .await;
        check(
            "v0.2.0",
            include_str!("upgrade/credential-crd-v0.2.0.json"),
            |provider, external| ReleasedSpec {
                user: "alice".into(),
                kind: Some("Upstream".to_owned()),
                passkey: None,
                external: Some(external),
                provider: Some(provider.to_owned()),
            },
        )
        .await;
    }
}
