# zeabur-identity-k8s

Zeabur Identity's Kubernetes side: storage adapters on the custom resources that hold its state,
garbage collection of expired objects, the install manifests, and the kube-apiserver
`AuthenticationConfiguration` that makes a cluster accept Zeabur Identity's tokens.

## Contents

- [`objects`](crate::objects): the three single-use primitives behind every security-relevant
  write.
- [`keys`](crate::keys), [`directory`](crate::directory), [`credentials`](crate::credentials),
  [`grants`](crate::grants), [`setup`](crate::setup): the
  `zeabur-identity-keys` and `zeabur-identity-store` traits implemented on Kubernetes objects.
- [`gc`](crate::gc): deletes expired grants and invitations, driven by a metadata-only watch.
- [`rbac`](crate::rbac), [`deployment`](crate::deployment): the install manifests, generated
  from code; tests check `deploy/crds.json` and `deploy/rbac.json` against them.
- [`kube_config`](crate::kube_config), [`internal_tls`](crate::internal_tls): the
  kube-apiserver configuration and the in-cluster discovery certificate.
- [`invitations`](crate::invitations), [`setup`](crate::setup), [`clients`](crate::clients): the
  admin's side of `zeabur-identityctl invite`, `zeabur-identityctl setup-link` and `zeabur-identityctl client create`.

## Place in the workspace

Depends on `zeabur-identity-api` (the custom resources), `zeabur-identity-core`, `zeabur-identity-keys`, `zeabur-identity-store` and `zeabur-identity-tls`. Used by the `zeabur-identity`
server, the `zeabur-identityctl` admin CLI and the `zeabur-identity-e2e` tests.

## Key properties

- **No write before authentication.** Pre-login flows, WebAuthn challenges and authorization
  codes stay in sealed cookies and process memory. The API server sees one write per code
  redemption, one per refresh and one when a grant ends, so anonymous traffic cannot fill etcd
  (the failure mode of storing a request object per unauthenticated `/authorize`, seen in
  [Dex]).
- **Current authorization data, indexed misses.** Watches maintain a client index and a
  metadata-only user UID index, shared by directory clones. The client index keeps the display
  name and home URL, and drops the secret hash, redirect URIs and audiences. The sign-in page's
  application list and the account page's client names read only this index. The asynchronous constructor
  waits for both initial snapshots within 30 seconds; the last clone dropping stops the watches.
  Annotations, labels, managed fields, owner references and finalizers are discarded before
  reflection; the locator does not use them, and GitOps metadata can dominate retained memory.
  Names, namespaces, UIDs and resource versions remain intact.
  Relists replace each index atomically. Arbitrarily many unknown client IDs or user
  subjects cause no per-request API reads, and new objects become visible when their watch events
  arrive. Known clients and users are read directly on every request: secrets, permissions and
  disabled flags are never cached. A subject lookup verifies the directly read user's UID, so
  deleting and recreating an object under the same name cannot substitute a different user.
  All-namespaces indexes use each object's metadata namespace for direct reads; duplicate client
  names across namespaces fail closed rather than selecting an arbitrary client.
  Watch errors are logged and retry with backoff, never a per-ID GET fallback. Directory GETs
  do not emit per-request INFO logs or maintain custom telemetry counters.
- **Single use is decided by the API server.** Create with a deterministic name, update with
  `resourceVersion`, delete with `uid` and `resourceVersion` preconditions ([API concepts],
  [DeleteOptions]). Ambiguous answers fail closed. The integration tests race 64 concurrent
  requests per primitive against a real k3s API server: exactly one wins.
- **Least privilege for the server.** Zeabur Identity's service account reaches Secrets only by name
  (`get`/`update` on the key Secret, `get`/`delete` on the setup Secret, `get` on the internal
  certificate), and `create` on core `Events` for the account page's audit trail. It has no
  `list`, `watch` or `create` on Secrets, since `create` cannot be
  limited to a name ([RBAC]). It has nothing outside its namespace, no RBAC objects and no
  `impersonate`. A compromised Zeabur Identity can change Zeabur Identity's own state (it holds
  the signing key anyway) but cannot reach other workloads or grant itself cluster rights.
- **Admin rights come from the account type.** Installation binds `zeabur:admins` to
  `cluster-admin` (`ClusterRoleBinding` `zeabur-identity-cluster-admins`) and binds nothing for
  other groups. Only `User`s with `accountType: Admin` get the `admins` group; the CRD refuses
  `admins` in `spec.groups`. Install-wide settings (`teams`, `admin-aal3`) live in the `ConfigMap`
  `zeabur-identity-settings`, which Zeabur Identity reads by name and admins write.
- **Hashes only.** Grants, invitations, the setup token and client secrets are stored as
  SHA-256 hashes of high-entropy values; credentials hold public keys. Client secrets are
  generated, never chosen, because an unsalted hash of a password could be reversed offline.

## References

- [API concepts] The Kubernetes Authors, "Kubernetes API Concepts: Resource versions,"
  Kubernetes documentation.
- [DeleteOptions] The Kubernetes Authors, "`DeleteOptions`," Kubernetes API reference.
- [RBAC] The Kubernetes Authors, "Using RBAC Authorization," Kubernetes documentation.
- [KEP-3331] The Kubernetes Authors, "KEP-3331: Structured Authentication Configuration,"
  kubernetes/enhancements.
- [Dex] Dex project, `storage/kubernetes/`, commit 05a2750, and issues #1091, #1292, #1969.

[API concepts]: https://kubernetes.io/docs/reference/using-api/api-concepts/
[DeleteOptions]: https://kubernetes.io/docs/reference/kubernetes-api/common-definitions/delete-options/
[RBAC]: https://kubernetes.io/docs/reference/access-authn-authz/rbac/
[KEP-3331]: https://github.com/kubernetes/enhancements/tree/master/keps/sig-auth/3331-structured-authentication-configuration
[Dex]: https://github.com/dexidp/dex/tree/05a275057112ba93e17db21f600b756f000f1c21/storage/kubernetes
