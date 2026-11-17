---
name: zeabur-identity-cluster-tests
description: Run Zeabur Identity's Kubernetes integration and end-to-end tests on a disposable k3s cluster, and debug kube-apiserver's authentication configuration. Use when changing anything in zeabur-identity-k8s, the server's background tasks, manifests, kube-config output or the container image.
---

# Cluster tests

Set up the disposable cluster and run the tests as `CONTRIBUTING.md` ("Disposable k3d cluster")
says, on a Linux machine or VM, never on a cluster you use. kube-apiserver re-reads
`<dir>/authn/authn.yaml` about once a minute, so the e2e test takes 1–3 minutes. After a change to
upstream sign-in, also run `./scripts/keycloak-e2e.sh`.

## What to check when something fails
- **Tokens never accepted** (whoami times out): read the apiserver log —
  `docker logs k3d-zeabur-identity-server-0 2>&1 | grep -iE "authentication config|oidc"`. Config
  validation errors (for example CEL type errors; JSON claims are untyped, use `dyn(...)` for
  comprehensions) make the reload skip the file permanently until it changes. A healthy reload
  logs `reloaded authentication config`.
- **`kube-config` waits, then fails on the internal certificate**: read
  `kubectl -n <namespace> describe certificate zeabur-identity-internal-ca zeabur-identity-internal-tls`.
  A cert-manager webhook error right after `k3d-up.sh` passes on retry.
- **Probe CEL quickly**: write a candidate config with a dummy issuer into the mounted
  directory, wait ~70 s, and read the log; a health error about the dummy issuer means the
  config itself validated. Restore the empty config afterwards.
