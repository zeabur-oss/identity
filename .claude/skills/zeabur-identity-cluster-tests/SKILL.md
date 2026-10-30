---
name: zeabur-identity-cluster-tests
description: Run Zeabur Identity's Kubernetes integration and end-to-end tests on a disposable k3s cluster, and debug kube-apiserver's authentication configuration. Use when changing anything in zeabur-identity-k8s, the server's background tasks, manifests, kube-config output or the container image.
---

# Cluster tests

Follow `zeabur-oss-cluster-tests` (install: `npx skills add zeabur-oss/skills --skill
zeabur-oss-cluster-tests`; `skills-lock.json` pins it): a disposable cluster on a Linux machine
or VM, a snapshot restored after every run, and the common failures. Sync with
`rsync -a --delete --exclude target ./ host:zeabur-identity/`.

## Cluster with a writable authentication config
`scripts/k3d-up.sh` creates it with cert-manager, as CI does. kube-apiserver re-reads
`<dir>/authn/authn.yaml` about once a minute; the file starts with no issuer:

```sh
./scripts/k3d-up.sh ~/zeabur-identity-k3d && export KUBECONFIG=~/zeabur-identity-k3d/kubeconfig
```

## Run
```sh
cargo nextest run --locked --run-ignored only -E 'binary(kubernetes)'          # storage, RBAC, admission
./scripts/build-image.sh zeabur-identity:e2e && k3d image import zeabur-identity:e2e -c zeabur-identity
ZEABUR_IDENTITY_E2E_IMAGE=zeabur-identity:e2e ZEABUR_IDENTITY_E2E_AUTHN_DIR=$HOME/zeabur-identity-k3d/authn \
ZEABUR_IDENTITY_E2E_MEASUREMENTS=/tmp/m.json \
  cargo nextest run --locked --run-ignored only -E 'binary(e2e)'
```
The e2e test takes 1–3 minutes, mostly waiting for kube-apiserver to reload the config.

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
- The e2e test writes the kubelet's memory figures to `ZEABUR_IDENTITY_E2E_MEASUREMENTS`.

Clean up with `k3d cluster delete zeabur-identity`.
