---
default: minor
---

# A Helm chart: `oci://ghcr.io/zeabur-oss/charts/identity`

`helm install identity oci://ghcr.io/zeabur-oss/charts/identity` installs the CRDs, the server, an Ingress with a Let's Encrypt certificate at `identity.<ip>.sslip.io` by default, and prints the first administrator's setup link. Each release publishes the chart with the image pinned by digest. The committed CRDs moved to `deploy/chart/identity/crds/crds.yaml` and the RBAC to `deploy/chart/identity/files/rbac.json`.
