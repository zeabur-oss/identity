---
name: zeabur-identity-dev
description: What is special about Zeabur Identity — its binaries, conformance records, generated files and Kubernetes scale rules. Use before changing any Rust, TypeScript, Nix or CI file in this repo.
---

# Zeabur Identity development loop

What is Zeabur Identity's own. The checks CI runs (`scripts/ci/{lint,test,ui,kubernetes}.sh`),
commits and pull requests: `CONTRIBUTING.md`. Cluster tests: `zeabur-identity-cluster-tests`.
The interface: `zeabur-identity-ui`.

## Crates and binaries
- The crate table is in `README.md`. Binaries: `zeabur-identity` (in-cluster server) and
  `zeabur-identityctl` (admin CLI).

## Conformance
- Implementing a MUST/SHOULD updates the ledger `docs/internal/conformance.md` (`zeabur-identity-spec-work`); the public
  `docs/reference/conformance.mdx` is narrative and changes only when a guarantee changes.

## Generated files
- Regenerate committed outputs in the same commit: `cargo run -q -p zeabur-identityctl -- crds | jq -r '.items[] | "---", tojson' >
  deploy/chart/identity/crds/crds.yaml`, `… -- rbac > deploy/chart/identity/files/rbac.json`,
  `deploy/chart/identity/files/deployment.json` (the command is in `deployment::tests::chart_objects_are_current`;
  tests fail when they are stale), and
  `templates/ds.html` (`./scripts/build-ui.sh`, which also builds `ui/dist`, not committed).

## Scale
- Watch with kube-rs `watcher`, `reflector` or `Controller`.
- One LIST of the namespace, selected by label, replaces a GET per object.
