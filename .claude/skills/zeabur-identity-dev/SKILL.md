---
name: zeabur-identity-dev
description: Day-to-day development loop for the Zeabur Identity repository — environment, the checks CI runs, lint conventions, commits. Use before changing any Rust, TypeScript, Nix or CI file in this repo.
---

# Zeabur Identity development loop

Follow the shared skills (install: `npx skills add zeabur-oss/skills --skill <name>`;
`skills-lock.json` pins them): `zeabur-oss-rust` (Nix toolchain, workspace, lints, common
checks), `zeabur-oss-standards` (with [`STANDARDS.md`](STANDARDS.md) here),
`zeabur-oss-workflow` (commits and pull requests). This skill adds what is Zeabur Identity's own.

## Crates and binaries
- The crate table is in `README.md`. Binaries: `zeabur-identity` (in-cluster server) and
  `zeabur-identityctl` (admin CLI).

## Checks (what CI runs, beyond `zeabur-oss-rust`'s)
```sh
nix develop -c ./scripts/ci.sh unsafe-report
```
Cluster tests: see the `zeabur-identity-cluster-tests` skill. The `ui` job (bun, Tailwind,
oxlint, oxfmt, fallow from `ui/package.json`) is in `zeabur-identity-ui`.

## Documentation
- A comment says only what the code cannot: a quirk and its cause, a workaround, or the
  specification section behind behaviour that must not change, cited in rustdoc (see
  `zeabur-identity-spec-work`). Usually one line; no design rationale, history or measurements.
- Implementing a MUST/SHOULD updates `docs/reference/conformance.mdx`.

## Generated files
- Regenerate committed outputs in the same commit: `cargo run -q -p zeabur-identityctl -- crds >
  deploy/crds.json`, `… -- rbac > deploy/rbac.json` (tests fail when they are stale), and the UI
  assets with `templates/ds.html` (`./scripts/build-ui.sh`).
