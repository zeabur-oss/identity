---
name: zeabur-identity-dev
description: Day-to-day development loop for the Zeabur Identity repository — environment, the checks CI runs, lint conventions, commits. Use before changing any Rust, TypeScript, Nix or CI file in this repo.
---

# Zeabur Identity development loop

## Environment
- Everything runs inside the Nix dev shell: prefix commands with `nix develop -c …` (or enter
  `nix develop`). Do not use system-installed toolchains; `flake.lock` pins the
  Rust nightly.
- The workspace is a flat `crates/` directory; dependencies only point downwards (see the crate
  table in `README.md`). Put new code in the lowest crate that can hold it; never add an upward
  dependency. Binaries: `zeabur-identity` (in-cluster server) and `zeabur-identityctl` (admin CLI).
- Workspace dependency versions live in the root `Cargo.toml` `[workspace.dependencies]`;
  crates use `name.workspace = true`.

## Checks (what CI runs)
```sh
nix develop -c cargo fmt --all --check   # drop --check to apply the formatting
nix develop -c cargo lint          # clippy --workspace --all-targets --all-features --locked -D warnings
RUSTDOCFLAGS="-D warnings" nix develop -c cargo doc --workspace --no-deps --document-private-items --locked
nix develop -c cargo nextest run --workspace --all-features --locked --no-tests=warn
nix develop -c cargo deny --locked check
nix develop -c ./scripts/ci.sh unsafe-report
nix develop -c bash -c 'shellcheck scripts/*.sh && actionlint && nixfmt --check flake.nix'
```
Iterate per crate with `-p <crate>` to keep builds short. Cluster tests: see the
`zeabur-identity-cluster-tests` skill. The `ui` job (bun, Tailwind, oxlint, oxfmt, fallow from
`ui/package.json`) is in `zeabur-identity-ui`.

## Lint conventions
- `unsafe` is forbidden. No panics on input: no `unwrap`/`expect`/indexing outside tests.
- Suppress a lint only with `#[expect(lint, reason = "…")]`; never `#[allow]`.
- Matches in security logic are exhaustive (no wildcard arms on enums).
- Output to stdout/stderr only through a binary's `output` module; everything else uses
  `tracing`.
- Docs: identifiers in backticks (clippy `doc_markdown`); add proper nouns to `clippy.toml`
  `doc-valid-idents` instead of backticking them.
- `rustfmt` reflows code; when editing with scripts, match on short, stable anchors.

## Standards
- Writing a comment, rustdoc or commit message; adding or removing a test; adding a trait, layer,
  option or flag; or code that lists, watches, polls, stores or fans out: apply
  [`STANDARDS.md`](STANDARDS.md) and check the change against it.

## Documentation
- Rationale goes in rustdoc next to the code: state the decision and why, cite the
  specification section, paper or prior art (see `zeabur-identity-spec-work`). Each crate's README is its
  crate-level doc (`#![doc = include_str!("../README.md")]`).
- Implementing a MUST/SHOULD updates `docs/reference/conformance.mdx`.

## Commits
- Conventional Commits (`feat:`, `fix:`, `refactor:`, `docs:`, `chore(scope):`, `!` for breaking
  changes with a `BREAKING CHANGE:` footer).
- Sign off every commit (`git commit -s`, DCO). Do not add tool- or session-specific trailers.
- Regenerate committed outputs in the same commit: `cargo run -q -p zeabur-identityctl -- crds >
  deploy/crds.json`, `… -- rbac > deploy/rbac.json` (tests fail when they are stale), and the UI
  assets with `templates/ds.html` (`./scripts/build-ui.sh`).
