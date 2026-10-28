# Contributing

## Developer Certificate of Origin

This project uses the [Developer Certificate of Origin 1.1](DCO), not a CLA. Sign off every
commit to certify that you wrote it or otherwise have the right to submit it under the project
licence:

```sh
git commit -s
```

CI rejects pull requests whose commits lack a `Signed-off-by` line matching the author. Commit
messages follow [Conventional Commits](https://www.conventionalcommits.org/).

## Building from source

Use a Linux machine matching your cluster's architecture, with Docker running and Nix
flakes enabled:

```sh
git clone https://github.com/zeabur-oss/identity.git
cd zeabur-identity
nix develop
cargo build --release --locked -p zeabur-identityctl
alias zeabur-identityctl="$PWD/target/release/zeabur-identityctl"
./scripts/build-image.sh zeabur-identity:dev
```

For a local k3s cluster, import the image and choose it for the installation:

```sh
docker save zeabur-identity:dev | sudo k3s ctr images import -
export ZEABUR_IDENTITY_IMAGE=docker.io/library/zeabur-identity:dev
```

Continue at [Install Zeabur Identity](docs/get-started/quickstart.mdx), with the cluster-admin
kubeconfig from the guide. For a k3d test cluster, use the [test setup](#disposable-k3d-cluster)
below.

## Before you open a pull request

Run what CI runs. CI calls `scripts/ci.sh` once per job through the shared workflow of
[zeabur-oss/.github](https://github.com/zeabur-oss/.github); the script enters `nix develop`
itself, so a job runs the same on your machine:

```sh
./scripts/ci.sh --list          # format clippy docs test cargo-deny unsafe-report ui kubernetes
./scripts/ci.sh format          # cargo fmt, nixfmt, shellcheck, actionlint
./scripts/ci.sh clippy          # cargo lint: all targets and features, -D warnings
./scripts/ci.sh test            # and docs, cargo-deny, unsafe-report, ui
./scripts/ci.sh kubernetes      # k3s with Docker: see "Disposable k3d cluster" below
```

The `ui` job's `fallow audit --base HEAD^` compares with the previous commit; on a branch, run
`(cd ui && bun run fallow audit --base main)` inside `nix develop` instead.

Design rationale lives next to the code, in rustdoc: state the decision and its reason, and
cite the specification section, paper or prior art it rests on (the crates show the style).
Never cite something you have not read; write "not verified" instead. Code that implements a
MUST or SHOULD of a specification updates [docs/reference/conformance.mdx](docs/reference/conformance.mdx).
Documentation is written in English.

## Toolchain

- `flake.lock` is the only place the compiler version is set. `nix develop` takes the newest
  nightly in the locked rust-overlay that has every component and target listed in `flake.nix`.
  There is no `rust-toolchain.toml`; use `nix develop`, not rustup.
- The pinned nightly enables the parallel front end (`-Zthreads`), current clippy lints and
  rustfmt's import ordering. No `#![feature]` is used. Moving to stable is a configuration
  change: use `rust-bin.stable.latest` in `flake.nix`, drop `-Zthreads` from `.cargo/config.toml`
  and the nightly-only `rustfmt.toml` options.
- Renovate's lock file maintenance (`renovate.json`) updates `flake.lock` every Monday, and with it
  the nightly. A new nightly can bring new clippy lints or change a nightly-only setting; fix those
  on that pull request before merging.

Release binaries are built with `trim-paths = "all"`, so they carry no build-host paths.

## Compiler cache (optional)

The repository sets up no compiler cache. To share compiled crates between checkouts and
worktrees on your machine, install [kache](https://ninja.kunobi.com/docs/kache/getting-started/c-cpp)
and set `RUSTC_WRAPPER=kache` in your shell profile; `nix develop` keeps it. The C code that build
scripts compile (aws-lc-sys) goes through kache too, with no further setup.
`scripts/release.sh build` unsets `RUSTC_WRAPPER`, so release binaries are always compiled.

## Lints and formatting

Lints are set once for the workspace in `Cargo.toml`. All are `warn`, so unfinished work still
compiles locally, and `cargo lint` turns every warning into an error in CI.

- `unsafe_code` and `non_ascii_idents` are forbidden.
- clippy `pedantic`, `cargo` and `nursery` are on.
- A selection of `restriction` lints targets what matters in an internet-facing authentication
  server: no panics on input (`unwrap_used`, `expect_used`, `indexing_slicing`, …; tests may
  unwrap), exhaustive matches in security logic (`wildcard_enum_match_arm`), no silently dropped
  errors (`map_err_ignore`, `let_underscore_must_use`, …), and no unexplained suppressions:
  use `#[expect(lint, reason = "…")]`, which also fails once it is no longer needed.
- Only the binaries' `output` modules write to stdout or stderr; everything else logs through
  `tracing`.

`rustfmt.toml` groups and orders imports, wraps comments at 100 columns and fails on code it
cannot format.

## Dependencies

`cargo deny check` enforces the policy in `deny.toml`:

- Licences must be OSI-approved ([SPDX list](https://spdx.org/licenses/),
  [OSI](https://opensource.org/licenses)); crates come from crates.io only; no `*` versions.
- TLS uses rustls with [aws-lc-rs](https://aws.github.io/aws-lc-rs/) as the only cryptographic
  backend. `ring`, OpenSSL, `native-tls`, the FIPS build of aws-lc and `webpki-roots` (whose
  CDLA licence is not OSI-approved; the image ships a CA bundle instead) are banned.
- [RustSec](https://rustsec.org/) advisories and yanked versions fail the check. Every ignored
  advisory carries its reason in `deny.toml`.

Cargo does not pick a release younger than seven days unless it is already in the lock file
(`registry.global-min-publish-age` in `.cargo/config.toml`), which gives the community time to
catch a compromised release. An urgent security update overrides it for one command:
`CARGO_REGISTRY_GLOBAL_MIN_PUBLISH_AGE="0 days" cargo update -p <crate>`.

The sign-in pages' build tools (`ui/package.json`) follow the same rules: exact versions in a
committed `bun.lock`, no release younger than seven days (`ui/bunfig.toml`), OSI-approved
licences and no install scripts. They are the versions Zeabur's web interface uses. The design
system is a Git dependency pinned to a commit.

[Renovate](https://docs.renovatebot.com/) (`renovate.json`) opens the weekly crate, `ui/` package,
action digest and k3s updates under the same seven-day delay; compatible crate updates share one
pull request, and so do compatible `ui/` updates.
A crate update that brings in new `unsafe` or native code fails `unsafe-report` until the
allowlist entry below is added and reviewed, so those pull requests are never merged unread.

A dependency that reaches the shipped binaries and contains `unsafe` code or builds native code
needs an entry in `supply-chain/unsafe-allowlist.toml` with a reason and the date a maintainer
approved it. `scripts/unsafe-report.sh` scans the shipped dependency graph (normal and build
dependencies of `zeabur-identity` and `zeabur-identityctl` for the image target), lists every such crate and fails
on one that is not approved; an entry marked `pending` is a proposal awaiting review. The count
is a review signal, not an audit.

## Tests

- **Unit and integration tests** run anywhere: `cargo nextest run --workspace`.
- **Cluster tests** and **end-to-end tests** are `#[ignore]`d and require a disposable cluster
  where you are cluster admin. The setup below is what `./scripts/ci.sh kubernetes` runs, in CI and
  locally.

### Disposable k3d cluster

Run from the Zeabur Identity checkout on a Linux machine or VM with Docker running, Nix with flakes,
and permission to use Docker. Enter `nix develop` for the tools, including k3d and kubectl.
Do not use a production cluster: the tests create and delete resources and replace the
API server's authentication configuration.

`scripts/k3d-up.sh` creates the cluster, as CI does. Give it a fresh disposable directory:

```sh
nix develop
dir=$(mktemp -d)
./scripts/k3d-up.sh "$dir"
export KUBECONFIG="$dir/kubeconfig"
kubectl get nodes                         # Ready
cargo nextest run --locked --run-ignored only -E 'binary(kubernetes)'
```

The script's header says what it sets up: the API server reads its authentication configuration
from `$dir/authn/authn.yaml`, which starts with no issuer, and the kubeconfig stays in `$dir`.

Build and import the image, then run the end-to-end scenario against the same cluster:

```sh
./scripts/build-image.sh zeabur-identity:e2e
k3d image import zeabur-identity:e2e --cluster zeabur-identity
ZEABUR_IDENTITY_E2E_IMAGE=zeabur-identity:e2e \
ZEABUR_IDENTITY_E2E_AUTHN_DIR="$dir/authn" \
ZEABUR_IDENTITY_E2E_MEASUREMENTS="$dir/measurements.json" \
  cargo nextest run --locked --run-ignored only -E 'binary(e2e)'
```

The scenario installs Zeabur Identity, enrols a software passkey, signs in, and checks
`kubectl auth whoami`, the admin account's rights across a refresh and the pod's memory. See the
[zeabur-identity-e2e README](crates/zeabur-identity-e2e/README.md) for its assertions and reload timing.

When finished:

```sh
k3d cluster delete zeabur-identity
```

The temporary directory holds the authentication configuration and optional measurements;
remove it when you no longer need those results.
