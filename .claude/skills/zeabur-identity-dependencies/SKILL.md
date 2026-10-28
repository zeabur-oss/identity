---
name: zeabur-identity-dependencies
description: Add or upgrade a Rust or frontend dependency in Zeabur Identity under its supply-chain policy (OSI licences, aws-lc-rs only, publish-age delay, unsafe/native review). Use whenever Cargo.toml, Cargo.lock, flake.nix, ui/package.json or ui/bun.lock changes.
---

# Dependencies

## Rust
- **Prefer what is already in the graph.** `cargo tree -i <crate> -e normal` shows whether a
  crate is already compiled in (for example hyper, rustls, url). A small, reviewed in-tree
  implementation can beat a new dependency with `unsafe` code; weigh it explicitly.
- **Add at the workspace level**: version and features in the root
  `[workspace.dependencies]`, `name.workspace = true` in the crate. Disable default features you
  do not need; check that no second crypto backend arrives (`ring`, OpenSSL and `webpki-roots`
  are banned in `deny.toml`).
- **Publish age.** Cargo refuses versions younger than seven days. For an urgent security fix:
  `CARGO_REGISTRY_GLOBAL_MIN_PUBLISH_AGE="0 days" cargo update -p <crate>`.
- **Run** `cargo deny --locked check` and `./scripts/ci.sh unsafe-report`. Every shipped crate that
  contains `unsafe` or builds native code needs an entry in `supply-chain/unsafe-allowlist.toml`:
  `kind`, a concrete `reason` (where the unsafe is, whether it runs only at build time), and
  `approved = "pending"` until a maintainer reviews it and sets the date. Only normal and build
  dependencies of `zeabur-identity` and `zeabur-identityctl` count; dev-dependencies and test crates do not.
- **Advisories** that do not apply need an `ignore` entry in `deny.toml` with the reason.
## Frontend (`ui/`)
- The sign-in pages use the same toolchain as Zeabur's `web/`, at the same versions: TypeScript,
  Tailwind CSS (CLI), oxlint, oxfmt and fallow. Move a version here when web moves it. Only bun and
  brotli come from `flake.nix`. Only the built assets ship; the packages are build-time only.
- Add with `bun add -d <pkg>` inside `nix develop`, from `ui/`. `bunfig.toml` pins exact versions
  and refuses releases younger than seven days (`minimumReleaseAge`). It also skips peer
  dependencies: the design system's React peers are not installed.
- Licences are OSI-approved, as for crates.
- Never add `trustedDependencies`: no package may run install scripts. `bun pm untrusted` lists
  the blocked ones (`@parcel/watcher`, through the Tailwind CLI, whose prebuilt binary is used).
- Commit `package.json` and `bun.lock` together; CI installs with `bun ci`, which fails if they
  disagree.
- `@zeabur/design-system` is a Git dependency pinned to a commit
  (`github:zeabur-oss/design-system#<commit>`), in the same form as web. To try an unpublished
  design-system commit, point it at a local tarball (`file:/…/zeabur-design-system-0.1.0.tgz`,
  see the design system's `design-system-change` skill) and `bun install`; never commit
  `package.json` or `bun.lock` with that path.
- fallow is not in nixpkgs. It runs as `bunx fallow@<version>` from the `fallow` script in
  `package.json`. Its platform packages ship a prebuilt binary (npm provenance) and run no install
  scripts. Bump it to a release at least seven days old, in the script and in `.fallowrc.json`'s
  `$schema`, with web.
- Renovate (`renovate.json`) updates `ui/` on web's schedule and with web's grouping.
