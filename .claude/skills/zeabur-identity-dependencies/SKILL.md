---
name: zeabur-identity-dependencies
description: Add or upgrade a Rust or frontend dependency in Zeabur Identity under its supply-chain policy (OSI licences, aws-lc-rs only, publish-age delay, unsafe/native review). Use whenever Cargo.toml, Cargo.lock, flake.nix, ui/package.json or ui/bun.lock changes.
---

# Dependencies

Follow `zeabur-oss-dependencies` (install: `npx skills add zeabur-oss/skills --skill
zeabur-oss-dependencies`; `skills-lock.json` pins it). This skill adds what is Zeabur
Identity's own.

## Rust
- The unsafe report is `./scripts/ci.sh unsafe-report`. Only normal and build dependencies of
  `zeabur-identity` and `zeabur-identityctl` count.

## Frontend (`ui/`)
- The sign-in pages use the same toolchain as Zeabur's `web/`, at the same versions: TypeScript,
  Tailwind CSS (CLI), oxlint, oxfmt and fallow. Move a version here when web moves it, fallow
  included. Only bun and brotli come from `flake.nix`. Only the built assets ship; the packages
  are build-time only.
- Add with `bun add -d <pkg>` from `ui/`. `bunfig.toml` also skips peer dependencies: the design
  system's React peers are not installed.
- `bun pm untrusted` lists `@parcel/watcher`, through the Tailwind CLI, whose prebuilt binary is
  used.
- `@zeabur/design-system` is a Git dependency pinned to a commit
  (`github:zeabur-oss/design-system#<commit>`).
- Renovate (`renovate.json`) updates `ui/` on web's schedule and with web's grouping.
