#!/usr/bin/env bash
# The short checks: each needs about a minute to set up a runner and its dev shell but much less
# to run. `lint.sh` runs both groups one after another; CI runs them side by side. The cargo group
# stays in one process because its steps share the target/ lock.
set -euo pipefail
cd "$(dirname "$0")/../.."
source scripts/lib.sh

static() {
  cargo fmt --all --check
  nixfmt --check flake.nix
  shellcheck scripts/*.sh scripts/ci/*.sh
  ./scripts/ci/patterns.sh
  jactionlint
  helm lint --strict deploy/chart/identity --set global.domain=203.0.113.1.sslip.io
  # helm lint lets a failed `required` pass; template fails on it.
  helm template deploy/chart/identity --set issuer=https://identity.example.com >/dev/null
}

cargo_checks() {
  cargo lint
  RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --document-private-items --locked
  cargo deny --locked check
  bun install --frozen-lockfile
  # Writes target/unsafe-report.md, which the workflow uploads.
  node_modules/.bin/zeabur-oss-unsafe-report zeabur-identity zeabur-identityctl
  node_modules/.bin/zeabur-oss-levels
}

case "${1:-all}" in
  static) static ;;
  cargo) cargo_checks ;;
  all) static; cargo_checks ;;
  *) echo "usage: lint.sh [static|cargo]" >&2; exit 2 ;;
esac
