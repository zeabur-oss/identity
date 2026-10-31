#!/usr/bin/env bash
# One CI job, as .github/workflows/ci.yml runs it (through zeabur-oss/.github's shared CI workflow)
# and as anyone runs it locally. The workflow only checks out, installs Nix and restores caches,
# then calls this script, so a job behaves the same on GitHub and on any Linux machine with Nix
# (and Docker, for the kubernetes job).
#
#   scripts/ci.sh --list     # the job names, without the dev shell
#   scripts/ci.sh <job>      # run one job; it enters the Nix dev shell itself
#
# A job may leave files in $CI_ARTIFACTS; CI uploads them as the artifact `ci-<job>`.
#
# The kubernetes job creates the k3d cluster `zeabur-identity` in a temporary directory of its own
# (kubeconfig, authentication configuration, measurements) and deletes it when it ends; set
# ZEABUR_CI_KEEP=1 to keep both. K3S_IMAGE picks the k3s release.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"

jobs=(format clippy docs test cargo-deny unsafe-report ui kubernetes)

if [[ "${1:-}" == --list ]]; then
  printf '%s\n' "${jobs[@]}"
  exit 0
fi
job="${1:?usage: scripts/ci.sh <job> | --list}"
printf '%s\n' "${jobs[@]}" | grep -qxF -- "$job" ||
  { echo "error: no job named $job (scripts/ci.sh --list)" >&2; exit 1; }

# The marker tells a re-run inside the dev shell apart from a call outside it.
if [[ -z "${ZEABUR_CI_SHELL:-}" ]]; then
  export ZEABUR_CI_SHELL=1
  exec nix develop "$root" --command "$0" "$@"
fi

export RUSTDOCFLAGS="-D warnings"
k3s_image="${K3S_IMAGE:-rancher/k3s:v1.36.5-k3s1}"
cluster=zeabur-identity

# The image size and the pod's memory after a sign-in, from the end-to-end test.
kubernetes_report() {
  local size working_set
  size=$(docker image inspect --format '{{.Size}}' zeabur-identity:e2e 2>/dev/null || echo n/a)
  working_set=$(jq -r .pod_working_set_bytes "$work/measurements.json" 2>/dev/null || echo n/a)
  {
    echo "### Image size and memory ($k3s_image)"
    echo "| Measure | Bytes |"
    echo "|---|---|"
    echo "| Image \`zeabur-identity:e2e\` | $size |"
    echo "| Pod working set after a sign-in | $working_set |"
  } | tee -a "${GITHUB_STEP_SUMMARY:-/dev/null}"
  if [[ -n "${CI_ARTIFACTS:-}" && -f "$work/measurements.json" ]]; then
    mkdir -p "$CI_ARTIFACTS"
    cp "$work/measurements.json" "$CI_ARTIFACTS/"
  fi
}

kubernetes_end() {
  local status=$?
  kubernetes_report || true
  if [[ -z "${ZEABUR_CI_KEEP:-}" ]]; then
    k3d cluster delete "$cluster" >/dev/null 2>&1 || true
    rm -rf "$work" || true
  else
    echo "kept: k3d cluster $cluster, KUBECONFIG=$work/kubeconfig" >&2
  fi
  exit "$status"
}

case "$job" in
  format)
    cargo fmt --all --check
    nixfmt --check flake.nix
    shellcheck scripts/*.sh
    actionlint
    bun install --frozen-lockfile
    bun fmt --check scripts/release.ts
    bun check scripts/
    ;;
  clippy) cargo lint ;;
  docs) cargo doc --workspace --no-deps --document-private-items --locked ;;
  test) cargo nextest run --workspace --all-features --locked --no-tests=warn ;;
  cargo-deny) cargo deny --locked check ;;
  unsafe-report)
    bun install --frozen-lockfile
    status=0
    node_modules/.bin/zeabur-oss-unsafe-report zeabur-identity zeabur-identityctl || status=$?
    if [[ -n "${CI_ARTIFACTS:-}" && -f target/unsafe-report.md ]]; then
      mkdir -p "$CI_ARTIFACTS"
      cp target/unsafe-report.md "$CI_ARTIFACTS/"
    fi
    exit "$status"
    ;;
  # Sign-in pages: format, lint and typecheck; the committed assets and design-system classes must
  # match the sources; budgets and contrast. fallow: unused code and boundaries, then new findings
  # against HEAD^ (CI fetches two commits; on a pull request, HEAD^ is the base branch); health
  # does not fail the job.
  ui)
    (cd ui && bun ci && bun run fmt:check && bun run lint && bun run typecheck)
    ./scripts/build-ui.sh
    git diff --exit-code -- crates/zeabur-identity-ui/assets crates/zeabur-identity-ui/templates/ds.html
    ./scripts/ui-budget.sh
    python3 .claude/skills/zeabur-identity-ui/contrast.py
    (cd ui && bun run fallow dead-code --baseline fallow-baseline.json &&
      bun run fallow audit --base HEAD^ && bun run fallow health --report-only)
    ;;
  # k3s with cert-manager, whose kube-apiserver reads its AuthenticationConfiguration from
  # $work/authn so that the end-to-end test can install Zeabur Identity's (and remove it after).
  kubernetes)
    work="$(mktemp -d -p "${RUNNER_TEMP:-${TMPDIR:-/tmp}}" zeabur-identity-ci.XXXXXX)"
    k3d cluster delete "$cluster" >/dev/null 2>&1 || true
    trap kubernetes_end EXIT
    CLUSTER="$cluster" K3S_IMAGE="$k3s_image" ./scripts/k3d-up.sh "$work"
    export KUBECONFIG="$work/kubeconfig"
    cargo nextest run --locked --run-ignored only -E 'binary(kubernetes)'
    ./scripts/build-image.sh zeabur-identity:e2e
    k3d image import zeabur-identity:e2e --cluster "$cluster"
    # Passkey sign-in and `kubectl auth whoami`.
    ZEABUR_IDENTITY_E2E_IMAGE=zeabur-identity:e2e \
      ZEABUR_IDENTITY_E2E_AUTHN_DIR="$work/authn" \
      ZEABUR_IDENTITY_E2E_MEASUREMENTS="$work/measurements.json" \
      cargo nextest run --locked --run-ignored only -E 'binary(e2e)'
    ;;
esac
