#!/usr/bin/env bash
# k3s with cert-manager, whose kube-apiserver reads its AuthenticationConfiguration from
# $work/authn so that the end-to-end test can install Zeabur Identity's (and remove it after): the
# integration tests, then passkey sign-in and `kubectl auth whoami`. The cluster `zeabur-identity`
# and its directory (kubeconfig, authentication configuration, measurements) are deleted at the end;
# ZEABUR_CI_KEEP=1 keeps both. K3S_IMAGE picks the k3s release.
# shellcheck source-path=SCRIPTDIR
source "$(dirname "$0")/lib.sh"

k3s_image="${K3S_IMAGE:-rancher/k3s:v1.37.1-k3s1}"
cluster=zeabur-identity
work="$(mktemp -d -p "${RUNNER_TEMP:-${TMPDIR:-/tmp}}" zeabur-identity-ci.XXXXXX)"

# The image size and the pod's memory after a sign-in, from the end-to-end test.
report() {
  local size working_set
  size=$(docker image inspect --format '{{.Size}}' zeabur-identity:e2e 2>/dev/null || echo n/a)
  working_set=$(jq -r .pod_working_set_bytes "$work/measurements.json" 2>/dev/null || echo n/a)
  {
    echo "### Image size and memory ($k3s_image)"
    echo "| Measure | Bytes |"
    echo "|---|---|"
    echo "| Image \`zeabur-identity:e2e\` | $size |"
    echo "| Pod working set after a sign-in | $working_set |"
  } | summary
  keep "$work/measurements.json"
}

end() {
  local status=$?
  report || true
  if [[ -z "${ZEABUR_CI_KEEP:-}" ]]; then
    k3d cluster delete "$cluster" >/dev/null 2>&1 || true
    rm -rf "$work" || true
  else
    echo "kept: k3d cluster $cluster, KUBECONFIG=$work/kubeconfig" >&2
  fi
  exit "$status"
}

k3d cluster delete "$cluster" >/dev/null 2>&1 || true
trap end EXIT
CLUSTER="$cluster" K3S_IMAGE="$k3s_image" ./scripts/k3d-up.sh "$work"
export KUBECONFIG="$work/kubeconfig"
cargo nextest run --locked --run-ignored only -E 'binary(kubernetes)'
./scripts/build-image.sh zeabur-identity:e2e
k3d image import zeabur-identity:e2e --cluster "$cluster"
ZEABUR_IDENTITY_E2E_IMAGE=zeabur-identity:e2e \
  ZEABUR_IDENTITY_E2E_AUTHN_DIR="$work/authn" \
  ZEABUR_IDENTITY_E2E_MEASUREMENTS="$work/measurements.json" \
  cargo nextest run --locked --run-ignored only -E 'binary(e2e)'
