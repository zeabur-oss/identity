#!/usr/bin/env bash
# Creates a disposable k3d cluster with cert-manager for the cluster and end-to-end tests.
# kube-apiserver reads its
# AuthenticationConfiguration from <dir>/authn/authn.yaml, which starts with no issuer; the
# end-to-end test replaces it (ZEABUR_IDENTITY_E2E_AUTHN_DIR=<dir>/authn). The kubeconfig goes to
# <dir>/kubeconfig, never into the default one. Run inside `nix develop` on Linux with Docker.
#   scripts/k3d-up.sh <dir> [k3d cluster create arguments...]
#   export KUBECONFIG=<dir>/kubeconfig
#
# CLUSTER names the cluster (default zeabur-identity); K3S_IMAGE picks the k3s release.
# ZEABUR_REGISTRY_MIRRORS (`docker.io=http://mirror:5001,ghcr.io=...`) makes the node pull
# through those mirrors. Delete the cluster with `k3d cluster delete <name>`.
set -euo pipefail

dir="${1:?usage: k3d-up.sh <dir> [k3d cluster create arguments...]}"
shift
mkdir -p "$dir/authn"
dir="$(cd "$dir" && pwd)"
cluster="${CLUSTER:-zeabur-identity}"

# Runs one wait; when it times out, says which one and shows why, since the cluster is gone by
# the time anyone reads the CI log. wait_for <namespace> <command...>
wait_for() {
  local ns="$1" pod
  shift
  "$@" && return 0
  echo "error: timed out: $*" >&2
  kubectl -n "$ns" get pods -o wide >&2 || true
  kubectl -n "$ns" get events --sort-by=.lastTimestamp >&2 || true
  for pod in $(kubectl -n "$ns" get pods --no-headers 2> /dev/null \
    | awk '{ split($2, ready, "/"); if (ready[1] != ready[2]) print $1 }'); do
    kubectl -n "$ns" describe pod "$pod" >&2 || true
    kubectl -n "$ns" logs "$pod" --all-containers --prefix --tail=40 >&2 || true
  done
  exit 1
}

# Mount the directory, not the file: kube-apiserver must see the atomic replacement. The
# `anonymous` section cannot change on a reload.
printf 'apiVersion: apiserver.config.k8s.io/v1\nkind: AuthenticationConfiguration\nanonymous:\n  enabled: false\njwt: []\n' \
  > "$dir/authn/authn.yaml"

args=()
if [[ -n "${ZEABUR_REGISTRY_MIRRORS:-}" ]]; then
  IFS=, read -ra mirrors <<< "$ZEABUR_REGISTRY_MIRRORS"
  {
    echo "mirrors:"
    for mirror in "${mirrors[@]}"; do
      [[ "$mirror" == ?*=?* ]] || { echo "error: ZEABUR_REGISTRY_MIRRORS: want registry=endpoint, got $mirror" >&2; exit 1; }
      printf '  "%s":\n    endpoint: ["%s"]\n' "${mirror%%=*}" "${mirror#*=}"
    done
  } > "$dir/registries.yaml"
  args+=(--registry-config "$dir/registries.yaml")
fi

k3d cluster create "$cluster" --image "${K3S_IMAGE:-rancher/k3s:v1.37.2-k3s1}" --no-lb --wait --timeout 300s \
  --kubeconfig-update-default=false --kubeconfig-switch-context=false "${args[@]}" \
  --volume "$dir/authn:/etc/rancher/k3s/zeabur-identity@server:0" \
  --k3s-arg "--kube-apiserver-arg=authentication-config=/etc/rancher/k3s/zeabur-identity/authn.yaml@server:0" \
  "$@"
k3d kubeconfig get "$cluster" > "$dir/kubeconfig"

# cert-manager issues the internal listener's certificate. The version follows the Zeabur
# Catalog's cert-manager component.
cert_manager_version=v1.21.3
cert_manager_sha256=c04a51295adda2b1a775146751f973e787190778c7f35180861d9678876e5c74
curl -fsSL -o "$dir/cert-manager.yaml" \
  "https://github.com/cert-manager/cert-manager/releases/download/$cert_manager_version/cert-manager.yaml"
echo "$cert_manager_sha256  $dir/cert-manager.yaml" | sha256sum -c --quiet
KUBECONFIG="$dir/kubeconfig" kubectl apply --server-side -f "$dir/cert-manager.yaml" >/dev/null
export KUBECONFIG="$dir/kubeconfig"
wait_for cert-manager kubectl -n cert-manager wait deployment --all \
  --for=condition=Available --timeout=300s
