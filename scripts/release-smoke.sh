#!/usr/bin/env bash
# Run inside pinned `nix develop` on native Linux with Docker 28+ (API 1.48+).
# Requires k3d, kubectl, curl and jq. Creates/deletes its own disposable k3s cluster;
# downloads k3s (scripts/k3d-up.sh) and k3d's helper image if absent. Never rebuilds.
set -euo pipefail

if [[ $# != 2 ]]; then
  echo "usage: release-smoke.sh <zeabur-identityctl-archive> <image-ref>" >&2
  exit 2
fi
: "${IN_NIX_SHELL:?run inside nix develop}"
if [[ "$(uname -s)" != Linux ]]; then
  echo "release smoke requires native Linux and Docker" >&2
  exit 2
fi
case "$(uname -m)" in
  x86_64) arch=amd64 ;;
  aarch64 | arm64) arch=arm64 ;;
  *) echo "release smoke supports only Linux amd64 and arm64" >&2; exit 2 ;;
esac
archive="$1"
image="$2"
work="$(mktemp -d)"
cluster="identity-smoke-${work##*.}"
cluster="${cluster,,}"
local_image="zeabur-identity:smoke-${cluster#identity-smoke-}"
namespace=zeabur-identity-release-smoke
issuer=https://release-smoke.zeabur-identity.invalid
cluster_started=false
image_tagged=false
forward_pid=
export KUBECONFIG="$work/kubeconfig"

cleanup() {
  status=$?
  trap - EXIT
  if [[ -n "$forward_pid" ]]; then
    kill "$forward_pid" 2> /dev/null || true
    wait "$forward_pid" 2> /dev/null || true
  fi
  if [[ "$status" != 0 && -s "$KUBECONFIG" ]]; then
    kubectl --request-timeout=10s -n "$namespace" get pods -o wide >&2 || true
    kubectl --request-timeout=10s -n "$namespace" describe deployment zeabur-identity >&2 || true
    kubectl --request-timeout=10s -n "$namespace" logs deployment/zeabur-identity --all-containers --tail=100 >&2 || true
    kubectl --request-timeout=10s -n "$namespace" get events --sort-by=.lastTimestamp >&2 || true
    if [[ -f "$work/port-forward.log" ]]; then
      cat "$work/port-forward.log" >&2
    fi
  fi
  if [[ "$cluster_started" == true ]]; then
    k3d cluster delete "$cluster" >&2 || true
  fi
  if [[ "$image_tagged" == true ]]; then
    docker image rm "$local_image" > /dev/null || true
  fi
  rm -rf "$work"
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# A single regular executable is the complete CLI archive contract. Streaming the
# file out avoids honoring archive ownership, links or other extraction metadata.
if [[ "$(tar -tzf "$archive")" != zeabur-identityctl ]]; then
  echo "expected archive containing only zeabur-identityctl" >&2
  exit 1
fi
tar -xOzf "$archive" zeabur-identityctl > "$work/zeabur-identityctl"
chmod 0755 "$work/zeabur-identityctl"
# These commands do not consult kubeconfig, so they also check useful offline CLI behavior.
"$work/zeabur-identityctl" crds > "$work/crds.json"
"$work/zeabur-identityctl" rbac --namespace "$namespace" > "$work/rbac.json"
jq -e '.apiVersion == "v1" and .kind == "List" and (.items | length > 0)
  and all(.items[]; .kind == "CustomResourceDefinition" and .spec.group == "identity.zeabur.com")' \
  "$work/crds.json" > /dev/null
jq -e --arg namespace "$namespace" '.apiVersion == "v1" and .kind == "List"
  and any(.items[]; .kind == "Namespace" and .metadata.name == $namespace)
  and any(.items[]; .kind == "RoleBinding" and .metadata.namespace == $namespace)
  and any(.items[]; .kind == "Secret" and .metadata.name == "zeabur-identity-signing-keys")' \
  "$work/rbac.json" > /dev/null

# Pin the local snapshot by image ID before importing. Retagging changes no bytes,
# and imagePullPolicy=Never below prevents a registry from replacing the candidate.
if ! docker image inspect "$image" > /dev/null 2>&1; then
  docker pull "$image"
fi
image_id="$(docker image inspect --format '{{.Id}}' "$image")"
platform="$(docker image inspect --format '{{.Os}}/{{.Architecture}}' "$image_id")"
if [[ "$platform" != "linux/$arch" ]]; then
  echo "candidate image platform $platform does not match native linux/$arch" >&2
  exit 1
fi
docker tag "$image_id" "$local_image"
image_tagged=true
# A registry pull can retain a multi-platform index with only native content.
# Export only that platform so containerd does not require absent sibling manifests.
docker image save --platform "linux/$arch" --output "$work/image.tar" "$local_image"
# k3d-up.sh writes the kubeconfig to $work, never to the caller's.
cluster_started=true
CLUSTER="$cluster" "$(dirname "$0")/k3d-up.sh" "$work" \
  --k3s-arg '--disable=traefik@server:0' --k3s-arg '--disable=servicelb@server:0'
k3d image import "$work/image.tar" --cluster "$cluster"
kubectl apply -f "$work/crds.json"
kubectl wait --for=condition=Established --timeout=90s -f "$work/crds.json"
kubectl apply -f "$work/rbac.json"
# Exercise the archived install command as well as the production hardened Deployment:
# real service account, namespace RBAC, read-only root, non-root UID and seccomp.
"$work/zeabur-identityctl" manifests --issuer "$issuer" --namespace "$namespace" --image "$local_image" \
  | jq '(.items[] | select(.kind == "Deployment") | .spec.template.spec.containers[]).imagePullPolicy = "Never"' \
  > "$work/manifests.json"
# RBAC includes the initially empty signing-key Secret: do not reapply it after startup.
kubectl apply -f "$work/manifests.json"
kubectl -n "$namespace" rollout status deployment/zeabur-identity --timeout=180s
kubectl -n "$namespace" get secret zeabur-identity-signing-keys -o json \
  | jq -e '.data | type == "object" and length > 0' > /dev/null

# Let the kernel choose the host port, avoiding collisions across concurrent runs.
# Create the log synchronously: the parent can read it before the background
# process has executed its redirection.
: > "$work/port-forward.log"
kubectl -n "$namespace" port-forward --address 127.0.0.1 service/zeabur-identity :80 \
  > "$work/port-forward.log" 2>&1 &
forward_pid=$!
port=
for ((attempt = 0; attempt < 60; attempt++)); do
  if ! kill -0 "$forward_pid" 2> /dev/null; then
    echo "port-forward exited before becoming ready" >&2
    exit 1
  fi
  while IFS= read -r line; do
    if [[ "$line" =~ Forwarding\ from\ 127\.0\.0\.1:([0-9]+) ]]; then
      port="${BASH_REMATCH[1]}"
      break
    fi
  done < "$work/port-forward.log"
  if [[ -n "$port" ]]; then
    break
  fi
  sleep 1
done
if [[ -z "$port" ]]; then
  echo "timed out waiting for port-forward" >&2
  exit 1
fi
base="http://127.0.0.1:$port"
curl --fail --silent --show-error --max-time 10 "$base/healthz" > /dev/null
curl --fail --silent --show-error --max-time 10 "$base/readyz" > /dev/null
curl --fail --silent --show-error --max-time 10 "$base/.well-known/openid-configuration" \
  > "$work/discovery.json"
jq -e --arg issuer "$issuer" '.issuer == $issuer and (.jwks_uri | startswith($issuer + "/"))
  and (.token_endpoint | startswith($issuer + "/"))' "$work/discovery.json" > /dev/null
jwks_path="$(jq -er --arg issuer "$issuer" '.jwks_uri | ltrimstr($issuer)' "$work/discovery.json")"
curl --fail --silent --show-error --max-time 10 "$base$jwks_path" \
  | jq -e '(.keys | length > 0) and all(.keys[]; (.kid | length > 0)
    and (.kty == "EC" or .kty == "RSA") and (has("d") | not))' > /dev/null
printf 'Smoked archived CLI and Kubernetes-backed image %s (%s).\n' "$image" "$image_id"
