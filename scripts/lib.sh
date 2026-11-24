# shellcheck shell=bash
# Sourced by the scripts: `cargo` goes through kache when the shell has it.
cargo() {
  if command -v kache >/dev/null; then
    kache cargo -- "$@"
  else
    command cargo "$@"
  fi
}

# Pushes the local image $1 to the registry that scripts/k3d-up.sh created with cluster $2, as
# repository and tag $3 (`zeabur-identity:e2e-1a2b3c`), and prints the reference the nodes pull it
# by. The other arguments go to `docker push`. Not `k3d image import`: k3d 5.9.0 can report
# success before ctr has read the tarball. The kubelet pulls from the registry, so a missing
# image is an ImagePullBackOff with a reason.
k3d_push() {
  local image=$1 cluster=$2 ref=$3 registry port
  shift 3
  registry="$cluster-registry"
  port=$(docker port "$registry" 5000/tcp) || return
  port=${port%%$'\n'*}
  port=${port##*:}
  [[ -n $port ]] || { echo "k3d registry $registry has no host port" >&2; return 1; }
  # The callers run this in $(...), where errexit is off: every step returns its own failure.
  docker tag "$image" "localhost:$port/$ref" || return
  docker push --quiet "$@" "localhost:$port/$ref" >&2 || return
  docker image rm "localhost:$port/$ref" >/dev/null
  echo "$registry:5000/$ref"
}

# Prints the pods in namespace $1 with a container that is not ready, or with no container yet.
pods_not_ready() {
  kubectl -n "$1" get pods -o json |
    jq -r '.items[] | select((.status.containerStatuses // []) | length == 0 or any(.[]; .ready | not)) | .metadata.name'
}
