# shellcheck shell=bash
# Sourced by the scripts: `cargo` goes through kache when the shell has it.
cargo() {
  if command -v kache >/dev/null; then
    kache cargo -- "$@"
  else
    command cargo "$@"
  fi
}

# Loads images into every node of the k3d cluster $1; the other arguments go to
# `docker image save`. Not `k3d image import`: k3d 5.9.0 can take a `ctr` exec that has not
# started for one that exited 0, delete the tarball and report success. `docker exec` returns
# ctr's exit status.
k3d_import() {
  local cluster=$1 nodes node
  shift
  nodes=$(for role in server agent; do
    docker ps --filter "label=k3d.cluster=$cluster" --filter "label=k3d.role=$role" --format '{{.Names}}'
  done)
  [[ -n $nodes ]] || { echo "k3d cluster $cluster has no nodes" >&2; return 1; }
  for node in $nodes; do
    docker image save "$@" | docker exec -i "$node" ctr image import --all-platforms -
  done
}

# Prints the pods in namespace $1 with a container that is not ready, or with no container yet.
pods_not_ready() {
  kubectl -n "$1" get pods -o json |
    jq -r '.items[] | select((.status.containerStatuses // []) | length == 0 or any(.[]; .ready | not)) | .metadata.name'
}
