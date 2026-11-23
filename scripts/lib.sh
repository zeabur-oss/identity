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
  nodes=$(docker ps --filter "label=k3d.cluster=$cluster" --format '{{.Label "k3d.role"}} {{.Names}}' |
    awk '$1 == "server" || $1 == "agent" { print $2 }')
  [[ -n $nodes ]] || { echo "k3d cluster $cluster has no nodes" >&2; return 1; }
  for node in $nodes; do
    docker image save "$@" | docker exec -i "$node" ctr image import --all-platforms -
  done
}
