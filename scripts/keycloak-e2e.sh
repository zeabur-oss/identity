#!/usr/bin/env bash
# Signs in to Zeabur Identity through Keycloak, an OpenID provider with its own CA: the scenario in
# crates/zeabur-identity-e2e/tests/e2e.rs (`keycloak_links_signs_in_and_unlinks`). Creates a k3d
# cluster, builds and imports the image, and runs Keycloak in Docker on the cluster's network with
# the realm in crates/zeabur-identity-e2e/keycloak/realm.json. Pods reach it as host.k3d.internal,
# which k3d puts in the cluster DNS; the test reaches it on 127.0.0.1. The cluster, the container
# and the temporary directory are deleted at the end; ZEABUR_CI_KEEP=1 keeps them.
# Run inside `nix develop` on Linux with Docker. Not part of CI: it pulls the Keycloak image.
set -euo pipefail
cd "$(dirname "$0")/.."

keycloak_image="${KEYCLOAK_IMAGE:-quay.io/keycloak/keycloak:26.2.5}"
cluster=zeabur-identity-keycloak
container=zeabur-identity-keycloak
host=host.k3d.internal
port=8443
work="$(mktemp -d -p "${TMPDIR:-/tmp}" zeabur-identity-keycloak.XXXXXX)"

end() {
  local status=$?
  if [[ -z "${ZEABUR_CI_KEEP:-}" ]]; then
    docker rm -f "$container" > /dev/null 2>&1 || true
    k3d cluster delete "$cluster" > /dev/null 2>&1 || true
    rm -rf "$work" || true
  else
    echo "kept: k3d cluster $cluster, container $container, KUBECONFIG=$work/kubeconfig" >&2
  fi
  exit "$status"
}

docker rm -f "$container" > /dev/null 2>&1 || true
k3d cluster delete "$cluster" > /dev/null 2>&1 || true
trap end EXIT

# A CA of its own and a certificate for host.k3d.internal, so Zeabur Identity must be told to trust
# it, as with a provider inside a company network.
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 \
  -subj "/CN=Zeabur Identity e2e Keycloak CA" -keyout "$work/ca.key" -out "$work/ca.crt" 2> /dev/null
# Keycloak runs as UID 1000, so its certificate and key go in a directory of their own that any
# user can read; the CA key stays in the private $work.
certs="$work/certs"
mkdir -m 0755 "$certs"
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -subj "/CN=$host" -keyout "$certs/tls.key" -out "$work/tls.csr" 2> /dev/null
openssl x509 -req -in "$work/tls.csr" -CA "$work/ca.crt" -CAkey "$work/ca.key" -CAcreateserial \
  -days 1 -extfile <(printf 'subjectAltName=DNS:%s\nextendedKeyUsage=serverAuth\n' "$host") \
  -out "$certs/tls.crt" 2> /dev/null
chmod 0644 "$certs/tls.key" "$certs/tls.crt"

CLUSTER="$cluster" ./scripts/k3d-up.sh "$work"
export KUBECONFIG="$work/kubeconfig"
./scripts/build-image.sh zeabur-identity:e2e
k3d image import zeabur-identity:e2e --cluster "$cluster"

docker run -d --name "$container" --network "k3d-$cluster" -p "$port:$port" \
  -v "$certs:/opt/keycloak/conf/certs:ro" \
  -v "$PWD/crates/zeabur-identity-e2e/keycloak:/opt/keycloak/data/import:ro" \
  "$keycloak_image" start-dev --import-realm --http-enabled=false --https-port="$port" \
  --hostname="https://$host:$port" \
  --https-certificate-file=/opt/keycloak/conf/certs/tls.crt \
  --https-certificate-key-file=/opt/keycloak/conf/certs/tls.key > /dev/null
for _ in $(seq 1 90); do
  if curl -fsS --cacert "$work/ca.crt" --resolve "$host:$port:127.0.0.1" \
    "https://$host:$port/realms/zeabur/.well-known/openid-configuration" > /dev/null 2>&1; then
    break
  fi
  sleep 2
done
curl -fsS --cacert "$work/ca.crt" --resolve "$host:$port:127.0.0.1" \
  "https://$host:$port/realms/zeabur/.well-known/openid-configuration" > /dev/null

ZEABUR_IDENTITY_E2E_IMAGE=zeabur-identity:e2e \
  ZEABUR_IDENTITY_E2E_KEYCLOAK_ISSUER="https://$host:$port/realms/zeabur" \
  ZEABUR_IDENTITY_E2E_KEYCLOAK_ADDRESS="127.0.0.1:$port" \
  ZEABUR_IDENTITY_E2E_KEYCLOAK_CA="$work/ca.crt" \
  cargo nextest run --locked --run-ignored only --no-capture \
  -E 'binary(e2e) and test(keycloak_links_signs_in_and_unlinks)'
