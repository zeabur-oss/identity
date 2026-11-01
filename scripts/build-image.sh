#!/usr/bin/env bash
# Builds Zeabur Identity's container image for this machine's architecture: a static musl binary in an
# otherwise empty image (Containerfile). Run on Linux inside `nix develop`; needs docker.
#   scripts/build-image.sh zeabur-identity:dev
set -euo pipefail

tag="${1:?usage: build-image.sh <tag>}"
root="$(cd "$(dirname "$0")/.." && pwd)"
target="$(uname -m | sed -e 's/^arm64$/aarch64/')-unknown-linux-musl"

"$root/scripts/build-ui.sh"
ZEABUR_IDENTITY_UI_DIST="$root/ui/dist" cargo build --release --locked --target "$target" -p zeabur-identity --manifest-path "$root/Cargo.toml"
context="$root/target/image"
rm -rf "$context"
mkdir -p "$context"
cp "$root/target/$target/release/zeabur-identity" "$context/zeabur-identity"
# Staged as a tree with explicit modes: `COPY --chmod` to a nested path also applies the mode to
# the parent directories it creates, and a 0444 /etc cannot be traversed by the non-root user.
install -d -m 0755 "$context/etc" "$context/etc/ssl" "$context/etc/ssl/certs"
install -m 0444 "${ZEABUR_IDENTITY_CA_BUNDLE:?run inside nix develop}" "$context/etc/ssl/certs/ca-certificates.crt"
docker build --file "$root/Containerfile" --tag "$tag" "$context"
size=$(docker image inspect --format '{{.Size}}' "$tag")
echo "image $tag: $size bytes"
