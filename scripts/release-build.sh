#!/usr/bin/env bash
# The files of a release for this machine's architecture, in <dist>: the zeabur-identityctl archive
# and its SBOM, the image as image.tar and its SBOM. Then release-smoke.sh runs that archive and
# image on a disposable k3s. Native Linux amd64 or arm64 in `nix develop`, with Docker 28 or later.
# Release binaries are always compiled, never taken from a compiler cache.
#
#   scripts/release-build.sh <version> <dist>
set -euo pipefail

usage="usage: scripts/release-build.sh <version> <dist>"
version=${1:?$usage}
mkdir -p "${2:?$usage}"
dist=$(cd "$2" && pwd)
root=$(cd "$(dirname "$0")/.." && pwd)
ca=${ZEABUR_IDENTITY_CA_BUNDLE:?run inside nix develop}
case "$(uname -sm)" in
  "Linux x86_64") arch=amd64 target=x86_64-unknown-linux-musl ;;
  "Linux aarch64") arch=arm64 target=aarch64-unknown-linux-musl ;;
  *) echo "build on native Linux amd64 or arm64" >&2; exit 2 ;;
esac
archive=zeabur-identityctl-$version-linux-$arch.tar.gz
cli_sbom=zeabur-identityctl-$version-linux-$arch.cdx.json
image_sbom=zeabur-identity-$version-linux-$arch.cdx.json
work=$(mktemp -d)
trap 'rm -r "$work"' EXIT

# mkShell sets SOURCE_DATE_EPOCH to 1980; the commit's time replaces it.
SOURCE_DATE_EPOCH=$(git -C "$root" show -s --format=%ct HEAD)
export SOURCE_DATE_EPOCH SYFT_CHECK_FOR_APP_UPDATE=false
unset RUSTC_WRAPPER
release=${CARGO_TARGET_DIR:-$root/target}/$target/release

"$root/scripts/build-ui.sh"
# Embedded cargo-auditable metadata lets Syft inventory dependencies in the shipped binaries.
ZEABUR_IDENTITY_UI_DIST=$root/ui/dist cargo auditable build --release --locked --target "$target" \
  --manifest-path "$root/Cargo.toml" -p zeabur-identityctl -p zeabur-identity
for binary in zeabur-identityctl zeabur-identity; do
  if readelf --program-headers --dynamic "$release/$binary" | rg -q 'INTERP|\(NEEDED\)'; then
    echo "$binary is not a fully static executable" >&2
    exit 1
  fi
done

# <file>: a CycloneDX document with Cargo components.
cargo_components() {
  jq -e '.bomFormat == "CycloneDX" and any(.components[]?; .purl // "" | startswith("pkg:cargo/"))' \
    "$1" >/dev/null || { echo "$1 is not a CycloneDX document with Cargo components" >&2; exit 1; }
}

install -D -m 0755 "$release/zeabur-identityctl" "$work/cli/zeabur-identityctl"
tar --format=ustar --sort=name --mtime="@$SOURCE_DATE_EPOCH" --owner=0 --group=0 --numeric-owner \
  --mode=0755 -C "$work/cli" -cf - zeabur-identityctl | gzip -n -9 >"$dist/$archive"
# Scan the exact file packaged above, not Cargo manifests or a fresh build.
syft scan "file:$work/cli/zeabur-identityctl" --output "cyclonedx-json=$dist/$cli_sbom"
cargo_components "$dist/$cli_sbom"

# The same staged tree as build-image.sh: directories 0755, so the non-root user can traverse them.
stage=$work/image
install -d -m 0755 "$stage/etc" "$stage/etc/ssl" "$stage/etc/ssl/certs"
install -m 0555 "$release/zeabur-identity" "$stage/zeabur-identity"
install -m 0444 "$ca" "$stage/etc/ssl/certs/ca-certificates.crt"
find "$stage" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +
image=zeabur-identity:release-$arch
docker build --platform "linux/$arch" --network none --build-arg "SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH" \
  --file "$root/Containerfile" --tag "$image" "$stage"
docker image save --output "$dist/image.tar" "$image"

# A scratch image has no distro package database to own the CA bundle. Capture all file digests
# in Syft, then record that bundle as a CycloneDX file component.
bundle=/etc/ssl/certs/ca-certificates.crt
SYFT_FILE_METADATA_SELECTION=all SYFT_FILE_METADATA_DIGESTS=sha256 syft scan "docker-archive:$dist/image.tar" \
  --output "syft-json=$work/image.syft.json" --output "cyclonedx-json=$work/image.cdx.json"
sha=$(jq -r --arg bundle "$bundle" \
  '[.files[] | select(.location.path == $bundle) | .digests[] | select(.algorithm == "sha256") | .value]
   | unique | if length == 1 then .[0] else error("missing or ambiguous CA bundle digest in the image") end' \
  "$work/image.syft.json")
jq --arg bundle "$bundle" --arg sha "$sha" --arg ca "$ca" \
  '.components = (.components // []) + [{type: "file", "bom-ref": "file:\($bundle)", name: $bundle,
     hashes: [{alg: "SHA-256", content: $sha}],
     properties: [{name: "zeabur-identity:nix-source", value: $ca}]}]' \
  "$work/image.cdx.json" >"$dist/$image_sbom"
cargo_components "$dist/$image_sbom"
echo "Built $dist/$archive and $image (not published)."

"$root/scripts/release-smoke.sh" "$dist/$archive" "$image"
