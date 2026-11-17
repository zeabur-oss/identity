#!/usr/bin/env bash
# What a user does with a draft's files in <downloaded>, after verify-assets has checked SHA256SUMS
# and each asset's provenance: the image is the signed index of the recorded platform images, its
# SBOM attestation is this platform's, and the archive and image run on a disposable k3s. Native
# Linux amd64 or arm64 in `nix develop`, after `bun install`, with Docker 28 or later.
#
#   scripts/release-verify.sh <version> <downloaded>
#
# RELEASE_SOURCE_REPOSITORY (zeabur-oss/identity) and RELEASE_SOURCE_REF (refs/tags/<version>)
# name the signer.
set -euo pipefail

usage="usage: scripts/release-verify.sh <version> <downloaded>"
version=${1:?$usage}
downloaded=$(cd "${2:?$usage}" && pwd)
root=$(cd "$(dirname "$0")/.." && pwd)
case "$(uname -sm)" in
  "Linux x86_64") arch=amd64 ;;
  "Linux aarch64") arch=arm64 ;;
  *) echo "verify on native Linux amd64 or arm64" >&2; exit 2 ;;
esac
repository=${RELEASE_SOURCE_REPOSITORY:-zeabur-oss/identity}
ref=${RELEASE_SOURCE_REF:-refs/tags/$version}
work=$(mktemp -d)
trap 'rm -r "$work"' EXIT
# A fresh, empty registry login: a publisher's login must not hide a private package.
export DOCKER_CONFIG=$work/docker
mkdir "$DOCKER_CONFIG"

index=$(bun x zeabur-oss-release verify-image --digests "$downloaded/digests.txt" linux/amd64 linux/arm64 |
  tail -n 1)

# --type checks the in-toto predicate type, and claim checking binds its subject to the image.
cosign verify-attestation --type cyclonedx \
  --certificate-identity-regexp "^https://github\.com/${repository//./\\.}/\.github/workflows/release\.yml@" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-github-workflow-repository "$repository" --certificate-github-workflow-ref "$ref" \
  "$index" >"$work/attestations.jsonl"
# An actual CycloneDX document inside the verified envelope, this platform's, not only its label.
# jq compares values, so the key order cosign gives the predicate does not matter.
sbom=zeabur-identity-$version-linux-$arch.cdx.json
jq -s -e --slurpfile expected "$downloaded/$sbom" '
  map(.payload | @base64d | fromjson) as $statements
  | ($statements | length > 0)
    and all($statements[]; .predicateType == "https://cyclonedx.org/bom"
      and .predicate.bomFormat == "CycloneDX"
      and (.predicate.specVersion | test("^[0-9]+[.][0-9]+$"))
      and (.predicate.version | type == "number" and . >= 1 and floor == .)
      and (.predicate.components | type == "array"))
    and any($statements[]; .predicate == $expected[0])' "$work/attestations.jsonl" >/dev/null ||
  { echo "$index has no valid CycloneDX attestation of $sbom" >&2; exit 1; }

docker pull --platform "linux/$arch" "$index"
"$root/scripts/release-smoke.sh" "$downloaded/zeabur-identityctl-$version-linux-$arch.tar.gz" "$index"
echo "release $version verified on linux/$arch"
