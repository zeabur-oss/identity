#!/usr/bin/env bash
# The release stages that zeabur-oss/.github's shared release workflow calls, one per job
# (.github/workflows/release.yml). Each enters the Nix dev shell itself: the flake of the current
# directory (the checkout being released), else this script's repository. zeabur-oss-release
# (zeabur-oss/.github, release/) pushes, signs and verifies; this script keeps what is Zeabur
# Identity's own.
#
#   scripts/release.sh check   <version>                            versions and CHANGELOG section
#   scripts/release.sh build   <version> <os> <arch> <dist>         build and smoke one platform
#   scripts/release.sh publish <version> <artifacts> <published>    push by digest, sign, attest SBOMs
#   scripts/release.sh assets  <version> <artifacts> <release>      release assets, SHA256SUMS, notes
#   scripts/release.sh verify  <version> <os> <arch> <downloaded>   check the draft's files and image
#
# <version> is vX.Y.Z. <artifacts> holds candidate-linux-<arch>/ (build) and published/ (publish).
# Only Linux amd64 and arm64 are built, each natively. Release binaries are always compiled, never
# taken from a compiler cache. publish and assets run in GitHub Actions only (they sign with its
# OIDC token); build and verify also run on any Linux machine with Nix and Docker 28 or later.
#
# Signatures name the shared workflow, not this repository's. verify reads the expected signer from
# RELEASE_CERT_IDENTITY_REGEXP, RELEASE_SIGNER_WORKFLOW, RELEASE_SOURCE_REPOSITORY and
# RELEASE_SOURCE_REF; unset, they default to zeabur-oss/.github's release workflow, run for
# zeabur-oss/identity at refs/tags/<version> (zeabur-oss-release and the cosign calls below alike).
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
archs=(amd64 arm64)
oidc_issuer=https://token.actions.githubusercontent.com

usage() {
  sed -n '/^#   scripts/s/^#   //p' "$0" >&2
  exit 2
}

stage="${1:-}"
case "$stage" in
  check) [[ $# == 2 ]] || usage ;;
  build | verify) [[ $# == 5 ]] || usage ;;
  publish | assets) [[ $# == 4 ]] || usage ;;
  *) usage ;;
esac
version="$2"
if [[ ! "$version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "error: $version is not vX.Y.Z" >&2
  exit 2
fi

# The marker tells a re-run inside the dev shell apart from a call outside it.
if [[ -z "${ZEABUR_RELEASE_SHELL:-}" ]]; then
  export ZEABUR_RELEASE_SHELL=1
  flake="$PWD"
  [[ -f "$flake/flake.nix" ]] || flake="$root"
  exec nix develop "$flake" --command "$0" "$@"
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# The one reference digests.txt records for a kind, such as `index` or `linux/amd64`.
recorded() { # <digests.txt> <kind>
  local ref
  ref="$(awk -v kind="$2" '{ ref = $NF; $NF = ""; sub(/ +$/, "") } $0 == kind { print ref }' "$1")"
  [[ "$ref" =~ ^[^[:space:]@]+@sha256:[0-9a-f]{64}$ ]] || { echo "error: $1 has no single $2" >&2; return 1; }
  echo "$ref"
}

native_arch() {
  case "$(uname -s):$(uname -m)" in
    Linux:x86_64) echo amd64 ;;
    Linux:aarch64 | Linux:arm64) echo arm64 ;;
    *) echo "error: releases are built and checked on Linux amd64 or arm64 only" >&2; return 1 ;;
  esac
}

# The platform arguments of build and verify: Linux, and this machine's architecture.
platform() {
  local os="$1" arch="$2"
  if [[ "$os" != linux ]]; then
    echo "error: no $os release; only linux" >&2
    exit 2
  fi
  if [[ "$arch" != "$(native_arch)" ]]; then
    echo "error: $arch must be built and checked on a native $arch machine" >&2
    exit 2
  fi
}

# Every workspace crate (zeabur-identityctl, zeabur-identity...) and ui/package.json carry the
# version, Cargo.lock agrees (--locked), and CHANGELOG.md has its section.
check() {
  local number="${version#v}" wrong
  wrong="$(cargo metadata --locked --no-deps --format-version 1 --manifest-path "$root/Cargo.toml" |
    jq -r --arg v "$number" '.packages[] | select(.version != $v) | "\(.name) \(.version)"')"
  if [[ -n "$wrong" ]]; then
    printf 'error: crates not at %s:\n%s\n' "$number" "$wrong" >&2
    exit 1
  fi
  if ! jq -e --arg v "$number" '.version == $v' "$root/ui/package.json" >/dev/null; then
    echo "error: ui/package.json is not at $number" >&2
    exit 1
  fi
  zeabur-oss-release notes "$root/CHANGELOG.md" "$version" >/dev/null
  echo "$version: crates, Cargo.lock, ui/package.json and CHANGELOG.md agree"
}

# Static musl binaries, the CLI archive and both SBOMs, and the image (as image.tar) in <dist>; then
# release-smoke.sh runs that archive and image on a disposable k3s cluster.
build() {
  local os="$1" arch="$2" output target target_dir
  platform "$os" "$arch"
  mkdir -p "$3"
  output="$(cd "$3" && pwd)"
  : "${ZEABUR_IDENTITY_CA_BUNDLE:?run inside nix develop}"
  # mkShell sets its own epoch: the release's is the commit's.
  SOURCE_DATE_EPOCH="$(git -C "$root" log -1 --format=%ct HEAD)"
  export SOURCE_DATE_EPOCH
  case "$arch" in
    amd64) target=x86_64-unknown-linux-musl ;;
    arm64) target=aarch64-unknown-linux-musl ;;
  esac
  mkdir -p "$work/cli" "$work/image"
  target_dir="${CARGO_TARGET_DIR:-$root/target}"
  mkdir -p "$target_dir"
  target_dir="$(cd "$target_dir" && pwd)"

  # Release binaries are always compiled, never taken from a compiler cache (CONTRIBUTING.md).
  unset RUSTC_WRAPPER

  # Embedded cargo-auditable metadata lets Syft inventory dependencies in shipped binaries,
  # instead of reporting every package in the workspace or Cargo.lock.
  cargo auditable build --release --locked --target "$target" --target-dir "$target_dir" \
    --manifest-path "$root/Cargo.toml" -p zeabur-identityctl -p zeabur-identity
  local binary elf
  for binary in zeabur-identityctl zeabur-identity; do
    elf="$(readelf --program-headers --dynamic "$target_dir/$target/release/$binary")"
    if [[ "$elf" == *INTERP* || "$elf" == *'(NEEDED)'* ]]; then
      echo "error: $binary is not a fully static executable" >&2
      exit 1
    fi
  done
  local archive="$output/zeabur-identityctl-$version-linux-$arch.tar.gz"
  install -m 0755 "$target_dir/$target/release/zeabur-identityctl" "$work/cli/zeabur-identityctl"
  tar --format=ustar --sort=name --mtime="@$SOURCE_DATE_EPOCH" \
    --owner=0 --group=0 --numeric-owner --mode=0755 \
    -C "$work/cli" -cf - zeabur-identityctl | gzip -n -9 >"$archive"

  # Scan the exact file packaged above, not Cargo manifests or a fresh build.
  export SYFT_CHECK_FOR_APP_UPDATE=false
  syft scan "file:$work/cli/zeabur-identityctl" \
    --output "cyclonedx-json=$output/zeabur-identityctl-$version-linux-$arch.cdx.json"
  jq -e '.bomFormat == "CycloneDX" and any(.components[]?; (.purl // "") | startswith("pkg:cargo/"))' \
    "$output/zeabur-identityctl-$version-linux-$arch.cdx.json" >/dev/null

  # The same staged tree as build-image.sh: directories 0755, so the non-root user can traverse them.
  install -m 0555 "$target_dir/$target/release/zeabur-identity" "$work/image/zeabur-identity"
  install -d -m 0755 "$work/image/etc" "$work/image/etc/ssl" "$work/image/etc/ssl/certs"
  install -m 0444 "$ZEABUR_IDENTITY_CA_BUNDLE" "$work/image/etc/ssl/certs/ca-certificates.crt"
  touch -d "@$SOURCE_DATE_EPOCH" "$work/image/zeabur-identity" "$work/image/etc" \
    "$work/image/etc/ssl" "$work/image/etc/ssl/certs" "$work/image/etc/ssl/certs/ca-certificates.crt"
  local image="zeabur-identity:release-$arch"
  docker build --platform "linux/$arch" --network none --build-arg "SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH" \
    --file "$root/Containerfile" --tag "$image" "$work/image"
  docker image save --output "$output/image.tar" "$image"

  # A scratch image has no distro package database to own the CA bundle. Capture all file digests
  # in Syft, then record that bundle as a CycloneDX file component.
  # See https://oss.anchore.com/docs/reference/syft/configuration/ (file.metadata).
  SYFT_FILE_METADATA_SELECTION=all SYFT_FILE_METADATA_DIGESTS=sha256 \
    syft scan "docker-archive:$output/image.tar" \
    --output "syft-json=$work/image.syft.json" \
    --output "cyclonedx-json=$work/image.cdx.json"
  local ca_sha
  ca_sha="$(jq -er '[.files[] | select(.location.path == "/etc/ssl/certs/ca-certificates.crt")
    | .digests[] | select(.algorithm == "sha256") | .value] | unique
    | if length == 1 then .[0] else error("missing or ambiguous CA bundle digest") end' "$work/image.syft.json")"
  jq --arg sha "$ca_sha" --arg source "$ZEABUR_IDENTITY_CA_BUNDLE" '
    .components += [{
      type: "file", "bom-ref": "file:/etc/ssl/certs/ca-certificates.crt",
      name: "/etc/ssl/certs/ca-certificates.crt",
      hashes: [{alg: "SHA-256", content: $sha}],
      properties: [{name: "zeabur-identity:nix-source", value: $source}]
    }]
  ' "$work/image.cdx.json" >"$output/zeabur-identity-$version-linux-$arch.cdx.json"
  jq -e '.bomFormat == "CycloneDX" and any(.components[]?; (.purl // "") | startswith("pkg:cargo/"))' \
    "$output/zeabur-identity-$version-linux-$arch.cdx.json" >/dev/null
  echo "Built $archive and $image (not published)."

  "$root/scripts/release-smoke.sh" "$archive" "$image"
}

# Pushes each platform's smoked image by digest, then the multi-platform index as the tag
# <version> without its v, and signs each (zeabur-oss-release push-image). Then attests the
# CycloneDX SBOMs; the shared workflow adds build provenance for every subject in
# <published>/subjects.json. Never compiles.
publish() {
  local artifacts published
  artifacts="$(cd "$1" && pwd)"
  mkdir -p "$2"
  published="$(cd "$2" && pwd)"
  : "${GITHUB_REPOSITORY:?}" "${GITHUB_ACTOR:?}" "${GH_TOKEN:?}"
  local image="ghcr.io/${GITHUB_REPOSITORY,,}"
  # Refuse overwriting a release (including a previous failed draft). Recovery is manual.
  if gh release view "$version" --repo "$GITHUB_REPOSITORY" >/dev/null 2>&1; then
    echo "error: release $version already exists; inspect it before retrying" >&2
    exit 1
  fi
  local arch dir platforms=()
  for arch in "${archs[@]}"; do
    dir="$artifacts/candidate-linux-$arch"
    [[ -f "$dir/image.tar" && -f "$dir/zeabur-identity-$version-linux-$arch.cdx.json" ]] ||
      { echo "error: $dir has no image.tar or image SBOM" >&2; exit 1; }
    platforms+=("linux/$arch=$dir/image.tar")
  done

  export DOCKER_CONFIG="$work/docker"
  mkdir -p "$DOCKER_CONFIG"
  printf '%s' "$GH_TOKEN" | docker login ghcr.io --username "$GITHUB_ACTOR" --password-stdin
  rm -f "$published/digests.txt" "$published/subjects.json"
  zeabur-oss-release push-image --repository "$image" --tag "${version#v}" --attest-platforms \
    --digests "$published/digests.txt" --subjects "$published/subjects.json" "${platforms[@]}"

  # Each platform image carries its own SBOM; the index carries both.
  local index sbom
  index="$(recorded "$published/digests.txt" index)"
  for arch in "${archs[@]}"; do
    sbom="$artifacts/candidate-linux-$arch/zeabur-identity-$version-linux-$arch.cdx.json"
    cosign attest --yes --type cyclonedx --predicate "$sbom" "$(recorded "$published/digests.txt" "linux/$arch")"
    cosign attest --yes --type cyclonedx --predicate "$sbom" "$index"
  done
  cat "$published/subjects.json" "$published/digests.txt"
}

# The draft release's files: both CLI archives and every SBOM, digests.txt, a provenance summary,
# SHA256SUMS over them and its Sigstore bundle; and the notes, from CHANGELOG.md.
assets() {
  local artifacts release
  artifacts="$(cd "$1" && pwd)"
  mkdir -p "$2/assets"
  release="$(cd "$2" && pwd)"
  : "${GITHUB_REPOSITORY:?}" "${GITHUB_SHA:?}" "${GITHUB_RUN_ID:?}" "${GITHUB_RUN_ATTEMPT:?}"
  local out="$release/assets" arch dir
  for arch in "${archs[@]}"; do
    dir="$artifacts/candidate-linux-$arch"
    cp "$dir/zeabur-identityctl-$version-linux-$arch.tar.gz" \
      "$dir/zeabur-identityctl-$version-linux-$arch.cdx.json" \
      "$dir/zeabur-identity-$version-linux-$arch.cdx.json" "$out/"
  done
  cp "$artifacts/published/digests.txt" "$out/"
  recorded "$out/digests.txt" index >/dev/null
  local server="${GITHUB_SERVER_URL:-https://github.com}"
  jq -n --arg commit "$GITHUB_SHA" --arg repository "$server/$GITHUB_REPOSITORY" --arg version "$version" \
    --arg run "$server/$GITHUB_REPOSITORY/actions/runs/$GITHUB_RUN_ID/attempts/$GITHUB_RUN_ATTEMPT" \
    '{source: $repository, commit: $commit, version: $version, workflowRun: $run,
      build: "Pinned flake.lock; cargo auditable build --release --locked; native Linux musl"}' \
    >"$out/provenance.json"
  zeabur-oss-release checksums "$out"
  zeabur-oss-release notes "$root/CHANGELOG.md" "$version" --docs https://oss.zeabur.com/docs/identity/ \
    >"$release/notes.md"
}

# What a user does with the draft's files: the signed SHA256SUMS covers exactly them, each has build
# provenance, and the image is the signed index of the recorded platform images
# (zeabur-oss-release). Then its SBOM attestation, and the archive and image on a disposable k3s.
verify() {
  local os="$1" arch="$2" directory
  platform "$os" "$arch"
  directory="$(cd "$3" && pwd)"
  local identity_regexp="${RELEASE_CERT_IDENTITY_REGEXP:-^https://github\.com/zeabur-oss/\.github/\.github/workflows/release\.yml@}"
  local repository="${RELEASE_SOURCE_REPOSITORY:-zeabur-oss/identity}"
  local source_ref="${RELEASE_SOURCE_REF:-refs/tags/$version}"
  local certificate=(--certificate-identity-regexp "$identity_regexp" --certificate-oidc-issuer "$oidc_issuer"
    --certificate-github-workflow-repository "$repository" --certificate-github-workflow-ref "$source_ref")
  local release=(--repository zeabur-oss/identity --version "$version")
  local archive="zeabur-identityctl-$version-linux-$arch.tar.gz" assets=(digests.txt provenance.json) a
  for a in "${archs[@]}"; do
    assets+=("zeabur-identityctl-$version-linux-$a.tar.gz" "zeabur-identityctl-$version-linux-$a.cdx.json"
      "zeabur-identity-$version-linux-$a.cdx.json")
  done
  # Do not inherit the publisher's Docker login: this must work for a public consumer.
  export DOCKER_CONFIG="$work/docker"
  mkdir -p "$DOCKER_CONFIG"

  zeabur-oss-release verify-assets "${release[@]}" "$directory" "${assets[@]}"
  zeabur-oss-release verify-image "${release[@]}" --digests "$directory/digests.txt" "${archs[@]/#/linux/}"

  local image
  image="$(recorded "$directory/digests.txt" index)"
  # --type checks the in-toto predicate type, and claim checking binds its subject to the image.
  cosign verify-attestation "${certificate[@]}" --type cyclonedx "$image" >"$work/attestations.json"
  # An actual CycloneDX document inside the verified envelope, this platform's, not only its label.
  jq --slurp --exit-status --slurpfile expected "$directory/zeabur-identity-$version-linux-$arch.cdx.json" '
    length > 0 and any(.[]; (.payload | @base64d | fromjson).predicate == $expected[0]) and all(.[];
      (.payload | @base64d | fromjson) as $statement |
      $statement.predicateType == "https://cyclonedx.org/bom" and
      $statement.predicate.bomFormat == "CycloneDX" and
      ($statement.predicate.specVersion | type == "string" and test("^[0-9]+[.][0-9]+$")) and
      ($statement.predicate.version | type == "number" and . >= 1 and floor == .) and
      ($statement.predicate.components | type == "array")
    )
  ' "$work/attestations.json" >/dev/null

  docker pull --platform "linux/$arch" "$image"
  "$root/scripts/release-smoke.sh" "$directory/$archive" "$image"
}

shift 2
"$stage" "$@"
