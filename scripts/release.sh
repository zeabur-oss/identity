#!/usr/bin/env bash
# The release stages that zeabur-oss/.github's shared release workflow calls, one per job
# (.github/workflows/release.yml). Each enters the Nix dev shell itself: the flake of the current
# directory (the checkout being released), else this script's repository.
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
# zeabur-oss/identity at refs/tags/<version>.
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

# The lines of the CHANGELOG.md section `## [X.Y.Z]` (optionally ` - <date>`), without its heading.
changelog_section() {
  awk -v heading="## [${version#v}]" '
    $0 == heading || index($0, heading " ") == 1 { found = 1; next }
    found && /^## / { exit }
    found { print; if (NF) text = 1 }
    END { if (!text) exit 1 }
  ' "$root/CHANGELOG.md"
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
  if ! changelog_section >/dev/null; then
    echo "error: CHANGELOG.md has no section '## [$number]'" >&2
    exit 1
  fi
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
# <version>. Signs each and attests its CycloneDX SBOM; the shared workflow adds build provenance
# for every subject in <published>/subjects.json. Never compiles.
publish() {
  local artifacts published
  artifacts="$(cd "$1" && pwd)"
  mkdir -p "$2"
  published="$(cd "$2" && pwd)"
  : "${GITHUB_REPOSITORY:?}" "${GITHUB_RUN_ID:?}" "${GITHUB_RUN_ATTEMPT:?}" "${GITHUB_ACTOR:?}" "${GH_TOKEN:?}"
  local image="ghcr.io/${GITHUB_REPOSITORY,,}"
  changelog_section >/dev/null || { echo "error: CHANGELOG.md has no section for $version" >&2; exit 1; }
  # Refuse overwriting a release (including a previous failed draft). Recovery is manual.
  if gh release view "$version" --repo "$GITHUB_REPOSITORY" >/dev/null 2>&1; then
    echo "error: release $version already exists; inspect it before retrying" >&2
    exit 1
  fi
  local arch dir
  for arch in "${archs[@]}"; do
    dir="$artifacts/candidate-linux-$arch"
    [[ -f "$dir/image.tar" && -f "$dir/zeabur-identity-$version-linux-$arch.cdx.json" ]] ||
      { echo "error: $dir has no image.tar or image SBOM" >&2; exit 1; }
  done

  export DOCKER_CONFIG="$work/docker"
  mkdir -p "$DOCKER_CONFIG"
  local auth=(--authfile "$DOCKER_CONFIG/config.json")
  printf '%s' "$GH_TOKEN" | docker login ghcr.io --username "$GITHUB_ACTOR" --password-stdin
  local refs=() digests=() candidate digest ref
  : >"$published/image-digests.txt"
  for arch in "${archs[@]}"; do
    dir="$artifacts/candidate-linux-$arch"
    candidate="$image:candidate-$GITHUB_RUN_ID-$GITHUB_RUN_ATTEMPT-$arch"
    # The input is our own smoked build; signatures are added below. Do not depend on a host-wide
    # containers/policy.json.
    skopeo --insecure-policy copy "${auth[@]}" "docker-archive:$dir/image.tar" "docker://$candidate"
    digest="$(skopeo inspect "${auth[@]}" --format '{{.Digest}}' "docker://$candidate")"
    ref="$image@$digest"
    refs+=("$ref")
    digests+=("$digest")
    cosign sign --yes "$ref"
    cosign attest --yes --type cyclonedx --predicate "$dir/zeabur-identity-$version-linux-$arch.cdx.json" "$ref"
    printf '%s  %s\n' "$arch" "$ref" >>"$published/image-digests.txt"
  done
  # The index lists only the platform images above, by digest (never rebuilt). Its tag is the
  # version without the v (0.1.1), as every zeabur-oss image and chart is tagged.
  tag="${version#v}"
  docker manifest create "$image:$tag" "${refs[@]}"
  docker manifest push "$image:$tag"
  digest="sha256:$(skopeo inspect --raw "${auth[@]}" "docker://$image:$tag" | sha256sum | cut -d ' ' -f 1)"
  ref="$image@$digest"
  digests+=("$digest")
  printf 'index  %s\n' "$ref" >>"$published/image-digests.txt"
  cosign sign --yes "$ref"
  # Both platform SBOMs on the index too, as well as on each platform image.
  for arch in "${archs[@]}"; do
    cosign attest --yes --type cyclonedx \
      --predicate "$artifacts/candidate-linux-$arch/zeabur-identity-$version-linux-$arch.cdx.json" "$ref"
  done
  printf '%s\n' "${digests[@]}" |
    jq -R --arg name "$image" '{name: $name, digest: .}' | jq -s . >"$published/subjects.json"
  cat "$published/image-digests.txt"
}

# The draft release's files: both CLI archives and every SBOM, the image digests, a provenance
# summary, SHA256SUMS over them and its Sigstore bundle; and the notes, from CHANGELOG.md.
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
  grep -q '^index ' "$artifacts/published/image-digests.txt" ||
    { echo "error: $artifacts/published/image-digests.txt has no index" >&2; exit 1; }
  cp "$artifacts/published/image-digests.txt" "$out/"
  local server="${GITHUB_SERVER_URL:-https://github.com}"
  jq -n --arg commit "$GITHUB_SHA" --arg repository "$server/$GITHUB_REPOSITORY" --arg version "$version" \
    --arg run "$server/$GITHUB_REPOSITORY/actions/runs/$GITHUB_RUN_ID/attempts/$GITHUB_RUN_ATTEMPT" \
    '{source: $repository, commit: $commit, version: $version, workflowRun: $run,
      build: "Pinned flake.lock; cargo auditable build --release --locked; native Linux musl"}' \
    >"$out/provenance.json"
  (
    cd "$out"
    sha256sum zeabur-identityctl-*.tar.gz zeabur-identity*.cdx.json image-digests.txt provenance.json >SHA256SUMS
    cosign sign-blob --yes --bundle SHA256SUMS.sigstore.json SHA256SUMS
  )
  {
    changelog_section
    printf '\nSource commit: %s\n\n' "$GITHUB_SHA"
    printf 'Linux amd64 and arm64 static CLI archives and container image.\n\n'
    printf '## Image digests\n\n```text\n'
    cat "$out/image-digests.txt"
    printf '```\n\nVerify signatures, checksums and SBOMs with [the release instructions](%s/%s/blob/%s/docs/reference/releases.mdx).\n' \
      "$server" "$GITHUB_REPOSITORY" "$GITHUB_SHA"
  } >"$release/notes.md"
}

# What a user does with the draft's files: the signed SHA256SUMS covers them and they match it,
# their build provenance names the shared release workflow, the image is the signed index, its
# signature and SBOM attestation verify; then the archive and image run on a disposable k3s.
verify() {
  local os="$1" arch="$2" directory
  platform "$os" "$arch"
  directory="$(cd "$3" && pwd)"
  local identity_regexp="${RELEASE_CERT_IDENTITY_REGEXP:-^https://github\.com/zeabur-oss/\.github/\.github/workflows/release\.yml@}"
  local signer_workflow="${RELEASE_SIGNER_WORKFLOW:-zeabur-oss/.github/.github/workflows/release.yml}"
  local repository="${RELEASE_SOURCE_REPOSITORY:-zeabur-oss/identity}"
  local source_ref="${RELEASE_SOURCE_REF:-refs/tags/$version}"
  local certificate=(--certificate-identity-regexp "$identity_regexp" --certificate-oidc-issuer "$oidc_issuer"
    --certificate-github-workflow-repository "$repository" --certificate-github-workflow-ref "$source_ref")
  local archive="zeabur-identityctl-$version-linux-$arch.tar.gz"
  # Do not inherit the publisher's Docker login: this must work for a public consumer.
  export DOCKER_CONFIG="$work/docker"
  mkdir -p "$DOCKER_CONFIG"

  cosign verify-blob "${certificate[@]}" --bundle "$directory/SHA256SUMS.sigstore.json" "$directory/SHA256SUMS"
  (
    cd "$directory"
    # The signed manifest must cover every file used below, not just an unrelated one.
    local asset
    for asset in "$archive" "zeabur-identityctl-$version-linux-$arch.cdx.json" \
      "zeabur-identity-$version-linux-$arch.cdx.json" image-digests.txt provenance.json; do
      awk -v asset="$asset" '$1 ~ /^[0-9a-f]{64}$/ && substr($0, 67) == asset { found = 1 }
        END { exit !found }' SHA256SUMS ||
        { echo "error: signed SHA256SUMS does not cover $asset" >&2; exit 1; }
    done
    sha256sum --check --strict SHA256SUMS
  )
  # Build provenance (GitHub artifact attestations), for the archive here and the image below.
  local attestation=(--repo "$repository" --signer-workflow "$signer_workflow" --source-ref "$source_ref")
  gh attestation verify "$directory/$archive" "${attestation[@]}" >/dev/null

  # The image is the index recorded in the signed image-digests.txt.
  local image
  image="$(awk '$1 == "index" { print $2; n++ } END { if (n != 1) exit 1 }' "$directory/image-digests.txt")" ||
    { echo "error: image-digests.txt must name exactly one index" >&2; exit 1; }
  if [[ ! "$image" =~ ^[^[:space:]@]+@sha256:[0-9a-f]{64}$ ]]; then
    echo "error: the index $image is not <repository>@sha256:<digest>" >&2
    exit 1
  fi
  cosign verify "${certificate[@]}" "$image" >"$work/image-signature.json"
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
  gh attestation verify "oci://$image" "${attestation[@]}" >/dev/null

  docker pull --platform "linux/$arch" "$image"
  "$root/scripts/release-smoke.sh" "$directory/$archive" "$image"
}

shift 2
"$stage" "$@"
