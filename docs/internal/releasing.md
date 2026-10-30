# Releasing

`.github/workflows/release.yml` calls the shared release workflow of
[zeabur-oss/.github](https://github.com/zeabur-oss/.github), pinned by commit. That workflow runs
this repository's `scripts/release.sh`, one stage per job, each in the dev shell of the commit
being released. The steps every zeabur-oss release shares (pushing by digest, signing,
`SHA256SUMS`, the notes and most of verification) are `zeabur-oss-release` from
[zeabur-oss/.github](https://github.com/zeabur-oss/.github/tree/main/release), pinned in
`flake.lock`:

| Stage | Does |
|---|---|
| `check` | Every workspace crate (including `zeabur-identityctl`), `Cargo.lock` and `ui/package.json` carry the version, and `CHANGELOG.md` has its `## [X.Y.Z]` section. |
| `build` | Per platform (Linux amd64 and arm64, each natively): static musl binaries, the CLI archive, CycloneDX SBOMs and the image, then `scripts/release-smoke.sh` runs that archive and image on a disposable k3s cluster. |
| `publish` | Pushes each smoked image to `ghcr.io/zeabur-oss/identity` by digest and the multi-platform index as the version tag, signs them and records them in `digests.txt`, then attests their SBOMs with cosign; the shared workflow adds build provenance. |
| `assets` | The release files, `SHA256SUMS` with its Sigstore bundle, and the notes: the version's `CHANGELOG.md` section and a link to the documentation. |
| `verify` | On fresh amd64 and arm64 runners: checks the draft's files, their signatures and provenance, the image's index, signatures and SBOM, then runs the downloaded CLI and the image on k3s. |

The signatures name the shared workflow, not this repository's: see
[Release files and verification](../reference/releases.mdx).

A tag is a SemVer 2.0.0 version with a `v` and no build metadata. `vX.Y.Z` is a normal release;
`vX.Y.Z-<pre-release>` (`v0.1.2-beta.1`, `v1.0.0-rc.1`) is a GitHub pre-release, never marked
latest. A pre-release has no `CHANGELOG.md` section of its own: it reads the section of its normal
version (`## [0.1.2]`), and the crates and `ui/package.json` carry the full version
(`0.1.2-beta.1`).

1. Update the workspace version in `Cargo.toml`, `Cargo.lock` and `ui/package.json`. Add a
   `## [<VERSION>] - <DATE>` section to `CHANGELOG.md` with the alpha status, platform scope and
   known limitations. Use level-three headings within each version; the release notes include only
   the matching version section. Merge the release commit to `main`.
2. In GitHub Actions, select **Release → Run workflow**, choose that commit's branch and enter
   the matching version, such as `v0.1.1`. This builds and smokes both platforms without
   publishing.
3. Make sure the GHCR package `zeabur-oss/identity` is public and this repository's Actions token
   can write to it. If the package is new, the first publishing run creates it; change its
   visibility before the download checks run. Set repository rulesets to protect `main` and
   restrict release-tag changes to maintainers.
   Enable GitHub private vulnerability reporting and confirm the reporting link in `SECURITY.md`
   works before making the release public.
4. Check that **CI** passed on `main` for the release commit, then tag it and push the tag. Replace `YOUR_RELEASE_COMMIT` with its commit hash:

   ```sh
   git tag v0.1.1 YOUR_RELEASE_COMMIT
   git push origin v0.1.1
   ```

5. Watch the **Release** run in GitHub Actions. A successful run leaves a **draft release**;
   it never makes the GitHub release public automatically.
6. Download the draft assets with a maintainer's authenticated GitHub CLI:

   ```sh
   gh release download v0.1.1 --repo zeabur-oss/identity --dir downloaded
   ```

   Draft assets are not anonymously downloadable. For the download step in
   [Get started](../get-started/quickstart.mdx), transfer these exact assets to the clean test server and
   perform the same signature and checksum verification; do not rebuild the CLI or image.
   Complete the [installation checklist](release-check.md) on Linux amd64 and arm64.
   Record the release commit, CLI checksums, image digests, cluster versions and observed
   outcomes in the release tracking issue. Keep acceptance failures
   visible; a green release workflow is not a substitute for this checklist.
7. Only after the workflow and installation acceptance pass, make the release public:

   ```sh
   gh release edit v0.1.1 --repo zeabur-oss/identity --draft=false
   ```

   Repeat the guide's unauthenticated downloads and signature/checksum verification against
   the public URLs. Announce the release only after those checks succeed.

The tag must match the versions, and the commit must be on `main`. The
workflow builds both platforms using the pinned Rust/Nix toolchain and locked dependencies, and tests the
CLI archives and images it will publish. It then signs and uploads the artifacts, downloads them
on fresh runners, and verifies and runs them while the release stays a draft. Signing uses
GitHub's short-lived identity token through Sigstore. The download verification job needs
`contents: write`: GitHub exposes draft releases only to tokens with push access, even in a
public repository. It does not publish or edit the release; making it public remains a separate
maintainer action.

Image tags are public while the GitHub release is still a draft. Do not treat an image tag or
a successful build as installation acceptance. Use the `index` digest in the release's
`digests.txt` when pinning a deployment.

If publication succeeds but download verification fails, preserve the draft, tag and signed
artifacts. Fix `scripts/release.sh` on `main`, then run **Release → Run workflow** from `main`
with the existing version and `verify_only` enabled:

```sh
gh workflow run release.yml --ref main -f version=v0.1.1 -F verify_only=true
```

This mode skips build and publication. It uses the existing tag's pinned Nix environment with
the scripts of the commit the run was started from, and reruns native amd64/arm64 signature,
checksum and Kubernetes smoke verification against the existing assets, allowing verification
fixes without changing the release tag or artifacts. It reads the image digest from the signed
`digests.txt` and binds the image to it before pulling. It does not rebuild, re-sign,
overwrite or publish anything.

If publication itself fails, inspect the logs and any partial draft or registry uploads before
deciding how to recover. Do not blindly rerun publication or move an existing version tag. A
version whose tag exists but which was never published is withdrawn, not reused: bump to the next
patch version and note the withdrawn one in `CHANGELOG.md`, as 0.1.1 does for 0.1.0.

## Try the artifacts on a test machine

On a disposable Linux machine matching the chosen architecture, install Docker 28 or later
(API 1.48+, required for single-platform image export), check out the release tag and, with the
`downloaded` directory from the examples above and an authenticated `gh`, run:

```sh
./scripts/release.sh verify v0.1.1 linux "$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')" downloaded
```

The script enters `nix develop` itself, verifies the downloads, pulls the image and creates a
temporary k3s cluster. It uses the downloaded CLI to install Zeabur Identity, checks the running
server and removes the cluster when finished. It needs access to GHCR, Sigstore, the GitHub API,
the k3s image and Nix caches.

To rehearse one platform's build locally, without publishing:
`./scripts/release.sh build v0.1.1 linux <amd64|arm64> dist`.

For a local build, follow [Building from source](https://github.com/zeabur-oss/identity/blob/main/CONTRIBUTING.md#building-from-source).

Before publishing a new version, follow the [installation checklist](release-check.md)
to check the guide, browser sign-in and account recovery with the release artifacts.
