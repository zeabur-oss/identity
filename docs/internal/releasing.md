# Releasing

`.github/workflows/release.yml` builds, publishes and verifies a release, one job per stage, each
in the dev shell of the commit being released. The steps every zeabur-oss release shares (pushing
by digest, signing, `SHA256SUMS` and most of verification) are `@zeabur-oss/release` from
[zeabur-oss/.github](https://github.com/zeabur-oss/.github/tree/main/release), pinned in
`package.json` and `bun.lock`:

| Job | Does |
|---|---|
| `check` | Every workspace crate (including `zeabur-identityctl`), `Cargo.lock` and `ui/package.json` carry the version, and `CHANGELOG.md` has its `## X.Y.Z (YYYY-MM-DD)` section. |
| `build` | Per platform (Linux amd64 and arm64, each natively), `scripts/release-build.sh`: static musl binaries, the CLI archive, CycloneDX SBOMs and the image, then `scripts/release-smoke.sh` runs that archive and image on a disposable k3s cluster. |
| `publish` | Pushes each smoked image to `ghcr.io/zeabur-oss/identity` by digest and the multi-platform index as the version tag, signs them and records them in `digests.txt`, then attests their SBOMs with cosign. `attest` adds build provenance. |
| `release` | Adds the release files (including `resources.json`, the archive's `zeabur-identityctl resources`) and `SHA256SUMS` with its Sigstore bundle to the draft. |
| `verify` | On fresh amd64 and arm64 runners: checks the draft's files, their signatures and provenance, then `scripts/release-verify.sh` checks the image's index, signatures and SBOM and runs the downloaded CLI and the image on k3s. |

The signatures name this repository's `.github/workflows/release.yml`: see
[Release files and verification](../reference/releases.mdx).

A tag is a SemVer 2.0.0 version with a `v` and no build metadata. `vX.Y.Z` is a normal release;
`vX.Y.Z-<pre-release>` (`v0.1.2-beta.1`, `v1.0.0-rc.1`) is a GitHub pre-release, never marked
latest. A pre-release has a `CHANGELOG.md` section of its own (`## 0.1.2-beta.1 (YYYY-MM-DD)`), and
the crates and `ui/package.json` carry the full version (`0.1.2-beta.1`).

1. Run the **Release pull request** workflow (Actions, **Run workflow** on `main`), with
   `prerelease: rc` for a release candidate. knope turns the change files in `.changeset/` into the
   next `CHANGELOG.md` section and sets the version in `Cargo.toml`, `Cargo.lock` and
   `ui/package.json`, and zeabur-oss-bot opens
   `chore(release): vX.Y.Z`. Edit `CHANGELOG.md` on that branch to add the platform scope and known
   limitations. Use level-three headings within each version and keep each
   paragraph and list item on one line; the release notes are the matching version section as it is.
2. In GitHub Actions, select **Release → Run workflow**, choose `release/next` and enter
   the matching version, such as `v0.1.1`. This builds and smokes both platforms without
   publishing.
3. Make sure the GHCR package `zeabur-oss/identity` is public and this repository's Actions token
   can write to it. If the package is new, the first publishing run creates it; change its
   visibility before the download checks run. Set repository rulesets to protect `main` and
   restrict release-tag changes to maintainers.
   Enable GitHub private vulnerability reporting and confirm the reporting link in `SECURITY.md`
   works before making the release public.
4. Merge the release pull request to `main` once its CI has passed. zeabur-oss-bot tags the
   merge commit as soon as it lands, which starts the **Release** run.
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
artifacts. Do not rebuild, re-sign, overwrite or publish anything. Fix the check on
`main`, then run the failed jobs again, or run `scripts/release-verify.sh` from a checkout of `main`
on a Linux machine of each architecture, as shown below. It reads the image digest from the signed `digests.txt` and binds the image to it
before pulling.

If publication itself fails, inspect the logs and any partial draft or registry uploads before
deciding how to recover. Do not blindly rerun publication or move an existing version tag. A
version whose tag exists but which was never published is withdrawn, not reused: bump to the next
patch version and note the withdrawn one in `CHANGELOG.md`, as 0.1.1 does for 0.1.0.

## Try the artifacts on a test machine

On a disposable Linux machine matching the chosen architecture, install Docker 28 or later
(API 1.48+, required for single-platform image export), Nix and an authenticated `gh`. Check out the
release tag (or `main`, to try a fix to the check), download the draft's files into `downloaded`
as in the steps above and run:

```sh
nix develop --command bun install --frozen-lockfile
nix develop --command bun x zeabur-oss-release verify-assets downloaded
nix develop --command scripts/release-verify.sh v0.1.1 downloaded
```

`verify-assets` checks `SHA256SUMS` and each file's provenance. Set
`RELEASE_SOURCE_REF=refs/tags/v0.1.1` for it when the checkout is not the tag.
`release-verify.sh` checks the image's index, signatures and SBOM, then creates a temporary k3s cluster, uses
the downloaded CLI to install Zeabur Identity, checks the running server and removes the cluster
when finished. It needs access to GHCR, Sigstore, the GitHub API, the k3s image and Nix caches.

To rehearse one platform's build locally, without publishing:
`nix develop --command scripts/release-build.sh v0.1.1 dist`.

For a local build, follow [Building from source](../../CONTRIBUTING.md#building-from-source).

Before publishing a new version, follow the [installation checklist](release-check.md)
to check the guide, browser sign-in and account recovery with the release artifacts.
