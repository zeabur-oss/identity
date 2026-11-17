---
default: minor
---

# Releases are signed by identity's own release workflow

From this release on, the signing certificate of the image, its SBOM attestations and `SHA256SUMS` names `zeabur-oss/identity/.github/workflows/release.yml`, not `zeabur-oss/.github/.github/workflows/release.yml`. Verify with `--certificate-identity-regexp '^https://github\.com/zeabur-oss/identity/\.github/workflows/release\.yml@'` and `gh attestation verify --signer-workflow zeabur-oss/identity/.github/workflows/release.yml`. Releases up to v0.3.0 keep the old identity.
