# Changelog

## Unreleased

### Changed

- The server image's version tag drops the `v`, as every zeabur-oss image and chart does: `ghcr.io/zeabur-oss/identity:0.1.2`, not `:v0.1.2`. The 0.1.1 image is also tagged `0.1.1`; its `v0.1.1` tag stays and names the same digest.
- The release file `image-digests.txt` is now `digests.txt`, with a line per image kind (`linux/amd64`, `linux/arm64`, `index`), as in every zeabur-oss release ([release files](docs/reference/releases.mdx)). The `index` line is unchanged.
- Release notes are the changelog section and a link to the documentation; the digests are in the signed `digests.txt`.
- Images are pushed by digest with no `candidate-*` tags left in GHCR.

## 0.1.1 (2026-10-28)

First published alpha, for evaluating passkey-based access to self-managed Kubernetes clusters. Use a disposable cluster and keep an independent cluster-admin kubeconfig.

### Added

- Passkey enrollment and sign-in, with optional linked GitHub and Google accounts for everyday access.
- Kubernetes-backed users, credentials, invitations and grants; no separate database.
- Static Linux amd64 and arm64 CLI archives and a multi-platform server image, with signed checksums, image signatures, CycloneDX SBOMs and source/build provenance.
- Admin accounts. A `User` with `accountType: Admin` signs in with a passkey only, and its tokens carry `zeabur:admins`, bound to `cluster-admin` by the ClusterRoleBinding `zeabur-identity-cluster-admins`. `zeabur-identityctl setup-link` creates the first user as an admin account; `zeabur-identityctl invite --admin` and `zeabur-identityctl account-type <name> <admin|regular>` make or change others.
- Sessions follow NIST SP 800-63B-4: regular accounts' tokens last 10 minutes, admin accounts' 5 minutes; sessions end after 1 hour idle (15 minutes for admins with several teams or AAL3) and 12 hours after sign-in. Server options: `--refresh-idle`, `--refresh-absolute`, `--admin-token-lifetime`, `--admin-refresh-idle`.
- The ConfigMap `zeabur-identity-settings` holds install-wide settings: `teams` (`single` or `multiple`) and `admin-aal3`, which limits admin accounts to device-bound passkeys.
- Internal discovery uses cert-manager. `zeabur-identityctl kube-config` has cert-manager issue a root CA (10 years) and the internal listener's certificate (90 days, renewed automatically) in Zeabur Identity's namespace. The printed configuration changes only if the root CA or the ClusterIP changes. Without cert-manager, use `--discovery public`. The root CA's private key lives in Secret `zeabur-identity-internal-ca`: anyone who can read Secrets in Zeabur Identity's namespace can issue a certificate for the internal address.
- The account page links and unlinks GitHub or Google accounts. Both need a passkey confirmation from the last five minutes. The provider's callback links the account only to the session that started it. An account already linked to a user is refused, admin accounts cannot link, and the last way to sign in cannot be unlinked. The `User` gets `AccountLinked` or `AccountUnlinked` events.
- The setup page explains a disabled account, an expired confirmation and an already registered passkey.
- `zeabur-identityctl invite` refuses a user who already has a passkey or a linked account, as `setup-link` does. `invite --reset` deletes them, the user's sessions and pending invitations first.
- Setup links and invitations stay valid for 7 days at most (`--valid-for`).
- Issuing and redeeming a setup link or invitation each record a core `Event` on the `User` (`SetupLinkIssued`, `InvitationIssued`, `SetupLinkRedeemed`, `InvitationRedeemed`). If `zeabur-identityctl` cannot record the `Event`, it does not print the link.
- A disabled user (`spec.disabled: true`) cannot redeem a setup link or an invitation.
- A new passkey without a name shows on the account page as "Passkey added" with its creation date.

### Installation and platform scope

Follow [Get started](https://github.com/zeabur-oss/identity/blob/main/docs/get-started/quickstart.mdx) for installation and signature verification. Pin the image by the digest in the release's `image-digests.txt` asset. Signatures and build provenance name the shared release workflow of [zeabur-oss/.github](https://github.com/zeabur-oss/.github), which this repository's release workflow calls, not a workflow of zeabur-oss/identity.

| Surface | Scope | |---|---| | CLI archives and server images | Linux amd64 and arm64 | | Installation guide | Ubuntu 24.04 or later; k3s v1.36.5+k3s1 | | Automated cluster integration and E2E | k3s v1.36.5-k3s1 | | `kube-config --distro` | `k3s` on K3s/RKE2, `generic` elsewhere | | macOS, Windows and other CLI targets | No prebuilt archives; source builds are outside the release artifact matrix |

CI coverage does not establish successful installation of these release artifacts. Before making the draft public, maintainers must record clean-install, browser sign-in, permission, expiry and account-recovery results using the [release installation checklist](https://github.com/zeabur-oss/identity/blob/main/docs/internal/release-check.md) in [issue #43](https://github.com/zeabur-oss/identity/issues/43).

### Known limitations and security boundaries

- Alpha releases can break configuration and resource schemas. There are no migration, upgrade or rollback guarantees for the `v1alpha1` Kubernetes resources.
- No browser SSO sessions, RP-Initiated Logout or Back-Channel Logout. Each authorization request requires sign-in.
- DPoP is not implemented; kube-apiserver accepts bearer tokens. Zeabur Identity is not OpenID Foundation certified, and the certification suite has not been run.
- Disabling a user, resetting passkeys or revoking a grant prevents session renewal; an already issued access token remains usable until expiry, up to ten minutes with default settings.
- Keep SSH/console access, an independent cluster-admin credential and tested backups. See [operations](https://github.com/zeabur-oss/identity/blob/main/docs/operations/emergency-access.mdx).
- Only the latest published alpha is eligible for security fixes; older alphas receive no backports. See the [security policy](https://github.com/zeabur-oss/identity/blob/main/SECURITY.md).

## 0.1.0 (2026-10-28)

Withdrawn: the tag `v0.1.0` exists, but its release workflow failed and nothing was published (no GitHub release, image or signatures). Its changes are released as 0.1.1.
