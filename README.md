<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/images/cover-dark.avif">
  <img alt="Zeabur Identity: admin.conf crossed out; sign in to Kubernetes with a passkey" src="docs/images/cover-light.avif">
</picture>

# Zeabur Identity

**Delete `admin.conf`. Sign in to your cluster with a passkey.**

Most self-managed clusters are run with one admin kubeconfig that never expires, gets copied to
every laptop, and cannot be revoked. Zeabur Identity replaces it
with a passkey: `kubectl` opens your browser, you touch your fingerprint reader, and you get a
token that lasts minutes, not years.

> **Status: v0.1.1 alpha.** Releases can change the Kubernetes resources, and nothing converts
> them between versions, so an upgrade or a rollback can fail.
> See the [release notes](CHANGELOG.md#011---2026-10-28) and [support policy](SECURITY.md).

https://github.com/user-attachments/assets/4c6e29f2-341c-4622-8cc5-4337e13e53b5

*Signing in to [Aptakube](https://aptakube.com) with a passkey: the cluster opens for browsing,
and restarting a deployment is refused with 403 for an account without that right.*

## Why Zeabur Identity

- **Passkeys, not passwords.** Touch ID, Windows Hello or a security key. Teammates can also
  link a GitHub or Google account for everyday access.
- **Admin rights belong to admin accounts.** Keep a separate admin account for cluster changes.
  It signs in with a passkey only, its tokens last 5 minutes, and its sessions are shorter.
  Everyday accounts get only the rights you bind to their groups.
- **No forever key on anyone's laptop.** Tokens last minutes and Kubernetes checks them itself.
  Every session ends 12 hours after sign-in. Revoke a person's sessions and their access ends
  when the token in hand expires, within ten minutes.
- **Runs inside the cluster it protects.** One small pod, no database, no extra
  servers. Tested in CI on k3s; RKE2 uses the same configuration. OpenID Connect apps such as Argo CD or Grafana can use the same issuer.

## What it looks like

<table>
  <tr>
    <td width="50%"><picture>
      <source media="(prefers-color-scheme: dark)" srcset="docs/images/sign-in-dark.avif">
      <img alt="Sign-in page with a passkey button and Continue with GitHub" src="docs/images/sign-in-light.avif">
    </picture></td>
    <td width="50%"><picture>
      <source media="(prefers-color-scheme: dark)" srcset="docs/images/setup-dark.avif">
      <img alt="Setup page for creating a passkey from a one-time link" src="docs/images/setup-light.avif">
    </picture></td>
  </tr>
  <tr>
    <td align="center"><b>Everyday sign-in</b><br>passkey or GitHub</td>
    <td align="center"><b>Joining</b><br>a one-time invitation link</td>
  </tr>
</table>

## How it works

1. You run `kubectl get pods`. Your browser opens Zeabur Identity's sign-in page.
2. You sign in with your passkey. `kubectl` receives a token valid for ten minutes and renews it
   quietly while you work.
3. Kubernetes checks the token itself. Zeabur Identity never sits in the path of your requests.

Need to change something? Sign in with your admin account. It uses a passkey only and has full
rights at once, without a second sign-in. For stricter rules, such as security keys only for
admins, see [Manage users](docs/users/admin-sessions.mdx).

## Get started

Follow the [step-by-step guide](docs/get-started/quickstart.mdx) to install k3s on an Ubuntu server,
download and verify Zeabur Identity, and sign in with a passkey from your computer (macOS, Linux or
Windows).

For an existing cluster, first [download and verify Zeabur Identity](docs/reference/releases.mdx).
Then install it with your cluster-admin kubeconfig:

```sh
export ZEABUR_IDENTITY_ISSUER=https://login.example.com
zeabur-identityctl crds | kubectl apply --server-side -f -
zeabur-identityctl manifests --image "$ZEABUR_IDENTITY_IMAGE" --serve-arg=--invitations | kubectl apply --server-side -f -
# Prints kube-apiserver's configuration and how to install it for your distribution:
zeabur-identityctl kube-config --distro k3s > authn.yaml
# A one-time link: open it and create your passkey.
zeabur-identityctl setup-link --username admin
```

For development builds, see [Building from source](CONTRIBUTING.md#building-from-source).

Then:

- Sign in with [GitHub](docs/users/github-sign-in.mdx) or [Google](docs/users/google-sign-in.mdx).
- [Register clients](docs/users/clients.mdx) such as Grafana or Argo CD, with
  `zeabur-identityctl client create`.
- [Manage users](docs/users/manage-users.mdx): groups, admin rights, lost passkeys, removing people;
  [provision them from a directory](docs/users/provisioning.mdx) with a small sync script.
- `zeabur-identityctl invite --username alice` to send someone a one-time link. It needs the server
  started with `--invitations`, as above; without it the link cannot be redeemed.

## Learn more

- [Architecture](docs/reference/architecture.mdx): how the pieces fit, security properties, the crates.
- [Conformance](docs/reference/conformance.mdx): every specification requirement, mapped to code and tests.
- [Contributing](CONTRIBUTING.md): development setup, the checks CI runs, dependency policy.
- [Releases](docs/reference/releases.mdx): supported platforms, tag workflow, signatures, checksums and SBOMs.

## Licence and credits

Apache-2.0. Contributions are accepted under the [Developer Certificate of Origin](DCO).

The sign-in pages take their styles and component classes from Zeabur's design system
(Apache-2.0, built on [shadcn/ui](https://ui.shadcn.com), MIT) and ship the
[Geist](https://github.com/vercel/geist-font) font (SIL Open Font License 1.1,
`crates/zeabur-identity-ui/assets/LICENSE-Geist.txt`). The container image includes
Mozilla's CA certificate bundle as packaged by nixpkgs (MPL-2.0).
