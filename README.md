<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/images/cover-dark.avif">
  <img alt="Zeabur Identity: everyone signs in with their own account. No shared admin file. Sign in with a passkey, GitHub, Google or a password." src="docs/images/cover-light.avif">
</picture>

**English** · [繁體中文](README.zh-TW.md) · [简体中文](README.zh-CN.md)

# Zeabur Identity

**Everyone on your team signs in to Zeabur with their own account, and no one shares an admin
password or file.** Zeabur Identity is the part of Zeabur that knows who is signing in. It shows
the sign-in page, checks each person's passkey, password, or GitHub or Google account, and gives them
only the access you assigned.

## Using Zeabur?

Zeabur's sign-in page is Zeabur Identity, so a cluster that runs Zeabur already has it. You
manage people in Zeabur, not here:

- **Invite people and choose their projects** in **Members**:
  [Invite members and assign project permissions](https://oss.zeabur.com/docs/zeabur/cluster/members/).
- **Setting up Zeabur on a cluster?** Zeabur Identity is installed first.
  [Install Zeabur in an existing cluster](https://oss.zeabur.com/docs/zeabur/install/existing-cluster/)
  lists what you need and links to the steps. One command that installs Zeabur together with
  Zeabur Identity is tracked in [zeabur-oss/zeabur#430](https://github.com/zeabur-oss/zeabur/issues/430).

To move from zeabur.com to your own server, or for anything else about Zeabur, see the
[Zeabur documentation](https://oss.zeabur.com/docs/zeabur/).

## What it does for you

- **An account for each person.** Nobody copies one admin file to every laptop. When someone
  leaves, end their sessions and their access stops within ten minutes.
- **Sign in the way you already do.** A passkey (Touch ID, Windows Hello, or a security key),
  GitHub, Google, your company's sign-in, or a password.
- **Two factors for admins.** By default, an admin signs in with a passkey, or with a password and
  a code from an authenticator app.
- **Runs on your server.** One small program in your cluster, with no database and no outside
  service. Accounts are stored in the cluster itself.

## Use it on its own

Zeabur Identity also works without Zeabur, on any self-managed Kubernetes cluster.

**Delete `admin.conf`. Sign in to your cluster with your own account.**

Most self-managed clusters are run with one admin kubeconfig that never expires, gets copied to
every laptop, and cannot be revoked. Zeabur Identity replaces it with a sign-in: `kubectl` opens
your browser, you sign in with a passkey, SSO, or a password, and you get a token that lasts
minutes, not years.

https://github.com/user-attachments/assets/4c6e29f2-341c-4622-8cc5-4337e13e53b5

*Signing in to [Aptakube](https://aptakube.com) with a passkey: the cluster opens for browsing,
and restarting a deployment is refused with 403 for an account without that right.*

### Why Zeabur Identity

- **Passkeys, SSO, or passwords.** Touch ID, Windows Hello, or a security key. Teammates can also
  link a GitHub or Google account, or a company account through an OpenID provider, or set a
  password of at least 15 characters.
- **Admin rights belong to admin accounts.** Keep a separate admin account for cluster changes.
  By default it signs in with a passkey, or a password and an authenticator app code; you can
  require passkeys only. Its tokens last 5 minutes. Everyday accounts get only the rights you bind
  to their groups.
- **No forever key on anyone's laptop.** Tokens last minutes, and kube-apiserver checks them on
  every request. Every session ends 12 hours after sign-in. Revoke a person's sessions and their
  access ends when the token in hand expires, within ten minutes.
- **Runs inside the cluster it protects.** One small pod, no database, no extra servers. Users,
  credentials, and clients are Kubernetes objects. Tested in CI on k3s; RKE2 uses the same
  configuration. OpenID Connect apps such as Argo CD or Grafana can use the same issuer.

### What it looks like

<table>
  <tr>
    <td width="50%"><picture>
      <source media="(prefers-color-scheme: dark)" srcset="docs/images/sign-in-dark.avif">
      <img alt="Sign-in page with username and password, Sign in with a passkey and Continue with GitHub" src="docs/images/sign-in-light.avif">
    </picture></td>
    <td width="50%"><picture>
      <source media="(prefers-color-scheme: dark)" srcset="docs/images/setup-dark.avif">
      <img alt="Setup page from a one-time link, with Create passkey and Use a password" src="docs/images/setup-light.avif">
    </picture></td>
  </tr>
  <tr>
    <td align="center"><b>Everyday sign-in</b><br>passkey or GitHub</td>
    <td align="center"><b>Joining</b><br>a one-time invitation link</td>
  </tr>
</table>

### How it works

1. You run `kubectl get pods`. Your browser opens Zeabur Identity's sign-in page.
2. You sign in. `kubectl` receives a token valid for ten minutes and renews it quietly while you
   work.
3. Kubernetes checks the token itself. Zeabur Identity never sits in the path of your requests.

Need to change something? Sign in with your admin account. It has full rights at once, without a
second sign-in. For stricter rules, such as security keys only for admins, see
[Admin accounts and sessions](docs/users/admin-sessions.mdx).

### Get started

Follow the [step-by-step guide](docs/get-started/quickstart.mdx) to install k3s on an Ubuntu server,
download and verify Zeabur Identity, and sign in from your computer (macOS, Linux or Windows).

For an existing cluster, first [download and verify Zeabur Identity](docs/reference/releases.mdx).
Then install it with your cluster-admin kubeconfig:

```sh
export ZEABUR_IDENTITY_ISSUER=https://login.example.com
zeabur-identityctl crds | kubectl apply --server-side -f -
zeabur-identityctl manifests --image "$ZEABUR_IDENTITY_IMAGE" --serve-arg=--invitations | kubectl apply --server-side -f -
kubectl -n zeabur-identity rollout status deploy/zeabur-identity --timeout=180s
# Prints kube-apiserver's configuration and how to install it for your distribution:
zeabur-identityctl kube-config --distro k3s > authn.yaml
# A one-time link: open it and set up the first admin's sign-in.
zeabur-identityctl setup-link --username admin
```

[Install on an existing cluster](docs/get-started/existing-cluster.mdx) has each step with a
command that checks it. For development builds, see
[Building from source](CONTRIBUTING.md#building-from-source).

Then:

- Sign in with [GitHub, Google or your own OpenID provider](docs/users/upstream-sign-in.mdx), such as Keycloak.
- [Register clients](docs/users/clients.mdx) such as Grafana or Argo CD, with
  `zeabur-identityctl client create`.
- [Manage users](docs/users/manage-users.mdx): groups, admin rights, lost passkeys, removing people;
  [provision them from a directory](docs/users/provisioning.mdx) with a small sync script.
- `zeabur-identityctl invite --username alice` to send someone a one-time link. It needs the server
  started with `--invitations`, as above; without it the link cannot be redeemed.

## Documentation

For Zeabur users:

- [Invite members and assign project permissions](https://oss.zeabur.com/docs/zeabur/cluster/members/)
- [Install Zeabur in an existing cluster](https://oss.zeabur.com/docs/zeabur/install/existing-cluster/)

Using Zeabur Identity on its own:

- [Install on k3s on Ubuntu](docs/get-started/quickstart.mdx) and [install on an existing cluster](docs/get-started/existing-cluster.mdx)
- [Manage users](docs/users/manage-users.mdx), [admin accounts and sessions](docs/users/admin-sessions.mdx), [sign out and remove users](docs/users/offboarding.mdx), [sign in with GitHub, Google or an OpenID provider](docs/users/upstream-sign-in.mdx), [sync users from a directory](docs/users/provisioning.mdx) and [register clients](docs/users/clients.mdx)
- [Emergency access](docs/operations/emergency-access.mdx), [backup and restore](docs/operations/backup-restore.mdx) and [upgrade](docs/operations/upgrade.mdx)
- [Architecture](docs/reference/architecture.mdx): how the pieces fit, security properties, the crates.
- [Conformance](docs/reference/conformance.mdx): every specification requirement, mapped to code and tests.
- [Releases](docs/reference/releases.mdx): supported platforms, tag workflow, signatures, checksums and SBOMs.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md): development setup, the checks CI runs, dependency policy.
Report security issues as described in [SECURITY.md](SECURITY.md).

## Licence and credits

Apache-2.0. Contributions are accepted under the [Developer Certificate of Origin](DCO).

The sign-in pages take their styles and component classes from Zeabur's design system
(Apache-2.0, built on [shadcn/ui](https://ui.shadcn.com), MIT) and ship the
[Geist](https://github.com/vercel/geist-font) font (SIL Open Font License 1.1,
`vendor/geist/LICENSE.txt` in the design system). The container image includes
Mozilla's CA certificate bundle as packaged by nixpkgs (MPL-2.0).
