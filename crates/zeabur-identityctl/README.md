# zeabur-identityctl

The Zeabur Identity admin CLI. It runs on an administrator's machine with the administrator's own
kubeconfig, never inside the cluster, and is not part of the server image. Work that needs more
rights than Zeabur Identity's service account has (installing RBAC, creating users and the setup
Secret, having cert-manager issue the internal certificate) therefore happens here, with a
human's credentials.

## Commands

Set the public issuer URL before running commands that need it:

```sh
export ZEABUR_IDENTITY_ISSUER=https://auth.example.com
```

Replace the example URL with your own issuer. `zeabur-identityctl` reads `ZEABUR_IDENTITY_ISSUER` for
`manifests`, `kube-config`, `setup-link` and `invite`, so those commands need no issuer flag.

- `zeabur-identityctl crds`: the custom resource definitions as a Kubernetes `List`, for
  `kubectl apply --server-side -f -`.
- `zeabur-identityctl rbac`: the namespace, service account, `Role`, `RoleBinding`, the admin binding and
  the empty key Secret.
- `zeabur-identityctl manifests --image <ref>`: everything `rbac` prints plus the Service
  and the single-replica Deployment.
- `zeabur-identityctl resources`: the memory the default Deployment requests in total, as JSON
  (`{"requestMemoryMiB": 24}`). Each release publishes it as `resources.json`.
- `zeabur-identityctl kube-config --distro <k3s|generic>`: issues the
  internal listener's certificate if needed (the CA key is discarded), prints the kube-apiserver
  `AuthenticationConfiguration` on stdout and how to install it on stderr. `k3s` covers K3s/RKE2.
- `zeabur-identityctl setup-link [--username admin] [--reset]`: a one-time link that
  enrols a passkey for the first admin (created as an admin account, with no groups), or recovers
  the account with `--reset`, which first deletes the user's pending invitations, passkeys,
  linked accounts and sessions. It expires after 60 minutes by default, 7 days at most.
- `zeabur-identityctl invite --username <name> [--admin] [--reset]`: creates the `User` if
  needed and a one-time enrolment link (7 days by default and at most), printed for you to send.
  A user who already has a passkey or a linked account gets a link only with `--reset`, which
  works as for `setup-link`.
- `zeabur-identityctl account-type <name> <admin|regular>`: changes a user's account type. The
  change applies at the user's next sign-in or refresh.
- `zeabur-identityctl client create <client-id> --type <public|confidential> --redirect-uri <uri>`:
  prints an `OAuthClient` after checking it against the same rules as the CRD schema. A
  confidential client gets a generated 256-bit secret, printed once on stderr; the object holds
  only its hash. See [Registering clients](../../docs/users/clients.mdx).
- `zeabur-identityctl upstream migrate [--dry-run]`: turns the running Deployment's removed
  `--github-*` and `--google-*` server options into the `UpstreamProvider` objects `github` and
  `google`, and copies their client secrets into the Secret `zeabur-identity-upstream`. Run it
  when upgrading, before applying the new manifests; running it again changes nothing.

Results (JSON, YAML or a link) go to stdout and messages to stderr, so commands compose with
`kubectl apply -f -`.

### Invite users

The server must accept invitations: enable `zeabur-identity --invitations` or set
`ZEABUR_IDENTITY_INVITATIONS=true` in its Deployment. When generating the Deployment, pass
`--serve-arg=--invitations` to `zeabur-identityctl manifests`.

```sh
zeabur-identityctl invite --username alice --display-name 'Alice' \
  --group developers --valid-for 1d
```

`--group` is repeatable. Together with `--display-name` and `--admin`, it applies **only when
creating a new user**; inviting an existing user does not change their name, groups or account
type. Edit that user's `User` resource, or use `account-type`, to change those fields. Groups
appear to Kubernetes as `zeabur:<group>`. `--admin` makes the new user an admin account: it
signs in with a passkey only, and its tokens carry `zeabur:admins`. `--valid-for` controls how
long the link can be redeemed (default `7d`, at most `7d`). Send the printed link privately.

`invite` refuses a user who already has a passkey or a linked account: whoever holds the link
could add a passkey and sign in as that user. `--reset` first deletes the user's pending
invitations, credentials and sessions, as `setup-link --reset` does.

`invite` and `setup-link` record each link as an `Event` on the `User` (`InvitationIssued`,
`SetupLinkIssued`). If the `Event` fails, the command prints no link; your kubeconfig needs
`create` on `events` in Zeabur Identity's namespace.

### Configure token limits and the internal certificate

`kube-config` generates a maximum accepted token lifetime of `1h` (`--max-token-lifetime`).
The server issues tokens of at most 1 hour, so the default accepts all of them. A lower limit
makes kube-apiserver refuse longer tokens:

```sh
zeabur-identityctl kube-config --distro k3s --max-token-lifetime 15m
```

The default internal discovery mode needs [cert-manager](https://cert-manager.io/docs/).
`kube-config` applies a root CA (10 years), a `CA` Issuer and a serving certificate in Zeabur
Identity's namespace, waits until cert-manager issues them, and prints the root CA in the
configuration. cert-manager renews the serving certificate with its defaults (90 days, renewed
30 days before expiry). The configuration does not change when it does. Without cert-manager,
`kube-config` stops with an error; use `--discovery public` instead.

Check the certificates with `kubectl -n zeabur-identity get certificate`. To change the serving
certificate's duration, set `spec.duration` and `spec.renewBefore` on Certificate
`zeabur-identity-internal-tls` with `kubectl`; `kube-config` does not reset them. See the
[deployment guide](../../docs/get-started/quickstart.mdx) for installation steps and
[operations](../../docs/operations/backup-restore.mdx) to replace the root CA.

## Place in the workspace

Depends on `zeabur-identity-core` and `zeabur-identity-k8s`. Nothing depends on it.

## Key properties

- **Admin rights only for admin accounts.** The installed binding gives `cluster-admin` to
  `zeabur:admins`, which only accounts with `accountType: Admin` carry. Other groups get no
  rights until you bind them.
- **Secrets stay hashed.** Setup and invitation tokens and client secrets are 256-bit random
  values; only their SHA-256 is written to the cluster, and a link carries its token in the URL
  fragment.
- **Single use.** Redeeming a setup link or invitation deletes its object with `uid` and
  `resourceVersion` preconditions, so only one redemption can succeed; a new setup link
  invalidates the previous one.
