# zeabur-identity-api

The `identity.zeabur.com/v1alpha1` custom resources (`User`, `Credential`, `OAuthClient`, `Grant`,
`Invitation` and `UpstreamProvider`) and the names that Zeabur Identity shares with the programs that write these
objects: the API group, the labels and annotations, the admin group, and
`token_hash`, the stored form of tokens and client secrets.

## Use it

Each release tag of `zeabur-oss/identity` is a version of this crate, with the version of the
release. Depend on the tag of the Zeabur Identity release that you install:

```toml
[dependencies]
zeabur-identity-api = { git = "https://github.com/zeabur-oss/identity", tag = "v0.2.0" }
```

The crate depends only on `k8s-openapi`, `kube`, `schemars`, `serde`, `serde_json`, `thiserror`,
`url` and `aws-lc-rs`. It holds no client and does no I/O.

## Two roles of Zeabur Identity

Zeabur Identity has two roles. The types in this crate belong to one or both of them.

- **It signs people in.** A person signs in with a passkey, or with a linked account at an upstream
  provider. An `UpstreamProvider` configures a provider: GitHub, or an OpenID provider such as
  Google or Keycloak. A `Credential` holds each passkey and each linked account. For a linked
  account, `spec.external` holds the upstream issuer and subject, and that pair identifies the
  account. The `upstream` module has their types, `Issuer`, `Subject` and `ExternalId`, which
  check the syntax and keep the bytes as they are.
- **It is an OpenID provider for registered applications.** An `OAuthClient` registers an
  application, for example `kubectl`, Argo CD or Grafana. Zeabur Identity signs its ID tokens with
  ES256, or with RS256 if the client sets `idTokenSigningAlg`. A `Grant` holds the refresh-token
  family of one sign-in.

## What another program may write

| Object | Supported | Not supported |
|---|---|---|
| `User` | Create it, change `spec` (groups, `disabled`, `accountType`), delete it. | Put `admins` in `spec.groups`: an account gets the admin group only from `accountType: Admin`. |
| `Invitation` | Create one as described below, and delete it to cancel. | Change one after creation: its `spec` is immutable. |
| `OAuthClient` | Create, change and delete it. A confidential client stores `token_hash` of its secret in `spec.secretHash`. | A secret that a person chose: the hash is unsalted, so only a random secret of 256 bits is safe. |
| `Credential` | List it, and delete it to revoke a passkey or unlink an account. | Create or change it. Zeabur Identity writes it when a person enrols a passkey or links an account, and its name is derived from the credential. |
| `Grant` | List it, and delete it to end a sign-in. | Create or change it. |
| `UpstreamProvider` | Create, change and delete it. Put its client secret in the Secret `upstream_provider::SECRET` under the object name. | A client secret in the object itself. |

To invite a person, write an `Invitation` the way `zeabur-identityctl invite` does:

1. Make a token `<invitation name>.<secret>`, with 32 random bytes as unpadded base64url for the
   secret.
2. Set `spec.user` to the `User`'s name, `spec.tokenHash` to `token_hash` of
   the whole token, and `spec.expiresAt` in Unix seconds.
3. Set an owner reference to the `User`. Zeabur Identity refuses an invitation for a `User` with
   another UID.
4. Set the label `USER_LABEL`, and set
   `EXPIRES_AT_ANNOTATION` and
   `EXPIRY_BUCKET_LABEL` so that the garbage collector deletes it.
5. Give the person the link `<issuer>/setup#token=<token>`. The server redeems it only if it runs
   with `--invitations`.

An admin account (`accountType: Admin`) signs in only with a passkey, never with a linked
account. The tokens of an admin account carry the group `ADMIN_GROUP`, which
Kubernetes sees with the `IDENTITY_PREFIX` as `zeabur:admins`.

## Place in the workspace

`zeabur-identity-api` depends on no other workspace crate, so a program can depend on it without
the server's code. `zeabur-identity-keys`, `zeabur-identity-store`, `zeabur-identity-oauth`,
`zeabur-identity-signin`, `zeabur-identity-k8s`, the `zeabur-identity` server and the
`zeabur-identityctl` admin CLI depend on it.
