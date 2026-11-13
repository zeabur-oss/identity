---
default: major
---

# A `Credential` is a passkey or a linked account by the field it has

A `Credential` has `passkey` or `external`, exactly one, and no longer has `type` or `provider`. Credentials stored by v0.1 and v0.2.0 keep working after you apply this version's CRDs: they sign in and can be unlinked as before, with no migration. A `Credential` manifest of your own that sets `type` or `provider` fails `kubectl apply` until you remove them.

The account page names a linked account after the `UpstreamProvider` with the account's issuer.

Zeabur Identity no longer changes linked accounts when it starts, and its Role no longer has `patch` on `credentials`. The server no longer accepts `--github-client-id`, `--github-client-secret-file`, `--google-client-id` or `--google-client-secret-file`, which v0.2.0 already refused with a message. If one is still in the Deployment's `args`, the server stops with an unknown-argument error. Their `ZEABUR_IDENTITY_*` variables are ignored.
