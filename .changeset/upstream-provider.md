---
default: major
---

# Sign-in providers are `UpstreamProvider` objects

GitHub, Google and any other OpenID provider are now `UpstreamProvider` objects in Zeabur Identity's namespace, with their client secrets in the Secret `zeabur-identity-upstream`, one key for each provider. Zeabur Identity applies a new, changed or deleted provider and a changed secret at the next sign-in, without a restart. Deleting a provider keeps its linked accounts. Any provider with the same issuer signs them in again.

The server no longer has `--github-client-id`, `--github-client-secret-file`, `--google-client-id` or `--google-client-secret-file`, or their `ZEABUR_IDENTITY_*` variables. If one is still set, the server does not start, and the log names the option and what replaces it.

To upgrade with GitHub or Google sign-in set up (the upgrade notes in "Upgrade and roll back Zeabur Identity" have the commands):

1. Save the current CRDs with the old `zeabur-identityctl crds`. A rollback needs them.
2. Apply this version's CRDs.
3. Copy each client secret into the Secret `zeabur-identity-upstream`, under the key `github` or `google`.
4. Create an `UpstreamProvider` named `github` (`type: GitHub`) or `google` (`type: OpenID`, `issuer: https://accounts.google.com`, `displayName: Google`). With these names, the callback URLs registered at GitHub and Google stay the same.
5. Regenerate the manifests with `zeabur-identityctl manifests` without the four removed options, and apply them.

When it starts, Zeabur Identity turns each linked GitHub or Google account into a `Credential` of `type: Upstream` with `provider: github` or `provider: google`. Names, owners and labels stay, so linked accounts sign in as before. A `Credential` you create for a linked account now needs `type: Upstream` and `provider`.

This change can't be undone in place: the previous version can't read `type: Upstream`, and neither version's CRD lets a credential change back. To roll back, restore the pre-upgrade backup, or, with Zeabur Identity stopped, export the `Upstream` credentials with their old type, delete them, apply the saved CRDs and create them again. Accounts linked through providers other than `github` and `google` are lost in a rollback.
