---
default: major
---

# GitHub and Google sign-in are `UpstreamProvider` objects

`--github-client-id`, `--github-client-secret-file`, `--google-client-id` and `--google-client-secret-file`, and their `ZEABUR_IDENTITY_*` environment variables, are removed. GitHub and Google are now `UpstreamProvider` objects of `type: GitHub` or `type: Google`, like other providers, with their client secrets in the Secret `zeabur-identity-upstream`, and changes apply without a restart. The server and `zeabur-identityctl manifests` refuse the removed options. When upgrading, apply the new CRDs, then run `zeabur-identityctl upstream migrate` before applying the new manifests: it creates the providers `github` and `google` from the running Deployment's options and copies their client secrets. Callback URLs and linked accounts stay the same. See "Upgrade and roll back Zeabur Identity" in the docs.
