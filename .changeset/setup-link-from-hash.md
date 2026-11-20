---
default: minor
---

# `zeabur-identity setup-link` stores a setup token made elsewhere

`zeabur-identity setup-link --token-hash sha256:<hex>` runs in the cluster with the pod's service account and stores the first administrator's setup token from its hash, as `zeabur-identityctl setup-link` does. A Helm chart can make the token, print the link in its notes, and run this in a hook Job, which never sees the token. If the user can already sign in, it changes nothing.
