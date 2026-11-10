---
default: minor
---

# `zeabur-identityctl client create --output json` prints the client ID, the secret and the manifest as one JSON object

A script can read the new client's secret and its `OAuthClient` from stdout in one step. A confidential client's secret is in `secret`, and the command prints nothing on stderr in this mode. A public client has no `secret` field. Without `--output json`, the command prints the `OAuthClient` as before.
