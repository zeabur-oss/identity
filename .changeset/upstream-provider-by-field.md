---
default: major
---

# An `UpstreamProvider` is OpenID or GitHub by the field it has

An `UpstreamProvider` has `clientId` and exactly one of `openid` or `github`. It no longer has `type` or `clientSecretKey`, and `issuer`, `displayName` and `scopes` move into `openid`:

```yaml
spec:
  clientId: 1234-abc.apps.googleusercontent.com
  openid:
    issuer: https://accounts.google.com
    displayName: Google
---
spec:
  clientId: Ov23li...
  github: {}
```

The client secret is the key with the object name in the Secret `zeabur-identity-upstream`. `displayName` is optional and defaults to the object name.

The server does not start while an `UpstreamProvider` written for v0.2.0 is stored. After you apply this version's CRDs, apply each provider again in the new form; the upgrade notes have the commands. If a key in `zeabur-identity-upstream` differs from its provider's name, copy the secret to a key with that name.
