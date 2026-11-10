---
default: major
---

# Google sign-in reads Google's endpoints from its discovery document

Before Zeabur Identity sends a user to Google, it reads `https://accounts.google.com/.well-known/openid-configuration` and then uses the sign-in, token and key addresses listed there. If your cluster limits outgoing traffic, also allow HTTPS to `accounts.google.com`, in addition to `oauth2.googleapis.com` and `www.googleapis.com`. If the document cannot be read or names a different issuer, **Continue with Google** shows an error and the server log records `provider_unavailable`. Zeabur Identity never falls back to built-in addresses.
