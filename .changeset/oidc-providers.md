---
default: minor
---

# Sign in with your organization's OpenID Connect provider

Regular accounts can sign in with any OpenID Connect provider, such as Keycloak, Authentik, Microsoft Entra ID or Okta. Add the provider as an `UpstreamProvider` object, put its client secret in the Secret `zeabur-identity-upstream`, and link accounts as with GitHub and Google. Changes apply without a restart. Apply the new `deploy/crds.json` and `deploy/rbac.json` first. See "Let users sign in with your identity provider" in the docs.
