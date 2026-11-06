---
default: minor
---

# Sign in with your organization's OpenID Connect provider

Regular accounts can sign in with any OpenID Connect provider, such as Keycloak, Authentik, Microsoft Entra ID or Okta. Add the provider as an `UpstreamProvider` object, put its client secret in the Secret `zeabur-identity-upstream`, and link accounts as with GitHub and Google. Changes apply without a restart. Upgrade as described in "Upgrade and roll back Zeabur Identity" so the new CRD and role are applied. See "Let users sign in with your identity provider" in the docs.
