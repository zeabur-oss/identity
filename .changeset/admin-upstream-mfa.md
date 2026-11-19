---
default: minor
---

# Admins sign in through an OpenID provider that enforces a second factor

An `UpstreamProvider` with `openid` takes `mfa: Enforced` for a provider you run that asks every sign-in for a second factor, such as Microsoft Entra ID or Keycloak. Under the default `admin-sign-in: two-factor`, admin accounts can sign in with and link accounts from such a provider; its tokens carry `amr: ["mfa"]`. Zeabur Identity does not check the setting. Providers without it, GitHub and Google included, still sign admins in only under `any`. The account page now offers admins the providers they may link.
