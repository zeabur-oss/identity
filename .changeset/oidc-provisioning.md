---
default: minor
---

# OpenID Connect providers can create users at first sign-in

Set `provisioning` on an `UpstreamProvider` to create a regular `User` the first time an account signs in, when a claim in its ID token, such as a group or a Google Workspace `hd`, has one of the values you list. The username comes from `preferred_username` or `email`. Zeabur Identity's role can now create users, but not change or delete them. Upgrade as described in "Upgrade and roll back Zeabur Identity" so the new CRD and role are applied.
