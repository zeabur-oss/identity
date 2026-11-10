---
default: patch
---

# Sign-in buttons show each provider by its display name

The sign-in and setup pages show a **Continue with** button for each `UpstreamProvider`, under the passkey option, in the order of the provider names. A provider that is neither GitHub nor Google has a sign-in icon instead of the passkey icon. A long display name is shortened with an ellipsis and no longer makes the page wider than the screen. The same applies to the link buttons on the account page.
