---
default: patch
---

# The Identity URL opens the account page

Opening the bare Identity URL, such as `https://identity.<ip>.sslip.io/`, now redirects to `/account`, which offers sign-in when there is no session. Before, the browser downloaded an empty file. An unknown path now answers `404` with a short plain-text page instead of an empty, untyped response.
