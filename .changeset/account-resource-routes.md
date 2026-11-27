---
default: minor
---

# Use resource routes for the account page and type its requests

The account page now changes a credential or session with the HTTP method that fits it. `PATCH /account/passkeys/{name}` renames a passkey. `DELETE` on `/account/passkeys/{name}`, `/account/links/{name}` and `/account/sessions/{name}` removes one. `DELETE /account/sessions` ends every other session, and `DELETE /account/session` signs out. `POST`, `PUT` and `DELETE /account/password` add, change and remove the password, and `PUT /account/authenticator` replaces the authenticator app. The old paths, such as `/account/passkeys/remove` and `/account/sign-out`, are gone. Only the server's own pages called them.

`ui/src/contract.ts` now also holds the request types and a table of every route the pages call, with its method and path. The server writes it from its own types, a test fails when it is stale, and the pages call the server only through it.
