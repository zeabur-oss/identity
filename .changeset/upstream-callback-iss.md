---
default: patch
---

# Upstream sign-in refuses a return from the provider whose `iss` names another issuer

When GitHub or Google sends the browser back with an `iss` parameter, Zeabur Identity compares it with the issuer it sent the user to. If the value differs, is empty or appears twice, the sign-in or account linking ends with an error before the code is used. The audit log records `issuer_mismatch`. If `iss` is missing, sign-in and account linking work as before. A sign-in that was in progress during the upgrade ends with an error. Start it again.
