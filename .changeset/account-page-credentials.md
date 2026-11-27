---
default: minor
---

# Add a password, replace the authenticator app and get new recovery codes on the account page

A user with a passkey and no password can add a password on the account page after a passkey confirmation. An admin who needs an authenticator app sets one up in the same step and gets recovery codes. An admin with a password can replace the authenticator app or get new recovery codes there, confirmed with a passkey or with the password and a code. The old app and the old codes stop working, and the user's other sessions end after each change. Admins no longer need a setup link with `--reset` for these cases.
