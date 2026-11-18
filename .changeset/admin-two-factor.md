---
default: minor
---

# Choose how admin accounts sign in

The new `admin-sign-in` key in the ConfigMap `zeabur-identity-settings` replaces `admin-aal3`. It takes `any`, `two-factor`, `passkey` or `device-bound-passkey`. The default, `two-factor`, lets admins sign in with a passkey, or with a password and a code from an authenticator app. An admin who sets a password scans a QR code on the setup page, enters a code, and gets 10 recovery codes. Each code and each recovery code works once, and wrong codes count as wrong passwords.

Zeabur Identity no longer reads `admin-aal3`. If you set it to `"true"`, set `admin-sign-in` to `device-bound-passkey` before you upgrade, or admins can sign in with any passkey or a password and code. To keep admins on passkeys only, set `admin-sign-in` to `passkey`.
