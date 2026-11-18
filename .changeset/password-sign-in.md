---
default: minor
---

# Regular users can sign in with a password

The setup page leads with **Create passkey** and offers **Use a password** among the other ways; it no longer asks for a passkey name, which users can set on the account page. The sign-in page asks for a username and password, with the passkey and the providers below. Passwords have at least 15 characters and are checked against a list of common passwords. Each browser where the user has signed in keeps its own count of wrong guesses, so guesses from elsewhere can't lock the user out.

Zeabur Identity keeps the key it mixes into password hashes in the new Secret `zeabur-identity-password-key`. The installer creates it empty, Zeabur Identity fills it at startup, and the Role lets Zeabur Identity read and update it. Back it up with the signing keys.
