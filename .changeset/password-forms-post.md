---
default: patch
---

# Password forms no longer put the password in the address bar

The sign-in, setup and account forms are sent with `POST`. Before, a browser that did not run the page script sent them as `GET`, and the username and password ended up in the URL.
