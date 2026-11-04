---
default: major
---

# The server no longer has `--upstream-ca-file`

`--upstream-ca-file` and `ZEABUR_IDENTITY_UPSTREAM_CA_FILE` are removed. GitHub and Google use public CAs, which the image's CA bundle already trusts. If your cluster reaches them through a proxy that re-signs TLS with its own CA, mount that CA into a directory and set both `SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt` (the image's bundle) and `SSL_CERT_DIR=<that directory>` on the Deployment. Setting `SSL_CERT_DIR` alone replaces the image's bundle.
