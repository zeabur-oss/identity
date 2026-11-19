---
default: patch
---

# `zeabur-identityctl kube-config` writes the kube-apiserver configuration as JSON

The file still starts with a comment line and still goes to `authn.yaml`: kube-apiserver reads JSON as YAML. The certificate authority is now one string with `\n` line breaks instead of a block.
