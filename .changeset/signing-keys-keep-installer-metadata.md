---
default: patch
---

# Saving signing keys no longer breaks helm upgrade

Zeabur Identity now changes only the keys in the Secret `zeabur-identity-signing-keys` and keeps the labels and annotations the installer set. Before, it replaced them with its own label, so a later server-side `helm upgrade` failed with a conflict on `app.kubernetes.io/managed-by`, and `helm.sh/resource-policy: keep` was lost. Its writes to the Kubernetes API now have the field manager `zeabur-identity` instead of `unknown`.
