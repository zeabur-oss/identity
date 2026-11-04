---
default: major
---

# The server no longer has `--store`

`--store` and `ZEABUR_IDENTITY_STORE` are removed, with the in-memory store that could not sign anyone in. The server always keeps its state in Kubernetes objects. The server refuses to start when it is given `--store`, so delete `--store kubernetes` from the Deployment's `args` if you set it; the chart does not.
