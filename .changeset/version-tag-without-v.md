---
default: patch
---

# The server image's version tag drops the `v`

As every zeabur-oss image and chart does: `ghcr.io/zeabur-oss/identity:0.1.2`, not `:v0.1.2`. The 0.1.1 image is also tagged `0.1.1`; its `v0.1.1` tag stays and names the same digest.
