---
default: patch
---

# Releases publish `resources.json` with the memory request

`zeabur-identityctl resources` prints the total memory request of the default install as `{"requestMemoryMiB": 24}`, and each release lists the same output as `resources.json` in the signed `SHA256SUMS`, so an installer can check a server's memory before downloading anything ([release files](docs/reference/releases.mdx)).
