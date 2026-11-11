---
default: minor
---

# Programs that write Zeabur Identity's objects can use the zeabur-identity-api crate

The crate holds the `identity.zeabur.com` custom resources, the API group, the labels and annotations, the admin group and `token_hash`, the stored form of invitation tokens and client secrets. Depend on it with Cargo at the tag of the release you install: `zeabur-identity-api = { git = "https://github.com/zeabur-oss/identity", tag = "vX.Y.Z" }`. Its README says which objects another program may create, change or only delete.
