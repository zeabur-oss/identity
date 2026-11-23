---
default: patch
---

# Duration flags accept jiff's friendly format

`--token-lifetime`, `--refresh-idle`, `--valid-for` and the other duration flags of `zeabur-identity` and `zeabur-identityctl` now also accept compound and ISO 8601 values, such as `1h30m`, `1w` or `PT10M`. Every value they accepted before keeps its meaning, up to about 20,000 years. A value of zero, a negative value, or one in months or years is refused with the name of the flag.
