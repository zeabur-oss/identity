---
default: major
---

# The server no longer has flags for key timings, metadata caching, worker threads or the key Secret's name

`--key-rotation-period`, `--key-publish-ahead`, `--key-retain-after`, `--metadata-max-age`, `--worker-threads` and `--key-secret`, and their `ZEABUR_IDENTITY_*` environment variables, are removed. The server always uses the former defaults: keys sign for 7 days, are published 24 hours ahead and kept 24 hours after, discovery documents are cached for 5 minutes, there are 2 worker threads, and the signing keys are in the Secret `zeabur-identity-signing-keys`. The server refuses to start when it is given one of the removed flags. If your deployment passes one, delete it from the Deployment's `args` and `env`; the chart sets none of them.
