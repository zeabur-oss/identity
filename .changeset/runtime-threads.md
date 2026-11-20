---
default: patch
---

# The server starts one worker thread per CPU

The server used to start two Tokio worker threads. It now starts one per CPU that the container can use, which is Tokio's default.
