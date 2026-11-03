---
default: patch
---

# Zeabur Identity asks for 24Mi of memory instead of 32Mi

Zeabur Identity used about 6Mi in a cluster with 35 pods, so its request drops to 24Mi. The limit stays at 128Mi.
