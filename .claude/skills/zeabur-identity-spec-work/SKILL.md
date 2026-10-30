---
name: zeabur-identity-spec-work
description: Implement or change a protocol behaviour in Zeabur Identity (OAuth, OpenID Connect, WebAuthn, Kubernetes authentication) the way the codebase expects — from the specification text, with citations, adversarial tests and a conformance entry. Use for any security-relevant feature or fix.
---

# Specification-driven work

Follow `zeabur-oss-spec-work` (install: `npx skills add zeabur-oss/skills --skill
zeabur-oss-spec-work`; `skills-lock.json` pins it): read the source, cite it in rustdoc, fail
closed, test the attack. In Zeabur Identity also:

1. **Single-use things** (codes, links, ceremonies, PAR URIs, upstream `state`) are consumed by
   one atomic step (create-once, compare-and-swap, delete with `uid`/`resourceVersion`
   preconditions) before anything is issued.
2. **Cluster tests** for admission or RBAC: `zeabur-identity-cluster-tests`.
3. **Record conformance.** Add or update the row in `docs/reference/conformance.mdx`: section,
   requirement, level, code path, test name, status. Partial or not implemented is fine when
   stated plainly.
