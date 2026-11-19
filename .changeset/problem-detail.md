---
default: patch
---

# Refusals from the sign-in endpoints say why in the page language

Each RFC 9457 problem now carries `detail`, its message in the language of the request's `Accept-Language`, and, where they apply, `refresh` (the page shows a list that changed) and `next` (`code`, `ended`, `new-link` or `reauth`). The sign-in pages show `detail` instead of keeping their own message for each problem.
