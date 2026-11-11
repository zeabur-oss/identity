---
default: patch
---

# The account page no longer uses a per-session CSRF token

Changes on `/account` are refused unless the request is same-origin (`Sec-Fetch-Site: same-origin`, or an `Origin` equal to the issuer when the header is missing) and has a JSON body. A request with neither header, with `Sec-Fetch-Site: cross-site` or `same-site`, or without a JSON content type is refused as before. The `csrf` field is no longer sent or read, and the `csrf` problem type is gone.
