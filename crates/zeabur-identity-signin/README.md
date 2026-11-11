# zeabur-identity-signin

How a person proves who they are to Zeabur Identity: passkey enrolment with a one-time link, passkey
sign-in, sign-in with an upstream identity provider (GitHub, Google), and the routes in front of
the sign-in pages.

## Entry points

| Router | Routes |
|---|---|
| `router` | `POST /setup/options`, `POST /setup` (enrol), `POST /login/options`, `POST /login`, and the `account` routes: `GET /account`, `POST /account/…`, `GET /.well-known/passkey-endpoints` |
| `upstream::router` | `POST /upstream/{provider}/start`, `POST /account/links/start`, `GET /upstream/{provider}/callback` |
| `pages::router` | `GET /login`, `GET /setup`, `GET /assets/{name}` |

`passkeys` wraps webauthn-rs as the relying party, `upstream::provider` talks to GitHub and
to OpenID providers such as Google, which it finds through their discovery documents, and `problem` renders errors as RFC 9457 problem details ([RFC 9457 §3][rfc9457]).

Depends on `zeabur-identity-core`, `zeabur-identity-keys` (upstream ID token signatures), `zeabur-identity-store` (users,
credentials, enrolment tokens), `zeabur-identity-oauth` (the pending authorization request a sign-in
completes) and `zeabur-identity-ui` (page rendering). Used by the `zeabur-identity` server and the end-to-end
tests; `zeabur-identity-test-support` provides the software authenticator for the tests.

## Design

- **Enrolment links.** A link is `https://<issuer>/setup#token=…`: the cluster admin's setup token,
  or an invitation token `<invitation>.<secret>`. The token sits in the URL fragment, so it never
  reaches the server or proxy logs; the page script posts it. Only its SHA-256 is stored. Zeabur Identity
  never creates users or tokens; an admin does, with their own Kubernetes credentials.
- **Single use.** The token is checked (constant-time hash comparison and expiry) when the
  ceremony starts and again when it finishes. It is consumed only after the registration
  verifies, so an abandoned attempt does not burn the link, and before the credential is stored,
  through a conditional write in the store that exactly one concurrent redemption wins. A racing
  first-admin endpoint is a known failure (Pocket ID advisory [GHSA-x6w5-6mr5-mxrx][pocketid]).
- **Passkeys.** Discoverable credentials with user verification required at registration and at
  every assertion ([WebAuthn Level 3 §5.4.6, §7.1, §7.2][webauthn]), attestation `none`, and
  relying party ID equal to the issuer's host, so a passkey cannot be used on another origin.
  The assertion's user handle must be the credential owner's. A passkey sign-in asserts
  `amr = ["swk", "mfa"]` ([RFC 8176 §2][rfc8176]); synced passkeys reach AAL2 in
  [NIST SP 800-63B-4][nist] terms. Every sign-in failure returns the same `passkey-failed`
  problem, so responses do not reveal which users or credentials exist.
- **Ceremony state without a write.** webauthn-rs state is sealed with a process key into the
  `__Host-zeabur-identity-webauthn` cookie (`SameSite=Strict`, five minutes), bound to its purpose; the
  ceremony ID is recorded once it verifies, so a captured response cannot be replayed.
- **Cross-site requests.** Every JSON endpoint requires `Sec-Fetch-Site: same-origin`
  ([Fetch Metadata][fetchmeta]) or, failing that header, an `Origin` equal to the issuer, plus an
  `application/json` body, as the [OWASP CSRF guidance][owasp] recommends. Cookies use the
  `__Host-` prefix ([RFC 6265bis][rfc6265bis]) because cookies lack integrity against
  related-domain attackers ([Zheng et al.][zheng], [Squarcina et al.][squarcina]).
- **Account page.** `/account` signs in with a passkey into a one-hour session stored as a
  `Grant` named `s-…` (client `zeabur_identity`, which no OAuth client can have, and a name a
  refresh token cannot use). The `__Host-zeabur-identity-session` cookie is `HttpOnly` and
  `SameSite=Lax`; changes also need a CSRF token derived from the session secret. Every read and
  write is filtered to the session's user by name and UID. Adding or removing a passkey, and
  linking or unlinking an upstream account, needs a user-verified assertion from the last five
  minutes by one of the user's own passkeys (Kanidm's privilege window works the same way). The
  last passkey cannot be removed, and an upstream account cannot be unlinked if the user has no
  other credential; the Kubernetes store makes both hold under concurrent changes with
  `resourceVersion` preconditions. Removing a passkey or unlinking an account revokes every
  session and grant it signed in. Changes are
  logged to `zeabur_identity::audit` and recorded as `Event`s on the `User`. A redeemed setup
  link or invitation is recorded the same way (`SetupLinkRedeemed`, `InvitationRedeemed`).
- **Upstream providers.** An upstream account signs in only if it was linked to a user, either
  by redeeming an enrolment link with it, by linking it on the account page, or by an admin
  creating the `Credential`; nothing is created on first sign-in. A link from the account page
  binds the sealed state to the session, user and UID that started it, so the callback links
  nothing unless the same session is still signed in ([RFC 6749 §10.12][rfc6749]). An account
  that is already linked to any user is refused. Accounts are keyed by the provider's stable identifier (GitHub's
  numeric ID, Google's `sub`), never a login name or email. `state`, `nonce` and the PKCE
  verifier ([RFC 7636][rfc7636]) travel in a sealed `__Host-` cookie with `SameSite=Lax`, the
  strictest setting that survives the provider's redirect back. Google ID tokens are validated
  as [OpenID Connect Core 1.0 §3.1.3.7][oidc] requires.
- **Admin accounts are passkey-only.** Upstream sign-ins carry no `amr` value and give no
  evidence of user verification, so an admin account can neither sign in with GitHub or Google
  nor link either; the page says "Use a passkey for this account". With the install-wide
  `admin-aal3` setting, an admin account also needs a device-bound passkey (WebAuthn BE flag
  unset) at sign-in and at enrolment. The authenticator reports BE itself; attestation is
  `none`, so nothing verifies it.

## References

- W3C, "Web Authentication: An API for accessing Public Key Credentials, Level 3," W3C
  Recommendation, Aug. 2026. <https://www.w3.org/TR/webauthn-3/>
- M. Jones, P. Hunt, and A. Nadalin, "Authentication Method Reference Values," RFC 8176, IETF,
  Jun. 2017. <https://www.rfc-editor.org/rfc/rfc8176>
- M. Nottingham, E. Wilde, and S. Dalal, "Problem Details for HTTP APIs," RFC 9457, IETF,
  Jul. 2023. <https://www.rfc-editor.org/rfc/rfc9457>
- N. Sakimura, J. Bradley, and N. Agarwal, "Proof Key for Code Exchange by OAuth Public
  Clients," RFC 7636, IETF, Sep. 2015. <https://www.rfc-editor.org/rfc/rfc7636>
- S. Bingler, M. West, and J. Wilander, Eds., "Cookies: HTTP State Management Mechanism,"
  Internet-Draft draft-ietf-httpbis-rfc6265bis, IETF, work in progress.
  <https://datatracker.ietf.org/doc/draft-ietf-httpbis-rfc6265bis/>
- NIST, "Digital Identity Guidelines: Authentication and Authenticator Management,"
  SP 800-63B-4, Jul. 2025. <https://pages.nist.gov/800-63-4/sp800-63b.html>
- W3C, "Fetch Metadata Request Headers," W3C Working Draft.
  <https://www.w3.org/TR/fetch-metadata/>
- OWASP Foundation, "Cross-Site Request Forgery Prevention Cheat Sheet."
  <https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html>
- N. Sakimura, J. Bradley, M. Jones, B. de Medeiros, and C. Mortimore, "OpenID Connect Core 1.0
  incorporating errata set 2," OpenID Foundation, Dec. 2023.
  <https://openid.net/specs/openid-connect-core-1_0.html>
- X. Zheng, J. Jiang, J. Liang, H. Duan, S. Chen, T. Wan, and N. Weaver, "Cookies Lack
  Integrity: Real-World Implications," in *Proc. 24th USENIX Security Symp.*, 2015,
  pp. 707–721. <https://www.usenix.org/conference/usenixsecurity15/technical-sessions/presentation/zheng>
- M. Squarcina, P. Adão, L. Veronese, and M. Maffei, "Cookie Crumbles: Breaking and Fixing Web
  Session Integrity," in *Proc. 32nd USENIX Security Symp.*, 2023, pp. 5539–5556.
  <https://www.usenix.org/conference/usenixsecurity23/presentation/squarcina>
- Pocket ID, "Concurrent initial setup requests create multiple unauthenticated
  administrators," GitHub security advisory GHSA-x6w5-6mr5-mxrx.
  <https://github.com/pocket-id/pocket-id/security/advisories/GHSA-x6w5-6mr5-mxrx>

[webauthn]: https://www.w3.org/TR/webauthn-3/
[rfc8176]: https://www.rfc-editor.org/rfc/rfc8176
[rfc9457]: https://www.rfc-editor.org/rfc/rfc9457
[rfc7636]: https://www.rfc-editor.org/rfc/rfc7636
[rfc6749]: https://www.rfc-editor.org/rfc/rfc6749#section-10.12
[rfc6265bis]: https://datatracker.ietf.org/doc/draft-ietf-httpbis-rfc6265bis/
[nist]: https://pages.nist.gov/800-63-4/sp800-63b.html
[fetchmeta]: https://www.w3.org/TR/fetch-metadata/
[owasp]: https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html
[oidc]: https://openid.net/specs/openid-connect-core-1_0.html
[pocketid]: https://github.com/pocket-id/pocket-id/security/advisories/GHSA-x6w5-6mr5-mxrx
[zheng]: https://www.usenix.org/conference/usenixsecurity15/technical-sessions/presentation/zheng
[squarcina]: https://www.usenix.org/conference/usenixsecurity23/presentation/squarcina
