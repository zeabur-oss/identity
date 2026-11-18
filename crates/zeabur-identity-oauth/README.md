# zeabur-identity-oauth

The OAuth 2.0 / OpenID Connect authorization server of Zeabur Identity: the authorization endpoint,
codes with PKCE, the token endpoint, refresh-token families, pushed authorization requests
(PAR), revocation, UserInfo and provider metadata. Its access tokens are meant to be verified
offline by kube-apiserver's structured authentication configuration.

## Entry points

- `endpoints::router`: `/authorize`, `/token`, `/par`, `/revoke` and `/userinfo`.
  `endpoints::complete_authorization` is how a sign-in method hands an authenticated user back.
- `discovery::ProviderMetadata` (the discovery document) and `metadata::router` (serves it,
  the JWK set and the health endpoints).
- `AuthorizationServer`: shared state; `Lifetimes::DEFAULT` holds the default lifetimes.
- `authorize`, `code`, `pkce`, `refresh`, `tokens`, `client_auth`, `userinfo`: the protocol
  pieces, each documented with the rules it implements.

## Workspace dependencies

Depends on `zeabur-identity-core` (clock, issuer URL, sealing and hashing), `zeabur-identity-keys` (signing keys
and JWS), `zeabur-identity-store` (the `Directory` and `GrantStore` ports) and `zeabur-identity-ui` (the error
page). Used by `zeabur-identity` (the server), `zeabur-identity-signin` (which calls `complete_authorization`),
`zeabur-identity-k8s` and the end-to-end tests.

## Security properties

- No request writes to storage before the user has authenticated. The validated request and
  the code are sealed under a key that exists only in the process; a restart fails closed.
- PKCE S256 is required for every client; `plain` is rejected (RFC 9700 §2.1.1, RFC 7636).
- Codes live 60 seconds and are single-use; a replayed code revokes what it issued
  (RFC 6749 §4.1.2).
- Refresh tokens rotate; a replayed one revokes its whole family (RFC 9700 §4.14.2). Only
  SHA-256 hashes of refresh secrets are stored.
- Access tokens (RFC 9068) and ID tokens differ in their claims, not only in `typ`, because
  kube-apiserver does not check `typ`. Each access token has exactly one audience from the
  client's allowlist.
- UserInfo resolves the immutable `sub` UID through directory metadata, then directly reads
  the user and checks the UID and disabled state. Stale index entries and recreated objects
  cannot substitute another identity. Access-token claims are unchanged; existing tokens
  remain usable without refresh.
- Token and session lifetimes follow the account type and the install-wide settings
  (`Lifetimes::for_account`). Regular: access token 10 min, refresh idle 1 h. Admin: access
  token 5 min, refresh idle 1 h, or 15 min with several teams or `admin-sign-in: device-bound-passkey`. Every refresh family ends
  12 h after the sign-in. Only admin accounts' tokens carry the `admins` group. The account type
  and settings are read again at every refresh.
- `auth_time` is the passkey or upstream sign-in and survives refresh. There is no single
  sign-on session, so every authorization request is a fresh sign-in and `max_age` is always
  met. The token response adds `refresh_expires_in`: the seconds until the refresh token goes
  idle.
- Every redirect is `303 See Other` and carries `iss` (RFC 9207).

## Event logs

Token and revocation outcomes use the `zeabur_identity::audit` tracing target. `oauth.code_exchange`
and `oauth.refresh` succeed only after all requested tokens have been signed. These operations are not fresh sign-ins. Failures are
emitted at the handler's final result boundary with a fixed OAuth reason, or `not_form`.
Only an authenticated client is recorded; issuance success uses the already-verified local
user name and subject.

`oauth.replay` and `oauth.client_binding` describe detection before attempted deletion, not
proof that deletion succeeded. `oauth.revocation_request` with `outcome=success` and
`reason=accepted` means the request was accepted, including RFC 7009's invalid-token no-op.
Storage and signing diagnostics retain their module targets and fixed categorical reasons,
and include full error details. Audit records omit tokens, codes, credentials, groups and raw
errors; operational and dependency diagnostics do not share this guarantee. See the server
README for stdout formatting, filtering and best-effort collection limits.

## References

- [RFC 6749] OAuth 2.0; [RFC 7636] PKCE; [RFC 9700] OAuth 2.0 Security BCP; [RFC 9068] JWT
  access tokens; [RFC 9126] PAR; [RFC 7009] revocation; [RFC 9207] issuer identification.
- [OpenID Connect Core 1.0] and [OpenID Connect Discovery 1.0]; [RFC 8414] server metadata.

[RFC 6749]: https://www.rfc-editor.org/rfc/rfc6749
[RFC 7636]: https://www.rfc-editor.org/rfc/rfc7636
[RFC 9700]: https://www.rfc-editor.org/rfc/rfc9700
[RFC 9068]: https://www.rfc-editor.org/rfc/rfc9068
[RFC 9126]: https://www.rfc-editor.org/rfc/rfc9126
[RFC 7009]: https://www.rfc-editor.org/rfc/rfc7009
[RFC 9207]: https://www.rfc-editor.org/rfc/rfc9207
[RFC 8414]: https://www.rfc-editor.org/rfc/rfc8414
[OpenID Connect Core 1.0]: https://openid.net/specs/openid-connect-core-1_0.html
[OpenID Connect Discovery 1.0]: https://openid.net/specs/openid-connect-discovery-1_0.html
