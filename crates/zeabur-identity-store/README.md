# zeabur-identity-store

Storage interfaces (ports) for Zeabur Identity, with in-memory adapters for tests.
The Kubernetes adapters, backed by the `User`, `Credential`, `OAuthClient`, `Grant` and
`Invitation` custom resources, live in `zeabur-identity-k8s`. The one-time setup token lives in a Secret.

## Ports

- `Directory`: clients and users, read-only.
- `GrantStore`: refresh-token families (`Grant`), with `classify` deciding what a presented
  token means.
- `CredentialStore`: passkeys and linked upstream accounts.
- `SetupStore`: the one-time setup token and invitations.

Each port has a `Memory*` adapter in this crate.

## Workspace dependencies

Depends on `zeabur-identity-core` (clock, constant-time comparison, hashing) and `zeabur-identity-keys` (the
signing algorithm of a client's ID tokens). Used by `zeabur-identity-oauth`, `zeabur-identity-signin`,
`zeabur-identity-k8s` and `zeabur-identity`.

## Design rules

- Every security-relevant operation is one atomic backend step: create with a deterministic
  name (insert-once), replace if unchanged (compare-and-swap), or delete if unchanged. On
  Kubernetes these are a create, an update carrying `resourceVersion`, and a delete with `uid`
  and `resourceVersion` preconditions.
- Lost races are outcomes (`AlreadyExists`, `Replay`, `AlreadyUsed`, `Conflict`), never
  errors. `StoreError` means the backend failed or answered ambiguously, and callers fail
  closed: an error is never treated as success.
- Only hashes of secrets are stored: refresh tokens, client secrets, setup and invitation
  tokens. Passkeys are public-key records.
- Object names derived from secrets or external identifiers are SHA-256 based, so names
  reveal nothing and a duplicate fails on create.
- There is no port for pre-authentication state: pending sign-ins, WebAuthn challenges and
  codes are sealed or kept in process memory, so anonymous requests cannot write to storage.

## References

- [RFC 6749] OAuth 2.0 (§4.1.2 single-use codes); [RFC 9700] OAuth 2.0 Security BCP (§4.14
  refresh-token reuse detection).
- [Kubernetes API concepts] (optimistic concurrency) and [DeleteOptions] (preconditions).
- [WebAuthn Level 3] §7.1 (duplicate credential IDs).

[RFC 6749]: https://www.rfc-editor.org/rfc/rfc6749
[RFC 9700]: https://www.rfc-editor.org/rfc/rfc9700
[Kubernetes API concepts]: https://kubernetes.io/docs/reference/using-api/api-concepts/
[DeleteOptions]: https://kubernetes.io/docs/reference/kubernetes-api/common-definitions/delete-options/
[WebAuthn Level 3]: https://www.w3.org/TR/webauthn-3/
