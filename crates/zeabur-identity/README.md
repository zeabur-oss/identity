# zeabur-identity

The Zeabur Identity server: a passkey-first OpenID Connect issuer that runs as one pod in the cluster
whose kube-apiserver accepts its tokens. This crate is the `zeabur-identity` binary plus a small library
(used by its tests) that wires configuration, storage, keys and HTTP together.

## Contents

- [`cli`](crate::cli): the flags. Every flag also has a `ZEABUR_IDENTITY_*` environment variable, the
  form a Deployment sets; with this few values, no configuration file is needed.
- [`config`](crate::config): the validated configuration, checked before the runtime starts
  (exit code 2 on error).
- [`serve`](crate::serve): starts the background tasks and the public listener.
- [`internal`](crate::internal): the in-cluster TLS listener that kube-apiserver fetches
  discovery and keys from.
- [`output`](crate::output): the only code that writes to stdout or stderr outside the logger.

## Two binaries

`zeabur-identity` is only the in-cluster server; the container image holds nothing else. Everything an
administrator does (printing the install manifests, issuing setup links and invitations,
having cert-manager issue the internal certificate and printing the kube-apiserver configuration) lives in
`zeabur-identityctl`, which runs with the administrator's own kubeconfig. The server's service account
could not do those things anyway: it cannot create Secrets, users or RBAC bindings.

## Place in the workspace

Depends on every library crate: `zeabur-identity-core`, `zeabur-identity-keys`, `zeabur-identity-store`, `zeabur-identity-tls`,
`zeabur-identity-ui`, `zeabur-identity-oauth`, `zeabur-identity-signin` and `zeabur-identity-k8s`.
Nothing depends on it.

## Key properties

- **Fails closed at startup.** Signing keys are loaded or created before the port is bound; the
  Kubernetes directory's metadata watches must also publish their initial snapshots within
  30 s. Startup failure stops background watchers rather than exposing a partially initialized
  server. `/healthz` answers once the process runs, `/readyz` once keys are published.
  The generated Deployment uses a two-minute startup probe budget before enabling normal
  liveness/readiness checks, so slow initialization is not mistaken for a deadlock.
- **Small and bounded.** A Tokio runtime with two worker threads (one would work; two keep a
  slow request from stalling the key rotator) and axum on HTTP/1.1. Every request body is at most
  16 KiB, handled within 10 s. Each business route/method service independently permits 64
  concurrent handlers, including page assets; metadata and probes use no business slots.
  Saturated services fail immediately with `503`, `Retry-After: 1` and `Cache-Control: no-store`;
  they never queue outside the timeout or borrow another route's slots. Overload events are
  DEBUG-only, avoiding per-rejection log writes at the default INFO level.
  Per-source-IP rate limiting belongs at the ingress; see [the deployment guide].
  The end-to-end test requires the pod's working set after a sign-in to stay within 30 MiB.
- **TLS ends in front of the public listener** (ingress or gateway). The issuer is an `https`
  URL ([OIDC Discovery] §3, [RFC 8414] §2) without a path, so the OpenID and OAuth metadata
  locations coincide at the root ([RFC 8414] §3), and it must match kube-apiserver's
  `issuer.url` byte for byte.
- **Short tokens.** Access tokens default to 10 minutes (`--token-lifetime` or
  `ZEABUR_IDENTITY_TOKEN_LIFETIME`), with an allowed range of 1 minute to 1 hour ([RFC 6750] §5.3).
  Admin accounts' tokens default to 5 minutes (`--admin-token-lifetime` or
  `ZEABUR_IDENTITY_ADMIN_TOKEN_LIFETIME`), with the same range. kube-apiserver cannot revoke
  these tokens, and it refuses tokens longer than `zeabur-identityctl kube-config
  --max-token-lifetime` (1 hour by default).
- **Sessions end.** A refresh-token family ends after `--refresh-idle` (1 hour) without use and
  `--refresh-absolute` (12 hours) after the sign-in. An admin family idles out after
  `--admin-refresh-idle` (15 minutes, `ZEABUR_IDENTITY_ADMIN_REFRESH_IDLE`) when the `ConfigMap`
  `zeabur-identity-settings` says `teams: multiple` or `admin-aal3: "true"`. Idle limits cannot
  exceed the absolute limit. The `ConfigMap` is read at every sign-in and refresh.
  Signing keys stay published longer than the longest token, and the JWK set's `max-age` is
  shorter than the publish-ahead time.
- **Logs** mix authentication/security events and operational/dependency diagnostics on
  stdout. SIGTERM drains in-flight requests and stops background tasks before exit.

## Logging

Zeabur Identity writes all logs to stdout. Two kinds of record share that stream:

- **audit events**: sign-ins, enrolments, token issuance and similar, with a fixed set of
  fields, always under the target `zeabur_identity::audit`;
- **diagnostics**: everything else, from Zeabur Identity's own modules and its dependencies, under their
  usual Rust module targets.

### Format

By default each line is one JSON object, in `tracing`'s native layout: `timestamp`, `level`,
`target` and the event's `fields`. Span fields are left out. It is not OTLP, syslog, ECS or
OCSF. `--log-format text` (or `ZEABUR_IDENTITY_LOG_FORMAT=text`) prints human-readable lines instead;
these can include span context, so use JSON when a machine collects the logs. Neither format
uses colour. Command-line help and errors, and `zeabur-identityctl`'s output, are not affected.

### What gets logged

The default filter is `warn,zeabur-identity=info`: Zeabur Identity at INFO, dependencies at WARN and above. Set
`ZEABUR_IDENTITY_LOG` to change it. The value **replaces** the whole filter rather than adding to it, so
to debug rustls while keeping the rest, write `warn,zeabur-identity=info,rustls=debug`, not just
`rustls=debug`. `zeabur_identity::audit=info` selects audit events on their own, and `ZEABUR_IDENTITY_LOG=off`
turns logging off. If the value cannot be parsed, Zeabur Identity falls back to the default and logs
`reason="invalid_filter"` without repeating the bad value.

### Audit events

Every audit event has `target="zeabur_identity::audit"`. Its fields:

| Field | Present | Meaning |
|---|---|---|
| `event` | always | what happened, for example `auth.sign_in` |
| `outcome` | always | `success` or `failure`; independent of the log level |
| `reason` | sometimes | one of a fixed set of values |
| `user` | sometimes | the verified local `User` name |
| `subject` | sometimes | that user's local UID (not a GitHub or Google ID) |
| `client` | sometimes | an authenticated OAuth client |
| `method`, `provider` | events about signing in, enrolment and linking | how the person signed in; fixed sets of values |
| `phase` | `auth.passkey_enrollment` | `start` or `finish` |

Only `event` and `outcome` are always there; treat every other field as optional. OAuth code
exchange, refresh and revocation events, for example, carry no `method` or `provider`.

How to read them:

- **`auth.sign_in` with `success`** means a fresh sign-in completed. Starting a passkey or
  GitHub/Google sign-in is logged as its own event, and does not mean it finished.
- **Code exchange, refresh and revocation** are separate events, never counted as sign-ins.
  Revocation reports `accepted` even when the token did not exist, as RFC 7009 requires.
- **`auth.passkey_enrollment`** logs a start and a finish; **`auth.account_link`** succeeds
  once the credential exists. A bad GitHub/Google callback stays `auth.upstream_callback`.
- **Identity is recorded only once verified.** A failed passkey attempt carries no `user`, even
  if the credential ID belongs to someone; so does a disabled user's rejected attempt. During
  enrolment with a one-time link, `user` can appear without `subject`.
- **Replay and wrong-client events** report the detection, not that the token was then revoked.

To list successful fresh sign-ins:

```sh
jq -c 'select(.target == "zeabur_identity::audit" and .fields.event == "auth.sign_in" and .fields.outcome == "success") | {timestamp, user: .fields.user, subject: .fields.subject, method: .fields.method, provider: .fields.provider}'
```

The newest such record gives a user's last *observed* sign-in. A missing record does not prove
that someone never signed in.

### Secrets in logs

Audit event fields never contain raw errors, credentials or tokens. **Diagnostics make no such
promise**: an error message can include details from a backend response, even at WARN or
ERROR, and DEBUG or TRACE can show more. Because both share one stream, protect access,
transport and retention of the **whole** stream. Filtering or redacting later does not undo
what the container log already holds.

### Collecting the logs

Zeabur Identity bundles no collector. A downstream tool such as a [Vector route] can parse each line as
JSON and send target `zeabur_identity::audit` to audit storage and everything else to operational
storage. The target alone is enough to route on. Keep lines that fail to parse on an error
route rather than dropping them, and pass dependency records through without inventing `event`
or `outcome` fields. If your collector maps the target to `log.logger` or an instrumentation
scope, the audit scope is `zeabur_identity::audit`. The target labels the record; it does not prove
where it came from.

### What this is not

This is a best-effort event history, not Kubernetes audit logging and not a compliance-grade
audit trail. Records can be lost or duplicated by filtering, crashes, retries, collection or
retention. There are no request IDs, event UUIDs, hash chains or acknowledgements.

[Vector route]: https://vector.dev/docs/reference/configuration/transforms/route/

## References

- [OIDC Discovery] N. Sakimura, J. Bradley, M. Jones, and E. Jay, "OpenID Connect Discovery 1.0
  incorporating errata set 2," OpenID Foundation, Dec. 2023.
- [RFC 8414] M. Jones, N. Sakimura, and J. Bradley, "OAuth 2.0 Authorization Server Metadata,"
  RFC 8414, IETF, Jun. 2018.
- [RFC 6750] M. Jones and D. Hardt, "The OAuth 2.0 Authorization Framework: Bearer Token
  Usage," RFC 6750, IETF, Oct. 2012.

[OIDC Discovery]: https://openid.net/specs/openid-connect-discovery-1_0.html
[RFC 8414]: https://www.rfc-editor.org/rfc/rfc8414
[RFC 6750]: https://www.rfc-editor.org/rfc/rfc6750

[the deployment guide]: ../../docs/get-started/quickstart.mdx
