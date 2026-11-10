# zeabur-identity-core

Primitives every Zeabur Identity crate shares. Nothing here performs I/O.

## Contents

- [`clock`](crate::clock): [`UnixTime`](crate::clock::UnixTime) and the
  [`Clock`](crate::clock::Clock) trait. Everything time-dependent takes a `Clock`, so tests
  drive time explicitly instead of sleeping.
- [`crypto`](crate::crypto): randomness, SHA-256, constant-time comparison, and
  [`Sealer`](crate::crypto::Sealer), which seals self-contained
  protocol state with AES-256-GCM-SIV.
- [`config`](crate::config): validated configuration values, in particular
  [`BaseUrl`](crate::config::BaseUrl), the form of the issuer identifier.
- [`protocol`](crate::protocol): endpoint paths that several crates must agree on.
- [`account`](crate::account): account types, the install-wide settings, and which sign-in
  methods each account type may use.

## Place in the workspace

`zeabur-identity-core` depends on no other workspace crate. Nearly every other crate depends on it:
`zeabur-identity-keys`, `zeabur-identity-store`, `zeabur-identity-ui`, `zeabur-identity-oauth`, `zeabur-identity-signin`, `zeabur-identity-tls`,
`zeabur-identity-k8s`, and the `zeabur-identity` and `zeabur-identityctl` binaries.

## Cryptographic backend

All cryptography in Zeabur Identity's own code goes through [aws-lc-rs] (and rustls with its aws-lc-rs
provider for TLS); `ring`, OpenSSL and `native-tls` are banned in the dependency policy. One
backend means one C library to track and one set of advisories. aws-lc-rs is the provider the
rustls project recommends for its feature set and performance [rustls], and it covers every
primitive Zeabur Identity needs: ES256 and RS256 signing (including RSA key generation), SHA-256, HMAC,
HKDF, AES-GCM and AES-GCM-SIV, constant-time comparison and a CSPRNG. `ring` was not chosen
because it depends on a single maintainer and, as of October 2026, has had no release since
March 2025.

aws-lc-rs does not expose XChaCha20-Poly1305 (only the raw `aws-lc-sys` bindings do, which
would need `unsafe`). [`Sealer`](crate::crypto::Sealer) therefore uses AES-256-GCM-SIV with
random nonces: its resistance to nonce misuse covers the nonce-collision concern that would
otherwise motivate an extended-nonce cipher.

## References

- [aws-lc-rs] Amazon Web Services, "aws-lc-rs User Guide." <https://aws.github.io/aws-lc-rs/>
- [rustls] rustls project, `README.md`. <https://github.com/rustls/rustls/blob/main/README.md>

[aws-lc-rs]: https://aws.github.io/aws-lc-rs/
[rustls]: https://github.com/rustls/rustls/blob/main/README.md
