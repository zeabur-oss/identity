# zeabur-identity-tls

TLS for Zeabur Identity's own connections, all on rustls with the aws-lc-rs provider.

## Contents

- [`trust`](crate::trust): the certificate authorities trusted for outgoing TLS (upstream
  identity providers): the system bundle.
- [`certificate`](crate::certificate): loads a PEM chain and key for rustls.
- [`listener`](crate::listener): a TLS listener for axum whose certificate can be replaced while
  it runs, with bounded, time-limited handshakes.

## Place in the workspace

Depends on no other Zeabur Identity crate. Used by `zeabur-identity-k8s` (reads the internal certificate from
its Secret) and by the `zeabur-identity` server, which runs the internal listener and builds its
outgoing trust roots here.

## Why the internal listener has its own certificate

kube-apiserver must fetch Zeabur Identity's discovery document and JWK set to verify tokens. Going
through the public issuer URL makes the control plane depend on public DNS, the ingress and a
publicly trusted certificate. Instead, `issuer.discoveryURL` can point kube-apiserver at an
in-cluster address ([KEP-3331], [Kubernetes authentication]). That address must use `https`
([apiserver validation]), and kube-apiserver resolves names with the host's resolver, so cluster
DNS names such as `*.svc.cluster.local` do not resolve ([kube-apiserver OIDC], [Kubernetes DNS]).
The internal address is therefore a fixed ClusterIP (or loopback on a single node), and the
serving certificate names it as an IP SAN.

The certificate chains to a private CA that goes into kube-apiserver's
`issuer.certificateAuthority`. cert-manager issues and renews it (see `zeabur-identity-k8s`'s
`internal_tls`). kube-apiserver is pinned to that CA rather than the system roots,
because anyone able to serve the internal address could otherwise hand it their own signing
keys. A CA certificate is needed even though nothing else trusts it, because Go's TLS stack
requires the chain to end in a certificate with `CA:TRUE`.

## Security properties

- The listener replaces its certificate while it runs, so a renewed certificate needs no
  restart.
- Outgoing connections trust the system CA bundle, not a compiled-in root list:
  `webpki-roots` is licensed CDLA-Permissive-2.0, which is not OSI-approved. Connections to
  kube-apiserver do not use [`trust`](crate::trust); they trust the service account's CA only.

## References

- [KEP-3331] The Kubernetes Authors, "KEP-3331: Structured Authentication Configuration,"
  kubernetes/enhancements.
- [Kubernetes authentication] The Kubernetes Authors, "Authenticating: Using authentication
  configuration," Kubernetes documentation.
- [apiserver validation] The Kubernetes Authors,
  `staging/src/k8s.io/apiserver/pkg/apis/apiserver/validation/validation.go`, tag v1.37.1.
- [kube-apiserver OIDC] The Kubernetes Authors,
  `staging/src/k8s.io/apiserver/plugin/pkg/authenticator/token/oidc/oidc.go`.
- [Kubernetes DNS] The Kubernetes Authors, "DNS for Services and Pods," Kubernetes documentation.

[KEP-3331]: https://github.com/kubernetes/enhancements/tree/master/keps/sig-auth/3331-structured-authentication-configuration
[Kubernetes authentication]: https://kubernetes.io/docs/reference/access-authn-authz/authentication/
[apiserver validation]: https://github.com/kubernetes/kubernetes/blob/v1.37.1/staging/src/k8s.io/apiserver/pkg/apis/apiserver/validation/validation.go
[kube-apiserver OIDC]: https://github.com/kubernetes/kubernetes/blob/master/staging/src/k8s.io/apiserver/plugin/pkg/authenticator/token/oidc/oidc.go
[Kubernetes DNS]: https://kubernetes.io/docs/concepts/services-networking/dns-pod-service/
