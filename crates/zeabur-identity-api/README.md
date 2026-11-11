# zeabur-identity-api

The `identity.zeabur.com/v1alpha1` custom resources (`User`, `Credential`, `OAuthClient`, `Grant`
and `Invitation`) and the names that Zeabur Identity shares with the programs that write these
objects: the API group, the labels and annotations, and the admin group.

## Place in the workspace

`zeabur-identity-api` depends on no other workspace crate, so a program can depend on it without
the server's code. `zeabur-identity-keys`, `zeabur-identity-store`, `zeabur-identity-k8s`, the
`zeabur-identity` server and the `zeabur-identityctl` admin CLI depend on it.
