# Check a release installation

Use this checklist when preparing a release. Start with a fresh Ubuntu server or VM and
follow [Get started](../get-started/quickstart.mdx), using the release CLI and image. Run it on Linux amd64
and arm64, with a browser on a separate computer.

For a draft candidate, use a maintainer's authenticated `gh release download` as described in
[Publish a release](releasing.md), then transfer those exact assets to the
test server and run the guide's verification commands. Draft download URLs are not public.
Repeat the public download and verification steps after publication, before announcing the release.

## Record the setup

Keep a short record with:

- release version, CLI archive SHA-256 and image digest;
- the guide's commit, Ubuntu version and CPU architecture;
- output from `kubectl version` and `kubectl get nodes -o wide`;
- each check below and its result.

Keep tokens, private keys and setup or invitation links out of the record.

## Install and sign in

- [ ] Download the CLI and verify its signature and checksum. Verify the image signature and SBOM.
- [ ] Install CRDs, RBAC, the Deployment and HTTPS ingress using the guide. Check that the pod is ready and HTTPS discovery returns the configured issuer.
- [ ] Install kube-apiserver's authentication configuration and wait for its successful reload.
- [ ] Create the first admin's setup link. Open it in the browser and create a passkey.
- [ ] Sign in through kubelogin. `kubectl auth whoami` should show `zeabur:admin` and `zeabur:admins`.
- [ ] Try the guide's ConfigMap write and delete. Expect both to succeed without another sign-in.
- [ ] Check admin-token expiry using the steps below.
- [ ] Wait more than five minutes, then run `kubectl auth whoami` again. Expect it to succeed without the browser: kubelogin renews the token with its refresh token.

## Check the five-minute admin token

Use the computer's kubeconfig from the guide. Install `jq` for this check. These commands
save one admin account's token in a private temporary directory so every request uses that same token:

```sh
umask 077
work=$(mktemp -d)
kubectl oidc-login get-token \
  --oidc-issuer-url=https://identity.example.test \
  --oidc-client-id=kubectl \
  --oidc-use-access-token \
  --token-cache-dir="$work/cache" \
  --listen-address=127.0.0.1:8000 \
  --oidc-redirect-url=http://127.0.0.1:8000/ > "$work/credential.json"
kubectl config view --raw --minify -o json |
  jq --slurpfile credential "$work/credential.json" '
    .users = [{name: "fixed-admin", user: {token: $credential[0].status.token}}] |
    .contexts[0].context.user = "fixed-admin"
  ' > "$work/kubeconfig"
```

For a Homebrew installation, replace `kubectl oidc-login` with `kubelogin`. If you use WSL,
add the `--certificate-authority` option from the guide to `get-token`.

Check the saved token and print its expiry time:

```sh
kubectl --kubeconfig="$work/kubeconfig" auth whoami
jq -r '.status.token | split(".")[1] | gsub("-"; "+") | gsub("_"; "/") |
  @base64d | fromjson | .exp | todateiso8601' "$work/credential.json"
```

Wait until after that time, then repeat the request:

```sh
kubectl --kubeconfig="$work/kubeconfig" auth whoami
```

The first request should show `zeabur:admins`. The second should fail with
`Unauthorized`. Save the expiry time and request results, then remove the temporary files:

```sh
rm -rf "$work"
```

## Check account changes

Use a test user such as `alice`, keeping the server's cluster-admin kubeconfig available.
[Managing users](../users/manage-users.mdx) has the commands for each operation.

- [ ] **Invitation:** invite Alice, open her link and create a passkey. Sign in as Alice and check her username and groups. Opening the used invitation again should fail.
- [ ] **Disable:** set Alice's `disabled` field to `true`. Check that a fresh sign-in fails and her existing session cannot renew. Re-enable her before continuing.
- [ ] **Sign out:** sign in as Alice, then delete her `Grant`. Check that the session cannot renew. Kubernetes still accepts an access token already issued until its expiry, up to ten minutes with the default settings.
- [ ] **Account type:** run `zeabur-identityctl account-type alice admin`. Check that Alice's next sign-in includes `zeabur:admins` and, if GitHub, Google or OpenID Connect sign-in is set up, that signing in with it shows "Use a passkey for this account". Run `zeabur-identityctl account-type alice regular` before continuing.
- [ ] **Lost passkey:** run `zeabur-identityctl setup-link --username alice --reset`. Check that the old passkey fails, pending invitations are removed and old sessions cannot renew. Open the new link, create a replacement passkey and sign in again.

When checking session renewal, use the same session before and after the change. A new
browser sign-in creates a new session. Record the access token's expiry and the observed
renewal result without recording the token itself. Kubernetes also accepts existing access
tokens until expiry after disabling an account or resetting its passkeys.

## Finish the record

Add the observed results and any fixes needed to the release issue. Include the final
version and image digest, and repeat affected checks after a fix. Remove the test cluster
using the guide's cleanup steps when finished.
