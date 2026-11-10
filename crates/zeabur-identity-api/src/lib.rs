#![doc = include_str!("../README.md")]
//! # Custom resources
//!
//! Zeabur Identity's long-term state lives in five namespaced kinds; private key material lives in
//! Secrets. Short-lived state (pre-login flows, WebAuthn challenges, authorization codes) never
//! reaches the API server.
//! Each kind exists because a native object cannot do its job:
//!
//! - [`user::User`]: admins or GitOps own `spec`; Zeabur Identity only reads it. A custom resource
//!   provides admission checks for usernames and groups, and whoever manages users needs no access
//!   to Secrets. Session state belongs to [`grant::Grant`], not the user.
//! - [`credential::Credential`]: the name is derived from the credential's unique key, so a
//!   duplicate `create` fails with `409` across replicas. A `ConfigMap` could do that, but has no
//!   schema for the type union and is readable by the namespace `view` role. A kind of its own also
//!   gives typed revocation (`kubectl delete credential`).
//! - [`client::OAuthClient`]: configuration written in GitOps repositories, which must be rejected
//!   at `kubectl apply` when it breaks [RFC 9700] (non-loopback `http`, fragments, plaintext
//!   secrets).
//! - [`grant::Grant`]: as Secrets, grants would need namespace-wide `create`, `list` and `delete`
//!   on Secrets (`create` cannot be limited to a name, [RBAC]), which would also reach the signing
//!   keys. A grant holds only hashes; `kubectl get grants` shows who is signed in.
//! - [`invitation::Invitation`]: written by an admin, redeemed by Zeabur Identity. As Secrets,
//!   pending invitations could only be found with `list` on Secrets.
//!
//! Format rules (lengths, patterns, list sizes) are `OpenAPI` `maxLength`, `pattern` and
//! `maxItems`, which cost nothing against the CEL cost budget; CEL rules
//! (`x-kubernetes-validations`) are used only for immutability and cross-field checks. Every
//! string and list is bounded, because the API server rejects a definition whose estimated rule
//! cost exceeds the budget ([CRD validation]); k3s 1.36 refused an unbounded version of these
//! schemas for exactly that reason. GitOps-authored objects are thus validated at admission, and
//! Zeabur Identity validates again when it reads them.
//!
//! Custom resources are not covered by k3s Secret encryption at rest. That is acceptable for
//! their content: hashes of high-entropy secrets, public keys and metadata.
//!
//! # References
//!
//! - [RFC 9700] T. Lodderstedt, J. Bradley, A. Labunets, and D. Fett, "Best Current Practice for
//!   OAuth 2.0 Security," RFC 9700, BCP 240, IETF, Jan. 2025.
//! - [RBAC] The Kubernetes Authors, "Using RBAC Authorization: Referring to resources," Kubernetes
//!   documentation.
//! - [CRD validation] The Kubernetes Authors, "Extend the Kubernetes API with
//!   `CustomResourceDefinitions`: Validation rules," Kubernetes documentation.
//!
//! [RFC 9700]: https://www.rfc-editor.org/rfc/rfc9700
//! [RBAC]: https://kubernetes.io/docs/reference/access-authn-authz/rbac/
//! [CRD validation]: https://kubernetes.io/docs/tasks/extend-kubernetes/custom-resources/custom-resource-definitions/

pub mod client;
pub mod credential;
pub mod grant;
pub mod invitation;
pub mod upstream;
pub mod user;

use k8s_openapi::apiextensions_apiserver::pkg::apis::apiextensions::v1::CustomResourceDefinition;
use kube::CustomResourceExt as _;

/// The API group.
pub const GROUP: &str = "identity.zeabur.com";

/// Prefix kube-apiserver puts before every Zeabur Identity username and group.
pub const IDENTITY_PREFIX: &str = "zeabur:";

/// The group every token of an admin account carries, and no other token. Kubernetes sees it as
/// `zeabur:admins`, which the install binds to `cluster-admin`. A `User` gets it only from
/// `accountType: Admin`.
pub const ADMIN_GROUP: &str = "admins";

/// Label naming the `User` object a record belongs to.
pub const USER_LABEL: &str = "identity.zeabur.com/user";

/// Label naming the `OAuthClient` a record belongs to.
pub const CLIENT_LABEL: &str = "identity.zeabur.com/client";

/// Annotation holding the expiry time of a short-lived object, in Unix seconds.
pub const EXPIRES_AT_ANNOTATION: &str = "identity.zeabur.com/expires-at";

/// Label holding the expiry hour (Unix seconds / 3600). Its presence selects objects for garbage
/// collection; its value lets a list-based collector select only past hours.
pub const EXPIRY_BUCKET_LABEL: &str = "identity.zeabur.com/expiry-bucket";

/// The stored form of a high-entropy secret: `sha256:` and the 64 lowercase hex digits of the
/// SHA-256 of `token`.
///
/// Zeabur Identity stores invitation and setup tokens (`Invitation` `spec.tokenHash`), client
/// secrets (`OAuthClient` `spec.secretHash`) and refresh tokens in this form, and compares a
/// presented value by this hash. Unsalted SHA-256 is enough only because every hashed value
/// carries at least 256 bits of entropy. Never hash a password or another value a person chose.
#[must_use]
pub fn token_hash(token: &[u8]) -> String {
    let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, token);
    let mut out = String::with_capacity(71);
    out.push_str("sha256:");
    for byte in digest.as_ref() {
        for nibble in [byte >> 4, byte & 0x0F] {
            out.extend(char::from_digit(u32::from(nibble), 16));
        }
    }
    out
}

/// Every custom resource definition, in a stable order.
#[must_use]
pub fn definitions() -> Vec<CustomResourceDefinition> {
    vec![
        user::User::crd(),
        credential::Credential::crd(),
        client::OAuthClient::crd(),
        grant::Grant::crd(),
        invitation::Invitation::crd(),
    ]
}

/// Renders all definitions as a Kubernetes `List`, ready for `kubectl apply -f -`, without a
/// trailing newline.
///
/// # Errors
///
/// Returns an error if serialization fails.
pub fn definitions_json() -> serde_json::Result<String> {
    let list = serde_json::json!({
        "apiVersion": "v1",
        "kind": "List",
        "items": definitions(),
    });
    serde_json::to_string_pretty(&list)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_hash_is_sha256_in_lowercase_hex() {
        // FIPS 180-2 appendix B.1 test vector: SHA-256("abc").
        assert_eq!(
            token_hash(b"abc"),
            "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    /// The committed manifest must match the code. Regenerate with
    /// `cargo run -q -- crds > deploy/crds.json`.
    #[test]
    fn committed_manifest_is_current() {
        let committed = include_str!("../../../deploy/crds.json");
        // Compare parsed JSON: test builds may enable serde_json features (such as
        // `preserve_order`, through dev-dependencies) that change key order but not
        // content.
        let parse = |s: &str| serde_json::from_str::<serde_json::Value>(s).unwrap();
        assert!(
            committed.ends_with('\n') && parse(committed) == parse(&definitions_json().unwrap()),
            "deploy/crds.json is stale: run `cargo run -q -- crds > deploy/crds.json`"
        );
    }
}
