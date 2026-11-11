//! Property tests for redirect URI registration: what `zeabur-identityctl client create` accepts
//! must survive every parser between the registration and the user's browser.
//!
//! The candidates come from [`redirect_uri_candidates`], which the cluster tests also use to
//! compare this rule with the `OAuthClient` admission rule.

mod redirect_uri_candidates;

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use axum::http::{HeaderValue, Uri};
    use proptest::prelude::*;
    use url::{Host, Url};
    use zeabur_identity_api::client::{ClientType, MAX_REDIRECT_URI};
    use zeabur_identity_k8s::clients::redirect_uri_allowed;
    use zeabur_identity_oauth::authorize::response_location;
    use zeabur_identity_store::Client;

    use crate::redirect_uri_candidates::candidate;

    /// `https` with a host, or `http` on a loopback address, with no fragment or credentials, as
    /// a browser reads `url`.
    fn browser_sees_an_allowed_target(url: &Url) -> bool {
        let origin = match (url.scheme(), url.host()) {
            ("https", Some(_)) => true,
            ("http", Some(Host::Ipv4(ip))) => ip == Ipv4Addr::LOCALHOST,
            ("http", Some(Host::Ipv6(ip))) => ip == Ipv6Addr::LOCALHOST,
            _ => false,
        };
        origin && url.fragment().is_none() && url.username().is_empty() && url.password().is_none()
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(4096))]

        /// An accepted URI is read the same way by the browser (WHATWG) and the `http` crate
        /// (RFC 3986), and the authorization response built on it is a valid `Location` that
        /// still points at the same origin and path.
        #[test]
        fn accepted_uris_survive_every_parser_on_the_way(uri in candidate()) {
            if !redirect_uri_allowed(&uri) {
                return Ok(());
            }
            let url = Url::parse(&uri).unwrap();
            prop_assert!(browser_sees_an_allowed_target(&url));

            let rfc3986: Uri = uri.parse().unwrap();
            prop_assert_eq!(rfc3986.scheme_str(), Some(url.scheme()));
            prop_assert_eq!(rfc3986.host(), url.host_str());
            prop_assert_eq!(rfc3986.port_u16(), url.port());

            let location =
                response_location(&uri, &[("code", "c")], Some("s"), "https://identity.example");
            prop_assert!(HeaderValue::try_from(location.as_str()).is_ok());
            let followed = Url::parse(&location).unwrap();
            prop_assert_eq!(followed.origin(), url.origin());
            prop_assert_eq!(followed.path(), url.path());
            let pairs: Vec<_> = followed.query_pairs().collect();
            prop_assert!(pairs.iter().any(|(k, v)| k == "code" && v == "c"));
            prop_assert!(pairs.iter().any(|(k, v)| k == "state" && v == "s"));
        }

        /// Writing an allowed target the way the browser does, with every `%` starting an
        /// escape, always makes it acceptable, which is what the error message tells the
        /// administrator to do.
        #[test]
        fn the_browser_form_of_an_allowed_target_is_accepted(uri in candidate()) {
            let Ok(url) = Url::parse(&uri) else {
                return Ok(());
            };
            if !browser_sees_an_allowed_target(&url) {
                return Ok(());
            }
            let stray_percent = url.as_str().split('%').skip(1).any(|after| {
                !after.as_bytes().get(..2).is_some_and(|d| d.iter().all(u8::is_ascii_hexdigit))
            });
            if stray_percent || url.as_str().len() > MAX_REDIRECT_URI {
                return Ok(());
            }
            prop_assert!(redirect_uri_allowed(url.as_str()), "{}", url.as_str());
        }

        /// A registered loopback URI matches the same URI on any port (RFC 8252 §7.3).
        #[test]
        fn accepted_loopback_uris_match_on_any_port(uri in candidate(), port in 1024_u16..) {
            if !(redirect_uri_allowed(&uri) && uri.starts_with("http:")) {
                return Ok(());
            }
            let mut requested = Url::parse(&uri).unwrap();
            requested.set_port(Some(port)).unwrap();
            let client = Client {
                id: "native".into(),
                display_name: None,
                kind: ClientType::Public,
                redirect_uris: vec![uri],
                audiences: vec![],
                secret_hash: None,
                id_token_alg: zeabur_identity_keys::Algorithm::Es256,
                home_url: None,
            };
            prop_assert!(zeabur_identity_oauth::authorize::redirect_uri_allowed(
                &client,
                requested.as_str()
            ));
        }
    }
}
