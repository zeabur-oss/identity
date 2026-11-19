//! How a person signed in, what that sign-in asserts, and the one step that completes it.

use zeabur_identity_core::account::Method;
use zeabur_identity_core::clock::{Clock, UnixTime};
use zeabur_identity_oauth::AuthorizationServer;
use zeabur_identity_oauth::authorize::Authentication;
use zeabur_identity_oauth::endpoints::complete_authorization;
use zeabur_identity_store::{Directory, GrantStore, User};

use crate::password::SecondFactor;

/// How a person signed in.
#[derive(Clone, Copy)]
pub(crate) enum SignInMethod {
    /// A passkey, with user verification.
    Passkey {
        /// Its authenticator reported BE unset.
        device_bound: bool,
    },
    /// A password, and the second factor checked with it.
    Password(Option<SecondFactor>),
    /// A linked upstream account.
    Upstream {
        /// The operator marks the provider `mfa: Enforced`.
        mfa_enforced: bool,
    },
}

impl SignInMethod {
    /// The authentication methods it asserts, as `amr` values ([RFC 8176] §2).
    ///
    /// - A passkey: `swk`, proof of possession of a key. Attestation is `none`, so a
    ///   hardware-backed key cannot be claimed and `hwk` is not used. `mfa`: the authenticator
    ///   verified the user with a PIN or biometric in addition to possession, a multi-factor
    ///   cryptographic authenticator in NIST SP 800-63B-4 terms.
    /// - A password: `pwd`; with a TOTP code also `otp` and `mfa`; with a recovery code `mfa`.
    /// - An upstream account: `mfa` on the operator's statement alone when the provider is marked
    ///   `mfa: Enforced`, else nothing.
    ///
    /// [RFC 8176]: https://www.rfc-editor.org/rfc/rfc8176.html#section-2
    pub(crate) const fn amr(self) -> &'static [&'static str] {
        match self {
            Self::Passkey { .. } => &["swk", "mfa"],
            Self::Password(None) => &["pwd"],
            Self::Password(Some(SecondFactor::Totp(_))) => &["pwd", "otp", "mfa"],
            Self::Password(Some(SecondFactor::Recovery(_))) => &["pwd", "mfa"],
            Self::Upstream { mfa_enforced: true } => &["mfa"],
            Self::Upstream {
                mfa_enforced: false,
            } => &[],
        }
    }

    /// How [`allows`](zeabur_identity_core::account::allows) sees it.
    pub(crate) const fn policy(self) -> Method {
        match self {
            Self::Passkey { device_bound } => Method::Passkey { device_bound },
            Self::Password(second) => Method::Password {
                second_factor: second.is_some(),
            },
            Self::Upstream { mfa_enforced } => Method::Upstream { mfa_enforced },
        }
    }

    /// `user` signed in this way at `now` with the `Credential` named `credential`.
    pub(crate) fn authentication(
        self,
        user: &User,
        credential: String,
        now: UnixTime,
    ) -> Authentication {
        let (user_verified, device_bound) = match self {
            Self::Passkey { device_bound } => (true, device_bound),
            Self::Password(_) | Self::Upstream { .. } => (false, false),
        };
        Authentication {
            user: user.name.clone(),
            subject: user.subject.clone(),
            auth_time: now,
            amr: self.amr().iter().map(|m| (*m).to_owned()).collect(),
            credential: Some(credential),
            user_verified,
            device_bound,
        }
    }
}

/// Completes the authorization request sealed in `flow` for `authentication`, and returns where to
/// send the browser. `None` when the request is gone or expired; the error is logged.
pub(crate) fn finish<D: Directory, G: GrantStore, C: Clock>(
    oauth: &AuthorizationServer<D, G, C>,
    flow: &str,
    authentication: Authentication,
) -> Option<String> {
    complete_authorization(oauth, flow, authentication)
        .inspect_err(|error| {
            tracing::warn!(
                reason = "authorization_failed",
                ?error,
                "authorization failed"
            );
        })
        .ok()
}
