#![doc = include_str!("../README.md")]

pub mod certificate;
pub mod logging;

use passkey::authenticator::{Authenticator, UiHint, UserCheck, UserValidationMethod};
use passkey::client::Client as PasskeyClient;
use passkey::crypto::aws_lc_rs::AwsLcRsBackend;
use passkey::types::ctap2::{Aaguid, Ctap2Error};

/// A device whose user always passes verification (biometric or PIN).
#[derive(Debug, Clone, Copy, Default)]
pub struct VerifiedUser;

#[async_trait::async_trait]
impl UserValidationMethod for VerifiedUser {
    type PasskeyItem = passkey::types::Passkey;

    async fn check_user<'a>(
        &self,
        _hint: UiHint<'a, Self::PasskeyItem>,
        presence: bool,
        verification: bool,
    ) -> Result<UserCheck, Ctap2Error> {
        Ok(UserCheck {
            presence,
            verification,
        })
    }

    fn is_presence_enabled(&self) -> bool {
        true
    }

    fn is_verification_enabled(&self) -> Option<bool> {
        Some(true)
    }
}

/// A device holding one passkey; it answers discoverable (empty allow-list) requests.
pub type Device = PasskeyClient<
    Option<passkey::types::Passkey>,
    VerifiedUser,
    AwsLcRsBackend,
    public_suffix::PublicSuffixList,
    (),
>;

/// A new device with no passkey.
#[must_use]
pub fn device() -> Device {
    PasskeyClient::new(Authenticator::new(
        Aaguid::new_empty(),
        None,
        VerifiedUser,
        AwsLcRsBackend,
    ))
}
