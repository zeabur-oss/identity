//! Passkey (WebAuthn Level 3) ceremonies, wrapping webauthn-rs.
//!
//! Policy: discoverable credentials (resident key required, so the browser can offer them
//! through conditional mediation without asking for a username first), user verification
//! required at registration and at every assertion, attestation `none`, relying party ID = the
//! issuer's host, origin = the issuer. The sign counter is not persisted: synced passkeys
//! report 0, a counter is only a signal (WebAuthn Level 3 §6.1.1), and storing it would cost a
//! write per sign-in.

use serde::Deserialize;
use thiserror::Error;
use webauthn_rs::prelude::{
    AuthenticationResult, CreationChallengeResponse, Credential, DiscoverableAuthentication,
    Passkey, PasskeyRegistration, PublicKeyCredential, RegisterPublicKeyCredential,
    RequestChallengeResponse, Url, Uuid, Webauthn, WebauthnBuilder, WebauthnError,
};
use webauthn_rs_core::internals::AuthenticatorData;
use webauthn_rs_core::proto::{Registration, ResidentKeyRequirement};
use zeabur_identity_core::config::BaseUrl;

/// A failed ceremony. Details are logged by the caller; users see a generic message.
#[derive(Debug, Error)]
pub enum PasskeyError {
    /// The relying party configuration is invalid (for example an issuer without a host).
    #[error("invalid WebAuthn configuration: {0}")]
    Config(String),
    /// The browser's response did not verify.
    #[error("passkey verification failed: {0}")]
    Verification(String),
    /// The authenticator did not verify the user (WebAuthn UV flag).
    #[error("the authenticator did not verify the user")]
    NotUserVerified,
}

/// The relying party.
pub struct Passkeys {
    webauthn: Webauthn,
    rp_id: String,
}

impl std::fmt::Debug for Passkeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Passkeys")
    }
}

impl Passkeys {
    /// The relying party for `issuer`: RP ID is its host, the only allowed origin is the issuer.
    ///
    /// # Errors
    ///
    /// [`PasskeyError::Config`] if the issuer cannot serve as a WebAuthn origin.
    pub fn new(issuer: &BaseUrl) -> Result<Self, PasskeyError> {
        let origin =
            Url::parse(issuer.as_str()).map_err(|e| PasskeyError::Config(e.to_string()))?;
        let rp_id = origin
            .host_str()
            .ok_or_else(|| PasskeyError::Config("the issuer has no host".to_owned()))?
            .to_owned();
        let webauthn = WebauthnBuilder::new(&rp_id, &origin)
            .and_then(|builder| builder.rp_name("Zeabur Identity").build())
            .map_err(|e| PasskeyError::Config(e.to_string()))?;
        Ok(Self { webauthn, rp_id })
    }

    /// The relying party ID: the issuer's host.
    #[must_use]
    pub fn rp_id(&self) -> &str {
        &self.rp_id
    }

    /// Starts registering a passkey for the user with WebAuthn user handle `handle`. Returns the
    /// `CredentialCreationOptions` JSON for the browser and the state to keep. `exclude` lists
    /// the user's existing credential IDs, so an authenticator that holds one says so instead of
    /// creating a second.
    ///
    /// # Errors
    ///
    /// [`PasskeyError::Verification`] if the library cannot build the challenge.
    pub fn begin_registration(
        &self,
        handle: Uuid,
        username: &str,
        display_name: &str,
        exclude: Vec<Vec<u8>>,
    ) -> Result<(CreationChallengeResponse, PasskeyRegistration), PasskeyError> {
        let exclude = (!exclude.is_empty()).then_some(exclude);
        let (mut options, state) = self
            .webauthn
            .start_passkey_registration(handle, username, display_name, exclude)
            .map_err(|e| PasskeyError::Verification(e.to_string()))?;
        // Sign-in uses discoverable credentials (no username first), so the credential must be
        // resident. webauthn-rs defaults to non-resident for broad compatibility; its resident-key
        // registration needs an attestation CA list, and this relying party asks for none.
        if let Some(selection) = options.public_key.authenticator_selection.as_mut() {
            selection.require_resident_key = true;
            selection.resident_key = Some(ResidentKeyRequirement::Required);
        }
        Ok((options, state))
    }

    /// Verifies the browser's registration response.
    ///
    /// # Errors
    ///
    /// [`PasskeyError::Verification`] if it does not verify against `state`.
    pub fn finish_registration(
        &self,
        response: &RegisterPublicKeyCredential,
        state: &PasskeyRegistration,
    ) -> Result<Passkey, PasskeyError> {
        self.webauthn
            .finish_passkey_registration(response, state)
            .map_err(|e| PasskeyError::Verification(e.to_string()))
    }

    /// Starts a sign-in with any discoverable credential (conditional mediation).
    ///
    /// # Errors
    ///
    /// [`PasskeyError::Verification`] if the library cannot build the challenge.
    pub fn begin_sign_in(
        &self,
    ) -> Result<(RequestChallengeResponse, DiscoverableAuthentication), PasskeyError> {
        self.webauthn
            .start_discoverable_authentication()
            .map_err(|e| PasskeyError::Verification(e.to_string()))
    }

    /// Reads the user handle and credential ID from an assertion, before it is verified.
    ///
    /// # Errors
    ///
    /// [`PasskeyError::Verification`] if the response carries no valid user handle.
    pub fn identify(
        &self,
        response: &PublicKeyCredential,
    ) -> Result<(Uuid, Vec<u8>), PasskeyError> {
        self.webauthn
            .identify_discoverable_authentication(response)
            .map(|(handle, id)| (handle, id.to_vec()))
            .map_err(|e| PasskeyError::Verification(e.to_string()))
    }

    /// Verifies an assertion made with `passkey`, requiring user verification.
    ///
    /// # Errors
    ///
    /// [`PasskeyError::Verification`] if the signature or client data do not verify;
    /// [`PasskeyError::NotUserVerified`] if UV was not performed.
    pub fn finish_sign_in(
        &self,
        response: &PublicKeyCredential,
        state: DiscoverableAuthentication,
        passkey: &Passkey,
    ) -> Result<AuthenticationResult, PasskeyError> {
        let result = self
            .webauthn
            .finish_discoverable_authentication_v2(response, state, passkey)
            .map_err(|e| {
                if matches!(e, WebauthnError::UserNotVerified) {
                    PasskeyError::NotUserVerified
                } else {
                    PasskeyError::Verification(e.to_string())
                }
            })?;
        // The library requires UV under this policy; check again so a library change cannot
        // silently weaken it (Pocket ID advisory
        // GHSA-pgqv-hh75-xx4x: UV was required in the options but not checked).
        if !result.user_verified() {
            return Err(PasskeyError::NotUserVerified);
        }
        Ok(result)
    }
}

pub use zeabur_identity_store::passkey_credential_name as credential_name;

/// The AAGUID in a registration response, lowercase and hyphenated; `None` when the
/// authenticator sends zeros, as some platforms do under attestation `none`.
///
/// webauthn-rs keeps the AAGUID only for attestation formats it verifies, so this reads the
/// attestation object (WebAuthn Level 3 §6.5.4) again. The AAGUID is only shown.
#[must_use]
pub fn aaguid(response: &RegisterPublicKeyCredential) -> Option<String> {
    let object: AttestationObject<'_> =
        serde_cbor_2::from_slice(&response.response.attestation_object).ok()?;
    let data = AuthenticatorData::<Registration>::try_from(object.auth_data).ok()?;
    let aaguid = data.acd?.aaguid;
    aaguid
        .iter()
        .any(|b| *b != 0)
        .then(|| Uuid::from_bytes(aaguid).hyphenated().to_string())
}

/// The part of the attestation object that holds the authenticator data.
#[derive(Deserialize)]
struct AttestationObject<'a> {
    #[serde(rename = "authData")]
    auth_data: &'a [u8],
}

/// The backup flags of a registered passkey (WebAuthn Level 3 §6.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackupFlags {
    /// BE: the credential may be synced.
    pub eligible: bool,
    /// BS: the credential is synced.
    pub state: bool,
}

/// The BE and BS flags webauthn-rs recorded for `passkey`.
#[must_use]
pub fn backup_flags(passkey: &Passkey) -> BackupFlags {
    let credential = Credential::from(passkey.clone());
    BackupFlags {
        eligible: credential.backup_eligible,
        state: credential.backup_state,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registration_requires_resident_keys_and_uv() {
        let passkeys =
            Passkeys::new(&BaseUrl::parse("issuer", "https://login.example.com").unwrap()).unwrap();
        let (options, _) = passkeys
            .begin_registration(Uuid::nil(), "alice", "Alice", vec![b"old".to_vec()])
            .unwrap();
        let json = serde_json::to_value(&options).unwrap();
        let selection = &json["publicKey"]["authenticatorSelection"];
        assert_eq!(selection["residentKey"], "required");
        assert_eq!(selection["requireResidentKey"], true);
        assert_eq!(selection["userVerification"], "required");
        assert_eq!(json["publicKey"]["rp"]["id"], "login.example.com");
        assert_eq!(json["publicKey"]["attestation"], "none");
        assert_eq!(json["publicKey"]["excludeCredentials"][0]["id"], "b2xk");
    }

    fn attestation_object(auth_data: &[u8]) -> Vec<u8> {
        // {"fmt": "none", "attStmt": {}, "authData": h'…'}
        let mut cbor = vec![0xA3, 0x63];
        cbor.extend_from_slice(b"fmt");
        cbor.push(0x64);
        cbor.extend_from_slice(b"none");
        cbor.push(0x67);
        cbor.extend_from_slice(b"attStmt");
        cbor.push(0xA0);
        cbor.push(0x68);
        cbor.extend_from_slice(b"authData");
        cbor.push(0x59);
        cbor.extend_from_slice(&u16::try_from(auth_data.len()).unwrap().to_be_bytes());
        cbor.extend_from_slice(auth_data);
        cbor
    }

    #[test]
    fn reads_the_aaguid_from_auth_data() {
        let aaguid = Uuid::parse_str("ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4").unwrap();
        // RP ID hash, flags UP UV BE BS AT, counter, AAGUID, credential ID h'07', key {}.
        let mut data = vec![0; 32];
        data.push(0x5D);
        data.extend_from_slice(&[0; 4]);
        data.extend_from_slice(aaguid.as_bytes());
        data.extend_from_slice(&[0, 1, 7, 0xA0]);
        let mut response: RegisterPublicKeyCredential = serde_json::from_str(
            r#"{"id":"AA","rawId":"AA","type":"public-key","extensions":{},
            "response":{"attestationObject":"","clientDataJSON":""}}"#,
        )
        .unwrap();
        response.response.attestation_object = attestation_object(&data);
        assert_eq!(super::aaguid(&response), Some(aaguid.to_string()));
        // Zero AAGUID (attestation "none" on some platforms) and garbage give nothing.
        data[37..53].fill(0);
        response.response.attestation_object = attestation_object(&data);
        assert_eq!(super::aaguid(&response), None);
        for garbage in [&[][..], &[0xA1], &[0xBF, 0xFF], &[0xA1, 0x7B, 0xFF]] {
            response.response.attestation_object = garbage.to_vec();
            assert_eq!(super::aaguid(&response), None);
        }
    }

    #[test]
    fn sign_in_uses_conditional_mediation() {
        let passkeys =
            Passkeys::new(&BaseUrl::parse("issuer", "https://login.example.com").unwrap()).unwrap();
        let (options, _) = passkeys.begin_sign_in().unwrap();
        let json = serde_json::to_value(&options).unwrap();
        assert_eq!(json["mediation"], "conditional");
        assert_eq!(json["publicKey"]["userVerification"], "required");
        assert!(
            json["publicKey"]["allowCredentials"]
                .as_array()
                .is_none_or(Vec::is_empty)
        );
    }

    #[test]
    fn credential_names_are_dns_safe_and_distinct() {
        let a = credential_name(b"one");
        assert_eq!(a.len(), 66);
        assert!(
            a.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        );
        assert_ne!(a, credential_name(b"two"));
    }
}
