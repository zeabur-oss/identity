//! Passkey (WebAuthn Level 3) ceremonies, wrapping webauthn-rs.
//!
//! Policy: discoverable credentials (resident key required, so the browser can offer them
//! through conditional mediation without asking for a username first), user verification
//! required at registration and at every assertion, attestation `none`, relying party ID = the
//! issuer's host, origin = the issuer. The sign counter is not persisted: synced passkeys
//! report 0, a counter is only a signal (WebAuthn Level 3 §6.1.1), and storing it would cost a
//! write per sign-in.

use thiserror::Error;
use webauthn_rs::prelude::{
    DiscoverableAuthentication, Passkey, PasskeyRegistration, PublicKeyCredential,
    RegisterPublicKeyCredential, RequestChallengeResponse, Url, Uuid, Webauthn, WebauthnBuilder,
    WebauthnError,
};
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
    ) -> Result<(serde_json::Value, PasskeyRegistration), PasskeyError> {
        let exclude = (!exclude.is_empty()).then_some(exclude);
        let (options, state) = self
            .webauthn
            .start_passkey_registration(handle, username, display_name, exclude)
            .map_err(|e| PasskeyError::Verification(e.to_string()))?;
        let mut options =
            serde_json::to_value(options).map_err(|e| PasskeyError::Verification(e.to_string()))?;
        // Sign-in uses discoverable credentials (no username first), so the credential must be
        // resident. webauthn-rs defaults to non-resident for broad compatibility.
        if let Some(selection) = options
            .get_mut("publicKey")
            .and_then(|p| p.get_mut("authenticatorSelection"))
            .and_then(serde_json::Value::as_object_mut)
        {
            selection.insert("requireResidentKey".into(), true.into());
            selection.insert("residentKey".into(), "required".into());
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
    ) -> Result<(), PasskeyError> {
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
        Ok(())
    }
}

pub use zeabur_identity_store::passkey_credential_name as credential_name;

/// What a registration response says about the authenticator.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Authenticator {
    /// AAGUID, lowercase and hyphenated; `None` when the authenticator sends zeros, as with
    /// attestation `none` on some platforms.
    pub aaguid: Option<String>,
    /// BE: the credential may be synced.
    pub backup_eligible: bool,
}

const FLAG_BE: u8 = 0x08;
const FLAG_AT: u8 = 0x40;

/// Reads the AAGUID and flags from the registration response's `authData`.
///
/// webauthn-rs drops the AAGUID under attestation `none`, so this reads it directly. The AAGUID
/// is only shown. BE
/// decides whether an admin may register the passkey when AAL3 is on. The authenticator reports
/// BE itself: attestation is `none`, so nothing verifies it.
#[must_use]
pub fn authenticator(response: &RegisterPublicKeyCredential) -> Authenticator {
    auth_data(&response.response.attestation_object).map_or_else(Authenticator::default, |data| {
        let flags = data.get(32).copied().unwrap_or(0);
        let aaguid = data
            .get(37..53)
            .filter(|_| flags & FLAG_AT != 0)
            .filter(|bytes| bytes.iter().any(|b| *b != 0))
            .and_then(|bytes| Uuid::from_slice(bytes).ok())
            .map(|uuid| uuid.hyphenated().to_string());
        Authenticator {
            aaguid,
            backup_eligible: flags & FLAG_BE != 0,
        }
    })
}

/// Whether the authenticator reported the backup eligibility flag (BE) in a sign-in assertion.
/// The flags follow the 32-byte RP ID hash in the signed authenticator data.
#[must_use]
pub fn assertion_backup_eligible(response: &PublicKeyCredential) -> bool {
    response
        .response
        .authenticator_data
        .get(32)
        .is_some_and(|flags| flags & FLAG_BE != 0)
}

/// The BE and BS flags as recorded in a stored credential record.
#[must_use]
pub fn backup_flags(record: &str) -> (bool, bool) {
    let value: serde_json::Value = serde_json::from_str(record).unwrap_or_default();
    let flag = |name: &str| {
        value
            .get("cred")
            .and_then(|cred| cred.get(name))
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false)
    };
    (flag("backup_eligible"), flag("backup_state"))
}

/// The `authData` byte string in a CBOR attestation object (WebAuthn Level 3 §6.5.4): a map
/// with text keys `fmt`, `attStmt` and `authData`. Only definite lengths are accepted, as CTAP2
/// canonical encoding requires.
fn auth_data(object: &[u8]) -> Option<&[u8]> {
    let mut reader = Cbor { bytes: object };
    let (major, entries) = reader.head()?;
    if major != 5 {
        return None;
    }
    for _ in 0..entries {
        let (major, length) = reader.head()?;
        if major != 3 {
            return None;
        }
        let key = reader.take(length)?;
        if key == b"authData" {
            let (major, length) = reader.head()?;
            return (major == 2).then(|| reader.take(length)).flatten();
        }
        reader.skip(0)?;
    }
    None
}

struct Cbor<'a> {
    bytes: &'a [u8],
}

impl<'a> Cbor<'a> {
    fn byte(&mut self) -> Option<u8> {
        let (first, rest) = self.bytes.split_first()?;
        self.bytes = rest;
        Some(*first)
    }

    fn take(&mut self, length: u64) -> Option<&'a [u8]> {
        let length = usize::try_from(length).ok()?;
        if length > self.bytes.len() {
            return None;
        }
        let (taken, rest) = self.bytes.split_at(length);
        self.bytes = rest;
        Some(taken)
    }

    /// Major type and argument of the next item.
    fn head(&mut self) -> Option<(u8, u64)> {
        let initial = self.byte()?;
        let argument = match initial & 0x1F {
            small @ 0..=23 => u64::from(small),
            24 => u64::from(self.byte()?),
            25 => u64::from(u16::from_be_bytes(self.take(2)?.try_into().ok()?)),
            26 => u64::from(u32::from_be_bytes(self.take(4)?.try_into().ok()?)),
            27 => u64::from_be_bytes(self.take(8)?.try_into().ok()?),
            _ => return None,
        };
        Some((initial >> 5, argument))
    }

    fn skip(&mut self, depth: usize) -> Option<()> {
        if depth > 16 {
            return None;
        }
        let (major, argument) = self.head()?;
        match major {
            0 | 1 | 7 => Some(()),
            2 | 3 => self.take(argument).map(|_| ()),
            4 => (0..argument).try_for_each(|_| self.skip(depth + 1)),
            5 => (0..argument).try_for_each(|_| {
                self.skip(depth + 1)?;
                self.skip(depth + 1)
            }),
            6 => self.skip(depth + 1),
            _ => None,
        }
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
        let json = options;
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
        let mut data = vec![0; 32];
        data.push(0x45 | FLAG_BE | 0x10);
        data.extend_from_slice(&[0; 4]);
        data.extend_from_slice(aaguid.as_bytes());
        data.extend_from_slice(&[0, 1, 7]);
        let object = attestation_object(&data);
        let found = auth_data(&object).map(<[u8]>::to_vec);
        assert_eq!(found, Some(data.clone()));
        let mut response: RegisterPublicKeyCredential = serde_json::from_value(serde_json::json!({
            "id": "AA", "rawId": "AA", "type": "public-key", "extensions": {},
            "response": {"attestationObject": "", "clientDataJSON": ""}
        }))
        .unwrap();
        response.response.attestation_object = object;
        assert_eq!(
            authenticator(&response),
            Authenticator {
                aaguid: Some(aaguid.to_string()),
                backup_eligible: true
            }
        );
        // Zero AAGUID (attestation "none" on some platforms) and garbage give nothing.
        data[37..53].fill(0);
        response.response.attestation_object = attestation_object(&data);
        assert_eq!(authenticator(&response).aaguid, None);
        for garbage in [&[][..], &[0xA1], &[0xBF, 0xFF], &[0xA1, 0x7B, 0xFF]] {
            assert_eq!(auth_data(garbage), None);
        }
    }

    #[test]
    fn reads_backup_flags_from_records() {
        let record = r#"{"cred":{"backup_eligible":true,"backup_state":false}}"#;
        assert_eq!(backup_flags(record), (true, false));
        assert_eq!(backup_flags("{}"), (false, false));
        assert_eq!(backup_flags("not json"), (false, false));
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
