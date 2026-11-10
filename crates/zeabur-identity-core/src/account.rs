//! Account types, and the install-wide settings that decide how each type signs in.
//!
//! An admin account signs in only with a passkey, never with a linked GitHub or Google account,
//! and its tokens carry the admin group (`zeabur_identity_api::ADMIN_GROUP`). A regular account may
//! use every sign-in method the server offers. With [`Settings::admin_aal3`], an admin account
//! also needs a device-bound passkey: one whose authenticator reports the WebAuthn backup
//! eligibility flag (BE) as unset. NIST SP 800-63B-4 allows synced passkeys up to AAL2 only,
//! because syncing makes the key exportable ([sp800-63b]).
//!
//! The authenticator reports BE itself. Attestation is `none`, so nothing verifies the flag.
//!
//! [sp800-63b]: https://pages.nist.gov/800-63-4/sp800-63b.html

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Name of the `ConfigMap` that holds [`Settings`], in Zeabur Identity's namespace.
pub const SETTINGS_CONFIG_MAP: &str = "zeabur-identity-settings";
/// [`SETTINGS_CONFIG_MAP`] key for [`Settings::teams`]: `single` or `multiple`.
pub const TEAMS_KEY: &str = "teams";
/// [`SETTINGS_CONFIG_MAP`] key for [`Settings::admin_aal3`]: `true` or `false`.
pub const ADMIN_AAL3_KEY: &str = "admin-aal3";

/// What kind of account a `User` is.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum AccountType {
    /// Day-to-day work. Signs in with every method the server offers.
    #[default]
    Regular,
    /// Administers the cluster. Signs in with a passkey only.
    Admin,
}

/// How many teams share the cluster. It decides how long an idle admin session lasts.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Teams {
    /// One team. The admin is often the only person, so admin sessions idle as long as regular
    /// ones.
    #[default]
    Single,
    /// Several teams. Admin sessions end after a short idle time.
    Multiple,
}

/// Install-wide settings, from [`SETTINGS_CONFIG_MAP`]. A missing `ConfigMap` or key gives the
/// default.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Settings {
    /// How many teams share the cluster.
    pub teams: Teams,
    /// Admin accounts need a device-bound passkey, and their sessions end after a short idle
    /// time.
    pub admin_aal3: bool,
}

impl Settings {
    /// Whether an idle admin session ends after the short admin limit.
    #[must_use]
    pub const fn short_admin_idle(self) -> bool {
        matches!(self.teams, Teams::Multiple) || self.admin_aal3
    }

    /// The settings in a `ConfigMap`'s `data`.
    ///
    /// A value that is not understood gives the stricter setting, and the key appears in the
    /// returned list of bad keys.
    #[must_use]
    pub fn from_data(data: &BTreeMap<String, String>) -> (Self, Vec<&'static str>) {
        let mut bad = Vec::new();
        let teams = match data.get(TEAMS_KEY).map(|v| v.trim()) {
            None | Some("single") => Teams::Single,
            Some("multiple") => Teams::Multiple,
            Some(_) => {
                bad.push(TEAMS_KEY);
                Teams::Multiple
            }
        };
        let admin_aal3 = match data.get(ADMIN_AAL3_KEY).map(|v| v.trim()) {
            None | Some("false") => false,
            Some("true") => true,
            Some(_) => {
                bad.push(ADMIN_AAL3_KEY);
                true
            }
        };
        (Self { teams, admin_aal3 }, bad)
    }
}

/// How someone signed in, or wants to add as a way to sign in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Method {
    /// A passkey. `device_bound` is true when its authenticator reported BE unset.
    Passkey {
        /// The passkey cannot be synced to other devices.
        device_bound: bool,
    },
    /// A linked GitHub or Google account.
    Upstream,
}

/// Why an account cannot use a sign-in method.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// Admin accounts sign in with a passkey only.
    AdminNeedsPasskey,
    /// With [`Settings::admin_aal3`], admin accounts need a device-bound passkey.
    AdminNeedsDeviceBoundPasskey,
}

/// Whether `account` may sign in with `method`, or register it, under `settings`.
///
/// # Errors
///
/// The [`Refusal`] that applies.
pub const fn allows(
    account: AccountType,
    settings: Settings,
    method: Method,
) -> Result<(), Refusal> {
    match (account, method) {
        (AccountType::Regular, Method::Passkey { .. } | Method::Upstream) => Ok(()),
        (AccountType::Admin, Method::Upstream) => Err(Refusal::AdminNeedsPasskey),
        (AccountType::Admin, Method::Passkey { device_bound }) => {
            if settings.admin_aal3 && !device_bound {
                Err(Refusal::AdminNeedsDeviceBoundPasskey)
            } else {
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SYNCED: Method = Method::Passkey {
        device_bound: false,
    };
    const DEVICE: Method = Method::Passkey { device_bound: true };

    #[test]
    fn admin_accounts_sign_in_with_passkeys_only() {
        for settings in [
            Settings::default(),
            Settings {
                teams: Teams::Multiple,
                admin_aal3: false,
            },
        ] {
            assert_eq!(
                allows(AccountType::Regular, settings, Method::Upstream),
                Ok(())
            );
            assert_eq!(allows(AccountType::Regular, settings, SYNCED), Ok(()));
            assert_eq!(
                allows(AccountType::Admin, settings, Method::Upstream),
                Err(Refusal::AdminNeedsPasskey)
            );
            assert_eq!(allows(AccountType::Admin, settings, SYNCED), Ok(()));
            assert_eq!(allows(AccountType::Admin, settings, DEVICE), Ok(()));
        }
    }

    #[test]
    fn aal3_refuses_synced_passkeys_for_admins_only() {
        let aal3 = Settings {
            teams: Teams::Single,
            admin_aal3: true,
        };
        assert_eq!(
            allows(AccountType::Admin, aal3, SYNCED),
            Err(Refusal::AdminNeedsDeviceBoundPasskey)
        );
        assert_eq!(allows(AccountType::Admin, aal3, DEVICE), Ok(()));
        assert_eq!(
            allows(AccountType::Admin, aal3, Method::Upstream),
            Err(Refusal::AdminNeedsPasskey)
        );
        assert_eq!(allows(AccountType::Regular, aal3, SYNCED), Ok(()));
        assert_eq!(allows(AccountType::Regular, aal3, Method::Upstream), Ok(()));
    }

    #[test]
    fn short_admin_idle_follows_teams_or_aal3() {
        let cases = [
            (Teams::Single, false, false),
            (Teams::Multiple, false, true),
            (Teams::Single, true, true),
            (Teams::Multiple, true, true),
        ];
        for (teams, admin_aal3, short) in cases {
            let settings = Settings { teams, admin_aal3 };
            assert_eq!(settings.short_admin_idle(), short, "{settings:?}");
        }
    }

    #[test]
    fn settings_from_a_config_map() {
        let data = |pairs: &[(&str, &str)]| -> BTreeMap<String, String> {
            pairs
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect()
        };
        assert_eq!(
            Settings::from_data(&data(&[])),
            (Settings::default(), vec![])
        );
        assert_eq!(
            Settings::from_data(&data(&[("teams", "multiple"), ("admin-aal3", "true")])),
            (
                Settings {
                    teams: Teams::Multiple,
                    admin_aal3: true
                },
                vec![]
            )
        );
        // A value that is not understood fails closed to the stricter setting.
        assert_eq!(
            Settings::from_data(&data(&[("teams", "many"), ("admin-aal3", "yes")])),
            (
                Settings {
                    teams: Teams::Multiple,
                    admin_aal3: true
                },
                vec![TEAMS_KEY, ADMIN_AAL3_KEY]
            )
        );
    }
}
