//! Account types, and the install-wide settings that decide how each type signs in.
//!
//! A regular account may use every sign-in method the server offers. An admin account's tokens
//! carry the admin group (`zeabur_identity_api::ADMIN_GROUP`), so [`Settings::admin_sign_in`]
//! decides which methods it may use. The default, [`AdminSignIn::TwoFactor`], asks for two
//! factors: a passkey, or a password with a TOTP code. NIST SP 800-63B-4 allows synced passkeys
//! up to AAL2 only, because syncing makes the key exportable ([sp800-63b]), so
//! [`AdminSignIn::DeviceBoundPasskey`] asks for a passkey whose authenticator reports the WebAuthn
//! backup eligibility flag (BE) as unset.
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
/// [`SETTINGS_CONFIG_MAP`] key for [`Settings::admin_sign_in`]: `any`, `two-factor`, `passkey` or
/// `device-bound-passkey`.
pub const ADMIN_SIGN_IN_KEY: &str = "admin-sign-in";

/// What kind of account a `User` is.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum AccountType {
    /// Day-to-day work. Signs in with every method the server offers.
    #[default]
    Regular,
    /// Administers the cluster. Signs in as [`Settings::admin_sign_in`] allows.
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

/// The sign-in methods an admin account may use, from the weakest to the strictest.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum AdminSignIn {
    /// Every method the server offers, a password alone included (AAL1).
    Any,
    /// A passkey, or a password with a second factor (AAL2).
    #[default]
    TwoFactor,
    /// Any passkey: phishing-resistant (AAL2).
    Passkey,
    /// Device-bound passkeys only (AAL3). Admin sessions also end after a short idle time.
    DeviceBoundPasskey,
}

/// Install-wide settings, from [`SETTINGS_CONFIG_MAP`]. A missing `ConfigMap` or key gives the
/// default.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Settings {
    /// How many teams share the cluster.
    pub teams: Teams,
    /// How admin accounts sign in.
    pub admin_sign_in: AdminSignIn,
}

impl Settings {
    /// Whether an idle admin session ends after the short admin limit.
    #[must_use]
    pub const fn short_admin_idle(self) -> bool {
        matches!(self.teams, Teams::Multiple)
            || matches!(self.admin_sign_in, AdminSignIn::DeviceBoundPasskey)
    }

    /// The settings in a `ConfigMap`'s `data`.
    ///
    /// A value that is not understood gives the strictest setting, and the key appears in the
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
        let admin_sign_in = match data.get(ADMIN_SIGN_IN_KEY).map(|v| v.trim()) {
            Some("any") => AdminSignIn::Any,
            None | Some("two-factor") => AdminSignIn::TwoFactor,
            Some("passkey") => AdminSignIn::Passkey,
            Some("device-bound-passkey") => AdminSignIn::DeviceBoundPasskey,
            Some(_) => {
                bad.push(ADMIN_SIGN_IN_KEY);
                AdminSignIn::DeviceBoundPasskey
            }
        };
        (
            Self {
                teams,
                admin_sign_in,
            },
            bad,
        )
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
    /// A linked GitHub, Google or OpenID account.
    Upstream,
    /// A password, with a second factor or without.
    Password {
        /// A TOTP or recovery code was checked too.
        second_factor: bool,
    },
}

/// Why an account cannot use a sign-in method.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// The setting allows admin accounts a passkey only.
    Passkey,
    /// The setting allows admin accounts a device-bound passkey only.
    DeviceBoundPasskey,
    /// Admin accounts need a passkey, or a password with a second factor.
    TwoFactor,
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
    if matches!(account, AccountType::Regular) {
        return Ok(());
    }
    match (settings.admin_sign_in, method) {
        (AdminSignIn::Any, _)
        | (AdminSignIn::TwoFactor | AdminSignIn::Passkey, Method::Passkey { .. })
        | (
            AdminSignIn::TwoFactor,
            Method::Password {
                second_factor: true,
            },
        )
        | (AdminSignIn::DeviceBoundPasskey, Method::Passkey { device_bound: true }) => Ok(()),
        (AdminSignIn::TwoFactor, Method::Upstream | Method::Password { .. }) => {
            Err(Refusal::TwoFactor)
        }
        (AdminSignIn::Passkey, Method::Upstream | Method::Password { .. }) => Err(Refusal::Passkey),
        (AdminSignIn::DeviceBoundPasskey, _) => Err(Refusal::DeviceBoundPasskey),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SYNCED: Method = Method::Passkey {
        device_bound: false,
    };
    const DEVICE: Method = Method::Passkey { device_bound: true };
    const PASSWORD: Method = Method::Password {
        second_factor: false,
    };
    const TWO_FACTOR: Method = Method::Password {
        second_factor: true,
    };
    const METHODS: [Method; 5] = [SYNCED, DEVICE, Method::Upstream, PASSWORD, TWO_FACTOR];

    fn admin(level: AdminSignIn, method: Method) -> Result<(), Refusal> {
        let settings = Settings {
            admin_sign_in: level,
            ..Settings::default()
        };
        allows(AccountType::Admin, settings, method)
    }

    #[test]
    fn regular_accounts_use_every_method_at_every_level() {
        for level in [
            AdminSignIn::Any,
            AdminSignIn::TwoFactor,
            AdminSignIn::Passkey,
            AdminSignIn::DeviceBoundPasskey,
        ] {
            let settings = Settings {
                admin_sign_in: level,
                ..Settings::default()
            };
            for method in METHODS {
                assert_eq!(allows(AccountType::Regular, settings, method), Ok(()));
            }
        }
    }

    #[test]
    fn each_level_allows_admins_what_it_names() {
        use AdminSignIn::{Any, DeviceBoundPasskey, Passkey, TwoFactor};
        let cases = [
            (Any, [Ok(()), Ok(()), Ok(()), Ok(()), Ok(())]),
            (
                TwoFactor,
                [
                    Ok(()),
                    Ok(()),
                    Err(Refusal::TwoFactor),
                    Err(Refusal::TwoFactor),
                    Ok(()),
                ],
            ),
            (
                Passkey,
                [
                    Ok(()),
                    Ok(()),
                    Err(Refusal::Passkey),
                    Err(Refusal::Passkey),
                    Err(Refusal::Passkey),
                ],
            ),
            (
                DeviceBoundPasskey,
                [
                    Err(Refusal::DeviceBoundPasskey),
                    Ok(()),
                    Err(Refusal::DeviceBoundPasskey),
                    Err(Refusal::DeviceBoundPasskey),
                    Err(Refusal::DeviceBoundPasskey),
                ],
            ),
        ];
        for (level, expected) in cases {
            for (method, expected) in METHODS.into_iter().zip(expected) {
                assert_eq!(admin(level, method), expected, "{level:?} {method:?}");
            }
        }
    }

    #[test]
    fn short_admin_idle_follows_teams_or_device_bound_passkeys() {
        let cases = [
            (Teams::Single, AdminSignIn::TwoFactor, false),
            (Teams::Multiple, AdminSignIn::TwoFactor, true),
            (Teams::Single, AdminSignIn::Passkey, false),
            (Teams::Single, AdminSignIn::DeviceBoundPasskey, true),
        ];
        for (teams, admin_sign_in, short) in cases {
            let settings = Settings {
                teams,
                admin_sign_in,
            };
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
        assert_eq!(Settings::default().admin_sign_in, AdminSignIn::TwoFactor);
        for (value, level) in [
            ("any", AdminSignIn::Any),
            ("two-factor", AdminSignIn::TwoFactor),
            ("passkey", AdminSignIn::Passkey),
            ("device-bound-passkey", AdminSignIn::DeviceBoundPasskey),
        ] {
            let (settings, bad) = Settings::from_data(&data(&[("admin-sign-in", value)]));
            assert_eq!((settings.admin_sign_in, bad), (level, vec![]));
        }
        // A value that is not understood fails closed to the strictest setting.
        assert_eq!(
            Settings::from_data(&data(&[("teams", "many"), ("admin-sign-in", "yes")])),
            (
                Settings {
                    teams: Teams::Multiple,
                    admin_sign_in: AdminSignIn::DeviceBoundPasskey,
                },
                vec![TEAMS_KEY, ADMIN_SIGN_IN_KEY]
            )
        );
    }
}
