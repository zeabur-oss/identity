//! Interface languages: English, Traditional Chinese (Taiwan), Simplified Chinese.
//!
//! Wording and terms follow `docs/internal/wording.md` in the Zeabur repository.

use zeabur_identity_core::password::MIN_CHARS;

mod en;
mod zh_cn;
mod zh_tw;

/// A supported interface language.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lang {
    /// English.
    En,
    /// Traditional Chinese as used in Taiwan.
    ZhTw,
    /// Simplified Chinese as used in mainland China.
    ZhCn,
}

impl Lang {
    /// All languages, in the order the switcher shows them.
    pub const ALL: [Self; 3] = [Self::En, Self::ZhTw, Self::ZhCn];

    /// The BCP 47 tag.
    #[must_use]
    pub const fn tag(self) -> &'static str {
        match self {
            Self::En => "en",
            Self::ZhTw => "zh-TW",
            Self::ZhCn => "zh-CN",
        }
    }

    /// The messages.
    #[must_use]
    pub const fn messages(self) -> &'static Messages {
        match self {
            Self::En => &en::MESSAGES,
            Self::ZhTw => &zh_tw::MESSAGES,
            Self::ZhCn => &zh_cn::MESSAGES,
        }
    }

    /// The supported language matching one BCP 47 language range, if any.
    #[must_use]
    pub fn from_range(range: &str) -> Option<Self> {
        let range = range.trim().to_ascii_lowercase();
        let mut parts = range.split('-');
        match parts.next()? {
            "en" => Some(Self::En),
            "zh" => {
                let rest: Vec<&str> = parts.collect();
                // Script subtags decide first, then regions where Traditional script is used.
                if rest.contains(&"hant") || rest.iter().any(|r| matches!(*r, "tw" | "hk" | "mo")) {
                    Some(Self::ZhTw)
                } else {
                    Some(Self::ZhCn)
                }
            }
            _ => None,
        }
    }

    /// Chooses the language: an explicit `lang` parameter wins, then the `Accept-Language` header
    /// (highest quality first, RFC 9110 §12.5.4), then English.
    #[must_use]
    pub fn negotiate(explicit: Option<&str>, accept_language: Option<&str>) -> Self {
        if let Some(lang) = explicit.and_then(Self::from_range) {
            return lang;
        }
        let mut ranges: Vec<(u16, usize, &str)> = accept_language
            .unwrap_or_default()
            .split(',')
            .take(32)
            .enumerate()
            .filter_map(|(index, item)| {
                let mut fields = item.split(';');
                let range = fields.next()?.trim();
                let quality = fields
                    .find_map(|f| f.trim().strip_prefix("q="))
                    .map_or(Some(1000), |q| qvalue(q.trim()))?;
                (quality > 0).then_some((quality, index, range))
            })
            .collect();
        ranges.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
        ranges
            .iter()
            .find_map(|(_, _, range)| Self::from_range(range))
            .unwrap_or(Self::En)
    }
}

/// Parses an RFC 9110 §12.4.2 `qvalue` into thousandths: `0`, `0.5`, `0.125`, `1`, `1.000`.
fn qvalue(value: &str) -> Option<u16> {
    let (whole, fraction) = value.split_once('.').unwrap_or((value, ""));
    if fraction.len() > 3 || !fraction.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let thousandths: u16 = format!("{fraction:0<3}").parse().ok()?;
    match whole {
        "0" => Some(thousandths),
        "1" if thousandths == 0 => Some(1000),
        _ => None,
    }
}

/// What the error page says for one kind of failure.
#[derive(Debug, Clone, Copy)]
pub struct ErrorText {
    /// The situation.
    pub title: &'static str,
    /// What happened, in the reader's terms.
    pub cause: &'static str,
    /// What to do next; empty when the page shows the steps another way.
    pub next: &'static str,
}

/// Every string the sign-in pages show.
#[derive(Debug)]
#[expect(
    missing_docs,
    reason = "each field is named after where its text appears; see the English values"
)]
pub struct Messages {
    pub language_name: &'static str,
    pub nav_language: &'static str,
    pub login_title: &'static str,
    pub login_subtitle: &'static str,
    pub login_continue_to: &'static str,
    pub login_username: &'static str,
    pub login_passkey: &'static str,
    pub login_password: &'static str,
    pub login_submit: &'static str,
    pub password_failed: &'static str,
    pub login_code: &'static str,
    pub login_code_hint: &'static str,
    pub login_other_account: &'static str,
    pub code_failed: &'static str,
    pub admin_two_factor: &'static str,
    pub setup_totp_title: &'static str,
    pub setup_totp_body: &'static str,
    pub setup_totp_qr: &'static str,
    pub setup_totp_key_title: &'static str,
    pub setup_totp_key_body: &'static str,
    pub setup_totp_code: &'static str,
    pub setup_code_failed: &'static str,
    pub recovery_title: &'static str,
    pub recovery_body: &'static str,
    pub password_held: &'static str,
    pub password_missing: &'static str,
    pub busy: &'static str,
    pub setup_password: &'static str,
    /// With the minimum length.
    pub setup_password_hint: fn(usize) -> String,
    pub setup_password_submit: &'static str,
    pub setup_password_set: &'static str,
    pub setup_other_ways: &'static str,
    /// With the minimum length.
    pub weak_too_short: fn(usize) -> String,
    pub weak_too_long: &'static str,
    pub weak_common: &'static str,
    pub weak_context: &'static str,
    pub passkey_failed: &'static str,
    pub passkey_cancelled: &'static str,
    pub passkey_unsupported_title: &'static str,
    pub passkey_unsupported_body: &'static str,
    pub noscript_title: &'static str,
    pub noscript_body: &'static str,
    pub no_request_title: &'static str,
    pub no_request_body: &'static str,
    pub admin_passkey_only: &'static str,
    /// The account page leaves out providers that admin accounts may not use.
    pub admin_providers_held_back: &'static str,
    pub device_passkey_needed: &'static str,
    pub working: &'static str,
    pub generic_error: &'static str,
    pub setup_title: &'static str,
    pub setup_subtitle: &'static str,
    pub setup_label: &'static str,
    pub setup_label_hint: &'static str,
    pub setup_create: &'static str,
    pub setup_done_title: &'static str,
    pub setup_done_body: &'static str,
    pub setup_done_continue_body: &'static str,
    pub setup_invalid: &'static str,
    pub setup_missing_token: &'static str,
    pub error_title: &'static str,
    pub error_body: &'static str,
    pub error_detail_label: &'static str,
    /// Between two sentences joined in one paragraph: a space in English, nothing after 。.
    pub sentence_gap: &'static str,
    /// With the provider's name, for example GitHub.
    pub continue_with: fn(&str) -> String,
    pub upstream_or: &'static str,
    pub upstream_linked_title: &'static str,
    pub upstream_linked_body: &'static str,
    pub lost_passkey_title: &'static str,
    pub lost_passkey_body: &'static str,
    pub lost_passkey_note: &'static str,
    pub new_link_title: &'static str,
    pub new_link_body: &'static str,
    pub new_link_admin: &'static str,
    pub no_request_apps_body: &'static str,
    /// With the application's name.
    pub open_app: fn(&str) -> String,
    pub backup_title: &'static str,
    pub backup_body: &'static str,
    pub backup_new_link: &'static str,
    pub account_title: &'static str,
    pub account_signed_out: &'static str,
    /// With the username.
    pub signed_in_as: fn(&str) -> String,
    pub sign_out: &'static str,
    pub passkeys_title: &'static str,
    pub passkey_unnamed: &'static str,
    /// The name of a passkey without a label, with its creation date as a `<time>` element.
    pub passkey_unnamed_dated: fn(&str) -> String,
    /// With a date as a `<time>` element.
    pub passkey_added: fn(&str) -> String,
    /// With a date as a `<time>` element.
    pub passkey_last_used: fn(&str) -> String,
    pub passkey_synced: &'static str,
    pub passkey_device_bound: &'static str,
    pub passkey_this_device: &'static str,
    pub rename: &'static str,
    pub save: &'static str,
    pub cancel: &'static str,
    pub remove: &'static str,
    pub remove_title: &'static str,
    pub remove_body: &'static str,
    pub last_passkey_note: &'static str,
    pub add_passkey: &'static str,
    pub passkey_exists: &'static str,
    pub last_passkey_error: &'static str,
    pub changed_error: &'static str,
    pub passkey_gone_error: &'static str,
    pub signed_out_error: &'static str,
    pub confirm_working: &'static str,
    pub sessions_title: &'static str,
    pub sessions_note: &'static str,
    pub session_account: &'static str,
    pub session_this: &'static str,
    /// With a date as a `<time>` element.
    pub session_signed_in: fn(&str) -> String,
    /// With the passkey's label.
    pub session_passkey: fn(&str) -> String,
    pub sign_out_others: &'static str,
    pub manage_passkeys: &'static str,
    pub methods_title: &'static str,
    pub methods_note: &'static str,
    pub passkeys_none: &'static str,
    pub passkeys_one: &'static str,
    /// With the number of passkeys, two or more.
    pub passkeys_many: fn(usize) -> String,
    pub add: &'static str,
    pub change: &'static str,
    pub password_on: &'static str,
    pub password_on_authenticator: &'static str,
    pub linked: &'static str,
    pub not_linked: &'static str,
    pub link: &'static str,
    /// With the number of other sessions.
    pub sessions_others: fn(usize) -> String,
    /// With a date as a `<time>` element.
    pub linked_on: fn(&str) -> String,
    /// With the provider's name, for example GitHub.
    pub link_with: fn(&str) -> String,
    pub unlink_title: &'static str,
    pub unlink_body: &'static str,
    pub last_credential_error: &'static str,
    pub password_title: &'static str,
    pub password_note: &'static str,
    pub password_authenticator_note: &'static str,
    pub password_current: &'static str,
    pub password_new: &'static str,
    pub password_change: &'static str,
    pub password_remove: &'static str,
    pub password_remove_title: &'static str,
    pub password_remove_body: &'static str,
    pub password_remove_authenticator: &'static str,
    pub password_changed: &'static str,
    pub password_removed: &'static str,
    pub password_wrong: &'static str,
    pub password_conflict: &'static str,
    pub password_held_here: &'static str,
    pub password_exists: &'static str,
    pub authenticator_gone: &'static str,
    pub password_off: &'static str,
    pub password_add: &'static str,
    pub password_add_note: &'static str,
    pub password_added: &'static str,
    pub authenticator_replace: &'static str,
    pub authenticator_replace_title: &'static str,
    pub authenticator_replace_body: &'static str,
    pub authenticator_new_code: &'static str,
    pub authenticator_replaced: &'static str,
    pub authenticator_confirm: &'static str,
    pub authenticator_confirm_passkey: &'static str,
    pub recovery_regenerate: &'static str,
    pub recovery_regenerate_title: &'static str,
    pub recovery_regenerate_body: &'static str,
    pub recovery_regenerated: &'static str,
    pub recovery_saved: &'static str,
    pub passkey_sign_in_needed: &'static str,
    pub account_disabled: &'static str,
    pub ceremony_expired: &'static str,
    pub setup_passkey_exists: &'static str,
    pub err_request_expired: ErrorText,
    pub err_state_mismatch: ErrorText,
    pub err_malformed: ErrorText,
    pub err_unknown_client: ErrorText,
    pub err_redirect_uri: ErrorText,
    pub err_provider_denied: ErrorText,
    pub err_provider_failed: ErrorText,
    pub err_clock_skew: ErrorText,
    pub err_account_not_linked: ErrorText,
    pub err_account_already_linked: ErrorText,
    pub err_account_session: ErrorText,
    pub err_user_unavailable: ErrorText,
    pub err_admin_passkey: ErrorText,
    pub err_setup_link: ErrorText,
    pub err_server: ErrorText,
}

impl Messages {
    /// The hint under a new password field, with the minimum length.
    #[must_use]
    pub fn password_hint(&self) -> String {
        (self.setup_password_hint)(MIN_CHARS)
    }

    /// The refusal of a password that is too short, with the minimum length.
    #[must_use]
    pub fn too_short(&self) -> String {
        (self.weak_too_short)(MIN_CHARS)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn negotiation() {
        assert_eq!(Lang::negotiate(None, None), Lang::En);
        assert_eq!(Lang::negotiate(Some("zh-TW"), Some("en")), Lang::ZhTw);
        assert_eq!(
            Lang::negotiate(Some("fr"), Some("zh-CN")),
            Lang::ZhCn,
            "unsupported explicit falls through"
        );
        assert_eq!(
            Lang::negotiate(None, Some("zh-Hant-HK,en;q=0.5")),
            Lang::ZhTw
        );
        assert_eq!(Lang::negotiate(None, Some("zh-Hans")), Lang::ZhCn);
        assert_eq!(Lang::negotiate(None, Some("zh")), Lang::ZhCn);
        assert_eq!(
            Lang::negotiate(None, Some("fr, en;q=0.4, zh-TW;q=0.8")),
            Lang::ZhTw,
            "by quality"
        );
        assert_eq!(
            Lang::negotiate(None, Some("zh-TW;q=0, en")),
            Lang::En,
            "q=0 excluded"
        );
        assert_eq!(Lang::negotiate(None, Some("de")), Lang::En);
    }

    #[test]
    fn qvalues() {
        assert_eq!(qvalue("1"), Some(1000));
        assert_eq!(qvalue("1.000"), Some(1000));
        assert_eq!(qvalue("0.5"), Some(500));
        assert_eq!(qvalue("0.125"), Some(125));
        assert_eq!(qvalue("0"), Some(0));
        for bad in ["", "1.5", "2", "0.1234", "-0", "0.-1", "abc", ".5"] {
            assert_eq!(qvalue(bad), None, "{bad}");
        }
    }

    #[test]
    fn negotiate_never_panics_on_garbage() {
        for input in ["", ",,,", ";q=", "zh;q=abc", "*;q=0.5", &"x,".repeat(1000)] {
            assert!(Lang::ALL.contains(&Lang::negotiate(Some(input), Some(input))));
        }
    }

    #[test]
    fn every_language_has_text() {
        for lang in Lang::ALL {
            let m = lang.messages();
            assert!(
                !m.login_title.is_empty() && !m.setup_done_body.is_empty(),
                "{lang:?}"
            );
            assert!((m.continue_with)("GitHub").contains("GitHub"), "{lang:?}");
            assert!((m.open_app)("Wiki").contains("Wiki"), "{lang:?}");
            assert!((m.signed_in_as)("dana").contains("dana"), "{lang:?}");
            assert!((m.session_passkey)("Laptop").contains("Laptop"), "{lang:?}");
            assert!((m.link_with)("GitHub").contains("GitHub"), "{lang:?}");
            assert!((m.passkeys_many)(7).contains('7'), "{lang:?}");
            assert!((m.sessions_others)(7).contains('7'), "{lang:?}");
            assert!(
                m.password_hint().contains(&MIN_CHARS.to_string()),
                "{lang:?}"
            );
            assert!(m.too_short().contains(&MIN_CHARS.to_string()), "{lang:?}");
            for dated in [
                m.passkey_unnamed_dated,
                m.passkey_added,
                m.passkey_last_used,
                m.session_signed_in,
                m.linked_on,
            ] {
                assert!(
                    dated("<time>D</time>").contains("<time>D</time>"),
                    "{lang:?}"
                );
            }
        }
    }
}
