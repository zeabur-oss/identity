//! Interface languages: English, Traditional Chinese (Taiwan), Simplified Chinese.
//!
//! Wording and terms follow `docs/wording.md` in the Zeabur repository.

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
            Self::En => &EN,
            Self::ZhTw => &ZH_TW,
            Self::ZhCn => &ZH_CN,
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
    pub login_username_hint: &'static str,
    pub login_passkey: &'static str,
    pub passkey_failed: &'static str,
    pub passkey_cancelled: &'static str,
    pub passkey_unsupported_title: &'static str,
    pub passkey_unsupported_body: &'static str,
    pub noscript_title: &'static str,
    pub noscript_body: &'static str,
    pub no_request_title: &'static str,
    pub no_request_body: &'static str,
    pub admin_passkey_only: &'static str,
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
    /// `%provider%` is replaced with the provider's name, for example GitHub.
    pub continue_with: &'static str,
    pub upstream_or: &'static str,
    pub upstream_linked_title: &'static str,
    pub upstream_linked_body: &'static str,
    pub use_username: &'static str,
    pub lost_passkey_title: &'static str,
    pub lost_passkey_body: &'static str,
    pub lost_passkey_note: &'static str,
    pub new_link_title: &'static str,
    pub new_link_body: &'static str,
    pub new_link_admin: &'static str,
    pub no_request_apps_body: &'static str,
    /// `%app%` is replaced with the application's name.
    pub open_app: &'static str,
    pub backup_title: &'static str,
    pub backup_body: &'static str,
    pub backup_new_link: &'static str,
    pub account_title: &'static str,
    pub account_signed_out: &'static str,
    /// `%user%` is replaced with the username.
    pub signed_in_as: &'static str,
    pub sign_out: &'static str,
    pub passkeys_title: &'static str,
    pub passkey_unnamed: &'static str,
    /// The name of a passkey without a label. `%date%` is replaced with its creation date.
    pub passkey_unnamed_dated: &'static str,
    /// `%date%` is replaced with a date.
    pub passkey_added: &'static str,
    /// `%date%` is replaced with a date.
    pub passkey_last_used: &'static str,
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
    /// `%date%` is replaced with a date.
    pub session_signed_in: &'static str,
    /// `%name%` is replaced with the passkey's label.
    pub session_passkey: &'static str,
    pub sign_out_others: &'static str,
    pub manage_passkeys: &'static str,
    pub linked_title: &'static str,
    pub linked_note: &'static str,
    pub linked_none: &'static str,
    /// `%date%` is replaced with a date.
    pub linked_on: &'static str,
    /// `%provider%` is replaced with the provider's name, for example GitHub.
    pub link_with: &'static str,
    pub unlink_title: &'static str,
    pub unlink_body: &'static str,
    pub last_credential_error: &'static str,
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

/// English.
pub const EN: Messages = Messages {
    language_name: "English",
    nav_language: "Language",
    login_title: "Sign in",
    login_subtitle: "Use a passkey on this device or your phone.",
    login_continue_to: "Continue to",
    login_username: "Username",
    login_username_hint: "Optional. The browser can suggest a passkey here.",
    login_passkey: "Sign in with a passkey",
    passkey_failed: "Unable to verify the passkey. Try again or use another passkey.",
    passkey_cancelled: "The passkey dialog closed early. Try again.",
    passkey_unsupported_title: "This browser can’t use passkeys",
    passkey_unsupported_body: "Open this page in a current version of Safari, Chrome, Edge, or Firefox, or on your phone.",
    noscript_title: "JavaScript is turned off",
    noscript_body: "Passkeys need JavaScript. Turn it on for this site and reload the page.",
    no_request_title: "Nothing to sign in to",
    no_request_body: "Start from the app or command you want to use, such as kubectl. It opens this page when you need to sign in.",
    admin_passkey_only: "Admin accounts sign in with a passkey only.",
    device_passkey_needed: "This passkey syncs to other devices. Admin accounts here need a security key, or a passkey that stays on one device.",
    working: "Waiting for the passkey…",
    generic_error: "Unable to complete the request. Try again. If it keeps failing, contact your administrator.",
    setup_title: "Set up a passkey",
    setup_subtitle: "This one-time link adds a passkey to your account.",
    setup_label: "Passkey name",
    setup_label_hint: "Optional. A name such as “Work laptop” helps you recognize it later.",
    setup_create: "Create passkey",
    setup_done_title: "Passkey created",
    setup_done_body: "Sign in with this passkey from your app or kubectl. You can close this page.",
    setup_done_continue_body: "Use it to finish signing in.",
    setup_invalid: "This setup link is invalid, already used, or expired.",
    setup_missing_token: "This setup link is incomplete. Open the full link, including the part after “#”.",
    error_title: "Unable to continue sign-in",
    error_body: "Go back to the app and start again. If this keeps happening, contact your administrator.",
    error_detail_label: "Details",
    continue_with: "Continue with %provider%",
    upstream_or: "or",
    upstream_linked_title: "Account linked",
    upstream_linked_body: "You can now sign in with this account. You can close this page.",
    use_username: "Use a username",
    lost_passkey_title: "Lost all your passkeys?",
    lost_passkey_body: "Ask an administrator for a setup link. They can create one in Zeabur, under Members. If you’re the only administrator, run this on the server:",
    lost_passkey_note: "It removes your old passkeys and signs out every session, then prints a link for a new passkey.",
    new_link_title: "Get a new link",
    new_link_body: "If you already created a passkey with this link, sign in with it. Otherwise, whoever runs the server can make a new link by running this there:",
    new_link_admin: "An administrator can also create one in Zeabur, under Members.",
    no_request_apps_body: "Open an app below. It brings you here when you need to sign in.",
    open_app: "Open %app%",
    backup_title: "Add a backup passkey",
    backup_body: "Unless this passkey syncs to your other devices, add a second one on another device, such as your phone, so losing one device doesn’t lock you out.",
    backup_new_link: "This link works only once. For another, an administrator creates an invitation in Zeabur, under Members, or whoever runs the server runs this there:",
    account_title: "Account",
    account_signed_out: "Sign in to see your passkeys and where you’re signed in.",
    signed_in_as: "Signed in as %user%",
    sign_out: "Sign out",
    passkeys_title: "Passkeys",
    passkey_unnamed: "Passkey",
    passkey_unnamed_dated: "Passkey added %date%",
    passkey_added: "Added %date%",
    passkey_last_used: "Last used %date%",
    passkey_synced: "Synced",
    passkey_device_bound: "On one device",
    passkey_this_device: "This device",
    rename: "Rename",
    save: "Save",
    cancel: "Cancel",
    remove: "Remove",
    remove_title: "Remove this passkey?",
    remove_body: "You won’t be able to sign in with it, and sessions started with it are signed out. You’ll confirm with a passkey first.",
    last_passkey_note: "This is your only passkey, so it can’t be removed.",
    add_passkey: "Add a passkey",
    passkey_exists: "This passkey is already registered.",
    last_passkey_error: "Your other passkeys were removed in the meantime. Add another before removing this one.",
    changed_error: "Your passkeys changed in the meantime. Check the list and try again.",
    passkey_gone_error: "This passkey was already removed.",
    signed_out_error: "Your session ended. Reload the page and sign in again.",
    confirm_working: "Confirm with a passkey…",
    sessions_title: "Sessions",
    sessions_note: "Signing out an app stops it from renewing its access. What it already has expires within minutes.",
    session_account: "Account page",
    session_this: "This session",
    session_signed_in: "Signed in %date%",
    session_passkey: "Passkey: %name%",
    sign_out_others: "Sign out everywhere else",
    manage_passkeys: "Manage your passkeys",
    linked_title: "Linked accounts",
    linked_note: "Sign in to apps with one of these instead of a passkey. You’ll confirm with a passkey before you link or remove one.",
    linked_none: "No account linked yet.",
    linked_on: "Linked %date%",
    link_with: "Link %provider%",
    unlink_title: "Remove this linked account?",
    unlink_body: "You won’t be able to sign in with it, and sessions started with it are signed out. You’ll confirm with a passkey first.",
    last_credential_error: "This is your only way to sign in. Add a passkey before you remove it.",
    account_disabled: "This account is turned off, so the link doesn’t work. Ask an administrator to turn it back on, then open this link again.",
    ceremony_expired: "The passkey prompt expired. Try again.",
    setup_passkey_exists: "This passkey is already registered. Sign in with it instead.",
    err_request_expired: ErrorText {
        title: "This sign-in expired",
        cause: "The sign-in request timed out, was already used, or was started in another browser.",
        next: "Go back to the app and sign in again.",
    },
    err_state_mismatch: ErrorText {
        title: "This sign-in doesn’t match this browser",
        cause: "The provider’s answer doesn’t match a sign-in started here. This happens when the sign-in took more than 10 minutes, started in another browser, or the page was reloaded after it finished.",
        next: "Start again from the app in this browser. If it keeps happening, allow cookies for this site.",
    },
    err_malformed: ErrorText {
        title: "The app’s sign-in request can’t be used",
        cause: "The request is incomplete or not in the format Zeabur Identity expects.",
        next: "Go back to the app and try again. If it keeps happening, the app’s sign-in settings need fixing; the details below say what is wrong.",
    },
    err_unknown_client: ErrorText {
        title: "This app isn’t registered",
        cause: "Zeabur Identity has no client with the ID the app sent, so it can’t send you back to the app safely.",
        next: "An administrator needs to register the app as a client, or fix the client ID in the app’s settings.",
    },
    err_redirect_uri: ErrorText {
        title: "This app’s return address isn’t registered",
        cause: "The app asked to come back to an address that isn’t one of its registered redirect URIs, so Zeabur Identity won’t send you there.",
        next: "An administrator needs to add the app’s redirect URI to its client registration, or fix it in the app’s settings.",
    },
    err_provider_denied: ErrorText {
        title: "Sign-in was cancelled",
        cause: "The provider came back without signing you in, for example because you cancelled or denied access there.",
        next: "Start again from the app, or sign in with a passkey.",
    },
    err_provider_failed: ErrorText {
        title: "Unable to verify the provider’s answer",
        cause: "Zeabur Identity couldn’t reach the provider, or couldn’t verify what it sent back.",
        next: "Try again in a minute. If it keeps failing, whoever runs the server can check Zeabur Identity’s logs:",
    },
    err_clock_skew: ErrorText {
        title: "The server’s clock looks wrong",
        cause: "The provider’s sign-in token looks expired or issued in the future. This happens when the server’s clock is off by more than a minute.",
        next: "Whoever runs the server can check that its clock is synchronized:",
    },
    err_account_not_linked: ErrorText {
        title: "This account isn’t linked",
        cause: "No user signs in with this account yet.",
        next: "Sign in with a passkey, or open an invitation link and link the account there. An administrator creates invitations in Zeabur, under Members.",
    },
    err_account_already_linked: ErrorText {
        title: "This account is already linked",
        cause: "A user already signs in with this account, so it can’t be linked again.",
        next: "Sign in with it, or link a different account.",
    },
    err_account_session: ErrorText {
        title: "Linking didn’t finish",
        cause: "Linking has to finish in the account session that started it. That session ended, for example because you signed out.",
        next: "Open the account page, sign in, and link the account again.",
    },
    err_user_unavailable: ErrorText {
        title: "This user can’t sign in",
        cause: "The user linked to this account is turned off or no longer exists.",
        next: "Ask an administrator to turn the user back on, or to invite you again.",
    },
    err_admin_passkey: ErrorText {
        title: "Use a passkey for this account",
        cause: "This is an admin account. Admin accounts sign in with a passkey only, not with GitHub or Google.",
        next: "Go back and sign in with your passkey.",
    },
    err_setup_link: ErrorText {
        title: "This setup link no longer works",
        cause: "The link is invalid, already used, or expired.",
        next: "",
    },
    err_server: ErrorText {
        title: "Zeabur Identity couldn’t finish",
        cause: "Something failed on the server, for example Kubernetes didn’t answer in time.",
        next: "Try again in a minute. If it keeps failing, whoever runs the server can check Zeabur Identity’s logs:",
    },
};

/// Traditional Chinese (Taiwan).
pub const ZH_TW: Messages = Messages {
    language_name: "繁體中文",
    nav_language: "語言",
    login_title: "登入",
    login_subtitle: "使用這台裝置或手機上的通行密鑰。",
    login_continue_to: "繼續前往",
    login_username: "使用者名稱",
    login_username_hint: "選填。瀏覽器可以在這裡列出可用的通行密鑰。",
    login_passkey: "使用通行密鑰登入",
    passkey_failed: "無法驗證這個通行密鑰。再試一次，或改用其他通行密鑰。",
    passkey_cancelled: "通行密鑰對話窗在完成前就關閉了，再試一次。",
    passkey_unsupported_title: "這個瀏覽器無法使用通行密鑰",
    passkey_unsupported_body: "改用最新版的 Safari、Chrome、Edge 或 Firefox 開啟這個頁面，或在手機上開啟。",
    noscript_title: "JavaScript 已關閉",
    noscript_body: "通行密鑰需要 JavaScript。請為這個網站開啟 JavaScript，再重新載入頁面。",
    no_request_title: "目前沒有登入要求",
    no_request_body: "從要使用的應用程式或指令（例如 kubectl）開始，需要登入時就會開啟這個頁面。",
    admin_passkey_only: "管理員帳號只能用通行密鑰登入。",
    device_passkey_needed: "這個通行密鑰會同步到其他裝置。這裡的管理員帳號要用安全金鑰，或只存在一台裝置上的通行密鑰。",
    working: "正在等待通行密鑰…",
    generic_error: "無法完成操作。再試一次，如果仍然失敗，請聯絡管理員。",
    setup_title: "設定通行密鑰",
    setup_subtitle: "這個連結只能用一次，用來為你的帳號新增通行密鑰。",
    setup_label: "通行密鑰名稱",
    setup_label_hint: "選填。例如「公司筆電」，方便日後辨認。",
    setup_create: "建立通行密鑰",
    setup_done_title: "已建立通行密鑰",
    setup_done_body: "之後在應用程式或 kubectl 中用這個通行密鑰登入。現在可以關閉這個頁面。",
    setup_done_continue_body: "用它完成登入。",
    setup_invalid: "這個設定連結無效、已使用過或已過期。",
    setup_missing_token: "設定連結不完整。開啟完整的連結，含「#」之後的部分。",
    error_title: "無法繼續登入",
    error_body: "回到應用程式重新開始。如果一直發生，請聯絡管理員。",
    error_detail_label: "詳細資訊",
    continue_with: "使用 %provider% 繼續",
    upstream_or: "或",
    upstream_linked_title: "已連結帳號",
    upstream_linked_body: "之後可以用這個帳號登入。現在可以關閉這個頁面。",
    use_username: "輸入使用者名稱",
    lost_passkey_title: "通行密鑰全部遺失了？",
    lost_passkey_body: "請管理員給你一個設定連結，管理員可以在 Zeabur 的「成員」建立。如果你是唯一的管理員，在伺服器上執行：",
    lost_passkey_note: "這會移除舊的通行密鑰並登出所有工作階段，再印出建立新通行密鑰的連結。",
    new_link_title: "取得新的連結",
    new_link_body: "如果已經用這個連結建立了通行密鑰，直接用它登入；如果還沒有，管理伺服器的人可以在伺服器上執行這個指令，產生新的連結：",
    new_link_admin: "管理員也可以在 Zeabur 的「成員」建立新的連結。",
    no_request_apps_body: "開啟下方的應用程式，需要登入時，應用程式會帶你回到這裡。",
    open_app: "開啟 %app%",
    backup_title: "新增備用通行密鑰",
    backup_body: "如果這個通行密鑰不會同步到你的其他裝置，建議在另一台裝置（例如手機）上再建立一個，遺失一台裝置時仍然可以登入。",
    backup_new_link: "這個連結只能用一次。要再取得連結，管理員可以在 Zeabur 的「成員」建立邀請，或由管理伺服器的人在伺服器上執行：",
    account_title: "帳號",
    account_signed_out: "登入後可以查看你的通行密鑰，以及目前登入的位置。",
    signed_in_as: "目前以 %user% 登入",
    sign_out: "登出",
    passkeys_title: "通行密鑰",
    passkey_unnamed: "通行密鑰",
    passkey_unnamed_dated: "%date% 新增的通行密鑰",
    passkey_added: "%date% 新增",
    passkey_last_used: "上次使用：%date%",
    passkey_synced: "已同步",
    passkey_device_bound: "只存在一台裝置上",
    passkey_this_device: "這台裝置",
    rename: "重新命名",
    save: "儲存",
    cancel: "取消",
    remove: "移除",
    remove_title: "要移除這個通行密鑰嗎？",
    remove_body: "移除後就無法再用它登入，用它開始的工作階段也會登出。移除前需要先用通行密鑰確認身分。",
    last_passkey_note: "這是你唯一的通行密鑰，不能移除。",
    add_passkey: "新增通行密鑰",
    passkey_exists: "這個通行密鑰已經註冊過了。",
    last_passkey_error: "其他通行密鑰在這段期間已移除。請先新增另一個，再移除這個。",
    changed_error: "通行密鑰在這段期間有變動。確認清單後再試一次。",
    passkey_gone_error: "這個通行密鑰已經移除了。",
    signed_out_error: "工作階段已結束。重新載入頁面並再次登入。",
    confirm_working: "請用通行密鑰確認…",
    sessions_title: "工作階段",
    sessions_note: "應用程式登出後就無法再延長存取權限，已取得的權限會在幾分鐘內失效。",
    session_account: "帳號頁面",
    session_this: "目前的工作階段",
    session_signed_in: "%date% 登入",
    session_passkey: "通行密鑰：%name%",
    sign_out_others: "登出其他所有工作階段",
    manage_passkeys: "管理通行密鑰",
    linked_title: "連結的帳號",
    linked_note: "登入應用程式時，可以改用這些帳號，不必用通行密鑰。連結或移除前，要先用通行密鑰確認身分。",
    linked_none: "還沒有連結任何帳號。",
    linked_on: "%date% 連結",
    link_with: "連結 %provider%",
    unlink_title: "要移除這個連結的帳號嗎？",
    unlink_body: "移除後就無法再用它登入，用它開始的工作階段也會登出。移除前需要先用通行密鑰確認身分。",
    last_credential_error: "這是你唯一的登入方式，先新增通行密鑰再移除。",
    account_disabled: "這個帳號已停用，所以連結無法使用。請管理員重新啟用帳號，再開啟一次這個連結。",
    ceremony_expired: "通行密鑰的提示已逾時，再試一次。",
    setup_passkey_exists: "這個通行密鑰已經註冊過了，直接用它登入就好。",
    err_request_expired: ErrorText {
        title: "這次登入已過期",
        cause: "登入要求已逾時、已使用過，或是在其他瀏覽器開始的。",
        next: "回到應用程式重新登入。",
    },
    err_state_mismatch: ErrorText {
        title: "登入與這個瀏覽器不符",
        cause: "外部帳號傳回的結果，與這個瀏覽器開始的登入不符。登入超過 10 分鐘、在其他瀏覽器開始，或完成後重新載入頁面，都會發生這種情況。",
        next: "在這個瀏覽器中從應用程式重新開始。如果一直發生，請允許這個網站使用 Cookie。",
    },
    err_malformed: ErrorText {
        title: "無法使用應用程式的登入要求",
        cause: "要求不完整，或格式不符合 Zeabur Identity 的要求。",
        next: "回到應用程式再試一次。如果一直發生，代表應用程式的登入設定需要修正，下方的詳細資訊會說明問題。",
    },
    err_unknown_client: ErrorText {
        title: "這個應用程式尚未註冊",
        cause: "Zeabur Identity 找不到應用程式傳來的用戶端 ID，所以無法安全地帶你回到應用程式。",
        next: "需要管理員把應用程式註冊為用戶端，或修正應用程式設定中的用戶端 ID。",
    },
    err_redirect_uri: ErrorText {
        title: "應用程式的返回位址尚未註冊",
        cause: "應用程式要求返回的位址不在已註冊的重新導向 URI 中，所以 Zeabur Identity 不會把你送到那裡。",
        next: "需要管理員把應用程式的重新導向 URI 加入用戶端註冊，或修正應用程式設定。",
    },
    err_provider_denied: ErrorText {
        title: "已取消登入",
        cause: "外部帳號沒有完成登入就返回了，例如你在那裡取消或拒絕了存取。",
        next: "從應用程式重新開始，或改用通行密鑰登入。",
    },
    err_provider_failed: ErrorText {
        title: "無法驗證外部帳號的回應",
        cause: "Zeabur Identity 無法連線到外部帳號的服務，或無法驗證傳回的內容。",
        next: "過一分鐘再試。如果仍然失敗，管理伺服器的人可以檢視 Zeabur Identity 的日誌：",
    },
    err_clock_skew: ErrorText {
        title: "伺服器的時鐘可能不準",
        cause: "外部帳號的登入權杖看起來已過期，或簽發時間在未來。伺服器時鐘誤差超過一分鐘時，就會發生這種情況。",
        next: "管理伺服器的人可以檢查時鐘是否已同步：",
    },
    err_account_not_linked: ErrorText {
        title: "這個帳號尚未連結",
        cause: "目前沒有任何使用者以這個帳號登入。",
        next: "改用通行密鑰登入，或開啟邀請連結，在那裡連結這個帳號。管理員可以在 Zeabur 的「成員」建立邀請。",
    },
    err_account_already_linked: ErrorText {
        title: "這個帳號已經連結",
        cause: "已有使用者以這個帳號登入，所以無法再次連結。",
        next: "直接用它登入，或改連結其他帳號。",
    },
    err_account_session: ErrorText {
        title: "連結沒有完成",
        cause: "連結要在開始連結的那個帳號工作階段中完成，但這個工作階段已經結束，例如你已登出。",
        next: "開啟帳號頁面，登入後再連結一次。",
    },
    err_user_unavailable: ErrorText {
        title: "這位使用者無法登入",
        cause: "與這個帳號連結的使用者已停用或不存在。",
        next: "請管理員重新啟用這位使用者，或再次邀請你。",
    },
    err_admin_passkey: ErrorText {
        title: "這個帳號要用通行密鑰登入",
        cause: "這是管理員帳號。管理員帳號只能用通行密鑰登入，不能用 GitHub 或 Google。",
        next: "回上一頁，改用你的通行密鑰登入。",
    },
    err_setup_link: ErrorText {
        title: "這個設定連結已無法使用",
        cause: "連結無效、已使用過或已過期。",
        next: "",
    },
    err_server: ErrorText {
        title: "Zeabur Identity 無法完成操作",
        cause: "伺服器發生錯誤，例如 Kubernetes 沒有及時回應。",
        next: "過一分鐘再試。如果仍然失敗，管理伺服器的人可以檢視 Zeabur Identity 的日誌：",
    },
};

/// Simplified Chinese.
pub const ZH_CN: Messages = Messages {
    language_name: "简体中文",
    nav_language: "语言",
    login_title: "登录",
    login_subtitle: "使用此设备或手机上的通行密钥。",
    login_continue_to: "继续前往",
    login_username: "用户名",
    login_username_hint: "可选。浏览器可以在这里列出可用的通行密钥。",
    login_passkey: "使用通行密钥登录",
    passkey_failed: "无法验证通行密钥。请重试或改用其他通行密钥。",
    passkey_cancelled: "通行密钥对话框在完成前就关闭了，请重试。",
    passkey_unsupported_title: "此浏览器无法使用通行密钥",
    passkey_unsupported_body: "改用最新版的 Safari、Chrome、Edge 或 Firefox 打开此页面，或在手机上打开。",
    noscript_title: "JavaScript 已关闭",
    noscript_body: "通行密钥需要 JavaScript。请为此网站开启 JavaScript，然后重新加载页面。",
    no_request_title: "当前没有登录请求",
    no_request_body: "从要使用的应用或命令（例如 kubectl）开始，需要登录时就会打开此页面。",
    admin_passkey_only: "管理员账号只能用通行密钥登录。",
    device_passkey_needed: "这个通行密钥会同步到其他设备。这里的管理员账号要用安全密钥，或只保存在一台设备上的通行密钥。",
    working: "正在等待通行密钥…",
    generic_error: "无法完成操作。再试一次，如果仍然失败，请联系管理员。",
    setup_title: "设置通行密钥",
    setup_subtitle: "此一次性链接会为你的账号添加通行密钥。",
    setup_label: "通行密钥名称",
    setup_label_hint: "可选。例如“工作笔记本”，方便以后辨认。",
    setup_create: "创建通行密钥",
    setup_done_title: "已创建通行密钥",
    setup_done_body: "之后在应用或 kubectl 中用此通行密钥登录。现在可以关闭此页面。",
    setup_done_continue_body: "用它完成登录。",
    setup_invalid: "设置链接无效、已使用或已过期。",
    setup_missing_token: "设置链接不完整。打开完整链接，含“#”之后的部分。",
    error_title: "无法继续登录",
    error_body: "返回应用重新开始。如果一直出现，请联系管理员。",
    error_detail_label: "详细信息",
    continue_with: "使用 %provider% 继续",
    upstream_or: "或",
    upstream_linked_title: "已关联账号",
    upstream_linked_body: "之后可以用这个账号登录。现在可以关闭此页面。",
    use_username: "输入用户名",
    lost_passkey_title: "通行密钥全部丢失了？",
    lost_passkey_body: "请管理员给你一个设置链接，管理员可以在 Zeabur 的“成员”中创建。如果你是唯一的管理员，在服务器上运行：",
    lost_passkey_note: "这会移除旧的通行密钥并退出所有会话，然后输出创建新通行密钥的链接。",
    new_link_title: "获取新链接",
    new_link_body: "如果已经用此链接创建了通行密钥，直接用它登录；如果还没有，管理服务器的人可以在服务器上运行此命令，生成新链接：",
    new_link_admin: "管理员也可以在 Zeabur 的“成员”中创建新链接。",
    no_request_apps_body: "打开下方的应用，需要登录时，应用会带你回到这里。",
    open_app: "打开 %app%",
    backup_title: "添加备用通行密钥",
    backup_body: "如果此通行密钥不会同步到你的其他设备，建议在另一台设备（例如手机）上再创建一个，丢失一台设备时仍然可以登录。",
    backup_new_link: "此链接只能使用一次。要再获取链接，管理员可以在 Zeabur 的“成员”中创建邀请，或由管理服务器的人在服务器上运行：",
    account_title: "账号",
    account_signed_out: "登录后可以查看你的通行密钥，以及当前登录的位置。",
    signed_in_as: "当前以 %user% 登录",
    sign_out: "退出登录",
    passkeys_title: "通行密钥",
    passkey_unnamed: "通行密钥",
    passkey_unnamed_dated: "%date% 添加的通行密钥",
    passkey_added: "%date% 添加",
    passkey_last_used: "上次使用：%date%",
    passkey_synced: "已同步",
    passkey_device_bound: "只保存在一台设备上",
    passkey_this_device: "此设备",
    rename: "重命名",
    save: "保存",
    cancel: "取消",
    remove: "移除",
    remove_title: "要移除此通行密钥吗？",
    remove_body: "移除后就无法再用它登录，用它开始的会话也会退出登录。移除前需要先用通行密钥确认身份。",
    last_passkey_note: "这是你唯一的通行密钥，不能移除。",
    add_passkey: "添加通行密钥",
    passkey_exists: "此通行密钥已经注册过了。",
    last_passkey_error: "其他通行密钥在此期间已移除。请先添加另一个，再移除这个。",
    changed_error: "通行密钥在此期间有变动。确认列表后再试一次。",
    passkey_gone_error: "此通行密钥已经移除了。",
    signed_out_error: "会话已结束。重新加载页面并再次登录。",
    confirm_working: "请用通行密钥确认…",
    sessions_title: "会话",
    sessions_note: "应用退出登录后就无法再延长访问权限，已获得的权限会在几分钟内失效。",
    session_account: "账号页面",
    session_this: "当前会话",
    session_signed_in: "%date% 登录",
    session_passkey: "通行密钥：%name%",
    sign_out_others: "退出其他所有会话",
    manage_passkeys: "管理通行密钥",
    linked_title: "关联的账号",
    linked_note: "登录应用时，可以改用这些账号，不必用通行密钥。关联或移除前，需要先用通行密钥确认身份。",
    linked_none: "还没有关联任何账号。",
    linked_on: "%date% 关联",
    link_with: "关联 %provider%",
    unlink_title: "要移除此关联账号吗？",
    unlink_body: "移除后就无法再用它登录，用它开始的会话也会退出登录。移除前需要先用通行密钥确认身份。",
    last_credential_error: "这是你唯一的登录方式，先添加通行密钥再移除。",
    account_disabled: "此账号已停用，所以链接无法使用。请管理员重新启用账号，再打开一次此链接。",
    ceremony_expired: "通行密钥提示已超时，请重试。",
    setup_passkey_exists: "此通行密钥已经注册过了，直接用它登录即可。",
    err_request_expired: ErrorText {
        title: "本次登录已过期",
        cause: "登录请求已超时、已使用过，或是在其他浏览器中发起的。",
        next: "返回应用重新登录。",
    },
    err_state_mismatch: ErrorText {
        title: "登录与此浏览器不符",
        cause: "外部账号返回的结果与此浏览器中发起的登录不符。登录超过 10 分钟、在其他浏览器中发起，或完成后重新加载页面，都会出现这种情况。",
        next: "在此浏览器中从应用重新开始。如果一直出现，请允许此网站使用 Cookie。",
    },
    err_malformed: ErrorText {
        title: "无法使用应用的登录请求",
        cause: "请求不完整，或格式不符合 Zeabur Identity 的要求。",
        next: "返回应用再试一次。如果一直出现，说明应用的登录配置需要修正，下方的详细信息会说明问题。",
    },
    err_unknown_client: ErrorText {
        title: "此应用尚未注册",
        cause: "Zeabur Identity 找不到应用发来的客户端 ID，所以无法安全地带你返回应用。",
        next: "需要管理员将应用注册为客户端，或修正应用配置中的客户端 ID。",
    },
    err_redirect_uri: ErrorText {
        title: "应用的返回地址尚未注册",
        cause: "应用要求返回的地址不在已注册的重定向 URI 中，所以 Zeabur Identity 不会把你送到那里。",
        next: "需要管理员将应用的重定向 URI 加入客户端注册，或修正应用配置。",
    },
    err_provider_denied: ErrorText {
        title: "已取消登录",
        cause: "外部账号未完成登录就返回了，例如你在那里取消或拒绝了访问。",
        next: "从应用重新开始，或改用通行密钥登录。",
    },
    err_provider_failed: ErrorText {
        title: "无法验证外部账号的响应",
        cause: "Zeabur Identity 无法连接外部账号的服务，或无法验证返回的内容。",
        next: "过一分钟再试。如果仍然失败，管理服务器的人可以查看 Zeabur Identity 的日志：",
    },
    err_clock_skew: ErrorText {
        title: "服务器时钟可能不准",
        cause: "外部账号的登录令牌看起来已过期，或签发时间在未来。服务器时钟误差超过一分钟时，就会出现这种情况。",
        next: "管理服务器的人可以检查时钟是否已同步：",
    },
    err_account_not_linked: ErrorText {
        title: "此账号尚未关联",
        cause: "目前没有任何用户使用此账号登录。",
        next: "改用通行密钥登录，或打开邀请链接，在那里关联此账号。管理员可以在 Zeabur 的“成员”中创建邀请。",
    },
    err_account_already_linked: ErrorText {
        title: "此账号已关联",
        cause: "已有用户使用此账号登录，所以无法再次关联。",
        next: "直接用它登录，或改为关联其他账号。",
    },
    err_account_session: ErrorText {
        title: "关联没有完成",
        cause: "关联要在发起关联的那个账号会话中完成，但这个会话已经结束，例如你已退出登录。",
        next: "打开账号页面，登录后再关联一次。",
    },
    err_user_unavailable: ErrorText {
        title: "此用户无法登录",
        cause: "与此账号关联的用户已停用或不存在。",
        next: "请管理员重新启用此用户，或再次邀请你。",
    },
    err_admin_passkey: ErrorText {
        title: "此账号要用通行密钥登录",
        cause: "这是管理员账号。管理员账号只能用通行密钥登录，不能用 GitHub 或 Google。",
        next: "返回上一页，改用你的通行密钥登录。",
    },
    err_setup_link: ErrorText {
        title: "此设置链接已无法使用",
        cause: "链接无效、已使用过或已过期。",
        next: "",
    },
    err_server: ErrorText {
        title: "Zeabur Identity 无法完成操作",
        cause: "服务器出错，例如 Kubernetes 没有及时响应。",
        next: "过一分钟再试。如果仍然失败，管理服务器的人可以查看 Zeabur Identity 的日志：",
    },
};

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
            assert!(m.continue_with.contains("%provider%"), "{lang:?}");
            assert!(m.open_app.contains("%app%"), "{lang:?}");
            assert!(m.signed_in_as.contains("%user%"), "{lang:?}");
            assert!(m.session_passkey.contains("%name%"), "{lang:?}");
            assert!(m.link_with.contains("%provider%"), "{lang:?}");
            for dated in [
                m.passkey_unnamed_dated,
                m.passkey_added,
                m.passkey_last_used,
                m.session_signed_in,
                m.linked_on,
            ] {
                assert!(dated.contains("%date%"), "{lang:?}");
            }
        }
    }
}
