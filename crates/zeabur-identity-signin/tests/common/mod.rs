//! Checks shared by the sign-in and upstream tests.

use serde_json::Value;

/// Checks the fields and message of one `zeabur_identity::audit` record against the documented
/// shape of its event (`crates/zeabur-identity/README.md`, "Audit events"). Operators filter on
/// these names, so a refactor must not rename, add or drop one.
pub fn assert_audit_shape(record: &Value) {
    let fields = record["fields"].as_object().unwrap();
    let event = fields["event"].as_str().unwrap();
    // The OAuth endpoints' events are checked by their own tests.
    if event.starts_with("oauth.") {
        return;
    }
    let outcome = fields["outcome"].as_str().unwrap();
    let success = match outcome {
        "success" => true,
        "failure" => false,
        other => panic!("outcome {other}"),
    };
    let method = fields.get("method").and_then(Value::as_str);
    let phase = fields.get("phase").and_then(Value::as_str);
    let (optional, required, messages): (&[&str], &[&str], [&str; 2]) = match (event, method) {
        ("auth.passkey_enrollment", Some("passkey")) => (
            &["user", "subject"],
            &["method", "phase"],
            match phase {
                Some("start") => ["passkey enrollment started", "passkey enrollment failed"],
                Some("finish") => ["passkey enrolled", "passkey enrollment failed"],
                other => panic!("phase {other:?}"),
            },
        ),
        ("auth.passkey_options", Some("passkey")) => (
            &[],
            &["method"],
            ["passkey options accepted", "passkey options failed"],
        ),
        ("auth.sign_in", Some("passkey")) => (
            &["user", "subject"],
            &["method"],
            ["signed in with a passkey", "passkey sign-in failed"],
        ),
        ("auth.sign_in", Some("password")) => (
            &["user", "subject"],
            &["method"],
            ["signed in with a password", "password sign-in failed"],
        ),
        ("auth.password_enrollment", Some("password")) => (
            &["user"],
            &["method"],
            ["password set", "setting a password failed"],
        ),
        ("auth.upstream_start", Some("upstream")) => (
            &["provider"],
            &["method"],
            ["upstream request started", "upstream request failed"],
        ),
        (
            "auth.upstream_callback"
            | "auth.sign_in"
            | "auth.account_link"
            | "account.upstream_linked",
            Some("upstream"),
        ) => (
            &["provider", "user", "subject"],
            &["method"],
            ["upstream operation completed", "upstream operation failed"],
        ),
        (event, None) if event.starts_with("account.") && success => (
            &[
                "actor",
                "subject",
                "credential",
                "aaguid",
                "session",
                "client_ip",
                "peer",
                "user_agent",
            ],
            &["revoked"],
            ["account changed", "account change failed"],
        ),
        (event, None) if event.starts_with("account.") => (
            &[
                "actor",
                "subject",
                "credential",
                "session",
                "client_ip",
                "peer",
                "user_agent",
            ],
            &[],
            ["account changed", "account change failed"],
        ),
        other => panic!("unknown audit event {other:?}: {record}"),
    };
    let message = if success { messages[0] } else { messages[1] };
    assert_eq!(fields["message"], message, "{record}");
    let reason: &[&str] = if success { &[] } else { &["reason"] };
    for key in required.iter().chain(reason) {
        assert!(fields.contains_key(*key), "{key} missing: {record}");
    }
    for key in fields.keys() {
        let known = ["event", "outcome", "message"].contains(&key.as_str())
            || optional.contains(&key.as_str())
            || required.contains(&key.as_str())
            || reason.contains(&key.as_str());
        assert!(known, "unexpected field {key}: {record}");
    }
}
