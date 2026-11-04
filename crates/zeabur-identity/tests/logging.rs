//! Actual-binary checks for supplied logging overrides that cannot be decoded as UTF-8.

#![cfg(unix)]

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt as _;
    use std::process::Command;

    #[test]
    fn non_unicode_filter_warns_without_echoing_the_value() {
        let output = Command::new(env!("CARGO_BIN_EXE_zeabur-identity"))
            .args([
                "--issuer",
                "https://login.example.com",
                "--log-format",
                "json",
                "--token-lifetime",
                "1s",
            ])
            .env(
                "ZEABUR_IDENTITY_LOG",
                OsString::from_vec(b"PRIVATE_FILTER_SENTINEL\xff".to_vec()),
            )
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert_eq!(output.stderr.as_slice(), b"");
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert!(stdout.contains("\"reason\":\"invalid_filter\""));
        assert!(stdout.contains("\"reason\":\"invalid_configuration\""));
        assert!(!stdout.contains("PRIVATE_FILTER_SENTINEL"));
    }
}
