//! Actual-binary check that `setup-link` runs in a pod whose environment holds the server's
//! variables.

#[cfg(test)]
mod tests {
    use std::process::Command;

    #[test]
    fn server_variables_do_not_block_setup_link() {
        let hash = format!("sha256:{}", "0a".repeat(32));
        let output = Command::new(env!("CARGO_BIN_EXE_zeabur-identity"))
            .args(["setup-link", "--token-hash", &hash])
            .env("ZEABUR_IDENTITY_NAMESPACE", "zeabur-identity")
            .env("ZEABUR_IDENTITY_LISTEN", "0.0.0.0:8080")
            .env("KUBECONFIG", "/nonexistent/kubeconfig")
            .env_remove("KUBERNETES_SERVICE_HOST")
            .env_remove("KUBERNETES_SERVICE_PORT")
            .output()
            .unwrap();
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert_eq!(output.status.code(), Some(1), "{stdout}");
        assert!(
            stdout.contains("\"reason\":\"setup_link_failed\""),
            "{stdout}"
        );
    }
}
