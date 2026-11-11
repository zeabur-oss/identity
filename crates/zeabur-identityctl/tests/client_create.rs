//! `zeabur-identityctl client create --output json`, run as a process.

#[cfg(test)]
mod tests {
    use std::process::{Command, Output};

    use zeabur_identity_api::client::{ClientRegistration, ClientType};
    use zeabur_identity_api::token_hash;

    fn client_create(args: &[&str]) -> Output {
        let output = Command::new(env!("CARGO_BIN_EXE_zeabur-identityctl"))
            .args(["client", "create"])
            .args(args)
            .env_remove("ZEABUR_IDENTITY_NAMESPACE")
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        output
    }

    #[test]
    fn json_output_carries_a_secret_that_matches_the_manifest_hash() {
        let output = client_create(&[
            "grafana",
            "--type",
            "confidential",
            "--redirect-uri",
            "https://grafana.example.com/login/generic_oauth",
            "--output",
            "json",
        ]);
        let registration: ClientRegistration = serde_json::from_slice(&output.stdout).unwrap();
        let secret = registration.secret.unwrap();

        assert_eq!(registration.client_id, "grafana");
        assert_eq!(
            registration.manifest.metadata.name.as_deref(),
            Some("grafana")
        );
        assert_eq!(
            registration.manifest.spec.secret_hash,
            Some(token_hash(secret.as_bytes()))
        );
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(
            !stderr.contains(&secret),
            "the secret is also on stderr: {stderr}"
        );
    }

    #[test]
    fn json_output_of_a_public_client_has_no_secret() {
        let output = client_create(&[
            "kubectl",
            "--type",
            "public",
            "--redirect-uri",
            "http://127.0.0.1/callback",
            "--output",
            "json",
        ]);
        let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert!(json.get("secret").is_none(), "{json}");
        let registration: ClientRegistration = serde_json::from_value(json).unwrap();
        assert_eq!(registration.manifest.spec.kind, ClientType::Public);
        assert_eq!(registration.manifest.spec.secret_hash, None);
    }
}
