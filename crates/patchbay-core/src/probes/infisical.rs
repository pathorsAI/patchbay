//! `infisical` — logged-in users in `~/.infisical/infisical-config.json`.
//!
//! The JWT itself lives in the configured vault backend (keychain or an
//! encrypted file), not in this config, so `expires_at` is unknown. The config
//! also holds a `vaultBackendPassphrase`; the struct below deliberately has no
//! field for it, so it is dropped during parsing and can never reach a caller.

use serde::Deserialize;

use crate::paths::Paths;
use crate::probe::{unknown_profile, unsupported_switch, unsupported_verify, Probe};
use crate::types::{PermissionsReport, Profile, SwitchOutcome, ToolStatus, VerifyOutcome};
use crate::util::{read_text, run};

pub struct InfisicalProbe {
    paths: Paths,
}

#[derive(Deserialize)]
struct Config {
    #[serde(default, rename = "loggedInUserEmail")]
    logged_in_user_email: Option<String>,
    #[serde(default, rename = "LoggedInUserDomain")]
    logged_in_user_domain: Option<String>,
    #[serde(default, rename = "loggedInUsers")]
    logged_in_users: Vec<LoggedInUser>,
    #[serde(default, rename = "vaultBackendType")]
    vault_backend_type: Option<String>,
}

#[derive(Deserialize)]
struct LoggedInUser {
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    domain: Option<String>,
}

impl InfisicalProbe {
    pub const TOOL: &'static str = "infisical";
    /// `infisical user switch` is an interactive picker: it takes no profile
    /// argument and no non-interactive flag, so patchbay hands the command to
    /// the human rather than driving a TUI.
    const SWITCH_HINT: &'static str = "infisical user switch";

    pub fn new(paths: Paths) -> Self {
        Self { paths }
    }
}

impl Probe for InfisicalProbe {
    fn tool(&self) -> &'static str {
        Self::TOOL
    }

    fn status(&self) -> anyhow::Result<ToolStatus> {
        let path = self.paths.infisical_config();
        let installed = self.paths.has_binary("infisical") || path.is_file();
        let mut status = ToolStatus::empty(Self::TOOL, installed);

        let text = match read_text(&path) {
            Ok(Some(text)) => text,
            Ok(None) => return Ok(status),
            Err(e) => {
                status.note(e);
                return Ok(status);
            }
        };

        let config: Config = match serde_json::from_str(&text) {
            Ok(config) => config,
            Err(e) => {
                status.note(format!("infisical-config.json is not valid JSON ({e})"));
                return Ok(status);
            }
        };

        for user in &config.logged_in_users {
            let Some(email) = &user.email else { continue };
            status.profiles.push(
                Profile::new(email)
                    .with_meta("domain", user.domain.clone())
                    .with_meta("vault_backend", config.vault_backend_type.clone()),
            );
        }

        if let Some(active) = &config.logged_in_user_email {
            if !status.profiles.iter().any(|p| &p.id == active) {
                // The active account is not always mirrored into the list.
                status.profiles.push(
                    Profile::new(active)
                        .with_meta("domain", config.logged_in_user_domain.clone())
                        .with_meta("vault_backend", config.vault_backend_type.clone()),
                );
            }
            status.active = Some(active.clone());
        }

        if !status.profiles.is_empty() {
            status.note(format!(
                "token expiry is unknown because the JWT is kept in the {} vault backend, not in this config",
                config.vault_backend_type.as_deref().unwrap_or("configured")
            ));
        }

        Ok(status)
    }

    fn switch(&self, profile_id: &str) -> anyhow::Result<SwitchOutcome> {
        let status = self.status()?;
        if !status.profiles.iter().any(|p| p.id == profile_id) {
            return Ok(unknown_profile(Self::TOOL, profile_id, &status));
        }
        Ok(unsupported_switch(
            Self::TOOL,
            "`infisical user switch` is an interactive picker with no way to name a profile on the command line, so patchbay will not drive it blind",
            Some(Self::SWITCH_HINT),
        ))
    }

    fn verify(&self) -> anyhow::Result<VerifyOutcome> {
        if !self.paths.may_exec() || !self.paths.has_binary("infisical") {
            return Ok(unsupported_verify(
                Self::TOOL,
                "the infisical CLI is not available on PATH",
                Some("infisical login status"),
            ));
        }
        let out = run("infisical", &["login", "status"])?;
        Ok(if out.ok {
            VerifyOutcome::Valid {
                tool: Self::TOOL.to_string(),
                detail: out.message(),
            }
        } else {
            VerifyOutcome::Invalid {
                tool: Self::TOOL.to_string(),
                detail: out.message(),
            }
        })
    }

    fn permissions(&self) -> anyhow::Result<PermissionsReport> {
        Ok(PermissionsReport::unsupported(
            Self::TOOL,
            "Infisical permissions are per-project roles held server-side; patchbay does not query the API",
            Some("check the member's role in the Infisical project settings"),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    fn fixture(body: &str) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().to_path_buf();
        fs::create_dir_all(home.join(".infisical")).unwrap();
        fs::write(home.join(".infisical/infisical-config.json"), body).unwrap();
        (dir, home)
    }

    #[test]
    fn test_users_and_active_email() {
        let (_dir, home) = fixture(
            r#"{"loggedInUserEmail":"b@example.com","LoggedInUserDomain":"https://app.infisical.com/api","loggedInUsers":[{"email":"a@example.com","domain":"https://app.infisical.com/api"},{"email":"b@example.com","domain":"https://eu.infisical.com/api"}],"vaultBackendType":"file","vaultBackendPassphrase":"ZmFrZS1maXh0dXJl"}"#,
        );
        let status = InfisicalProbe::new(Paths::for_test(&home))
            .status()
            .unwrap();
        let ids: Vec<_> = status.profiles.iter().map(|p| p.id.as_str()).collect();
        assert_eq!(ids, vec!["a@example.com", "b@example.com"]);
        assert_eq!(status.active.as_deref(), Some("b@example.com"));
        assert_eq!(
            status.profiles[1].meta["domain"],
            "https://eu.infisical.com/api"
        );
        assert!(status.profiles.iter().all(|p| p.expires_at.is_none()));

        // The vault passphrase must never survive parsing.
        let json = serde_json::to_string(&status).unwrap();
        assert!(!json.contains("ZmFrZS1maXh0dXJl"), "{json}");
        assert!(!json.to_lowercase().contains("passphrase"), "{json}");
    }

    #[test]
    fn test_active_user_missing_from_the_list_is_still_a_profile() {
        let (_dir, home) =
            fixture(r#"{"loggedInUserEmail":"solo@example.com","loggedInUsers":[]}"#);
        let status = InfisicalProbe::new(Paths::for_test(&home))
            .status()
            .unwrap();
        assert_eq!(status.profiles.len(), 1);
        assert_eq!(status.active.as_deref(), Some("solo@example.com"));
    }

    #[test]
    fn test_missing_and_malformed() {
        let dir = tempfile::tempdir().unwrap();
        let status = InfisicalProbe::new(Paths::for_test(dir.path()))
            .status()
            .unwrap();
        assert!(!status.installed);
        assert!(status.profiles.is_empty());

        let (_dir, home) = fixture("{ this is not json");
        let status = InfisicalProbe::new(Paths::for_test(&home))
            .status()
            .unwrap();
        assert!(status.installed);
        assert!(status.profiles.is_empty());
        assert!(status.notes.iter().any(|n| n.contains("not valid JSON")));
    }

    #[test]
    fn test_switch_returns_the_interactive_command_as_a_hint() {
        let (_dir, home) = fixture(r#"{"loggedInUsers":[{"email":"a@example.com"}]}"#);
        let probe = InfisicalProbe::new(Paths::for_test(&home));
        match probe.switch("a@example.com").unwrap() {
            SwitchOutcome::Unsupported { hint, .. } => {
                assert_eq!(hint.as_deref(), Some("infisical user switch"));
            }
            other => panic!("expected Unsupported, got {other:?}"),
        }
        // Unknown ids are still reported as unknown, not as a hint.
        assert!(matches!(
            probe.switch("nobody@example.com").unwrap(),
            SwitchOutcome::UnknownProfile { .. }
        ));
    }
}
