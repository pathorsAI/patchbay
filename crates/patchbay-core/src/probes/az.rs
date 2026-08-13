//! `az` — Azure subscriptions from `~/.azure/azureProfile.json`.
//!
//! Profiles are subscriptions (id = subscription id), and the one with
//! `isDefault` is active. Azure writes this file with a UTF-8 BOM, which
//! [`read_text`] strips.
//!
//! Tokens live in a separate MSAL cache (keychain-backed on macOS), so
//! `expires_at` is unknown rather than absent.

use serde::Deserialize;

use crate::paths::Paths;
use crate::probe::{unknown_profile, unsupported_switch, Probe};
use crate::types::{PermissionsReport, Profile, SwitchOutcome, ToolStatus, VerifyOutcome};
use crate::util::read_text;

pub struct AzProbe {
    paths: Paths,
}

#[derive(Deserialize)]
struct AzureProfile {
    #[serde(default)]
    subscriptions: Vec<Subscription>,
}

#[derive(Deserialize)]
struct Subscription {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    state: Option<String>,
    #[serde(default, rename = "isDefault")]
    is_default: bool,
    #[serde(default, rename = "tenantId")]
    tenant_id: Option<String>,
    #[serde(default, rename = "tenantDefaultDomain")]
    tenant_default_domain: Option<String>,
    #[serde(default, rename = "environmentName")]
    environment_name: Option<String>,
    #[serde(default)]
    user: Option<User>,
}

#[derive(Deserialize)]
struct User {
    #[serde(default)]
    name: Option<String>,
    #[serde(default, rename = "type")]
    kind: Option<String>,
}

impl AzProbe {
    pub const TOOL: &'static str = "az";

    pub fn new(paths: Paths) -> Self {
        Self { paths }
    }

    /// Accept a subscription id or its display name — humans and agents both
    /// tend to reach for the name.
    fn resolve(status: &ToolStatus, profile_id: &str) -> Option<String> {
        status
            .profiles
            .iter()
            .find(|p| p.id == profile_id)
            .or_else(|| {
                status
                    .profiles
                    .iter()
                    .find(|p| p.label.eq_ignore_ascii_case(profile_id))
            })
            .map(|p| p.id.clone())
    }
}

impl Probe for AzProbe {
    fn tool(&self) -> &'static str {
        Self::TOOL
    }

    fn status(&self) -> anyhow::Result<ToolStatus> {
        let path = self.paths.azure_profile();
        let installed = self.paths.has_binary("az") || path.is_file();
        let mut status = ToolStatus::empty(Self::TOOL, installed);
        for note in self.paths.path_notes("azure") {
            status.note(note);
        }

        let text = match read_text(&path) {
            Ok(Some(text)) => text,
            Ok(None) => return Ok(status),
            Err(e) => {
                status.note(e);
                return Ok(status);
            }
        };

        let profile: AzureProfile = match serde_json::from_str(&text) {
            Ok(profile) => profile,
            Err(e) => {
                status.note(format!("azureProfile.json is not valid JSON ({e})"));
                return Ok(status);
            }
        };

        let mut disabled = Vec::new();
        for subscription in profile.subscriptions {
            let Some(id) = subscription.id else { continue };
            let name = subscription.name.clone().unwrap_or_else(|| id.clone());
            if subscription
                .state
                .as_deref()
                .is_some_and(|s| !s.eq_ignore_ascii_case("Enabled"))
            {
                disabled.push(name.clone());
            }
            if subscription.is_default {
                status.active = Some(id.clone());
            }
            status.profiles.push(
                Profile::new(&id)
                    .label(&name)
                    .with_meta(
                        "user",
                        subscription.user.as_ref().and_then(|u| u.name.clone()),
                    )
                    .with_meta(
                        "user_type",
                        subscription.user.as_ref().and_then(|u| u.kind.clone()),
                    )
                    .with_meta("state", subscription.state.clone())
                    .with_meta("tenant_id", subscription.tenant_id.clone())
                    .with_meta("tenant_domain", subscription.tenant_default_domain.clone())
                    .with_meta("environment", subscription.environment_name.clone()),
            );
        }

        if !status.profiles.is_empty() {
            if status.active.is_none() {
                status.note(
                    "no subscription is marked as default; `az` commands will need --subscription"
                        .to_string(),
                );
            }
            if !disabled.is_empty() {
                status.note(format!(
                    "subscriptions not in the Enabled state: {}",
                    disabled.join(", ")
                ));
            }
            status.note(
                "token expiry is unknown because the Azure CLI keeps tokens in a separate MSAL cache".to_string(),
            );
        }

        Ok(status)
    }

    fn switch(&self, profile_id: &str) -> anyhow::Result<SwitchOutcome> {
        let status = self.status()?;
        let Some(id) = Self::resolve(&status, profile_id) else {
            return Ok(unknown_profile(Self::TOOL, profile_id, &status));
        };
        if !self.paths.may_exec() {
            return Ok(unsupported_switch(
                Self::TOOL,
                "command execution is disabled for this probe",
                Some(&format!("az account set --subscription {id}")),
            ));
        }

        let out = self
            .paths
            .run("az", &["account", "set", "--subscription", &id])?;
        Ok(if out.ok {
            SwitchOutcome::Switched {
                tool: Self::TOOL.to_string(),
                profile_id: id.clone(),
                detail: format!("az account set --subscription {id}"),
                notes: vec![
                    "this changes the default subscription only; the signed-in account and tenant are unchanged".to_string(),
                ],
            }
        } else {
            SwitchOutcome::Failed {
                tool: Self::TOOL.to_string(),
                profile_id: id,
                detail: out.message(),
            }
        })
    }

    fn verify(&self) -> anyhow::Result<VerifyOutcome> {
        if !self.paths.may_exec() || !self.paths.has_binary("az") {
            return Ok(crate::probe::unsupported_verify(
                Self::TOOL,
                "the az CLI is not available on PATH",
                Some("az account get-access-token"),
            ));
        }
        // `--output none` keeps the minted token off stdout entirely.
        let out = self
            .paths
            .run("az", &["account", "get-access-token", "--output", "none"])?;
        Ok(if out.ok {
            VerifyOutcome::Valid {
                tool: Self::TOOL.to_string(),
                detail: "the active subscription minted an access token".to_string(),
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
            "Azure RBAC role assignments are per-scope; patchbay does not query them",
            Some("az role assignment list --assignee <user> --all"),
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
        fs::create_dir_all(home.join(".azure")).unwrap();
        fs::write(home.join(".azure/azureProfile.json"), body).unwrap();
        (dir, home)
    }

    const PROFILE: &str = r#"{"installationId":"fake","subscriptions":[
      {"id":"11111111-1111-1111-1111-111111111111","name":"Students","state":"Disabled","user":{"name":"a@example.com","type":"user"},"isDefault":false,"tenantId":"tttt","tenantDefaultDomain":"example.com","environmentName":"AzureCloud"},
      {"id":"22222222-2222-2222-2222-222222222222","name":"Production","state":"Enabled","user":{"name":"b@example.com","type":"user"},"isDefault":true,"tenantId":"uuuu","environmentName":"AzureCloud"}
    ]}"#;

    #[test]
    fn test_subscriptions_and_default() {
        let (_dir, home) = fixture(PROFILE);
        let status = AzProbe::new(Paths::for_test(&home)).status().unwrap();
        assert_eq!(status.profiles.len(), 2);
        assert_eq!(
            status.active.as_deref(),
            Some("22222222-2222-2222-2222-222222222222")
        );
        assert_eq!(status.profiles[0].label, "Students");
        assert_eq!(status.profiles[0].meta["user"], "a@example.com");
        assert_eq!(status.profiles[0].meta["tenant_domain"], "example.com");
        assert!(status.profiles.iter().all(|p| p.expires_at.is_none()));
        assert!(status
            .notes
            .iter()
            .any(|n| n.contains("not in the Enabled state")));
    }

    #[test]
    fn test_bom_prefixed_file_parses() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().to_path_buf();
        fs::create_dir_all(home.join(".azure")).unwrap();
        let mut bytes = vec![0xEF, 0xBB, 0xBF];
        bytes.extend_from_slice(PROFILE.as_bytes());
        fs::write(home.join(".azure/azureProfile.json"), bytes).unwrap();

        let status = AzProbe::new(Paths::for_test(&home)).status().unwrap();
        assert_eq!(status.profiles.len(), 2);
    }

    #[test]
    fn test_switch_accepts_id_or_display_name() {
        let (_dir, home) = fixture(PROFILE);
        let probe = AzProbe::new(Paths::for_test(&home));
        let status = probe.status().unwrap();
        assert_eq!(
            AzProbe::resolve(&status, "Students").as_deref(),
            Some("11111111-1111-1111-1111-111111111111")
        );
        assert_eq!(
            AzProbe::resolve(&status, "11111111-1111-1111-1111-111111111111").as_deref(),
            Some("11111111-1111-1111-1111-111111111111")
        );
        assert!(AzProbe::resolve(&status, "nope").is_none());
        assert!(matches!(
            probe.switch("nope").unwrap(),
            SwitchOutcome::UnknownProfile { .. }
        ));
    }

    #[test]
    fn test_no_default_subscription_is_flagged() {
        let (_dir, home) = fixture(
            r#"{"subscriptions":[{"id":"abc","name":"Only","state":"Enabled","isDefault":false}]}"#,
        );
        let status = AzProbe::new(Paths::for_test(&home)).status().unwrap();
        assert!(status.active.is_none());
        assert!(status
            .notes
            .iter()
            .any(|n| n.contains("no subscription is marked as default")));
    }

    #[test]
    fn test_missing_and_malformed() {
        let dir = tempfile::tempdir().unwrap();
        let status = AzProbe::new(Paths::for_test(dir.path())).status().unwrap();
        assert!(!status.installed);
        assert!(status.profiles.is_empty());

        let (_dir, home) = fixture("{\"subscriptions\": [ truncated");
        let status = AzProbe::new(Paths::for_test(&home)).status().unwrap();
        assert!(status.profiles.is_empty());
        assert!(status.notes.iter().any(|n| n.contains("not valid JSON")));
    }
}
