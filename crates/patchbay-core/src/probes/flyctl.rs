//! `flyctl` — Fly.io's single flat config.
//!
//! Not installed on this machine; verified against the CLI's source
//! (`helpers/config.go`, `internal/config/config.go`). `FLY_CONFIG_DIR`, else
//! `~/.fly`, holding `config.yml`:
//!
//! ```yaml
//! access_token: FlyV1 fm2_...
//! metrics_token: ...
//! send_metrics: true
//! auto_update: true
//! last_login: 2026-08-11T09:14:22.481773+08:00
//! ```
//!
//! Two things worth knowing, both encoded below:
//!
//! * **No organisation is recorded.** `fly` is org-centric in use, but the org
//!   comes from `--org` / `FLY_ORG` at run time and is never written here. The
//!   probe must not invent one from a project's `fly.toml`, which is a
//!   different thing entirely.
//! * **`last_login` is not an expiry.** Fly tokens are macaroons that may carry
//!   their own expiry *inside the token string*, and reading that would mean
//!   reading the secret. So `expires_at` stays `None`.
//!
//! The binary is installed as `flyctl` and almost always aliased to `fly`;
//! both names are checked.

use serde::Deserialize;

use crate::paths::Paths;
use crate::probe::{unsupported_switch, unsupported_verify, Probe};
use crate::types::{PermissionsReport, Profile, SwitchOutcome, ToolStatus, VerifyOutcome};
use crate::util::{parse_timestamp, read_text};

pub struct FlyctlProbe {
    paths: Paths,
}

/// `access_token` and `metrics_token` are presence-only.
#[derive(Deserialize, Default)]
struct Config {
    #[serde(default)]
    access_token: Option<serde::de::IgnoredAny>,
    #[serde(default)]
    metrics_token: Option<serde::de::IgnoredAny>,
    #[serde(default)]
    last_login: Option<String>,
    #[serde(default)]
    auto_update: Option<bool>,
}

impl FlyctlProbe {
    pub const TOOL: &'static str = "flyctl";
    const PROFILE_ID: &'static str = "default";

    pub fn new(paths: Paths) -> Self {
        Self { paths }
    }
}

impl Probe for FlyctlProbe {
    fn tool(&self) -> &'static str {
        Self::TOOL
    }

    fn status(&self) -> anyhow::Result<ToolStatus> {
        let path = self.paths.fly_config();
        let installed =
            self.paths.has_binary("flyctl") || self.paths.has_binary("fly") || path.is_file();
        let mut status = ToolStatus::empty(Self::TOOL, installed);
        for note in self.paths.path_notes("fly") {
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

        let config: Config = match serde_yaml_ng::from_str(&text) {
            Ok(config) => config,
            Err(e) => {
                status.note(format!("fly config.yml is not valid YAML ({e})"));
                return Ok(status);
            }
        };

        if self.paths.env("FLY_ACCESS_TOKEN").is_some() || self.paths.env("FLY_API_TOKEN").is_some()
        {
            status.note(
                "a Fly token is set in the environment and overrides the stored one".to_string(),
            );
        }

        if config.access_token.is_none() {
            status.note(format!(
                "{} exists but holds no access_token; flyctl is not logged in",
                path.display()
            ));
            return Ok(status);
        }

        let last_login = config.last_login.as_deref().and_then(parse_timestamp);

        status.profiles.push(
            Profile::new(Self::PROFILE_ID)
                .label("fly.io login")
                // Deliberately not last_login: see the module docs.
                .expires_at(None)
                .with_meta("last_login", last_login.map(|at| at.to_rfc3339()))
                .with_meta("has_metrics_token", config.metrics_token.is_some())
                .with_meta("auto_update", config.auto_update)
                .with_meta("source", path.display().to_string()),
        );
        status.active = Some(Self::PROFILE_ID.to_string());

        status.note(
            "flyctl has one flat config with no profiles and no organisation: the org comes from \
             --org or FLY_ORG at run time, not from disk"
                .to_string(),
        );
        status.note(
            "the token is a macaroon stored in plain text in config.yml; any expiry is encoded \
             inside the token itself, which patchbay will not read"
                .to_string(),
        );

        Ok(status)
    }

    fn switch(&self, _profile_id: &str) -> anyhow::Result<SwitchOutcome> {
        Ok(unsupported_switch(
            Self::TOOL,
            "flyctl stores a single token with no profile concept; re-authenticate to change \
             accounts",
            Some("fly auth login"),
        ))
    }

    fn verify(&self) -> anyhow::Result<VerifyOutcome> {
        Ok(unsupported_verify(
            Self::TOOL,
            "patchbay does not run flyctl yet; `fly auth whoami` is a network call",
            Some("fly auth whoami"),
        ))
    }

    fn permissions(&self) -> anyhow::Result<PermissionsReport> {
        Ok(PermissionsReport::unsupported(
            Self::TOOL,
            "a Fly macaroon carries its own caveats inside the token, which patchbay will not \
             read; org membership decides the rest",
            Some("fly orgs list"),
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
        fs::create_dir_all(home.join(".fly")).unwrap();
        fs::write(home.join(".fly/config.yml"), body).unwrap();
        (dir, home)
    }

    const CONFIG: &str = "access_token: FlyV1 fm2_fakefixturemacaroon\n\
                          metrics_token: fake-fixture-metrics\n\
                          send_metrics: true\n\
                          auto_update: true\n\
                          last_login: 2026-08-11T09:14:22.481773+08:00\n";

    #[test]
    fn test_login_without_inventing_an_expiry_or_an_org() {
        let (_dir, home) = fixture(CONFIG);
        let status = FlyctlProbe::new(Paths::for_test(&home)).status().unwrap();
        assert_eq!(status.active.as_deref(), Some("default"));
        let profile = &status.profiles[0];
        assert!(profile.expires_at.is_none(), "last_login is not an expiry");
        assert_eq!(
            profile.meta["last_login"],
            "2026-08-11T01:14:22.481773+00:00"
        );
        assert_eq!(profile.meta["has_metrics_token"], true);
        assert!(profile.meta.get("org").is_none());
        assert!(status.notes.iter().any(|n| n.contains("no organisation")));

        let json = serde_json::to_string(&status).unwrap();
        assert!(!json.contains("fm2_fakefixturemacaroon"), "{json}");
        assert!(!json.contains("fake-fixture-metrics"), "{json}");
    }

    #[test]
    fn test_environment_token_is_flagged() {
        let (_dir, home) = fixture(CONFIG);
        let paths = Paths::for_test(&home).with_env("FLY_ACCESS_TOKEN", "fake-fixture-env");
        let status = FlyctlProbe::new(paths).status().unwrap();
        assert!(status.notes.iter().any(|n| n.contains("environment")));
        let json = serde_json::to_string(&status).unwrap();
        assert!(!json.contains("fake-fixture-env"), "{json}");
    }

    #[test]
    fn test_config_dir_override_is_followed_and_noted() {
        let dir = tempfile::tempdir().unwrap();
        let elsewhere = dir.path().join("fly-config");
        fs::create_dir_all(&elsewhere).unwrap();
        fs::write(elsewhere.join("config.yml"), CONFIG).unwrap();
        let paths =
            Paths::for_test(dir.path()).with_env("FLY_CONFIG_DIR", elsewhere.to_str().unwrap());
        let status = FlyctlProbe::new(paths).status().unwrap();
        assert_eq!(status.profiles.len(), 1);
        assert!(status.notes.iter().any(|n| n.contains("$FLY_CONFIG_DIR=")));
    }

    #[test]
    fn test_missing_malformed_and_tokenless() {
        let dir = tempfile::tempdir().unwrap();
        let status = FlyctlProbe::new(Paths::for_test(dir.path()))
            .status()
            .unwrap();
        assert!(!status.installed);
        assert!(status.profiles.is_empty());
        assert!(status.notes.is_empty());

        let (_dir, home) = fixture("access_token: [unclosed\n");
        let status = FlyctlProbe::new(Paths::for_test(&home)).status().unwrap();
        assert!(status.notes.iter().any(|n| n.contains("not valid YAML")));

        let (_dir, home) = fixture("send_metrics: true\n");
        let status = FlyctlProbe::new(Paths::for_test(&home)).status().unwrap();
        assert!(status.profiles.is_empty());
        assert!(status.notes.iter().any(|n| n.contains("not logged in")));
    }
}
