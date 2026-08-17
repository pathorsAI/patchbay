//! `vercel` — the single global login the Vercel CLI keeps on disk.
//!
//! Paths verified **empirically** on macOS (Vercel CLI installed via pnpm):
//! `~/Library/Application Support/com.vercel.cli/` holds `auth.json` (a `token`
//! key, plus two `// Note` / `// Docs` comment keys) and `config.json` (global
//! preferences; `currentTeam` appears there once you have scoped the CLI to a
//! team). The CLI resolves that directory through `xdg-app-paths`, so an
//! explicit `XDG_CONFIG_HOME` moves it; `~/.now` is the pre-rename location.
//!
//! A Vercel CLI token does not expire: it is long-lived and stops working only
//! when it is revoked at the dashboard. That is [`Expiry::NoExpiry`], a fact
//! about the credential rather than a gap in what patchbay can read.
//!
//! `token` is typed as [`serde::de::IgnoredAny`]: serde confirms the key exists
//! and discards the value, so the token never leaves the parser's stack.

use std::path::PathBuf;

use serde::Deserialize;

use crate::paths::Paths;
use crate::probe::{unsupported_switch, unsupported_verify, Probe};
use crate::types::{Expiry, PermissionsReport, Profile, SwitchOutcome, ToolStatus, VerifyOutcome};
use crate::util::read_text;

pub struct VercelProbe {
    paths: Paths,
}

#[derive(Deserialize)]
struct Auth {
    #[serde(default)]
    token: Option<serde::de::IgnoredAny>,
}

#[derive(Deserialize)]
struct Config {
    #[serde(default, rename = "currentTeam")]
    current_team: Option<String>,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    username: Option<String>,
    /// Older CLIs kept the token in `config.json` instead of `auth.json`.
    #[serde(default)]
    token: Option<serde::de::IgnoredAny>,
}

impl VercelProbe {
    pub const TOOL: &'static str = "vercel";
    /// Vercel has one login, not a set; the id keeps `switch` honest.
    const PROFILE_ID: &'static str = "default";

    pub fn new(paths: Paths) -> Self {
        Self { paths }
    }

    /// First config directory that actually holds an `auth.json` or a
    /// `config.json`, in the order [`Paths::vercel_dirs`] lists them.
    fn config_dir(&self) -> Option<PathBuf> {
        self.paths
            .vercel_dirs()
            .into_iter()
            .find(|dir| dir.join("auth.json").is_file() || dir.join("config.json").is_file())
    }
}

impl Probe for VercelProbe {
    fn tool(&self) -> &'static str {
        Self::TOOL
    }

    fn status(&self) -> anyhow::Result<ToolStatus> {
        let dir = self.config_dir();
        let installed = self.paths.has_binary("vercel") || dir.is_some();
        let mut status = ToolStatus::empty(Self::TOOL, installed);
        for note in self.paths.path_notes("vercel") {
            status.push_note(note);
        }

        let Some(dir) = dir else {
            return Ok(status);
        };

        let auth: Option<Auth> = match read_text(&dir.join("auth.json")) {
            Ok(Some(text)) => match serde_json::from_str(&text) {
                Ok(auth) => Some(auth),
                Err(e) => {
                    status.problem(format!("auth.json is not valid JSON ({e})"));
                    None
                }
            },
            Ok(None) => None,
            Err(e) => {
                status.problem(e);
                None
            }
        };

        let config: Option<Config> = match read_text(&dir.join("config.json")) {
            Ok(Some(text)) => match serde_json::from_str(&text) {
                Ok(config) => Some(config),
                Err(e) => {
                    status.problem(format!("config.json is not valid JSON ({e})"));
                    None
                }
            },
            Ok(None) => None,
            Err(e) => {
                status.problem(e);
                None
            }
        };

        let has_token = auth.as_ref().is_some_and(|a| a.token.is_some())
            || config.as_ref().is_some_and(|c| c.token.is_some());
        if !has_token {
            status.info(format!(
                "{} exists but holds no token; vercel is not logged in",
                dir.display()
            ));
            return Ok(status);
        }

        let team = config.as_ref().and_then(|c| c.current_team.clone());
        let identity = config
            .as_ref()
            .and_then(|c| c.email.clone().or_else(|| c.username.clone()));

        status.profiles.push(
            Profile::new(Self::PROFILE_ID)
                .label(match (&identity, &team) {
                    (Some(who), Some(team)) => format!("{who} (team {team})"),
                    (Some(who), None) => who.clone(),
                    (None, Some(team)) => format!("team {team}"),
                    (None, None) => "vercel login".to_string(),
                })
                // Long-lived by design; revocation happens at the dashboard.
                .expiry(Expiry::NoExpiry)
                .with_meta("current_team", team.clone())
                .with_meta("identity", identity)
                .with_meta("source", dir.display().to_string()),
        );
        status.active = Some(Self::PROFILE_ID.to_string());

        status.info("a vercel token's reach is decided by the team it belongs to");
        if team.is_none() {
            status.info("no currentTeam is recorded, so commands run against your personal scope");
        }

        Ok(status)
    }

    fn switch(&self, _profile_id: &str) -> anyhow::Result<SwitchOutcome> {
        // `vercel switch <team>` is interactive when the slug is wrong and
        // rewrites machine-global scope, so it stays a human's call.
        Ok(unsupported_switch(
            Self::TOOL,
            "vercel holds a single login; the team scope is changed with an interactive command",
            Some("vercel switch <team-slug>"),
        ))
    }

    fn verify(&self) -> anyhow::Result<VerifyOutcome> {
        Ok(unsupported_verify(
            Self::TOOL,
            "patchbay does not run vercel yet; the CLI is node-based and slow to start",
            Some("vercel whoami"),
        ))
    }

    fn permissions(&self) -> anyhow::Result<PermissionsReport> {
        Ok(PermissionsReport::unsupported(
            Self::TOOL,
            "a Vercel CLI token carries no scope list on disk; access follows the team membership \
             of the account that created it",
            Some("vercel teams ls"),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::NoteKind;
    use std::fs;
    use std::path::Path;

    const DIR: &str = "Library/Application Support/com.vercel.cli";

    fn write(home: &Path, rel: &str, body: &str) {
        let path = home.join(rel);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, body).unwrap();
    }

    // Shape copied from a real auth.json; the token value is invented.
    const AUTH: &str = r#"{
  "// Note": "This is your Vercel credentials file.",
  "token": "FAKEFIXTUREVERCELTOKEN"
}"#;

    #[test]
    fn test_login_with_a_team_scope() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        write(home, &format!("{DIR}/auth.json"), AUTH);
        write(
            home,
            &format!("{DIR}/config.json"),
            r#"{ "currentTeam": "team_pathors", "email": "dev@example.com" }"#,
        );

        let status = VercelProbe::new(Paths::for_test(home)).status().unwrap();
        assert!(status.installed);
        assert_eq!(status.active.as_deref(), Some("default"));
        assert_eq!(status.profiles.len(), 1);
        let profile = &status.profiles[0];
        assert_eq!(profile.label, "dev@example.com (team team_pathors)");
        assert_eq!(profile.meta["current_team"], "team_pathors");
        // Not "we could not find out" — the token genuinely has no deadline.
        assert_eq!(profile.expiry, Expiry::NoExpiry);
        assert!(profile.expires_at().is_none());

        let json = serde_json::to_string(&status).unwrap();
        assert!(!json.contains("FAKEFIXTUREVERCELTOKEN"), "{json}");
    }

    #[test]
    fn test_personal_scope_is_called_out() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        write(home, &format!("{DIR}/auth.json"), AUTH);
        write(
            home,
            &format!("{DIR}/config.json"),
            r#"{ "telemetry": {} }"#,
        );
        let status = VercelProbe::new(Paths::for_test(home)).status().unwrap();
        assert_eq!(status.profiles[0].label, "vercel login");
        assert!(status
            .notes
            .iter()
            .any(|n| n.kind == NoteKind::Info && n.text.contains("personal scope")));
    }

    #[test]
    fn test_legacy_now_directory_is_still_read() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        write(home, ".now/auth.json", AUTH);
        let status = VercelProbe::new(Paths::for_test(home)).status().unwrap();
        assert_eq!(status.profiles.len(), 1);
        assert!(status.profiles[0].meta["source"]
            .as_str()
            .unwrap()
            .ends_with(".now"));
    }

    #[test]
    fn test_missing_and_malformed_and_tokenless() {
        let dir = tempfile::tempdir().unwrap();
        let status = VercelProbe::new(Paths::for_test(dir.path()))
            .status()
            .unwrap();
        assert!(!status.installed);
        assert!(status.profiles.is_empty());
        assert!(status.notes.is_empty());

        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), &format!("{DIR}/auth.json"), "{ not json");
        let status = VercelProbe::new(Paths::for_test(dir.path()))
            .status()
            .unwrap();
        assert!(status.installed);
        assert!(status.profiles.is_empty());
        assert!(status
            .notes
            .iter()
            .any(|n| n.kind == NoteKind::Problem && n.text.contains("not valid JSON")));

        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), &format!("{DIR}/auth.json"), "{}");
        let status = VercelProbe::new(Paths::for_test(dir.path()))
            .status()
            .unwrap();
        assert!(status.profiles.is_empty());
        // Not logged in is a state the board already shows; it is not a fault.
        assert!(status
            .notes
            .iter()
            .any(|n| n.kind == NoteKind::Info && n.text.contains("not logged in")));
    }

    #[test]
    fn test_switch_and_verify_are_honest_about_not_being_supported() {
        let dir = tempfile::tempdir().unwrap();
        let probe = VercelProbe::new(Paths::for_test(dir.path()));
        assert!(matches!(
            probe.switch("team_x").unwrap(),
            SwitchOutcome::Unsupported { .. }
        ));
        assert!(matches!(
            probe.verify().unwrap(),
            VerifyOutcome::Unsupported { .. }
        ));
        assert!(!probe.permissions().unwrap().supported);
    }
}
