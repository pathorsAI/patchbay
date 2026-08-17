//! `claude` — Claude Code's own login, as recorded in `~/.claude.json`.
//!
//! Shape verified **empirically** on this machine. The file is Claude Code's
//! whole local state (a few hundred KB of it), of which four things matter:
//!
//! * `oauthAccount` — `{ emailAddress, organizationUuid, accountUuid,
//!   billingType, … }`. The email is the profile.
//! * `mcpServers` — the user-scoped MCP servers, counted as metadata.
//! * `projects` — one entry per directory Claude Code has run in. Counted
//!   only: those paths say a lot about a machine and none of it is patchbay's
//!   business.
//! * `installMethod` / `userID` — install-level facts, useful when two Claude
//!   Code installs disagree.
//!
//! The OAuth token itself is **not** in this file — on macOS it lives in the
//! Keychain — so the expiry is `Unknown`, not absent, exactly like `gh`.
//! `CLAUDE_CONFIG_DIR` moves the directory that holds the file.

use std::collections::BTreeMap;

use serde::Deserialize;

use crate::paths::Paths;
use crate::probe::{unsupported_switch, unsupported_verify, Probe};
use crate::types::{
    Expiry, Note, PermissionsReport, Profile, SwitchOutcome, ToolStatus, VerifyOutcome,
};
use crate::util::read_text;

pub struct ClaudeProbe {
    paths: Paths,
}

/// Everything not named here is dropped by serde, including the transcript and
/// history material that makes up most of the file.
#[derive(Deserialize, Default)]
struct State {
    #[serde(default, rename = "oauthAccount")]
    oauth_account: Option<OauthAccount>,
    #[serde(default, rename = "mcpServers")]
    mcp_servers: BTreeMap<String, serde::de::IgnoredAny>,
    #[serde(default)]
    projects: BTreeMap<String, serde::de::IgnoredAny>,
    #[serde(default, rename = "installMethod")]
    install_method: Option<String>,
    #[serde(default, rename = "hasCompletedOnboarding")]
    has_completed_onboarding: Option<bool>,
}

#[derive(Deserialize)]
struct OauthAccount {
    #[serde(default, rename = "emailAddress")]
    email_address: Option<String>,
    #[serde(default, rename = "organizationUuid")]
    organization_uuid: Option<String>,
    #[serde(default, rename = "organizationName")]
    organization_name: Option<String>,
    #[serde(default, rename = "billingType")]
    billing_type: Option<String>,
}

impl ClaudeProbe {
    pub const TOOL: &'static str = "claude";

    pub fn new(paths: Paths) -> Self {
        Self { paths }
    }
}

impl Probe for ClaudeProbe {
    fn tool(&self) -> &'static str {
        Self::TOOL
    }

    fn status(&self) -> anyhow::Result<ToolStatus> {
        let path = self.paths.claude_json();
        let installed = self.paths.has_binary("claude") || path.is_file();
        let mut status = ToolStatus::empty(Self::TOOL, installed);
        for note in self.paths.path_notes("claude") {
            status.push_note(note);
        }

        let text = match read_text(&path) {
            Ok(Some(text)) => text,
            Ok(None) => return Ok(status),
            Err(e) => {
                status.problem(e);
                return Ok(status);
            }
        };

        let state: State = match serde_json::from_str(&text) {
            Ok(state) => state,
            Err(e) => {
                status.problem(format!("{} is not valid JSON ({e})", path.display()));
                return Ok(status);
            }
        };

        let Some(account) = state.oauth_account else {
            status.info(
                "no oauthAccount in .claude.json; Claude Code has state here but no signed-in \
                 account (an API-key setup looks like this too)",
            );
            return Ok(status);
        };

        let id = account
            .email_address
            .clone()
            .unwrap_or_else(|| "claude account".to_string());
        status.profiles.push(
            Profile::new(&id)
                // The token is in the Keychain, so no expiry is knowable here.
                .expiry(Expiry::unknown("in the OS keychain"))
                .with_meta("organization", account.organization_name.clone())
                .with_meta("organization_uuid", account.organization_uuid.clone())
                .with_meta("billing_type", account.billing_type.clone())
                .with_meta("install_method", state.install_method.clone())
                .with_meta("mcp_servers", state.mcp_servers.len())
                .with_meta("projects", state.projects.len()),
        );
        status.active = Some(id);

        if state.has_completed_onboarding == Some(false) {
            status.info("onboarding has not been completed on this machine");
        }

        Ok(status)
    }

    fn switch(&self, _profile_id: &str) -> anyhow::Result<SwitchOutcome> {
        Ok(unsupported_switch(
            Self::TOOL,
            "Claude Code holds one signed-in account and switching is an interactive browser flow",
            Some("claude /login"),
        ))
    }

    fn verify(&self) -> anyhow::Result<VerifyOutcome> {
        // Any real check is an API call on the user's own quota. Not something
        // to do behind their back.
        Ok(unsupported_verify(
            Self::TOOL,
            "verifying would spend the user's own API quota; the account in status is read from \
             local state",
            Some("claude /status"),
        ))
    }

    fn permissions(&self) -> anyhow::Result<PermissionsReport> {
        let status = self.status()?;
        let Some(profile) = status.profiles.first() else {
            return Ok(PermissionsReport::unsupported(
                Self::TOOL,
                "Claude Code is not signed in on this machine",
                Some("claude /login"),
            ));
        };
        Ok(PermissionsReport {
            tool: Self::TOOL.to_string(),
            supported: true,
            subject: Some(profile.id.clone()),
            // Claude Code's grant carries no scope list of its own.
            scopes: Vec::new(),
            notes: vec![Note::info(
                "what this login may do follows the plan and the organisation's settings, \
                 neither of which is recorded locally",
            )],
            hint: Some("claude /status".to_string()),
            scope: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::NoteKind;
    use std::fs;
    use std::path::PathBuf;

    fn fixture(body: &str) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().to_path_buf();
        fs::write(home.join(".claude.json"), body).unwrap();
        (dir, home)
    }

    // Key names copied from a real .claude.json; every value is invented.
    const STATE: &str = r#"{
      "numStartups": 480,
      "installMethod": "native",
      "userID": "fakefixtureuserid",
      "hasCompletedOnboarding": true,
      "projects": { "/work/a": {}, "/work/b": {} },
      "mcpServers": { "patchbay": {}, "grafana": {} },
      "oauthAccount": {
        "accountUuid": "aaaa-1111",
        "emailAddress": "dev@example.com",
        "organizationUuid": "bbbb-2222",
        "organizationName": "Example Ltd",
        "billingType": "stripe_subscription"
      }
    }"#;

    #[test]
    fn test_account_and_counted_metadata() {
        let (_dir, home) = fixture(STATE);
        let status = ClaudeProbe::new(Paths::for_test(&home)).status().unwrap();
        assert_eq!(status.active.as_deref(), Some("dev@example.com"));
        let profile = &status.profiles[0];
        assert_eq!(profile.meta["organization"], "Example Ltd");
        assert_eq!(profile.meta["billing_type"], "stripe_subscription");
        assert_eq!(profile.meta["mcp_servers"], 2);
        assert_eq!(profile.meta["projects"], 2);
        // Keychain-backed, like gh — and the reason travels in the type now,
        // so nothing about it is left to a note.
        assert_eq!(profile.expires_at(), None);
        assert_eq!(profile.expiry, Expiry::unknown("in the OS keychain"));
        assert!(!status.notes.iter().any(|n| n.text.contains("keychain")));
        // The panel has a whole MCP view; a count here only says it twice.
        assert!(!status.notes.iter().any(|n| n.text.contains("MCP")));

        // Project paths are counted, never listed.
        let json = serde_json::to_string(&status).unwrap();
        assert!(!json.contains("/work/a"), "{json}");
        assert!(!json.contains("fakefixtureuserid"), "{json}");
    }

    #[test]
    fn test_state_without_an_account() {
        let (_dir, home) = fixture(r#"{ "numStartups": 3, "projects": { "/work/a": {} } }"#);
        let status = ClaudeProbe::new(Paths::for_test(&home)).status().unwrap();
        assert!(status.installed);
        assert!(status.profiles.is_empty());
        // An API-key setup looks exactly like this, so it must not alarm.
        let unsigned = status
            .notes
            .iter()
            .find(|n| n.text.contains("no oauthAccount"))
            .expect("the accountless state is explained");
        assert_eq!(unsigned.kind, NoteKind::Info);
    }

    #[test]
    fn test_missing_and_malformed() {
        let dir = tempfile::tempdir().unwrap();
        let status = ClaudeProbe::new(Paths::for_test(dir.path()))
            .status()
            .unwrap();
        assert!(!status.installed);
        assert!(status.profiles.is_empty());
        assert!(status.notes.is_empty());

        let (_dir, home) = fixture("{ \"oauthAccount\": ");
        let status = ClaudeProbe::new(Paths::for_test(&home)).status().unwrap();
        assert!(status.installed);
        let malformed = status
            .notes
            .iter()
            .find(|n| n.text.contains("not valid JSON"))
            .expect("the parse failure is reported");
        assert_eq!(malformed.kind, NoteKind::Problem);
    }

    #[test]
    fn test_config_dir_override_is_followed_and_noted() {
        let dir = tempfile::tempdir().unwrap();
        let elsewhere = dir.path().join("claude-home");
        fs::create_dir_all(&elsewhere).unwrap();
        fs::write(elsewhere.join(".claude.json"), STATE).unwrap();
        let paths =
            Paths::for_test(dir.path()).with_env("CLAUDE_CONFIG_DIR", elsewhere.to_str().unwrap());
        let status = ClaudeProbe::new(paths).status().unwrap();
        assert_eq!(status.profiles.len(), 1);
        assert!(status
            .notes
            .iter()
            .any(|n| n.text.contains("$CLAUDE_CONFIG_DIR=")));
    }

    #[test]
    fn test_permissions_names_the_account_but_claims_no_scopes() {
        let (_dir, home) = fixture(STATE);
        let report = ClaudeProbe::new(Paths::for_test(&home))
            .permissions()
            .unwrap();
        assert!(report.supported);
        assert_eq!(report.subject.as_deref(), Some("dev@example.com"));
        assert!(report.scopes.is_empty());
    }
}
