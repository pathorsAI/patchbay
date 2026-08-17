//! `op` — 1Password CLI accounts.
//!
//! Not installed on this machine; verified against 1Password's own
//! documentation (config directories, sign-in, biometric unlock) plus a
//! maintained third-party parser of the same file. The config directory is
//! searched in the CLI's documented order — `OP_CONFIG_DIR`, `~/.op`,
//! `$XDG_CONFIG_HOME/.op`, `~/.config/op`, `$XDG_CONFIG_HOME/op` — and
//! `~/.op` wins over `~/.config/op`, which is the easy thing to get wrong.
//!
//! The file is JSON with camelCase keys:
//!
//! ```json
//! { "latest_signin": "my",
//!   "accounts": [ { "shorthand": "my", "url": "https://my.1password.com",
//!                   "email": "dev@example.com", "accountUUID": "…",
//!                   "userUUID": "…" } ] }
//! ```
//!
//! **Absence proves nothing.** With the desktop app integration (biometric
//! unlock) the account roster comes from the app, and `op account forget --all`
//! is the documented way to empty this file while `op` keeps working. So an
//! empty or missing `accounts` array is reported as "unknown, ask verify",
//! never as "not signed in".
//!
//! Nothing in the file is treated as safe by default beyond the account
//! identifiers below: a `device` key is documented only by community examples,
//! and older versions wrote an `accountKey`. What is not named here is not read.

use serde::Deserialize;

use crate::paths::Paths;
use crate::probe::{unsupported_switch, Probe};
use crate::types::{
    ActiveConcept, Expiry, PermissionsReport, Profile, SwitchOutcome, ToolStatus, VerifyOutcome,
};

/// Where an `op` session's deadline lives — which is to say, not on disk. The
/// CLI holds a 30-minute idle timer in the session itself, so patchbay can
/// only report that there is one, never when it lands.
const SESSION_EXPIRY: &str = "in a 30-minute idle session, never written to disk";
use crate::util::read_text;

pub struct OpProbe {
    paths: Paths,
}

#[derive(Deserialize, Default)]
struct Config {
    /// The shorthand of the account signed in to most recently.
    #[serde(default)]
    latest_signin: Option<String>,
    #[serde(default)]
    accounts: Vec<Account>,
}

#[derive(Deserialize)]
struct Account {
    #[serde(default)]
    shorthand: Option<String>,
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    email: Option<String>,
    #[serde(default, rename = "accountUUID")]
    account_uuid: Option<String>,
}

impl OpProbe {
    pub const TOOL: &'static str = "op";

    pub fn new(paths: Paths) -> Self {
        Self { paths }
    }
}

impl Probe for OpProbe {
    fn tool(&self) -> &'static str {
        Self::TOOL
    }

    fn status(&self) -> anyhow::Result<ToolStatus> {
        let candidates = self.paths.op_config_candidates();
        let path = candidates.iter().find(|p| p.is_file()).cloned();
        let installed = self.paths.has_binary("op") || path.is_some();
        let mut status = ToolStatus::empty(Self::TOOL, installed);
        for note in self.paths.path_notes("op") {
            status.push_note(note);
        }

        if !installed {
            return Ok(status);
        }

        let Some(path) = path else {
            status.info(
                "no op config file in any of the documented locations; with the desktop app \
                 integration that is normal — the account list then lives in the 1Password app",
            );
            return Ok(status);
        };

        let text = match read_text(&path) {
            Ok(Some(text)) => text,
            Ok(None) => return Ok(status),
            Err(e) => {
                status.problem(e);
                return Ok(status);
            }
        };

        let config: Config = match serde_json::from_str(&text) {
            Ok(config) => config,
            Err(e) => {
                status.problem(format!("{} is not valid JSON ({e})", path.display()));
                return Ok(status);
            }
        };

        for account in &config.accounts {
            let id = account
                .shorthand
                .clone()
                .or_else(|| account.account_uuid.clone())
                .or_else(|| account.url.clone());
            let Some(id) = id else { continue };
            status.profiles.push(
                Profile::new(&id)
                    .label(match (&account.email, &account.url) {
                        (Some(email), Some(url)) => format!("{email} @ {url}"),
                        (Some(email), None) => email.clone(),
                        (None, Some(url)) => url.clone(),
                        (None, None) => id.clone(),
                    })
                    .expiry(Expiry::unknown(SESSION_EXPIRY))
                    .with_meta("email", account.email.clone())
                    .with_meta("url", account.url.clone())
                    .with_meta("account_uuid", account.account_uuid.clone()),
            );
        }

        if status.profiles.is_empty() {
            status.info(format!(
                "{} lists no accounts; with biometric unlock the roster comes from the desktop \
                 app instead, so this is not proof that op is signed out",
                path.display()
            ));
            return Ok(status);
        }

        // `latest_signin` is the closest thing to an active account — and it is
        // only the last one used, not a selection, which is what the
        // not-applicable concept below says.
        if let Some(latest) = config.latest_signin {
            if status.profiles.iter().any(|p| p.id == latest) {
                status.active = Some(latest);
            }
        }
        status.active_concept = ActiveConcept::not_applicable(
            "`latest_signin` is the last account used, and any command can name another with \
             --account",
        );

        Ok(status)
    }

    fn switch(&self, profile_id: &str) -> anyhow::Result<SwitchOutcome> {
        Ok(unsupported_switch(
            Self::TOOL,
            "op selects an account per command rather than globally, and signing in is \
             interactive",
            Some(&format!("op signin --account {profile_id}")),
        ))
    }

    fn verify(&self) -> anyhow::Result<VerifyOutcome> {
        if !self.paths.may_exec() || !self.paths.has_binary("op") {
            return Ok(crate::probe::unsupported_verify(
                Self::TOOL,
                "the op CLI is not available on PATH",
                Some("op whoami"),
            ));
        }
        let out = self.paths.run("op", &["whoami"])?;
        Ok(if out.ok {
            VerifyOutcome::Valid {
                tool: Self::TOOL.to_string(),
                detail: out.message(),
            }
        } else {
            VerifyOutcome::Invalid {
                tool: Self::TOOL.to_string(),
                detail: format!(
                    "{} (a 1Password session expires after 30 minutes of inactivity)",
                    out.message()
                ),
            }
        })
    }

    fn permissions(&self) -> anyhow::Result<PermissionsReport> {
        Ok(PermissionsReport::unsupported(
            Self::TOOL,
            "vault access is granted per account in 1Password itself and is not recorded on this \
             machine",
            Some("op vault list"),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::NoteKind;
    use std::fs;
    use std::path::Path;

    fn write(home: &Path, rel: &str, body: &str) {
        let path = home.join(rel);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, body).unwrap();
    }

    const CONFIG: &str = r#"{
      "latest_signin": "my",
      "device": "FAKEFIXTUREDEVICEID",
      "accounts": [
        { "shorthand": "my", "url": "https://my.1password.com",
          "email": "dev@example.com", "accountUUID": "AAAA1111", "userUUID": "BBBB2222" },
        { "shorthand": "work", "url": "https://work.1password.com",
          "email": "ops@example.com", "accountUUID": "CCCC3333", "userUUID": "DDDD4444" }
      ]
    }"#;

    #[test]
    fn test_accounts_and_latest_signin() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), ".config/op/config", CONFIG);
        let status = OpProbe::new(Paths::for_test(dir.path())).status().unwrap();
        let ids: Vec<_> = status.profiles.iter().map(|p| p.id.as_str()).collect();
        assert_eq!(ids, vec!["my", "work"]);
        assert_eq!(status.active.as_deref(), Some("my"));
        assert_eq!(
            status.profiles[0].label,
            "dev@example.com @ https://my.1password.com"
        );
        // The 30-minute idle window is the expiry state now, not a paragraph.
        assert_eq!(status.profiles[0].expiry, Expiry::unknown(SESSION_EXPIRY));
        assert!(status.profiles[0].expires_at().is_none());
        assert!(!status.notes.iter().any(|n| n.text.contains("30 minutes")));
        // Likewise the "not a permanent selection" note.
        assert!(status.active_concept.is_not_applicable());
        assert!(!status
            .notes
            .iter()
            .any(|n| n.text.contains("latest_signin")));

        // The undocumented device id is not something patchbay passes on.
        let json = serde_json::to_string(&status).unwrap();
        assert!(!json.contains("FAKEFIXTUREDEVICEID"), "{json}");
        assert!(
            !json.contains("BBBB2222"),
            "user uuid is not needed: {json}"
        );
    }

    #[test]
    fn test_dot_op_wins_over_dot_config_op() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), ".config/op/config", CONFIG);
        write(
            dir.path(),
            ".op/config",
            r#"{ "accounts": [ { "shorthand": "legacy", "email": "old@example.com" } ] }"#,
        );
        let status = OpProbe::new(Paths::for_test(dir.path())).status().unwrap();
        assert_eq!(status.profiles.len(), 1);
        assert_eq!(status.profiles[0].id, "legacy");
    }

    #[test]
    fn test_empty_account_list_is_not_reported_as_signed_out() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), ".config/op/config", r#"{ "accounts": [] }"#);
        let status = OpProbe::new(Paths::for_test(dir.path())).status().unwrap();
        assert!(status.installed);
        assert!(status.profiles.is_empty());
        assert!(status.notes.iter().any(
            |n| n.kind == NoteKind::Info && n.text.contains("not proof that op is signed out")
        ));
    }

    #[test]
    fn test_missing_and_malformed() {
        let dir = tempfile::tempdir().unwrap();
        let status = OpProbe::new(Paths::for_test(dir.path())).status().unwrap();
        assert!(!status.installed);
        assert!(status.profiles.is_empty());
        assert!(status.notes.is_empty());

        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), ".config/op/config", "{ \"accounts\": ");
        let status = OpProbe::new(Paths::for_test(dir.path())).status().unwrap();
        assert!(status.installed);
        assert!(status
            .notes
            .iter()
            .any(|n| n.kind == NoteKind::Problem && n.text.contains("not valid JSON")));
    }

    #[test]
    fn test_config_dir_override_is_followed_and_noted() {
        let dir = tempfile::tempdir().unwrap();
        let elsewhere = dir.path().join("opdir");
        fs::create_dir_all(&elsewhere).unwrap();
        fs::write(elsewhere.join("config"), CONFIG).unwrap();
        let paths =
            Paths::for_test(dir.path()).with_env("OP_CONFIG_DIR", elsewhere.to_str().unwrap());
        let status = OpProbe::new(paths).status().unwrap();
        assert_eq!(status.profiles.len(), 2);
        assert!(status
            .notes
            .iter()
            .any(|n| n.text.contains("$OP_CONFIG_DIR=")));
    }
}
