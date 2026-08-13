//! `firebase` — the Google login `firebase-tools` keeps in its configstore.
//!
//! Path and shape verified **empirically** on macOS at
//! `~/.config/configstore/firebase-tools.json` (the `configstore` npm package,
//! which is XDG-aware). The interesting keys:
//!
//! * `user` — the decoded id-token claims of the primary account. `email` is
//!   the only field patchbay takes.
//! * `tokens` — `{ expires_at (epoch **milliseconds**), refresh_token,
//!   access_token, scopes, scope, ... }`. The two token values are
//!   [`serde::de::IgnoredAny`]; only the expiry and the scope list are read.
//! * `additionalAccounts` — `[{ user, tokens }]` for `firebase login:add`.
//! * `activeProjects` — a project alias per working directory, which is why
//!   patchbay reports the *account*, not the project, as the profile.
//!
//! The access token is an hour-long OAuth token that firebase-tools refreshes
//! silently, so an expiry in the past is normal and is explained in a note
//! rather than raised as a failure.

use serde::Deserialize;

use crate::paths::Paths;
use crate::probe::{unsupported_switch, unsupported_verify, Probe};
use crate::types::{PermissionsReport, Profile, SwitchOutcome, ToolStatus, VerifyOutcome};
use crate::util::{parse_epoch_millis, read_text};

pub struct FirebaseProbe {
    paths: Paths,
}

#[derive(Deserialize, Default)]
struct Store {
    #[serde(default)]
    user: Option<User>,
    #[serde(default)]
    tokens: Option<Tokens>,
    #[serde(default, rename = "additionalAccounts")]
    additional_accounts: Vec<Account>,
    #[serde(default, rename = "activeProjects")]
    active_projects: std::collections::BTreeMap<String, String>,
}

#[derive(Deserialize)]
struct Account {
    #[serde(default)]
    user: Option<User>,
    #[serde(default)]
    tokens: Option<Tokens>,
}

#[derive(Deserialize)]
struct User {
    #[serde(default)]
    email: Option<String>,
}

/// `access_token` / `refresh_token` / `id_token` are deliberately absent from
/// this struct: what serde never names, it never holds.
#[derive(Deserialize)]
struct Tokens {
    #[serde(default)]
    expires_at: Option<i64>,
    #[serde(default)]
    scopes: Vec<String>,
}

impl FirebaseProbe {
    pub const TOOL: &'static str = "firebase";

    pub fn new(paths: Paths) -> Self {
        Self { paths }
    }

    fn profile(email: &str, tokens: Option<&Tokens>) -> Profile {
        let expires_at = tokens
            .and_then(|t| t.expires_at)
            .and_then(parse_epoch_millis);
        Profile::new(email)
            .expires_at(expires_at)
            .with_meta(
                "scopes",
                tokens.map(|t| t.scopes.clone()).unwrap_or_default(),
            )
            .with_meta("auth", "google oauth")
    }
}

impl Probe for FirebaseProbe {
    fn tool(&self) -> &'static str {
        Self::TOOL
    }

    fn status(&self) -> anyhow::Result<ToolStatus> {
        let path = self.paths.firebase_config();
        let installed = self.paths.has_binary("firebase") || path.is_file();
        let mut status = ToolStatus::empty(Self::TOOL, installed);
        for note in self.paths.path_notes("firebase") {
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

        let store: Store = match serde_json::from_str(&text) {
            Ok(store) => store,
            Err(e) => {
                status.note(format!("firebase-tools.json is not valid JSON ({e})"));
                return Ok(status);
            }
        };

        if let Some(email) = store.user.as_ref().and_then(|u| u.email.clone()) {
            status
                .profiles
                .push(Self::profile(&email, store.tokens.as_ref()).with_meta("primary", true));
            status.active = Some(email);
        }
        for account in &store.additional_accounts {
            let Some(email) = account.user.as_ref().and_then(|u| u.email.clone()) else {
                continue;
            };
            if status.profiles.iter().any(|p| p.id == email) {
                continue;
            }
            status
                .profiles
                .push(Self::profile(&email, account.tokens.as_ref()).with_meta("primary", false));
        }

        if status.profiles.is_empty() {
            if !store.active_projects.is_empty() {
                status.note(
                    "firebase-tools has project aliases on this machine but no logged-in account"
                        .to_string(),
                );
            }
            return Ok(status);
        }

        status.note(
            "the stored access token lasts about an hour; firebase-tools refreshes it silently, \
             so an expiry in the past does not mean you are logged out"
                .to_string(),
        );
        if !store.active_projects.is_empty() {
            status.note(format!(
                "the active Firebase project is per-directory ({} recorded); the profile above is \
                 the account, not the project",
                store.active_projects.len()
            ));
        }
        if !store.additional_accounts.is_empty() {
            status.note(
                "extra accounts from `firebase login:add` are selected per command with \
                 `--account`, not globally"
                    .to_string(),
            );
        }

        Ok(status)
    }

    fn switch(&self, _profile_id: &str) -> anyhow::Result<SwitchOutcome> {
        // firebase-tools has no global account switch: `--account` is a
        // per-invocation flag, and `firebase login` is interactive.
        Ok(unsupported_switch(
            Self::TOOL,
            "firebase-tools selects an account per command rather than globally",
            Some("firebase --account <email> <command>"),
        ))
    }

    fn verify(&self) -> anyhow::Result<VerifyOutcome> {
        Ok(unsupported_verify(
            Self::TOOL,
            "patchbay does not run firebase yet; the CLI is node-based and slow to start",
            Some("firebase login:list"),
        ))
    }

    fn permissions(&self) -> anyhow::Result<PermissionsReport> {
        let status = self.status()?;
        let Some(profile) = status
            .active
            .as_ref()
            .and_then(|id| status.profiles.iter().find(|p| &p.id == id))
        else {
            return Ok(PermissionsReport::unsupported(
                Self::TOOL,
                "firebase-tools is not logged in",
                Some("firebase login"),
            ));
        };
        let scopes: Vec<String> = profile
            .meta
            .get("scopes")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        Ok(PermissionsReport {
            tool: Self::TOOL.to_string(),
            supported: true,
            subject: Some(profile.id.clone()),
            scopes,
            notes: vec![
                "these are the OAuth scopes of the local grant; what you may actually do is \
                 decided by the account's IAM roles on each Firebase project"
                    .to_string(),
            ],
            hint: Some("firebase login --reauth".to_string()),
        })
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
        fs::create_dir_all(home.join(".config/configstore")).unwrap();
        fs::write(home.join(".config/configstore/firebase-tools.json"), body).unwrap();
        (dir, home)
    }

    // Shape mirrors a real store; every token value is invented.
    const STORE: &str = r#"{
      "user": { "email": "dev@example.com", "sub": "1015", "email_verified": true },
      "tokens": {
        "expires_at": 1766355597325,
        "refresh_token": "fake-fixture-refresh",
        "access_token": "fake-fixture-access",
        "id_token": "fake-fixture-id",
        "scopes": ["email", "https://www.googleapis.com/auth/cloud-platform"]
      },
      "additionalAccounts": [
        { "user": { "email": "ops@example.com" }, "tokens": { "expires_at": 1766355597325, "access_token": "fake-fixture-second" } }
      ],
      "activeProjects": { "/work/app": "app-prod", "/work/site": "site-dev" }
    }"#;

    #[test]
    fn test_primary_and_additional_accounts() {
        let (_dir, home) = fixture(STORE);
        let status = FirebaseProbe::new(Paths::for_test(&home)).status().unwrap();
        let ids: Vec<_> = status.profiles.iter().map(|p| p.id.as_str()).collect();
        assert_eq!(ids, vec!["dev@example.com", "ops@example.com"]);
        assert_eq!(status.active.as_deref(), Some("dev@example.com"));
        assert_eq!(status.profiles[0].meta["primary"], true);
        // epoch milliseconds, not seconds.
        assert_eq!(
            status.profiles[0].expires_at.unwrap().to_rfc3339(),
            "2025-12-21T22:19:57.325+00:00"
        );
        assert_eq!(status.profiles[0].meta["scopes"][0], "email");
        assert!(status.notes.iter().any(|n| n.contains("per-directory")));
        assert!(status.notes.iter().any(|n| n.contains("--account")));
    }

    #[test]
    fn test_no_token_material_reaches_the_output() {
        let (_dir, home) = fixture(STORE);
        let status = FirebaseProbe::new(Paths::for_test(&home)).status().unwrap();
        let json = serde_json::to_string(&status).unwrap();
        for secret in [
            "fake-fixture-refresh",
            "fake-fixture-access",
            "fake-fixture-id",
            "fake-fixture-second",
        ] {
            assert!(!json.contains(secret), "leaked {secret}");
        }
    }

    #[test]
    fn test_projects_without_a_login() {
        let (_dir, home) = fixture(r#"{ "activeProjects": { "/work/app": "app-prod" } }"#);
        let status = FirebaseProbe::new(Paths::for_test(&home)).status().unwrap();
        assert!(status.installed);
        assert!(status.profiles.is_empty());
        assert!(status
            .notes
            .iter()
            .any(|n| n.contains("no logged-in account")));
    }

    #[test]
    fn test_missing_and_malformed() {
        let dir = tempfile::tempdir().unwrap();
        let status = FirebaseProbe::new(Paths::for_test(dir.path()))
            .status()
            .unwrap();
        assert!(!status.installed);
        assert!(status.profiles.is_empty());

        let (_dir, home) = fixture("{ \"user\": ");
        let status = FirebaseProbe::new(Paths::for_test(&home)).status().unwrap();
        assert!(status.installed);
        assert!(status.notes.iter().any(|n| n.contains("not valid JSON")));
    }

    #[test]
    fn test_permissions_reports_the_local_grant() {
        let (_dir, home) = fixture(STORE);
        let report = FirebaseProbe::new(Paths::for_test(&home))
            .permissions()
            .unwrap();
        assert!(report.supported);
        assert_eq!(report.subject.as_deref(), Some("dev@example.com"));
        assert_eq!(report.scopes.len(), 2);

        let dir = tempfile::tempdir().unwrap();
        let report = FirebaseProbe::new(Paths::for_test(dir.path()))
            .permissions()
            .unwrap();
        assert!(!report.supported);
    }
}
