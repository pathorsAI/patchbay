//! `gcloud` — configurations, credentialed accounts, and the ADC trap.
//!
//! State read (all under `~/.config/gcloud`, or `$CLOUDSDK_CONFIG`):
//!
//! | file | what |
//! |---|---|
//! | `active_config` | plain text: name of the active configuration |
//! | `configurations/config_<name>` | INI: `[core] account/project`, `[compute] region/zone` |
//! | `credentials.db` | SQLite: which accounts have stored credentials |
//! | `access_tokens.db` | SQLite: per-account access token expiry |
//! | `application_default_credentials.json` | ADC — a *separate* credential that does not follow configuration switches |
//!
//! Profiles are configurations. A configuration's expiry is the token expiry of
//! the account it names.

use std::collections::HashMap;
use std::path::Path;

use chrono::{DateTime, Utc};
use rusqlite::{Connection, OpenFlags};

use crate::paths::Paths;
use crate::probe::{unknown_profile, unsupported_switch, unsupported_verify, Probe};
use crate::types::{PermissionsReport, Profile, SwitchOutcome, ToolStatus, VerifyOutcome};
use crate::util::{read_text, run, Ini};

pub struct GcloudProbe {
    paths: Paths,
}

/// What `application_default_credentials.json` tells us. Never its token.
struct Adc {
    account: Option<String>,
    quota_project: Option<String>,
}

impl GcloudProbe {
    pub const TOOL: &'static str = "gcloud";

    pub fn new(paths: Paths) -> Self {
        Self { paths }
    }

    /// Accounts with stored credentials. Only `account_id` is ever read — the
    /// `value` blob holds the actual refresh token and is never touched.
    fn credentialed_accounts(dir: &Path, notes: &mut Vec<String>) -> Vec<String> {
        let path = dir.join("credentials.db");
        if !path.is_file() {
            return Vec::new();
        }
        match query_column(&path, "credentials", "account_id") {
            Ok(rows) => rows.into_iter().map(|(id, _)| id).collect(),
            Err(e) => {
                notes.push(format!("could not read credentials.db ({e})"));
                Vec::new()
            }
        }
    }

    /// account -> access token expiry. Degrades to an empty map when the file,
    /// the table or the column is missing — gcloud's schema has moved before.
    fn token_expiries(dir: &Path, notes: &mut Vec<String>) -> HashMap<String, DateTime<Utc>> {
        let path = dir.join("access_tokens.db");
        if !path.is_file() {
            return HashMap::new();
        }
        match query_column(&path, "access_tokens", "account_id") {
            Ok(rows) => rows
                .into_iter()
                .filter_map(|(account, expiry)| {
                    let expiry = expiry.and_then(|raw| crate::util::parse_timestamp(&raw))?;
                    Some((account, expiry))
                })
                .collect(),
            Err(e) => {
                notes.push(format!(
                    "could not read token expiry from access_tokens.db ({e}); expiry unknown"
                ));
                HashMap::new()
            }
        }
    }

    fn read_adc(&self, notes: &mut Vec<String>) -> Option<Adc> {
        let path = self
            .paths
            .gcloud_dir()
            .join("application_default_credentials.json");
        if !path.is_file() {
            return None;
        }
        // Parse only the two identifying fields; client_secret / refresh_token
        // in this file are deliberately never bound to a variable.
        match read_text(&path) {
            Ok(Some(text)) => match serde_json::from_str::<serde_json::Value>(&text) {
                // gcloud writes `"account": ""` for user ADC, so an empty
                // string means "not recorded", not "account named empty".
                Ok(json) => Some(Adc {
                    account: json
                        .get("account")
                        .and_then(|v| v.as_str())
                        .filter(|s| !s.is_empty())
                        .map(str::to_string),
                    quota_project: json
                        .get("quota_project_id")
                        .and_then(|v| v.as_str())
                        .filter(|s| !s.is_empty())
                        .map(str::to_string),
                }),
                Err(_) => {
                    notes.push(
                        "application_default_credentials.json exists but is not valid JSON"
                            .to_string(),
                    );
                    Some(Adc {
                        account: None,
                        quota_project: None,
                    })
                }
            },
            Ok(None) => None,
            Err(e) => {
                notes.push(e);
                Some(Adc {
                    account: None,
                    quota_project: None,
                })
            }
        }
    }
}

impl Probe for GcloudProbe {
    fn tool(&self) -> &'static str {
        Self::TOOL
    }

    fn status(&self) -> anyhow::Result<ToolStatus> {
        let dir = self.paths.gcloud_dir();
        let installed = self.paths.has_binary("gcloud") || dir.is_dir();
        let mut status = ToolStatus::empty(Self::TOOL, installed);

        let active = match read_text(&dir.join("active_config")) {
            Ok(Some(text)) => {
                let name = text.trim().to_string();
                (!name.is_empty()).then_some(name)
            }
            Ok(None) => None,
            Err(e) => {
                status.note(e);
                None
            }
        };

        let credentialed = Self::credentialed_accounts(&dir, &mut status.notes);
        let expiries = Self::token_expiries(&dir, &mut status.notes);

        // Configurations are the profiles.
        let config_dir = dir.join("configurations");
        let mut used_accounts: Vec<String> = Vec::new();
        if config_dir.is_dir() {
            let mut entries: Vec<_> = std::fs::read_dir(&config_dir)
                .map(|rd| rd.filter_map(Result::ok).collect())
                .unwrap_or_default();
            entries.sort_by_key(|e| e.file_name());

            for entry in entries {
                let file_name = entry.file_name();
                let Some(name) = file_name.to_str().and_then(|n| n.strip_prefix("config_")) else {
                    continue;
                };
                let text = match read_text(&entry.path()) {
                    Ok(Some(text)) => text,
                    Ok(None) => continue,
                    Err(e) => {
                        status.note(e);
                        continue;
                    }
                };
                let ini = Ini::parse(&text);
                let core = ini.section("core");
                let compute = ini.section("compute");
                let account = core.and_then(|s| s.get("account")).map(str::to_string);
                if let Some(account) = &account {
                    used_accounts.push(account.clone());
                }

                let expires_at = account.as_ref().and_then(|a| expiries.get(a)).copied();
                let profile = Profile::new(name)
                    .expires_at(expires_at)
                    .with_meta("account", account.clone())
                    .with_meta("project", core.and_then(|s| s.get("project")))
                    .with_meta("region", compute.and_then(|s| s.get("region")))
                    .with_meta("zone", compute.and_then(|s| s.get("zone")))
                    .with_meta(
                        "account_credentialed",
                        account
                            .as_ref()
                            .map(|a| credentialed.iter().any(|c| c == a)),
                    );
                status.profiles.push(profile);
            }
        }

        if let Some(active) = &active {
            if !status.profiles.iter().any(|p| &p.id == active) {
                status.note(format!(
                    "active_config names `{active}` but there is no configurations/config_{active}"
                ));
            }
            // The account the active configuration points at must actually
            // have credentials, or every gcloud call will prompt for login.
            if let Some(profile) = status.profiles.iter().find(|p| &p.id == active) {
                if profile.meta.get("account_credentialed") == Some(&serde_json::Value::Bool(false))
                {
                    let account = profile
                        .meta
                        .get("account")
                        .and_then(|v| v.as_str())
                        .unwrap_or("?");
                    status.note(format!(
                        "active configuration `{active}` uses account {account}, which has no stored credentials (run `gcloud auth login {account}`)"
                    ));
                }
            }
        }
        status.active = active.clone();

        // Credentialed accounts that no configuration points at: available to
        // switch to, but invisible from the configuration list alone.
        let unused: Vec<&String> = credentialed
            .iter()
            .filter(|a| !used_accounts.contains(a))
            .collect();
        if !unused.is_empty() {
            status.note(format!(
                "credentialed accounts not used by any configuration: {}",
                unused
                    .iter()
                    .map(|s| s.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }

        // The ADC trap: a second, independent credential that client libraries,
        // Terraform and most SDKs use — and which `configurations activate`
        // does not touch.
        if let Some(adc) = self.read_adc(&mut status.notes) {
            let mut note = "application default credentials (ADC) exist".to_string();
            if let Some(account) = &adc.account {
                note.push_str(&format!(" for {account}"));
            }
            if let Some(project) = &adc.quota_project {
                note.push_str(&format!(" (quota project {project})"));
            }
            note.push_str(
                "; ADC is separate from the active configuration and does NOT follow `gcloud config configurations activate` — client libraries and Terraform keep using it until you run `gcloud auth application-default login`",
            );
            status.note(note);

            if let (Some(adc_account), Some(active)) = (&adc.account, &status.active) {
                let config_account = status
                    .profiles
                    .iter()
                    .find(|p| &p.id == active)
                    .and_then(|p| p.meta.get("account"))
                    .and_then(|v| v.as_str());
                if let Some(config_account) = config_account {
                    if config_account != adc_account {
                        status.note(format!(
                            "ADC mismatch: configuration `{active}` uses {config_account} but ADC is {adc_account}"
                        ));
                    }
                }
            }
        }

        Ok(status)
    }

    fn switch(&self, profile_id: &str) -> anyhow::Result<SwitchOutcome> {
        let status = self.status()?;
        if !status.profiles.iter().any(|p| p.id == profile_id) {
            return Ok(unknown_profile(Self::TOOL, profile_id, &status));
        }
        if !self.paths.may_exec() {
            return Ok(unsupported_switch(
                Self::TOOL,
                "command execution is disabled for this probe",
                Some(&format!(
                    "gcloud config configurations activate {profile_id}"
                )),
            ));
        }

        let out = run(
            "gcloud",
            &["config", "configurations", "activate", profile_id],
        )?;
        if !out.ok {
            return Ok(SwitchOutcome::Failed {
                tool: Self::TOOL.to_string(),
                profile_id: profile_id.to_string(),
                detail: out.message(),
            });
        }

        // Re-read so the caller is told about the ADC state *after* the switch.
        let mut notes = vec![
            "application default credentials do not follow this switch; if you use client libraries, Terraform, or anything reading ADC, run `gcloud auth application-default login` as well".to_string(),
        ];
        if let Ok(after) = self.status() {
            notes.extend(
                after.notes.into_iter().filter(|n| {
                    n.starts_with("ADC mismatch") || n.contains("no stored credentials")
                }),
            );
        }
        Ok(SwitchOutcome::Switched {
            tool: Self::TOOL.to_string(),
            profile_id: profile_id.to_string(),
            detail: format!("gcloud config configurations activate {profile_id}"),
            notes,
        })
    }

    fn verify(&self) -> anyhow::Result<VerifyOutcome> {
        if !self.paths.may_exec() {
            return Ok(unsupported_verify(
                Self::TOOL,
                "command execution is disabled for this probe",
                Some("gcloud auth print-access-token"),
            ));
        }
        // Mints/refreshes an access token for the active account: the cheapest
        // honest liveness check. The token itself is discarded, never parsed.
        let out = run("gcloud", &["auth", "print-access-token", "--quiet"])?;
        Ok(if out.ok {
            VerifyOutcome::Valid {
                tool: Self::TOOL.to_string(),
                detail: "active account minted an access token".to_string(),
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
            "IAM roles are per-project and per-resource; patchbay does not resolve them yet",
            Some("gcloud projects get-iam-policy <project> --flatten=bindings[].members --filter=bindings.members:<account>"),
        ))
    }
}

/// Read `(key, second_column)` pairs from a SQLite table, defensively.
///
/// The database is opened read-only, and the table and columns are checked via
/// `PRAGMA table_info` before querying, so a gcloud schema change degrades to
/// "unknown" instead of an error. For `access_tokens` the second column is the
/// token expiry; for `credentials` there is none.
fn query_column(
    path: &Path,
    table: &str,
    key_column: &str,
) -> rusqlite::Result<Vec<(String, Option<String>)>> {
    let conn = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI,
    )?;

    let mut columns: Vec<String> = Vec::new();
    {
        let mut stmt = conn.prepare(&format!("PRAGMA table_info(\"{table}\")"))?;
        let rows = stmt.query_map([], |row| row.get::<_, String>(1))?;
        for row in rows {
            columns.push(row?);
        }
    }
    if !columns.iter().any(|c| c == key_column) {
        return Ok(Vec::new());
    }

    // Only `token_expiry` is ever selected alongside the key — never the
    // access_token / value columns.
    let has_expiry = columns.iter().any(|c| c == "token_expiry");
    let sql = if has_expiry {
        format!("SELECT \"{key_column}\", token_expiry FROM \"{table}\"")
    } else {
        format!("SELECT \"{key_column}\" FROM \"{table}\"")
    };

    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map([], |row| {
        let key: String = row.get(0)?;
        let expiry: Option<String> = if has_expiry {
            // Stored as TIMESTAMP; SQLite may hand it back as text or NULL.
            row.get::<_, Option<String>>(1).unwrap_or(None)
        } else {
            None
        };
        Ok((key, expiry))
    })?;

    let mut out = Vec::new();
    for row in rows {
        out.push(row?);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    /// Builds a fake `~/.config/gcloud`. All credential material in fixtures is
    /// invented — no real token ever appears in this repository.
    struct Fixture {
        _dir: tempfile::TempDir,
        home: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let home = dir.path().to_path_buf();
            fs::create_dir_all(home.join(".config/gcloud/configurations")).unwrap();
            Self { _dir: dir, home }
        }

        fn gcloud(&self) -> PathBuf {
            self.home.join(".config/gcloud")
        }

        fn config(&self, name: &str, body: &str) -> &Self {
            fs::write(
                self.gcloud()
                    .join("configurations")
                    .join(format!("config_{name}")),
                body,
            )
            .unwrap();
            self
        }

        fn active(&self, name: &str) -> &Self {
            fs::write(self.gcloud().join("active_config"), format!("{name}\n")).unwrap();
            self
        }

        fn credentials_db(&self, accounts: &[&str]) -> &Self {
            let conn = Connection::open(self.gcloud().join("credentials.db")).unwrap();
            conn.execute(
                "CREATE TABLE credentials (account_id TEXT PRIMARY KEY, value BLOB)",
                [],
            )
            .unwrap();
            for account in accounts {
                conn.execute(
                    "INSERT INTO credentials VALUES (?1, ?2)",
                    rusqlite::params![account, "fake-not-a-real-credential"],
                )
                .unwrap();
            }
            self
        }

        fn tokens_db(&self, rows: &[(&str, &str)]) -> &Self {
            let conn = Connection::open(self.gcloud().join("access_tokens.db")).unwrap();
            conn.execute(
                "CREATE TABLE access_tokens (account_id TEXT PRIMARY KEY, access_token TEXT, token_expiry TIMESTAMP)",
                [],
            )
            .unwrap();
            for (account, expiry) in rows {
                conn.execute(
                    "INSERT INTO access_tokens VALUES (?1, ?2, ?3)",
                    rusqlite::params![account, "fake-access-token", expiry],
                )
                .unwrap();
            }
            self
        }

        fn probe(&self) -> GcloudProbe {
            GcloudProbe::new(Paths::for_test(&self.home))
        }
    }

    #[test]
    fn test_happy_path_configurations_accounts_and_expiry() {
        let fx = Fixture::new();
        fx.config(
            "default",
            "[core]\naccount = a@example.com\nproject = proj-a\n",
        )
        .config(
            "work",
            "[core]\naccount = b@example.com\nproject = proj-b\n\n[compute]\nregion = asia-east1\nzone = asia-east1-b\n",
        )
        .active("work")
        .credentials_db(&["a@example.com", "b@example.com"])
        .tokens_db(&[("b@example.com", "2030-01-02 03:04:05.123456")]);

        let status = fx.probe().status().unwrap();
        assert_eq!(status.active.as_deref(), Some("work"));
        assert_eq!(status.profiles.len(), 2);

        let work = status.profiles.iter().find(|p| p.id == "work").unwrap();
        assert_eq!(work.meta["account"], "b@example.com");
        assert_eq!(work.meta["project"], "proj-b");
        assert_eq!(work.meta["region"], "asia-east1");
        assert_eq!(work.meta["account_credentialed"], true);
        assert_eq!(
            work.expires_at.unwrap().to_rfc3339(),
            "2030-01-02T03:04:05.123456+00:00"
        );

        // No credentials for an account => no expiry, not a fabricated one.
        let default = status.profiles.iter().find(|p| p.id == "default").unwrap();
        assert!(default.expires_at.is_none());
    }

    #[test]
    fn test_adc_note_is_always_raised_and_mismatch_is_called_out() {
        let fx = Fixture::new();
        fx.config("work", "[core]\naccount = b@example.com\n")
            .active("work");
        fs::write(
            fx.gcloud().join("application_default_credentials.json"),
            r#"{"account":"other@example.com","quota_project_id":"proj-q","type":"authorized_user","refresh_token":"fake-fixture-value"}"#,
        )
        .unwrap();

        let status = fx.probe().status().unwrap();
        let notes = status.notes.join("\n");
        assert!(notes.contains("ADC"), "{notes}");
        assert!(notes.contains("proj-q"), "{notes}");
        assert!(notes.contains("does NOT follow"), "{notes}");
        assert!(notes.contains("ADC mismatch"), "{notes}");
        // Never leak the credential itself.
        assert!(!notes.contains("fake-fixture-value"), "{notes}");
    }

    #[test]
    fn test_adc_with_an_empty_account_field_does_not_claim_a_mismatch() {
        // Real user ADC files carry `"account": ""`; that means "not recorded",
        // and must not render as `ADC is ` or a false mismatch.
        let fx = Fixture::new();
        fx.config("work", "[core]\naccount = b@example.com\n")
            .active("work");
        fs::write(
            fx.gcloud().join("application_default_credentials.json"),
            r#"{"account":"","client_id":"fake","refresh_token":"fake-fixture-value","type":"authorized_user"}"#,
        )
        .unwrap();

        let status = fx.probe().status().unwrap();
        let notes = status.notes.join("\n");
        assert!(notes.contains("(ADC) exist;"), "{notes}");
        assert!(!notes.contains("ADC mismatch"), "{notes}");
        assert!(!notes.contains("exist for "), "{notes}");
    }

    #[test]
    fn test_missing_everything_is_not_installed_and_not_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let probe = GcloudProbe::new(Paths::for_test(dir.path()));
        let status = probe.status().unwrap();
        assert!(!status.installed);
        assert!(status.profiles.is_empty());
        assert!(status.active.is_none());
        assert!(status.notes.is_empty());
    }

    #[test]
    fn test_malformed_files_degrade_to_notes() {
        let fx = Fixture::new();
        fx.config("broken", "this is not ini\n\0\0").active("ghost");
        // A corrupt SQLite file must not take the board down.
        fs::write(fx.gcloud().join("credentials.db"), b"not a database").unwrap();
        fs::write(fx.gcloud().join("access_tokens.db"), b"not a database").unwrap();

        let status = fx.probe().status().unwrap();
        assert_eq!(status.active.as_deref(), Some("ghost"));
        let notes = status.notes.join("\n");
        assert!(notes.contains("no configurations/config_ghost"), "{notes}");
        assert!(notes.contains("credentials.db"), "{notes}");
        // The unparseable config still shows up, just with no metadata.
        let broken = status.profiles.iter().find(|p| p.id == "broken").unwrap();
        assert!(broken.meta.get("account").is_none());
    }

    #[test]
    fn test_schema_drift_in_access_tokens_degrades_to_unknown_expiry() {
        let fx = Fixture::new();
        fx.config("work", "[core]\naccount = b@example.com\n")
            .active("work")
            .credentials_db(&["b@example.com"]);
        // Table exists but the expiry column is gone.
        let conn = Connection::open(fx.gcloud().join("access_tokens.db")).unwrap();
        conn.execute(
            "CREATE TABLE access_tokens (account_id TEXT PRIMARY KEY, access_token TEXT)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO access_tokens VALUES ('b@example.com', 'fake')",
            [],
        )
        .unwrap();
        drop(conn);

        let status = fx.probe().status().unwrap();
        let work = status.profiles.iter().find(|p| p.id == "work").unwrap();
        assert!(work.expires_at.is_none());
        assert_eq!(work.meta["account_credentialed"], true);
    }

    #[test]
    fn test_active_account_without_credentials_is_flagged() {
        let fx = Fixture::new();
        fx.config("work", "[core]\naccount = ghost@example.com\n")
            .active("work")
            .credentials_db(&["someone@example.com"]);

        let status = fx.probe().status().unwrap();
        let notes = status.notes.join("\n");
        assert!(notes.contains("no stored credentials"), "{notes}");
        assert!(notes.contains("not used by any configuration"), "{notes}");
    }

    #[test]
    fn test_switch_to_unknown_profile_lists_the_real_ones() {
        let fx = Fixture::new();
        fx.config("work", "[core]\naccount = b@example.com\n");
        match fx.probe().switch("nope").unwrap() {
            SwitchOutcome::UnknownProfile { available, .. } => {
                assert_eq!(available, vec!["work".to_string()]);
            }
            other => panic!("expected UnknownProfile, got {other:?}"),
        }
    }
}
