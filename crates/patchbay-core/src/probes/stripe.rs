//! `stripe` — projects in the Stripe CLI's `config.toml`.
//!
//! Not installed on this machine; paths and shape verified against the CLI's
//! own source (`pkg/config/config.go`, `pkg/config/profile.go`). Notes:
//!
//! * The config folder is `$XDG_CONFIG_HOME/stripe`, else `~/.config/stripe` —
//!   the CLI reads `XDG_CONFIG_HOME` with no platform switch, so this holds on
//!   macOS too.
//! * A TOML table is a profile iff it has a `display_name` (the CLI's own
//!   `isProfile()` rule). Top-level scalars (`color`, `machine_uuid`,
//!   `installed_plugins`) are not profiles.
//! * **There is no active-profile pointer.** The active profile is literally
//!   the `[default]` table; `stripe config --switch` *rewrites the file*,
//!   swapping tables around. `STRIPE_PROJECT_NAME` overrides the choice at
//!   runtime, which is why it is reported as a note.
//! * `test_mode_key_expires_at` / `live_mode_key_expires_at` are plain
//!   `YYYY-MM-DD` dates (90 days from login), not RFC 3339.
//! * `test_mode_api_key` is a **real secret in plaintext**, `live_mode_api_key`
//!   is stored redacted with the real value in the keychain, and
//!   `credentials.json` in the same folder is a plaintext secret store. None of
//!   the three is ever parsed into a value here.

use std::collections::BTreeMap;

use chrono::{NaiveDate, TimeZone, Utc};
use serde::Deserialize;

use crate::paths::Paths;
use crate::probe::{unsupported_switch, unsupported_verify, Probe};
use crate::types::{PermissionsReport, Profile, SwitchOutcome, ToolStatus, VerifyOutcome};
use crate::util::read_text;

pub struct StripeProbe {
    paths: Paths,
}

/// Only the non-secret half of a profile table is named here.
#[derive(Deserialize, Default)]
struct ProfileTable {
    #[serde(default)]
    display_name: Option<String>,
    #[serde(default)]
    account_id: Option<String>,
    #[serde(default)]
    device_name: Option<String>,
    #[serde(default)]
    test_mode_key_expires_at: Option<String>,
    #[serde(default)]
    live_mode_key_expires_at: Option<String>,
    /// Presence only — this one is a real secret in plaintext.
    #[serde(default)]
    test_mode_api_key: Option<serde::de::IgnoredAny>,
    /// Presence only — stored redacted, real value in the keychain.
    #[serde(default)]
    live_mode_api_key: Option<serde::de::IgnoredAny>,
}

impl StripeProbe {
    pub const TOOL: &'static str = "stripe";
    /// The table the CLI treats as active.
    const ACTIVE_TABLE: &'static str = "default";

    pub fn new(paths: Paths) -> Self {
        Self { paths }
    }

    /// Stripe writes `YYYY-MM-DD` with no time and no zone. Treat it as end of
    /// that day UTC, so a key is not called expired hours early.
    fn parse_expiry(raw: &str) -> Option<chrono::DateTime<Utc>> {
        let date = NaiveDate::parse_from_str(raw.trim(), "%Y-%m-%d").ok()?;
        Utc.from_utc_datetime(&date.and_hms_opt(23, 59, 59)?).into()
    }
}

impl Probe for StripeProbe {
    fn tool(&self) -> &'static str {
        Self::TOOL
    }

    fn status(&self) -> anyhow::Result<ToolStatus> {
        let path = self.paths.stripe_config();
        let installed = self.paths.has_binary("stripe") || path.is_file();
        let mut status = ToolStatus::empty(Self::TOOL, installed);
        for note in self.paths.path_notes("stripe") {
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

        // Parse as a generic table first: the file mixes top-level scalars with
        // profile tables, and a strict struct would reject the scalars.
        let root: BTreeMap<String, toml::Value> = match toml::from_str(&text) {
            Ok(root) => root,
            Err(e) => {
                status.note(format!("stripe config.toml is not valid TOML ({e})"));
                return Ok(status);
            }
        };

        let mut plaintext_test_keys = Vec::new();
        for (name, value) in &root {
            let Some(table) = value.as_table() else {
                continue;
            };
            let profile: ProfileTable = match table.clone().try_into() {
                Ok(profile) => profile,
                Err(_) => continue,
            };
            // The CLI's own rule for "is this a profile".
            if profile.display_name.is_none() {
                continue;
            }
            if profile.test_mode_api_key.is_some() {
                plaintext_test_keys.push(name.clone());
            }

            // The test-mode key is the one the CLI uses day to day, so its
            // expiry is the one that decides the profile's state.
            let expires_at = profile
                .test_mode_key_expires_at
                .as_deref()
                .and_then(Self::parse_expiry);
            let live_expiry = profile
                .live_mode_key_expires_at
                .as_deref()
                .and_then(Self::parse_expiry);

            status.profiles.push(
                Profile::new(name.as_str())
                    .label(profile.display_name.clone().unwrap_or_else(|| name.clone()))
                    .expires_at(expires_at)
                    .with_meta("account_id", profile.account_id.clone())
                    .with_meta("device_name", profile.device_name.clone())
                    .with_meta("has_test_mode_key", profile.test_mode_api_key.is_some())
                    .with_meta("has_live_mode_key", profile.live_mode_api_key.is_some())
                    .with_meta(
                        "live_mode_key_expires_at",
                        live_expiry.map(|at| at.to_rfc3339()),
                    ),
            );
        }

        if status.profiles.is_empty() {
            if !root.is_empty() {
                status.note(
                    "stripe config.toml has no profile tables; a table counts as a profile only \
                     once it has a display_name"
                        .to_string(),
                );
            }
            return Ok(status);
        }

        // No pointer key exists: `[default]` *is* the active profile.
        if status.profiles.iter().any(|p| p.id == Self::ACTIVE_TABLE) {
            status.active = Some(Self::ACTIVE_TABLE.to_string());
        }
        status.note(
            "stripe has no active-profile pointer: the `[default]` table is the active profile, \
             and `stripe config --switch` rewrites the file to move tables in and out of it"
                .to_string(),
        );
        if let Some(project) = self.paths.env("STRIPE_PROJECT_NAME") {
            status.note(format!(
                "STRIPE_PROJECT_NAME={project} is set and overrides that choice for every command"
            ));
        }
        if self.paths.env("STRIPE_API_KEY").is_some() {
            status.note(
                "STRIPE_API_KEY is set in the environment and takes precedence over every stored \
                 profile"
                    .to_string(),
            );
        }
        if !plaintext_test_keys.is_empty() {
            status.note(format!(
                "the test-mode key for {} is stored in plain text in config.toml (the live-mode \
                 key is redacted there and kept in the keychain)",
                plaintext_test_keys.join(", ")
            ));
        }
        if path
            .parent()
            .map(|dir| dir.join("credentials.json").is_file())
            .unwrap_or(false)
        {
            status.note(
                "credentials.json sits next to config.toml: that is the plaintext fallback secret \
                 store the CLI uses when the OS keyring is unavailable"
                    .to_string(),
            );
        }

        Ok(status)
    }

    fn switch(&self, _profile_id: &str) -> anyhow::Result<SwitchOutcome> {
        // Switching rewrites the config file, moving tables in and out of
        // `[default]`. patchbay will not do that on someone's behalf.
        Ok(unsupported_switch(
            Self::TOOL,
            "switching a stripe profile rewrites config.toml rather than moving a pointer; \
             patchbay will not restructure that file for you",
            Some("stripe config --set-default <profile> (or pass --project-name per command)"),
        ))
    }

    fn verify(&self) -> anyhow::Result<VerifyOutcome> {
        Ok(unsupported_verify(
            Self::TOOL,
            "patchbay does not run stripe yet; the stored key expiry in status is the cheap answer",
            Some("stripe config --list"),
        ))
    }

    fn permissions(&self) -> anyhow::Result<PermissionsReport> {
        Ok(PermissionsReport::unsupported(
            Self::TOOL,
            "a Stripe CLI key's rights come from the account and the key's restrictions, neither \
             of which is recorded on disk",
            Some("the API keys page of the Stripe dashboard"),
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
        fs::create_dir_all(home.join(".config/stripe")).unwrap();
        fs::write(home.join(".config/stripe/config.toml"), body).unwrap();
        (dir, home)
    }

    // Key names from the CLI's own constants; every value is invented.
    const CONFIG: &str = r#"
color = "auto"
machine_uuid = "8f14e45f-ceea-467a-9c2b-4a1d7f0c9e33"
installed_plugins = []

[default]
account_id = "acct_1FAKEFIXTURE"
display_name = "Pathors Ltd"
device_name = "fixture-mbp"
test_mode_api_key = "sk_test_fakefixturesecret"
test_mode_key_expires_at = "2030-11-11"
live_mode_api_key = "sk_live_fake****fixt"
live_mode_key_expires_at = "2030-12-01"

[staging]
display_name = "Pathors Staging"
test_mode_api_key = "sk_test_fakefixturestaging"
test_mode_key_expires_at = "2020-01-01"
"#;

    #[test]
    fn test_profiles_come_from_tables_with_a_display_name() {
        let (_dir, home) = fixture(CONFIG);
        let status = StripeProbe::new(Paths::for_test(&home)).status().unwrap();
        let ids: Vec<_> = status.profiles.iter().map(|p| p.id.as_str()).collect();
        assert_eq!(ids, vec!["default", "staging"]);
        assert_eq!(status.active.as_deref(), Some("default"));

        let default = &status.profiles[0];
        assert_eq!(default.label, "Pathors Ltd");
        assert_eq!(default.meta["account_id"], "acct_1FAKEFIXTURE");
        assert_eq!(default.meta["has_live_mode_key"], true);
        // End of day UTC, not midnight, so a key is not called expired early.
        assert_eq!(
            default.expires_at.unwrap().to_rfc3339(),
            "2030-11-11T23:59:59+00:00"
        );
        assert!(status.notes.iter().any(|n| n.contains("no active-profile")));
        assert!(status.notes.iter().any(|n| n.contains("plain text")));

        let json = serde_json::to_string(&status).unwrap();
        for secret in [
            "sk_test_fakefixturesecret",
            "sk_test_fakefixturestaging",
            "sk_live_fake",
        ] {
            assert!(!json.contains(secret), "leaked {secret}");
        }
    }

    #[test]
    fn test_environment_overrides_are_called_out() {
        let (_dir, home) = fixture(CONFIG);
        let paths = Paths::for_test(&home)
            .with_env("STRIPE_PROJECT_NAME", "staging")
            .with_env("STRIPE_API_KEY", "sk_test_fakefixtureenv");
        let status = StripeProbe::new(paths).status().unwrap();
        assert!(status
            .notes
            .iter()
            .any(|n| n.contains("STRIPE_PROJECT_NAME=staging")));
        assert!(status.notes.iter().any(|n| n.contains("STRIPE_API_KEY")));
        let json = serde_json::to_string(&status).unwrap();
        assert!(!json.contains("sk_test_fakefixtureenv"), "{json}");
    }

    #[test]
    fn test_plaintext_credentials_file_is_flagged() {
        let (_dir, home) = fixture(CONFIG);
        fs::write(
            home.join(".config/stripe/credentials.json"),
            "{\"fixture\": true}",
        )
        .unwrap();
        let status = StripeProbe::new(Paths::for_test(&home)).status().unwrap();
        assert!(status
            .notes
            .iter()
            .any(|n| n.contains("plaintext fallback secret store")));
    }

    #[test]
    fn test_missing_malformed_and_profileless() {
        let dir = tempfile::tempdir().unwrap();
        let status = StripeProbe::new(Paths::for_test(dir.path()))
            .status()
            .unwrap();
        assert!(!status.installed);
        assert!(status.profiles.is_empty());

        let (_dir, home) = fixture("this is not = = toml [[[");
        let status = StripeProbe::new(Paths::for_test(&home)).status().unwrap();
        assert!(status.notes.iter().any(|n| n.contains("not valid TOML")));

        let (_dir, home) = fixture("color = \"auto\"\n\n[scratch]\ndevice_name = \"x\"\n");
        let status = StripeProbe::new(Paths::for_test(&home)).status().unwrap();
        assert!(status.profiles.is_empty());
        assert!(status.notes.iter().any(|n| n.contains("display_name")));
    }

    #[test]
    fn test_expiry_parser_rejects_rfc3339_shaped_junk() {
        assert!(StripeProbe::parse_expiry("2030-11-11").is_some());
        assert!(StripeProbe::parse_expiry("never").is_none());
        assert!(StripeProbe::parse_expiry("").is_none());
    }
}
