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
use crate::probes::cli_verify;
use crate::types::{
    ActiveConcept, Expiry, PermissionsReport, Profile, SwitchOutcome, ToolStatus, VerifyOutcome,
};
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

    /// What `stripe whoami` is, and is not.
    ///
    /// Stripe's CLI has no read-only command that both names the account and
    /// exercises the key: `whoami` is explicit that it "reads credentials from
    /// the config file and keychain — no API calls are made". So the tick means
    /// "this is the key the CLI will send", not "Stripe still honours it", and
    /// the detail says so rather than letting a green row imply the stronger
    /// claim.
    ///
    /// **Why `whoami` and not `config --list`.** `config --list` prints the
    /// config file back, and that file holds `test_mode_api_key` in plain text.
    /// It is the same local read with a live secret in the output and no
    /// `authenticated` flag to read. `whoami` reports key *availability* and
    /// expiry without ever printing key material.
    const CHECK_CAVEAT: &'static str =
        "the stripe CLI names the key it will use (`whoami` reads the local config and keychain, \
         so it does not prove Stripe still accepts it)";

    /// Stripe writes `YYYY-MM-DD` with no time and no zone. Treat it as end of
    /// that day UTC, so a key is not called expired hours early.
    fn parse_expiry(raw: &str) -> Option<chrono::DateTime<Utc>> {
        let date = NaiveDate::parse_from_str(raw.trim(), "%Y-%m-%d").ok()?;
        Utc.from_utc_datetime(&date.and_hms_opt(23, 59, 59)?).into()
    }
}

/// `stripe whoami --format json`.
///
/// Every field is optional on purpose — the schema is documented as stable, but
/// a verify that fails because one key moved is worse than a thinner sentence.
/// Note what is *not* here: the key values. `whoami` reports availability and
/// expiry only, which is exactly why it is the command patchbay runs.
#[derive(Deserialize, Default)]
struct Whoami {
    #[serde(default)]
    authenticated: Option<bool>,
    #[serde(default)]
    display_name: Option<String>,
    #[serde(default)]
    account_id: Option<String>,
    #[serde(default)]
    device_name: Option<String>,
    #[serde(default)]
    test_mode_key: Option<KeyState>,
    #[serde(default)]
    live_mode_key: Option<KeyState>,
}

#[derive(Deserialize, Default)]
struct KeyState {
    #[serde(default)]
    available: Option<bool>,
    #[serde(default)]
    expires_at: Option<String>,
}

impl Whoami {
    fn parse(stdout: &str) -> Option<Self> {
        serde_json::from_str(stdout.trim()).ok()
    }

    fn describe(&self) -> String {
        let who = self
            .display_name
            .clone()
            .or_else(|| self.account_id.clone())
            .unwrap_or_else(|| "an account it would not name".to_string());
        let mut parts = Vec::new();
        if let Some(account) = self.account_id.clone().filter(|a| *a != who) {
            parts.push(account);
        }
        if let Some(device) = self.device_name.clone() {
            parts.push(format!("device {device}"));
        }
        for (label, key) in [
            ("test key", self.test_mode_key.as_ref()),
            ("live key", self.live_mode_key.as_ref()),
        ] {
            let Some(key) = key else { continue };
            if key.available == Some(false) {
                continue;
            }
            match key.expires_at.as_deref().map(str::trim) {
                Some(when) if !when.is_empty() => parts.push(format!("{label} to {when}")),
                _ => parts.push(label.to_string()),
            }
        }
        match parts.is_empty() {
            true => who,
            false => format!("{who} ({})", parts.join(", ")),
        }
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

        // Parse as a generic table first: the file mixes top-level scalars with
        // profile tables, and a strict struct would reject the scalars.
        let root: BTreeMap<String, toml::Value> = match toml::from_str(&text) {
            Ok(root) => root,
            Err(e) => {
                status.problem(format!("stripe config.toml is not valid TOML ({e})"));
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
                    // The CLI writes a 90-day date at login. When it is absent
                    // the key still has a life, patchbay just cannot see it.
                    .expiry(match expires_at {
                        Some(at) => Expiry::At(at),
                        None => Expiry::unknown("not recorded in config.toml"),
                    })
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
                status.info(
                    "stripe config.toml has no profile tables; a table counts as a profile only \
                     once it has a display_name",
                );
            }
            return Ok(status);
        }

        // No pointer key exists: `[default]` *is* the active profile.
        if status.profiles.iter().any(|p| p.id == Self::ACTIVE_TABLE) {
            status.active = Some(Self::ACTIVE_TABLE.to_string());
        }
        status.active_concept = ActiveConcept::not_applicable(
            "the [default] table is the active profile; stripe has no pointer to move",
        );
        if let Some(project) = self.paths.env("STRIPE_PROJECT_NAME") {
            status.warn(format!(
                "STRIPE_PROJECT_NAME={project} is set and overrides the [default] table for every \
                 command"
            ));
        }
        if self.paths.env("STRIPE_API_KEY").is_some() {
            status.warn(
                "STRIPE_API_KEY is set in the environment and takes precedence over every stored \
                 profile",
            );
        }
        if !plaintext_test_keys.is_empty() {
            status.warn(format!(
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
            status.warn(
                "credentials.json sits next to config.toml: that is the plaintext fallback secret \
                 store the CLI uses when the OS keyring is unavailable",
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
        let status = self.status()?;
        self.verify_profile(status.active.as_deref().unwrap_or(Self::ACTIVE_TABLE))
    }

    /// One profile, as the CLI itself resolves it.
    ///
    /// `--project-name` is the CLI's own per-invocation profile selector, so
    /// asking about a profile never rewrites the file the way
    /// `config --set-default` would.
    fn verify_profile(&self, profile_id: &str) -> anyhow::Result<VerifyOutcome> {
        if !self.paths.may_exec() || !self.paths.has_binary("stripe") {
            return Ok(unsupported_verify(
                Self::TOOL,
                "the stripe CLI is not available on PATH",
                Some("stripe whoami"),
            ));
        }

        let mut args = vec!["whoami", "--format", "json"];
        if profile_id != Self::ACTIVE_TABLE {
            args.extend_from_slice(&["--project-name", profile_id]);
        }
        // The CLI fires a telemetry beacon and then *waits up to three seconds*
        // for it before exiting. patchbay's verify should not pay that, and
        // should not phone home on the user's behalf either.
        let out = self.paths.run_env(
            "stripe",
            &args,
            &[("STRIPE_CLI_TELEMETRY_OPTOUT", "1"), ("DO_NOT_TRACK", "1")],
        )?;
        if !out.ok {
            return Ok(cli_verify::failure_outcome(
                Self::TOOL,
                &out,
                "the Stripe CLI",
                "stripe login",
            ));
        }

        let who = Whoami::parse(&out.stdout);
        if who.as_ref().is_some_and(|w| w.authenticated == Some(false)) {
            return Ok(VerifyOutcome::Invalid {
                tool: Self::TOOL.to_string(),
                detail: format!(
                    "the stripe CLI holds no key for profile `{profile_id}` — run `stripe login`"
                ),
            });
        }
        Ok(VerifyOutcome::Valid {
            tool: Self::TOOL.to_string(),
            detail: match who {
                Some(who) => format!("{}: {}", Self::CHECK_CAVEAT, who.describe()),
                // `whoami` exits non-zero when it is not authenticated, so a
                // zero exit is still an answer even when the shape is strange.
                None => format!(
                    "{}, but `stripe whoami --format json` did not parse",
                    Self::CHECK_CAVEAT
                ),
            },
        })
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
    use crate::types::NoteKind;
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
            default.expires_at().unwrap().to_rfc3339(),
            "2030-11-11T23:59:59+00:00"
        );
        // "which one is active" is not a question stripe answers with a
        // pointer, so it is a property of the status rather than a note.
        assert_eq!(
            status.active_concept,
            ActiveConcept::not_applicable(
                "the [default] table is the active profile; stripe has no pointer to move"
            )
        );
        assert!(!status
            .notes
            .iter()
            .any(|n| n.text.contains("no active-profile")));
        // A secret in plain text is a warning, not a remark.
        let plaintext = status
            .notes
            .iter()
            .find(|n| n.text.contains("plain text"))
            .expect("the plaintext test key is called out");
        assert_eq!(plaintext.kind, NoteKind::Warn);

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
        // An env var silently outranking the stored login is a warning.
        for text in ["STRIPE_PROJECT_NAME=staging", "STRIPE_API_KEY"] {
            let note = status
                .notes
                .iter()
                .find(|n| n.text.contains(text))
                .unwrap_or_else(|| panic!("no note about {text}"));
            assert_eq!(note.kind, NoteKind::Warn, "{text}");
        }
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
        let note = status
            .notes
            .iter()
            .find(|n| n.text.contains("plaintext fallback secret store"))
            .expect("credentials.json is called out");
        assert_eq!(note.kind, NoteKind::Warn);
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
        // A file that will not parse is broken, not a remark.
        let malformed = status
            .notes
            .iter()
            .find(|n| n.text.contains("not valid TOML"))
            .expect("the parse failure is reported");
        assert_eq!(malformed.kind, NoteKind::Problem);

        let (_dir, home) = fixture("color = \"auto\"\n\n[scratch]\ndevice_name = \"x\"\n");
        let status = StripeProbe::new(Paths::for_test(&home)).status().unwrap();
        assert!(status.profiles.is_empty());
        let explanation = status
            .notes
            .iter()
            .find(|n| n.text.contains("display_name"))
            .expect("the profile rule is explained");
        assert_eq!(explanation.kind, NoteKind::Info);
    }

    // ---------------------------------------------------------------- verify

    fn probe_with(
        home: &std::path::Path,
        exec: std::sync::Arc<crate::util::FakeExec>,
    ) -> StripeProbe {
        StripeProbe::new(Paths::for_test(home).with_exec(exec))
    }

    /// `stripe whoami --format json`, authenticated. Note what a real answer
    /// does *not* contain: any key value.
    const WHOAMI: &str = r#"{
      "authenticated": true,
      "profile_name": "default",
      "display_name": "Pathors Ltd",
      "account_id": "acct_1FAKEFIXTURE",
      "device_name": "fixture-mbp",
      "test_mode_key": { "available": true, "expires_at": "2030-11-11" },
      "live_mode_key": { "available": true, "expires_at": "2030-12-01" },
      "api_version": "2026-03-31"
    }"#;

    #[test]
    fn test_verify_names_the_account_and_never_quotes_a_key() {
        let (_dir, home) = fixture(CONFIG);
        let exec = std::sync::Arc::new(crate::util::FakeExec::new().on("whoami", true, WHOAMI, ""));
        let outcome = probe_with(&home, exec.clone()).verify().unwrap();
        let call = exec.last().unwrap();
        assert_eq!(call.line(), "stripe whoami --format json");
        // The CLI waits up to three seconds on a telemetry beacon otherwise.
        assert!(
            call.env
                .iter()
                .any(|(k, v)| k == "STRIPE_CLI_TELEMETRY_OPTOUT" && v == "1"),
            "{:?}",
            call.env
        );
        match outcome {
            VerifyOutcome::Valid { detail, .. } => {
                assert!(detail.contains("Pathors Ltd"), "{detail}");
                assert!(detail.contains("acct_1FAKEFIXTURE"), "{detail}");
                assert!(detail.contains("test key to 2030-11-11"), "{detail}");
                // The caveat travels with the tick: this is a local read.
                assert!(detail.contains("does not prove"), "{detail}");
                assert_eq!(detail.lines().count(), 1, "{detail}");
            }
            other => panic!("expected Valid, got {other:?}"),
        }
    }

    #[test]
    fn test_verify_profile_pins_the_profile_it_was_asked_about() {
        let (_dir, home) = fixture(CONFIG);
        let exec = std::sync::Arc::new(crate::util::FakeExec::new().on("whoami", true, WHOAMI, ""));
        let probe = probe_with(&home, exec.clone());
        probe.verify_profile("staging").unwrap();
        let args = exec.last().unwrap().args;
        assert!(
            args.contains(&"--project-name".to_string()) && args.contains(&"staging".to_string()),
            "{args:?}"
        );

        // The default profile is the one the CLI already uses; naming it adds
        // nothing and `--project-name default` is not how it is spelled.
        probe.verify_profile("default").unwrap();
        assert!(
            !exec
                .last()
                .unwrap()
                .args
                .contains(&"--project-name".to_string()),
            "{:?}",
            exec.last().unwrap().args
        );
    }

    #[test]
    fn test_an_unauthenticated_answer_is_a_logged_out_answer() {
        let (_dir, home) = fixture(CONFIG);
        // `whoami` exits 1 in this state, but the flag is honoured either way.
        let exec = std::sync::Arc::new(crate::util::FakeExec::new().on(
            "whoami",
            true,
            r#"{ "authenticated": false, "profile_name": "default" }"#,
            "",
        ));
        match probe_with(&home, exec).verify().unwrap() {
            VerifyOutcome::Invalid { detail, .. } => {
                assert!(detail.contains("stripe login"), "{detail}");
            }
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    #[test]
    fn test_no_key_expired_key_and_an_outage_get_three_different_answers() {
        let (_dir, home) = fixture(CONFIG);

        let none = std::sync::Arc::new(crate::util::FakeExec::new().on(
            "whoami",
            false,
            "You have not configured API keys yet.\n",
            "",
        ));
        match probe_with(&home, none).verify().unwrap() {
            VerifyOutcome::Invalid { detail, .. } => {
                assert!(detail.contains("stripe login"), "{detail}");
            }
            other => panic!("expected Invalid, got {other:?}"),
        }

        let expired = std::sync::Arc::new(crate::util::FakeExec::new().on(
            "whoami",
            false,
            "",
            "The API key for the default profile has expired. Run `stripe login` to re-authenticate.\nYou can also set the STRIPE_API_KEY environment variable.\n",
        ));
        match probe_with(&home, expired).verify().unwrap() {
            VerifyOutcome::Invalid { detail, .. } => {
                assert!(detail.contains("rejected"), "{detail}");
                // One sentence, not both of the CLI's lines.
                assert_eq!(detail.lines().count(), 1, "{detail}");
                assert!(!detail.contains("STRIPE_API_KEY"), "{detail}");
            }
            other => panic!("expected Invalid, got {other:?}"),
        }

        let offline = std::sync::Arc::new(crate::util::FakeExec::new().on(
            "whoami",
            false,
            "",
            "Get \"https://api.stripe.com/v1/account\": dial tcp: lookup api.stripe.com: no such host\n",
        ));
        match probe_with(&home, offline).verify().unwrap() {
            VerifyOutcome::Unsupported { reason, .. } => {
                assert!(reason.contains("could not reach"), "{reason}");
            }
            other => panic!("expected Unsupported, got {other:?}"),
        }
    }

    #[test]
    fn test_unreadable_output_degrades_instead_of_panicking() {
        let (_dir, home) = fixture(CONFIG);
        for junk in ["", "not json", "[[[[", "null"] {
            let exec =
                std::sync::Arc::new(crate::util::FakeExec::new().on("whoami", true, junk, ""));
            match probe_with(&home, exec).verify().unwrap() {
                VerifyOutcome::Valid { detail, .. } => {
                    assert!(detail.contains("did not parse"), "{junk:?} -> {detail}");
                }
                other => panic!("expected Valid for {junk:?}, got {other:?}"),
            }
        }

        // Valid JSON of an unexpected shape is not a crash either.
        let exec = std::sync::Arc::new(crate::util::FakeExec::new().on("whoami", true, "{}", ""));
        match probe_with(&home, exec).verify().unwrap() {
            VerifyOutcome::Valid { detail, .. } => {
                assert!(detail.contains("would not name"), "{detail}")
            }
            other => panic!("expected Valid, got {other:?}"),
        }
    }

    #[test]
    fn test_verify_without_the_binary_stays_unsupported() {
        let (_dir, home) = fixture(CONFIG);
        match StripeProbe::new(Paths::for_test(&home)).verify().unwrap() {
            VerifyOutcome::Unsupported { reason, hint, .. } => {
                assert!(reason.contains("not available on PATH"), "{reason}");
                assert_eq!(hint.as_deref(), Some("stripe whoami"));
            }
            other => panic!("expected Unsupported, got {other:?}"),
        }
    }

    #[test]
    fn test_expiry_parser_rejects_rfc3339_shaped_junk() {
        assert!(StripeProbe::parse_expiry("2030-11-11").is_some());
        assert!(StripeProbe::parse_expiry("never").is_none());
        assert!(StripeProbe::parse_expiry("").is_none());
    }
}
