//! `huggingface` — the Hub token(s) under `~/.cache/huggingface`.
//!
//! Not installed on this machine; verified against `huggingface_hub`'s source
//! (`constants.py`, `utils/_auth.py`). Two files, both under `HF_HOME` (else
//! `$XDG_CACHE_HOME/huggingface`, else `~/.cache/huggingface`):
//!
//! * `token` — the active token, raw, nothing else in the file. **Presence
//!   only**; it is never opened.
//! * `stored_tokens` — an INI file for named tokens. Section name = token name
//!   (`hf auth login --token-name`, or `oauth-<username>` for browser logins),
//!   fields `hf_token`, optionally `refresh_token` and `expires_at` (Unix
//!   seconds, as a string). Only `expires_at` is read.
//!
//! **Which named token is active cannot be known from disk.** The library
//! decides by comparing the *value* in `token` against each section's
//! `hf_token`, and patchbay does not read token values. So `active` is `None`
//! with a note, rather than a guess. (`hf auth list` will tell a human, at the
//! cost of printing a partially masked token.)
//!
//! The CLI is `hf`; `huggingface-cli` was removed in huggingface_hub 1.0 and is
//! only checked as a legacy install signal.

use crate::paths::Paths;
use crate::probe::{unsupported_switch, unsupported_verify, Probe};
use crate::probes::cli_verify;
use crate::types::{Expiry, PermissionsReport, Profile, SwitchOutcome, ToolStatus, VerifyOutcome};
use crate::util::{read_text, Ini};

pub struct HuggingfaceProbe {
    paths: Paths,
}

impl HuggingfaceProbe {
    pub const TOOL: &'static str = "huggingface";
    /// The name used when only the single `token` file exists.
    const DEFAULT_PROFILE: &'static str = "default";

    pub fn new(paths: Paths) -> Self {
        Self { paths }
    }

    /// The whoami invocation for whichever CLI generation is installed.
    ///
    /// huggingface_hub 1.0 renamed the binary and moved the verb: `hf auth
    /// whoami` replaced `huggingface-cli whoami`. Machines mid-upgrade have
    /// only one of them, so the command is chosen rather than assumed.
    ///
    /// **`--format json` is not an optimisation, it is a correctness fix.** The
    /// modern CLI defaults to `--format auto`, which sniffs environment
    /// variables to decide whether it is talking to a human or to an AI agent
    /// harness and *changes the output shape accordingly*. patchbay is
    /// frequently launched from exactly such a harness, so leaving the format
    /// to auto-detection means parsing a different answer depending on who
    /// started the panel. The flag pins it.
    fn whoami_command(&self) -> Option<(&'static str, Vec<&'static str>)> {
        if !self.paths.may_exec() {
            return None;
        }
        if self.paths.has_binary("hf") {
            Some(("hf", vec!["auth", "whoami", "--format", "json"]))
        } else if self.paths.has_binary("huggingface-cli") {
            // The pre-1.0 CLI has neither the `auth` verb nor `--format`.
            Some(("huggingface-cli", vec!["whoami"]))
        } else {
            None
        }
    }

    /// `(username, orgs)` out of whoami, in either dialect it speaks.
    ///
    /// JSON first: `{"user": "...", "orgs": "a,b", "endpoint": null}` — note
    /// that `orgs` is a **comma-joined string**, not a list, and is `null` when
    /// there are none. Anything that is not JSON falls through to the legacy
    /// text shape, which is the username on its own line and an optional
    /// `orgs:  a,b` beneath it.
    fn parse_whoami(stdout: &str) -> Option<(String, Vec<String>)> {
        if let Some(parsed) = Self::parse_whoami_json(stdout) {
            return Some(parsed);
        }
        Self::parse_whoami_text(stdout)
    }

    fn parse_whoami_json(stdout: &str) -> Option<(String, Vec<String>)> {
        let value: serde_json::Value = serde_json::from_str(stdout.trim()).ok()?;
        let user = value.get("user")?.as_str()?.trim().to_string();
        if user.is_empty() {
            return None;
        }
        let orgs = value
            .get("orgs")
            .and_then(|o| o.as_str())
            .map(|o| {
                o.split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect()
            })
            .unwrap_or_default();
        Some((user, orgs))
    }

    fn parse_whoami_text(stdout: &str) -> Option<(String, Vec<String>)> {
        let mut user = None;
        let mut orgs = Vec::new();
        for line in stdout.lines() {
            // NO_COLOR is set on every child, but a bold escape that slips
            // through must not become part of a username.
            let line = strip_ansi(line);
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            if let Some(rest) = line.to_lowercase().strip_prefix("orgs:") {
                let start = line.len() - rest.len();
                orgs = line[start..]
                    .split(',')
                    .map(|o| o.trim().to_string())
                    .filter(|o| !o.is_empty())
                    .collect();
                continue;
            }
            // A private-endpoint notice follows the username; do not take it.
            if line.starts_with("Authenticated through") {
                continue;
            }
            if user.is_none() {
                user = Some(line.to_string());
            }
        }
        user.map(|user| (user, orgs))
    }
}

/// Drop CSI escape sequences. Deliberately tiny: this only ever sees one short
/// line of a CLI's own output, and a dependency for that would be absurd.
fn strip_ansi(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut chars = line.chars();
    while let Some(c) = chars.next() {
        if c != '\u{1b}' {
            out.push(c);
            continue;
        }
        // ESC [ … <final byte in @..~>
        for c in chars.by_ref() {
            if ('\u{40}'..='\u{7e}').contains(&c) && c != '[' {
                break;
            }
        }
    }
    out
}

impl Probe for HuggingfaceProbe {
    fn tool(&self) -> &'static str {
        Self::TOOL
    }

    fn status(&self) -> anyhow::Result<ToolStatus> {
        let dir = self.paths.huggingface_dir();
        let token = self.paths.huggingface_token();
        let stored = self.paths.huggingface_stored_tokens();
        let installed =
            self.paths.has_binary("hf") || self.paths.has_binary("huggingface-cli") || dir.is_dir();
        let mut status = ToolStatus::empty(Self::TOOL, installed);
        for note in self.paths.path_notes("huggingface") {
            status.push_note(note);
        }

        if !installed {
            return Ok(status);
        }

        // Existence only: this file *is* the token.
        let has_active_token = token.is_file();

        // The named-token store is safe to parse — as long as only expires_at
        // is taken out of it.
        let named = match read_text(&stored) {
            Ok(Some(text)) => Ini::parse(&text),
            Ok(None) => Ini::default(),
            Err(e) => {
                status.problem(e);
                Ini::default()
            }
        };

        for section in &named.sections {
            let expires_at = section
                .get("expires_at")
                .and_then(|raw| raw.trim().parse::<i64>().ok())
                .and_then(|secs| chrono::DateTime::from_timestamp(secs, 0));
            // `expires_at` is only ever written for a browser login. A plain
            // access token has no deadline at all; an OAuth section missing
            // the field has one patchbay cannot see.
            let oauth = section.get("refresh_token").is_some();
            let expiry = match (expires_at, oauth) {
                (Some(at), _) => Expiry::At(at),
                (None, true) => Expiry::unknown("not recorded in stored_tokens"),
                (None, false) => Expiry::NoExpiry,
            };
            status.profiles.push(
                Profile::new(&section.name)
                    .expiry(expiry)
                    .with_meta(
                        "auth",
                        if oauth {
                            "oauth (browser login)"
                        } else {
                            "access token"
                        },
                    )
                    .with_meta("source", "stored_tokens"),
            );
        }

        if status.profiles.is_empty() && has_active_token {
            status.profiles.push(
                Profile::new(Self::DEFAULT_PROFILE)
                    .label("hugging face token")
                    // A bare `token` file is always a plain access token.
                    .expiry(Expiry::NoExpiry)
                    .with_meta("auth", "access token")
                    .with_meta("source", token.display().to_string()),
            );
            status.active = Some(Self::DEFAULT_PROFILE.to_string());
        }

        if self.paths.env("HF_TOKEN").is_some()
            || self.paths.env("HUGGING_FACE_HUB_TOKEN").is_some()
        {
            status.warn(
                "an HF token is set in the environment and takes precedence over both files — a \
                 missing token file does not mean you are logged out",
            );
        }

        if status.profiles.is_empty() {
            return Ok(status);
        }

        if !named.sections.is_empty() {
            // Deliberately not guessed: see the module docs.
            status.info(format!(
                "{} named token(s); which one is active cannot be told from disk without reading \
                 token values, which patchbay will not do — `hf auth list` marks it with a *",
                named.sections.len()
            ));
            if !has_active_token {
                // Tokens are stored, none is selected: every hf call goes out
                // unauthenticated until one is.
                status.problem(
                    "there are named tokens but no active token file, so the CLI is not \
                     authenticated until you run `hf auth switch`",
                );
            }
        }

        Ok(status)
    }

    fn switch(&self, profile_id: &str) -> anyhow::Result<SwitchOutcome> {
        // `hf auth switch` copies a token value into the active token file.
        // That is exactly the operation patchbay refuses to perform.
        Ok(unsupported_switch(
            Self::TOOL,
            "switching copies a token value between files, which patchbay will not do",
            Some(&format!("hf auth switch --token-name {profile_id}")),
        ))
    }

    fn verify(&self) -> anyhow::Result<VerifyOutcome> {
        let Some((bin, args)) = self.whoami_command() else {
            return Ok(unsupported_verify(
                Self::TOOL,
                "the hf CLI is not available on PATH",
                Some("hf auth whoami"),
            ));
        };

        let out = self.paths.run(bin, &args)?;
        if !out.ok {
            // No token and a rejected token both exit 1 here — `Error: Not
            // logged in` versus `Error: Invalid user token.` — so the text is
            // what separates them, which is precisely what `classify` does.
            return Ok(cli_verify::failure_outcome(
                Self::TOOL,
                &out,
                "the Hugging Face Hub",
                "hf auth login",
            ));
        }

        // Belt and braces for older hub releases, which printed `Not logged in`
        // and exited **zero**: on those, the exit code alone files a logged-out
        // machine as a working login.
        if cli_verify::says_logged_out(&out.stdout) {
            return Ok(VerifyOutcome::Invalid {
                tool: Self::TOOL.to_string(),
                detail: "not logged in — run `hf auth login`".to_string(),
            });
        }

        Ok(match Self::parse_whoami(&out.stdout) {
            Some((user, orgs)) => VerifyOutcome::Valid {
                tool: Self::TOOL.to_string(),
                detail: match orgs.is_empty() {
                    true => format!("the Hub accepted the token for {user}"),
                    false => format!(
                        "the Hub accepted the token for {user} (orgs: {})",
                        orgs.join(", ")
                    ),
                },
            },
            None => VerifyOutcome::Valid {
                tool: Self::TOOL.to_string(),
                detail: "the Hub accepted the token, but `whoami` named no user".to_string(),
            },
        })
    }

    fn permissions(&self) -> anyhow::Result<PermissionsReport> {
        Ok(PermissionsReport::unsupported(
            Self::TOOL,
            "a Hub token's scopes (read / write / fine-grained repo access) are recorded at \
             huggingface.co, not on this machine",
            Some("hf auth whoami"),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::NoteKind;
    use std::fs;
    use std::path::Path;

    fn hf_dir(home: &Path) -> std::path::PathBuf {
        let dir = home.join(".cache/huggingface");
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn test_single_token_file_is_one_profile_and_is_never_opened() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = hf_dir(tmp.path());
        fs::write(dir.join("token"), "hf_fakefixturetokenvalue").unwrap();

        let status = HuggingfaceProbe::new(Paths::for_test(tmp.path()))
            .status()
            .unwrap();
        assert!(status.installed);
        assert_eq!(status.active.as_deref(), Some("default"));
        assert_eq!(status.profiles.len(), 1);
        // A plain access token has no deadline at all — a different claim from
        // "there is one and we cannot see it".
        assert_eq!(status.profiles[0].expiry, Expiry::NoExpiry);
        // The type carries that now, so no note repeats it.
        assert!(!status.notes.iter().any(|n| n.text.contains("expiry")));

        let json = serde_json::to_string(&status).unwrap();
        assert!(!json.contains("hf_fakefixturetokenvalue"), "{json}");
    }

    #[test]
    fn test_named_tokens_expose_expiry_but_not_which_is_active() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = hf_dir(tmp.path());
        fs::write(dir.join("token"), "hf_fakefixtureactive").unwrap();
        fs::write(
            dir.join("stored_tokens"),
            "[work]\nhf_token = hf_fakefixturework\n\n\
             [oauth-dev]\nhf_token = hf_fakefixtureoauth\nrefresh_token = fake-fixture-refresh\nexpires_at = 1785000000\n",
        )
        .unwrap();

        let status = HuggingfaceProbe::new(Paths::for_test(tmp.path()))
            .status()
            .unwrap();
        let ids: Vec<_> = status.profiles.iter().map(|p| p.id.as_str()).collect();
        assert_eq!(ids, vec!["work", "oauth-dev"]);
        // A named access token never expires; the dated OAuth one does.
        assert_eq!(status.profiles[0].expiry, Expiry::NoExpiry);
        assert_eq!(
            status.profiles[1].expires_at().unwrap().to_rfc3339(),
            "2026-07-25T17:20:00+00:00"
        );
        assert_eq!(status.profiles[1].meta["auth"], "oauth (browser login)");
        // Not guessed.
        assert!(status.active.is_none());
        let unknowable = status
            .notes
            .iter()
            .find(|n| n.text.contains("cannot be told from disk"))
            .expect("the unknowable active token is explained");
        assert_eq!(unknowable.kind, NoteKind::Info);

        let json = serde_json::to_string(&status).unwrap();
        for secret in [
            "hf_fakefixtureactive",
            "hf_fakefixturework",
            "hf_fakefixtureoauth",
            "fake-fixture-refresh",
        ] {
            assert!(!json.contains(secret), "leaked {secret}");
        }
    }

    #[test]
    fn test_an_undated_oauth_login_is_unknown_rather_than_endless() {
        // A browser login *does* expire; a section that lost its expires_at is
        // the one case where huggingface owes an Unknown, not a NoExpiry.
        let tmp = tempfile::tempdir().unwrap();
        let dir = hf_dir(tmp.path());
        fs::write(dir.join("token"), "hf_fixture").unwrap();
        fs::write(
            dir.join("stored_tokens"),
            "[oauth-dev]\nhf_token = hf_fixture\nrefresh_token = fake-fixture-refresh\n",
        )
        .unwrap();
        let status = HuggingfaceProbe::new(Paths::for_test(tmp.path()))
            .status()
            .unwrap();
        assert_eq!(
            status.profiles[0].expiry,
            Expiry::unknown("not recorded in stored_tokens")
        );
        assert_eq!(status.profiles[0].expires_at(), None);
    }

    #[test]
    fn test_named_tokens_without_an_active_file_are_called_out() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = hf_dir(tmp.path());
        fs::write(dir.join("stored_tokens"), "[work]\nhf_token = hf_fixture\n").unwrap();
        let status = HuggingfaceProbe::new(Paths::for_test(tmp.path()))
            .status()
            .unwrap();
        assert_eq!(status.profiles.len(), 1);
        // Tokens on disk, none selected: hf calls go out unauthenticated.
        let stranded = status
            .notes
            .iter()
            .find(|n| n.text.contains("not authenticated"))
            .expect("the stranded state is reported");
        assert_eq!(stranded.kind, NoteKind::Problem);
    }

    #[test]
    fn test_hf_home_override_and_environment_token() {
        let tmp = tempfile::tempdir().unwrap();
        let elsewhere = tmp.path().join("hf-home");
        fs::create_dir_all(&elsewhere).unwrap();
        fs::write(elsewhere.join("token"), "hf_fixture").unwrap();
        let paths = Paths::for_test(tmp.path())
            .with_env("HF_HOME", elsewhere.to_str().unwrap())
            .with_env("HF_TOKEN", "hf_fakefixtureenv");
        let status = HuggingfaceProbe::new(paths).status().unwrap();
        assert_eq!(status.profiles.len(), 1);
        assert!(status.notes.iter().any(|n| n.text.contains("$HF_HOME=")));
        let env = status
            .notes
            .iter()
            .find(|n| n.text.contains("set in the environment"))
            .expect("the env token is called out");
        assert_eq!(env.kind, NoteKind::Warn);
        let json = serde_json::to_string(&status).unwrap();
        assert!(!json.contains("hf_fakefixtureenv"), "{json}");
    }

    // ---------------------------------------------------------------- verify

    fn probe_with(
        home: &std::path::Path,
        exec: std::sync::Arc<crate::util::FakeExec>,
    ) -> HuggingfaceProbe {
        HuggingfaceProbe::new(Paths::for_test(home).with_exec(exec))
    }

    #[test]
    fn test_verify_pins_the_output_format_and_reports_user_and_orgs() {
        let tmp = tempfile::tempdir().unwrap();
        let exec = std::sync::Arc::new(crate::util::FakeExec::new().on(
            "whoami",
            true,
            r#"{"user": "pathors", "orgs": "pathors-ai,cerana", "endpoint": null}"#,
            "",
        ));
        let outcome = probe_with(tmp.path(), exec.clone()).verify().unwrap();
        // `--format auto` sniffs the environment for an AI-agent harness and
        // changes shape; patchbay is often started from one, so the format is
        // pinned rather than detected.
        assert_eq!(exec.last().unwrap().line(), "hf auth whoami --format json");
        match outcome {
            VerifyOutcome::Valid { detail, .. } => {
                assert!(detail.contains("pathors"), "{detail}");
                // `orgs` arrives as one comma-joined string, not a list.
                assert!(detail.contains("pathors-ai, cerana"), "{detail}");
            }
            other => panic!("expected Valid, got {other:?}"),
        }
    }

    #[test]
    fn test_the_legacy_text_shape_still_parses() {
        let tmp = tempfile::tempdir().unwrap();
        let exec = std::sync::Arc::new(crate::util::FakeExec::new().on(
            "whoami",
            true,
            "pathors\norgs:  pathors-ai,cerana\n",
            "",
        ));
        match probe_with(tmp.path(), exec).verify().unwrap() {
            VerifyOutcome::Valid { detail, .. } => {
                assert!(detail.contains("pathors-ai, cerana"), "{detail}")
            }
            other => panic!("expected Valid, got {other:?}"),
        }
    }

    #[test]
    fn test_no_token_and_a_bad_token_both_exit_one_and_are_told_apart() {
        // Both are exit 1 with an `Error: …` on stderr, so only the text
        // separates "you never logged in" from "your token was rejected".
        let tmp = tempfile::tempdir().unwrap();
        let exec = std::sync::Arc::new(crate::util::FakeExec::new().on(
            "whoami",
            false,
            "",
            "Error: Not logged in\n",
        ));
        match probe_with(tmp.path(), exec).verify().unwrap() {
            VerifyOutcome::Invalid { detail, .. } => {
                assert!(detail.contains("not logged in"), "{detail}");
                assert!(detail.contains("hf auth login"), "{detail}");
            }
            other => panic!("expected Invalid, got {other:?}"),
        }

        let exec = std::sync::Arc::new(crate::util::FakeExec::new().on(
            "whoami",
            false,
            "",
            "Error: Invalid user token. The token stored is invalid. Please run `hf auth login --force` to set a new token.\n",
        ));
        match probe_with(tmp.path(), exec).verify().unwrap() {
            VerifyOutcome::Invalid { detail, .. } => {
                assert!(detail.contains("rejected"), "{detail}");
                assert_eq!(detail.lines().count(), 1, "{detail}");
            }
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    #[test]
    fn test_not_logged_in_on_a_zero_exit_is_still_not_logged_in() {
        // Older hub releases printed this and exited **0**.
        let tmp = tempfile::tempdir().unwrap();
        let exec = std::sync::Arc::new(crate::util::FakeExec::new().on(
            "whoami",
            true,
            "Not logged in\n",
            "",
        ));
        match probe_with(tmp.path(), exec).verify().unwrap() {
            VerifyOutcome::Invalid { detail, .. } => {
                assert!(detail.contains("hf auth login"), "{detail}");
            }
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    #[test]
    fn test_a_revoked_token_and_an_outage_are_told_apart() {
        let tmp = tempfile::tempdir().unwrap();
        let revoked = std::sync::Arc::new(crate::util::FakeExec::new().on(
            "whoami",
            false,
            "401 Client Error: Unauthorized for url: https://huggingface.co/api/whoami-v2\n{\"error\":\"Invalid credentials in Authorization header\"}\n",
            "",
        ));
        match probe_with(tmp.path(), revoked).verify().unwrap() {
            VerifyOutcome::Invalid { detail, .. } => {
                assert!(detail.contains("hf auth login"), "{detail}");
                assert_eq!(detail.lines().count(), 1, "{detail}");
            }
            other => panic!("expected Invalid, got {other:?}"),
        }

        let offline = std::sync::Arc::new(crate::util::FakeExec::new().on(
            "whoami",
            false,
            "",
            "requests.exceptions.ConnectionError: HTTPSConnectionPool(host='huggingface.co', port=443): Max retries exceeded\n",
        ));
        match probe_with(tmp.path(), offline).verify().unwrap() {
            VerifyOutcome::Unsupported { reason, .. } => {
                assert!(reason.contains("could not reach"), "{reason}");
            }
            other => panic!("expected Unsupported, got {other:?}"),
        }
    }

    #[test]
    fn test_unreadable_output_degrades_instead_of_panicking() {
        let tmp = tempfile::tempdir().unwrap();
        for junk in ["", "\n\n\n", "\u{1b}[1m\u{1b}[0m"] {
            let exec =
                std::sync::Arc::new(crate::util::FakeExec::new().on("whoami", true, junk, ""));
            match probe_with(tmp.path(), exec).verify().unwrap() {
                VerifyOutcome::Valid { detail, .. } => {
                    assert!(detail.contains("named no user"), "{junk:?} -> {detail}");
                }
                other => panic!("expected Valid for {junk:?}, got {other:?}"),
            }
        }
    }

    #[test]
    fn test_the_legacy_binary_uses_the_verb_it_understands() {
        // `hf auth whoami` did not exist before huggingface_hub 1.0.
        assert_eq!(
            HuggingfaceProbe::parse_whoami("pathors\n").map(|(u, _)| u),
            Some("pathors".to_string())
        );
        assert_eq!(strip_ansi("\u{1b}[1morgs: \u{1b}[0m a"), "orgs:  a");
    }

    #[test]
    fn test_verify_without_the_binary_stays_unsupported() {
        let tmp = tempfile::tempdir().unwrap();
        match HuggingfaceProbe::new(Paths::for_test(tmp.path()))
            .verify()
            .unwrap()
        {
            VerifyOutcome::Unsupported { reason, hint, .. } => {
                assert!(reason.contains("not available on PATH"), "{reason}");
                assert_eq!(hint.as_deref(), Some("hf auth whoami"));
            }
            other => panic!("expected Unsupported, got {other:?}"),
        }
    }

    #[test]
    fn test_absent_and_empty_cache() {
        let tmp = tempfile::tempdir().unwrap();
        let status = HuggingfaceProbe::new(Paths::for_test(tmp.path()))
            .status()
            .unwrap();
        assert!(!status.installed);
        assert!(status.profiles.is_empty());
        assert!(status.notes.is_empty());

        let tmp = tempfile::tempdir().unwrap();
        hf_dir(tmp.path());
        let status = HuggingfaceProbe::new(Paths::for_test(tmp.path()))
            .status()
            .unwrap();
        assert!(status.installed);
        assert!(status.profiles.is_empty());
    }
}
