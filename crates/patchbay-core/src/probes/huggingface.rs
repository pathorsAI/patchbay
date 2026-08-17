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
        Ok(unsupported_verify(
            Self::TOOL,
            "patchbay does not run the hf CLI yet; `hf auth whoami` is a network call",
            Some("hf auth whoami"),
        ))
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
