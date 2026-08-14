//! `rclone` — remotes defined in `rclone.conf`.
//!
//! Each INI section is a remote. OAuth remotes store a `token` value that is a
//! JSON blob; patchbay parses it *only* to pull out `expiry`, and copies
//! nothing else out of it. Config keys are allow-listed before being placed in
//! `meta`, because rclone configs also hold `client_secret`, `pass`, `key` and
//! friends.
//!
//! rclone has no "active remote": every command names its remote explicitly.
//! `active` is therefore always `None` and switching is unsupported by design.

use crate::paths::Paths;
use crate::probe::{unsupported_switch, unsupported_verify, Probe};
use crate::types::{PermissionsReport, Profile, SwitchOutcome, ToolStatus, VerifyOutcome};
use crate::util::{parse_timestamp, read_text, Ini};

pub struct RcloneProbe {
    paths: Paths,
}

/// What a remote's `token` blob says, with nothing of the token in it.
struct TokenState {
    expiry: Option<chrono::DateTime<chrono::Utc>>,
    refreshable: bool,
}

/// Config keys that are safe to surface. Anything not listed here is dropped,
/// which is the right default for a file full of credentials.
const SAFE_KEYS: &[&str] = &[
    "type",
    "remote",
    "provider",
    "region",
    "team_drive",
    "root_folder_id",
    "scope",
    "user",
];

impl RcloneProbe {
    pub const TOOL: &'static str = "rclone";

    pub fn new(paths: Paths) -> Self {
        Self { paths }
    }

    /// Read an rclone OAuth token blob: when it expires, and whether rclone can
    /// renew it without you. `None` for a malformed blob; no part of the token
    /// is ever returned in any form — `refresh_token` is reduced to a bool at
    /// the point it is read.
    ///
    /// The distinction matters because rclone refreshes an access token itself
    /// on the next command and writes the new one back to `rclone.conf`. For a
    /// remote with a refresh token that hourly `expiry` is not the login's, and
    /// showing it as one marks working remotes expired for as long as you
    /// happen not to have used them.
    fn token_state(raw: &str) -> Option<TokenState> {
        let json: serde_json::Value = serde_json::from_str(raw).ok()?;
        Some(TokenState {
            expiry: json
                .get("expiry")
                .and_then(|v| v.as_str())
                .and_then(parse_timestamp),
            refreshable: json
                .get("refresh_token")
                .and_then(|v| v.as_str())
                .is_some_and(|s| !s.is_empty()),
        })
    }
}

impl RcloneProbe {
    /// `used / total` from `rclone about --json`, when the backend reports it.
    fn quota(stdout: &str) -> Option<String> {
        #[derive(serde::Deserialize)]
        struct About {
            #[serde(default)]
            total: Option<i64>,
            #[serde(default)]
            used: Option<i64>,
            #[serde(default)]
            free: Option<i64>,
        }
        let about: About = serde_json::from_str(stdout).ok()?;
        match (about.used, about.total) {
            (Some(used), Some(total)) if total > 0 => Some(format!(
                "{} of {} used ({}%)",
                human_bytes(used),
                human_bytes(total),
                (used as f64 / total as f64 * 100.0).round() as i64
            )),
            (Some(used), _) => Some(format!("{} used", human_bytes(used))),
            (None, Some(total)) => Some(format!("{} total", human_bytes(total))),
            _ => about.free.map(|free| format!("{} free", human_bytes(free))),
        }
    }

    /// Whether the failure was "this backend has no `about`" rather than "your
    /// credential is bad".
    fn about_unsupported(message: &str) -> bool {
        let lower = message.to_lowercase();
        lower.contains("doesn't support about")
            || lower.contains("does not support about")
            || lower.contains("not supported")
            || lower.contains("unsupported")
    }
}

/// Bytes as something a human reads at a glance.
fn human_bytes(bytes: i64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value.abs() >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

impl Probe for RcloneProbe {
    fn tool(&self) -> &'static str {
        Self::TOOL
    }

    fn status(&self) -> anyhow::Result<ToolStatus> {
        let path = self.paths.rclone_conf();
        let installed = self.paths.has_binary("rclone") || path.is_file();
        let mut status = ToolStatus::empty(Self::TOOL, installed);
        for note in self.paths.path_notes("rclone") {
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

        let ini = Ini::parse(&text);
        if ini.sections.is_empty() && !text.trim().is_empty() {
            status.note("rclone.conf has no readable remote sections".to_string());
        }

        let mut unparsed_tokens = Vec::new();
        let mut refreshable_remotes = 0usize;
        for section in &ini.sections {
            let mut profile = Profile::new(&section.name);

            if let Some(raw) = section.get("token") {
                match Self::token_state(raw) {
                    Some(state) => {
                        profile = profile
                            .expires_at(state.expiry.filter(|_| !state.refreshable))
                            .with_meta("refreshable", state.refreshable);
                        refreshable_remotes += usize::from(state.refreshable);
                    }
                    None => unparsed_tokens.push(section.name.clone()),
                }
                profile = profile.with_meta("auth", "oauth token");
            } else if section.get("service_account_file").is_some() {
                profile = profile.with_meta("auth", "service account file");
            } else if section.get("type").map(|t| t == "alias") == Some(true) {
                profile = profile.with_meta("auth", "inherits from the target remote");
            }

            for key in SAFE_KEYS {
                if let Some(value) = section.get(key).filter(|v| !v.is_empty()) {
                    profile = profile.with_meta(key, value);
                }
            }
            status.profiles.push(profile);
        }

        if !unparsed_tokens.is_empty() {
            status.note(format!(
                "could not read an expiry from the stored token of: {}",
                unparsed_tokens.join(", ")
            ));
        }
        if refreshable_remotes > 0 {
            status.note(format!(
                "{refreshable_remotes} remote(s) carry a refresh token, so rclone renews the access token itself and rewrites rclone.conf; the `expiry` in those blobs dates that access token, not the login, and is not reported as one"
            ));
        }
        if !status.profiles.is_empty() {
            status.note(
                "rclone has no active remote; every command names its remote explicitly"
                    .to_string(),
            );
        }

        Ok(status)
    }

    fn switch(&self, _profile_id: &str) -> anyhow::Result<SwitchOutcome> {
        Ok(unsupported_switch(
            Self::TOOL,
            "rclone has no active remote to switch; the remote is an argument to each command",
            Some("rclone ls <remote>:"),
        ))
    }

    /// Every remote, one line each. rclone has no active remote, so "verify
    /// rclone" can only mean "verify all of them" — which patchbay does, rather
    /// than asking the user which one they meant.
    fn verify(&self) -> anyhow::Result<VerifyOutcome> {
        if !self.paths.may_exec() || !self.paths.has_binary("rclone") {
            return Ok(unsupported_verify(
                Self::TOOL,
                "the rclone CLI is not available on PATH",
                Some("rclone about <remote>:"),
            ));
        }
        let status = self.status()?;
        if status.profiles.is_empty() {
            return Ok(unsupported_verify(
                Self::TOOL,
                "no remotes are configured",
                Some("rclone config"),
            ));
        }

        let mut lines = Vec::new();
        let mut any_invalid = false;
        for profile in &status.profiles {
            let outcome = self.verify_profile(&profile.id)?;
            let (mark, detail) = match &outcome {
                VerifyOutcome::Valid { detail, .. } => ("ok", detail),
                VerifyOutcome::Invalid { detail, .. } => {
                    any_invalid = true;
                    ("FAILED", detail)
                }
                VerifyOutcome::Unsupported { reason, .. } => ("skipped", reason),
            };
            lines.push(format!("{}: {mark} — {detail}", profile.id));
        }
        let detail = lines.join("; ");
        Ok(if any_invalid {
            VerifyOutcome::Invalid {
                tool: Self::TOOL.to_string(),
                detail,
            }
        } else {
            VerifyOutcome::Valid {
                tool: Self::TOOL.to_string(),
                detail,
            }
        })
    }

    /// One remote, actually checked.
    ///
    /// `rclone about <remote>:` is the cheapest call that proves the stored
    /// credential still works, and on the backends that support it the answer
    /// carries quota — genuinely useful, and free. Backends that do not support
    /// `about` (an alias to a subfolder, an S3 bucket) fall back to a shallow
    /// `lsd`, which proves reachability without listing anything deep.
    fn verify_profile(&self, profile_id: &str) -> anyhow::Result<VerifyOutcome> {
        if !self.paths.may_exec() || !self.paths.has_binary("rclone") {
            return Ok(unsupported_verify(
                Self::TOOL,
                "the rclone CLI is not available on PATH",
                Some(&format!("rclone about {profile_id}:")),
            ));
        }

        let status = self.status()?;
        let Some(profile) = status.profiles.iter().find(|p| p.id == profile_id) else {
            return Ok(unsupported_verify(
                Self::TOOL,
                &format!(
                    "no remote called `{profile_id}`; configured remotes: {}",
                    status
                        .profiles
                        .iter()
                        .map(|p| p.id.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
                Some("rclone config"),
            ));
        };

        // An alias forwards to another remote, so a check of it is really a
        // check of the target. Say so, rather than reporting a pass whose
        // meaning is one indirection away.
        let via = profile
            .meta
            .get("remote")
            .and_then(|v| v.as_str())
            .map(|target| format!(" (alias → {target})"))
            .unwrap_or_default();

        let remote = format!("{profile_id}:");
        let out = self.paths.run("rclone", &["about", &remote, "--json"])?;
        if out.ok {
            let detail = match Self::quota(&out.stdout) {
                Some(quota) => format!("reachable{via}; {quota}"),
                None => format!("reachable{via}"),
            };
            return Ok(VerifyOutcome::Valid {
                tool: Self::TOOL.to_string(),
                detail,
            });
        }

        // `about` is optional in rclone's backend interface. A backend that
        // does not implement it is not a broken credential, so fall back to
        // something every backend can do.
        let message = out.message();
        if Self::about_unsupported(&message) {
            let out = self
                .paths
                .run("rclone", &["lsd", &remote, "--max-depth", "1"])?;
            return Ok(if out.ok {
                VerifyOutcome::Valid {
                    tool: Self::TOOL.to_string(),
                    detail: format!(
                        "reachable{via}; this backend does not report quota, so patchbay listed \
                         the top level instead"
                    ),
                }
            } else {
                VerifyOutcome::Invalid {
                    tool: Self::TOOL.to_string(),
                    detail: format!("{}{via}", out.message()),
                }
            });
        }

        Ok(VerifyOutcome::Invalid {
            tool: Self::TOOL.to_string(),
            detail: format!("{message}{via}"),
        })
    }

    fn permissions(&self) -> anyhow::Result<PermissionsReport> {
        Ok(PermissionsReport::unsupported(
            Self::TOOL,
            "permissions belong to the remote's provider, not to rclone",
            Some("rclone config show <remote>"),
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
        fs::create_dir_all(home.join(".config/rclone")).unwrap();
        fs::write(home.join(".config/rclone/rclone.conf"), body).unwrap();
        (dir, home)
    }

    // Token blobs below are invented; the shape matches rclone, the values do not.
    const CONF: &str = r#"
[work]
type = drive
token = {"access_token":"fake-fixture-access","refresh_token":"fake-fixture-refresh","expiry":"2030-05-01T12:00:00.123456789+08:00"}
team_drive =
root_folder_id = abc123

[archive]
type = s3
provider = AWS
region = ap-northeast-1
access_key_id = AKIAFAKEFIXTURE
secret_access_key = fake-fixture-secret

[legal]
type = alias
remote = work:Legal
"#;

    #[test]
    fn test_a_remote_with_no_refresh_token_keeps_its_expiry() {
        // Some backends hand out an access token and nothing to renew it with;
        // there the timestamp really is when the remote stops working.
        let (_dir, home) = fixture(
            "[box]\ntype = box\ntoken = {\"access_token\":\"fake-fixture-access\",\"expiry\":\"2030-05-01T12:00:00.123456789+08:00\"}\n",
        );
        let status = RcloneProbe::new(Paths::for_test(&home)).status().unwrap();
        assert_eq!(status.profiles[0].meta["refreshable"], false);
        assert_eq!(
            status.profiles[0].expires_at.unwrap().to_rfc3339(),
            "2030-05-01T04:00:00.123456789+00:00"
        );
    }

    #[test]
    fn test_remotes_expiry_and_allow_listed_meta() {
        let (_dir, home) = fixture(CONF);
        let status = RcloneProbe::new(Paths::for_test(&home)).status().unwrap();
        let ids: Vec<_> = status.profiles.iter().map(|p| p.id.as_str()).collect();
        assert_eq!(ids, vec!["work", "archive", "legal"]);
        assert!(status.active.is_none());

        let work = &status.profiles[0];
        assert_eq!(work.meta["type"], "drive");
        assert_eq!(work.meta["auth"], "oauth token");
        assert_eq!(work.meta["root_folder_id"], "abc123");
        // Empty values are not carried through as noise.
        assert!(work.meta.get("team_drive").is_none());
        // A refresh token beside the expiry: rclone renews it and rewrites the
        // config, so that timestamp is the access token's, not the login's.
        assert_eq!(work.meta["refreshable"], true);
        assert!(work.expires_at.is_none());
        assert!(status
            .notes
            .iter()
            .any(|n| n.contains("renews the access token itself")));

        let legal = &status.profiles[2];
        assert_eq!(legal.meta["remote"], "work:Legal");
        assert_eq!(legal.meta["auth"], "inherits from the target remote");
        assert!(legal.expires_at.is_none());
    }

    #[test]
    fn test_no_credential_material_reaches_the_output() {
        let (_dir, home) = fixture(CONF);
        let status = RcloneProbe::new(Paths::for_test(&home)).status().unwrap();
        let json = serde_json::to_string(&status).unwrap();
        for secret in [
            "fake-fixture-access",
            "fake-fixture-refresh",
            "AKIAFAKEFIXTURE",
            "fake-fixture-secret",
        ] {
            assert!(!json.contains(secret), "leaked {secret} in {json}");
        }
        assert!(!json.contains("access_key_id"), "{json}");
    }

    #[test]
    fn test_unparseable_token_degrades_to_unknown_expiry_with_a_note() {
        let (_dir, home) = fixture("[broken]\ntype = drive\ntoken = not-json-at-all\n");
        let status = RcloneProbe::new(Paths::for_test(&home)).status().unwrap();
        assert_eq!(status.profiles.len(), 1);
        assert!(status.profiles[0].expires_at.is_none());
        assert!(status
            .notes
            .iter()
            .any(|n| n.contains("could not read an expiry")));
    }

    #[test]
    fn test_missing_and_empty() {
        let dir = tempfile::tempdir().unwrap();
        let status = RcloneProbe::new(Paths::for_test(dir.path()))
            .status()
            .unwrap();
        assert!(!status.installed);
        assert!(status.profiles.is_empty());
        assert!(status.notes.is_empty());

        let (_dir, home) = fixture("garbage with no sections\n");
        let status = RcloneProbe::new(Paths::for_test(&home)).status().unwrap();
        assert!(status.profiles.is_empty());
        assert!(status
            .notes
            .iter()
            .any(|n| n.contains("no readable remote sections")));
    }

    // --- verification, through the scripted exec seam ----------------------

    use crate::util::FakeExec;
    use std::sync::Arc;

    /// A fixture home plus a scripted rclone. No subprocess, no network.
    fn with_exec(conf: &str, exec: FakeExec) -> (tempfile::TempDir, RcloneProbe, Arc<FakeExec>) {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().to_path_buf();
        fs::create_dir_all(home.join(".config/rclone")).unwrap();
        fs::write(home.join(".config/rclone/rclone.conf"), conf).unwrap();
        let exec = Arc::new(exec);
        let paths = Paths::for_test(&home).with_exec(exec.clone());
        (dir, RcloneProbe::new(paths), exec)
    }

    const REMOTES: &str = "[pathors]\ntype = drive\ntoken = {\"expiry\":\"2030-01-01T00:00:00Z\"}\n\n[legal]\ntype = alias\nremote = pathors:法務 Legal\n";

    #[test]
    fn test_verify_profile_runs_about_and_reports_quota() {
        let (_dir, probe, exec) = with_exec(
            REMOTES,
            FakeExec::new().on(
                "about pathors:",
                true,
                r#"{"total":161061273600,"used":6979321856,"free":154081951744}"#,
                "",
            ),
        );

        match probe.verify_profile("pathors").unwrap() {
            VerifyOutcome::Valid { detail, .. } => {
                assert!(detail.contains("reachable"), "{detail}");
                assert!(
                    detail.contains("6.5 GiB of 150.0 GiB used (4%)"),
                    "{detail}"
                );
            }
            other => panic!("expected Valid, got {other:?}"),
        }
        // It really ran the command, rather than describing one.
        assert_eq!(exec.last().unwrap().line(), "rclone about pathors: --json");
    }

    #[test]
    fn test_verify_profile_resolves_an_alias_and_says_so() {
        let (_dir, probe, _exec) = with_exec(
            REMOTES,
            FakeExec::new().on("about legal:", true, r#"{"total":100,"used":25}"#, ""),
        );
        match probe.verify_profile("legal").unwrap() {
            VerifyOutcome::Valid { detail, .. } => {
                assert!(
                    detail.contains("alias → pathors:法務 Legal"),
                    "the target the check really went through is missing: {detail}"
                );
            }
            other => panic!("expected Valid, got {other:?}"),
        }
    }

    #[test]
    fn test_a_backend_without_about_falls_back_to_a_shallow_listing() {
        let (_dir, probe, exec) = with_exec(
            REMOTES,
            FakeExec::new()
                .on("about", false, "", "Error: doesn't support about")
                .on(
                    "lsd",
                    true,
                    "          -1 2026-01-01 00:00:00        -1 folder\n",
                    "",
                ),
        );

        match probe.verify_profile("pathors").unwrap() {
            VerifyOutcome::Valid { detail, .. } => {
                assert!(detail.contains("does not report quota"), "{detail}");
            }
            other => panic!("expected Valid, got {other:?}"),
        }
        let lines: Vec<String> = exec.calls().iter().map(|c| c.line()).collect();
        assert_eq!(
            lines,
            vec![
                "rclone about pathors: --json",
                "rclone lsd pathors: --max-depth 1"
            ]
        );
    }

    #[test]
    fn test_a_real_failure_is_invalid_and_keeps_rclones_own_message() {
        let (_dir, probe, _exec) = with_exec(
            REMOTES,
            FakeExec::new().on(
                "about",
                false,
                "",
                "Failed to about: couldn't fetch token: oauth2: cannot fetch token: 400 Bad Request",
            ),
        );
        match probe.verify_profile("pathors").unwrap() {
            VerifyOutcome::Invalid { detail, .. } => {
                assert!(detail.contains("couldn't fetch token"), "{detail}");
            }
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    #[test]
    fn test_an_unknown_remote_lists_the_ones_that_exist() {
        let (_dir, probe, exec) = with_exec(REMOTES, FakeExec::new());
        match probe.verify_profile("nope").unwrap() {
            VerifyOutcome::Unsupported { reason, .. } => {
                assert!(reason.contains("no remote called `nope`"), "{reason}");
                assert!(reason.contains("pathors"), "{reason}");
                assert!(reason.contains("legal"), "{reason}");
            }
            other => panic!("expected Unsupported, got {other:?}"),
        }
        assert!(exec.calls().is_empty(), "an unknown remote must not exec");
    }

    #[test]
    fn test_tool_level_verify_checks_every_remote_instead_of_refusing() {
        // The old behaviour was `unsupported` plus a command to paste. Now the
        // answer is the answer.
        let (_dir, probe, exec) = with_exec(
            REMOTES,
            FakeExec::new()
                .on("about pathors:", true, r#"{"total":100,"used":50}"#, "")
                .on("about legal:", false, "", "directory not found"),
        );

        match probe.verify().unwrap() {
            VerifyOutcome::Invalid { detail, .. } => {
                assert!(detail.contains("pathors: ok"), "{detail}");
                assert!(detail.contains("legal: FAILED"), "{detail}");
            }
            other => panic!("expected Invalid, got {other:?}"),
        }
        assert_eq!(exec.calls().len(), 2, "one check per remote");
    }

    #[test]
    fn test_human_bytes_reads_like_a_human_wrote_it() {
        assert_eq!(human_bytes(512), "512 B");
        assert_eq!(human_bytes(1536), "1.5 KiB");
        assert_eq!(human_bytes(6979321856), "6.5 GiB");
        assert_eq!(human_bytes(161061273600), "150.0 GiB");
    }
}
