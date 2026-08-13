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

    /// Pull `expiry` out of an rclone OAuth token blob. Returns `None` for a
    /// malformed blob; the token itself is never returned in any form.
    fn token_expiry(raw: &str) -> Option<chrono::DateTime<chrono::Utc>> {
        let json: serde_json::Value = serde_json::from_str(raw).ok()?;
        json.get("expiry")
            .and_then(|v| v.as_str())
            .and_then(parse_timestamp)
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
        for section in &ini.sections {
            let mut profile = Profile::new(&section.name);

            if let Some(raw) = section.get("token") {
                match Self::token_expiry(raw) {
                    Some(expiry) => profile = profile.expires_at(Some(expiry)),
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

    fn verify(&self) -> anyhow::Result<VerifyOutcome> {
        Ok(unsupported_verify(
            Self::TOOL,
            "verification needs a specific remote, which this call has no way to name",
            Some("rclone about <remote>:"),
        ))
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
        assert_eq!(
            work.expires_at.unwrap().to_rfc3339(),
            "2030-05-01T04:00:00.123456789+00:00"
        );

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
}
