//! `neon` — the Neon Postgres CLI's OAuth grant.
//!
//! **The rename trap.** The binary was renamed `neonctl` -> `neon`, but the
//! config directory kept the old name. Verified empirically with `neon`
//! 2.38.2 on this machine: the binary is `neon` (with `neonctl` still installed
//! as an alias) and the state is `~/.config/neonctl/credentials.json`. The
//! probe therefore looks for either binary and reads the `neonctl` directory.
//!
//! `credentials.json` (shape verified empirically) holds
//! `{ access_token, refresh_token, id_token, scope, token_type, expires_in,
//! expires_at, user_id }`. `expires_at` is epoch **milliseconds**; the three
//! token fields are never named by the parser at all.
//!
//! That `expires_at` is only the login's expiry when the grant is *not*
//! offline-scoped. With `offline`/`offline_access` in the scope list the CLI
//! refreshes the access token itself on the next command, so the timestamp
//! describes an hour-long token nobody has to think about — reported as an
//! expiry it puts a live login on the board as "expired 12d". Offline-scoped
//! grants therefore carry no expiry, only a note.
//!
//! `NEON_API_KEY` in the environment overrides the file entirely, which is how
//! CI runs the CLI — worth a note, because the file's expiry then describes a
//! credential nothing is using.

use serde::Deserialize;

use crate::paths::Paths;
use crate::probe::{unsupported_switch, unsupported_verify, Probe};
use crate::types::{PermissionsReport, Profile, SwitchOutcome, ToolStatus, VerifyOutcome};
use crate::util::{parse_epoch_millis, read_text};

pub struct NeonProbe {
    paths: Paths,
}

/// `access_token` / `refresh_token` / `id_token` are deliberately not fields.
#[derive(Deserialize)]
struct Credentials {
    #[serde(default)]
    expires_at: Option<i64>,
    #[serde(default)]
    scope: Option<String>,
    #[serde(default)]
    user_id: Option<String>,
    #[serde(default)]
    token_type: Option<String>,
}

impl NeonProbe {
    pub const TOOL: &'static str = "neon";
    const PROFILE_ID: &'static str = "default";

    pub fn new(paths: Paths) -> Self {
        Self { paths }
    }

    /// Neon writes the scope list as one space-separated string.
    fn scopes(raw: Option<&str>) -> Vec<String> {
        raw.map(|s| s.split_whitespace().map(str::to_string).collect())
            .unwrap_or_default()
    }
}

impl Probe for NeonProbe {
    fn tool(&self) -> &'static str {
        Self::TOOL
    }

    fn status(&self) -> anyhow::Result<ToolStatus> {
        let path = self.paths.neon_dir().join("credentials.json");
        // Both names are current: `neon` is the CLI, `neonctl` the old alias.
        let installed =
            self.paths.has_binary("neon") || self.paths.has_binary("neonctl") || path.is_file();
        let mut status = ToolStatus::empty(Self::TOOL, installed);
        for note in self.paths.path_notes("neon") {
            status.note(note);
        }

        if self.paths.env("NEON_API_KEY").is_some() {
            status.note(
                "NEON_API_KEY is set in the environment and overrides the stored login; the CLI \
                 will use that key regardless of what is on disk"
                    .to_string(),
            );
        }

        let text = match read_text(&path) {
            Ok(Some(text)) => text,
            Ok(None) => return Ok(status),
            Err(e) => {
                status.note(e);
                return Ok(status);
            }
        };

        let credentials: Credentials = match serde_json::from_str(&text) {
            Ok(credentials) => credentials,
            Err(e) => {
                status.note(format!("credentials.json is not valid JSON ({e})"));
                return Ok(status);
            }
        };

        let expires_at = credentials.expires_at.and_then(parse_epoch_millis);
        if credentials.expires_at.is_some() && expires_at.is_none() {
            status.note("expires_at is present but is not a usable timestamp".to_string());
        }

        let scopes = Self::scopes(credentials.scope.as_deref());
        let refreshable = scopes.iter().any(|s| s.starts_with("offline"));

        status.profiles.push(
            Profile::new(Self::PROFILE_ID)
                .label(match &credentials.user_id {
                    Some(id) => format!("neon user {id}"),
                    None => "neon oauth login".to_string(),
                })
                // Only a grant that cannot refresh itself has an expiry worth
                // showing; see the module header.
                .expires_at(expires_at.filter(|_| !refreshable))
                .with_meta("user_id", credentials.user_id.clone())
                .with_meta("token_type", credentials.token_type.clone())
                .with_meta("scopes", scopes)
                .with_meta("refreshable", refreshable)
                .with_meta("source", path.display().to_string()),
        );
        status.active = Some(Self::PROFILE_ID.to_string());

        status.note(
            "the config directory is still `neonctl` even though the binary is now `neon`"
                .to_string(),
        );
        if refreshable {
            status.note(
                "the grant is offline-scoped, so the CLI refreshes the access token itself; the \
                 only timestamp in credentials.json dates that hourly token, not the login, and \
                 nothing here says when the grant behind it stops working"
                    .to_string(),
            );
        }

        Ok(status)
    }

    fn switch(&self, _profile_id: &str) -> anyhow::Result<SwitchOutcome> {
        Ok(unsupported_switch(
            Self::TOOL,
            "neon holds a single OAuth grant with no profile concept; re-authenticate to change \
             accounts",
            Some("neon auth"),
        ))
    }

    fn verify(&self) -> anyhow::Result<VerifyOutcome> {
        Ok(unsupported_verify(
            Self::TOOL,
            "patchbay does not run neon yet; `neon me` is a network call and the local expiry is \
             usually enough",
            Some("neon me"),
        ))
    }

    fn permissions(&self) -> anyhow::Result<PermissionsReport> {
        let status = self.status()?;
        let Some(profile) = status.profiles.first() else {
            return Ok(PermissionsReport::unsupported(
                Self::TOOL,
                "neon is not logged in",
                Some("neon auth"),
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
            subject: profile
                .meta
                .get("user_id")
                .and_then(|v| v.as_str())
                .map(str::to_string),
            scopes,
            notes: vec![
                "scopes come from the local OAuth grant; membership of each Neon organisation \
                 decides what those scopes can actually reach"
                    .to_string(),
            ],
            hint: Some("neon auth".to_string()),
            scope: None,
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
        fs::create_dir_all(home.join(".config/neonctl")).unwrap();
        fs::write(home.join(".config/neonctl/credentials.json"), body).unwrap();
        (dir, home)
    }

    // Key set copied from a real credentials.json; values are invented.
    fn credentials(expires_at: i64) -> String {
        format!(
            r#"{{
              "access_token": "fake-fixture-access",
              "expires_in": 3600,
              "id_token": "fake-fixture-id",
              "refresh_token": "fake-fixture-refresh",
              "scope": "openid offline offline_access urn:neoncloud:projects:read",
              "token_type": "bearer",
              "expires_at": {expires_at},
              "user_id": "0a1b2c3d-0000-4444-8888-abcdefabcdef"
            }}"#
        )
    }

    /// The same credentials without the two offline scopes: an access token
    /// that really is the whole login.
    fn credentials_without_offline(expires_at: i64) -> String {
        credentials(expires_at).replace("openid offline offline_access ", "openid ")
    }

    #[test]
    fn test_grant_scopes_and_no_expiry_for_a_grant_that_refreshes_itself() {
        let (_dir, home) = fixture(&credentials(1785611828464));
        let status = NeonProbe::new(Paths::for_test(&home)).status().unwrap();
        assert_eq!(status.active.as_deref(), Some("default"));
        let profile = &status.profiles[0];
        assert!(profile.expires_at.is_none());
        assert_eq!(profile.meta["scopes"][0], "openid");
        assert_eq!(profile.meta["refreshable"], true);
        assert_eq!(profile.meta["token_type"], "bearer");
        assert!(status.notes.iter().any(|n| n.contains("still `neonctl`")));

        let json = serde_json::to_string(&status).unwrap();
        for secret in [
            "fake-fixture-access",
            "fake-fixture-id",
            "fake-fixture-refresh",
        ] {
            assert!(!json.contains(secret), "leaked {secret}");
        }
    }

    #[test]
    fn test_a_long_stale_offline_grant_is_not_a_dead_login() {
        // 2021-01-01 in milliseconds — an hourly token five years past, which
        // read as the login's expiry parked neon permanently in the board's
        // expired tally.
        let (_dir, home) = fixture(&credentials(1609459200000));
        let status = NeonProbe::new(Paths::for_test(&home)).status().unwrap();
        assert!(status.profiles[0].expires_at.is_none());
        assert_eq!(
            status.connection_state(),
            crate::types::ConnectionState::Connected
        );
        assert!(status
            .notes
            .iter()
            .any(|n| n.contains("refreshes the access token itself")));
    }

    #[test]
    fn test_a_grant_that_cannot_refresh_keeps_its_expiry() {
        // No offline scope: when this hour is up the login really is over, so
        // the timestamp is the answer rather than noise.
        let (_dir, home) = fixture(&credentials_without_offline(1785611828464));
        let status = NeonProbe::new(Paths::for_test(&home)).status().unwrap();
        assert_eq!(status.profiles[0].meta["refreshable"], false);
        assert_eq!(
            status.profiles[0].expires_at.unwrap().to_rfc3339(),
            "2026-08-01T19:17:08.464+00:00"
        );
    }

    #[test]
    fn test_api_key_in_the_environment_is_flagged() {
        let (_dir, home) = fixture(&credentials(1785611828464));
        let paths = Paths::for_test(&home).with_env("NEON_API_KEY", "fake-fixture-key");
        let status = NeonProbe::new(paths).status().unwrap();
        assert!(status.notes.iter().any(|n| n.contains("NEON_API_KEY")));
        let json = serde_json::to_string(&status).unwrap();
        assert!(!json.contains("fake-fixture-key"), "{json}");
    }

    #[test]
    fn test_missing_and_malformed() {
        let dir = tempfile::tempdir().unwrap();
        let status = NeonProbe::new(Paths::for_test(dir.path()))
            .status()
            .unwrap();
        assert!(!status.installed);
        assert!(status.profiles.is_empty());
        assert!(status.notes.is_empty());

        let (_dir, home) = fixture("{\"expires_at\":");
        let status = NeonProbe::new(Paths::for_test(&home)).status().unwrap();
        assert!(status.installed);
        assert!(status.profiles.is_empty());
        assert!(status.notes.iter().any(|n| n.contains("not valid JSON")));
    }

    #[test]
    fn test_credentials_without_an_expiry_degrade_to_unknown() {
        let (_dir, home) = fixture(r#"{ "access_token": "fake", "scope": "openid" }"#);
        let status = NeonProbe::new(Paths::for_test(&home)).status().unwrap();
        assert_eq!(status.profiles.len(), 1);
        assert!(status.profiles[0].expires_at.is_none());
        assert_eq!(status.profiles[0].meta["refreshable"], false);
    }
}
