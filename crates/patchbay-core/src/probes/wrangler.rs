//! `wrangler` — the Cloudflare OAuth grant on disk.
//!
//! Wrangler keeps one global login at
//! `~/Library/Preferences/.wrangler/config/default.toml`, with the older
//! `~/.wrangler/config/default.toml` still present on machines that predate the
//! move. Presence of the file means "logged in"; `expiration_time` gives a real
//! expiry and `scopes` gives a real permissions list.
//!
//! `oauth_token` and `refresh_token` are typed as [`serde::de::IgnoredAny`]:
//! serde confirms the keys exist and throws the values away, so no Cloudflare
//! token is ever held in memory beyond the parser's stack.

use serde::Deserialize;

use crate::paths::Paths;
use crate::probe::{unsupported_switch, unsupported_verify, Probe};
use crate::types::{PermissionsReport, Profile, SwitchOutcome, ToolStatus, VerifyOutcome};
use crate::util::{parse_timestamp, read_text};

pub struct WranglerProbe {
    paths: Paths,
}

#[derive(Deserialize)]
struct WranglerConfig {
    #[serde(default)]
    oauth_token: Option<serde::de::IgnoredAny>,
    #[serde(default)]
    refresh_token: Option<serde::de::IgnoredAny>,
    #[serde(default)]
    api_token: Option<serde::de::IgnoredAny>,
    #[serde(default)]
    expiration_time: Option<String>,
    #[serde(default)]
    scopes: Vec<String>,
}

impl WranglerProbe {
    pub const TOOL: &'static str = "wrangler";
    /// The single login wrangler supports, named so it has a stable id.
    const PROFILE_ID: &'static str = "default";

    pub fn new(paths: Paths) -> Self {
        Self { paths }
    }
}

impl Probe for WranglerProbe {
    fn tool(&self) -> &'static str {
        Self::TOOL
    }

    fn status(&self) -> anyhow::Result<ToolStatus> {
        let candidates = self.paths.wrangler_candidates();
        let present: Vec<_> = candidates.iter().filter(|p| p.is_file()).collect();
        let installed = self.paths.has_binary("wrangler") || !present.is_empty();
        let mut status = ToolStatus::empty(Self::TOOL, installed);
        for note in self.paths.path_notes("wrangler") {
            status.note(note);
        }

        let Some(path) = present.first().copied() else {
            return Ok(status);
        };
        if present.len() > 1 {
            status.note(format!(
                "two wrangler configs exist; reading {} and ignoring {}",
                path.display(),
                present[1].display()
            ));
        }

        let text = match read_text(path) {
            Ok(Some(text)) => text,
            Ok(None) => return Ok(status),
            Err(e) => {
                status.note(e);
                return Ok(status);
            }
        };

        let config: WranglerConfig = match toml::from_str(&text) {
            Ok(config) => config,
            Err(e) => {
                status.note(format!("{} is not valid TOML ({e})", path.display()));
                return Ok(status);
            }
        };

        if config.oauth_token.is_none() && config.api_token.is_none() {
            status.note(format!(
                "{} exists but holds no token; wrangler is not logged in",
                path.display()
            ));
            return Ok(status);
        }

        let expires_at = config.expiration_time.as_deref().and_then(parse_timestamp);
        if config.expiration_time.is_some() && expires_at.is_none() {
            status.note("expiration_time is present but could not be parsed".to_string());
        }

        status.profiles.push(
            Profile::new(Self::PROFILE_ID)
                .label(if config.api_token.is_some() {
                    "cloudflare api token"
                } else {
                    "cloudflare oauth login"
                })
                .expires_at(expires_at)
                .with_meta(
                    "auth_type",
                    if config.api_token.is_some() {
                        "api_token"
                    } else {
                        "oauth"
                    },
                )
                .with_meta("scopes", config.scopes.clone())
                .with_meta("refreshable", config.refresh_token.is_some())
                .with_meta("source", path.display().to_string()),
        );
        status.active = Some(Self::PROFILE_ID.to_string());

        if let Some(expires_at) = expires_at {
            if expires_at < chrono::Utc::now() && config.refresh_token.is_some() {
                status.note(
                    "the access token has expired, but a refresh token is present: wrangler will renew it silently on the next command".to_string(),
                );
            }
        }

        Ok(status)
    }

    fn switch(&self, _profile_id: &str) -> anyhow::Result<SwitchOutcome> {
        Ok(unsupported_switch(
            Self::TOOL,
            "wrangler holds a single global login with no profile concept; re-authenticate to change accounts",
            Some("wrangler logout && wrangler login"),
        ))
    }

    fn verify(&self) -> anyhow::Result<VerifyOutcome> {
        // `wrangler whoami` is a network call that also happens to be slow to
        // start (node). Left unsupported until it earns its place.
        Ok(unsupported_verify(
            Self::TOOL,
            "patchbay does not run wrangler yet; the local expiry in status is usually enough",
            Some("wrangler whoami"),
        ))
    }

    fn permissions(&self) -> anyhow::Result<PermissionsReport> {
        let status = self.status()?;
        let Some(profile) = status.profiles.first() else {
            return Ok(PermissionsReport::unsupported(
                Self::TOOL,
                "wrangler is not logged in",
                Some("wrangler login"),
            ));
        };
        // Scopes come straight from the local grant — no network needed.
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
                .get("auth_type")
                .and_then(|v| v.as_str())
                .map(str::to_string),
            scopes,
            notes: vec![
                "scopes are read from the local OAuth grant; account-level API token permissions are not visible here".to_string(),
            ],
            hint: Some("re-run `wrangler login` to request a different scope set".to_string()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::Path;

    const NEW_PATH: &str = "Library/Preferences/.wrangler/config/default.toml";
    const OLD_PATH: &str = ".wrangler/config/default.toml";

    fn write(home: &Path, rel: &str, body: &str) {
        let path = home.join(rel);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, body).unwrap();
    }

    // Invented token values: nothing here resembles a real Cloudflare grant.
    fn config(expiry: &str) -> String {
        format!(
            "oauth_token = \"fake-fixture-oauth\"\nexpiration_time = \"{expiry}\"\nrefresh_token = \"fake-fixture-refresh\"\nscopes = [ \"account:read\", \"workers:write\" ]\n"
        )
    }

    #[test]
    fn test_expiry_and_scopes_without_touching_the_token() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().to_path_buf();
        write(&home, NEW_PATH, &config("2030-03-13T10:24:29.685Z"));

        let status = WranglerProbe::new(Paths::for_test(&home)).status().unwrap();
        assert_eq!(status.active.as_deref(), Some("default"));
        assert_eq!(status.profiles.len(), 1);
        let profile = &status.profiles[0];
        assert_eq!(
            profile.expires_at.unwrap().to_rfc3339(),
            "2030-03-13T10:24:29.685+00:00"
        );
        assert_eq!(profile.meta["auth_type"], "oauth");
        assert_eq!(profile.meta["refreshable"], true);
        assert_eq!(profile.meta["scopes"][1], "workers:write");

        let json = serde_json::to_string(&status).unwrap();
        assert!(!json.contains("fake-fixture-oauth"), "{json}");
        assert!(!json.contains("fake-fixture-refresh"), "{json}");
    }

    #[test]
    fn test_new_location_wins_and_the_duplicate_is_reported() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().to_path_buf();
        write(&home, NEW_PATH, &config("2030-01-01T00:00:00Z"));
        write(&home, OLD_PATH, &config("2029-01-01T00:00:00Z"));

        let status = WranglerProbe::new(Paths::for_test(&home)).status().unwrap();
        assert_eq!(
            status.profiles[0].expires_at.unwrap().to_rfc3339(),
            "2030-01-01T00:00:00+00:00"
        );
        assert!(status
            .notes
            .iter()
            .any(|n| n.contains("two wrangler configs")));
    }

    #[test]
    fn test_legacy_location_is_used_when_it_is_the_only_one() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().to_path_buf();
        write(&home, OLD_PATH, &config("2030-01-01T00:00:00Z"));
        let status = WranglerProbe::new(Paths::for_test(&home)).status().unwrap();
        assert_eq!(status.profiles.len(), 1);
        assert!(status.profiles[0].meta["source"]
            .as_str()
            .unwrap()
            .ends_with(OLD_PATH));
    }

    #[test]
    fn test_expired_with_refresh_token_is_explained() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().to_path_buf();
        write(&home, NEW_PATH, &config("2020-01-01T00:00:00Z"));
        let status = WranglerProbe::new(Paths::for_test(&home)).status().unwrap();
        assert!(status.notes.iter().any(|n| n.contains("renew it silently")));
    }

    #[test]
    fn test_missing_and_malformed() {
        let dir = tempfile::tempdir().unwrap();
        let status = WranglerProbe::new(Paths::for_test(dir.path()))
            .status()
            .unwrap();
        assert!(!status.installed);
        assert!(status.profiles.is_empty());

        let home = dir.path().to_path_buf();
        write(&home, NEW_PATH, "this is not = = toml [[[");
        let status = WranglerProbe::new(Paths::for_test(&home)).status().unwrap();
        assert!(status.installed);
        assert!(status.profiles.is_empty());
        assert!(status.notes.iter().any(|n| n.contains("not valid TOML")));
    }

    #[test]
    fn test_tokenless_config_is_not_a_login() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().to_path_buf();
        write(&home, NEW_PATH, "scopes = []\n");
        let status = WranglerProbe::new(Paths::for_test(&home)).status().unwrap();
        assert!(status.profiles.is_empty());
        assert!(status.notes.iter().any(|n| n.contains("not logged in")));
    }

    #[test]
    fn test_permissions_reads_scopes_from_the_local_grant() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().to_path_buf();
        write(&home, NEW_PATH, &config("2030-01-01T00:00:00Z"));
        let report = WranglerProbe::new(Paths::for_test(&home))
            .permissions()
            .unwrap();
        assert!(report.supported);
        assert_eq!(report.scopes, vec!["account:read", "workers:write"]);
    }
}
