//! `aws` — shared config/credentials INI plus the SSO token cache.
//!
//! Profiles come from `~/.aws/config` (`[default]` and `[profile NAME]`) and
//! `~/.aws/credentials` (`[NAME]`). Only SSO profiles have a knowable expiry:
//! it lives in `~/.aws/sso/cache/*.json`. Static access keys never expire, so
//! their `expires_at` is `None` — which is not the same as "unknown".
//!
//! The AWS CLI has no persistent "active profile" on disk: it is the
//! `AWS_PROFILE` environment variable, defaulting to `default`. That is why
//! switching is deliberately unsupported — a child process cannot change its
//! parent shell's environment.

use std::collections::BTreeMap;
use std::path::Path;

use chrono::{DateTime, Utc};

use crate::paths::Paths;
use crate::probe::{unsupported_switch, unsupported_verify, Probe};
use crate::types::{PermissionsReport, Profile, SwitchOutcome, ToolStatus, VerifyOutcome};
use crate::util::{parse_timestamp, read_text, Ini};

pub struct AwsProbe {
    paths: Paths,
}

#[derive(Default)]
struct Entry {
    in_config: bool,
    in_credentials: bool,
    region: Option<String>,
    sso_start_url: Option<String>,
    sso_account_id: Option<String>,
    sso_role_name: Option<String>,
    sso_session: Option<String>,
    has_sso: bool,
    has_static_keys: bool,
    role_arn: Option<String>,
}

impl Entry {
    fn kind(&self) -> &'static str {
        if self.has_sso {
            "sso"
        } else if self.role_arn.is_some() {
            "assume-role"
        } else if self.has_static_keys {
            "static-keys"
        } else {
            "unknown"
        }
    }
}

/// One `~/.aws/sso/cache/*.json` entry, reduced to what patchbay may keep.
/// The `accessToken` field in these files is never deserialized.
struct SsoCacheEntry {
    start_url: Option<String>,
    expires_at: DateTime<Utc>,
}

impl AwsProbe {
    pub const TOOL: &'static str = "aws";

    pub fn new(paths: Paths) -> Self {
        Self { paths }
    }

    fn load_ini(path: &Path, notes: &mut Vec<String>) -> Option<Ini> {
        match read_text(path) {
            Ok(Some(text)) => Some(Ini::parse(&text)),
            Ok(None) => None,
            Err(e) => {
                notes.push(e);
                None
            }
        }
    }

    /// SSO token cache, newest first. Files that are not token caches (role
    /// credential caches, junk) are skipped silently.
    fn sso_cache(dir: &Path) -> Vec<SsoCacheEntry> {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return Vec::new();
        };
        let mut out: Vec<SsoCacheEntry> = entries
            .filter_map(Result::ok)
            .filter(|e| e.path().extension().is_some_and(|ext| ext == "json"))
            .filter_map(|e| {
                let text = read_text(&e.path()).ok().flatten()?;
                let json: serde_json::Value = serde_json::from_str(&text).ok()?;
                let expires_at = json
                    .get("expiresAt")
                    .and_then(|v| v.as_str())
                    .and_then(parse_timestamp)?;
                Some(SsoCacheEntry {
                    start_url: json
                        .get("startUrl")
                        .and_then(|v| v.as_str())
                        .map(str::to_string),
                    expires_at,
                })
            })
            .collect();
        out.sort_by_key(|e| std::cmp::Reverse(e.expires_at));
        out
    }
}

impl Probe for AwsProbe {
    fn tool(&self) -> &'static str {
        Self::TOOL
    }

    fn status(&self) -> anyhow::Result<ToolStatus> {
        let config_path = self.paths.aws_config();
        let credentials_path = self.paths.aws_credentials();
        let installed =
            self.paths.has_binary("aws") || config_path.is_file() || credentials_path.is_file();
        let mut status = ToolStatus::empty(Self::TOOL, installed);
        for note in self.paths.path_notes("aws_config") {
            status.note(note);
        }
        for note in self.paths.path_notes("aws_credentials") {
            status.note(note);
        }

        // BTreeMap so the board is stable across runs.
        let mut entries: BTreeMap<String, Entry> = BTreeMap::new();

        if let Some(ini) = Self::load_ini(&config_path, &mut status.notes) {
            for section in &ini.sections {
                // `[default]`, `[profile work]`, and `[sso-session x]` which is
                // not a profile.
                let name = if section.name == "default" {
                    "default".to_string()
                } else if let Some(rest) = section.name.strip_prefix("profile ") {
                    rest.trim().to_string()
                } else {
                    continue;
                };
                let entry = entries.entry(name).or_default();
                entry.in_config = true;
                entry.region = section.get("region").map(str::to_string);
                entry.sso_start_url = section.get("sso_start_url").map(str::to_string);
                entry.sso_account_id = section.get("sso_account_id").map(str::to_string);
                entry.sso_role_name = section.get("sso_role_name").map(str::to_string);
                entry.sso_session = section.get("sso_session").map(str::to_string);
                entry.has_sso = section.has_prefix("sso_");
                entry.role_arn = section.get("role_arn").map(str::to_string);
                entry.has_static_keys |= section.get("aws_access_key_id").is_some();
            }
        }

        if let Some(ini) = Self::load_ini(&credentials_path, &mut status.notes) {
            for section in &ini.sections {
                let entry = entries.entry(section.name.clone()).or_default();
                entry.in_credentials = true;
                // Presence only — key ids and secrets are never stored.
                entry.has_static_keys |= section.get("aws_access_key_id").is_some();
                if entry.region.is_none() {
                    entry.region = section.get("region").map(str::to_string);
                }
            }
        }

        let cache = Self::sso_cache(&self.paths.aws_sso_cache_dir());

        for (name, entry) in entries {
            // Only SSO profiles have a cached session that expires. Match on
            // the start URL when we can, else fall back to the newest token.
            let expires_at = if entry.has_sso {
                let matched = entry.sso_start_url.as_ref().and_then(|url| {
                    cache
                        .iter()
                        .find(|c| c.start_url.as_deref() == Some(url.as_str()))
                });
                matched.or(cache.first()).map(|c| c.expires_at)
            } else {
                None
            };

            let source = match (entry.in_config, entry.in_credentials) {
                (true, true) => "config+credentials",
                (true, false) => "config",
                _ => "credentials",
            };

            status.profiles.push(
                Profile::new(&name)
                    .expires_at(expires_at)
                    .with_meta("type", entry.kind())
                    .with_meta("source", source)
                    .with_meta("region", entry.region.clone())
                    .with_meta("sso_start_url", entry.sso_start_url.clone())
                    .with_meta("sso_session", entry.sso_session.clone())
                    .with_meta("sso_account_id", entry.sso_account_id.clone())
                    .with_meta("sso_role_name", entry.sso_role_name.clone())
                    .with_meta("role_arn", entry.role_arn.clone()),
            );
        }

        // Active profile is environment state, not file state.
        match self.paths.env("AWS_PROFILE") {
            Some(name) => {
                status.active = Some(name.to_string());
                if !status.profiles.iter().any(|p| p.id == name) {
                    status.note(format!(
                        "AWS_PROFILE is set to `{name}` but no such profile exists in ~/.aws"
                    ));
                }
            }
            None => {
                if status.profiles.iter().any(|p| p.id == "default") {
                    status.active = Some("default".to_string());
                    status.note(
                        "AWS_PROFILE is not set, so the `default` profile is in effect".to_string(),
                    );
                } else if !status.profiles.is_empty() {
                    status.note(
                        "AWS_PROFILE is not set and there is no `default` profile; aws commands will fail until you export one".to_string(),
                    );
                }
            }
        }

        if status.profiles.iter().any(|p| p.expires_at.is_none())
            && status
                .profiles
                .iter()
                .any(|p| p.meta.get("type").and_then(|v| v.as_str()) == Some("static-keys"))
        {
            status.note(
                "static access keys do not expire; patchbay cannot tell whether they were revoked without `pb verify aws`".to_string(),
            );
        }

        Ok(status)
    }

    fn switch(&self, profile_id: &str) -> anyhow::Result<SwitchOutcome> {
        // Deliberately unsupported: the active profile is an environment
        // variable in the caller's shell, which no child process can change.
        Ok(unsupported_switch(
            Self::TOOL,
            "the active AWS profile is the AWS_PROFILE environment variable, which patchbay cannot set in your shell",
            Some(&format!("export AWS_PROFILE={profile_id}")),
        ))
    }

    fn verify(&self) -> anyhow::Result<VerifyOutcome> {
        if !self.paths.may_exec() || !self.paths.has_binary("aws") {
            return Ok(unsupported_verify(
                Self::TOOL,
                "the aws CLI is not available on PATH",
                Some("aws sts get-caller-identity"),
            ));
        }
        let out = self.paths.run("aws", &["sts", "get-caller-identity", "--output", "json"])?;
        Ok(if out.ok {
            let arn = serde_json::from_str::<serde_json::Value>(&out.stdout)
                .ok()
                .and_then(|v| v.get("Arn").and_then(|a| a.as_str()).map(str::to_string))
                .unwrap_or_else(|| "credentials accepted".to_string());
            VerifyOutcome::Valid {
                tool: Self::TOOL.to_string(),
                detail: arn,
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
            "IAM policy evaluation is not implemented; the attached policies of the calling identity are not readable without extra permissions",
            Some("aws iam list-attached-user-policies --user-name <user>"),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    struct Fixture {
        _dir: tempfile::TempDir,
        home: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let home = dir.path().to_path_buf();
            fs::create_dir_all(home.join(".aws/sso/cache")).unwrap();
            Self { _dir: dir, home }
        }

        fn write(&self, rel: &str, body: &str) -> &Self {
            let path = self.home.join(rel);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, body).unwrap();
            self
        }

        fn probe(&self) -> AwsProbe {
            AwsProbe::new(Paths::for_test(&self.home))
        }
    }

    #[test]
    fn test_profiles_from_both_files_are_merged() {
        let fx = Fixture::new();
        fx.write(
            ".aws/config",
            "[default]\nregion = us-east-1\n\n[profile work]\nregion = ap-northeast-1\nsso_start_url = https://example.awsapps.com/start\nsso_account_id = 111122223333\nsso_role_name = Admin\n\n[sso-session corp]\nsso_region = us-east-1\n",
        )
        .write(
            ".aws/credentials",
            "[default]\naws_access_key_id = AKIAFAKEFIXTUREKEY\naws_secret_access_key = fake-fixture-secret\n",
        );

        let status = fx.probe().status().unwrap();
        let ids: Vec<_> = status.profiles.iter().map(|p| p.id.as_str()).collect();
        assert_eq!(ids, vec!["default", "work"]);

        let default = &status.profiles[0];
        assert_eq!(default.meta["source"], "config+credentials");
        assert_eq!(default.meta["type"], "static-keys");
        assert!(default.expires_at.is_none());

        let work = &status.profiles[1];
        assert_eq!(work.meta["type"], "sso");
        assert_eq!(work.meta["sso_account_id"], "111122223333");
        // `[sso-session corp]` is not a profile.
        assert!(!ids.contains(&"corp"));

        // No secret material anywhere in the serialized status.
        let json = serde_json::to_string(&status).unwrap();
        assert!(!json.contains("AKIAFAKEFIXTUREKEY"), "{json}");
        assert!(!json.contains("fake-fixture-secret"), "{json}");
    }

    #[test]
    fn test_sso_expiry_is_matched_by_start_url() {
        let fx = Fixture::new();
        fx.write(
            ".aws/config",
            "[profile work]\nsso_start_url = https://work.awsapps.com/start\nsso_role_name = Admin\n\n[profile other]\nsso_start_url = https://other.awsapps.com/start\n",
        )
        .write(
            ".aws/sso/cache/aaa.json",
            r#"{"startUrl":"https://work.awsapps.com/start","expiresAt":"2030-01-01T00:00:00Z","accessToken":"fake-fixture-token"}"#,
        )
        .write(
            ".aws/sso/cache/bbb.json",
            r#"{"startUrl":"https://other.awsapps.com/start","expiresAt":"2029-01-01T00:00:00Z","accessToken":"fake-fixture-token"}"#,
        )
        .write(".aws/sso/cache/junk.json", "{not json")
        .write(".aws/sso/cache/notacache.json", r#"{"hello":"world"}"#);

        let status = fx.probe().status().unwrap();
        let work = status.profiles.iter().find(|p| p.id == "work").unwrap();
        let other = status.profiles.iter().find(|p| p.id == "other").unwrap();
        assert_eq!(
            work.expires_at.unwrap().to_rfc3339(),
            "2030-01-01T00:00:00+00:00"
        );
        assert_eq!(
            other.expires_at.unwrap().to_rfc3339(),
            "2029-01-01T00:00:00+00:00"
        );

        let json = serde_json::to_string(&status).unwrap();
        assert!(!json.contains("fake-fixture-token"), "{json}");
    }

    #[test]
    fn test_active_follows_aws_profile_env() {
        let fx = Fixture::new();
        fx.write(".aws/config", "[default]\n\n[profile work]\n");

        let probe = AwsProbe::new(Paths::for_test(&fx.home).with_env("AWS_PROFILE", "work"));
        assert_eq!(probe.status().unwrap().active.as_deref(), Some("work"));

        // Unset -> default, with a note explaining why.
        let status = fx.probe().status().unwrap();
        assert_eq!(status.active.as_deref(), Some("default"));
        assert!(status
            .notes
            .iter()
            .any(|n| n.contains("AWS_PROFILE is not set")));

        // Set to something that does not exist -> flagged.
        let probe = AwsProbe::new(Paths::for_test(&fx.home).with_env("AWS_PROFILE", "ghost"));
        let status = probe.status().unwrap();
        assert_eq!(status.active.as_deref(), Some("ghost"));
        assert!(status.notes.iter().any(|n| n.contains("no such profile")));
    }

    #[test]
    fn test_missing_files_are_quiet() {
        let dir = tempfile::tempdir().unwrap();
        let status = AwsProbe::new(Paths::for_test(dir.path())).status().unwrap();
        assert!(!status.installed);
        assert!(status.profiles.is_empty());
        assert!(status.active.is_none());
        assert!(status.notes.is_empty());
    }

    #[test]
    fn test_malformed_config_does_not_fail_the_probe() {
        let fx = Fixture::new();
        fx.write(
            ".aws/config",
            "]]] garbage [[[\nno = section\n[profile ok]\nregion = us-east-1\n",
        );
        let status = fx.probe().status().unwrap();
        let ids: Vec<_> = status.profiles.iter().map(|p| p.id.as_str()).collect();
        assert_eq!(ids, vec!["ok"]);
    }

    #[test]
    fn test_switch_is_unsupported_with_an_actionable_hint() {
        let dir = tempfile::tempdir().unwrap();
        match AwsProbe::new(Paths::for_test(dir.path()))
            .switch("work")
            .unwrap()
        {
            SwitchOutcome::Unsupported { hint, .. } => {
                assert_eq!(hint.as_deref(), Some("export AWS_PROFILE=work"));
            }
            other => panic!("expected Unsupported, got {other:?}"),
        }
    }
}
