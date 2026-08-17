//! `gh` — GitHub CLI hosts and accounts.
//!
//! `~/.config/gh/hosts.yml` lists every host, the accounts logged in to it, and
//! which account is active per host. Tokens normally live in the OS keychain,
//! so `expires_at` is `None` (unknown, not expired). When a token *is* stored
//! in the file instead, patchbay detects the key's presence — never its value —
//! and raises a note.
//!
//! Profile ids are `host/user` so multi-host setups stay unambiguous; `switch`
//! also accepts a bare username when it is unique.

use std::collections::BTreeMap;

use serde::Deserialize;

use crate::paths::Paths;
use crate::probe::{unknown_profile, unsupported_switch, unsupported_verify, Probe};
use crate::types::{PermissionsReport, Profile, SwitchOutcome, ToolStatus, VerifyOutcome};
use crate::util::read_text;

pub struct GhProbe {
    paths: Paths,
}

/// Deliberately narrow: `oauth_token` is typed as `IgnoredAny` so serde reports
/// whether the key exists without the value ever being retained.
#[derive(Deserialize)]
struct Host {
    #[serde(default)]
    user: Option<String>,
    #[serde(default)]
    users: BTreeMap<String, serde::de::IgnoredAny>,
    #[serde(default)]
    git_protocol: Option<String>,
    #[serde(default)]
    oauth_token: Option<serde::de::IgnoredAny>,
}

impl GhProbe {
    pub const TOOL: &'static str = "gh";

    pub fn new(paths: Paths) -> Self {
        Self { paths }
    }

    /// Resolve a user-supplied id to `(host, user)`. Accepts `host/user` and a
    /// bare `user` when that name appears on exactly one host.
    fn resolve(status: &ToolStatus, profile_id: &str) -> Option<(String, String)> {
        let exact = status.profiles.iter().find(|p| p.id == profile_id);
        let candidate = exact.or_else(|| {
            let mut matches = status
                .profiles
                .iter()
                .filter(|p| p.meta.get("user").and_then(|v| v.as_str()) == Some(profile_id));
            let first = matches.next();
            match matches.next() {
                Some(_) => None, // ambiguous across hosts
                None => first,
            }
        })?;
        let host = candidate.meta.get("host")?.as_str()?.to_string();
        let user = candidate.meta.get("user")?.as_str()?.to_string();
        Some((host, user))
    }

    /// Pull the scopes out of `gh auth status` output. The line looks like:
    /// `- Token scopes: 'repo', 'read:org'`
    fn parse_scopes(text: &str) -> Vec<String> {
        text.lines()
            .find_map(|line| line.split_once("Token scopes:"))
            .map(|(_, list)| {
                list.split(',')
                    .map(|s| s.trim().trim_matches('\'').trim_matches('"').to_string())
                    .filter(|s| !s.is_empty() && s != "none")
                    .collect()
            })
            .unwrap_or_default()
    }

    fn parse_account(text: &str) -> Option<String> {
        text.lines()
            .find_map(|line| line.split_once("Logged in to "))
            .map(|(_, rest)| rest.trim())
            .and_then(|rest| {
                let rest = rest.split_once(" account ").map(|(_, a)| a).unwrap_or(rest);
                rest.split_whitespace().next().map(str::to_string)
            })
    }
}

impl Probe for GhProbe {
    fn tool(&self) -> &'static str {
        Self::TOOL
    }

    fn status(&self) -> anyhow::Result<ToolStatus> {
        let path = self.paths.gh_hosts();
        let installed = self.paths.has_binary("gh") || path.is_file();
        let mut status = ToolStatus::empty(Self::TOOL, installed);
        for note in self.paths.path_notes("gh") {
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

        let hosts: BTreeMap<String, Host> = match serde_yaml_ng::from_str(&text) {
            Ok(hosts) => hosts,
            Err(e) => {
                status.note(format!("hosts.yml is not valid YAML ({e})"));
                return Ok(status);
            }
        };

        let mut active_per_host: Vec<(String, String)> = Vec::new();
        for (host, config) in &hosts {
            if config.oauth_token.is_some() {
                status.note(format!(
                    "the token for {host} is stored in plain text in hosts.yml rather than the system keychain"
                ));
            }
            // Accounts appear under `users:`; older files only have `user:`.
            let mut users: Vec<String> = config.users.keys().cloned().collect();
            if let Some(active) = &config.user {
                if !users.contains(active) {
                    users.push(active.clone());
                }
                active_per_host.push((host.clone(), active.clone()));
            }
            for user in users {
                status.profiles.push(
                    Profile::new(format!("{host}/{user}"))
                        .label(format!("{user} @ {host}"))
                        .with_meta("host", host.as_str())
                        .with_meta("user", user.as_str())
                        .with_meta("git_protocol", config.git_protocol.clone())
                        .with_meta(
                            "token_storage",
                            if config.oauth_token.is_some() {
                                "hosts.yml"
                            } else {
                                "keychain"
                            },
                        ),
                );
            }
        }

        // gh keeps one active account per host. Prefer github.com.
        status.active = active_per_host
            .iter()
            .find(|(host, _)| host == "github.com")
            .or_else(|| active_per_host.first())
            .map(|(host, user)| format!("{host}/{user}"));

        if active_per_host.len() > 1 {
            status.note(format!(
                "gh keeps one active account per host: {}",
                active_per_host
                    .iter()
                    .map(|(h, u)| format!("{h} -> {u}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        if !status.profiles.is_empty() {
            status.note(
                "token expiry is unknown because gh stores tokens in the system keychain; use `pb verify gh` to check them".to_string(),
            );
        }

        Ok(status)
    }

    fn switch(&self, profile_id: &str) -> anyhow::Result<SwitchOutcome> {
        let status = self.status()?;
        let Some((host, user)) = Self::resolve(&status, profile_id) else {
            return Ok(unknown_profile(Self::TOOL, profile_id, &status));
        };
        if !self.paths.may_exec() {
            return Ok(unsupported_switch(
                Self::TOOL,
                "command execution is disabled for this probe",
                Some(&format!("gh auth switch --hostname {host} --user {user}")),
            ));
        }

        let out = self.paths.run(
            "gh",
            &["auth", "switch", "--hostname", &host, "--user", &user],
        )?;
        Ok(if out.ok {
            SwitchOutcome::Switched {
                tool: Self::TOOL.to_string(),
                profile_id: format!("{host}/{user}"),
                detail: if out.message().is_empty() {
                    format!("active gh account on {host} is now {user}")
                } else {
                    out.message()
                },
                notes: vec![
                    "this changes gh only; git credential helpers and any GH_TOKEN in your environment are unaffected".to_string(),
                ],
            }
        } else {
            SwitchOutcome::Failed {
                tool: Self::TOOL.to_string(),
                profile_id: profile_id.to_string(),
                detail: out.message(),
            }
        })
    }

    fn verify(&self) -> anyhow::Result<VerifyOutcome> {
        if !self.paths.may_exec() || !self.paths.has_binary("gh") {
            return Ok(unsupported_verify(
                Self::TOOL,
                "the gh CLI is not available on PATH",
                Some("gh auth status --active"),
            ));
        }
        let out = self.paths.run("gh", &["auth", "status", "--active"])?;
        Ok(if out.ok {
            VerifyOutcome::Valid {
                tool: Self::TOOL.to_string(),
                detail: Self::parse_account(&out.stdout)
                    .map(|a| format!("token accepted for {a}"))
                    .unwrap_or_else(|| "token accepted".to_string()),
            }
        } else {
            VerifyOutcome::Invalid {
                tool: Self::TOOL.to_string(),
                detail: out.message(),
            }
        })
    }

    fn permissions(&self) -> anyhow::Result<PermissionsReport> {
        if !self.paths.may_exec() || !self.paths.has_binary("gh") {
            return Ok(PermissionsReport::unsupported(
                Self::TOOL,
                "the gh CLI is not available on PATH",
                Some("gh auth status --active"),
            ));
        }
        let out = self.paths.run("gh", &["auth", "status", "--active"])?;
        if !out.ok {
            return Ok(PermissionsReport {
                tool: Self::TOOL.to_string(),
                supported: true,
                subject: None,
                scopes: Vec::new(),
                notes: vec![format!(
                    "gh could not report the active token: {}",
                    out.message()
                )],
                hint: Some("gh auth login".to_string()),
                scope: None,
            });
        }

        // gh prints the report on stdout; be tolerant and read both.
        let text = format!("{}\n{}", out.stdout, out.stderr);
        let scopes = Self::parse_scopes(&text);
        let mut notes = Vec::new();
        if scopes.is_empty() {
            notes.push(
                "gh reported no token scopes; fine-grained personal access tokens do not expose classic scopes".to_string(),
            );
        }
        Ok(PermissionsReport {
            tool: Self::TOOL.to_string(),
            supported: true,
            subject: Self::parse_account(&text),
            scopes,
            notes,
            hint: Some(
                "add a missing scope with `gh auth refresh -s <scope>` (e.g. `gh auth refresh -s read:project`)".to_string(),
            ),
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
        fs::create_dir_all(home.join(".config/gh")).unwrap();
        fs::write(home.join(".config/gh/hosts.yml"), body).unwrap();
        (dir, home)
    }

    #[test]
    fn test_users_map_and_active_user() {
        let (_dir, home) = fixture(
            "github.com:\n    git_protocol: https\n    users:\n        alice: {}\n        bob:\n    user: alice\n",
        );
        let status = GhProbe::new(Paths::for_test(&home)).status().unwrap();
        let ids: Vec<_> = status.profiles.iter().map(|p| p.id.as_str()).collect();
        assert_eq!(ids, vec!["github.com/alice", "github.com/bob"]);
        assert_eq!(status.active.as_deref(), Some("github.com/alice"));
        assert_eq!(status.profiles[0].meta["git_protocol"], "https");
        assert_eq!(status.profiles[0].meta["token_storage"], "keychain");
        assert!(status.profiles.iter().all(|p| p.expires_at.is_none()));
    }

    #[test]
    fn test_enterprise_host_keeps_ids_unambiguous() {
        let (_dir, home) = fixture(
            "github.com:\n    users:\n        alice: {}\n    user: alice\ngh.corp.example:\n    users:\n        alice: {}\n    user: alice\n",
        );
        let status = GhProbe::new(Paths::for_test(&home)).status().unwrap();
        assert_eq!(status.profiles.len(), 2);
        assert_eq!(status.active.as_deref(), Some("github.com/alice"));
        assert!(status
            .notes
            .iter()
            .any(|n| n.contains("one active account per host")));
        // A bare, ambiguous username must not resolve.
        assert!(GhProbe::resolve(&status, "alice").is_none());
        assert!(GhProbe::resolve(&status, "github.com/alice").is_some());
    }

    #[test]
    fn test_plaintext_token_is_flagged_but_never_read() {
        let (_dir, home) = fixture(
            "github.com:\n    oauth_token: gho_fakefixturetokenvalue\n    user: alice\n    users:\n        alice: {}\n",
        );
        let status = GhProbe::new(Paths::for_test(&home)).status().unwrap();
        let json = serde_json::to_string(&status).unwrap();
        assert!(status.notes.iter().any(|n| n.contains("plain text")));
        assert!(!json.contains("gho_fakefixturetokenvalue"), "{json}");
        assert_eq!(status.profiles[0].meta["token_storage"], "hosts.yml");
    }

    #[test]
    fn test_missing_and_malformed() {
        let dir = tempfile::tempdir().unwrap();
        let status = GhProbe::new(Paths::for_test(dir.path())).status().unwrap();
        assert!(!status.installed);
        assert!(status.profiles.is_empty());

        let (_dir, home) = fixture("github.com:\n  - this is a list not a map\n");
        let status = GhProbe::new(Paths::for_test(&home)).status().unwrap();
        assert!(status.profiles.is_empty());
        assert!(status.notes.iter().any(|n| n.contains("not valid YAML")));
    }

    #[test]
    fn test_parse_scopes_from_real_gh_output() {
        let text = "github.com\n  \u{2713} Logged in to github.com account alice (keyring)\n  - Active account: true\n  - Git operations protocol: https\n  - Token: gho_************\n  - Token scopes: 'admin:org', 'repo', 'workflow'\n";
        assert_eq!(
            GhProbe::parse_scopes(text),
            vec!["admin:org", "repo", "workflow"]
        );
        assert_eq!(GhProbe::parse_account(text).as_deref(), Some("alice"));
    }

    #[test]
    fn test_parse_scopes_handles_none_and_absent() {
        assert!(GhProbe::parse_scopes("  - Token scopes: none\n").is_empty());
        assert!(GhProbe::parse_scopes("nothing here").is_empty());
    }
}
