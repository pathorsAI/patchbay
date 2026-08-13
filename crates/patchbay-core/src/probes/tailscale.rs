//! `tailscale` — tailnet logins, which have almost no readable tier-1 state.
//!
//! Verified **empirically** on macOS. The App Store / Developer ID build is
//! sandboxed and keeps its state inside a group container:
//! `~/Library/Group Containers/W5364U7YZB.group.io.tailscale.ipn.macos/profile-data/<id>/`,
//! one directory per profile, where `<id>` matches the `ID` column of
//! `tailscale switch --list` (confirmed: `f4fe` on this machine). The files in
//! there are an internal, undocumented store — not a config format patchbay is
//! willing to parse — so tier 1 reports *that a profile exists* and leaves the
//! tailnet name, node key expiry and online state to `verify`.
//!
//! The open-source daemon (Homebrew, Linux) instead keeps a single
//! `/var/lib/tailscale/tailscaled.state`, which is root-owned; its presence is
//! used as an install signal only.
//!
//! `verify` parses `tailscale status --json` (`BackendState`,
//! `CurrentTailnet.Name`, `Self.Online`, `Self.KeyExpiry`). Note that the
//! Homebrew CLI prints a version-skew warning on **stderr**, so stdout stays
//! clean JSON.

use serde::Deserialize;

use crate::paths::Paths;
use crate::probe::{unknown_profile, unsupported_switch, unsupported_verify, Probe};
use crate::types::{PermissionsReport, Profile, SwitchOutcome, ToolStatus, VerifyOutcome};
use crate::util::{parse_timestamp, run};

pub struct TailscaleProbe {
    paths: Paths,
}

#[derive(Deserialize)]
struct Status {
    #[serde(default, rename = "BackendState")]
    backend_state: Option<String>,
    #[serde(default, rename = "CurrentTailnet")]
    current_tailnet: Option<Tailnet>,
    #[serde(default, rename = "Self")]
    self_node: Option<Node>,
}

#[derive(Deserialize)]
struct Tailnet {
    #[serde(default, rename = "Name")]
    name: Option<String>,
}

#[derive(Deserialize)]
struct Node {
    #[serde(default, rename = "DNSName")]
    dns_name: Option<String>,
    #[serde(default, rename = "Online")]
    online: Option<bool>,
    #[serde(default, rename = "KeyExpiry")]
    key_expiry: Option<String>,
}

impl TailscaleProbe {
    pub const TOOL: &'static str = "tailscale";

    pub fn new(paths: Paths) -> Self {
        Self { paths }
    }

    /// Profile ids from the sandboxed group container, sorted for stability.
    fn stored_profiles(&self) -> Vec<String> {
        let dir = self.paths.tailscale_profile_dir();
        let Ok(entries) = std::fs::read_dir(&dir) else {
            return Vec::new();
        };
        let mut ids: Vec<String> = entries
            .filter_map(|e| e.ok())
            .filter(|e| e.path().is_dir())
            .filter_map(|e| e.file_name().into_string().ok())
            .filter(|name| !name.starts_with('.'))
            .collect();
        ids.sort();
        ids
    }

    /// Parse `tailscale switch --list`:
    ///
    /// ```text
    /// ID    Tailnet                Account
    /// bdc8  example.com            someone@example.com
    /// f4fe  pathors.com            contact@pathors.com*
    /// ```
    ///
    /// The trailing `*` marks the current profile.
    fn parse_switch_list(text: &str) -> Vec<(String, String, String, bool)> {
        text.lines()
            .filter_map(|line| {
                let mut fields = line.split_whitespace();
                let id = fields.next()?;
                let tailnet = fields.next()?;
                let account = fields.next().unwrap_or(tailnet);
                if id.eq_ignore_ascii_case("ID") || tailnet.eq_ignore_ascii_case("Tailnet") {
                    return None; // header
                }
                let current = account.ends_with('*') || tailnet.ends_with('*');
                Some((
                    id.to_string(),
                    tailnet.trim_end_matches('*').to_string(),
                    account.trim_end_matches('*').to_string(),
                    current,
                ))
            })
            .collect()
    }
}

impl Probe for TailscaleProbe {
    fn tool(&self) -> &'static str {
        Self::TOOL
    }

    fn status(&self) -> anyhow::Result<ToolStatus> {
        let stored = self.stored_profiles();
        let state_file = self.paths.tailscaled_state();
        let installed = self.paths.has_binary("tailscale")
            || !stored.is_empty()
            || self.paths.tailscale_profile_dir().is_dir()
            || state_file.is_file();
        let mut status = ToolStatus::empty(Self::TOOL, installed);
        for note in self.paths.path_notes("tailscale") {
            status.note(note);
        }

        if !installed {
            return Ok(status);
        }

        for id in &stored {
            status.profiles.push(
                Profile::new(id.as_str())
                    .label(format!("tailscale profile {id}"))
                    .with_meta("source", "macOS group container")
                    .with_meta("detail", "run `pb verify tailscale` for the tailnet name"),
            );
        }

        // The sandboxed app keeps cached state for the profile it has loaded,
        // so a single directory is the active one. With several, patchbay will
        // not guess.
        match stored.len() {
            0 => status.note(
                "tailscale keeps its login inside the daemon's own state store, which patchbay \
                 does not parse; run `pb verify tailscale` to see the tailnet and key expiry"
                    .to_string(),
            ),
            1 => {
                status.active = Some(stored[0].clone());
                status.note(
                    "the profile id comes from the app's group container; the tailnet name, \
                     online state and node key expiry need `pb verify tailscale`"
                        .to_string(),
                );
            }
            n => status.note(format!(
                "{n} stored profiles, and which one is loaded is not readable from disk; run \
                 `tailscale switch --list`"
            )),
        }

        Ok(status)
    }

    fn switch(&self, profile_id: &str) -> anyhow::Result<SwitchOutcome> {
        if !self.paths.may_exec() || !self.paths.has_binary("tailscale") {
            return Ok(unsupported_switch(
                Self::TOOL,
                "the tailscale CLI is not available on PATH",
                Some(&format!("tailscale switch {profile_id}")),
            ));
        }

        // `switch` takes an id, a tailnet name or an account; validate against
        // the live list so an unknown value gets the available ids back.
        let listed = run("tailscale", &["switch", "--list"])?;
        if listed.ok {
            let profiles = Self::parse_switch_list(&listed.stdout);
            let known = profiles.iter().any(|(id, tailnet, account, _)| {
                id == profile_id || tailnet == profile_id || account == profile_id
            });
            if !profiles.is_empty() && !known {
                let mut status = ToolStatus::empty(Self::TOOL, true);
                status.profiles = profiles
                    .iter()
                    .map(|(id, tailnet, _, _)| Profile::new(id.as_str()).label(tailnet.as_str()))
                    .collect();
                return Ok(unknown_profile(Self::TOOL, profile_id, &status));
            }
        }

        let out = run("tailscale", &["switch", profile_id])?;
        Ok(if out.ok {
            SwitchOutcome::Switched {
                tool: Self::TOOL.to_string(),
                profile_id: profile_id.to_string(),
                detail: if out.message().is_empty() {
                    format!("tailscale is now on profile {profile_id}")
                } else {
                    out.message()
                },
                notes: vec![
                    "switching tailnets drops every connection routed over the previous one, \
                     including SSH sessions and tunnels"
                        .to_string(),
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
        if !self.paths.may_exec() || !self.paths.has_binary("tailscale") {
            return Ok(unsupported_verify(
                Self::TOOL,
                "the tailscale CLI is not available on PATH",
                Some("tailscale status --json"),
            ));
        }
        let out = run("tailscale", &["status", "--json"])?;
        if !out.ok {
            return Ok(VerifyOutcome::Invalid {
                tool: Self::TOOL.to_string(),
                detail: out.message(),
            });
        }
        // stdout is clean JSON even when the CLI warns about version skew on
        // stderr.
        let status: Status = match serde_json::from_str(&out.stdout) {
            Ok(status) => status,
            Err(e) => {
                return Ok(VerifyOutcome::Invalid {
                    tool: Self::TOOL.to_string(),
                    detail: format!("could not read `tailscale status --json` ({e})"),
                })
            }
        };

        let backend = status
            .backend_state
            .unwrap_or_else(|| "Unknown".to_string());
        let tailnet = status
            .current_tailnet
            .and_then(|t| t.name)
            .unwrap_or_else(|| "unknown tailnet".to_string());
        let node = status.self_node;
        let expiry = node
            .as_ref()
            .and_then(|n| n.key_expiry.as_deref())
            .and_then(parse_timestamp);
        let mut detail = format!("backend {backend} on {tailnet}");
        if let Some(name) = node.as_ref().and_then(|n| n.dns_name.clone()) {
            detail.push_str(&format!("; node {}", name.trim_end_matches('.')));
        }
        if let Some(online) = node.as_ref().and_then(|n| n.online) {
            detail.push_str(if online { "; online" } else { "; offline" });
        }
        if let Some(expiry) = expiry {
            detail.push_str(&format!("; node key expires {}", expiry.to_rfc3339()));
        }

        Ok(if backend == "Running" {
            VerifyOutcome::Valid {
                tool: Self::TOOL.to_string(),
                detail,
            }
        } else {
            VerifyOutcome::Invalid {
                tool: Self::TOOL.to_string(),
                detail: format!("{detail} (not connected; `tailscale up` to reconnect)"),
            }
        })
    }

    fn permissions(&self) -> anyhow::Result<PermissionsReport> {
        Ok(PermissionsReport::unsupported(
            Self::TOOL,
            "what a node may reach is decided by the tailnet's ACL policy on the coordination \
             server, not by anything on this machine",
            Some("tailscale netcheck / the Access Controls page of the admin console"),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    const GROUP: &str =
        "Library/Group Containers/W5364U7YZB.group.io.tailscale.ipn.macos/profile-data";

    fn with_profiles(ids: &[&str]) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().to_path_buf();
        for id in ids {
            fs::create_dir_all(home.join(GROUP).join(id)).unwrap();
        }
        (dir, home)
    }

    #[test]
    fn test_single_stored_profile_is_treated_as_active() {
        let (_dir, home) = with_profiles(&["f4fe"]);
        let status = TailscaleProbe::new(Paths::for_test(&home))
            .status()
            .unwrap();
        assert!(status.installed);
        assert_eq!(status.active.as_deref(), Some("f4fe"));
        assert_eq!(status.profiles.len(), 1);
        assert!(status.profiles[0].expires_at.is_none());
        assert!(status.notes.iter().any(|n| n.contains("pb verify")));
    }

    #[test]
    fn test_several_profiles_are_listed_without_guessing_the_active_one() {
        let (_dir, home) = with_profiles(&["bdc8", "f4fe"]);
        let status = TailscaleProbe::new(Paths::for_test(&home))
            .status()
            .unwrap();
        let ids: Vec<_> = status.profiles.iter().map(|p| p.id.as_str()).collect();
        assert_eq!(ids, vec!["bdc8", "f4fe"]);
        assert!(status.active.is_none());
        assert!(status.notes.iter().any(|n| n.contains("2 stored profiles")));
    }

    #[test]
    fn test_absent_machine_reports_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let status = TailscaleProbe::new(Paths::for_test(dir.path()))
            .status()
            .unwrap();
        assert!(!status.installed);
        assert!(status.profiles.is_empty());
        assert!(status.notes.is_empty());
    }

    #[test]
    fn test_empty_container_is_installed_but_unreadable() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join(GROUP)).unwrap();
        let status = TailscaleProbe::new(Paths::for_test(dir.path()))
            .status()
            .unwrap();
        assert!(status.installed);
        assert!(status.profiles.is_empty());
        assert!(status.notes.iter().any(|n| n.contains("does not parse")));
    }

    #[test]
    fn test_parse_switch_list_from_real_output() {
        let text = "ID    Tailnet                Account\n\
                    bdc8  example.com            someone@example.com\n\
                    f4fe  pathors.com            contact@pathors.com*\n";
        let parsed = TailscaleProbe::parse_switch_list(text);
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].0, "bdc8");
        assert_eq!(parsed[1].1, "pathors.com");
        assert_eq!(parsed[1].2, "contact@pathors.com");
        assert!(!parsed[0].3);
        assert!(parsed[1].3, "the starred row is the current profile");
    }

    #[test]
    fn test_tier_two_is_unsupported_without_exec() {
        let dir = tempfile::tempdir().unwrap();
        let probe = TailscaleProbe::new(Paths::for_test(dir.path()));
        assert!(matches!(
            probe.verify().unwrap(),
            VerifyOutcome::Unsupported { .. }
        ));
        assert!(matches!(
            probe.switch("f4fe").unwrap(),
            SwitchOutcome::Unsupported { .. }
        ));
        assert!(!probe.permissions().unwrap().supported);
    }
}
