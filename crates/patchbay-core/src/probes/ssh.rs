//! `ssh` — `Host` blocks in `~/.ssh/config`, and what the agent is holding.
//!
//! Verified **empirically** against this machine's `~/.ssh/config`: `Host`
//! blocks (including `Include` lines pulling in other files, e.g. colima's),
//! plus a directory of key pairs. Profiles are the `Host` aliases — labels
//! only. Nothing inside a key file is read; a private key is exactly the kind
//! of material patchbay refuses to touch, so the probe counts key *pairs* by
//! looking for `<name>.pub` and never opens either half.
//!
//! ssh has no active host: the host is an argument to every command. `active`
//! is therefore always `None`, like the rclone and docker probes.
//!
//! `verify` runs `ssh-add -l`, which talks to the local agent only — no
//! network, but it is still tier 2 because it executes a binary.

use crate::paths::Paths;
use crate::probe::{unsupported_switch, unsupported_verify, Probe};
use crate::types::{PermissionsReport, Profile, SwitchOutcome, ToolStatus, VerifyOutcome};
use crate::util::{read_text};

pub struct SshProbe {
    paths: Paths,
}

/// One `Host` block, reduced to the non-secret facts worth showing.
#[derive(Debug, Default, PartialEq)]
struct HostBlock {
    alias: String,
    hostname: Option<String>,
    user: Option<String>,
    port: Option<String>,
    identity_file: Option<String>,
    proxy_jump: Option<String>,
}

impl SshProbe {
    pub const TOOL: &'static str = "ssh";

    pub fn new(paths: Paths) -> Self {
        Self { paths }
    }

    /// Parse the subset of `ssh_config` patchbay cares about.
    ///
    /// The real grammar allows `Key value`, `Key=value`, quoting and multiple
    /// patterns per `Host`. Wildcard-only blocks (`Host *`) are defaults rather
    /// than destinations and are skipped.
    fn parse_config(text: &str) -> (Vec<HostBlock>, Vec<String>) {
        let mut hosts: Vec<HostBlock> = Vec::new();
        let mut includes: Vec<String> = Vec::new();
        // A `Host` line may name several patterns, and the directives that
        // follow apply to all of them.
        let mut current: Vec<usize> = Vec::new();

        for raw in text.lines() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (key, value) = match line.split_once([' ', '\t', '=']) {
                Some((k, v)) => (
                    k.trim().to_ascii_lowercase(),
                    v.trim_matches([' ', '\t', '=', '"']),
                ),
                None => continue,
            };
            match key.as_str() {
                "host" => {
                    current.clear();
                    for pattern in value.split_whitespace() {
                        if pattern.contains('*')
                            || pattern.contains('?')
                            || pattern.starts_with('!')
                        {
                            continue;
                        }
                        current.push(hosts.len());
                        hosts.push(HostBlock {
                            alias: pattern.to_string(),
                            ..Default::default()
                        });
                    }
                }
                "include" => includes.push(value.to_string()),
                _ => {
                    for index in &current {
                        let host = &mut hosts[*index];
                        let value = Some(value.to_string());
                        match key.as_str() {
                            "hostname" => host.hostname = value,
                            "user" => host.user = value,
                            "port" => host.port = value,
                            "identityfile" => host.identity_file = value,
                            "proxyjump" => host.proxy_jump = value,
                            _ => {}
                        }
                    }
                }
            }
        }
        (hosts, includes)
    }

    /// Count key pairs in `~/.ssh` by their `.pub` half, so no private key is
    /// ever opened. Returns the names, sorted.
    fn key_names(&self) -> Vec<String> {
        let Ok(entries) = std::fs::read_dir(self.paths.ssh_dir()) else {
            return Vec::new();
        };
        let mut names: Vec<String> = entries
            .filter_map(|e| e.ok())
            .filter_map(|e| e.file_name().into_string().ok())
            .filter_map(|name| name.strip_suffix(".pub").map(str::to_string))
            .collect();
        names.sort();
        names
    }

    /// `ssh-add -l` prints `<bits> <fingerprint> <comment> (<type>)` per key.
    /// Only the count and the key types are kept — a fingerprint is public,
    /// but there is no reason to carry one around.
    fn parse_agent_list(text: &str) -> Vec<String> {
        text.lines()
            .filter_map(|line| {
                // Only a real key line ends in a parenthesised type; "The agent
                // has no identities." must not be mistaken for one.
                let line = line.trim();
                let kind = line.strip_suffix(')')?.rsplit_once('(')?.1.trim();
                (!kind.is_empty()).then(|| kind.to_string())
            })
            .collect()
    }
}

impl Probe for SshProbe {
    fn tool(&self) -> &'static str {
        Self::TOOL
    }

    fn status(&self) -> anyhow::Result<ToolStatus> {
        let path = self.paths.ssh_config();
        // ssh ships with the OS; the config is what makes it interesting.
        let installed = self.paths.has_binary("ssh") || path.is_file();
        let mut status = ToolStatus::empty(Self::TOOL, installed);
        for note in self.paths.path_notes("ssh") {
            status.note(note);
        }

        let text = match read_text(&path) {
            Ok(Some(text)) => text,
            Ok(None) => {
                if installed {
                    status.note(format!(
                        "no {} on this machine, so there are no host aliases to list",
                        path.display()
                    ));
                }
                return Ok(status);
            }
            Err(e) => {
                status.note(e);
                return Ok(status);
            }
        };

        let (hosts, includes) = Self::parse_config(&text);
        for host in hosts {
            status.profiles.push(
                Profile::new(&host.alias)
                    .label(match &host.hostname {
                        Some(hostname) => format!("{} -> {hostname}", host.alias),
                        None => host.alias.clone(),
                    })
                    .with_meta("hostname", host.hostname)
                    .with_meta("user", host.user)
                    .with_meta("port", host.port)
                    // The path of a key, never its contents.
                    .with_meta("identity_file", host.identity_file)
                    .with_meta("proxy_jump", host.proxy_jump),
            );
        }

        let keys = self.key_names();
        if !keys.is_empty() {
            status.note(format!(
                "{} key pair(s) in {}: {}",
                keys.len(),
                self.paths.ssh_dir().display(),
                keys.join(", ")
            ));
        }
        if !includes.is_empty() {
            status.note(format!(
                "the config pulls in more hosts patchbay has not expanded: Include {}",
                includes.join(", ")
            ));
        }
        if !status.profiles.is_empty() {
            status.note(
                "ssh has no active host; the destination is an argument to each command. Key \
                 material is never read — run `pb verify ssh` to see what the agent is holding"
                    .to_string(),
            );
        }

        Ok(status)
    }

    fn switch(&self, _profile_id: &str) -> anyhow::Result<SwitchOutcome> {
        Ok(unsupported_switch(
            Self::TOOL,
            "ssh has no active host to switch; the destination is an argument to each command",
            Some("ssh <host>"),
        ))
    }

    fn verify(&self) -> anyhow::Result<VerifyOutcome> {
        if !self.paths.may_exec() || !self.paths.has_binary("ssh-add") {
            return Ok(unsupported_verify(
                Self::TOOL,
                "ssh-add is not available on PATH",
                Some("ssh-add -l"),
            ));
        }
        // Talks to the local agent socket only; no host is contacted.
        let out = self.paths.run("ssh-add", &["-l"])?;
        let keys = Self::parse_agent_list(&out.stdout);
        Ok(if out.ok && !keys.is_empty() {
            VerifyOutcome::Valid {
                tool: Self::TOOL.to_string(),
                detail: format!(
                    "the ssh agent is holding {} key(s): {}",
                    keys.len(),
                    keys.join(", ")
                ),
            }
        } else {
            VerifyOutcome::Invalid {
                tool: Self::TOOL.to_string(),
                detail: format!(
                    "the ssh agent has no identities loaded ({}); key-file logins still work, \
                     agent-only ones will not",
                    out.message()
                ),
            }
        })
    }

    fn permissions(&self) -> anyhow::Result<PermissionsReport> {
        Ok(PermissionsReport::unsupported(
            Self::TOOL,
            "what an ssh key may do is decided by each server's authorized_keys, which is not on \
             this machine",
            Some("ssh <host> id"),
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
        fs::create_dir_all(home.join(".ssh")).unwrap();
        fs::write(home.join(".ssh/config"), body).unwrap();
        (dir, home)
    }

    const CONFIG: &str = "\
Include /Users/dev/.colima/ssh_config

Host *
  AddKeysToAgent yes

Host db-tunnel
  HostName 10.0.0.5
  User postgres
  Port 2222
  IdentityFile ~/.ssh/id_ed25519
  ProxyJump bastion

Host bastion jump.example.com
  HostName bastion.example.com
  User=admin
";

    #[test]
    fn test_host_blocks_become_profiles() {
        let (_dir, home) = fixture(CONFIG);
        let status = SshProbe::new(Paths::for_test(&home)).status().unwrap();
        let ids: Vec<_> = status.profiles.iter().map(|p| p.id.as_str()).collect();
        // `Host *` is a defaults block, not a destination.
        assert_eq!(ids, vec!["db-tunnel", "bastion", "jump.example.com"]);
        assert!(status.active.is_none());

        let db = &status.profiles[0];
        assert_eq!(db.label, "db-tunnel -> 10.0.0.5");
        assert_eq!(db.meta["user"], "postgres");
        assert_eq!(db.meta["port"], "2222");
        assert_eq!(db.meta["identity_file"], "~/.ssh/id_ed25519");
        assert_eq!(db.meta["proxy_jump"], "bastion");
        assert!(db.expires_at.is_none());

        // One `Host` line, two patterns: the directives apply to both, and
        // `User=admin` is the same directive with the other separator.
        assert_eq!(status.profiles[1].meta["user"], "admin");
        assert_eq!(status.profiles[2].meta["user"], "admin");
        assert_eq!(status.profiles[1].meta["hostname"], "bastion.example.com");
        assert!(status.notes.iter().any(|n| n.contains("Include")));
    }

    #[test]
    fn test_keys_are_counted_never_read() {
        let (_dir, home) = fixture("Host a\n  HostName a.example.com\n");
        // A private key and its public half. Only the name is ever used.
        fs::write(
            home.join(".ssh/id_ed25519"),
            "PRIVATE-KEY-FIXTURE-DO-NOT-READ",
        )
        .unwrap();
        fs::write(home.join(".ssh/id_ed25519.pub"), "ssh-ed25519 AAAAfixture").unwrap();
        fs::write(home.join(".ssh/known_hosts"), "").unwrap();

        let status = SshProbe::new(Paths::for_test(&home)).status().unwrap();
        assert!(status
            .notes
            .iter()
            .any(|n| n.contains("1 key pair(s)") && n.contains("id_ed25519")));
        let json = serde_json::to_string(&status).unwrap();
        assert!(!json.contains("PRIVATE-KEY-FIXTURE"), "{json}");
        assert!(!json.contains("AAAAfixture"), "{json}");
    }

    #[test]
    fn test_missing_config_and_garbage() {
        let dir = tempfile::tempdir().unwrap();
        let status = SshProbe::new(Paths::for_test(dir.path())).status().unwrap();
        assert!(!status.installed);
        assert!(status.profiles.is_empty());

        // Not a config at all: no hosts, no panic, no notes about hosts.
        let (_dir, home) = fixture("<<<<<<< HEAD\nnonsense\n");
        let status = SshProbe::new(Paths::for_test(&home)).status().unwrap();
        assert!(status.profiles.is_empty());
    }

    #[test]
    fn test_parse_agent_list_from_real_output() {
        let text = "256 SHA256:abc dev@example.com (ED25519)\n\
                    3072 SHA256:def other@example.com (RSA)\n";
        assert_eq!(SshProbe::parse_agent_list(text), vec!["ED25519", "RSA"]);
        assert!(SshProbe::parse_agent_list("The agent has no identities.").is_empty());
    }

    #[test]
    fn test_tier_two_is_unsupported_without_exec() {
        let dir = tempfile::tempdir().unwrap();
        let probe = SshProbe::new(Paths::for_test(dir.path()));
        assert!(matches!(
            probe.verify().unwrap(),
            VerifyOutcome::Unsupported { .. }
        ));
        assert!(matches!(
            probe.switch("db-tunnel").unwrap(),
            SwitchOutcome::Unsupported { .. }
        ));
        assert!(!probe.permissions().unwrap().supported);
    }
}
