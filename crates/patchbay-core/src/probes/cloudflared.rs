//! `cloudflared` — Cloudflare Tunnel origin certificates, and which one is in
//! force.
//!
//! Verified **empirically** against cloudflared 2025.2.1 on a machine running
//! two Cloudflare accounts. `~/.cloudflared` holds two kinds of file:
//!
//! * `cert.pem`, and any other `*.pem` — the *account* credentials, written by
//!   `cloudflared tunnel login`. Each authorises creating, deleting and running
//!   tunnels for one account. `cert.pem` is the default; a second file
//!   (`cert-pathors.pem` on this machine) is only used when `TUNNEL_ORIGIN_CERT`
//!   or `--origincert` names it.
//! * `<uuid>.json` — one per tunnel, holding `AccountTag`, `TunnelID` and
//!   `TunnelSecret`. Run credentials, not logins.
//!
//! **What counts as a profile: the certificate.** That is the identity
//! dimension — which Cloudflare account a `cloudflared` command operates as.
//! Tunnels are not identities (four tunnels on one account is one login), so
//! they are reported in `meta`.
//!
//! The trap this probe exists for: with two certificates on disk, every
//! `cloudflared` command uses `cert.pem` unless the environment says otherwise,
//! so a second account's tunnel silently operates as the first. Nothing on the
//! machine tells you which one is in force — `cloudflared` has no `whoami` and
//! no persistent "use this account" state.
//!
//! **Secret handling, twice over.**
//!
//! * `cert.pem` is **never parsed**. It is a PEM bundle containing a private
//!   key and an Argo tunnel token; patchbay takes its existence, its filename
//!   and its mtime and nothing else. There is no code path in this file that
//!   reads its bytes, and that is deliberate — a probe has no business holding
//!   private key material to report a login.
//! * `TunnelSecret` is **never read**. [`TunnelCredential`] has no field for it,
//!   so serde drops it during parsing and it never exists in memory.

use serde::Deserialize;

use crate::paths::Paths;
use crate::probe::{unsupported_switch, unsupported_verify, Probe};
use crate::types::{PermissionsReport, Profile, SwitchOutcome, ToolStatus, VerifyOutcome};
use crate::util::read_text;

pub struct CloudflaredProbe {
    paths: Paths,
}

/// One `<uuid>.json`, minus its secret. `TunnelSecret` is absent on purpose:
/// serde drops unknown fields, so the value never reaches memory.
#[derive(Debug, Deserialize)]
struct TunnelCredential {
    #[serde(default, rename = "AccountTag")]
    account_tag: Option<String>,
    #[serde(default, rename = "TunnelID")]
    tunnel_id: Option<String>,
    #[serde(default, rename = "TunnelName")]
    tunnel_name: Option<String>,
}

/// `config.yml`: which tunnel it runs and how many ingress rules it has.
#[derive(Debug, Default, Deserialize)]
struct TunnelConfig {
    /// Tunnel name or UUID.
    #[serde(default)]
    tunnel: Option<String>,
    #[serde(default)]
    ingress: Vec<serde_yaml_ng::Value>,
    /// Some setups point at the credentials file rather than naming a tunnel.
    #[serde(default, rename = "credentials-file")]
    credentials_file: Option<String>,
}

/// One tunnel credential, reduced to what is safe to report.
#[derive(Debug, Clone)]
struct TunnelRef {
    id: String,
    name: Option<String>,
    account: Option<String>,
}

impl TunnelRef {
    /// Name when the file records one, else the UUID.
    fn display(&self) -> String {
        self.name.clone().unwrap_or_else(|| self.id.clone())
    }
}

impl CloudflaredProbe {
    pub const TOOL: &'static str = "cloudflared";
    /// cloudflared's own default when nothing names a certificate.
    const DEFAULT_CERT: &'static str = "cert.pem";

    pub fn new(paths: Paths) -> Self {
        Self { paths }
    }

    /// Every `*.pem` in the credential directory, sorted, with its mtime.
    ///
    /// Contents are never read — only the directory entry.
    fn origin_certs(&self) -> Vec<(String, Option<std::time::SystemTime>)> {
        let dir = self.paths.cloudflared_dir();
        let Ok(entries) = std::fs::read_dir(&dir) else {
            return Vec::new();
        };
        let mut certs: Vec<(String, Option<std::time::SystemTime>)> = entries
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().is_some_and(|ext| ext == "pem"))
            .map(|e| {
                let modified = e.metadata().ok().and_then(|m| m.modified().ok());
                (e.file_name().to_string_lossy().into_owned(), modified)
            })
            .collect();
        certs.sort_by(|a, b| a.0.cmp(&b.0));
        certs
    }

    /// Every tunnel credential in the directory, secret-free.
    fn tunnels(&self, notes: &mut Vec<String>) -> Vec<TunnelRef> {
        let dir = self.paths.cloudflared_dir();
        let Ok(entries) = std::fs::read_dir(&dir) else {
            return Vec::new();
        };
        let mut files: Vec<std::path::PathBuf> = entries
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|ext| ext == "json"))
            .collect();
        // Directory order is arbitrary; sort so the board is stable.
        files.sort();

        let mut tunnels = Vec::new();
        for path in files {
            let text = match read_text(&path) {
                Ok(Some(text)) => text,
                Ok(None) => continue,
                Err(e) => {
                    notes.push(e);
                    continue;
                }
            };
            // A file that is not a tunnel credential is not an error: this
            // directory collects unrelated JSON on some setups.
            let Ok(credential) = serde_json::from_str::<TunnelCredential>(&text) else {
                continue;
            };
            let id = credential.tunnel_id.filter(|i| !i.is_empty());
            let account = credential.account_tag.filter(|a| !a.is_empty());
            if id.is_none() && account.is_none() {
                continue;
            }
            tunnels.push(TunnelRef {
                // The filename is the UUID when the field is missing.
                id: id.unwrap_or_else(|| {
                    path.file_stem()
                        .map(|s| s.to_string_lossy().into_owned())
                        .unwrap_or_default()
                }),
                name: credential.tunnel_name.filter(|n| !n.is_empty()),
                account,
            });
        }
        tunnels
    }

    /// `config.yml`, when there is one.
    fn config(&self, notes: &mut Vec<String>) -> Option<TunnelConfig> {
        let path = self.paths.cloudflared_config();
        match read_text(&path) {
            Ok(Some(text)) => match serde_yaml_ng::from_str::<TunnelConfig>(&text) {
                Ok(config) => Some(config),
                Err(e) => {
                    notes.push(format!("{} is not valid YAML ({e})", path.display()));
                    None
                }
            },
            Ok(None) => None,
            Err(e) => {
                notes.push(e);
                None
            }
        }
    }
}

impl Probe for CloudflaredProbe {
    fn tool(&self) -> &'static str {
        Self::TOOL
    }

    fn status(&self) -> anyhow::Result<ToolStatus> {
        let dir = self.paths.cloudflared_dir();
        let installed = self.paths.has_binary("cloudflared") || dir.is_dir();
        let mut status = ToolStatus::empty(Self::TOOL, installed);
        for note in self.paths.path_notes("cloudflared") {
            status.note(note);
        }
        for note in self.paths.path_notes("cloudflared_config") {
            status.note(note);
        }

        let mut notes = Vec::new();
        let certs = self.origin_certs();
        let tunnels = self.tunnels(&mut notes);
        let config = self.config(&mut notes);
        for note in notes {
            status.note(note);
        }

        // The certificate in force. When `TUNNEL_ORIGIN_CERT` points outside
        // the credential directory it is still the active identity, so it joins
        // the profile list under its own file name.
        let active_cert = self.paths.cloudflared_origin_cert();
        let explicit = self.paths.cloudflared_origin_cert_is_explicit();
        let active_name = active_cert
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| Self::DEFAULT_CERT.to_string());

        if certs.is_empty() && !active_cert.is_file() {
            if installed {
                status.note(format!(
                    "no origin certificate in {}; run `cloudflared tunnel login`",
                    dir.display()
                ));
            }
            return Ok(status);
        }

        // Directory-wide facts. A tunnel credential cannot be attributed to a
        // certificate without parsing the certificate, which this probe will
        // not do, so these are reported as properties of the directory rather
        // than pretending to belong to one identity.
        let tunnel_names: Vec<String> = tunnels.iter().map(TunnelRef::display).collect();
        let mut accounts: Vec<String> = tunnels.iter().filter_map(|t| t.account.clone()).collect();
        accounts.sort();
        accounts.dedup();

        let mut listed = certs.clone();
        if explicit && !listed.iter().any(|(name, _)| name == &active_name) {
            let modified = std::fs::metadata(&active_cert)
                .ok()
                .and_then(|m| m.modified().ok());
            listed.push((active_name.clone(), modified));
        }

        for (name, modified) in &listed {
            let path = if name == &active_name && explicit {
                active_cert.clone()
            } else {
                dir.join(name)
            };
            status.profiles.push(
                Profile::new(name)
                    .label(format!("origin certificate {name}"))
                    // No expiry: an origin certificate records none on disk.
                    .expires_at(None)
                    .with_meta("path", path.display().to_string())
                    .with_meta(
                        "modified",
                        modified.and_then(|m| {
                            chrono::DateTime::<chrono::Utc>::from(m).to_rfc3339().into()
                        }),
                    )
                    .with_meta("is_default", name == Self::DEFAULT_CERT)
                    .with_meta("tunnels_in_directory", tunnel_names.len())
                    .with_meta("tunnel_names", tunnel_names.clone())
                    .with_meta("accounts_in_directory", accounts.clone()),
            );
        }

        if active_cert.is_file() {
            status.active = Some(active_name.clone());
        } else if explicit {
            status.note(format!(
                "TUNNEL_ORIGIN_CERT points at {}, which does not exist; every cloudflared \
                 command will fail until it does",
                active_cert.display()
            ));
        } else {
            status.note(format!(
                "no {} in {}; cloudflared needs `--origincert` or TUNNEL_ORIGIN_CERT to name \
                 one of the certificates that are there",
                Self::DEFAULT_CERT,
                dir.display()
            ));
        }

        // The whole reason this probe exists.
        if listed.len() > 1 {
            let others: Vec<&str> = listed
                .iter()
                .map(|(n, _)| n.as_str())
                .filter(|n| *n != active_name)
                .collect();
            status.note(format!(
                "{} origin certificates here, one per Cloudflare account: `{}` is in force and \
                 {} only applies when TUNNEL_ORIGIN_CERT or --origincert names it. cloudflared \
                 has no persistent account selection, so a command run without either operates \
                 as `{}`",
                listed.len(),
                active_name,
                if others.len() == 1 {
                    format!("`{}`", others[0])
                } else {
                    format!("each of {}", others.join(", "))
                },
                active_name
            ));
        }
        if explicit {
            status.note(format!(
                "TUNNEL_ORIGIN_CERT is set, so this shell operates as `{active_name}` — other \
                 shells, launchd jobs and editors on this machine do not inherit it"
            ));
        }

        if let Some(config) = config {
            let path = self.paths.cloudflared_config();
            let mut parts = vec![format!("{} defines", path.display())];
            match &config.tunnel {
                Some(tunnel) => parts.push(format!("tunnel `{tunnel}`")),
                None => parts.push("no tunnel".to_string()),
            }
            parts.push(format!("{} ingress rule(s)", config.ingress.len()));
            if config.credentials_file.is_some() {
                parts.push("and names a credentials file".to_string());
            }
            status.note(parts.join(" "));
            for profile in &mut status.profiles {
                profile.meta["config_tunnel"] = config
                    .tunnel
                    .clone()
                    .map(serde_json::Value::String)
                    .unwrap_or(serde_json::Value::Null);
                profile.meta["config_ingress_rules"] = config.ingress.len().into();
            }
        }

        if !tunnels.is_empty() {
            status.note(format!(
                "{} tunnel credential{} in this directory — per-tunnel run secrets, not logins; \
                 patchbay reads their ids and account tags and never their TunnelSecret",
                tunnels.len(),
                if tunnels.len() == 1 { "" } else { "s" }
            ));
        }
        status.note(
            "origin certificates record no expiry on disk, so patchbay cannot date them; one \
             stays valid until it is revoked in the Cloudflare dashboard",
        );
        Ok(status)
    }

    fn switch(&self, profile_id: &str) -> anyhow::Result<SwitchOutcome> {
        // cloudflared keeps no "current account" anywhere — the selection is
        // per-command, through an environment variable or a flag. There is no
        // file for patchbay to edit, so the honest answer is the export line,
        // the same shape the aws probe returns for AWS_PROFILE.
        let dir = self.paths.cloudflared_dir();
        let known: Vec<String> = self.origin_certs().into_iter().map(|(n, _)| n).collect();
        if !known.is_empty() && !known.iter().any(|n| n == profile_id) {
            let status = self.status()?;
            return Ok(crate::probe::unknown_profile(
                Self::TOOL,
                profile_id,
                &status,
            ));
        }
        Ok(unsupported_switch(
            Self::TOOL,
            "cloudflared has no persistent account selection: the origin certificate is chosen \
             per command by TUNNEL_ORIGIN_CERT or --origincert, so there is no state for \
             patchbay to change",
            Some(&format!(
                "export TUNNEL_ORIGIN_CERT={}",
                dir.join(profile_id).display()
            )),
        ))
    }

    fn verify(&self) -> anyhow::Result<VerifyOutcome> {
        if !self.paths.may_exec() || !self.paths.has_binary("cloudflared") {
            return Ok(unsupported_verify(
                Self::TOOL,
                "the cloudflared CLI is not available on PATH",
                Some("cloudflared tunnel list"),
            ));
        }
        let cert = self.paths.cloudflared_origin_cert();
        if !cert.is_file() {
            return Ok(VerifyOutcome::Invalid {
                tool: Self::TOOL.to_string(),
                detail: format!(
                    "{} does not exist; run `cloudflared tunnel login`",
                    cert.display()
                ),
            });
        }
        // Names the certificate explicitly so this checks the identity the
        // board just reported as active, not whatever the ambient environment
        // of this process happens to say.
        let out = self.paths.run(
            "cloudflared",
            &[
                "tunnel",
                "--origincert",
                &cert.display().to_string(),
                "list",
                "--output",
                "json",
            ],
        )?;
        let name = cert
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        Ok(if out.ok {
            let count = serde_json::from_str::<Vec<serde_json::Value>>(&out.stdout)
                .map(|t| t.len())
                .unwrap_or_default();
            VerifyOutcome::Valid {
                tool: Self::TOOL.to_string(),
                detail: format!(
                    "`{name}` is accepted; the account it belongs to has {count} tunnel(s)"
                ),
            }
        } else {
            VerifyOutcome::Invalid {
                tool: Self::TOOL.to_string(),
                detail: format!("`{name}` was rejected: {}", out.message()),
            }
        })
    }

    fn permissions(&self) -> anyhow::Result<PermissionsReport> {
        Ok(PermissionsReport::unsupported(
            Self::TOOL,
            "an origin certificate authorises tunnel management for one account and carries no \
             scope list patchbay can read without parsing the certificate, which it will not do",
            Some("check Networks → Tunnels in the Cloudflare dashboard"),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    /// The secret from the fixture below. Every leak assertion greps for it.
    const FIXTURE_SECRET: &str = "c2VjcmV0LXZhbHVlLXRoYXQtbXVzdC1uZXZlci1sZWFr";
    /// Stand-in for the private key material inside a real cert.pem.
    const FIXTURE_CERT_BODY: &str =
        "-----BEGIN ARGO TUNNEL TOKEN-----\nZmFrZS1wcml2YXRlLWtleS1tYXRlcmlhbA==\n-----END ARGO TUNNEL TOKEN-----\n";

    fn fixture() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().to_path_buf();
        fs::create_dir_all(home.join(".cloudflared")).unwrap();
        (dir, home)
    }

    fn write_cert(home: &std::path::Path, name: &str) {
        fs::write(home.join(".cloudflared").join(name), FIXTURE_CERT_BODY).unwrap();
    }

    /// The exact shape of a real `<uuid>.json`, secret value replaced.
    fn write_tunnel(home: &std::path::Path, id: &str, account: &str) {
        fs::write(
            home.join(format!(".cloudflared/{id}.json")),
            format!(
                r#"{{"AccountTag":"{account}","TunnelSecret":"{FIXTURE_SECRET}","TunnelID":"{id}","Endpoint":""}}"#
            ),
        )
        .unwrap();
    }

    /// The machine this probe was written against: two accounts, four tunnels.
    fn two_account_machine() -> (tempfile::TempDir, PathBuf) {
        let (dir, home) = fixture();
        write_cert(&home, "cert.pem");
        write_cert(&home, "cert-pathors.pem");
        write_tunnel(&home, "2926b191-c50d-4cff-be39-a5b5a8f83125", "acctA");
        write_tunnel(&home, "54e839b7-a986-47cd-b23b-d643de93d129", "acctA");
        write_tunnel(&home, "9af8e2a2-af48-40d2-adac-194fe473dc9a", "acctB");
        write_tunnel(&home, "e3533e84-ae7b-4b40-bc6b-a9f5ffdc386d", "acctB");
        (dir, home)
    }

    #[test]
    fn test_certificates_are_the_profiles_and_the_default_is_active() {
        let (_dir, home) = two_account_machine();
        let status = CloudflaredProbe::new(Paths::for_test(&home))
            .status()
            .unwrap();

        assert!(status.installed);
        let ids: Vec<&str> = status.profiles.iter().map(|p| p.id.as_str()).collect();
        assert_eq!(ids, vec!["cert-pathors.pem", "cert.pem"]);
        // Nothing names a certificate, so cloudflared's own default wins.
        assert_eq!(status.active.as_deref(), Some("cert.pem"));

        let default = status.profiles.iter().find(|p| p.id == "cert.pem").unwrap();
        assert_eq!(default.meta["is_default"], true);
        assert_eq!(default.expires_at, None);
        assert!(default.meta["modified"].is_string());
    }

    #[test]
    fn test_two_certificates_get_the_silent_wrong_account_warning() {
        let (_dir, home) = two_account_machine();
        let status = CloudflaredProbe::new(Paths::for_test(&home))
            .status()
            .unwrap();

        let warning = status
            .notes
            .iter()
            .find(|n| n.contains("one per Cloudflare account"))
            .unwrap_or_else(|| panic!("no multi-cert warning in {:?}", status.notes));
        assert!(warning.contains("`cert.pem` is in force"), "{warning}");
        assert!(warning.contains("cert-pathors.pem"), "{warning}");
        assert!(warning.contains("TUNNEL_ORIGIN_CERT"), "{warning}");
    }

    #[test]
    fn test_tunnel_origin_cert_selects_the_active_identity() {
        let (_dir, home) = two_account_machine();
        let paths = Paths::for_test(&home).with_env(
            "TUNNEL_ORIGIN_CERT",
            home.join(".cloudflared/cert-pathors.pem").to_str().unwrap(),
        );
        let status = CloudflaredProbe::new(paths).status().unwrap();

        assert_eq!(status.active.as_deref(), Some("cert-pathors.pem"));
        assert!(
            status
                .notes
                .iter()
                .any(|n| n.contains("other shells, launchd jobs and editors")),
            "{:?}",
            status.notes
        );
    }

    #[test]
    fn test_a_cert_outside_the_directory_still_becomes_the_active_profile() {
        let (dir, home) = fixture();
        write_cert(&home, "cert.pem");
        let elsewhere = dir.path().join("work/cert-other.pem");
        fs::create_dir_all(elsewhere.parent().unwrap()).unwrap();
        fs::write(&elsewhere, FIXTURE_CERT_BODY).unwrap();

        let paths =
            Paths::for_test(&home).with_env("TUNNEL_ORIGIN_CERT", elsewhere.to_str().unwrap());
        let status = CloudflaredProbe::new(paths).status().unwrap();

        assert_eq!(status.active.as_deref(), Some("cert-other.pem"));
        let ids: Vec<&str> = status.profiles.iter().map(|p| p.id.as_str()).collect();
        assert!(ids.contains(&"cert-other.pem"), "{ids:?}");
        assert!(ids.contains(&"cert.pem"), "{ids:?}");
    }

    #[test]
    fn test_a_dangling_tunnel_origin_cert_is_called_out() {
        let (_dir, home) = fixture();
        write_cert(&home, "cert.pem");
        let paths = Paths::for_test(&home).with_env("TUNNEL_ORIGIN_CERT", "/nowhere/gone.pem");
        let status = CloudflaredProbe::new(paths).status().unwrap();

        assert_eq!(status.active, None);
        assert!(
            status.notes.iter().any(|n| n.contains("does not exist")),
            "{:?}",
            status.notes
        );
    }

    #[test]
    fn test_the_tunnel_secret_and_the_certificate_never_reach_the_status() {
        let (_dir, home) = two_account_machine();
        let status = CloudflaredProbe::new(Paths::for_test(&home))
            .status()
            .unwrap();
        let json = serde_json::to_string(&status).unwrap();

        // The per-tunnel run secret, which is the thing that matters.
        assert!(
            !json.contains(FIXTURE_SECRET),
            "the TunnelSecret leaked: {json}"
        );
        // And no field carrying it. (The prose note naming the field is fine —
        // it is the promise, not the value, so this checks the JSON key form.)
        assert!(!json.contains(r#""TunnelSecret""#), "{json}");
        assert!(
            !status
                .profiles
                .iter()
                .any(|p| p.meta.to_string().to_lowercase().contains("secret")),
            "a profile's meta mentions a secret: {json}"
        );
        // The certificate's own bytes: never parsed, so never anywhere.
        assert!(
            !json.contains("ZmFrZS1wcml2YXRl"),
            "cert material leaked: {json}"
        );
        assert!(!json.contains("ARGO TUNNEL TOKEN"), "{json}");
    }

    #[test]
    fn test_tunnels_are_metadata_not_profiles() {
        let (_dir, home) = two_account_machine();
        let status = CloudflaredProbe::new(Paths::for_test(&home))
            .status()
            .unwrap();

        // Four tunnels across two accounts, still two profiles — one per cert.
        assert_eq!(status.profiles.len(), 2);
        for profile in &status.profiles {
            assert_eq!(profile.meta["tunnels_in_directory"], 4);
            assert_eq!(
                profile.meta["accounts_in_directory"],
                serde_json::json!(["acctA", "acctB"])
            );
            assert_eq!(profile.meta["tunnel_names"].as_array().unwrap().len(), 4);
        }
        assert!(
            status
                .notes
                .iter()
                .any(|n| n.contains("per-tunnel run secrets, not logins")),
            "{:?}",
            status.notes
        );
    }

    #[test]
    fn test_a_named_tunnel_is_shown_by_name() {
        let (_dir, home) = fixture();
        write_cert(&home, "cert.pem");
        fs::write(
            home.join(".cloudflared/11111111-1111-1111-1111-111111111111.json"),
            format!(
                r#"{{"AccountTag":"acctA","TunnelName":"prod-ingress","TunnelSecret":"{FIXTURE_SECRET}","TunnelID":"11111111-1111-1111-1111-111111111111"}}"#
            ),
        )
        .unwrap();

        let status = CloudflaredProbe::new(Paths::for_test(&home))
            .status()
            .unwrap();
        assert_eq!(
            status.profiles[0].meta["tunnel_names"],
            serde_json::json!(["prod-ingress"])
        );
    }

    #[test]
    fn test_config_yml_lands_in_meta_and_a_note() {
        let (_dir, home) = fixture();
        write_cert(&home, "cert.pem");
        fs::write(
            home.join(".cloudflared/config.yml"),
            "tunnel: prod-ingress\ncredentials-file: /Users/x/.cloudflared/abc.json\ningress:\n  - hostname: app.example.com\n    service: http://localhost:8080\n  - service: http_status:404\n",
        )
        .unwrap();

        let status = CloudflaredProbe::new(Paths::for_test(&home))
            .status()
            .unwrap();
        assert_eq!(status.profiles[0].meta["config_tunnel"], "prod-ingress");
        assert_eq!(status.profiles[0].meta["config_ingress_rules"], 2);
        assert!(
            status
                .notes
                .iter()
                .any(|n| n.contains("tunnel `prod-ingress`") && n.contains("2 ingress rule(s)")),
            "{:?}",
            status.notes
        );
    }

    #[test]
    fn test_tunnel_config_env_moves_the_config_file() {
        let (dir, home) = fixture();
        write_cert(&home, "cert.pem");
        let custom = dir.path().join("elsewhere.yml");
        fs::write(&custom, "tunnel: from-env\ningress: []\n").unwrap();

        let paths = Paths::for_test(&home).with_env("TUNNEL_CONFIG", custom.to_str().unwrap());
        let status = CloudflaredProbe::new(paths).status().unwrap();
        assert_eq!(status.profiles[0].meta["config_tunnel"], "from-env");
        assert!(status.notes.iter().any(|n| n.contains("TUNNEL_CONFIG")));
    }

    #[test]
    fn test_a_malformed_config_is_a_note_not_a_failure() {
        let (_dir, home) = fixture();
        write_cert(&home, "cert.pem");
        fs::write(home.join(".cloudflared/config.yml"), "tunnel: [unclosed\n").unwrap();

        let status = CloudflaredProbe::new(Paths::for_test(&home))
            .status()
            .unwrap();
        assert_eq!(status.active.as_deref(), Some("cert.pem"));
        assert!(
            status.notes.iter().any(|n| n.contains("not valid YAML")),
            "{:?}",
            status.notes
        );
    }

    #[test]
    fn test_unrelated_and_broken_json_is_skipped_quietly() {
        let (_dir, home) = fixture();
        write_cert(&home, "cert.pem");
        write_tunnel(&home, "11111111-1111-1111-1111-111111111111", "acctA");
        fs::write(
            home.join(".cloudflared/notes.json"),
            r#"{"unrelated":true}"#,
        )
        .unwrap();
        fs::write(home.join(".cloudflared/broken.json"), "{ not json").unwrap();

        let status = CloudflaredProbe::new(Paths::for_test(&home))
            .status()
            .unwrap();
        assert_eq!(status.profiles[0].meta["tunnels_in_directory"], 1);
    }

    #[test]
    fn test_tunnels_without_any_certificate_report_no_login() {
        let (_dir, home) = fixture();
        write_tunnel(&home, "11111111-1111-1111-1111-111111111111", "acctA");

        let status = CloudflaredProbe::new(Paths::for_test(&home))
            .status()
            .unwrap();
        assert!(status.profiles.is_empty());
        assert_eq!(status.active, None);
        assert!(
            status.notes.iter().any(|n| n.contains("tunnel login")),
            "{:?}",
            status.notes
        );
    }

    #[test]
    fn test_missing_directory_is_a_quiet_absence() {
        let dir = tempfile::tempdir().unwrap();
        let status = CloudflaredProbe::new(Paths::for_test(dir.path()))
            .status()
            .unwrap();
        assert!(!status.installed);
        assert!(status.profiles.is_empty());
        assert!(status.notes.is_empty());
    }

    #[test]
    fn test_switch_hands_back_the_export_line() {
        let (_dir, home) = two_account_machine();
        let probe = CloudflaredProbe::new(Paths::for_test(&home));

        match probe.switch("cert-pathors.pem").unwrap() {
            SwitchOutcome::Unsupported { hint, reason, .. } => {
                let hint = hint.unwrap();
                assert!(hint.starts_with("export TUNNEL_ORIGIN_CERT="), "{hint}");
                assert!(hint.ends_with(".cloudflared/cert-pathors.pem"), "{hint}");
                assert!(reason.contains("per command"), "{reason}");
            }
            other => panic!("expected Unsupported, got {other:?}"),
        }

        // A certificate that is not there is an unknown profile, not a hint to
        // export a path that does not exist.
        match probe.switch("cert-nope.pem").unwrap() {
            SwitchOutcome::UnknownProfile { available, .. } => {
                assert_eq!(available, vec!["cert-pathors.pem", "cert.pem"]);
            }
            other => panic!("expected UnknownProfile, got {other:?}"),
        }
    }

    #[test]
    fn test_verify_never_execs_in_a_test_context() {
        let (_dir, home) = two_account_machine();
        assert!(matches!(
            CloudflaredProbe::new(Paths::for_test(&home))
                .verify()
                .unwrap(),
            VerifyOutcome::Unsupported { .. }
        ));
    }
}
