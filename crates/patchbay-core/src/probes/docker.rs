//! `docker` — registry logins from `~/.docker/config.json`.
//!
//! Shape verified **empirically** on macOS (Docker Desktop): `auths` maps a
//! registry URL to an entry that is *empty* when a credential helper owns the
//! secret (`{"https://index.docker.io/v1/": {}}` plus a `credsStore` or
//! `credHelpers` key), and holds a base64 `auth` field when it does not.
//! `DOCKER_CONFIG` moves the directory.
//!
//! **There is no active registry.** `docker` talks to whichever registry the
//! image reference names, and every login stays live at once — so each registry
//! is a profile, `active` is `None`, and `switch` is unsupported by design.
//! That is the same shape as the rclone probe.
//!
//! The `auth` / `identitytoken` values are [`serde::de::IgnoredAny`]: patchbay
//! reports *where* the credential lives, never the credential.

use std::collections::BTreeMap;

use serde::Deserialize;

use crate::paths::Paths;
use crate::probe::{unsupported_switch, unsupported_verify, Probe};
use crate::types::{
    ActiveConcept, Expiry, PermissionsReport, Profile, SwitchOutcome, ToolStatus, VerifyOutcome,
};
use crate::util::read_text;

pub struct DockerProbe {
    paths: Paths,
}

#[derive(Deserialize, Default)]
struct Config {
    #[serde(default)]
    auths: BTreeMap<String, AuthEntry>,
    /// The helper that owns every registry unless overridden per registry.
    #[serde(default, rename = "credsStore")]
    creds_store: Option<String>,
    /// Per-registry helper, e.g. `{"asia-east1-docker.pkg.dev": "gcloud"}`.
    #[serde(default, rename = "credHelpers")]
    cred_helpers: BTreeMap<String, String>,
    #[serde(default, rename = "currentContext")]
    current_context: Option<String>,
}

#[derive(Deserialize, Default)]
struct AuthEntry {
    /// base64 of `user:password`. Presence only — never the value.
    #[serde(default)]
    auth: Option<serde::de::IgnoredAny>,
    #[serde(default)]
    identitytoken: Option<serde::de::IgnoredAny>,
    #[serde(default)]
    email: Option<String>,
}

impl DockerProbe {
    pub const TOOL: &'static str = "docker";

    pub fn new(paths: Paths) -> Self {
        Self { paths }
    }

    /// Where the secret for a registry actually lives.
    fn storage(config: &Config, registry: &str, entry: &AuthEntry) -> &'static str {
        if config.cred_helpers.contains_key(registry) {
            // The helper's own name is carried separately in `meta`.
            return "credential helper";
        }
        if entry.auth.is_some() {
            return "config.json";
        }
        if entry.identitytoken.is_some() {
            return "config.json (identity token)";
        }
        if config.creds_store.is_some() {
            return "credential store";
        }
        // An empty entry with nothing claiming it: Docker Desktop's platform
        // default helper (docker-credential-osxkeychain) usually holds it.
        "platform default helper"
    }
}

impl Probe for DockerProbe {
    fn tool(&self) -> &'static str {
        Self::TOOL
    }

    fn status(&self) -> anyhow::Result<ToolStatus> {
        let path = self.paths.docker_config();
        let installed = self.paths.has_binary("docker") || path.is_file();
        let mut status = ToolStatus::empty(Self::TOOL, installed);
        for note in self.paths.path_notes("docker") {
            status.push_note(note);
        }

        let text = match read_text(&path) {
            Ok(Some(text)) => text,
            Ok(None) => return Ok(status),
            Err(e) => {
                status.problem(e);
                return Ok(status);
            }
        };

        let config: Config = match serde_json::from_str(&text) {
            Ok(config) => config,
            Err(e) => {
                status.problem(format!("docker config.json is not valid JSON ({e})"));
                return Ok(status);
            }
        };

        let mut plaintext = Vec::new();
        for (registry, entry) in &config.auths {
            let storage = Self::storage(&config, registry, entry);
            if storage.starts_with("config.json") {
                plaintext.push(registry.clone());
            }
            status.profiles.push(
                Profile::new(registry)
                    .label(match registry.as_str() {
                        "https://index.docker.io/v1/" => "Docker Hub".to_string(),
                        other => other.to_string(),
                    })
                    // A registry login is a stored username/password or a
                    // helper-held token; neither records a deadline.
                    .expiry(Expiry::NoExpiry)
                    .with_meta("registry", registry.as_str())
                    .with_meta("credential_storage", storage)
                    .with_meta(
                        "helper",
                        config
                            .cred_helpers
                            .get(registry)
                            .cloned()
                            .or_else(|| config.creds_store.clone()),
                    )
                    .with_meta("email", entry.email.clone()),
            );
        }

        // Registries reachable only through a helper never appear under `auths`
        // until you log in, but the helper mapping is still a real fact.
        for (registry, helper) in &config.cred_helpers {
            if config.auths.contains_key(registry) {
                continue;
            }
            status.profiles.push(
                Profile::new(registry)
                    .label(format!("{registry} (via {helper})"))
                    .expiry(Expiry::NoExpiry)
                    .with_meta("registry", registry.as_str())
                    .with_meta("credential_storage", "credential helper")
                    .with_meta("helper", helper.as_str()),
            );
        }

        if status.profiles.is_empty() {
            return Ok(status);
        }

        // Deliberately left as None: see the module docs.
        status.active = None;
        status.active_concept = ActiveConcept::not_applicable(
            "every logged-in registry is used at once, chosen by the image reference",
        );
        if !plaintext.is_empty() {
            status.warn(format!(
                "credentials for {} are base64 in config.json rather than in a credential \
                 helper — base64 is encoding, not encryption",
                plaintext.join(", ")
            ));
        }
        if let Some(context) = &config.current_context {
            status.info(format!(
                "the active docker *context* (daemon endpoint) is `{context}`; that is a \
                 different thing from a registry login"
            ));
        }
        // The "no expiry is recorded" half of this now lives in `Expiry::NoExpiry`.
        // Revocation is a separate fact and nothing on this machine can see it.
        status.info("a helper-backed registry token may still have been revoked server-side");
        if status
            .profiles
            .iter()
            .any(|p| p.meta.get("credential_storage") == Some(&"platform default helper".into()))
        {
            status.info(
                "some entries name no credential store, so the secret is held by whichever helper \
                 the platform installs (docker-credential-osxkeychain on macOS) — or the entry is \
                 a leftover from a logout",
            );
        }

        Ok(status)
    }

    fn switch(&self, _profile_id: &str) -> anyhow::Result<SwitchOutcome> {
        Ok(unsupported_switch(
            Self::TOOL,
            "docker has no active registry to switch; every login is live at once and the image \
             reference picks the registry",
            Some("docker login <registry>"),
        ))
    }

    fn verify(&self) -> anyhow::Result<VerifyOutcome> {
        Ok(unsupported_verify(
            Self::TOOL,
            "verification needs a specific registry, which this call has no way to name",
            Some("docker login <registry>"),
        ))
    }

    fn permissions(&self) -> anyhow::Result<PermissionsReport> {
        Ok(PermissionsReport::unsupported(
            Self::TOOL,
            "push/pull rights belong to each registry's own account model, not to docker",
            Some("docker login <registry>"),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::NoteKind;
    use std::fs;
    use std::path::PathBuf;

    fn fixture(body: &str) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().to_path_buf();
        fs::create_dir_all(home.join(".docker")).unwrap();
        fs::write(home.join(".docker/config.json"), body).unwrap();
        (dir, home)
    }

    #[test]
    fn test_helper_backed_registries_become_profiles_with_no_active_one() {
        let (_dir, home) = fixture(
            r#"{
              "auths": { "https://index.docker.io/v1/": {} },
              "credsStore": "osxkeychain",
              "credHelpers": { "asia-east1-docker.pkg.dev": "gcloud" }
            }"#,
        );
        let status = DockerProbe::new(Paths::for_test(&home)).status().unwrap();
        let ids: Vec<_> = status.profiles.iter().map(|p| p.id.as_str()).collect();
        assert_eq!(
            ids,
            vec!["https://index.docker.io/v1/", "asia-east1-docker.pkg.dev"]
        );
        assert_eq!(status.profiles[0].label, "Docker Hub");
        assert_eq!(
            status.profiles[0].meta["credential_storage"],
            "credential store"
        );
        assert_eq!(status.profiles[0].meta["helper"], "osxkeychain");
        assert_eq!(status.profiles[1].meta["helper"], "gcloud");
        assert!(status.active.is_none());
        // The empty active slot is a property of docker, not a caveat to warn about.
        assert_eq!(
            status.active_concept,
            ActiveConcept::not_applicable(
                "every logged-in registry is used at once, chosen by the image reference"
            )
        );
        assert!(!status
            .notes
            .iter()
            .any(|n| n.text.contains("no active registry")));
        assert!(status
            .profiles
            .iter()
            .all(|p| p.expiry == Expiry::NoExpiry && p.expires_at().is_none()));
    }

    #[test]
    fn test_plaintext_auth_is_flagged_but_never_read() {
        let (_dir, home) = fixture(
            r#"{ "auths": { "registry.example.com": { "auth": "ZmFrZWZpeHR1cmU=", "email": "dev@example.com" } } }"#,
        );
        let status = DockerProbe::new(Paths::for_test(&home)).status().unwrap();
        assert_eq!(status.profiles[0].meta["credential_storage"], "config.json");
        assert_eq!(status.profiles[0].meta["email"], "dev@example.com");
        // A secret sitting in plain text is a risk, not a fact of life.
        assert!(status
            .notes
            .iter()
            .any(|n| n.kind == NoteKind::Warn && n.text.contains("base64 is encoding")));
        let json = serde_json::to_string(&status).unwrap();
        assert!(!json.contains("ZmFrZWZpeHR1cmU="), "{json}");
    }

    #[test]
    fn test_current_context_is_reported_as_a_different_thing() {
        let (_dir, home) =
            fixture(r#"{ "auths": { "registry.example.com": {} }, "currentContext": "colima" }"#);
        let status = DockerProbe::new(Paths::for_test(&home)).status().unwrap();
        assert!(status
            .notes
            .iter()
            .any(|n| n.kind == NoteKind::Info && n.text.contains("`colima`")));
    }

    #[test]
    fn test_missing_and_malformed_and_empty() {
        let dir = tempfile::tempdir().unwrap();
        let status = DockerProbe::new(Paths::for_test(dir.path()))
            .status()
            .unwrap();
        assert!(!status.installed);
        assert!(status.profiles.is_empty());
        assert!(status.notes.is_empty());

        let (_dir, home) = fixture("{ \"auths\": ");
        let status = DockerProbe::new(Paths::for_test(&home)).status().unwrap();
        assert!(status.installed);
        assert!(status
            .notes
            .iter()
            .any(|n| n.kind == NoteKind::Problem && n.text.contains("not valid JSON")));

        // A config with no logins at all is a normal, quiet state.
        let (_dir, home) = fixture(r#"{ "features": { "buildkit": true } }"#);
        let status = DockerProbe::new(Paths::for_test(&home)).status().unwrap();
        assert!(status.profiles.is_empty());
        assert!(status.notes.is_empty());
    }
}
