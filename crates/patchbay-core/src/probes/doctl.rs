//! `doctl` — DigitalOcean's named auth contexts.
//!
//! Not installed on this machine; verified against the CLI's source
//! (`commands/command_config.go`, `commands/doit.go`) and its README. On macOS
//! the file is `~/Library/Application Support/doctl/config.yaml` — Go's
//! `os.UserConfigDir` does not consult `XDG_CONFIG_HOME` on Darwin, whatever
//! doctl's own help text says.
//!
//! **The trap.** The `default` context's token is stored at the *top level* as
//! `access-token` and is **absent from `auth-contexts`**. `doctl auth list`
//! synthesizes it back in; a probe that just lists the map under-reports by
//! one, and misses the most common setup entirely. This probe synthesizes it
//! the same way.
//!
//! ```yaml
//! context: pathors-team
//! access-token: dop_v1_...
//! auth-contexts:
//!   pathors-team: dop_v1_...
//! api-url: ""
//! ```
//!
//! Every token value — top level and map values alike — is presence-only. The
//! *keys* of `auth-contexts` are context names and are exactly what a probe
//! wants. There are no expiry timestamps anywhere in the file.

use std::collections::BTreeMap;

use serde::Deserialize;

use crate::paths::Paths;
use crate::probe::{unknown_profile, unsupported_switch, unsupported_verify, Probe};
use crate::types::{Expiry, PermissionsReport, Profile, SwitchOutcome, ToolStatus, VerifyOutcome};
use crate::util::read_text;

pub struct DoctlProbe {
    paths: Paths,
}

#[derive(Deserialize, Default)]
struct Config {
    /// The active context. Always lower-cased by doctl; defaults to `default`.
    #[serde(default)]
    context: Option<String>,
    /// The `default` context's token. Presence only.
    #[serde(default, rename = "access-token")]
    access_token: Option<serde::de::IgnoredAny>,
    /// Name -> token. Only the names are ever used.
    #[serde(default, rename = "auth-contexts")]
    auth_contexts: BTreeMap<String, serde::de::IgnoredAny>,
    #[serde(default, rename = "api-url")]
    api_url: Option<String>,
}

impl DoctlProbe {
    pub const TOOL: &'static str = "doctl";
    /// The context doctl falls back to, and the one that is invisible in the
    /// `auth-contexts` map.
    const DEFAULT_CONTEXT: &'static str = "default";

    pub fn new(paths: Paths) -> Self {
        Self { paths }
    }
}

impl Probe for DoctlProbe {
    fn tool(&self) -> &'static str {
        Self::TOOL
    }

    fn status(&self) -> anyhow::Result<ToolStatus> {
        let path = self.paths.doctl_config();
        let installed = self.paths.has_binary("doctl") || path.is_file();
        let mut status = ToolStatus::empty(Self::TOOL, installed);
        for note in self.paths.path_notes("doctl") {
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

        let config: Config = match serde_yaml_ng::from_str(&text) {
            Ok(config) => config,
            Err(e) => {
                status.problem(format!("doctl config.yaml is not valid YAML ({e})"));
                return Ok(status);
            }
        };

        // The default context is real but never listed; put it back first so
        // the order matches `doctl auth list`.
        if config.access_token.is_some() {
            status.profiles.push(
                Profile::new(Self::DEFAULT_CONTEXT)
                    .label("default context")
                    // DigitalOcean personal access tokens are dateless: they
                    // live until someone revokes them.
                    .expiry(Expiry::NoExpiry)
                    .with_meta("token_storage", "config.yaml (top-level access-token)")
                    .with_meta("api_url", config.api_url.clone().filter(|u| !u.is_empty())),
            );
        }
        for name in config.auth_contexts.keys() {
            if name == Self::DEFAULT_CONTEXT {
                continue;
            }
            status.profiles.push(
                Profile::new(name.as_str())
                    .expiry(Expiry::NoExpiry)
                    .with_meta("token_storage", "config.yaml (auth-contexts)")
                    .with_meta("api_url", config.api_url.clone().filter(|u| !u.is_empty())),
            );
        }

        if status.profiles.is_empty() {
            if !text.trim().is_empty() {
                status.info("doctl config.yaml holds no access token");
            }
            return Ok(status);
        }

        // `context` is optional; doctl treats its absence as `default`.
        let active = config
            .context
            .map(|c| c.to_lowercase())
            .unwrap_or_else(|| Self::DEFAULT_CONTEXT.to_string());
        if let Some(context) = self.paths.env("DIGITALOCEAN_CONTEXT") {
            status.warn(format!(
                "DIGITALOCEAN_CONTEXT={context} is set and overrides the context recorded in the \
                 file"
            ));
        }
        if self.paths.env("DIGITALOCEAN_ACCESS_TOKEN").is_some() {
            status.warn(
                "DIGITALOCEAN_ACCESS_TOKEN is set in the environment and takes precedence over \
                 every stored context",
            );
        }
        if status.profiles.iter().any(|p| p.id == active) {
            status.active = Some(active);
        } else {
            // A pointer at a context that is not here: doctl will fail.
            status.problem(format!(
                "the recorded context `{active}` has no token in this file"
            ));
        }

        status.warn("doctl keeps its tokens in plain text in config.yaml");

        Ok(status)
    }

    fn switch(&self, profile_id: &str) -> anyhow::Result<SwitchOutcome> {
        let status = self.status()?;
        if !status.profiles.iter().any(|p| p.id == profile_id) {
            return Ok(unknown_profile(Self::TOOL, profile_id, &status));
        }
        // `doctl auth switch` rewrites the same file patchbay just read, and
        // the CLI is the only thing that should own that file's layout.
        Ok(unsupported_switch(
            Self::TOOL,
            "patchbay does not rewrite doctl's config.yaml; the CLI owns that file",
            Some(&format!("doctl auth switch --context {profile_id}")),
        ))
    }

    fn verify(&self) -> anyhow::Result<VerifyOutcome> {
        Ok(unsupported_verify(
            Self::TOOL,
            "patchbay does not run doctl yet; `doctl account get` is a network call",
            Some("doctl account get"),
        ))
    }

    fn permissions(&self) -> anyhow::Result<PermissionsReport> {
        Ok(PermissionsReport::unsupported(
            Self::TOOL,
            "a DigitalOcean token's scopes are set when it is created and are not recorded on \
             disk",
            Some("the API tokens page of the DigitalOcean control panel"),
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
        fs::create_dir_all(home.join("Library/Application Support/doctl")).unwrap();
        fs::write(
            home.join("Library/Application Support/doctl/config.yaml"),
            body,
        )
        .unwrap();
        (dir, home)
    }

    #[test]
    fn test_default_context_is_synthesized_from_the_top_level_token() {
        let (_dir, home) = fixture(
            "context: pathors-team\n\
             access-token: dop_v1_fakefixturedefault\n\
             auth-contexts:\n  \
               pathors-team: dop_v1_fakefixtureteam\n  \
               cerana: dop_v1_fakefixturecerana\n\
             api-url: \"\"\n",
        );
        let status = DoctlProbe::new(Paths::for_test(&home)).status().unwrap();
        let ids: Vec<_> = status.profiles.iter().map(|p| p.id.as_str()).collect();
        // `default` is not in the map, and would be missed by a naive probe.
        assert_eq!(ids, vec!["default", "cerana", "pathors-team"]);
        assert_eq!(status.active.as_deref(), Some("pathors-team"));
        // Dateless by design, which is a different claim from "we don't know".
        assert!(status.profiles.iter().all(|p| p.expiry == Expiry::NoExpiry));
        // The expiry explanation now lives in the type, not in a note.
        assert!(!status.notes.iter().any(|n| n.text.contains("no expiry")));

        let json = serde_json::to_string(&status).unwrap();
        for secret in [
            "dop_v1_fakefixturedefault",
            "dop_v1_fakefixtureteam",
            "dop_v1_fakefixturecerana",
        ] {
            assert!(!json.contains(secret), "leaked {secret}");
        }
    }

    #[test]
    fn test_a_bare_default_login_still_shows_up() {
        let (_dir, home) = fixture("access-token: dop_v1_fakefixture\n");
        let status = DoctlProbe::new(Paths::for_test(&home)).status().unwrap();
        assert_eq!(status.profiles.len(), 1);
        assert_eq!(status.active.as_deref(), Some("default"));
    }

    #[test]
    fn test_environment_overrides_are_called_out() {
        let (_dir, home) = fixture("access-token: dop_v1_fakefixture\n");
        let paths = Paths::for_test(&home)
            .with_env("DIGITALOCEAN_CONTEXT", "other")
            .with_env("DIGITALOCEAN_ACCESS_TOKEN", "dop_v1_fakefixtureenv");
        let status = DoctlProbe::new(paths).status().unwrap();
        for text in ["DIGITALOCEAN_CONTEXT=other", "DIGITALOCEAN_ACCESS_TOKEN"] {
            let note = status
                .notes
                .iter()
                .find(|n| n.text.contains(text))
                .unwrap_or_else(|| panic!("no note about {text}"));
            assert_eq!(note.kind, NoteKind::Warn, "{text}");
        }
        let json = serde_json::to_string(&status).unwrap();
        assert!(!json.contains("dop_v1_fakefixtureenv"), "{json}");
    }

    #[test]
    fn test_context_pointing_at_nothing_is_reported() {
        let (_dir, home) = fixture("context: ghost\naccess-token: dop_v1_fakefixture\n");
        let status = DoctlProbe::new(Paths::for_test(&home)).status().unwrap();
        assert!(status.active.is_none());
        // A dangling context pointer is broken configuration.
        let dangling = status
            .notes
            .iter()
            .find(|n| n.text.contains("`ghost` has no token"))
            .expect("the dangling context is reported");
        assert_eq!(dangling.kind, NoteKind::Problem);
    }

    #[test]
    fn test_missing_malformed_and_tokenless() {
        let dir = tempfile::tempdir().unwrap();
        let status = DoctlProbe::new(Paths::for_test(dir.path()))
            .status()
            .unwrap();
        assert!(!status.installed);
        assert!(status.profiles.is_empty());

        let (_dir, home) = fixture("context: [unclosed\n");
        let status = DoctlProbe::new(Paths::for_test(&home)).status().unwrap();
        let malformed = status
            .notes
            .iter()
            .find(|n| n.text.contains("not valid YAML"))
            .expect("the parse failure is reported");
        assert_eq!(malformed.kind, NoteKind::Problem);

        let (_dir, home) = fixture("output: text\n");
        let status = DoctlProbe::new(Paths::for_test(&home)).status().unwrap();
        assert!(status.profiles.is_empty());
        let tokenless = status
            .notes
            .iter()
            .find(|n| n.text.contains("no access token"))
            .expect("the tokenless file is explained");
        assert_eq!(tokenless.kind, NoteKind::Info);
    }

    #[test]
    fn test_switch_names_the_command_and_rejects_unknown_contexts() {
        let (_dir, home) = fixture("access-token: dop_v1_fakefixture\n");
        let probe = DoctlProbe::new(Paths::for_test(&home));
        assert!(matches!(
            probe.switch("nope").unwrap(),
            SwitchOutcome::UnknownProfile { .. }
        ));
        assert!(matches!(
            probe.switch("default").unwrap(),
            SwitchOutcome::Unsupported { .. }
        ));
    }
}
