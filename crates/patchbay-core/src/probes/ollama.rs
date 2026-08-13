//! `ollama` — the local model daemon.
//!
//! Not installed on this machine; verified against ollama's own source
//! (`auth/auth.go`, `manifest/paths.go`, `envconfig/config.go`). What is on
//! disk under `~/.ollama`:
//!
//! * `id_ed25519` / `id_ed25519.pub` — the machine's key pair. `ollama signin`
//!   registers the *public* half with ollama.com; **no bearer token is ever
//!   written**, so the private key is the only secret and it is never opened.
//! * `models/manifests/<host>/<namespace>/<model>/<tag>` — one file per model.
//!   Counted with the same fixed four-level walk ollama itself uses.
//!
//! There is exactly one identity, so `active` is that one profile. There is no
//! expiry anywhere: nothing token-shaped is stored.
//!
//! `verify` shells out to `ollama --version`, which asks the local daemon
//! whether it is up. patchbay-core has no HTTP client and this is not worth
//! adding one for — `GET /api/version` and `ollama --version` answer the same
//! question, and the process route keeps the dependency graph honest.

use crate::paths::Paths;
use crate::probe::{unsupported_switch, unsupported_verify, Probe};
use crate::types::{PermissionsReport, Profile, SwitchOutcome, ToolStatus, VerifyOutcome};

pub struct OllamaProbe {
    paths: Paths,
}

impl OllamaProbe {
    pub const TOOL: &'static str = "ollama";
    const PROFILE_ID: &'static str = "default";

    pub fn new(paths: Paths) -> Self {
        Self { paths }
    }

    /// Count model manifests the way ollama does: everything at exactly
    /// `manifests/*/*/*/*` that is a file, corrupt entries tolerated.
    fn model_count(&self) -> usize {
        fn children(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
            std::fs::read_dir(dir)
                .map(|entries| entries.filter_map(|e| e.ok()).map(|e| e.path()).collect())
                .unwrap_or_default()
        }
        let manifests = self.paths.ollama_models_dir().join("manifests");
        let mut count = 0;
        for host in children(&manifests) {
            for namespace in children(&host) {
                for model in children(&namespace) {
                    count += children(&model).iter().filter(|p| p.is_file()).count();
                }
            }
        }
        count
    }
}

impl Probe for OllamaProbe {
    fn tool(&self) -> &'static str {
        Self::TOOL
    }

    fn status(&self) -> anyhow::Result<ToolStatus> {
        let dir = self.paths.ollama_dir();
        let installed = self.paths.has_binary("ollama") || dir.is_dir();
        let mut status = ToolStatus::empty(Self::TOOL, installed);
        for note in self.paths.path_notes("ollama") {
            status.note(note);
        }

        if !installed {
            return Ok(status);
        }

        // Presence of the public half is enough; neither file is opened.
        let has_key = dir.join("id_ed25519.pub").is_file() || dir.join("id_ed25519").is_file();
        let models = self.model_count();

        if !has_key && models == 0 && !dir.is_dir() {
            return Ok(status);
        }

        status.profiles.push(
            Profile::new(Self::PROFILE_ID)
                .label("this machine's ollama identity")
                .with_meta("has_signing_key", has_key)
                .with_meta("models", models)
                .with_meta(
                    "models_dir",
                    self.paths.ollama_models_dir().display().to_string(),
                ),
        );
        status.active = Some(Self::PROFILE_ID.to_string());

        if !has_key {
            status.note(
                "no id_ed25519 key pair yet; ollama creates one on first use and registers its \
                 public half when you run `ollama signin`"
                    .to_string(),
            );
        }
        if self.paths.env("OLLAMA_API_KEY").is_some() {
            status.note(
                "OLLAMA_API_KEY is set in the environment; that is the headless path and bypasses \
                 the local key pair"
                    .to_string(),
            );
        }
        status.note(
            "ollama stores no token and no expiry: requests are signed with the local key pair, \
             so `pb verify ollama` (is the daemon up?) is the only liveness answer"
                .to_string(),
        );

        Ok(status)
    }

    fn switch(&self, _profile_id: &str) -> anyhow::Result<SwitchOutcome> {
        Ok(unsupported_switch(
            Self::TOOL,
            "ollama has one identity per machine, tied to its local key pair",
            Some("ollama signin"),
        ))
    }

    fn verify(&self) -> anyhow::Result<VerifyOutcome> {
        if !self.paths.may_exec() || !self.paths.has_binary("ollama") {
            return Ok(unsupported_verify(
                Self::TOOL,
                "the ollama CLI is not available on PATH",
                Some("ollama --version"),
            ));
        }
        // `ollama --version` reports the client version and warns when it
        // cannot reach the local daemon — the same answer as GET /api/version,
        // without pulling an HTTP client into patchbay-core.
        let out = self.paths.run("ollama", &["--version"])?;
        let text = format!("{}\n{}", out.stdout, out.stderr);
        let unreachable = text.to_lowercase().contains("could not connect")
            || text.to_lowercase().contains("not running");
        Ok(if out.ok && !unreachable {
            VerifyOutcome::Valid {
                tool: Self::TOOL.to_string(),
                detail: out.message(),
            }
        } else {
            VerifyOutcome::Invalid {
                tool: Self::TOOL.to_string(),
                detail: format!("{} (start it with `ollama serve`)", out.message()),
            }
        })
    }

    fn permissions(&self) -> anyhow::Result<PermissionsReport> {
        Ok(PermissionsReport::unsupported(
            Self::TOOL,
            "a local ollama daemon has no permission model; what you may pull from ollama.com \
             follows the account the machine key is registered to",
            Some("ollama signin"),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::Path;

    fn model(home: &Path, host: &str, namespace: &str, name: &str, tag: &str) {
        let dir = home
            .join(".ollama/models/manifests")
            .join(host)
            .join(namespace)
            .join(name);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join(tag), "{\"layers\":[]}").unwrap();
    }

    #[test]
    fn test_models_are_counted_and_the_key_is_only_noticed() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        fs::create_dir_all(home.join(".ollama")).unwrap();
        fs::write(
            home.join(".ollama/id_ed25519"),
            "PRIVATE-KEY-FIXTURE-DO-NOT-READ",
        )
        .unwrap();
        fs::write(
            home.join(".ollama/id_ed25519.pub"),
            "ssh-ed25519 AAAAfixture",
        )
        .unwrap();
        model(home, "registry.ollama.ai", "library", "llama3", "latest");
        model(home, "registry.ollama.ai", "library", "llama3", "70b");
        model(home, "registry.ollama.ai", "library", "qwen3", "latest");

        let status = OllamaProbe::new(Paths::for_test(home)).status().unwrap();
        assert!(status.installed);
        assert_eq!(status.active.as_deref(), Some("default"));
        assert_eq!(status.profiles[0].meta["models"], 3);
        assert_eq!(status.profiles[0].meta["has_signing_key"], true);
        assert!(status.profiles[0].expires_at.is_none());

        let json = serde_json::to_string(&status).unwrap();
        assert!(!json.contains("PRIVATE-KEY-FIXTURE"), "{json}");
    }

    #[test]
    fn test_manifest_walk_ignores_the_wrong_depth() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        // A stray file two levels up is not a model.
        let manifests = home.join(".ollama/models/manifests/registry.ollama.ai");
        fs::create_dir_all(&manifests).unwrap();
        fs::write(manifests.join("stray"), "x").unwrap();
        model(home, "registry.ollama.ai", "library", "llama3", "latest");

        let status = OllamaProbe::new(Paths::for_test(home)).status().unwrap();
        assert_eq!(status.profiles[0].meta["models"], 1);
    }

    #[test]
    fn test_models_dir_override_is_followed() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        fs::create_dir_all(home.join(".ollama")).unwrap();
        let elsewhere = home.join("big-disk/models/manifests/registry.ollama.ai/library/x");
        fs::create_dir_all(&elsewhere).unwrap();
        fs::write(elsewhere.join("latest"), "{}").unwrap();

        let paths = Paths::for_test(home).with_env(
            "OLLAMA_MODELS",
            home.join("big-disk/models").to_str().unwrap(),
        );
        let status = OllamaProbe::new(paths).status().unwrap();
        assert_eq!(status.profiles[0].meta["models"], 1);
    }

    #[test]
    fn test_absent_machine_and_a_bare_directory() {
        let dir = tempfile::tempdir().unwrap();
        let status = OllamaProbe::new(Paths::for_test(dir.path()))
            .status()
            .unwrap();
        assert!(!status.installed);
        assert!(status.profiles.is_empty());
        assert!(status.notes.is_empty());

        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join(".ollama")).unwrap();
        let status = OllamaProbe::new(Paths::for_test(dir.path()))
            .status()
            .unwrap();
        assert!(status.installed);
        assert_eq!(status.profiles[0].meta["models"], 0);
        assert!(status.notes.iter().any(|n| n.contains("no id_ed25519")));
    }

    #[test]
    fn test_tier_two_is_unsupported_without_exec() {
        let dir = tempfile::tempdir().unwrap();
        let probe = OllamaProbe::new(Paths::for_test(dir.path()));
        assert!(matches!(
            probe.verify().unwrap(),
            VerifyOutcome::Unsupported { .. }
        ));
        assert!(!probe.permissions().unwrap().supported);
    }
}
