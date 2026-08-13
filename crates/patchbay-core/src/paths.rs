//! Every filesystem location and environment lookup a probe is allowed to make.
//!
//! Probes never touch `std::env` or the real home directory directly — they are
//! constructed with a `Paths` and read only through it. That is what makes the
//! unit tests hermetic: they hand a probe a tempdir and a fake environment.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Whether `installed` detection may consult the real `PATH`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinaryLookup {
    /// Ask the OS (`which`). Used in production.
    System,
    /// Never look. Used in tests so results depend only on the fixture home.
    Disabled,
}

#[derive(Debug, Clone)]
pub struct Paths {
    home: PathBuf,
    env: HashMap<String, String>,
    lookup: BinaryLookup,
}

impl Paths {
    /// Real machine: real home, real environment, real `PATH` lookups.
    pub fn detect() -> anyhow::Result<Self> {
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .ok_or_else(|| anyhow::anyhow!("HOME is not set; cannot locate CLI config files"))?;
        Ok(Self {
            home,
            env: std::env::vars().collect(),
            lookup: BinaryLookup::System,
        })
    }

    /// Test constructor: fixture home, empty environment, no `PATH` lookups.
    pub fn for_test(home: impl Into<PathBuf>) -> Self {
        Self {
            home: home.into(),
            env: HashMap::new(),
            lookup: BinaryLookup::Disabled,
        }
    }

    pub fn with_env(mut self, key: &str, value: &str) -> Self {
        self.env.insert(key.to_string(), value.to_string());
        self
    }

    pub fn home(&self) -> &Path {
        &self.home
    }

    pub fn env(&self, key: &str) -> Option<&str> {
        self.env
            .get(key)
            .map(|s| s.as_str())
            .filter(|s| !s.is_empty())
    }

    /// `true` when the binary is on `PATH`. Always `false` in tests.
    pub fn has_binary(&self, name: &str) -> bool {
        match self.lookup {
            BinaryLookup::System => which::which(name).is_ok(),
            BinaryLookup::Disabled => false,
        }
    }

    /// Whether probes are allowed to execute the tool's own CLI. Tier-2
    /// operations short-circuit to `Unsupported` when this is false.
    pub fn may_exec(&self) -> bool {
        self.lookup == BinaryLookup::System
    }

    fn join(&self, rel: &str) -> PathBuf {
        self.home.join(rel)
    }

    // --- per-tool locations -------------------------------------------------
    // Centralised here so a Linux/Windows port is a change in one file.

    /// `CLOUDSDK_CONFIG` wins, else `~/.config/gcloud`.
    pub fn gcloud_dir(&self) -> PathBuf {
        match self.env("CLOUDSDK_CONFIG") {
            Some(dir) => PathBuf::from(dir),
            None => self.join(".config/gcloud"),
        }
    }

    /// `AWS_CONFIG_FILE` wins, else `~/.aws/config`.
    pub fn aws_config(&self) -> PathBuf {
        match self.env("AWS_CONFIG_FILE") {
            Some(p) => PathBuf::from(p),
            None => self.join(".aws/config"),
        }
    }

    /// `AWS_SHARED_CREDENTIALS_FILE` wins, else `~/.aws/credentials`.
    pub fn aws_credentials(&self) -> PathBuf {
        match self.env("AWS_SHARED_CREDENTIALS_FILE") {
            Some(p) => PathBuf::from(p),
            None => self.join(".aws/credentials"),
        }
    }

    pub fn aws_sso_cache_dir(&self) -> PathBuf {
        self.join(".aws/sso/cache")
    }

    pub fn gh_hosts(&self) -> PathBuf {
        match self.env("GH_CONFIG_DIR") {
            Some(dir) => PathBuf::from(dir).join("hosts.yml"),
            None => self.join(".config/gh/hosts.yml"),
        }
    }

    pub fn infisical_config(&self) -> PathBuf {
        self.join(".infisical/infisical-config.json")
    }

    /// Kubeconfig search list. `KUBECONFIG` is a `:`-separated list of files
    /// that kubectl merges; when unset the single default is used.
    pub fn kube_configs(&self) -> Vec<PathBuf> {
        match self.env("KUBECONFIG") {
            Some(list) => list
                .split(':')
                .filter(|s| !s.trim().is_empty())
                .map(PathBuf::from)
                .collect(),
            None => vec![self.join(".kube/config")],
        }
    }

    /// Wrangler's global config, newest location first.
    pub fn wrangler_candidates(&self) -> Vec<PathBuf> {
        vec![
            self.join("Library/Preferences/.wrangler/config/default.toml"),
            self.join(".wrangler/config/default.toml"),
        ]
    }

    pub fn rclone_conf(&self) -> PathBuf {
        match self.env("RCLONE_CONFIG") {
            Some(p) => PathBuf::from(p),
            None => self.join(".config/rclone/rclone.conf"),
        }
    }

    pub fn azure_profile(&self) -> PathBuf {
        match self.env("AZURE_CONFIG_DIR") {
            Some(dir) => PathBuf::from(dir).join("azureProfile.json"),
            None => self.join(".azure/azureProfile.json"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_paths_never_touch_the_real_home() {
        let p = Paths::for_test("/nowhere");
        assert_eq!(p.gcloud_dir(), PathBuf::from("/nowhere/.config/gcloud"));
        assert!(!p.has_binary("sh"));
        assert!(p.env("HOME").is_none());
    }

    #[test]
    fn test_env_overrides_win() {
        let p = Paths::for_test("/nowhere").with_env("CLOUDSDK_CONFIG", "/custom/gcloud");
        assert_eq!(p.gcloud_dir(), PathBuf::from("/custom/gcloud"));
    }

    #[test]
    fn test_kubeconfig_list_is_split() {
        let p = Paths::for_test("/nowhere").with_env("KUBECONFIG", "/a.yaml:/b.yaml");
        assert_eq!(
            p.kube_configs(),
            vec![PathBuf::from("/a.yaml"), PathBuf::from("/b.yaml")]
        );
    }
}
