//! Every filesystem location and environment lookup a probe is allowed to make.
//!
//! Probes never touch `std::env` or the real home directory directly — they are
//! constructed with a `Paths` and read only through it. That is what makes the
//! unit tests hermetic: they hand a probe a tempdir and a fake environment.
//!
//! # Where a path comes from
//!
//! Three layers, highest first:
//!
//! 1. **The tool's own environment variable** — `CLOUDSDK_CONFIG`,
//!    `AWS_CONFIG_FILE`, `DOCKER_CONFIG`, `KUBECONFIG`, … A probe must mirror
//!    what the CLI itself reads; disagreeing with the variable the CLI obeys
//!    would make the board lie.
//! 2. **patchbay's own config**, `~/.config/patchbay/config.toml`:
//!
//!    ```toml
//!    [paths]
//!    gcloud = "/Volumes/work/gcloud"
//!    aws_config = "/Volumes/work/aws/config"
//!    ```
//!
//!    This layer exists mostly for the desktop app: launched from Finder it
//!    inherits none of your shell's environment, so the variables in layer 1
//!    are simply not there.
//! 3. **The platform default** — `~/.config/gcloud`, `~/.aws/config`, … with
//!    `XDG_CONFIG_HOME` honoured for the tools that actually respect it
//!    (verified per tool; it is *not* applied blanket, because gcloud for one
//!    ignores it).
//!
//! An override in effect is never silent: [`Paths::path_notes`] returns a line
//! naming it, and every probe puts that line in its `ToolStatus`.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};

/// Whether `installed` detection may consult the real `PATH`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinaryLookup {
    /// Ask the OS (`which`). Used in production.
    System,
    /// Never look. Used in tests so results depend only on the fixture home.
    Disabled,
    /// Every binary is "present" and tier 2 is allowed, but execution goes to
    /// a scripted [`crate::util::Exec`]. Used by tests that need to exercise a
    /// verify path without a subprocess.
    Scripted,
}

/// One overridable location: the key used in `[paths]`, and the environment
/// variable the tool's own CLI reads for it (`None` when the tool has none).
///
/// This table is the single source of truth for both resolution and
/// validation, so a key that resolves is a key `config.toml` accepts.
const LOCATIONS: &[(&str, Option<&str>)] = &[
    ("gcloud", Some("CLOUDSDK_CONFIG")),
    ("aws_config", Some("AWS_CONFIG_FILE")),
    ("aws_credentials", Some("AWS_SHARED_CREDENTIALS_FILE")),
    ("gh", Some("GH_CONFIG_DIR")),
    ("infisical", None),
    ("kubeconfig", Some("KUBECONFIG")),
    ("wrangler", None),
    ("rclone", Some("RCLONE_CONFIG")),
    ("azure", Some("AZURE_CONFIG_DIR")),
    ("vercel", None),
    ("firebase", None),
    ("neon", None),
    ("docker", Some("DOCKER_CONFIG")),
    ("tailscale", None),
    ("ssh", None),
    ("stripe", None),
    ("supabase", Some("SUPABASE_HOME")),
    ("fly", Some("FLY_CONFIG_DIR")),
    ("doctl", None),
    ("npm", Some("NPM_CONFIG_USERCONFIG")),
    ("op", Some("OP_CONFIG_DIR")),
    ("ollama", None),
    ("huggingface", Some("HF_HOME")),
    ("claude", Some("CLAUDE_CONFIG_DIR")),
    ("ngrok", Some("NGROK_CONFIG")),
    ("cloudflared", None),
    ("cloudflared_config", Some("TUNNEL_CONFIG")),
];

fn env_var_for(key: &str) -> Option<&'static str> {
    LOCATIONS
        .iter()
        .find(|(k, _)| *k == key)
        .and_then(|(_, var)| *var)
}

#[derive(Debug, Clone)]
pub struct Paths {
    home: PathBuf,
    env: HashMap<String, String>,
    lookup: BinaryLookup,
    /// The `[paths]` table of patchbay's own config, already validated.
    overrides: BTreeMap<String, PathBuf>,
    /// Problems with that config: a malformed file, an unknown key. Reported,
    /// never fatal — a typo must not blank the board.
    config_warnings: Vec<String>,
    /// How this `Paths` runs other tools' CLIs.
    exec: crate::util::SharedExec,
}

impl Paths {
    /// Real machine: real home, real environment, real `PATH` lookups, plus
    /// `~/.config/patchbay/config.toml` if it exists.
    pub fn detect() -> anyhow::Result<Self> {
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .ok_or_else(|| anyhow::anyhow!("HOME is not set; cannot locate CLI config files"))?;
        Ok(Self::from_env(home, std::env::vars().collect(), BinaryLookup::System).load_config())
    }

    /// Explicit home + environment. The only constructor that takes an
    /// environment map; `std::env` is read in [`Paths::detect`] and nowhere
    /// else, which is what keeps the probes' tests hermetic.
    pub fn from_env(
        home: impl Into<PathBuf>,
        env: HashMap<String, String>,
        lookup: BinaryLookup,
    ) -> Self {
        Self {
            home: home.into(),
            env,
            lookup,
            overrides: BTreeMap::new(),
            config_warnings: Vec::new(),
            exec: std::sync::Arc::new(crate::util::SystemExec),
        }
    }

    /// Test constructor: fixture home, empty environment, no `PATH` lookups,
    /// no config file (call [`Paths::load_config`] to opt into one).
    pub fn for_test(home: impl Into<PathBuf>) -> Self {
        Self::from_env(home, HashMap::new(), BinaryLookup::Disabled)
    }

    pub fn with_env(mut self, key: &str, value: &str) -> Self {
        self.env.insert(key.to_string(), value.to_string());
        self
    }

    /// Apply the `[paths]` table of `<patchbay config dir>/config.toml`.
    /// Missing file: nothing happens. Malformed file or unknown key: a warning,
    /// and the rest of the table still applies.
    pub fn load_config(mut self) -> Self {
        let path = self.patchbay_dir().join("config.toml");
        let text = match crate::util::read_text(&path) {
            Ok(Some(text)) => text,
            Ok(None) => return self,
            Err(e) => {
                self.config_warnings.push(format!("patchbay config: {e}"));
                return self;
            }
        };

        #[derive(serde::Deserialize)]
        struct Config {
            #[serde(default)]
            paths: BTreeMap<String, String>,
        }

        let config: Config = match toml::from_str(&text) {
            Ok(config) => config,
            Err(e) => {
                self.config_warnings.push(format!(
                    "patchbay config: {} is not valid TOML ({e}); its [paths] overrides were \
                     ignored",
                    path.display()
                ));
                return self;
            }
        };

        for (key, value) in config.paths {
            if LOCATIONS.iter().any(|(k, _)| *k == key) {
                self.overrides.insert(key, PathBuf::from(value));
            } else {
                self.config_warnings.push(format!(
                    "patchbay config: unknown key `{key}` in the [paths] table of {}; known \
                     keys: {}",
                    path.display(),
                    LOCATIONS
                        .iter()
                        .map(|(k, _)| *k)
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
            }
        }
        self
    }

    /// Set one `[paths]` override directly. For tests, and for callers that
    /// have their own configuration story.
    pub fn with_path_override(mut self, key: &str, path: impl Into<PathBuf>) -> Self {
        debug_assert!(
            LOCATIONS.iter().any(|(k, _)| *k == key),
            "unknown path key `{key}`"
        );
        self.overrides.insert(key.to_string(), path.into());
        self
    }

    /// Problems found while reading patchbay's own config. Surfaced on the
    /// board by [`crate::Registry::status_all`].
    pub fn config_warnings(&self) -> &[String] {
        &self.config_warnings
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

    /// `true` when the binary is on `PATH`. Always `false` in plain tests, and
    /// always `true` when a scripted exec is in force — the fake decides what
    /// running it does.
    pub fn has_binary(&self, name: &str) -> bool {
        match self.lookup {
            BinaryLookup::System => which::which(name).is_ok(),
            BinaryLookup::Disabled => false,
            BinaryLookup::Scripted => true,
        }
    }

    /// Where the binary is, not just whether it exists. Version checking needs
    /// the path itself: it is what says whether Homebrew, npm, bun or the
    /// vendor's own installer put it there. `None` in tests, like
    /// [`Paths::has_binary`].
    pub fn binary_path(&self, name: &str) -> Option<PathBuf> {
        match self.lookup {
            BinaryLookup::System => which::which(name).ok(),
            BinaryLookup::Disabled => None,
        }
    }

    /// Whether probes are allowed to execute the tool's own CLI. Tier-2
    /// operations short-circuit to `Unsupported` when this is false.
    pub fn may_exec(&self) -> bool {
        matches!(self.lookup, BinaryLookup::System | BinaryLookup::Scripted)
    }

    /// Run another tool's CLI through whichever [`crate::util::Exec`] is in
    /// force. **Every probe uses this rather than [`crate::util::run`]**, which
    /// is what keeps the test suite out of subprocesses.
    pub fn run(&self, bin: &str, args: &[&str]) -> anyhow::Result<crate::util::CmdOutput> {
        self.exec.run(bin, args, &[])
    }

    /// [`Paths::run`], with extra environment for the child process only.
    ///
    /// patchbay cannot change the parent shell's environment, but the command
    /// *it* runs is its own — which is how "verify that profile" works for the
    /// tools that select an identity through a variable.
    pub fn run_env(
        &self,
        bin: &str,
        args: &[&str],
        env: &[(&str, &str)],
    ) -> anyhow::Result<crate::util::CmdOutput> {
        self.exec.run(bin, args, env)
    }

    /// Replace the exec. Tests pass a [`crate::util::FakeExec`]; doing so also
    /// switches binary lookup to [`BinaryLookup::Scripted`], so the probe takes
    /// its tier-2 path instead of short-circuiting.
    pub fn with_exec(mut self, exec: crate::util::SharedExec) -> Self {
        self.exec = exec;
        self.lookup = BinaryLookup::Scripted;
        self
    }

    fn join(&self, rel: &str) -> PathBuf {
        self.home.join(rel)
    }

    /// The three-layer lookup. `default` is only evaluated when neither the
    /// tool's environment variable nor patchbay's config has an opinion.
    fn resolve(&self, key: &str, default: impl FnOnce() -> PathBuf) -> PathBuf {
        if let Some(value) = env_var_for(key).and_then(|var| self.env(var)) {
            return PathBuf::from(value);
        }
        if let Some(path) = self.overrides.get(key) {
            return path.clone();
        }
        default()
    }

    /// Human-readable note for a non-default location, empty when the default
    /// is in force. Every probe forwards this into its `ToolStatus.notes`, so
    /// "why is it reading *that* file" is answered on the board.
    pub fn path_notes(&self, key: &str) -> Vec<String> {
        if let Some((var, value)) = env_var_for(key).and_then(|var| Some((var, self.env(var)?))) {
            return vec![format!(
                "reading {key} state from ${var}={value} rather than the default location"
            )];
        }
        if let Some(path) = self.overrides.get(key) {
            return vec![format!(
                "reading {key} state from {} (set by the [paths] table of {})",
                path.display(),
                self.patchbay_dir().join("config.toml").display()
            )];
        }
        Vec::new()
    }

    /// The XDG config root: `XDG_CONFIG_HOME` when set, else `~/.config`.
    /// Only used for the tools verified to respect it — gcloud, for one,
    /// does not.
    fn xdg_config(&self) -> PathBuf {
        match self.env("XDG_CONFIG_HOME") {
            Some(dir) => PathBuf::from(dir),
            None => self.join(".config"),
        }
    }

    // --- per-tool locations -------------------------------------------------
    // Centralised here so a Linux/Windows port is a change in one file.

    /// `CLOUDSDK_CONFIG` wins, else `~/.config/gcloud`. gcloud hard-codes that
    /// directory and does **not** consult `XDG_CONFIG_HOME`.
    pub fn gcloud_dir(&self) -> PathBuf {
        self.resolve("gcloud", || self.join(".config/gcloud"))
    }

    /// `AWS_CONFIG_FILE` wins, else `~/.aws/config`.
    pub fn aws_config(&self) -> PathBuf {
        self.resolve("aws_config", || self.join(".aws/config"))
    }

    /// `AWS_SHARED_CREDENTIALS_FILE` wins, else `~/.aws/credentials`.
    /// Deliberately a separate key: the two files move independently.
    pub fn aws_credentials(&self) -> PathBuf {
        self.resolve("aws_credentials", || self.join(".aws/credentials"))
    }

    pub fn aws_sso_cache_dir(&self) -> PathBuf {
        self.join(".aws/sso/cache")
    }

    /// `GH_CONFIG_DIR` names the directory; gh also honours `XDG_CONFIG_HOME`.
    pub fn gh_hosts(&self) -> PathBuf {
        self.resolve("gh", || self.xdg_config().join("gh"))
            .join("hosts.yml")
    }

    pub fn infisical_config(&self) -> PathBuf {
        self.resolve("infisical", || {
            self.join(".infisical/infisical-config.json")
        })
    }

    /// Kubeconfig search list. `KUBECONFIG` is a `:`-separated list of files
    /// that kubectl merges; when unset the single default is used. A `[paths]`
    /// override may be a list too.
    pub fn kube_configs(&self) -> Vec<PathBuf> {
        fn split(list: &str) -> Vec<PathBuf> {
            list.split(':')
                .filter(|s| !s.trim().is_empty())
                .map(PathBuf::from)
                .collect()
        }
        if let Some(list) = self.env("KUBECONFIG") {
            return split(list);
        }
        if let Some(path) = self.overrides.get("kubeconfig") {
            return split(&path.to_string_lossy());
        }
        vec![self.join(".kube/config")]
    }

    /// Wrangler's global config, newest location first.
    /// ngrok's config, newest location first. `NGROK_CONFIG` wins outright;
    /// otherwise the v3 platform directory is preferred over the v2 location,
    /// which upgrading ngrok leaves behind rather than migrating.
    pub fn ngrok_candidates(&self) -> Vec<PathBuf> {
        if let Some(path) = self.env("NGROK_CONFIG") {
            return vec![PathBuf::from(path)];
        }
        if let Some(path) = self.overrides.get("ngrok") {
            return vec![path.clone()];
        }
        vec![
            self.join("Library/Application Support/ngrok/ngrok.yml"),
            self.join(".ngrok2/ngrok.yml"),
        ]
    }

    /// cloudflared's credential directory: the origin certificates plus one
    /// JSON per tunnel.
    ///
    /// `TUNNEL_ORIGIN_CERT` is deliberately *not* consulted here. It selects
    /// which certificate is in force, which is an identity question, not a
    /// location one — see [`Paths::cloudflared_origin_cert`].
    pub fn cloudflared_dir(&self) -> PathBuf {
        self.resolve("cloudflared", || self.join(".cloudflared"))
    }

    /// The origin certificate in force: `TUNNEL_ORIGIN_CERT` when set, else the
    /// default `cert.pem` inside [`Paths::cloudflared_dir`]. `None` from the
    /// env var means "the default", not "no certificate".
    pub fn cloudflared_origin_cert(&self) -> PathBuf {
        match self.env("TUNNEL_ORIGIN_CERT") {
            Some(path) => PathBuf::from(path),
            None => self.cloudflared_dir().join("cert.pem"),
        }
    }

    /// Whether the origin certificate was chosen by the environment rather
    /// than by the default. The difference is a silent-wrong-account trap, so
    /// the probe reports it.
    pub fn cloudflared_origin_cert_is_explicit(&self) -> bool {
        self.env("TUNNEL_ORIGIN_CERT").is_some()
    }

    /// cloudflared's tunnel config, which names the tunnel and its ingress
    /// rules. `TUNNEL_CONFIG` wins, else `config.yml` in the credential dir.
    pub fn cloudflared_config(&self) -> PathBuf {
        self.resolve("cloudflared_config", || {
            self.cloudflared_dir().join("config.yml")
        })
    }

    pub fn wrangler_candidates(&self) -> Vec<PathBuf> {
        if let Some(path) = self.overrides.get("wrangler") {
            return vec![path.clone()];
        }
        vec![
            self.join("Library/Preferences/.wrangler/config/default.toml"),
            self.join(".wrangler/config/default.toml"),
        ]
    }

    /// `RCLONE_CONFIG` points at the *file*, not a directory. rclone also
    /// honours `XDG_CONFIG_HOME`.
    pub fn rclone_conf(&self) -> PathBuf {
        self.resolve("rclone", || self.xdg_config().join("rclone/rclone.conf"))
    }

    pub fn azure_profile(&self) -> PathBuf {
        self.resolve("azure", || self.join(".azure"))
            .join("azureProfile.json")
    }

    /// Vercel's global config directory. Verified empirically on macOS:
    /// `~/Library/Application Support/com.vercel.cli/{auth.json,config.json}`.
    /// The CLI uses `xdg-app-paths`, so an explicit `XDG_CONFIG_HOME` moves it;
    /// `~/.now` is the pre-2020 location and is still read here for old machines.
    pub fn vercel_dirs(&self) -> Vec<PathBuf> {
        if let Some(dir) = self.overrides.get("vercel") {
            return vec![dir.clone()];
        }
        let mut dirs = Vec::new();
        if let Some(xdg) = self.env("XDG_CONFIG_HOME") {
            dirs.push(PathBuf::from(xdg).join("com.vercel.cli"));
        }
        dirs.push(self.join("Library/Application Support/com.vercel.cli"));
        dirs.push(self.join(".now"));
        dirs
    }

    /// `firebase-tools` stores its login through the `configstore` npm package,
    /// which is XDG-aware. Verified empirically at
    /// `~/.config/configstore/firebase-tools.json`.
    pub fn firebase_config(&self) -> PathBuf {
        self.resolve("firebase", || {
            self.xdg_config().join("configstore/firebase-tools.json")
        })
    }

    /// The Neon CLI was renamed `neonctl` -> `neon`, but the config directory
    /// kept the old name. Verified empirically with `neon` 2.38.2:
    /// `~/.config/neonctl/credentials.json`. The directory is derived from the
    /// home directory rather than `XDG_CONFIG_HOME`; `--config-dir` overrides
    /// it per invocation, which a file probe cannot see — hence the `[paths]`
    /// key.
    pub fn neon_dir(&self) -> PathBuf {
        self.resolve("neon", || self.join(".config/neonctl"))
    }

    /// `DOCKER_CONFIG` names the *directory*, else `~/.docker`.
    pub fn docker_config(&self) -> PathBuf {
        self.resolve("docker", || self.join(".docker"))
            .join("config.json")
    }

    /// The macOS Tailscale app is sandboxed: its per-profile state lives in the
    /// group container, one directory per profile id. Verified empirically —
    /// the directory names match the `ID` column of `tailscale switch --list`.
    pub fn tailscale_profile_dir(&self) -> PathBuf {
        self.resolve("tailscale", || {
            self.join(
                "Library/Group Containers/W5364U7YZB.group.io.tailscale.ipn.macos/profile-data",
            )
        })
    }

    /// Open-source `tailscaled` (Homebrew, Linux) keeps a single state file
    /// instead of the sandboxed group container.
    pub fn tailscaled_state(&self) -> PathBuf {
        PathBuf::from("/var/lib/tailscale/tailscaled.state")
    }

    pub fn ssh_dir(&self) -> PathBuf {
        self.resolve("ssh", || self.join(".ssh"))
    }

    pub fn ssh_config(&self) -> PathBuf {
        self.ssh_dir().join("config")
    }

    /// Stripe CLI: `$XDG_CONFIG_HOME/stripe/config.toml`, else
    /// `~/.config/stripe/config.toml`. The CLI reads `XDG_CONFIG_HOME` with no
    /// platform switch, so this holds on macOS too.
    pub fn stripe_config(&self) -> PathBuf {
        self.resolve("stripe", || self.xdg_config().join("stripe/config.toml"))
    }

    /// The Supabase CLI's state root: `SUPABASE_HOME`, else `~/.supabase`.
    /// It holds `access-token` (the raw token — presence only) and `profile`
    /// (the environment name, safe to read).
    pub fn supabase_home(&self) -> PathBuf {
        self.resolve("supabase", || self.join(".supabase"))
    }

    /// flyctl: `config.yml` under `FLY_CONFIG_DIR`, else `~/.fly`.
    pub fn fly_config(&self) -> PathBuf {
        self.resolve("fly", || self.join(".fly")).join("config.yml")
    }

    /// doctl on macOS: `~/Library/Application Support/doctl/config.yaml`.
    /// Go's `os.UserConfigDir` does *not* consult `XDG_CONFIG_HOME` on Darwin,
    /// whatever doctl's own help text says.
    pub fn doctl_config(&self) -> PathBuf {
        self.resolve("doctl", || {
            self.join("Library/Application Support/doctl/config.yaml")
        })
    }

    /// npm's per-user config. `NPM_CONFIG_USERCONFIG` wins, else `~/.npmrc`.
    pub fn npmrc(&self) -> PathBuf {
        self.resolve("npm", || self.join(".npmrc"))
    }

    /// 1Password CLI v2 account list, in the CLI's own documented search order:
    /// `OP_CONFIG_DIR`, `~/.op`, `$XDG_CONFIG_HOME/.op`, `~/.config/op`,
    /// `$XDG_CONFIG_HOME/op`. The file is JSON despite the extensionless name.
    /// (The `--config` flag is first in that order but is per-invocation.)
    pub fn op_config_candidates(&self) -> Vec<PathBuf> {
        let mut dirs = Vec::new();
        if let Some(dir) = self.env("OP_CONFIG_DIR") {
            dirs.push(PathBuf::from(dir));
        }
        if let Some(dir) = self.overrides.get("op") {
            dirs.push(dir.clone());
        }
        dirs.push(self.join(".op"));
        if let Some(xdg) = self.env("XDG_CONFIG_HOME") {
            dirs.push(PathBuf::from(xdg).join(".op"));
        }
        dirs.push(self.xdg_config().join("op"));
        if let Some(xdg) = self.env("XDG_CONFIG_HOME") {
            dirs.push(PathBuf::from(xdg).join("op"));
        }

        let mut out: Vec<PathBuf> = Vec::new();
        for dir in dirs {
            let candidate = dir.join("config");
            if !out.contains(&candidate) {
                out.push(candidate);
            }
        }
        out
    }

    /// Ollama's home. `OLLAMA_MODELS` moves only the model store.
    pub fn ollama_dir(&self) -> PathBuf {
        self.resolve("ollama", || self.join(".ollama"))
    }

    pub fn ollama_models_dir(&self) -> PathBuf {
        match self.env("OLLAMA_MODELS") {
            Some(dir) => PathBuf::from(dir),
            None => self.ollama_dir().join("models"),
        }
    }

    /// Hugging Face's home: `HF_HOME`, else `$XDG_CACHE_HOME/huggingface`,
    /// else `~/.cache/huggingface`.
    pub fn huggingface_dir(&self) -> PathBuf {
        self.resolve("huggingface", || match self.env("XDG_CACHE_HOME") {
            Some(cache) => PathBuf::from(cache).join("huggingface"),
            None => self.join(".cache/huggingface"),
        })
    }

    /// The active Hugging Face token file. `HF_TOKEN_PATH` wins.
    pub fn huggingface_token(&self) -> PathBuf {
        match self.env("HF_TOKEN_PATH") {
            Some(p) => PathBuf::from(p),
            None => self.huggingface_dir().join("token"),
        }
    }

    /// The named-token store. It has no environment variable of its own: it is
    /// always a sibling of [`Paths::huggingface_token`].
    pub fn huggingface_stored_tokens(&self) -> PathBuf {
        let token = self.huggingface_token();
        match token.parent() {
            Some(dir) => dir.join("stored_tokens"),
            None => self.huggingface_dir().join("stored_tokens"),
        }
    }

    /// Claude Code's state file. `CLAUDE_CONFIG_DIR` moves the directory that
    /// holds it; the file itself keeps its name.
    pub fn claude_json(&self) -> PathBuf {
        self.resolve("claude", || self.home.clone())
            .join(".claude.json")
    }

    /// patchbay's own config directory. `PATCHBAY_CONFIG_DIR` wins, else
    /// `~/.config/patchbay`.
    pub fn patchbay_dir(&self) -> PathBuf {
        match self.env("PATCHBAY_CONFIG_DIR") {
            Some(dir) => PathBuf::from(dir),
            None => self.join(".config/patchbay"),
        }
    }

    /// The key vault's metadata registry. Secret values are never stored here —
    /// they live in the OS keychain (see [`crate::keystore`]).
    pub fn keys_file(&self) -> PathBuf {
        self.patchbay_dir().join("keys.json")
    }

    /// The version-check cache (see [`crate::versions`]). Public information
    /// about public software — no secrets, so no 0600 handling.
    pub fn versions_file(&self) -> PathBuf {
        self.patchbay_dir().join("versions.json")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

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
    fn test_keys_file_lives_under_the_patchbay_config_dir() {
        let p = Paths::for_test("/nowhere");
        assert_eq!(
            p.keys_file(),
            PathBuf::from("/nowhere/.config/patchbay/keys.json")
        );
        let p = Paths::for_test("/nowhere").with_env("PATCHBAY_CONFIG_DIR", "/custom/pb");
        assert_eq!(p.keys_file(), PathBuf::from("/custom/pb/keys.json"));
    }

    #[test]
    fn test_kubeconfig_list_is_split() {
        let p = Paths::for_test("/nowhere").with_env("KUBECONFIG", "/a.yaml:/b.yaml");
        assert_eq!(
            p.kube_configs(),
            vec![PathBuf::from("/a.yaml"), PathBuf::from("/b.yaml")]
        );
        // A `[paths]` override may be a list too.
        let p = Paths::for_test("/nowhere").with_path_override("kubeconfig", "/c.yaml:/d.yaml");
        assert_eq!(
            p.kube_configs(),
            vec![PathBuf::from("/c.yaml"), PathBuf::from("/d.yaml")]
        );
    }

    #[test]
    fn test_new_tool_locations_are_macos_shaped() {
        let p = Paths::for_test("/nowhere");
        assert_eq!(
            p.vercel_dirs()[0],
            PathBuf::from("/nowhere/Library/Application Support/com.vercel.cli")
        );
        assert_eq!(
            p.firebase_config(),
            PathBuf::from("/nowhere/.config/configstore/firebase-tools.json")
        );
        // The binary is `neon`; the directory is still `neonctl`.
        assert_eq!(p.neon_dir(), PathBuf::from("/nowhere/.config/neonctl"));
        assert_eq!(
            p.docker_config(),
            PathBuf::from("/nowhere/.docker/config.json")
        );
        assert_eq!(p.ssh_config(), PathBuf::from("/nowhere/.ssh/config"));
        assert_eq!(
            p.stripe_config(),
            PathBuf::from("/nowhere/.config/stripe/config.toml")
        );
        assert_eq!(p.fly_config(), PathBuf::from("/nowhere/.fly/config.yml"));
        assert_eq!(p.supabase_home(), PathBuf::from("/nowhere/.supabase"));
        assert_eq!(
            p.doctl_config(),
            PathBuf::from("/nowhere/Library/Application Support/doctl/config.yaml")
        );
        assert_eq!(p.npmrc(), PathBuf::from("/nowhere/.npmrc"));
        // `~/.op` is searched before `~/.config/op`.
        assert_eq!(
            p.op_config_candidates(),
            vec![
                PathBuf::from("/nowhere/.op/config"),
                PathBuf::from("/nowhere/.config/op/config"),
            ]
        );
        assert_eq!(
            p.ollama_models_dir(),
            PathBuf::from("/nowhere/.ollama/models")
        );
        assert_eq!(
            p.huggingface_dir(),
            PathBuf::from("/nowhere/.cache/huggingface")
        );
        assert_eq!(
            p.huggingface_stored_tokens(),
            PathBuf::from("/nowhere/.cache/huggingface/stored_tokens")
        );
        assert_eq!(p.claude_json(), PathBuf::from("/nowhere/.claude.json"));
    }

    #[test]
    fn test_new_tool_env_overrides_win() {
        let p = Paths::for_test("/nowhere")
            .with_env("XDG_CONFIG_HOME", "/xdg")
            .with_env("DOCKER_CONFIG", "/dk")
            .with_env("NPM_CONFIG_USERCONFIG", "/npm/rc")
            .with_env("FLY_CONFIG_DIR", "/fly")
            .with_env("SUPABASE_HOME", "/sb")
            .with_env("HF_HOME", "/hf")
            .with_env("CLAUDE_CONFIG_DIR", "/cc");
        assert_eq!(
            p.firebase_config(),
            PathBuf::from("/xdg/configstore/firebase-tools.json")
        );
        assert_eq!(p.stripe_config(), PathBuf::from("/xdg/stripe/config.toml"));
        assert_eq!(p.vercel_dirs()[0], PathBuf::from("/xdg/com.vercel.cli"));
        assert_eq!(p.docker_config(), PathBuf::from("/dk/config.json"));
        assert_eq!(p.npmrc(), PathBuf::from("/npm/rc"));
        assert_eq!(p.fly_config(), PathBuf::from("/fly/config.yml"));
        assert_eq!(p.supabase_home(), PathBuf::from("/sb"));
        assert_eq!(p.huggingface_dir(), PathBuf::from("/hf"));
        assert_eq!(p.claude_json(), PathBuf::from("/cc/.claude.json"));
        assert_eq!(
            p.op_config_candidates(),
            vec![
                PathBuf::from("/nowhere/.op/config"),
                PathBuf::from("/xdg/.op/config"),
                PathBuf::from("/xdg/op/config"),
            ]
        );
        // gcloud ignores XDG_CONFIG_HOME, so it must not move with it.
        assert_eq!(p.gcloud_dir(), PathBuf::from("/nowhere/.config/gcloud"));
        // gh and rclone do respect it.
        assert_eq!(p.gh_hosts(), PathBuf::from("/xdg/gh/hosts.yml"));
        assert_eq!(p.rclone_conf(), PathBuf::from("/xdg/rclone/rclone.conf"));
    }

    // --- the three-layer resolution ----------------------------------------

    fn config_home(body: &str) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join(".config/patchbay")).unwrap();
        fs::write(dir.path().join(".config/patchbay/config.toml"), body).unwrap();
        dir
    }

    #[test]
    fn test_precedence_tool_env_beats_config_file_beats_default() {
        let dir = config_home(
            "[paths]\n\
             gcloud = \"/from/config/gcloud\"\n\
             aws_config = \"/from/config/aws\"\n\
             rclone = \"/from/config/rclone.conf\"\n",
        );
        let paths = Paths::for_test(dir.path())
            .load_config()
            // Only gcloud has its own variable set.
            .with_env("CLOUDSDK_CONFIG", "/from/env/gcloud");

        // 1. the tool's own variable wins, because that is what gcloud reads.
        assert_eq!(paths.gcloud_dir(), PathBuf::from("/from/env/gcloud"));
        // 2. patchbay's config wins over the default.
        assert_eq!(paths.aws_config(), PathBuf::from("/from/config/aws"));
        assert_eq!(
            paths.rclone_conf(),
            PathBuf::from("/from/config/rclone.conf")
        );
        // 3. an untouched key keeps its default.
        assert_eq!(paths.aws_credentials(), dir.path().join(".aws/credentials"));
        assert!(paths.config_warnings().is_empty());
    }

    #[test]
    fn test_path_notes_name_the_layer_in_force() {
        let dir = config_home("[paths]\naws_config = \"/from/config/aws\"\n");
        let paths = Paths::for_test(dir.path())
            .load_config()
            .with_env("CLOUDSDK_CONFIG", "/from/env/gcloud");

        let gcloud = paths.path_notes("gcloud");
        assert_eq!(gcloud.len(), 1);
        assert!(
            gcloud[0].contains("$CLOUDSDK_CONFIG=/from/env/gcloud"),
            "{gcloud:?}"
        );

        let aws = paths.path_notes("aws_config");
        assert_eq!(aws.len(), 1);
        assert!(aws[0].contains("/from/config/aws"), "{aws:?}");
        assert!(aws[0].contains("[paths]"), "{aws:?}");

        // The default location is not worth a note.
        assert!(paths.path_notes("docker").is_empty());
    }

    #[test]
    fn test_unknown_keys_and_broken_config_warn_without_breaking_anything() {
        let dir = config_home("[paths]\ngclod = \"/typo\"\naws_config = \"/ok\"\n");
        let paths = Paths::for_test(dir.path()).load_config();
        assert_eq!(paths.config_warnings().len(), 1);
        assert!(paths.config_warnings()[0].contains("unknown key `gclod`"));
        // The rest of the table still applies.
        assert_eq!(paths.aws_config(), PathBuf::from("/ok"));
        assert_eq!(paths.gcloud_dir(), dir.path().join(".config/gcloud"));

        let dir = config_home("[paths\nthis is not toml");
        let paths = Paths::for_test(dir.path()).load_config();
        assert_eq!(paths.config_warnings().len(), 1);
        assert!(paths.config_warnings()[0].contains("not valid TOML"));
        assert_eq!(paths.gcloud_dir(), dir.path().join(".config/gcloud"));
    }

    #[test]
    fn test_no_config_file_is_the_quiet_case() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::for_test(dir.path()).load_config();
        assert!(paths.config_warnings().is_empty());
        assert!(paths.path_notes("gcloud").is_empty());
    }

    #[test]
    fn test_from_env_takes_an_injected_environment() {
        let env: HashMap<String, String> = [("DOCKER_CONFIG".to_string(), "/dk".to_string())]
            .into_iter()
            .collect();
        let paths = Paths::from_env("/nowhere", env, BinaryLookup::Disabled);
        assert_eq!(paths.docker_config(), PathBuf::from("/dk/config.json"));
        assert!(!paths.may_exec());
    }

    #[test]
    fn test_every_location_key_is_resolvable() {
        // Guards the table against a key that config.toml would accept but
        // nothing ever reads.
        let paths = Paths::for_test("/nowhere");
        for (key, _) in LOCATIONS {
            let with = Paths::for_test("/nowhere").with_path_override(key, "/moved");
            let moved = match *key {
                "gcloud" => with.gcloud_dir() != paths.gcloud_dir(),
                "aws_config" => with.aws_config() != paths.aws_config(),
                "aws_credentials" => with.aws_credentials() != paths.aws_credentials(),
                "gh" => with.gh_hosts() != paths.gh_hosts(),
                "infisical" => with.infisical_config() != paths.infisical_config(),
                "kubeconfig" => with.kube_configs() != paths.kube_configs(),
                "wrangler" => with.wrangler_candidates() != paths.wrangler_candidates(),
                "rclone" => with.rclone_conf() != paths.rclone_conf(),
                "azure" => with.azure_profile() != paths.azure_profile(),
                "vercel" => with.vercel_dirs() != paths.vercel_dirs(),
                "firebase" => with.firebase_config() != paths.firebase_config(),
                "neon" => with.neon_dir() != paths.neon_dir(),
                "docker" => with.docker_config() != paths.docker_config(),
                "tailscale" => with.tailscale_profile_dir() != paths.tailscale_profile_dir(),
                "ssh" => with.ssh_config() != paths.ssh_config(),
                "stripe" => with.stripe_config() != paths.stripe_config(),
                "supabase" => with.supabase_home() != paths.supabase_home(),
                "fly" => with.fly_config() != paths.fly_config(),
                "doctl" => with.doctl_config() != paths.doctl_config(),
                "npm" => with.npmrc() != paths.npmrc(),
                "op" => with.op_config_candidates() != paths.op_config_candidates(),
                "ollama" => with.ollama_dir() != paths.ollama_dir(),
                "huggingface" => with.huggingface_dir() != paths.huggingface_dir(),
                "claude" => with.claude_json() != paths.claude_json(),
                "ngrok" => with.ngrok_candidates() != paths.ngrok_candidates(),
                "cloudflared" => with.cloudflared_dir() != paths.cloudflared_dir(),
                "cloudflared_config" => with.cloudflared_config() != paths.cloudflared_config(),
                other => panic!("`{other}` is in LOCATIONS but no accessor uses it"),
            };
            assert!(moved, "the [paths] key `{key}` changes nothing");
        }
    }
}
