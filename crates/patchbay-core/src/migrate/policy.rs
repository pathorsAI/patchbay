//! What can move to a new machine, and what cannot.
//!
//! This is the table the whole migration feature rests on. Every tool patchbay
//! probes declares one [`Portability`], and the classification is a claim about
//! *that tool's* credential storage — checked against the same evidence the
//! probe module was written from. A wrong entry here is either a broken login
//! on the new machine (something classified portable that was not) or pointless
//! re-auth work (something portable classified as bound), so each variant
//! carries the reason in the table itself rather than in a commit message.
//!
//! Three verdicts:
//!
//! * [`Portability::Portable`] — the credential is in a file the tool reads on
//!   any machine. Copy the file, the login works. These are the ones `pb export`
//!   actually carries.
//! * [`Portability::DeviceBound`] — the credential is held by the OS keychain,
//!   a hardware-backed store, or is a key that *identifies this device*. There
//!   is nothing on disk to copy, and copying what is there would either fail or
//!   be an impersonation. Re-auth on the new machine.
//! * [`Portability::PointerOnly`] — nothing patchbay is willing to move, but the
//!   *identity* is worth recording so the new machine knows what to re-create.
//!
//! The last two both become a line in the manifest's `gaps` list with the exact
//! command that closes them. The difference is why, and the user deserves the
//! why.
//!
//! **Locations, not paths.** A portable tool names [`Location`]s, never literal
//! paths. A `Location` resolves through [`Paths`] on *both* machines, so a
//! source with `AWS_CONFIG_FILE` pointing at an external volume exports the
//! right file, and a destination with its own override receives it in the right
//! place.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::paths::Paths;

// ---------------------------------------------------------------------------
// locations
// ---------------------------------------------------------------------------

/// One resolvable place a portable credential lives.
///
/// The wire name (`snake_case`) is what travels in a bundle, so these variants
/// are a compatibility surface: rename one and older bundles stop importing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Location {
    /// gcloud's config directory. Only the credential store and the named
    /// configurations travel; logs and caches do not.
    Gcloud,
    AwsConfig,
    AwsCredentials,
    /// The SSO token cache. Short-lived, but copying it means the new machine
    /// is usable before the first `aws sso login`.
    AwsSsoCache,
    Wrangler,
    Rclone,
    /// Every file kubectl merges, however many `KUBECONFIG` names.
    KubeConfigs,
    Vercel,
    Firebase,
    Neon,
    Doctl,
    Fly,
    Npmrc,
    /// `~/.ssh/config` and nothing else. Private keys never travel.
    SshConfig,
    Docker,
    /// ngrok's `ngrok.yml`, which holds the authtoken.
    Ngrok,
    /// cloudflared's origin certificate and per-tunnel credential files.
    /// Portable, and the most sensitive thing in a bundle after the AWS keys —
    /// see [`cloudflared_include`].
    Cloudflared,
}

/// How the files under a [`Location`] are collected and put back.
enum Layout {
    /// Exactly one file. The destination is whatever `Paths` resolves, so an
    /// override on either machine is honoured independently.
    Single(fn(&Paths) -> PathBuf),
    /// A directory. Entries matching `include` travel with their relative path
    /// preserved; everything else is left behind.
    Tree {
        root: fn(&Paths) -> PathBuf,
        include: fn(&Path) -> bool,
    },
    /// Several files that all land in one directory on the destination — the
    /// `KUBECONFIG` list, whose members may live anywhere on the source.
    Fan {
        sources: fn(&Paths) -> Vec<PathBuf>,
        dest_dir: fn(&Paths) -> PathBuf,
    },
}

/// One file picked up by [`Location::collect`].
#[derive(Debug, Clone, PartialEq)]
pub struct CollectedFile {
    pub location: Location,
    /// Path under the location's root; the file's own name for `Single`/`Fan`.
    pub rel: String,
    pub source: PathBuf,
    /// Unix mode of the source file, so `0600` on a credentials file survives.
    pub mode: u32,
}

/// gcloud writes a lot into its config directory. This is the credential half:
/// the two SQLite stores, the ADC file, the active-configuration pointer and
/// the named configurations. `logs/`, caches and the legacy `.last_*` files
/// stay behind — they are noise, and some of them are large.
fn gcloud_include(rel: &Path) -> bool {
    let name = rel.to_string_lossy();
    matches!(
        name.as_ref(),
        "credentials.db"
            | "access_tokens.db"
            | "application_default_credentials.json"
            | "active_config"
    ) || name.starts_with("configurations/")
        || name.starts_with("legacy_credentials/")
}

/// The Vercel CLI keeps its token in `auth.json` and the rest in `config.json`.
fn vercel_include(rel: &Path) -> bool {
    matches!(rel.to_string_lossy().as_ref(), "auth.json" | "config.json")
}

/// The Neon CLI's directory also holds a `preferences.json`; only the
/// credentials are worth moving.
fn neon_include(rel: &Path) -> bool {
    rel.to_string_lossy().as_ref() == "credentials.json"
}

fn json_files(rel: &Path) -> bool {
    rel.extension().is_some_and(|e| e == "json")
}

/// cloudflared's `~/.cloudflared`: the origin certificate (`cert.pem`, which is
/// an *account* credential — it authorises creating tunnels and routing DNS for
/// the whole zone) and one `<tunnel-uuid>.json` per tunnel (which holds
/// `TunnelSecret`).
///
/// Both travel, because a machine without them cannot run the tunnels it owns,
/// and both are treated as opaque bytes: patchbay copies the files and **never
/// parses `TunnelSecret`, never puts a tunnel secret in the manifest, and never
/// names one in a log line or an error.** The manifest records only that the
/// `cloudflared` location was carried.
///
/// `config.yml` deliberately does not travel: it names local ingress rules and
/// service ports that belong to the old machine.
fn cloudflared_include(rel: &Path) -> bool {
    let name = rel.to_string_lossy();
    name == "cert.pem" || rel.extension().is_some_and(|e| e == "json")
}

/// ngrok's config, newest location first. Resolved from `Paths`' home and
/// environment rather than a named accessor, because `Paths` has no ngrok entry
/// yet — swap this for `Paths::ngrok_config()` the day it grows one.
fn ngrok_config(paths: &Paths) -> PathBuf {
    if let Some(explicit) = paths.env("NGROK_CONFIG") {
        return PathBuf::from(explicit);
    }
    first_existing(vec![
        paths
            .home()
            .join("Library/Application Support/ngrok/ngrok.yml"),
        paths.home().join(".config/ngrok/ngrok.yml"),
        paths.home().join(".ngrok2/ngrok.yml"),
    ])
}

/// cloudflared's state directory. `TUNNEL_ORIGIN_CERT` names the *certificate*,
/// so the directory that holds it is what matters here.
fn cloudflared_dir(paths: &Paths) -> PathBuf {
    if let Some(cert) = paths.env("TUNNEL_ORIGIN_CERT") {
        if let Some(dir) = Path::new(cert).parent() {
            return dir.to_path_buf();
        }
    }
    paths.home().join(".cloudflared")
}

/// First candidate that exists, else the first — so both machines agree on
/// which of a tool's several historical locations is "the" one.
fn first_existing(candidates: Vec<PathBuf>) -> PathBuf {
    candidates
        .iter()
        .find(|p| p.exists())
        .cloned()
        .or_else(|| candidates.first().cloned())
        .unwrap_or_default()
}

impl Location {
    fn layout(&self) -> Layout {
        match self {
            Self::Gcloud => Layout::Tree {
                root: Paths::gcloud_dir,
                include: gcloud_include,
            },
            Self::AwsConfig => Layout::Single(Paths::aws_config),
            Self::AwsCredentials => Layout::Single(Paths::aws_credentials),
            Self::AwsSsoCache => Layout::Tree {
                root: Paths::aws_sso_cache_dir,
                include: json_files,
            },
            Self::Wrangler => Layout::Single(|p| first_existing(p.wrangler_candidates())),
            Self::Rclone => Layout::Single(Paths::rclone_conf),
            Self::KubeConfigs => Layout::Fan {
                sources: Paths::kube_configs,
                dest_dir: |p| {
                    p.kube_configs()
                        .first()
                        .and_then(|f| f.parent().map(Path::to_path_buf))
                        .unwrap_or_else(|| p.home().join(".kube"))
                },
            },
            Self::Vercel => Layout::Tree {
                root: |p| first_existing(p.vercel_dirs()),
                include: vercel_include,
            },
            Self::Firebase => Layout::Single(Paths::firebase_config),
            Self::Neon => Layout::Tree {
                root: Paths::neon_dir,
                include: neon_include,
            },
            Self::Doctl => Layout::Single(Paths::doctl_config),
            Self::Fly => Layout::Single(Paths::fly_config),
            Self::Npmrc => Layout::Single(Paths::npmrc),
            Self::SshConfig => Layout::Single(Paths::ssh_config),
            Self::Docker => Layout::Single(Paths::docker_config),
            Self::Ngrok => Layout::Single(ngrok_config),
            Self::Cloudflared => Layout::Tree {
                root: cloudflared_dir,
                include: cloudflared_include,
            },
        }
    }

    /// Stable key, matching the serde name. Used in reports and bundle ids.
    pub fn key(&self) -> &'static str {
        match self {
            Self::Gcloud => "gcloud",
            Self::AwsConfig => "aws_config",
            Self::AwsCredentials => "aws_credentials",
            Self::AwsSsoCache => "aws_sso_cache",
            Self::Wrangler => "wrangler",
            Self::Rclone => "rclone",
            Self::KubeConfigs => "kube_configs",
            Self::Vercel => "vercel",
            Self::Firebase => "firebase",
            Self::Neon => "neon",
            Self::Doctl => "doctl",
            Self::Fly => "fly",
            Self::Npmrc => "npmrc",
            Self::SshConfig => "ssh_config",
            Self::Docker => "docker",
            Self::Ngrok => "ngrok",
            Self::Cloudflared => "cloudflared",
        }
    }

    /// One line for SETUP.md and the export report.
    pub fn describe(&self) -> &'static str {
        match self {
            Self::Gcloud => "gcloud credential store and named configurations",
            Self::AwsConfig => "AWS profiles (~/.aws/config)",
            Self::AwsCredentials => "AWS access keys (~/.aws/credentials)",
            Self::AwsSsoCache => "AWS SSO token cache",
            Self::Wrangler => "Cloudflare wrangler OAuth config",
            Self::Rclone => "rclone remotes (rclone.conf)",
            Self::KubeConfigs => "kubeconfig(s)",
            Self::Vercel => "Vercel auth and config",
            Self::Firebase => "firebase-tools login (configstore)",
            Self::Neon => "Neon CLI credentials",
            Self::Doctl => "doctl config",
            Self::Fly => "flyctl config",
            Self::Npmrc => "npm registry tokens (~/.npmrc)",
            Self::SshConfig => "SSH client config — Host blocks only, never keys",
            Self::Docker => "Docker registry list (~/.docker/config.json)",
            Self::Ngrok => "ngrok authtoken (ngrok.yml)",
            Self::Cloudflared => "cloudflared origin certificate and tunnel credentials",
        }
    }

    /// Every file at this location on the machine `paths` describes.
    ///
    /// Missing files and missing directories are the ordinary "tool not set up"
    /// state, not an error: they simply contribute nothing.
    pub fn collect(&self, paths: &Paths) -> Vec<CollectedFile> {
        match self.layout() {
            Layout::Single(resolve) => {
                let source = resolve(paths);
                self.one(&source, file_name(&source)).into_iter().collect()
            }
            Layout::Tree { root, include } => {
                let root = root(paths);
                let mut out = Vec::new();
                walk(&root, &root, include, &mut out);
                out.sort();
                out.iter()
                    .filter_map(|rel| self.one(&root.join(rel), rel.to_string_lossy().into_owned()))
                    .collect()
            }
            Layout::Fan { sources, .. } => {
                let mut seen: Vec<String> = Vec::new();
                let mut out = Vec::new();
                for source in sources(paths) {
                    let mut rel = file_name(&source);
                    // Two `KUBECONFIG` entries can share a basename; the second
                    // one keeps its content rather than overwriting the first.
                    while seen.contains(&rel) {
                        rel = format!("dup-{}-{rel}", seen.len());
                    }
                    if let Some(file) = self.one(&source, rel.clone()) {
                        seen.push(rel);
                        out.push(file);
                    }
                }
                out
            }
        }
    }

    fn one(&self, source: &Path, rel: String) -> Option<CollectedFile> {
        let meta = std::fs::metadata(source).ok()?;
        if !meta.is_file() {
            return None;
        }
        Some(CollectedFile {
            location: *self,
            rel,
            source: source.to_path_buf(),
            mode: mode_of(&meta),
        })
    }

    /// Where a collected file goes on the machine `paths` describes.
    ///
    /// The inverse of [`Location::collect`], resolved from the *destination's*
    /// `Paths` — which is the entire reason locations are keys and not paths.
    pub fn destination(&self, paths: &Paths, rel: &str) -> PathBuf {
        match self.layout() {
            Layout::Single(resolve) => resolve(paths),
            Layout::Tree { root, .. } => root(paths).join(rel),
            Layout::Fan { dest_dir, .. } => dest_dir(paths).join(rel),
        }
    }
}

fn file_name(path: &Path) -> String {
    path.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "file".to_string())
}

#[cfg(unix)]
fn mode_of(meta: &std::fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    meta.permissions().mode() & 0o777
}

#[cfg(not(unix))]
fn mode_of(_meta: &std::fs::Metadata) -> u32 {
    0o600
}

/// Depth-first walk collecting paths relative to `root`. Symlinks are followed
/// only as far as `metadata` does — a link out of the tree still has to pass
/// `include`, and `include` is a fixed allowlist per location.
fn walk(root: &Path, dir: &Path, include: fn(&Path) -> bool, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(rel) = path.strip_prefix(root) else {
            continue;
        };
        let rel = rel.to_path_buf();
        if path.is_dir() {
            // Descend only where the allowlist could still match.
            if include(&rel) || include(&rel.join("x")) {
                walk(root, &path, include, out);
            }
        } else if include(&rel) {
            out.push(rel);
        }
    }
}

// ---------------------------------------------------------------------------
// portability
// ---------------------------------------------------------------------------

/// Whether a tool's login survives a move, and why not when it does not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Portability {
    /// The credential is in files patchbay can copy verbatim.
    Portable { locations: &'static [Location] },
    /// The credential is in the OS keychain, a hardware store, or is a key that
    /// names *this device*. Nothing to copy.
    DeviceBound { reason: &'static str },
    /// patchbay deliberately will not move what is there. The identity travels
    /// in the manifest so the new machine knows what to re-create.
    PointerOnly { needs: &'static str },
}

/// The `snake_case` name that goes in the manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PortabilityKind {
    Portable,
    DeviceBound,
    PointerOnly,
}

impl Portability {
    pub fn kind(&self) -> PortabilityKind {
        match self {
            Self::Portable { .. } => PortabilityKind::Portable,
            Self::DeviceBound { .. } => PortabilityKind::DeviceBound,
            Self::PointerOnly { .. } => PortabilityKind::PointerOnly,
        }
    }

    pub fn locations(&self) -> &'static [Location] {
        match self {
            Self::Portable { locations } => locations,
            _ => &[],
        }
    }

    /// Why this tool cannot simply be copied. Empty for a portable tool.
    pub fn reason(&self) -> &'static str {
        match self {
            Self::Portable { .. } => "",
            Self::DeviceBound { reason } => reason,
            Self::PointerOnly { needs } => needs,
        }
    }
}

/// One tool's migration story.
#[derive(Debug, Clone, Copy)]
pub struct ToolPolicy {
    pub tool: &'static str,
    pub portability: Portability,
    /// The command that re-establishes the login on the new machine. Shown to
    /// a human, and handed to an agent as the thing to run or to hand back.
    pub fix: &'static str,
    /// Whether `fix` opens a browser — the one thing an AI agent must not try
    /// to drive itself.
    pub needs_browser: bool,
    /// How to get the binary onto a machine that does not have it.
    pub install: &'static str,
    /// Whether the export should spend a tier-2 call recording what the active
    /// credential is allowed to do. Only where a probe implements it *and* the
    /// answer is worth re-creating by hand on the far side.
    pub record_permissions: bool,
}

const fn tool(
    tool: &'static str,
    portability: Portability,
    fix: &'static str,
    needs_browser: bool,
    install: &'static str,
) -> ToolPolicy {
    ToolPolicy {
        tool,
        portability,
        fix,
        needs_browser,
        install,
        record_permissions: false,
    }
}

/// Every tool on the board, classified. A probe added without a line here fails
/// `test_every_registered_tool_has_a_policy`.
pub const POLICIES: &[ToolPolicy] = &[
    // --- portable ----------------------------------------------------------
    //
    // gcloud keeps refresh tokens in `credentials.db` (SQLite, plaintext) and
    // the named configurations beside it. Both are ordinary files with no
    // machine binding; `gcloud config configurations list` on the new machine
    // shows the same set.
    tool(
        "gcloud",
        Portability::Portable {
            locations: &[Location::Gcloud],
        },
        "gcloud auth login",
        true,
        "brew install --cask google-cloud-sdk",
    ),
    // `~/.aws/credentials` is long-lived access keys in an INI file — the most
    // portable credential there is. The SSO cache is short-lived but valid
    // anywhere until it expires, so it travels too and saves a login.
    tool(
        "aws",
        Portability::Portable {
            locations: &[
                Location::AwsConfig,
                Location::AwsCredentials,
                Location::AwsSsoCache,
            ],
        },
        "aws sso login",
        true,
        "brew install awscli",
    ),
    // wrangler writes its OAuth refresh token into a TOML file under
    // `~/Library/Preferences/.wrangler`; nothing about it is device-scoped.
    tool(
        "wrangler",
        Portability::Portable {
            locations: &[Location::Wrangler],
        },
        "wrangler login",
        true,
        "npm i -g wrangler",
    ),
    // rclone.conf holds every remote, with secrets obscured (not encrypted)
    // unless the user set a config password. Either way it is designed to be
    // copied — rclone's own docs tell you to.
    tool(
        "rclone",
        Portability::Portable {
            locations: &[Location::Rclone],
        },
        "rclone config",
        false,
        "brew install rclone",
    ),
    // A kubeconfig is a portable document by design: certs and tokens inline,
    // or an exec plugin that re-auths on the new machine.
    tool(
        "kubectl",
        Portability::Portable {
            locations: &[Location::KubeConfigs],
        },
        "kubectl config get-contexts",
        false,
        "brew install kubectl",
    ),
    // `auth.json` is a bare bearer token the CLI sends as-is.
    tool(
        "vercel",
        Portability::Portable {
            locations: &[Location::Vercel],
        },
        "vercel login",
        true,
        "npm i -g vercel",
    ),
    // firebase-tools stores its refresh token through the `configstore` npm
    // package: plain JSON in `~/.config/configstore`.
    tool(
        "firebase",
        Portability::Portable {
            locations: &[Location::Firebase],
        },
        "firebase login",
        true,
        "npm i -g firebase-tools",
    ),
    tool(
        "neon",
        Portability::Portable {
            locations: &[Location::Neon],
        },
        "neon auth",
        true,
        "npm i -g neonctl",
    ),
    // doctl's config.yaml carries the API token in cleartext.
    tool(
        "doctl",
        Portability::Portable {
            locations: &[Location::Doctl],
        },
        "doctl auth init",
        false,
        "brew install doctl",
    ),
    // flyctl's config.yml carries `access_token` in cleartext.
    tool(
        "flyctl",
        Portability::Portable {
            locations: &[Location::Fly],
        },
        "fly auth login",
        true,
        "brew install flyctl",
    ),
    // npm has no keychain integration at all: `_authToken` lines are the
    // credential, and npm reads them on any machine.
    tool(
        "npm",
        Portability::Portable {
            locations: &[Location::Npmrc],
        },
        "npm login",
        true,
        "brew install node",
    ),
    // ONLY `~/.ssh/config`. The Host blocks are configuration and worth having
    // on the new machine; the private keys beside them are exactly what
    // patchbay refuses to touch, here and in the probe. Move those yourself,
    // or better, generate new ones.
    tool(
        "ssh",
        Portability::Portable {
            locations: &[Location::SshConfig],
        },
        "ssh-keygen -t ed25519",
        false,
        "(preinstalled)",
    ),
    // `~/.docker/config.json` is the registry list plus the name of the
    // credential helper. When a helper owns the secret — the normal case on
    // macOS — the secret stays in the keychain and does NOT travel, so a
    // `docker login` may still be needed. That is a note, not a reason to skip
    // the file: the registry list is worth having.
    tool(
        "docker",
        Portability::Portable {
            locations: &[Location::Docker],
        },
        "docker login",
        false,
        "brew install --cask docker",
    ),
    // ngrok's `ngrok.yml` is a YAML file whose `authtoken` is the credential,
    // read on any machine. Portable, and worth carrying: without it every
    // `ngrok http` on the new box is anonymous and rate-limited.
    tool(
        "ngrok",
        Portability::Portable {
            locations: &[Location::Ngrok],
        },
        "ngrok config add-authtoken <token>",
        true,
        "brew install ngrok",
    ),
    // PORTABLE BUT SENSITIVE. `cert.pem` authorises tunnel and DNS changes for
    // a whole Cloudflare zone, and each `<uuid>.json` holds a `TunnelSecret`.
    // They travel because a machine that cannot run its own tunnels has not
    // been migrated — but they travel as opaque bytes inside the encrypted
    // payload only: never parsed, never in the manifest, never in a log line.
    // See `cloudflared_include`.
    tool(
        "cloudflared",
        Portability::Portable {
            locations: &[Location::Cloudflared],
        },
        "cloudflared tunnel login",
        true,
        "brew install cloudflared",
    ),
    // --- device-bound ------------------------------------------------------
    ToolPolicy {
        record_permissions: true,
        ..tool(
            "gh",
            Portability::DeviceBound {
                reason: "the OAuth token lives in the OS keychain; hosts.yml only names the \
                         accounts",
            },
            "gh auth login",
            true,
            "brew install gh",
        )
    },
    tool(
        "az",
        Portability::DeviceBound {
            reason: "the MSAL token cache is keychain-backed on macOS; azureProfile.json is only \
                     the subscription list",
        },
        "az login",
        true,
        "brew install azure-cli",
    ),
    tool(
        "infisical",
        Portability::DeviceBound {
            reason: "the JWT lives in the configured vault backend (keychain, or a file sealed \
                     with a machine passphrase), never in infisical-config.json",
        },
        "infisical login",
        true,
        "brew install infisical/get-cli/infisical",
    ),
    tool(
        "op",
        Portability::DeviceBound {
            reason: "1Password registers the device itself; the session is unlocked by biometrics \
                     or the desktop app, and no transferable credential exists on disk",
        },
        "op account add",
        true,
        "brew install --cask 1password-cli",
    ),
    tool(
        "supabase",
        Portability::DeviceBound {
            reason: "the access token is in the OS keyring (service `Supabase CLI`); the \
                     plaintext fallback file only exists on keyring-less machines",
        },
        "supabase login",
        true,
        "brew install supabase/tap/supabase",
    ),
    tool(
        "stripe",
        Portability::DeviceBound {
            reason: "the live-mode key is stored redacted in config.toml with the real value in \
                     the keychain; copying the file would move a test key and a lie",
        },
        "stripe login",
        true,
        "brew install stripe/stripe-cli/stripe",
    ),
    tool(
        "tailscale",
        Portability::DeviceBound {
            reason: "the node key IS this device's identity on the tailnet; copying it would put \
                     two machines behind one node, which is not a migration but an impersonation",
        },
        "tailscale up",
        true,
        "brew install --cask tailscale",
    ),
    tool(
        "claude",
        Portability::DeviceBound {
            reason: "the OAuth token is in the macOS Keychain; ~/.claude.json holds the account \
                     email and project list, not the credential",
        },
        "claude  (then /login)",
        true,
        "npm i -g @anthropic-ai/claude-code",
    ),
    tool(
        "ollama",
        Portability::DeviceBound {
            reason: "`ollama signin` registers this machine's ed25519 PUBLIC key; the private \
                     half is the credential and patchbay never copies a private key",
        },
        "ollama signin",
        true,
        "brew install ollama",
    ),
    // --- pointer-only ------------------------------------------------------
    //
    // `~/.cache/huggingface/token` is a bare token in a *cache* directory, and
    // which named token is active cannot be determined from disk at all (the
    // library compares values, which patchbay does not read). Copying it would
    // move a raw secret out of a cache and could restore an ambiguous active
    // token; `hf auth login --token` is one paste and unambiguous.
    tool(
        "huggingface",
        Portability::PointerOnly {
            needs: "the Hub token itself — patchbay records which named tokens existed, not their \
                    values",
        },
        "hf auth login",
        false,
        "pip install -U huggingface_hub",
    ),
];

pub fn policy_for(tool: &str) -> Option<&'static ToolPolicy> {
    POLICIES.iter().find(|p| p.tool == tool)
}

/// Every location any portable tool names, in table order and without repeats.
pub fn all_locations() -> Vec<Location> {
    let mut out: Vec<Location> = Vec::new();
    for policy in POLICIES {
        for location in policy.portability.locations() {
            if !out.contains(location) {
                out.push(*location);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::fs;

    /// The guard rail this table exists for: a new probe with no policy is a
    /// tool that would silently fail to migrate.
    ///
    /// Asserted against [`crate::Registry::tool_names`], never a count — the
    /// board grows, and a hardcoded number turns "somebody added a probe" into
    /// a puzzle instead of the one-line message below.
    ///
    /// The reverse is deliberately *not* an error: a policy may name a probe
    /// that has not landed yet, which is how this table gets written ahead of a
    /// tool rather than a release behind it.
    #[test]
    fn test_every_registered_tool_has_a_policy() {
        let dir = tempfile::tempdir().unwrap();
        let registry = crate::Registry::all(Paths::for_test(dir.path()));
        for tool in registry.tool_names() {
            assert!(
                policy_for(tool).is_some(),
                "`{tool}` has a probe but no migration policy; add one to POLICIES in \
                 migrate/policy.rs saying whether its credential can move"
            );
        }
    }

    #[test]
    fn test_the_policy_table_names_each_tool_once() {
        let mut seen = HashSet::new();
        for policy in POLICIES {
            assert!(
                seen.insert(policy.tool),
                "`{}` is in POLICIES twice; policy_for would silently pick the first",
                policy.tool
            );
        }
    }

    /// cloudflared's files are account credentials. They belong in the
    /// encrypted payload and nowhere else, and `config.yml` — which describes
    /// the *old* machine's local ingress — must stay behind.
    #[test]
    fn test_cloudflared_carries_credentials_and_not_local_ingress() {
        let dir = home_with(&[
            (".cloudflared/cert.pem", "-----BEGIN PRIVATE KEY-----\n"),
            (
                ".cloudflared/8f21-uuid.json",
                r#"{"AccountTag":"a","TunnelSecret":"c2VjcmV0","TunnelID":"8f21"}"#,
            ),
            (
                ".cloudflared/config.yml",
                "ingress:\n  - service: http://localhost:8080\n",
            ),
        ]);
        let rels: Vec<String> = Location::Cloudflared
            .collect(&Paths::for_test(dir.path()))
            .into_iter()
            .map(|f| f.rel)
            .collect();
        assert!(rels.contains(&"cert.pem".to_string()), "{rels:?}");
        assert!(rels.contains(&"8f21-uuid.json".to_string()), "{rels:?}");
        assert!(
            !rels.contains(&"config.yml".to_string()),
            "local ingress config followed the credentials: {rels:?}"
        );
    }

    #[test]
    fn test_ngrok_and_cloudflared_honour_their_own_environment_variables() {
        let paths = Paths::for_test("/nowhere");
        assert_eq!(
            ngrok_config(&paths),
            PathBuf::from("/nowhere/Library/Application Support/ngrok/ngrok.yml")
        );
        assert_eq!(
            ngrok_config(&paths.clone().with_env("NGROK_CONFIG", "/vol/ngrok.yml")),
            PathBuf::from("/vol/ngrok.yml")
        );
        assert_eq!(
            cloudflared_dir(&paths),
            PathBuf::from("/nowhere/.cloudflared")
        );
        assert_eq!(
            cloudflared_dir(&paths.with_env("TUNNEL_ORIGIN_CERT", "/vol/cf/cert.pem")),
            PathBuf::from("/vol/cf")
        );
    }

    #[test]
    fn test_every_policy_carries_a_reason_and_a_fix() {
        for policy in POLICIES {
            assert!(!policy.fix.is_empty(), "{} has no fix command", policy.tool);
            assert!(
                !policy.install.is_empty(),
                "{} has no install hint",
                policy.tool
            );
            match policy.portability {
                Portability::Portable { locations } => assert!(
                    !locations.is_empty(),
                    "{} is portable but names no location",
                    policy.tool
                ),
                _ => assert!(
                    policy.portability.reason().len() > 20,
                    "{} needs a real explanation, not `{}`",
                    policy.tool,
                    policy.portability.reason()
                ),
            }
        }
    }

    #[test]
    fn test_ssh_private_keys_are_never_a_location() {
        let policy = policy_for("ssh").unwrap();
        assert_eq!(policy.portability.locations(), &[Location::SshConfig]);
        // The only ssh location must resolve to the config file itself, never
        // the directory that holds the keys.
        let paths = Paths::for_test("/nowhere");
        assert_eq!(
            Location::SshConfig.destination(&paths, "config"),
            PathBuf::from("/nowhere/.ssh/config")
        );
    }

    #[test]
    fn test_location_keys_are_unique_and_match_their_wire_name() {
        let mut seen = HashSet::new();
        for location in all_locations() {
            assert!(seen.insert(location.key()), "duplicate key {location:?}");
            let wire = serde_json::to_value(location).unwrap();
            assert_eq!(wire, location.key(), "{location:?}");
            assert!(!location.describe().is_empty());
        }
        // Every variant must be reachable from some tool, or it is a location
        // nothing would ever export.
        assert!(all_locations().len() >= 15, "{:?}", all_locations().len());
    }

    // --- collection ---------------------------------------------------------

    fn home_with(files: &[(&str, &str)]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        for (rel, body) in files {
            let path = dir.path().join(rel);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(&path, body).unwrap();
        }
        dir
    }

    #[test]
    fn test_single_file_locations_round_trip_through_paths() {
        let dir = home_with(&[
            (".aws/config", "[default]\nregion = eu-west-1\n"),
            (".aws/credentials", "[default]\naws_access_key_id = AKIA\n"),
            (".npmrc", "//registry.npmjs.org/:_authToken=npm_x\n"),
        ]);
        let paths = Paths::for_test(dir.path());

        let files = Location::AwsCredentials.collect(&paths);
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].rel, "credentials");
        assert_eq!(files[0].source, dir.path().join(".aws/credentials"));

        // The destination is resolved from the *target* machine's Paths, so an
        // override there moves the file without the bundle knowing.
        let target =
            Paths::for_test("/other").with_env("AWS_SHARED_CREDENTIALS_FILE", "/vol/creds");
        assert_eq!(
            Location::AwsCredentials.destination(&target, &files[0].rel),
            PathBuf::from("/vol/creds")
        );
        assert_eq!(
            Location::Npmrc.destination(&Paths::for_test("/other"), "npmrc"),
            PathBuf::from("/other/.npmrc")
        );
    }

    #[test]
    fn test_gcloud_tree_takes_credentials_and_leaves_the_noise() {
        let dir = home_with(&[
            (".config/gcloud/credentials.db", "sqlite"),
            (".config/gcloud/access_tokens.db", "sqlite"),
            (".config/gcloud/active_config", "work"),
            (".config/gcloud/configurations/config_work", "[core]\n"),
            (".config/gcloud/configurations/config_default", "[core]\n"),
            (".config/gcloud/logs/2026.01.01/run.log", "chatter"),
            (".config/gcloud/.last_survey_prompt.yaml", "x"),
        ]);
        let paths = Paths::for_test(dir.path());
        let rels: Vec<String> = Location::Gcloud
            .collect(&paths)
            .into_iter()
            .map(|f| f.rel)
            .collect();
        assert_eq!(
            rels,
            vec![
                "access_tokens.db",
                "active_config",
                "configurations/config_default",
                "configurations/config_work",
                "credentials.db",
            ]
        );
    }

    #[test]
    fn test_kubeconfig_fan_keeps_every_file_and_lands_them_in_one_directory() {
        let dir = home_with(&[
            ("kube/a.yaml", "apiVersion: v1\n"),
            ("kube/b.yaml", "apiVersion: v1\n"),
        ]);
        let list = format!(
            "{}:{}",
            dir.path().join("kube/a.yaml").display(),
            dir.path().join("kube/b.yaml").display()
        );
        let paths = Paths::for_test(dir.path()).with_env("KUBECONFIG", &list);
        let files = Location::KubeConfigs.collect(&paths);
        assert_eq!(files.len(), 2);
        assert_eq!(files[0].rel, "a.yaml");

        // A default destination collapses them into ~/.kube/.
        let target = Paths::for_test("/other");
        assert_eq!(
            Location::KubeConfigs.destination(&target, "a.yaml"),
            PathBuf::from("/other/.kube/a.yaml")
        );
    }

    #[test]
    fn test_missing_files_and_directories_collect_nothing() {
        let paths = Paths::for_test("/nowhere");
        for location in all_locations() {
            assert!(
                location.collect(&paths).is_empty(),
                "{location:?} invented a file"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn test_file_mode_travels() {
        use std::os::unix::fs::PermissionsExt;
        let dir = home_with(&[(".aws/credentials", "[default]\n")]);
        let path = dir.path().join(".aws/credentials");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let files = Location::AwsCredentials.collect(&Paths::for_test(dir.path()));
        assert_eq!(files[0].mode, 0o600);
    }
}
