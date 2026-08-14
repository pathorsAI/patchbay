//! Which version of each CLI is installed, which is current, and how to close
//! the gap.
//!
//! Three facts travel together but are gathered independently, because they
//! fail independently:
//!
//! * **installed version** — from executing the tool's own version command.
//! * **latest version + update command** — from the tool's *install source*.
//! * advisories — curated, version-independent, and in [`crate::deprecations`].
//!
//! # Why this is not tier 1
//!
//! Executing 23 binaries costs seconds; `gcloud --version` alone starts a
//! Python interpreter. The status board must stay in the tens of milliseconds,
//! so [`crate::Registry::status_all`] reads **only** the cache
//! ([`Paths::versions_file`]) and never execs, never dials out. A cold cache
//! means no version column, never a slow board.
//!
//! Filling the cache is an explicit action: `pb check-updates`, the MCP
//! `check_updates` tool, or a panel button.
//!
//! # Why install-source detection is the whole trick
//!
//! "What is the latest version" has no single answer — it depends entirely on
//! where the binary came from. Resolving the source first turns 23 lookups into
//! a handful: every Homebrew-managed tool is answered by **one**
//! `brew outdated --json=v2` call (this machine has 193 outdated formulae; one
//! call covers all of them), every npm-family tool by one small registry GET,
//! and self-updating vendor CLIs by no network call at all.
//!
//! # Seams
//!
//! Nothing here reaches the machine or the network directly. Execution goes
//! through [`VersionRunner`], Homebrew through [`BrewSource`], HTTP through the
//! [`HttpClient`] the key vault already defines. The tests inject all three, so
//! no test in this crate execs a binary or opens a socket.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::{Duration as StdDuration, Instant};

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

use crate::keys_verify::{HttpClient, UreqClient};
use crate::paths::Paths;

/// How long a cached answer is considered current. A day: CLI releases are not
/// an emergency, and the point of the cache is that the board never waits.
pub const DEFAULT_TTL_HOURS: i64 = 24;

/// Upper bound on concurrent workers. Small on purpose — this runs on a laptop
/// while the user waits, and the expensive part is one `brew` call anyway.
const MAX_THREADS: usize = 8;

/// Whole-run ceiling. A wedged network must not hang `pb check-updates`.
const TOTAL_BUDGET: StdDuration = StdDuration::from_secs(90);

/// Ceiling for one tool's version command. `gcloud --version` is the slow one
/// at roughly a second; anything past this is stuck, not slow.
const EXEC_TIMEOUT_HINT: StdDuration = StdDuration::from_secs(20);

// ---------------------------------------------------------------------------
// the wire types
// ---------------------------------------------------------------------------

/// Where a tool came from, which is what decides how "latest" is looked up.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    /// Installed by Homebrew. Answered in one batch call.
    Homebrew,
    /// A global npm package, installed with npm.
    Npm,
    /// A global npm package, installed with bun.
    Bun,
    /// A global npm package, installed with pnpm.
    Pnpm,
    /// Direct download of a GitHub release.
    Github,
    /// The vendor's CLI updates itself; there is no package index to consult.
    SelfManaged,
    /// Shipped with the operating system.
    System,
    /// patchbay could not tell. No claim is made about `latest`.
    Unknown,
}

impl Source {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Homebrew => "brew",
            Self::Npm => "npm",
            Self::Bun => "bun",
            Self::Pnpm => "pnpm",
            Self::Github => "github",
            Self::SelfManaged => "self-managed",
            Self::System => "system",
            Self::Unknown => "unknown",
        }
    }

    /// Whether resolving `latest` for this source needs the network.
    fn needs_network(&self) -> bool {
        matches!(self, Self::Npm | Self::Bun | Self::Pnpm | Self::Github)
    }
}

/// Everything patchbay knows about one tool's version, as cached and as shown.
///
/// `latest: None` is always "patchbay did not find out", never "you are up to
/// date" — `note` says which of the two it was.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VersionInfo {
    pub tool: String,
    /// As reported by the tool itself. `None` when it is not installed, or its
    /// version command failed.
    pub installed: Option<String>,
    /// As reported by the install source. `None` when patchbay could not ask.
    pub latest: Option<String>,
    pub source: Source,
    /// The exact command that would update this tool, when one is known.
    pub update_command: Option<String>,
    pub checked_at: DateTime<Utc>,
    /// Why a field is empty, or anything the user should know about the lookup
    /// (rate limits, timeouts, a vendor with no version endpoint).
    #[serde(default)]
    pub note: Option<String>,
}

impl VersionInfo {
    fn new(tool: &str, source: Source, now: DateTime<Utc>) -> Self {
        Self {
            tool: tool.to_string(),
            installed: None,
            latest: None,
            source,
            update_command: None,
            checked_at: now,
            note: None,
        }
    }

    /// `true` only when both versions are known and `latest` is genuinely
    /// newer. An unknown either side is never reported as an update.
    pub fn update_available(&self) -> bool {
        match (&self.installed, &self.latest) {
            (Some(installed), Some(latest)) => is_newer(latest, installed),
            _ => false,
        }
    }

    /// `2.95.0 → 2.97.0` when there is an update, else the installed version,
    /// else nothing. The compact form the status board puts in a cell.
    pub fn marker(&self) -> Option<String> {
        match (&self.installed, self.update_available()) {
            (Some(installed), true) => Some(format!(
                "{installed} → {}",
                self.latest.as_deref().unwrap_or("?")
            )),
            (Some(installed), false) => Some(installed.clone()),
            (None, _) => None,
        }
    }

    fn is_fresh(&self, now: DateTime<Utc>, ttl: Duration) -> bool {
        now.signed_duration_since(self.checked_at) < ttl
    }
}

/// Order two dotted versions numerically, component by component.
///
/// String comparison is not good enough: `"1.10.0" < "1.9.0"` lexicographically,
/// which would report an upgrade as a downgrade. `None` when either side is not
/// purely numeric (a build id like `10.2p1`, a date stamp) — better to admit
/// there is no order than to invent one.
///
/// Missing components count as zero, so `1.2` and `1.2.0` are equal.
pub fn compare(a: &str, b: &str) -> Option<std::cmp::Ordering> {
    let a = numeric_parts(a)?;
    let b = numeric_parts(b)?;
    let len = a.len().max(b.len());
    for i in 0..len {
        let x = a.get(i).copied().unwrap_or(0);
        let y = b.get(i).copied().unwrap_or(0);
        if x != y {
            return Some(x.cmp(&y));
        }
    }
    Some(std::cmp::Ordering::Equal)
}

/// Whether `latest` is genuinely ahead of `installed`.
///
/// When the two cannot be ordered numerically, a *difference* is reported but
/// never an ordering we cannot justify.
pub fn is_newer(latest: &str, installed: &str) -> bool {
    match compare(latest, installed) {
        Some(ordering) => ordering == std::cmp::Ordering::Greater,
        None => normalize(latest) != normalize(installed),
    }
}

fn normalize(v: &str) -> &str {
    v.trim().trim_start_matches('v')
}

fn numeric_parts(v: &str) -> Option<Vec<u64>> {
    let core = normalize(v).split(['-', '+']).next()?;
    let mut out = Vec::new();
    for part in core.split('.') {
        out.push(part.parse::<u64>().ok()?);
    }
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

// ---------------------------------------------------------------------------
// parsing a version out of a CLI's own output
// ---------------------------------------------------------------------------

/// How to pull a version number out of the text a tool prints.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseStrategy {
    /// The first dotted-numeric token anywhere in the output. Correct for 22 of
    /// the 23 tools, including the chatty ones — `gh version 2.95.0 (…)`,
    /// `Docker version 28.3.2, build 578ccf607d`, `Client Version: v1.32.2`.
    FirstSemver,
    /// Take whatever directly follows a literal marker. The escape hatch for
    /// output where the first number is the *wrong* number.
    AfterMarker(&'static str),
}

/// The first dotted-numeric version in `text`, with any leading `v` and any
/// surrounding punctuation removed. `None` when there is no such token.
pub fn first_semver(text: &str) -> Option<String> {
    text.split_whitespace().find_map(semver_in)
}

/// Scan one whitespace-delimited token for an embedded dotted version, so
/// `aws-cli/2.32.6` and `v1.32.2,` both work.
fn semver_in(token: &str) -> Option<String> {
    let chars: Vec<char> = token.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if !chars[i].is_ascii_digit() {
            i += 1;
            continue;
        }
        let start = i;
        let mut dots = 0;
        let mut last_digit = i;
        while i < chars.len() {
            if chars[i].is_ascii_digit() {
                last_digit = i;
                i += 1;
            } else if chars[i] == '.' && i + 1 < chars.len() && chars[i + 1].is_ascii_digit() {
                dots += 1;
                i += 1;
            } else {
                break;
            }
        }
        // At least one dot: a bare integer is a count or a year, not a version.
        if dots >= 1 {
            return Some(chars[start..=last_digit].iter().collect());
        }
        i = (last_digit + 1).max(i);
    }
    None
}

/// Apply a tool's parse strategy to its version output.
pub fn parse_version(strategy: ParseStrategy, text: &str) -> Option<String> {
    match strategy {
        ParseStrategy::FirstSemver => first_semver(text),
        ParseStrategy::AfterMarker(marker) => {
            let rest = text.split_once(marker)?.1;
            let value: String = rest
                .chars()
                .take_while(|c| !c.is_whitespace() && *c != ',' && *c != ';')
                .collect();
            let value = value.trim_start_matches('v').trim().to_string();
            if value.is_empty() {
                None
            } else {
                Some(value)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// the table
// ---------------------------------------------------------------------------

/// How to update a tool that manages its own updates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SelfUpdate {
    /// The command the human runs.
    pub command: &'static str,
    /// Why patchbay is not computing a latest version for this one.
    pub note: &'static str,
}

/// One tool's version story: how to ask it, and where "latest" lives.
///
/// The install-source fields are *candidates*, not conclusions — the source is
/// resolved from the binary's real path at check time ([`classify_path`]), and
/// these say what to do once it is known.
#[derive(Debug, Clone, Copy)]
pub struct ToolVersionSpec {
    pub tool: &'static str,
    /// Binary names to try, in order. More than one where the tool was renamed
    /// (`neon`/`neonctl`, `hf`/`huggingface-cli`, `fly`/`flyctl`).
    pub bins: &'static [&'static str],
    pub args: &'static [&'static str],
    pub parse: ParseStrategy,
    /// Homebrew formula or cask name, when Homebrew packages this tool. Not
    /// always the tool key: `kubectl` is `kubernetes-cli`, `neon` is `neonctl`.
    pub brew: Option<&'static str>,
    /// npm package name, when it is distributed on the npm registry.
    pub npm: Option<&'static str>,
    /// `owner/repo`, when releases are published on GitHub.
    pub github: Option<&'static str>,
    /// The vendor's own updater, for CLIs with no package index behind them.
    pub self_update: Option<SelfUpdate>,
}

/// Tools deliberately without a version entry.
///
/// Empty today. It exists so that opting a tool out is a visible, reviewed
/// decision rather than a gap that [`tests::test_every_registered_tool_has_a_version_entry`]
/// silently tolerates.
pub const OPTED_OUT: &[&str] = &[];

/// Every tool patchbay can report a version for.
///
/// Formats were verified by running each command on a machine that has it
/// (see the parsing tests, which are those exact strings); the rest come from
/// each tool's published docs and are marked as such.
pub const VERSIONS: &[ToolVersionSpec] = &[
    // `Google Cloud SDK 578.0.0` followed by a component list. Verified.
    ToolVersionSpec {
        tool: "gcloud",
        bins: &["gcloud"],
        args: &["--version"],
        parse: ParseStrategy::FirstSemver,
        brew: Some("google-cloud-sdk"),
        npm: None,
        github: None,
        self_update: Some(SelfUpdate {
            command: "gcloud components update",
            note: "gcloud manages its own components; there is no package index to compare against",
        }),
    },
    // `aws-cli/2.32.6 Python/3.13.9 Darwin/…` — from the AWS CLI v2 docs.
    ToolVersionSpec {
        tool: "aws",
        bins: &["aws"],
        args: &["--version"],
        parse: ParseStrategy::FirstSemver,
        brew: Some("awscli"),
        npm: None,
        github: Some("aws/aws-cli"),
        self_update: Some(SelfUpdate {
            command: "re-run the AWS CLI v2 macOS installer package",
            note: "AWS ships the v2 CLI as an OS installer package, not through a package index",
        }),
    },
    // stdout is `azure-cli   2.88.0 *`; the "updates available" warning goes to
    // stderr and is not parsed. Verified.
    ToolVersionSpec {
        tool: "az",
        bins: &["az"],
        args: &["--version"],
        parse: ParseStrategy::FirstSemver,
        brew: Some("azure-cli"),
        npm: None,
        github: Some("Azure/azure-cli"),
        self_update: Some(SelfUpdate {
            command: "az upgrade",
            note: "the Azure CLI upgrades itself",
        }),
    },
    // Bare `14.2.1`. Verified.
    ToolVersionSpec {
        tool: "firebase",
        bins: &["firebase"],
        args: &["--version"],
        parse: ParseStrategy::FirstSemver,
        brew: None,
        npm: Some("firebase-tools"),
        github: Some("firebase/firebase-tools"),
        self_update: None,
    },
    // Bare `2.38.2`, from either binary name. Verified.
    ToolVersionSpec {
        tool: "neon",
        bins: &["neon", "neonctl"],
        args: &["--version"],
        parse: ParseStrategy::FirstSemver,
        brew: Some("neonctl"),
        npm: Some("neonctl"),
        github: Some("neondatabase/neonctl"),
        self_update: None,
    },
    // Bare `2.x.y`, per the Supabase CLI docs.
    ToolVersionSpec {
        tool: "supabase",
        bins: &["supabase"],
        args: &["--version"],
        parse: ParseStrategy::FirstSemver,
        brew: Some("supabase"),
        npm: Some("supabase"),
        github: Some("supabase/cli"),
        self_update: None,
    },
    // `flyctl v0.3.x darwin/arm64 Commit: … BuildDate: …`, per flyctl's docs.
    ToolVersionSpec {
        tool: "flyctl",
        bins: &["flyctl", "fly"],
        args: &["version"],
        parse: ParseStrategy::FirstSemver,
        brew: Some("flyctl"),
        npm: None,
        github: Some("superfly/flyctl"),
        self_update: Some(SelfUpdate {
            command: "fly version upgrade",
            note: "flyctl installed by its own install script updates itself",
        }),
    },
    // `doctl version 1.x.y-release`, per doctl's docs.
    ToolVersionSpec {
        tool: "doctl",
        bins: &["doctl"],
        args: &["version"],
        parse: ParseStrategy::FirstSemver,
        brew: Some("doctl"),
        npm: None,
        github: Some("digitalocean/doctl"),
        self_update: None,
    },
    // `gh version 2.95.0 (2026-06-17)` — note the date must not be mistaken for
    // the version, which is why the extractor requires a dot. Verified.
    ToolVersionSpec {
        tool: "gh",
        bins: &["gh"],
        args: &["--version"],
        parse: ParseStrategy::FirstSemver,
        brew: Some("gh"),
        npm: None,
        github: Some("cli/cli"),
        self_update: None,
    },
    // Bare `10.9.8`. Verified.
    ToolVersionSpec {
        tool: "npm",
        bins: &["npm"],
        args: &["--version"],
        parse: ParseStrategy::FirstSemver,
        brew: None,
        npm: Some("npm"),
        github: None,
        self_update: None,
    },
    // `infisical version 0.43.121`. Verified.
    ToolVersionSpec {
        tool: "infisical",
        bins: &["infisical"],
        args: &["--version"],
        parse: ParseStrategy::FirstSemver,
        brew: Some("infisical"),
        npm: None,
        github: Some("Infisical/infisical"),
        self_update: None,
    },
    // Bare `2.x.y`, per the 1Password CLI docs. Homebrew ships it as a cask.
    ToolVersionSpec {
        tool: "op",
        bins: &["op"],
        args: &["--version"],
        parse: ParseStrategy::FirstSemver,
        brew: Some("1password-cli"),
        npm: None,
        github: None,
        self_update: Some(SelfUpdate {
            command: "op update",
            note: "the 1Password CLI updates itself outside any package index",
        }),
    },
    // `Client Version: v1.32.2` / `Kustomize Version: v5.5.0` — the client
    // version comes first, so the shared extractor is right here. Verified.
    ToolVersionSpec {
        tool: "kubectl",
        bins: &["kubectl"],
        args: &["version", "--client"],
        parse: ParseStrategy::FirstSemver,
        brew: Some("kubernetes-cli"),
        npm: None,
        github: Some("kubernetes/kubernetes"),
        self_update: None,
    },
    // Bare `4.105.0`. Verified.
    ToolVersionSpec {
        tool: "wrangler",
        bins: &["wrangler"],
        args: &["--version"],
        parse: ParseStrategy::FirstSemver,
        brew: None,
        npm: Some("wrangler"),
        github: None,
        self_update: None,
    },
    // `Vercel CLI 42.2.0` then the bare number again. Verified.
    ToolVersionSpec {
        tool: "vercel",
        bins: &["vercel"],
        args: &["--version"],
        parse: ParseStrategy::FirstSemver,
        brew: None,
        npm: Some("vercel"),
        github: None,
        self_update: None,
    },
    // `rclone v1.73.5` then a build banner mentioning `go1.26.2` and the OS
    // version — the first token is the right one. Verified.
    ToolVersionSpec {
        tool: "rclone",
        bins: &["rclone"],
        args: &["--version"],
        parse: ParseStrategy::FirstSemver,
        brew: Some("rclone"),
        npm: None,
        github: Some("rclone/rclone"),
        self_update: None,
    },
    // `Docker version 28.3.2, build 578ccf607d` — the trailing comma is part of
    // the token and is stripped. Verified.
    ToolVersionSpec {
        tool: "docker",
        bins: &["docker"],
        args: &["--version"],
        parse: ParseStrategy::FirstSemver,
        brew: Some("docker"),
        npm: None,
        github: None,
        self_update: Some(SelfUpdate {
            command: "update Docker Desktop from its own menu",
            note: "Docker Desktop bundles and updates the docker CLI itself",
        }),
    },
    // `ngrok version 3.25.1`. Verified. Homebrew ships it as a CASK, not a
    // formula, so `brew outdated --json=v2` reports it under `casks`.
    ToolVersionSpec {
        tool: "ngrok",
        bins: &["ngrok"],
        args: &["--version"],
        parse: ParseStrategy::FirstSemver,
        brew: Some("ngrok"),
        npm: None,
        github: None,
        self_update: None,
    },
    // `cloudflared version 2025.2.1 (built …)`. Verified. Calendar versioning,
    // which the semver extractor still handles: three dotted numbers.
    ToolVersionSpec {
        tool: "cloudflared",
        bins: &["cloudflared"],
        args: &["--version"],
        parse: ParseStrategy::FirstSemver,
        brew: Some("cloudflared"),
        npm: None,
        github: Some("cloudflare/cloudflared"),
        self_update: None,
    },
    // `1.94.2` then a commit/go banner. Verified.
    ToolVersionSpec {
        tool: "tailscale",
        bins: &["tailscale"],
        args: &["version"],
        parse: ParseStrategy::FirstSemver,
        brew: Some("tailscale"),
        npm: None,
        github: Some("tailscale/tailscale"),
        self_update: None,
    },
    // `OpenSSH_10.2p1, LibreSSL 3.3.6` on stderr. The ONE case where the shared
    // extractor is wrong: the first dotted number it finds is LibreSSL's, and
    // OpenSSH's own `10.2p1` is not dotted-numeric at all. Verified.
    ToolVersionSpec {
        tool: "ssh",
        bins: &["ssh"],
        args: &["-V"],
        parse: ParseStrategy::AfterMarker("OpenSSH_"),
        brew: Some("openssh"),
        npm: None,
        github: None,
        self_update: Some(SelfUpdate {
            command: "softwareupdate --install --all",
            note: "/usr/bin/ssh ships with macOS and moves with the OS",
        }),
    },
    // `stripe version 1.x.y`, per the Stripe CLI docs.
    ToolVersionSpec {
        tool: "stripe",
        bins: &["stripe"],
        args: &["--version"],
        parse: ParseStrategy::FirstSemver,
        brew: Some("stripe"),
        npm: None,
        github: Some("stripe/stripe-cli"),
        self_update: None,
    },
    // `ollama version is 0.x.y`, per Ollama's docs.
    ToolVersionSpec {
        tool: "ollama",
        bins: &["ollama"],
        args: &["--version"],
        parse: ParseStrategy::FirstSemver,
        brew: Some("ollama"),
        npm: None,
        github: Some("ollama/ollama"),
        self_update: None,
    },
    // The `hf` CLI ships inside the `huggingface_hub` Python package, so the
    // version it prints is the library's. Both binary names are tried because
    // `huggingface-cli` is what older installs still have on PATH.
    ToolVersionSpec {
        tool: "huggingface",
        bins: &["hf", "huggingface-cli"],
        args: &["version"],
        parse: ParseStrategy::FirstSemver,
        brew: None,
        npm: None,
        github: Some("huggingface/huggingface_hub"),
        self_update: Some(SelfUpdate {
            command: "pip install -U huggingface_hub",
            note: "the CLI is part of the huggingface_hub Python package, not a standalone release",
        }),
    },
    // `2.1.220 (Claude Code)`. Verified.
    ToolVersionSpec {
        tool: "claude",
        bins: &["claude"],
        args: &["--version"],
        parse: ParseStrategy::FirstSemver,
        brew: None,
        npm: Some("@anthropic-ai/claude-code"),
        github: None,
        self_update: Some(SelfUpdate {
            command: "claude update",
            note: "the native install updates itself",
        }),
    },
];

pub fn spec_for(tool: &str) -> Option<&'static ToolVersionSpec> {
    VERSIONS.iter().find(|s| s.tool == tool)
}

// ---------------------------------------------------------------------------
// patchbay's own row
// ---------------------------------------------------------------------------

/// patchbay, as it appears in its own table.
///
/// Deliberately *not* in [`VERSIONS`]: that table is keyed by registered tools,
/// and patchbay has no probe of itself. Callers ask for this row by putting the
/// name in the tool list ([`crate::Registry::check_updates`] always does), and
/// [`check_updates_with`] answers it without touching [`spec_for`].
pub const SELF_TOOL: &str = "patchbay";

/// patchbay's release feed — the same one the panel's in-app updater reads.
pub const SELF_REPO: &str = "pathorsAI/patchbay";

/// The spec behind [`SELF_TOOL`].
///
/// `bins` and `args` are never used: the installed version is compiled in (see
/// [`resolve_self`]), because the code asking the question *is* the answer, and
/// the `pb` on `PATH` may be a different build entirely. The rest is a normal
/// GitHub-release spec, so the lookup and the update command fall out of the
/// machinery every other tool already goes through.
static SELF_SPEC: ToolVersionSpec = ToolVersionSpec {
    tool: SELF_TOOL,
    bins: &["pb"],
    args: &["--version"],
    parse: ParseStrategy::FirstSemver,
    brew: None,
    npm: None,
    github: Some(SELF_REPO),
    self_update: Some(SelfUpdate {
        command: "download the DMG / curl the CLI tarball from the release page",
        note:
            "patchbay ships as a signed DMG and CLI tarballs; the panel offers the update in place",
    }),
};

/// patchbay's row: the installed version without executing anything.
///
/// [`Source::Github`] rather than self-managed — the release page really is the
/// index, so `latest` is a normal lookup that rides phase 3 with every other
/// GitHub tool, sharing the same rate-limit stop. Only the *update command* is
/// a human instruction, the way `gcloud`'s is.
fn resolve_self(now: DateTime<Utc>) -> Resolved {
    let mut info = VersionInfo::new(SELF_TOOL, Source::Github, now);
    info.installed = Some(env!("CARGO_PKG_VERSION").to_string());
    Resolved {
        spec: &SELF_SPEC,
        package: None,
        info,
    }
}

// ---------------------------------------------------------------------------
// install-source detection
// ---------------------------------------------------------------------------

/// A source resolved from a real binary path, with the package name that path
/// revealed (which beats the table: `neon`'s binary lives in the `neonctl`
/// Cellar, and only the path says so).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetectedSource {
    pub source: Source,
    pub package: Option<String>,
}

/// Homebrew prefixes to recognise. `HOMEBREW_PREFIX` when the shell exported
/// it, else both standard locations — Apple silicon and Intel.
fn brew_prefixes(paths: &Paths) -> Vec<PathBuf> {
    match paths.env("HOMEBREW_PREFIX") {
        Some(prefix) => vec![PathBuf::from(prefix)],
        None => vec![PathBuf::from("/opt/homebrew"), PathBuf::from("/usr/local")],
    }
}

/// Global bin directories of the JS package managers that do not leave a
/// `node_modules` component in the resolved path (pnpm installs a shim).
fn js_bin_dirs(paths: &Paths) -> Vec<(PathBuf, Source)> {
    let mut dirs = vec![(paths.home().join(".bun/bin"), Source::Bun)];
    match paths.env("PNPM_HOME") {
        Some(home) => dirs.push((PathBuf::from(home), Source::Pnpm)),
        None => dirs.push((paths.home().join("Library/pnpm"), Source::Pnpm)),
    }
    dirs
}

/// Classify a binary by where it lives.
///
/// `link` is the path found on `PATH`; `resolved` is that path with symlinks
/// followed. Both matter: pnpm's shim tells you nothing once resolved (it is
/// its own target), while bun's and npm's shims only reveal the package after
/// resolution.
///
/// Order is deliberate. A Homebrew-installed JS tool has *both* a Cellar prefix
/// and a `node_modules` component, and Homebrew is the thing that would update
/// it, so Homebrew wins.
pub fn classify_path(link: &Path, resolved: &Path, paths: &Paths) -> Option<DetectedSource> {
    let resolved_str = resolved.to_string_lossy().to_string();

    for prefix in brew_prefixes(paths) {
        if resolved.starts_with(&prefix) || link.starts_with(&prefix) {
            // `…/Cellar/<formula>/<version>/…` names the formula outright.
            let package = path_component_after(&resolved_str, "/Cellar/");
            return Some(DetectedSource {
                source: Source::Homebrew,
                package,
            });
        }
    }

    if let Some(package) = npm_package_in(&resolved_str) {
        let source = if resolved_str.contains("/.bun/") {
            Source::Bun
        } else if resolved_str.contains("/pnpm/") || resolved_str.contains("/Library/pnpm/") {
            Source::Pnpm
        } else {
            Source::Npm
        };
        return Some(DetectedSource {
            source,
            package: Some(package),
        });
    }

    let parent = link.parent();
    for (dir, source) in js_bin_dirs(paths) {
        if parent == Some(dir.as_path()) {
            return Some(DetectedSource {
                source,
                package: None,
            });
        }
    }

    if link.starts_with("/usr/bin") || link.starts_with("/bin") || link.starts_with("/usr/sbin") {
        return Some(DetectedSource {
            source: Source::System,
            package: None,
        });
    }

    None
}

/// `…/node_modules/wrangler/bin/wrangler.js` -> `wrangler`, and
/// `…/node_modules/@anthropic-ai/claude-code/…` -> `@anthropic-ai/claude-code`.
/// The *last* `node_modules` wins, so a nested dependency path resolves to the
/// dependency rather than to its host package.
fn npm_package_in(path: &str) -> Option<String> {
    let idx = path.rfind("/node_modules/")?;
    let rest = &path[idx + "/node_modules/".len()..];
    let mut parts = rest.split('/');
    let first = parts.next().filter(|p| !p.is_empty())?;
    if first.starts_with('@') {
        let second = parts.next().filter(|p| !p.is_empty())?;
        Some(format!("{first}/{second}"))
    } else {
        Some(first.to_string())
    }
}

fn path_component_after(path: &str, marker: &str) -> Option<String> {
    let idx = path.find(marker)?;
    let rest = &path[idx + marker.len()..];
    rest.split('/')
        .next()
        .filter(|p| !p.is_empty())
        .map(String::from)
}

/// The update command for a resolved source and package.
fn update_command(source: Source, package: Option<&str>, spec: &ToolVersionSpec) -> Option<String> {
    let package = package.or(spec.npm).or(spec.brew);
    match source {
        Source::Homebrew => package.map(|p| format!("brew upgrade {p}")),
        Source::Npm => package.map(|p| format!("npm install -g {p}@latest")),
        Source::Bun => package.map(|p| format!("bun add -g {p}@latest")),
        Source::Pnpm => package.map(|p| format!("pnpm add -g {p}@latest")),
        Source::Github => spec.self_update.map(|u| u.command.to_string()).or_else(|| {
            spec.github.map(|repo| {
                format!(
                    "download the latest release from https://github.com/{repo}/releases/latest"
                )
            })
        }),
        Source::SelfManaged | Source::System => spec.self_update.map(|u| u.command.to_string()),
        Source::Unknown => None,
    }
}

// ---------------------------------------------------------------------------
// the cache
// ---------------------------------------------------------------------------

/// The on-disk cache. No secrets, so no 0600 dance — this is public
/// information about public software.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VersionCache {
    /// Bumped if the shape ever changes; an unknown value is treated as a cold
    /// cache rather than an error.
    #[serde(default = "cache_version")]
    pub version: u32,
    #[serde(default)]
    pub entries: BTreeMap<String, VersionInfo>,
}

fn cache_version() -> u32 {
    1
}

impl VersionCache {
    /// Read the cache. A missing, unreadable or malformed file is an empty
    /// cache, never an error: a corrupt cache must not be able to break the
    /// status board.
    pub fn load(path: &Path) -> Self {
        let Ok(Some(text)) = crate::util::read_text(path) else {
            return Self::default();
        };
        serde_json::from_str(&text).unwrap_or_default()
    }

    pub fn save(&self, path: &Path) -> anyhow::Result<()> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let text = serde_json::to_string_pretty(self)?;
        // Write-then-rename: a killed process leaves the old cache, not half a
        // new one.
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, text)?;
        std::fs::rename(&tmp, path)?;
        Ok(())
    }

    pub fn get(&self, tool: &str) -> Option<&VersionInfo> {
        self.entries.get(tool)
    }

    /// The entry for `tool`, only if it has not aged out.
    pub fn get_fresh(&self, tool: &str, now: DateTime<Utc>, ttl: Duration) -> Option<&VersionInfo> {
        self.entries.get(tool).filter(|e| e.is_fresh(now, ttl))
    }

    pub fn put(&mut self, info: VersionInfo) {
        self.entries.insert(info.tool.clone(), info);
    }
}

// ---------------------------------------------------------------------------
// seams
// ---------------------------------------------------------------------------

/// Runs a tool's own version command. The seam that keeps `exec` out of tests.
pub trait VersionRunner: Send + Sync {
    /// `Ok(output)` for a command that ran (whatever its exit status — several
    /// CLIs print their version to stderr and exit non-zero), `Err` when the
    /// binary could not be spawned.
    fn run(&self, bin: &str, args: &[&str]) -> Result<String, String>;
}

/// The real runner: [`crate::util::run`], preferring stdout and falling back to
/// stderr (`ssh -V` writes its version there).
pub struct CommandRunner;

impl VersionRunner for CommandRunner {
    fn run(&self, bin: &str, args: &[&str]) -> Result<String, String> {
        let output = crate::util::run(bin, args).map_err(|e| e.to_string())?;
        let text = if output.stdout.trim().is_empty() {
            output.stderr
        } else {
            output.stdout
        };
        Ok(text)
    }
}

/// Finds a tool's binary and resolves it through any symlinks.
///
/// A seam of its own because *where* a binary is decides which source owns it,
/// and a test must be able to describe a machine layout without having one.
pub trait BinaryLocator: Send + Sync {
    /// `(path as found on PATH, path with symlinks followed)`, or `None` when
    /// the binary is not installed.
    fn locate(&self, name: &str) -> Option<(PathBuf, PathBuf)>;
}

/// The real `PATH`, via [`Paths::binary_path`].
pub struct SystemBinaries<'a>(pub &'a Paths);

impl BinaryLocator for SystemBinaries<'_> {
    fn locate(&self, name: &str) -> Option<(PathBuf, PathBuf)> {
        let link = self.0.binary_path(name)?;
        let resolved = std::fs::canonicalize(&link).unwrap_or_else(|_| link.clone());
        Some((link, resolved))
    }
}

/// Supplies `brew outdated --json=v2`. One call answers every Homebrew tool.
pub trait BrewSource: Send + Sync {
    fn outdated_json(&self) -> Result<String, String>;
}

/// The real Homebrew, called exactly once per `check_updates` run.
#[derive(Default)]
pub struct BrewCli {
    calls: AtomicUsize,
}

impl BrewCli {
    pub fn new() -> Self {
        Self::default()
    }

    /// How many times Homebrew was actually invoked. The batch guarantee is
    /// the whole point of the design, so it is observable rather than assumed.
    pub fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl BrewSource for BrewCli {
    fn outdated_json(&self) -> Result<String, String> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let output = crate::util::run("brew", &["outdated", "--json=v2"])
            .map_err(|e| format!("could not run brew ({e})"))?;
        if output.stdout.trim().is_empty() {
            return Err(format!(
                "brew outdated produced no output ({})",
                output.message()
            ));
        }
        Ok(output.stdout)
    }
}

/// `brew outdated --json=v2`, reduced to name -> current version.
///
/// Formulae and casks are merged into one index: the two namespaces do not
/// collide for anything patchbay tracks, and a caller only wants to know
/// whether *its* tool is behind.
pub fn parse_brew_outdated(json: &str) -> Result<HashMap<String, String>, String> {
    #[derive(Deserialize)]
    struct Outdated {
        #[serde(default)]
        formulae: Vec<Entry>,
        #[serde(default)]
        casks: Vec<Entry>,
    }
    #[derive(Deserialize)]
    struct Entry {
        name: String,
        #[serde(default)]
        current_version: String,
    }

    let parsed: Outdated = serde_json::from_str(json)
        .map_err(|e| format!("brew outdated returned unusable JSON: {e}"))?;
    let mut out = HashMap::new();
    for entry in parsed.formulae.into_iter().chain(parsed.casks) {
        if !entry.current_version.is_empty() {
            // Casks version as `<version>,<build>` (ngrok: `3.39.11,dy27w…`).
            // The build id is noise next to what the tool reports about
            // itself, so it is dropped; formulae have no comma and are
            // unaffected.
            let version = match entry.current_version.split_once(',') {
                Some((version, _build)) => version.to_string(),
                None => entry.current_version,
            };
            out.insert(entry.name, version);
        }
    }
    Ok(out)
}

/// The npm registry's `latest` dist-tag for a package.
pub fn npm_latest(package: &str, http: &dyn HttpClient) -> Result<String, String> {
    #[derive(Deserialize)]
    struct Packument {
        #[serde(default)]
        version: String,
    }
    // Scoped names must keep their `/` unescaped; the registry's abbreviated
    // endpoint is what npm itself uses for this.
    let url = format!("https://registry.npmjs.org/{package}/latest");
    let response = http.get(&url, &[("Accept", "application/json")])?;
    match response.status {
        200 => {
            let parsed: Packument = serde_json::from_str(&response.body)
                .map_err(|e| format!("the npm registry returned unusable JSON: {e}"))?;
            if parsed.version.is_empty() {
                Err("the npm registry did not report a version".to_string())
            } else {
                Ok(parsed.version)
            }
        }
        404 => Err(format!("the npm registry has no package `{package}`")),
        status => Err(format!("the npm registry returned HTTP {status}")),
    }
}

/// Whether a GitHub lookup failed because the unauthenticated quota is spent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GithubError {
    /// 403/429 with the rate-limit headers. Do not retry, do not spam.
    RateLimited,
    Other(String),
}

/// The tag of a repository's latest release.
///
/// Unauthenticated, which means 60 requests an hour for the whole machine. A
/// rate-limit answer is reported as exactly that and never retried — the point
/// of the cache is that we ask rarely.
pub fn github_latest(repo: &str, http: &dyn HttpClient) -> Result<String, GithubError> {
    #[derive(Deserialize)]
    struct Release {
        #[serde(default)]
        tag_name: String,
    }
    let url = format!("https://api.github.com/repos/{repo}/releases/latest");
    let response = http
        .get(
            &url,
            &[
                ("Accept", "application/vnd.github+json"),
                ("X-GitHub-Api-Version", "2022-11-28"),
            ],
        )
        .map_err(GithubError::Other)?;

    match response.status {
        200 => {
            let parsed: Release = serde_json::from_str(&response.body)
                .map_err(|e| GithubError::Other(format!("GitHub returned unusable JSON: {e}")))?;
            let tag = parsed.tag_name.trim().trim_start_matches('v');
            if tag.is_empty() {
                Err(GithubError::Other(
                    "GitHub reported a release with no tag".to_string(),
                ))
            } else {
                Ok(tag.to_string())
            }
        }
        // GitHub uses 403 for both "rate limited" and "forbidden"; the
        // remaining-quota header is what tells them apart.
        403 | 429 => {
            if response.header("x-ratelimit-remaining") == Some("0")
                || response.body.contains("rate limit")
            {
                Err(GithubError::RateLimited)
            } else {
                Err(GithubError::Other("GitHub returned HTTP 403".to_string()))
            }
        }
        404 => Err(GithubError::Other(format!(
            "GitHub has no published release for {repo}"
        ))),
        status => Err(GithubError::Other(format!("GitHub returned HTTP {status}"))),
    }
}

// ---------------------------------------------------------------------------
// the check
// ---------------------------------------------------------------------------

/// What one `check_updates` run did, alongside what it found.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CheckReport {
    pub entries: Vec<VersionInfo>,
    /// How many times Homebrew was invoked. Should be 0 or 1, forever.
    pub brew_calls: usize,
    /// Outbound HTTP requests made (npm registry + GitHub).
    pub network_calls: usize,
    /// Tools answered from a still-fresh cache instead of being re-checked.
    pub from_cache: usize,
    pub elapsed_ms: u64,
    /// Run-level problems: brew missing, the budget running out.
    #[serde(default)]
    pub notes: Vec<String>,
}

impl CheckReport {
    /// Tools with an update waiting.
    pub fn outdated(&self) -> Vec<&VersionInfo> {
        self.entries
            .iter()
            .filter(|e| e.update_available())
            .collect()
    }
}

/// Knobs for one run.
#[derive(Debug, Clone, Copy)]
pub struct CheckOptions {
    /// Ignore cached entries and re-check everything.
    pub refresh: bool,
    pub ttl: Duration,
}

impl Default for CheckOptions {
    fn default() -> Self {
        Self {
            refresh: false,
            ttl: Duration::hours(DEFAULT_TTL_HOURS),
        }
    }
}

/// Every edge of the machine a check has to touch, in one place so a test can
/// replace all of them at once.
pub struct Deps<'a> {
    pub runner: &'a dyn VersionRunner,
    pub brew: &'a dyn BrewSource,
    pub http: &'a dyn HttpClient,
    pub binaries: &'a dyn BinaryLocator,
}

/// Check every named tool against the real machine and the real network, and
/// write the result to the cache.
pub fn check_updates(paths: &Paths, tools: &[&str], options: CheckOptions) -> CheckReport {
    let brew = BrewCli::new();
    let http = UreqClient::new();
    let binaries = SystemBinaries(paths);
    let report = check_updates_with(
        paths,
        tools,
        options,
        &Deps {
            runner: &CommandRunner,
            brew: &brew,
            http: &http,
            binaries: &binaries,
        },
    );
    // Persisting is best effort: a read-only home should not fail the command.
    let mut cache = VersionCache::load(&paths.versions_file());
    for info in &report.entries {
        cache.put(info.clone());
    }
    let _ = cache.save(&paths.versions_file());
    report
}

/// [`check_updates`] with every outside edge injected. This is what the tests
/// call, and it never writes the cache file.
pub fn check_updates_with(
    paths: &Paths,
    tools: &[&str],
    options: CheckOptions,
    deps: &Deps<'_>,
) -> CheckReport {
    let started = Instant::now();
    let now = Utc::now();
    let mut report = CheckReport::default();

    let cache = VersionCache::load(&paths.versions_file());
    let mut specs: Vec<&'static ToolVersionSpec> = Vec::new();
    // patchbay reports itself alongside the tools it watches, but it is not one
    // of them: no probe, no entry in VERSIONS, nothing to exec. Held aside here
    // and answered by `resolve_self` below.
    let mut wants_self = false;
    for tool in tools {
        if *tool == SELF_TOOL {
            wants_self = true;
            continue;
        }
        match spec_for(tool) {
            Some(spec) => specs.push(spec),
            None if OPTED_OUT.contains(tool) => {}
            None => report
                .notes
                .push(format!("no version entry for `{tool}`; skipped")),
        }
    }

    // Anything still fresh is answered from the cache and never touched again —
    // which is what makes a second run inside the TTL do zero network work.
    let mut pending: Vec<&'static ToolVersionSpec> = Vec::new();
    for spec in specs {
        match (
            options.refresh,
            cache.get_fresh(spec.tool, now, options.ttl),
        ) {
            (false, Some(cached)) => {
                report.from_cache += 1;
                report.entries.push(cached.clone());
            }
            _ => pending.push(spec),
        }
    }

    // patchbay's own row obeys that same TTL — it is one more GitHub lookup,
    // and there is no reason for it to be the one thing that asks every run.
    let mut self_pending = false;
    if wants_self {
        match (
            options.refresh,
            cache.get_fresh(SELF_TOOL, now, options.ttl),
        ) {
            (false, Some(cached)) => {
                report.from_cache += 1;
                report.entries.push(cached.clone());
            }
            _ => self_pending = true,
        }
    }

    // --- phase 1: local. Ask each tool its own version, in parallel. --------
    let mut resolved: Vec<Resolved> = run_bounded(&pending, MAX_THREADS, |spec| {
        resolve_local(spec, paths, deps, now)
    });
    if self_pending {
        resolved.push(resolve_self(now));
    }

    // --- phase 2: Homebrew. ONE call, however many brew tools there are. ----
    let brew_wanted = resolved.iter().any(|r| r.info.source == Source::Homebrew);
    if brew_wanted {
        report.brew_calls += 1;
        match deps
            .brew
            .outdated_json()
            .and_then(|json| parse_brew_outdated(&json))
        {
            Ok(index) => {
                for item in resolved.iter_mut() {
                    if item.info.source != Source::Homebrew {
                        continue;
                    }
                    let Some(name) = item.package.clone() else {
                        continue;
                    };
                    match index.get(&name) {
                        Some(current) => item.info.latest = Some(current.clone()),
                        // Absent from `brew outdated` means brew considers it
                        // current — the installed version IS the latest.
                        None => item.info.latest = item.info.installed.clone(),
                    }
                }
            }
            Err(e) => {
                report.notes.push(format!("Homebrew lookup failed: {e}"));
                for item in resolved.iter_mut() {
                    if item.info.source == Source::Homebrew {
                        item.info.note = Some(format!("could not ask Homebrew: {e}"));
                    }
                }
            }
        }
    }

    // --- phase 3: network, for the sources that need it. --------------------
    let budget_left = TOTAL_BUDGET.checked_sub(started.elapsed());
    let network: Vec<usize> = resolved
        .iter()
        .enumerate()
        .filter(|(_, r)| r.info.source.needs_network() && r.info.latest.is_none())
        .map(|(i, _)| i)
        .collect();

    if !network.is_empty() {
        match budget_left {
            None => report
                .notes
                .push("ran out of time before the network lookups; try again".to_string()),
            Some(_) => {
                let calls = AtomicUsize::new(0);
                // A rate-limited GitHub answer stops every other GitHub lookup
                // in this run: 60 requests an hour is shared machine-wide, and
                // hammering it helps nobody.
                let rate_limited = Mutex::new(false);
                let jobs: Vec<(usize, &'static ToolVersionSpec, Option<String>, Source)> = network
                    .iter()
                    .map(|&i| {
                        (
                            i,
                            resolved[i].spec,
                            resolved[i].package.clone(),
                            resolved[i].info.source,
                        )
                    })
                    .collect();

                let results =
                    run_bounded(&jobs, MAX_THREADS.min(4), |(i, spec, package, source)| {
                        let outcome = lookup_latest(
                            spec,
                            package.as_deref(),
                            *source,
                            deps.http,
                            &calls,
                            &rate_limited,
                            started,
                        );
                        (*i, outcome)
                    });
                report.network_calls += calls.load(Ordering::SeqCst);
                for (i, outcome) in results {
                    match outcome {
                        Ok(latest) => resolved[i].info.latest = Some(latest),
                        Err(note) => resolved[i].info.note = Some(note),
                    }
                }
            }
        }
    }

    // --- finish: fill in the update command and any explanatory note. -------
    for item in resolved.iter_mut() {
        item.info.update_command =
            update_command(item.info.source, item.package.as_deref(), item.spec);
        if item.info.latest.is_none() && item.info.note.is_none() {
            item.info.note = match item.info.source {
                Source::SelfManaged | Source::System => {
                    item.spec.self_update.map(|u| u.note.to_string())
                }
                Source::Unknown => Some(
                    "patchbay could not tell how this tool was installed, so it makes no claim \
                     about the latest version"
                        .to_string(),
                ),
                _ => None,
            };
        }
    }

    report.entries.extend(resolved.into_iter().map(|r| r.info));
    report.entries.sort_by(|a, b| a.tool.cmp(&b.tool));
    report.elapsed_ms = started.elapsed().as_millis() as u64;
    report
}

/// One tool mid-flight: its spec, the package name its path revealed, and the
/// answer being assembled.
struct Resolved {
    spec: &'static ToolVersionSpec,
    package: Option<String>,
    info: VersionInfo,
}

/// Everything that can be learned without leaving the machine: is it here, what
/// version does it claim, and where did it come from.
fn resolve_local(
    spec: &'static ToolVersionSpec,
    paths: &Paths,
    deps: &Deps<'_>,
    now: DateTime<Utc>,
) -> Resolved {
    let found = spec.bins.iter().find_map(|bin| {
        let (link, resolved) = deps.binaries.locate(bin)?;
        Some((*bin, link, resolved))
    });

    let Some((bin, link, resolved_path)) = found else {
        let mut info = VersionInfo::new(spec.tool, Source::Unknown, now);
        info.note = Some("not installed".to_string());
        return Resolved {
            spec,
            package: None,
            info,
        };
    };

    let detected = classify_path(&link, &resolved_path, paths);
    let (source, package) = match detected {
        Some(d) => {
            let package = d.package.or_else(|| match d.source {
                Source::Homebrew => spec.brew.map(String::from),
                Source::Npm | Source::Bun | Source::Pnpm => spec.npm.map(String::from),
                _ => None,
            });
            (d.source, package)
        }
        // Nothing in the path said anything: fall back to what the table
        // declares, in order of how authoritative the answer would be.
        None if spec.self_update.is_some() => (Source::SelfManaged, None),
        None if spec.github.is_some() => (Source::Github, None),
        None => (Source::Unknown, None),
    };

    // A detected source with nothing to look up (a Homebrew formula we cannot
    // name, say) degrades to self-managed rather than lying about a package.
    let source = match source {
        Source::Homebrew if package.is_none() => Source::Unknown,
        other => other,
    };

    let mut info = VersionInfo::new(spec.tool, source, now);
    match deps.runner.run(bin, spec.args) {
        Ok(text) => match parse_version(spec.parse, &text) {
            Some(version) => info.installed = Some(version),
            None => {
                info.note = Some(format!(
                    "`{bin} {}` produced no recognisable version",
                    spec.args.join(" ")
                ))
            }
        },
        Err(e) => info.note = Some(format!("could not run `{bin}`: {e}")),
    }

    Resolved {
        spec,
        package,
        info,
    }
}

#[allow(clippy::too_many_arguments)]
fn lookup_latest(
    spec: &'static ToolVersionSpec,
    package: Option<&str>,
    source: Source,
    http: &dyn HttpClient,
    calls: &AtomicUsize,
    rate_limited: &Mutex<bool>,
    started: Instant,
) -> Result<String, String> {
    if started.elapsed() >= TOTAL_BUDGET {
        return Err("the run's time budget ran out before this lookup".to_string());
    }
    match source {
        Source::Npm | Source::Bun | Source::Pnpm => {
            let package = package
                .or(spec.npm)
                .ok_or_else(|| "no npm package name for this tool".to_string())?;
            calls.fetch_add(1, Ordering::SeqCst);
            npm_latest(package, http)
        }
        Source::Github => {
            if *rate_limited.lock().unwrap() {
                return Err(
                    "skipped: GitHub's unauthenticated rate limit was already hit in this run"
                        .to_string(),
                );
            }
            let repo = spec
                .github
                .ok_or_else(|| "no GitHub repository for this tool".to_string())?;
            calls.fetch_add(1, Ordering::SeqCst);
            match github_latest(repo, http) {
                Ok(tag) => Ok(tag),
                Err(GithubError::RateLimited) => {
                    *rate_limited.lock().unwrap() = true;
                    Err("GitHub's unauthenticated rate limit (60/hour) is spent; \
                         patchbay will not retry until it resets"
                        .to_string())
                }
                Err(GithubError::Other(e)) => Err(e),
            }
        }
        _ => Err("this source needs no network lookup".to_string()),
    }
}

/// Run `f` over `items` on at most `limit` scoped threads, preserving order.
///
/// Scoped threads rather than a pool: everything borrowed here lives on the
/// stack of the caller, and the work is a fixed, small batch.
fn run_bounded<T: Sync, R: Send>(items: &[T], limit: usize, f: impl Fn(&T) -> R + Sync) -> Vec<R> {
    if items.is_empty() {
        return Vec::new();
    }
    let next = AtomicUsize::new(0);
    let slots: Vec<Mutex<Option<R>>> = (0..items.len()).map(|_| Mutex::new(None)).collect();
    let threads = limit.clamp(1, items.len());

    std::thread::scope(|scope| {
        for _ in 0..threads {
            scope.spawn(|| loop {
                let i = next.fetch_add(1, Ordering::SeqCst);
                if i >= items.len() {
                    break;
                }
                let value = f(&items[i]);
                *slots[i].lock().unwrap() = Some(value);
            });
        }
    });

    slots
        .into_iter()
        .filter_map(|slot| slot.into_inner().unwrap())
        .collect()
}

/// Documented so the constant is not dead weight when the runner changes.
#[allow(dead_code)]
const fn _exec_timeout_hint() -> StdDuration {
    EXEC_TIMEOUT_HINT
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys_verify::{HttpResponse, StubHttp};

    // --- the shared extractor, against real captured output -----------------

    /// Every one of these strings was produced by running the command on a real
    /// machine (or, where marked, is the format the vendor documents).
    #[test]
    fn test_first_semver_handles_every_real_format_we_met() {
        let cases = [
            // verified on this machine
            (
                "Google Cloud SDK 578.0.0\nbeta 2026.07.24\nbq 2.1.36",
                "578.0.0",
            ),
            (
                "azure-cli                         2.88.0 *\n\ncore  2.88.0 *",
                "2.88.0",
            ),
            ("14.2.1", "14.2.1"),
            ("2.38.2", "2.38.2"),
            (
                "gh version 2.95.0 (2026-06-17)\nhttps://github.com/cli/cli/releases/tag/v2.95.0",
                "2.95.0",
            ),
            ("10.9.8", "10.9.8"),
            ("infisical version 0.43.121", "0.43.121"),
            (
                "Client Version: v1.32.2\nKustomize Version: v5.5.0",
                "1.32.2",
            ),
            (
                "rclone v1.73.5\n- os/version: darwin 26.5.1 (64 bit)\n- go/version: go1.26.2",
                "1.73.5",
            ),
            ("Docker version 28.3.2, build 578ccf607d", "28.3.2"),
            (
                "1.94.2\n  tailscale commit: 2de4d317\n  long version: 1.94.2-t2de4d317a",
                "1.94.2",
            ),
            ("2.1.220 (Claude Code)", "2.1.220"),
            ("4.105.0", "4.105.0"),
            ("Vercel CLI 42.2.0\n42.2.0", "42.2.0"),
            // documented formats for tools not installed here
            (
                "aws-cli/2.32.6 Python/3.13.9 Darwin/25.5.0 source/arm64",
                "2.32.6",
            ),
            (
                "flyctl v0.3.211 darwin/arm64 Commit: abc123 BuildDate: 2026-05-01",
                "0.3.211",
            ),
            ("doctl version 1.104.0-release", "1.104.0"),
            ("stripe version 1.21.8", "1.21.8"),
            ("ollama version is 0.5.7", "0.5.7"),
            ("2.30.0", "2.30.0"),
        ];
        for (raw, expected) in cases {
            assert_eq!(
                first_semver(raw).as_deref(),
                Some(expected),
                "misparsed: {raw:?}"
            );
        }
    }

    #[test]
    fn test_a_bare_integer_or_a_date_is_never_mistaken_for_a_version() {
        // gh prints a release date right after the version; a build hash and a
        // plain count must not win either.
        assert_eq!(first_semver("released 2026-06-17").as_deref(), None);
        assert_eq!(first_semver("build 578ccf607d").as_deref(), None);
        assert_eq!(first_semver("2 updates available").as_deref(), None);
        assert_eq!(first_semver("").as_deref(), None);
    }

    #[test]
    fn test_ssh_needs_its_override_because_the_shared_extractor_is_wrong() {
        // Real `ssh -V` output, which is on stderr and is unlike anything else
        // patchbay meets: OpenSSH's own version is `10.2p1`, which is not
        // dotted-numeric, and LibreSSL's `3.3.6` is sitting right next to it.
        let raw = "OpenSSH_10.2p1, LibreSSL 3.3.6";
        // The shared extractor truncates at the `p` and reports `10.2` — the
        // right release, the wrong string, and it would compare wrong against
        // any patch-level release. Hence the override.
        assert_eq!(first_semver(raw).as_deref(), Some("10.2"));

        let spec = spec_for("ssh").unwrap();
        assert_eq!(parse_version(spec.parse, raw).as_deref(), Some("10.2p1"));
        // An older release, to show the marker is not just matching one string.
        assert_eq!(
            parse_version(spec.parse, "OpenSSH_9.8p1, LibreSSL 3.3.6").as_deref(),
            Some("9.8p1")
        );
    }

    #[test]
    fn test_after_marker_handles_missing_markers_and_empty_tails() {
        assert_eq!(
            parse_version(ParseStrategy::AfterMarker("OpenSSH_"), "nothing here"),
            None
        );
        assert_eq!(
            parse_version(ParseStrategy::AfterMarker("OpenSSH_"), "OpenSSH_ "),
            None
        );
        assert_eq!(
            parse_version(ParseStrategy::AfterMarker("v"), "verylong 1.2").as_deref(),
            Some("erylong")
        );
    }

    // --- the table ----------------------------------------------------------

    /// The guard that fails when someone adds a probe and forgets this table.
    #[test]
    fn test_every_registered_tool_has_a_version_entry() {
        let dir = tempfile::tempdir().unwrap();
        let registry = crate::Registry::all(Paths::for_test(dir.path()));
        for tool in registry.tool_names() {
            assert!(
                spec_for(tool).is_some() || OPTED_OUT.contains(&tool),
                "`{tool}` has no entry in versions::VERSIONS and is not in OPTED_OUT — \
                 add one, or opt it out on purpose"
            );
        }
    }

    #[test]
    fn test_the_version_table_has_no_strays_and_no_duplicates() {
        let dir = tempfile::tempdir().unwrap();
        let registry = crate::Registry::all(Paths::for_test(dir.path()));
        let known = registry.tool_names();
        let mut seen: Vec<&str> = Vec::new();
        for spec in VERSIONS {
            assert!(
                known.contains(&spec.tool),
                "versions::VERSIONS has `{}`, which is not a registered tool",
                spec.tool
            );
            assert!(
                !seen.contains(&spec.tool),
                "duplicate entry for {}",
                spec.tool
            );
            assert!(!spec.bins.is_empty(), "{} names no binary", spec.tool);
            assert!(!spec.args.is_empty(), "{} names no version args", spec.tool);
            // Every tool must have SOME way to answer "what is current".
            assert!(
                spec.brew.is_some()
                    || spec.npm.is_some()
                    || spec.github.is_some()
                    || spec.self_update.is_some(),
                "{} has no route to a latest version at all",
                spec.tool
            );
            seen.push(spec.tool);
        }
    }

    // --- version comparison -------------------------------------------------

    /// The MCP tool description enumerates these, and the panel keys off them.
    #[test]
    fn test_source_wire_names_are_stable() {
        for (source, wire) in [
            (Source::Homebrew, "homebrew"),
            (Source::Npm, "npm"),
            (Source::Bun, "bun"),
            (Source::Pnpm, "pnpm"),
            (Source::Github, "github"),
            (Source::SelfManaged, "self_managed"),
            (Source::System, "system"),
            (Source::Unknown, "unknown"),
        ] {
            assert_eq!(serde_json::to_value(source).unwrap(), wire);
        }
        // The terminal label is allowed to be shorter than the wire name, but
        // must never be empty.
        for source in [Source::Homebrew, Source::SelfManaged, Source::Unknown] {
            assert!(!source.label().is_empty());
        }
        assert_eq!(Source::Homebrew.label(), "brew");
    }

    #[test]
    fn test_version_comparison_is_numeric_not_lexicographic() {
        assert!(
            is_newer("1.10.0", "1.9.0"),
            "the classic string-compare bug"
        );
        assert!(is_newer("2.97.0", "2.95.0"));
        assert!(is_newer("3.1.1", "2.38.2"));
        assert!(!is_newer("2.95.0", "2.97.0"));
        assert!(!is_newer("2.95.0", "2.95.0"));
        // A leading v on either side is noise.
        assert!(is_newer("v1.36.3", "1.32.2"));
        assert!(!is_newer("v1.32.2", "1.32.2"));
        // Different component counts.
        assert!(is_newer("1.2.1", "1.2"));
        assert!(!is_newer("1.2", "1.2.0"));
        // Non-numeric: a difference, but never a claimed ordering.
        assert!(is_newer("10.2p1", "10.1p1"));
        assert!(!is_newer("10.2p1", "10.2p1"));
    }

    #[test]
    fn test_update_available_needs_both_sides_to_be_known() {
        let now = Utc::now();
        let mut info = VersionInfo::new("gh", Source::Homebrew, now);
        assert!(!info.update_available());
        assert_eq!(info.marker(), None);

        info.installed = Some("2.95.0".into());
        assert!(
            !info.update_available(),
            "an unknown latest is not an update"
        );
        assert_eq!(info.marker().as_deref(), Some("2.95.0"));

        info.latest = Some("2.97.0".into());
        assert!(info.update_available());
        assert_eq!(info.marker().as_deref(), Some("2.95.0 → 2.97.0"));

        info.latest = Some("2.95.0".into());
        assert!(!info.update_available());
        assert_eq!(info.marker().as_deref(), Some("2.95.0"));
    }

    // --- install-source detection, against real captured paths --------------

    fn paths() -> Paths {
        Paths::for_test("/Users/yjack")
    }

    #[test]
    fn test_classify_path_recognises_every_real_layout_on_this_machine() {
        let p = paths();
        let case =
            |link: &str, resolved: &str| classify_path(Path::new(link), Path::new(resolved), &p);

        // Homebrew: the Cellar directory names the formula, which is how `neon`
        // is correctly attributed to the `neonctl` formula.
        let brew = case(
            "/opt/homebrew/bin/gh",
            "/opt/homebrew/Cellar/gh/2.95.0/bin/gh",
        )
        .unwrap();
        assert_eq!(brew.source, Source::Homebrew);
        assert_eq!(brew.package.as_deref(), Some("gh"));

        let neon = case(
            "/opt/homebrew/bin/neon",
            "/opt/homebrew/Cellar/neonctl/2.38.2/libexec/lib/node_modules/neonctl/bin/cli.js",
        )
        .unwrap();
        assert_eq!(
            neon.source,
            Source::Homebrew,
            "a brew-installed JS tool is brew's to update, not npm's"
        );
        assert_eq!(neon.package.as_deref(), Some("neonctl"));

        // bun's global install leaves node_modules in the resolved path.
        let bun = case(
            "/Users/yjack/.bun/bin/wrangler",
            "/Users/yjack/.bun/install/global/node_modules/wrangler/bin/wrangler.js",
        )
        .unwrap();
        assert_eq!(bun.source, Source::Bun);
        assert_eq!(bun.package.as_deref(), Some("wrangler"));

        // nvm-managed npm global.
        let npm = case(
            "/Users/yjack/.nvm/versions/node/v20.11.0/bin/firebase",
            "/Users/yjack/.nvm/versions/node/v20.11.0/lib/node_modules/firebase-tools/lib/bin/firebase.js",
        )
        .unwrap();
        assert_eq!(npm.source, Source::Npm);
        assert_eq!(npm.package.as_deref(), Some("firebase-tools"));

        // pnpm writes a shim that resolves to itself — only the directory tells.
        let pnpm = case(
            "/Users/yjack/Library/pnpm/vercel",
            "/Users/yjack/Library/pnpm/vercel",
        )
        .unwrap();
        assert_eq!(pnpm.source, Source::Pnpm);
        assert_eq!(pnpm.package, None, "the shim reveals no package name");

        // macOS system binary.
        let system = case("/usr/bin/ssh", "/usr/bin/ssh").unwrap();
        assert_eq!(system.source, Source::System);

        // A vendor SDK in the home directory says nothing.
        assert_eq!(
            case(
                "/Users/yjack/google-cloud-sdk/bin/gcloud",
                "/Users/yjack/google-cloud-sdk/bin/gcloud"
            ),
            None
        );
    }

    #[test]
    fn test_scoped_npm_packages_survive_detection() {
        assert_eq!(
            npm_package_in("/Users/yjack/.local/lib/node_modules/@anthropic-ai/claude-code/cli.js")
                .as_deref(),
            Some("@anthropic-ai/claude-code")
        );
        // The LAST node_modules wins, so a nested dependency resolves to itself.
        assert_eq!(
            npm_package_in("/x/node_modules/host/node_modules/dep/bin.js").as_deref(),
            Some("dep")
        );
        assert_eq!(npm_package_in("/usr/bin/ssh"), None);
    }

    #[test]
    fn test_homebrew_prefix_can_be_moved_by_the_environment() {
        let p = Paths::for_test("/Users/yjack").with_env("HOMEBREW_PREFIX", "/custom/brew");
        let hit = classify_path(
            Path::new("/custom/brew/bin/gh"),
            Path::new("/custom/brew/Cellar/gh/2.95.0/bin/gh"),
            &p,
        )
        .unwrap();
        assert_eq!(hit.source, Source::Homebrew);
        // …and the default locations no longer count.
        assert_eq!(
            classify_path(
                Path::new("/opt/homebrew/bin/gh"),
                Path::new("/opt/homebrew/Cellar/gh/2.95.0/bin/gh"),
                &p
            ),
            None
        );
    }

    #[test]
    fn test_update_commands_name_the_manager_that_actually_owns_the_tool() {
        let gh = spec_for("gh").unwrap();
        assert_eq!(
            update_command(Source::Homebrew, Some("gh"), gh).as_deref(),
            Some("brew upgrade gh")
        );
        let wrangler = spec_for("wrangler").unwrap();
        assert_eq!(
            update_command(Source::Bun, Some("wrangler"), wrangler).as_deref(),
            Some("bun add -g wrangler@latest")
        );
        assert_eq!(
            update_command(Source::Pnpm, None, spec_for("vercel").unwrap()).as_deref(),
            Some("pnpm add -g vercel@latest"),
            "a shim with no package name falls back to the table"
        );
        assert_eq!(
            update_command(Source::SelfManaged, None, spec_for("gcloud").unwrap()).as_deref(),
            Some("gcloud components update")
        );
        assert_eq!(
            update_command(Source::Unknown, None, spec_for("gh").unwrap()),
            None,
            "an unknown source must not suggest a command"
        );
    }

    // --- brew batch parsing, from a captured fixture -------------------------

    /// A trimmed slice of the real `brew outdated --json=v2` from a machine
    /// with 193 outdated formulae, keeping the entries patchbay cares about
    /// plus a couple of unrelated ones and the cask array.
    const BREW_OUTDATED: &str = r#"{
      "formulae": [
        {"name":"abseil","installed_versions":["20250814.1"],"current_version":"20260526.0","pinned":false,"pinned_version":null},
        {"name":"azure-cli","installed_versions":["2.88.0"],"current_version":"2.89.1","pinned":false,"pinned_version":null},
        {"name":"docker","installed_versions":["28.3.2"],"current_version":"29.7.2","pinned":false,"pinned_version":null},
        {"name":"gh","installed_versions":["2.95.0"],"current_version":"2.97.0","pinned":false,"pinned_version":null},
        {"name":"kubernetes-cli","installed_versions":["1.32.2"],"current_version":"1.36.3","pinned":false,"pinned_version":null},
        {"name":"neonctl","installed_versions":["2.38.2"],"current_version":"3.1.1","pinned":false,"pinned_version":null},
        {"name":"rclone","installed_versions":["1.73.5"],"current_version":"1.75.0","pinned":false,"pinned_version":null},
        {"name":"tailscale","installed_versions":["1.94.2"],"current_version":"1.102.2","pinned":false,"pinned_version":null}
      ],
      "casks": [
        {"name":"ngrok","installed_versions":["3.20.0,4QSnm64SzWz,a"],"current_version":"3.39.11,dy27whJwwmb,a","pinned":false,"pinned_version":null},
        {"name":"1password-cli","installed_versions":["2.30.0"],"current_version":"2.31.1","pinned":false,"pinned_version":null}
      ]
    }"#;

    #[test]
    fn test_brew_outdated_json_is_indexed_by_name_across_formulae_and_casks() {
        let index = parse_brew_outdated(BREW_OUTDATED).unwrap();
        assert_eq!(index.get("gh").map(String::as_str), Some("2.97.0"));
        assert_eq!(
            index.get("kubernetes-cli").map(String::as_str),
            Some("1.36.3")
        );
        assert_eq!(index.get("neonctl").map(String::as_str), Some("3.1.1"));
        // Casks are in the same index.
        assert_eq!(
            index.get("1password-cli").map(String::as_str),
            Some("2.31.1")
        );
        // A cask's `<version>,<build>` loses the build id: it is noise beside
        // what the tool reports about itself.
        assert_eq!(index.get("ngrok").map(String::as_str), Some("3.39.11"));
        // Not outdated == not present; the caller reads that as "current".
        assert_eq!(index.get("infisical"), None);
        assert_eq!(index.len(), 10);
    }

    #[test]
    fn test_brew_outdated_garbage_is_an_error_not_a_panic() {
        assert!(parse_brew_outdated("<html>brew is not installed</html>").is_err());
        // An empty but well-formed answer is a legitimate "nothing is outdated".
        assert!(parse_brew_outdated(r#"{"formulae":[],"casks":[]}"#)
            .unwrap()
            .is_empty());
    }

    // --- the registries, through the HTTP stub -------------------------------

    #[test]
    fn test_npm_registry_latest_is_read_from_the_version_field() {
        let http = StubHttp::responding(HttpResponse::new(
            200,
            r#"{"name":"wrangler","version":"4.122.0","dist":{"tarball":"…"}}"#,
        ));
        assert_eq!(npm_latest("wrangler", &http).unwrap(), "4.122.0");
        assert_eq!(
            http.last_url().unwrap(),
            "https://registry.npmjs.org/wrangler/latest"
        );
    }

    #[test]
    fn test_npm_registry_scoped_names_keep_their_slash() {
        let http = StubHttp::responding(HttpResponse::new(200, r#"{"version":"2.1.220"}"#));
        npm_latest("@anthropic-ai/claude-code", &http).unwrap();
        assert_eq!(
            http.last_url().unwrap(),
            "https://registry.npmjs.org/@anthropic-ai/claude-code/latest"
        );
    }

    #[test]
    fn test_npm_registry_failures_degrade_to_an_explained_error() {
        let missing = StubHttp::responding(HttpResponse::new(404, r#"{"error":"Not found"}"#));
        assert!(npm_latest("nope", &missing)
            .unwrap_err()
            .contains("no package"));

        let junk = StubHttp::responding(HttpResponse::new(200, "<html>"));
        assert!(npm_latest("wrangler", &junk)
            .unwrap_err()
            .contains("unusable JSON"));

        let dead = StubHttp::failing("dns error");
        assert_eq!(npm_latest("wrangler", &dead).unwrap_err(), "dns error");
    }

    #[test]
    fn test_github_releases_latest_strips_the_leading_v() {
        let http = StubHttp::responding(HttpResponse::new(
            200,
            r#"{"tag_name":"v2.27.0","name":"2.27.0","draft":false}"#,
        ));
        assert_eq!(
            github_latest("neondatabase/neonctl", &http).unwrap(),
            "2.27.0"
        );
        assert_eq!(
            http.last_url().unwrap(),
            "https://api.github.com/repos/neondatabase/neonctl/releases/latest"
        );
    }

    #[test]
    fn test_github_rate_limit_is_told_apart_from_a_plain_403() {
        let limited = StubHttp::responding(
            HttpResponse::new(403, r#"{"message":"API rate limit exceeded for 1.2.3.4."}"#)
                .with_header("x-ratelimit-remaining", "0"),
        );
        assert_eq!(
            github_latest("cli/cli", &limited).unwrap_err(),
            GithubError::RateLimited
        );

        let forbidden = StubHttp::responding(
            HttpResponse::new(403, r#"{"message":"Repository access blocked"}"#)
                .with_header("x-ratelimit-remaining", "57"),
        );
        assert!(matches!(
            github_latest("cli/cli", &forbidden).unwrap_err(),
            GithubError::Other(_)
        ));

        let none = StubHttp::responding(HttpResponse::new(404, r#"{"message":"Not Found"}"#));
        assert!(matches!(
            github_latest("x/y", &none).unwrap_err(),
            GithubError::Other(_)
        ));
    }

    // --- the cache ----------------------------------------------------------

    fn info(tool: &str, installed: &str, latest: &str, at: DateTime<Utc>) -> VersionInfo {
        let mut info = VersionInfo::new(tool, Source::Homebrew, at);
        info.installed = Some(installed.into());
        info.latest = Some(latest.into());
        info.update_command = Some(format!("brew upgrade {tool}"));
        info
    }

    #[test]
    fn test_cache_round_trips_through_disk() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested/versions.json");
        let now = Utc::now();

        let mut cache = VersionCache::default();
        cache.put(info("gh", "2.95.0", "2.97.0", now));
        cache.put(info("rclone", "1.73.5", "1.75.0", now));
        cache.save(&path).unwrap();

        let back = VersionCache::load(&path);
        assert_eq!(back.entries.len(), 2);
        let gh = back.get("gh").unwrap();
        assert_eq!(gh.installed.as_deref(), Some("2.95.0"));
        assert_eq!(gh.latest.as_deref(), Some("2.97.0"));
        assert!(gh.update_available());
        assert_eq!(gh.update_command.as_deref(), Some("brew upgrade gh"));
    }

    #[test]
    fn test_cache_ttl_expires_entries_without_deleting_them() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("versions.json");
        let now = Utc::now();
        let ttl = Duration::hours(DEFAULT_TTL_HOURS);

        let mut cache = VersionCache::default();
        cache.put(info("gh", "2.95.0", "2.97.0", now - Duration::hours(1)));
        cache.put(info(
            "rclone",
            "1.73.5",
            "1.75.0",
            now - Duration::hours(25),
        ));
        cache.save(&path).unwrap();

        let back = VersionCache::load(&path);
        assert!(back.get_fresh("gh", now, ttl).is_some(), "1h old is fresh");
        assert!(
            back.get_fresh("rclone", now, ttl).is_none(),
            "25h old is stale"
        );
        // Stale is not gone: the board still shows what it last knew.
        assert!(back.get("rclone").is_some());
        // gh was written an hour ago, so it ages out an hour before the clock
        // reads a full TTL from now. Exactly at the boundary counts as stale.
        assert!(back
            .get_fresh("gh", now + Duration::hours(22), ttl)
            .is_some());
        assert!(back
            .get_fresh("gh", now + Duration::hours(23), ttl)
            .is_none());
    }

    #[test]
    fn test_a_missing_or_corrupt_cache_is_simply_empty() {
        let dir = tempfile::tempdir().unwrap();
        assert!(VersionCache::load(&dir.path().join("nope.json"))
            .entries
            .is_empty());

        let broken = dir.path().join("broken.json");
        std::fs::write(&broken, "{ not json at all").unwrap();
        assert!(VersionCache::load(&broken).entries.is_empty());

        let wrong_shape = dir.path().join("wrong.json");
        std::fs::write(&wrong_shape, r#"{"entries":"nope"}"#).unwrap();
        assert!(VersionCache::load(&wrong_shape).entries.is_empty());
    }

    // --- the orchestration --------------------------------------------------

    /// Canned version output, keyed by binary name. Never execs.
    struct FakeRunner {
        outputs: HashMap<String, String>,
        calls: AtomicUsize,
    }

    impl FakeRunner {
        fn new(pairs: &[(&str, &str)]) -> Self {
            Self {
                outputs: pairs
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect(),
                calls: AtomicUsize::new(0),
            }
        }
    }

    impl VersionRunner for FakeRunner {
        fn run(&self, bin: &str, _args: &[&str]) -> Result<String, String> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.outputs
                .get(bin)
                .cloned()
                .ok_or_else(|| format!("no such binary: {bin}"))
        }
    }

    /// Counts how many times Homebrew was asked.
    struct FakeBrew {
        json: String,
        calls: AtomicUsize,
    }

    impl FakeBrew {
        fn new(json: &str) -> Self {
            Self {
                json: json.to_string(),
                calls: AtomicUsize::new(0),
            }
        }
    }

    impl BrewSource for FakeBrew {
        fn outdated_json(&self) -> Result<String, String> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(self.json.clone())
        }
    }

    /// A made-up `PATH`: binary name -> (path on PATH, path after symlinks).
    /// Lets a test describe this machine's real layout without having it.
    struct FakeBinaries(HashMap<String, (PathBuf, PathBuf)>);

    impl FakeBinaries {
        /// The real layout captured from the machine this was developed on.
        fn machine() -> Self {
            Self::of(&[
                ("gh", "/opt/homebrew/bin/gh", "/opt/homebrew/Cellar/gh/2.95.0/bin/gh"),
                (
                    "rclone",
                    "/opt/homebrew/bin/rclone",
                    "/opt/homebrew/Cellar/rclone/1.73.5/bin/rclone",
                ),
                (
                    "docker",
                    "/opt/homebrew/bin/docker",
                    "/opt/homebrew/Cellar/docker/28.3.2/bin/docker",
                ),
                (
                    "wrangler",
                    "/Users/yjack/.bun/bin/wrangler",
                    "/Users/yjack/.bun/install/global/node_modules/wrangler/bin/wrangler.js",
                ),
                (
                    "neon",
                    "/opt/homebrew/bin/neon",
                    "/opt/homebrew/Cellar/neonctl/2.38.2/libexec/lib/node_modules/neonctl/bin/cli.js",
                ),
                (
                    "gcloud",
                    "/Users/yjack/google-cloud-sdk/bin/gcloud",
                    "/Users/yjack/google-cloud-sdk/bin/gcloud",
                ),
                ("ssh", "/usr/bin/ssh", "/usr/bin/ssh"),
            ])
        }

        fn of(entries: &[(&str, &str, &str)]) -> Self {
            Self(
                entries
                    .iter()
                    .map(|(name, link, resolved)| {
                        (
                            name.to_string(),
                            (PathBuf::from(link), PathBuf::from(resolved)),
                        )
                    })
                    .collect(),
            )
        }

        fn none() -> Self {
            Self(HashMap::new())
        }
    }

    impl BinaryLocator for FakeBinaries {
        fn locate(&self, name: &str) -> Option<(PathBuf, PathBuf)> {
            self.0.get(name).cloned()
        }
    }

    /// The version output this machine really produces, for the fake PATH above.
    fn machine_runner() -> FakeRunner {
        FakeRunner::new(&[
            ("gh", "gh version 2.95.0 (2026-06-17)"),
            ("rclone", "rclone v1.73.5"),
            ("docker", "Docker version 28.3.2, build 578ccf607d"),
            ("wrangler", "4.105.0"),
            ("neon", "2.38.2"),
            ("gcloud", "Google Cloud SDK 578.0.0\nbeta 2026.07.24"),
            ("ssh", "OpenSSH_10.2p1, LibreSSL 3.3.6"),
        ])
    }

    fn deps<'a>(
        runner: &'a dyn VersionRunner,
        brew: &'a dyn BrewSource,
        http: &'a dyn HttpClient,
        binaries: &'a dyn BinaryLocator,
    ) -> Deps<'a> {
        Deps {
            runner,
            brew,
            http,
            binaries,
        }
    }

    #[test]
    fn test_a_run_asks_homebrew_exactly_once_however_many_brew_tools_there_are() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::for_test(dir.path());
        let runner = machine_runner();
        let brew = FakeBrew::new(BREW_OUTDATED);
        let http = StubHttp::failing("the network must not be touched here");
        let bins = FakeBinaries::machine();

        let report = check_updates_with(
            &paths,
            &["gh", "rclone", "docker", "neon"],
            CheckOptions::default(),
            &deps(&runner, &brew, &http, &bins),
        );

        assert_eq!(
            brew.calls.load(Ordering::SeqCst),
            1,
            "four brew tools, one brew call — this is the whole efficiency claim"
        );
        assert_eq!(report.brew_calls, 1);
        assert_eq!(report.network_calls, 0, "brew tools need no HTTP");
        assert_eq!(http.call_count(), 0);
        assert_eq!(report.entries.len(), 4);

        let by = |tool: &str| report.entries.iter().find(|e| e.tool == tool).unwrap();
        let gh = by("gh");
        assert_eq!(gh.source, Source::Homebrew);
        assert_eq!(gh.installed.as_deref(), Some("2.95.0"));
        assert_eq!(gh.latest.as_deref(), Some("2.97.0"));
        assert!(gh.update_available());
        assert_eq!(gh.update_command.as_deref(), Some("brew upgrade gh"));

        // `neon`'s binary lives in the `neonctl` Cellar, and that is the name
        // `brew outdated` reports it under. Getting this wrong would silently
        // report the tool as current forever.
        let neon = by("neon");
        assert_eq!(neon.latest.as_deref(), Some("3.1.1"));
        assert_eq!(neon.update_command.as_deref(), Some("brew upgrade neonctl"));
    }

    #[test]
    fn test_a_brew_tool_absent_from_outdated_is_current_not_unknown() {
        let dir = tempfile::tempdir().unwrap();
        // infisical is brew-installed but NOT in the outdated fixture.
        let bins = FakeBinaries::of(&[(
            "infisical",
            "/opt/homebrew/bin/infisical",
            "/opt/homebrew/Cellar/infisical/0.43.121/bin/infisical",
        )]);
        let runner = FakeRunner::new(&[("infisical", "infisical version 0.43.121")]);
        let brew = FakeBrew::new(BREW_OUTDATED);
        let http = StubHttp::failing("must not be called");

        let report = check_updates_with(
            &Paths::for_test(dir.path()),
            &["infisical"],
            CheckOptions::default(),
            &deps(&runner, &brew, &http, &bins),
        );
        let entry = &report.entries[0];
        assert_eq!(entry.installed.as_deref(), Some("0.43.121"));
        assert_eq!(
            entry.latest.as_deref(),
            Some("0.43.121"),
            "not in `brew outdated` means brew considers it current"
        );
        assert!(!entry.update_available());
    }

    #[test]
    fn test_npm_family_tools_go_to_the_registry_with_the_right_manager() {
        let dir = tempfile::tempdir().unwrap();
        let bins = FakeBinaries::machine();
        let runner = machine_runner();
        let brew = FakeBrew::new(BREW_OUTDATED);
        let http = StubHttp::responding(HttpResponse::new(200, r#"{"version":"4.122.0"}"#));

        let report = check_updates_with(
            &Paths::for_test(dir.path()),
            &["wrangler"],
            CheckOptions::default(),
            &deps(&runner, &brew, &http, &bins),
        );
        let entry = &report.entries[0];
        assert_eq!(entry.source, Source::Bun, "it lives under ~/.bun");
        assert_eq!(entry.installed.as_deref(), Some("4.105.0"));
        assert_eq!(entry.latest.as_deref(), Some("4.122.0"));
        assert!(entry.update_available());
        // bun installed it, so bun is what updates it — not npm.
        assert_eq!(
            entry.update_command.as_deref(),
            Some("bun add -g wrangler@latest")
        );
        assert_eq!(report.network_calls, 1);
        assert_eq!(report.brew_calls, 0, "no brew tool in this run");
    }

    #[test]
    fn test_a_self_managed_vendor_cli_makes_no_network_call_and_says_why() {
        let dir = tempfile::tempdir().unwrap();
        let bins = FakeBinaries::machine();
        let runner = machine_runner();
        let brew = FakeBrew::new(BREW_OUTDATED);
        let http = StubHttp::failing("must not be called");

        let report = check_updates_with(
            &Paths::for_test(dir.path()),
            &["gcloud", "ssh"],
            CheckOptions::default(),
            &deps(&runner, &brew, &http, &bins),
        );
        let by = |tool: &str| report.entries.iter().find(|e| e.tool == tool).unwrap();

        let gcloud = by("gcloud");
        assert_eq!(gcloud.source, Source::SelfManaged);
        assert_eq!(gcloud.installed.as_deref(), Some("578.0.0"));
        assert_eq!(gcloud.latest, None, "no package index to ask");
        assert_eq!(
            gcloud.update_command.as_deref(),
            Some("gcloud components update")
        );
        assert!(gcloud.note.as_deref().unwrap().contains("no package index"));

        let ssh = by("ssh");
        assert_eq!(ssh.source, Source::System);
        assert_eq!(
            ssh.installed.as_deref(),
            Some("10.2p1"),
            "the override works end to end"
        );

        assert_eq!(report.network_calls, 0);
        assert_eq!(http.call_count(), 0);
    }

    // --- patchbay's own row -------------------------------------------------

    #[test]
    fn test_patchbay_reports_itself_without_execing_a_binary() {
        let dir = tempfile::tempdir().unwrap();
        // Nothing on PATH and a runner that refuses everything: the row must
        // still come out installed, because the version is compiled in.
        let bins = FakeBinaries::none();
        let runner = FakeRunner::new(&[]);
        let brew = FakeBrew::new(BREW_OUTDATED);
        let http = StubHttp::responding(HttpResponse::new(200, r#"{"tag_name":"v99.0.0"}"#));

        let report = check_updates_with(
            &Paths::for_test(dir.path()),
            &[SELF_TOOL],
            CheckOptions::default(),
            &deps(&runner, &brew, &http, &bins),
        );

        assert_eq!(report.entries.len(), 1);
        let entry = &report.entries[0];
        assert_eq!(entry.tool, "patchbay");
        assert_eq!(
            entry.installed.as_deref(),
            Some(env!("CARGO_PKG_VERSION")),
            "the build asking the question is the build installed"
        );
        assert_eq!(entry.latest.as_deref(), Some("99.0.0"));
        assert_eq!(entry.source, Source::Github);
        assert!(entry.update_available());
        // A human instruction, like gcloud's — there is no command that
        // upgrades patchbay from a package index.
        assert_eq!(
            entry.update_command.as_deref(),
            Some("download the DMG / curl the CLI tarball from the release page")
        );
        assert_eq!(
            http.last_url().unwrap(),
            "https://api.github.com/repos/pathorsAI/patchbay/releases/latest"
        );
        assert_eq!(runner.calls.load(Ordering::SeqCst), 0, "nothing was exec'd");
        assert_eq!(report.brew_calls, 0);
    }

    #[test]
    fn test_patchbays_own_row_is_cached_like_every_other() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::for_test(dir.path());
        let now = Utc::now();

        let mut cached = VersionInfo::new(SELF_TOOL, Source::Github, now);
        cached.installed = Some("0.2.0".into());
        cached.latest = Some("0.3.0".into());
        let mut cache = VersionCache::default();
        cache.put(cached);
        cache.save(&paths.versions_file()).unwrap();

        let runner = FakeRunner::new(&[]);
        let brew = FakeBrew::new(BREW_OUTDATED);
        let http = StubHttp::failing("GitHub must not be asked inside the TTL");
        let bins = FakeBinaries::none();

        let report = check_updates_with(
            &paths,
            &[SELF_TOOL],
            CheckOptions::default(),
            &deps(&runner, &brew, &http, &bins),
        );
        assert_eq!(report.from_cache, 1);
        assert_eq!(report.network_calls, 0);
        assert_eq!(http.call_count(), 0);
        assert_eq!(report.entries[0].latest.as_deref(), Some("0.3.0"));
    }

    #[test]
    fn test_patchbay_is_not_a_registered_tool_and_needs_no_version_entry() {
        let dir = tempfile::tempdir().unwrap();
        let registry = crate::Registry::all(Paths::for_test(dir.path()));
        assert!(
            !registry.tool_names().contains(&SELF_TOOL),
            "patchbay probes CLIs; it is not one of them"
        );
        assert!(
            spec_for(SELF_TOOL).is_none(),
            "the self row lives outside VERSIONS on purpose — see SELF_SPEC"
        );
    }

    #[test]
    fn test_a_fresh_cache_makes_a_second_run_do_no_work_at_all() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::for_test(dir.path());
        let now = Utc::now();

        let mut cache = VersionCache::default();
        cache.put(info("gh", "2.95.0", "2.97.0", now));
        cache.save(&paths.versions_file()).unwrap();

        let runner = machine_runner();
        let brew = FakeBrew::new(BREW_OUTDATED);
        let http = StubHttp::failing("must not be called");
        let bins = FakeBinaries::machine();

        let report = check_updates_with(
            &paths,
            &["gh"],
            CheckOptions::default(),
            &deps(&runner, &brew, &http, &bins),
        );

        assert_eq!(report.from_cache, 1);
        assert_eq!(report.brew_calls, 0, "nothing pending means no brew call");
        assert_eq!(report.network_calls, 0);
        assert_eq!(runner.calls.load(Ordering::SeqCst), 0, "no exec either");
        assert_eq!(report.entries[0].latest.as_deref(), Some("2.97.0"));

        // --refresh ignores the cache and does the work again.
        let refreshed = check_updates_with(
            &paths,
            &["gh"],
            CheckOptions {
                refresh: true,
                ..CheckOptions::default()
            },
            &deps(&runner, &brew, &http, &bins),
        );
        assert_eq!(refreshed.from_cache, 0);
        assert_eq!(refreshed.brew_calls, 1);
        assert_eq!(
            runner.calls.load(Ordering::SeqCst),
            1,
            "re-execed on refresh"
        );
    }

    #[test]
    fn test_a_tool_that_is_not_installed_is_reported_not_guessed_at() {
        let dir = tempfile::tempdir().unwrap();
        let bins = FakeBinaries::none();
        let runner = FakeRunner::new(&[]);
        let brew = FakeBrew::new(BREW_OUTDATED);
        let http = StubHttp::failing("must not be called");
        let report = check_updates_with(
            &Paths::for_test(dir.path()),
            &["stripe"],
            CheckOptions::default(),
            &deps(&runner, &brew, &http, &bins),
        );
        let entry = &report.entries[0];
        assert_eq!(entry.installed, None);
        assert_eq!(entry.latest, None);
        assert_eq!(entry.source, Source::Unknown);
        assert_eq!(entry.note.as_deref(), Some("not installed"));
        assert!(!entry.update_available());
        assert_eq!(runner.calls.load(Ordering::SeqCst), 0, "nothing to exec");
    }

    #[test]
    fn test_an_unknown_tool_key_is_noted_rather_than_silently_dropped() {
        let dir = tempfile::tempdir().unwrap();
        let bins = FakeBinaries::none();
        let runner = FakeRunner::new(&[]);
        let brew = FakeBrew::new(BREW_OUTDATED);
        let http = StubHttp::failing("must not be called");
        let report = check_updates_with(
            &Paths::for_test(dir.path()),
            &["not-a-tool"],
            CheckOptions::default(),
            &deps(&runner, &brew, &http, &bins),
        );
        assert!(report.entries.is_empty());
        assert!(report.notes[0].contains("no version entry for `not-a-tool`"));
    }

    #[test]
    fn test_a_failing_brew_degrades_only_the_brew_tools() {
        struct DeadBrew;
        impl BrewSource for DeadBrew {
            fn outdated_json(&self) -> Result<String, String> {
                Err("could not run brew".to_string())
            }
        }

        let dir = tempfile::tempdir().unwrap();
        let bins = FakeBinaries::machine();
        let runner = machine_runner();
        let http = StubHttp::failing("must not be called");
        let report = check_updates_with(
            &Paths::for_test(dir.path()),
            &["gh"],
            CheckOptions::default(),
            &deps(&runner, &DeadBrew, &http, &bins),
        );
        let gh = &report.entries[0];
        // The installed version still came through; only `latest` is missing.
        assert_eq!(gh.installed.as_deref(), Some("2.95.0"));
        assert_eq!(gh.latest, None);
        assert!(gh
            .note
            .as_deref()
            .unwrap()
            .contains("could not ask Homebrew"));
        assert!(report
            .notes
            .iter()
            .any(|n| n.contains("Homebrew lookup failed")));
    }

    #[test]
    fn test_a_failing_registry_degrades_one_tool_and_never_the_run() {
        let dir = tempfile::tempdir().unwrap();
        let bins = FakeBinaries::machine();
        let runner = machine_runner();
        let brew = FakeBrew::new(BREW_OUTDATED);
        let http = StubHttp::failing("dns error: no record found");

        let report = check_updates_with(
            &Paths::for_test(dir.path()),
            &["wrangler", "gh"],
            CheckOptions::default(),
            &deps(&runner, &brew, &http, &bins),
        );
        let by = |tool: &str| report.entries.iter().find(|e| e.tool == tool).unwrap();

        let wrangler = by("wrangler");
        assert_eq!(wrangler.installed.as_deref(), Some("4.105.0"));
        assert_eq!(wrangler.latest, None);
        assert!(wrangler.note.as_deref().unwrap().contains("dns error"));
        // The brew tool in the same run is entirely unaffected.
        assert_eq!(by("gh").latest.as_deref(), Some("2.97.0"));
    }

    #[test]
    fn test_github_rate_limiting_stops_after_the_first_hit_instead_of_spamming() {
        let dir = tempfile::tempdir().unwrap();
        // Three GitHub-sourced tools, all installed somewhere unclassifiable so
        // they fall through to the GitHub route.
        let bins = FakeBinaries::of(&[
            ("doctl", "/Users/yjack/bin/doctl", "/Users/yjack/bin/doctl"),
            (
                "stripe",
                "/Users/yjack/bin/stripe",
                "/Users/yjack/bin/stripe",
            ),
            (
                "supabase",
                "/Users/yjack/bin/supabase",
                "/Users/yjack/bin/supabase",
            ),
        ]);
        let runner = FakeRunner::new(&[
            ("doctl", "doctl version 1.104.0-release"),
            ("stripe", "stripe version 1.21.8"),
            ("supabase", "2.22.6"),
        ]);
        let brew = FakeBrew::new(BREW_OUTDATED);
        let http = StubHttp::responding(
            HttpResponse::new(403, r#"{"message":"API rate limit exceeded"}"#)
                .with_header("x-ratelimit-remaining", "0"),
        );

        let report = check_updates_with(
            &Paths::for_test(dir.path()),
            &["doctl", "stripe", "supabase"],
            CheckOptions::default(),
            &deps(&runner, &brew, &http, &bins),
        );

        assert!(
            http.call_count() < 3,
            "a spent rate limit must stop the run's other GitHub lookups, not be hit three times"
        );
        for entry in &report.entries {
            assert_eq!(entry.latest, None);
            let note = entry.note.as_deref().unwrap_or_default();
            assert!(
                note.contains("rate limit"),
                "{} should explain the rate limit, got {note:?}",
                entry.tool
            );
        }
    }

    #[test]
    fn test_run_bounded_preserves_order_and_runs_everything() {
        let items: Vec<usize> = (0..50).collect();
        let out = run_bounded(&items, 8, |i| i * 2);
        assert_eq!(out, items.iter().map(|i| i * 2).collect::<Vec<_>>());
        assert!(run_bounded::<usize, usize>(&[], 8, |i| *i).is_empty());
    }
}
