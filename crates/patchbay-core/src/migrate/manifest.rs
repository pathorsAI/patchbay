//! `manifest.json` — the readable half of a bundle.
//!
//! Everything in here is designed to be printed, diffed, pasted into a chat and
//! read by a stranger. The hard rule of [`crate::types`] applies with no
//! exceptions: **no secret value may appear in a manifest.** Profiles, account
//! names, scopes, expiry dates, the *names* of environment variables an MCP
//! server sets — yes. Their values, never. The test at the bottom of this file
//! serializes a manifest built from deliberately secret-shaped fixtures and
//! greps the JSON for them.
//!
//! The manifest also carries the [`SetupItem`] list: the things that could not
//! travel, each with the exact command that fixes it. That list is what turns
//! "your credentials are half moved" into a checklist an agent can work.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::policy::{Location, PortabilityKind};
use crate::types::{Profile, ToolCategory};

/// Bundle format version. Bump on any change that an older build could not read
/// correctly; [`super::bundle`] refuses a bundle from the future.
pub const BUNDLE_VERSION: u32 = 1;

/// Whether a [`SetupItem`] is still outstanding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SetupStatus {
    /// Still to do.
    Open,
    /// Verified closed by re-probing this machine.
    Done,
    /// Cannot be checked from here (the tool is not installed, or nothing on
    /// disk would show the difference).
    Unknown,
}

impl SetupStatus {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Done => "done",
            Self::Unknown => "unknown",
        }
    }
}

/// One thing a human or an agent has to do on the new machine.
///
/// The shape is deliberately identical in the manifest (predicted at export
/// time) and in `pb plan` / `plan_setup` (re-evaluated against the machine in
/// front of you), so an agent learns one schema.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SetupItem {
    /// Stable id, unique in a plan: `tool:gh`, `install:kubectl`,
    /// `switch:gcloud`, `key:cf-api`, `mcp:cursor/patchbay`. Pass it to
    /// `mark_setup_done` to have patchbay re-check just this one.
    pub id: String,
    /// The tool this is about, for grouping.
    pub tool: String,
    /// What is missing, in a sentence.
    pub what: String,
    /// Whether patchbay itself can close this without a human — a profile
    /// switch, a key re-registration. `false` means somebody has to log in.
    pub auto: bool,
    /// The exact command that closes it. Never a description of a command.
    pub command: String,
    /// Whether `command` opens a browser. An agent must hand these to the
    /// human rather than trying to drive them.
    pub needs_browser: bool,
    pub status: SetupStatus,
    /// Extra context: why it cannot travel, what patchbay already did.
    #[serde(default)]
    pub detail: Vec<String>,
}

impl SetupItem {
    pub fn new(id: impl Into<String>, tool: impl Into<String>, what: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            tool: tool.into(),
            what: what.into(),
            auto: false,
            command: String::new(),
            needs_browser: false,
            status: SetupStatus::Open,
            detail: Vec::new(),
        }
    }

    pub fn command(mut self, command: impl Into<String>, needs_browser: bool) -> Self {
        self.command = command.into();
        self.needs_browser = needs_browser;
        self
    }

    pub fn auto(mut self, auto: bool) -> Self {
        self.auto = auto;
        self
    }

    pub fn status(mut self, status: SetupStatus) -> Self {
        self.status = status;
        self
    }

    pub fn detail(mut self, detail: impl Into<String>) -> Self {
        self.detail.push(detail.into());
        self
    }

    pub fn is_open(&self) -> bool {
        self.status == SetupStatus::Open
    }
}

/// One tool as the source machine had it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ToolRecord {
    pub tool: String,
    pub category: ToolCategory,
    pub installed: bool,
    pub portability: PortabilityKind,
    /// Why it could not travel. Empty for a portable tool.
    #[serde(default)]
    pub reason: String,
    pub profiles: Vec<Profile>,
    pub active: Option<String>,
    /// Locations whose files are inside this bundle.
    #[serde(default)]
    pub carried: Vec<Location>,
    /// Who the active credential is, and what it may do — recorded only for the
    /// tools whose policy asks for it (today: `gh`), because it is the thing
    /// that is easiest to get wrong when re-authing by hand.
    #[serde(default)]
    pub subject: Option<String>,
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(default)]
    pub notes: Vec<String>,
}

/// One vault key, metadata only. `included` says whether its *value* is in the
/// encrypted payload; without `--keys` every entry is `included: false` and the
/// new machine gets a checklist instead of the secrets.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct KeyRecord {
    pub id: String,
    pub provider: String,
    pub label: String,
    #[serde(default)]
    pub purpose: Option<String>,
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(default)]
    pub expires_at: Option<DateTime<Utc>>,
    /// Last 4 characters, exactly as the vault stores them.
    pub last4: String,
    pub included: bool,
}

/// One project from the env vault, readable without decrypting anything —
/// [`KeyRecord`]'s role for [`crate::envs`].
///
/// Names and counts only. A variable name is not a secret, but a *list* of
/// them is noise in a document meant to be read, so an environment reports how
/// many variables its synced layer holds rather than which; the payload's own
/// [`crate::envs::ProjectEntry`] has the names for the code that restores them.
///
/// **No local-layer count.** The local layer does not travel at all, and a
/// number next to it in a manifest would imply that something of it did.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EnvProjectRecord {
    pub id: String,
    pub default_env: String,
    #[serde(default)]
    pub environments: Vec<EnvEnvironmentRecord>,
    /// Where the synced layer is pulled from, if the project is linked. Absent
    /// means nothing on the new machine can rebuild it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sync: Option<EnvSyncRecord>,
}

/// One environment of one carried project.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EnvEnvironmentRecord {
    pub name: String,
    /// How many variables a `pb env pull` is expected to restore here.
    pub synced_vars: usize,
    /// When the source machine last pulled. `null` if it never did.
    #[serde(default)]
    pub synced_at: Option<DateTime<Utc>>,
}

/// A project's sync pin, as the manifest reports it: enough to see which
/// remote and which login a pull will need, and nothing that could authorize
/// one. The API base URL and the environment-name mapping stay in the payload's
/// own entry — they are configuration, not something a reader needs.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EnvSyncRecord {
    pub provider: String,
    /// The remote's own project identifier.
    pub project_id: String,
    /// The account the pull has to run as.
    pub account: String,
}

/// One MCP server as one client had it registered. Same value-free contract as
/// [`crate::mcp_clients::McpServerEntry`]: names of environment variables and
/// headers, never their values.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct McpRecord {
    pub client: String,
    pub name: String,
    /// `stdio npx (3 args)`, `http https://…` — the same summary the board shows.
    pub summary: String,
    #[serde(default)]
    pub env_keys: Vec<String>,
    #[serde(default)]
    pub header_keys: Vec<String>,
    /// Whether the registration (values included) is in the encrypted payload.
    pub carried: bool,
}

/// Where the bundle came from. Deliberately thin: enough to tell two bundles
/// apart, nothing that profiles the machine.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Source {
    /// The patchbay that wrote it.
    pub patchbay_version: String,
    pub os: String,
}

/// How a manifest was produced, and therefore what a reader may assume.
///
/// The distinction matters to anyone planning against one. A `Bundle` manifest
/// travelled beside the credential files it describes, so `carried` is the list
/// of things that really did move. An `Inventory` manifest travelled alone —
/// it is a record of what this machine uses, nothing more, and every login on
/// the new machine has to be made by hand. `pb plan` re-probes either way, so
/// this changes what the file *claims*, not what the checklist checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ManifestKind {
    /// Written inside an encrypted bundle, beside the files it describes.
    #[default]
    Bundle,
    /// Written on its own by `pb manifest`. Carries no credential, and nothing
    /// it names has travelled.
    Inventory,
}

impl ManifestKind {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Bundle => "bundle",
            Self::Inventory => "inventory",
        }
    }
}

/// The whole readable manifest.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Manifest {
    pub version: u32,
    /// Bundle or inventory. Defaults to `bundle` so a manifest written by an
    /// older patchbay still reads correctly.
    #[serde(default)]
    pub kind: ManifestKind,
    pub created_at: DateTime<Utc>,
    pub source: Source,
    pub tools: Vec<ToolRecord>,
    #[serde(default)]
    pub keys: Vec<KeyRecord>,
    #[serde(default)]
    pub mcp: Vec<McpRecord>,
    /// The env vault's projects, by id. Their *values* are not in the bundle at
    /// all; `pb env pull` rebuilds each synced layer on the new machine.
    #[serde(default)]
    pub env_projects: Vec<EnvProjectRecord>,
    /// What will not have travelled, with the command for each.
    #[serde(default)]
    pub gaps: Vec<SetupItem>,
}

impl Manifest {
    pub fn tool(&self, tool: &str) -> Option<&ToolRecord> {
        self.tools.iter().find(|t| t.tool == tool)
    }

    /// Pretty JSON, the form written into the bundle as `manifest.json`.
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_else(|_| "{}".to_string())
    }

    pub fn from_json(text: &str) -> anyhow::Result<Self> {
        let manifest: Self = serde_json::from_str(text)
            .map_err(|e| anyhow::anyhow!("not a readable patchbay manifest: {e}"))?;
        if manifest.version > BUNDLE_VERSION {
            anyhow::bail!(
                "this manifest was written by a newer patchbay (format version {}, this build \
                 understands {BUNDLE_VERSION}); upgrade patchbay rather than guess at it",
                manifest.version
            );
        }
        Ok(manifest)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest_with_secret_shaped_everything() -> Manifest {
        Manifest {
            version: BUNDLE_VERSION,
            kind: ManifestKind::default(),
            created_at: Utc::now(),
            source: Source {
                patchbay_version: "0.1.0".into(),
                os: "macos".into(),
            },
            tools: vec![ToolRecord {
                tool: "gh".into(),
                category: ToolCategory::Code,
                installed: true,
                portability: PortabilityKind::DeviceBound,
                reason: "keychain".into(),
                profiles: vec![Profile::new("github.com/octocat")
                    .with_meta("git_protocol", "ssh")
                    // A probe would never put a token here; if one ever did,
                    // the grep below is what catches it.
                    .with_meta("host", "github.com")],
                active: Some("github.com/octocat".into()),
                carried: vec![],
                subject: Some("octocat".into()),
                scopes: vec!["repo".into(), "read:org".into()],
                notes: vec![],
            }],
            keys: vec![KeyRecord {
                id: "cf-api".into(),
                provider: "cloudflare".into(),
                label: "CF deploy".into(),
                purpose: Some("deploy from CI".into()),
                scopes: vec!["workers:edit".into()],
                expires_at: None,
                last4: "9876".into(),
                included: false,
            }],
            mcp: vec![McpRecord {
                client: "claude-code".into(),
                name: "grafana".into(),
                summary: "stdio uvx (1 arg)".into(),
                env_keys: vec!["GRAFANA_TOKEN".into()],
                header_keys: vec!["Authorization".into()],
                carried: true,
            }],
            env_projects: vec![EnvProjectRecord {
                id: "pathors".into(),
                default_env: "dev".into(),
                environments: vec![EnvEnvironmentRecord {
                    name: "dev".into(),
                    synced_vars: 12,
                    synced_at: None,
                }],
                sync: Some(EnvSyncRecord {
                    provider: "infisical".into(),
                    project_id: "3f0b-uuid".into(),
                    account: "me@work.com".into(),
                }),
            }],
            gaps: vec![
                SetupItem::new("tool:gh", "gh", "re-authenticate").command("gh auth login", true)
            ],
        }
    }

    #[test]
    fn test_a_manifest_carries_no_secret_value() {
        let manifest = manifest_with_secret_shaped_everything();
        let json = manifest.to_json();
        // Names yes, values no.
        assert!(json.contains("GRAFANA_TOKEN"), "{json}");
        assert!(json.contains("Authorization"), "{json}");
        for forbidden in [
            "glsa_",
            "Bearer ",
            "ghp_",
            "aws_secret_access_key",
            "BEGIN OPENSSH PRIVATE KEY",
            "_authToken",
            "passphrase",
        ] {
            assert!(
                !json.contains(forbidden),
                "`{forbidden}` appeared in a manifest:\n{json}"
            );
        }
        // last4 is the only thing derived from a value, and four characters is
        // the whole point.
        assert!(json.contains("\"last4\": \"9876\""), "{json}");
    }

    /// The env vault's half of the same contract: what a pull will restore, in
    /// counts, and not one word about the layer that does not travel.
    #[test]
    fn test_an_env_project_record_counts_the_synced_layer_and_never_the_local_one() {
        let json = manifest_with_secret_shaped_everything().to_json();
        assert!(json.contains("\"synced_vars\": 12"), "{json}");
        assert!(json.contains("me@work.com"), "{json}");
        // No `local_names`, no local count, no attachment root: a number beside
        // the local layer would imply something of it had moved.
        assert!(!json.contains("local"), "{json}");
        assert!(!json.contains("Users"), "{json}");
    }

    #[test]
    fn test_manifest_round_trips() {
        let manifest = manifest_with_secret_shaped_everything();
        let back = Manifest::from_json(&manifest.to_json()).unwrap();
        assert_eq!(back, manifest);
        assert_eq!(back.tool("gh").unwrap().scopes, vec!["repo", "read:org"]);
        assert!(back.tool("nope").is_none());
    }

    #[test]
    fn test_a_manifest_from_the_future_is_refused_with_advice() {
        let mut manifest = manifest_with_secret_shaped_everything();
        manifest.version = BUNDLE_VERSION + 7;
        let err = Manifest::from_json(&manifest.to_json())
            .unwrap_err()
            .to_string();
        assert!(err.contains("newer patchbay"), "{err}");
        assert!(err.contains("upgrade patchbay"), "{err}");
    }

    #[test]
    fn test_setup_item_builder_and_status() {
        let item = SetupItem::new("tool:gh", "gh", "re-authenticate")
            .command("gh auth login", true)
            .detail("token lives in the keychain");
        assert!(item.is_open());
        assert!(!item.auto);
        assert_eq!(item.detail.len(), 1);
        assert!(!item.clone().status(SetupStatus::Done).is_open());
        assert_eq!(SetupStatus::Done.label(), "done");
        assert!(item.auto(true).auto);
    }
}
