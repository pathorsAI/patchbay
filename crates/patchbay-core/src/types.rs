//! Serializable data model shared by the CLI, the MCP server and the desktop app.
//!
//! Hard rule for every type in this module: it carries *metadata about*
//! credentials, never credential material. No token, secret, passphrase or
//! private key value may ever be placed in these structs.

use chrono::{DateTime, Duration, Utc};
use serde::ser::SerializeStruct;
use serde::{Deserialize, Serialize, Serializer};

/// What a tool is *for*. Grouping lives here rather than in a UI so the CLI,
/// the MCP server and the panel all slice the board the same way.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolCategory {
    Cloud,
    Code,
    Secrets,
    Cluster,
    Edge,
    Storage,
    /// A tool patchbay knows about but has not classified yet.
    Other,
}

impl ToolCategory {
    /// The category of a tool key. Unknown keys are [`ToolCategory::Other`] so
    /// a newly added probe still appears on the board.
    pub fn for_tool(tool: &str) -> Self {
        match tool {
            "gcloud" | "aws" | "az" => Self::Cloud,
            "gh" => Self::Code,
            "infisical" => Self::Secrets,
            "kubectl" => Self::Cluster,
            "wrangler" => Self::Edge,
            "rclone" => Self::Storage,
            _ => Self::Other,
        }
    }

    /// Display name, for a sidebar heading or a `--category` value.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Cloud => "Cloud",
            Self::Code => "Code",
            Self::Secrets => "Secrets",
            Self::Cluster => "Cluster",
            Self::Edge => "Edge",
            Self::Storage => "Storage",
            Self::Other => "Other",
        }
    }
}

/// Whether a tool is usable right now, derived from its profiles and expiries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionState {
    /// An active profile, with nothing expiring imminently.
    Connected,
    /// An active profile whose credential has expired or is about to.
    Attention,
    /// Installed, but nothing is selected — or there is nothing to select.
    Disconnected,
    /// The tool is not on this machine.
    NotInstalled,
}

impl ConnectionState {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Connected => "Connected",
            Self::Attention => "Attention",
            Self::Disconnected => "Disconnected",
            Self::NotInstalled => "Not installed",
        }
    }
}

/// A credential this close to expiry needs a human before it bites.
const ATTENTION_WINDOW_HOURS: i64 = 24;

/// The state of one developer CLI on this machine.
///
/// `Serialize` is written by hand so the derived [`ToolStatus::connection_state`]
/// travels in the JSON without being stored on the struct — it depends on the
/// clock, and a stored copy would go stale the moment it was written.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct ToolStatus {
    /// Stable tool key, e.g. `"gcloud"`, `"gh"`.
    pub tool: String,
    /// Binary is on `PATH`, or the tool's config directory exists.
    pub installed: bool,
    pub profiles: Vec<Profile>,
    /// Id of the active profile, if the tool has a notion of one.
    pub active: Option<String>,
    /// Human-readable caveats: ADC mismatches, malformed files, missing dirs.
    pub notes: Vec<String>,
    /// What the tool is for. Derived from `tool`; see [`ToolCategory::for_tool`].
    #[serde(default = "ToolCategory::unknown")]
    pub category: ToolCategory,
}

impl ToolCategory {
    /// Deserialization fallback for JSON written before categories existed.
    fn unknown() -> Self {
        Self::Other
    }
}

impl Serialize for ToolStatus {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        // Destructured on purpose: a new field on ToolStatus breaks this
        // function rather than silently dropping out of every JSON consumer.
        let Self {
            tool,
            installed,
            profiles,
            active,
            notes,
            category,
        } = self;
        let mut out = serializer.serialize_struct("ToolStatus", 7)?;
        out.serialize_field("tool", tool)?;
        out.serialize_field("installed", installed)?;
        out.serialize_field("category", category)?;
        out.serialize_field("profiles", profiles)?;
        out.serialize_field("active", active)?;
        out.serialize_field("notes", notes)?;
        out.serialize_field("connection_state", &self.connection_state())?;
        out.end()
    }
}

impl ToolStatus {
    /// A status for a tool that is not installed / has no state on this machine.
    pub fn empty(tool: &str, installed: bool) -> Self {
        Self {
            category: ToolCategory::for_tool(tool),
            tool: tool.to_string(),
            installed,
            profiles: Vec::new(),
            active: None,
            notes: Vec::new(),
        }
    }

    /// Whether this tool is usable right now.
    pub fn connection_state(&self) -> ConnectionState {
        self.connection_state_at(Utc::now())
    }

    /// [`ToolStatus::connection_state`] against an explicit clock.
    pub fn connection_state_at(&self, now: DateTime<Utc>) -> ConnectionState {
        if !self.installed {
            return ConnectionState::NotInstalled;
        }
        if self.active.is_none() || self.profiles.is_empty() {
            return ConnectionState::Disconnected;
        }
        // The active credential decides; when the tool does not date it (gh's
        // keychain tokens), fall back to the soonest expiry it does know.
        let deadline = self.active_expiry().or_else(|| self.soonest_expiry());
        match deadline {
            Some(at) if at - now < Duration::hours(ATTENTION_WINDOW_HOURS) => {
                ConnectionState::Attention
            }
            _ => ConnectionState::Connected,
        }
    }

    pub fn note(&mut self, note: impl Into<String>) {
        self.notes.push(note.into());
    }

    /// The soonest expiry across all profiles, if any profile knows its expiry.
    pub fn soonest_expiry(&self) -> Option<DateTime<Utc>> {
        self.profiles.iter().filter_map(|p| p.expires_at).min()
    }

    /// Expiry of the active profile, if known.
    pub fn active_expiry(&self) -> Option<DateTime<Utc>> {
        let active = self.active.as_ref()?;
        self.profiles
            .iter()
            .find(|p| &p.id == active)
            .and_then(|p| p.expires_at)
    }
}

/// One login / profile / context inside a tool.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Profile {
    /// Stable id used for `switch`: account email, profile name, context name.
    pub id: String,
    /// Display label. Often equal to `id`.
    pub label: String,
    /// `None` means unknown or not applicable (e.g. token lives in the Keychain).
    pub expires_at: Option<DateTime<Utc>>,
    /// Small extra facts: project, region, domain, subscription owner.
    /// Never token values.
    pub meta: serde_json::Value,
}

impl Profile {
    pub fn new(id: impl Into<String>) -> Self {
        let id = id.into();
        Self {
            label: id.clone(),
            id,
            expires_at: None,
            meta: serde_json::Value::Object(Default::default()),
        }
    }

    pub fn label(mut self, label: impl Into<String>) -> Self {
        self.label = label.into();
        self
    }

    pub fn expires_at(mut self, at: Option<DateTime<Utc>>) -> Self {
        self.expires_at = at;
        self
    }

    /// Attach a metadata key. Ignored when the value is `null`.
    pub fn with_meta(mut self, key: &str, value: impl Into<serde_json::Value>) -> Self {
        let value = value.into();
        if !value.is_null() {
            if let Some(map) = self.meta.as_object_mut() {
                map.insert(key.to_string(), value);
            }
        }
        self
    }
}

/// Result of asking a tool to change its active profile.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum SwitchOutcome {
    /// The switch was applied.
    Switched {
        tool: String,
        profile_id: String,
        /// What was run / what changed.
        detail: String,
        /// Follow-on caveats, e.g. gcloud ADC not following the switch.
        notes: Vec<String>,
    },
    /// The tool has no non-interactive switch, or patchbay cannot do it safely.
    Unsupported {
        tool: String,
        reason: String,
        /// Command the human should run instead.
        hint: Option<String>,
    },
    /// No such profile. Lists what is available so an agent can retry.
    UnknownProfile {
        tool: String,
        profile_id: String,
        available: Vec<String>,
    },
    /// The switch was attempted and the tool refused.
    Failed {
        tool: String,
        profile_id: String,
        detail: String,
    },
}

/// Result of a tier-2 liveness check (may exec the CLI and hit the network).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum VerifyOutcome {
    /// Credentials work right now.
    Valid { tool: String, detail: String },
    /// Credentials are present but rejected / expired.
    Invalid { tool: String, detail: String },
    /// patchbay has no verification path for this tool yet.
    Unsupported {
        tool: String,
        reason: String,
        hint: Option<String>,
    },
}

/// What the active credential of a tool is allowed to do.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PermissionsReport {
    pub tool: String,
    /// `false` when patchbay cannot report permissions for this tool yet;
    /// `scopes` will be empty and `hint` explains where to look.
    pub supported: bool,
    /// Who the permissions belong to (account, user, subscription).
    pub subject: Option<String>,
    /// Granted scopes / roles, as reported by the tool.
    pub scopes: Vec<String>,
    pub notes: Vec<String>,
    /// How to change what is granted.
    pub hint: Option<String>,
}

impl PermissionsReport {
    pub fn unsupported(tool: &str, reason: &str, hint: Option<&str>) -> Self {
        Self {
            tool: tool.to_string(),
            supported: false,
            subject: None,
            scopes: Vec::new(),
            notes: vec![reason.to_string()],
            hint: hint.map(|h| h.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(hours_from_now: i64) -> Option<DateTime<Utc>> {
        Some(Utc::now() + Duration::hours(hours_from_now))
    }

    fn status_with(active: Option<&str>, profiles: Vec<Profile>) -> ToolStatus {
        let mut status = ToolStatus::empty("gcloud", true);
        status.profiles = profiles;
        status.active = active.map(|a| a.to_string());
        status
    }

    #[test]
    fn test_every_shipped_tool_has_a_real_category() {
        let expected = [
            ("gcloud", ToolCategory::Cloud),
            ("aws", ToolCategory::Cloud),
            ("az", ToolCategory::Cloud),
            ("gh", ToolCategory::Code),
            ("infisical", ToolCategory::Secrets),
            ("kubectl", ToolCategory::Cluster),
            ("wrangler", ToolCategory::Edge),
            ("rclone", ToolCategory::Storage),
        ];
        for (tool, category) in expected {
            assert_eq!(ToolCategory::for_tool(tool), category, "{tool}");
            assert_eq!(ToolStatus::empty(tool, true).category, category, "{tool}");
        }
        assert_eq!(ToolCategory::for_tool("brand-new"), ToolCategory::Other);
    }

    #[test]
    fn test_connection_state_covers_every_shape_of_board() {
        let now = Utc::now();

        let absent = ToolStatus::empty("gcloud", false);
        assert_eq!(
            absent.connection_state_at(now),
            ConnectionState::NotInstalled
        );

        // Installed but nothing selected — rclone's every-command-names-its-remote shape.
        let idle = status_with(None, vec![Profile::new("pathors")]);
        assert_eq!(idle.connection_state_at(now), ConnectionState::Disconnected);

        let empty = ToolStatus::empty("gcloud", true);
        assert_eq!(empty.connection_state_at(now), ConnectionState::Disconnected);

        // An undated credential (gh keeps tokens in the keychain) still counts.
        let undated = status_with(Some("pathors"), vec![Profile::new("pathors")]);
        assert_eq!(
            undated.connection_state_at(now),
            ConnectionState::Connected
        );

        let healthy = status_with(
            Some("pathors"),
            vec![Profile::new("pathors").expires_at(at(72))],
        );
        assert_eq!(healthy.connection_state_at(now), ConnectionState::Connected);

        let soon = status_with(
            Some("pathors"),
            vec![Profile::new("pathors").expires_at(at(3))],
        );
        assert_eq!(soon.connection_state_at(now), ConnectionState::Attention);

        let stale = status_with(
            Some("pathors"),
            vec![Profile::new("pathors").expires_at(at(-48))],
        );
        assert_eq!(stale.connection_state_at(now), ConnectionState::Attention);

        // Active profile has no expiry of its own: the soonest known one decides.
        let mixed = status_with(
            Some("pathors"),
            vec![
                Profile::new("pathors"),
                Profile::new("default").expires_at(at(-1)),
            ],
        );
        assert_eq!(mixed.connection_state_at(now), ConnectionState::Attention);
    }

    #[test]
    fn test_json_carries_category_and_connection_state() {
        let status = status_with(
            Some("pathors"),
            vec![Profile::new("pathors").expires_at(at(240))],
        );
        let json = serde_json::to_value(&status).unwrap();
        assert_eq!(json["category"], "cloud");
        assert_eq!(json["connection_state"], "connected");

        // The derived field is not an input: reading it back is lossless.
        let back: ToolStatus = serde_json::from_value(json).unwrap();
        assert_eq!(back, status);
    }

    #[test]
    fn test_labels_are_human_readable() {
        assert_eq!(ToolCategory::Cloud.label(), "Cloud");
        assert_eq!(ToolCategory::Other.label(), "Other");
        assert_eq!(ConnectionState::NotInstalled.label(), "Not installed");
    }
}
