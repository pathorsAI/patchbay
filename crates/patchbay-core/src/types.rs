//! Serializable data model shared by the CLI, the MCP server and the desktop app.
//!
//! Hard rule for every type in this module: it carries *metadata about*
//! credentials, never credential material. No token, secret, passphrase or
//! private key value may ever be placed in these structs.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// The state of one developer CLI on this machine.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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
}

impl ToolStatus {
    /// A status for a tool that is not installed / has no state on this machine.
    pub fn empty(tool: &str, installed: bool) -> Self {
        Self {
            tool: tool.to_string(),
            installed,
            profiles: Vec::new(),
            active: None,
            notes: Vec::new(),
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
