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
    Containers,
    Network,
    Payments,
    Ai,
    /// A tool patchbay knows about but has not classified yet.
    Other,
}

impl ToolCategory {
    /// The category of a tool key. Unknown keys are [`ToolCategory::Other`] so
    /// a newly added probe still appears on the board.
    pub fn for_tool(tool: &str) -> Self {
        match tool {
            "gcloud" | "aws" | "az" | "firebase" | "neon" | "supabase" | "flyctl" | "doctl" => {
                Self::Cloud
            }
            "gh" | "npm" => Self::Code,
            "infisical" | "op" => Self::Secrets,
            "kubectl" => Self::Cluster,
            "wrangler" | "vercel" => Self::Edge,
            "rclone" => Self::Storage,
            "docker" => Self::Containers,
            "tailscale" | "ssh" | "ngrok" | "cloudflared" => Self::Network,
            "stripe" => Self::Payments,
            "ollama" | "huggingface" | "claude" => Self::Ai,
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
            Self::Containers => "Containers",
            Self::Network => "Network",
            Self::Payments => "Payments",
            Self::Ai => "AI",
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

/// How much a [`Note`] should alarm the reader.
///
/// The board is read at a glance, so the difference between "docker has no
/// active registry, which is normal for docker" and "docker's credential store
/// is unreadable" has to survive being rendered. It does not survive being a
/// bare string, which is what these notes used to be: the panel drew every one
/// of them behind the same amber warning triangle and the whole board read as
/// a list of complaints.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NoteKind {
    /// How the tool works, what was counted, where a file was read from.
    /// Nothing is wrong and nothing needs doing. Rendered without a glyph.
    Info,
    /// A real risk or a genuine surprise — a secret sitting in plain text, an
    /// environment variable quietly overriding the stored login. Nothing is
    /// broken yet.
    Warn,
    /// Something on this machine is broken or is going to fail: a config file
    /// that will not parse, a reference to a profile that does not exist, a
    /// credential store patchbay cannot read.
    Problem,
}

impl NoteKind {
    /// Whether this kind is worth counting on the collapsed card.
    pub fn is_alarming(&self) -> bool {
        matches!(self, Self::Warn | Self::Problem)
    }
}

/// One caveat about one tool, carrying how loudly to say it.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Note {
    pub kind: NoteKind,
    pub text: String,
}

impl Note {
    pub fn info(text: impl Into<String>) -> Self {
        Self {
            kind: NoteKind::Info,
            text: text.into(),
        }
    }

    pub fn warn(text: impl Into<String>) -> Self {
        Self {
            kind: NoteKind::Warn,
            text: text.into(),
        }
    }

    pub fn problem(text: impl Into<String>) -> Self {
        Self {
            kind: NoteKind::Problem,
            text: text.into(),
        }
    }
}

/// When — and whether — a login stops working.
///
/// `Option<DateTime>` could not tell these apart, and the probes papered over
/// the gap by writing a paragraph of prose into `notes` explaining which case
/// applied. Thirteen probes each had their own wording for it. The distinction
/// belongs in the type: a consumer that has to parse English to learn whether
/// `null` means "never expires" or "expires but we cannot see when" is a
/// consumer that will get it wrong.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Expiry {
    /// A real deadline, known and dated.
    At(DateTime<Utc>),
    /// This credential does not expire by design — a static AWS access key, an
    /// ngrok authtoken, a docker registry credential.
    NoExpiry,
    /// There is an expiry, but it lives somewhere patchbay will not read: an
    /// OS keychain, a vendor's own binary cache. `reason` is a short noun
    /// phrase for a tooltip, e.g. "in the system keychain".
    Unknown { reason: String },
    /// The CLI renews this silently, so there is no deadline a human has to
    /// act on. `access_token_expires` is the short-lived access token's own
    /// clock where patchbay can see it — useful for debugging, never a login
    /// expiry, and deliberately not what [`Expiry::deadline`] reports.
    Refreshable {
        access_token_expires: Option<DateTime<Utc>>,
    },
}

impl Default for Expiry {
    fn default() -> Self {
        Self::Unknown {
            reason: String::new(),
        }
    }
}

impl Expiry {
    /// Convenience for the common `Unknown` construction.
    pub fn unknown(reason: impl Into<String>) -> Self {
        Self::Unknown {
            reason: reason.into(),
        }
    }

    /// The moment a human has to do something about, if there is one.
    ///
    /// Only [`Expiry::At`] has one. A refreshable token's hourly access-token
    /// clock is not a deadline: the CLI will renew it without anyone noticing,
    /// and reporting it here would put half the board into `Attention` for no
    /// reason.
    pub fn deadline(&self) -> Option<DateTime<Utc>> {
        match self {
            Self::At(at) => Some(*at),
            _ => None,
        }
    }

    /// Short label for a chip.
    pub fn label(&self) -> &'static str {
        match self {
            Self::At(_) => "expires",
            Self::NoExpiry => "no expiry",
            Self::Unknown { .. } => "expiry unknown",
            Self::Refreshable { .. } => "auto-renewed",
        }
    }
}

/// Flat wire form of [`Expiry`]: a `state` discriminant plus whichever payload
/// that state carries. Written out rather than derived because an internally
/// tagged enum cannot hold a newtype variant whose payload is a bare string,
/// and because a flat object is what the panel wants to switch on.
#[derive(Serialize, Deserialize)]
struct ExpiryWire {
    state: ExpiryState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    access_token_expires: Option<DateTime<Utc>>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ExpiryState {
    At,
    NoExpiry,
    Unknown,
    Refreshable,
}

impl From<Expiry> for ExpiryWire {
    fn from(value: Expiry) -> Self {
        let (state, at, reason, access_token_expires) = match value {
            Expiry::At(at) => (ExpiryState::At, Some(at), None, None),
            Expiry::NoExpiry => (ExpiryState::NoExpiry, None, None, None),
            Expiry::Unknown { reason } => (ExpiryState::Unknown, None, Some(reason), None),
            Expiry::Refreshable {
                access_token_expires,
            } => (ExpiryState::Refreshable, None, None, access_token_expires),
        };
        Self {
            state,
            at,
            reason,
            access_token_expires,
        }
    }
}

impl TryFrom<ExpiryWire> for Expiry {
    type Error = String;

    fn try_from(wire: ExpiryWire) -> Result<Self, Self::Error> {
        Ok(match wire.state {
            ExpiryState::At => {
                Self::At(wire.at.ok_or("expiry state \"at\" without an `at` field")?)
            }
            ExpiryState::NoExpiry => Self::NoExpiry,
            ExpiryState::Unknown => Self::Unknown {
                reason: wire.reason.unwrap_or_default(),
            },
            ExpiryState::Refreshable => Self::Refreshable {
                access_token_expires: wire.access_token_expires,
            },
        })
    }
}

impl Serialize for Expiry {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        ExpiryWire::from(self.clone()).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Expiry {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = ExpiryWire::deserialize(deserializer)?;
        Self::try_from(wire).map_err(serde::de::Error::custom)
    }
}

/// Whether this tool holds a *persistent selection* of one login.
///
/// Most do, and [`ToolStatus::active`] names it. A few genuinely do not: every
/// `rclone` command names its own remote, docker holds credentials for several
/// registries at once, npm's registry auth is per-scope, ssh takes its
/// destination as an argument. Those probes used to say so in a note, which
/// meant the panel flagged a warning on a tool that was working exactly as
/// designed. It is a property of the tool, so it lives on the status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ActiveConcept {
    /// The tool selects one profile at a time. `active` names it, or is `None`
    /// because nothing has been selected yet — which is worth showing.
    Selects,
    /// The tool keeps no selection to switch. `reason` is a short phrase for a
    /// tooltip; the panel shows it there rather than filing a warning.
    ///
    /// This does **not** mean `active` must be `None`. Several tools have no
    /// selection and still have a sensible default to name: op's
    /// `latest_signin` is the last account signed in to, stripe has a
    /// `[default]` table, flyctl has one login and no way to hold a second.
    /// The value is real and belongs on the board; what `NotApplicable` says
    /// is that it is a default rather than a choice, and that an empty slot
    /// here is the right answer instead of a missing one.
    NotApplicable { reason: String },
}

impl Default for ActiveConcept {
    fn default() -> Self {
        Self::Selects
    }
}

impl ActiveConcept {
    pub fn not_applicable(reason: impl Into<String>) -> Self {
        Self::NotApplicable {
            reason: reason.into(),
        }
    }

    /// `true` when an empty active slot is normal for this tool.
    pub fn is_not_applicable(&self) -> bool {
        matches!(self, Self::NotApplicable { .. })
    }
}

/// A key from the vault, shown next to the tool it belongs with.
///
/// The compact projection of a [`crate::keys::KeyEntry`] — enough to identify
/// and triage it on the board, and nothing more. Like everything in this
/// module: metadata only, never the value.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct KeyRef {
    pub id: String,
    pub label: String,
    /// Last 4 characters of the secret.
    pub last4: String,
    pub expires_at: Option<DateTime<Utc>>,
    /// Derived from `expires_at` and the clock at the moment of the read.
    pub expiry_state: crate::keys::KeyExpiryState,
}

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
    /// Whether an empty `active` means "nothing selected" or "not a question
    /// this tool answers". See [`ActiveConcept`].
    #[serde(default)]
    pub active_concept: ActiveConcept,
    /// Human-readable caveats: ADC mismatches, malformed files, missing dirs.
    /// Each carries its own [`NoteKind`] — see [`ToolStatus::info`] and friends.
    pub notes: Vec<Note>,
    /// What the tool is for. Derived from `tool`; see [`ToolCategory::for_tool`].
    #[serde(default = "ToolCategory::unknown")]
    pub category: ToolCategory,
    /// Standalone keys from the vault whose provider maps to this tool — the
    /// Cloudflare API token that sits beside `wrangler`'s own login. Populated
    /// by [`crate::Registry`] when a key registry is attached; empty otherwise.
    #[serde(default)]
    pub registered_keys: Vec<KeyRef>,
    /// Installed version, latest version and how to update — read from the
    /// version cache, never computed here. `None` on a cold cache, which is the
    /// normal state until someone runs `pb check-updates`; it means "not
    /// checked yet", never "up to date".
    #[serde(default)]
    pub version: Option<crate::versions::VersionInfo>,
    /// Curated notices: renames, removals, end-of-life. Static data, so these
    /// are present whether or not the version cache is warm.
    #[serde(default)]
    pub advisories: Vec<crate::deprecations::Advisory>,
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
            active_concept,
            notes,
            category,
            registered_keys,
            version,
            advisories,
        } = self;
        let mut out = serializer.serialize_struct("ToolStatus", 11)?;
        out.serialize_field("tool", tool)?;
        out.serialize_field("installed", installed)?;
        out.serialize_field("category", category)?;
        out.serialize_field("profiles", profiles)?;
        out.serialize_field("active", active)?;
        out.serialize_field("active_concept", active_concept)?;
        out.serialize_field("notes", notes)?;
        out.serialize_field("registered_keys", registered_keys)?;
        out.serialize_field("version", version)?;
        out.serialize_field("advisories", advisories)?;
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
            active_concept: ActiveConcept::Selects,
            notes: Vec::new(),
            registered_keys: Vec::new(),
            version: None,
            advisories: Vec::new(),
        }
    }

    /// `true` when the version cache says a newer release is available.
    /// `false` on a cold cache — an unknown is never reported as an update.
    pub fn update_available(&self) -> bool {
        self.version.as_ref().is_some_and(|v| v.update_available())
    }

    /// Advisories serious enough to act on: something removed or abandoned.
    pub fn blocking_advisories(&self) -> Vec<&crate::deprecations::Advisory> {
        self.advisories.iter().filter(|a| a.is_blocking()).collect()
    }

    /// Keys on this row that have expired or are about to.
    pub fn keys_needing_attention(&self) -> Vec<&KeyRef> {
        self.registered_keys
            .iter()
            .filter(|k| k.expiry_state.needs_attention())
            .collect()
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

    /// Record a caveat. There is deliberately no `note()` taking bare text:
    /// the kind is a judgement only the probe can make, so every call site
    /// has to make it.
    ///
    /// Exact duplicates are dropped. Several probes reach the same conclusion
    /// by more than one route — a missing directory noticed once per config
    /// file — and saying it twice only costs the reader.
    pub fn push_note(&mut self, note: Note) {
        if !self.notes.contains(&note) {
            self.notes.push(note);
        }
    }

    /// How the tool works, what was counted, where a file was read from.
    pub fn info(&mut self, text: impl Into<String>) {
        self.push_note(Note::info(text));
    }

    /// A real risk or surprise, but nothing is broken.
    pub fn warn(&mut self, text: impl Into<String>) {
        self.push_note(Note::warn(text));
    }

    /// Something here is broken or is going to fail.
    pub fn problem(&mut self, text: impl Into<String>) {
        self.push_note(Note::problem(text));
    }

    /// Notes worth alarming the reader about — everything but [`NoteKind::Info`].
    pub fn alarming_notes(&self) -> impl Iterator<Item = &Note> {
        self.notes.iter().filter(|n| n.kind.is_alarming())
    }

    /// The soonest real deadline across all profiles.
    ///
    /// Only [`Expiry::At`] counts: a silently refreshed token has no deadline
    /// a human needs to meet, and an unknown one is unknown, not imminent.
    pub fn soonest_expiry(&self) -> Option<DateTime<Utc>> {
        self.profiles.iter().filter_map(|p| p.expires_at()).min()
    }

    /// Expiry of the active profile, if it has a real deadline.
    pub fn active_expiry(&self) -> Option<DateTime<Utc>> {
        let active = self.active.as_ref()?;
        self.profiles
            .iter()
            .find(|p| &p.id == active)
            .and_then(|p| p.expires_at())
    }
}

/// One login / profile / context inside a tool.
///
/// `Serialize` is written by hand for the same reason [`ToolStatus`]'s is: the
/// JSON still carries `expires_at`, but it is *derived* from [`Profile::expiry`]
/// at the moment of writing rather than stored. Two fields that must agree are
/// two fields that eventually will not; there is nowhere here to put a
/// disagreement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Profile {
    /// Stable id used for `switch`: account email, profile name, context name.
    pub id: String,
    /// Display label. Often equal to `id`.
    pub label: String,
    /// When — and whether — this login stops working. See [`Expiry`].
    pub expiry: Expiry,
    /// Small extra facts: project, region, domain, subscription owner.
    /// Never token values.
    pub meta: serde_json::Value,
}

impl Serialize for Profile {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let Self {
            id,
            label,
            expiry,
            meta,
        } = self;
        let mut out = serializer.serialize_struct("Profile", 5)?;
        out.serialize_field("id", id)?;
        out.serialize_field("label", label)?;
        out.serialize_field("expiry", expiry)?;
        // Kept for consumers written against the pre-0.4 shape. `Some` only
        // for a real deadline; the three states that are not one all read as
        // `null`, exactly as they did before `Expiry` existed.
        out.serialize_field("expires_at", &self.expires_at())?;
        out.serialize_field("meta", meta)?;
        out.end()
    }
}

/// Deserialization shape. `expires_at` is accepted and used only when no
/// `expiry` is present, so JSON written by an older patchbay still reads.
#[derive(Deserialize)]
struct ProfileWire {
    id: String,
    label: String,
    #[serde(default)]
    expiry: Option<Expiry>,
    #[serde(default)]
    expires_at: Option<DateTime<Utc>>,
    #[serde(default)]
    meta: serde_json::Value,
}

impl<'de> Deserialize<'de> for Profile {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = ProfileWire::deserialize(deserializer)?;
        let expiry = wire.expiry.unwrap_or(match wire.expires_at {
            Some(at) => Expiry::At(at),
            None => Expiry::default(),
        });
        Ok(Self {
            id: wire.id,
            label: wire.label,
            expiry,
            meta: match wire.meta {
                serde_json::Value::Null => serde_json::Value::Object(Default::default()),
                other => other,
            },
        })
    }
}

impl Profile {
    pub fn new(id: impl Into<String>) -> Self {
        let id = id.into();
        Self {
            label: id.clone(),
            id,
            expiry: Expiry::default(),
            meta: serde_json::Value::Object(Default::default()),
        }
    }

    pub fn label(mut self, label: impl Into<String>) -> Self {
        self.label = label.into();
        self
    }

    pub fn expiry(mut self, expiry: Expiry) -> Self {
        self.expiry = expiry;
        self
    }

    /// The deadline this profile carries, if it carries one.
    ///
    /// The single source of the serialized `expires_at`, so the two can never
    /// disagree. Delegates to [`Expiry::deadline`]: a refreshable token's
    /// hourly clock is not a login expiry and does not appear here.
    pub fn expires_at(&self) -> Option<DateTime<Utc>> {
        self.expiry.deadline()
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
    /// Nothing was attempted: this patchbay is running with command execution
    /// switched off, so it cannot invoke the tool's CLI. A property of
    /// patchbay's own configuration, not of the tool — which is why it is a
    /// distinct state rather than an `Unsupported` reason string. The panel
    /// turns it into a disabled button with a tooltip; it must never appear
    /// as a caveat about the user's login.
    ExecDisabled {
        tool: String,
        /// Command the human can run themselves in the meantime.
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
    /// Nothing was checked: command execution is switched off in this
    /// patchbay. See [`SwitchOutcome::ExecDisabled`].
    ExecDisabled { tool: String, hint: Option<String> },
}

/// One thing a tool's permissions can be read *against*.
///
/// Some tools have a single answer to "what may this credential do" — a gh
/// token carries its scopes wherever it goes. Others do not: a Google account's
/// IAM roles exist per project, so "what may I do" is only a question once a
/// project is named. This is that name, resolved by the probe rather than typed
/// by the human.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PermissionScope {
    /// What [`crate::Probe::permissions_in`] takes, e.g. a GCP project id.
    pub id: String,
    /// How to show it — a display name where the tool has one, else the id.
    pub label: String,
    /// The scope the tool's current configuration already points at, so the
    /// picker can open on the answer the user most likely wants.
    pub active: bool,
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
    pub notes: Vec<Note>,
    /// How to change what is granted.
    pub hint: Option<String>,
    /// Which [`PermissionScope`] this report is about, when the tool has any.
    /// `None` means the tool answers once for the whole credential — the
    /// field is omitted from JSON entirely in that case, so consumers written
    /// against the unscoped shape keep parsing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
}

impl PermissionsReport {
    pub fn unsupported(tool: &str, reason: &str, hint: Option<&str>) -> Self {
        Self {
            tool: tool.to_string(),
            supported: false,
            subject: None,
            scopes: Vec::new(),
            notes: vec![Note::info(reason)],
            hint: hint.map(|h| h.to_string()),
            scope: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(hours_from_now: i64) -> Expiry {
        Expiry::At(Utc::now() + Duration::hours(hours_from_now))
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
            ("vercel", ToolCategory::Edge),
            ("firebase", ToolCategory::Cloud),
            ("neon", ToolCategory::Cloud),
            ("supabase", ToolCategory::Cloud),
            ("flyctl", ToolCategory::Cloud),
            ("doctl", ToolCategory::Cloud),
            ("docker", ToolCategory::Containers),
            ("tailscale", ToolCategory::Network),
            ("ssh", ToolCategory::Network),
            ("stripe", ToolCategory::Payments),
            ("npm", ToolCategory::Code),
            ("op", ToolCategory::Secrets),
            ("ollama", ToolCategory::Ai),
            ("huggingface", ToolCategory::Ai),
            ("claude", ToolCategory::Ai),
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
        assert_eq!(
            empty.connection_state_at(now),
            ConnectionState::Disconnected
        );

        // An undated credential (gh keeps tokens in the keychain) still counts.
        let undated = status_with(Some("pathors"), vec![Profile::new("pathors")]);
        assert_eq!(undated.connection_state_at(now), ConnectionState::Connected);

        let healthy = status_with(
            Some("pathors"),
            vec![Profile::new("pathors").expiry(at(72))],
        );
        assert_eq!(healthy.connection_state_at(now), ConnectionState::Connected);

        let soon = status_with(Some("pathors"), vec![Profile::new("pathors").expiry(at(3))]);
        assert_eq!(soon.connection_state_at(now), ConnectionState::Attention);

        let stale = status_with(
            Some("pathors"),
            vec![Profile::new("pathors").expiry(at(-48))],
        );
        assert_eq!(stale.connection_state_at(now), ConnectionState::Attention);

        // Active profile has no expiry of its own: the soonest known one decides.
        let mixed = status_with(
            Some("pathors"),
            vec![
                Profile::new("pathors"),
                Profile::new("default").expiry(at(-1)),
            ],
        );
        assert_eq!(mixed.connection_state_at(now), ConnectionState::Attention);
    }

    #[test]
    fn test_json_carries_category_and_connection_state() {
        let status = status_with(
            Some("pathors"),
            vec![Profile::new("pathors").expiry(at(240))],
        );
        let json = serde_json::to_value(&status).unwrap();
        assert_eq!(json["category"], "cloud");
        assert_eq!(json["connection_state"], "connected");

        // The derived field is not an input: reading it back is lossless.
        let back: ToolStatus = serde_json::from_value(json).unwrap();
        assert_eq!(back, status);
    }

    #[test]
    fn test_registered_keys_travel_in_the_json_and_survive_a_round_trip() {
        let mut status = status_with(Some("default"), vec![Profile::new("default")]);
        status.tool = "wrangler".into();
        status.registered_keys = vec![KeyRef {
            id: "cf-api".into(),
            label: "CF API token".into(),
            last4: "1234".into(),
            expires_at: at(48).deadline(),
            expiry_state: crate::keys::KeyExpiryState::ExpiringSoon,
        }];

        let json = serde_json::to_value(&status).unwrap();
        assert_eq!(json["registered_keys"][0]["id"], "cf-api");
        assert_eq!(json["registered_keys"][0]["last4"], "1234");
        assert_eq!(json["registered_keys"][0]["expiry_state"], "expiring_soon");
        assert_eq!(status.keys_needing_attention().len(), 1);

        let back: ToolStatus = serde_json::from_value(json).unwrap();
        assert_eq!(back, status);
    }

    #[test]
    fn test_serialized_expires_at_can_never_disagree_with_expiry() {
        // The whole reason `expires_at` is derived rather than stored. Only a
        // real deadline produces a timestamp; the three states that are not a
        // deadline all serialize as null, including the refreshable one whose
        // access token *does* carry a time.
        let soon = Utc::now() + Duration::hours(2);
        let cases = [
            (Expiry::At(soon), Some(soon), "at"),
            (Expiry::NoExpiry, None, "no_expiry"),
            (Expiry::unknown("in the system keychain"), None, "unknown"),
            (
                Expiry::Refreshable {
                    access_token_expires: Some(soon),
                },
                None,
                "refreshable",
            ),
        ];

        for (expiry, deadline, wire) in cases {
            let profile = Profile::new("p").expiry(expiry.clone());
            assert_eq!(profile.expires_at(), deadline, "{wire}");

            let json = serde_json::to_value(&profile).unwrap();
            assert_eq!(json["expiry"]["state"], wire);
            assert_eq!(
                json["expires_at"],
                serde_json::to_value(deadline).unwrap(),
                "{wire}"
            );

            let back: Profile = serde_json::from_value(json).unwrap();
            assert_eq!(back, profile, "{wire}");
            assert_eq!(back.expires_at(), back.expiry.deadline(), "{wire}");
        }
    }

    #[test]
    fn test_refreshable_access_token_never_drags_a_row_into_attention() {
        // The trap this type exists to close: wrangler and neon renew their
        // hourly access token silently, so its clock is not a login deadline.
        let expired_hourly = Expiry::Refreshable {
            access_token_expires: Some(Utc::now() - Duration::hours(5)),
        };
        let status = status_with(
            Some("pathors"),
            vec![Profile::new("pathors").expiry(expired_hourly)],
        );
        assert_eq!(status.soonest_expiry(), None);
        assert_eq!(status.active_expiry(), None);
        assert_eq!(
            status.connection_state_at(Utc::now()),
            ConnectionState::Connected
        );
    }

    #[test]
    fn test_expiry_survives_a_round_trip_and_reads_the_pre_expiry_shape() {
        let at = Utc::now() + Duration::hours(9);
        for expiry in [
            Expiry::At(at),
            Expiry::NoExpiry,
            Expiry::unknown("in the Azure MSAL cache"),
            Expiry::Refreshable {
                access_token_expires: None,
            },
            Expiry::Refreshable {
                access_token_expires: Some(at),
            },
        ] {
            let json = serde_json::to_value(&expiry).unwrap();
            let back: Expiry = serde_json::from_value(json).unwrap();
            assert_eq!(back, expiry);
        }

        // A profile written by 0.3.x has expires_at and no expiry at all.
        let legacy = serde_json::json!({
            "id": "prod", "label": "prod", "expires_at": at, "meta": {}
        });
        let back: Profile = serde_json::from_value(legacy).unwrap();
        assert_eq!(back.expiry, Expiry::At(at));

        let undated = serde_json::json!({"id": "prod", "label": "prod", "meta": {}});
        let back: Profile = serde_json::from_value(undated).unwrap();
        assert!(matches!(back.expiry, Expiry::Unknown { .. }));
    }

    #[test]
    fn test_notes_carry_a_kind_and_only_the_loud_ones_count() {
        let mut status = ToolStatus::empty("docker", true);
        status.info("docker has no single active registry");
        status.warn("credentials are stored base64-encoded, not encrypted");
        status.problem("docker config.json is not valid JSON");

        assert_eq!(status.notes.len(), 3);
        assert_eq!(status.alarming_notes().count(), 2);

        let json = serde_json::to_value(&status).unwrap();
        assert_eq!(json["notes"][0]["kind"], "info");
        assert_eq!(json["notes"][1]["kind"], "warn");
        assert_eq!(json["notes"][2]["kind"], "problem");

        let back: ToolStatus = serde_json::from_value(json).unwrap();
        assert_eq!(back, status);
    }

    #[test]
    fn test_the_same_note_twice_is_recorded_once() {
        let mut status = ToolStatus::empty("gcloud", true);
        status.problem("~/.config/gcloud does not exist");
        status.problem("~/.config/gcloud does not exist");
        // Same words, different severity: a genuinely different claim.
        status.info("~/.config/gcloud does not exist");
        assert_eq!(status.notes.len(), 2);
    }

    #[test]
    fn test_active_concept_says_whether_an_empty_slot_is_normal() {
        let selects = ToolStatus::empty("gcloud", true);
        assert_eq!(selects.active_concept, ActiveConcept::Selects);
        assert!(!selects.active_concept.is_not_applicable());

        let mut rclone = ToolStatus::empty("rclone", true);
        rclone.active_concept =
            ActiveConcept::not_applicable("every rclone command names its own remote");
        assert!(rclone.active_concept.is_not_applicable());

        let json = serde_json::to_value(&rclone).unwrap();
        assert_eq!(json["active_concept"]["kind"], "not_applicable");
        assert_eq!(
            json["active_concept"]["reason"],
            "every rclone command names its own remote"
        );

        let back: ToolStatus = serde_json::from_value(json).unwrap();
        assert_eq!(back, rclone);
    }

    #[test]
    fn test_exec_disabled_is_its_own_outcome_not_a_reason_string() {
        // It describes patchbay's configuration, so the panel can disable the
        // button instead of printing a caveat about the user's login.
        let switch = SwitchOutcome::ExecDisabled {
            tool: "gh".into(),
            hint: Some("gh auth switch".into()),
        };
        let json = serde_json::to_value(&switch).unwrap();
        assert_eq!(json["result"], "exec_disabled");
        assert_eq!(json["hint"], "gh auth switch");

        let verify = VerifyOutcome::ExecDisabled {
            tool: "ngrok".into(),
            hint: None,
        };
        assert_eq!(
            serde_json::to_value(&verify).unwrap()["result"],
            "exec_disabled"
        );
    }

    #[test]
    fn test_json_written_before_registered_keys_existed_still_reads() {
        let legacy = serde_json::json!({
            "tool": "gh", "installed": true, "profiles": [], "active": null,
            "notes": [], "category": "code"
        });
        let back: ToolStatus = serde_json::from_value(legacy).unwrap();
        assert!(back.registered_keys.is_empty());
    }

    #[test]
    fn test_category_wire_names_are_snake_case() {
        // The panel and the MCP schema both key off these strings.
        for (category, wire) in [
            (ToolCategory::Containers, "containers"),
            (ToolCategory::Network, "network"),
            (ToolCategory::Payments, "payments"),
            (ToolCategory::Ai, "ai"),
        ] {
            assert_eq!(serde_json::to_value(category).unwrap(), wire);
        }
    }

    #[test]
    fn test_labels_are_human_readable() {
        assert_eq!(ToolCategory::Cloud.label(), "Cloud");
        assert_eq!(ToolCategory::Containers.label(), "Containers");
        assert_eq!(ToolCategory::Network.label(), "Network");
        assert_eq!(ToolCategory::Payments.label(), "Payments");
        assert_eq!(ToolCategory::Ai.label(), "AI");
        assert_eq!(ToolCategory::Other.label(), "Other");
        assert_eq!(ConnectionState::NotInstalled.label(), "Not installed");
    }
}
