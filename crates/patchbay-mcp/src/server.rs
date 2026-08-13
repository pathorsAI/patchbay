//! The MCP surface over [`patchbay_core::Registry`].
//!
//! Built on the official Rust MCP SDK (`rmcp` 3.x) using its macro router:
//! `#[tool_router]` collects the `#[tool]`-annotated methods into a
//! `ToolRouter<Self>`, and `#[tool_handler]` wires that router into the
//! [`ServerHandler`] impl.
//!
//! Tool descriptions are written for an AI operator deciding *whether* to
//! call, not for a human skimming reference docs — they are the main thing
//! that keeps an agent off the expensive tier-2 paths and stops it from
//! swallowing the caveats a switch returns. They are passed as explicit
//! `description = "..."` strings rather than doc comments because the doc
//! comment extractor drops blank lines, which would collapse each description
//! into one unreadable block.

use std::sync::Arc;

use patchbay_core::{KeyRegistry, McpClientRegistry, Registry};
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{
    CallToolResult, ContentBlock, Implementation, ProtocolVersion, ServerCapabilities, ServerInfo,
};
use rmcp::{tool, tool_handler, tool_router, ErrorData, ServerHandler};
use schemars::JsonSchema;
use serde::Deserialize;

/// Guidance handed to the client at `initialize`. This is the one thing an
/// agent reads before it has called anything, so the tier split, the
/// look-before-you-act rule and the "unsupported is an answer" rule all live
/// here as well as on the individual tools.
const INSTRUCTIONS: &str = "\
patchbay reports and switches the active login of the developer CLIs on this machine \
(gcloud, aws, gh, kubectl, az, wrangler, rclone, infisical).

Read this before using the tools.

1. Two tiers, very different costs. `list_connections` and `get_status` are tier 1: they read \
local config files only, take milliseconds, and never touch the network. Call them freely. \
`verify` and `get_permissions` are tier 2: they execute the tool's own CLI and may hit the \
network, taking seconds. Call those only when the user asks, or to resolve something tier 1 \
left genuinely ambiguous.

2. Look before you act. Which account, project or context is active is machine-global state \
that the user or another process may have changed since you last looked. Start from \
`list_connections` rather than from memory, from earlier in this session, or from what a \
command 'usually' uses.

3. `switch_profile` mutates state for the whole machine, not just your session, and the `notes` \
it returns carry real traps. Relay notes and hints to the user verbatim instead of \
summarising them away.

4. An 'unsupported' result is a normal answer, not a failure to retry. It means patchbay \
deliberately will not do that automatically, and `hint` names the command the human should \
run. Surface the hint; do not retry, and do not run the hint yourself.

5. `expires_at: null` means the expiry is UNKNOWN — commonly the token lives in the OS \
keychain where patchbay cannot read it without running the tool. It does not mean expired. \
Use `verify` if you need certainty.

6. Every connection tool returns metadata about credentials. Token, secret and key values are \
never returned by them.

7. The key vault (`store_key`, `list_keys`, `get_key`, `remove_key`) is a different thing from \
the connection tools above: it is this machine's registry for standalone API keys and tokens \
that no CLI tracks. `store_key` is the one you should reach for unprompted — whenever you create \
or receive a long-lived API key or token during a task, register it, so the user's patchbay \
stays the source of truth. Secrets go into the OS keychain; only the last 4 characters are \
written to disk. Never echo a secret anywhere else.

8. Reading a stored value back (`get_key`) and deleting one (`remove_key`) are refused unless \
the user started this server with PATCHBAY_ALLOW_SECRET_READ=1. That refusal is final: relay it \
and stop, and point the user at `pb key copy <id>` if they want the value themselves. \
`verify_key` is NOT gated: it returns a verdict, never a value, so use it whenever you need to \
know whether a key still works.

9. WHERE DOES THIS CREDENTIAL GO? Apply this rule every time you meet, create or rotate one, \
without being asked:

   Does the value belong to the HUMAN, across projects? -> patchbay. Cloudflare API tokens, \
provider API keys, personal access tokens, machine-level credentials, anything the user would \
reuse on their next project or paste into a second repo. Register it with `store_key`. If an \
entry with that id already exists, update it rather than inventing a second one, and when you \
ROTATE a credential re-store it under the SAME id with overwrite: true and a fresh expires_at. \
patchbay is the machine's source of truth for these; an unregistered one is a key the user will \
find in two years with no idea what it opens.

   Does it belong to ONE application or deployment? -> NOT patchbay. Route app env to the \
project's secret manager (Infisical or equivalent): per-app `.env` contents, service \
configuration, database URLs, deploy-time secrets for a specific codebase. Those belong with the \
codebase and its environments, not in the user's personal vault. Do not dump a `.env` file into \
`store_key` — it will bury the handful of credentials that actually matter under a pile of \
application config, which is the failure mode this rule exists to prevent.

   Unsure? Ask which project the value is scoped to. If the answer is 'all of them' or 'it is \
mine', it is a patchbay key.

10. The MCP client tools (`list_mcp_clients`, `add_mcp_server`, `copy_mcp_server`, \
`remove_mcp_server`) are a third thing again: they read and edit the config files in which the AI \
clients on this machine — Claude Code, Claude Desktop, Cursor, Codex, Windsurf, VS Code — register \
their MCP servers. `list_mcp_clients` is cheap and safe. The other three modify another tool's \
config, which takes effect on that tool's NEXT start, so say what you changed and that a restart \
is needed. Confirm with the user before removing anything. Never write a secret into a server's \
`env` or `headers` through these tools: those land in a plain-text config file. Reference an \
environment variable name, or register the secret with `store_key`, instead.

11. `plan_setup` and `mark_setup_done` are the fourth thing again: the checklist for finishing a \
MOVE to a new machine, after `pb export` / `pb import` have carried whatever could be carried. \
Work the list one item at a time; run only the items whose `auto` is true; hand every \
`needs_browser` item to the human with the exact command rather than trying to drive a browser \
login yourself; and re-check with `mark_setup_done` after each one, because patchbay re-probes the \
tool instead of believing what you report. Stop when `complete` is true, and do not invent extra \
setup work.";

/// `{ "tool": "gcloud" }` — identifies one supported CLI.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct ToolParams {
    /// Tool key. One of: "gcloud", "aws", "az", "firebase", "neon",
    /// "supabase", "flyctl", "doctl", "gh", "npm", "infisical", "op",
    /// "kubectl", "wrangler", "vercel", "rclone", "docker", "tailscale",
    /// "ssh", "stripe", "ollama", "huggingface", "claude". An unknown key
    /// returns an error listing every valid key, so you can retry with a
    /// correct one.
    pub tool: String,
}

/// `{ "tool": "gcloud", "profile_id": "work" }`.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct SwitchParams {
    /// Tool key, e.g. "gcloud". An unknown key returns an error listing every
    /// valid key.
    pub tool: String,
    /// The profile to make active. Must be one of the `profiles[].id` values
    /// reported by `get_status` for this tool — look it up rather than
    /// guessing at an account name.
    pub profile_id: String,
}

/// The MCP server. Holds one detected [`Registry`] for the process lifetime;
/// probes re-read their files on every call, so the data is never stale.
#[derive(Clone)]
pub struct PatchbayServer {
    /// `pub(crate)` because the migration tools in [`crate::migrate`] need both
    /// the probes and the `Paths` they were bound to.
    pub(crate) registry: Arc<Registry>,
    /// The key vault. `pub(crate)` because its tools live in [`crate::keys`].
    pub(crate) keys: Arc<KeyRegistry>,
    /// The MCP client board. `pub(crate)` because its tools live in
    /// [`crate::mcp_clients`].
    pub(crate) clients: Arc<McpClientRegistry>,
    tool_router: ToolRouter<Self>,
}

impl PatchbayServer {
    pub fn new(registry: Registry, keys: KeyRegistry, clients: McpClientRegistry) -> Self {
        Self {
            registry: Arc::new(registry),
            keys: Arc::new(keys),
            clients: Arc::new(clients),
            // Four routers, merged: connection tools here, vault tools in
            // `keys.rs`, MCP client tools in `mcp_clients.rs`, migration tools
            // in `migrate.rs`. Built once, not per request.
            tool_router: Self::tool_router()
                + Self::keys_router()
                + Self::mcp_clients_router()
                + Self::migrate_router(),
        }
    }
}

/// Probes do blocking file IO and (tier 2) spawn subprocesses. Run them on the
/// blocking pool so a slow `gcloud` call cannot stall the stdio transport.
pub(crate) async fn offload<T, F>(f: F) -> Result<T, ErrorData>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| ErrorData::internal_error(format!("patchbay worker failed: {e}"), None))
}

/// Success result. Object-shaped payloads also go out as `structuredContent`;
/// the text block carries pretty-printed JSON in every case, so a client that
/// ignores structured content still gets the whole answer.
///
/// `structuredContent` is specified as a JSON *object*, so an array payload
/// (`list_connections`) is returned as a text block only rather than being
/// wrapped in a synthetic envelope the caller would have to unwrap.
pub(crate) fn json_ok(value: serde_json::Value) -> CallToolResult {
    let text = serde_json::to_string_pretty(&value).unwrap_or_else(|_| value.to_string());
    let mut result = CallToolResult::success(vec![ContentBlock::text(text)]);
    if value.is_object() {
        result.structured_content = Some(value);
    }
    result
}

/// Registry failures come back as *tool* errors rather than protocol errors:
/// MCP clients render tool errors to the caller, and the message matters here
/// (an unknown-tool error lists the valid tool names, which is what lets an
/// agent self-correct without another round trip).
pub(crate) fn tool_error(err: anyhow::Error) -> CallToolResult {
    CallToolResult::error(vec![ContentBlock::text(format!("{err:#}"))])
}

/// Serialization of our own owned data cannot realistically fail; if it
/// somehow does, that is patchbay itself being broken — a protocol error.
pub(crate) fn encode<T: serde::Serialize>(value: &T) -> Result<serde_json::Value, ErrorData> {
    serde_json::to_value(value)
        .map_err(|e| ErrorData::internal_error(format!("failed to serialize result: {e}"), None))
}

#[tool_router]
impl PatchbayServer {
    #[tool(description = "\
TIER 1, CHEAP. List every developer CLI patchbay knows about and its current auth state. Reads \
local config files only: no subprocess, no network, low milliseconds.

Call this freely, and call it FIRST. Never assume which account, project or context is active \
from the conversation, from earlier in this session, or from what a command 'usually' uses — \
the active profile is machine-global state that the user or another process may have changed \
since you last looked.

Returns a JSON array of ToolStatus objects: { tool, installed, category, profiles: [{ id, label, \
expires_at, meta }], active, notes, connection_state }.

- `category` groups the board's 23 tools: cloud (gcloud, aws, az, firebase, neon, supabase, \
flyctl, doctl), code (gh, npm), secrets (infisical, op), cluster (kubectl), edge (wrangler, \
vercel), storage (rclone), containers (docker), network (tailscale, ssh), payments (stripe), \
ai (ollama, huggingface, claude), other. Filter on it when the user's request is about a class \
of tool ('am I logged into my cloud accounts?') rather than a named one.
- Some tools have no *active* profile by design — docker, rclone, ssh and npm all use every \
credential concurrently and pick one per command — so `active: null` there is normal, not a \
problem to fix.
- `connection_state` is patchbay's own verdict, derived from the fields below: `connected` \
(an active profile, nothing expiring within 24h), `attention` (active, but the credential is \
expired or expires within 24h — this is the one to surface), `disconnected` (installed, nothing \
active), `not_installed`. Prefer it over re-deriving the state from expiries yourself.
- `active` is the id you would pass to switch_profile. It may be null when nothing is logged in, \
or when the tool has no notion of an active profile.
- `expires_at: null` means UNKNOWN, not expired — usually the token lives in the OS keychain \
where patchbay cannot read the expiry without running the tool. Never report a null expiry as an \
expired credential; call `verify` if you need certainty.
- `registered_keys` lists standalone vault keys filed against this tool — a Cloudflare API \
token used for direct API calls shows up on the `wrangler` row even though no CLI tracks it. \
Each carries { id, label, last4, expires_at, expiry_state }; anything `expired` or \
`expiring_soon` is worth surfacing, and `verify_key` can confirm it against the issuer.
- `notes` carries the real caveats (malformed config, mismatched Application Default \
Credentials, missing directory). Read them; they explain surprises.
- A probe that fails degrades to `installed: false` plus an explanatory note, so one broken tool \
never blanks the board.
- Credential material is never returned, only metadata about it.")]
    async fn list_connections(&self) -> Result<CallToolResult, ErrorData> {
        let registry = self.registry.clone();
        let statuses = offload(move || registry.status_all()).await?;
        Ok(json_ok(encode(&statuses)?))
    }

    #[tool(description = "\
TIER 1, CHEAP. The auth state of one tool: its profiles, which one is active, and any caveats. \
Local config file reads only — no subprocess, no network, low milliseconds. Same contract and \
same caveats as list_connections, narrowed to a single tool.

Use this before any operation whose result depends on the active account, project or context, \
instead of assuming the login is still what it was earlier.

Returns one ToolStatus: { tool, installed, category, profiles: [{ id, label, expires_at, meta }], \
active, notes, registered_keys, connection_state }. `registered_keys` is the vault's standalone \
keys for this tool (id, label, last4, expires_at, expiry_state). `connection_state` is the quickest read: `connected`, \
`attention` (expired or expiring within 24h), `disconnected`, `not_installed`. Remember that \
`expires_at: null` means the expiry is unknown (token held in the OS keychain), which is not the \
same as expired — use `verify` if the difference matters.

An unrecognised `tool` comes back as an error whose message lists every valid tool key; retry \
with one of those.")]
    async fn get_status(
        &self,
        Parameters(ToolParams { tool }): Parameters<ToolParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let registry = self.registry.clone();
        match offload(move || registry.status(&tool)).await? {
            Ok(status) => Ok(json_ok(encode(&status)?)),
            Err(err) => Ok(tool_error(err)),
        }
    }

    #[tool(description = "\
MUTATES MACHINE-GLOBAL STATE. Change which profile / account / context a tool treats as active. \
The change is written to the tool's own config on disk, so it affects every other shell, \
terminal, editor, background process and CI runner on this machine — not just your session, and \
not just the current directory.

Do not call this speculatively or to 'fix' a failure on a hunch. Call it when the user asked to \
switch, or after telling them which profile you are about to activate and why. `profile_id` must \
be one of the `profiles[].id` values from get_status, so call that first rather than guessing at \
an account name.

Returns a SwitchOutcome, discriminated by the `result` field:

- 'switched' — applied. `notes` carries follow-on traps that you MUST pass through to the user \
rather than swallow. The canonical one: gcloud Application Default Credentials do NOT follow a \
configuration switch, so client libraries, Terraform and anything else using ADC keep \
authenticating as the OLD identity until the user separately runs \
`gcloud auth application-default login`. Reporting a clean switch while hiding that note is how \
people deploy to the wrong project.
- 'unsupported' — a normal answer, not a failure. This tool has no switch patchbay can perform \
safely and non-interactively. `hint` is a command for the HUMAN to run: surface it and stop. Do \
not retry, and do not run the hint yourself.
- 'unknown_profile' — no such profile. `available` lists the ids that do exist, so you can retry \
with a correct one.
- 'failed' — the switch was attempted and the tool refused. `detail` says why.")]
    async fn switch_profile(
        &self,
        Parameters(SwitchParams { tool, profile_id }): Parameters<SwitchParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let registry = self.registry.clone();
        match offload(move || registry.switch(&tool, &profile_id)).await? {
            Ok(outcome) => Ok(json_ok(encode(&outcome)?)),
            Err(err) => Ok(tool_error(err)),
        }
    }

    #[tool(description = "\
TIER 2, EXPENSIVE. Prove that a tool's active credential actually works right now, by executing \
that tool's own CLI — which normally makes a network round trip. Seconds, not milliseconds.

Do NOT call this routinely, and do not use it as a warm-up before other work. Call it only when \
either (a) the user explicitly asks whether a login is still good, or (b) tier 1 \
(list_connections / get_status) showed something ambiguous you need to resolve — an `expires_at` \
in the past, an `expires_at` of null you actually need pinned down, or notes suggesting the \
config is inconsistent — AND the answer changes what you do next. If tier 1 already answered the \
question, stop there.

Returns a VerifyOutcome, discriminated by the `result` field:

- 'valid' — the credential works right now.
- 'invalid' — a credential is present but was rejected or has expired. The user needs to \
re-authenticate; say so plainly.
- 'unsupported' — patchbay has no verification path for this tool yet. A normal answer, not an \
error: `hint` may name a command for the human to run. Surface it and stop; retrying will not \
change anything.")]
    async fn verify(
        &self,
        Parameters(ToolParams { tool }): Parameters<ToolParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let registry = self.registry.clone();
        match offload(move || registry.verify(&tool)).await? {
            Ok(outcome) => Ok(json_ok(encode(&outcome)?)),
            Err(err) => Ok(tool_error(err)),
        }
    }

    #[tool(description = "\
TIER 2, EXPENSIVE. Report what a tool's active credential is ALLOWED to do — subject, granted \
scopes and roles — by executing that tool's own CLI, which may hit the network. Seconds, not \
milliseconds.

Call this when the user asks about permissions, or when an operation failed with something that \
looks like a scope or role problem and knowing the granted scopes changes your advice. It is not \
part of a routine status check: use list_connections for that.

Returns a PermissionsReport: { tool, supported, subject, scopes, notes, hint }.

`supported: false` is a normal answer, not a failure: patchbay cannot enumerate permissions for \
this tool yet, `scopes` will be empty, and `hint` tells the human where to look or what to run. \
Relay the hint; do not retry.")]
    async fn get_permissions(
        &self,
        Parameters(ToolParams { tool }): Parameters<ToolParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let registry = self.registry.clone();
        match offload(move || registry.permissions(&tool)).await? {
            Ok(report) => Ok(json_ok(encode(&report)?)),
            Err(err) => Ok(tool_error(err)),
        }
    }
}

// `router = self.tool_router` uses the router built once in `new()`. The macro
// default (`Self::tool_router()`) would rebuild it on every list/call.
#[tool_handler(router = self.tool_router)]
impl ServerHandler for PatchbayServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(
                Implementation::new("patchbay-mcp", env!("CARGO_PKG_VERSION"))
                    .with_title("patchbay")
                    .with_description(
                        "Status board and switchboard for the developer CLI logins on this machine.",
                    ),
            )
            .with_instructions(INSTRUCTIONS)
    }

    /// Accept every protocol version this SDK knows, so older clients that
    /// still send `2024-11-05` can connect.
    fn supported_protocol_versions(&self) -> std::borrow::Cow<'static, [ProtocolVersion]> {
        std::borrow::Cow::Borrowed(ProtocolVersion::KNOWN_VERSIONS)
    }
}
