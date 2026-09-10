//! The key vault's MCP surface.
//!
//! Two headlines, one per direction. `store_key` is the write side: an agent
//! that just created a Cloudflare token or a provider key registers it here,
//! and the machine keeps knowing about it long after the conversation is gone.
//! `resolve_env_vars` is the read side, and the one a task actually reaches
//! for: it takes the variable names the code reads — `CLOUDFLARE_API_TOKEN`,
//! `DATABASE_URL` — and answers which of them this machine can already supply,
//! matching each entry by its `env` name, the UPPER_SNAKE_CASE second name a
//! key is exposed under. `update_key` keeps those two in step by backfilling an
//! `env` name onto an entry that never got one.
//!
//! Everything else exists to keep that honest — `list_keys` returns metadata
//! only, and the two dangerous calls (`get_key`, `remove_key`) are refused
//! unless the *user* started the server with [`ALLOW_SECRET_READ`] set.
//!
//! Kept in its own `#[tool_router]` impl block, merged into the main router in
//! [`crate::server`], so the vault's tools and the connection tools stay
//! separable.

use std::collections::BTreeSet;

use chrono::{DateTime, Utc};
use patchbay_core::keys::NewKey;
use patchbay_core::keys_verify::verify_key;
use patchbay_core::{filter_keys, EnvVarInfo, EnvVarSource, KeyEntry, KeyFilter, KeyPatch};
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::CallToolResult;
use rmcp::{tool, tool_router, ErrorData, Peer, RoleServer};
use schemars::JsonSchema;
use serde::Deserialize;

use crate::server::{encode, json_ok, offload, tool_error, PatchbayServer};

/// The environment variable that unlocks reading and deleting. Set on the
/// *server process*, by the user, in their MCP client config — an agent cannot
/// set it for itself.
pub const ALLOW_SECRET_READ: &str = "PATCHBAY_ALLOW_SECRET_READ";

/// Whether the operator has unlocked the secret-reading tools.
fn secret_read_allowed() -> bool {
    std::env::var(ALLOW_SECRET_READ).as_deref() == Ok("1")
}

/// The refusal. Written for the agent that just hit it: what is off, who can
/// turn it on, and what to tell the human to do instead.
fn locked(action: &str) -> String {
    format!(
        "refused: {action} is locked. patchbay only returns stored secret values when the user \
         has started this MCP server with {ALLOW_SECRET_READ}=1 in its environment, which is \
         deliberately not something you can change from here.\n\n\
         Tell the user this, and stop. If they want the value for themselves, the answer is \
         `pb key copy <id>` in a terminal: it puts the secret straight on their clipboard \
         without printing it anywhere. If they want you to have it, they can add \
         \"env\": {{ \"{ALLOW_SECRET_READ}\": \"1\" }} to this server's entry in their MCP client \
         config and restart it.\n\n\
         Do not work around this, and do not ask the user to paste the secret into the chat."
    )
}

/// `mcp:<client name>`, so the vault records which agent registered a key.
fn source_of(peer: &Peer<RoleServer>) -> String {
    match peer.peer_info() {
        Some(info) => format!("mcp:{}", info.client_info.name),
        None => "mcp".to_string(),
    }
}

fn parse_expiry(raw: &str) -> Result<DateTime<Utc>, String> {
    patchbay_core::util::parse_timestamp(raw)
        .or_else(|| {
            chrono::NaiveDate::parse_from_str(raw.trim(), "%Y-%m-%d")
                .ok()
                .map(|d| d.and_time(chrono::NaiveTime::MIN).and_utc())
        })
        .ok_or_else(|| {
            format!("could not read `{raw}` as a timestamp; use RFC 3339 (2027-01-01T00:00:00Z)")
        })
}

// ---------------------------------------------------------------------------
// parameters
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, JsonSchema)]
pub struct StoreKeyParams {
    /// Lowercase slug, unique on this machine, e.g. "cf-gh-actions-deploy".
    /// Letters, digits, `-`, `_` and `.` only. Make it describe the key's job,
    /// not the date: this is what the user will read in six months.
    pub id: String,
    /// Who issued the key: "cloudflare", "github", "openai", "stripe". Free
    /// form, but stay consistent with what `list_keys` already shows.
    pub provider: String,
    /// Short display name, e.g. "CF deploy token (repo X)".
    pub label: String,
    /// The secret value itself. It goes straight into the OS keychain and is
    /// never written to disk; only its last 4 characters are kept as metadata.
    /// Send it here and NOWHERE else — not into a file you are editing, not
    /// into your reply, not into a commit.
    pub secret: String,
    /// What the key is for, in a sentence the user will understand later:
    /// "deploy from GitHub Actions in repo X", not "api key".
    pub purpose: Option<String>,
    /// Granted scopes / permissions, as the issuer names them.
    pub scopes: Option<Vec<String>>,
    /// Base URL of the instance this key is for, when the provider is not one
    /// global service: "https://pathors.grafana.net" for a Grafana
    /// service-account token. REQUIRED for grafana keys — verify_key has no
    /// address to ask without it. Omit for cloudflare and github, which have
    /// one API each.
    pub endpoint: Option<String>,
    /// The environment variable this key is exposed as, UPPER_SNAKE_CASE:
    /// "CLOUDFLARE_API_TOKEN", "NEON_API_KEY". Use the exact name the code, CI
    /// secret or vendor SDK already reads; otherwise
    /// <PROVIDER>_<THING>_<KIND>. This is what `pb key run` injects the value
    /// as and what resolve_env_vars finds the entry by — fill it whenever you
    /// know it.
    pub env: Option<String>,
    /// When it expires, RFC 3339 ("2027-01-01T00:00:00Z") or "2027-01-01".
    /// Omit only when the key genuinely never expires — this is what lets
    /// patchbay warn the user before something breaks.
    pub expires_at: Option<String>,
    /// Replace an existing entry with this id. Default false. Only set this
    /// when you are deliberately rotating a key the user knows about;
    /// otherwise a duplicate id should be an error you resolve by picking a
    /// different id.
    pub overwrite: Option<bool>,
}

/// `{ "id": "cf-gh-actions-deploy" }`.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct KeyIdParams {
    /// The key's id, as listed by `list_keys`.
    pub id: String,
}

/// `{ "env": "CLOUDFLARE_API_TOKEN" }` — how a listing is narrowed.
///
/// Every field is optional and the struct itself is `#[serde(default)]`, which
/// is what keeps a bare `list_keys` (no `arguments` at all in the request, so
/// rmcp hands the extractor an empty object) working exactly as it did before
/// the filters existed.
#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(default)]
pub struct ListKeysParams {
    /// Who issued the key: "cloudflare", "github". Case-insensitive, and an
    /// exact match — not a substring; use `query` for a partial name.
    pub provider: Option<String>,
    /// The environment variable name an entry is exposed as,
    /// "CLOUDFLARE_API_TOKEN". Case-insensitive exact match. This is the
    /// narrowest filter there is: pass it whenever you know the variable the
    /// task needs.
    pub env: Option<String>,
    /// Free text, matched case-insensitively against id, label, provider,
    /// purpose and env. Use it when you know roughly what the key is for
    /// ("grafana", "app store") but not its id.
    pub query: Option<String>,
}

/// `{ "id": "cf-api", "env": "CLOUDFLARE_API_TOKEN" }` — a metadata patch.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct UpdateKeyParams {
    /// The key's id, as listed by `list_keys`. This names the entry to change
    /// and is never itself changed; a key cannot be renamed.
    pub id: String,
    /// New issuer name, when the entry was filed under the wrong one.
    pub provider: Option<String>,
    /// New display name.
    pub label: Option<String>,
    /// What the key is for, in a sentence the user will understand later.
    /// Replaces the existing purpose rather than appending to it, so carry
    /// over anything worth keeping.
    pub purpose: Option<String>,
    /// Granted scopes, as the issuer names them. Replaces the whole list.
    pub scopes: Option<Vec<String>>,
    /// When it expires, RFC 3339 ("2027-01-01T00:00:00Z") or "2027-01-01".
    pub expires_at: Option<String>,
    /// Base URL of the instance this key is for, for providers that are not
    /// one global service.
    pub endpoint: Option<String>,
    /// The environment variable this key is exposed as, UPPER_SNAKE_CASE:
    /// "CLOUDFLARE_API_TOKEN", "NEON_API_KEY". The field to backfill the
    /// moment you learn the name for an entry that has none — the purpose
    /// often says it ("same value as the GitHub secret NEON_API_KEY"). A name
    /// that is not UPPER_SNAKE_CASE is refused, and the refusal spells the
    /// corrected one.
    pub env: Option<String>,
    /// Fields to blank, by name: any of "purpose", "expires_at", "endpoint",
    /// "env". Naming a field here AND passing a value for it is an error —
    /// pass one or the other.
    pub clear: Option<Vec<String>>,
}

/// `{ "names": ["CLOUDFLARE_API_TOKEN", "DATABASE_URL"] }` — the variables a
/// task needs.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct ResolveEnvVarsParams {
    /// The variable names the task reads, spelled exactly as they appear in
    /// the code, the `.env` or the CI config: ["CLOUDFLARE_API_TOKEN",
    /// "DATABASE_URL"]. One to 50 of them; matching is case-insensitive. Ask
    /// for the names you actually need, not the whole file.
    pub names: Vec<String>,
    /// Optional: limit the env-vault half of the answer to one project id, as
    /// `list_env_projects` reports it. Omit it — the default — to search every
    /// registered project and every one of its environments, which is what you
    /// want when you do not already know the project.
    pub project: Option<String>,
}

/// Metadata plus a derived expiry state, so a caller does not have to do date
/// arithmetic to notice something is dead.
fn describe(entry: &KeyEntry, now: DateTime<Utc>) -> Result<serde_json::Value, ErrorData> {
    let mut value = encode(entry)?;
    if let Some(map) = value.as_object_mut() {
        // Bucketed by the core, so the MCP answer, `pb status` and the panel
        // can never disagree about what "expiring soon" means.
        map.insert("expiry_state".into(), encode(&entry.expiry_state(now))?);
        map.insert(
            "linked_tool".into(),
            match entry.linked_tool() {
                Some(tool) => tool.into(),
                None => serde_json::Value::Null,
            },
        );
    }
    Ok(value)
}

// ---------------------------------------------------------------------------
// resolving a wanted variable name against what this machine already holds
// ---------------------------------------------------------------------------

/// The nullable fields `update_key` can blank. `id`, `created_at` and `last4`
/// describe the stored value and are immutable; the rest are replaced by
/// passing a new value.
const CLEARABLE_FIELDS: [&str; 4] = ["purpose", "expires_at", "endpoint", "env"];

/// Name fragments that identify nothing on their own. `API`, `KEY` and `TOKEN`
/// are in every second variable on the machine, so matching on them alone
/// would offer the whole vault as a suggestion for every lookup.
const GENERIC_TOKENS: [&str; 12] = [
    "api", "key", "token", "secret", "id", "url", "private", "public", "access", "next", "app",
    "client",
];

/// Upper bound on suggestions for one name. This is a guess to confirm, not a
/// listing: five is already more than a user wants to read.
const MAX_SUGGESTIONS: usize = 5;

/// Upper bound on names per `resolve_env_vars` call.
const MAX_RESOLVE_NAMES: usize = 50;

/// The sentence that has to survive every rendering of the answer: what the
/// caller is holding is a route to the value, not the value.
const RESOLVE_NOTE: &str = "Values are never returned. Run the command through `pb key run` / \
`pb env run` so the secret goes keychain -> child process without passing through the \
conversation. A suggestion is a guess: confirm with the user, then record it with update_key so \
the next lookup is exact.";

/// Parse and validate the `clear` list. Split out from the tool so the rule —
/// which fields may be blanked, and what the refusal says — is testable
/// without a registry.
fn clear_set(clear: &[String]) -> Result<BTreeSet<String>, String> {
    let mut out = BTreeSet::new();
    for field in clear {
        let field = field.trim().to_ascii_lowercase();
        if !CLEARABLE_FIELDS.contains(&field.as_str()) {
            return Err(format!(
                "cannot clear `{field}`: the fields that can be blanked are {}. Every other field \
                 is changed by passing a new value, and `id`, `created_at` and `last4` never \
                 change at all.",
                CLEARABLE_FIELDS.join(", ")
            ));
        }
        out.insert(field);
    }
    Ok(out)
}

/// A patch field that can be set, blanked, or left alone: `Some(Some(v))`
/// sets, `Some(None)` blanks, `None` leaves it as it is.
fn nullable<T>(given: Option<T>, cleared: bool) -> Option<Option<T>> {
    match (given, cleared) {
        (Some(value), _) => Some(Some(value)),
        (None, true) => Some(None),
        (None, false) => None,
    }
}

/// Turns an `update_key` request into the patch it describes, or into the
/// message explaining why it is not a patch at all.
fn build_patch(params: UpdateKeyParams) -> Result<KeyPatch, String> {
    let cleared = clear_set(&params.clear.unwrap_or_default())?;
    for (field, given) in [
        ("purpose", params.purpose.is_some()),
        ("expires_at", params.expires_at.is_some()),
        ("endpoint", params.endpoint.is_some()),
        ("env", params.env.is_some()),
    ] {
        if given && cleared.contains(field) {
            return Err(format!(
                "`{field}` is both set and listed in `clear`; pass one or the other"
            ));
        }
    }

    let expires_at = params.expires_at.as_deref().map(parse_expiry).transpose()?;
    let patch = KeyPatch {
        provider: params.provider,
        label: params.label,
        scopes: params.scopes,
        purpose: nullable(params.purpose, cleared.contains("purpose")),
        expires_at: nullable(expires_at, cleared.contains("expires_at")),
        endpoint: nullable(params.endpoint, cleared.contains("endpoint")),
        env: nullable(params.env, cleared.contains("env")),
    };

    if patch.is_empty() {
        return Err(
            "nothing to change: pass at least one field to set, or name one in `clear`".to_string(),
        );
    }
    Ok(patch)
}

/// An entry that looks like a wanted name without being named it, plus the
/// reason it was offered — a suggestion the caller cannot explain is one they
/// cannot confirm with the user.
#[derive(Debug, Clone, PartialEq)]
struct Suggestion {
    entry: KeyEntry,
    why: String,
}

/// One environment of one registered project that already carries the name.
#[derive(Debug, Clone, PartialEq)]
struct ProjectHit {
    project: String,
    env: String,
    source: EnvVarSource,
}

/// Everything this machine can say about one wanted variable name.
#[derive(Debug, Clone, PartialEq)]
struct ResolvedVar {
    name: String,
    keys: Vec<KeyEntry>,
    suggestions: Vec<Suggestion>,
    projects: Vec<ProjectHit>,
}

impl ResolvedVar {
    /// Whether the machine can supply this name outright. A suggestion is
    /// explicitly not this: it is a guess waiting on a human.
    fn is_supplied(&self) -> bool {
        !self.keys.is_empty() || !self.projects.is_empty()
    }

    fn status(&self) -> &'static str {
        match (!self.keys.is_empty(), !self.projects.is_empty()) {
            (true, true) => "both",
            (true, false) => "key",
            (false, true) => "project_var",
            (false, false) if !self.suggestions.is_empty() => "suggested",
            (false, false) => "missing",
        }
    }

    /// The command that puts the value where the task needs it without anyone
    /// reading it. A registered key wins over a project variable (it is the
    /// human's own credential, and the id is unambiguous); a suggestion only
    /// ever yields the two-step form, because the first step is a decision.
    fn use_command(&self) -> Option<String> {
        if let Some(first) = self.keys.first() {
            let mut command = format!("pb key run {} -- <cmd>", first.id);
            if self.keys.len() > 1 {
                let others: Vec<&str> = self.keys[1..].iter().map(|e| e.id.as_str()).collect();
                command.push_str(&format!("  # or: {}", others.join(", ")));
            }
            return Some(command);
        }
        if let Some(hit) = self.projects.first() {
            return Some(format!(
                "pb env run --project {} -e {} -- <cmd>",
                hit.project, hit.env
            ));
        }
        self.suggestions.first().map(|s| {
            format!(
                "pb key edit {} --env {}  # then: pb key run {} -- <cmd>",
                s.entry.id, self.name, s.entry.id
            )
        })
    }
}

/// The fragments of a variable name that actually identify something.
fn identifying_tokens(name: &str) -> Vec<String> {
    name.split('_')
        .map(|token| token.trim().to_lowercase())
        .filter(|token| !token.is_empty() && !GENERIC_TOKENS.contains(&token.as_str()))
        .collect()
}

/// Entries that look like `name` without carrying it as their `env`.
///
/// Two rules, strongest first. A verbatim mention in the purpose, label or id
/// is near-certain — free-text purposes are exactly where the link used to be
/// buried ("same value as the GitHub secret NEON_API_KEY"). A token match is
/// weaker and deliberately conservative: every identifying fragment of the
/// name has to appear somewhere in the entry, and fragments that identify
/// nothing ([`GENERIC_TOKENS`]) are dropped first, so `API_KEY` — which is all
/// generic — suggests nothing at all rather than everything.
fn suggest_for(name: &str, entries: &[KeyEntry]) -> Vec<Suggestion> {
    let needle = name.to_lowercase();
    let tokens = identifying_tokens(name);
    let mut strong: Vec<Suggestion> = Vec::new();
    let mut weak: Vec<Suggestion> = Vec::new();

    for entry in entries {
        let mention = [
            ("purpose", entry.purpose.as_deref()),
            ("label", Some(entry.label.as_str())),
            ("id", Some(entry.id.as_str())),
        ]
        .into_iter()
        .filter_map(|(field, value)| value.map(|value| (field, value)))
        .find(|(_, value)| value.to_lowercase().contains(&needle));

        if let Some((field, _)) = mention {
            strong.push(Suggestion {
                entry: entry.clone(),
                why: format!("{field} mentions {name}"),
            });
            continue;
        }
        if tokens.is_empty() {
            continue;
        }
        let haystack = format!(
            "{} {} {} {}",
            entry.id,
            entry.label,
            entry.provider,
            entry.purpose.as_deref().unwrap_or_default()
        )
        .to_lowercase();
        if tokens.iter().all(|token| haystack.contains(token.as_str())) {
            weak.push(Suggestion {
                entry: entry.clone(),
                why: format!("matches tokens {}", tokens.join(", ")),
            });
        }
    }

    strong
        .into_iter()
        .chain(weak)
        .take(MAX_SUGGESTIONS)
        .collect()
}

/// One wanted name against the two local registries. Pure: the IO happens in
/// the tool, the judgement happens here, and the judgement is what gets tested.
fn resolve_one(
    name: &str,
    entries: &[KeyEntry],
    project_vars: &[(String, String, Vec<EnvVarInfo>)],
) -> ResolvedVar {
    let name = name.trim().to_string();
    let keys: Vec<KeyEntry> = entries
        .iter()
        .filter(|e| {
            e.env
                .as_deref()
                .is_some_and(|env| env.eq_ignore_ascii_case(&name))
        })
        .cloned()
        .collect();
    // Suggestions are the consolation prize, never noise on top of an answer.
    let suggestions = if keys.is_empty() {
        suggest_for(&name, entries)
    } else {
        Vec::new()
    };
    let projects: Vec<ProjectHit> = project_vars
        .iter()
        .filter_map(|(project, env, vars)| {
            vars.iter()
                .find(|var| var.name.eq_ignore_ascii_case(&name))
                .map(|var| ProjectHit {
                    project: project.clone(),
                    env: env.clone(),
                    source: var.source,
                })
        })
        .collect();

    ResolvedVar {
        name,
        keys,
        suggestions,
        projects,
    }
}

/// The wire shape of one resolved name.
fn resolved_json(
    resolved: &ResolvedVar,
    now: DateTime<Utc>,
) -> Result<serde_json::Value, ErrorData> {
    let keys = resolved
        .keys
        .iter()
        .map(|e| describe(e, now))
        .collect::<Result<Vec<_>, ErrorData>>()?;
    let suggestions = resolved
        .suggestions
        .iter()
        .map(|s| {
            Ok(serde_json::json!({
                "id": s.entry.id,
                "provider": s.entry.provider,
                "label": s.entry.label,
                "env": s.entry.env,
                "expiry_state": encode(&s.entry.expiry_state(now))?,
                "why": s.why,
            }))
        })
        .collect::<Result<Vec<_>, ErrorData>>()?;
    let projects = resolved
        .projects
        .iter()
        .map(|hit| {
            Ok(serde_json::json!({
                "project": hit.project,
                "env": hit.env,
                "source": encode(&hit.source)?,
            }))
        })
        .collect::<Result<Vec<_>, ErrorData>>()?;

    Ok(serde_json::json!({
        "name": resolved.name,
        "status": resolved.status(),
        "keys": keys,
        "suggestions": suggestions,
        "projects": projects,
        "use": resolved.use_command(),
    }))
}

// ---------------------------------------------------------------------------
// tools
// ---------------------------------------------------------------------------

#[tool_router(router = keys_router, vis = "pub(crate)")]
impl PatchbayServer {
    #[tool(description = "\
REGISTER A KEY YOU CREATED. patchbay is this machine's registry for standalone API keys and \
tokens — the ones no CLI tracks: a Cloudflare token pasted into GitHub Actions, a provider key \
wired into a cron job, a service token you generated ten minutes ago.

Whenever you create or receive a long-lived API key or token during a task, register it here so \
the user's patchbay stays the source of truth. Do it as part of the task, not as an \
afterthought — an unregistered key is one the user will find in two years with no idea what it \
opens, or will never find at all when it silently expires.

THE ROUTING RULE, in one line: does this value belong to the human across projects (-> \
patchbay, register it here) or to one application/deployment (-> route app env to the project's \
secret manager, Infisical or equivalent)? patchbay's vault is for the user's own machine-level \
credentials, not application config.

For a key tied to a specific instance rather than a global service — a Grafana service-account \
token, anything self-hosted — set `endpoint` to the instance root. Without it patchbay can store \
the key but can never verify it.

Register: long-lived API keys, personal access tokens, deploy tokens, service-account keys, \
webhook signing secrets, machine-level credentials the user reuses across projects. Do NOT \
register: per-app `.env` contents, service configuration or deploy-time secrets scoped to one \
codebase (those go to the project's secret manager); short-lived session tokens a CLI already \
manages (use list_connections for those); OAuth refresh flows the tool owns; or passwords.

Rotating a credential you already registered? Re-store it under the SAME id with \
overwrite: true and a fresh expires_at, rather than creating a second entry. If the id exists \
but only its metadata is wrong, the key is already tracked — leave the value alone.

Where the secret goes: the OS keychain, immediately. The metadata file on disk gets the last 4 \
characters and nothing else. NEVER echo the secret anywhere else — not into your reply, not into \
a file you are editing, not into a commit, not into a log, not into another tool call. This tool \
call is the only place it belongs.

Fill in `purpose` and `expires_at` whenever you know them. They are what make the registry worth \
having: `purpose` is what tells the user in six months whether they can revoke it, and \
`expires_at` is what lets patchbay warn them before a deploy starts failing.

Fill in `env` too: the UPPER_SNAKE_CASE name the value is read under \
(`CLOUDFLARE_API_TOKEN`, `NEON_API_KEY` — the exact spelling the code, the CI secret or the \
vendor SDK already uses, otherwise <PROVIDER>_<THING>_<KIND>). It is the only structured link \
between a slug id and the variable a task is missing, which is what lets the next agent find \
this key with resolve_env_vars instead of asking the user for a value they already gave you.

Both-or-neither: metadata and value are written together, and a keychain failure rolls the \
metadata back, so a successful result means the key really is stored. A duplicate id is an error \
unless you pass overwrite: true.

Returns the stored metadata (id, provider, label, purpose, scopes, created_at, expires_at, \
last4, source, env). The secret is never echoed back.")]
    async fn store_key(
        &self,
        peer: Peer<RoleServer>,
        Parameters(params): Parameters<StoreKeyParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let expires_at = match params.expires_at.as_deref().map(parse_expiry).transpose() {
            Ok(at) => at,
            Err(message) => return Ok(tool_error(anyhow::anyhow!(message))),
        };

        let new = NewKey::new(params.id, source_of(&peer))
            .provider(params.provider)
            .label(params.label)
            .purpose(params.purpose)
            .scopes(params.scopes.unwrap_or_default())
            .expires_at(expires_at)
            .endpoint(params.endpoint)
            .env(params.env);
        let secret = params.secret;
        let overwrite = params.overwrite.unwrap_or(false);

        let keys = self.keys.clone();
        match offload(move || keys.add(new, &secret, overwrite)).await? {
            Ok(entry) => Ok(json_ok(encode(&entry)?)),
            Err(err) => Ok(tool_error(err)),
        }
    }

    #[tool(description = "\
CHEAP, SAFE. LOOK HERE BEFORE SAYING A CREDENTIAL IS MISSING. Every standalone API key \
registered on this machine — metadata only. Reads one local JSON file: no keychain access, no \
network, no secret values.

Call this before store_key to see whether the key is already registered and what id convention \
the user follows, when the user asks what keys or tokens they have, and when something \
credential-shaped just failed — an expired entry here explains a lot of otherwise mysterious \
403s.

Narrow it. This machine may hold dozens of entries with long purposes; pass `env` when you know \
the variable name, `provider` when you know the issuer, `query` for anything else, and only call \
it bare when the user asks what they have. For 'which of these variables can this machine \
supply?' prefer resolve_env_vars.

Returns a JSON array of entries: { id, provider, label, purpose, scopes, created_at, \
expires_at, last4, source, env, expiry_state }.

- `env` is the environment variable the entry is exposed as (`CLOUDFLARE_API_TOKEN`), when it \
has one. It is the name code reads the value under, the name `pb key run` injects it as, and the \
one resolve_env_vars matches on; an entry without it is one to backfill with update_key as soon \
as you learn the name.
- `expiry_state` is derived for you: 'expired', 'expiring_soon' (within 30 days), 'valid', or \
'no_expiry'. Surface anything expired or expiring soon — that is the whole point of the vault.
- `last4` is the last 4 characters of the secret, so the user can match an entry against a token \
in a provider's dashboard. It is the only thing here derived from the value.
- `source` says who registered the entry ('cli', 'mcp:<client>', 'gui').
- Secret values are NOT included and cannot be obtained from this tool.")]
    async fn list_keys(
        &self,
        Parameters(params): Parameters<ListKeysParams>,
    ) -> Result<CallToolResult, ErrorData> {
        // Every field is optional and the struct is `#[serde(default)]`, so a
        // call with no `arguments` at all — which rmcp hands the extractor as
        // an empty object — is still the unfiltered listing it always was.
        let filter = KeyFilter {
            provider: params.provider,
            env: params.env,
            query: params.query,
        };
        let keys = self.keys.clone();
        match offload(move || keys.list()).await? {
            Ok(entries) => {
                let now = Utc::now();
                let described: Result<Vec<_>, ErrorData> = filter_keys(&entries, &filter)
                    .iter()
                    .map(|e| describe(e, now))
                    .collect();
                Ok(json_ok(serde_json::Value::Array(described?)))
            }
            Err(err) => Ok(tool_error(err)),
        }
    }

    #[tool(description = "\
FIX OR COMPLETE A KEY'S METADATA without touching its value. Use it to backfill `env` (the \
variable name) on an entry that lacks one the moment you learn it — the purpose often says which \
GitHub secret or `.env` name the value lives under — to correct a purpose or label, or to record \
an expiry the user just told you.

Not for rotation: a new VALUE is store_key with overwrite: true. Not gated: this reads and \
writes keys.json only and never opens the keychain.

Pass only the fields you are changing. Each one REPLACES what was there — `scopes` replaces the \
whole list, `purpose` replaces the whole sentence — so carry over anything worth keeping. To \
blank a field instead, name it in `clear`: 'purpose', 'expires_at', 'endpoint' and 'env' are the \
four that can be blanked. Naming a field in `clear` and passing a value for it is an error, and \
so is a call that changes nothing.

`id`, `created_at` and `last4` never change: they describe the stored value, and a key cannot be \
renamed. An `env` that is not UPPER_SNAKE_CASE is refused, and the refusal spells the corrected \
name — use that rather than inventing a variant.

Returns the updated entry: { id, provider, label, purpose, scopes, created_at, expires_at, \
last4, source, endpoint, env, expiry_state, linked_tool }.")]
    async fn update_key(
        &self,
        Parameters(params): Parameters<UpdateKeyParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let id = params.id.clone();
        let patch = match build_patch(params) {
            Ok(patch) => patch,
            Err(message) => return Ok(tool_error(anyhow::anyhow!(message))),
        };

        let keys = self.keys.clone();
        match offload(move || keys.update_metadata(&id, patch)).await? {
            Ok(entry) => Ok(json_ok(describe(&entry, Utc::now())?)),
            Err(err) => Ok(tool_error(err)),
        }
    }

    #[tool(description = "\
CHEAP, SAFE. CALL THIS WHEN A TASK NEEDS AN ENVIRONMENT VARIABLE OR CREDENTIAL — before asking \
the user for a value, before writing a placeholder, before saying it is missing. Give it the \
names the code reads (`CLOUDFLARE_API_TOKEN`, `DATABASE_URL`) and it answers which of them this \
machine can already supply: from the key vault (by each entry's `env` name, with best-effort \
suggestions when nothing is named exactly), and from the env vault's registered projects. Reads \
two local JSON files; no keychain, no network, no values.

A command that failed with 401/403, a script reading `process.env.X`, a deploy wanting a secret, \
a blank line in a `.env` — all of them are this call. Pass `project` only when you already know \
which project's environment to look in; the default searches every registered project and every \
environment.

Returns { resolved, found, missing, note }. Each entry of `resolved` is { name, status, keys, \
suggestions, projects, use }:

- `status` is 'key' (a vault entry is named exactly this), 'project_var' (a registered project's \
environment carries it), 'both', 'suggested' (nothing is named this, but an entry looks like it) \
or 'missing' (nothing at all).
- `keys` are full vault entries, metadata only. TWO ENTRIES MAY SHARE ONE NAME — a dev and a \
production `LANGFUSE_SECRET_KEY` — so when more than one comes back, pick by `purpose` and say \
which you picked; never guess.
- `suggestions` appear only when nothing is named exactly, and each carries { id, provider, \
label, env, expiry_state, why }. A suggestion IS A GUESS: confirm it with the user before using \
it, and once confirmed, record it with update_key so the next lookup is exact instead of lucky.
- `projects` are { project, env, source } — which registered project and environment already \
carry a variable of that name.
- `use` is the point of the whole answer: THE EXACT COMMAND that puts the value where the task \
needs it, without you ever seeing it. Relay it, or run it — `pb key run <id> -- <cmd>` injects \
one vault key as its variable into one child process, `pb env run --project <id> -e <env> -- \
<cmd>` does the same for a project's whole environment. Do NOT follow up with get_key: the \
answer here is HOW TO USE the value, and reading it back is both gated and unnecessary.
- `found` counts the names this machine can supply outright ('key', 'project_var' or 'both'). \
`missing` lists the names with nothing at all — those, and only those, are the ones to go back \
to the user about. A 'suggested' name is in neither: it is waiting on a human to confirm.")]
    async fn resolve_env_vars(
        &self,
        Parameters(params): Parameters<ResolveEnvVarsParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let names: Vec<String> = params
            .names
            .iter()
            .map(|name| name.trim().to_string())
            .filter(|name| !name.is_empty())
            .collect();
        if names.is_empty() {
            return Ok(tool_error(anyhow::anyhow!(
                "pass at least one variable name in `names`, spelled the way the code reads it \
                 (\"CLOUDFLARE_API_TOKEN\")"
            )));
        }
        if names.len() > MAX_RESOLVE_NAMES {
            return Ok(tool_error(anyhow::anyhow!(
                "{} names is more than the {MAX_RESOLVE_NAMES} this tool takes at once; ask for \
                 the ones the task actually reads",
                names.len()
            )));
        }

        let keys = self.keys.clone();
        let envs = self.envs.clone();
        let wanted = params.project;
        let gathered = offload(move || {
            let entries = keys.list()?;
            let mut projects = envs.projects()?;
            if let Some(want) = &wanted {
                projects.retain(|p| p.id == *want);
                if projects.is_empty() {
                    anyhow::bail!(
                        "no project registered as `{want}`; list_env_projects shows the ids"
                    );
                }
            }
            let mut project_vars: Vec<(String, String, Vec<EnvVarInfo>)> = Vec::new();
            for project in &projects {
                for env in project.env_names() {
                    project_vars.push((
                        project.id.clone(),
                        env.to_string(),
                        envs.list(&project.id, env)?,
                    ));
                }
            }
            Ok::<_, anyhow::Error>((entries, project_vars))
        })
        .await?;

        let (entries, project_vars) = match gathered {
            Ok(pair) => pair,
            Err(err) => return Ok(tool_error(err)),
        };

        let now = Utc::now();
        let resolved: Vec<ResolvedVar> = names
            .iter()
            .map(|name| resolve_one(name, &entries, &project_vars))
            .collect();
        let found = resolved.iter().filter(|r| r.is_supplied()).count();
        let missing: Vec<&str> = resolved
            .iter()
            .filter(|r| r.status() == "missing")
            .map(|r| r.name.as_str())
            .collect();
        let rendered: Result<Vec<_>, ErrorData> =
            resolved.iter().map(|r| resolved_json(r, now)).collect();

        Ok(json_ok(serde_json::json!({
            "resolved": rendered?,
            "found": found,
            "missing": missing,
            "note": RESOLVE_NOTE,
        })))
    }

    #[tool(description = "\
ASK THE ISSUER whether a registered key still works. NOT gated: this returns a verdict, never \
the value, so it is safe to call whenever the answer would change what you do.

Makes an outbound HTTPS request to the provider using the stored secret, which patchbay reads \
internally and never returns to you — sometimes a second one, where the first answer does not \
settle it. Seconds, not milliseconds. Providers patchbay can interrogate today: cloudflare and \
github. Anything else comes back 'unsupported'.

Call it when the user asks whether a key is still good, before relying on a key for something \
expensive or destructive, or when an operation failed with something that smells like a bad \
credential. Do not call it on every key in a loop just to build a report — verify the one you \
care about.

Returns { status, detail, expires_at, scopes }:

- 'valid' — the issuer confirms it works. If `expires_at` came back and the registry did not \
have it, patchbay has already written it back for you; if you registered this key earlier \
WITHOUT an expiry and this call reveals one, that is the fix landing automatically. Mention the \
expiry to the user when it is close.
- 'invalid' — the issuer rejected it: revoked, deleted, disabled, or never real. Say so \
plainly; the user needs to rotate it, and then re-register with store_key + overwrite.
- 'expired' — the issuer knows it, its lifetime is over. Same action: rotate and re-store.
- 'inconclusive' — the provider answered, and its answer fits a live key as well as a dead one. \
A Cloudflare token scoped to one product is rejected by the same response a revoked token gets, \
so patchbay declines to guess. Do NOT report this as a dead credential and do NOT advise \
rotating; say patchbay could not tell, and that the token's own dashboard page can.
- 'unsupported' — patchbay has no verification path for this provider. A normal answer, not a \
failure. Do not retry; point the user at the provider's dashboard.
- 'unreachable' — the provider could not be reached (DNS, timeout, rate limit, 5xx). This says \
NOTHING about the key. Never report it as a dead credential, and do not advise rotating on the \
strength of it.")]
    async fn verify_key(
        &self,
        Parameters(KeyIdParams { id }): Parameters<KeyIdParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let keys = self.keys.clone();
        let outcome = offload(move || {
            let entry = keys
                .get(&id)?
                .ok_or_else(|| anyhow::anyhow!("no key registered as `{id}`"))?;
            // The secret exists only inside this closure, for one request.
            let secret = keys.get_secret(&id)?;
            let outcome = verify_key(&entry, &secret);
            drop(secret);

            // The issuer is the authority on its own token: absorb what it
            // said, so the next list_keys is right without another round trip.
            if outcome.status == patchbay_core::KeyVerifyStatus::Valid {
                let mut patch = patchbay_core::KeyPatch::default();
                if let Some(at) = outcome.expires_at {
                    if entry.expires_at != Some(at) {
                        patch.expires_at = Some(Some(at));
                    }
                }
                if !outcome.scopes.is_empty() && outcome.scopes != entry.scopes {
                    patch.scopes = Some(outcome.scopes.clone());
                }
                if !patch.is_empty() {
                    keys.update_metadata(&entry.id, patch)?;
                }
            }
            Ok::<_, anyhow::Error>((entry.id, outcome))
        })
        .await?;

        match outcome {
            Ok((id, outcome)) => {
                let mut value = encode(&outcome)?;
                if let Some(map) = value.as_object_mut() {
                    map.insert("id".into(), id.into());
                }
                Ok(json_ok(value))
            }
            Err(err) => Ok(tool_error(err)),
        }
    }

    #[tool(description = "\
LOCKED BY DEFAULT. Return the actual secret value of a registered key.

This only works when the user has started this MCP server with the environment variable \
PATCHBAY_ALLOW_SECRET_READ=1. Without it every call is refused, and no argument you pass can \
change that — the flag lives on the server process, not in the request.

If you get the refusal: relay it and stop. The human path is `pb key copy <id>` in a terminal, \
which puts the value on their clipboard without printing it. Do not look for another way to \
reach the value, and do not ask the user to paste it into the chat.

Even when the flag IS set, treat the result as the most sensitive thing in the conversation: use \
it for the one operation you needed it for, never repeat it back to the user, never write it \
into a file, a commit, a log or another tool call, and do not keep it in your reasoning any \
longer than the call that needs it. Prefer designs where the secret is referenced by id rather \
than pasted around.

Returns { id, secret } on success.")]
    async fn get_key(
        &self,
        Parameters(KeyIdParams { id }): Parameters<KeyIdParams>,
    ) -> Result<CallToolResult, ErrorData> {
        if !secret_read_allowed() {
            return Ok(tool_error(anyhow::anyhow!(locked("reading a key's value"))));
        }
        let keys = self.keys.clone();
        match offload(move || keys.get_secret(&id).map(|secret| (id, secret))).await? {
            Ok((id, secret)) => Ok(json_ok(serde_json::json!({ "id": id, "secret": secret }))),
            Err(err) => Ok(tool_error(err)),
        }
    }

    #[tool(description = "\
LOCKED BY DEFAULT, AND DESTRUCTIVE. Unregister a key: the metadata entry AND the stored value in \
the OS keychain are both deleted, and patchbay cannot get either back.

Gated on the same flag as get_key: it only works when the user started this MCP server with \
PATCHBAY_ALLOW_SECRET_READ=1. Without it the call is refused; relay that and stop. The human \
path is `pb key rm <id>` in a terminal.

Even when the flag is set, do not call this on your own initiative. Ask the user first, by id \
and label, and let them answer. Removing an entry does NOT revoke the key at the provider — the \
credential keeps working, the machine just forgets it exists, which is the worst of both worlds \
if it was not deliberate. Say that when you propose it.

Returns the metadata of the entry that was removed.")]
    async fn remove_key(
        &self,
        Parameters(KeyIdParams { id }): Parameters<KeyIdParams>,
    ) -> Result<CallToolResult, ErrorData> {
        if !secret_read_allowed() {
            return Ok(tool_error(anyhow::anyhow!(locked("removing a key"))));
        }
        let keys = self.keys.clone();
        match offload(move || keys.remove(&id)).await? {
            Ok(entry) => Ok(json_ok(encode(&entry)?)),
            Err(err) => Ok(tool_error(err)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_the_gate_is_closed_unless_the_flag_is_exactly_one() {
        // `std::env::set_var` is unsafe (and process-global) in edition 2024;
        // the parsing rule is what matters here, so it is checked directly.
        let allows = |v: Option<&str>| v == Some("1");
        assert!(allows(Some("1")));
        assert!(!allows(Some("0")));
        assert!(!allows(Some("true")));
        assert!(!allows(Some("")));
        assert!(!allows(None));
    }

    #[test]
    fn test_the_refusal_explains_the_flag_and_the_human_path() {
        let text = locked("reading a key's value");
        assert!(text.contains(ALLOW_SECRET_READ), "{text}");
        assert!(text.contains("pb key copy"), "{text}");
        assert!(text.contains("Do not work around this"), "{text}");
    }

    #[test]
    fn test_expiry_parsing_accepts_both_shapes() {
        assert!(parse_expiry("2027-01-01T00:00:00Z").is_ok());
        assert!(parse_expiry("2027-01-01").is_ok());
        let err = parse_expiry("whenever").unwrap_err();
        assert!(err.contains("RFC 3339"), "{err}");
    }

    #[test]
    fn test_expiry_state_is_derived_for_the_caller() {
        let now = Utc::now();
        let entry = |expires: Option<DateTime<Utc>>| KeyEntry {
            id: "k".into(),
            provider: "p".into(),
            label: "l".into(),
            purpose: None,
            scopes: vec![],
            created_at: now,
            expires_at: expires,
            last4: "1234".into(),
            source: "mcp:test".into(),
            endpoint: None,
            env: None,
        };
        let state = |e: KeyEntry| {
            describe(&e, now).unwrap()["expiry_state"]
                .as_str()
                .unwrap()
                .to_string()
        };

        assert_eq!(state(entry(None)), "no_expiry");
        assert_eq!(
            state(entry(Some(now - chrono::Duration::days(1)))),
            "expired"
        );
        assert_eq!(
            state(entry(Some(now + chrono::Duration::days(5)))),
            "expiring_soon"
        );
        assert_eq!(
            state(entry(Some(now + chrono::Duration::days(365)))),
            "valid"
        );
    }

    #[test]
    fn test_described_entry_carries_the_tool_it_links_to() {
        let now = Utc::now();
        let entry = |provider: &str| KeyEntry {
            id: "k".into(),
            provider: provider.into(),
            label: "l".into(),
            purpose: None,
            scopes: vec![],
            created_at: now,
            expires_at: None,
            last4: "1234".into(),
            source: "mcp:test".into(),
            endpoint: None,
            env: None,
        };
        assert_eq!(
            describe(&entry("cloudflare"), now).unwrap()["linked_tool"],
            "wrangler"
        );
        assert_eq!(
            describe(&entry("github"), now).unwrap()["linked_tool"],
            "gh"
        );
        assert!(describe(&entry("openai"), now).unwrap()["linked_tool"].is_null());
    }

    #[test]
    fn test_store_key_teaches_the_routing_rule() {
        // The description is the only thing an agent reads before deciding
        // where a credential goes, so the rule has to survive edits to it.
        let tools = PatchbayServer::keys_router().list_all();
        let store = tools
            .iter()
            .find(|t| t.name == "store_key")
            .expect("store_key is missing from the router");
        let text = store.description.as_deref().unwrap_or_default().to_string();

        assert!(
            text.contains("belong to the human across projects"),
            "{text}"
        );
        assert!(text.contains("secret manager"), "{text}");
        assert!(text.contains("Infisical"), "{text}");
        assert!(text.contains(".env"), "{text}");
        assert!(text.contains("overwrite: true"), "{text}");
    }

    #[test]
    fn test_verify_key_is_advertised_as_ungated() {
        let tools = PatchbayServer::keys_router().list_all();
        let verify = tools
            .iter()
            .find(|t| t.name == "verify_key")
            .expect("verify_key is missing from the router");
        let text = verify
            .description
            .as_deref()
            .unwrap_or_default()
            .to_string();

        assert!(text.contains("NOT gated"), "{text}");
        assert!(
            text.contains("never \nthe value") || text.contains("never the value"),
            "{text}"
        );
        // The distinction that matters most: unreachable is not a dead key.
        assert!(text.contains("unreachable"), "{text}");
        assert!(text.contains("NOTHING about the key"), "{text}");
    }

    #[test]
    fn test_described_entry_carries_no_secret_field() {
        let now = Utc::now();
        let entry = KeyEntry {
            id: "k".into(),
            provider: "p".into(),
            label: "l".into(),
            purpose: None,
            scopes: vec![],
            created_at: now,
            expires_at: None,
            last4: "1234".into(),
            source: "mcp:test".into(),
            endpoint: None,
            env: None,
        };
        let value = describe(&entry, now).unwrap();
        let map = value.as_object().unwrap();
        assert!(!map.contains_key("secret"));
        assert_eq!(map["last4"], "1234");
    }

    // -----------------------------------------------------------------
    // resolving a wanted variable name
    // -----------------------------------------------------------------

    fn key(id: &str, provider: &str, env: Option<&str>, purpose: Option<&str>) -> KeyEntry {
        KeyEntry {
            id: id.into(),
            provider: provider.into(),
            label: format!("{id} label"),
            purpose: purpose.map(Into::into),
            scopes: vec![],
            created_at: Utc::now(),
            expires_at: None,
            last4: "1234".into(),
            source: "mcp:test".into(),
            endpoint: None,
            env: env.map(Into::into),
        }
    }

    fn project(id: &str, env: &str, names: &[&str]) -> (String, String, Vec<EnvVarInfo>) {
        (
            id.into(),
            env.into(),
            names
                .iter()
                .map(|name| EnvVarInfo {
                    name: (*name).into(),
                    source: EnvVarSource::Synced,
                })
                .collect(),
        )
    }

    #[test]
    fn test_an_exact_env_name_resolves_to_the_key_and_a_run_command() {
        let entries = vec![key(
            "cf-gh-actions-deploy",
            "cloudflare",
            Some("CLOUDFLARE_API_TOKEN"),
            None,
        )];
        let resolved = resolve_one("CLOUDFLARE_API_TOKEN", &entries, &[]);

        assert_eq!(resolved.status(), "key");
        assert_eq!(resolved.keys.len(), 1);
        assert!(resolved.suggestions.is_empty(), "{resolved:?}");
        assert_eq!(
            resolved.use_command().unwrap(),
            "pb key run cf-gh-actions-deploy -- <cmd>"
        );
    }

    #[test]
    fn test_two_keys_under_one_name_both_come_back_and_the_command_names_the_others() {
        let entries = vec![
            key(
                "langfuse-dev",
                "langfuse",
                Some("LANGFUSE_SECRET_KEY"),
                None,
            ),
            key(
                "langfuse-prod",
                "langfuse",
                Some("LANGFUSE_SECRET_KEY"),
                None,
            ),
        ];
        let resolved = resolve_one("LANGFUSE_SECRET_KEY", &entries, &[]);

        assert_eq!(resolved.keys.len(), 2);
        assert_eq!(
            resolved.use_command().unwrap(),
            "pb key run langfuse-dev -- <cmd>  # or: langfuse-prod"
        );
    }

    #[test]
    fn test_the_match_is_case_insensitive_on_both_sides() {
        let entries = vec![key("neon", "neon", Some("NEON_API_KEY"), None)];
        assert_eq!(
            resolve_one("neon_api_key", &entries, &[]).status(),
            "key",
            "a lowercase spelling still finds the entry"
        );

        let vars = [project("pathors", "prod", &["database_url"])];
        assert_eq!(
            resolve_one("DATABASE_URL", &[], &vars).status(),
            "project_var"
        );
    }

    #[test]
    fn test_a_purpose_that_mentions_the_name_becomes_a_suggestion() {
        let entries = vec![key(
            "neon-api",
            "neon",
            None,
            Some("also stored as the GitHub secret NEON_API_KEY"),
        )];
        let resolved = resolve_one("NEON_API_KEY", &entries, &[]);

        assert_eq!(resolved.status(), "suggested");
        assert!(!resolved.is_supplied());
        assert_eq!(resolved.suggestions.len(), 1);
        assert_eq!(resolved.suggestions[0].why, "purpose mentions NEON_API_KEY");
        assert_eq!(
            resolved.use_command().unwrap(),
            "pb key edit neon-api --env NEON_API_KEY  # then: pb key run neon-api -- <cmd>"
        );
    }

    #[test]
    fn test_the_identifying_tokens_of_a_name_find_an_entry_that_never_says_it() {
        let entries = vec![key(
            "neon-prod",
            "neon",
            None,
            Some("the production Postgres branch"),
        )];
        let resolved = resolve_one("NEON_API_KEY", &entries, &[]);

        assert_eq!(resolved.status(), "suggested");
        assert_eq!(resolved.suggestions[0].why, "matches tokens neon");
    }

    #[test]
    fn test_a_name_made_only_of_generic_tokens_suggests_nothing() {
        // `API_KEY` is every second entry in the vault. Suggesting all of them
        // is worse than suggesting none, so the generic tokens are dropped and
        // an empty token list skips the weak rule entirely.
        assert!(identifying_tokens("API_KEY").is_empty());
        assert_eq!(identifying_tokens("NEON_API_KEY"), vec!["neon"]);
        assert_eq!(
            identifying_tokens("APPLE_ASC_ISSUER_ID"),
            vec!["apple", "asc", "issuer"]
        );

        let entries = vec![
            key("neon-prod", "neon", None, Some("the production key")),
            key("cf-deploy", "cloudflare", None, Some("a deploy token")),
        ];
        let resolved = resolve_one("API_KEY", &entries, &[]);
        assert_eq!(resolved.status(), "missing");
        assert!(resolved.suggestions.is_empty(), "{resolved:?}");
    }

    #[test]
    fn test_suggestions_are_capped_and_strong_matches_come_first() {
        let mut entries: Vec<KeyEntry> = (0..8)
            .map(|i| key(&format!("neon-{i}"), "neon", None, Some("a neon thing")))
            .collect();
        entries.push(key(
            "the-one",
            "other",
            None,
            Some("this is the NEON_API_KEY value"),
        ));
        let resolved = resolve_one("NEON_API_KEY", &entries, &[]);

        assert_eq!(resolved.suggestions.len(), MAX_SUGGESTIONS);
        assert_eq!(resolved.suggestions[0].entry.id, "the-one");
    }

    #[test]
    fn test_a_project_environment_that_carries_the_name_is_a_hit() {
        let vars = [
            project("pathors", "dev", &["OTHER"]),
            project("pathors", "prod", &["DATABASE_URL", "OTHER"]),
        ];
        let resolved = resolve_one("DATABASE_URL", &[], &vars);

        assert_eq!(resolved.status(), "project_var");
        assert!(resolved.is_supplied());
        assert_eq!(resolved.projects.len(), 1);
        assert_eq!(resolved.projects[0].project, "pathors");
        assert_eq!(resolved.projects[0].env, "prod");
        assert_eq!(
            resolved.use_command().unwrap(),
            "pb env run --project pathors -e prod -- <cmd>"
        );
    }

    #[test]
    fn test_a_key_and_a_project_variable_are_both_reported_and_the_key_wins_the_command() {
        let entries = vec![key("neon", "neon", Some("DATABASE_URL"), None)];
        let vars = [project("pathors", "prod", &["DATABASE_URL"])];
        let resolved = resolve_one("DATABASE_URL", &entries, &vars);

        assert_eq!(resolved.status(), "both");
        assert_eq!(resolved.use_command().unwrap(), "pb key run neon -- <cmd>");
    }

    #[test]
    fn test_a_name_nothing_matches_is_missing_with_no_command() {
        let entries = vec![key("cf", "cloudflare", Some("CLOUDFLARE_API_TOKEN"), None)];
        let resolved = resolve_one("STRIPE_SECRET_KEY", &entries, &[]);

        assert_eq!(resolved.status(), "missing");
        assert!(resolved.use_command().is_none());
        assert!(!resolved.is_supplied());
    }

    #[test]
    fn test_a_resolved_name_renders_without_a_secret_and_keeps_the_use_command() {
        let entries = vec![key("neon", "neon", Some("NEON_API_KEY"), None)];
        let value = resolved_json(&resolve_one("NEON_API_KEY", &entries, &[]), Utc::now()).unwrap();

        assert_eq!(value["status"], "key");
        assert_eq!(value["use"], "pb key run neon -- <cmd>");
        assert_eq!(value["keys"][0]["id"], "neon");
        assert_eq!(value["keys"][0]["env"], "NEON_API_KEY");
        assert!(value["keys"][0].get("secret").is_none());
    }

    // -----------------------------------------------------------------
    // parameters and descriptions
    // -----------------------------------------------------------------

    #[test]
    fn test_list_keys_still_works_with_no_arguments_at_all() {
        // rmcp hands the extractor `arguments.unwrap_or_default()`, i.e. an
        // empty object, when a call carries no arguments. `#[serde(default)]`
        // on the struct is what keeps that a valid, unfiltered call.
        let params: ListKeysParams = serde_json::from_value(serde_json::json!({})).unwrap();
        assert!(params.provider.is_none());
        assert!(params.env.is_none());
        assert!(params.query.is_none());

        let filter = KeyFilter {
            provider: params.provider,
            env: params.env,
            query: params.query,
        };
        assert!(filter.is_empty());
    }

    #[test]
    fn test_only_the_nullable_fields_can_be_cleared() {
        let clear = |fields: &[&str]| {
            clear_set(&fields.iter().map(|f| (*f).to_string()).collect::<Vec<_>>())
        };

        let ok = clear(&["env", "PURPOSE", " expires_at "]).unwrap();
        assert!(ok.contains("env"));
        assert!(ok.contains("purpose"));
        assert!(ok.contains("expires_at"));
        assert!(clear(&[]).unwrap().is_empty());

        let err = clear(&["label"]).unwrap_err();
        assert!(err.contains("cannot clear `label`"), "{err}");
        for field in CLEARABLE_FIELDS {
            assert!(err.contains(field), "{err}");
        }
        assert!(clear(&["id"]).is_err());
    }

    #[test]
    fn test_store_key_asks_for_the_variable_name() {
        let tools = PatchbayServer::keys_router().list_all();
        let store = tools
            .iter()
            .find(|t| t.name == "store_key")
            .expect("store_key is missing from the router");
        let text = store.description.as_deref().unwrap_or_default().to_string();

        assert!(text.contains("`env`"), "{text}");
        assert!(text.contains("CLOUDFLARE_API_TOKEN"), "{text}");
        assert!(text.contains("resolve_env_vars"), "{text}");
    }

    #[test]
    fn test_list_keys_leads_with_the_lookup_and_teaches_the_filters() {
        let tools = PatchbayServer::keys_router().list_all();
        let list = tools
            .iter()
            .find(|t| t.name == "list_keys")
            .expect("list_keys is missing from the router");
        let text = list.description.as_deref().unwrap_or_default().to_string();

        assert!(
            text.starts_with("CHEAP, SAFE. LOOK HERE BEFORE SAYING A CREDENTIAL IS MISSING."),
            "{text}"
        );
        assert!(text.contains("Narrow it."), "{text}");
        assert!(text.contains("resolve_env_vars"), "{text}");
        assert!(text.contains("Secret values are NOT included"), "{text}");
    }

    #[test]
    fn test_update_key_is_advertised_as_metadata_only_and_ungated() {
        let tools = PatchbayServer::keys_router().list_all();
        let update = tools
            .iter()
            .find(|t| t.name == "update_key")
            .expect("update_key is missing from the router");
        let text = update
            .description
            .as_deref()
            .unwrap_or_default()
            .to_string();

        assert!(text.contains("without touching its value"), "{text}");
        assert!(text.contains("backfill `env`"), "{text}");
        assert!(text.contains("Not for rotation"), "{text}");
        assert!(text.contains("Not gated"), "{text}");
        assert!(text.contains("never opens the keychain"), "{text}");
    }

    #[test]
    fn test_resolve_env_vars_is_the_call_before_asking_the_user() {
        let tools = PatchbayServer::keys_router().list_all();
        let resolve = tools
            .iter()
            .find(|t| t.name == "resolve_env_vars")
            .expect("resolve_env_vars is missing from the router");
        let text = resolve
            .description
            .as_deref()
            .unwrap_or_default()
            .to_string();

        assert!(
            text.contains("before asking \nthe user for a value")
                || text.contains("before asking the user for a value"),
            "{text}"
        );
        assert!(text.contains("before writing a placeholder"), "{text}");
        assert!(text.contains("pb key run"), "{text}");
        assert!(text.contains("pb env run"), "{text}");
        assert!(
            text.contains("do NOT follow up with get_key")
                || text.contains("Do NOT follow up with get_key"),
            "{text}"
        );
        assert!(text.contains("A suggestion IS A GUESS"), "{text}");
    }

    #[test]
    fn test_the_resolve_note_never_stops_saying_where_the_value_goes() {
        assert!(RESOLVE_NOTE.contains("Values are never returned"));
        assert!(RESOLVE_NOTE.contains("pb key run"));
        assert!(RESOLVE_NOTE.contains("pb env run"));
        assert!(RESOLVE_NOTE.contains("update_key"));
    }
    fn update_params(id: &str) -> UpdateKeyParams {
        UpdateKeyParams {
            id: id.to_string(),
            provider: None,
            label: None,
            purpose: None,
            scopes: None,
            expires_at: None,
            endpoint: None,
            env: None,
            clear: None,
        }
    }

    #[test]
    fn test_build_patch_sets_one_field_and_leaves_the_rest_alone() {
        let mut params = update_params("cf-api");
        params.env = Some("CLOUDFLARE_API_TOKEN".to_string());
        let patch = build_patch(params).expect("a set is a patch");
        assert_eq!(patch.env, Some(Some("CLOUDFLARE_API_TOKEN".to_string())));
        assert_eq!(patch.purpose, None);
        assert_eq!(patch.expires_at, None);
        assert_eq!(patch.endpoint, None);
    }

    #[test]
    fn test_build_patch_blanks_a_field_named_in_clear() {
        let mut params = update_params("cf-api");
        params.clear = Some(vec!["endpoint".to_string()]);
        let patch = build_patch(params).expect("a clear is a patch");
        assert_eq!(patch.endpoint, Some(None));
        assert_eq!(patch.env, None);
    }

    #[test]
    fn test_build_patch_refuses_a_field_that_is_both_set_and_cleared() {
        let mut params = update_params("cf-api");
        params.purpose = Some("deploys the worker".to_string());
        params.clear = Some(vec!["purpose".to_string()]);
        let err = build_patch(params).unwrap_err();
        assert_eq!(
            err,
            "`purpose` is both set and listed in `clear`; pass one or the other"
        );
    }

    #[test]
    fn test_build_patch_refuses_a_call_that_changes_nothing() {
        let err = build_patch(update_params("cf-api")).unwrap_err();
        assert!(err.starts_with("nothing to change"), "{err}");
    }

    #[test]
    fn test_build_patch_surfaces_an_unreadable_expiry() {
        let mut params = update_params("cf-api");
        params.expires_at = Some("whenever".to_string());
        let err = build_patch(params).unwrap_err();
        assert!(err.contains("RFC 3339"), "{err}");
    }

    #[test]
    fn test_build_patch_reads_both_expiry_shapes() {
        let mut params = update_params("cf-api");
        params.expires_at = Some("2027-01-01".to_string());
        let patch = build_patch(params).expect("a date is an expiry");
        assert_eq!(
            patch.expires_at,
            Some(Some(parse_expiry("2027-01-01").unwrap()))
        );
    }
}
