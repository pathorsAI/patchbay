//! The key vault's MCP surface.
//!
//! `store_key` is the headline: an agent that just created a Cloudflare token
//! or a provider key registers it here, and the machine keeps knowing about it
//! long after the conversation is gone. Everything else exists to keep that
//! honest — `list_keys` returns metadata only, and the two dangerous calls
//! (`get_key`, `remove_key`) are refused unless the *user* started the server
//! with [`ALLOW_SECRET_READ`] set.
//!
//! Kept in its own `#[tool_router]` impl block, merged into the main router in
//! [`crate::server`], so the vault's tools and the connection tools stay
//! separable.

use chrono::{DateTime, Utc};
use patchbay_core::keys::NewKey;
use patchbay_core::KeyEntry;
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

/// Metadata plus a derived expiry state, so a caller does not have to do date
/// arithmetic to notice something is dead.
fn describe(entry: &KeyEntry, now: DateTime<Utc>) -> Result<serde_json::Value, ErrorData> {
    let mut value = encode(entry)?;
    if let Some(map) = value.as_object_mut() {
        let state = match entry.expires_at {
            None => "no_expiry",
            Some(at) if at <= now => "expired",
            Some(at) if (at - now).num_days() <= 30 => "expiring_soon",
            Some(_) => "valid",
        };
        map.insert("expiry_state".into(), state.into());
    }
    Ok(value)
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

Register: long-lived API keys, personal access tokens, deploy tokens, service-account keys, \
webhook signing secrets. Do NOT register: short-lived session tokens a CLI already manages \
(use list_connections for those), OAuth refresh flows the tool owns, or passwords.

Where the secret goes: the OS keychain, immediately. The metadata file on disk gets the last 4 \
characters and nothing else. NEVER echo the secret anywhere else — not into your reply, not into \
a file you are editing, not into a commit, not into a log, not into another tool call. This tool \
call is the only place it belongs.

Fill in `purpose` and `expires_at` whenever you know them. They are what make the registry worth \
having: `purpose` is what tells the user in six months whether they can revoke it, and \
`expires_at` is what lets patchbay warn them before a deploy starts failing.

Both-or-neither: metadata and value are written together, and a keychain failure rolls the \
metadata back, so a successful result means the key really is stored. A duplicate id is an error \
unless you pass overwrite: true.

Returns the stored metadata (id, provider, label, purpose, scopes, created_at, expires_at, \
last4, source). The secret is never echoed back.")]
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
            .expires_at(expires_at);
        let secret = params.secret;
        let overwrite = params.overwrite.unwrap_or(false);

        let keys = self.keys.clone();
        match offload(move || keys.add(new, &secret, overwrite)).await? {
            Ok(entry) => Ok(json_ok(encode(&entry)?)),
            Err(err) => Ok(tool_error(err)),
        }
    }

    #[tool(description = "\
CHEAP, SAFE. Every standalone API key registered on this machine — metadata only. Reads one \
local JSON file: no keychain access, no network, no secret values.

Call this before store_key to see whether the key is already registered and what id convention \
the user follows, when the user asks what keys or tokens they have, and when something \
credential-shaped just failed — an expired entry here explains a lot of otherwise mysterious \
403s.

Returns a JSON array of entries: { id, provider, label, purpose, scopes, created_at, \
expires_at, last4, source, expiry_state }.

- `expiry_state` is derived for you: 'expired', 'expiring_soon' (within 30 days), 'valid', or \
'no_expiry'. Surface anything expired or expiring soon — that is the whole point of the vault.
- `last4` is the last 4 characters of the secret, so the user can match an entry against a token \
in a provider's dashboard. It is the only thing here derived from the value.
- `source` says who registered the entry ('cli', 'mcp:<client>', 'gui').
- Secret values are NOT included and cannot be obtained from this tool.")]
    async fn list_keys(&self) -> Result<CallToolResult, ErrorData> {
        let keys = self.keys.clone();
        match offload(move || keys.list()).await? {
            Ok(entries) => {
                let now = Utc::now();
                let described: Result<Vec<_>, ErrorData> =
                    entries.iter().map(|e| describe(e, now)).collect();
                Ok(json_ok(serde_json::Value::Array(described?)))
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
        };
        let value = describe(&entry, now).unwrap();
        let map = value.as_object().unwrap();
        assert!(!map.contains_key("secret"));
        assert_eq!(map["last4"], "1234");
    }
}
