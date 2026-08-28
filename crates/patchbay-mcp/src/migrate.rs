//! The AI-guided half of a machine move.
//!
//! Copying files is the easy half and needs no agent. The hard half is the
//! twenty minutes of "log in to this, switch that, re-create this token" that
//! nobody enjoys and everybody half-finishes — which is exactly the shape of
//! work an agent is good at, provided it cannot lie to itself about progress.
//!
//! So there are two tools and no more:
//!
//! * `plan_setup` — the list, re-derived from the machine every call.
//! * `mark_setup_done` — re-probes one item and says whether it actually
//!   closed. It ignores what the caller claims; the probe decides.
//!
//! There is a third, of a different kind: `write_manifest` writes the
//! secret-free inventory this machine could hand to a new one. It is safe for
//! an agent because it is the one part of a move that touches no credential —
//! `pb export` and `pb import` do, and want a passphrase typed by a human, so
//! they stay in the CLI where the human is.

#[cfg(test)]
use std::path::Path;
use std::path::PathBuf;

use patchbay_core::migrate::{self, Exporter, Manifest, SetupItem, SetupStatus};
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::CallToolResult;
use rmcp::{tool, tool_router, ErrorData};
use schemars::JsonSchema;
use serde::Deserialize;

use crate::server::{encode, json_ok, offload, tool_error, PatchbayServer};

#[derive(Debug, Deserialize, JsonSchema)]
pub struct PlanParams {
    /// Path to a `manifest.json` exported from the OLD machine, if you have
    /// one. With it, the plan is "what the other machine had that this one does
    /// not". Without it, the plan is "what on this machine is not logged in",
    /// which is still useful — omit it rather than guessing at a path.
    pub manifest_path: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct WriteManifestParams {
    /// Where to write the file. A path the user named, or somewhere they will
    /// find it again — a repository they sync, not a temp directory.
    pub path: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct MarkDoneParams {
    /// The `id` of the item, exactly as `plan_setup` returned it — for example
    /// "tool:gh", "install:kubectl", "switch:gcloud", "key:cf-api",
    /// "env:pathors".
    pub item_id: String,
    /// Path to the same `manifest.json` you passed to `plan_setup`, if any.
    /// Leaving it out when the plan used one will report the item as unknown.
    pub manifest_path: Option<String>,
}

/// Load a manifest named by an agent.
///
/// The path comes from a model, so it is checked and reported rather than
/// trusted: a typo has to come back as "no such file", not as an empty plan
/// that reads like "nothing left to do".
fn load_manifest(path: Option<&str>) -> anyhow::Result<Option<Manifest>> {
    let Some(path) = path.map(PathBuf::from) else {
        return Ok(None);
    };
    if !path.is_file() {
        anyhow::bail!(
            "no manifest at {}. Pass the path to the `manifest.json` from the old machine, or \
             omit manifest_path entirely to plan against this machine alone.",
            path.display()
        );
    }
    let text = std::fs::read_to_string(&path)
        .map_err(|e| anyhow::anyhow!("could not read {}: {e}", path.display()))?;
    Manifest::from_json(&text).map(Some)
}

/// Plan items plus the counts an agent needs to decide whether it is finished.
fn plan_json(items: &[SetupItem]) -> Result<serde_json::Value, ErrorData> {
    let open = items.iter().filter(|i| i.is_open()).count();
    let blocked = items
        .iter()
        .filter(|i| i.status == SetupStatus::Unknown)
        .count();
    Ok(serde_json::json!({
        "open": open,
        "done": items.len() - open - blocked,
        "blocked": blocked,
        "complete": open == 0,
        "items": encode(&items)?,
    }))
}

#[tool_router(router = migrate_router, vis = "pub(crate)")]
impl PatchbayServer {
    #[tool(description = "\
TIER 1, CHEAP. The remaining work to finish setting this machine up — one item per thing that is \
not true here yet, each with the exact command that fixes it. Re-probes every tool on every call, \
so it is always current and safe to call repeatedly.

Use it after `pb import` has restored what could be copied, or any time the user says they are on \
a new machine, or asks what is left to set up.

HOW TO WORK THE LIST — this matters more than the schema:

1. One item at a time, in the order returned. Do not batch, and do not run four logins at once: \
each one changes machine-global state, and a failure in the middle of a batch is unattributable.
2. If `auto` is true, patchbay can close it itself — run the `command`. These are profile \
switches and re-registrations, not logins.
3. If `needs_browser` is true, STOP and hand the exact `command` to the human. Do not run it \
yourself and do not try to drive the browser: an OAuth flow started in a subshell you cannot see \
usually hangs, and you will report success for a login that never happened.
4. After each item, call `mark_setup_done` with its `id`. That re-probes the tool and tells you \
whether the gap actually closed. Never mark something done because you ran the command — the \
probe decides, not you.
5. Stop when `complete` is true. Do not invent extra setup work.

Returns { open, done, blocked, complete, items: [ { id, tool, what, auto, command, \
needs_browser, status, detail } ] }.

- `status` is 'open' (still to do), 'done' (verified true here) or 'unknown' (cannot be checked \
yet — normally because the CLI is not installed, so its own install item comes first).
- `detail` explains WHY something could not travel — the OAuth token being in the OS keychain, \
a node key that identifies the old device. Relay it; it is the difference between the user \
thinking patchbay failed and understanding that no tool could have done better.
- Every item is metadata. No secret value is ever returned by this tool, including for items \
about the key vault.")]
    async fn plan_setup(
        &self,
        Parameters(PlanParams { manifest_path }): Parameters<PlanParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let manifest = match load_manifest(manifest_path.as_deref()) {
            Ok(manifest) => manifest,
            Err(err) => return Ok(tool_error(err)),
        };
        let registry = self.registry.clone();
        let keys = self.keys.clone();
        let clients = self.clients.clone();
        let envs = self.envs.clone();
        let items = offload(move || {
            migrate::plan(
                registry.paths(),
                &registry,
                &keys,
                &clients,
                &envs,
                manifest.as_ref(),
            )
        })
        .await?;
        Ok(json_ok(plan_json(&items)?))
    }

    #[tool(description = "\
TIER 1, CHEAP. Write this machine's inventory — the record of which CLIs it uses, which profiles \
and accounts are active, which API keys are in the vault and which MCP servers are registered — \
to a `manifest.json` the user can commit, sync or carry to a new machine.

NO SECRET VALUE IS IN THIS FILE, by construction and by test. No credential file is even opened. \
It carries names, accounts, scopes, expiry dates and the NAMES of the environment variables an \
MCP server sets — never a value. That is what makes it the one part of a machine move an agent \
can do unsupervised, and what makes the file safe to put in a repository.

Use it when the user wants a record of what they have set up, wants their setup reproducible on \
another machine, or is about to move machines and does not want to move credentials.

It is NOT a backup and it will not log anybody in. On the new machine the file is the INPUT to \
`plan_setup(manifest_path)`, which turns it into the checklist: install this, log into that. To \
actually carry credentials the user runs `pb export` themselves — that needs a passphrase and \
belongs to them, not to you.

One caveat worth relaying: a key's `purpose` note is free text written by whoever registered it, \
and it travels verbatim. If someone has pasted a secret into a purpose, it will be in this file. \
Nothing patchbay stores as a secret is.

Returns { path, tools, keys, mcp, env_projects, gaps } — counts, not contents.")]
    async fn write_manifest(
        &self,
        Parameters(WriteManifestParams { path }): Parameters<WriteManifestParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let registry = self.registry.clone();
        let keys = self.keys.clone();
        let clients = self.clients.clone();
        let envs = self.envs.clone();
        let target = PathBuf::from(&path);
        let written = offload(move || {
            let manifest = Exporter {
                paths: registry.paths(),
                registry: &registry,
                vault: &keys,
                clients: &clients,
                envs: &envs,
            }
            .manifest(chrono::Utc::now())?;
            std::fs::write(&target, format!("{}\n", manifest.to_json()))
                .map_err(|e| anyhow::anyhow!("could not write {}: {e}", target.display()))?;
            Ok::<_, anyhow::Error>(manifest)
        })
        .await?;
        // The write is the fallible half; a failed write must come back as a
        // tool error the agent can read, not as a transport-level failure.
        let written = match written {
            Ok(manifest) => manifest,
            Err(err) => return Ok(tool_error(err)),
        };

        Ok(json_ok(serde_json::json!({
            "path": path,
            "tools": written.tools.iter().filter(|t| t.installed).count(),
            "keys": written.keys.len(),
            "mcp": written.mcp.len(),
            "env_projects": written.env_projects.len(),
            "gaps": written.gaps.len(),
        })))
    }

    #[tool(description = "\
TIER 1, CHEAP. Re-check ONE item from `plan_setup` and report whether the gap really closed. \
patchbay re-reads that tool's own state files; it does not take your word for it, and it does not \
take the user's.

Call it immediately after each item you (or the human) acted on. If it comes back still open, the \
thing did not work — say so plainly and try the next approach, rather than moving on and leaving \
the user to discover it later.

`item_id` is the `id` from `plan_setup`, verbatim. Pass the same `manifest_path` you planned \
with, or the item will not be found.

Returns { item_id, closed, item: { …the re-derived item… } }, or `found: false` when no item \
with that id is in the current plan. `found: false` after you acted is usually good news — it \
means the whole reason for the item is gone — but check `plan_setup` rather than assuming.

A browser login you handed to the human will keep coming back open until they actually finish it. \
That is the tool working, not a bug: wait for them, then re-check.")]
    async fn mark_setup_done(
        &self,
        Parameters(MarkDoneParams {
            item_id,
            manifest_path,
        }): Parameters<MarkDoneParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let manifest = match load_manifest(manifest_path.as_deref()) {
            Ok(manifest) => manifest,
            Err(err) => return Ok(tool_error(err)),
        };
        let registry = self.registry.clone();
        let keys = self.keys.clone();
        let clients = self.clients.clone();
        let envs = self.envs.clone();
        let id = item_id.clone();
        let found = offload(move || {
            migrate::recheck(
                registry.paths(),
                &registry,
                &keys,
                &clients,
                &envs,
                manifest.as_ref(),
                &id,
            )
        })
        .await?;

        Ok(json_ok(match found {
            Some(item) => serde_json::json!({
                "item_id": item_id,
                "found": true,
                "closed": item.status == SetupStatus::Done,
                "item": encode(&item)?,
            }),
            None => serde_json::json!({
                "item_id": item_id,
                "found": false,
                "closed": false,
                "hint": "no item with that id is in the current plan; call plan_setup again to \
                         see what is left (and check you passed the same manifest_path)",
            }),
        }))
    }
}

/// Kept out of the tool bodies so the path handling can be tested without an
/// MCP client.
#[cfg(test)]
fn manifest_error(path: &Path) -> String {
    load_manifest(Some(&path.display().to_string()))
        .map(|_| String::new())
        .unwrap_or_else(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_a_missing_manifest_is_a_clear_error_not_an_empty_plan() {
        let message = manifest_error(Path::new("/nope/manifest.json"));
        assert!(message.contains("no manifest at"), "{message}");
        assert!(message.contains("omit manifest_path"), "{message}");
    }

    #[test]
    fn test_no_manifest_path_is_a_legitimate_plan() {
        assert!(load_manifest(None).unwrap().is_none());
    }

    #[test]
    fn test_a_manifest_from_the_future_is_refused_by_path_too() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("manifest.json");
        std::fs::write(&path, r#"{"version":99,"created_at":"2026-08-13T00:00:00Z","source":{"patchbay_version":"9","os":"macos"},"tools":[]}"#).unwrap();
        let message = manifest_error(&path);
        assert!(message.contains("newer patchbay"), "{message}");
    }

    #[test]
    fn test_plan_json_counts_the_three_states() {
        let items = vec![
            SetupItem::new("a", "gh", "x").status(SetupStatus::Open),
            SetupItem::new("b", "gh", "y").status(SetupStatus::Done),
            SetupItem::new("c", "gh", "z").status(SetupStatus::Unknown),
        ];
        let json = plan_json(&items).unwrap();
        assert_eq!(json["open"], 1);
        assert_eq!(json["done"], 1);
        assert_eq!(json["blocked"], 1);
        assert_eq!(json["complete"], false);

        let json = plan_json(&[SetupItem::new("b", "gh", "y").status(SetupStatus::Done)]).unwrap();
        assert_eq!(json["complete"], true);
    }
}
