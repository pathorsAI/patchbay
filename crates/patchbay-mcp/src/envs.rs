//! The project env vault's MCP surface.
//!
//! [`crate::keys`] exposes the credentials that belong to the *human*. This
//! module exposes the other half: the environment variables one *directory*
//! needs, per environment, in two layers — `synced` (a local mirror of the
//! project's remote, refreshed wholesale by `pull_env`) and `local` (set on
//! this machine, never pushed, and it wins on merge).
//!
//! **There is deliberately no read tool.** Nothing here returns a variable's
//! value: not gated behind [`crate::keys::ALLOW_SECRET_READ`], not gated behind
//! anything — the tool simply does not exist in v1. An agent that needs the
//! values is asking for the wrong thing; the human paths are `pb env run --
//! <cmd>` and `pb env export` in a terminal, where the values never pass
//! through a model's context at all. Everything here is therefore metadata
//! (names, counts, provenance) or a one-way write.
//!
//! Kept in its own `#[tool_router]` impl block, merged into the main router in
//! [`crate::server`], the same way the key vault's tools are.

use std::collections::BTreeSet;

use patchbay_core::env_sync;
use patchbay_core::envs::ProjectEntry;
use patchbay_core::{EnvRegistry, Paths};
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::CallToolResult;
use rmcp::{tool, tool_router, ErrorData};
use schemars::JsonSchema;
use serde::Deserialize;

use crate::server::{encode, json_ok, offload, tool_error, PatchbayServer};

// ---------------------------------------------------------------------------
// parameters
// ---------------------------------------------------------------------------

/// `{ "project": "pathors", "env": "staging" }` — one project, optionally one
/// of its environments.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct EnvSelectorParams {
    /// The project's id, exactly as `list_env_projects` reports it (a lowercase
    /// slug like "pathors"). This is patchbay's own name for the directory, not
    /// a path and not the remote's project id — look it up rather than guessing
    /// from the repo name.
    pub project: String,
    /// Which environment: "dev", "staging", "production". Omit it to use the
    /// project's `default_env`, which is what a user who did not say means.
    /// Only name one when the user did, or when the task is unambiguously about
    /// another environment — reading or writing the wrong environment is the
    /// mistake this field exists to make visible.
    pub env: Option<String>,
}

/// `{ "project": "pathors", "name": "STRIPE_KEY", "value": "sk_live_…" }`.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct SetEnvVarParams {
    /// The project's id, as `list_env_projects` reports it.
    pub project: String,
    /// Which environment to write to. Omit it for the project's `default_env`.
    /// A credential you created for staging must not land in production
    /// because the field was left off — if the user named an environment, name
    /// it here.
    pub env: Option<String>,
    /// The variable's name, as a POSIX shell would export it:
    /// `[A-Za-z_][A-Za-z0-9_]*`. Use the name the code already reads
    /// (`DATABASE_URL`, `STRIPE_SECRET_KEY`), not a description of it.
    pub name: String,
    /// The value. It goes straight into the OS keychain, is never written to
    /// the metadata file, and is never echoed back by this or any other tool.
    /// Send it here and NOWHERE else — not into a `.env` file you are editing,
    /// not into your reply, not into a commit, not into a log.
    pub value: String,
}

// ---------------------------------------------------------------------------
// shaping
// ---------------------------------------------------------------------------

/// The environment a call means: the one it named, or the project's default.
///
/// An empty or whitespace-only `env` is treated as absent rather than as an
/// invalid name — a client that fills optional strings with `""` should get the
/// default, not a validation error about a name nobody typed.
fn resolve_env(project: &ProjectEntry, requested: Option<&str>) -> String {
    match requested.map(str::trim) {
        Some(env) if !env.is_empty() => env.to_string(),
        _ => project.default_env.clone(),
    }
}

/// The error for a project id nothing is registered under. Names the tool that
/// lists the real ids, so the caller can self-correct without a round trip
/// through the user.
fn unknown_project(id: &str) -> anyhow::Error {
    anyhow::anyhow!(
        "no project registered as `{id}`; `list_env_projects` shows the ids that exist, and \
         `pb env init --id {id}` registers a new directory in a terminal"
    )
}

fn require(envs: &EnvRegistry, id: &str) -> anyhow::Result<ProjectEntry> {
    envs.get(id)?.ok_or_else(|| unknown_project(id))
}

/// One project as the tools report it: registration, environments with counts,
/// and the sync config. **Metadata only** — this cannot carry a value, because
/// [`ProjectEntry`] does not hold one.
fn describe_project(project: &ProjectEntry) -> Result<serde_json::Value, ErrorData> {
    let mut environments = Vec::with_capacity(project.environments.len());
    for (name, meta) in &project.environments {
        // The merged view is a union, not a sum: a local override shares its
        // name with the synced variable it shadows.
        let distinct: BTreeSet<&String> = meta
            .synced_names
            .iter()
            .chain(meta.local_names.iter())
            .collect();
        environments.push(serde_json::json!({
            "name": name,
            "var_count": distinct.len(),
            "synced_count": meta.synced_names.len(),
            "local_count": meta.local_names.len(),
            "synced_at": encode(&meta.synced_at)?,
        }));
    }

    Ok(serde_json::json!({
        "id": project.id,
        // `display()` rather than serializing the PathBuf: a path that is not
        // valid UTF-8 would fail to serialize, and a lossy path is a far better
        // answer here than a failed tool call.
        "root": project.root.display().to_string(),
        "default_env": project.default_env,
        "created_at": encode(&project.created_at)?,
        "environments": environments,
        "sync": match &project.sync {
            Some(sync) => encode(sync)?,
            None => serde_json::Value::Null,
        },
    }))
}

/// What `set_env_var` reports back. Built here, and tested here, because the
/// one thing it must never contain is the value it just stored.
fn stored_summary(project: &str, env: &str, name: &str, shadows_synced: bool) -> serde_json::Value {
    let note = if shadows_synced {
        format!(
            "`{name}` also exists in the synced layer of `{project}/{env}`; the local value now \
             shadows it, and will keep shadowing it after every future pull_env"
        )
    } else {
        format!("`{name}` is set only in the local layer of `{project}/{env}`")
    };
    serde_json::json!({
        "project": project,
        "env": env,
        "name": name,
        "layer": "local",
        "shadows_synced": shadows_synced,
        "note": note,
    })
}

// ---------------------------------------------------------------------------
// tools
// ---------------------------------------------------------------------------

#[tool_router(router = envs_router, vis = "pub(crate)")]
impl PatchbayServer {
    #[tool(description = "\
CHEAP, SAFE. Every project directory registered in this machine's env vault — metadata only. \
Reads one local JSON file: no keychain access, no network, no variable values.

The env vault is a different thing from the key vault. A key belongs to the HUMAN across \
projects; these are the environment variables ONE directory needs before it will boot — the \
contents of what would otherwise be an undocumented `.env`. Each environment has two layers: \
`synced` (mirrored from the project's remote secret manager by pull_env, replaced wholesale by \
the next pull) and `local` (set on this machine by set_env_var, never pushed anywhere, and it \
WINS over a synced variable of the same name).

Call this first when the user mentions their project's env, when you are about to set a variable \
and need the project id and the environment names, or when you want to know whether a directory \
is registered at all.

Returns a JSON array of projects: { id, root, default_env, created_at, environments[], sync }.

- `id` is patchbay's slug for the directory and the value every other env tool takes as \
`project`. `root` is the directory it means.
- `default_env` is the environment used when a call omits `env`. Do not assume it is 'dev'.
- `environments[]` is { name, var_count, synced_count, local_count, synced_at }. `var_count` is \
the distinct names a consumer would see (a local override shares its name with the synced \
variable it shadows, so the counts do not simply add up). `synced_at: null` means this \
environment has NEVER been pulled — it exists on local values alone, which is normal, not broken.
- `sync` is the remote this project pulls from — { provider, project_id, account, domain, \
env_map } — or null when the project has never been linked. `account` is the login a pull must \
run as; `env_map` is patchbay's environment name -> the remote's own slug, for remotes that call \
`production` something else. A null `sync` is why a pull_env would fail, and the fix is \
`pb env link` in a terminal.
- Variable NAMES are not listed here; use list_env_vars for one environment. Variable VALUES are \
not returned by this or any other tool.")]
    async fn list_env_projects(&self) -> Result<CallToolResult, ErrorData> {
        let envs = self.envs.clone();
        match offload(move || envs.projects()).await? {
            Ok(projects) => {
                let described: Result<Vec<_>, ErrorData> =
                    projects.iter().map(describe_project).collect();
                Ok(json_ok(serde_json::Value::Array(described?)))
            }
            Err(err) => Ok(tool_error(err)),
        }
    }

    #[tool(description = "\
CHEAP, SAFE. Which variables one environment of one project holds, and where each one comes \
from. Metadata only: this reads the registry file and NEVER touches the keychain, so it costs \
milliseconds and cannot leak a value.

Use it to answer 'is DATABASE_URL set for staging?', to check whether a variable you are about \
to write already exists, and to explain a misconfiguration — a variable an agent expects to be \
synced but which is actually a stale local override is a very common cause of 'it works on the \
remote but not here'.

Omit `env` to get the project's default environment. Returns { project, env, default_env, count, \
vars: [{ name, source }] }, sorted by name.

`source` is derived from the two name lists, and is the field worth reading:

- 'synced' — pulled from the remote, not overridden here. The next pull_env can change or remove \
it.
- 'local' — set on this machine only. It is not on the remote, and patchbay will never push it \
there; if a teammate needs it, they must add it to the remote themselves.
- 'local_override' — present in BOTH layers, and the LOCAL value is the one in effect. Pulling \
does not change that. If the user is puzzled that a freshly pulled value is not taking effect, \
this is almost always the reason — say so, and note that clearing it is `pb env unset` in a \
terminal.

VALUES ARE NOT RETURNED, and no tool returns them: there is no env read or export tool at all, \
gated or otherwise. If the user needs the values, the answer is `pb env run -- <cmd>` (runs a \
command with the merged environment) or `pb env export` in their terminal.")]
    async fn list_env_vars(
        &self,
        Parameters(EnvSelectorParams { project, env }): Parameters<EnvSelectorParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let envs = self.envs.clone();
        let listed = offload(move || {
            let entry = require(&envs, &project)?;
            let env = resolve_env(&entry, env.as_deref());
            let vars = envs.list(&entry.id, &env)?;
            Ok::<_, anyhow::Error>((entry, env, vars))
        })
        .await?;

        match listed {
            Ok((entry, env, vars)) => Ok(json_ok(serde_json::json!({
                "project": entry.id,
                "env": env,
                "default_env": entry.default_env,
                "count": vars.len(),
                "vars": encode(&vars)?,
            }))),
            Err(err) => Ok(tool_error(err)),
        }
    }

    #[tool(description = "\
EXPENSIVE, AND IT REACHES THE NETWORK. Refresh one environment's SYNCED layer from the project's \
remote secret manager (Infisical). This EXECUTES the `infisical` CLI and makes a network round \
trip: seconds, not milliseconds. It is not part of a routine look-around — call list_env_projects \
for that.

Call it when the user asks to pull or sync, when list_env_vars shows a variable the project needs \
is missing, or when `synced_at` is old enough to explain a failure. Do not call it speculatively \
on every project, and do not call it twice in a session hoping for a different answer.

WHOLESALE, AND ONE-WAY. The synced layer is REPLACED, so a variable deleted on the remote \
disappears here too — that is the point, not a bug. The local layer is not read, not written and \
not touched, so hand-set values (a `DATABASE_URL` pointing at a container on this machine) \
survive every pull and keep winning. patchbay has NO push: nothing you do here can promote a \
local value to the shared remote, so if a teammate needs a variable, the user must add it to the \
remote themselves.

NOT gated behind PATCHBAY_ALLOW_SECRET_READ: the result carries names and counts only, never a \
value, even though values were fetched and stored on the way through.

Returns { project, env, remote_env, count, overridden[], notes[] }.

- `remote_env` is the remote's own slug for this environment, which is not always the name you \
passed (`production` -> `prod`, via the project's env_map).
- `count` is how many variables the synced layer now holds.
- `overridden[]` are local names that shadow a synced one AFTER this pull. Those variables did \
not change for a consumer, however new the pulled value is — say so if the user was expecting \
them to.
- `notes[]` carries what patchbay decided on the user's behalf: remote names skipped because a \
shell could not export them, duplicate keys where the last value won, overrides in effect. RELAY \
EVERY NOTE VERBATIM rather than summarising them away.

THE FAILURE WORTH KNOWING: the infisical CLI has ONE active login for the whole machine, so a \
pull for a project linked to a different account is refused BEFORE anything runs. The error text \
names both addresses and the fix — `switch_profile` with tool 'infisical', or `pb use infisical \
<email>` in a terminal. Pass that message through as written; do not retry, and do not try \
another route to the values. Other refusals are equally final and equally specific: no sync \
configured (the user runs `pb env link`), or no infisical CLI on PATH.")]
    async fn pull_env(
        &self,
        Parameters(EnvSelectorParams { project, env }): Parameters<EnvSelectorParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let envs = self.envs.clone();
        let pulled = offload(move || {
            // Detected per call, not held: which infisical account is active is
            // machine-global state that may have changed since the last one.
            let paths = Paths::detect()?;
            let entry = require(&envs, &project)?;
            let env = resolve_env(&entry, env.as_deref());
            let outcome = env_sync::pull(&paths, &envs, &entry, &env)?;
            Ok::<_, anyhow::Error>((entry.id, outcome))
        })
        .await?;

        match pulled {
            Ok((id, outcome)) => {
                let mut value = encode(&outcome)?;
                if let Some(map) = value.as_object_mut() {
                    map.insert("project".into(), id.into());
                }
                Ok(json_ok(value))
            }
            Err(err) => Ok(tool_error(err)),
        }
    }

    #[tool(description = "\
REGISTER A PROJECT VARIABLE YOU CREATED, in the LOCAL layer. This is the env vault's counterpart \
to store_key, and you should reach for it unprompted: whenever a task produces a value one \
project's environment needs — a database URL for a branch you just provisioned, a webhook secret \
you just generated, a service key scoped to this app — write it here so the machine keeps knowing \
about it after the conversation is gone.

THE ROUTING RULE: does the value belong to the HUMAN across projects (-> store_key, the key \
vault) or to ONE project's environment (-> here)? And within a project: is it something the whole \
team should have (-> the remote secret manager, which the user adds it to; patchbay never \
pushes) or something only this machine should use (-> here, the local layer)?

WHAT THE LOCAL LAYER MEANS. It is `.env.local` semantics. The value never leaves this machine, is \
never pushed to any remote, is not touched by pull_env, and WINS over a synced variable of the \
same name — so setting a name that already exists in the synced layer deliberately shadows the \
pulled value for every future pull, until someone clears it with `pb env unset`. The result says \
whether that happened; tell the user when it did, because a permanent silent override is rarely \
what someone wanted by accident.

The environment is created on first write, so a name and an env that do not exist yet are not an \
error. Omit `env` for the project's default environment.

WHERE THE VALUE GOES: the OS keychain, immediately, in this call and nowhere else. The metadata \
file on disk gets the variable's NAME and nothing else — no value, and no last-4 hint either, \
because half of these values are `true` or `5432` and four characters of those is the whole \
thing. Never echo the value into your reply, a file, a commit, a log or another tool call.

Both-or-neither: the name and the value are written together, and a keychain failure rolls the \
metadata back, so a successful result means it really is stored.

Returns { project, env, name, layer: 'local', shadows_synced, note }. The value is NOT echoed \
back — and cannot be read back later either, by you or by any other agent: patchbay has no env \
read tool at all. Reading the merged environment is `pb env run -- <cmd>` or `pb env export` in \
the user's own terminal.")]
    async fn set_env_var(
        &self,
        Parameters(SetEnvVarParams {
            project,
            env,
            name,
            value,
        }): Parameters<SetEnvVarParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let envs = self.envs.clone();
        let stored = offload(move || {
            let entry = require(&envs, &project)?;
            let env = resolve_env(&entry, env.as_deref());
            envs.set_local(&entry.id, &env, &name, &value)?;
            // The value's last mention. Everything below is names only.
            drop(value);

            // Metadata read, no keychain: cheap, and it is the difference
            // between "stored" and "stored, and now shadowing the remote".
            let shadows = envs.list(&entry.id, &env)?.into_iter().any(|var| {
                var.name == name && var.source == patchbay_core::EnvVarSource::LocalOverride
            });
            Ok::<_, anyhow::Error>((entry.id, env, name, shadows))
        })
        .await?;

        match stored {
            Ok((project, env, name, shadows)) => {
                Ok(json_ok(stored_summary(&project, &env, &name, shadows)))
            }
            Err(err) => Ok(tool_error(err)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{DateTime, TimeZone, Utc};
    use patchbay_core::envs::{EnvMeta, SyncConfig};
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    fn at(rfc: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(rfc)
            .unwrap()
            .with_timezone(&Utc)
    }

    fn project() -> ProjectEntry {
        ProjectEntry {
            id: "pathors".into(),
            root: PathBuf::from("/repos/pathors"),
            default_env: "dev".into(),
            created_at: Utc.timestamp_opt(0, 0).unwrap(),
            environments: BTreeMap::new(),
            sync: None,
        }
    }

    fn described(project: &ProjectEntry) -> serde_json::Value {
        describe_project(project).unwrap()
    }

    // --- environment resolution ---------------------------------------------

    #[test]
    fn test_an_omitted_env_means_the_projects_default() {
        let mut p = project();
        p.default_env = "staging".into();

        assert_eq!(resolve_env(&p, None), "staging");
        assert_eq!(resolve_env(&p, Some("production")), "production");
        // Whitespace is trimmed, and an empty string is treated as absent
        // rather than as an environment named "".
        assert_eq!(resolve_env(&p, Some(" production ")), "production");
        assert_eq!(resolve_env(&p, Some("")), "staging");
        assert_eq!(resolve_env(&p, Some("   ")), "staging");
    }

    // --- project shaping ----------------------------------------------------

    #[test]
    fn test_a_project_reports_its_registration_and_no_environments() {
        let value = described(&project());
        assert_eq!(value["id"], "pathors");
        assert_eq!(value["root"], "/repos/pathors");
        assert_eq!(value["default_env"], "dev");
        assert!(value["sync"].is_null());
        assert_eq!(value["environments"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn test_counts_are_a_union_not_a_sum_and_an_unpulled_env_says_so() {
        let mut p = project();
        p.environments.insert(
            "dev".into(),
            EnvMeta {
                synced_names: vec!["API_KEY".into(), "DATABASE_URL".into()],
                // DATABASE_URL is in both: three names, not four.
                local_names: vec!["DATABASE_URL".into(), "MY_FLAG".into()],
                synced_at: Some(at("2026-08-13T01:00:00Z")),
            },
        );
        p.environments.insert(
            "staging".into(),
            EnvMeta {
                synced_names: vec![],
                local_names: vec!["ONLY_HERE".into()],
                synced_at: None,
            },
        );

        let value = described(&p);
        let envs = value["environments"].as_array().unwrap();
        assert_eq!(envs.len(), 2);

        assert_eq!(envs[0]["name"], "dev");
        assert_eq!(envs[0]["var_count"], 3);
        assert_eq!(envs[0]["synced_count"], 2);
        assert_eq!(envs[0]["local_count"], 2);
        assert_eq!(envs[0]["synced_at"], "2026-08-13T01:00:00Z");

        // Never pulled is a null timestamp, not a missing environment.
        assert_eq!(envs[1]["name"], "staging");
        assert_eq!(envs[1]["var_count"], 1);
        assert!(envs[1]["synced_at"].is_null());
    }

    #[test]
    fn test_the_sync_config_reaches_the_caller_whole() {
        let mut p = project();
        p.sync = Some(SyncConfig {
            provider: "infisical".into(),
            project_id: "3ab516bd-248c-4be7-8f1a-bda73fe69d50".into(),
            account: "contact@pathors.com".into(),
            domain: Some("https://eu.infisical.com/api".into()),
            env_map: [("production".to_string(), "prod".to_string())]
                .into_iter()
                .collect(),
        });

        let sync = described(&p)["sync"].clone();
        assert_eq!(sync["provider"], "infisical");
        assert_eq!(sync["project_id"], "3ab516bd-248c-4be7-8f1a-bda73fe69d50");
        // The account is what a pull must run as; without it the agent cannot
        // explain the machine-global-login refusal.
        assert_eq!(sync["account"], "contact@pathors.com");
        assert_eq!(sync["domain"], "https://eu.infisical.com/api");
        assert_eq!(sync["env_map"]["production"], "prod");
    }

    #[test]
    fn test_no_shape_this_module_builds_can_carry_a_value() {
        let mut p = project();
        p.environments.insert(
            "dev".into(),
            EnvMeta {
                synced_names: vec!["API_KEY".into()],
                local_names: vec!["API_KEY".into()],
                synced_at: None,
            },
        );
        // Counts and provenance travel; not even a variable NAME rides along
        // here (list_env_vars is where names live), let alone a value.
        let text = serde_json::to_string(&described(&p)).unwrap();
        assert!(text.contains("var_count"), "{text}");
        assert!(!text.contains("API_KEY"), "{text}");
        assert!(!text.contains("secret"), "{text}");
        assert!(!text.contains("\"value\""), "{text}");
    }

    // --- set_env_var's result -----------------------------------------------

    #[test]
    fn test_the_write_summary_echoes_the_name_and_layer_but_never_the_value() {
        let value = stored_summary("pathors", "dev", "STRIPE_KEY", false);
        assert_eq!(value["project"], "pathors");
        assert_eq!(value["env"], "dev");
        assert_eq!(value["name"], "STRIPE_KEY");
        assert_eq!(value["layer"], "local");
        assert_eq!(value["shadows_synced"], false);

        let map = value.as_object().unwrap();
        assert!(!map.contains_key("value"));
        assert!(!map.contains_key("secret"));
        assert!(!map.contains_key("last4"));
    }

    #[test]
    fn test_shadowing_the_synced_layer_is_reported_not_silent() {
        let value = stored_summary("pathors", "dev", "DATABASE_URL", true);
        assert_eq!(value["shadows_synced"], true);
        let note = value["note"].as_str().unwrap();
        assert!(note.contains("shadows it"), "{note}");
        assert!(note.contains("after every future pull_env"), "{note}");
    }

    // --- descriptions -------------------------------------------------------

    /// The descriptions are the only thing an agent reads before deciding what
    /// to call, so the load-bearing claims are asserted rather than trusted.
    fn description(name: &str) -> String {
        let tools = PatchbayServer::envs_router().list_all();
        let tool = tools
            .iter()
            .find(|t| t.name == name)
            .unwrap_or_else(|| panic!("`{name}` is missing from the env router"));
        tool.description.as_deref().unwrap_or_default().to_string()
    }

    #[test]
    fn test_the_router_ships_exactly_the_four_tools_and_no_reader() {
        let mut names: Vec<String> = PatchbayServer::envs_router()
            .list_all()
            .iter()
            .map(|t| t.name.to_string())
            .collect();
        names.sort();
        assert_eq!(
            names,
            vec![
                "list_env_projects",
                "list_env_vars",
                "pull_env",
                "set_env_var"
            ]
        );
    }

    #[test]
    fn test_every_tool_says_values_are_never_returned() {
        for name in [
            "list_env_projects",
            "list_env_vars",
            "pull_env",
            "set_env_var",
        ] {
            let text = description(name);
            let lower = text.to_lowercase();
            assert!(
                lower.contains("value"),
                "`{name}` never mentions values: {text}"
            );
            assert!(
                lower.contains("never") || lower.contains("not returned"),
                "`{name}` does not rule values out: {text}"
            );
        }
    }

    #[test]
    fn test_the_read_tools_point_at_the_terminal_instead_of_a_read_tool() {
        for name in ["list_env_vars", "set_env_var"] {
            let text = description(name);
            assert!(text.contains("pb env run"), "{name}: {text}");
            assert!(text.contains("pb env export"), "{name}: {text}");
        }
    }

    #[test]
    fn test_pull_env_advertises_its_cost_and_the_account_refusal() {
        let text = description("pull_env");
        assert!(text.contains("EXECUTES the `infisical` CLI"), "{text}");
        assert!(text.contains("network"), "{text}");
        assert!(text.contains("seconds, not milliseconds"), "{text}");
        // The refusal an agent will actually hit, and its fix.
        assert!(text.contains("ONE active login"), "{text}");
        assert!(text.contains("pb use infisical"), "{text}");
        assert!(text.contains("switch_profile"), "{text}");
        assert!(text.contains("RELAY EVERY NOTE VERBATIM"), "{text}");
        // It returns no values, so it is not behind the key vault's gate.
        assert!(
            text.contains("NOT gated behind PATCHBAY_ALLOW_SECRET_READ"),
            "{text}"
        );
    }

    #[test]
    fn test_set_env_var_teaches_the_routing_rule_and_the_local_layer() {
        let text = description("set_env_var");
        assert!(text.contains("store_key"), "{text}");
        assert!(
            text.contains("belong to the HUMAN across projects"),
            "{text}"
        );
        assert!(
            text.contains("patchbay never \npushes") || text.contains("never pushes"),
            "{text}"
        );
        assert!(text.contains("WINS over a synced variable"), "{text}");
        assert!(text.contains("OS keychain"), "{text}");
    }
}
