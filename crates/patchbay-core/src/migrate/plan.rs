//! The gap list, re-read from the machine in front of you.
//!
//! A manifest's `gaps` array is a *prediction* made on the old machine. This
//! module makes the real thing: it re-probes every tool, compares against what
//! the manifest said the source had, and returns one [`SetupItem`] per thing
//! that is still not true here — plus the ones that already are, marked
//! [`SetupStatus::Done`], so an agent working the list can see it shrinking
//! rather than guess.
//!
//! Two entry points, and they share all their logic on purpose:
//!
//! * [`plan`] — the whole list.
//! * [`recheck`] — one item by id, for `mark_setup_done`. It re-probes rather
//!   than trusting the caller's claim, which is the entire point: an agent that
//!   ran `gh auth login` in a subshell and got no browser has not closed
//!   anything, and should be told so.
//!
//! Without a manifest ([`plan`] with `None`) this is still useful on its own:
//! it becomes "what on this machine is not logged in", which is what `pb plan`
//! does with no arguments.

use super::manifest::{Manifest, SetupItem, SetupStatus, ToolRecord};
use super::policy::{policy_for, Portability};
use crate::envs::EnvRegistry;
use crate::keys::KeyRegistry;
use crate::mcp_clients::McpClientRegistry;
use crate::paths::Paths;
use crate::registry::Registry;
use crate::types::{ConnectionState, ToolStatus};

/// Every outstanding item, plus the closed ones for context.
///
/// `manifest` is what the source machine had; `None` plans against this machine
/// alone.
pub fn plan(
    paths: &Paths,
    registry: &Registry,
    vault: &KeyRegistry,
    clients: &McpClientRegistry,
    envs: &EnvRegistry,
    manifest: Option<&Manifest>,
) -> Vec<SetupItem> {
    let _ = paths;
    let mut items = Vec::new();
    let statuses = registry.status_all();

    for status in &statuses {
        let expected = manifest.and_then(|m| m.tool(&status.tool));
        items.extend(tool_items(status, expected));
    }
    items.extend(key_items(vault, manifest));
    items.extend(mcp_items(clients, manifest));
    items.extend(env_items(envs, manifest));
    items
}

/// One item by id, re-derived from the machine. `None` when no such id exists
/// in the current plan — which is itself an answer: there is nothing to do.
pub fn recheck(
    paths: &Paths,
    registry: &Registry,
    vault: &KeyRegistry,
    clients: &McpClientRegistry,
    envs: &EnvRegistry,
    manifest: Option<&Manifest>,
    id: &str,
) -> Option<SetupItem> {
    plan(paths, registry, vault, clients, envs, manifest)
        .into_iter()
        .find(|item| item.id == id)
}

// ---------------------------------------------------------------------------
// tools
// ---------------------------------------------------------------------------

/// Whether the source machine had anything worth re-creating for this tool.
fn source_had_something(expected: Option<&ToolRecord>, status: &ToolStatus) -> bool {
    match expected {
        Some(record) => {
            record.installed && (!record.profiles.is_empty() || record.active.is_some())
        }
        // No manifest: plan against what is here.
        None => status.installed,
    }
}

fn tool_items(status: &ToolStatus, expected: Option<&ToolRecord>) -> Vec<SetupItem> {
    let Some(policy) = policy_for(&status.tool) else {
        return Vec::new();
    };
    if !source_had_something(expected, status) {
        return Vec::new();
    }

    let mut items = Vec::new();
    let state = status.connection_state();

    // 1. Is the CLI even here? Nothing else about this tool can be checked
    //    until it is, so this item comes first and the login item goes
    //    `Unknown` behind it rather than claiming a verdict it cannot have.
    if state == ConnectionState::NotInstalled {
        items.push(
            SetupItem::new(
                format!("install:{}", status.tool),
                &status.tool,
                format!("`{}` is not installed on this machine", status.tool),
            )
            .command(policy.install, false),
        );
    }

    // 2. Is it logged in?
    //
    // Two deliberate departures from the status board here, both because a
    // checklist is a different thing from a warning light:
    //
    //  * `Attention` is Open only when the credential has ACTUALLY expired. The
    //    board is right to flag a gcloud access token with 40 minutes left —
    //    but gcloud refreshes that itself, and a setup list that can never
    //    reach zero is a setup list people stop working.
    //  * a `concurrent` tool with profiles is Done. docker, rclone, ssh and npm
    //    have no active profile by design, so `Disconnected` there means
    //    "healthy", not "logged out".
    let now = chrono::Utc::now();
    let expired = status
        .active_expiry()
        .or_else(|| status.soonest_expiry())
        .is_some_and(|at| at <= now);

    let (login_status, what) = match state {
        ConnectionState::Connected => {
            (SetupStatus::Done, format!("`{}` is logged in", status.tool))
        }
        ConnectionState::Attention if expired => (
            SetupStatus::Open,
            format!("`{}`'s credential has expired", status.tool),
        ),
        ConnectionState::Attention => (
            SetupStatus::Done,
            format!(
                "`{}` is logged in (its credential expires within 24h; the tool refreshes it)",
                status.tool
            ),
        ),
        ConnectionState::Disconnected if policy.concurrent && !status.profiles.is_empty() => (
            SetupStatus::Done,
            format!(
                "`{}` has {} credential(s); it has no active profile by design",
                status.tool,
                status.profiles.len()
            ),
        ),
        ConnectionState::Disconnected => (
            SetupStatus::Open,
            format!("`{}` is installed but nothing is logged in", status.tool),
        ),
        ConnectionState::NotInstalled => (
            SetupStatus::Unknown,
            format!(
                "`{}` cannot be checked until the CLI is installed",
                status.tool
            ),
        ),
    };
    let mut login = SetupItem::new(format!("tool:{}", status.tool), &status.tool, what)
        .command(policy.fix, policy.needs_browser)
        .status(login_status);
    if !matches!(policy.portability, Portability::Portable { .. }) {
        login = login.detail(policy.portability.reason());
    }
    if let Some(record) = expected {
        if let Some(active) = &record.active {
            login = login.detail(format!("the old machine was `{active}` here"));
        }
        if !record.scopes.is_empty() {
            login = login.detail(format!(
                "it had these scopes, which the new login has to match: {}",
                record.scopes.join(", ")
            ));
        }
    }
    items.push(login);

    // 3. Logged in, but as somebody else. patchbay can fix this one itself.
    if state != ConnectionState::NotInstalled {
        if let Some(record) = expected {
            if let (Some(want), here) = (record.active.as_ref(), status.active.as_ref()) {
                let known = status.profiles.iter().any(|p| &p.id == want);
                if here != Some(want) && known {
                    items.push(
                        SetupItem::new(
                            format!("switch:{}", status.tool),
                            &status.tool,
                            format!(
                                "`{}` is on `{}`; the old machine was on `{want}`",
                                status.tool,
                                here.map(String::as_str).unwrap_or("nothing")
                            ),
                        )
                        .command(format!("pb use {} {want}", status.tool), false)
                        .auto(true),
                    );
                }
            }
        }
    }
    items
}

// ---------------------------------------------------------------------------
// vault
// ---------------------------------------------------------------------------

fn key_items(vault: &KeyRegistry, manifest: Option<&Manifest>) -> Vec<SetupItem> {
    let here = vault.list().unwrap_or_default();
    let mut items = Vec::new();

    if let Some(manifest) = manifest {
        for key in &manifest.keys {
            let present = here.iter().any(|e| e.id == key.id);
            items.push(
                SetupItem::new(
                    format!("key:{}", key.id),
                    "key vault",
                    if present {
                        format!("`{}` is registered on this machine", key.id)
                    } else {
                        format!(
                            "`{}` ({}, …{}) was registered on the old machine and is not here",
                            key.id, key.provider, key.last4
                        )
                    },
                )
                .command(
                    format!(
                        "pb key add {} --provider {} --label \"{}\"",
                        key.id, key.provider, key.label
                    ),
                    false,
                )
                .status(if present {
                    SetupStatus::Done
                } else {
                    SetupStatus::Open
                })
                .detail(if key.included {
                    "its value was inside the bundle"
                } else {
                    "its value did NOT travel; get a fresh one from the issuer"
                }),
            );
        }
        return items;
    }

    // No manifest: the vault's own health is still worth a line.
    let now = chrono::Utc::now();
    for entry in here {
        if entry.expiry_state(now).needs_attention() {
            items.push(
                SetupItem::new(
                    format!("key:{}", entry.id),
                    "key vault",
                    format!(
                        "`{}` ({}) is {}",
                        entry.id,
                        entry.provider,
                        entry.expiry_state(now).label()
                    ),
                )
                .command(format!("pb key verify {}", entry.id), false),
            );
        }
    }
    items
}

// ---------------------------------------------------------------------------
// MCP clients
// ---------------------------------------------------------------------------

fn mcp_items(clients: &McpClientRegistry, manifest: Option<&Manifest>) -> Vec<SetupItem> {
    let Some(manifest) = manifest else {
        return Vec::new();
    };
    let here = clients.clients();
    manifest
        .mcp
        .iter()
        .map(|record| {
            let present = here.iter().any(|c| {
                c.client == record.client
                    && c.servers
                        .iter()
                        .any(|s| s.name == record.name && s.is_writable_scope())
            });
            let mut item = SetupItem::new(
                format!("mcp:{}/{}", record.client, record.name),
                "mcp",
                if present {
                    format!("`{}` is registered in {}", record.name, record.client)
                } else {
                    format!(
                        "`{}` ({}) was registered in {} on the old machine",
                        record.name, record.summary, record.client
                    )
                },
            )
            .command("pb import <bundle>", false)
            .status(if present {
                SetupStatus::Done
            } else {
                SetupStatus::Open
            })
            .detail(
                "the registration, including any env or header values, is inside the bundle; \
                 re-running the import restores it",
            );
            if !record.env_keys.is_empty() || !record.header_keys.is_empty() {
                item = item.detail(format!(
                    "it sets: {}",
                    record
                        .env_keys
                        .iter()
                        .chain(record.header_keys.iter())
                        .cloned()
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
            }
            item
        })
        .collect()
}

// ---------------------------------------------------------------------------
// env vault
// ---------------------------------------------------------------------------

/// One item per carried project that a pull can rebuild.
///
/// **`auto` is false, deliberately**, even though `pb env pull` is a patchbay
/// command and every other patchbay-can-do-it-itself item is `true`. A pull
/// runs the infisical CLI, whose active login is machine-global: unless this
/// machine happens to be logged in as the account the project is pinned to, the
/// pull refuses and tells the user to run `pb use infisical <email>` first. An
/// agent firing these blind would collect a row of confusing failures, so the
/// account goes in the detail and the human decides.
///
/// Without a manifest there is nothing to say: a project registered here with
/// no pull yet is a normal state, not an outstanding move.
fn env_items(envs: &EnvRegistry, manifest: Option<&Manifest>) -> Vec<SetupItem> {
    let Some(manifest) = manifest else {
        return Vec::new();
    };
    let here = envs.projects().unwrap_or_default();

    let mut items = Vec::new();
    for record in &manifest.env_projects {
        let Some(sync) = &record.sync else {
            // Not linked: `collect_env_projects` already made a gap for the
            // ones that had a synced layer, and there is no pull to suggest.
            continue;
        };
        let local = here.iter().find(|p| p.id == record.id);
        // Done only when this machine has pulled SINCE the bundle was written.
        // `synced_at` travels with the entry, so its mere presence proves
        // nothing — a restored project looks pulled the moment it lands.
        let pulled_here = local.is_some_and(|project| {
            record.environments.iter().any(|env| {
                let before = env.synced_at;
                let now = project.env(&env.name).and_then(|meta| meta.synced_at);
                match (now, before) {
                    (Some(now), Some(before)) => now > before,
                    (Some(_), None) => true,
                    _ => false,
                }
            })
        });

        let mut item = SetupItem::new(
            format!("env:{}", record.id),
            "env vault",
            if pulled_here {
                format!("`{}`'s synced layer has been pulled here", record.id)
            } else {
                format!(
                    "`{}`'s variables are not on this machine; no value travels in a bundle, so \
                     the synced layer is rebuilt by pulling it",
                    record.id
                )
            },
        )
        .command(format!("pb env pull --project {}", record.id), false)
        .auto(false)
        .status(if pulled_here {
            SetupStatus::Done
        } else {
            SetupStatus::Open
        })
        .detail(format!(
            "it is pinned to the {} account `{}`; the CLI's active login is machine-global, so \
             `pb use infisical {}` may have to come first",
            sync.provider, sync.account, sync.account
        ));

        if local.is_none() {
            item = item.detail(format!(
                "no project `{}` is registered here yet — `pb import` registers it, or `pb env \
                 init --id {}` does",
                record.id, record.id
            ));
        }
        items.push(item);
    }
    items
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keystore::MemoryKeystore;
    use crate::migrate::export::{Exporter, KeySelection};
    use crate::migrate::manifest::Manifest;
    use chrono::Utc;
    use std::fs;
    use std::path::PathBuf;

    struct Machine {
        _dir: tempfile::TempDir,
        home: PathBuf,
        paths: Paths,
        registry: Registry,
        vault: KeyRegistry,
        clients: McpClientRegistry,
        envs: EnvRegistry,
    }

    impl Machine {
        fn new(files: &[(&str, &str)]) -> Self {
            let dir = tempfile::tempdir().unwrap();
            for (rel, body) in files {
                let path = dir.path().join(rel);
                fs::create_dir_all(path.parent().unwrap()).unwrap();
                fs::write(&path, body).unwrap();
            }
            let home = dir.path().to_path_buf();
            let paths = Paths::for_test(&home);
            Self {
                registry: Registry::all(paths.clone()),
                vault: KeyRegistry::new(home.join("keys.json"), Box::new(MemoryKeystore::new())),
                clients: McpClientRegistry::with_paths(paths.clone()),
                envs: EnvRegistry::new(
                    home.join("projects.json"),
                    home.join("attachments.json"),
                    Box::new(MemoryKeystore::new()),
                ),
                paths,
                home,
                _dir: dir,
            }
        }

        fn manifest(&self) -> Manifest {
            Exporter {
                paths: &self.paths,
                registry: &self.registry,
                vault: &self.vault,
                clients: &self.clients,
                envs: &self.envs,
            }
            .payload(&KeySelection::None, Utc::now())
            .unwrap()
            .manifest
        }

        fn plan(&self, manifest: Option<&Manifest>) -> Vec<SetupItem> {
            plan(
                &self.paths,
                &self.registry,
                &self.vault,
                &self.clients,
                &self.envs,
                manifest,
            )
        }
    }

    const GH_HOSTS: &str = "github.com:\n    user: octocat\n    users:\n        octocat:\n";
    const AWS_CONFIG: &str = "[default]\nregion = eu-west-1\n[profile work]\nregion = us-east-1\n";

    fn item<'a>(items: &'a [SetupItem], id: &str) -> &'a SetupItem {
        items
            .iter()
            .find(|i| i.id == id)
            .unwrap_or_else(|| panic!("no item `{id}` in {:?}", ids(items)))
    }

    fn ids(items: &[SetupItem]) -> Vec<&str> {
        items.iter().map(|i| i.id.as_str()).collect()
    }

    #[test]
    fn test_a_bare_machine_gets_every_gap_the_source_had() {
        let source = Machine::new(&[
            (".config/gh/hosts.yml", GH_HOSTS),
            (".aws/config", AWS_CONFIG),
        ]);
        let manifest = source.manifest();

        let dest = Machine::new(&[]);
        let items = dest.plan(Some(&manifest));

        // gh: nothing here at all, so both the install and the login are open.
        // (`has_binary` is disabled in tests, so every tool reads as absent.)
        assert_eq!(item(&items, "install:gh").status, SetupStatus::Open);
        assert_eq!(item(&items, "install:gh").command, "brew install gh");
        let login = item(&items, "tool:gh");
        assert_eq!(login.status, SetupStatus::Unknown);
        assert_eq!(login.command, "gh auth login");
        assert!(login.needs_browser);
        assert!(
            login.detail.iter().any(|d| d.contains("keychain")),
            "{login:?}"
        );
        assert!(
            login
                .detail
                .iter()
                .any(|d| d.contains("github.com/octocat")),
            "the plan should say who the old machine was: {login:?}"
        );
    }

    #[test]
    fn test_a_tool_that_is_logged_in_here_is_marked_done() {
        let source = Machine::new(&[(".config/gh/hosts.yml", GH_HOSTS)]);
        let manifest = source.manifest();
        // Same login already present on the destination.
        let dest = Machine::new(&[(".config/gh/hosts.yml", GH_HOSTS)]);
        let items = dest.plan(Some(&manifest));

        assert_eq!(item(&items, "tool:gh").status, SetupStatus::Done);
        assert!(!items.iter().any(|i| i.id == "install:gh"));
        assert!(!item(&items, "tool:gh").is_open());
    }

    #[test]
    fn test_a_wrong_active_profile_is_a_switch_patchbay_can_do_itself() {
        let source = Machine::new(&[
            (".config/gcloud/active_config", "work"),
            (
                ".config/gcloud/configurations/config_work",
                "[core]\naccount = me@work.com\nproject = work-proj\n",
            ),
            (
                ".config/gcloud/configurations/config_home",
                "[core]\naccount = me@home.com\nproject = home-proj\n",
            ),
        ]);
        let manifest = source.manifest();

        let dest = Machine::new(&[
            (".config/gcloud/active_config", "home"),
            (
                ".config/gcloud/configurations/config_work",
                "[core]\naccount = me@work.com\nproject = work-proj\n",
            ),
            (
                ".config/gcloud/configurations/config_home",
                "[core]\naccount = me@home.com\nproject = home-proj\n",
            ),
        ]);
        let items = dest.plan(Some(&manifest));

        let switch = item(&items, "switch:gcloud");
        assert!(switch.auto, "a profile switch is patchbay's own job");
        assert_eq!(switch.command, "pb use gcloud work");
        assert!(!switch.needs_browser);
    }

    #[test]
    fn test_a_key_that_did_not_travel_is_open_and_closes_once_registered() {
        let source = Machine::new(&[]);
        source
            .vault
            .add(
                crate::keys::NewKey::new("cf-api", "cli")
                    .provider("cloudflare")
                    .label("CF deploy"),
                "cf-secret-1234",
                false,
            )
            .unwrap();
        let manifest = source.manifest();

        let dest = Machine::new(&[]);
        let open = item(&dest.plan(Some(&manifest)), "key:cf-api").clone();
        assert_eq!(open.status, SetupStatus::Open);
        assert!(open.command.contains("pb key add cf-api"), "{open:?}");
        assert!(open.detail.iter().any(|d| d.contains("did NOT travel")));

        dest.vault
            .add(
                crate::keys::NewKey::new("cf-api", "cli").provider("cloudflare"),
                "new-value-5678",
                false,
            )
            .unwrap();
        assert_eq!(
            item(&dest.plan(Some(&manifest)), "key:cf-api").status,
            SetupStatus::Done
        );
    }

    #[test]
    fn test_an_mcp_registration_the_destination_lacks_is_on_the_plan() {
        let source = Machine::new(&[(
            ".cursor/mcp.json",
            r#"{"mcpServers":{"grafana":{"command":"uvx","args":["mcp-grafana"],"env":{"GRAFANA_TOKEN":"glsa_x"}}}}"#,
        )]);
        let manifest = source.manifest();

        let dest = Machine::new(&[]);
        let items = dest.plan(Some(&manifest));
        let mcp = item(&items, "mcp:cursor/grafana");
        assert_eq!(mcp.status, SetupStatus::Open);
        assert!(
            mcp.detail.iter().any(|d| d.contains("GRAFANA_TOKEN")),
            "{mcp:?}"
        );
        // Names, never values, even here.
        let json = serde_json::to_string(&items).unwrap();
        assert!(!json.contains("glsa_x"), "{json}");
    }

    /// The env vault's item is the one patchbay deliberately will NOT run
    /// itself: a pull is only valid under the account the project is pinned to,
    /// and that login is machine-global.
    #[test]
    fn test_a_carried_env_project_asks_for_a_pull_and_names_the_account() {
        let source = Machine::new(&[]);
        crate::migrate::export::tests::seed_env_vault(
            &source.envs,
            &source.home.join("repos/pathors"),
        );
        let manifest = source.manifest();

        let dest = Machine::new(&[]);
        let items = dest.plan(Some(&manifest));
        let pull = item(&items, "env:pathors");
        assert_eq!(pull.command, "pb env pull --project pathors");
        assert!(!pull.auto, "a pull can fail on the wrong login: {pull:?}");
        assert!(!pull.needs_browser);
        assert_eq!(pull.status, SetupStatus::Open);
        assert!(
            pull.detail.iter().any(|d| d.contains("me@work.com")),
            "the pinned account has to be on the item: {pull:?}"
        );
        assert!(
            pull.detail.iter().any(|d| d.contains("pb use infisical")),
            "{pull:?}"
        );
        // `legacy` has no sync config, so there is no pull to suggest — the
        // export already made that a gap of its own.
        assert!(
            !items.iter().any(|i| i.id == "env:legacy"),
            "{:?}",
            ids(&items)
        );
        // Names, never values, here as everywhere.
        let json = serde_json::to_string(&items).unwrap();
        assert!(!json.contains("postgres://"), "{json}");
    }

    #[test]
    fn test_an_env_project_closes_once_it_has_actually_been_pulled_here() {
        let source = Machine::new(&[]);
        crate::migrate::export::tests::seed_env_vault(
            &source.envs,
            &source.home.join("repos/pathors"),
        );
        let manifest = source.manifest();

        // Import-shaped destination: the entry is here, `synced_at` and all,
        // which must NOT read as done — it is the source's timestamp.
        let dest = Machine::new(&[]);
        for project in &source.envs.projects().unwrap() {
            dest.envs.adopt(project).unwrap();
        }
        assert_eq!(
            item(&dest.plan(Some(&manifest)), "env:pathors").status,
            SetupStatus::Open
        );

        // A pull on THIS machine moves the timestamp, and only then.
        dest.envs
            .replace_synced(
                "pathors",
                "dev",
                [("DATABASE_URL".to_string(), "postgres://here/db".to_string())]
                    .into_iter()
                    .collect(),
                Utc::now(),
            )
            .unwrap();
        assert_eq!(
            item(&dest.plan(Some(&manifest)), "env:pathors").status,
            SetupStatus::Done
        );
    }

    /// docker, rclone, ssh and npm use every credential they have at once.
    /// Reporting them as "logged out" forever would make the plan unfinishable.
    #[test]
    fn test_a_tool_with_no_active_profile_by_design_is_not_a_gap() {
        let m = Machine::new(&[
            (
                ".docker/config.json",
                r#"{"auths":{"https://index.docker.io/v1/":{}},"credsStore":"desktop"}"#,
            ),
            (".ssh/config", "Host prod\n  HostName 10.0.0.1\n"),
            (
                ".npmrc",
                "//registry.npmjs.org/:_authToken=npm_x\n//other/:_authToken=npm_y\n",
            ),
        ]);
        let items = m.plan(None);
        for tool in ["docker", "ssh", "npm"] {
            let login = item(&items, &format!("tool:{tool}"));
            assert_eq!(login.status, SetupStatus::Done, "{login:?}");
            assert!(login.what.contains("by design"), "{login:?}");
        }
        // kubectl is not concurrent: an empty kubeconfig really is a gap.
        let m = Machine::new(&[(".kube/config", "apiVersion: v1\nclusters: []\n")]);
        assert_eq!(
            item(&m.plan(None), "tool:kubectl").status,
            SetupStatus::Open
        );
    }

    /// A credential that expires in an hour is not a setup task; one that
    /// expired yesterday is.
    #[test]
    fn test_expiring_soon_is_done_and_actually_expired_is_open() {
        // An AWS SSO session dates a real login — unlike gcloud, whose only
        // dated thing is an hourly access token it refreshes by itself, which
        // is why that probe reports no expiry at all.
        let soon = (Utc::now() + chrono::Duration::hours(1)).to_rfc3339();
        let past = (Utc::now() - chrono::Duration::days(2)).to_rfc3339();

        for (stamp, expected) in [(soon, SetupStatus::Done), (past, SetupStatus::Open)] {
            let m = Machine::new(&[
                (
                    ".aws/config",
                    "[default]\nsso_start_url = https://work.awsapps.com/start\nsso_role_name = Admin\nregion = us-east-1\n",
                ),
                (
                    ".aws/sso/cache/aaa.json",
                    &format!(
                        r#"{{"startUrl":"https://work.awsapps.com/start","expiresAt":"{stamp}","accessToken":"fake-fixture-token"}}"#
                    ),
                ),
            ]);
            let items = m.plan(None);
            assert_eq!(
                item(&items, "tool:aws").status,
                expected,
                "{:?}",
                item(&items, "tool:aws")
            );
        }
    }

    #[test]
    fn test_planning_without_a_manifest_reads_this_machine_alone() {
        let m = Machine::new(&[(".config/gh/hosts.yml", GH_HOSTS)]);
        let items = m.plan(None);
        // gh is logged in here, so it is Done rather than absent...
        assert_eq!(item(&items, "tool:gh").status, SetupStatus::Done);
        // ...and a tool with nothing on this machine produces no item at all.
        assert!(
            !items.iter().any(|i| i.tool == "stripe"),
            "{:?}",
            ids(&items)
        );
        assert!(!items.iter().any(|i| i.id.starts_with("mcp:")));
    }

    #[test]
    fn test_an_expiring_vault_key_shows_up_without_a_manifest() {
        let m = Machine::new(&[]);
        m.vault
            .add(
                crate::keys::NewKey::new("cf-api", "cli")
                    .provider("cloudflare")
                    .expires_at(Some(Utc::now() + chrono::Duration::days(3))),
                "cf-secret-1234",
                false,
            )
            .unwrap();
        let items = m.plan(None);
        let key = item(&items, "key:cf-api");
        assert!(key.what.contains("expiring soon"), "{key:?}");
        assert_eq!(key.command, "pb key verify cf-api");
    }

    #[test]
    fn test_recheck_re_probes_rather_than_believing_anyone() {
        let source = Machine::new(&[(".config/gh/hosts.yml", GH_HOSTS)]);
        let manifest = source.manifest();
        let dest = Machine::new(&[]);

        let before = recheck(
            &dest.paths,
            &dest.registry,
            &dest.vault,
            &dest.clients,
            &dest.envs,
            Some(&manifest),
            "tool:gh",
        )
        .unwrap();
        assert!(before.status != SetupStatus::Done);

        // Actually do the thing, on disk, where a probe can see it.
        fs::create_dir_all(dest.home.join(".config/gh")).unwrap();
        fs::write(dest.home.join(".config/gh/hosts.yml"), GH_HOSTS).unwrap();

        let after = recheck(
            &dest.paths,
            &dest.registry,
            &dest.vault,
            &dest.clients,
            &dest.envs,
            Some(&manifest),
            "tool:gh",
        )
        .unwrap();
        assert_eq!(after.status, SetupStatus::Done);

        // An id nobody planned is `None`, not a fabricated success.
        assert!(recheck(
            &dest.paths,
            &dest.registry,
            &dest.vault,
            &dest.clients,
            &dest.envs,
            Some(&manifest),
            "tool:invented",
        )
        .is_none());
    }

    #[test]
    fn test_every_item_carries_a_command() {
        let source = Machine::new(&[
            (".config/gh/hosts.yml", GH_HOSTS),
            (".aws/config", AWS_CONFIG),
            (
                ".cursor/mcp.json",
                r#"{"mcpServers":{"g":{"command":"uvx"}}}"#,
            ),
        ]);
        source
            .vault
            .add(crate::keys::NewKey::new("k", "cli"), "v-1234", false)
            .unwrap();
        let manifest = source.manifest();
        let items = Machine::new(&[]).plan(Some(&manifest));
        assert!(!items.is_empty());
        for item in &items {
            assert!(!item.command.is_empty(), "{item:?} has no command");
            assert!(!item.what.is_empty(), "{item:?} says nothing");
        }
    }
}
