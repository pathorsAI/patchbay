//! `pb env …` — the project env vault in the terminal.
//!
//! One directory, two layers per environment: `synced` is whatever the last
//! pull took from Infisical, `local` is what this machine set by hand. Local
//! wins on merge, survives every pull, and never leaves the box — patchbay has
//! no push, here or anywhere else.
//!
//! Values may reach exactly two places: the environment of the child process
//! [`Command::Run`] spawns, and the stdout of [`Command::Export`]. Never argv,
//! never a table, never an error message. `list` and `diff` are name-only by
//! construction — they read the metadata file and do not touch the keychain at
//! all, which is also what makes them fast enough to put in a shell hook.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::{IsTerminal, Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use clap::{Args, Subcommand, ValueEnum};
use patchbay_core::envs::{
    parse_dotenv, render_dotenv, validate_project_id, EnvRegistry, EnvVarInfo, EnvVarSource,
    ProjectEntry, SyncConfig, DEFAULT_ENV,
};
use patchbay_core::paths::Paths;
use patchbay_core::probes::infisical;

use crate::render::{self, Styles};

/// Width budget for the tables, matching the status board.
const TABLE_WIDTH: usize = 100;
const GAP: usize = 2;
const COL_ID_MAX: usize = 24;
const COL_ENVS_MAX: usize = 22;
const COL_SYNC_MAX: usize = 32;
const COL_NAME_MAX: usize = 40;
/// Wide enough for `local override`, the longest source label there is.
const COL_SOURCE: usize = 14;
const DASH: &str = "—";

/// The file the infisical CLI drops in a linked repo.
const INFISICAL_FILE: &str = ".infisical.json";

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Register a directory as a project.
    ///
    /// Reads `.infisical.json` if the directory has one, and records the sync
    /// automatically when this machine is logged in to infisical.
    Init {
        /// Project id. Defaults to the directory's own name as a slug.
        #[arg(long, value_name = "SLUG")]
        id: Option<String>,
        /// The directory to register. Defaults to the current one.
        #[arg(long, value_name = "PATH")]
        dir: Option<PathBuf>,
        /// Environment `pb env` uses when a command does not say.
        #[arg(long, value_name = "ENV", default_value = DEFAULT_ENV)]
        default_env: String,
    },
    /// Point a project at an Infisical project, replacing any earlier link.
    Link {
        /// Infisical's own project id (a UUID), from `.infisical.json` or the
        /// project URL.
        #[arg(long, value_name = "ID")]
        project_id: String,
        /// patchbay project to link. Defaults to this directory's.
        #[arg(long, value_name = "ID")]
        project: Option<String>,
        /// Account the pull must run as. Defaults to the active infisical login.
        #[arg(long, value_name = "EMAIL")]
        account: Option<String>,
        /// API base URL, for self-hosted or EU instances.
        #[arg(long, value_name = "URL")]
        domain: Option<String>,
        /// Environment name mapping, for remotes that spell them differently:
        /// `--map production=prod,dev=development`.
        #[arg(long, value_delimiter = ',', value_name = "LOCAL=REMOTE")]
        map: Vec<String>,
    },
    /// Every registered project.
    Projects {
        #[arg(long)]
        json: bool,
    },
    /// Variable names in one environment. Metadata only — never values.
    List {
        #[command(flatten)]
        target: Target,
        #[arg(long)]
        json: bool,
    },
    /// Replace the synced layer from the remote. The local layer is untouched.
    Pull {
        #[command(flatten)]
        target: Target,
        #[arg(long)]
        json: bool,
    },
    /// Set one variable in the local layer.
    ///
    /// The value is read from stdin when something is piped in, and from a
    /// hidden prompt otherwise. It is never taken as an argument.
    Set {
        name: String,
        #[command(flatten)]
        target: Target,
    },
    /// Remove one variable from the local layer.
    Unset {
        name: String,
        #[command(flatten)]
        target: Target,
    },
    /// Merge a `.env` file into the local layer. `-` reads stdin.
    Import {
        #[arg(value_name = "FILE")]
        file: PathBuf,
        #[command(flatten)]
        target: Target,
    },
    /// Which names are overridden, local-only or synced-only. Names only.
    Diff {
        #[command(flatten)]
        target: Target,
        #[arg(long)]
        json: bool,
    },
    /// Run a command with the merged environment applied.
    Run {
        #[command(flatten)]
        target: Target,
        /// The command, after `--`: `pb env run -- npm run dev`.
        #[arg(trailing_var_arg = true, required = true, value_name = "CMD")]
        command: Vec<String>,
    },
    /// Print the merged environment. **This is the one command that prints
    /// values** — redirect it, or prefer `pb env run`.
    Export {
        #[command(flatten)]
        target: Target,
        #[arg(long, value_enum, default_value_t = ExportFormat::Dotenv)]
        format: ExportFormat,
    },
    /// Unregister a project: metadata entry and every stored value.
    Forget {
        /// Project to forget. Defaults to this directory's.
        #[arg(long, value_name = "ID")]
        project: Option<String>,
        /// Skip the confirmation prompt.
        #[arg(long)]
        yes: bool,
    },
}

/// Which project and environment a subcommand acts on.
#[derive(Args, Debug, Default)]
pub struct Target {
    /// Project id, as `pb env projects` lists it. Defaults to the project this
    /// directory belongs to.
    #[arg(long, value_name = "ID")]
    project: Option<String>,
    /// Environment name. Defaults to the project's own default.
    #[arg(short, long, value_name = "ENV")]
    env: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum ExportFormat {
    /// `NAME='value'` lines, as a `.env` file.
    Dotenv,
    /// A flat `{"NAME": "value"}` object.
    Json,
}

/// Returns the process exit code.
pub fn run(command: Command, styles: &Styles) -> Result<i32> {
    let registry = EnvRegistry::detect()?;

    match command {
        Command::Init {
            id,
            dir,
            default_env,
        } => {
            let root = absolute_dir(dir)?;
            let id = match id {
                Some(id) => id,
                None => default_project_id(&root)?,
            };
            let entry = registry.register(&id, &root, &default_env)?;

            println!("registered {}", entry.id);
            println!("  root:        {}", render::tilde(&entry.root));
            println!("  default env: {}", entry.default_env);
            println!("  metadata:    {}", registry.path().display());
            print_adopted_sync(&registry, &entry)?;
            Ok(0)
        }

        Command::Link {
            project_id,
            project,
            account,
            domain,
            map,
        } => {
            let entry = resolve_project(&registry, project.as_deref())?;
            let account = match account {
                Some(account) => account,
                None => {
                    let paths = Paths::detect()?;
                    infisical::active_account(&paths)?.ok_or_else(|| {
                        anyhow::anyhow!("no infisical login to pin; pass --account <email>")
                    })?
                }
            };
            let updated = registry.set_sync(
                &entry.id,
                SyncConfig {
                    provider: "infisical".to_string(),
                    project_id,
                    account,
                    domain,
                    env_map: parse_env_map(&map)?,
                },
            )?;

            println!("linked {}", updated.id);
            print_sync(&updated);
            Ok(0)
        }

        Command::Projects { json } => {
            let projects = registry.projects()?;
            if json {
                // Machine-readable: JSON only, no ANSI, no extras.
                println!("{}", serde_json::to_string_pretty(&projects)?);
                return Ok(0);
            }
            if projects.is_empty() {
                println!("no projects registered yet");
                println!("  pb env init   (in the directory you want to register)");
                return Ok(0);
            }
            print!("{}", render_projects(&projects, styles));
            Ok(0)
        }

        Command::List { target, json } => {
            let (project, env) = resolve(&registry, &target)?;
            // Names and provenance only: this never opens the keychain.
            let vars = registry.list(&project.id, &env)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&vars)?);
                return Ok(0);
            }
            let synced_at = project.env(&env).and_then(|meta| meta.synced_at);
            print!(
                "{}",
                render_list(&project.id, &env, &vars, synced_at, Utc::now(), styles)
            );
            Ok(0)
        }

        Command::Pull { target, json } => {
            let (project, env) = resolve(&registry, &target)?;
            let paths = Paths::detect()?;
            let outcome = patchbay_core::env_sync::pull(&paths, &registry, &project, &env)?;

            if json {
                println!("{}", serde_json::to_string_pretty(&outcome)?);
                return Ok(0);
            }
            println!(
                "pulled {} variable{} into {}/{}",
                outcome.count,
                plural(outcome.count),
                project.id,
                outcome.env
            );
            println!("  remote environment: {}", outcome.remote_env);
            for note in &outcome.notes {
                println!("  note: {note}");
            }
            println!("  the local layer was not touched — it never is");
            Ok(0)
        }

        Command::Set { name, target } => {
            let (project, env) = resolve(&registry, &target)?;
            let value = read_value(&name, &project.id, &env)?;
            registry.set_local(&project.id, &env, &name, &value)?;
            drop(value);

            println!(
                "set {name} in {}/{env} (local layer — never synced)",
                project.id
            );
            println!("  it survives every `pb env pull`, and patchbay never pushes it anywhere");
            Ok(0)
        }

        Command::Unset { name, target } => {
            let (project, env) = resolve(&registry, &target)?;
            let note = registry.unset_local(&project.id, &env, &name)?;
            println!("unset {name} in {}/{env} (local layer)", project.id);
            if let Some(note) = note {
                println!("  note: {note}");
            }
            Ok(0)
        }

        Command::Import { file, target } => {
            let (project, env) = resolve(&registry, &target)?;
            let text = read_dotenv_file(&file)?;
            let source = describe_source(&file);
            // The parser names line numbers and never the line: a line it could
            // not read is, by definition, a string patchbay does not understand.
            let vars = parse_dotenv(&text)
                .map_err(|e| anyhow::anyhow!("could not read {source} as a .env file: {e}"))?;
            let count = registry.import_local(&project.id, &env, &vars)?;

            if count == 0 {
                println!("{source} held no variables; nothing was imported");
                return Ok(0);
            }
            println!(
                "imported {count} variable{} into {}/{env} (local layer)",
                plural(count),
                project.id
            );
            println!("  patchbay never pushes them anywhere — they stay on this machine");
            Ok(0)
        }

        Command::Diff { target, json } => {
            let (project, env) = resolve(&registry, &target)?;
            let sections = Diff::of(&registry.list(&project.id, &env)?);
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "project": project.id,
                        "env": env,
                        "overrides": sections.overrides,
                        "local_only": sections.local_only,
                        "synced_only": sections.synced_only,
                    }))?
                );
                return Ok(0);
            }
            print!("{}", render_diff(&project.id, &env, &sections, styles));
            Ok(0)
        }

        Command::Run { target, command } => {
            let (project, env) = resolve(&registry, &target)?;
            let merged = registry.merged(&project.id, &env)?;
            let (bin, args) = command
                .split_first()
                .ok_or_else(|| anyhow::anyhow!("nothing to run; pass a command after `--`"))?;

            // stderr, so a command whose stdout is being piped stays clean.
            eprintln!(
                "injecting {} var{} into `{bin}` ({}/{env}: {} synced, {} local)",
                merged.vars.len(),
                plural(merged.vars.len()),
                project.id,
                merged.from_synced.len(),
                merged.from_local.len()
            );

            let mut child = std::process::Command::new(bin);
            child.args(args);
            child
                .env_clear()
                .envs(child_env(std::env::vars_os().collect(), &merged.vars));
            let status = child
                .status()
                .with_context(|| format!("could not run `{bin}`"))?;

            match status.code() {
                Some(code) => Ok(code),
                None => {
                    eprintln!("pb: `{bin}` was killed by a signal");
                    Ok(1)
                }
            }
        }

        Command::Export { target, format } => {
            let (project, env) = resolve(&registry, &target)?;
            let merged = registry.merged(&project.id, &env)?;

            // The warning goes to stderr so a redirect still produces a clean
            // file, and it comes first so it is on screen before the values are.
            if std::io::stdout().is_terminal() {
                eprintln!(
                    "this prints secret values to your terminal; prefer `pb env run -- <cmd>`, \
                     or redirect: pb env export > .env"
                );
            }
            match format {
                ExportFormat::Dotenv => print!("{}", render_dotenv(&merged.vars)),
                ExportFormat::Json => println!("{}", render_json(&merged.vars)?),
            }
            Ok(0)
        }

        Command::Forget { project, yes } => {
            let entry = resolve_project(&registry, project.as_deref())?;
            if !yes && !confirm(&entry)? {
                println!("left {} alone", entry.id);
                return Ok(0);
            }
            let removed = registry.forget(&entry.id)?;

            println!("forgot {} ({})", removed.id, render::tilde(&removed.root));
            println!(
                "  its stored values are gone from the {}",
                registry.store_name()
            );
            println!("  nothing was revoked — whatever the remote holds is untouched");
            Ok(0)
        }
    }
}

// ---------------------------------------------------------------------------
// resolution
// ---------------------------------------------------------------------------

/// The project and environment a command acts on: the flags if given, this
/// directory's project and its own default otherwise.
fn resolve(registry: &EnvRegistry, target: &Target) -> Result<(ProjectEntry, String)> {
    let project = resolve_project(registry, target.project.as_deref())?;
    let env = target
        .env
        .clone()
        .unwrap_or_else(|| project.default_env.clone());
    Ok((project, env))
}

fn resolve_project(registry: &EnvRegistry, id: Option<&str>) -> Result<ProjectEntry> {
    if let Some(id) = id {
        return registry.get(id)?.ok_or_else(|| {
            anyhow::anyhow!("no project registered as `{id}`; `pb env projects` lists them")
        });
    }
    let dir = std::env::current_dir().context("could not read the current directory")?;
    registry.find_by_dir(&dir)?.ok_or_else(|| {
        anyhow::anyhow!(
            "no project registered for this directory; run `pb env init` here, or pass \
             --project <id> (pb env projects lists them)"
        )
    })
}

/// `--dir` made absolute, or the current directory. Relative paths are joined
/// onto the cwd rather than canonicalized: the registry compares roots by path
/// prefix, and resolving symlinks here would make the answer depend on the
/// filesystem's mood.
fn absolute_dir(dir: Option<PathBuf>) -> Result<PathBuf> {
    let raw = match dir {
        Some(dir) => dir,
        None => return std::env::current_dir().context("could not read the current directory"),
    };
    let joined = if raw.is_absolute() {
        raw
    } else {
        std::env::current_dir()
            .context("could not read the current directory")?
            .join(raw)
    };
    // Drops `.` components, so `--dir .` records the directory, not `…/.`.
    Ok(joined.components().collect())
}

/// The default id for a directory: its own name, lowercased, with everything a
/// slug cannot hold folded to `-`.
fn default_project_id(root: &Path) -> Result<String> {
    let slug = slugify_dir_name(root).ok_or_else(|| {
        anyhow::anyhow!(
            "{} has no directory name to take an id from; pass --id <slug>",
            root.display()
        )
    })?;
    validate_project_id(&slug)
        .map_err(|e| anyhow::anyhow!("{e}; pass --id <slug> to name this project yourself"))?;
    Ok(slug)
}

fn slugify_dir_name(root: &Path) -> Option<String> {
    let name = root.file_name()?.to_string_lossy().to_ascii_lowercase();
    if name.is_empty() {
        return None;
    }
    Some(
        name.chars()
            .map(|c| {
                if c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '-') {
                    c
                } else {
                    '-'
                }
            })
            .collect(),
    )
}

/// `--map production=prod,dev=development` as a patchbay→remote name map.
fn parse_env_map(pairs: &[String]) -> Result<BTreeMap<String, String>> {
    let mut map = BTreeMap::new();
    for pair in pairs {
        let pair = pair.trim();
        // A trailing comma is a typo, not an instruction.
        if pair.is_empty() {
            continue;
        }
        let (local, remote) = pair.split_once('=').ok_or_else(|| {
            anyhow::anyhow!(
                "`{pair}` is not `local=remote`; --map takes comma-separated pairs, \
                 e.g. --map production=prod"
            )
        })?;
        let (local, remote) = (local.trim(), remote.trim());
        if local.is_empty() || remote.is_empty() {
            anyhow::bail!("`{pair}` has an empty side; --map takes `local=remote` pairs");
        }
        map.insert(local.to_string(), remote.to_string());
    }
    Ok(map)
}

// ---------------------------------------------------------------------------
// .infisical.json
// ---------------------------------------------------------------------------

/// The two fields patchbay reads out of a repo's `.infisical.json`.
#[derive(Debug, Default, PartialEq, Eq)]
struct InfisicalProject {
    workspace_id: Option<String>,
    default_environment: Option<String>,
}

/// Read those two fields, ignoring everything else in the file — it holds
/// several more keys and they change between CLI releases.
fn parse_infisical_json(text: &str) -> Result<InfisicalProject> {
    let value: serde_json::Value =
        serde_json::from_str(text).map_err(|e| anyhow::anyhow!("it is not valid JSON ({e})"))?;
    if !value.is_object() {
        anyhow::bail!("it is not a JSON object");
    }
    let field = |name: &str| {
        value
            .get(name)
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
    };
    Ok(InfisicalProject {
        workspace_id: field("workspaceId"),
        default_environment: field("defaultEnvironment"),
    })
}

/// Record the sync a freshly registered project's `.infisical.json` implies,
/// and say what happened either way.
///
/// A malformed file is a note, not a failure: the project is registered, and
/// `pb env link` can do by hand what this could not do automatically.
fn print_adopted_sync(registry: &EnvRegistry, entry: &ProjectEntry) -> Result<()> {
    let path = entry.root.join(INFISICAL_FILE);
    let Ok(text) = std::fs::read_to_string(&path) else {
        println!("  hint: link it with `pb env link --project-id <infisical project id>`");
        return Ok(());
    };
    let file = match parse_infisical_json(&text) {
        Ok(file) => file,
        Err(e) => {
            println!("  note: {INFISICAL_FILE} is here but patchbay could not read it: {e}");
            println!("  hint: link it with `pb env link --project-id <infisical project id>`");
            return Ok(());
        }
    };

    match (&file.workspace_id, active_account_or_none()) {
        (Some(workspace_id), Some(account)) => {
            let linked = registry.set_sync(
                &entry.id,
                SyncConfig {
                    provider: "infisical".to_string(),
                    project_id: workspace_id.clone(),
                    account,
                    domain: None,
                    env_map: BTreeMap::new(),
                },
            )?;
            println!("  read {INFISICAL_FILE} in the project root");
            print_sync(&linked);
        }
        (Some(workspace_id), None) => {
            println!("  read {INFISICAL_FILE}: infisical project {workspace_id}");
            println!(
                "  no infisical login on this machine to pin it to, so nothing was linked; \
                 run `infisical login`, then `pb env link --project-id {workspace_id}`"
            );
        }
        (None, _) => {
            println!("  note: {INFISICAL_FILE} names no workspaceId");
            println!("  hint: link it with `pb env link --project-id <infisical project id>`");
        }
    }

    // Applying the remote's own default silently would mean a `pb env pull`
    // that quietly reads a different environment than the one it names.
    if let Some(remote_default) = &file.default_environment {
        if remote_default != &entry.default_env {
            println!(
                "  hint: {INFISICAL_FILE} calls its default environment `{remote_default}`; if \
                 that is this project's `{}`, record it with `pb env link --project-id <id> \
                 --map {}={remote_default}`",
                entry.default_env, entry.default_env
            );
        }
    }
    Ok(())
}

/// The active infisical login, or `None` when there is none *or* when the
/// machine cannot be asked. Neither is a reason to fail a registration.
fn active_account_or_none() -> Option<String> {
    let paths = Paths::detect().ok()?;
    infisical::active_account(&paths).ok().flatten()
}

fn print_sync(entry: &ProjectEntry) {
    let Some(sync) = &entry.sync else {
        return;
    };
    println!("  sync:        {} {}", sync.provider, sync.project_id);
    println!("  account:     {}", sync.account);
    if let Some(domain) = &sync.domain {
        println!("  domain:      {domain}");
    }
    if !sync.env_map.is_empty() {
        let pairs: Vec<String> = sync
            .env_map
            .iter()
            .map(|(local, remote)| format!("{local}→{remote}"))
            .collect();
        println!("  env map:     {}", pairs.join(", "));
    }
    println!(
        "  the sync is pinned to this account: pulls will refuse under any other infisical login"
    );
}

// ---------------------------------------------------------------------------
// input
// ---------------------------------------------------------------------------

/// Read the value from a pipe, or prompt for it without echo. Never argv:
/// that is world-readable through `ps` and lands in `~/.zsh_history` verbatim.
fn read_value(name: &str, project: &str, env: &str) -> Result<String> {
    let stdin = std::io::stdin();
    if stdin.is_terminal() {
        let value = rpassword::prompt_password(format!(
            "value for {name} in {project}/{env} (not echoed): "
        ))
        .context("could not read the value from the terminal")?;
        if value.is_empty() {
            anyhow::bail!("no value entered");
        }
        return Ok(value);
    }
    let mut buf = String::new();
    stdin
        .lock()
        .read_to_string(&mut buf)
        .context("could not read the value from stdin")?;
    let value = buf.trim_end_matches(['\n', '\r']).to_string();
    if value.is_empty() {
        anyhow::bail!(
            "nothing on stdin; pipe the value in, or run this from a terminal to be prompted"
        );
    }
    Ok(value)
}

/// A `.env` file, or stdin for `-`.
fn read_dotenv_file(file: &Path) -> Result<String> {
    if file == Path::new("-") {
        let mut buf = String::new();
        std::io::stdin()
            .lock()
            .read_to_string(&mut buf)
            .context("could not read the .env from stdin")?;
        return Ok(buf);
    }
    std::fs::read_to_string(file).with_context(|| format!("could not read {}", file.display()))
}

fn describe_source(file: &Path) -> String {
    if file == Path::new("-") {
        "stdin".to_string()
    } else {
        file.display().to_string()
    }
}

/// `y`/`yes` on stdin. Anything else, including EOF, means no.
fn confirm(entry: &ProjectEntry) -> Result<bool> {
    let envs = entry.environments.len();
    print!(
        "forget {} ({envs} environment{}) and delete its stored values from the keychain? [y/N] ",
        entry.id,
        plural(envs)
    );
    std::io::stdout().flush().ok();
    let mut answer = String::new();
    if std::io::stdin()
        .read_line(&mut answer)
        .context("could not read the answer")?
        == 0
    {
        println!();
        return Ok(false);
    }
    Ok(matches!(
        answer.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
}

// ---------------------------------------------------------------------------
// the child environment
// ---------------------------------------------------------------------------

/// This process's environment with the vault's values laid over it.
///
/// Built explicitly rather than left to `Command`'s own overlay so the result
/// is a value a test can inspect: the merged environment must win over an
/// inherited variable of the same name, which is the whole point of `pb env
/// run` in a shell that already exported a stale `DATABASE_URL`.
fn child_env(
    inherited: Vec<(OsString, OsString)>,
    merged: &BTreeMap<String, String>,
) -> Vec<(OsString, OsString)> {
    let mut out: Vec<(OsString, OsString)> = inherited
        .into_iter()
        .filter(|(name, _)| match name.to_str() {
            Some(name) => !merged.contains_key(name),
            // A name that is not UTF-8 cannot collide with a vault name, which
            // the core validates as `[A-Za-z_][A-Za-z0-9_]*`.
            None => true,
        })
        .collect();
    out.extend(
        merged
            .iter()
            .map(|(name, value)| (OsString::from(name), OsString::from(value))),
    );
    out
}

// ---------------------------------------------------------------------------
// output
// ---------------------------------------------------------------------------

/// Names only, in three buckets. Values never enter this type.
#[derive(Debug, Default, PartialEq, Eq)]
struct Diff {
    /// Local names shadowing a synced one.
    overrides: Vec<String>,
    /// Set here and nowhere else.
    local_only: Vec<String>,
    /// Pulled, and not overridden here.
    synced_only: Vec<String>,
}

impl Diff {
    fn of(vars: &[EnvVarInfo]) -> Self {
        let take = |want: EnvVarSource| -> Vec<String> {
            vars.iter()
                .filter(|v| v.source == want)
                .map(|v| v.name.clone())
                .collect()
        };
        Self {
            overrides: take(EnvVarSource::LocalOverride),
            local_only: take(EnvVarSource::Local),
            synced_only: take(EnvVarSource::Synced),
        }
    }

    fn is_empty(&self) -> bool {
        self.overrides.is_empty() && self.local_only.is_empty() && self.synced_only.is_empty()
    }
}

/// A flat `{"NAME": "value"}` object, built by hand: `MergedEnv` deliberately
/// does not derive `Serialize`, and this is the one place that is on purpose.
fn render_json(vars: &BTreeMap<String, String>) -> Result<String> {
    let mut object = serde_json::Map::new();
    for (name, value) in vars {
        object.insert(name.clone(), serde_json::Value::String(value.clone()));
    }
    Ok(serde_json::to_string_pretty(&serde_json::Value::Object(
        object,
    ))?)
}

fn plural(n: usize) -> &'static str {
    if n == 1 {
        ""
    } else {
        "s"
    }
}

fn pad(s: &str, width: usize) -> String {
    let len = s.chars().count();
    if len >= width {
        s.to_string()
    } else {
        format!("{s}{}", " ".repeat(width - len))
    }
}

/// Width of a column: the widest value in it, bounded by `max`, never narrower
/// than its header.
fn column_width(values: impl Iterator<Item = usize>, header: &str, max: usize) -> usize {
    values
        .chain(std::iter::once(header.len()))
        .max()
        .unwrap_or(header.len())
        .min(max)
        .max(header.len())
}

/// The project table. Roots are long, so ROOT takes whatever the other columns
/// leave and gets truncated into it.
pub fn render_projects(projects: &[ProjectEntry], styles: &Styles) -> String {
    let sync_cell = |p: &ProjectEntry| match &p.sync {
        Some(sync) => format!("{}:{}", sync.provider, sync.account),
        None => DASH.to_string(),
    };
    let envs_cell = |p: &ProjectEntry| {
        let names = p.env_names();
        if names.is_empty() {
            DASH.to_string()
        } else {
            names.join(",")
        }
    };

    let id_w = column_width(
        projects.iter().map(|p| p.id.chars().count()),
        "ID",
        COL_ID_MAX,
    );
    let envs_w = column_width(
        projects.iter().map(|p| envs_cell(p).chars().count()),
        "ENVS",
        COL_ENVS_MAX,
    );
    let sync_w = column_width(
        projects.iter().map(|p| sync_cell(p).chars().count()),
        "SYNC",
        COL_SYNC_MAX,
    );
    let fixed = id_w + envs_w + sync_w + GAP * 3;
    let root_w = TABLE_WIDTH.saturating_sub(fixed).max(16);

    let gap = " ".repeat(GAP);
    let mut out = String::new();

    let header = format!(
        "{}{gap}{}{gap}{}{gap}{}",
        pad("ID", id_w),
        pad("ROOT", root_w),
        pad("ENVS", envs_w),
        "SYNC",
    );
    out.push_str(&styles.paint(bold(), header.trim_end()));
    out.push('\n');

    for project in projects {
        let id = pad(&render::truncate(&project.id, id_w), id_w);
        let root = pad(
            &render::truncate(&render::tilde(&project.root), root_w),
            root_w,
        );
        let envs = pad(&render::truncate(&envs_cell(project), envs_w), envs_w);
        let sync = render::truncate(&sync_cell(project), sync_w);
        // An unlinked project is a fact about the project, not a warning.
        let sync = if project.sync.is_none() {
            styles.paint(dim(), &sync)
        } else {
            sync
        };

        let line = format!("{id}{gap}{root}{gap}{envs}{gap}{sync}");
        out.push_str(line.trim_end());
        out.push('\n');
    }
    out
}

/// One environment's names and where each came from, under a line saying what
/// the environment is. `now` is injected so this is testable without a clock.
pub fn render_list(
    project: &str,
    env: &str,
    vars: &[EnvVarInfo],
    synced_at: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
    styles: &Styles,
) -> String {
    let count = |want: EnvVarSource| vars.iter().filter(|v| v.source == want).count();
    let overrides = count(EnvVarSource::LocalOverride);
    let synced = count(EnvVarSource::Synced) + overrides;
    let local = count(EnvVarSource::Local) + overrides;
    // A synced layer that has never been pulled is not "0 seconds old".
    let when = match synced_at {
        Some(at) => format!("synced {}", render::humanize_ago(now, at)),
        None => "never pulled".to_string(),
    };

    let mut out = format!(
        "{project}/{env} · {} variable{} · {synced} synced · {local} local · {overrides} \
         override{} · {when}\n",
        vars.len(),
        plural(vars.len()),
        plural(overrides)
    );
    if vars.is_empty() {
        out.push_str("  nothing here yet — `pb env pull` fills the synced layer, `pb env set` the local one\n");
        return out;
    }

    let name_w = column_width(
        vars.iter().map(|v| v.name.chars().count()),
        "NAME",
        COL_NAME_MAX,
    );
    let gap = " ".repeat(GAP);
    let header = format!("{}{gap}{}", pad("NAME", name_w), "SOURCE");
    out.push_str(&styles.paint(bold(), header.trim_end()));
    out.push('\n');

    for var in vars {
        let name = pad(&render::truncate(&var.name, name_w), name_w);
        let label = pad(var.source.label(), COL_SOURCE);
        // An override is the one row that changes what a consumer sees, so it
        // is the one row worth colouring.
        let source = match var.source {
            EnvVarSource::LocalOverride => styles.paint(yellow(), &label),
            EnvVarSource::Local => label,
            EnvVarSource::Synced => styles.paint(dim(), &label),
        };
        let line = format!("{name}{gap}{source}");
        out.push_str(line.trim_end());
        out.push('\n');
    }
    out
}

fn render_diff(project: &str, env: &str, diff: &Diff, styles: &Styles) -> String {
    let mut out = format!("{project}/{env}\n");
    if diff.is_empty() {
        out.push_str("  no variables in either layer\n");
        return out;
    }
    let mut section = |title: &str, names: &[String], style: anstyle::Style| {
        if names.is_empty() {
            return;
        }
        out.push_str(&styles.paint(style, &format!("  {title} ({})", names.len())));
        out.push('\n');
        for name in names {
            out.push_str(&format!("    {name}\n"));
        }
    };
    section(
        "local overrides — shadowing a synced value",
        &diff.overrides,
        yellow(),
    );
    section(
        "local only — never pushed anywhere",
        &diff.local_only,
        bold(),
    );
    section(
        "synced only — replaced by the next pull",
        &diff.synced_only,
        dim(),
    );
    out
}

fn bold() -> anstyle::Style {
    anstyle::Style::new() | anstyle::Effects::BOLD
}

fn dim() -> anstyle::Style {
    anstyle::Style::new() | anstyle::Effects::DIMMED
}

fn yellow() -> anstyle::Style {
    anstyle::Style::new().fg_color(Some(anstyle::AnsiColor::Yellow.into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;
    use patchbay_core::keystore::MemoryKeystore;

    fn now() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc)
    }

    /// A vault in a tempdir over a fake keystore. Nothing here touches the real
    /// `$HOME`, the real keychain or a real process.
    fn vault() -> (tempfile::TempDir, EnvRegistry) {
        let dir = tempfile::tempdir().unwrap();
        let registry = EnvRegistry::new(
            dir.path().join("projects.json"),
            Box::new(MemoryKeystore::new()),
        );
        (dir, registry)
    }

    /// One project, one environment, both layers, one override.
    fn seeded(registry: &EnvRegistry) {
        registry
            .register("pathors", "/repos/pathors", "dev")
            .unwrap();
        registry
            .replace_synced(
                "pathors",
                "dev",
                [
                    ("API_KEY".to_string(), "remote-key".to_string()),
                    ("DATABASE_URL".to_string(), "postgres://remote".to_string()),
                ]
                .into_iter()
                .collect(),
                now() - Duration::hours(2),
            )
            .unwrap();
        registry
            .set_local("pathors", "dev", "DATABASE_URL", "postgres://localhost")
            .unwrap();
        registry
            .set_local("pathors", "dev", "MY_FLAG", "true")
            .unwrap();
    }

    fn var(name: &str, source: EnvVarSource) -> EnvVarInfo {
        EnvVarInfo {
            name: name.to_string(),
            source,
        }
    }

    // --- tables -------------------------------------------------------------

    #[test]
    fn test_projects_table_is_plain_and_aligned_without_color() {
        let (_dir, registry) = vault();
        seeded(&registry);
        registry
            .register("side", "/repos/side-project", "dev")
            .unwrap();
        registry
            .set_sync(
                "pathors",
                SyncConfig {
                    provider: "infisical".into(),
                    project_id: "3ab516bd".into(),
                    account: "contact@pathors.com".into(),
                    domain: None,
                    env_map: BTreeMap::new(),
                },
            )
            .unwrap();

        let projects = registry.projects().unwrap();
        let out = render_projects(&projects, &Styles::new(false));
        assert!(!out.contains('\u{1b}'), "plain mode must emit no ANSI");

        let lines: Vec<&str> = out.lines().collect();
        assert!(lines[0].starts_with("ID"), "{out}");
        assert_eq!(lines.len(), 3, "{out}");
        assert!(lines[1].contains("/repos/pathors"), "{out}");
        assert!(lines[1].contains("dev"), "{out}");
        assert!(lines[1].contains("infisical:contact@pathors.com"), "{out}");
        // An unlinked project with no environments shows dashes, not blanks.
        assert!(lines[2].contains(DASH), "{out}");

        // Every column starts at the same offset on every row.
        let col = lines[0].find("ROOT").unwrap();
        assert!(lines[1][col..].starts_with("/repos/pathors"), "{out}");
        assert!(lines[2][col..].starts_with("/repos/side-project"), "{out}");
    }

    #[test]
    fn test_list_names_the_layers_and_never_shows_a_value() {
        let (_dir, registry) = vault();
        seeded(&registry);

        let vars = registry.list("pathors", "dev").unwrap();
        let synced_at = registry.get("pathors").unwrap().unwrap().environments["dev"].synced_at;
        let out = render_list(
            "pathors",
            "dev",
            &vars,
            synced_at,
            now(),
            &Styles::new(false),
        );
        assert!(!out.contains('\u{1b}'), "plain mode must emit no ANSI");

        let lines: Vec<&str> = out.lines().collect();
        // The header line says what this environment is before the table does.
        assert!(lines[0].starts_with("pathors/dev · 3 variables"), "{out}");
        assert!(lines[0].contains("2 synced"), "{out}");
        assert!(lines[0].contains("2 local"), "{out}");
        assert!(lines[0].contains("1 override"), "{out}");
        assert!(lines[0].contains("synced 2h ago"), "{out}");
        assert!(lines[1].starts_with("NAME"), "{out}");

        assert!(lines[2].starts_with("API_KEY"), "{out}");
        assert!(lines[2].ends_with("synced"), "{out}");
        assert!(lines[3].contains("local override"), "{out}");
        assert!(lines[4].contains("MY_FLAG"), "{out}");
        assert_eq!(lines.len(), 5, "{out}");

        // Not one value from either layer reached the screen.
        for value in [
            "postgres://localhost",
            "postgres://remote",
            "remote-key",
            "true",
        ] {
            assert!(!out.contains(value), "`{value}` leaked into {out}");
        }
    }

    #[test]
    fn test_a_never_pulled_environment_says_so_rather_than_showing_an_age() {
        let out = render_list(
            "pathors",
            "dev",
            &[var("MY_FLAG", EnvVarSource::Local)],
            None,
            now(),
            &Styles::new(false),
        );
        assert!(out.contains("never pulled"), "{out}");
        assert!(out.contains("1 variable ·"), "{out}");
        assert!(!out.contains("ago"), "{out}");
    }

    #[test]
    fn test_an_empty_environment_says_how_to_fill_it() {
        let out = render_list("pathors", "dev", &[], None, now(), &Styles::new(false));
        assert!(out.contains("0 variables"), "{out}");
        assert!(out.contains("pb env pull"), "{out}");
        assert!(!out.contains("NAME"), "{out}");
    }

    #[test]
    fn test_an_override_is_coloured_when_color_is_on() {
        let out = render_list(
            "pathors",
            "dev",
            &[var("DATABASE_URL", EnvVarSource::LocalOverride)],
            None,
            now(),
            &Styles::new(true),
        );
        assert!(out.contains('\u{1b}'), "{out}");
        assert!(out.contains("local override"), "{out}");
    }

    // --- diff ---------------------------------------------------------------

    #[test]
    fn test_diff_buckets_by_source_and_prints_names_only() {
        let (_dir, registry) = vault();
        seeded(&registry);

        let diff = Diff::of(&registry.list("pathors", "dev").unwrap());
        assert_eq!(diff.overrides, vec!["DATABASE_URL"]);
        assert_eq!(diff.local_only, vec!["MY_FLAG"]);
        assert_eq!(diff.synced_only, vec!["API_KEY"]);

        let out = render_diff("pathors", "dev", &diff, &Styles::new(false));
        assert!(out.starts_with("pathors/dev\n"), "{out}");
        assert!(out.contains("local overrides"), "{out}");
        assert!(out.contains("local only"), "{out}");
        assert!(out.contains("synced only"), "{out}");
        assert!(out.contains("    DATABASE_URL\n"), "{out}");
        assert!(!out.contains("postgres"), "{out}");

        // The sections are in order: what shadows, what is only here, what is
        // only there.
        let at = |needle: &str| out.find(needle).unwrap();
        assert!(at("local overrides") < at("local only"), "{out}");
        assert!(at("local only") < at("synced only"), "{out}");
    }

    #[test]
    fn test_diff_skips_empty_sections_and_says_when_there_is_nothing() {
        let diff = Diff::of(&[var("MY_FLAG", EnvVarSource::Local)]);
        let out = render_diff("pathors", "dev", &diff, &Styles::new(false));
        assert!(out.contains("local only"), "{out}");
        assert!(out.contains("(1)"), "{out}");
        assert!(!out.contains("synced only"), "{out}");
        assert!(!out.contains("local overrides"), "{out}");

        let out = render_diff("pathors", "dev", &Diff::default(), &Styles::new(false));
        assert!(out.contains("no variables in either layer"), "{out}");
    }

    // --- export -------------------------------------------------------------

    #[test]
    fn test_export_renders_dotenv_and_json_from_the_same_merged_values() {
        let (_dir, registry) = vault();
        seeded(&registry);
        let merged = registry.merged("pathors", "dev").unwrap();

        // The local layer wins, which is the whole reason it exists.
        let dotenv = render_dotenv(&merged.vars);
        assert_eq!(
            dotenv,
            "API_KEY='remote-key'\nDATABASE_URL='postgres://localhost'\nMY_FLAG='true'\n"
        );

        let json = render_json(&merged.vars).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["DATABASE_URL"], "postgres://localhost");
        assert_eq!(parsed["MY_FLAG"], "true");
        assert_eq!(parsed.as_object().unwrap().len(), 3);
        // A flat object of strings — no layer metadata smuggled alongside.
        assert!(parsed.as_object().unwrap().values().all(|v| v.is_string()));
    }

    #[test]
    fn test_export_json_quotes_what_dotenv_would_have_to_escape() {
        let vars: BTreeMap<String, String> = [
            ("A".to_string(), "line\nbreak".to_string()),
            ("B".to_string(), "it's".to_string()),
        ]
        .into_iter()
        .collect();

        assert_eq!(
            render_dotenv(&vars),
            "A=\"line\\nbreak\"\nB='it'\\''s'\n",
            "the core's dotenv quoting is what keeps this one line per variable"
        );
        let parsed: serde_json::Value = serde_json::from_str(&render_json(&vars).unwrap()).unwrap();
        assert_eq!(parsed["A"], "line\nbreak");
        assert_eq!(parsed["B"], "it's");
    }

    // --- run ----------------------------------------------------------------

    #[test]
    fn test_the_child_environment_puts_the_vault_over_what_was_inherited() {
        let inherited: Vec<(OsString, OsString)> = [
            ("PATH", "/usr/bin"),
            ("DATABASE_URL", "postgres://stale-shell-export"),
        ]
        .into_iter()
        .map(|(k, v)| (OsString::from(k), OsString::from(v)))
        .collect();
        let merged: BTreeMap<String, String> = [
            (
                "DATABASE_URL".to_string(),
                "postgres://localhost".to_string(),
            ),
            ("MY_FLAG".to_string(), "true".to_string()),
        ]
        .into_iter()
        .collect();

        let env = child_env(inherited, &merged);
        let lookup = |name: &str| {
            env.iter()
                .filter(|(k, _)| k == name)
                .map(|(_, v)| v.to_string_lossy().to_string())
                .collect::<Vec<_>>()
        };

        // The vault wins, and it wins exactly once: a duplicated name would let
        // the child's own lookup decide which value it got.
        assert_eq!(lookup("DATABASE_URL"), vec!["postgres://localhost"]);
        assert_eq!(lookup("MY_FLAG"), vec!["true"]);
        // Everything else is inherited untouched.
        assert_eq!(lookup("PATH"), vec!["/usr/bin"]);
        assert_eq!(env.len(), 3);
    }

    // --- init --------------------------------------------------------------

    #[test]
    fn test_the_default_id_is_the_directory_name_as_a_slug() {
        let id = |path: &str| default_project_id(Path::new(path));
        assert_eq!(id("/repos/pathors").unwrap(), "pathors");
        assert_eq!(id("/repos/Patchbay").unwrap(), "patchbay");
        assert_eq!(id("/repos/my repo (old)").unwrap(), "my-repo--old-");
        assert_eq!(id("/repos/app.v2_final").unwrap(), "app.v2_final");
        // Non-ASCII is not a slug character, so it folds like anything else.
        assert_eq!(id("/repos/app專案").unwrap(), "app--");
    }

    #[test]
    fn test_a_name_that_cannot_be_a_slug_asks_for_one() {
        // A leading dot survives slugification but is not a legal id start.
        let err = default_project_id(Path::new("/repos/.hidden"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("must start with a letter or digit"), "{err}");
        assert!(err.contains("--id"), "{err}");

        // Same for a name whose *first* character is one patchbay had to fold.
        let err = default_project_id(Path::new("/repos/專案"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("must start with a letter or digit"), "{err}");

        let err = default_project_id(Path::new("/")).unwrap_err().to_string();
        assert!(err.contains("no directory name"), "{err}");
    }

    #[test]
    fn test_env_map_pairs_parse_and_a_malformed_one_is_named() {
        let pairs =
            |raw: &[&str]| parse_env_map(&raw.iter().map(|s| s.to_string()).collect::<Vec<_>>());

        let map = pairs(&["production=prod", " dev = development "]).unwrap();
        assert_eq!(map["production"], "prod");
        assert_eq!(map["dev"], "development");
        assert_eq!(map.len(), 2);
        // A trailing comma is a typo, not an instruction.
        assert_eq!(pairs(&["production=prod", ""]).unwrap().len(), 1);
        assert!(pairs(&[]).unwrap().is_empty());

        let err = pairs(&["production"]).unwrap_err().to_string();
        assert!(err.contains("is not `local=remote`"), "{err}");
        let err = pairs(&["=prod"]).unwrap_err().to_string();
        assert!(err.contains("empty side"), "{err}");
    }

    #[test]
    fn test_infisical_json_is_read_tolerantly() {
        let file = parse_infisical_json(
            r#"{"workspaceId":"3ab516bd-248c","defaultEnvironment":"prod",
                "gitBranchToEnvironmentMapping":null,"somethingNew":42}"#,
        )
        .unwrap();
        assert_eq!(file.workspace_id.as_deref(), Some("3ab516bd-248c"));
        assert_eq!(file.default_environment.as_deref(), Some("prod"));

        // The CLI writes an empty default environment far more often than a
        // useful one, and empty is not a name.
        let file =
            parse_infisical_json(r#"{"workspaceId":"abc","defaultEnvironment":""}"#).unwrap();
        assert_eq!(file.default_environment, None);
        assert_eq!(
            parse_infisical_json("{}").unwrap(),
            InfisicalProject::default()
        );

        // Malformed is an error the caller turns into a note, not a panic.
        let err = parse_infisical_json("{not json").unwrap_err().to_string();
        assert!(err.contains("not valid JSON"), "{err}");
        let err = parse_infisical_json("[]").unwrap_err().to_string();
        assert!(err.contains("not a JSON object"), "{err}");
    }

    #[test]
    fn test_forgetting_a_project_takes_every_stored_layer_with_it() {
        let (_dir, registry) = vault();
        seeded(&registry);
        assert!(registry
            .get("pathors")
            .unwrap()
            .unwrap()
            .env("dev")
            .is_some());

        let removed = registry.forget("pathors").unwrap();
        assert_eq!(removed.id, "pathors");
        assert!(registry.projects().unwrap().is_empty());
        // And the reason `pb env forget` says nothing was revoked: the keychain
        // items are gone, the remote's copies are not ours to touch.
        assert!(registry.get("pathors").unwrap().is_none());
    }
}
