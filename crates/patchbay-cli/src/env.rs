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
    parse_dotenv, read_marker, render_dotenv, validate_project_id, write_marker, Attachment,
    EnvRegistry, EnvVarInfo, EnvVarSource, ProjectEntry, SyncConfig, DEFAULT_ENV,
    DEFAULT_SECRET_PATH, MARKER_FILE,
};
use patchbay_core::paths::Paths;
use patchbay_core::probes::infisical;

use crate::render::{self, Styles};

/// Width budget for the tables, matching the status board.
const TABLE_WIDTH: usize = 100;
const GAP: usize = 2;
const COL_ID_MAX: usize = 24;
const COL_ENVS_MAX: usize = 22;
/// Wide enough for `infisical:` plus a work email plus a short secret path —
/// the SYNC cell's three parts, and the last one is the one a reader cannot
/// reconstruct from anywhere else. The column only grows to what the rows
/// need, so projects pulling from the root are no wider than they were.
const COL_SYNC_MAX: usize = 42;
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
    /// Writes a `.patchbay.toml` marker in the directory naming the project:
    /// commit it, and every checkout of the repo resolves to this project
    /// without an attach step. Re-running this in another worktree of a project
    /// that already exists attaches that directory instead of failing, and
    /// running it in a fresh clone that carries a marker registers the project
    /// the repo names.
    ///
    /// Reads `.infisical.json` if the directory has one, and records the sync
    /// automatically when this machine is logged in to infisical.
    Init {
        /// Project id. Defaults to what the directory's `.patchbay.toml` names,
        /// and to the directory's own name as a slug when there is none.
        #[arg(long, value_name = "SLUG")]
        id: Option<String>,
        /// The directory to register. Defaults to the current one.
        #[arg(long, value_name = "PATH")]
        dir: Option<PathBuf>,
        /// Environment `pb env` uses when a command does not say.
        #[arg(long, value_name = "ENV", default_value = DEFAULT_ENV)]
        default_env: String,
        /// Do not write the `.patchbay.toml` marker. This machine's attachment
        /// still resolves the directory; other checkouts will not.
        #[arg(long)]
        no_marker: bool,
    },
    /// Bind a directory on this machine to a project that already exists.
    ///
    /// This is the machine-local, deliberate binding, and it OVERRIDES any
    /// `.patchbay.toml` marker committed in the repo: what the person at the
    /// keyboard says beats what the repo ships, and nothing in a repo can take
    /// that back. Use it for a worktree, a second clone, or a checkout whose
    /// marker names the wrong project.
    Attach {
        /// Project id, as `pb env projects` lists it.
        #[arg(value_name = "ID")]
        project: String,
        /// The directory to bind. Defaults to the current one.
        #[arg(long, value_name = "PATH")]
        dir: Option<PathBuf>,
    },
    /// Unbind a directory. The project, its environments and its values stay,
    /// and a committed `.patchbay.toml` keeps resolving the directory.
    Detach {
        /// The directory to unbind. Defaults to the current one.
        #[arg(long, value_name = "PATH")]
        dir: Option<PathBuf>,
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
        /// Folder inside the Infisical project to pull from: `--path /outbox`.
        /// Defaults to `/`, the root — which holds nothing at all in a project
        /// that keeps a folder per service.
        #[arg(long, value_name = "PATH")]
        path: Option<String>,
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
            no_marker,
        } => {
            let root = absolute_dir(dir)?;
            let done = init(&registry, &root, id.as_deref(), &default_env, !no_marker)?;

            if done.shared {
                println!(
                    "attached {} to {}",
                    render::tilde(&done.attachment.root),
                    done.entry.id
                );
                println!(
                    "  this checkout now shares project `{}`'s environments",
                    done.entry.id
                );
            } else {
                println!("registered {}", done.entry.id);
                println!("  attached:    {}", render::tilde(&done.attachment.root));
            }
            println!("  default env: {}", done.entry.default_env);
            if let Some(marker) = &done.marker {
                if done.marker_was_there {
                    println!(
                        "  marker:      {} (already names this project)",
                        render::tilde(marker)
                    );
                } else {
                    println!("  marker:      {}", render::tilde(marker));
                    println!(
                        "  commit it and every checkout of this repo — any machine, any \
                         worktree — resolves to this project"
                    );
                }
            }
            println!("  metadata:    {}", registry.path().display());

            if done.shared {
                // The project already exists, so its link is already decided.
                // Re-reading this checkout's `.infisical.json` here could
                // silently replace an env map somebody set by hand.
                print_sync(&done.entry);
            } else {
                print_adopted_sync(&registry, &done.entry, &root)?;
            }
            Ok(0)
        }

        Command::Attach { project, dir } => {
            let entry = resolve_project(&registry, Some(&project))?;
            let root = absolute_dir(dir)?;
            let attachment = registry.attach(&root, &entry.id)?;

            println!(
                "attached {} to {}",
                render::tilde(&attachment.root),
                entry.id
            );
            println!("  default env: {}", entry.default_env);
            // A marker patchbay cannot read is not worth failing an attachment
            // that already succeeded over — `pb env list` will say so loudly
            // enough, and this line is only ever a note.
            if let Some(claimed) = read_marker(&root).ok().flatten() {
                if claimed != entry.id {
                    println!(
                        "  note: {MARKER_FILE} here names `{claimed}`; this attachment overrides \
                         it on this machine"
                    );
                }
            }
            println!(
                "  an attachment is machine-local: it beats any {MARKER_FILE} the repo commits, \
                 and it does not travel"
            );
            Ok(0)
        }

        Command::Detach { dir } => {
            let root = absolute_dir(dir)?;
            let gone = registry.detach(&root)?;

            println!(
                "detached {} from {}",
                render::tilde(&gone.root),
                gone.project
            );
            println!("  the project, its environments and its values are untouched");
            if let Some(claimed) = read_marker(&root).ok().flatten() {
                println!(
                    "  {MARKER_FILE} here still names `{claimed}`, so this directory resolves to \
                     it again; `rm {MARKER_FILE}` if the repo should stop claiming it"
                );
            }
            Ok(0)
        }

        Command::Link {
            project_id,
            project,
            account,
            path,
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
                    // `link` replaces the whole config, so an omitted --path
                    // means the root here rather than "keep the old folder" —
                    // the same rule --domain and --map have always followed.
                    // `set_sync` normalises the spelling.
                    secret_path: path.unwrap_or_else(|| DEFAULT_SECRET_PATH.to_string()),
                },
            )?;

            println!("linked {}", updated.id);
            print_sync(&updated);
            Ok(0)
        }

        Command::Projects { json } => {
            let projects = registry.projects()?;
            // Attachments are folded into a ROOTS column rather than given a
            // table of their own: a root is only ever interesting as *which
            // project this directory is*, and a second table would make the
            // reader join them by hand. The one thing a column cannot show is
            // an attachment whose project is not registered here, so
            // `render_projects` names those in a footer instead.
            let mut roots: BTreeMap<String, Vec<PathBuf>> = BTreeMap::new();
            for attachment in registry.attachments()? {
                roots
                    .entry(attachment.project)
                    .or_default()
                    .push(attachment.root);
            }
            if json {
                // Machine-readable: the portable manifest's own shape, and
                // nothing else. This machine's attachments live in another file
                // for a reason, and folding them in here would produce JSON
                // that cannot be copied to the next laptop.
                println!("{}", serde_json::to_string_pretty(&projects)?);
                return Ok(0);
            }
            if projects.is_empty() {
                println!("no projects registered yet");
                println!("  pb env init   (in the directory you want to register)");
                return Ok(0);
            }
            print!("{}", render_projects(&projects, &roots, styles));
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
            println!("  secret path:        {}", outcome.secret_path);
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
            // Counted before, because `forget` takes them with it.
            let detached = registry.attachments_of(&entry.id)?;
            let removed = registry.forget(&entry.id)?;

            println!("forgot {}", removed.id);
            if !detached.is_empty() {
                println!(
                    "  detached {} director{} on this machine:",
                    detached.len(),
                    if detached.len() == 1 { "y" } else { "ies" }
                );
                for root in &detached {
                    println!("    {}", render::tilde(root));
                }
            }
            println!(
                "  its stored values are gone from the {}",
                registry.store_name()
            );
            println!("  nothing was revoked — whatever the remote holds is untouched");
            // patchbay does not go editing repositories, and it cannot see the
            // checkouts it was never attached to.
            println!(
                "  a committed {MARKER_FILE} is untouched: run `rm {MARKER_FILE}` in the repo if \
                 it should stop claiming `{}`",
                removed.id
            );
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
            "no project registered for this directory. Three ways in: `pb env init` here to \
             register a new project, `pb env attach <id>` to bind this directory to one that \
             already exists, or work in a checkout carrying a committed {MARKER_FILE}, which \
             resolves on its own. `pb env projects` lists what exists, and --project <id> \
             overrides all of it for one command"
        )
    })
}

/// What [`Command::Init`] did, separated from the printing so the decision this
/// makes — register a new project, or join one this directory already resolves
/// to — is testable without a terminal.
#[derive(Debug)]
struct Init {
    entry: ProjectEntry,
    attachment: Attachment,
    /// The directory joined a project that already existed, rather than
    /// registering a new one.
    shared: bool,
    /// The marker written, or already in place. `None` with `--no-marker`.
    marker: Option<PathBuf>,
    /// The marker was already there, naming this project. Nothing was written,
    /// and telling the user to go and commit it would be noise.
    marker_was_there: bool,
}

/// Register `root` as a project, or attach it to the one it already resolves
/// to, and (unless told not to) leave a marker naming the result.
fn init(
    registry: &EnvRegistry,
    root: &Path,
    id: Option<&str>,
    default_env: &str,
    marker: bool,
) -> Result<Init> {
    // What the repo itself claims, read first and read even under
    // `--no-marker`: a committed marker is the best name this project has —
    // it is already in the history — and `init` choosing a different one would
    // leave the directory contradicting its own file. This is what makes the
    // fresh-clone case work: `git clone && pb env init` registers the project
    // the repo names, whatever the checkout directory happens to be called.
    let claimed = read_marker(root)?;
    let want = match (id, &claimed) {
        (Some(id), _) => id.to_string(),
        (None, Some(claimed)) => claimed.clone(),
        (None, None) => default_project_id(root)?,
    };

    // Fatal, and before anything is registered: an explicit `--id` that
    // disagrees with the marker is a directory being pulled in two directions,
    // and half a registration is the worst place to find that out.
    // `--no-marker` is the way through — it writes no marker to refuse, and the
    // attachment it makes beats the marker anyway.
    if marker {
        if let Some(claimed) = &claimed {
            if claimed != &want {
                anyhow::bail!(
                    "{} already claims project `{claimed}`, so `{want}` was not registered; drop \
                     --id to register it as `{claimed}` the way the repo names it, use `pb env \
                     attach <id>` to bind this directory to a different project (an attachment \
                     beats the marker), or pass --no-marker to register `{want}` and leave the \
                     file alone",
                    root.join(MARKER_FILE).display()
                );
            }
        }
    }

    // A second worktree of a project this machine already knows should join it
    // rather than die on the duplicate id. A resolution *failure* is not fatal
    // here: a marker naming a project the registry lacks is precisely what
    // running `pb env init` is meant to fix.
    let resolved = registry.find_by_dir(root).unwrap_or_default();
    let shared = resolved.as_ref().is_some_and(|p| p.id == want);
    let entry = match resolved {
        // A genuinely different id still registers its own project: `--id` is
        // the user saying they meant a new one.
        Some(existing) if shared => existing,
        _ => registry.register(&want, default_env)?,
    };
    let attachment = registry.attach(root, &entry.id)?;
    let marker = marker.then(|| write_marker(root, &entry.id)).transpose()?;

    Ok(Init {
        entry,
        attachment,
        shared,
        marker,
        marker_was_there: claimed.is_some(),
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
fn print_adopted_sync(registry: &EnvRegistry, entry: &ProjectEntry, root: &Path) -> Result<()> {
    // The directory is passed in rather than read back off the project: a
    // project has no directory of its own, only the attachments this machine
    // made — and `init` knows which one it just created.
    let path = root.join(INFISICAL_FILE);
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
                    // `.infisical.json` records a workspace, never a folder
                    // inside it, so an adopted link reads the project root and
                    // `pb env link --path` is how it learns better.
                    secret_path: DEFAULT_SECRET_PATH.to_string(),
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
    // Always, including the root: this is the line that tells somebody who
    // linked a project whose secrets live in a folder that they have just
    // pointed patchbay at an empty one.
    println!("  secret path: {}", sync.remote_path());
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

/// The ROOTS cell for one project: this machine's attachments for it, comma
/// joined while they fit and collapsed to the first plus `+N more` when they do
/// not. An ellipsis in the middle of the second path would say less than the
/// count does: what a reader wants from a wide list is *how many*, and one full
/// path to recognise the project by.
///
/// The count is reserved out of `width` rather than left to the row's own
/// truncation, which would eat it and leave a bare `…` claiming nothing in
/// particular.
fn roots_cell(paths: Option<&[PathBuf]>, width: usize) -> String {
    let paths = match paths {
        Some(paths) if !paths.is_empty() => paths,
        // Not attached *here*. Normal for a project that arrived with a copied
        // projects.json, and for a repo resolved by its marker.
        _ => return DASH.to_string(),
    };
    let shown: Vec<String> = paths.iter().map(|path| render::tilde(path)).collect();
    let joined = shown.join(", ");
    if joined.chars().count() <= width || shown.len() == 1 {
        return joined;
    }
    let suffix = format!(" +{} more", shown.len() - 1);
    let room = width.saturating_sub(suffix.chars().count());
    format!("{}{suffix}", render::truncate(&shown[0], room))
}

/// The SYNC cell at its natural width, which is also what the column is sized
/// against.
///
/// A non-root secret path is shown because a reader cannot infer it and it
/// decides what a pull returns; the root is left off, since a column saying `/`
/// on every row would be pure noise.
fn sync_full(p: &ProjectEntry) -> String {
    match &p.sync {
        Some(sync) if !sync.is_root_path() => {
            format!("{}:{} {}", sync.provider, sync.account, sync.remote_path())
        }
        Some(sync) => format!("{}:{}", sync.provider, sync.account),
        None => DASH.to_string(),
    }
}

/// The SYNC cell squeezed into `width`. The path suffix is reserved out of the
/// width rather than left to the row's own truncation — the same trick the
/// ROOTS column plays with `+N more`, and for the same reason: truncation eats
/// the end of the cell, which is exactly the part nobody could guess.
fn sync_cell(p: &ProjectEntry, width: usize) -> String {
    let full = sync_full(p);
    if full.chars().count() <= width {
        return full;
    }
    match &p.sync {
        Some(sync) if !sync.is_root_path() => {
            let suffix = format!(" {}", sync.remote_path());
            let room = width.saturating_sub(suffix.chars().count());
            format!(
                "{}{suffix}",
                render::truncate(&format!("{}:{}", sync.provider, sync.account), room)
            )
        }
        _ => render::truncate(&full, width),
    }
}

/// The ENVS cell: the environment names, or a dash for a project that has none
/// registered yet.
fn envs_cell(p: &ProjectEntry) -> String {
    let names = p.env_names();
    if names.is_empty() {
        DASH.to_string()
    } else {
        names.join(",")
    }
}

/// The project table. Roots are long, so ROOTS takes whatever the other columns
/// leave and gets truncated into it.
///
/// `roots` is this machine's attachments, by project id — a project may have
/// several (worktrees), and one copied from another machine may have none here
/// at all.
pub fn render_projects(
    projects: &[ProjectEntry],
    roots: &BTreeMap<String, Vec<PathBuf>>,
    styles: &Styles,
) -> String {
    let unattached = projects.iter().any(|p| !roots.contains_key(&p.id));

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
        projects.iter().map(|p| sync_full(p).chars().count()),
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
        pad("ROOTS", root_w),
        pad("ENVS", envs_w),
        "SYNC",
    );
    out.push_str(&styles.paint(bold(), header.trim_end()));
    out.push('\n');

    for project in projects {
        let id = pad(&render::truncate(&project.id, id_w), id_w);
        let root = pad(
            &render::truncate(
                &roots_cell(roots.get(&project.id).map(Vec::as_slice), root_w),
                root_w,
            ),
            root_w,
        );
        let envs = pad(&render::truncate(&envs_cell(project), envs_w), envs_w);
        let sync = sync_cell(project, sync_w);
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
    // An attachment whose project is not registered here has no row to appear
    // in, and `find_by_dir` skips it in silence. This footer is the only place
    // it is ever visible, which is the whole reason it exists.
    let dangling: Vec<&str> = roots
        .keys()
        .filter(|id| !projects.iter().any(|p| &p.id == *id))
        .map(String::as_str)
        .collect();
    if !dangling.is_empty() {
        out.push_str(&styles.paint(
            dim(),
            &format!(
                "attached to project{} no longer registered here: {} — `pb env detach --dir \
                 <path>` clears them",
                plural(dangling.len()),
                dangling.join(", ")
            ),
        ));
        out.push('\n');
    }
    // A dash under ROOTS reads as "broken" unless it is explained once.
    if unattached {
        out.push_str(&styles.paint(
            dim(),
            &format!(
                "{DASH} no directory on this machine is attached; a checkout with a committed \
                 {MARKER_FILE} resolves without one, or `pb env attach <id>`"
            ),
        ));
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
            dir.path().join("attachments.json"),
            Box::new(MemoryKeystore::new()),
        );
        (dir, registry)
    }

    /// One project attached to one directory, one environment, both layers,
    /// one override.
    fn seeded(registry: &EnvRegistry) {
        registry.register("pathors", "dev").unwrap();
        registry.attach("/repos/pathors", "pathors").unwrap();
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

    /// This machine's attachments, in the shape `render_projects` wants.
    fn roots_of(registry: &EnvRegistry) -> BTreeMap<String, Vec<PathBuf>> {
        let mut roots: BTreeMap<String, Vec<PathBuf>> = BTreeMap::new();
        for attachment in registry.attachments().unwrap() {
            roots
                .entry(attachment.project)
                .or_default()
                .push(attachment.root);
        }
        roots
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
        registry.register("side", "dev").unwrap();
        registry.attach("/repos/side-project", "side").unwrap();
        registry
            .set_sync(
                "pathors",
                SyncConfig {
                    provider: "infisical".into(),
                    project_id: "3ab516bd".into(),
                    account: "contact@pathors.com".into(),
                    domain: None,
                    env_map: BTreeMap::new(),
                    secret_path: DEFAULT_SECRET_PATH.into(),
                },
            )
            .unwrap();

        let projects = registry.projects().unwrap();
        let out = render_projects(&projects, &roots_of(&registry), &Styles::new(false));
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
        let col = lines[0].find("ROOTS").unwrap();
        assert!(lines[1][col..].starts_with("/repos/pathors"), "{out}");
        assert!(lines[2][col..].starts_with("/repos/side-project"), "{out}");
    }

    #[test]
    fn test_the_sync_column_shows_a_secret_path_and_hides_the_root_one() {
        let (_dir, registry) = vault();
        registry.register("coldmail", "dev").unwrap();
        registry.attach("/repos/coldmail", "coldmail").unwrap();
        registry.register("pathors", "dev").unwrap();
        registry.attach("/repos/pathors", "pathors").unwrap();
        let link = |id: &str, path: &str| {
            registry
                .set_sync(
                    id,
                    SyncConfig {
                        provider: "infisical".into(),
                        project_id: "3ab516bd".into(),
                        account: "contact@pathors.com".into(),
                        domain: None,
                        env_map: BTreeMap::new(),
                        secret_path: path.into(),
                    },
                )
                .unwrap();
        };
        link("coldmail", "/outbox");
        link("pathors", DEFAULT_SECRET_PATH);

        let out = render_projects(
            &registry.projects().unwrap(),
            &roots_of(&registry),
            &Styles::new(false),
        );
        let lines: Vec<&str> = out.lines().collect();

        // Which folder a project pulls from is the one thing in this row a
        // reader cannot work out for themselves, so it is shown whole.
        assert!(lines[1].starts_with("coldmail"), "{out}");
        assert!(
            lines[1].contains("infisical:contact@pathors.com /outbox"),
            "{out}"
        );
        // And the default says nothing, because `/` on every row is noise.
        assert!(lines[2].starts_with("pathors"), "{out}");
        assert!(
            lines[2].trim_end().ends_with("contact@pathors.com"),
            "{out}"
        );
    }

    #[test]
    fn test_the_roots_column_counts_worktrees_and_explains_a_dash() {
        let (_dir, registry) = vault();
        registry.register("pathors", "dev").unwrap();
        registry.attach("/repos/pathors", "pathors").unwrap();
        registry
            .attach("/repos/pathors-worktrees/feature-a", "pathors")
            .unwrap();
        registry
            .attach("/repos/pathors-worktrees/feature-b", "pathors")
            .unwrap();
        // Registered, and attached nowhere on this machine — what a copied
        // projects.json looks like before anybody checks the repo out.
        registry.register("elsewhere", "dev").unwrap();

        let projects = registry.projects().unwrap();
        let out = render_projects(&projects, &roots_of(&registry), &Styles::new(false));
        let lines: Vec<&str> = out.lines().collect();

        // Three roots do not fit the column, so the first one stays whole and
        // the rest become a count rather than an ellipsis.
        assert!(lines[1].contains("/repos/pathors "), "{out}");
        assert!(lines[1].contains("+2 more"), "{out}");
        assert!(!lines[1].contains("feature-a"), "{out}");

        assert!(lines[2].starts_with("elsewhere"), "{out}");
        assert!(lines[2].contains(DASH), "{out}");
        // And the dash is explained once, at the bottom, rather than read as a
        // project that is somehow broken.
        assert!(lines[3].starts_with(DASH), "{out}");
        assert!(lines[3].contains(MARKER_FILE), "{out}");
        assert!(lines[3].contains("pb env attach"), "{out}");
        assert_eq!(lines.len(), 4, "{out}");

        // Two short roots still fit, and are simply both shown.
        let (_dir, registry) = vault();
        registry.register("pathors", "dev").unwrap();
        registry.attach("/a", "pathors").unwrap();
        registry.attach("/b", "pathors").unwrap();
        let out = render_projects(
            &registry.projects().unwrap(),
            &roots_of(&registry),
            &Styles::new(false),
        );
        assert!(out.contains("/a, /b"), "{out}");
        assert!(!out.contains("more"), "{out}");
        // Every project has a root here, so nothing is explained that does not
        // need explaining.
        assert_eq!(out.lines().count(), 2, "{out}");
    }

    #[test]
    fn test_an_attachment_to_a_forgotten_project_is_named_not_hidden() {
        let (_dir, registry) = vault();
        registry.register("pathors", "dev").unwrap();
        registry.attach("/repos/pathors", "pathors").unwrap();

        // What a projects.json copied from another machine leaves behind: a
        // root pointing at a project this registry does not have. `find_by_dir`
        // skips it silently, so the table is where it has to surface.
        let mut roots = roots_of(&registry);
        roots.insert("ghost".to_string(), vec![PathBuf::from("/repos/ghost")]);

        let out = render_projects(&registry.projects().unwrap(), &roots, &Styles::new(false));
        let last = out.lines().last().unwrap();
        assert!(last.contains("no longer registered here"), "{out}");
        assert!(last.contains("ghost"), "{out}");
        assert!(last.contains("pb env detach"), "{out}");
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

    // --- init, markers and the second worktree ------------------------------

    /// A real directory under a tempdir, because `init` reads and writes a
    /// marker file in it.
    fn workdir(dir: &tempfile::TempDir, relative: &str) -> PathBuf {
        let path = dir.path().join(relative);
        std::fs::create_dir_all(&path).unwrap();
        path
    }

    fn marker_text(root: &Path) -> String {
        std::fs::read_to_string(root.join(MARKER_FILE)).unwrap()
    }

    #[test]
    fn test_init_registers_attaches_and_leaves_a_marker_to_commit() {
        let (dir, registry) = vault();
        let root = workdir(&dir, "repos/pathors");

        let done = init(&registry, &root, None, "dev", true).unwrap();
        assert_eq!(done.entry.id, "pathors");
        assert!(!done.shared);
        assert_eq!(done.attachment.root, root);
        assert_eq!(done.marker, Some(root.join(MARKER_FILE)));
        assert!(!done.marker_was_there, "there was nothing here to find");
        assert!(marker_text(&root).contains("project = \"pathors\""));

        // Both routes now answer for this directory, and the marker alone would
        // answer on a machine that never attached it.
        assert_eq!(registry.attachments_of("pathors").unwrap(), vec![root]);
        assert_eq!(
            read_marker(&done.attachment.root).unwrap().as_deref(),
            Some("pathors")
        );
    }

    #[test]
    fn test_no_marker_leaves_the_repo_alone() {
        let (dir, registry) = vault();
        let root = workdir(&dir, "repos/pathors");

        let done = init(&registry, &root, None, "dev", false).unwrap();
        assert!(done.marker.is_none());
        assert!(!root.join(MARKER_FILE).exists());
        // The machine still resolves it; nobody else's checkout will.
        assert_eq!(
            registry.find_by_dir(&root).unwrap().map(|p| p.id),
            Some("pathors".to_string())
        );
    }

    #[test]
    fn test_a_second_worktree_joins_the_project_instead_of_colliding() {
        let (dir, registry) = vault();
        let first = workdir(&dir, "repos/pathors");
        init(&registry, &first, None, "dev", true).unwrap();

        // A second checkout of the same repo — a worktree named after its
        // branch, so the directory name says nothing. The marker is what makes
        // this the same project.
        let second = workdir(&dir, "repos/pathors-worktrees/feature-a");
        std::fs::copy(first.join(MARKER_FILE), second.join(MARKER_FILE)).unwrap();

        let done = init(&registry, &second, None, "dev", true).unwrap();
        assert!(
            done.shared,
            "the duplicate id should have joined, not failed"
        );
        assert_eq!(done.entry.id, "pathors");
        assert_eq!(registry.projects().unwrap().len(), 1);
        assert_eq!(
            registry.attachments_of("pathors").unwrap(),
            vec![first, second.clone()]
        );
        // Idempotent: the marker it already carries is the one it wanted, so
        // nothing was written and nothing is asked of the user.
        assert_eq!(done.marker, Some(second.join(MARKER_FILE)));
        assert!(done.marker_was_there);
    }

    #[test]
    fn test_init_refuses_to_take_a_directory_another_project_claims() {
        let (dir, registry) = vault();
        let root = workdir(&dir, "repos/pathors");
        std::fs::write(root.join(MARKER_FILE), "project = \"upstream\"\n").unwrap();

        let err = init(&registry, &root, Some("fork"), "dev", true)
            .unwrap_err()
            .to_string();
        assert!(err.contains("already claims project `upstream`"), "{err}");
        assert!(err.contains("drop --id"), "{err}");
        assert!(err.contains("pb env attach"), "{err}");
        assert!(err.contains("--no-marker"), "{err}");

        // Nothing was registered, nothing was attached, and the repo's file is
        // exactly as it was.
        assert!(registry.projects().unwrap().is_empty());
        assert!(registry.attachments().unwrap().is_empty());
        assert_eq!(marker_text(&root), "project = \"upstream\"\n");

        // --no-marker is the way through: no marker is written, so there is
        // nothing to refuse — and the attachment beats the marker anyway.
        let done = init(&registry, &root, Some("fork"), "dev", false).unwrap();
        assert!(!done.shared);
        assert_eq!(done.entry.id, "fork");
        assert_eq!(
            registry.find_by_dir(&root).unwrap().map(|p| p.id),
            Some("fork".to_string())
        );
    }

    #[test]
    fn test_a_fresh_clone_registers_under_the_name_the_repo_committed() {
        let (dir, registry) = vault();
        // The checkout directory is called something else entirely, which is
        // the normal case: `git clone <url> ./work`, or a worktree named after
        // a branch.
        let root = workdir(&dir, "checkouts/work");
        std::fs::write(root.join(MARKER_FILE), "project = \"pathors\"\n").unwrap();
        // Resolution fails here — the registry never travelled — and that is
        // precisely the state `pb env init` is run to leave.
        assert!(registry.find_by_dir(&root).is_err());

        let done = init(&registry, &root, None, "dev", true).unwrap();
        assert!(!done.shared);
        assert_eq!(
            done.entry.id, "pathors",
            "the committed name should win over the directory's"
        );
        assert_eq!(
            registry.find_by_dir(&root).unwrap().map(|p| p.id),
            Some("pathors".to_string())
        );
        // And it did not rewrite the file it took the name from.
        assert_eq!(marker_text(&root), "project = \"pathors\"\n");
    }

    #[test]
    fn test_an_explicit_different_id_still_registers_its_own_project() {
        let (dir, registry) = vault();
        let root = workdir(&dir, "repos/pathors");
        init(&registry, &root, None, "dev", true).unwrap();

        // Inside the same tree, but told to be something else: the marker above
        // resolves, and is deliberately not what the user asked for.
        let nested = workdir(&dir, "repos/pathors/tools/scraper");
        let done = init(&registry, &nested, Some("scraper"), "dev", false).unwrap();
        assert!(!done.shared);
        assert_eq!(done.entry.id, "scraper");
        assert_eq!(registry.projects().unwrap().len(), 2);
        // The attachment is deeper than the marker's directory, so it wins.
        assert_eq!(
            registry.find_by_dir(&nested).unwrap().map(|p| p.id),
            Some("scraper".to_string())
        );
    }

    #[test]
    fn test_attach_help_says_it_overrides_the_marker() {
        let command = <Command as clap::Subcommand>::augment_subcommands(clap::Command::new("env"));
        let attach = command
            .get_subcommands()
            .find(|c| c.get_name() == "attach")
            .expect("`pb env attach` is missing");
        let help = attach
            .get_long_about()
            .or_else(|| attach.get_about())
            .unwrap()
            .to_string();
        assert!(help.contains("OVERRIDES"), "{help}");
        assert!(help.contains(MARKER_FILE), "{help}");
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
