//! `pb` — the patchbay command line.
//!
//! Thin shell over `patchbay_core::Registry`: it decides *how* to show what the
//! probes found, and never reads tool state itself. Formatting lives in
//! [`render`]; this file is argument parsing, dispatch and exit codes.

mod env;
mod keys;
mod mcp;
mod migrate;
mod render;

use anyhow::Result;
use chrono::Utc;
use clap::{Parser, Subcommand};
use patchbay_core::{
    Advisory, CheckOptions, KeyRegistry, McpClientRegistry, PermissionsReport, Registry,
    SwitchOutcome, VerifyOutcome,
};

use render::Styles;

#[derive(Parser, Debug)]
#[command(
    name = "pb",
    version,
    about = "patchbay - a status board for the CLI logins on your machine"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Show every tool: active profile, profile count, soonest expiry, notes.
    Status {
        /// Emit the raw status list as JSON instead of a table.
        #[arg(long)]
        json: bool,
        /// Compare this machine against another one's `manifest.json` and list
        /// what differs, instead of showing the board.
        #[arg(long, value_name = "MANIFEST")]
        diff: Option<std::path::PathBuf>,
    },
    /// Switch a tool to another profile.
    Use {
        /// Tool key, e.g. `gcloud`, `aws`, `gh`.
        tool: String,
        /// Profile id, as listed by `pb status --json`.
        profile: String,
        #[arg(long)]
        json: bool,
    },
    /// Check whether a tool's credentials actually work right now.
    ///
    /// patchbay runs the tool's own check itself — it does not hand back a
    /// command to paste. With `--profile`, it checks that one profile: an
    /// rclone remote, an ssh host, a kubectl context.
    Verify {
        tool: String,
        /// Profile to check, as listed by `pb status --json`. Defaults to
        /// whatever the tool treats as active.
        #[arg(long, value_name = "ID")]
        profile: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Show what the active credential of a tool is allowed to do.
    Perms {
        tool: String,
        #[arg(long)]
        json: bool,
    },
    /// Check every tool's installed version against its install source.
    ///
    /// Unlike `pb status`, this executes each tool's version command and asks
    /// Homebrew, the npm registry and GitHub what the current release is, then
    /// caches the answers for `pb status` to show. Seconds, not milliseconds.
    CheckUpdates {
        /// Re-check everything, ignoring cache entries that are still current.
        #[arg(long)]
        refresh: bool,
        #[arg(long)]
        json: bool,
    },
    /// The key vault: standalone API keys and tokens no CLI tracks.
    Key {
        #[command(subcommand)]
        command: keys::Command,
    },
    /// Project env vault: per-project variables in synced + local layers.
    Env {
        #[command(subcommand)]
        command: env::Command,
    },
    /// MCP servers across the AI clients on this machine.
    Mcp {
        #[command(subcommand)]
        command: mcp::Command,
    },
    /// Pack this machine's movable logins into one encrypted bundle.
    Export {
        #[arg(long, short)]
        out: Option<std::path::PathBuf>,
        /// Include vault secret values: bare for all, `--keys=a,b` for some.
        #[arg(long, num_args = 0..=1, value_delimiter = ',', default_missing_value = "")]
        keys: Option<Vec<String>>,
        /// Write into a cloud-sync folder anyway.
        #[arg(long)]
        force: bool,
        #[arg(long)]
        json: bool,
    },
    /// Restore a bundle onto this machine.
    Import {
        bundle: std::path::PathBuf,
        /// Print the plan and write nothing.
        #[arg(long)]
        dry_run: bool,
        #[arg(long)]
        json: bool,
    },
    /// What still needs doing on this machine to finish a move.
    Plan {
        /// Compare against a `manifest.json` from another machine.
        #[arg(long, value_name = "FILE")]
        manifest: Option<std::path::PathBuf>,
        /// Show closed items too.
        #[arg(long)]
        all: bool,
        #[arg(long)]
        json: bool,
    },
}

fn main() {
    match run() {
        Ok(code) => std::process::exit(code),
        Err(err) => {
            eprintln!("pb: {err:#}");
            std::process::exit(1);
        }
    }
}

/// Returns the process exit code. Errors here are patchbay's own failures
/// (unknown tool, unreadable home); a tool reporting bad news is not an error.
fn run() -> Result<i32> {
    let cli = Cli::parse();
    let registry = Registry::detect()?;

    match cli.command {
        Command::Status { json, diff } => {
            if let Some(manifest) = diff {
                let vault = KeyRegistry::detect()?;
                let clients = McpClientRegistry::with_paths(registry.paths().clone());
                return migrate::print_status_diff(
                    &registry,
                    &vault,
                    &clients,
                    &manifest,
                    &styles(),
                );
            }
            let statuses = registry.status_all();
            if json {
                // Must stay machine-readable: JSON only, no ANSI, no extras.
                println!("{}", serde_json::to_string_pretty(&statuses)?);
            } else {
                print!(
                    "{}",
                    render::render_status(&statuses, Utc::now(), &styles())
                );
            }
            Ok(0)
        }
        Command::Use {
            tool,
            profile,
            json,
        } => {
            let outcome = registry.switch(&tool, &profile)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&outcome)?);
            } else {
                print_switch(&outcome);
            }
            Ok(switch_exit_code(&outcome))
        }
        Command::Verify {
            tool,
            profile,
            json,
        } => {
            let outcome = registry.verify_profile(&tool, profile.as_deref())?;
            if json {
                println!("{}", serde_json::to_string_pretty(&outcome)?);
            } else {
                print_verify(&outcome);
            }
            Ok(match outcome {
                VerifyOutcome::Invalid { .. } => 1,
                _ => 0,
            })
        }
        Command::Perms { tool, json } => {
            let report = registry.permissions(&tool)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                print_perms(&report);
            }
            Ok(0)
        }
        Command::CheckUpdates { refresh, json } => {
            let report = registry.check_updates(CheckOptions {
                refresh,
                ..CheckOptions::default()
            });
            // Advisories are static data, so they are reported whether or not
            // the version lookups succeeded.
            let advisories: Vec<Advisory> = registry
                .status_all()
                .iter()
                .flat_map(|s| s.advisories.clone())
                .collect();

            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "report": report,
                        "advisories": advisories,
                    }))?
                );
            } else {
                print!(
                    "{}",
                    render::render_check_updates(&report, &advisories, &styles())
                );
            }
            // Something removed or unmaintained is worth failing a script over;
            // a rename that still works is not.
            Ok(i32::from(advisories.iter().any(Advisory::is_blocking)))
        }
        // The vault has its own registry: it stores keys the user gave patchbay
        // on purpose, not state discovered by a probe.
        Command::Key { command } => keys::run(command, &styles()),
        // The env vault is the other half of the same idea: values the user
        // handed patchbay on purpose, filed against a directory instead of a
        // person.
        Command::Env { command } => env::run(command, &styles()),
        // Likewise the MCP board: these are other tools' config files, not
        // credential state, so it has its own registry too.
        Command::Mcp { command } => mcp::run(command, &styles()),
        // Migration needs all three registries at once — the board, the vault
        // and the MCP clients are all part of what moves — so its subcommands
        // are flattened onto the top level and dispatched together.
        Command::Export {
            out,
            keys,
            force,
            json,
        } => migrate::run(
            migrate::Command::Export {
                out,
                keys,
                force,
                json,
            },
            &styles(),
        ),
        Command::Import {
            bundle,
            dry_run,
            json,
        } => migrate::run(
            migrate::Command::Import {
                bundle,
                dry_run,
                json,
            },
            &styles(),
        ),
        Command::Plan {
            manifest,
            all,
            json,
        } => migrate::run(
            migrate::Command::Plan {
                manifest,
                all,
                json,
            },
            &styles(),
        ),
    }
}

fn styles() -> Styles {
    Styles::detect()
}

/// `Unsupported` is information, not failure — it still exits 0.
fn switch_exit_code(outcome: &SwitchOutcome) -> i32 {
    match outcome {
        SwitchOutcome::Switched { .. } | SwitchOutcome::Unsupported { .. } => 0,
        SwitchOutcome::UnknownProfile { .. } | SwitchOutcome::Failed { .. } => 1,
    }
}

fn print_switch(outcome: &SwitchOutcome) {
    match outcome {
        SwitchOutcome::Switched {
            tool,
            profile_id,
            detail,
            notes,
        } => {
            println!("{tool}: switched to {profile_id}");
            if !detail.is_empty() {
                println!("  {detail}");
            }
            // Notes here carry real traps (gcloud ADC not following the
            // switch), so each one gets its own line rather than being folded
            // into the confirmation.
            if !notes.is_empty() {
                println!("{}", render::indent_lines(notes));
            }
        }
        SwitchOutcome::Unsupported { tool, reason, hint } => {
            println!("{tool}: cannot switch automatically");
            println!("  {reason}");
            if let Some(hint) = hint {
                println!("  run: {hint}");
            }
        }
        SwitchOutcome::UnknownProfile {
            tool,
            profile_id,
            available,
        } => {
            eprintln!("{tool}: unknown profile `{profile_id}`");
            if available.is_empty() {
                eprintln!("  no profiles found for {tool}");
            } else {
                eprintln!("  available:");
                for id in available {
                    eprintln!("    {id}");
                }
            }
        }
        SwitchOutcome::Failed {
            tool,
            profile_id,
            detail,
        } => {
            eprintln!("{tool}: failed to switch to {profile_id}");
            eprintln!("  {detail}");
        }
    }
}

fn print_verify(outcome: &VerifyOutcome) {
    match outcome {
        VerifyOutcome::Valid { tool, detail } => {
            println!("{tool}: valid");
            println!("  {detail}");
        }
        VerifyOutcome::Invalid { tool, detail } => {
            eprintln!("{tool}: invalid");
            eprintln!("  {detail}");
        }
        VerifyOutcome::Unsupported { tool, reason, hint } => {
            println!("{tool}: cannot verify");
            println!("  {reason}");
            if let Some(hint) = hint {
                println!("  run: {hint}");
            }
        }
    }
}

fn print_perms(report: &PermissionsReport) {
    let PermissionsReport {
        tool,
        supported,
        subject,
        scopes,
        notes,
        hint,
    } = report;

    if *supported {
        match subject {
            Some(subject) => println!("{tool}: {subject}"),
            None => println!("{tool}:"),
        }
        if scopes.is_empty() {
            println!("  (no scopes reported)");
        } else {
            println!("  scopes ({}):", scopes.len());
            println!("{}", render::render_scopes(scopes));
        }
    } else {
        println!("{tool}: permissions not available");
    }

    if !notes.is_empty() {
        println!("{}", render::indent_lines(notes));
    }
    // Labelled so it cannot be mistaken for another note.
    if let Some(hint) = hint {
        println!("  hint: {hint}");
    }
}
