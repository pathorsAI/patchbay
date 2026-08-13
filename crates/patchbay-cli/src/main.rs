//! `pb` — the patchbay command line.
//!
//! Thin shell over `patchbay_core::Registry`: it decides *how* to show what the
//! probes found, and never reads tool state itself. Formatting lives in
//! [`render`]; this file is argument parsing, dispatch and exit codes.

mod render;

use anyhow::Result;
use chrono::Utc;
use clap::{Parser, Subcommand};
use patchbay_core::{PermissionsReport, Registry, SwitchOutcome, VerifyOutcome};

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
    Verify {
        tool: String,
        #[arg(long)]
        json: bool,
    },
    /// Show what the active credential of a tool is allowed to do.
    Perms {
        tool: String,
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
        Command::Status { json } => {
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
        Command::Verify { tool, json } => {
            let outcome = registry.verify(&tool)?;
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
