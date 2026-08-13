//! `pb export`, `pb import`, `pb plan` — moving a machine, in the terminal.
//!
//! The passphrase is read from a hidden prompt and never from an argument:
//! argv is world-readable through `ps` and lands in `~/.zsh_history` verbatim,
//! which is the same reason `pb key add` refuses a secret on the command line.
//! On export it is asked for twice, because a bundle nobody can decrypt is a
//! bundle that has to be made again from a machine you may have already wiped.
//!
//! Nothing here reads a credential file itself: [`patchbay_core::migrate`] does
//! that. This module decides what to print.

use std::io::{IsTerminal, Write};
use std::path::PathBuf;

use anyhow::{Context, Result};
use chrono::Utc;
use clap::Subcommand;
use patchbay_core::migrate::{
    self, export, import, manifest::SetupStatus, Exporter, ImportOptions, Importer, KeySelection,
    Manifest, SetupItem,
};
use patchbay_core::{KeyRegistry, McpClientRegistry, Registry};

use crate::render::{self, Styles};

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Pack this machine's movable logins into one encrypted bundle.
    Export {
        /// Where to write it. Defaults to `./patchbay-<today>.pbx`.
        #[arg(long, short)]
        out: Option<PathBuf>,
        /// Include vault secret values. Bare `--keys` means all of them;
        /// `--keys=id1,id2` means those. Without it only metadata travels.
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
        bundle: PathBuf,
        /// Print the plan and write nothing.
        #[arg(long)]
        dry_run: bool,
        #[arg(long)]
        json: bool,
    },
    /// What still needs doing on this machine.
    Plan {
        /// Compare against a `manifest.json` from another machine.
        #[arg(long, value_name = "FILE")]
        manifest: Option<PathBuf>,
        /// Show closed items too.
        #[arg(long)]
        all: bool,
        #[arg(long)]
        json: bool,
    },
}

/// Returns the process exit code. A non-empty plan exits 1, so
/// `pb plan && deploy` does the obvious thing in a script.
pub fn run(command: Command, styles: &Styles) -> Result<i32> {
    let registry = Registry::detect()?;
    let paths = registry.paths().clone();
    let vault = KeyRegistry::detect()?;
    let clients = McpClientRegistry::with_paths(paths.clone());

    match command {
        Command::Export {
            out,
            keys,
            force,
            json,
        } => {
            let path = out.unwrap_or_else(|| PathBuf::from(export::default_file_name(Utc::now())));
            // Refuse a bad destination BEFORE asking for a passphrase: being
            // made to type one twice and then told no is a small cruelty.
            export::check_destination(&path, force)?;

            let selection = key_selection(keys);
            let payload = Exporter {
                paths: &paths,
                registry: &registry,
                vault: &vault,
                clients: &clients,
            }
            .payload(&selection, Utc::now())?;

            let passphrase = ask_passphrase_twice()?;
            let report = export::write(&path, &payload, &passphrase, force, None)?;
            drop(passphrase);

            if json {
                println!("{}", serde_json::to_string_pretty(&export_json(&report))?);
            } else {
                print_export(&report, styles);
            }
            Ok(0)
        }

        Command::Import {
            bundle,
            dry_run,
            json,
        } => {
            // Version first, so a bundle from a newer patchbay is refused
            // before the user types anything.
            migrate::peek_version(&bundle)?;
            let passphrase = ask_passphrase("passphrase: ")?;
            let payload = migrate::bundle::read(&bundle, &passphrase)?;
            drop(passphrase);

            let report = Importer {
                paths: &paths,
                registry: &registry,
                vault: &vault,
                clients: &clients,
            }
            .run(&payload, &ImportOptions { dry_run })?;

            if json {
                println!("{}", serde_json::to_string_pretty(&import_json(&report))?);
            } else {
                print_import(&report, styles);
            }
            Ok(0)
        }

        Command::Plan {
            manifest,
            all,
            json,
        } => {
            let manifest = manifest.as_deref().map(read_manifest).transpose()?;
            let items = migrate::plan(&paths, &registry, &vault, &clients, manifest.as_ref());
            let shown: Vec<&SetupItem> = items
                .iter()
                .filter(|i| all || i.status != SetupStatus::Done)
                .collect();

            if json {
                println!("{}", serde_json::to_string_pretty(&shown)?);
            } else {
                print_plan(&shown, styles);
            }
            Ok(i32::from(items.iter().any(SetupItem::is_open)))
        }
    }
}

/// The manifest half of `pb status --diff <manifest>`: which tools this machine
/// disagrees with. Lives here rather than in `main` so all the migration
/// formatting is in one file.
pub fn print_status_diff(
    registry: &Registry,
    vault: &KeyRegistry,
    clients: &McpClientRegistry,
    manifest: &std::path::Path,
    styles: &Styles,
) -> Result<i32> {
    let manifest = read_manifest(manifest)?;
    let items = migrate::plan(registry.paths(), registry, vault, clients, Some(&manifest));
    let open: Vec<&SetupItem> = items.iter().filter(|i| i.is_open()).collect();
    println!(
        "{} of {} things the other machine had are not true here",
        open.len(),
        items.len()
    );
    print_plan(&open, styles);
    Ok(i32::from(!open.is_empty()))
}

fn read_manifest(path: &std::path::Path) -> Result<Manifest> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("could not read {}", path.display()))?;
    Manifest::from_json(&text)
}

/// `--keys` absent -> none; bare `--keys` -> all; `--keys=a,b` -> those.
fn key_selection(keys: Option<Vec<String>>) -> KeySelection {
    match keys {
        None => KeySelection::None,
        Some(ids) => {
            let ids: Vec<String> = ids.into_iter().filter(|i| !i.trim().is_empty()).collect();
            if ids.is_empty() {
                KeySelection::All
            } else {
                KeySelection::Only(ids)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// passphrase
// ---------------------------------------------------------------------------

fn ask_passphrase(prompt: &str) -> Result<String> {
    if !std::io::stdin().is_terminal() {
        anyhow::bail!(
            "a passphrase is required and stdin is not a terminal; run this from a shell rather \
             than a pipe (patchbay will not take a passphrase as an argument — argv is visible to \
             `ps` and is written to your shell history)"
        );
    }
    let value = rpassword::prompt_password(prompt)
        .map_err(|e| anyhow::anyhow!("could not read the passphrase: {e}"))?;
    if value.is_empty() {
        anyhow::bail!("an empty passphrase would leave the bundle effectively unencrypted");
    }
    Ok(value)
}

fn ask_passphrase_twice() -> Result<String> {
    let first = ask_passphrase("passphrase for the bundle: ")?;
    let second = ask_passphrase("again: ")?;
    if first != second {
        anyhow::bail!("the two passphrases do not match; nothing was written");
    }
    Ok(first)
}

// ---------------------------------------------------------------------------
// printing
// ---------------------------------------------------------------------------

fn print_export(report: &export::ExportReport, styles: &Styles) {
    println!(
        "wrote {} ({} file(s), {})",
        report.path.display(),
        report.files,
        human_bytes(report.bytes)
    );
    if !report.tools_carried.is_empty() {
        println!("  carried:   {}", report.tools_carried.join(", "));
    }
    if !report.tools_bound.is_empty() {
        println!("  re-auth:   {}", report.tools_bound.join(", "));
    }
    if !report.keys_included.is_empty() {
        println!(
            "  key values: {} ({})",
            report.keys_included.len(),
            report.keys_included.join(", ")
        );
    }
    if !report.keys_listed.is_empty() {
        println!(
            "  keys listed without their values: {}",
            report.keys_listed.join(", ")
        );
    }
    if report.mcp_carried > 0 {
        println!("  mcp:       {} server(s)", report.mcp_carried);
        if !report.mcp_values_carried.is_empty() {
            // The values themselves are in the bundle; naming them is the
            // whole point, so nobody is surprised by what travelled.
            println!(
                "             carrying values for: {}",
                report.mcp_values_carried.join(", ")
            );
        }
    }
    println!(
        "  {} item(s) will need doing on the new machine",
        report.gaps
    );
    println!();
    for warning in &report.warnings {
        println!("{}", styles.paint(warn_style(), &format!("! {warning}")));
    }
    println!(
        "\nnext: copy the file across, then `pb import {}`",
        file_name(&report.path)
    );
}

fn file_name(path: &std::path::Path) -> String {
    path.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.display().to_string())
}

fn print_import(report: &import::ImportReport, styles: &Styles) {
    if report.dry_run {
        println!(
            "{}\n",
            styles.paint(warn_style(), "DRY RUN — nothing was written")
        );
    }
    for file in &report.files {
        println!("  {:<10} {}", file.outcome.label(), file.path.display());
        if let import::FileOutcome::Replaced { backup: Some(at) } = &file.outcome {
            println!("             (was backed up to {})", at.display());
        }
        if let import::FileOutcome::Skipped { reason } = &file.outcome {
            println!("             {reason}");
        }
    }
    for key in &report.keys {
        println!("  {:<10} key {}", key.outcome.label(), key.id);
    }
    for server in &report.mcp {
        println!(
            "  {:<10} mcp {}/{}",
            server.outcome.label(),
            server.client,
            server.name
        );
    }
    println!();
    for note in &report.notes {
        println!("{}", styles.paint(warn_style(), &format!("! {note}")));
    }

    let open: Vec<&SetupItem> = report.open_items().collect();
    if open.is_empty() {
        println!("\nnothing left to do.");
    } else {
        println!("\n{} item(s) left:", open.len());
        print_plan(&open, styles);
    }
}

fn print_plan(items: &[&SetupItem], styles: &Styles) {
    if items.is_empty() {
        println!("nothing to do.");
        return;
    }
    for item in items {
        let mark = match item.status {
            SetupStatus::Done => styles.paint(dim_style(), "[done]"),
            SetupStatus::Unknown => styles.paint(dim_style(), "[?]   "),
            SetupStatus::Open if item.auto => styles.paint(ok_style(), "[auto]"),
            SetupStatus::Open => styles.paint(warn_style(), "[todo]"),
        };
        println!("{mark} {}", item.what);
        if !item.command.is_empty() && item.status != SetupStatus::Done {
            let browser = if item.needs_browser {
                "   (opens a browser)"
            } else {
                ""
            };
            println!("       {}{browser}", item.command);
        }
        // `indent_lines` on an empty slice is an empty string, which `println!`
        // would still turn into a blank line between every item.
        if item.status != SetupStatus::Done && !item.detail.is_empty() {
            println!("{}", render::indent_lines(&item.detail));
        }
        let _ = std::io::stdout().flush();
    }
}

fn human_bytes(bytes: usize) -> String {
    match bytes {
        b if b < 1024 => format!("{b} B"),
        b if b < 1024 * 1024 => format!("{:.0} KB", b as f64 / 1024.0),
        b => format!("{:.1} MB", b as f64 / (1024.0 * 1024.0)),
    }
}

fn warn_style() -> anstyle::Style {
    anstyle::Style::new().fg_color(Some(anstyle::AnsiColor::Yellow.into()))
}

fn ok_style() -> anstyle::Style {
    anstyle::Style::new().fg_color(Some(anstyle::AnsiColor::Green.into()))
}

fn dim_style() -> anstyle::Style {
    anstyle::Style::new() | anstyle::Effects::DIMMED
}

// ---------------------------------------------------------------------------
// JSON
// ---------------------------------------------------------------------------
//
// The report types live in the core and hold no secrets, but they are not
// `Serialize` — they are shaped for printing. These two functions are the wire
// format, kept explicit so a field added to a report cannot silently change
// what `--json` emits.

fn export_json(report: &export::ExportReport) -> serde_json::Value {
    serde_json::json!({
        "path": report.path,
        "files": report.files,
        "bytes": report.bytes,
        "tools_carried": report.tools_carried,
        "tools_needing_reauth": report.tools_bound,
        "key_values_included": report.keys_included,
        "keys_listed_only": report.keys_listed,
        "mcp_servers": report.mcp_carried,
        "mcp_value_names_carried": report.mcp_values_carried,
        "gaps": report.gaps,
        "warnings": report.warnings,
    })
}

fn import_json(report: &import::ImportReport) -> serde_json::Value {
    let files: Vec<serde_json::Value> = report
        .files
        .iter()
        .map(|f| {
            serde_json::json!({
                "tool": f.tool,
                "location": f.location,
                "path": f.path,
                "action": f.outcome.label(),
            })
        })
        .collect();
    serde_json::json!({
        "dry_run": report.dry_run,
        "files": files,
        "keys": report.keys.iter().map(|k| serde_json::json!({
            "id": k.id, "action": k.outcome.label(),
        })).collect::<Vec<_>>(),
        "mcp": report.mcp.iter().map(|m| serde_json::json!({
            "client": m.client,
            "name": m.name,
            "action": m.outcome.label(),
            "value_names_carried": m.values_carried,
        })).collect::<Vec<_>>(),
        "notes": report.notes,
        "remaining": report.remaining,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_selection_reads_the_three_shapes_of_the_flag() {
        assert_eq!(key_selection(None), KeySelection::None);
        // Bare `--keys` arrives as an empty value, not as an empty vec.
        assert_eq!(key_selection(Some(vec![String::new()])), KeySelection::All);
        assert_eq!(key_selection(Some(vec![])), KeySelection::All);
        assert_eq!(
            key_selection(Some(vec!["a".into(), "b".into()])),
            KeySelection::Only(vec!["a".into(), "b".into()])
        );
    }

    #[test]
    fn test_human_bytes() {
        assert_eq!(human_bytes(12), "12 B");
        assert_eq!(human_bytes(2048), "2 KB");
        assert_eq!(human_bytes(3 * 1024 * 1024), "3.0 MB");
    }

    #[test]
    fn test_file_name_survives_a_bare_name() {
        assert_eq!(file_name(std::path::Path::new("a/b.pbx")), "b.pbx");
        assert_eq!(file_name(std::path::Path::new("b.pbx")), "b.pbx");
    }
}
