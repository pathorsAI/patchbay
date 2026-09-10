//! `pb export`, `pb import`, `pb plan` — moving a machine, in the terminal.
//!
//! The passphrase is read from a hidden prompt and never from an argument:
//! argv is world-readable through `ps` and lands in `~/.zsh_history` verbatim,
//! which is the same reason `pb key add` refuses a secret on the command line.
//! On export it is asked for twice, because a bundle nobody can decrypt is a
//! bundle that has to be made again from a machine you may have already wiped.
//!
//! Automation names its source instead — `--passphrase-file` or
//! `--passphrase-fd`, the way gpg, restic, borg and age do it — which keeps the
//! value out of argv and out of a history file just as well. The refusal that
//! used to stand here instead ("stdin is not a terminal") stopped none of that
//! and was worked around with a pty wrapper, which echoed the passphrase into a
//! log: exactly the leak the rule exists to prevent. A file or fd source also
//! skips the confirmation read on export — nothing was typed, so there is
//! nothing to have mistyped.
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
use patchbay_core::{EnvRegistry, KeyRegistry, McpClientRegistry, Registry};

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
        /// Read the passphrase from the first line of this file instead of
        /// prompting. The file must not be group- or world-readable. patchbay
        /// will not take a passphrase as an argument: argv is visible to `ps`
        /// and is written to your shell history.
        #[arg(long, value_name = "PATH", conflicts_with = "passphrase_fd")]
        passphrase_file: Option<PathBuf>,
        /// Read the passphrase from the first line of an already-open file
        /// descriptor (`--passphrase-fd 3`), for automation that will not put
        /// it in a file either.
        #[arg(long, value_name = "N", conflicts_with = "passphrase_file")]
        passphrase_fd: Option<i32>,
        #[arg(long)]
        json: bool,
    },
    /// Write the secret-free record of what this machine uses.
    Manifest {
        /// Where to write it. Defaults to stdout.
        #[arg(long, short)]
        out: Option<PathBuf>,
    },
    /// Restore a bundle onto this machine.
    Import {
        bundle: PathBuf,
        /// Print the plan and write nothing.
        #[arg(long)]
        dry_run: bool,
        /// Restore the key vault half only, skipping the credential files, the
        /// MCP registrations and the env projects. For finishing a move whose
        /// keychain writes were refused; the file half is idempotent anyway, so
        /// a plain re-run is equally safe and reports `unchanged`.
        #[arg(long)]
        keys_only: bool,
        /// Read the passphrase from the first line of this file instead of
        /// prompting. The file must not be group- or world-readable. patchbay
        /// will not take a passphrase as an argument: argv is visible to `ps`
        /// and is written to your shell history.
        #[arg(long, value_name = "PATH", conflicts_with = "passphrase_fd")]
        passphrase_file: Option<PathBuf>,
        /// Read the passphrase from the first line of an already-open file
        /// descriptor (`--passphrase-fd 3`), for automation that will not put
        /// it in a file either.
        #[arg(long, value_name = "N", conflicts_with = "passphrase_file")]
        passphrase_fd: Option<i32>,
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
    let envs = EnvRegistry::detect()?;

    match command {
        Command::Export {
            out,
            keys,
            force,
            passphrase_file,
            passphrase_fd,
            json,
        } => {
            let source = PassphraseSource::from_flags(passphrase_file, passphrase_fd)?;
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
                envs: &envs,
            }
            .payload(&selection, Utc::now())?;

            let passphrase = ask_passphrase_twice(&source)?;
            let report = export::write(&path, &payload, &passphrase, force, None)?;
            drop(passphrase);

            if json {
                println!("{}", serde_json::to_string_pretty(&export_json(&report))?);
            } else {
                print_export(&report, styles);
            }
            Ok(0)
        }

        Command::Manifest { out } => {
            let manifest = Exporter {
                paths: &paths,
                registry: &registry,
                vault: &vault,
                clients: &clients,
                envs: &envs,
            }
            .manifest(Utc::now())?;

            // No passphrase, no cloud-folder check, no warning about moving the
            // file carefully: this one is meant to be committed and synced.
            // Those guards exist for bundles, and repeating them here would
            // teach people to ignore them where they matter.
            let json = manifest.to_json();
            match out {
                Some(path) => {
                    std::fs::write(&path, format!("{json}\n"))
                        .with_context(|| format!("writing {}", path.display()))?;
                    print_manifest(&manifest, &path, styles);
                }
                None => println!("{json}"),
            }
            Ok(0)
        }

        Command::Import {
            bundle,
            dry_run,
            keys_only,
            passphrase_file,
            passphrase_fd,
            json,
        } => {
            let source = PassphraseSource::from_flags(passphrase_file, passphrase_fd)?;
            // Version first, so a bundle from a newer patchbay is refused
            // before the user types anything.
            migrate::peek_version(&bundle)?;
            let passphrase = read_passphrase(&source, "passphrase: ")?;
            let payload = migrate::bundle::read(&bundle, &passphrase)?;
            drop(passphrase);

            let report = Importer {
                paths: &paths,
                registry: &registry,
                vault: &vault,
                clients: &clients,
                envs: &envs,
            }
            .run(&payload, &ImportOptions { dry_run, keys_only })?;

            if json {
                println!("{}", serde_json::to_string_pretty(&import_json(&report))?);
            } else {
                print_import(&report, styles);
            }
            // A keychain that refused the secrets leaves the vault half of this
            // machine incomplete however well the files went, so
            // `pb import && ./something` must not read as success — the same
            // contract `pb plan` keeps below.
            Ok(i32::from(report.keys_refused() > 0))
        }

        Command::Plan {
            manifest,
            all,
            json,
        } => {
            let manifest = manifest.as_deref().map(read_manifest).transpose()?;
            let items = migrate::plan(
                &paths,
                &registry,
                &vault,
                &clients,
                &envs,
                manifest.as_ref(),
            );
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
    envs: &EnvRegistry,
    manifest: &std::path::Path,
    styles: &Styles,
) -> Result<i32> {
    let manifest = read_manifest(manifest)?;
    let items = migrate::plan(
        registry.paths(),
        registry,
        vault,
        clients,
        envs,
        Some(&manifest),
    );
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

/// Where the passphrase comes from. None of the three is argv.
#[derive(Debug, Clone, PartialEq, Eq)]
enum PassphraseSource {
    /// A hidden prompt on the terminal. The default, and the only one that can
    /// be mistyped.
    Prompt,
    /// The first line of a file that nobody else may read.
    File(PathBuf),
    /// The first line of a descriptor the caller already opened.
    Fd(i32),
}

impl PassphraseSource {
    /// `clap` refuses the two flags together as well. The rule is repeated here
    /// because it belongs to the source rather than to one command's argument
    /// table, and both commands take the pair.
    fn from_flags(file: Option<PathBuf>, fd: Option<i32>) -> Result<Self> {
        match (file, fd) {
            (Some(_), Some(_)) => anyhow::bail!(
                "--passphrase-file and --passphrase-fd both name a source for the same \
                 passphrase; pass one of them"
            ),
            (Some(path), None) => Ok(Self::File(path)),
            (None, Some(fd)) => Ok(Self::Fd(fd)),
            (None, None) => Ok(Self::Prompt),
        }
    }

    fn is_typed(&self) -> bool {
        *self == Self::Prompt
    }
}

fn read_passphrase(source: &PassphraseSource, prompt: &str) -> Result<String> {
    let value = match source {
        PassphraseSource::Prompt => prompt_passphrase(prompt)?,
        PassphraseSource::File(path) => {
            let file = std::fs::File::open(path)
                .with_context(|| format!("could not open {}", path.display()))?;
            refuse_a_readable_file(path, &file)?;
            first_line(
                &mut std::io::BufReader::new(file),
                &path.display().to_string(),
            )?
        }
        PassphraseSource::Fd(fd) => read_fd(*fd)?,
    };
    if value.is_empty() {
        anyhow::bail!("an empty passphrase would leave the bundle effectively unencrypted");
    }
    Ok(value)
}

fn prompt_passphrase(prompt: &str) -> Result<String> {
    if !std::io::stdin().is_terminal() {
        anyhow::bail!(
            "a passphrase is required and stdin is not a terminal; name a source explicitly with \
             --passphrase-file <path> (mode 0600) or --passphrase-fd <n>. patchbay will not take \
             a passphrase as an argument — argv is visible to `ps` and is written to your shell \
             history — and it will not read one from a stdin nobody named, which is how a pty \
             wrapper ends up echoing it into a log."
        );
    }
    rpassword::prompt_password(prompt)
        .map_err(|e| anyhow::anyhow!("could not read the passphrase: {e}"))
}

/// The first line, with one trailing newline removed.
///
/// A trailing `\r` goes with it: a file written on Windows would otherwise
/// carry one into the key derivation, and what comes back then looks exactly
/// like a wrong passphrase rather than like a stray byte.
fn first_line(reader: &mut dyn std::io::BufRead, origin: &str) -> Result<String> {
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .with_context(|| format!("could not read a passphrase from {origin}"))?;
    let line = line.strip_suffix('\n').unwrap_or(&line);
    Ok(line.strip_suffix('\r').unwrap_or(line).to_string())
}

/// Refuse a passphrase file that anybody else on the machine can read.
///
/// With this flag the file *is* the secret, so it gets the rule ssh gives a
/// private key. Only the mode is checked: it is the mistake that actually
/// happens — a passphrase written with a default umask — and it is the one the
/// user can fix in one command.
#[cfg(unix)]
fn refuse_a_readable_file(path: &std::path::Path, file: &std::fs::File) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mode = file
        .metadata()
        .with_context(|| format!("could not stat {}", path.display()))?
        .permissions()
        .mode()
        & 0o777;
    if mode & 0o077 != 0 {
        anyhow::bail!(
            "{} is mode {mode:o}: its group or every user on this machine can read it, and with \
             --passphrase-file that file is the secret. Run `chmod 600 {}` and try again.",
            path.display(),
            path.display()
        );
    }
    Ok(())
}

/// No file mode to read, so nothing to check.
#[cfg(not(unix))]
fn refuse_a_readable_file(_path: &std::path::Path, _file: &std::fs::File) -> Result<()> {
    Ok(())
}

/// The first line of a descriptor the caller opened for us — `--passphrase-fd 3`
/// with a `3< …` redirect or a process substitution.
///
/// The descriptor belongs to that caller, so the `File` wrapper is leaked
/// rather than dropped: dropping it would close somebody else's fd.
#[cfg(unix)]
fn read_fd(fd: i32) -> Result<String> {
    use std::os::fd::FromRawFd;
    if fd < 0 {
        anyhow::bail!("--passphrase-fd {fd} is not a file descriptor");
    }
    let file = std::mem::ManuallyDrop::new(unsafe { std::fs::File::from_raw_fd(fd) });
    first_line(
        &mut std::io::BufReader::new(&*file),
        &format!("file descriptor {fd}"),
    )
}

#[cfg(not(unix))]
fn read_fd(fd: i32) -> Result<String> {
    anyhow::bail!("--passphrase-fd {fd} needs unix file descriptors; use --passphrase-file")
}

/// Twice for a typed passphrase, once for a file or a descriptor: a value
/// nobody typed cannot have been mistyped, and reading the same file twice
/// would only look like the tool did not believe the first read.
fn ask_passphrase_twice(source: &PassphraseSource) -> Result<String> {
    let first = read_passphrase(source, "passphrase for the bundle: ")?;
    if !source.is_typed() {
        return Ok(first);
    }
    let second = read_passphrase(source, "again: ")?;
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
    if !report.env_projects.is_empty() {
        // Metadata only, and saying so here is the point: an env project in a
        // bundle is a name, not a set of variables.
        println!(
            "  env:       {} project(s), names only ({})",
            report.env_projects.len(),
            report.env_projects.join(", ")
        );
    }
    println!(
        "  {} item(s) will need doing on the new machine",
        report.gaps
    );
    if let Some(sidecar) = &report.sidecar {
        // Named because it is the one file here that is safe to send ahead of
        // the bundle, and because the machine that needs it cannot read the
        // copy inside the bundle without the `pb` it explains how to install.
        println!(
            "  also wrote {} — install instructions in the clear, no inventory in it",
            file_name(sidecar)
        );
    }
    println!();
    for warning in &report.warnings {
        println!("{}", styles.paint(warn_style(), &format!("! {warning}")));
    }
    println!(
        "\nnext: copy the file across, then `pb import {}`",
        file_name(&report.path)
    );
    if let Some(sidecar) = &report.sidecar {
        println!(
            "      on a machine with no `pb` yet, start from {}",
            file_name(sidecar)
        );
    }
}

/// Written-to-a-file summary. Deliberately counts rather than lists: the file
/// itself is the listing, and a wall of tool names between the command and the
/// path buries the one line the reader needs.
fn print_manifest(manifest: &Manifest, path: &std::path::Path, styles: &Styles) {
    let installed = manifest.tools.iter().filter(|t| t.installed).count();
    println!("wrote {}", path.display());
    println!(
        "  {installed} CLI(s) installed, {} key(s), {} MCP registration(s), {} env project(s)",
        manifest.keys.len(),
        manifest.mcp.len(),
        manifest.env_projects.len(),
    );
    println!(
        "  {}",
        styles.paint(
            dim_style(),
            "no secret value is in this file — commit it, sync it, hand it to an agent"
        )
    );
    println!(
        "  {}",
        styles.paint(
            dim_style(),
            "on the new machine: pb plan --manifest <this file>"
        )
    );
}

fn file_name(path: &std::path::Path) -> String {
    path.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.display().to_string())
}

/// An import report is a run of independent sections, so this is a run of
/// independent printers. Nothing passes between them except the number of keys
/// the keychain refused, which the section that prints the keys is the only one
/// in a position to count and so is the one that returns it — the alternative,
/// a counter declared up here and mutated further down, is a variable whose
/// value depends on how far the reader has got.
fn print_import(report: &import::ImportReport, styles: &Styles) {
    print_dry_run_banner(report, styles);
    print_file_results(report);
    let keys_refused = print_key_results(report);
    print_mcp_results(report);
    print_env_project_results(report);
    println!();
    print_refused_key_warning(keys_refused, report.keys.len(), styles);
    print_notes(report, styles);
    print_remaining_plan(report, styles);
}

fn print_dry_run_banner(report: &import::ImportReport, styles: &Styles) {
    if report.dry_run {
        println!(
            "{}\n",
            styles.paint(warn_style(), "DRY RUN — nothing was written")
        );
    }
}

fn print_file_results(report: &import::ImportReport) {
    for file in &report.files {
        println!("  {:<10} {}", file.outcome.label(), file.path.display());
        if let import::FileOutcome::Replaced { backup: Some(at) } = &file.outcome {
            println!("             (was backed up to {})", at.display());
        }
        if let import::FileOutcome::Skipped { reason } = &file.outcome {
            println!("             {reason}");
        }
    }
}

/// Returns how many key values the keystore refused, for the warning below.
///
/// A key carries its reason the same way a file does. `restore_keys` puts
/// the keystore's error in there and this loop used to drop it, which turns
/// "every secret in the bundle was refused" into a column of bare `skip`
/// and leaves the one fact that explains it unprinted.
fn print_key_results(report: &import::ImportReport) -> usize {
    let mut keys_refused = 0usize;
    for key in &report.keys {
        println!("  {:<10} key {}", key.outcome.label(), key.id);
        if let import::FileOutcome::Skipped { reason } = &key.outcome {
            println!("             {reason}");
            keys_refused += 1;
        }
    }
    keys_refused
}

fn print_mcp_results(report: &import::ImportReport) {
    for server in &report.mcp {
        println!(
            "  {:<10} mcp {}/{}",
            server.outcome.label(),
            server.client,
            server.name
        );
    }
}

fn print_env_project_results(report: &import::ImportReport) {
    for project in &report.env_projects {
        println!(
            "  {:<10} env project {}",
            project.outcome.label(),
            project.id
        );
        if let import::FileOutcome::Skipped { reason } = &project.outcome {
            println!("             {reason}");
        }
    }
}

/// The file half of an import can succeed while every secret in it is
/// refused, and per-key lines scroll away. A keychain that will not take a
/// write is nearly always a session without a desktop login — over ssh, in
/// a cron job — which is a property of how the command was started and not
/// of the bundle, so it says how to start it differently.
fn print_refused_key_warning(keys_refused: usize, keys_total: usize, styles: &Styles) {
    if keys_refused > 0 {
        println!(
            "{}",
            styles.paint(
                warn_style(),
                &format!(
                    "! {keys_refused} of {keys_total} key value(s) never reached the keychain — \
                     the bundle still holds them, so nothing is lost, but the vault on this \
                     machine is incomplete. On macOS a keychain refuses every write from a \
                     session with no desktop login (ssh, cron): re-run this import from a \
                     Terminal in your own desktop session, and the file half above is idempotent \
                     — it will report `unchanged` rather than write anything twice."
                )
            )
        );
    }
}

fn print_notes(report: &import::ImportReport, styles: &Styles) {
    for note in &report.notes {
        println!("{}", styles.paint(warn_style(), &format!("! {note}")));
    }
}

fn print_remaining_plan(report: &import::ImportReport, styles: &Styles) {
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
        "setup_sidecar": report.sidecar,
        "files": report.files,
        "bytes": report.bytes,
        "tools_carried": report.tools_carried,
        "tools_needing_reauth": report.tools_bound,
        "key_values_included": report.keys_included,
        "keys_listed_only": report.keys_listed,
        "mcp_servers": report.mcp_carried,
        "mcp_value_names_carried": report.mcp_values_carried,
        "env_projects": report.env_projects,
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
        "keys_refused": report.keys_refused(),
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
        "env_projects": report.env_projects.iter().map(|p| serde_json::json!({
            "id": p.id, "action": p.outcome.label(),
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

    /// A passphrase file with the mode the flag insists on.
    #[cfg(unix)]
    fn passphrase_file(dir: &tempfile::TempDir, body: &str, mode: u32) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let path = dir.path().join("pass");
        std::fs::write(&path, body).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        path
    }

    #[cfg(unix)]
    #[test]
    fn test_a_passphrase_file_is_read_as_its_first_line() {
        let dir = tempfile::tempdir().unwrap();
        // A second line, and a trailing newline on the first: both are the
        // shape `echo … > pass` produces.
        let path = passphrase_file(&dir, "hunter2\nignored\n", 0o600);
        let source = PassphraseSource::File(path);
        assert_eq!(read_passphrase(&source, "p: ").unwrap(), "hunter2");
        // A file cannot be mistyped, so it is not read twice.
        assert_eq!(ask_passphrase_twice(&source).unwrap(), "hunter2");
    }

    #[cfg(unix)]
    #[test]
    fn test_a_passphrase_file_others_can_read_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        for mode in [0o640, 0o604, 0o666] {
            let path = passphrase_file(&dir, "hunter2\n", mode);
            let err = read_passphrase(&PassphraseSource::File(path), "p: ")
                .unwrap_err()
                .to_string();
            assert!(err.contains("chmod 600"), "mode {mode:o}: {err}");
            // The error may name the file; it may never name what is in it.
            assert!(!err.contains("hunter2"), "{err}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn test_a_passphrase_arrives_on_a_file_descriptor_the_caller_opened() {
        use std::os::fd::AsRawFd;
        let dir = tempfile::tempdir().unwrap();
        let path = passphrase_file(&dir, "hunter2\n", 0o600);
        let handle = std::fs::File::open(&path).unwrap();

        let read = read_passphrase(&PassphraseSource::Fd(handle.as_raw_fd()), "p: ").unwrap();
        assert_eq!(read, "hunter2");
        // The fd is still ours: reading it did not close it, which is what
        // `--passphrase-fd 3` depends on.
        assert!(handle.metadata().is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn test_an_empty_passphrase_is_refused_whatever_the_source() {
        let dir = tempfile::tempdir().unwrap();
        for body in ["", "\n", "\r\n"] {
            let path = passphrase_file(&dir, body, 0o600);
            let err = read_passphrase(&PassphraseSource::File(path), "p: ")
                .unwrap_err()
                .to_string();
            assert!(err.contains("empty passphrase"), "{body:?}: {err}");
        }
    }

    #[test]
    fn test_the_two_passphrase_flags_cannot_both_be_given() {
        let err = PassphraseSource::from_flags(Some(PathBuf::from("pass")), Some(3))
            .unwrap_err()
            .to_string();
        assert!(err.contains("--passphrase-file"), "{err}");
        assert!(err.contains("--passphrase-fd"), "{err}");

        // One of each is fine, and neither is the interactive default.
        assert_eq!(
            PassphraseSource::from_flags(Some(PathBuf::from("pass")), None).unwrap(),
            PassphraseSource::File(PathBuf::from("pass"))
        );
        assert_eq!(
            PassphraseSource::from_flags(None, Some(3)).unwrap(),
            PassphraseSource::Fd(3)
        );
        let default = PassphraseSource::from_flags(None, None).unwrap();
        assert_eq!(default, PassphraseSource::Prompt);
        assert!(default.is_typed());
    }

    #[test]
    fn test_a_first_line_loses_one_newline_and_nothing_else() {
        let mut line = std::io::Cursor::new(b"  hunter2 \r\nrest\n".to_vec());
        // Leading and trailing spaces are part of a passphrase; the line
        // ending is not.
        assert_eq!(first_line(&mut line, "test").unwrap(), "  hunter2 ");
        let mut no_newline = std::io::Cursor::new(b"hunter2".to_vec());
        assert_eq!(first_line(&mut no_newline, "test").unwrap(), "hunter2");
    }

    #[test]
    fn test_file_name_survives_a_bare_name() {
        assert_eq!(file_name(std::path::Path::new("a/b.pbx")), "b.pbx");
        assert_eq!(file_name(std::path::Path::new("b.pbx")), "b.pbx");
    }
}
