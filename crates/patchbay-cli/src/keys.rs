//! `pb key …` — the key vault in the terminal.
//!
//! Deliberate asymmetry, and the whole point of the design: **writing** a
//! secret is easy (pipe it in, or type it blind), **reading** one back is not.
//! There is no `pb key show`. A value leaves the vault two ways, neither of
//! them through this process's stdout, a shell history line or a log:
//! [`Command::Copy`] moves it from the keychain to the clipboard, and
//! [`Command::Run`] puts it straight into a child process's environment.
//!
//! Secrets never arrive as arguments either: argv is world-readable through
//! `ps` and gets written to `~/.zsh_history` verbatim.

use std::io::{IsTerminal, Read, Write};
use std::process::{Command as Process, Stdio};

use anyhow::{Context, Result};
use chrono::{DateTime, NaiveDate, NaiveTime, TimeZone, Utc};
use clap::{Args, Subcommand};
use patchbay_core::keys::{
    expiring_within_at, filter_keys, validate_env_name, KeyEntry, KeyFilter, KeyPatch, KeyRegistry,
    NewKey,
};
use patchbay_core::keys_verify::{verify_key, KeyVerifyOutcome, KeyVerifyStatus};
use patchbay_core::run_bounded;

use crate::render::{self, Styles};

/// Width budget for the list table, matching the status board.
const TABLE_WIDTH: usize = 100;
const GAP: usize = 2;
const COL_LAST4: usize = 5;
const COL_EXPIRES: usize = 16;
const COL_ID_MAX: usize = 24;
const COL_PROVIDER_MAX: usize = 12;
/// The ENV column pays for itself out of LABEL's budget: a variable name is
/// what a consumer looks a key up by, a label is only ever decoration.
const COL_ENV_MAX: usize = 22;
const COL_LABEL_MAX: usize = 18;
/// Width of the field-name column in `pb key edit`'s report of what changed.
const FIELD_COL: usize = 9;
/// Width of the verdict column in a `pb key verify` sweep: `inconclusive`, the
/// longest label there is.
const COL_VERDICT: usize = 12;
const DASH: &str = "—";

/// How many issuers a sweep talks to at once. Sixty round trips one after
/// another is a minute of watching a cursor; the ceiling is there because a
/// burst of parallel requests from one machine is what rate limiters exist to
/// notice, and it matches the one the version check already settled on.
const VERIFY_THREADS: usize = 8;

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Register a key patchbay should know about.
    ///
    /// The secret is read from stdin when something is piped in, and from a
    /// hidden prompt otherwise. It is never taken as an argument.
    Add(AddArgs),
    /// List registered keys. Metadata only — never values.
    List(ListArgs),
    /// Change a key's metadata. The stored value is never touched.
    ///
    /// Every `--no-*` clears its field. `id`, `last4` and the registration date
    /// are not editable: they describe the value in the keychain, and editing
    /// them here would only make the registry lie about it.
    Edit(EditArgs),
    /// Put a key's value on the clipboard, without printing it.
    Copy { id: String },
    /// Run a command with keys in its environment.
    ///
    /// The blessed path for an agent or a script that needs a credential: the
    /// value goes keychain → child process and never through a terminal, a log
    /// or a model's context. The parent environment is inherited and these are
    /// added to it, so the command still sees the shell it was launched from.
    #[command(after_help = "Examples:\n  \
        pb key run cloudflare-api-token-yjack-macbook -- wrangler deploy\n  \
        pb key run --as CF_TOKEN=cf-deploy neon-peregrine-ci -- ./deploy.sh")]
    Run {
        /// Keys to inject, each under its own recorded variable name.
        keys: Vec<String>,
        /// Inject ID under NAME for this run, whatever name it is stored with.
        #[arg(long = "as", value_name = "NAME=ID")]
        aliases: Vec<String>,
        /// The command, after `--`.
        #[arg(last = true, required = true, value_name = "CMD")]
        command: Vec<String>,
    },
    /// Ask the issuers whether keys still work.
    ///
    /// Exit codes: 1 a provider says one of them is dead, 2 nothing is dead but
    /// a provider could not be reached, 0 everything else — including the keys
    /// patchbay has no way to check.
    #[command(after_help = "Examples:\n  \
        pb key verify cf-r2-token-sonarqube-backups\n  \
        pb key verify cf-api gh-pat neon-api-key\n  \
        pb key verify --all")]
    Verify(VerifyArgs),
    /// Unregister a key: metadata entry and keychain item both.
    Rm {
        id: String,
        /// Skip the confirmation prompt.
        #[arg(long)]
        yes: bool,
    },
}

/// Everything `pb key verify` takes.
///
/// Ids are plural because they have to be: a vault of sixty keys and a checker
/// that answers one question per invocation is a checker nobody runs.
#[derive(Args, Debug)]
pub struct VerifyArgs {
    /// Keys to check. Leave empty only with `--all`.
    #[arg(value_name = "ID", required_unless_present = "all")]
    ids: Vec<String>,
    /// Check every registered key.
    #[arg(long, conflicts_with = "ids")]
    all: bool,
    /// The verdicts as JSON: a list when several keys were asked about, the
    /// bare object when it was one.
    #[arg(long)]
    json: bool,
    /// Report only: do not write the issuer's expiry and scopes back into
    /// the registry.
    #[arg(long)]
    no_update: bool,
}

/// Everything `pb key add` takes. The secret is deliberately absent: it is
/// read from stdin or a hidden prompt, never from argv.
#[derive(Args, Debug)]
pub struct AddArgs {
    /// Lowercase slug, unique in the vault, e.g. `cf-gh-actions-deploy`.
    id: String,
    /// Who issued it: `cloudflare`, `github`, `openai`, … Free-form.
    #[arg(long)]
    provider: Option<String>,
    /// Display name. Defaults to the id.
    #[arg(long)]
    label: Option<String>,
    /// What it is for, e.g. "deploy from GitHub Actions in repo X".
    #[arg(long)]
    purpose: Option<String>,
    /// Granted scopes, comma-separated.
    #[arg(long, value_delimiter = ',')]
    scopes: Vec<String>,
    /// Expiry: `2027-01-01`, or a full RFC 3339 timestamp.
    #[arg(long, value_name = "DATE")]
    expires: Option<String>,
    /// Instance URL, for providers with more than one address —
    /// `https://<you>.grafana.net`. Grafana needs it to verify.
    #[arg(long, value_name = "URL")]
    endpoint: Option<String>,
    /// Environment variable the key is exposed as, UPPER_SNAKE_CASE:
    /// `CLOUDFLARE_API_TOKEN`. What `pb key run` injects it as, and what an
    /// agent looks it up by.
    #[arg(long, value_name = "NAME")]
    env: Option<String>,
    /// Replace an existing entry with the same id (a rotation).
    #[arg(long)]
    overwrite: bool,
}

/// The listing's output mode and the filters that narrow it.
#[derive(Args, Debug)]
pub struct ListArgs {
    #[arg(long)]
    json: bool,
    /// Only keys expiring within this many days (already-expired included).
    #[arg(long, value_name = "DAYS")]
    expiring: Option<i64>,
    /// Only keys from this issuer.
    #[arg(long, value_name = "P")]
    provider: Option<String>,
    /// Only the key(s) exposed as this variable name.
    #[arg(long, value_name = "NAME")]
    env: Option<String>,
    /// Free text over id, label, provider, purpose and variable name.
    #[arg(long, value_name = "TEXT")]
    grep: Option<String>,
}

/// Which key to edit, and what to make of it.
#[derive(Args, Debug)]
pub struct EditArgs {
    /// The key to edit.
    id: String,
    #[command(flatten)]
    fields: EditFields,
}

/// The editable half of `pb key edit`, split out so the patch it describes can
/// be built — and tested — without a vault to write it to.
#[derive(Args, Debug)]
pub struct EditFields {
    /// Who issued it: `cloudflare`, `github`, `openai`, … Free-form.
    #[arg(long)]
    provider: Option<String>,
    /// Display name.
    #[arg(long)]
    label: Option<String>,
    /// What it is for, e.g. "deploy from GitHub Actions in repo X".
    #[arg(long, conflicts_with = "no_purpose")]
    purpose: Option<String>,
    /// Forget what this key is for.
    #[arg(long = "no-purpose")]
    no_purpose: bool,
    /// Replace the recorded scopes, comma-separated.
    #[arg(long, value_delimiter = ',')]
    scopes: Vec<String>,
    /// Expiry: `2027-01-01`, or a full RFC 3339 timestamp.
    #[arg(long, value_name = "DATE", conflicts_with = "no_expires")]
    expires: Option<String>,
    /// Forget the expiry.
    #[arg(long = "no-expires")]
    no_expires: bool,
    /// Instance URL, for providers with more than one address.
    #[arg(long, value_name = "URL", conflicts_with = "no_endpoint")]
    endpoint: Option<String>,
    /// Forget the instance URL.
    #[arg(long = "no-endpoint")]
    no_endpoint: bool,
    /// Environment variable the key is exposed as, UPPER_SNAKE_CASE.
    #[arg(long, value_name = "NAME", conflicts_with = "no_env")]
    env: Option<String>,
    /// Forget the variable name.
    #[arg(long = "no-env")]
    no_env: bool,
}

/// Returns the process exit code.
pub fn run(command: Command, styles: &Styles) -> Result<i32> {
    let registry = KeyRegistry::detect()?;

    match command {
        Command::Add(args) => add(&registry, args),
        Command::List(args) => list(&registry, args, styles),
        Command::Edit(args) => edit(&registry, args),
        Command::Copy { id } => copy(&registry, &id),
        Command::Run {
            keys,
            aliases,
            command,
        } => run_command(&registry, &keys, &aliases, &command),
        Command::Verify(args) => verify(&registry, args, styles),
        Command::Rm { id, yes } => rm(&registry, &id, yes),
    }
}

// ---------------------------------------------------------------------------
// add
// ---------------------------------------------------------------------------

/// `pb key add` — register a key and hand its value to the keychain.
fn add(registry: &KeyRegistry, args: AddArgs) -> Result<i32> {
    let AddArgs {
        id,
        provider,
        label,
        purpose,
        scopes,
        expires,
        endpoint,
        env,
        overwrite,
    } = args;

    let expires_at = expires.as_deref().map(parse_expiry).transpose()?;
    let new = NewKey::new(&id, "cli")
        .provider(provider.clone().unwrap_or_else(|| "unknown".to_string()))
        .label(label.unwrap_or_else(|| id.clone()))
        .purpose(purpose)
        .scopes(scopes)
        .expires_at(expires_at)
        .endpoint(endpoint)
        .env(env);

    let secret = read_secret(&id)?;
    let entry = registry.add(new, &secret, overwrite)?;
    drop(secret);

    println!("registered {} (…{})", entry.id, entry.last4);
    if let Some(endpoint) = &entry.endpoint {
        println!("  instance: {endpoint}");
    }
    if let Some(name) = &entry.env {
        println!("  env:      {name}");
    }
    println!("  value:    {}", registry.store_name());
    println!("  metadata: {}", registry.path().display());
    if provider.is_none() {
        println!("  hint: --provider makes the board far easier to scan");
    }
    if entry.expires_at.is_none() {
        println!("  hint: --expires lets patchbay warn you before it dies");
    }
    if entry.env.is_none() {
        println!("  hint: --env NAME lets `pb key run` and agents find it by the name code reads");
    }
    Ok(0)
}

// ---------------------------------------------------------------------------
// list
// ---------------------------------------------------------------------------

/// `pb key list` — the board, or the same rows as JSON.
fn list(registry: &KeyRegistry, args: ListArgs, styles: &Styles) -> Result<i32> {
    let ListArgs {
        json,
        expiring,
        provider,
        env,
        grep,
    } = args;

    let filter = KeyFilter {
        provider,
        env,
        query: grep,
    };
    let mut entries = registry.list()?;
    if let Some(days) = expiring {
        entries = expiring_within_at(&entries, Utc::now(), days);
    }
    // After the expiring cut, so the two narrow the same listing rather
    // than fighting over it.
    entries = filter_keys(&entries, &filter);

    if json {
        // Machine-readable: JSON only, no ANSI, no extras.
        println!("{}", serde_json::to_string_pretty(&entries)?);
        return Ok(0);
    }
    if entries.is_empty() {
        let active = active_filters(expiring, &filter);
        if active.is_empty() {
            println!("no keys registered yet");
            println!("  pb key add <id> --provider <who> --label \"<what>\"");
        } else if filter.is_empty() {
            // The expiring-only question deserves its own sentence: an
            // empty answer there is good news, not a failed search.
            println!(
                "no registered key expires within {}d",
                expiring.unwrap_or_default()
            );
        } else {
            println!("no registered key matches");
            println!("  filters: {}", active.join(", "));
        }
        return Ok(0);
    }
    print!("{}", render_table(&entries, Utc::now(), styles));
    Ok(0)
}

// ---------------------------------------------------------------------------
// copy
// ---------------------------------------------------------------------------

/// `pb key copy` — keychain → clipboard, with the value never touching stdout.
fn copy(registry: &KeyRegistry, id: &str) -> Result<i32> {
    let entry = registry
        .get(id)?
        .ok_or_else(|| anyhow::anyhow!("no key registered as `{id}`"))?;
    let secret = registry.get_secret(id)?;
    to_clipboard(&secret)?;
    drop(secret);
    println!("copied {} (…{}) to the clipboard", entry.id, entry.last4);
    println!("  it stays there until you copy something else — paste it and move on");
    Ok(0)
}

// ---------------------------------------------------------------------------
// rm
// ---------------------------------------------------------------------------

/// `pb key rm` — drop the metadata entry and the keychain item together.
fn rm(registry: &KeyRegistry, id: &str, yes: bool) -> Result<i32> {
    let entry = registry
        .get(id)?
        .ok_or_else(|| anyhow::anyhow!("no key registered as `{id}`"))?;
    if !yes && !confirm(&entry)? {
        println!("left {} alone", entry.id);
        return Ok(0);
    }
    let removed = registry.remove(id)?;
    println!("removed {} (…{})", removed.id, removed.last4);
    println!("  the value is gone from the {}", registry.store_name());
    println!("  revoke it at the provider too — patchbay only forgets it");
    Ok(0)
}

// ---------------------------------------------------------------------------
// verify
// ---------------------------------------------------------------------------

/// `pb key verify` — ask the issuers, then report (and usually record) what
/// they said.
fn verify(registry: &KeyRegistry, args: VerifyArgs, styles: &Styles) -> Result<i32> {
    let VerifyArgs {
        ids,
        all,
        json,
        no_update,
    } = args;

    let entries = verify_targets(registry, &ids, all)?;
    if entries.is_empty() {
        // Only reachable through `--all`. An id nobody registered is an error;
        // an empty vault is not.
        println!("no keys registered yet");
        return Ok(0);
    }

    let outcomes = verify_outcomes(registry, &entries)?;
    let updated = absorb_all(registry, &entries, &outcomes, no_update)?;

    // One key asked about by name keeps the answer it has always had: a full
    // block, and a bare object under `--json` that existing readers can still
    // index into. `--all` is a sweep and always answers as a list.
    let sweep = all || entries.len() > 1;
    if json {
        print_verify_json(&entries, &outcomes, &updated, sweep)?;
    } else if sweep {
        print_verify_sweep(&entries, &outcomes, &updated, styles);
    } else {
        print_verify(&entries[0], &outcomes[0], &updated[0], styles);
    }
    Ok(verify_exit_code(&outcomes))
}

/// The keys a run is about: everything registered under `--all`, otherwise the
/// ones named on the command line.
///
/// A named id nobody registered stops the run here rather than being filed as a
/// verdict, because it is a question patchbay cannot answer, not an answer.
fn verify_targets(registry: &KeyRegistry, ids: &[String], all: bool) -> Result<Vec<KeyEntry>> {
    if all {
        return registry.list();
    }
    ids.iter()
        .map(|id| {
            registry
                .get(id)?
                .ok_or_else(|| anyhow::anyhow!("no key registered as `{id}`"))
        })
        .collect()
}

/// Ask every issuer, a bounded number of them at a time.
///
/// Each secret is read inside the closure and dropped there, so even a sweep of
/// the whole vault never holds more than VERIFY_THREADS of them at once, and
/// none of them outlives its own request.
///
/// A value patchbay registered but cannot read back is a broken vault, not a
/// verdict about a key, so it stops the sweep instead of being filed as one.
fn verify_outcomes(registry: &KeyRegistry, entries: &[KeyEntry]) -> Result<Vec<KeyVerifyOutcome>> {
    run_bounded(entries, VERIFY_THREADS, |entry| {
        let secret = registry.get_secret(&entry.id)?;
        let outcome = verify_key(entry, &secret);
        drop(secret);
        Ok(outcome)
    })
    .into_iter()
    .collect()
}

/// What [`absorb`] wrote back for each key, in step with `entries`. `--no-update`
/// is a report-only run, so nothing is written and every key reports nothing.
///
/// Write-backs stay on this thread: they rewrite one metadata file, and eight
/// threads doing that would be eight chances to lose an entry.
fn absorb_all(
    registry: &KeyRegistry,
    entries: &[KeyEntry],
    outcomes: &[KeyVerifyOutcome],
    no_update: bool,
) -> Result<Vec<Vec<String>>> {
    let mut updated: Vec<Vec<String>> = Vec::new();
    for (entry, outcome) in entries.iter().zip(outcomes) {
        updated.push(if no_update {
            Vec::new()
        } else {
            absorb(registry, entry, outcome)?
        });
    }
    Ok(updated)
}

/// The verdicts as `--json`: a list for a sweep, the bare object for the one key
/// that was asked about by name.
fn print_verify_json(
    entries: &[KeyEntry],
    outcomes: &[KeyVerifyOutcome],
    updated: &[Vec<String>],
    sweep: bool,
) -> Result<()> {
    let mut values = Vec::new();
    for ((entry, outcome), updated) in entries.iter().zip(outcomes).zip(updated) {
        values.push(verify_json(entry, outcome, updated)?);
    }
    let value = if sweep {
        serde_json::Value::Array(values)
    } else {
        values.remove(0)
    };
    println!("{}", serde_json::to_string_pretty(&value)?);
    Ok(())
}

/// A sweep: one line per key, then the tally.
fn print_verify_sweep(
    entries: &[KeyEntry],
    outcomes: &[KeyVerifyOutcome],
    updated: &[Vec<String>],
    styles: &Styles,
) {
    let id_w = entries
        .iter()
        .map(|e| e.id.chars().count())
        .max()
        .unwrap_or_default();
    for ((entry, outcome), updated) in entries.iter().zip(outcomes).zip(updated) {
        println!("{}", verify_line(entry, outcome, id_w, styles));
        // The one thing a sweep must not do quietly. Rare, because it only
        // fires when the issuer knows something the registry did not.
        if !updated.is_empty() {
            println!(
                "  updated the registry from the provider: {}",
                updated.join(", ")
            );
        }
    }
    println!("{}", verify_summary(outcomes));
}

/// Three answers, because a script gating on this needs three.
///
/// `1` is the only one that means a key is dead, and it outranks everything: a
/// sweep that found one revoked token and lost the wifi halfway through is
/// still a sweep that found a revoked token. `2` is the honest answer when the
/// worst thing that happened was not being able to ask, which is neither a
/// clean bill of health nor a reason to rotate anything.
///
/// `inconclusive` and `unsupported` leave `0`, because both are patchbay
/// declining to answer about a key that gave it no reason for concern — and a
/// vault that is mostly providers patchbay cannot interrogate would otherwise
/// never exit clean.
fn verify_exit_code(outcomes: &[KeyVerifyOutcome]) -> i32 {
    if outcomes.iter().any(|o| o.status.is_bad_news()) {
        1
    } else if outcomes
        .iter()
        .any(|o| o.status == KeyVerifyStatus::Unreachable)
    {
        2
    } else {
        0
    }
}

/// One verdict as `--json`: the outcome, plus who it is about.
fn verify_json(
    entry: &KeyEntry,
    outcome: &KeyVerifyOutcome,
    updated: &[String],
) -> Result<serde_json::Value> {
    let mut value = serde_json::to_value(outcome)?;
    if let Some(map) = value.as_object_mut() {
        map.insert("id".into(), entry.id.clone().into());
        map.insert("provider".into(), entry.provider.clone().into());
        map.insert("metadata_updated".into(), updated.to_vec().into());
    }
    Ok(value)
}

/// One key's row in a sweep: the same verdict voice as the single-key report,
/// with the provider's message trimmed to whatever the line has left.
///
/// The id is never truncated, however wide it makes the column: the next thing
/// anyone does with a bad row is paste that id into another `pb key` command.
fn verify_line(
    entry: &KeyEntry,
    outcome: &KeyVerifyOutcome,
    id_w: usize,
    styles: &Styles,
) -> String {
    let verdict = styles.paint(
        verdict_style(outcome.status),
        &pad(outcome.status.label(), COL_VERDICT),
    );
    let detail_w = TABLE_WIDTH
        .saturating_sub(id_w + COL_VERDICT + GAP * 2)
        .max(20);
    let detail = render::truncate(&one_line(&outcome.detail), detail_w);
    let gap = " ".repeat(GAP);
    format!("{}{gap}{verdict}{gap}{detail}", pad(&entry.id, id_w))
        .trim_end()
        .to_string()
}

/// The tally that closes a sweep. Worst news first, and silent about the
/// verdicts nothing came back as.
fn verify_summary(outcomes: &[KeyVerifyOutcome]) -> String {
    const WORST_FIRST: [KeyVerifyStatus; 6] = [
        KeyVerifyStatus::Invalid,
        KeyVerifyStatus::Expired,
        KeyVerifyStatus::Inconclusive,
        KeyVerifyStatus::Unreachable,
        KeyVerifyStatus::Unsupported,
        KeyVerifyStatus::Valid,
    ];
    let tally: Vec<String> = WORST_FIRST
        .iter()
        .filter_map(|status| {
            let n = outcomes.iter().filter(|o| o.status == *status).count();
            (n > 0).then(|| format!("{n} {}", status.label()))
        })
        .collect();
    format!(
        "checked {} {}: {}",
        outcomes.len(),
        if outcomes.len() == 1 { "key" } else { "keys" },
        tally.join(", ")
    )
}

/// The colour a verdict draws in: green for good news, red for bad, and dim
/// for the answers that are not about the key at all.
fn verdict_style(status: KeyVerifyStatus) -> anstyle::Style {
    match status {
        KeyVerifyStatus::Valid => green(),
        KeyVerifyStatus::Invalid | KeyVerifyStatus::Expired => red(),
        KeyVerifyStatus::Inconclusive
        | KeyVerifyStatus::Unsupported
        | KeyVerifyStatus::Unreachable => dim(),
    }
}

/// Write back what the issuer just told us, and report what changed.
///
/// The provider is the authority on its own token, so a confirmed expiry or
/// scope list beats whatever was typed at registration time. Only a successful
/// verify may write: an unreachable provider must never blank a known expiry.
fn absorb(
    registry: &KeyRegistry,
    entry: &KeyEntry,
    outcome: &KeyVerifyOutcome,
) -> Result<Vec<String>> {
    if outcome.status != KeyVerifyStatus::Valid {
        return Ok(Vec::new());
    }
    let mut patch = KeyPatch::default();
    let mut changed = Vec::new();

    if let Some(at) = outcome.expires_at {
        if entry.expires_at != Some(at) {
            patch.expires_at = Some(Some(at));
            changed.push("expires_at".to_string());
        }
    }
    if !outcome.scopes.is_empty() && outcome.scopes != entry.scopes {
        patch.scopes = Some(outcome.scopes.clone());
        changed.push("scopes".to_string());
    }
    if patch.is_empty() {
        return Ok(Vec::new());
    }
    registry.update_metadata(&entry.id, patch)?;
    Ok(changed)
}

fn print_verify(entry: &KeyEntry, outcome: &KeyVerifyOutcome, updated: &[String], styles: &Styles) {
    println!(
        "{} (…{}) — {}",
        entry.id,
        entry.last4,
        styles.paint(verdict_style(outcome.status), outcome.status.label())
    );
    println!("  {}", one_line(&outcome.detail));

    if let Some(at) = outcome.expires_at {
        println!(
            "  expires: {} ({})",
            render::humanize_expiry(Utc::now(), at),
            at.format("%Y-%m-%d")
        );
    }
    if !outcome.scopes.is_empty() {
        println!("  scopes:  {}", outcome.scopes.join(", "));
    }
    if !updated.is_empty() {
        println!(
            "  updated the registry from the provider: {}",
            updated.join(", ")
        );
    }
    // `unsupported` covers two different situations: an issuer patchbay cannot
    // interrogate at all, and one it could if it had an address. Only the
    // second wants an endpoint, and the way to tell them apart is that the
    // provider's own message asked for one.
    if outcome.status == KeyVerifyStatus::Unsupported
        && entry.endpoint.is_none()
        && outcome.detail.contains("--endpoint")
    {
        println!(
            "  set one with: pb key add {} --provider {} --endpoint <url> --overwrite",
            entry.id, entry.provider
        );
    }
    if outcome.status == KeyVerifyStatus::Unreachable {
        println!("  the key was not tested — this is a connection problem, not a verdict");
    }
    if outcome.status == KeyVerifyStatus::Inconclusive {
        println!("  patchbay is not saying the key is dead — it is saying it cannot tell");
    }
}

// ---------------------------------------------------------------------------
// edit
// ---------------------------------------------------------------------------

/// `pb key edit` — apply a metadata patch, then read the stored entry back to
/// report what actually landed.
fn edit(registry: &KeyRegistry, args: EditArgs) -> Result<i32> {
    let EditArgs { id, fields } = args;
    let (patch, touched) = build_patch(fields)?;

    // A rejected name (`pb key edit x --env cf_token`) surfaces the
    // core's error verbatim: it already suggests the right spelling.
    let updated = registry.update_metadata(&id, patch)?;
    println!("updated {}", updated.id);
    for field in touched {
        let name = format!("{}:", field.label());
        println!("  {name:<FIELD_COL$} {}", field.value(&updated));
    }
    Ok(0)
}

/// The patch a set of `pb key edit` flags describes, and the fields it touches
/// — in the order they are reported. `Some(None)` is a deliberate clear, a
/// missing entry is "leave it alone", and an edit that would change nothing is
/// refused rather than written.
///
/// Pure, so every flag combination can be checked without a vault.
fn build_patch(fields: EditFields) -> Result<(KeyPatch, Vec<Field>)> {
    let EditFields {
        provider,
        label,
        purpose,
        no_purpose,
        scopes,
        expires,
        no_expires,
        endpoint,
        no_endpoint,
        env,
        no_env,
    } = fields;

    let mut patch = KeyPatch::default();
    let mut touched: Vec<Field> = Vec::new();

    if let Some(provider) = provider {
        patch.provider = Some(provider);
        touched.push(Field::Provider);
    }
    if let Some(label) = label {
        patch.label = Some(label);
        touched.push(Field::Label);
    }
    if no_purpose || purpose.is_some() {
        patch.purpose = Some(purpose);
        touched.push(Field::Purpose);
    }
    if !scopes.is_empty() {
        patch.scopes = Some(scopes);
        touched.push(Field::Scopes);
    }
    if no_expires || expires.is_some() {
        patch.expires_at = Some(expires.as_deref().map(parse_expiry).transpose()?);
        touched.push(Field::Expires);
    }
    if no_endpoint || endpoint.is_some() {
        patch.endpoint = Some(endpoint);
        touched.push(Field::Endpoint);
    }
    if no_env || env.is_some() {
        patch.env = Some(env);
        touched.push(Field::Env);
    }
    if patch.is_empty() {
        anyhow::bail!(
            "nothing to change; pass at least one of --provider, --label, --purpose, \
             --scopes, --expires, --endpoint, --env (or a --no-* to clear one)"
        );
    }
    Ok((patch, touched))
}

/// An editable metadata field, so `pb key edit` can report what it changed by
/// reading the *stored* entry back rather than echoing what was typed —
/// trimming and normalization happen in the core, and the report should show
/// what actually landed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Field {
    Provider,
    Label,
    Purpose,
    Scopes,
    Expires,
    Endpoint,
    Env,
}

impl Field {
    fn label(self) -> &'static str {
        match self {
            Self::Provider => "provider",
            Self::Label => "label",
            Self::Purpose => "purpose",
            Self::Scopes => "scopes",
            Self::Expires => "expires",
            Self::Endpoint => "endpoint",
            Self::Env => "env",
        }
    }

    /// This field on `entry`, as one line. A cleared field reads as a dash.
    fn value(self, entry: &KeyEntry) -> String {
        let or_dash = |v: Option<String>| v.unwrap_or_else(|| DASH.to_string());
        match self {
            Self::Provider => entry.provider.clone(),
            Self::Label => entry.label.clone(),
            Self::Purpose => or_dash(entry.purpose.as_deref().map(one_line)),
            Self::Scopes => {
                if entry.scopes.is_empty() {
                    DASH.to_string()
                } else {
                    entry.scopes.join(", ")
                }
            }
            Self::Expires => or_dash(entry.expires_at.map(|at| at.format("%Y-%m-%d").to_string())),
            Self::Endpoint => or_dash(entry.endpoint.clone()),
            Self::Env => or_dash(entry.env.clone()),
        }
    }
}

/// The filters a listing was narrowed by, for the "nothing matched" line. An
/// empty answer is only useful next to the question that produced it.
fn active_filters(expiring: Option<i64>, filter: &KeyFilter) -> Vec<String> {
    let mut active = Vec::new();
    if let Some(p) = &filter.provider {
        active.push(format!("provider={p}"));
    }
    if let Some(e) = &filter.env {
        active.push(format!("env={e}"));
    }
    if let Some(q) = &filter.query {
        active.push(format!("grep={q}"));
    }
    if let Some(days) = expiring {
        active.push(format!("expiring={days}d"));
    }
    active
}

// ---------------------------------------------------------------------------
// run
// ---------------------------------------------------------------------------

/// `pb key run` — resolve every requested key, then hand the values to a child
/// process's environment and nowhere else.
fn run_command(
    registry: &KeyRegistry,
    keys: &[String],
    aliases: &[String],
    command: &[String],
) -> Result<i32> {
    let (bin, args) = command
        .split_first()
        .ok_or_else(|| anyhow::anyhow!("nothing to run; pass a command after `--`"))?;
    let aliases = parse_aliases(aliases)?;

    // Everything is resolved before anything is spawned: a typo has to
    // fail here, not halfway through a deploy.
    let mut entries: Vec<KeyEntry> = Vec::new();
    for id in keys.iter().chain(aliases.iter().map(|(_, id)| id)) {
        if entries.iter().any(|e| &e.id == id) {
            continue;
        }
        entries.push(
            registry
                .get(id)?
                .ok_or_else(|| anyhow::anyhow!("no key registered as `{id}`"))?,
        );
    }
    let plan = injection_plan(&entries, keys, &aliases)?;

    // stderr, so a command whose stdout is being piped stays clean —
    // and names only, never a value or a fragment of one.
    let named: Vec<String> = plan
        .iter()
        .map(|(name, id)| format!("{name} ({id})"))
        .collect();
    eprintln!("injecting {} into `{bin}`", named.join(", "));

    let mut child = std::process::Command::new(bin);
    child.args(args);
    // The parent environment is inherited on purpose: unlike
    // `pb env run`, this adds a few credentials to an otherwise normal
    // shell rather than defining the whole environment.
    for (name, id) in &plan {
        let secret = registry.get_secret(id)?;
        child.env(name, &secret);
        drop(secret);
    }
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

/// `NAME=ID`, split on the first `=` so a key id containing one is still
/// readable. The name is held to the same shape a stored one is: an alias is a
/// variable name too, and a run is no excuse to invent a second spelling.
fn parse_aliases(raw: &[String]) -> Result<Vec<(String, String)>> {
    raw.iter()
        .map(|spec| {
            let (name, id) = spec.split_once('=').ok_or_else(|| {
                anyhow::anyhow!(
                    "`{spec}` is not a NAME=ID pair; write it like \
                     --as CF_TOKEN=cloudflare-api-token"
                )
            })?;
            let (name, id) = (name.trim(), id.trim());
            validate_env_name(name)?;
            if id.is_empty() {
                anyhow::bail!(
                    "`--as {spec}` names no key; write it like \
                     --as CF_TOKEN=cloudflare-api-token"
                );
            }
            Ok((name.to_string(), id.to_string()))
        })
        .collect()
}

/// The `(variable name, key id)` pairs a run injects, in the order they were
/// asked for: positional ids under their recorded name, then the `--as`
/// aliases. Pure, so the whole resolution can be tested without a keychain.
///
/// Two ids landing on one name is refused rather than resolved: silently
/// letting the later one win would hand a command a credential the caller did
/// not think they were passing.
fn injection_plan(
    entries: &[KeyEntry],
    ids: &[String],
    aliases: &[(String, String)],
) -> Result<Vec<(String, String)>> {
    let mut plan: Vec<(String, String)> = Vec::new();
    let mut add = |name: String, id: String| -> Result<()> {
        // The same injection asked for twice (positionally and by alias) is
        // one injection, not a collision.
        if plan.iter().any(|(n, i)| n == &name && i == &id) {
            return Ok(());
        }
        if let Some((_, other)) = plan.iter().find(|(n, _)| n == &name) {
            anyhow::bail!(
                "`{other}` and `{id}` would both be injected as {name}; \
                 give one of them another name with `--as OTHER_NAME={id}`"
            );
        }
        plan.push((name, id));
        Ok(())
    };

    for id in ids {
        let entry = entries
            .iter()
            .find(|e| &e.id == id)
            .ok_or_else(|| anyhow::anyhow!("no key registered as `{id}`"))?;
        let name = entry.env.clone().ok_or_else(|| {
            anyhow::anyhow!(
                "`{id}` has no env name; set one with `pb key edit {id} --env NAME`, \
                 or pass --as NAME={id} for this run"
            )
        })?;
        add(name, id.clone())?;
    }
    for (name, id) in aliases {
        add(name.clone(), id.clone())?;
    }
    Ok(plan)
}

// ---------------------------------------------------------------------------
// input
// ---------------------------------------------------------------------------

/// Read the secret from a pipe, or prompt for it without echo.
///
/// Piped input is trimmed of its trailing newline only — `echo` adds one, and a
/// key with meaningful leading whitespace is not ours to mangle.
fn read_secret(id: &str) -> Result<String> {
    let stdin = std::io::stdin();
    if stdin.is_terminal() {
        let secret = rpassword::prompt_password(format!("secret for {id} (not echoed): "))
            .context("could not read the secret from the terminal")?;
        if secret.is_empty() {
            anyhow::bail!("no secret entered");
        }
        return Ok(secret);
    }
    let mut buf = String::new();
    stdin
        .lock()
        .read_to_string(&mut buf)
        .context("could not read the secret from stdin")?;
    let secret = buf.trim_end_matches(['\n', '\r']).to_string();
    if secret.is_empty() {
        anyhow::bail!(
            "nothing on stdin; pipe the secret in, or run this from a terminal to be prompted"
        );
    }
    Ok(secret)
}

/// `y`/`yes` on stdin. Anything else, including EOF, means no.
fn confirm(entry: &KeyEntry) -> Result<bool> {
    print!(
        "remove {} (…{}) and delete its value from the keychain? [y/N] ",
        entry.id, entry.last4
    );
    std::io::stdout().flush().ok();
    let mut answer = String::new();
    if std::io::stdin().read_line(&mut answer)? == 0 {
        println!();
        return Ok(false);
    }
    Ok(matches!(
        answer.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
}

/// `2027-01-01` (midnight UTC) or any timestamp dialect the core understands.
fn parse_expiry(raw: &str) -> Result<DateTime<Utc>> {
    if let Ok(date) = NaiveDate::parse_from_str(raw.trim(), "%Y-%m-%d") {
        let midnight = date.and_time(NaiveTime::MIN);
        return Ok(Utc.from_utc_datetime(&midnight));
    }
    patchbay_core::util::parse_timestamp(raw)
        .ok_or_else(|| anyhow::anyhow!("could not read `{raw}` as a date; try `2027-01-01`"))
}

// ---------------------------------------------------------------------------
// output
// ---------------------------------------------------------------------------

/// Hand the value to `pbcopy` on stdin. Never argv, never stdout.
fn to_clipboard(secret: &str) -> Result<()> {
    let mut child = Process::new("pbcopy")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .context("could not run `pbcopy`")?;
    child
        .stdin
        .take()
        .ok_or_else(|| anyhow::anyhow!("`pbcopy` gave us no stdin"))?
        .write_all(secret.as_bytes())
        .context("could not write to `pbcopy`")?;
    let status = child.wait().context("`pbcopy` did not finish")?;
    if !status.success() {
        anyhow::bail!("`pbcopy` exited with {status}");
    }
    Ok(())
}

fn pad(s: &str, width: usize) -> String {
    let len = s.chars().count();
    if len >= width {
        s.to_string()
    } else {
        format!("{s}{}", " ".repeat(width - len))
    }
}

fn one_line(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
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

/// The list table. `now` is injected so this is testable without a clock.
pub fn render_table(entries: &[KeyEntry], now: DateTime<Utc>, styles: &Styles) -> String {
    let id_w = column_width(
        entries.iter().map(|e| e.id.chars().count()),
        "ID",
        COL_ID_MAX,
    );
    let provider_w = column_width(
        entries.iter().map(|e| e.provider.chars().count()),
        "PROVIDER",
        COL_PROVIDER_MAX,
    );
    let env_w = column_width(
        entries
            .iter()
            .map(|e| e.env.as_deref().map_or(0, |v| v.chars().count())),
        "ENV",
        COL_ENV_MAX,
    );
    let label_w = column_width(
        entries.iter().map(|e| e.label.chars().count()),
        "LABEL",
        COL_LABEL_MAX,
    );
    let fixed = id_w + provider_w + env_w + label_w + COL_LAST4 + COL_EXPIRES + GAP * 6;
    let purpose_w = TABLE_WIDTH.saturating_sub(fixed).max(12);

    let gap = " ".repeat(GAP);
    let mut out = String::new();

    let header = format!(
        "{}{gap}{}{gap}{}{gap}{}{gap}{}{gap}{}{gap}{}",
        pad("ID", id_w),
        pad("PROVIDER", provider_w),
        pad("ENV", env_w),
        pad("LABEL", label_w),
        pad("LAST4", COL_LAST4),
        pad("EXPIRES", COL_EXPIRES),
        "PURPOSE",
    );
    out.push_str(&styles.paint(bold(), header.trim_end()));
    out.push('\n');

    for entry in entries {
        let id = pad(&render::truncate(&entry.id, id_w), id_w);
        let provider = pad(&render::truncate(&entry.provider, provider_w), provider_w);
        // No variable name is a fact about the key, not a warning — same
        // treatment as a missing expiry.
        let env = match &entry.env {
            Some(name) => pad(&render::truncate(name, env_w), env_w),
            None => styles.paint(dim(), &pad(DASH, env_w)),
        };
        let label = pad(&render::truncate(&entry.label, label_w), label_w);
        let last4 = pad(&entry.last4, COL_LAST4);

        // No expiry is a fact about the key, not a warning: dim, not colored.
        let (expires_text, expires_style) = match entry.expires_at {
            Some(at) => (
                render::truncate(&render::humanize_expiry(now, at), COL_EXPIRES),
                render::expiry_level(now, at).style(),
            ),
            None => (DASH.to_string(), dim()),
        };
        let expires = styles.paint(expires_style, &pad(&expires_text, COL_EXPIRES));

        let purpose = match &entry.purpose {
            Some(p) => render::truncate(&one_line(p), purpose_w),
            None => String::new(),
        };
        let purpose = if purpose.is_empty() {
            purpose
        } else {
            styles.paint(dim(), &purpose)
        };

        let line = format!(
            "{id}{gap}{provider}{gap}{env}{gap}{label}{gap}{last4}{gap}{expires}{gap}{purpose}"
        );
        out.push_str(line.trim_end());
        out.push('\n');
    }
    out
}

fn bold() -> anstyle::Style {
    anstyle::Style::new() | anstyle::Effects::BOLD
}

fn dim() -> anstyle::Style {
    anstyle::Style::new() | anstyle::Effects::DIMMED
}

fn red() -> anstyle::Style {
    anstyle::Style::new().fg_color(Some(anstyle::AnsiColor::Red.into()))
}

fn green() -> anstyle::Style {
    anstyle::Style::new().fg_color(Some(anstyle::AnsiColor::Green.into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    fn now() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc)
    }

    fn entry(id: &str, expires: Option<DateTime<Utc>>) -> KeyEntry {
        KeyEntry {
            id: id.to_string(),
            provider: "cloudflare".into(),
            label: "CF deploy token".into(),
            purpose: Some("deploy from\nGitHub Actions".into()),
            scopes: vec!["workers:edit".into()],
            created_at: now(),
            expires_at: expires,
            last4: "1234".into(),
            source: "cli".into(),
            endpoint: None,
            env: None,
        }
    }

    fn with_env(id: &str, env: Option<&str>) -> KeyEntry {
        KeyEntry {
            env: env.map(Into::into),
            ..entry(id, None)
        }
    }

    #[test]
    fn test_table_is_plain_and_aligned_without_color() {
        let entries = vec![
            entry("cf-gh-actions-deploy", Some(now() + Duration::days(30))),
            entry("no-expiry", None),
        ];
        let out = render_table(&entries, now(), &Styles::new(false));
        assert!(!out.contains('\u{1b}'), "plain mode must emit no ANSI");

        let lines: Vec<&str> = out.lines().collect();
        assert!(lines[0].starts_with("ID"));
        assert!(lines[1].contains("cf-gh-actions-deploy"));
        assert!(lines[1].contains("1234"));
        assert!(lines[1].contains("in 30d"));
        // The multi-line purpose is flattened onto its own row, so it cannot
        // break alignment — header plus one line per key, nothing else.
        assert_eq!(lines.len(), 3, "{out}");
        assert!(lines[1].contains("deploy from GitHub"), "{out}");
        assert!(lines[2].contains(DASH), "no expiry should render as a dash");

        let col = lines[0].find("PROVIDER").unwrap();
        assert!(lines[1][col..].starts_with("cloudflare"));
        assert!(lines[2][col..].starts_with("cloudflare"));
    }

    #[test]
    fn test_env_column_sits_between_provider_and_label() {
        let entries = vec![
            with_env("cf-deploy", Some("CLOUDFLARE_API_TOKEN")),
            with_env("duns", None),
        ];
        let out = render_table(&entries, now(), &Styles::new(false));
        let lines: Vec<&str> = out.lines().collect();

        let provider_col = lines[0].find("PROVIDER").unwrap();
        let env_col = lines[0].find("ENV").unwrap();
        let label_col = lines[0].find("LABEL").unwrap();
        assert!(provider_col < env_col && env_col < label_col, "{out}");

        assert!(
            lines[1][env_col..].starts_with("CLOUDFLARE_API_TOKEN"),
            "{out}"
        );
        // No name is a dash in the same column, not a hole in the row.
        assert!(lines[2][env_col..].starts_with(DASH), "{out}");
        assert!(
            lines[1][label_col..].starts_with("CF deploy token"),
            "{out}"
        );
    }

    #[test]
    fn test_a_long_env_name_is_truncated_into_its_column() {
        let long = "A".repeat(COL_ENV_MAX + 20);
        let out = render_table(&[with_env("k", Some(&long))], now(), &Styles::new(false));
        assert!(!out.contains(&long), "{out}");
        assert!(
            out.contains(&format!("{}…", "A".repeat(COL_ENV_MAX - 1))),
            "{out}"
        );
    }

    #[test]
    fn test_table_never_shows_a_secret_field() {
        // The only thing derived from the value that may appear is last4.
        let out = render_table(&[entry("k", None)], now(), &Styles::new(false));
        assert!(out.contains("1234"));
        assert!(!out.to_lowercase().contains("secret"));
    }

    #[test]
    fn test_expired_key_is_colored_when_color_is_on() {
        let out = render_table(
            &[entry("old", Some(now() - Duration::days(2)))],
            now(),
            &Styles::new(true),
        );
        assert!(out.contains('\u{1b}'));
        assert!(out.contains("expired 2d ago"));
    }

    /// A vault in a tempdir over a fake keystore: `absorb` is registry logic,
    /// and no test may touch the real keychain or the network.
    fn vault() -> (tempfile::TempDir, KeyRegistry) {
        let dir = tempfile::tempdir().unwrap();
        let registry = KeyRegistry::new(
            dir.path().join("keys.json"),
            Box::new(patchbay_core::keystore::MemoryKeystore::new()),
        );
        (dir, registry)
    }

    fn outcome(status: KeyVerifyStatus) -> KeyVerifyOutcome {
        KeyVerifyOutcome {
            status,
            detail: "detail".into(),
            expires_at: None,
            scopes: vec![],
        }
    }

    #[test]
    fn test_a_valid_verify_writes_the_issuers_expiry_and_scopes_back() {
        let (_dir, registry) = vault();
        let entry = registry
            .add(
                NewKey::new("gh-pat", "cli").provider("github"),
                "token-1234",
                false,
            )
            .unwrap();
        assert_eq!(entry.expires_at, None);

        let expires = Utc::now() + chrono::Duration::days(90);
        let mut good = outcome(KeyVerifyStatus::Valid);
        good.expires_at = Some(expires);
        good.scopes = vec!["repo".into(), "workflow".into()];

        let changed = absorb(&registry, &entry, &good).unwrap();
        assert_eq!(changed, vec!["expires_at", "scopes"]);

        let stored = registry.get("gh-pat").unwrap().unwrap();
        assert_eq!(stored.expires_at, Some(expires));
        assert_eq!(stored.scopes, vec!["repo", "workflow"]);
        // The value is untouched by a metadata write-back.
        assert_eq!(registry.get_secret("gh-pat").unwrap(), "token-1234");

        // Verifying again changes nothing, so the output stays quiet.
        let entry = registry.get("gh-pat").unwrap().unwrap();
        assert!(absorb(&registry, &entry, &good).unwrap().is_empty());
    }

    #[test]
    fn test_only_a_valid_verify_may_write_back() {
        let (_dir, registry) = vault();
        let expires = Utc::now() + chrono::Duration::days(10);
        let entry = registry
            .add(
                NewKey::new("cf-api", "cli")
                    .provider("cloudflare")
                    .expires_at(Some(expires)),
                "value-1234",
                false,
            )
            .unwrap();

        // An unreachable provider knows nothing and must not blank the expiry
        // we already had.
        for status in [
            KeyVerifyStatus::Unreachable,
            KeyVerifyStatus::Unsupported,
            KeyVerifyStatus::Inconclusive,
            KeyVerifyStatus::Invalid,
            KeyVerifyStatus::Expired,
        ] {
            let mut out = outcome(status);
            out.expires_at = Some(Utc::now() + chrono::Duration::days(999));
            out.scopes = vec!["should-not-land".into()];
            assert!(
                absorb(&registry, &entry, &out).unwrap().is_empty(),
                "{status:?} must not write metadata"
            );
        }
        let stored = registry.get("cf-api").unwrap().unwrap();
        assert_eq!(stored.expires_at, Some(expires));
        assert!(stored.scopes.is_empty());
    }

    #[test]
    fn test_an_empty_scope_list_never_wipes_a_recorded_one() {
        let (_dir, registry) = vault();
        let entry = registry
            .add(
                NewKey::new("cf-api", "cli")
                    .provider("cloudflare")
                    .scopes(vec!["workers:edit".into()]),
                "value-1234",
                false,
            )
            .unwrap();

        // Cloudflare's verify endpoint reports no policies; that silence is not
        // evidence the key has no scopes.
        let changed = absorb(&registry, &entry, &outcome(KeyVerifyStatus::Valid)).unwrap();
        assert!(changed.is_empty());
        assert_eq!(
            registry.get("cf-api").unwrap().unwrap().scopes,
            vec!["workers:edit"]
        );
    }

    /// `pb key …` as clap sees it, without standing up the whole `pb` parser.
    #[derive(clap::Parser, Debug)]
    struct KeyCli {
        #[command(subcommand)]
        command: Command,
    }

    fn parse_verify(argv: &[&str]) -> Result<VerifyArgs, clap::Error> {
        use clap::Parser;
        match KeyCli::try_parse_from(argv)?.command {
            Command::Verify(args) => Ok(args),
            other => panic!("expected verify, parsed {other:?}"),
        }
    }

    #[test]
    fn test_verify_takes_a_list_of_ids_and_all_takes_none() {
        // What this replaces: `pb key verify a b c` was "unexpected argument
        // 'b' found", which made a 64-key vault 64 invocations.
        let args = parse_verify(&["pb", "verify", "a", "b", "c"]).unwrap();
        assert_eq!(args.ids, vec!["a", "b", "c"]);
        assert!(!args.all);

        let args = parse_verify(&["pb", "verify", "--all"]).unwrap();
        assert!(args.all && args.ids.is_empty());

        // Naming nothing is a mistake, not a sweep, and naming ids alongside
        // `--all` is two different questions at once.
        assert!(parse_verify(&["pb", "verify"]).is_err());
        assert!(parse_verify(&["pb", "verify", "--all", "a"]).is_err());
    }

    #[test]
    fn test_a_sweep_line_keeps_the_whole_id_and_spends_what_is_left_on_the_detail() {
        let long = "cf-r2-token-sonarqube-backups";
        let id_w = long.chars().count();
        let mut wordy = outcome(KeyVerifyStatus::Inconclusive);
        wordy.detail = "Cloudflare said `Invalid API Token` to both checks patchbay can make, \
                        and a token scoped to one product answers exactly like a revoked one"
            .to_string();

        let line = verify_line(&entry(long, None), &wordy, id_w, &Styles::new(false));
        assert!(line.starts_with(long), "the id must survive intact: {line}");
        assert!(line.contains("inconclusive"), "{line}");
        assert!(line.ends_with('…'), "a long detail is trimmed, not wrapped");
        assert!(line.chars().count() <= TABLE_WIDTH, "{line}");

        // A shorter id in the same sweep still lines its verdict up with the
        // widest one's.
        let short = verify_line(
            &entry("cf-api", None),
            &outcome(KeyVerifyStatus::Valid),
            id_w,
            &Styles::new(false),
        );
        assert_eq!(
            short.find("valid").unwrap(),
            line.find("inconclusive").unwrap(),
            "{short}\n{line}"
        );
    }

    #[test]
    fn test_the_sweep_summary_leads_with_the_bad_news_and_names_only_what_came_back() {
        let outcomes = vec![
            outcome(KeyVerifyStatus::Valid),
            outcome(KeyVerifyStatus::Valid),
            outcome(KeyVerifyStatus::Unsupported),
            outcome(KeyVerifyStatus::Inconclusive),
            outcome(KeyVerifyStatus::Invalid),
        ];
        assert_eq!(
            verify_summary(&outcomes),
            "checked 5 keys: 1 invalid, 1 inconclusive, 1 unsupported, 2 valid"
        );
        assert_eq!(
            verify_summary(&[outcome(KeyVerifyStatus::Valid)]),
            "checked 1 key: 1 valid"
        );
    }

    #[test]
    fn test_only_a_provider_saying_a_key_is_dead_fails_the_command() {
        for status in [
            KeyVerifyStatus::Valid,
            KeyVerifyStatus::Unsupported,
            KeyVerifyStatus::Inconclusive,
        ] {
            assert_eq!(verify_exit_code(&[outcome(status)]), 0, "{status:?}");
        }
        for status in [KeyVerifyStatus::Invalid, KeyVerifyStatus::Expired] {
            assert_eq!(verify_exit_code(&[outcome(status)]), 1, "{status:?}");
        }
        // One dead key does not get lost in a sweep of good ones.
        assert_eq!(
            verify_exit_code(&[
                outcome(KeyVerifyStatus::Valid),
                outcome(KeyVerifyStatus::Expired),
                outcome(KeyVerifyStatus::Unsupported),
            ]),
            1
        );
    }

    #[test]
    fn test_a_provider_that_could_not_be_reached_is_its_own_exit_code() {
        // Neither a clean bill of health nor a reason to rotate: a script that
        // gates on this needs to be able to tell "nothing wrong" from "could
        // not ask".
        assert_eq!(
            verify_exit_code(&[outcome(KeyVerifyStatus::Unreachable)]),
            2
        );
        assert_eq!(
            verify_exit_code(&[
                outcome(KeyVerifyStatus::Valid),
                outcome(KeyVerifyStatus::Unreachable),
                outcome(KeyVerifyStatus::Inconclusive),
            ]),
            2
        );
        // Bad news outranks it. A sweep that found a revoked token and then
        // lost the wifi still found a revoked token.
        assert_eq!(
            verify_exit_code(&[
                outcome(KeyVerifyStatus::Unreachable),
                outcome(KeyVerifyStatus::Invalid),
            ]),
            1
        );
    }

    #[test]
    fn test_parse_aliases_splits_on_the_first_equals_and_validates_the_name() {
        let raw = |v: &[&str]| -> Vec<String> { v.iter().map(|s| s.to_string()).collect() };

        assert_eq!(
            parse_aliases(&raw(&["CF_TOKEN=cf-deploy", " NEON_API_KEY = neon-ci "])).unwrap(),
            vec![
                ("CF_TOKEN".to_string(), "cf-deploy".to_string()),
                ("NEON_API_KEY".to_string(), "neon-ci".to_string()),
            ]
        );
        // An id may contain `=`; only the first one separates.
        assert_eq!(
            parse_aliases(&raw(&["TOKEN=weird=id"])).unwrap(),
            vec![("TOKEN".to_string(), "weird=id".to_string())]
        );

        let err = parse_aliases(&raw(&["CF_TOKEN"])).unwrap_err().to_string();
        assert!(err.contains("NAME=ID"), "{err}");
        let err = parse_aliases(&raw(&["CF_TOKEN="])).unwrap_err().to_string();
        assert!(err.contains("names no key"), "{err}");
        // The core owns the shape rule, and its suggestion comes through.
        let err = parse_aliases(&raw(&["cf_token=cf-deploy"]))
            .unwrap_err()
            .to_string();
        assert!(err.contains("UPPER_SNAKE_CASE"), "{err}");
        assert!(err.contains("`CF_TOKEN`"), "{err}");
    }

    #[test]
    fn test_injection_plan_uses_the_recorded_name_and_lets_an_alias_override_it() {
        let entries = vec![
            with_env("cf-deploy", Some("CLOUDFLARE_API_TOKEN")),
            with_env("neon-ci", Some("NEON_API_KEY")),
        ];
        let ids = |v: &[&str]| -> Vec<String> { v.iter().map(|s| s.to_string()).collect() };
        let alias = |name: &str, id: &str| (name.to_string(), id.to_string());

        assert_eq!(
            injection_plan(&entries, &ids(&["cf-deploy", "neon-ci"]), &[]).unwrap(),
            vec![
                alias("CLOUDFLARE_API_TOKEN", "cf-deploy"),
                alias("NEON_API_KEY", "neon-ci"),
            ]
        );

        // An alias alone: no positional id needed.
        assert_eq!(
            injection_plan(&entries, &[], &[alias("CF_TOKEN", "cf-deploy")]).unwrap(),
            vec![alias("CF_TOKEN", "cf-deploy")]
        );

        // The same key both ways is two injections under two names.
        assert_eq!(
            injection_plan(
                &entries,
                &ids(&["cf-deploy"]),
                &[alias("CF_TOKEN", "cf-deploy")]
            )
            .unwrap(),
            vec![
                alias("CLOUDFLARE_API_TOKEN", "cf-deploy"),
                alias("CF_TOKEN", "cf-deploy"),
            ]
        );

        // ...and asking for the very same injection twice is not a collision.
        assert_eq!(
            injection_plan(
                &entries,
                &ids(&["cf-deploy"]),
                &[alias("CLOUDFLARE_API_TOKEN", "cf-deploy")]
            )
            .unwrap(),
            vec![alias("CLOUDFLARE_API_TOKEN", "cf-deploy")]
        );
    }

    #[test]
    fn test_injection_plan_refuses_a_key_with_no_name_and_a_collision() {
        let entries = vec![
            with_env("cf-deploy", Some("CLOUDFLARE_API_TOKEN")),
            with_env("cf-r2", Some("CLOUDFLARE_API_TOKEN")),
            with_env("duns", None),
        ];
        let ids = |v: &[&str]| -> Vec<String> { v.iter().map(|s| s.to_string()).collect() };

        let err = injection_plan(&entries, &ids(&["duns"]), &[])
            .unwrap_err()
            .to_string();
        assert!(err.contains("has no env name"), "{err}");
        assert!(err.contains("pb key edit duns --env NAME"), "{err}");
        assert!(err.contains("--as NAME=duns"), "{err}");

        // Two keys of one provider share a conventional name; the run has to
        // say which is which rather than let the second win.
        let err = injection_plan(&entries, &ids(&["cf-deploy", "cf-r2"]), &[])
            .unwrap_err()
            .to_string();
        assert!(err.contains("cf-deploy"), "{err}");
        assert!(err.contains("cf-r2"), "{err}");
        assert!(err.contains("CLOUDFLARE_API_TOKEN"), "{err}");

        let err = injection_plan(&entries, &ids(&["ghost"]), &[])
            .unwrap_err()
            .to_string();
        assert!(err.contains("no key registered as `ghost`"), "{err}");
    }

    #[test]
    fn test_edit_reports_a_cleared_field_as_a_dash() {
        let mut e = entry("k", Some(now()));
        e.env = Some("CLOUDFLARE_API_TOKEN".into());

        assert_eq!(Field::Provider.value(&e), "cloudflare");
        assert_eq!(Field::Env.value(&e), "CLOUDFLARE_API_TOKEN");
        assert_eq!(Field::Scopes.value(&e), "workers:edit");
        assert_eq!(Field::Expires.value(&e), "2026-01-01");
        // A multi-line purpose is flattened, exactly as in the table.
        assert_eq!(Field::Purpose.value(&e), "deploy from GitHub Actions");

        let cleared = KeyEntry {
            purpose: None,
            scopes: vec![],
            expires_at: None,
            endpoint: None,
            env: None,
            ..e
        };
        for field in [
            Field::Purpose,
            Field::Scopes,
            Field::Expires,
            Field::Endpoint,
            Field::Env,
        ] {
            assert_eq!(field.value(&cleared), DASH, "{}", field.label());
        }
        // Every label, plus its colon, fits the column the report pads to.
        for field in [
            Field::Provider,
            Field::Label,
            Field::Purpose,
            Field::Scopes,
            Field::Expires,
            Field::Endpoint,
            Field::Env,
        ] {
            assert!(field.label().len() < FIELD_COL, "{}", field.label());
        }
    }

    #[test]
    fn test_active_filters_names_the_question_an_empty_listing_answered() {
        assert!(active_filters(None, &KeyFilter::default()).is_empty());
        assert_eq!(
            active_filters(
                Some(30),
                &KeyFilter {
                    provider: Some("cloudflare".into()),
                    env: Some("CLOUDFLARE_API_TOKEN".into()),
                    query: Some("deploy".into()),
                }
            ),
            vec![
                "provider=cloudflare",
                "env=CLOUDFLARE_API_TOKEN",
                "grep=deploy",
                "expiring=30d",
            ]
        );
    }

    #[test]
    fn test_parse_expiry_accepts_a_bare_date_and_rfc3339() {
        assert_eq!(
            parse_expiry("2027-01-01").unwrap(),
            DateTime::parse_from_rfc3339("2027-01-01T00:00:00Z").unwrap()
        );
        assert!(parse_expiry("2027-01-01T12:30:00Z").is_ok());
        let err = parse_expiry("next tuesday").unwrap_err().to_string();
        assert!(err.contains("2027-01-01"), "{err}");
    }

    /// No flags at all: every field left alone.
    fn untouched() -> EditFields {
        EditFields {
            provider: None,
            label: None,
            purpose: None,
            no_purpose: false,
            scopes: Vec::new(),
            expires: None,
            no_expires: false,
            endpoint: None,
            no_endpoint: false,
            env: None,
            no_env: false,
        }
    }

    #[test]
    fn test_build_patch_sets_only_the_fields_that_were_given() {
        let (patch, touched) = build_patch(EditFields {
            provider: Some("cloudflare".into()),
            scopes: vec!["workers:edit".into()],
            expires: Some("2027-01-01".into()),
            ..untouched()
        })
        .unwrap();

        assert_eq!(patch.provider.as_deref(), Some("cloudflare"));
        assert_eq!(
            patch.scopes.as_deref(),
            Some(&["workers:edit".to_string()][..])
        );
        assert_eq!(
            patch.expires_at,
            Some(Some(
                DateTime::parse_from_rfc3339("2027-01-01T00:00:00Z")
                    .unwrap()
                    .with_timezone(&Utc)
            ))
        );
        // Untouched fields stay absent, so update_metadata leaves them alone.
        assert!(patch.label.is_none());
        assert!(patch.purpose.is_none());
        assert!(patch.endpoint.is_none());
        assert!(patch.env.is_none());
        // Reported in the order the report prints them.
        assert_eq!(
            touched,
            vec![Field::Provider, Field::Scopes, Field::Expires]
        );
    }

    #[test]
    fn test_build_patch_distinguishes_clearing_from_leaving_alone() {
        let (patch, touched) = build_patch(EditFields {
            no_purpose: true,
            no_expires: true,
            no_endpoint: true,
            no_env: true,
            ..untouched()
        })
        .unwrap();

        // `Some(None)` is the clear; a missing entry would be "leave it".
        assert_eq!(patch.purpose, Some(None));
        assert_eq!(patch.expires_at, Some(None));
        assert_eq!(patch.endpoint, Some(None));
        assert_eq!(patch.env, Some(None));
        assert_eq!(
            touched,
            vec![Field::Purpose, Field::Expires, Field::Endpoint, Field::Env]
        );
    }

    #[test]
    fn test_build_patch_refuses_an_edit_that_changes_nothing() {
        let err = build_patch(untouched()).unwrap_err().to_string();
        assert!(err.contains("nothing to change"), "{err}");
        assert!(err.contains("--provider"), "{err}");
    }

    #[test]
    fn test_build_patch_rejects_an_unparseable_expiry() {
        let err = build_patch(EditFields {
            expires: Some("next tuesday".into()),
            ..untouched()
        })
        .unwrap_err()
        .to_string();
        assert!(err.contains("2027-01-01"), "{err}");
    }
}
