//! `pb key …` — the key vault in the terminal.
//!
//! Deliberate asymmetry, and the whole point of the design: **writing** a
//! secret is easy (pipe it in, or type it blind), **reading** one back is not.
//! There is no `pb key show`. The only way out is [`Command::Copy`], which
//! moves the value from the keychain to the clipboard without it ever passing
//! through this process's stdout, a shell history line or a log.
//!
//! Secrets never arrive as arguments either: argv is world-readable through
//! `ps` and gets written to `~/.zsh_history` verbatim.

use std::io::{IsTerminal, Read, Write};
use std::process::{Command as Process, Stdio};

use anyhow::{Context, Result};
use chrono::{DateTime, NaiveDate, NaiveTime, TimeZone, Utc};
use clap::Subcommand;
use patchbay_core::keys::{expiring_within_at, KeyEntry, KeyPatch, KeyRegistry, NewKey};
use patchbay_core::keys_verify::{verify_key, KeyVerifyOutcome, KeyVerifyStatus};

use crate::render::{self, Styles};

/// Width budget for the list table, matching the status board.
const TABLE_WIDTH: usize = 100;
const GAP: usize = 2;
const COL_LAST4: usize = 5;
const COL_EXPIRES: usize = 16;
const COL_ID_MAX: usize = 24;
const COL_PROVIDER_MAX: usize = 12;
const COL_LABEL_MAX: usize = 24;
const DASH: &str = "—";

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Register a key patchbay should know about.
    ///
    /// The secret is read from stdin when something is piped in, and from a
    /// hidden prompt otherwise. It is never taken as an argument.
    Add {
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
        /// Replace an existing entry with the same id (a rotation).
        #[arg(long)]
        overwrite: bool,
    },
    /// List registered keys. Metadata only — never values.
    List {
        #[arg(long)]
        json: bool,
        /// Only keys expiring within this many days (already-expired included).
        #[arg(long, value_name = "DAYS")]
        expiring: Option<i64>,
    },
    /// Put a key's value on the clipboard, without printing it.
    Copy { id: String },
    /// Ask the issuer whether a key still works.
    ///
    /// Exit codes: 0 verified (or nothing patchbay can check), 1 the provider
    /// says the key is dead, 2 the provider could not be reached.
    Verify {
        id: String,
        #[arg(long)]
        json: bool,
        /// Report only: do not write the issuer's expiry and scopes back into
        /// the registry.
        #[arg(long)]
        no_update: bool,
    },
    /// Unregister a key: metadata entry and keychain item both.
    Rm {
        id: String,
        /// Skip the confirmation prompt.
        #[arg(long)]
        yes: bool,
    },
}

/// Returns the process exit code.
pub fn run(command: Command, styles: &Styles) -> Result<i32> {
    let registry = KeyRegistry::detect()?;

    match command {
        Command::Add {
            id,
            provider,
            label,
            purpose,
            scopes,
            expires,
            endpoint,
            overwrite,
        } => {
            let expires_at = expires.as_deref().map(parse_expiry).transpose()?;
            let new = NewKey::new(&id, "cli")
                .provider(provider.clone().unwrap_or_else(|| "unknown".to_string()))
                .label(label.unwrap_or_else(|| id.clone()))
                .purpose(purpose)
                .scopes(scopes)
                .expires_at(expires_at)
                .endpoint(endpoint);

            let secret = read_secret(&id)?;
            let entry = registry.add(new, &secret, overwrite)?;
            drop(secret);

            println!("registered {} (…{})", entry.id, entry.last4);
            if let Some(endpoint) = &entry.endpoint {
                println!("  instance: {endpoint}");
            }
            println!("  value:    {}", registry.store_name());
            println!("  metadata: {}", registry.path().display());
            if provider.is_none() {
                println!("  hint: --provider makes the board far easier to scan");
            }
            if entry.expires_at.is_none() {
                println!("  hint: --expires lets patchbay warn you before it dies");
            }
            Ok(0)
        }

        Command::List { json, expiring } => {
            let mut entries = registry.list()?;
            if let Some(days) = expiring {
                entries = expiring_within_at(&entries, Utc::now(), days);
            }
            if json {
                // Machine-readable: JSON only, no ANSI, no extras.
                println!("{}", serde_json::to_string_pretty(&entries)?);
                return Ok(0);
            }
            if entries.is_empty() {
                match expiring {
                    Some(days) => println!("no registered key expires within {days}d"),
                    None => {
                        println!("no keys registered yet");
                        println!("  pb key add <id> --provider <who> --label \"<what>\"");
                    }
                }
                return Ok(0);
            }
            print!("{}", render_table(&entries, Utc::now(), styles));
            Ok(0)
        }

        Command::Copy { id } => {
            let entry = registry
                .get(&id)?
                .ok_or_else(|| anyhow::anyhow!("no key registered as `{id}`"))?;
            let secret = registry.get_secret(&id)?;
            to_clipboard(&secret)?;
            drop(secret);
            println!("copied {} (…{}) to the clipboard", entry.id, entry.last4);
            println!("  it stays there until you copy something else — paste it and move on");
            Ok(0)
        }

        Command::Verify {
            id,
            json,
            no_update,
        } => {
            let entry = registry
                .get(&id)?
                .ok_or_else(|| anyhow::anyhow!("no key registered as `{id}`"))?;
            // The secret lives for exactly this call and is never printed.
            let secret = registry.get_secret(&id)?;
            let outcome = verify_key(&entry, &secret);
            drop(secret);

            let updated = if no_update {
                Vec::new()
            } else {
                absorb(&registry, &entry, &outcome)?
            };

            if json {
                let mut value = serde_json::to_value(&outcome)?;
                if let Some(map) = value.as_object_mut() {
                    map.insert("id".into(), entry.id.clone().into());
                    map.insert("provider".into(), entry.provider.clone().into());
                    map.insert("metadata_updated".into(), updated.clone().into());
                }
                println!("{}", serde_json::to_string_pretty(&value)?);
            } else {
                print_verify(&entry, &outcome, &updated, styles);
            }
            Ok(match outcome.status {
                KeyVerifyStatus::Valid | KeyVerifyStatus::Unsupported => 0,
                KeyVerifyStatus::Invalid | KeyVerifyStatus::Expired => 1,
                // Distinct from 1: nothing was learned about the key.
                KeyVerifyStatus::Unreachable => 2,
            })
        }

        Command::Rm { id, yes } => {
            let entry = registry
                .get(&id)?
                .ok_or_else(|| anyhow::anyhow!("no key registered as `{id}`"))?;
            if !yes && !confirm(&entry)? {
                println!("left {} alone", entry.id);
                return Ok(0);
            }
            let removed = registry.remove(&id)?;
            println!("removed {} (…{})", removed.id, removed.last4);
            println!("  the value is gone from the {}", registry.store_name());
            println!("  revoke it at the provider too — patchbay only forgets it");
            Ok(0)
        }
    }
}

// ---------------------------------------------------------------------------
// verify
// ---------------------------------------------------------------------------

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
    let style = match outcome.status {
        KeyVerifyStatus::Valid => green(),
        KeyVerifyStatus::Invalid | KeyVerifyStatus::Expired => red(),
        KeyVerifyStatus::Unsupported | KeyVerifyStatus::Unreachable => dim(),
    };
    println!(
        "{} (…{}) — {}",
        entry.id,
        entry.last4,
        styles.paint(style, outcome.status.label())
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
    if outcome.status == KeyVerifyStatus::Unsupported && entry.endpoint.is_none() {
        println!(
            "  set one with: pb key add {} --provider {} --endpoint <url> --overwrite",
            entry.id, entry.provider
        );
    }
    if outcome.status == KeyVerifyStatus::Unreachable {
        println!("  the key was not tested — this is a connection problem, not a verdict");
    }
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
    let label_w = column_width(
        entries.iter().map(|e| e.label.chars().count()),
        "LABEL",
        COL_LABEL_MAX,
    );
    let fixed = id_w + provider_w + label_w + COL_LAST4 + COL_EXPIRES + GAP * 5;
    let purpose_w = TABLE_WIDTH.saturating_sub(fixed).max(12);

    let gap = " ".repeat(GAP);
    let mut out = String::new();

    let header = format!(
        "{}{gap}{}{gap}{}{gap}{}{gap}{}{gap}{}",
        pad("ID", id_w),
        pad("PROVIDER", provider_w),
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

        let line =
            format!("{id}{gap}{provider}{gap}{label}{gap}{last4}{gap}{expires}{gap}{purpose}");
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
}
