//! Pure formatting helpers for the `pb` terminal output.
//!
//! Everything here is deliberately side-effect free: rows are built from a
//! `ToolStatus` plus an explicit `now`, so the formatting logic is testable
//! without touching the real machine, the real clock or a real terminal.

use anstyle::{AnsiColor, Effects, Style};
use chrono::{DateTime, Duration, Utc};
use patchbay_core::{Advisory, CheckReport, ToolStatus};

/// Total budget for the status table. Keeps the board readable in a
/// 100-column terminal, which is the narrowest window we design for.
const TABLE_WIDTH: usize = 100;
/// Gap between columns.
const GAP: usize = 2;
const COL_PROFILES: usize = 8;
const COL_EXPIRES: usize = 18;
/// Upper bound for the ACTIVE column; long ids get truncated into it.
const COL_ACTIVE_MAX: usize = 28;

/// Placeholder for "this tool has no such value".
const DASH: &str = "—";

// ---------------------------------------------------------------------------
// colors
// ---------------------------------------------------------------------------

/// Whether ANSI escapes are emitted at all. Decided once, at startup.
#[derive(Clone, Copy, Debug)]
pub struct Styles {
    enabled: bool,
}

impl Styles {
    pub fn new(enabled: bool) -> Self {
        Self { enabled }
    }

    /// Color only when stdout is a real terminal and `NO_COLOR` is unset.
    pub fn detect() -> Self {
        use std::io::IsTerminal;
        let no_color = std::env::var_os("NO_COLOR").is_some();
        Self::new(std::io::stdout().is_terminal() && !no_color)
    }

    /// Wrap `text` in `style`, or return it untouched when color is off.
    pub fn paint(&self, style: Style, text: &str) -> String {
        if !self.enabled || text.is_empty() {
            return text.to_string();
        }
        format!("{}{}{}", style.render(), text, style.render_reset())
    }
}

fn dim() -> Style {
    Style::new() | Effects::DIMMED
}

fn bold() -> Style {
    Style::new() | Effects::BOLD
}

fn red() -> Style {
    Style::new().fg_color(Some(AnsiColor::Red.into()))
}

fn yellow() -> Style {
    Style::new().fg_color(Some(AnsiColor::Yellow.into()))
}

// ---------------------------------------------------------------------------
// duration humanizing
// ---------------------------------------------------------------------------

/// How alarming an expiry is. Drives the row color.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExpiryLevel {
    /// Already past, or under 24h away.
    Critical,
    /// Under 7 days away.
    Warn,
    /// Comfortably far out.
    Normal,
}

impl ExpiryLevel {
    /// The color this level paints its cell. Public so the key vault's table
    /// can color expiry the same way the status board does.
    pub fn style(self) -> Style {
        match self {
            ExpiryLevel::Critical => red(),
            ExpiryLevel::Warn => yellow(),
            ExpiryLevel::Normal => Style::new(),
        }
    }
}

/// Bucket a time-to-expiry into a color level.
pub fn expiry_level(now: DateTime<Utc>, at: DateTime<Utc>) -> ExpiryLevel {
    let left = at - now;
    if left <= Duration::zero() || left < Duration::hours(24) {
        ExpiryLevel::Critical
    } else if left < Duration::days(7) {
        ExpiryLevel::Warn
    } else {
        ExpiryLevel::Normal
    }
}

/// The magnitude of a duration, at most two units: `3d 4h`, `5h 20m`, `42m`.
fn magnitude(d: Duration) -> String {
    let secs = d.num_seconds().abs();
    let days = secs / 86_400;
    let hours = (secs % 86_400) / 3_600;
    let minutes = (secs % 3_600) / 60;

    if days > 0 {
        if hours > 0 {
            format!("{days}d {hours}h")
        } else {
            format!("{days}d")
        }
    } else if hours > 0 {
        if minutes > 0 {
            format!("{hours}h {minutes}m")
        } else {
            format!("{hours}h")
        }
    } else if minutes > 0 {
        format!("{minutes}m")
    } else {
        "<1m".to_string()
    }
}

/// `in 3d 4h` for the future, `expired 5d ago` for the past.
pub fn humanize_expiry(now: DateTime<Utc>, at: DateTime<Utc>) -> String {
    let left = at - now;
    if left > Duration::zero() {
        format!("in {}", magnitude(left))
    } else {
        format!("expired {} ago", magnitude(left))
    }
}

/// How long ago something happened: `2h ago`, `3d 4h ago`.
///
/// A timestamp in the future is a clock that disagrees with itself, not news
/// worth reporting, so it reads as `just now` rather than a negative age.
pub fn humanize_ago(now: DateTime<Utc>, at: DateTime<Utc>) -> String {
    let elapsed = now - at;
    if elapsed <= Duration::zero() {
        return "just now".to_string();
    }
    format!("{} ago", magnitude(elapsed))
}

// ---------------------------------------------------------------------------
// truncation / padding
// ---------------------------------------------------------------------------

/// Shorten to `max` characters, marking the cut with an ellipsis.
pub fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    match max {
        0 => String::new(),
        1 => "…".to_string(),
        _ => {
            let kept: String = s.chars().take(max - 1).collect();
            format!("{kept}…")
        }
    }
}

/// Pad to `width` with spaces (never truncates — callers truncate first).
fn pad(s: &str, width: usize) -> String {
    let len = s.chars().count();
    if len >= width {
        s.to_string()
    } else {
        format!("{s}{}", " ".repeat(width - len))
    }
}

/// Collapse whitespace so a multi-line note cannot break column alignment.
fn one_line(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

// ---------------------------------------------------------------------------
// status rows
// ---------------------------------------------------------------------------

/// The EXPIRES cell: rendered text plus the color bucket it belongs to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExpiryCell {
    pub text: String,
    pub level: ExpiryLevel,
}

/// One fully-resolved table row, still free of any ANSI.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StatusRow {
    pub tool: String,
    pub installed: bool,
    /// Active profile id, `None` when the tool has no active profile.
    pub active: Option<String>,
    pub profiles: usize,
    pub expires: Option<ExpiryCell>,
    /// First note, condensed to one line. `None` when the tool has no notes.
    pub note: Option<String>,
    /// Standalone vault keys filed against this tool.
    pub keys: usize,
    /// How many of those have expired or are about to.
    pub keys_attention: usize,
    /// `2.95.0 → 2.97.0`, only when an update is actually available. The
    /// installed version alone is not shown on the board: 23 rows of version
    /// numbers nobody asked about is noise, and `pb check-updates` prints them.
    pub update: Option<String>,
    /// How many curated advisories apply to this tool.
    pub advisories: usize,
}

/// Build the row for one tool. `now` is injected so this stays testable.
pub fn build_row(status: &ToolStatus, now: DateTime<Utc>) -> StatusRow {
    // Prefer the active profile's own expiry; fall back to the soonest across
    // all profiles, flagged so nobody reads it as the active credential's.
    let expires = match status.active_expiry() {
        Some(at) => Some(ExpiryCell {
            text: humanize_expiry(now, at),
            level: expiry_level(now, at),
        }),
        None => status.soonest_expiry().map(|at| ExpiryCell {
            text: format!("{} (other)", humanize_expiry(now, at)),
            level: expiry_level(now, at),
        }),
    };

    StatusRow {
        tool: status.tool.clone(),
        installed: status.installed,
        active: status.active.clone(),
        profiles: status.profiles.len(),
        expires,
        note: status.notes.first().map(|n| one_line(n)),
        keys: status.registered_keys.len(),
        keys_attention: status.keys_needing_attention().len(),
        update: status
            .version
            .as_ref()
            .filter(|v| v.update_available())
            .and_then(|v| v.marker()),
        advisories: status.advisories.len(),
    }
}

/// The `↑ 2.95.0 → 2.97.0` marker, or `None` when the tool is current or has
/// never been checked. A cold cache leaves the board exactly as it was.
pub fn update_marker(row: &StatusRow) -> Option<String> {
    row.update.as_ref().map(|u| format!("↑ {u}"))
}

/// The `⚠` marker for curated advisories. The detail goes below the table.
pub fn advisory_marker(row: &StatusRow) -> Option<String> {
    match row.advisories {
        0 => None,
        1 => Some("⚠ advisory".to_string()),
        n => Some(format!("⚠ {n} advisories")),
    }
}

/// The `+2 keys` marker for a row, with a `!` when one of them needs looking
/// at. `None` when the tool has no registered keys — the overwhelmingly common
/// case, and the board must not grow noise for it.
pub fn keys_marker(row: &StatusRow) -> Option<String> {
    if row.keys == 0 {
        return None;
    }
    let bang = if row.keys_attention > 0 { "!" } else { "" };
    Some(format!(
        "+{} key{}{bang}",
        row.keys,
        if row.keys == 1 { "" } else { "s" }
    ))
}

/// Render the whole board: header, rows, and a notes section when needed.
pub fn render_status(statuses: &[ToolStatus], now: DateTime<Utc>, styles: &Styles) -> String {
    let rows: Vec<StatusRow> = statuses.iter().map(|s| build_row(s, now)).collect();

    // TOOL is sized to the data; ACTIVE and NOTES share what is left.
    let tool_w = rows
        .iter()
        .map(|r| r.tool.chars().count())
        .chain(std::iter::once("TOOL".len()))
        .max()
        .unwrap_or(4);
    let active_w = rows
        .iter()
        .filter_map(|r| r.active.as_ref())
        .map(|a| a.chars().count())
        .chain(std::iter::once("ACTIVE".len()))
        .max()
        .unwrap_or(6)
        .min(COL_ACTIVE_MAX);
    let fixed = tool_w + active_w + COL_PROFILES + COL_EXPIRES + GAP * 4;
    let notes_w = TABLE_WIDTH.saturating_sub(fixed).max(12);

    let gap = " ".repeat(GAP);
    let mut out = String::new();

    let header = format!(
        "{}{gap}{}{gap}{}{gap}{}{gap}{}",
        pad("TOOL", tool_w),
        pad("ACTIVE", active_w),
        pad("PROFILES", COL_PROFILES),
        pad("EXPIRES", COL_EXPIRES),
        "NOTES",
    );
    out.push_str(&styles.paint(bold(), header.trim_end()));
    out.push('\n');

    for row in &rows {
        // A whole row goes dim when the tool is absent; otherwise only the
        // individual cells carry style.
        let row_style = if row.installed { None } else { Some(dim()) };

        let tool = pad(&truncate(&row.tool, tool_w), tool_w);
        let active_text = row.active.clone().unwrap_or_else(|| DASH.to_string());
        let active = pad(&truncate(&active_text, active_w), active_w);
        let profiles = pad(&row.profiles.to_string(), COL_PROFILES);

        let (expires_text, expires_style) = match &row.expires {
            Some(cell) => (truncate(&cell.text, COL_EXPIRES), Some(cell.level.style())),
            None => (DASH.to_string(), Some(dim())),
        };
        let expires_padded = pad(&expires_text, COL_EXPIRES);

        let note_text = if !row.installed {
            "not installed".to_string()
        } else {
            row.note.clone().unwrap_or_default()
        };
        // Markers lead the notes cell, most urgent first, so a busy row reads
        // as "⚠ advisory · ↑ 2.95.0 → 2.97.0 · +1 key · <the usual caveat>".
        let mut cell: Vec<String> = [advisory_marker(row), update_marker(row), keys_marker(row)]
            .into_iter()
            .flatten()
            .collect();
        if !note_text.is_empty() {
            cell.push(note_text);
        }
        let note = truncate(&cell.join(" · "), notes_w);

        let line = if let Some(style) = row_style {
            // Absent tool: one style for the whole line, no per-cell color.
            let raw = format!("{tool}{gap}{active}{gap}{profiles}{gap}{expires_padded}{gap}{note}");
            styles.paint(style, raw.trim_end())
        } else {
            let active_cell = if row.active.is_none() {
                styles.paint(dim(), &active)
            } else {
                active
            };
            let expires_cell = match expires_style {
                Some(style) => styles.paint(style, &expires_padded),
                None => expires_padded,
            };
            let note_cell = if note.is_empty() {
                note.clone()
            } else {
                styles.paint(dim(), &note)
            };
            let line = format!(
                "{tool}{gap}{active_cell}{gap}{profiles}{gap}{expires_cell}{gap}{note_cell}"
            );
            // trim_end is safe: any trailing reset belongs to a painted cell,
            // and an empty NOTES cell leaves only spaces behind.
            line.trim_end().to_string()
        };
        out.push_str(&line);
        out.push('\n');
    }

    // Full notes live below the table so they can never wreck alignment.
    let with_notes: Vec<&ToolStatus> = statuses.iter().filter(|s| !s.notes.is_empty()).collect();
    if !with_notes.is_empty() {
        out.push('\n');
        out.push_str(&styles.paint(bold(), "notes"));
        out.push('\n');
        for status in with_notes {
            for note in &status.notes {
                out.push_str(&format!("  {}: {}\n", status.tool, one_line(note)));
            }
        }
    }

    // Advisories get their own section: they are editorial facts about the
    // software, not observations about this machine's config, and folding them
    // in with the notes would blur that.
    let with_advisories: Vec<&ToolStatus> = statuses
        .iter()
        .filter(|s| !s.advisories.is_empty())
        .collect();
    if !with_advisories.is_empty() {
        out.push('\n');
        out.push_str(&styles.paint(bold(), "advisories"));
        out.push('\n');
        for status in with_advisories {
            for advisory in &status.advisories {
                out.push_str(&render_advisory(&status.tool, advisory, styles));
            }
        }
    }

    out
}

/// One advisory: a headline naming the tool and the kind, the message, and the
/// source so nobody has to take patchbay's word for it.
fn render_advisory(tool: &str, advisory: &Advisory, styles: &Styles) -> String {
    let head = format!("  {tool}: {}", advisory.kind.label());
    let style = if advisory.is_blocking() {
        red()
    } else {
        yellow()
    };
    let mut out = format!("{}\n", styles.paint(style, &head));
    out.push_str(&format!("    {}\n", one_line(&advisory.message)));
    if let Some(url) = &advisory.url {
        out.push_str(&styles.paint(dim(), &format!("    {url}")));
        out.push('\n');
    }
    out
}

// ---------------------------------------------------------------------------
// pb check-updates
// ---------------------------------------------------------------------------

/// The `pb check-updates` table, plus the advisory section and a one-line
/// summary of what the run actually cost.
pub fn render_check_updates(
    report: &CheckReport,
    advisories: &[Advisory],
    styles: &Styles,
) -> String {
    const COL_VERSION: usize = 14;
    const COL_SOURCE: usize = 13;

    let tool_w = report
        .entries
        .iter()
        .map(|e| e.tool.chars().count())
        .chain(std::iter::once("TOOL".len()))
        .max()
        .unwrap_or(4);

    let gap = " ".repeat(GAP);
    let mut out = String::new();

    let header = format!(
        "{}{gap}{}{gap}{}{gap}{}{gap}{}",
        pad("TOOL", tool_w),
        pad("INSTALLED", COL_VERSION),
        pad("LATEST", COL_VERSION),
        pad("SOURCE", COL_SOURCE),
        "UPDATE WITH",
    );
    out.push_str(&styles.paint(bold(), header.trim_end()));
    out.push('\n');

    for entry in &report.entries {
        let installed = entry.installed.clone().unwrap_or_else(|| DASH.to_string());
        let latest = entry.latest.clone().unwrap_or_else(|| DASH.to_string());
        let command = entry.update_command.clone().unwrap_or_default();

        let tool = pad(&truncate(&entry.tool, tool_w), tool_w);
        let installed_cell = pad(&truncate(&installed, COL_VERSION), COL_VERSION);
        let latest_cell = pad(&truncate(&latest, COL_VERSION), COL_VERSION);
        // A tool that is not here has no install source — printing `unknown`
        // would read as patchbay being confused rather than the tool being
        // absent, which is the state the whole row is already showing.
        let source_text = if entry.installed.is_none() {
            "not installed"
        } else {
            entry.source.label()
        };
        let source = pad(&truncate(source_text, COL_SOURCE), COL_SOURCE);

        // Only a row with something to do earns colour; everything else stays
        // quiet so the handful that matter are findable at a glance.
        let line = if entry.update_available() {
            let latest_cell = styles.paint(yellow(), &latest_cell);
            format!("{tool}{gap}{installed_cell}{gap}{latest_cell}{gap}{source}{gap}{command}")
        } else if entry.installed.is_none() {
            styles.paint(
                dim(),
                format!("{tool}{gap}{installed_cell}{gap}{latest_cell}{gap}{source}{gap}")
                    .trim_end(),
            )
        } else {
            format!("{tool}{gap}{installed_cell}{gap}{latest_cell}{gap}{source}{gap}")
        };
        out.push_str(line.trim_end());
        out.push('\n');
    }

    if !advisories.is_empty() {
        out.push('\n');
        out.push_str(&styles.paint(bold(), "advisories"));
        out.push('\n');
        for advisory in advisories {
            out.push_str(&render_advisory(&advisory.tool, advisory, styles));
        }
    }

    if !report.notes.is_empty() {
        out.push('\n');
        out.push_str(&styles.paint(bold(), "notes"));
        out.push('\n');
        for note in &report.notes {
            out.push_str(&format!("  {}\n", one_line(note)));
        }
    }

    // The cost line makes the batching claim checkable rather than asserted:
    // however many Homebrew tools there are, `brew` is called at most once.
    let outdated = report.outdated().len();
    let summary = format!(
        "\n{outdated} update{} · {} tool{} from cache · {} brew call{} · {} network call{} · {}ms",
        if outdated == 1 { "" } else { "s" },
        report.from_cache,
        if report.from_cache == 1 { "" } else { "s" },
        report.brew_calls,
        if report.brew_calls == 1 { "" } else { "s" },
        report.network_calls,
        if report.network_calls == 1 { "" } else { "s" },
        report.elapsed_ms,
    );
    out.push_str(&styles.paint(dim(), &summary));
    out.push('\n');
    out
}

// ---------------------------------------------------------------------------
// shared bits for the other subcommands
// ---------------------------------------------------------------------------

/// `~/…` for paths under the home directory: output is about *which* file, not
/// about how long the user's home path is.
pub fn tilde(path: &std::path::Path) -> String {
    let Some(home) = std::env::var_os("HOME") else {
        return path.display().to_string();
    };
    match path.strip_prefix(&home) {
        Ok(rest) => format!("~/{}", rest.display()),
        Err(_) => path.display().to_string(),
    }
}

/// Indent a list of lines under a heading line.
pub fn indent_lines(items: &[String]) -> String {
    items
        .iter()
        .map(|i| format!("  {}", one_line(i)))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Scopes, one per line under the `scopes:` heading, so a long grant list
/// stays scannable instead of becoming a wall of comma-separated text.
pub fn render_scopes(scopes: &[String]) -> String {
    scopes
        .iter()
        .map(|s| format!("    {s}"))
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use patchbay_core::{Profile, ToolStatus};

    fn now() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc)
    }

    #[test]
    fn test_humanize_future_days_and_hours() {
        let at = now() + Duration::days(3) + Duration::hours(4) + Duration::minutes(30);
        assert_eq!(humanize_expiry(now(), at), "in 3d 4h");
    }

    #[test]
    fn test_humanize_future_whole_days_drops_the_hours() {
        assert_eq!(humanize_expiry(now(), now() + Duration::days(2)), "in 2d");
    }

    #[test]
    fn test_humanize_future_minutes() {
        assert_eq!(
            humanize_expiry(now(), now() + Duration::minutes(42)),
            "in 42m"
        );
    }

    #[test]
    fn test_humanize_future_hours_and_minutes() {
        let at = now() + Duration::hours(5) + Duration::minutes(20);
        assert_eq!(humanize_expiry(now(), at), "in 5h 20m");
    }

    #[test]
    fn test_humanize_sub_minute() {
        assert_eq!(
            humanize_expiry(now(), now() + Duration::seconds(20)),
            "in <1m"
        );
    }

    #[test]
    fn test_humanize_ago_reads_as_an_age() {
        assert_eq!(humanize_ago(now(), now() - Duration::hours(2)), "2h ago");
        assert_eq!(
            humanize_ago(now(), now() - Duration::days(3) - Duration::hours(4)),
            "3d 4h ago"
        );
        // A future timestamp is a disagreeing clock, not a negative age.
        assert_eq!(humanize_ago(now(), now() + Duration::hours(1)), "just now");
    }

    #[test]
    fn test_humanize_past() {
        assert_eq!(
            humanize_expiry(now(), now() - Duration::days(5)),
            "expired 5d ago"
        );
    }

    #[test]
    fn test_expiry_level_buckets() {
        assert_eq!(
            expiry_level(now(), now() - Duration::minutes(1)),
            ExpiryLevel::Critical
        );
        assert_eq!(
            expiry_level(now(), now() + Duration::hours(23)),
            ExpiryLevel::Critical
        );
        assert_eq!(
            expiry_level(now(), now() + Duration::hours(25)),
            ExpiryLevel::Warn
        );
        assert_eq!(
            expiry_level(now(), now() + Duration::days(6)),
            ExpiryLevel::Warn
        );
        assert_eq!(
            expiry_level(now(), now() + Duration::days(8)),
            ExpiryLevel::Normal
        );
    }

    #[test]
    fn test_expiry_level_boundaries_are_inclusive_upward() {
        // Exactly 24h out is no longer critical; exactly 7d out is normal.
        assert_eq!(
            expiry_level(now(), now() + Duration::hours(24)),
            ExpiryLevel::Warn
        );
        assert_eq!(
            expiry_level(now(), now() + Duration::days(7)),
            ExpiryLevel::Normal
        );
    }

    #[test]
    fn test_truncate_leaves_short_strings_alone() {
        assert_eq!(truncate("abc", 5), "abc");
        assert_eq!(truncate("abcde", 5), "abcde");
    }

    #[test]
    fn test_truncate_marks_the_cut() {
        assert_eq!(truncate("abcdefgh", 5), "abcd…");
        assert_eq!(truncate("abc", 1), "…");
        assert_eq!(truncate("abc", 0), "");
    }

    #[test]
    fn test_truncate_counts_characters_not_bytes() {
        assert_eq!(truncate("äöüßz", 4), "äöü…");
    }

    #[test]
    fn test_pad_never_shrinks() {
        assert_eq!(pad("ab", 4), "ab  ");
        assert_eq!(pad("abcdef", 4), "abcdef");
    }

    #[test]
    fn test_one_line_collapses_newlines() {
        assert_eq!(one_line("a\n  b\tc "), "a b c");
    }

    #[test]
    fn test_row_prefers_the_active_profiles_expiry() {
        let mut status = ToolStatus::empty("gcloud", true);
        status.active = Some("me@example.com".into());
        status.profiles = vec![
            Profile::new("other@example.com").expires_at(Some(now() + Duration::hours(1))),
            Profile::new("me@example.com").expires_at(Some(now() + Duration::days(3))),
        ];
        let row = build_row(&status, now());
        let cell = row.expires.unwrap();
        assert_eq!(cell.text, "in 3d");
        // 3 days out is inside the 7-day warning window.
        assert_eq!(cell.level, ExpiryLevel::Warn);
    }

    #[test]
    fn test_row_falls_back_to_soonest_and_flags_it() {
        let mut status = ToolStatus::empty("aws", true);
        status.profiles = vec![Profile::new("prod").expires_at(Some(now() + Duration::hours(2)))];
        let row = build_row(&status, now());
        let cell = row.expires.unwrap();
        assert_eq!(cell.text, "in 2h (other)");
        assert_eq!(cell.level, ExpiryLevel::Critical);
    }

    #[test]
    fn test_row_without_expiry_is_empty() {
        let mut status = ToolStatus::empty("gh", true);
        status.profiles = vec![Profile::new("octocat")];
        status.active = Some("octocat".into());
        let row = build_row(&status, now());
        assert!(row.expires.is_none());
        assert_eq!(row.profiles, 1);
    }

    #[test]
    fn test_row_note_is_first_note_on_one_line() {
        let mut status = ToolStatus::empty("gcloud", true);
        status.note("ADC account\ndiffers from the\nactive account");
        status.note("second");
        let row = build_row(&status, now());
        assert_eq!(
            row.note.as_deref(),
            Some("ADC account differs from the active account")
        );
    }

    #[test]
    fn test_table_is_plain_and_aligned_without_color() {
        let mut installed = ToolStatus::empty("gcloud", true);
        installed.active = Some("me@example.com".into());
        installed.profiles =
            vec![Profile::new("me@example.com").expires_at(Some(now() + Duration::days(3)))];
        let absent = ToolStatus::empty("wrangler", false);

        let out = render_status(&[installed, absent], now(), &Styles::new(false));
        assert!(!out.contains('\u{1b}'), "plain mode must emit no ANSI");

        let lines: Vec<&str> = out.lines().collect();
        assert!(lines[0].starts_with("TOOL"));
        assert!(lines[1].contains("me@example.com"));
        assert!(lines[1].contains("in 3d"));
        assert!(lines[2].contains("not installed"));
        // Every column starts at the same offset on every row.
        let col = lines[0].find("ACTIVE").unwrap();
        assert!(lines[1][col..].starts_with("me@example.com"));
    }

    #[test]
    fn test_registered_keys_show_as_a_marker_in_the_notes_cell() {
        use patchbay_core::keys::KeyExpiryState;
        use patchbay_core::KeyRef;

        let key = |id: &str, state: KeyExpiryState| KeyRef {
            id: id.into(),
            label: id.into(),
            last4: "1234".into(),
            expires_at: None,
            expiry_state: state,
        };

        let mut healthy = ToolStatus::empty("wrangler", true);
        healthy.active = Some("default".into());
        healthy.profiles = vec![Profile::new("default")];
        healthy.registered_keys = vec![key("cf-api", KeyExpiryState::Valid)];

        let row = build_row(&healthy, now());
        assert_eq!(row.keys, 1);
        assert_eq!(row.keys_attention, 0);
        assert_eq!(keys_marker(&row).as_deref(), Some("+1 key"));

        let out = render_status(&[healthy.clone()], now(), &Styles::new(false));
        assert!(out.contains("+1 key"), "{out}");

        // Plural, and a bang when one of them needs attention.
        let mut urgent = healthy.clone();
        urgent.registered_keys = vec![
            key("cf-api", KeyExpiryState::Valid),
            key("cf-old", KeyExpiryState::Expired),
        ];
        let row = build_row(&urgent, now());
        assert_eq!(row.keys_attention, 1);
        assert_eq!(keys_marker(&row).as_deref(), Some("+2 keys!"));

        // The marker leads the cell and the real note follows it.
        let mut noted = urgent.clone();
        noted.note("two wrangler configs exist");
        let out = render_status(&[noted], now(), &Styles::new(false));
        assert!(out.contains("+2 keys! · two wrangler configs"), "{out}");
    }

    #[test]
    fn test_a_tool_without_keys_gets_no_marker_and_no_extra_noise() {
        let mut status = ToolStatus::empty("gh", true);
        status.active = Some("octocat".into());
        status.profiles = vec![Profile::new("octocat")];

        let row = build_row(&status, now());
        assert_eq!(row.keys, 0);
        assert_eq!(keys_marker(&row), None);

        let out = render_status(&[status], now(), &Styles::new(false));
        assert!(!out.contains("key"), "{out}");
    }

    // --- versions and advisories on the board -------------------------------

    fn with_version(tool: &str, installed: &str, latest: Option<&str>) -> ToolStatus {
        let mut status = ToolStatus::empty(tool, true);
        status.active = Some("default".into());
        status.profiles = vec![Profile::new("default")];
        status.version = Some(patchbay_core::VersionInfo {
            tool: tool.to_string(),
            installed: Some(installed.to_string()),
            latest: latest.map(String::from),
            source: patchbay_core::Source::Homebrew,
            update_command: Some(format!("brew upgrade {tool}")),
            checked_at: now(),
            note: None,
        });
        status
    }

    #[test]
    fn test_an_available_update_gets_a_marker_and_a_current_tool_gets_none() {
        let outdated = with_version("gh", "2.95.0", Some("2.97.0"));
        let row = build_row(&outdated, now());
        assert_eq!(row.update.as_deref(), Some("2.95.0 → 2.97.0"));
        assert_eq!(update_marker(&row).as_deref(), Some("↑ 2.95.0 → 2.97.0"));

        let out = render_status(&[outdated], now(), &Styles::new(false));
        assert!(out.contains("↑ 2.95.0 → 2.97.0"), "{out}");

        // Up to date: the board says nothing at all. 23 rows of version numbers
        // nobody asked for is noise.
        let current = with_version("rclone", "1.75.0", Some("1.75.0"));
        let row = build_row(&current, now());
        assert_eq!(row.update, None);
        assert_eq!(update_marker(&row), None);
        assert!(!render_status(&[current], now(), &Styles::new(false)).contains('↑'));

        // Unknown latest is not an update either.
        let unknown = with_version("docker", "28.3.2", None);
        assert_eq!(build_row(&unknown, now()).update, None);
    }

    #[test]
    fn test_a_cold_cache_leaves_the_board_exactly_as_it_was() {
        let mut status = ToolStatus::empty("gh", true);
        status.active = Some("octocat".into());
        status.profiles = vec![Profile::new("octocat")];
        let row = build_row(&status, now());
        assert_eq!(row.update, None);
        assert_eq!(row.advisories, 0);

        let out = render_status(&[status], now(), &Styles::new(false));
        assert!(!out.contains('↑'), "{out}");
        assert!(!out.contains('⚠'), "{out}");
        assert!(!out.contains("advisories"), "{out}");
    }

    fn advisory(tool: &str, blocking: bool) -> Advisory {
        Advisory {
            tool: tool.to_string(),
            kind: if blocking {
                patchbay_core::AdvisoryKind::Removed {
                    in_version: "1.0.0".into(),
                    replacement: "hf".into(),
                }
            } else {
                patchbay_core::AdvisoryKind::Renamed {
                    to: "neon".into(),
                    since: None,
                }
            },
            message: "the old command is going away and here is what replaces it".into(),
            url: Some("https://example.com/docs".into()),
        }
    }

    #[test]
    fn test_advisories_get_a_marker_and_a_detail_section_of_their_own() {
        let mut status = with_version("huggingface", "0.35.0", None);
        status.advisories = vec![advisory("huggingface", true)];

        let row = build_row(&status, now());
        assert_eq!(row.advisories, 1);
        assert_eq!(advisory_marker(&row).as_deref(), Some("⚠ advisory"));

        let out = render_status(&[status], now(), &Styles::new(false));
        assert!(out.contains("⚠ advisory"), "{out}");
        // The detail lives below the table, with its kind and its source.
        assert!(out.contains("\nadvisories\n"), "{out}");
        assert!(out.contains("  huggingface: removed"), "{out}");
        assert!(out.contains("https://example.com/docs"), "{out}");
        // …and it is NOT folded in with the probe notes.
        assert!(!out.contains("\nnotes\n"), "{out}");
    }

    #[test]
    fn test_markers_share_the_notes_cell_most_urgent_first() {
        use patchbay_core::keys::KeyExpiryState;
        use patchbay_core::KeyRef;

        let mut status = with_version("neon", "2.38.2", Some("3.1.1"));
        status.advisories = vec![advisory("neon", false)];
        status.registered_keys = vec![KeyRef {
            id: "neon-api".into(),
            label: "neon".into(),
            last4: "1234".into(),
            expires_at: None,
            expiry_state: KeyExpiryState::Valid,
        }];
        status.note("two config directories exist");

        let out = render_status(&[status], now(), &Styles::new(false));
        let row_line = out.lines().find(|l| l.starts_with("neon")).unwrap();
        let order = ["⚠ advisory", "↑ 2.38.2 → 3.1.1", "+1 key"];
        let mut last = 0;
        for marker in order {
            let at = row_line
                .find(marker)
                .unwrap_or_else(|| panic!("{marker} missing from {row_line:?}"));
            assert!(at >= last, "{marker} is out of order in {row_line:?}");
            last = at;
        }
    }

    #[test]
    fn test_pluralised_advisory_marker() {
        let mut status = with_version("aws", "1.29.0", None);
        status.advisories = vec![advisory("aws", true), advisory("aws", false)];
        let row = build_row(&status, now());
        assert_eq!(advisory_marker(&row).as_deref(), Some("⚠ 2 advisories"));
    }

    // --- pb check-updates ---------------------------------------------------

    fn entry(
        tool: &str,
        installed: Option<&str>,
        latest: Option<&str>,
        source: patchbay_core::Source,
    ) -> patchbay_core::VersionInfo {
        patchbay_core::VersionInfo {
            tool: tool.to_string(),
            installed: installed.map(String::from),
            latest: latest.map(String::from),
            source,
            update_command: installed.map(|_| format!("brew upgrade {tool}")),
            checked_at: now(),
            note: None,
        }
    }

    #[test]
    fn test_check_updates_table_shows_every_column_and_a_cost_summary() {
        use patchbay_core::Source;
        let report = CheckReport {
            entries: vec![
                entry("gh", Some("2.95.0"), Some("2.97.0"), Source::Homebrew),
                entry("rclone", Some("1.75.0"), Some("1.75.0"), Source::Homebrew),
                entry("stripe", None, None, Source::Unknown),
            ],
            brew_calls: 1,
            network_calls: 2,
            from_cache: 0,
            elapsed_ms: 1234,
            notes: vec![],
        };

        let out = render_check_updates(&report, &[], &Styles::new(false));
        assert!(!out.contains('\u{1b}'), "plain mode must emit no ANSI");
        let lines: Vec<&str> = out.lines().collect();
        assert!(lines[0].starts_with("TOOL"));
        assert!(lines[0].contains("INSTALLED"));
        assert!(lines[0].contains("LATEST"));
        assert!(lines[0].contains("SOURCE"));
        assert!(lines[0].contains("UPDATE WITH"));

        assert!(out.contains("2.95.0"));
        assert!(out.contains("brew upgrade gh"));
        // A tool that is not installed shows dashes, not a fake version, and
        // says so rather than claiming an "unknown" install source.
        let stripe = out.lines().find(|l| l.starts_with("stripe")).unwrap();
        assert!(stripe.contains(DASH), "{stripe:?}");
        assert!(stripe.contains("not installed"), "{stripe:?}");
        assert!(!stripe.contains("unknown"), "{stripe:?}");

        // The summary is what makes the batching claim checkable.
        assert!(out.contains("1 update ·"), "{out}");
        assert!(out.contains("1 brew call"), "{out}");
        assert!(out.contains("2 network calls"), "{out}");
        assert!(out.contains("1234ms"), "{out}");
    }

    #[test]
    fn test_check_updates_reports_advisories_and_run_notes() {
        let report = CheckReport {
            entries: vec![entry(
                "huggingface",
                Some("0.35.0"),
                None,
                patchbay_core::Source::SelfManaged,
            )],
            brew_calls: 0,
            network_calls: 0,
            from_cache: 1,
            elapsed_ms: 3,
            notes: vec!["Homebrew lookup failed: brew is not installed".into()],
        };
        let out = render_check_updates(
            &report,
            &[advisory("huggingface", true)],
            &Styles::new(false),
        );
        assert!(out.contains("\nadvisories\n"), "{out}");
        assert!(out.contains("huggingface: removed"), "{out}");
        assert!(out.contains("\nnotes\n"), "{out}");
        assert!(out.contains("brew is not installed"), "{out}");
        assert!(out.contains("1 tool from cache"), "{out}");
    }

    #[test]
    fn test_check_updates_colours_only_the_rows_with_something_to_do() {
        use patchbay_core::Source;
        let report = CheckReport {
            entries: vec![entry(
                "gh",
                Some("2.95.0"),
                Some("2.97.0"),
                Source::Homebrew,
            )],
            brew_calls: 1,
            ..CheckReport::default()
        };
        let out = render_check_updates(&report, &[], &Styles::new(true));
        assert!(out.contains('\u{1b}'));
        assert!(out.contains("2.97.0"));
    }

    #[test]
    fn test_table_lists_full_notes_below() {
        let mut status = ToolStatus::empty("gcloud", true);
        status.note("ADC points at a different account than gcloud config");
        let out = render_status(&[status], now(), &Styles::new(false));
        assert!(out.contains("\nnotes\n"), "{out}");
        assert!(
            out.contains("  gcloud: ADC points at a different account"),
            "{out}"
        );
    }

    #[test]
    fn test_table_emits_ansi_when_color_is_on() {
        let mut status = ToolStatus::empty("aws", true);
        status.active = Some("prod".into());
        status.profiles = vec![Profile::new("prod").expires_at(Some(now() - Duration::days(1)))];
        let out = render_status(&[status], now(), &Styles::new(true));
        assert!(out.contains('\u{1b}'));
        assert!(out.contains("expired 1d ago"));
    }
}
