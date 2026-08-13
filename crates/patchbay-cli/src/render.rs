//! Pure formatting helpers for the `pb` terminal output.
//!
//! Everything here is deliberately side-effect free: rows are built from a
//! `ToolStatus` plus an explicit `now`, so the formatting logic is testable
//! without touching the real machine, the real clock or a real terminal.

use anstyle::{AnsiColor, Effects, Style};
use chrono::{DateTime, Duration, Utc};
use patchbay_core::ToolStatus;

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
    fn style(self) -> Style {
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
    }
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
        let note = truncate(&note_text, notes_w);

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

    out
}

// ---------------------------------------------------------------------------
// shared bits for the other subcommands
// ---------------------------------------------------------------------------

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
