//! Small shared helpers: tolerant file reads, a minimal INI parser, timestamp
//! parsing, the one place where patchbay shells out, and the write-safety
//! machinery every mutation of somebody else's config file goes through.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use chrono::{DateTime, NaiveDateTime, TimeZone, Utc};

/// Read a UTF-8 file, stripping a UTF-8 BOM if present (the Azure CLI writes
/// one). `Ok(None)` when the file does not exist or is not a regular file —
/// both are ordinary "tool not set up" states, not errors.
pub fn read_text(path: &Path) -> Result<Option<String>, String> {
    if !path.is_file() {
        return Ok(None);
    }
    match std::fs::read(path) {
        Ok(bytes) => {
            let bytes = bytes
                .strip_prefix(&[0xEF, 0xBB, 0xBF][..])
                .unwrap_or(&bytes)
                .to_vec();
            match String::from_utf8(bytes) {
                Ok(text) => Ok(Some(text)),
                Err(_) => Err(format!("{} is not valid UTF-8", path.display())),
            }
        }
        Err(e) => Err(format!("could not read {}: {}", path.display(), e)),
    }
}

/// A parsed INI file: ordered sections, each an ordered list of key/value pairs.
/// Deliberately tiny — the INI dialects patchbay reads (aws, gcloud, rclone) are
/// flat `key = value` under `[section]` headers.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct Ini {
    pub sections: Vec<IniSection>,
}

#[derive(Debug, Default, Clone, PartialEq)]
pub struct IniSection {
    pub name: String,
    pub entries: Vec<(String, String)>,
}

impl IniSection {
    pub fn get(&self, key: &str) -> Option<&str> {
        self.entries
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(key))
            .map(|(_, v)| v.as_str())
    }

    pub fn has_prefix(&self, prefix: &str) -> bool {
        self.entries.iter().any(|(k, _)| k.starts_with(prefix))
    }
}

impl Ini {
    /// Never fails: lines that are not a header or a `key = value` pair are
    /// skipped. Values are split on the *first* `=` so JSON values survive.
    pub fn parse(text: &str) -> Self {
        let mut sections: Vec<IniSection> = Vec::new();
        for raw in text.lines() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
                continue;
            }
            if let Some(rest) = line.strip_prefix('[') {
                if let Some(name) = rest.strip_suffix(']') {
                    sections.push(IniSection {
                        name: name.trim().to_string(),
                        entries: Vec::new(),
                    });
                }
                continue;
            }
            if let Some((key, value)) = line.split_once('=') {
                if let Some(section) = sections.last_mut() {
                    section
                        .entries
                        .push((key.trim().to_string(), value.trim().to_string()));
                }
            }
        }
        Self { sections }
    }

    pub fn section(&self, name: &str) -> Option<&IniSection> {
        self.sections.iter().find(|s| s.name == name)
    }
}

/// Parse the timestamp dialects patchbay meets in credential caches:
/// RFC 3339, and gcloud's naive `YYYY-MM-DD HH:MM:SS[.ffffff]` (which is UTC).
pub fn parse_timestamp(raw: &str) -> Option<DateTime<Utc>> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    if let Ok(dt) = DateTime::parse_from_rfc3339(raw) {
        return Some(dt.with_timezone(&Utc));
    }
    for fmt in [
        "%Y-%m-%d %H:%M:%S%.f",
        "%Y-%m-%dT%H:%M:%S%.f",
        "%Y-%m-%d %H:%M:%S%.f%#z",
        "%Y-%m-%dT%H:%M:%SZ",
    ] {
        if let Ok(naive) = NaiveDateTime::parse_from_str(raw, fmt) {
            return Some(Utc.from_utc_datetime(&naive));
        }
    }
    // Unix epoch seconds (some SSO caches).
    if let Ok(secs) = raw.parse::<i64>() {
        return DateTime::from_timestamp(secs, 0);
    }
    None
}

/// Epoch **milliseconds**, the dialect the JS-based CLIs write (`neon`'s
/// `credentials.json`, `firebase-tools`' `tokens.expires_at`).
///
/// Kept separate from [`parse_timestamp`] on purpose: a millisecond value fed
/// to a seconds parser silently lands ~55 000 years in the future, which would
/// read as a perfectly healthy credential.
pub fn parse_epoch_millis(millis: i64) -> Option<DateTime<Utc>> {
    DateTime::from_timestamp_millis(millis)
}

/// Outcome of shelling out to a tool's own CLI.
#[derive(Debug, Clone)]
pub struct CmdOutput {
    pub ok: bool,
    pub stdout: String,
    pub stderr: String,
}

impl CmdOutput {
    /// stdout if non-empty, else stderr — for one-line status reporting.
    pub fn message(&self) -> String {
        let text = if self.stdout.trim().is_empty() {
            self.stderr.trim()
        } else {
            self.stdout.trim()
        };
        text.lines()
            .filter(|l| !l.trim().is_empty())
            .collect::<Vec<_>>()
            .join("; ")
    }
}

/// Run a tool's CLI and capture its output.
///
/// `Err` only when the binary could not be spawned at all. Non-zero exit is a
/// normal result and comes back as `ok: false`.
pub fn run(bin: &str, args: &[&str]) -> anyhow::Result<CmdOutput> {
    run_env(bin, args, &[])
}

/// [`run`], with extra environment for the child process only.
///
/// This is how patchbay answers "verify *that* profile" for tools that select
/// an identity through the environment: it cannot change the parent shell, but
/// it can absolutely set the variable on the command it runs itself.
pub fn run_env(bin: &str, args: &[&str], env: &[(&str, &str)]) -> anyhow::Result<CmdOutput> {
    let mut command = Command::new(bin);
    command.args(args).env("NO_COLOR", "1").env("CLICOLOR", "0");
    for (key, value) in env {
        command.env(key, value);
    }
    let output = command
        .output()
        .map_err(|e| anyhow::anyhow!("could not run `{} {}`: {}", bin, args.join(" "), e))?;
    Ok(CmdOutput {
        ok: output.status.success(),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    })
}

// ---------------------------------------------------------------------------
// the exec seam
// ---------------------------------------------------------------------------

/// How a probe runs another tool's CLI.
///
/// Tier-2 work — `verify`, `permissions` — means executing somebody else's
/// binary, which a unit test must never do. Probes therefore never call
/// [`run`] directly; they go through the [`Exec`] their [`crate::Paths`]
/// carries, which is the real thing in production and a scripted fake in tests.
pub trait Exec: std::fmt::Debug + Send + Sync {
    /// Run `bin` with `args`, plus `env` for the child only.
    fn run(&self, bin: &str, args: &[&str], env: &[(&str, &str)]) -> anyhow::Result<CmdOutput>;
}

/// The real one: spawns the process.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemExec;

impl Exec for SystemExec {
    fn run(&self, bin: &str, args: &[&str], env: &[(&str, &str)]) -> anyhow::Result<CmdOutput> {
        run_env(bin, args, env)
    }
}

/// One recorded invocation, for assertions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecCall {
    pub bin: String,
    pub args: Vec<String>,
    pub env: Vec<(String, String)>,
}

impl ExecCall {
    /// The command as a shell-ish line, for readable assertions.
    pub fn line(&self) -> String {
        std::iter::once(self.bin.clone())
            .chain(self.args.iter().cloned())
            .collect::<Vec<_>>()
            .join(" ")
    }
}

/// Scripted [`Exec`] for tests. Matches on a substring of the command line and
/// records everything it was asked to run, so a test can assert both the
/// outcome and the command that produced it — without a subprocess.
#[derive(Debug, Default)]
pub struct FakeExec {
    /// `(substring the command line must contain, what to return)`, first match
    /// wins. An empty substring matches anything.
    scripted: std::sync::Mutex<Vec<(String, CmdOutput)>>,
    calls: std::sync::Mutex<Vec<ExecCall>>,
}

impl FakeExec {
    pub fn new() -> Self {
        Self::default()
    }

    /// Reply to any command whose line contains `matching`.
    pub fn on(self, matching: &str, ok: bool, stdout: &str, stderr: &str) -> Self {
        self.scripted.lock().expect("exec lock").push((
            matching.to_string(),
            CmdOutput {
                ok,
                stdout: stdout.to_string(),
                stderr: stderr.to_string(),
            },
        ));
        self
    }

    /// Every command run, in order.
    pub fn calls(&self) -> Vec<ExecCall> {
        self.calls.lock().expect("exec lock").clone()
    }

    pub fn last(&self) -> Option<ExecCall> {
        self.calls.lock().expect("exec lock").last().cloned()
    }
}

impl Exec for FakeExec {
    fn run(&self, bin: &str, args: &[&str], env: &[(&str, &str)]) -> anyhow::Result<CmdOutput> {
        let call = ExecCall {
            bin: bin.to_string(),
            args: args.iter().map(|a| a.to_string()).collect(),
            env: env
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        };
        let line = call.line();
        self.calls.lock().expect("exec lock").push(call);

        let scripted = self.scripted.lock().expect("exec lock");
        for (matching, output) in scripted.iter() {
            if matching.is_empty() || line.contains(matching.as_str()) {
                return Ok(CmdOutput {
                    ok: output.ok,
                    stdout: output.stdout.clone(),
                    stderr: output.stderr.clone(),
                });
            }
        }
        // Nothing scripted: the same shape as a binary that is not there.
        Err(anyhow::anyhow!(
            "could not run `{line}`: no such file or directory"
        ))
    }
}

/// Shared handle to whichever [`Exec`] is in force.
pub type SharedExec = Arc<dyn Exec>;

// ---------------------------------------------------------------------------
// writing other tools' config files
// ---------------------------------------------------------------------------
//
// Three steps, in this order, for every mutation patchbay makes to a file it
// does not own:
//
//   1. a rolling backup — the file is copied to `<path>.patchbay-bak` first;
//   2. parse–modify–serialize by the caller, never a rewrite from a template,
//      so unknown keys and other entries survive;
//   3. an atomic write: temp file in the same directory, then rename.
//
// Step 2 is the caller's job and the one that cannot be shared: every format
// differs. Steps 1 and 3 are identical everywhere, and live here.

/// Appended to a config path to make its rolling backup. One generation only:
/// the point is an undo for the write patchbay just did, not an archive.
const BACKUP_SUFFIX: &str = ".patchbay-bak";

/// `<path>.patchbay-bak`. Suffix, not extension: `mcp.json.patchbay-bak` keeps
/// the original name visible, and `with_extension` would eat the `.json`.
pub fn backup_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(BACKUP_SUFFIX);
    PathBuf::from(name)
}

/// Copy the file aside before it is modified. A single rolling generation: the
/// undo for the write about to happen. `Ok(None)` when there was no file yet.
pub fn backup(path: &Path) -> anyhow::Result<Option<PathBuf>> {
    if !path.is_file() {
        return Ok(None);
    }
    let dest = backup_path(path);
    std::fs::copy(path, &dest).map_err(|e| {
        anyhow::anyhow!(
            "could not back {} up to {}: {e}; nothing was modified",
            path.display(),
            dest.display()
        )
    })?;
    Ok(Some(dest))
}

/// Temp file in the same directory, then rename. A crash mid-write leaves the
/// original untouched rather than a truncated config no tool can parse.
pub fn write_atomic(path: &Path, body: &str) -> anyhow::Result<()> {
    let dir = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("{} has no parent directory", path.display()))?;
    std::fs::create_dir_all(dir)
        .map_err(|e| anyhow::anyhow!("could not create {}: {e}", dir.display()))?;

    let file_name = path
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("{} has no file name", path.display()))?
        .to_string_lossy()
        .into_owned();
    let tmp = dir.join(format!(".{file_name}.patchbay-tmp"));

    std::fs::write(&tmp, body)
        .map_err(|e| anyhow::anyhow!("could not write {}: {e}", tmp.display()))?;

    // Keep the file's own permissions; these configs hold API keys and vault
    // passphrases, and a new one should not be born world-readable.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path)
            .map(|m| m.permissions().mode() & 0o777)
            .unwrap_or(0o600);
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(mode))
            .map_err(|e| anyhow::anyhow!("could not chmod {}: {e}", tmp.display()))?;
    }

    std::fs::rename(&tmp, path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        anyhow::anyhow!("could not replace {}: {e}", path.display())
    })
}

/// Serialize JSON back out in the shape the file already had.
///
/// Tools write these files themselves, and each has a house style: Claude Code
/// pretty-prints, the Infisical CLI writes one compact line with `": "` and
/// `", "` separators and no trailing newline. Handing either one back in the
/// other's format makes a whole-file diff out of a two-field change — which
/// buries the edit patchbay actually made and looks, to anyone reading
/// `git diff` or the backup, like patchbay rewrote the lot.
///
/// `original` is the text as read; `None` for a file being created, which gets
/// the pretty form.
pub fn serialize_json_preserving_style(root: &serde_json::Value, original: Option<&str>) -> String {
    match JsonStyle::of(original) {
        JsonStyle::Pretty => {
            let mut body = serde_json::to_string_pretty(root).unwrap_or_default();
            body.push('\n');
            body
        }
        JsonStyle::Compact => serde_json::to_string(root).unwrap_or_default(),
        JsonStyle::CompactSpaced => {
            let mut out = Vec::new();
            let mut ser = serde_json::Serializer::with_formatter(&mut out, SpacedCompactFormatter);
            match serde::Serialize::serialize(root, &mut ser) {
                Ok(()) => String::from_utf8(out).unwrap_or_default(),
                // Unreachable for an in-memory Value; fall back rather than panic.
                Err(_) => serde_json::to_string(root).unwrap_or_default(),
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum JsonStyle {
    /// Indented, one key per line, trailing newline.
    Pretty,
    /// One line, `{"a":1}`.
    Compact,
    /// One line, `{"a": 1, "b": 2}` — what Go's encoder with `SetIndent("","")`
    /// and several CLIs produce.
    CompactSpaced,
}

impl JsonStyle {
    fn of(original: Option<&str>) -> Self {
        let Some(text) = original else {
            return Self::Pretty;
        };
        // A one-key file is not evidence of a house style; `{}` even less so.
        if text.trim_end().contains('\n') || text.len() <= 2 {
            return Self::Pretty;
        }
        // Majority vote over the object separators actually used, so a `": "`
        // sitting inside a string value cannot swing the whole file.
        let spaced = text.matches("\": \"").count() + text.matches("\": ").count();
        let tight = text.matches("\":\"").count() + text.matches("\":").count();
        if spaced > tight - spaced.min(tight) {
            Self::CompactSpaced
        } else {
            Self::Compact
        }
    }
}

/// serde_json's compact form writes `{"a":1}`. Tools that write `{"a": 1}` on
/// one line need this formatter, or every byte of their file changes.
struct SpacedCompactFormatter;

impl serde_json::ser::Formatter for SpacedCompactFormatter {
    fn begin_object_key<W: ?Sized + std::io::Write>(
        &mut self,
        writer: &mut W,
        first: bool,
    ) -> std::io::Result<()> {
        if first {
            Ok(())
        } else {
            writer.write_all(b", ")
        }
    }

    fn begin_object_value<W: ?Sized + std::io::Write>(
        &mut self,
        writer: &mut W,
    ) -> std::io::Result<()> {
        writer.write_all(b": ")
    }

    fn begin_array_value<W: ?Sized + std::io::Write>(
        &mut self,
        writer: &mut W,
        first: bool,
    ) -> std::io::Result<()> {
        if first {
            Ok(())
        } else {
            writer.write_all(b", ")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serialize_json_keeps_the_files_own_shape() {
        let value: serde_json::Value = serde_json::from_str(r#"{"a":"x","b":"y"}"#).unwrap();

        // A tight one-liner stays tight, with no trailing newline.
        let out = serialize_json_preserving_style(&value, Some(r#"{"a":"x","b":"y"}"#));
        assert_eq!(out, r#"{"a":"x","b":"y"}"#);

        // A spaced one-liner keeps its spaces.
        let out = serialize_json_preserving_style(&value, Some(r#"{"a": "x", "b": "y"}"#));
        assert_eq!(out, r#"{"a": "x", "b": "y"}"#);

        // A pretty file stays pretty, with the trailing newline it had.
        let out = serialize_json_preserving_style(&value, Some("{\n  \"a\": \"x\"\n}\n"));
        assert!(out.contains("\n  \"a\": \"x\""), "{out}");
        assert!(out.ends_with('\n'));

        // A file being created gets the readable form.
        assert!(serialize_json_preserving_style(&value, None).ends_with("}\n"));
        // An empty or trivial original is not evidence of a compact house style.
        assert!(serialize_json_preserving_style(&value, Some("{}")).ends_with("}\n"));
    }

    #[test]
    fn test_spaced_compact_round_trips_a_real_infisical_config() {
        // The exact shape the Infisical CLI writes: one line, `": "` and `", "`
        // separators, a nested array of objects, no trailing newline.
        let original = r#"{"loggedInUserEmail": "a@example.com", "LoggedInUserDomain": "https://app.infisical.com/api", "loggedInUsers": [{"email": "a@example.com", "domain": "https://app.infisical.com/api"}], "vaultBackendType": "file", "vaultBackendPassphrase": "ZmFrZQ=="}"#;
        let value: serde_json::Value = serde_json::from_str(original).unwrap();
        // Untouched in, byte-identical out.
        assert_eq!(
            serialize_json_preserving_style(&value, Some(original)),
            original
        );
    }

    #[test]
    fn test_a_colon_space_inside_a_value_does_not_flip_the_style() {
        // Every separator here is tight; the `": "` lives inside a URL-ish
        // string. One occurrence must not outvote three real separators.
        let original = r#"{"a":"x: y","b":"z","c":"w"}"#;
        let value: serde_json::Value = serde_json::from_str(original).unwrap();
        assert_eq!(
            serialize_json_preserving_style(&value, Some(original)),
            original
        );
    }

    #[test]
    fn test_backup_path_keeps_the_original_name_visible() {
        assert_eq!(
            backup_path(Path::new("/a/mcp.json")),
            PathBuf::from("/a/mcp.json.patchbay-bak")
        );
        assert_eq!(
            backup_path(Path::new("/a/config.toml")),
            PathBuf::from("/a/config.toml.patchbay-bak")
        );
    }

    #[test]
    fn test_backup_of_a_missing_file_is_not_an_error() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(backup(&dir.path().join("nope.json")).unwrap(), None);
    }

    #[test]
    fn test_write_atomic_leaves_no_temp_file_and_keeps_the_mode() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.json");
        std::fs::write(&path, "old").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }

        let saved = backup(&path).unwrap().unwrap();
        write_atomic(&path, "new").unwrap();

        assert_eq!(std::fs::read_to_string(&path).unwrap(), "new");
        assert_eq!(std::fs::read_to_string(&saved).unwrap(), "old");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "mode was {:o}", mode & 0o777);
        }
        // The temp file is a rename source, never a leftover.
        let stray: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.contains("patchbay-tmp"))
            .collect();
        assert!(stray.is_empty(), "left a temp file behind: {stray:?}");
    }

    #[test]
    fn test_ini_parses_sections_and_keeps_json_values_intact() {
        let ini = Ini::parse(
            "# comment\n[core]\naccount = a@b.com\nproject = p\n\n[remote]\ntoken = {\"a\":\"b=c\"}\n",
        );
        assert_eq!(ini.sections.len(), 2);
        assert_eq!(ini.section("core").unwrap().get("account"), Some("a@b.com"));
        assert_eq!(
            ini.section("remote").unwrap().get("token"),
            Some("{\"a\":\"b=c\"}")
        );
    }

    #[test]
    fn test_ini_skips_garbage_instead_of_failing() {
        let ini = Ini::parse("not ini at all\n<<<<<<< HEAD\n[ok]\nk = v\n");
        assert_eq!(ini.section("ok").unwrap().get("k"), Some("v"));
    }

    #[test]
    fn test_parse_timestamp_dialects() {
        assert!(parse_timestamp("2026-08-13T09:35:10.145276Z").is_some());
        assert!(parse_timestamp("2026-08-13 09:35:10.145205").is_some());
        assert!(parse_timestamp("2026-03-13T10:24:29.685Z").is_some());
        assert!(parse_timestamp("").is_none());
        assert!(parse_timestamp("never").is_none());
    }

    #[test]
    fn test_parse_epoch_millis_is_not_the_seconds_parser() {
        // A real value out of ~/.config/neonctl/credentials.json.
        let at = parse_epoch_millis(1785611828464).unwrap();
        assert_eq!(at.to_rfc3339(), "2026-08-01T19:17:08.464+00:00");
        // The same number through the seconds path lands in the far future.
        use chrono::Datelike;
        assert!(parse_timestamp("1785611828464").unwrap().year() > 9999);
        assert!(parse_epoch_millis(i64::MAX).is_none());
    }

    #[test]
    fn test_read_text_missing_file_is_not_an_error() {
        assert_eq!(read_text(Path::new("/nope/nope.json")), Ok(None));
    }
}
