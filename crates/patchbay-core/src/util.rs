//! Small shared helpers: tolerant file reads, a minimal INI parser, timestamp
//! parsing, and the one place where patchbay shells out.

use std::path::Path;
use std::process::Command;

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

/// Outcome of shelling out to a tool's own CLI.
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
    let output = Command::new(bin)
        .args(args)
        .env("NO_COLOR", "1")
        .env("CLICOLOR", "0")
        .output()
        .map_err(|e| anyhow::anyhow!("could not run `{} {}`: {}", bin, args.join(" "), e))?;
    Ok(CmdOutput {
        ok: output.status.success(),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn test_read_text_missing_file_is_not_an_error() {
        assert_eq!(read_text(Path::new("/nope/nope.json")), Ok(None));
    }
}
