//! `PATH` repair for processes launched outside a login shell.
//!
//! macOS hands GUI apps and launchd children a bare
//! `/usr/bin:/bin:/usr/sbin:/sbin` — nothing the user's shell startup files
//! add (Homebrew, `~/google-cloud-sdk/bin`, npm prefixes, cargo) is on it.
//! Inside such a process every `which` lookup fails, so the panel and an MCP
//! server spawned by a GUI client both report installed CLIs as "not available
//! on PATH" while the same probe in a terminal finds them instantly.
//!
//! [`adopt_login_shell_path`] closes the gap: when — and only when — the
//! inherited `PATH` looks like the launchd default, it asks the user's own
//! shell (as a login + interactive shell, so `~/.zprofile` *and* `~/.zshrc`
//! both get their say) what `PATH` it would give a terminal, and adopts that
//! for the rest of the process. Terminal launches pay nothing: their `PATH`
//! already carries user entries, which fails the launchd-default test.
//!
//! The shell runs with stdin and stderr on `/dev/null` and a hard timeout, so
//! a prompt-happy rc file can delay startup by at most [`SHELL_TIMEOUT`], never
//! hang it. Its stdout is parsed only between two markers printed by our own
//! command; rc-file chatter outside them is discarded unread.

use std::time::Duration;

/// Two of these bracket the `PATH` value in the shell's stdout, so rc-file
/// output cannot masquerade as it.
const MARKER: &str = "<<patchbay:path>>";

/// How long the login shell gets before it is killed and the repair skipped.
/// Generous: nvm-laden zshrcs take around a second, not five.
const SHELL_TIMEOUT: Duration = Duration::from_secs(5);

/// Replace this process's `PATH` with the user's login-shell `PATH` when the
/// inherited one is the bare launchd default. Call once, at the top of `main`,
/// before anything resolves or spawns a CLI. A no-op in a terminal, on
/// non-unix platforms, and whenever the shell cannot answer.
pub fn adopt_login_shell_path() {
    #[cfg(unix)]
    {
        let current = std::env::var("PATH").unwrap_or_default();
        if !is_launchd_default(&current) {
            return;
        }
        let Some(shell_path) = login_shell_path() else {
            return;
        };
        let merged = merge_paths(&shell_path, &current);
        if !merged.is_empty() && merged != current {
            std::env::set_var("PATH", merged);
        }
    }
}

/// `true` when every entry is one launchd (or an installer's postflight) puts
/// there on its own — i.e. no evidence a user-configured environment reached
/// this process. One entry outside the set means someone set a real `PATH`,
/// and second-guessing it would be wrong more often than right.
fn is_launchd_default(path: &str) -> bool {
    const SYSTEM_DIRS: &[&str] = &[
        "/usr/bin",
        "/bin",
        "/usr/sbin",
        "/sbin",
        "/usr/local/bin",
        "/Library/Apple/usr/bin",
        "/System/Cryptexes/App/usr/bin",
    ];
    let mut entries = path.split(':').filter(|e| !e.is_empty()).peekable();
    entries.peek().is_some() && entries.all(|e| SYSTEM_DIRS.contains(&e))
}

/// `preferred` first, then whatever `current` adds, first occurrence wins.
/// The login shell's ordering is what the user's terminal resolves with, so
/// it must also be what decides between two installs of the same tool here.
fn merge_paths(preferred: &str, current: &str) -> String {
    let mut seen: Vec<&str> = Vec::new();
    for entry in preferred.split(':').chain(current.split(':')) {
        if !entry.is_empty() && !seen.contains(&entry) {
            seen.push(entry);
        }
    }
    seen.join(":")
}

/// The command the login shell runs: print `PATH` between two markers.
/// fish spells "the colon-joined PATH" differently, every POSIX-ish shell
/// (zsh, bash, sh, dash, ksh) accepts the `"$PATH"` form.
fn print_path_command(shell: &str) -> String {
    if shell.rsplit('/').next() == Some("fish") {
        format!("printf '{MARKER}%s{MARKER}' (string join : $PATH)")
    } else {
        format!("printf '{MARKER}%s{MARKER}' \"$PATH\"")
    }
}

/// The text our own printf produced, or `None` when the markers never showed
/// up (a shell that refused the command, an rc file that exec'd away).
fn between_markers(output: &str) -> Option<&str> {
    let start = output.find(MARKER)? + MARKER.len();
    let len = output[start..].find(MARKER)?;
    Some(&output[start..start + len])
}

/// Ask `$SHELL` (login + interactive) for its `PATH`. `None` on any failure —
/// the caller keeps the `PATH` it has, which is the worst case today, not a
/// new one.
#[cfg(unix)]
fn login_shell_path() -> Option<String> {
    use std::io::Read;
    use std::process::{Command, Stdio};
    use std::time::Instant;

    let shell = std::env::var("SHELL")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "/bin/sh".to_string());

    let mut child = Command::new(&shell)
        .args(["-l", "-i", "-c", &print_path_command(&shell)])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;

    // Poll rather than block: an rc file waiting on a prompt must cost a
    // bounded delay, not a hung process. The single printf cannot fill the
    // pipe, so the child never blocks on us either.
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if start.elapsed() < SHELL_TIMEOUT => {
                std::thread::sleep(Duration::from_millis(25));
            }
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    }

    let mut output = String::new();
    child.stdout.take()?.read_to_string(&mut output).ok()?;
    between_markers(&output)
        .map(str::to_string)
        .filter(|p| !p.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn launchd_default_is_recognised() {
        assert!(is_launchd_default("/usr/bin:/bin:/usr/sbin:/sbin"));
        assert!(is_launchd_default(
            "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
        ));
    }

    /// One user entry — a Homebrew prefix, a home-dir bin — means a real
    /// environment reached us and the repair must stand down.
    #[test]
    fn a_user_entry_defeats_the_launchd_test() {
        assert!(!is_launchd_default(
            "/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin"
        ));
        assert!(!is_launchd_default(
            "/Users/dev/google-cloud-sdk/bin:/usr/bin:/bin"
        ));
        assert!(!is_launchd_default(""));
    }

    #[test]
    fn merge_prefers_the_shell_order_and_deduplicates() {
        assert_eq!(
            merge_paths("/opt/homebrew/bin:/usr/bin:/bin", "/usr/bin:/bin:/sbin"),
            "/opt/homebrew/bin:/usr/bin:/bin:/sbin"
        );
        assert_eq!(merge_paths("", "/usr/bin::/bin"), "/usr/bin:/bin");
    }

    #[test]
    fn markers_isolate_the_path_from_rc_chatter() {
        let noisy = format!("welcome banner\n{MARKER}/a:/b{MARKER}\ntrailing");
        assert_eq!(between_markers(&noisy), Some("/a:/b"));
        assert_eq!(between_markers("no markers here"), None);
        assert_eq!(between_markers(MARKER), None);
    }

    #[test]
    fn fish_gets_its_own_spelling() {
        assert!(print_path_command("/opt/homebrew/bin/fish").contains("string join"));
        assert!(print_path_command("/bin/zsh").contains("\"$PATH\""));
    }
}
