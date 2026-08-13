//! Where the secret values of the key vault actually live.
//!
//! patchbay never writes a secret to disk. The registry keeps metadata (see
//! [`crate::keys`]); the value itself goes into the macOS Keychain through this
//! trait, so the on-disk footprint of a registered key is its last four
//! characters and nothing more.
//!
//! The trait exists for two reasons: a Linux port becomes one more impl, and —
//! more importantly — the unit tests get [`MemoryKeystore`]. **No test in this
//! workspace may exercise [`SecurityCliKeystore`]**: it would execute
//! `security(1)` and write to the developer's real login keychain.

use std::collections::HashMap;
use std::process::Command;
use std::sync::Mutex;

/// The `-s` (service) value every patchbay keychain item is filed under, so a
/// human can find and audit them: `security find-generic-password -s patchbay`.
pub const KEYCHAIN_SERVICE: &str = "patchbay";

/// Storage for secret values, keyed by [`crate::keys::KeyEntry::id`].
///
/// Implementations must never log, print or embed a secret value in an error.
pub trait Keystore: Send + Sync {
    /// Store (or replace) the value for `id`.
    fn put(&self, id: &str, secret: &str) -> anyhow::Result<()>;

    /// The value for `id`, or `Ok(None)` when the store has no such item.
    fn get(&self, id: &str) -> anyhow::Result<Option<String>>;

    /// Delete the item. `Ok(false)` when there was nothing to delete — that is
    /// a normal outcome, not an error, so `remove` can heal a half-state.
    fn delete(&self, id: &str) -> anyhow::Result<bool>;

    /// Human-readable name of the backing store, for messages.
    fn describe(&self) -> &'static str;
}

// ---------------------------------------------------------------------------
// macOS Keychain, via the `security` CLI
// ---------------------------------------------------------------------------

/// The real store on macOS: generic passwords in the login keychain, filed
/// under service [`KEYCHAIN_SERVICE`] with the key id as the account.
#[derive(Debug, Default, Clone, Copy)]
pub struct SecurityCliKeystore;

impl SecurityCliKeystore {
    pub fn new() -> Self {
        Self
    }
}

/// `security(1)` exits 44 when the requested item is not in the keychain.
const ERR_SEC_ITEM_NOT_FOUND: i32 = 44;

/// Run `security` and capture its output.
///
/// Nothing from `stdout` is ever logged by callers of this function on the read
/// path: for `find-generic-password -w`, stdout *is* the secret.
fn security(args: &[&str]) -> anyhow::Result<(Option<i32>, String, String)> {
    let out = Command::new("security")
        .args(args)
        .output()
        .map_err(|e| anyhow::anyhow!("could not run `security`: {e}"))?;
    Ok((
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    ))
}

/// One line of `security`'s stderr, for error messages. Trimmed and collapsed;
/// `security` never echoes the password on stderr, but callers still pass the
/// result through [`scrub`] before it reaches a user.
fn first_line(text: &str) -> String {
    text.lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .unwrap_or("no output")
        .to_string()
}

/// Belt and braces: remove the secret from a string that is about to be shown.
/// Nothing is expected to echo it — this is here so that a future change to
/// `security`, or a different backend, cannot turn an error path into a leak.
fn scrub(text: &str, secret: &str) -> String {
    if secret.is_empty() {
        return text.to_string();
    }
    text.replace(secret, "<redacted>")
}

impl Keystore for SecurityCliKeystore {
    fn put(&self, id: &str, secret: &str) -> anyhow::Result<()> {
        // KNOWN TRADEOFF: `-w <value>` puts the secret in this process's argv,
        // where it is visible to `ps` for the lifetime of the call (milliseconds,
        // and on macOS only to the same user — but visible). `security` has no
        // way to take a password on stdin, so the CLI cannot avoid it.
        //
        // TODO: replace this whole impl with the Security framework
        // (SecItemAdd / SecItemCopyMatching / SecItemDelete via the
        // `security-framework` crate), which passes the value in memory and
        // never builds a command line at all.
        let (code, _stdout, stderr) = security(&[
            "add-generic-password",
            "-U",
            "-s",
            KEYCHAIN_SERVICE,
            "-a",
            id,
            "-w",
            secret,
        ])?;
        if code == Some(0) {
            return Ok(());
        }
        anyhow::bail!(
            "keychain refused to store `{id}`: {}",
            scrub(&first_line(&stderr), secret)
        )
    }

    fn get(&self, id: &str) -> anyhow::Result<Option<String>> {
        let (code, stdout, stderr) = security(&[
            "find-generic-password",
            "-s",
            KEYCHAIN_SERVICE,
            "-a",
            id,
            "-w",
        ])?;
        match code {
            // stdout is the secret; it is returned, never logged.
            Some(0) => Ok(Some(stdout.trim_end_matches('\n').to_string())),
            Some(ERR_SEC_ITEM_NOT_FOUND) => Ok(None),
            _ => anyhow::bail!("keychain lookup for `{id}` failed: {}", first_line(&stderr)),
        }
    }

    fn delete(&self, id: &str) -> anyhow::Result<bool> {
        // Prints the item's attributes (not its value) on success; discarded.
        let (code, _stdout, stderr) =
            security(&["delete-generic-password", "-s", KEYCHAIN_SERVICE, "-a", id])?;
        match code {
            Some(0) => Ok(true),
            Some(ERR_SEC_ITEM_NOT_FOUND) => Ok(false),
            _ => anyhow::bail!("keychain refused to delete `{id}`: {}", first_line(&stderr)),
        }
    }

    fn describe(&self) -> &'static str {
        "macOS Keychain"
    }
}

// ---------------------------------------------------------------------------
// test fake
// ---------------------------------------------------------------------------

/// In-memory [`Keystore`] for tests. Never touches the real keychain and never
/// executes anything.
///
/// The failure switches exist to test the rollback path in
/// [`crate::keys::KeyRegistry::add`], which is the one place where a keystore
/// error has to undo an already-written metadata file.
#[derive(Debug, Default)]
pub struct MemoryKeystore {
    entries: Mutex<HashMap<String, String>>,
    fail_put: bool,
    fail_delete: bool,
}

impl MemoryKeystore {
    pub fn new() -> Self {
        Self::default()
    }

    /// A store whose writes always fail.
    pub fn failing_put() -> Self {
        Self {
            fail_put: true,
            ..Self::default()
        }
    }

    /// A store whose deletes always fail.
    pub fn failing_delete() -> Self {
        Self {
            fail_delete: true,
            ..Self::default()
        }
    }

    pub fn contains(&self, id: &str) -> bool {
        self.entries.lock().expect("keystore lock").contains_key(id)
    }

    pub fn len(&self) -> usize {
        self.entries.lock().expect("keystore lock").len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Keystore for MemoryKeystore {
    fn put(&self, id: &str, secret: &str) -> anyhow::Result<()> {
        if self.fail_put {
            anyhow::bail!("simulated keychain failure storing `{id}`");
        }
        self.entries
            .lock()
            .expect("keystore lock")
            .insert(id.to_string(), secret.to_string());
        Ok(())
    }

    fn get(&self, id: &str) -> anyhow::Result<Option<String>> {
        Ok(self.entries.lock().expect("keystore lock").get(id).cloned())
    }

    fn delete(&self, id: &str) -> anyhow::Result<bool> {
        if self.fail_delete {
            anyhow::bail!("simulated keychain failure deleting `{id}`");
        }
        Ok(self
            .entries
            .lock()
            .expect("keystore lock")
            .remove(id)
            .is_some())
    }

    fn describe(&self) -> &'static str {
        "in-memory test keystore"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_keystore_round_trip() {
        let store = MemoryKeystore::new();
        assert!(store.is_empty());
        store.put("a", "sekrit").unwrap();
        assert_eq!(store.get("a").unwrap().as_deref(), Some("sekrit"));
        assert!(store.contains("a"));
        assert!(store.delete("a").unwrap());
        // Deleting again is a normal no-op, not an error.
        assert!(!store.delete("a").unwrap());
        assert_eq!(store.get("a").unwrap(), None);
    }

    #[test]
    fn test_memory_keystore_failure_switches() {
        assert!(MemoryKeystore::failing_put().put("a", "s").is_err());
        assert!(MemoryKeystore::failing_delete().delete("a").is_err());
    }

    #[test]
    fn test_scrub_removes_the_secret() {
        assert_eq!(
            scrub("value was hunter2", "hunter2"),
            "value was <redacted>"
        );
        assert_eq!(scrub("nothing here", ""), "nothing here");
    }

    #[test]
    fn test_first_line_condenses_stderr() {
        assert_eq!(first_line("\n  boom  \nmore\n"), "boom");
        assert_eq!(first_line(""), "no output");
    }
}
