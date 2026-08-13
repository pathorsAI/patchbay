//! The set of probes patchbay knows about, and the entry points the CLI, the
//! MCP server and the app all go through.

use std::collections::HashMap;

use chrono::Utc;

use crate::keys::KeyRegistry;
use crate::keystore::SecurityCliKeystore;
use crate::paths::Paths;
use crate::probe::Probe;
use crate::probes;
use crate::types::{KeyRef, PermissionsReport, SwitchOutcome, ToolStatus, VerifyOutcome};

pub struct Registry {
    probes: Vec<Box<dyn Probe>>,
    /// The key vault, when one is attached. Optional so `Registry::all` stays
    /// usable in tests without a keystore, and so a machine with no vault is a
    /// normal empty board rather than a special case.
    keys: Option<KeyRegistry>,
}

impl Registry {
    /// Every probe, bound to the given paths.
    pub fn all(paths: Paths) -> Self {
        Self {
            probes: vec![
                Box::new(probes::gcloud::GcloudProbe::new(paths.clone())),
                Box::new(probes::aws::AwsProbe::new(paths.clone())),
                Box::new(probes::gh::GhProbe::new(paths.clone())),
                Box::new(probes::infisical::InfisicalProbe::new(paths.clone())),
                Box::new(probes::kubectl::KubectlProbe::new(paths.clone())),
                Box::new(probes::wrangler::WranglerProbe::new(paths.clone())),
                Box::new(probes::rclone::RcloneProbe::new(paths.clone())),
                Box::new(probes::az::AzProbe::new(paths)),
            ],
            keys: None,
        }
    }

    /// Attach a key vault, so statuses carry the standalone keys that belong
    /// beside each tool.
    pub fn with_keys(mut self, keys: KeyRegistry) -> Self {
        self.keys = Some(keys);
        self
    }

    /// Probes bound to the real machine, with the real key vault attached.
    pub fn detect() -> anyhow::Result<Self> {
        let paths = Paths::detect()?;
        let keys = KeyRegistry::with_paths(&paths, Box::new(SecurityCliKeystore::new()));
        Ok(Self::all(paths).with_keys(keys))
    }

    pub fn tool_names(&self) -> Vec<&'static str> {
        self.probes.iter().map(|p| p.tool()).collect()
    }

    pub fn get(&self, tool: &str) -> Option<&dyn Probe> {
        self.probes
            .iter()
            .find(|p| p.tool() == tool)
            .map(|p| p.as_ref())
    }

    fn require(&self, tool: &str) -> anyhow::Result<&dyn Probe> {
        self.get(tool).ok_or_else(|| {
            anyhow::anyhow!(
                "unknown tool `{}`; known tools: {}",
                tool,
                self.tool_names().join(", ")
            )
        })
    }

    /// Tier 1 for every tool. Infallible by construction: a probe that errors
    /// becomes a status carrying the error as a note, so one broken tool never
    /// blanks the board.
    pub fn status_all(&self) -> Vec<ToolStatus> {
        // Read the vault once for the whole board, not once per tool.
        let linked = self.linked_keys();
        self.probes
            .iter()
            .map(|p| {
                let mut status = p.status().unwrap_or_else(|e| {
                    let mut status = ToolStatus::empty(p.tool(), false);
                    status.note(format!("probe failed: {e}"));
                    status
                });
                linked.attach(&mut status);
                status
            })
            .collect()
    }

    pub fn status(&self, tool: &str) -> anyhow::Result<ToolStatus> {
        let mut status = self.require(tool)?.status()?;
        self.linked_keys().attach(&mut status);
        Ok(status)
    }

    /// The vault, indexed by the tool each key belongs beside.
    ///
    /// A vault that cannot be read degrades to an empty index plus a note on
    /// every row, exactly like a probe that fails: the key vault is a bonus on
    /// the status board and must never be able to blank it.
    fn linked_keys(&self) -> LinkedKeys {
        let Some(registry) = self.keys.as_ref() else {
            return LinkedKeys::default();
        };
        let entries = match registry.list() {
            Ok(entries) => entries,
            Err(e) => {
                return LinkedKeys {
                    by_tool: HashMap::new(),
                    note: Some(format!("registered keys unavailable: {e}")),
                }
            }
        };

        let now = Utc::now();
        let mut by_tool: HashMap<&'static str, Vec<KeyRef>> = HashMap::new();
        for entry in &entries {
            if let Some(tool) = entry.linked_tool() {
                by_tool.entry(tool).or_default().push(entry.as_ref_at(now));
            }
        }
        // Soonest expiry first, so the row's first key is the urgent one;
        // undated keys sort last rather than pretending to be fine.
        for refs in by_tool.values_mut() {
            refs.sort_by(|a, b| match (a.expires_at, b.expires_at) {
                (Some(x), Some(y)) => x.cmp(&y),
                (Some(_), None) => std::cmp::Ordering::Less,
                (None, Some(_)) => std::cmp::Ordering::Greater,
                (None, None) => a.id.cmp(&b.id),
            });
        }
        LinkedKeys {
            by_tool,
            note: None,
        }
    }

    pub fn switch(&self, tool: &str, profile_id: &str) -> anyhow::Result<SwitchOutcome> {
        self.require(tool)?.switch(profile_id)
    }

    pub fn verify(&self, tool: &str) -> anyhow::Result<VerifyOutcome> {
        self.require(tool)?.verify()
    }

    pub fn permissions(&self, tool: &str) -> anyhow::Result<PermissionsReport> {
        self.require(tool)?.permissions()
    }
}

/// The vault, grouped by tool, ready to be stamped onto statuses.
#[derive(Debug, Default)]
struct LinkedKeys {
    by_tool: HashMap<&'static str, Vec<KeyRef>>,
    /// Set when the vault could not be read at all.
    note: Option<String>,
}

impl LinkedKeys {
    fn attach(&self, status: &mut ToolStatus) {
        if let Some(refs) = self.by_tool.get(status.tool.as_str()) {
            status.registered_keys = refs.clone();
        }
        if let Some(note) = &self.note {
            status.note(note.clone());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_status_all_covers_every_tool_on_an_empty_machine() {
        let dir = tempfile::tempdir().unwrap();
        let registry = Registry::all(Paths::for_test(dir.path()));
        let all = registry.status_all();
        assert_eq!(all.len(), 8);
        for status in &all {
            assert!(!status.installed, "{} should look absent", status.tool);
            assert!(
                status.profiles.is_empty(),
                "{} leaked profiles",
                status.tool
            );
        }
    }

    /// A vault in a tempdir with a fake keystore — never the real one.
    fn vault(dir: &std::path::Path) -> KeyRegistry {
        KeyRegistry::new(
            dir.join("keys.json"),
            Box::new(crate::keystore::MemoryKeystore::new()),
        )
    }

    fn register(vault: &KeyRegistry, id: &str, provider: &str, expires_in_days: Option<i64>) {
        let new = crate::keys::NewKey::new(id, "cli")
            .provider(provider)
            .expires_at(expires_in_days.map(|d| Utc::now() + chrono::Duration::days(d)));
        vault.add(new, &format!("secret-for-{id}"), false).unwrap();
    }

    #[test]
    fn test_registered_keys_land_on_the_tool_they_belong_beside() {
        let dir = tempfile::tempdir().unwrap();
        let vault = vault(dir.path());
        // The motivating case: a standalone Cloudflare API token, broader than
        // wrangler's own OAuth login, shown on wrangler's row.
        register(&vault, "cf-api", "cloudflare", Some(10));
        register(&vault, "gh-pat", "github", None);
        register(&vault, "openai-prod", "openai", None);

        let registry = Registry::all(Paths::for_test(dir.path())).with_keys(vault);
        let board = registry.status_all();
        let row = |tool: &str| {
            board
                .iter()
                .find(|s| s.tool == tool)
                .unwrap_or_else(|| panic!("no {tool} row"))
                .clone()
        };

        let wrangler = row("wrangler");
        assert_eq!(wrangler.registered_keys.len(), 1);
        assert_eq!(wrangler.registered_keys[0].id, "cf-api");
        // last4 of "secret-for-cf-api", carried through from the vault.
        assert_eq!(wrangler.registered_keys[0].last4, "-api");
        assert_eq!(
            wrangler.registered_keys[0].expiry_state,
            crate::keys::KeyExpiryState::ExpiringSoon
        );

        assert_eq!(row("gh").registered_keys.len(), 1);
        // An unmapped provider simply does not appear anywhere on the board.
        for status in &board {
            assert!(
                !status.registered_keys.iter().any(|k| k.id == "openai-prod"),
                "an unmapped provider leaked onto {}",
                status.tool
            );
        }
        assert!(row("aws").registered_keys.is_empty());

        // The single-tool path agrees with the board.
        assert_eq!(
            registry.status("wrangler").unwrap().registered_keys.len(),
            1
        );
    }

    #[test]
    fn test_keys_on_a_row_are_sorted_soonest_expiry_first() {
        let dir = tempfile::tempdir().unwrap();
        let vault = vault(dir.path());
        register(&vault, "cf-undated", "cloudflare", None);
        register(&vault, "cf-far", "cf", Some(300));
        register(&vault, "cf-soon", "cloudflare", Some(2));

        let registry = Registry::all(Paths::for_test(dir.path())).with_keys(vault);
        let wrangler = registry.status("wrangler").unwrap();
        let ids: Vec<&str> = wrangler
            .registered_keys
            .iter()
            .map(|k| k.id.as_str())
            .collect();
        assert_eq!(ids, vec!["cf-soon", "cf-far", "cf-undated"]);
        assert_eq!(wrangler.keys_needing_attention().len(), 1);
    }

    #[test]
    fn test_a_board_without_a_vault_has_no_registered_keys() {
        let dir = tempfile::tempdir().unwrap();
        let registry = Registry::all(Paths::for_test(dir.path()));
        for status in registry.status_all() {
            assert!(status.registered_keys.is_empty(), "{}", status.tool);
            assert!(status.notes.iter().all(|n| !n.contains("registered keys")));
        }
    }

    #[test]
    fn test_an_unreadable_vault_notes_itself_but_never_blanks_the_board() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("keys.json");
        std::fs::write(&path, "{ not json").unwrap();
        let vault = KeyRegistry::new(path, Box::new(crate::keystore::MemoryKeystore::new()));

        let registry = Registry::all(Paths::for_test(dir.path())).with_keys(vault);
        let board = registry.status_all();
        assert_eq!(board.len(), 8, "the board must still be complete");
        for status in &board {
            assert!(status.registered_keys.is_empty());
            assert!(
                status
                    .notes
                    .iter()
                    .any(|n| n.contains("registered keys unavailable")),
                "{} lost the explanation",
                status.tool
            );
        }
    }

    #[test]
    fn test_unknown_tool_is_a_clear_error() {
        let dir = tempfile::tempdir().unwrap();
        let registry = Registry::all(Paths::for_test(dir.path()));
        let err = registry.status("nope").unwrap_err().to_string();
        assert!(err.contains("unknown tool"), "{err}");
        assert!(err.contains("gcloud"), "{err}");
    }
}
