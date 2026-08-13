//! The set of probes patchbay knows about, and the entry points the CLI, the
//! MCP server and the app all go through.

use std::collections::HashMap;

use chrono::Utc;

use crate::deprecations;
use crate::keys::KeyRegistry;
use crate::keystore::SecurityCliKeystore;
use crate::paths::Paths;
use crate::probe::Probe;
use crate::probes;
use crate::types::{KeyRef, PermissionsReport, SwitchOutcome, ToolStatus, VerifyOutcome};
use crate::versions::{self, CheckOptions, CheckReport, VersionCache};

pub struct Registry {
    probes: Vec<Box<dyn Probe>>,
    /// The key vault, when one is attached. Optional so `Registry::all` stays
    /// usable in tests without a keystore, and so a machine with no vault is a
    /// normal empty board rather than a special case.
    keys: Option<KeyRegistry>,
    /// Kept so [`Registry::status_all`] can surface problems with patchbay's
    /// own config (see [`Paths::config_warnings`]).
    paths: Paths,
}

impl Registry {
    /// Every probe, bound to the given paths. Grouped by category, matching
    /// the order the panel's sidebar lists them in.
    pub fn all(paths: Paths) -> Self {
        Self {
            probes: vec![
                // cloud
                Box::new(probes::gcloud::GcloudProbe::new(paths.clone())),
                Box::new(probes::aws::AwsProbe::new(paths.clone())),
                Box::new(probes::az::AzProbe::new(paths.clone())),
                Box::new(probes::firebase::FirebaseProbe::new(paths.clone())),
                Box::new(probes::neon::NeonProbe::new(paths.clone())),
                Box::new(probes::supabase::SupabaseProbe::new(paths.clone())),
                Box::new(probes::flyctl::FlyctlProbe::new(paths.clone())),
                Box::new(probes::doctl::DoctlProbe::new(paths.clone())),
                // code
                Box::new(probes::gh::GhProbe::new(paths.clone())),
                Box::new(probes::npm::NpmProbe::new(paths.clone())),
                // secrets
                Box::new(probes::infisical::InfisicalProbe::new(paths.clone())),
                Box::new(probes::op::OpProbe::new(paths.clone())),
                // cluster
                Box::new(probes::kubectl::KubectlProbe::new(paths.clone())),
                // edge
                Box::new(probes::wrangler::WranglerProbe::new(paths.clone())),
                Box::new(probes::vercel::VercelProbe::new(paths.clone())),
                // storage
                Box::new(probes::rclone::RcloneProbe::new(paths.clone())),
                // containers
                Box::new(probes::docker::DockerProbe::new(paths.clone())),
                // network
                Box::new(probes::tailscale::TailscaleProbe::new(paths.clone())),
                Box::new(probes::ssh::SshProbe::new(paths.clone())),
                Box::new(probes::ngrok::NgrokProbe::new(paths.clone())),
                Box::new(probes::cloudflared::CloudflaredProbe::new(paths.clone())),
                // payments
                Box::new(probes::stripe::StripeProbe::new(paths.clone())),
                // ai
                Box::new(probes::ollama::OllamaProbe::new(paths.clone())),
                Box::new(probes::huggingface::HuggingfaceProbe::new(paths.clone())),
                Box::new(probes::claude::ClaudeProbe::new(paths.clone())),
            ],
            keys: None,
            paths,
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

    /// The locations these probes read through. [`crate::migrate`] needs it to
    /// resolve the same files the board was built from.
    pub fn paths(&self) -> &Paths {
        &self.paths
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
        // Likewise the version cache: one file read for all 23 rows. This path
        // never execs and never dials out — a cold cache simply means no
        // version column.
        let versions = VersionCache::load(&self.paths.versions_file());
        let mut all: Vec<ToolStatus> = self
            .probes
            .iter()
            .map(|p| {
                let mut status = p.status().unwrap_or_else(|e| {
                    let mut status = ToolStatus::empty(p.tool(), false);
                    status.note(format!("probe failed: {e}"));
                    status
                });
                linked.attach(&mut status);
                self.attach_versions(&mut status, &versions);
                status
            })
            .collect();

        // A broken patchbay config is about patchbay, not about any one tool,
        // and the data model has no global slot for it. It goes on the first
        // status only — repeating it 23 times would drown the board and, for
        // an agent reading list_connections, cost 23 copies of the same
        // sentence. The message names itself, so it does not read as a
        // complaint about that tool.
        if let Some(first) = all.first_mut() {
            for warning in self.paths.config_warnings() {
                first.note(warning.clone());
            }
        }
        all
    }

    pub fn status(&self, tool: &str) -> anyhow::Result<ToolStatus> {
        let mut status = self.require(tool)?.status()?;
        self.linked_keys().attach(&mut status);
        self.attach_versions(
            &mut status,
            &VersionCache::load(&self.paths.versions_file()),
        );
        Ok(status)
    }

    /// Stamp the cached version info and any curated advisories onto a row.
    ///
    /// Deliberately cheap and deliberately incomplete: it reads the cache and a
    /// static table, and would rather report nothing than execute anything.
    fn attach_versions(&self, status: &mut ToolStatus, cache: &VersionCache) {
        status.version = cache.get(&status.tool).cloned();

        // Advisories are static data, so they do not need the cache to be warm.
        // The `PATH` lookups that feed the context only happen for the handful
        // of tools that actually have a rule.
        if !deprecations::has_rules(&status.tool) {
            return;
        }
        let installed = status.version.as_ref().and_then(|v| v.installed.as_deref());
        let binaries: Vec<&'static str> = versions::spec_for(&status.tool)
            .map(|spec| {
                spec.bins
                    .iter()
                    .copied()
                    .filter(|bin| self.paths.has_binary(bin))
                    .collect()
            })
            .unwrap_or_default();
        let ctx = deprecations::AdvisoryContext::new(installed, &binaries);
        status.advisories = deprecations::advisories_for(&status.tool, &ctx);
    }

    /// TIER 2. Execute every tool's version command and ask its install source
    /// what the current release is, then write the answers to the cache that
    /// [`Registry::status_all`] reads.
    ///
    /// Seconds, not milliseconds: this is the only entry point in patchbay that
    /// both spawns processes and makes outbound requests.
    pub fn check_updates(&self, options: CheckOptions) -> CheckReport {
        let tools = self.tool_names();
        versions::check_updates(&self.paths, &tools, options)
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

    /// Verify one profile of one tool. `None` verifies whatever the tool
    /// treats as active.
    pub fn verify_profile(
        &self,
        tool: &str,
        profile_id: Option<&str>,
    ) -> anyhow::Result<VerifyOutcome> {
        let probe = self.require(tool)?;
        match profile_id {
            Some(id) => probe.verify_profile(id),
            None => probe.verify(),
        }
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
            // What the link does not mean. The probe cannot say this: it never
            // sees the vault.
            if let Some(note) = crate::keys::key_link_note(&status.tool, refs.len()) {
                status.note(note);
            }
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
        assert_eq!(all.len(), 25);
        for status in &all {
            assert!(!status.installed, "{} should look absent", status.tool);
            assert!(
                status.profiles.is_empty(),
                "{} leaked profiles",
                status.tool
            );
            assert!(
                status.notes.is_empty(),
                "{} is noisy on a machine that has nothing: {:?}",
                status.tool,
                status.notes
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

    /// A second handle on the same vault file, for a test that reopens it.
    fn vault_at(dir: &std::path::Path) -> KeyRegistry {
        vault(dir)
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
    fn test_a_registered_cloudflare_token_warns_that_wrangler_oauth_is_not_it() {
        let dir = tempfile::tempdir().unwrap();
        let vault = vault(dir.path());
        register(&vault, "cf-api", "cloudflare", None);

        let registry = Registry::all(Paths::for_test(dir.path())).with_keys(vault);
        let board = registry.status_all();
        let wrangler = board.iter().find(|s| s.tool == "wrangler").unwrap();

        let note = wrangler
            .notes
            .iter()
            .find(|n| n.contains("different credential"))
            .unwrap_or_else(|| panic!("no caveat on the wrangler row: {:?}", wrangler.notes));
        assert!(note.contains("wrangler logout"), "{note}");
        assert!(note.contains("pb key verify"), "{note}");
        assert!(
            note.starts_with("1 standalone Cloudflare API token is"),
            "{note}"
        );

        // Singular and plural both read correctly.
        register(&vault_at(dir.path()), "cf-api-2", "cf", None);
        let registry = Registry::all(Paths::for_test(dir.path())).with_keys(vault_at(dir.path()));
        let board = registry.status_all();
        let wrangler = board.iter().find(|s| s.tool == "wrangler").unwrap();
        assert!(
            wrangler
                .notes
                .iter()
                .any(|n| n.starts_with("2 standalone Cloudflare API tokens are")),
            "{:?}",
            wrangler.notes
        );

        // A tool with no registered keys gains no note.
        let gh = board.iter().find(|s| s.tool == "gh").unwrap();
        assert!(!gh.notes.iter().any(|n| n.contains("different credential")));
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
        let expected = registry.tool_names().len();
        let board = registry.status_all();
        assert_eq!(board.len(), expected, "the board must still be complete");
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
    fn test_tool_keys_are_unique() {
        let dir = tempfile::tempdir().unwrap();
        let registry = Registry::all(Paths::for_test(dir.path()));
        let mut names = registry.tool_names();
        names.sort_unstable();
        let count = names.len();
        names.dedup();
        assert_eq!(names.len(), count, "duplicate tool key in the registry");
    }

    #[test]
    fn test_every_tool_is_categorised() {
        let dir = tempfile::tempdir().unwrap();
        let registry = Registry::all(Paths::for_test(dir.path()));
        for status in registry.status_all() {
            assert_ne!(
                status.category,
                crate::types::ToolCategory::Other,
                "{} has no category",
                status.tool
            );
        }
    }

    #[test]
    fn test_a_broken_patchbay_config_is_reported_on_the_board() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join(".config/patchbay")).unwrap();
        std::fs::write(
            dir.path().join(".config/patchbay/config.toml"),
            "[paths]\nnot_a_tool = \"/x\"\n",
        )
        .unwrap();
        let registry = Registry::all(Paths::for_test(dir.path()).load_config());
        let all = registry.status_all();
        assert!(all[0]
            .notes
            .iter()
            .any(|n| n.contains("patchbay config: unknown key `not_a_tool`")));
        // Once, not once per tool.
        let carriers = all
            .iter()
            .filter(|s| s.notes.iter().any(|n| n.contains("unknown key")))
            .count();
        assert_eq!(carriers, 1);
    }

    // --- versions and advisories on the board -------------------------------

    fn write_versions(paths: &Paths, entries: &[(&str, &str, Option<&str>)]) {
        let mut cache = crate::versions::VersionCache::default();
        for (tool, installed, latest) in entries {
            let mut info = crate::versions::VersionInfo {
                tool: tool.to_string(),
                installed: Some(installed.to_string()),
                latest: latest.map(String::from),
                source: crate::versions::Source::Homebrew,
                update_command: Some(format!("brew upgrade {tool}")),
                checked_at: Utc::now(),
                note: None,
            };
            info.note = None;
            cache.put(info);
        }
        cache.save(&paths.versions_file()).unwrap();
    }

    #[test]
    fn test_a_cold_cache_means_no_version_info_and_never_a_delay() {
        let dir = tempfile::tempdir().unwrap();
        let registry = Registry::all(Paths::for_test(dir.path()));
        for status in registry.status_all() {
            assert!(
                status.version.is_none(),
                "{} invented version info from nothing",
                status.tool
            );
            assert!(!status.update_available());
        }
    }

    #[test]
    fn test_the_board_reads_whatever_the_version_cache_holds() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::for_test(dir.path());
        write_versions(
            &paths,
            &[
                ("gh", "2.95.0", Some("2.97.0")),
                ("rclone", "1.73.5", Some("1.73.5")),
                ("docker", "28.3.2", None),
            ],
        );

        let board = Registry::all(paths).status_all();
        let row = |tool: &str| board.iter().find(|s| s.tool == tool).unwrap();

        let gh = row("gh");
        assert!(gh.update_available());
        assert_eq!(
            gh.version.as_ref().unwrap().marker().as_deref(),
            Some("2.95.0 → 2.97.0")
        );
        // Current: version shown, no update claimed.
        assert!(!row("rclone").update_available());
        // Unknown latest is never reported as an update.
        assert!(!row("docker").update_available());
        // A tool with nothing cached simply has nothing.
        assert!(row("kubectl").version.is_none());
    }

    #[test]
    fn test_advisories_reach_the_board_from_static_data_alone() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::for_test(dir.path());
        // Only the version is needed for a version-gated advisory — no exec,
        // no network, and no PATH lookups (which are disabled in tests).
        write_versions(&paths, &[("aws", "1.29.0", None), ("op", "2.30.0", None)]);

        let board = Registry::all(paths).status_all();
        let row = |tool: &str| board.iter().find(|s| s.tool == tool).unwrap();

        let aws = row("aws");
        assert_eq!(aws.advisories.len(), 1, "AWS CLI v1 is in maintenance mode");
        assert_eq!(aws.blocking_advisories().len(), 1);
        assert!(aws.advisories[0].message.contains("v2"));
        assert!(aws.advisories[0].url.is_some(), "every advisory is sourced");

        // v2 of the 1Password CLI has nothing to answer for.
        assert!(row("op").advisories.is_empty());
        // Neither does a tool with no rules at all.
        assert!(row("gh").advisories.is_empty());
    }

    #[test]
    fn test_version_and_advisories_survive_the_json_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::for_test(dir.path());
        write_versions(&paths, &[("aws", "1.29.0", Some("2.32.6"))]);

        let board = Registry::all(paths).status_all();
        let aws = board.iter().find(|s| s.tool == "aws").unwrap();

        let json = serde_json::to_value(aws).unwrap();
        assert_eq!(json["version"]["installed"], "1.29.0");
        // The wire name is the full `homebrew`; `brew` is only the short label
        // the terminal column uses.
        assert_eq!(json["version"]["source"], "homebrew");
        assert_eq!(json["advisories"][0]["kind"]["type"], "unmaintained");
        // The derived field is still there, and still not an input.
        assert_eq!(json["connection_state"], "not_installed");

        let back: ToolStatus = serde_json::from_value(json).unwrap();
        assert_eq!(&back, aws);
    }

    #[test]
    fn test_json_written_before_versions_existed_still_reads() {
        let legacy = serde_json::json!({
            "tool": "gh", "installed": true, "profiles": [], "active": null,
            "notes": [], "category": "code", "registered_keys": []
        });
        let back: ToolStatus = serde_json::from_value(legacy).unwrap();
        assert!(back.version.is_none());
        assert!(back.advisories.is_empty());
    }

    #[test]
    fn test_a_corrupt_version_cache_never_blanks_the_board() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::for_test(dir.path());
        std::fs::create_dir_all(paths.patchbay_dir()).unwrap();
        std::fs::write(paths.versions_file(), "{ not json").unwrap();

        let registry = Registry::all(paths);
        let expected = registry.tool_names().len();
        let board = registry.status_all();
        assert_eq!(board.len(), expected);
        for status in &board {
            assert!(status.version.is_none());
            assert!(status.notes.is_empty(), "{} got noisy", status.tool);
        }
    }

    #[test]
    fn test_the_single_tool_path_agrees_with_the_board() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::for_test(dir.path());
        write_versions(&paths, &[("gh", "2.95.0", Some("2.97.0"))]);

        let registry = Registry::all(paths);
        let one = registry.status("gh").unwrap();
        let board = registry.status_all();
        let from_board = board.iter().find(|s| s.tool == "gh").unwrap();
        assert_eq!(&one, from_board);
        assert!(one.update_available());
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
