//! `pb import` — put a bundle back onto a machine.
//!
//! # Where the plaintext lives
//!
//! In memory, and nowhere else. [`super::bundle::read`] returns a decrypted
//! [`Payload`]; each file goes straight from that value to its destination
//! through [`crate::util::write_atomic`], whose temp file is created *in the
//! destination directory* and renamed over the target. There is no staging
//! directory, so there is no window in which every credential on the machine
//! sits unencrypted in `/tmp` waiting for a crash to leave it there.
//!
//! # Never clobber silently
//!
//! Every destination that already exists is copied to `<path>.patchbay-bak`
//! before it is replaced — the same rolling backup [`crate::mcp_clients`] uses,
//! from the same helper. `--dry-run` ([`ImportOptions::dry_run`]) prints the
//! whole plan and writes nothing at all, backups included.
//!
//! # Idempotent
//!
//! A destination whose bytes already match the bundle is left alone entirely:
//! no write, no backup, and [`FileOutcome::Unchanged`] in the report. So the
//! second run of an import is a no-op that says so, which is what makes it safe
//! to re-run after fixing one item in the plan.
//!
//! # The one thing that is never replaced
//!
//! An env vault project ([`crate::envs`]) that already exists here is skipped
//! rather than overwritten, with a note naming it — see
//! [`Importer::restore_env_projects`]. Files get a backup and can be put back;
//! a project entry that lost its sync pin to a stale copy cannot.

use std::path::PathBuf;

use super::bundle::{BundleMcpServer, Payload};
use super::manifest::SetupItem;
use super::plan;
use super::policy::Location;
use crate::envs::EnvRegistry;
use crate::keys::{KeyRegistry, NewKey};
use crate::mcp_clients::{McpClientRegistry, ServerSpec, TransportSpec};
use crate::paths::Paths;
use crate::registry::Registry;
use crate::util::{backup, backup_path};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ImportOptions {
    /// Print the plan, change nothing.
    pub dry_run: bool,
}

/// What happened, or would happen, to one destination.
#[derive(Debug, Clone, PartialEq)]
pub enum FileOutcome {
    /// Nothing was there.
    Created,
    /// Something was there, and it was different. `backup` is where the old
    /// copy went (`None` in a dry run, where nothing is written).
    Replaced { backup: Option<PathBuf> },
    /// Already byte-identical. Not written, not backed up.
    Unchanged,
    /// patchbay would not write it. `reason` says why.
    Skipped { reason: String },
}

impl FileOutcome {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Created => "create",
            Self::Replaced { .. } => "replace",
            Self::Unchanged => "unchanged",
            Self::Skipped { .. } => "skip",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct FileResult {
    pub tool: String,
    pub location: Location,
    pub rel: String,
    pub path: PathBuf,
    pub outcome: FileOutcome,
}

#[derive(Debug, Clone, PartialEq)]
pub struct KeyResult {
    pub id: String,
    pub outcome: FileOutcome,
}

#[derive(Debug, Clone, PartialEq)]
pub struct McpResult {
    pub client: String,
    pub name: String,
    pub outcome: FileOutcome,
    /// Names — never values — of what the registration carries.
    pub values_carried: Vec<String>,
}

/// One env vault project the bundle carried.
#[derive(Debug, Clone, PartialEq)]
pub struct EnvProjectResult {
    pub id: String,
    pub outcome: FileOutcome,
}

/// Everything an import did, or would do.
#[derive(Debug, Clone, PartialEq)]
pub struct ImportReport {
    pub dry_run: bool,
    pub files: Vec<FileResult>,
    pub keys: Vec<KeyResult>,
    pub mcp: Vec<McpResult>,
    pub env_projects: Vec<EnvProjectResult>,
    /// The gap list, re-evaluated against this machine after the restore.
    pub remaining: Vec<SetupItem>,
    pub notes: Vec<String>,
}

impl ImportReport {
    pub fn written(&self) -> usize {
        self.files
            .iter()
            .filter(|f| {
                matches!(
                    f.outcome,
                    FileOutcome::Created | FileOutcome::Replaced { .. }
                )
            })
            .count()
    }

    pub fn open_items(&self) -> impl Iterator<Item = &SetupItem> {
        self.remaining.iter().filter(|i| i.is_open())
    }
}

/// Everything an import writes to.
pub struct Importer<'a> {
    pub paths: &'a Paths,
    pub registry: &'a Registry,
    pub vault: &'a KeyRegistry,
    pub clients: &'a McpClientRegistry,
    pub envs: &'a EnvRegistry,
}

impl Importer<'_> {
    pub fn run(&self, payload: &Payload, options: &ImportOptions) -> anyhow::Result<ImportReport> {
        let mut report = ImportReport {
            dry_run: options.dry_run,
            files: Vec::new(),
            keys: Vec::new(),
            mcp: Vec::new(),
            env_projects: Vec::new(),
            remaining: Vec::new(),
            notes: Vec::new(),
        };

        self.restore_files(payload, options, &mut report)?;
        self.restore_keys(payload, options, &mut report);
        self.restore_mcp(payload, options, &mut report);
        self.restore_env_projects(payload, options, &mut report);

        // The gaps are recomputed here rather than copied out of the manifest:
        // the manifest's list is what the *source* predicted, and by now some
        // of it may already be true on this machine.
        report.remaining = plan::plan(
            self.paths,
            self.registry,
            self.vault,
            self.clients,
            self.envs,
            Some(&payload.manifest),
        );
        Ok(report)
    }

    fn restore_files(
        &self,
        payload: &Payload,
        options: &ImportOptions,
        report: &mut ImportReport,
    ) -> anyhow::Result<()> {
        let mut kube_landed: Vec<String> = Vec::new();

        for file in &payload.files {
            let bytes = file.decode()?;
            let path = file.location.destination(self.paths, &file.rel);

            if file.location == Location::KubeConfigs {
                kube_landed.push(file.rel.clone());
            }

            let existing = std::fs::read(&path).ok();
            let outcome = match existing {
                Some(current) if current == bytes => FileOutcome::Unchanged,
                Some(_) if options.dry_run => FileOutcome::Replaced {
                    backup: Some(backup_path(&path)),
                },
                Some(_) => {
                    let saved = backup(&path)?;
                    self.write(&path, &bytes, file.mode)?;
                    FileOutcome::Replaced { backup: saved }
                }
                None if options.dry_run => FileOutcome::Created,
                None => {
                    self.write(&path, &bytes, file.mode)?;
                    FileOutcome::Created
                }
            };

            report.files.push(FileResult {
                tool: file.tool.clone(),
                location: file.location,
                rel: file.rel.clone(),
                path,
                outcome,
            });
        }

        // The one restore that cannot be complete on its own: kubectl merges
        // the files `KUBECONFIG` names, and this machine's variable is its own
        // business.
        if kube_landed.len() > 1 {
            let dir = Location::KubeConfigs.destination(self.paths, "");
            report.notes.push(format!(
                "{} kubeconfigs were restored into {}; kubectl only merges the files KUBECONFIG \
                 names, so set it (export KUBECONFIG={}) or `pb plan` will keep showing the \
                 contexts as missing",
                kube_landed.len(),
                dir.display(),
                kube_landed
                    .iter()
                    .map(|rel| dir.join(rel).display().to_string())
                    .collect::<Vec<_>>()
                    .join(":")
            ));
        }
        Ok(())
    }

    fn write(&self, path: &std::path::Path, bytes: &[u8], mode: u32) -> anyhow::Result<()> {
        // `write_atomic` takes text; credential stores are binary (gcloud's
        // SQLite), so the same three steps are done here over bytes.
        let dir = path
            .parent()
            .ok_or_else(|| anyhow::anyhow!("{} has no parent directory", path.display()))?;
        std::fs::create_dir_all(dir)
            .map_err(|e| anyhow::anyhow!("could not create {}: {e}", dir.display()))?;
        let name = path
            .file_name()
            .ok_or_else(|| anyhow::anyhow!("{} has no file name", path.display()))?
            .to_string_lossy()
            .into_owned();
        let tmp = dir.join(format!(".{name}.patchbay-tmp"));
        std::fs::write(&tmp, bytes)
            .map_err(|e| anyhow::anyhow!("could not write {}: {e}", tmp.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            // The source machine's mode, so a 0600 credentials file stays 0600
            // — and a 0644 one does not become 0600 and confuse its tool.
            std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(mode))
                .map_err(|e| anyhow::anyhow!("could not chmod {}: {e}", tmp.display()))?;
        }
        #[cfg(not(unix))]
        let _ = mode;
        std::fs::rename(&tmp, path).map_err(|e| {
            let _ = std::fs::remove_file(&tmp);
            anyhow::anyhow!("could not replace {}: {e}", path.display())
        })
    }

    fn restore_keys(&self, payload: &Payload, options: &ImportOptions, report: &mut ImportReport) {
        for secret in &payload.secrets {
            let meta = payload.manifest.keys.iter().find(|k| k.id == secret.id);
            // Same id, same last 4: already here. Compared on metadata rather
            // than by reading the keychain back, so an import does not trigger
            // an unlock prompt per key just to decide it has nothing to do.
            let existing = self.vault.get(&secret.id).ok().flatten();
            let unchanged = matches!(
                (&existing, meta),
                (Some(e), Some(m)) if e.last4 == m.last4 && e.provider == m.provider
            );

            let outcome = if unchanged {
                FileOutcome::Unchanged
            } else if options.dry_run {
                match existing {
                    Some(_) => FileOutcome::Replaced { backup: None },
                    None => FileOutcome::Created,
                }
            } else {
                let mut new = NewKey::new(&secret.id, "import");
                if let Some(meta) = meta {
                    new = new
                        .provider(&meta.provider)
                        .label(&meta.label)
                        .purpose(meta.purpose.clone())
                        .scopes(meta.scopes.clone())
                        .expires_at(meta.expires_at);
                }
                let replaced = existing.is_some();
                match self.vault.add(new, &secret.secret, true) {
                    Ok(_) if replaced => FileOutcome::Replaced { backup: None },
                    Ok(_) => FileOutcome::Created,
                    // A keychain that refuses one key must not abort the rest
                    // of the import; the error names the id, never the value.
                    Err(e) => FileOutcome::Skipped {
                        reason: format!("{e:#}"),
                    },
                }
            };
            report.keys.push(KeyResult {
                id: secret.id.clone(),
                outcome,
            });
        }
    }

    fn restore_mcp(&self, payload: &Payload, options: &ImportOptions, report: &mut ImportReport) {
        for server in &payload.mcp {
            let spec = to_spec(server);
            let values: Vec<String> = spec
                .env_keys()
                .into_iter()
                .chain(spec.header_keys())
                .collect();
            let current = self.clients.read_spec(&server.client, &server.name).ok();

            let outcome = if current.as_ref() == Some(&spec) {
                FileOutcome::Unchanged
            } else if options.dry_run {
                match current {
                    Some(_) => FileOutcome::Replaced {
                        backup: self
                            .clients
                            .config_path_of(&server.client)
                            .ok()
                            .map(|p| backup_path(&p)),
                    },
                    None => FileOutcome::Created,
                }
            } else {
                let replaced = current.is_some();
                // `overwrite: true` is right here and only here: the user asked
                // for this machine to look like the other one.
                match self
                    .clients
                    .add_server(&server.client, &server.name, &spec, true)
                {
                    Ok(write) if replaced => FileOutcome::Replaced {
                        backup: write.backup_path,
                    },
                    Ok(_) => FileOutcome::Created,
                    Err(e) => FileOutcome::Skipped {
                        reason: format!("{e:#}"),
                    },
                }
            };
            report.mcp.push(McpResult {
                client: server.client.clone(),
                name: server.name.clone(),
                outcome,
                values_carried: values,
            });
        }
        if !report.mcp.is_empty() {
            report.notes.push(
                "MCP clients read their config at startup; restart the ones above before the \
                 restored servers appear"
                    .to_string(),
            );
        }
    }

    /// Register the env vault projects the bundle carried, through
    /// [`EnvRegistry::adopt`].
    ///
    /// **A project id this machine already has is skipped, by name.** The
    /// destination may well be the newer of the two machines — it may have
    /// pulled since the bundle was written, or been re-linked to a different
    /// remote — and an import that overwrote its entry would replace a live
    /// sync pin with a stale one, silently. Skipping is recoverable (`pb env
    /// forget` then re-import); overwriting is not.
    ///
    /// Neither `attachments.json` nor the keychain is touched. The values come
    /// back from `pb env pull`, and which directories here belong to a project
    /// is this machine's own business — see the plan items in [`super::plan`].
    fn restore_env_projects(
        &self,
        payload: &Payload,
        options: &ImportOptions,
        report: &mut ImportReport,
    ) {
        for project in &payload.env_projects {
            let existing = self.envs.get(&project.id).ok().flatten();
            let outcome = match (existing, options.dry_run) {
                (Some(_), _) => {
                    report.notes.push(format!(
                        "env project `{}` is already registered here and was left exactly as it \
                         is; the bundle's copy was not applied (`pb env projects` shows what this \
                         machine has)",
                        project.id
                    ));
                    FileOutcome::Skipped {
                        reason: "already registered on this machine".to_string(),
                    }
                }
                (None, true) => FileOutcome::Created,
                (None, false) => match self.envs.adopt(project) {
                    Ok(_) => FileOutcome::Created,
                    // One unusable entry must not abort the rest of the import.
                    Err(e) => FileOutcome::Skipped {
                        reason: format!("{e:#}"),
                    },
                },
            };
            report.env_projects.push(EnvProjectResult {
                id: project.id.clone(),
                outcome,
            });
        }
        if report
            .env_projects
            .iter()
            .any(|p| p.outcome == FileOutcome::Created)
        {
            report.notes.push(
                "env projects arrived as metadata only — no variable value is ever in a bundle. \
                 Run `pb env pull --project <id>` for each linked project to rebuild its synced \
                 layer, and `pb env attach <id>` in the directories that belong to them"
                    .to_string(),
            );
        }
    }
}

fn to_spec(server: &BundleMcpServer) -> ServerSpec {
    let transport = match server.transport.as_str() {
        "http" => TransportSpec::Http {
            url: server.url.clone().unwrap_or_default(),
        },
        "sse" => TransportSpec::Sse {
            url: server.url.clone().unwrap_or_default(),
        },
        _ => TransportSpec::Stdio {
            command: server.command.clone().unwrap_or_default(),
            args: server.args.clone(),
        },
    };
    ServerSpec {
        transport,
        env: server.env.clone(),
        headers: server.headers.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keystore::MemoryKeystore;
    use crate::migrate::export::{Exporter, KeySelection};
    use chrono::Utc;
    use std::fs;

    struct Machine {
        _dir: tempfile::TempDir,
        home: PathBuf,
        paths: Paths,
        registry: Registry,
        vault: KeyRegistry,
        clients: McpClientRegistry,
        envs: EnvRegistry,
    }

    impl Machine {
        fn new(files: &[(&str, &str)]) -> Self {
            let dir = tempfile::tempdir().unwrap();
            for (rel, body) in files {
                let path = dir.path().join(rel);
                fs::create_dir_all(path.parent().unwrap()).unwrap();
                fs::write(&path, body).unwrap();
            }
            let home = dir.path().to_path_buf();
            let paths = Paths::for_test(&home);
            Self {
                registry: Registry::all(paths.clone()),
                vault: KeyRegistry::new(home.join("keys.json"), Box::new(MemoryKeystore::new())),
                clients: McpClientRegistry::with_paths(paths.clone()),
                envs: EnvRegistry::new(
                    home.join("projects.json"),
                    home.join("attachments.json"),
                    Box::new(MemoryKeystore::new()),
                ),
                paths,
                home,
                _dir: dir,
            }
        }

        fn payload(&self, keys: KeySelection) -> Payload {
            Exporter {
                paths: &self.paths,
                registry: &self.registry,
                vault: &self.vault,
                clients: &self.clients,
                envs: &self.envs,
            }
            .payload(&keys, Utc::now())
            .unwrap()
        }

        fn import(&self, payload: &Payload, dry_run: bool) -> ImportReport {
            Importer {
                paths: &self.paths,
                registry: &self.registry,
                vault: &self.vault,
                clients: &self.clients,
                envs: &self.envs,
            }
            .run(payload, &ImportOptions { dry_run })
            .unwrap()
        }

        fn read(&self, rel: &str) -> String {
            fs::read_to_string(self.home.join(rel)).unwrap()
        }

        fn exists(&self, rel: &str) -> bool {
            self.home.join(rel).exists()
        }
    }

    fn source_files() -> Vec<(&'static str, &'static str)> {
        vec![
            (".aws/config", "[default]\nregion = eu-west-1\n"),
            (
                ".aws/credentials",
                "[default]\naws_access_key_id = AKIAOLD\n",
            ),
            (".config/gcloud/credentials.db", "SQLite format 3 fake"),
            (".config/gcloud/active_config", "work"),
            (".npmrc", "//registry.npmjs.org/:_authToken=npm_OLD\n"),
            (".ssh/config", "Host prod\n  HostName 10.0.0.1\n"),
        ]
    }

    #[test]
    fn test_round_trip_into_a_second_empty_machine() {
        let source = Machine::new(&source_files());
        let dest = Machine::new(&[]);
        let payload = source.payload(KeySelection::None);

        let report = dest.import(&payload, false);
        assert!(report.written() >= 6, "{report:?}");
        assert!(report
            .files
            .iter()
            .all(|f| matches!(f.outcome, FileOutcome::Created)));

        // Byte-for-byte, in the destination's own resolved locations.
        for (rel, body) in source_files() {
            assert_eq!(dest.read(rel), body, "{rel}");
        }
    }

    #[test]
    fn test_a_second_import_changes_nothing_and_says_so() {
        let source = Machine::new(&source_files());
        let dest = Machine::new(&[]);
        let payload = source.payload(KeySelection::None);

        dest.import(&payload, false);
        let again = dest.import(&payload, false);

        assert_eq!(again.written(), 0);
        assert!(again
            .files
            .iter()
            .all(|f| f.outcome == FileOutcome::Unchanged));
        // Idempotent means no backups either: nothing was replaced.
        assert!(!dest.exists(".aws/config.patchbay-bak"));
        for (rel, body) in source_files() {
            assert_eq!(dest.read(rel), body, "{rel}");
        }
    }

    #[test]
    fn test_an_existing_destination_is_backed_up_never_clobbered() {
        let source = Machine::new(&source_files());
        let dest = Machine::new(&[(
            ".aws/credentials",
            "[default]\naws_access_key_id = KEEPME\n",
        )]);
        let payload = source.payload(KeySelection::None);

        let report = dest.import(&payload, false);
        let creds = report
            .files
            .iter()
            .find(|f| f.rel == "credentials")
            .unwrap();
        match &creds.outcome {
            FileOutcome::Replaced { backup } => {
                let backup = backup.as_ref().expect("a replace must leave a backup");
                assert_eq!(
                    fs::read_to_string(backup).unwrap(),
                    "[default]\naws_access_key_id = KEEPME\n"
                );
            }
            other => panic!("expected a replace, got {other:?}"),
        }
        assert_eq!(
            dest.read(".aws/credentials"),
            "[default]\naws_access_key_id = AKIAOLD\n"
        );
    }

    #[test]
    fn test_dry_run_writes_absolutely_nothing() {
        let source = Machine::new(&source_files());
        let dest = Machine::new(&[(
            ".aws/credentials",
            "[default]\naws_access_key_id = KEEPME\n",
        )]);
        let payload = source.payload(KeySelection::All);

        let before: Vec<PathBuf> = walk(&dest.home);
        let report = dest.import(&payload, true);

        assert!(report.dry_run);
        assert!(report.written() > 0, "the plan should still be populated");
        assert!(report
            .files
            .iter()
            .any(|f| matches!(f.outcome, FileOutcome::Replaced { .. })));
        assert_eq!(walk(&dest.home), before, "a dry run touched the filesystem");
        assert_eq!(
            dest.read(".aws/credentials"),
            "[default]\naws_access_key_id = KEEPME\n"
        );
        assert!(!dest.exists(".aws/credentials.patchbay-bak"));
    }

    fn walk(root: &std::path::Path) -> Vec<PathBuf> {
        let mut out = Vec::new();
        let mut stack = vec![root.to_path_buf()];
        while let Some(dir) = stack.pop() {
            let Ok(entries) = fs::read_dir(&dir) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                } else {
                    out.push(path);
                }
            }
        }
        out.sort();
        out
    }

    #[test]
    fn test_vault_secrets_land_in_the_destination_keystore() {
        let source = Machine::new(&[]);
        source
            .vault
            .add(
                NewKey::new("cf-api", "cli")
                    .provider("cloudflare")
                    .label("CF deploy"),
                "cf-secret-1234",
                false,
            )
            .unwrap();
        let payload = source.payload(KeySelection::All);

        let dest = Machine::new(&[]);
        let report = dest.import(&payload, false);
        assert_eq!(report.keys.len(), 1);
        assert_eq!(report.keys[0].outcome, FileOutcome::Created);
        assert_eq!(dest.vault.get_secret("cf-api").unwrap(), "cf-secret-1234");
        let entry = dest.vault.get("cf-api").unwrap().unwrap();
        assert_eq!(entry.provider, "cloudflare");
        assert_eq!(entry.label, "CF deploy");

        // Second run: recognised as already there, no keychain write.
        let again = dest.import(&payload, false);
        assert_eq!(again.keys[0].outcome, FileOutcome::Unchanged);
    }

    #[test]
    fn test_without_keys_nothing_reaches_the_destination_vault() {
        let source = Machine::new(&[]);
        source
            .vault
            .add(
                NewKey::new("cf-api", "cli").provider("cloudflare"),
                "cf-secret-1234",
                false,
            )
            .unwrap();
        let payload = source.payload(KeySelection::None);

        let dest = Machine::new(&[]);
        let report = dest.import(&payload, false);
        assert!(report.keys.is_empty());
        assert!(dest.vault.list().unwrap().is_empty());
        // …but the user is told the key exists and how to re-create it.
        let gap = report
            .remaining
            .iter()
            .find(|i| i.id == "key:cf-api")
            .expect("a key that did not travel must be on the plan");
        assert!(gap.command.contains("pb key add cf-api"), "{gap:?}");
    }

    #[test]
    fn test_mcp_registrations_are_restored_through_the_client_writer() {
        let source = Machine::new(&[(
            ".cursor/mcp.json",
            r#"{"mcpServers":{"grafana":{"command":"uvx","args":["mcp-grafana"],"env":{"GRAFANA_TOKEN":"glsa_x"}}}}"#,
        )]);
        let payload = source.payload(KeySelection::None);

        let dest = Machine::new(&[]);
        let report = dest.import(&payload, false);
        assert_eq!(report.mcp.len(), 1);
        assert_eq!(report.mcp[0].outcome, FileOutcome::Created);
        assert_eq!(report.mcp[0].values_carried, vec!["GRAFANA_TOKEN"]);
        let written = dest.read(".cursor/mcp.json");
        assert!(written.contains("mcp-grafana"), "{written}");
        assert!(report.notes.iter().any(|n| n.contains("restart")));

        // Idempotent through the client writer too.
        let again = dest.import(&payload, false);
        assert_eq!(again.mcp[0].outcome, FileOutcome::Unchanged);
    }

    #[test]
    fn test_env_projects_round_trip_without_their_values() {
        let source = Machine::new(&[]);
        let attached = source.home.join("repos/pathors");
        let pulled = crate::migrate::export::tests::seed_env_vault(&source.envs, &attached);
        let payload = source.payload(KeySelection::None);

        let dest = Machine::new(&[]);
        let report = dest.import(&payload, false);
        assert_eq!(report.env_projects.len(), 2);
        assert!(report
            .env_projects
            .iter()
            .all(|p| p.outcome == FileOutcome::Created));

        let landed = dest.envs.get("pathors").unwrap().unwrap();
        assert_eq!(landed.default_env, "dev");
        let dev = landed.env("dev").unwrap();
        assert_eq!(dev.synced_names, vec!["DATABASE_URL"]);
        assert_eq!(dev.synced_at, Some(pulled));
        // The local layer did not travel, in either half: no names…
        assert!(dev.local_names.is_empty(), "{dev:?}");
        // …and no values, in either layer. `merged` reads the keychain.
        assert!(dest.envs.merged("pathors", "dev").unwrap().vars.is_empty());
        // The pin survived, so a pull here knows where and as whom.
        let sync = landed.sync.as_ref().unwrap();
        assert_eq!(sync.project_id, "9f2c-uuid");
        assert_eq!(sync.account, "me@work.com");

        // Nothing on this machine is attached to it: paths are machine-local.
        assert!(dest.envs.attachments().unwrap().is_empty());
        assert!(!dest.exists("attachments.json"));
        assert!(report.notes.iter().any(|n| n.contains("pb env pull")));
    }

    #[test]
    fn test_a_project_that_already_exists_here_is_never_overwritten() {
        let source = Machine::new(&[]);
        crate::migrate::export::tests::seed_env_vault(
            &source.envs,
            &source.home.join("repos/pathors"),
        );
        let payload = source.payload(KeySelection::None);

        // The destination has its own `pathors`, linked somewhere else — it may
        // well be the newer machine.
        let dest = Machine::new(&[]);
        dest.envs.register("pathors", "staging").unwrap();
        dest.envs
            .set_sync(
                "pathors",
                crate::envs::SyncConfig {
                    provider: "infisical".into(),
                    project_id: "newer-uuid".into(),
                    account: "me@home.com".into(),
                    domain: None,
                    env_map: Default::default(),
                    secret_path: crate::envs::DEFAULT_SECRET_PATH.into(),
                },
            )
            .unwrap();
        let before = dest.envs.get("pathors").unwrap().unwrap();

        let report = dest.import(&payload, false);
        let skipped = report
            .env_projects
            .iter()
            .find(|p| p.id == "pathors")
            .unwrap();
        assert!(
            matches!(&skipped.outcome, FileOutcome::Skipped { reason } if reason.contains("already")),
            "{skipped:?}"
        );
        assert_eq!(dest.envs.get("pathors").unwrap().unwrap(), before);
        assert!(
            report.notes.iter().any(|n| n.contains("`pathors`")),
            "the skip has to be named: {:?}",
            report.notes
        );
        // The other one still landed: one skip is not an aborted import.
        assert!(dest.envs.get("legacy").unwrap().is_some());
    }

    #[test]
    fn test_a_dry_run_registers_no_project() {
        let source = Machine::new(&[]);
        crate::migrate::export::tests::seed_env_vault(
            &source.envs,
            &source.home.join("repos/pathors"),
        );
        let payload = source.payload(KeySelection::None);

        let dest = Machine::new(&[]);
        let report = dest.import(&payload, true);
        assert_eq!(report.env_projects.len(), 2);
        assert!(dest.envs.projects().unwrap().is_empty());
    }

    /// A bundle written before the env vault existed has no `env_projects` key
    /// at all. Serde's default fills it in, and the import is otherwise
    /// unchanged — which is why this section did not cost a `BUNDLE_VERSION`.
    #[test]
    fn test_a_bundle_from_before_the_env_vault_still_imports() {
        let source = Machine::new(&source_files());
        let payload = source.payload(KeySelection::None);

        let mut json = serde_json::to_value(&payload).unwrap();
        json.as_object_mut().unwrap().remove("env_projects");
        assert!(json.get("env_projects").is_none());
        let old: Payload = serde_json::from_value(json).unwrap();
        assert!(old.env_projects.is_empty());

        let dest = Machine::new(&[]);
        let report = dest.import(&old, false);
        assert!(report.env_projects.is_empty());
        assert!(report.written() >= 6, "{report:?}");
        for (rel, body) in source_files() {
            assert_eq!(dest.read(rel), body, "{rel}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn test_the_source_mode_travels_with_the_file() {
        use std::os::unix::fs::PermissionsExt;
        let source = Machine::new(&source_files());
        fs::set_permissions(
            source.home.join(".aws/credentials"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        let payload = source.payload(KeySelection::None);

        let dest = Machine::new(&[]);
        dest.import(&payload, false);
        let mode = fs::metadata(dest.home.join(".aws/credentials"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "mode was {:o}", mode & 0o777);
        // No stray temp files from the atomic write.
        assert!(!walk(&dest.home)
            .iter()
            .any(|p| p.to_string_lossy().contains("patchbay-tmp")));
    }

    #[test]
    fn test_a_destination_override_decides_where_a_file_lands() {
        let source = Machine::new(&source_files());
        let payload = source.payload(KeySelection::None);

        // The destination reads its AWS credentials from somewhere else.
        let dir = tempfile::tempdir().unwrap();
        let moved = dir.path().join("work/creds");
        let dest_home = tempfile::tempdir().unwrap();
        let paths = Paths::for_test(dest_home.path())
            .with_env("AWS_SHARED_CREDENTIALS_FILE", &moved.display().to_string());
        let registry = Registry::all(paths.clone());
        let vault = KeyRegistry::new(
            dest_home.path().join("keys.json"),
            Box::new(MemoryKeystore::new()),
        );
        let clients = McpClientRegistry::with_paths(paths.clone());
        let envs = EnvRegistry::new(
            dest_home.path().join("projects.json"),
            dest_home.path().join("attachments.json"),
            Box::new(MemoryKeystore::new()),
        );

        Importer {
            paths: &paths,
            registry: &registry,
            vault: &vault,
            clients: &clients,
            envs: &envs,
        }
        .run(&payload, &ImportOptions::default())
        .unwrap();

        assert_eq!(
            fs::read_to_string(&moved).unwrap(),
            "[default]\naws_access_key_id = AKIAOLD\n"
        );
        // And NOT at the default location.
        assert!(!dest_home.path().join(".aws/credentials").exists());
    }

    #[test]
    fn test_several_kubeconfigs_land_together_with_a_note() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join("kube")).unwrap();
        fs::write(dir.path().join("kube/a.yaml"), "apiVersion: v1\n").unwrap();
        fs::write(dir.path().join("kube/b.yaml"), "apiVersion: v1\n").unwrap();
        let list = format!(
            "{}:{}",
            dir.path().join("kube/a.yaml").display(),
            dir.path().join("kube/b.yaml").display()
        );
        let paths = Paths::for_test(dir.path()).with_env("KUBECONFIG", &list);
        let registry = Registry::all(paths.clone());
        let vault = KeyRegistry::new(
            dir.path().join("keys.json"),
            Box::new(MemoryKeystore::new()),
        );
        let clients = McpClientRegistry::with_paths(paths.clone());
        let envs = EnvRegistry::new(
            dir.path().join("projects.json"),
            dir.path().join("attachments.json"),
            Box::new(MemoryKeystore::new()),
        );
        let payload = Exporter {
            paths: &paths,
            registry: &registry,
            vault: &vault,
            clients: &clients,
            envs: &envs,
        }
        .payload(&KeySelection::None, Utc::now())
        .unwrap();

        let dest = Machine::new(&[]);
        let report = dest.import(&payload, false);
        assert!(dest.exists(".kube/a.yaml"));
        assert!(dest.exists(".kube/b.yaml"));
        assert!(
            report.notes.iter().any(|n| n.contains("KUBECONFIG")),
            "{:?}",
            report.notes
        );
    }

    #[test]
    fn test_the_remaining_list_is_recomputed_not_copied() {
        // gh on the source is device-bound, so the manifest predicts a gap...
        let source = Machine::new(&[(
            ".config/gh/hosts.yml",
            "github.com:\n    user: octocat\n    users:\n        octocat:\n",
        )]);
        let payload = source.payload(KeySelection::None);
        assert!(payload.manifest.gaps.iter().any(|g| g.id == "tool:gh"));

        // ...and on a destination that ALREADY has that login, it is closed.
        let dest = Machine::new(&[(
            ".config/gh/hosts.yml",
            "github.com:\n    user: octocat\n    users:\n        octocat:\n",
        )]);
        let report = dest.import(&payload, false);
        let gh = report.remaining.iter().find(|i| i.id == "tool:gh").unwrap();
        assert_eq!(
            gh.status,
            crate::migrate::manifest::SetupStatus::Done,
            "{gh:?}"
        );
        assert!(report.open_items().all(|i| i.id != "tool:gh"));
    }
}
