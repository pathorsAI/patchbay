//! `pb export` — collect everything that can travel into one encrypted file.
//!
//! Four parts go in, in this order of trust:
//!
//! 1. **Portable credential files**, copied verbatim, chosen by
//!    [`super::policy`] and located through [`Paths`] so a machine with
//!    `AWS_CONFIG_FILE` set exports the file its CLI actually reads.
//! 2. **Vault secrets** — opt-in ([`KeySelection`]). The default is metadata
//!    only: the new machine gets a checklist of what to re-create, not the
//!    values.
//! 3. **`manifest.json`** — no secrets, ever. Profiles, active identities,
//!    key metadata, MCP registrations by name, and the gap list.
//! 4. **`SETUP.md`** — written at export time so a machine with no patchbay on
//!    it yet still has instructions.
//!
//! And one thing that travels as *metadata only, by construction*: the env
//! vault's project manifest ([`crate::envs`]). Ids, environments, sync pins —
//! never a value, and never this machine's `attachments.json`, whose paths mean
//! nothing on the next laptop. See [`Exporter::collect_env_projects`].
//!
//! # Where the bundle is allowed to land
//!
//! Not in a cloud-sync folder, unless the user insists. Copying credential
//! files is not a metaphor for how sessions get hijacked — it is the technique,
//! and a bundle dropped in Dropbox is that technique performed on yourself, in
//! advance, with a sync client for delivery. [`check_destination`] refuses,
//! names the directory, and says to move the file by AirDrop, USB or LAN.

use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};

use super::bundle::{self, BundleFile, BundleMcpServer, BundleSecret, Payload};
use super::manifest::{
    EnvEnvironmentRecord, EnvProjectRecord, EnvSyncRecord, KeyRecord, Manifest, ManifestKind,
    McpRecord, SetupItem, Source, ToolRecord, BUNDLE_VERSION,
};
use super::policy::{policy_for, Portability};
use super::setup;
use crate::envs::{EnvRegistry, ProjectEntry};
use crate::keys::KeyRegistry;
use crate::mcp_clients::{McpClientRegistry, TransportSpec};
use crate::paths::Paths;
use crate::registry::Registry;
use crate::types::ToolStatus;

/// Which vault secrets travel inside the encrypted payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeySelection {
    /// Metadata only. The default, and the right default: a bundle without
    /// secrets is a bundle whose loss is embarrassing rather than fatal.
    None,
    /// Every registered key.
    All,
    /// Named ids only.
    Only(Vec<String>),
}

impl KeySelection {
    fn wants(&self, id: &str) -> bool {
        match self {
            Self::None => false,
            Self::All => true,
            Self::Only(ids) => ids.iter().any(|i| i == id),
        }
    }

    pub fn is_none(&self) -> bool {
        *self == Self::None
    }
}

/// What an export did, for the CLI to print and the MCP layer to return.
#[derive(Debug, Clone, PartialEq)]
pub struct ExportReport {
    pub path: PathBuf,
    pub files: usize,
    pub bytes: usize,
    /// Tools with at least one file in the bundle.
    pub tools_carried: Vec<String>,
    /// Tools that need a re-auth on the far side.
    pub tools_bound: Vec<String>,
    /// Vault keys whose value travelled.
    pub keys_included: Vec<String>,
    /// Vault keys whose metadata travelled without the value.
    pub keys_listed: Vec<String>,
    pub mcp_carried: usize,
    /// Names — never values — of the MCP env vars and headers whose values are
    /// inside the bundle. The caller must say these out loud.
    pub mcp_values_carried: Vec<String>,
    /// Env vault projects whose metadata travelled. Their values did not, in
    /// either layer.
    pub env_projects: Vec<String>,
    pub gaps: usize,
    pub warnings: Vec<String>,
}

/// `patchbay-2026-08-13.pbx`.
pub fn default_file_name(now: DateTime<Utc>) -> String {
    format!(
        "patchbay-{}.{}",
        now.format("%Y-%m-%d"),
        bundle::BUNDLE_EXTENSION
    )
}

/// Directory names that mean "this file is about to be uploaded".
///
/// Matched on path components so `~/Documents/dropbox-migration-notes` is not
/// caught, but `~/Library/CloudStorage/Dropbox/x` is.
const CLOUD_DIRS: &[(&str, &str)] = &[
    ("Mobile Documents", "iCloud Drive"),
    ("com~apple~CloudDocs", "iCloud Drive"),
    ("CloudStorage", "a cloud drive mounted by macOS"),
    ("Dropbox", "Dropbox"),
    ("Google Drive", "Google Drive"),
    ("GoogleDrive", "Google Drive"),
    ("OneDrive", "OneDrive"),
    ("Box Sync", "Box"),
    ("pCloud Drive", "pCloud"),
];

/// The cloud-sync service a path sits inside, if any.
pub fn cloud_service(path: &Path) -> Option<&'static str> {
    path.components().find_map(|c| {
        let name = c.as_os_str().to_string_lossy();
        CLOUD_DIRS.iter().find_map(|(needle, service)| {
            (name == *needle || name.starts_with(&format!("{needle}-"))).then_some(*service)
        })
    })
}

/// Refuse a destination inside a cloud-sync folder unless `force`.
///
/// Returns the warnings the caller must print either way — including the one
/// that matters most, which applies even to a good destination.
pub fn check_destination(path: &Path, force: bool) -> anyhow::Result<Vec<String>> {
    let mut warnings = vec![
        "this file is every credential on this machine in one place; move it by AirDrop, USB or \
         a direct LAN copy, and delete it from both machines once the import is done"
            .to_string(),
    ];
    if let Some(service) = cloud_service(path) {
        if !force {
            anyhow::bail!(
                "refusing to write the bundle to {}: that path is inside {service}, so the file \
                 would be uploaded the moment it is written. Copying credential files is exactly \
                 how sessions get hijacked — do not hand a sync client the whole set. Pick a \
                 local path (~/Desktop, /tmp) and move it by AirDrop, USB or LAN. Pass --force \
                 if you genuinely mean it.",
                path.display()
            );
        }
        warnings.push(format!(
            "--force: writing into {service}. The bundle will be uploaded; delete it from the \
             service's trash as well as your disk."
        ));
    }
    Ok(warnings)
}

// ---------------------------------------------------------------------------
// building the payload
// ---------------------------------------------------------------------------

/// Everything an export reads from. Grouped so the CLI, the MCP server and the
/// tests all build a payload the same way.
pub struct Exporter<'a> {
    pub paths: &'a Paths,
    pub registry: &'a Registry,
    pub vault: &'a KeyRegistry,
    pub clients: &'a McpClientRegistry,
    pub envs: &'a EnvRegistry,
}

impl Exporter<'_> {
    /// Read the machine and build the payload. Nothing is written here.
    pub fn payload(&self, keys: &KeySelection, now: DateTime<Utc>) -> anyhow::Result<Payload> {
        self.build(keys, now, ManifestKind::Bundle)
    }

    /// The readable half on its own: no credential file is opened, no vault
    /// secret is read, and the result carries nothing that has to be encrypted.
    ///
    /// This is the artifact you can commit, sync or paste into a chat — the
    /// record of *what this machine uses*, which on a new machine is enough for
    /// `pb plan --manifest` (or an agent over `plan_setup`) to say what to
    /// install and what to log into.
    pub fn manifest(&self, now: DateTime<Utc>) -> anyhow::Result<Manifest> {
        Ok(self
            .build(&KeySelection::None, now, ManifestKind::Inventory)?
            .manifest)
    }

    fn build(
        &self,
        keys: &KeySelection,
        now: DateTime<Utc>,
        kind: ManifestKind,
    ) -> anyhow::Result<Payload> {
        // An inventory reads no credential file at all. Skipping the walk is
        // not an optimisation: opening every credential on the machine to
        // produce a file that will hold none of them is exactly the kind of
        // unnecessary handling this command exists to avoid.
        let carry_files = kind == ManifestKind::Bundle;
        let mut files = Vec::new();
        let mut tools = Vec::new();
        let mut gaps = Vec::new();

        for status in self.registry.status_all() {
            let (record, gap) = self.tool_record(&status, carry_files, &mut files);
            gaps.extend(gap);
            tools.push(record);
        }

        let (key_records, secrets, key_gaps) = self.collect_keys(keys)?;
        gaps.extend(key_gaps);
        let (mcp_records, mcp_servers) = self.collect_mcp(carry_files);
        let (env_records, env_entries, env_gaps) = self.collect_env_projects();
        gaps.extend(env_gaps);

        let manifest = Manifest {
            version: BUNDLE_VERSION,
            kind,
            created_at: now,
            source: Source {
                patchbay_version: env!("CARGO_PKG_VERSION").to_string(),
                os: std::env::consts::OS.to_string(),
            },
            tools,
            keys: key_records,
            mcp: mcp_records,
            env_projects: env_records,
            gaps,
        };

        let setup_md = setup::render(&manifest);
        Ok(Payload {
            version: BUNDLE_VERSION,
            manifest,
            setup_md,
            files,
            secrets,
            mcp: mcp_servers,
            env_projects: env_entries,
        })
    }

    /// One tool's manifest row, and the gap it leaves if it cannot travel.
    ///
    /// Appends to `files` rather than returning them: a tool contributes zero
    /// or many files, and threading a second vector back out of here only to
    /// splice it into the same place would obscure that the caller's list is
    /// the one being built.
    fn tool_record(
        &self,
        status: &ToolStatus,
        carry_files: bool,
        files: &mut Vec<BundleFile>,
    ) -> (ToolRecord, Option<SetupItem>) {
        let policy = policy_for(&status.tool);
        let mut record = ToolRecord {
            tool: status.tool.clone(),
            category: status.category,
            installed: status.installed,
            portability: policy
                .map(|p| p.portability.kind())
                .unwrap_or(super::policy::PortabilityKind::PointerOnly),
            reason: policy.map(|p| p.portability.reason()).unwrap_or("").into(),
            profiles: status.profiles.clone(),
            active: status.active.clone(),
            carried: Vec::new(),
            subject: None,
            scopes: Vec::new(),
            // The bundle is a portable record, not a live board: its notes
            // are prose for whoever reads the manifest on the new machine,
            // so the severity a probe attached here does not travel.
            notes: status.notes.iter().map(|n| n.text.clone()).collect(),
        };

        let Some(policy) = policy else {
            return (record, None);
        };

        if carry_files {
            self.carry_tool_files(status, policy, &mut record, files);
        }

        // What the active credential may do, for the tools where re-creating
        // it by hand is easy to get wrong.
        if policy.record_permissions && status.installed && self.paths.may_exec() {
            if let Ok(report) = self.registry.permissions(&status.tool) {
                if report.supported {
                    record.subject = report.subject;
                    record.scopes = report.scopes;
                }
            }
        }

        // Docker's file names the credential helper; the helper's secrets
        // stay in the keychain. Say so where the user will see it.
        if status.tool == "docker" && !record.carried.is_empty() {
            record.notes.push(
                "the registry list travelled; any secret held by a credential helper \
                 (`credsStore`) stayed in this machine's keychain — `docker login` again on \
                 the new machine if a pull is refused"
                    .to_string(),
            );
        }

        (record, tool_gap(policy, status))
    }

    /// Copy every file this tool's policy points at into the bundle, recording
    /// which locations actually yielded one.
    fn carry_tool_files(
        &self,
        status: &ToolStatus,
        policy: &super::policy::ToolPolicy,
        record: &mut ToolRecord,
        files: &mut Vec<BundleFile>,
    ) {
        for location in policy.portability.locations() {
            for found in location.collect(self.paths) {
                let bytes = match std::fs::read(&found.source) {
                    Ok(bytes) => bytes,
                    // A file that vanished between the walk and the read is a
                    // note, not a failed export.
                    Err(e) => {
                        record.notes.push(format!(
                            "could not read {}: {e}; it is not in the bundle",
                            found.source.display()
                        ));
                        continue;
                    }
                };
                if !record.carried.contains(location) {
                    record.carried.push(*location);
                }
                files.push(BundleFile::encode(
                    &status.tool,
                    *location,
                    found.rel.clone(),
                    found.mode,
                    &bytes,
                ));
            }
        }
    }

    /// Vault metadata always; values only for the selected ids.
    fn collect_keys(
        &self,
        selection: &KeySelection,
    ) -> anyhow::Result<(Vec<KeyRecord>, Vec<BundleSecret>, Vec<SetupItem>)> {
        let entries = match self.vault.list() {
            Ok(entries) => entries,
            // A vault that cannot be read must not take the export down with
            // it: the credential files are the valuable half.
            Err(_) => return Ok((Vec::new(), Vec::new(), Vec::new())),
        };

        let mut records = Vec::new();
        let mut secrets = Vec::new();
        let mut gaps = Vec::new();
        for entry in entries {
            let mut included = false;
            if selection.wants(&entry.id) {
                match self.vault.get_secret(&entry.id) {
                    Ok(secret) => {
                        secrets.push(BundleSecret {
                            id: entry.id.clone(),
                            secret,
                        });
                        included = true;
                    }
                    Err(e) => gaps.push(
                        SetupItem::new(
                            format!("key:{}", entry.id),
                            "key vault",
                            format!(
                                "`{}` is registered but its value could not be read from this \
                             machine's keystore, so it is not in the bundle",
                                entry.id
                            ),
                        )
                        .command(format!("pb key add {} --overwrite", entry.id), false)
                        .detail(format!("{e:#}")),
                    ),
                }
            }
            if !included && !gaps.iter().any(|g| g.id == format!("key:{}", entry.id)) {
                gaps.push(
                    SetupItem::new(
                        format!("key:{}", entry.id),
                        "key vault",
                        format!(
                            "`{}` ({}, …{}) is registered here; its value did not travel",
                            entry.id, entry.provider, entry.last4
                        ),
                    )
                    .command(
                        format!(
                            "pb key add {} --provider {} --label \"{}\"",
                            entry.id, entry.provider, entry.label
                        ),
                        false,
                    ),
                );
            }
            records.push(KeyRecord {
                id: entry.id,
                provider: entry.provider,
                label: entry.label,
                purpose: entry.purpose,
                scopes: entry.scopes,
                expires_at: entry.expires_at,
                last4: entry.last4,
                included,
            });
        }
        Ok((records, secrets, gaps))
    }

    /// The env vault's portable project manifest, and nothing else it owns.
    ///
    /// Three exclusions, all deliberate and all load-bearing:
    ///
    /// * **`attachments.json` never travels.** It is a list of directories on
    ///   *this* machine, and a path from the old laptop is at best noise and at
    ///   worst a directory that exists on the new one and means something else.
    ///   Nothing here reads it. `pb env attach` is the new machine's own job.
    /// * **No value travels, in either layer.** Not the synced one — a pull
    ///   rebuilds it from the remote, which is authoritative in a way a
    ///   week-old bundle is not — and emphatically not the local one, which is
    ///   `.env.local` semantics: the `DATABASE_URL` pointing at a container on
    ///   the old machine is the exact thing that must not follow you.
    /// * **Every `local_names` list is cleared** from the entries that are
    ///   carried, because names without values would make `pb env list` on the
    ///   new machine promise variables `pb env run` could not produce.
    ///   `synced_names` and `synced_at` stay: those are an honest statement of
    ///   what a pull will restore and when it last happened.
    ///
    /// A registry that cannot be read is a note, not a failed export — the same
    /// tolerance [`Exporter::collect_keys`] has, for the same reason: the
    /// credential files are the half worth saving.
    fn collect_env_projects(&self) -> (Vec<EnvProjectRecord>, Vec<ProjectEntry>, Vec<SetupItem>) {
        let Ok(projects) = self.envs.projects() else {
            return (Vec::new(), Vec::new(), Vec::new());
        };

        let mut records = Vec::new();
        let mut entries = Vec::new();
        let mut gaps = Vec::new();
        for project in projects {
            records.push(EnvProjectRecord {
                id: project.id.clone(),
                default_env: project.default_env.clone(),
                environments: project
                    .environments
                    .iter()
                    .map(|(name, meta)| EnvEnvironmentRecord {
                        name: name.clone(),
                        synced_vars: meta.synced_names.len(),
                        synced_at: meta.synced_at,
                    })
                    .collect(),
                sync: project.sync.as_ref().map(|sync| EnvSyncRecord {
                    provider: sync.provider.clone(),
                    project_id: sync.project_id.clone(),
                    account: sync.account.clone(),
                }),
            });

            // A linked project is no gap at all: `pb env pull` rebuilds it, and
            // the plan says so. An unlinked one with a synced layer is the case
            // worth a line — something pulled those variables once, and nothing
            // on the new machine knows from where.
            if project.sync.is_none() {
                let synced: usize = project
                    .environments
                    .values()
                    .map(|meta| meta.synced_names.len())
                    .sum();
                if synced > 0 {
                    gaps.push(
                        SetupItem::new(
                            format!("env:{}", project.id),
                            "env vault",
                            format!(
                                "`{}` has {synced} synced variable(s) but no sync config, so its \
                                 synced layer cannot be rebuilt by `pb env pull` on the new \
                                 machine — values are not in the bundle",
                                project.id
                            ),
                        )
                        .command(
                            format!(
                                "pb env link --project {} --project-id <infisical project id>",
                                project.id
                            ),
                            false,
                        )
                        .detail(
                            "or set the values by hand there (`pb env set`) / load a `.env` with \
                             `pb env import`",
                        ),
                    );
                }
            }

            entries.push(carried_entry(&project));
        }
        (records, entries, gaps)
    }

    /// Every user-scope MCP registration, by name in the manifest and with
    /// values in the payload. Project scopes are read but never carried: they
    /// belong to a repository, not to the machine.
    /// `carry_values` is false for an inventory: the registrations are still
    /// worth listing (that is the point of the file), but nothing about them
    /// travels, and a record claiming otherwise is the one thing a manifest
    /// must never do.
    fn collect_mcp(&self, carry_values: bool) -> (Vec<McpRecord>, Vec<BundleMcpServer>) {
        let mut records = Vec::new();
        let mut servers = Vec::new();
        for client in self.clients.clients() {
            for entry in &client.servers {
                if !entry.is_writable_scope() {
                    continue;
                }
                let spec = carry_values
                    .then(|| self.clients.read_spec(&client.client, &entry.name).ok())
                    .flatten();
                if let Some(spec) = &spec {
                    let (transport, command, args, url) = match &spec.transport {
                        TransportSpec::Stdio { command, args } => {
                            ("stdio", Some(command.clone()), args.clone(), None)
                        }
                        TransportSpec::Http { url } => {
                            ("http", None, Vec::new(), Some(url.clone()))
                        }
                        TransportSpec::Sse { url } => ("sse", None, Vec::new(), Some(url.clone())),
                    };
                    servers.push(BundleMcpServer {
                        client: client.client.clone(),
                        name: entry.name.clone(),
                        transport: transport.to_string(),
                        command,
                        args,
                        url,
                        env: spec.env.clone(),
                        headers: spec.headers.clone(),
                    });
                }
                records.push(McpRecord {
                    client: client.client.clone(),
                    name: entry.name.clone(),
                    summary: entry.transport.summary(),
                    env_keys: entry.env_keys.clone(),
                    header_keys: entry.header_keys.clone(),
                    carried: spec.is_some(),
                });
            }
        }
        (records, servers)
    }
}

/// One project entry as it is allowed to leave the machine: the local layer's
/// name lists dropped, everything else verbatim. See
/// [`Exporter::collect_env_projects`] for why, and
/// [`crate::envs::EnvRegistry::adopt`] for the other half of the same rule.
fn carried_entry(project: &ProjectEntry) -> ProjectEntry {
    let mut entry = project.clone();
    for meta in entry.environments.values_mut() {
        meta.local_names.clear();
    }
    entry
}

/// The gap a non-portable tool leaves behind. `None` when there is nothing to
/// re-create — a tool that was never set up here is not a chore over there.
fn tool_gap(
    policy: &'static super::policy::ToolPolicy,
    status: &crate::types::ToolStatus,
) -> Option<SetupItem> {
    if matches!(policy.portability, Portability::Portable { .. }) {
        return None;
    }
    if !status.installed && status.profiles.is_empty() {
        return None;
    }
    let who = match &status.active {
        Some(active) => format!(" as `{active}`"),
        None if status.profiles.is_empty() => String::new(),
        None => format!(
            " ({} profile(s): {})",
            status.profiles.len(),
            status
                .profiles
                .iter()
                .map(|p| p.id.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ),
    };
    Some(
        SetupItem::new(
            format!("tool:{}", policy.tool),
            policy.tool,
            format!("log in to {}{who}", policy.tool),
        )
        .command(policy.fix, policy.needs_browser)
        .detail(policy.portability.reason()),
    )
}

// ---------------------------------------------------------------------------
// writing
// ---------------------------------------------------------------------------

/// Encrypt a payload to `path` and describe what went in.
pub fn write(
    path: &Path,
    payload: &Payload,
    passphrase: &str,
    force: bool,
    work_factor: Option<u8>,
) -> anyhow::Result<ExportReport> {
    let warnings = check_destination(path, force)?;
    bundle::write(path, payload, passphrase, work_factor)?;

    let mut tools_carried: Vec<String> = Vec::new();
    for file in &payload.files {
        if !tools_carried.contains(&file.tool) {
            tools_carried.push(file.tool.clone());
        }
    }
    let mut mcp_values: Vec<String> = Vec::new();
    for server in &payload.mcp {
        for (name, _) in server.env.iter().chain(server.headers.iter()) {
            if !mcp_values.contains(name) {
                mcp_values.push(name.clone());
            }
        }
    }

    Ok(ExportReport {
        path: path.to_path_buf(),
        files: payload.files.len(),
        bytes: payload.bytes_carried(),
        tools_carried,
        tools_bound: payload
            .manifest
            .tools
            .iter()
            .filter(|t| t.portability != super::policy::PortabilityKind::Portable && t.installed)
            .map(|t| t.tool.clone())
            .collect(),
        keys_included: payload.secrets.iter().map(|s| s.id.clone()).collect(),
        keys_listed: payload
            .manifest
            .keys
            .iter()
            .filter(|k| !k.included)
            .map(|k| k.id.clone())
            .collect(),
        mcp_carried: payload.mcp.len(),
        mcp_values_carried: mcp_values,
        env_projects: payload.env_projects.iter().map(|p| p.id.clone()).collect(),
        gaps: payload.manifest.gaps.len(),
        warnings,
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::keystore::MemoryKeystore;
    use crate::migrate::policy::Location;
    use std::fs;

    pub(crate) fn fake_home(files: &[(&str, &str)]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        for (rel, body) in files {
            let path = dir.path().join(rel);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(&path, body).unwrap();
        }
        dir
    }

    #[test]
    fn test_default_name_is_dated() {
        let now = DateTime::parse_from_rfc3339("2026-08-13T10:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        assert_eq!(default_file_name(now), "patchbay-2026-08-13.pbx");
    }

    #[test]
    fn test_cloud_directories_are_refused_by_name() {
        for (path, service) in [
            (
                "/Users/x/Library/Mobile Documents/com~apple~CloudDocs/b.pbx",
                "iCloud Drive",
            ),
            ("/Users/x/Dropbox/b.pbx", "Dropbox"),
            (
                "/Users/x/Library/CloudStorage/Dropbox-Personal/b.pbx",
                "a cloud drive mounted by macOS",
            ),
            ("/Users/x/Google Drive/My Drive/b.pbx", "Google Drive"),
            ("/Users/x/OneDrive/b.pbx", "OneDrive"),
        ] {
            let path = PathBuf::from(path);
            assert_eq!(cloud_service(&path), Some(service), "{}", path.display());
            let err = check_destination(&path, false).unwrap_err().to_string();
            assert!(err.contains("refusing"), "{err}");
            assert!(err.contains("--force"), "{err}");
            // --force lets it through, loudly.
            let warnings = check_destination(&path, true).unwrap();
            assert!(
                warnings.iter().any(|w| w.contains("--force")),
                "{warnings:?}"
            );
        }
    }

    #[test]
    fn test_an_ordinary_destination_is_allowed_but_still_warned_about() {
        let path = PathBuf::from("/Users/x/Desktop/dropbox-notes/patchbay.pbx");
        assert_eq!(cloud_service(&path), None);
        let warnings = check_destination(&path, false).unwrap();
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("AirDrop"), "{warnings:?}");
    }

    /// A machine with a handful of real-shaped credential files.
    pub(crate) fn machine() -> tempfile::TempDir {
        fake_home(&[
            (".aws/config", "[default]\nregion = eu-west-1\n"),
            (
                ".aws/credentials",
                "[default]\naws_access_key_id = AKIAEXAMPLE\naws_secret_access_key = SUPERSECRETVALUE\n",
            ),
            (".config/gcloud/credentials.db", "SQLite format 3\0fake"),
            (".config/gcloud/active_config", "work"),
            (".config/gcloud/logs/x.log", "noise"),
            (".kube/config", "apiVersion: v1\nclusters: []\n"),
            (".npmrc", "//registry.npmjs.org/:_authToken=npm_SECRET\n"),
            (".ssh/config", "Host prod\n  HostName 10.0.0.1\n"),
            (".ssh/id_ed25519", "-----BEGIN OPENSSH PRIVATE KEY-----\n"),
            (".docker/config.json", "{\"auths\":{},\"credsStore\":\"desktop\"}"),
        ])
    }

    pub(crate) fn exporter_parts(
        home: &Path,
    ) -> (Paths, Registry, KeyRegistry, McpClientRegistry, EnvRegistry) {
        let paths = Paths::for_test(home);
        let registry = Registry::all(paths.clone());
        let vault = KeyRegistry::new(home.join("keys.json"), Box::new(MemoryKeystore::new()));
        let clients = McpClientRegistry::with_paths(paths.clone());
        let envs = EnvRegistry::new(
            home.join("projects.json"),
            home.join("attachments.json"),
            Box::new(MemoryKeystore::new()),
        );
        (paths, registry, vault, clients, envs)
    }

    #[test]
    fn test_the_payload_carries_the_portable_files_and_nothing_else() {
        let home = machine();
        let (paths, registry, vault, clients, envs) = exporter_parts(home.path());
        let exporter = Exporter {
            paths: &paths,
            registry: &registry,
            vault: &vault,
            clients: &clients,
            envs: &envs,
        };
        let payload = exporter.payload(&KeySelection::None, Utc::now()).unwrap();

        let rels: Vec<(&str, &str)> = payload
            .files
            .iter()
            .map(|f| (f.location.key(), f.rel.as_str()))
            .collect();
        assert!(
            rels.contains(&("aws_credentials", "credentials")),
            "{rels:?}"
        );
        assert!(rels.contains(&("gcloud", "active_config")), "{rels:?}");
        assert!(rels.contains(&("kube_configs", "config")), "{rels:?}");
        assert!(rels.contains(&("ssh_config", "config")), "{rels:?}");
        // gcloud's logs and the ssh PRIVATE KEY are not in the bundle. The
        // second one is the important assertion in this whole file.
        assert!(!rels.iter().any(|(_, rel)| rel.contains("log")), "{rels:?}");
        assert!(
            !rels.iter().any(|(_, rel)| rel.contains("id_ed25519")),
            "a private key was collected: {rels:?}"
        );
        let all_bytes: String = payload
            .files
            .iter()
            .map(|f| String::from_utf8(f.decode().unwrap()).unwrap_or_default())
            .collect();
        assert!(
            !all_bytes.contains("BEGIN OPENSSH PRIVATE KEY"),
            "{all_bytes}"
        );
        assert!(
            all_bytes.contains("SUPERSECRETVALUE"),
            "the aws key did not travel"
        );
    }

    #[test]
    fn test_the_manifest_names_the_gaps_with_commands() {
        let home = fake_home(&[(
            ".config/gh/hosts.yml",
            "github.com:\n    user: octocat\n    users:\n        octocat:\n",
        )]);
        let (paths, registry, vault, clients, envs) = exporter_parts(home.path());
        let payload = Exporter {
            paths: &paths,
            registry: &registry,
            vault: &vault,
            clients: &clients,
            envs: &envs,
        }
        .payload(&KeySelection::None, Utc::now())
        .unwrap();

        let gh = payload
            .manifest
            .gaps
            .iter()
            .find(|g| g.id == "tool:gh")
            .expect("gh is device-bound and must be a gap");
        assert_eq!(gh.command, "gh auth login");
        assert!(gh.needs_browser);
        assert!(!gh.auto);
        assert!(gh.detail[0].contains("keychain"), "{:?}", gh.detail);
        // A tool that was never set up here is not a chore over there.
        assert!(!payload.manifest.gaps.iter().any(|g| g.id == "tool:stripe"));
        // And the manifest still has no secrets in it.
        let json = payload.manifest.to_json();
        assert!(!json.contains("oauth_token"), "{json}");
    }

    #[test]
    fn test_keys_are_metadata_only_until_asked_for() {
        let home = fake_home(&[]);
        let (paths, registry, vault, clients, envs) = exporter_parts(home.path());
        vault
            .add(
                crate::keys::NewKey::new("cf-api", "cli").provider("cloudflare"),
                "cf-secret-1234",
                false,
            )
            .unwrap();
        vault
            .add(
                crate::keys::NewKey::new("openai", "cli").provider("openai"),
                "sk-secret-5678",
                false,
            )
            .unwrap();
        let exporter = Exporter {
            paths: &paths,
            registry: &registry,
            vault: &vault,
            clients: &clients,
            envs: &envs,
        };

        // Default: metadata travels, values do not, and each becomes a gap.
        let bare = exporter.payload(&KeySelection::None, Utc::now()).unwrap();
        assert!(bare.secrets.is_empty());
        assert_eq!(bare.manifest.keys.len(), 2);
        assert!(bare.manifest.keys.iter().all(|k| !k.included));
        assert!(bare.manifest.gaps.iter().any(|g| g.id == "key:cf-api"));
        let json = serde_json::to_string(&bare.manifest).unwrap();
        assert!(!json.contains("cf-secret"), "{json}");
        assert!(!json.contains("sk-secret"), "{json}");

        // --keys=cf-api: one value travels, the other is still a gap.
        let some = exporter
            .payload(&KeySelection::Only(vec!["cf-api".into()]), Utc::now())
            .unwrap();
        assert_eq!(some.secrets.len(), 1);
        assert_eq!(some.secrets[0].secret, "cf-secret-1234");
        assert!(
            some.manifest
                .keys
                .iter()
                .find(|k| k.id == "cf-api")
                .unwrap()
                .included
        );
        assert!(!some.manifest.gaps.iter().any(|g| g.id == "key:cf-api"));
        assert!(some.manifest.gaps.iter().any(|g| g.id == "key:openai"));

        // --keys: everything.
        let all = exporter.payload(&KeySelection::All, Utc::now()).unwrap();
        assert_eq!(all.secrets.len(), 2);
        assert!(!all.manifest.gaps.iter().any(|g| g.id.starts_with("key:")));
    }

    #[test]
    fn test_an_inventory_manifest_carries_nothing_and_says_so() {
        // A machine with a portable credential file, a keychain-bound tool, and
        // an MCP registration whose env holds a secret — one of each kind that
        // an export would treat differently.
        let home = fake_home(&[
            (
                ".config/gh/hosts.yml",
                "github.com:\n    user: octocat\n    users:\n        octocat:\n",
            ),
            (
                ".config/gcloud/configurations/config_default",
                "[core]\naccount = a@b.com\n",
            ),
            (
                ".cursor/mcp.json",
                r#"{"mcpServers":{"grafana":{"command":"uvx","args":["mcp-grafana"],"env":{"GRAFANA_TOKEN":"glsa_secret"}}}}"#,
            ),
        ]);
        let (paths, registry, vault, clients, envs) = exporter_parts(home.path());
        let exporter = Exporter {
            paths: &paths,
            registry: &registry,
            vault: &vault,
            clients: &clients,
            envs: &envs,
        };

        // The bundle path reads the files; the inventory must not.
        let bundle = exporter.payload(&KeySelection::All, Utc::now()).unwrap();
        assert!(!bundle.files.is_empty(), "the bundle should carry files");
        assert_eq!(bundle.manifest.kind, ManifestKind::Bundle);

        let manifest = exporter.manifest(Utc::now()).unwrap();
        assert_eq!(manifest.kind, ManifestKind::Inventory);

        // Nothing may claim to have travelled, because nothing did.
        assert!(
            manifest.tools.iter().all(|t| t.carried.is_empty()),
            "an inventory carries no file, so no tool may list a carried location"
        );
        assert!(
            manifest.mcp.iter().all(|r| !r.carried),
            "an inventory carries no MCP value"
        );
        assert!(manifest.keys.iter().all(|k| !k.included));

        // But it is still a record: the tools and registrations are named.
        assert!(manifest.tools.iter().any(|t| t.tool == "gh"));
        let grafana = manifest
            .mcp
            .iter()
            .find(|r| r.name == "grafana")
            .expect("the registration is the point of the file");
        assert_eq!(grafana.env_keys, vec!["GRAFANA_TOKEN".to_string()]);

        // And the file is safe to commit: the variable name travels, its value
        // does not, and neither does anything else secret-shaped.
        let json = manifest.to_json();
        assert!(json.contains("GRAFANA_TOKEN"), "{json}");
        assert!(!json.contains("glsa_secret"), "{json}");
        assert!(!json.contains("oauth_token"), "{json}");
    }

    #[test]
    fn test_mcp_registrations_travel_with_their_values_and_are_named_without_them() {
        let home = fake_home(&[(
            ".cursor/mcp.json",
            r#"{"mcpServers":{"grafana":{"command":"uvx","args":["mcp-grafana"],"env":{"GRAFANA_TOKEN":"glsa_secret"}}}}"#,
        )]);
        let (paths, registry, vault, clients, envs) = exporter_parts(home.path());
        let payload = Exporter {
            paths: &paths,
            registry: &registry,
            vault: &vault,
            clients: &clients,
            envs: &envs,
        }
        .payload(&KeySelection::None, Utc::now())
        .unwrap();

        assert_eq!(payload.mcp.len(), 1);
        assert_eq!(
            payload.mcp[0].env[0],
            ("GRAFANA_TOKEN".into(), "glsa_secret".into())
        );
        let manifest = payload.manifest.to_json();
        assert!(manifest.contains("GRAFANA_TOKEN"), "{manifest}");
        assert!(!manifest.contains("glsa_secret"), "{manifest}");
    }

    /// Two projects, one of each shape, with values in the keystore and an
    /// attachment on this machine — everything the exclusions are about.
    ///
    /// `pathors` is linked and has both layers. `legacy` has a synced layer and
    /// no link, which is the only case that becomes a gap.
    pub(crate) fn seed_env_vault(envs: &EnvRegistry, attached: &Path) -> DateTime<Utc> {
        let pulled = DateTime::parse_from_rfc3339("2026-08-01T09:30:00Z")
            .unwrap()
            .with_timezone(&Utc);

        envs.register("pathors", "dev").unwrap();
        envs.replace_synced(
            "pathors",
            "dev",
            [(
                "DATABASE_URL".to_string(),
                "postgres://remote/db".to_string(),
            )]
            .into_iter()
            .collect(),
            pulled,
        )
        .unwrap();
        envs.set_local(
            "pathors",
            "dev",
            "DATABASE_URL",
            "postgres://localhost:5432/dev",
        )
        .unwrap();
        envs.set_local("pathors", "dev", "LOCAL_ONLY_TOKEN", "local-value-1234")
            .unwrap();
        envs.set_sync(
            "pathors",
            crate::envs::SyncConfig {
                provider: "infisical".into(),
                project_id: "9f2c-uuid".into(),
                account: "me@work.com".into(),
                domain: None,
                env_map: Default::default(),
                secret_path: crate::envs::DEFAULT_SECRET_PATH.into(),
            },
        )
        .unwrap();
        // A directory on THIS machine. Its path must not appear in a bundle.
        envs.attach(attached, "pathors").unwrap();

        envs.register("legacy", "dev").unwrap();
        envs.replace_synced(
            "legacy",
            "dev",
            [("OLD_KEY".to_string(), "old-value-5678".to_string())]
                .into_iter()
                .collect(),
            pulled,
        )
        .unwrap();
        pulled
    }

    #[test]
    fn test_the_env_vault_travels_as_names_and_pins_only() {
        let home = fake_home(&[]);
        let (paths, registry, vault, clients, envs) = exporter_parts(home.path());
        let pulled = seed_env_vault(&envs, &home.path().join("repos/pathors"));

        let payload = Exporter {
            paths: &paths,
            registry: &registry,
            vault: &vault,
            clients: &clients,
            envs: &envs,
        }
        .payload(&KeySelection::None, Utc::now())
        .unwrap();

        let carried = &payload.env_projects;
        assert_eq!(carried.len(), 2, "{carried:?}");
        let pathors = carried.iter().find(|p| p.id == "pathors").unwrap();
        let dev = pathors.env("dev").unwrap();
        // What a pull will restore, and when it last ran: honest, and useful.
        assert_eq!(dev.synced_names, vec!["DATABASE_URL"]);
        assert_eq!(dev.synced_at, Some(pulled));
        // The local layer's NAMES are dropped with its values. A name list
        // without values would make `pb env list` promise what it cannot give.
        assert!(dev.local_names.is_empty(), "{dev:?}");
        assert_eq!(pathors.sync.as_ref().unwrap().account, "me@work.com");

        // The manifest half: counts and the pin, no names, no local anything.
        let record = payload
            .manifest
            .env_projects
            .iter()
            .find(|p| p.id == "pathors")
            .unwrap();
        assert_eq!(record.environments[0].name, "dev");
        assert_eq!(record.environments[0].synced_vars, 1);
        assert_eq!(record.sync.as_ref().unwrap().project_id, "9f2c-uuid");

        // A linked project is no gap — `pb env pull` rebuilds it. An unlinked
        // one with a synced layer is, because nothing here can.
        assert!(!payload.manifest.gaps.iter().any(|g| g.id == "env:pathors"));
        let gap = payload
            .manifest
            .gaps
            .iter()
            .find(|g| g.id == "env:legacy")
            .expect("a synced layer with no sync config cannot be rebuilt");
        assert!(gap.what.contains("cannot be rebuilt"), "{gap:?}");
        assert!(
            gap.command.contains("pb env link --project legacy"),
            "{gap:?}"
        );
    }

    #[test]
    fn test_no_env_value_and_no_attachment_path_is_anywhere_in_a_bundle() {
        let home = fake_home(&[]);
        let out = tempfile::tempdir().unwrap();
        let (paths, registry, vault, clients, envs) = exporter_parts(home.path());
        let attached = home.path().join("repos/pathors");
        seed_env_vault(&envs, &attached);

        let payload = Exporter {
            paths: &paths,
            registry: &registry,
            vault: &vault,
            clients: &clients,
            envs: &envs,
        }
        .payload(&KeySelection::None, Utc::now())
        .unwrap();

        // The decrypted payload is the real test: the encryption is not what
        // keeps these out, the collection rules are.
        let json = serde_json::to_string(&payload).unwrap();
        for forbidden in [
            // synced values: rebuilt by a pull, never carried
            "postgres://remote/db",
            "old-value-5678",
            // local values: per-machine overrides, carried by nothing, ever
            "postgres://localhost:5432/dev",
            "local-value-1234",
            "LOCAL_ONLY_TOKEN",
            // this machine's attachment root
            "repos/pathors",
        ] {
            assert!(!json.contains(forbidden), "`{forbidden}` is in the payload");
        }
        assert!(!json.contains(&attached.display().to_string()));
        // Names of the synced layer DO travel: that is the honest part.
        assert!(json.contains("DATABASE_URL"), "{json}");

        let path = out.path().join("b.pbx");
        let report = write(&path, &payload, "pass", false, Some(10)).unwrap();
        assert_eq!(report.env_projects, vec!["pathors", "legacy"]);
        let raw = String::from_utf8_lossy(&std::fs::read(&path).unwrap()).into_owned();
        for forbidden in ["local-value-1234", "postgres://", "repos/pathors"] {
            assert!(!raw.contains(forbidden), "`{forbidden}` is in the .pbx");
        }
    }

    #[test]
    fn test_an_unreadable_env_registry_does_not_take_the_export_down() {
        let home = fake_home(&[]);
        let (paths, registry, vault, clients, _) = exporter_parts(home.path());
        std::fs::write(home.path().join("projects.json"), "{not json").unwrap();
        let envs = EnvRegistry::new(
            home.path().join("projects.json"),
            home.path().join("attachments.json"),
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
        .expect("the credential files are the half worth saving");
        assert!(payload.env_projects.is_empty());
        assert!(payload.manifest.env_projects.is_empty());
    }

    #[test]
    fn test_write_reports_what_went_in() {
        let home = machine();
        let out = tempfile::tempdir().unwrap();
        let (paths, registry, vault, clients, envs) = exporter_parts(home.path());
        let payload = Exporter {
            paths: &paths,
            registry: &registry,
            vault: &vault,
            clients: &clients,
            envs: &envs,
        }
        .payload(&KeySelection::None, Utc::now())
        .unwrap();

        let path = out.path().join("b.pbx");
        let report = write(&path, &payload, "pass", false, Some(10)).unwrap();
        assert!(report.files >= 6, "{report:?}");
        assert!(report.bytes > 0);
        assert!(report.tools_carried.contains(&"aws".to_string()));
        assert!(report.keys_included.is_empty());
        assert!(report.warnings[0].contains("AirDrop"));
        assert!(path.is_file());
    }

    #[test]
    fn test_locations_used_by_the_exporter_are_the_ones_the_policy_names() {
        // Guards against a location that exists but no tool references, which
        // would silently never be exported.
        let referenced = crate::migrate::policy::all_locations();
        for location in [Location::Gcloud, Location::SshConfig, Location::Docker] {
            assert!(referenced.contains(&location), "{location:?}");
        }
    }
}
