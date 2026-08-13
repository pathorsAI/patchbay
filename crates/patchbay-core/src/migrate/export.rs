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
    KeyRecord, Manifest, McpRecord, SetupItem, Source, ToolRecord, BUNDLE_VERSION,
};
use super::policy::{policy_for, Portability};
use super::setup;
use crate::keys::KeyRegistry;
use crate::mcp_clients::{McpClientRegistry, TransportSpec};
use crate::paths::Paths;
use crate::registry::Registry;

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
}

impl Exporter<'_> {
    /// Read the machine and build the payload. Nothing is written here.
    pub fn payload(&self, keys: &KeySelection, now: DateTime<Utc>) -> anyhow::Result<Payload> {
        let mut files = Vec::new();
        let mut tools = Vec::new();
        let mut gaps = Vec::new();

        for status in self.registry.status_all() {
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
                notes: status.notes.clone(),
            };

            if let Some(policy) = policy {
                for location in policy.portability.locations() {
                    for found in location.collect(self.paths) {
                        let bytes = match std::fs::read(&found.source) {
                            Ok(bytes) => bytes,
                            // A file that vanished between the walk and the
                            // read is a note, not a failed export.
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

                // What the active credential may do, for the tools where
                // re-creating it by hand is easy to get wrong.
                if policy.record_permissions && status.installed && self.paths.may_exec() {
                    if let Ok(report) = self.registry.permissions(&status.tool) {
                        if report.supported {
                            record.subject = report.subject;
                            record.scopes = report.scopes;
                        }
                    }
                }

                if let Some(gap) = tool_gap(policy, &status) {
                    gaps.push(gap);
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
            tools.push(record);
        }

        let (key_records, secrets, key_gaps) = self.collect_keys(keys)?;
        gaps.extend(key_gaps);
        let (mcp_records, mcp_servers) = self.collect_mcp();

        let manifest = Manifest {
            version: BUNDLE_VERSION,
            created_at: now,
            source: Source {
                patchbay_version: env!("CARGO_PKG_VERSION").to_string(),
                os: std::env::consts::OS.to_string(),
            },
            tools,
            keys: key_records,
            mcp: mcp_records,
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
        })
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

    /// Every user-scope MCP registration, by name in the manifest and with
    /// values in the payload. Project scopes are read but never carried: they
    /// belong to a repository, not to the machine.
    fn collect_mcp(&self) -> (Vec<McpRecord>, Vec<BundleMcpServer>) {
        let mut records = Vec::new();
        let mut servers = Vec::new();
        for client in self.clients.clients() {
            for entry in &client.servers {
                if !entry.is_writable_scope() {
                    continue;
                }
                let spec = self.clients.read_spec(&client.client, &entry.name).ok();
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
        gaps: payload.manifest.gaps.len(),
        warnings,
    })
}

#[cfg(test)]
mod tests {
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

    pub(crate) fn exporter_parts(home: &Path) -> (Paths, Registry, KeyRegistry, McpClientRegistry) {
        let paths = Paths::for_test(home);
        let registry = Registry::all(paths.clone());
        let vault = KeyRegistry::new(home.join("keys.json"), Box::new(MemoryKeystore::new()));
        let clients = McpClientRegistry::with_paths(paths.clone());
        (paths, registry, vault, clients)
    }

    #[test]
    fn test_the_payload_carries_the_portable_files_and_nothing_else() {
        let home = machine();
        let (paths, registry, vault, clients) = exporter_parts(home.path());
        let exporter = Exporter {
            paths: &paths,
            registry: &registry,
            vault: &vault,
            clients: &clients,
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
        let (paths, registry, vault, clients) = exporter_parts(home.path());
        let payload = Exporter {
            paths: &paths,
            registry: &registry,
            vault: &vault,
            clients: &clients,
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
        let (paths, registry, vault, clients) = exporter_parts(home.path());
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
    fn test_mcp_registrations_travel_with_their_values_and_are_named_without_them() {
        let home = fake_home(&[(
            ".cursor/mcp.json",
            r#"{"mcpServers":{"grafana":{"command":"uvx","args":["mcp-grafana"],"env":{"GRAFANA_TOKEN":"glsa_secret"}}}}"#,
        )]);
        let (paths, registry, vault, clients) = exporter_parts(home.path());
        let payload = Exporter {
            paths: &paths,
            registry: &registry,
            vault: &vault,
            clients: &clients,
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

    #[test]
    fn test_write_reports_what_went_in() {
        let home = machine();
        let out = tempfile::tempdir().unwrap();
        let (paths, registry, vault, clients) = exporter_parts(home.path());
        let payload = Exporter {
            paths: &paths,
            registry: &registry,
            vault: &vault,
            clients: &clients,
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
