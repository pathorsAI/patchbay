//! The project env vault: the environment variables a *project* needs.
//!
//! [`crate::keys`] holds standalone credentials that belong to a person or a
//! machine. This module holds the other half of the same problem: the twenty
//! variables a repo needs before it will boot — `DATABASE_URL`, the provider
//! keys, the feature flags — which today live in a `.env` file that is
//! gitignored, undocumented, and different on every laptop.
//!
//! **A project is a name, not a path.** `~/.config/patchbay/projects.json`
//! holds ids, environments and sync config and *no absolute path at all*, so it
//! is the same file on every machine you work from. Which directories on *this*
//! machine belong to a project is a separate, machine-local list —
//! [`Attachment`], in `~/.config/patchbay/attachments.json` — because the same
//! repo lives somewhere else on the next laptop, and a manifest that hard-codes
//! `/Users/you/repos/x` is a manifest that cannot travel.
//!
//! One project may have several attached roots. Git worktrees are the case that
//! forces it: `repo/`, `repo/.worktrees/feature-a` and a second clone are the
//! same project and want the same environment, and asking the user to register
//! three projects would give them three vaults to keep in sync by hand.
//!
//! **A repo may also name its own project**, in a [`MARKER_FILE`] committed at
//! its root — one line, `project = "pathors"`. A checkout then resolves with no
//! attach step at all, which is what makes a fresh `git clone` on a new laptop
//! work. See [`EnvRegistry::find_by_dir`] for the precedence rule and the
//! tradeoff that buys.
//!
//! **Taking your environment to a new machine** is therefore: get
//! `projects.json` over — `pb export` carries it inside the bundle, or copy the
//! file by hand — and `pb env pull` to rebuild every synced layer from the
//! remote. Checkouts carrying a marker resolve on their own; anything else takes
//! one `pb env attach <id>`. The local layer deliberately does *not* travel.
//! `.env.local` semantics are per-machine overrides, and a `DATABASE_URL`
//! pointing at a container on the old laptop is exactly the thing that must not
//! follow you.
//!
//! **Two layers per environment**, and the split is the whole point:
//!
//! * `synced` — what the last pull took from the remote (Infisical). Replaced
//!   wholesale by the next pull, never hand-edited.
//! * `local` — what this machine sets by hand. Never pushed anywhere, never
//!   touched by a pull, and it *wins* on merge. These are `.env.local`
//!   semantics: pointing `DATABASE_URL` at a container on your own machine has
//!   to survive every `pull`, or nobody will trust `pull`.
//!
//! patchbay **never pushes**. There is no code path in this crate that writes a
//! variable to a remote secret manager, deliberately: a tool that can silently
//! promote a local experiment into the team's shared `production` set is a tool
//! nobody should run.
//!
//! **The storage split** mirrors the key vault. Variable *names* and where they
//! came from live in `projects.json` — readable, greppable,
//! worthless to an attacker. *Values* live in the OS keychain behind
//! [`Keystore`], one item per (project, environment, layer), holding a compact
//! JSON object of the whole layer. One keychain round trip per export rather
//! than one per variable, which is what makes `pb env export` fast enough to
//! put in a shell hook.
//!
//! No `last4` is recorded for an env var, unlike a key: half of these values
//! are `true`, `5432` or `postgres`, and four characters of a five-character
//! value is not a hint, it is the value.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::keys::validate_slug;
use crate::keystore::{Keystore, SecurityCliKeystore};
use crate::paths::Paths;

/// Schema version of `projects.json`. Bump on an incompatible change.
pub const PROJECTS_FILE_VERSION: u32 = 1;

/// Schema version of `attachments.json`. Bump on an incompatible change.
///
/// Versioned separately from [`PROJECTS_FILE_VERSION`] on purpose: the two
/// files have different lifetimes. One is copied between machines, the other is
/// rebuilt on each.
pub const ATTACHMENTS_FILE_VERSION: u32 = 1;

/// The environment a project uses when nobody says which.
pub const DEFAULT_ENV: &str = "dev";

/// The file a repo commits to name its own project: `project = "<id>"` at a
/// directory root. See [`read_marker`] and [`EnvRegistry::find_by_dir`].
pub const MARKER_FILE: &str = ".patchbay.toml";

// ---------------------------------------------------------------------------
// validation
// ---------------------------------------------------------------------------

/// Project ids are lowercase slugs, exactly like key ids — they end up inside a
/// keychain account string, and they are what a human types on the CLI.
pub fn validate_project_id(id: &str) -> anyhow::Result<()> {
    validate_slug("project id", id)
}

/// Environment names follow the same rules: `dev`, `staging`, `production`.
/// The remote's own spelling can differ — that is what
/// [`SyncConfig::env_map`] is for.
pub fn validate_env_name(env: &str) -> anyhow::Result<()> {
    validate_slug("environment name", env)
}

/// `[A-Za-z_][A-Za-z0-9_]*` — what a POSIX shell will actually export. A name
/// outside this set cannot be set by `export` at all, so accepting it would
/// mean storing something no consumer of the vault could ever use.
pub fn validate_var_name(name: &str) -> anyhow::Result<()> {
    let Some(first) = name.chars().next() else {
        anyhow::bail!("an environment variable name cannot be empty");
    };
    if !(first.is_ascii_alphabetic() || first == '_') {
        anyhow::bail!(
            "`{name}` is not a usable environment variable name: it must start with a letter \
             or `_`"
        );
    }
    if let Some(bad) = name
        .chars()
        .find(|c| !(c.is_ascii_alphanumeric() || *c == '_'))
    {
        anyhow::bail!(
            "environment variable name `{name}` contains `{bad}`; use letters, digits and `_`"
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// model
// ---------------------------------------------------------------------------

/// Which of an environment's two layers a value belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnvLayer {
    /// Pulled from the remote. Replaced wholesale by the next pull.
    Synced,
    /// Set on this machine. Never leaves it.
    Local,
}

impl EnvLayer {
    /// Both layers, in merge order: synced first, local over it.
    pub const BOTH: [EnvLayer; 2] = [EnvLayer::Synced, EnvLayer::Local];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Synced => "synced",
            Self::Local => "local",
        }
    }
}

/// The keychain account one layer's values are filed under:
/// `env:<project>/<env>/<synced|local>`.
///
/// The `env:` prefix keeps this namespace clear of the key vault, whose ids are
/// slugs and can therefore never contain `:` or `/`. Everything before the
/// value is metadata a human can read in Keychain Access, which is the point:
/// an item nobody can identify is an item nobody will ever clean up.
pub fn keychain_account(project: &str, env: &str, layer: EnvLayer) -> String {
    format!("env:{project}/{env}/{}", layer.as_str())
}

/// One environment of one project. **Names only** — no values, and no `last4`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct EnvMeta {
    /// Names present in the synced layer, sorted.
    #[serde(default)]
    pub synced_names: Vec<String>,
    /// Names present in the local layer, sorted.
    #[serde(default)]
    pub local_names: Vec<String>,
    /// When the synced layer was last replaced. `null` until the first pull —
    /// an environment can exist with local values alone.
    #[serde(default)]
    pub synced_at: Option<DateTime<Utc>>,
}

/// Where a project's synced layer comes from.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SyncConfig {
    /// `"infisical"` — the only provider today, and validated as such.
    pub provider: String,
    /// The remote's own project identifier (a UUID, for Infisical).
    pub project_id: String,
    /// The account the pull must run as. The infisical CLI's active user is
    /// machine-global, so recording this is what lets a pull refuse rather than
    /// fail confusingly under somebody else's login.
    pub account: String,
    /// The API base URL, for self-hosted or EU instances. Absent means the
    /// CLI's own default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    /// patchbay environment name → the remote's slug, for the projects whose
    /// remote calls `production` something else. A name that is absent maps to
    /// itself.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub env_map: BTreeMap<String, String>,
}

impl SyncConfig {
    /// The remote's slug for a patchbay environment name.
    pub fn remote_env(&self, env: &str) -> String {
        self.env_map
            .get(env)
            .cloned()
            .unwrap_or_else(|| env.to_string())
    }
}

/// One registered project.
///
/// **Portable by construction**: not one field here is a path, which is what
/// makes `projects.json` a file you can copy to another machine. Where the
/// project lives *here* is an [`Attachment`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProjectEntry {
    /// Slug, unique across the registry, e.g. `"pathors"`.
    pub id: String,
    /// Which environment `pb env` uses when the command does not say.
    pub default_env: String,
    pub created_at: DateTime<Utc>,
    /// Environments, by name. Created implicitly by the first write.
    #[serde(default)]
    pub environments: BTreeMap<String, EnvMeta>,
    /// Where the synced layer comes from; absent until the project is linked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sync: Option<SyncConfig>,
}

impl ProjectEntry {
    pub fn env(&self, env: &str) -> Option<&EnvMeta> {
        self.environments.get(env)
    }

    /// Environment names, sorted (the map is a `BTreeMap`).
    pub fn env_names(&self) -> Vec<&str> {
        self.environments.keys().map(String::as_str).collect()
    }
}

/// Where one variable in one environment comes from. The fast path: derived
/// from the two name lists alone, with no keychain access.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnvVarSource {
    /// Pulled, and not overridden here.
    Synced,
    /// Set here, and not present in the synced layer.
    Local,
    /// Set here *and* pulled: the local value is what gets exported.
    LocalOverride,
}

impl EnvVarSource {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Synced => "synced",
            Self::Local => "local",
            Self::LocalOverride => "local override",
        }
    }
}

/// One variable, named but not valued.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EnvVarInfo {
    pub name: String,
    pub source: EnvVarSource,
}

/// An environment's two layers, merged. **Holds values**, which is why it
/// derives nothing: no `Serialize` that could put it in an MCP response by
/// accident, and no `Debug` that could put it in a log line. Callers render it
/// deliberately, field by field.
pub struct MergedEnv {
    /// The variables as a consumer would see them: local over synced.
    pub vars: BTreeMap<String, String>,
    /// Names that came from the synced layer, sorted.
    pub from_synced: Vec<String>,
    /// Names that came from the local layer, sorted.
    pub from_local: Vec<String>,
    /// Names in both — the local value won. Sorted.
    pub overridden: Vec<String>,
}

/// One directory on **this machine** that belongs to a project.
///
/// The mental model is a symlink: the directory is pointed at a project that is
/// managed centrally, and the project itself knows nothing about it. Several
/// roots may point at one project (worktrees, a second clone); one root points
/// at exactly one project.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Attachment {
    /// The directory, as the caller gave it — absolute, in practice.
    pub root: PathBuf,
    /// The project id it resolves to. May name a project that no longer
    /// exists; see [`EnvRegistry::find_by_dir`].
    pub project: String,
}

/// On-disk shape of [`MARKER_FILE`]. Deliberately not `deny_unknown_fields`:
/// keys patchbay does not know yet are room for a later version to use without
/// making today's builds reject a repo they could otherwise resolve.
#[derive(Debug, Deserialize)]
struct MarkerToml {
    project: String,
}

/// On-disk shape of `projects.json`.
#[derive(Debug, Serialize, Deserialize)]
struct ProjectsFile {
    version: u32,
    projects: Vec<ProjectEntry>,
}

/// On-disk shape of `attachments.json`. Machine-local, and never part of any
/// migration or export story — see [`crate::paths::Paths::attachments_file`].
#[derive(Debug, Serialize, Deserialize)]
struct AttachmentsFile {
    version: u32,
    attachments: Vec<Attachment>,
}

// ---------------------------------------------------------------------------
// the marker file
// ---------------------------------------------------------------------------

/// The project a directory's own [`MARKER_FILE`] names, if it has one.
///
/// The file is TOML with exactly one key that means anything —
/// `project = "pathors"` — validated as a project id, because a marker that
/// names something no registry could ever hold is a typo, not a claim.
///
/// A **missing** file is `Ok(None)`: most directories have none, and that is
/// the normal case, not a failure. A file that is *present* and unreadable —
/// broken TOML, no `project` key, an id that is not a slug — is an error naming
/// the file. Somebody committed that marker on purpose and every checkout of
/// that repo will hit it; failing loudly once is cheaper than every clone
/// silently resolving to nothing.
pub fn read_marker(dir: &Path) -> anyhow::Result<Option<String>> {
    let path = dir.join(MARKER_FILE);
    let Some(text) = read_text(&path)? else {
        return Ok(None);
    };
    let marker: MarkerToml = toml::from_str(&text).map_err(|e| {
        anyhow::anyhow!(
            "{} is not a readable patchbay marker: {e}; it holds one key, `project = \"<id>\"`",
            path.display()
        )
    })?;
    validate_project_id(&marker.project)
        .map_err(|e| anyhow::anyhow!("{} names an unusable project: {e}", path.display()))?;
    Ok(Some(marker.project))
}

/// Write the [`MARKER_FILE`] that makes `dir` resolve to `project_id` in any
/// checkout, and return the path written.
///
/// A plain write with default permissions, unlike everything else this module
/// touches: the file holds a project *name*, it is meant to be committed, and a
/// `0600` file in a repo would only confuse the next person to `ls -l` it.
///
/// Idempotent when the marker already names this project — the file is left
/// exactly as it is, so a comment or a future key somebody added survives.
/// Re-pointing an existing marker at a **different** project is refused: that is
/// a change to what every checkout of the repo resolves to, and it should be a
/// deliberate edit rather than the side effect of running a command in the wrong
/// directory.
pub fn write_marker(dir: &Path, project_id: &str) -> anyhow::Result<PathBuf> {
    validate_project_id(project_id)?;
    let path = dir.join(MARKER_FILE);

    if let Some(existing) = read_marker(dir)? {
        if existing == project_id {
            return Ok(path);
        }
        anyhow::bail!(
            "{} already names project `{existing}`, not `{project_id}`; delete it first if the \
             repo should change hands, or bind this directory alone with `pb env attach \
             {project_id}` (an attachment beats the marker and stays on this machine)",
            path.display()
        );
    }

    let body = format!(
        "# patchbay project marker — commit this file.\n\
         # Every checkout of this repo resolves to this project's environments on a\n\
         # machine whose registry holds it (`pb env projects`).\n\
         project = \"{project_id}\"\n"
    );
    std::fs::write(&path, body)
        .map_err(|e| anyhow::anyhow!("could not write {}: {e}", path.display()))?;
    Ok(path)
}

// ---------------------------------------------------------------------------
// registry
// ---------------------------------------------------------------------------

/// The env vault: a portable metadata file, a machine-local attachment file,
/// and a [`Keystore`] for the values.
///
/// Stateless between calls, like [`crate::keys::KeyRegistry`]: the files are
/// re-read on every operation, so a pull from the CLI is immediately visible to
/// a running MCP server.
pub struct EnvRegistry {
    path: PathBuf,
    attachments_path: PathBuf,
    store: Box<dyn Keystore>,
}

impl EnvRegistry {
    /// Bind to explicit file locations and a keystore. Tests use this with a
    /// tempdir and [`crate::keystore::MemoryKeystore`].
    pub fn new(
        path: impl Into<PathBuf>,
        attachments_path: impl Into<PathBuf>,
        store: Box<dyn Keystore>,
    ) -> Self {
        Self {
            path: path.into(),
            attachments_path: attachments_path.into(),
            store,
        }
    }

    /// Bind to the locations [`Paths`] reports, with the given keystore.
    pub fn with_paths(paths: &Paths, store: Box<dyn Keystore>) -> Self {
        Self::new(paths.projects_file(), paths.attachments_file(), store)
    }

    /// The real vault on this machine: `~/.config/patchbay/projects.json`,
    /// `~/.config/patchbay/attachments.json` and the macOS Keychain.
    pub fn detect() -> anyhow::Result<Self> {
        let paths = Paths::detect()?;
        Ok(Self::with_paths(
            &paths,
            Box::new(SecurityCliKeystore::new()),
        ))
    }

    /// The portable project manifest.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The machine-local attachment list.
    pub fn attachments_path(&self) -> &Path {
        &self.attachments_path
    }

    pub fn store_name(&self) -> &'static str {
        self.store.describe()
    }

    // --- reads --------------------------------------------------------------

    /// Every registered project, oldest registration first. A missing file is
    /// an empty vault, not an error.
    pub fn projects(&self) -> anyhow::Result<Vec<ProjectEntry>> {
        Ok(self.load()?.projects)
    }

    /// One project, or `None` when nothing is registered under that id.
    pub fn get(&self, id: &str) -> anyhow::Result<Option<ProjectEntry>> {
        Ok(self.projects()?.into_iter().find(|p| p.id == id))
    }

    /// Every attachment on this machine, sorted by root.
    pub fn attachments(&self) -> anyhow::Result<Vec<Attachment>> {
        Ok(self.load_attachments()?.attachments)
    }

    /// The directories on this machine attached to one project, sorted.
    ///
    /// Empty is a normal answer: a project copied over with `projects.json` has
    /// no attachment here until somebody makes one.
    pub fn attachments_of(&self, project_id: &str) -> anyhow::Result<Vec<PathBuf>> {
        Ok(self
            .attachments()?
            .into_iter()
            .filter(|a| a.project == project_id)
            .map(|a| a.root)
            .collect())
    }

    /// The project `dir` belongs to, by two routes in a fixed order.
    ///
    /// 1. **An attachment.** The project whose attached root is `dir` or an
    ///    ancestor of it. When several match — a repo attached inside an
    ///    attached monorepo — the deepest root wins, because that is the more
    ///    specific answer. A match here ends the search.
    /// 2. **A committed [`MARKER_FILE`]**, looked for in `dir` and then up
    ///    through its ancestors; the nearest one wins, for the same
    ///    specific-beats-general reason.
    ///
    /// Both comparisons are pure path prefixes, with no canonicalization:
    /// resolving symlinks here would mean the answer depends on the
    /// filesystem's mood, and `/tmp` on macOS is itself a symlink. A checkout
    /// reached through a symlinked path therefore will not match an
    /// attachment — pass `--project` there, or commit a marker, which is found
    /// by walking up from whatever path the caller actually used.
    ///
    /// # Why an attachment beats a marker
    ///
    /// An attachment is a deliberate, local act: somebody stood in that
    /// directory and said which project it belongs to. A marker is whatever the
    /// repo happens to ship. When the two disagree the person at the keyboard
    /// wins, so `pb env attach` is always the way to override a marker — and
    /// nothing a repo can contain takes that override away.
    ///
    /// # The tradeoff the marker buys, stated plainly
    ///
    /// Resolving by repo content means **repo content selects the project**:
    /// cloning a repository whose marker names `pathors` is enough to make
    /// `pb env run` inject that project's variables there. This is accepted
    /// deliberately, on the assumption that the repos on this machine are
    /// internal ones. Two things bound it: a marker can only *name* a project
    /// that already exists in this machine's own `projects.json` — it cannot
    /// define sync config, an account, or anything else — and an explicit
    /// attachment always wins. Somebody who works from untrusted checkouts
    /// should not commit markers and should attach instead.
    ///
    /// A **dangling** attachment — one whose project has since been forgotten —
    /// is skipped rather than fatal, and the next-deepest match is considered.
    /// [`EnvRegistry::forget`] is what stops them accumulating; this is only the
    /// belt to that pair of braces, because `projects.json` can also be
    /// hand-edited or replaced wholesale by a copy from another machine.
    ///
    /// A marker naming an unknown project is **not** treated the same way. It
    /// is an error, because it is an explicit claim rather than leftover state:
    /// the fix is to bring the registry over from the machine that has that
    /// project, and "the clone worked but `pb env` sees nothing here" hides
    /// exactly that.
    pub fn find_by_dir(&self, dir: &Path) -> anyhow::Result<Option<ProjectEntry>> {
        let projects = self.projects()?;

        let mut matches: Vec<Attachment> = self
            .attachments()?
            .into_iter()
            .filter(|a| dir.starts_with(&a.root))
            .collect();
        // Deepest first, so the first attachment with a live project wins.
        matches.sort_by_key(|a| std::cmp::Reverse(a.root.components().count()));
        if let Some(attached) = matches
            .into_iter()
            .find_map(|a| projects.iter().find(|p| p.id == a.project).cloned())
        {
            return Ok(Some(attached));
        }

        // Nothing on this machine claims the directory. What does the repo say?
        for ancestor in dir.ancestors() {
            let Some(claimed) = read_marker(ancestor)? else {
                continue;
            };
            return match projects.iter().find(|p| p.id == claimed) {
                Some(project) => Ok(Some(project.clone())),
                None => Err(anyhow::anyhow!(
                    "{} names project `{claimed}`, but this machine's registry has no project \
                     `{claimed}`; copy your projects.json from the machine that has it, or \
                     register it here with `pb env init --id {claimed}`",
                    ancestor.join(MARKER_FILE).display()
                )),
            };
        }
        Ok(None)
    }

    /// Every variable name in one environment and where it comes from.
    ///
    /// **Metadata only** — this never touches the keychain, which is what makes
    /// it safe to call on every prompt render.
    pub fn list(&self, project_id: &str, env: &str) -> anyhow::Result<Vec<EnvVarInfo>> {
        let project = self.require(project_id)?;
        let meta = project
            .env(env)
            .ok_or_else(|| unknown_env(&project, env))?
            .clone();

        let mut out: Vec<EnvVarInfo> = Vec::new();
        for name in &meta.synced_names {
            let source = if meta.local_names.contains(name) {
                EnvVarSource::LocalOverride
            } else {
                EnvVarSource::Synced
            };
            out.push(EnvVarInfo {
                name: name.clone(),
                source,
            });
        }
        for name in &meta.local_names {
            if meta.synced_names.contains(name) {
                continue;
            }
            out.push(EnvVarInfo {
                name: name.clone(),
                source: EnvVarSource::Local,
            });
        }
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }

    /// The environment as a consumer would see it: both layers read from the
    /// keychain, local over synced.
    ///
    /// The **only** method that returns values. Every caller is expected to
    /// gate it the way the key vault gates `get_secret`.
    pub fn merged(&self, project_id: &str, env: &str) -> anyhow::Result<MergedEnv> {
        let project = self.require(project_id)?;
        project.env(env).ok_or_else(|| unknown_env(&project, env))?;

        let synced = self.read_blob(&keychain_account(project_id, env, EnvLayer::Synced))?;
        let local = self.read_blob(&keychain_account(project_id, env, EnvLayer::Local))?;

        let from_synced: Vec<String> = synced.keys().cloned().collect();
        let from_local: Vec<String> = local.keys().cloned().collect();
        let overridden: Vec<String> = from_local
            .iter()
            .filter(|name| synced.contains_key(*name))
            .cloned()
            .collect();

        let mut vars = synced;
        for (name, value) in local {
            vars.insert(name, value);
        }

        Ok(MergedEnv {
            vars,
            from_synced,
            from_local,
            overridden,
        })
    }

    // --- writes -------------------------------------------------------------

    /// Register a project — a name and a default environment, nothing more.
    ///
    /// No directory is involved: point one at it with [`EnvRegistry::attach`].
    /// No keychain item is created either — an environment appears on the first
    /// write to it.
    pub fn register(&self, id: &str, default_env: &str) -> anyhow::Result<ProjectEntry> {
        validate_project_id(id)?;
        validate_env_name(default_env)?;

        let mut file = self.load()?;
        if file.projects.iter().any(|p| p.id == id) {
            anyhow::bail!(
                "a project is already registered as `{id}`; pick another id, attach this \
                 directory to it with `pb env attach {id}`, or remove it with `pb env forget \
                 --project {id}`"
            );
        }

        let entry = ProjectEntry {
            id: id.to_string(),
            default_env: default_env.to_string(),
            created_at: Utc::now(),
            environments: BTreeMap::new(),
            sync: None,
        };
        file.projects.push(entry.clone());
        self.save(&file)?;
        Ok(entry)
    }

    /// Take a project entry exactly as another machine had it — the write path
    /// [`crate::migrate::import`] uses, and the only one that sets
    /// `environments` and `sync` wholesale.
    ///
    /// [`EnvRegistry::register`] is the interactive route and is deliberately
    /// narrow: an id and a default environment, because everything else is
    /// earned by a later command. A migration bundle carries a project as a
    /// *record* instead, so restoring one is a single write rather than a
    /// replay of the commands that built it.
    ///
    /// **An id that already exists is refused**, and the caller reports the
    /// skip. The destination may be the newer machine, and quietly replacing
    /// its sync pin or its environment list with a copy from a bundle is not
    /// something an import gets to do behind the user's back.
    ///
    /// **Every environment's `local_names` is cleared on the way in**, whatever
    /// the caller passed. No local *value* can travel — the local layer is
    /// per-machine overrides by definition — and a name list with no values
    /// behind it would make `pb env list` claim variables `pb env run` could
    /// never inject. The exporter drops them too; this is the half that holds
    /// even for a bundle patchbay did not write.
    ///
    /// No keychain item is created either. An environment's values arrive from
    /// `pb env pull`, or they do not arrive.
    pub fn adopt(&self, entry: &ProjectEntry) -> anyhow::Result<ProjectEntry> {
        validate_project_id(&entry.id)?;
        validate_env_name(&entry.default_env)?;
        for (name, meta) in &entry.environments {
            validate_env_name(name)?;
            for var in &meta.synced_names {
                validate_var_name(var)?;
            }
        }

        let mut file = self.load()?;
        if file.projects.iter().any(|p| p.id == entry.id) {
            anyhow::bail!(
                "a project is already registered as `{}` on this machine; it was left exactly as \
                 it is",
                entry.id
            );
        }

        let mut entry = entry.clone();
        for meta in entry.environments.values_mut() {
            meta.local_names.clear();
        }
        file.projects.push(entry.clone());
        self.save(&file)?;
        Ok(entry)
    }

    /// Attach a directory on this machine to a project.
    ///
    /// `root` is stored exactly as given — callers pass an absolute path, and
    /// nothing here canonicalizes or resolves symlinks, for the reason
    /// [`EnvRegistry::find_by_dir`] gives.
    ///
    /// Re-attaching a root to the project it already has is a no-op that
    /// succeeds, so `pb env attach` is safe to put in a setup script.
    /// Re-pointing it at a *different* project is refused: silently moving a
    /// directory between vaults would change what `pb env run` injects there,
    /// which is not something a stray command should be able to do.
    ///
    /// # Why this is an explicit, machine-local act
    ///
    /// The other route to the same answer is a [`MARKER_FILE`] committed in the
    /// repo, and it is the one that makes a fresh clone work. An attachment is
    /// the heavier instrument on purpose: it lives outside every repository, in
    /// the user's own registry, and it **beats the marker** — so a directory
    /// whose repo claims the wrong project, or none, can always be pointed
    /// somewhere by hand, and no repo can take that back. See
    /// [`EnvRegistry::find_by_dir`] for the full precedence rule.
    pub fn attach(&self, root: impl Into<PathBuf>, project_id: &str) -> anyhow::Result<Attachment> {
        let root = root.into();
        if self.get(project_id)?.is_none() {
            anyhow::bail!(
                "no project registered as `{project_id}`; register one with `pb env init --id \
                 {project_id}`, or see what exists with `pb env projects`"
            );
        }

        let mut file = self.load_attachments()?;
        if let Some(existing) = file.attachments.iter().find(|a| a.root == root) {
            if existing.project == project_id {
                // Idempotent: nothing is written, so the file's mtime does not
                // move either.
                return Ok(existing.clone());
            }
            anyhow::bail!(
                "{} is already attached to project `{}`, not `{project_id}`; detach it first \
                 (`pb env detach --dir {}`) if you meant to move it",
                root.display(),
                existing.project,
                root.display()
            );
        }

        let attachment = Attachment {
            root,
            project: project_id.to_string(),
        };
        file.attachments.push(attachment.clone());
        self.save_attachments(&mut file)?;
        Ok(attachment)
    }

    /// Detach a directory. The project, its environments and its values are
    /// untouched — this only forgets that *this machine* maps that path.
    pub fn detach(&self, root: &Path) -> anyhow::Result<Attachment> {
        let mut file = self.load_attachments()?;
        let at = file
            .attachments
            .iter()
            .position(|a| a.root == root)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "nothing is attached at {}; `pb env projects` shows this machine's \
                     attachments",
                    root.display()
                )
            })?;
        let removed = file.attachments.remove(at);
        self.save_attachments(&mut file)?;
        Ok(removed)
    }

    /// Point a project at a remote, replacing whatever it was linked to.
    pub fn set_sync(&self, id: &str, sync: SyncConfig) -> anyhow::Result<ProjectEntry> {
        if sync.provider != "infisical" {
            anyhow::bail!(
                "`{}` is not a sync provider patchbay knows; the only one today is `infisical`",
                sync.provider
            );
        }
        for env in sync.env_map.keys() {
            validate_env_name(env)?;
        }

        let mut file = self.load()?;
        let project = project_mut(&mut file, id)?;
        project.sync = Some(sync);
        let updated = project.clone();
        self.save(&file)?;
        Ok(updated)
    }

    /// Unregister a project: this machine's attachments to it, the metadata
    /// entry, and every stored value for every environment, both layers.
    ///
    /// **Attachments go first.** They are machine-local convenience state, so
    /// losing them costs an `attach`; what must not survive is an attachment
    /// pointing at a project that no longer exists. Taking them first also
    /// keeps every failure path re-runnable: if a keychain delete then fails,
    /// the project entry is restored and `pb env forget` can simply be run
    /// again, whereas removing them last would leave a dangling attachment that
    /// no `forget` could ever reach.
    ///
    /// Metadata then keychain, with the same both-or-neither rule as the key
    /// vault. A value that is already absent is not an error — that is what
    /// [`Keystore::delete`] returning `Ok(false)` is for.
    pub fn forget(&self, id: &str) -> anyhow::Result<ProjectEntry> {
        let mut file = self.load()?;
        let at = file
            .projects
            .iter()
            .position(|p| p.id == id)
            .ok_or_else(|| unknown_project(id))?;
        let entry = file.projects.remove(at);

        let mut attachments = self.load_attachments()?;
        if attachments.attachments.iter().any(|a| a.project == id) {
            attachments.attachments.retain(|a| a.project != id);
            self.save_attachments(&mut attachments)?;
        }

        let previous = self.read_raw()?;
        self.save(&file)?;
        for env in entry.environments.keys() {
            for layer in EnvLayer::BOTH {
                let account = keychain_account(&entry.id, env, layer);
                if let Err(e) = self.store.delete(&account) {
                    // Earlier layers may already be gone. Restoring the metadata
                    // is still the right move: a registry entry whose values are
                    // missing can be re-pulled or re-set, whereas a keychain item
                    // nothing points at can only be found by hand.
                    self.restore(previous.as_deref())?;
                    return Err(e.context(format!(
                        "could not delete the stored {} values for `{id}/{env}`; the project was \
                         kept — remove the leftover keychain items by hand, or try again",
                        layer.as_str()
                    )));
                }
            }
        }
        Ok(entry)
    }

    /// Set one variable in the local layer, creating the environment if this is
    /// its first value.
    pub fn set_local(
        &self,
        project_id: &str,
        env: &str,
        name: &str,
        value: &str,
    ) -> anyhow::Result<()> {
        validate_env_name(env)?;
        validate_var_name(name)?;

        let account = keychain_account(project_id, env, EnvLayer::Local);
        let mut file = self.load()?;
        {
            let project = project_mut(&mut file, project_id)?;
            let meta = project.environments.entry(env.to_string()).or_default();
            insert_name(&mut meta.local_names, name);
        }
        let mut vars = self.read_blob(&account)?;
        vars.insert(name.to_string(), value.to_string());

        self.commit_layer(
            &file,
            &account,
            &vars,
            &format!("the local values of `{project_id}/{env}`"),
        )
    }

    /// Remove one variable from the local layer.
    ///
    /// Returns the note the caller should show, if any: when the same name is
    /// also in the synced layer, dropping the override does not remove the
    /// variable — it un-shadows the pulled value, and a user who is not told
    /// that will assume the variable is gone.
    pub fn unset_local(
        &self,
        project_id: &str,
        env: &str,
        name: &str,
    ) -> anyhow::Result<Option<String>> {
        validate_env_name(env)?;

        let account = keychain_account(project_id, env, EnvLayer::Local);
        let mut file = self.load()?;
        let note;
        {
            let project = project_mut(&mut file, project_id)?;
            let project_id = project.id.clone();
            let known: Vec<String> = project.environments.keys().cloned().collect();
            let meta = project.environments.get_mut(env).ok_or_else(|| {
                let known: Vec<&str> = known.iter().map(String::as_str).collect();
                unknown_env_named(&project_id, env, &known)
            })?;

            let Some(at) = meta.local_names.iter().position(|n| n == name) else {
                if meta.synced_names.iter().any(|n| n == name) {
                    anyhow::bail!(
                        "`{name}` in `{project_id}/{env}` comes from the synced layer, so there \
                         is no local override to remove; patchbay never pushes, so a pulled \
                         variable can only go away by disappearing from the remote and being \
                         pulled again"
                    );
                }
                anyhow::bail!(
                    "`{name}` is not set in the local layer of `{project_id}/{env}`; \
                     `pb env list --project {project_id} --env {env}` shows what is"
                );
            };
            meta.local_names.remove(at);
            note = meta.synced_names.iter().any(|n| n == name).then(|| {
                format!(
                    "`{name}` is still set by the synced layer of `{project_id}/{env}`; the \
                     pulled value is in effect again"
                )
            });
        }

        let mut vars = self.read_blob(&account)?;
        vars.remove(name);
        self.commit_layer(
            &file,
            &account,
            &vars,
            &format!("the local values of `{project_id}/{env}`"),
        )?;
        Ok(note)
    }

    /// Merge a batch of variables into the local layer. Returns how many
    /// landed.
    ///
    /// Every name is validated **before** anything is written: half an imported
    /// `.env` is worse than none, because the failure is silent at the point it
    /// matters — three commands later, when something reads a variable that was
    /// never stored.
    pub fn import_local(
        &self,
        project_id: &str,
        env: &str,
        vars: &[(String, String)],
    ) -> anyhow::Result<usize> {
        validate_env_name(env)?;
        for (name, _) in vars {
            validate_var_name(name)?;
        }
        if vars.is_empty() {
            // Nothing to store, and no reason to create an environment.
            return Ok(0);
        }

        let account = keychain_account(project_id, env, EnvLayer::Local);
        let mut file = self.load()?;
        {
            let project = project_mut(&mut file, project_id)?;
            let meta = project.environments.entry(env.to_string()).or_default();
            for (name, _) in vars {
                insert_name(&mut meta.local_names, name);
            }
        }
        let mut stored = self.read_blob(&account)?;
        for (name, value) in vars {
            stored.insert(name.clone(), value.clone());
        }

        self.commit_layer(
            &file,
            &account,
            &stored,
            &format!("the local values of `{project_id}/{env}`"),
        )?;
        Ok(vars.len())
    }

    /// Replace the synced layer wholesale. Called by [`crate::env_sync`] and
    /// nowhere else.
    ///
    /// Wholesale is the point: a variable deleted on the remote has to
    /// disappear here too, and a merge would keep it forever. The local layer
    /// is not read, not written, and not consulted.
    pub fn replace_synced(
        &self,
        project_id: &str,
        env: &str,
        vars: BTreeMap<String, String>,
        synced_at: DateTime<Utc>,
    ) -> anyhow::Result<()> {
        validate_env_name(env)?;
        for name in vars.keys() {
            validate_var_name(name)?;
        }

        let account = keychain_account(project_id, env, EnvLayer::Synced);
        let mut file = self.load()?;
        {
            let project = project_mut(&mut file, project_id)?;
            let meta = project.environments.entry(env.to_string()).or_default();
            meta.synced_names = vars.keys().cloned().collect();
            meta.synced_at = Some(synced_at);
        }
        self.commit_layer(
            &file,
            &account,
            &vars,
            &format!("the synced values of `{project_id}/{env}`"),
        )
    }

    // --- keychain plumbing --------------------------------------------------

    /// One layer's values. An absent item is an empty layer, not an error: a
    /// pull that returned nothing and an environment that has never been pulled
    /// look the same from here, and both are fine.
    fn read_blob(&self, account: &str) -> anyhow::Result<BTreeMap<String, String>> {
        let Some(raw) = self.store.get(account)? else {
            return Ok(BTreeMap::new());
        };
        serde_json::from_str(&raw).map_err(|e| {
            anyhow::anyhow!(
                "the {} item `{account}` is not a patchbay env set ({e}); delete that item and \
                 pull the environment again (`pb env pull`) or re-set its local values \
                 (`pb env set`)",
                self.store.describe()
            )
        })
    }

    /// Write metadata and one layer's blob: both or neither.
    ///
    /// The metadata file goes first and is restored byte-for-byte if the
    /// keystore refuses, so the registry can never claim a variable whose value
    /// was never stored.
    fn commit_layer(
        &self,
        file: &ProjectsFile,
        account: &str,
        vars: &BTreeMap<String, String>,
        what: &str,
    ) -> anyhow::Result<()> {
        // Compact: this is machine-read, and a pretty-printed blob would triple
        // the size of a keychain item for nobody's benefit.
        let body = serde_json::to_string(vars)?;

        let previous = self.read_raw()?;
        self.save(file)?;
        if let Err(e) = self.store.put(account, &body) {
            self.restore(previous.as_deref()).map_err(|restore_err| {
                anyhow::anyhow!(
                    "{e}; AND the metadata rollback failed: {restore_err}. {} may now disagree \
                     with the {} about {what}",
                    self.path.display(),
                    self.store.describe()
                )
            })?;
            return Err(e.context(format!(
                "could not store {what}; metadata rolled back, nothing changed"
            )));
        }
        Ok(())
    }

    fn require(&self, id: &str) -> anyhow::Result<ProjectEntry> {
        self.get(id)?.ok_or_else(|| unknown_project(id))
    }

    // --- file plumbing ------------------------------------------------------

    fn read_raw(&self) -> anyhow::Result<Option<String>> {
        read_text(&self.path)
    }

    fn load(&self) -> anyhow::Result<ProjectsFile> {
        let empty = || ProjectsFile {
            version: PROJECTS_FILE_VERSION,
            projects: Vec::new(),
        };
        let Some(text) = self.read_raw()? else {
            return Ok(empty());
        };
        if text.trim().is_empty() {
            return Ok(empty());
        }
        // A malformed registry is a hard error, not an empty one: starting over
        // silently would let the next write drop every project on the machine,
        // and the keychain items behind them would be orphaned with it.
        let file: ProjectsFile = serde_json::from_str(&text).map_err(|e| {
            anyhow::anyhow!(
                "{} is not a readable patchbay project registry: {e}",
                self.path.display()
            )
        })?;
        if file.version > PROJECTS_FILE_VERSION {
            anyhow::bail!(
                "{} was written by a newer patchbay (file version {}, this build understands {}); \
                 upgrade rather than risk rewriting it",
                self.path.display(),
                file.version,
                PROJECTS_FILE_VERSION
            );
        }
        Ok(file)
    }

    /// Write the registry atomically: temp file in the same directory, `0600`,
    /// then rename over the target.
    fn save(&self, file: &ProjectsFile) -> anyhow::Result<()> {
        let body = serde_json::to_string_pretty(&ProjectsFile {
            version: PROJECTS_FILE_VERSION,
            projects: file.projects.clone(),
        })?;
        write_atomic(&self.path, &body)
    }

    fn restore(&self, previous: Option<&str>) -> anyhow::Result<()> {
        match previous {
            Some(text) => write_atomic(&self.path, text),
            // There was no file before; removing it is the true rollback.
            None => match std::fs::remove_file(&self.path) {
                Ok(()) => Ok(()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(e) => Err(anyhow::anyhow!(
                    "could not remove {}: {e}",
                    self.path.display()
                )),
            },
        }
    }

    // --- the attachment file ------------------------------------------------
    // Same discipline as the project file: missing is empty, malformed is a
    // hard error naming the file, a newer version is refused rather than
    // rewritten.

    fn load_attachments(&self) -> anyhow::Result<AttachmentsFile> {
        let empty = || AttachmentsFile {
            version: ATTACHMENTS_FILE_VERSION,
            attachments: Vec::new(),
        };
        let Some(text) = read_text(&self.attachments_path)? else {
            return Ok(empty());
        };
        if text.trim().is_empty() {
            return Ok(empty());
        }
        let file: AttachmentsFile = serde_json::from_str(&text).map_err(|e| {
            anyhow::anyhow!(
                "{} is not a readable patchbay attachment list: {e}",
                self.attachments_path.display()
            )
        })?;
        if file.version > ATTACHMENTS_FILE_VERSION {
            anyhow::bail!(
                "{} was written by a newer patchbay (file version {}, this build understands {}); \
                 upgrade rather than risk rewriting it",
                self.attachments_path.display(),
                file.version,
                ATTACHMENTS_FILE_VERSION
            );
        }
        Ok(file)
    }

    /// Sorted by root, so a diff of this file between two moments shows what
    /// actually changed rather than what got appended.
    fn save_attachments(&self, file: &mut AttachmentsFile) -> anyhow::Result<()> {
        file.attachments.sort_by(|a, b| a.root.cmp(&b.root));
        let body = serde_json::to_string_pretty(&AttachmentsFile {
            version: ATTACHMENTS_FILE_VERSION,
            attachments: file.attachments.clone(),
        })?;
        write_atomic(&self.attachments_path, &body)
    }
}

// ---------------------------------------------------------------------------
// free functions
// ---------------------------------------------------------------------------

/// A file's text, or `None` when it does not exist yet.
fn read_text(path: &Path) -> anyhow::Result<Option<String>> {
    match std::fs::read_to_string(path) {
        Ok(text) => Ok(Some(text)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(anyhow::anyhow!("could not read {}: {e}", path.display())),
    }
}

/// Write one of the vault's files atomically: temp file in the same directory,
/// `0600`, then rename over the target.
fn write_atomic(path: &Path, body: &str) -> anyhow::Result<()> {
    let dir = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("{} has no parent directory", path.display()))?;
    std::fs::create_dir_all(dir)
        .map_err(|e| anyhow::anyhow!("could not create {}: {e}", dir.display()))?;

    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, body)
        .map_err(|e| anyhow::anyhow!("could not write {}: {e}", tmp.display()))?;
    // Variable names are not secret, and neither is a directory path — but
    // which of them a machine holds is nobody else's business.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| anyhow::anyhow!("could not chmod {}: {e}", tmp.display()))?;
    }
    std::fs::rename(&tmp, path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        anyhow::anyhow!("could not replace {}: {e}", path.display())
    })
}

fn project_mut<'a>(file: &'a mut ProjectsFile, id: &str) -> anyhow::Result<&'a mut ProjectEntry> {
    file.projects
        .iter_mut()
        .find(|p| p.id == id)
        .ok_or_else(|| unknown_project(id))
}

fn unknown_project(id: &str) -> anyhow::Error {
    anyhow::anyhow!("no project registered as `{id}`; register one with `pb env init --id {id}`")
}

fn unknown_env(project: &ProjectEntry, env: &str) -> anyhow::Error {
    unknown_env_named(&project.id, env, &project.env_names())
}

fn unknown_env_named(project_id: &str, env: &str, known: &[&str]) -> anyhow::Error {
    let known = if known.is_empty() {
        "it has none yet".to_string()
    } else {
        format!("it has {}", known.join(", "))
    };
    anyhow::anyhow!(
        "project `{project_id}` has no environment `{env}` ({known}); create one by setting a \
         value (`pb env set --project {project_id} --env {env} NAME` — the value is prompted \
         for, never an argument) or by pulling (`pb env pull --project {project_id} --env {env}`)"
    )
}

/// Add a name to a sorted, deduplicated name list.
fn insert_name(names: &mut Vec<String>, name: &str) {
    if let Err(at) = names.binary_search_by(|n| n.as_str().cmp(name)) {
        names.insert(at, name.to_string());
    }
}

// ---------------------------------------------------------------------------
// dotenv
// ---------------------------------------------------------------------------

/// Parse `.env` text into name/value pairs, in file order.
///
/// The dialect is the one everybody actually writes: `#` comments, blank lines,
/// an optional `export ` prefix, and values that are bare, single-quoted
/// (literal) or double-quoted (with `\n`, `\t`, `\r`, `\"` and `\\` escapes).
/// Adjacent quoted runs concatenate the way a shell would, which is what makes
/// the `'\''` idiom in [`render_dotenv`] round-trip.
///
/// A malformed line is an error naming the **line number and nothing else**: the
/// text of a line that failed to parse is, by definition, a string patchbay does
/// not understand — and the most likely thing it contains is a secret.
pub fn parse_dotenv(text: &str) -> anyhow::Result<Vec<(String, String)>> {
    let mut out = Vec::new();
    for (index, raw) in text.lines().enumerate() {
        let line_no = index + 1;
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line
            .strip_prefix("export ")
            .map(str::trim_start)
            .unwrap_or(line);

        let Some((name, rest)) = line.split_once('=') else {
            anyhow::bail!("line {line_no} is not `NAME=value`");
        };
        let name = name.trim();
        validate_var_name(name).map_err(|e| anyhow::anyhow!("line {line_no}: {e}"))?;
        out.push((name.to_string(), parse_dotenv_value(rest.trim(), line_no)?));
    }
    Ok(out)
}

fn parse_dotenv_value(raw: &str, line_no: usize) -> anyhow::Result<String> {
    // An unquoted value is the rest of the line, trimmed. `#` is *not* a comment
    // introducer here: `PASSWORD=hunter#2` is a password, not a truncated one.
    if !raw.starts_with('\'') && !raw.starts_with('"') {
        return Ok(raw.to_string());
    }

    let mut value = String::new();
    let mut chars = raw.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\'' => {
                let mut closed = false;
                for c in chars.by_ref() {
                    if c == '\'' {
                        closed = true;
                        break;
                    }
                    value.push(c);
                }
                if !closed {
                    anyhow::bail!("line {line_no} has an unterminated `'` quote");
                }
            }
            '"' => {
                let mut closed = false;
                while let Some(c) = chars.next() {
                    match c {
                        '"' => {
                            closed = true;
                            break;
                        }
                        '\\' => match chars.next() {
                            Some('n') => value.push('\n'),
                            Some('t') => value.push('\t'),
                            Some('r') => value.push('\r'),
                            Some('"') => value.push('"'),
                            Some('\\') => value.push('\\'),
                            // An escape patchbay does not define is left exactly
                            // as written: `\d` in a regex-shaped value means
                            // `\d`, and eating the backslash would corrupt it.
                            Some(other) => {
                                value.push('\\');
                                value.push(other);
                            }
                            None => break,
                        },
                        _ => value.push(c),
                    }
                }
                if !closed {
                    anyhow::bail!("line {line_no} has an unterminated `\"` quote");
                }
            }
            // A backslash outside quotes escapes the next character, which is
            // what makes `'a'\''b'` one value of `a'b`.
            '\\' => match chars.next() {
                Some(next) => value.push(next),
                None => value.push('\\'),
            },
            c if c.is_whitespace() => {
                let rest: String = chars.collect();
                let rest = rest.trim();
                if rest.is_empty() || rest.starts_with('#') {
                    return Ok(value);
                }
                anyhow::bail!("line {line_no} has trailing text after a quoted value");
            }
            '#' if value.is_empty() => return Ok(value),
            c => value.push(c),
        }
    }
    Ok(value)
}

/// Render variables as `.env` text: sorted, one `NAME='value'` per line, with a
/// trailing newline.
///
/// Single quotes, because they are the only shell quoting with no escapes
/// inside at all: an embedded `'` closes the string, emits an escaped one and
/// reopens it (`'\''`), and nothing else in the value can mean anything.
///
/// The exception is a value containing a newline, tab or carriage return, which
/// is written double-quoted with those characters escaped. A literal newline
/// inside single quotes is valid shell but would split the variable across two
/// lines, and every line-based reader of a `.env` file — including
/// [`parse_dotenv`] — would then read it wrong.
pub fn render_dotenv(vars: &BTreeMap<String, String>) -> String {
    let mut out = String::new();
    for (name, value) in vars {
        out.push_str(name);
        out.push('=');
        if value.contains(['\n', '\t', '\r']) {
            out.push('"');
            for c in value.chars() {
                match c {
                    '\n' => out.push_str("\\n"),
                    '\t' => out.push_str("\\t"),
                    '\r' => out.push_str("\\r"),
                    '"' => out.push_str("\\\""),
                    '\\' => out.push_str("\\\\"),
                    c => out.push(c),
                }
            }
            out.push('"');
        } else {
            out.push('\'');
            out.push_str(&value.replace('\'', r"'\''"));
            out.push('\'');
        }
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keystore::MemoryKeystore;
    use std::sync::Arc;

    /// A registry over a tempdir with a fake keystore. Nothing here touches the
    /// real `$HOME` or the real keychain.
    struct Vault {
        dir: tempfile::TempDir,
        registry: EnvRegistry,
        store: Arc<MemoryKeystore>,
    }

    /// `Box<dyn Keystore>` over a shared handle, so a test can inspect the fake
    /// after the registry has used it.
    struct Shared(Arc<MemoryKeystore>);

    impl Keystore for Shared {
        fn put(&self, id: &str, secret: &str) -> anyhow::Result<()> {
            self.0.put(id, secret)
        }
        fn get(&self, id: &str) -> anyhow::Result<Option<String>> {
            self.0.get(id)
        }
        fn delete(&self, id: &str) -> anyhow::Result<bool> {
            self.0.delete(id)
        }
        fn describe(&self) -> &'static str {
            self.0.describe()
        }
    }

    fn vault_with(store: MemoryKeystore) -> Vault {
        let dir = tempfile::tempdir().unwrap();
        // Through Paths, and through a directory that does not exist yet, so
        // the first write has to create it.
        let paths = Paths::for_test(dir.path());
        let store = Arc::new(store);
        let registry = EnvRegistry::with_paths(&paths, Box::new(Shared(store.clone())));
        Vault {
            dir,
            registry,
            store,
        }
    }

    fn vault() -> Vault {
        vault_with(MemoryKeystore::new())
    }

    /// A registry over one tempdir, for the tests that need two handles onto
    /// the same pair of files.
    fn registry_at(dir: &Path, store: Box<dyn Keystore>) -> EnvRegistry {
        EnvRegistry::new(
            dir.join("projects.json"),
            dir.join("attachments.json"),
            store,
        )
    }

    /// A registered project with one environment holding both layers.
    fn seeded() -> Vault {
        let v = vault();
        v.registry.register("pathors", DEFAULT_ENV).unwrap();
        v.registry
            .attach("/Users/x/repos/pathors", "pathors")
            .unwrap();
        v.registry
            .replace_synced(
                "pathors",
                "dev",
                [
                    ("DATABASE_URL".to_string(), "postgres://remote".to_string()),
                    ("API_KEY".to_string(), "remote-key".to_string()),
                ]
                .into_iter()
                .collect(),
                Utc::now(),
            )
            .unwrap();
        v.registry
            .set_local("pathors", "dev", "DATABASE_URL", "postgres://localhost")
            .unwrap();
        v.registry
            .set_local("pathors", "dev", "MY_FLAG", "true")
            .unwrap();
        v
    }

    fn blob(v: &Vault, env: &str, layer: EnvLayer) -> BTreeMap<String, String> {
        let raw = v
            .store
            .get(&keychain_account("pathors", env, layer))
            .unwrap()
            .expect("no keychain item");
        serde_json::from_str(&raw).unwrap()
    }

    // --- registration -------------------------------------------------------

    #[test]
    fn test_register_writes_metadata_and_no_keychain_items() {
        let v = vault();
        let entry = v.registry.register("pathors", "dev").unwrap();

        assert_eq!(entry.id, "pathors");
        assert_eq!(entry.default_env, "dev");
        assert!(entry.environments.is_empty());
        assert!(entry.sync.is_none());

        assert_eq!(v.registry.projects().unwrap(), vec![entry]);
        // An environment appears on the first write, not on registration; and a
        // project is a name, so registering one attaches nothing.
        assert!(v.store.is_empty());
        assert!(v.registry.attachments().unwrap().is_empty());
        assert!(!v.registry.attachments_path().exists());
    }

    #[test]
    fn test_empty_vault_is_not_an_error() {
        let v = vault();
        assert!(v.registry.projects().unwrap().is_empty());
        assert!(v.registry.get("nope").unwrap().is_none());
        assert!(v.registry.attachments().unwrap().is_empty());
        assert!(v.registry.attachments_of("nope").unwrap().is_empty());
        assert!(v
            .registry
            .find_by_dir(Path::new("/anywhere"))
            .unwrap()
            .is_none());
        assert!(!v.registry.path().exists());
        assert!(!v.registry.attachments_path().exists());
    }

    #[test]
    fn test_a_duplicate_id_names_the_conflict() {
        let v = vault();
        v.registry.register("pathors", "dev").unwrap();

        let err = v
            .registry
            .register("pathors", "dev")
            .unwrap_err()
            .to_string();
        assert!(err.contains("already registered as `pathors`"), "{err}");
        // The way out of a collision is now attach, so it is offered.
        assert!(err.contains("pb env attach pathors"), "{err}");

        assert_eq!(v.registry.projects().unwrap().len(), 1);
    }

    /// `adopt` is `pb import`'s way in. It takes the whole entry, and it takes
    /// no values with it — including the local layer's *names*, which a bundle
    /// should never have carried in the first place.
    #[test]
    fn test_adopt_takes_the_whole_entry_and_drops_the_local_layer() {
        let source = seeded();
        let carried = source.registry.get("pathors").unwrap().unwrap();
        assert!(!carried.env("dev").unwrap().local_names.is_empty());

        let dest = vault();
        let landed = dest.registry.adopt(&carried).unwrap();

        let dev = landed.env("dev").unwrap();
        assert_eq!(dev.synced_names, vec!["API_KEY", "DATABASE_URL"]);
        assert_eq!(dev.synced_at, carried.env("dev").unwrap().synced_at);
        assert!(dev.local_names.is_empty(), "{dev:?}");
        assert_eq!(dest.registry.get("pathors").unwrap().unwrap(), landed);
        // Metadata only: no value is invented, and no path is adopted either.
        assert!(dest.store.is_empty());
        assert!(dest.registry.attachments().unwrap().is_empty());
    }

    #[test]
    fn test_adopt_refuses_an_id_this_machine_already_has() {
        let source = seeded();
        let carried = source.registry.get("pathors").unwrap().unwrap();

        let dest = vault();
        dest.registry.register("pathors", "staging").unwrap();
        let before = dest.registry.get("pathors").unwrap().unwrap();

        let err = dest.registry.adopt(&carried).unwrap_err().to_string();
        assert!(err.contains("already registered as `pathors`"), "{err}");
        // Untouched, not merged, not half-written: this machine may be newer.
        assert_eq!(dest.registry.get("pathors").unwrap().unwrap(), before);
    }

    #[test]
    fn test_register_validates_the_id_and_the_default_env() {
        let v = vault();
        let err = v
            .registry
            .register("Pathors", "dev")
            .unwrap_err()
            .to_string();
        assert!(err.contains("project id"), "{err}");

        let err = v
            .registry
            .register("pathors", "Prod")
            .unwrap_err()
            .to_string();
        assert!(err.contains("environment name"), "{err}");
        assert!(!v.registry.path().exists());
    }

    // --- attachments --------------------------------------------------------

    #[test]
    fn test_attach_and_detach_round_trip() {
        let v = vault();
        v.registry.register("pathors", "dev").unwrap();

        let made = v.registry.attach("/repos/pathors", "pathors").unwrap();
        assert_eq!(made.root, PathBuf::from("/repos/pathors"));
        assert_eq!(made.project, "pathors");
        assert_eq!(v.registry.attachments().unwrap(), vec![made.clone()]);
        assert_eq!(
            v.registry.attachments_of("pathors").unwrap(),
            vec![PathBuf::from("/repos/pathors")]
        );
        assert_eq!(
            v.registry
                .find_by_dir(Path::new("/repos/pathors/src"))
                .unwrap()
                .map(|p| p.id),
            Some("pathors".to_string())
        );

        let gone = v.registry.detach(Path::new("/repos/pathors")).unwrap();
        assert_eq!(gone, made);
        assert!(v.registry.attachments().unwrap().is_empty());
        // Detaching is not forgetting: the project is untouched.
        assert!(v.registry.get("pathors").unwrap().is_some());
        assert!(v
            .registry
            .find_by_dir(Path::new("/repos/pathors"))
            .unwrap()
            .is_none());
    }

    #[test]
    fn test_re_attaching_the_same_pair_is_a_no_op() {
        let v = vault();
        v.registry.register("pathors", "dev").unwrap();
        v.registry.attach("/repos/pathors", "pathors").unwrap();
        let before = std::fs::read_to_string(v.registry.attachments_path()).unwrap();

        let again = v.registry.attach("/repos/pathors", "pathors").unwrap();
        assert_eq!(again.project, "pathors");
        assert_eq!(v.registry.attachments().unwrap().len(), 1);
        assert_eq!(
            std::fs::read_to_string(v.registry.attachments_path()).unwrap(),
            before
        );
    }

    #[test]
    fn test_attaching_a_root_to_a_second_project_is_refused() {
        let v = vault();
        v.registry.register("pathors", "dev").unwrap();
        v.registry.register("other", "dev").unwrap();
        v.registry.attach("/repos/pathors", "pathors").unwrap();
        let before = std::fs::read_to_string(v.registry.attachments_path()).unwrap();

        let err = v
            .registry
            .attach("/repos/pathors", "other")
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("already attached to project `pathors`"),
            "{err}"
        );
        assert!(err.contains("`other`"), "{err}");
        assert!(err.contains("pb env detach"), "{err}");

        // A refusal changes nothing on disk.
        assert_eq!(
            std::fs::read_to_string(v.registry.attachments_path()).unwrap(),
            before
        );
        assert_eq!(
            v.registry.attachments().unwrap()[0].project,
            "pathors",
            "the refusal moved the attachment anyway"
        );
    }

    #[test]
    fn test_attaching_to_an_unknown_project_points_at_init() {
        let v = vault();
        let err = v
            .registry
            .attach("/repos/ghost", "ghost")
            .unwrap_err()
            .to_string();
        assert!(err.contains("no project registered as `ghost`"), "{err}");
        assert!(err.contains("pb env init"), "{err}");
        assert!(err.contains("pb env projects"), "{err}");
        assert!(!v.registry.attachments_path().exists());
    }

    #[test]
    fn test_detaching_an_unattached_path_says_where_to_look() {
        let v = vault();
        let err = v
            .registry
            .detach(Path::new("/repos/nowhere"))
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("nothing is attached at /repos/nowhere"),
            "{err}"
        );
        assert!(err.contains("pb env projects"), "{err}");
    }

    #[test]
    fn test_every_worktree_of_a_repo_shares_one_project() {
        let v = vault();
        v.registry.register("pathors", "dev").unwrap();
        v.registry.attach("/repos/pathors", "pathors").unwrap();
        v.registry
            .attach("/repos/pathors-worktrees/feature-a", "pathors")
            .unwrap();
        // A second clone somewhere else entirely is the same project too.
        v.registry
            .attach("/tmp/scratch/pathors", "pathors")
            .unwrap();

        assert_eq!(
            v.registry.attachments_of("pathors").unwrap(),
            vec![
                PathBuf::from("/repos/pathors"),
                PathBuf::from("/repos/pathors-worktrees/feature-a"),
                PathBuf::from("/tmp/scratch/pathors"),
            ],
            "attachments are stored sorted by root"
        );
        for dir in [
            "/repos/pathors/src",
            "/repos/pathors-worktrees/feature-a/src",
            "/tmp/scratch/pathors",
        ] {
            assert_eq!(
                v.registry
                    .find_by_dir(Path::new(dir))
                    .unwrap()
                    .map(|p| p.id),
                Some("pathors".to_string()),
                "{dir} did not resolve to the shared project"
            );
        }
    }

    #[test]
    fn test_find_by_dir_prefers_the_deepest_attached_root() {
        let v = vault();
        v.registry.register("mono", "dev").unwrap();
        v.registry.register("inner", "dev").unwrap();
        v.registry.attach("/repos/mono", "mono").unwrap();
        v.registry.attach("/repos/mono/apps/web", "inner").unwrap();

        let hit = |dir: &str| {
            v.registry
                .find_by_dir(Path::new(dir))
                .unwrap()
                .map(|p| p.id)
        };
        assert_eq!(hit("/repos/mono"), Some("mono".into()));
        assert_eq!(hit("/repos/mono/services/api"), Some("mono".into()));
        // The nested project wins for its own subtree.
        assert_eq!(hit("/repos/mono/apps/web"), Some("inner".into()));
        assert_eq!(hit("/repos/mono/apps/web/src"), Some("inner".into()));
        // A sibling with the same prefix as a *string* is not a child path.
        assert_eq!(hit("/repos/monolith"), None);
        // A directory under no attachment belongs to nothing, even though both
        // projects exist.
        assert_eq!(hit("/elsewhere"), None);
    }

    #[test]
    fn test_a_dangling_attachment_is_skipped_not_fatal() {
        let v = vault();
        v.registry.register("mono", "dev").unwrap();
        v.registry.register("inner", "dev").unwrap();
        v.registry.attach("/repos/mono", "mono").unwrap();
        v.registry.attach("/repos/mono/apps/web", "inner").unwrap();

        // File surgery: drop `inner` from the manifest without going through
        // `forget`, exactly as copying another machine's projects.json would.
        let text = std::fs::read_to_string(v.registry.path()).unwrap();
        let mut file: serde_json::Value = serde_json::from_str(&text).unwrap();
        let projects = file["projects"].as_array_mut().unwrap();
        projects.retain(|p| p["id"] != "inner");
        std::fs::write(
            v.registry.path(),
            serde_json::to_string_pretty(&file).unwrap(),
        )
        .unwrap();

        // The dangling attachment is still on disk, and is simply not an answer.
        assert_eq!(v.registry.attachments().unwrap().len(), 2);
        assert_eq!(
            v.registry
                .find_by_dir(Path::new("/repos/mono/apps/web/src"))
                .unwrap()
                .map(|p| p.id),
            Some("mono".to_string()),
            "the deepest match was dead; the next one up should answer"
        );
    }

    // --- the marker file ----------------------------------------------------

    /// A directory under the vault's tempdir, optionally carrying a marker.
    /// Real directories, because the marker walk reads the filesystem.
    fn dir_with_marker(v: &Vault, relative: &str, marker: Option<&str>) -> PathBuf {
        let dir = v.dir.path().join(relative);
        std::fs::create_dir_all(&dir).unwrap();
        if let Some(body) = marker {
            std::fs::write(dir.join(MARKER_FILE), body).unwrap();
        }
        dir
    }

    #[test]
    fn test_a_marker_resolves_a_directory_nobody_attached() {
        let v = vault();
        v.registry.register("pathors", "dev").unwrap();
        let root = dir_with_marker(&v, "clone", Some("project = \"pathors\"\n"));
        let deep = dir_with_marker(&v, "clone/apps/web/src", None);

        // Nothing on this machine points at either directory.
        assert!(v.registry.attachments().unwrap().is_empty());
        for dir in [&root, &deep] {
            assert_eq!(
                v.registry.find_by_dir(dir).unwrap().map(|p| p.id),
                Some("pathors".to_string()),
                "{} did not resolve through the marker",
                dir.display()
            );
        }
        // Unknown keys are room for later versions, not a reason to refuse.
        let extra = dir_with_marker(
            &v,
            "clone2",
            Some("project = \"pathors\"\nsomething_new = 42\n"),
        );
        assert_eq!(read_marker(&extra).unwrap().as_deref(), Some("pathors"));
        // A directory with no marker anywhere above it still belongs to nothing.
        assert!(v.registry.find_by_dir(v.dir.path()).unwrap().is_none());
    }

    #[test]
    fn test_the_nearest_marker_wins() {
        let v = vault();
        v.registry.register("mono", "dev").unwrap();
        v.registry.register("inner", "dev").unwrap();
        dir_with_marker(&v, "mono", Some("project = \"mono\"\n"));
        let inner = dir_with_marker(&v, "mono/apps/web", Some("project = \"inner\"\n"));

        assert_eq!(
            v.registry.find_by_dir(&inner).unwrap().map(|p| p.id),
            Some("inner".to_string())
        );
        assert_eq!(
            v.registry
                .find_by_dir(&inner.join("src/components"))
                .unwrap()
                .map(|p| p.id),
            Some("inner".to_string())
        );
        assert_eq!(
            v.registry
                .find_by_dir(&v.dir.path().join("mono/services/api"))
                .unwrap()
                .map(|p| p.id),
            Some("mono".to_string())
        );
    }

    #[test]
    fn test_an_attachment_beats_the_marker() {
        let v = vault();
        v.registry.register("pathors", "dev").unwrap();
        v.registry.register("fork", "dev").unwrap();
        let root = dir_with_marker(&v, "clone", Some("project = \"pathors\"\n"));
        v.registry.attach(&root, "fork").unwrap();

        // The local, deliberate act wins over what the repo ships — and it wins
        // for the whole subtree.
        assert_eq!(
            v.registry.find_by_dir(&root).unwrap().map(|p| p.id),
            Some("fork".to_string())
        );
        assert_eq!(
            v.registry
                .find_by_dir(&root.join("src"))
                .unwrap()
                .map(|p| p.id),
            Some("fork".to_string())
        );

        // Detaching hands the directory back to the marker rather than to
        // nothing: the repo's claim was never removed.
        v.registry.detach(&root).unwrap();
        assert_eq!(
            v.registry.find_by_dir(&root).unwrap().map(|p| p.id),
            Some("pathors".to_string())
        );
    }

    #[test]
    fn test_a_marker_for_an_unknown_project_says_to_bring_the_registry() {
        let v = vault();
        v.registry.register("other", "dev").unwrap();
        let root = dir_with_marker(&v, "clone", Some("project = \"pathors\"\n"));

        // Silence would be the wrong answer here: the checkout is fine, the
        // registry is what did not travel.
        let err = v
            .registry
            .find_by_dir(&root.join("src"))
            .unwrap_err()
            .to_string();
        assert!(err.contains(MARKER_FILE), "{err}");
        assert!(err.contains("no project `pathors`"), "{err}");
        assert!(err.contains("projects.json"), "{err}");
        assert!(err.contains("pb env init --id pathors"), "{err}");
    }

    #[test]
    fn test_a_broken_marker_is_loud_rather_than_ignored() {
        let v = vault();
        v.registry.register("pathors", "dev").unwrap();

        let bad = dir_with_marker(&v, "a", Some("project = pathors\n"));
        let err = read_marker(&bad).unwrap_err().to_string();
        assert!(err.contains("is not a readable patchbay marker"), "{err}");
        assert!(err.contains(MARKER_FILE), "{err}");
        assert!(err.contains("`project = \"<id>\"`"), "{err}");

        let empty = dir_with_marker(&v, "b", Some("# nothing here\n"));
        let err = read_marker(&empty).unwrap_err().to_string();
        assert!(err.contains("project"), "{err}");

        // An id no registry could hold is a typo, and it is caught at the file.
        let shouty = dir_with_marker(&v, "c", Some("project = \"Pathors\"\n"));
        let err = read_marker(&shouty).unwrap_err().to_string();
        assert!(err.contains("names an unusable project"), "{err}");
        assert!(err.contains("project id"), "{err}");

        // And the resolution path surfaces it rather than falling through to a
        // marker further up.
        dir_with_marker(&v, "", Some("project = \"pathors\"\n"));
        assert!(v.registry.find_by_dir(&bad).is_err());
    }

    #[test]
    fn test_write_marker_round_trips_and_refuses_to_change_hands() {
        let v = vault();
        let root = dir_with_marker(&v, "clone", None);

        let path = write_marker(&root, "pathors").unwrap();
        assert_eq!(path, root.join(MARKER_FILE));
        assert_eq!(read_marker(&root).unwrap().as_deref(), Some("pathors"));

        // Idempotent, and byte-for-byte: a comment or a hand-added key survives
        // a second `pb env init`.
        let written = std::fs::read_to_string(&path).unwrap();
        assert!(written.contains("commit this file"), "{written}");
        std::fs::write(&path, format!("{written}extra = true\n")).unwrap();
        let before = std::fs::read_to_string(&path).unwrap();
        assert_eq!(write_marker(&root, "pathors").unwrap(), path);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), before);

        let err = write_marker(&root, "other").unwrap_err().to_string();
        assert!(err.contains("already names project `pathors`"), "{err}");
        assert!(err.contains("`other`"), "{err}");
        assert!(err.contains("pb env attach other"), "{err}");
        // A refusal changes nothing on disk.
        assert_eq!(std::fs::read_to_string(&path).unwrap(), before);

        let err = write_marker(&root, "Nope").unwrap_err().to_string();
        assert!(err.contains("project id"), "{err}");
    }

    #[cfg(unix)]
    #[test]
    fn test_the_marker_is_a_normal_committable_file() {
        use std::os::unix::fs::PermissionsExt;
        let v = vault();
        let root = dir_with_marker(&v, "clone", None);
        let path = write_marker(&root, "pathors").unwrap();

        // Unlike the registry files, this one is meant to be committed and read
        // by everyone who checks the repo out — so it gets whatever an ordinary
        // write gets, not the vault's `0600`.
        let control = root.join("control.txt");
        std::fs::write(&control, "x").unwrap();
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode(&path),
            mode(&control),
            "the marker was written with special permissions"
        );
    }

    #[test]
    fn test_the_projects_file_holds_no_path_from_this_machine() {
        let v = vault();
        let root = v.dir.path().join("repos/pathors");
        v.registry.register("pathors", "dev").unwrap();
        v.registry.attach(&root, "pathors").unwrap();
        v.registry.set_local("pathors", "dev", "A", "1").unwrap();

        // The whole portability promise, as one assertion: a manifest with an
        // absolute path in it is a manifest that cannot be copied to another
        // machine.
        let manifest = std::fs::read_to_string(v.registry.path()).unwrap();
        let here = v.dir.path().to_string_lossy().to_string();
        assert!(
            !manifest.contains(&here),
            "{here} leaked into the portable manifest:\n{manifest}"
        );
        assert!(!manifest.contains("root"), "{manifest}");

        // And the machine-local file is where it went.
        let attachments = std::fs::read_to_string(v.registry.attachments_path()).unwrap();
        assert!(attachments.contains(&here), "{attachments}");
    }

    #[test]
    fn test_forget_takes_every_layer_of_every_environment() {
        let v = seeded();
        v.registry
            .set_local("pathors", "staging", "ONLY_HERE", "1")
            .unwrap();
        assert_eq!(v.store.len(), 3);

        let entry = v.registry.forget("pathors").unwrap();
        assert_eq!(entry.id, "pathors");
        assert!(v.registry.projects().unwrap().is_empty());
        assert!(v.registry.attachments().unwrap().is_empty());
        assert!(
            v.store.is_empty(),
            "keychain items survived the project: {}",
            v.store.len()
        );

        let err = v.registry.forget("pathors").unwrap_err().to_string();
        assert!(err.contains("no project registered as `pathors`"), "{err}");
    }

    #[test]
    fn test_forget_takes_this_machines_attachments_and_leaves_the_rest() {
        let v = vault();
        v.registry.register("pathors", "dev").unwrap();
        v.registry.register("side", "dev").unwrap();
        v.registry.attach("/repos/pathors", "pathors").unwrap();
        v.registry
            .attach("/repos/pathors-worktrees/a", "pathors")
            .unwrap();
        v.registry.attach("/repos/side", "side").unwrap();

        v.registry.forget("pathors").unwrap();

        // Both of the forgotten project's roots went; the other project's did
        // not. A dangling attachment is what this prevents.
        assert_eq!(
            v.registry.attachments().unwrap(),
            vec![Attachment {
                root: PathBuf::from("/repos/side"),
                project: "side".to_string(),
            }]
        );
        assert!(v.registry.attachments_of("pathors").unwrap().is_empty());
        assert!(v
            .registry
            .find_by_dir(Path::new("/repos/pathors/src"))
            .unwrap()
            .is_none());
    }

    #[test]
    fn test_forget_keeps_the_project_when_a_delete_fails() {
        let dir = tempfile::tempdir().unwrap();
        let ok = registry_at(dir.path(), Box::new(MemoryKeystore::new()));
        ok.register("pathors", "dev").unwrap();
        ok.attach("/repos/pathors", "pathors").unwrap();
        ok.set_local("pathors", "dev", "A", "1").unwrap();

        let broken = registry_at(dir.path(), Box::new(MemoryKeystore::failing_delete()));
        let err = format!("{:#}", broken.forget("pathors").unwrap_err());
        assert!(err.contains("the project was kept"), "{err}");
        assert_eq!(broken.projects().unwrap().len(), 1);
        // The attachment went first, so re-running `forget` is the fix — and
        // nothing dangles in the meantime.
        assert!(broken.attachments().unwrap().is_empty());
    }

    #[test]
    fn test_set_sync_replaces_and_only_knows_one_provider() {
        let v = vault();
        v.registry.register("pathors", "dev").unwrap();

        let entry = v
            .registry
            .set_sync(
                "pathors",
                SyncConfig {
                    provider: "infisical".into(),
                    project_id: "3ab516bd-248c-4be7-8f1a-bda73fe69d50".into(),
                    account: "contact@pathors.com".into(),
                    domain: None,
                    env_map: [("production".to_string(), "prod".to_string())]
                        .into_iter()
                        .collect(),
                },
            )
            .unwrap();
        let sync = entry.sync.unwrap();
        assert_eq!(sync.remote_env("production"), "prod");
        // An unmapped name is its own slug.
        assert_eq!(sync.remote_env("dev"), "dev");

        let err = v
            .registry
            .set_sync(
                "pathors",
                SyncConfig {
                    provider: "vault".into(),
                    project_id: "x".into(),
                    account: "a@b.com".into(),
                    domain: None,
                    env_map: BTreeMap::new(),
                },
            )
            .unwrap_err()
            .to_string();
        assert!(err.contains("the only one today is `infisical`"), "{err}");
        // The good config is still in place.
        assert!(v.registry.get("pathors").unwrap().unwrap().sync.is_some());
    }

    // --- layers -------------------------------------------------------------

    #[test]
    fn test_values_go_to_the_keychain_and_names_go_to_the_file() {
        let v = seeded();

        assert_eq!(
            blob(&v, "dev", EnvLayer::Local),
            [
                (
                    "DATABASE_URL".to_string(),
                    "postgres://localhost".to_string()
                ),
                ("MY_FLAG".to_string(), "true".to_string()),
            ]
            .into_iter()
            .collect()
        );

        let meta = v.registry.get("pathors").unwrap().unwrap().environments["dev"].clone();
        assert_eq!(meta.synced_names, vec!["API_KEY", "DATABASE_URL"]);
        assert_eq!(meta.local_names, vec!["DATABASE_URL", "MY_FLAG"]);
        assert!(meta.synced_at.is_some());

        // Not one value reached the file — names and timestamps only.
        let raw = std::fs::read_to_string(v.registry.path()).unwrap();
        for value in [
            "postgres://localhost",
            "postgres://remote",
            "remote-key",
            "true",
        ] {
            assert!(!raw.contains(value), "`{value}` leaked into {raw}");
        }
        assert!(raw.contains("DATABASE_URL"), "{raw}");
    }

    #[test]
    fn test_one_keychain_item_per_layer() {
        let v = seeded();
        let accounts = ["env:pathors/dev/synced", "env:pathors/dev/local"];
        for account in accounts {
            assert!(v.store.contains(account), "missing `{account}`");
        }
        assert_eq!(v.store.len(), accounts.len());
    }

    #[cfg(unix)]
    #[test]
    fn test_metadata_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let v = seeded();
        let mode = std::fs::metadata(v.registry.path())
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "mode was {:o}", mode & 0o777);
    }

    #[test]
    fn test_set_local_creates_the_environment_and_survives_a_reopen() {
        let v = vault();
        v.registry.register("pathors", "dev").unwrap();
        v.registry
            .set_local("pathors", "staging", "MY_FLAG", "true")
            .unwrap();

        let project = v.registry.get("pathors").unwrap().unwrap();
        assert_eq!(project.env_names(), vec!["staging"]);

        // A second registry over the same file and store sees the same thing.
        let reopened = EnvRegistry::new(
            v.registry.path(),
            v.registry.attachments_path(),
            Box::new(Shared(v.store.clone())),
        );
        let merged = reopened.merged("pathors", "staging").unwrap();
        assert_eq!(merged.vars["MY_FLAG"], "true");
    }

    #[test]
    fn test_set_local_validates_before_touching_anything() {
        let v = vault();
        v.registry.register("pathors", "dev").unwrap();

        let err = v
            .registry
            .set_local("pathors", "dev", "1BAD", "x")
            .unwrap_err()
            .to_string();
        assert!(err.contains("must start with a letter or `_`"), "{err}");

        let err = v
            .registry
            .set_local("pathors", "dev", "HAS-DASH", "x")
            .unwrap_err()
            .to_string();
        assert!(err.contains("contains `-`"), "{err}");

        let err = v
            .registry
            .set_local("pathors", "Prod", "OK", "x")
            .unwrap_err()
            .to_string();
        assert!(err.contains("environment name"), "{err}");

        let err = v
            .registry
            .set_local("ghost", "dev", "OK", "x")
            .unwrap_err()
            .to_string();
        assert!(err.contains("no project registered as `ghost`"), "{err}");

        assert!(v.store.is_empty());
        assert!(v
            .registry
            .get("pathors")
            .unwrap()
            .unwrap()
            .environments
            .is_empty());
    }

    #[test]
    fn test_unset_local_says_the_synced_value_is_back() {
        let v = seeded();
        let note = v
            .registry
            .unset_local("pathors", "dev", "DATABASE_URL")
            .unwrap()
            .expect("an overridden name deserves a note");
        assert!(note.contains("still set by the synced layer"), "{note}");

        let merged = v.registry.merged("pathors", "dev").unwrap();
        assert_eq!(merged.vars["DATABASE_URL"], "postgres://remote");
        assert!(merged.overridden.is_empty());

        // A purely local name goes quietly.
        assert_eq!(
            v.registry.unset_local("pathors", "dev", "MY_FLAG").unwrap(),
            None
        );
        assert!(!v
            .registry
            .merged("pathors", "dev")
            .unwrap()
            .vars
            .contains_key("MY_FLAG"));
    }

    #[test]
    fn test_unset_local_refuses_a_synced_only_name() {
        let v = seeded();
        let err = v
            .registry
            .unset_local("pathors", "dev", "API_KEY")
            .unwrap_err()
            .to_string();
        assert!(err.contains("comes from the synced layer"), "{err}");
        assert!(err.contains("patchbay never pushes"), "{err}");

        let err = v
            .registry
            .unset_local("pathors", "dev", "NEVER_SET")
            .unwrap_err()
            .to_string();
        assert!(err.contains("not set in the local layer"), "{err}");

        // Both refusals changed nothing.
        assert_eq!(
            v.registry.list("pathors", "dev").unwrap().len(),
            3,
            "a refusal modified the registry"
        );
    }

    #[test]
    fn test_import_local_is_all_or_nothing() {
        let v = vault();
        v.registry.register("pathors", "dev").unwrap();

        let good: Vec<(String, String)> = vec![
            ("A".into(), "1".into()),
            ("B".into(), "2".into()),
            ("_C".into(), "3".into()),
        ];
        assert_eq!(v.registry.import_local("pathors", "dev", &good).unwrap(), 3);
        assert_eq!(v.registry.merged("pathors", "dev").unwrap().vars.len(), 3);

        let mut bad = good.clone();
        bad.push(("no good".into(), "4".into()));
        assert!(v.registry.import_local("pathors", "dev", &bad).is_err());
        // Not even the valid half of the batch landed.
        assert_eq!(v.registry.merged("pathors", "dev").unwrap().vars.len(), 3);

        // A merge, not a replacement.
        v.registry
            .import_local("pathors", "dev", &[("D".into(), "4".into())])
            .unwrap();
        let merged = v.registry.merged("pathors", "dev").unwrap();
        assert_eq!(merged.vars.len(), 4);
        assert_eq!(merged.vars["A"], "1");

        // Nothing to import creates nothing.
        assert_eq!(v.registry.import_local("pathors", "other", &[]).unwrap(), 0);
        assert!(v
            .registry
            .get("pathors")
            .unwrap()
            .unwrap()
            .env("other")
            .is_none());
    }

    #[test]
    fn test_replace_synced_is_wholesale_and_leaves_local_alone() {
        let v = seeded();
        let at = DateTime::parse_from_rfc3339("2026-08-13T01:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        v.registry
            .replace_synced(
                "pathors",
                "dev",
                [("ONLY_ONE".to_string(), "kept".to_string())]
                    .into_iter()
                    .collect(),
                at,
            )
            .unwrap();

        let meta = v.registry.get("pathors").unwrap().unwrap().environments["dev"].clone();
        // The old synced names are gone: a variable deleted upstream has to
        // disappear here too.
        assert_eq!(meta.synced_names, vec!["ONLY_ONE"]);
        assert_eq!(meta.synced_at, Some(at));
        // The local layer is untouched, values included.
        assert_eq!(meta.local_names, vec!["DATABASE_URL", "MY_FLAG"]);
        let merged = v.registry.merged("pathors", "dev").unwrap();
        assert_eq!(merged.vars["DATABASE_URL"], "postgres://localhost");
        assert_eq!(merged.vars["ONLY_ONE"], "kept");
        assert!(!merged.vars.contains_key("API_KEY"));
    }

    #[test]
    fn test_merged_puts_local_over_synced_and_reports_the_overlap() {
        let v = seeded();
        let merged = v.registry.merged("pathors", "dev").unwrap();

        assert_eq!(merged.vars["DATABASE_URL"], "postgres://localhost");
        assert_eq!(merged.vars["API_KEY"], "remote-key");
        assert_eq!(merged.vars["MY_FLAG"], "true");
        assert_eq!(merged.from_synced, vec!["API_KEY", "DATABASE_URL"]);
        assert_eq!(merged.from_local, vec!["DATABASE_URL", "MY_FLAG"]);
        assert_eq!(merged.overridden, vec!["DATABASE_URL"]);
    }

    #[test]
    fn test_list_is_metadata_only() {
        let v = seeded();
        // A store that panics the test if it is read at all: `list` is the fast
        // path, and reaching the keychain here would be the bug.
        struct NoReads;
        impl Keystore for NoReads {
            fn put(&self, _: &str, _: &str) -> anyhow::Result<()> {
                unreachable!("list must not write")
            }
            fn get(&self, id: &str) -> anyhow::Result<Option<String>> {
                panic!("list read the keychain item `{id}`")
            }
            fn delete(&self, _: &str) -> anyhow::Result<bool> {
                unreachable!("list must not delete")
            }
            fn describe(&self) -> &'static str {
                "a keystore that must not be read"
            }
        }

        let quiet = EnvRegistry::new(
            v.registry.path(),
            v.registry.attachments_path(),
            Box::new(NoReads),
        );
        let listed = quiet.list("pathors", "dev").unwrap();
        let seen: Vec<(&str, EnvVarSource)> =
            listed.iter().map(|v| (v.name.as_str(), v.source)).collect();
        assert_eq!(
            seen,
            vec![
                ("API_KEY", EnvVarSource::Synced),
                ("DATABASE_URL", EnvVarSource::LocalOverride),
                ("MY_FLAG", EnvVarSource::Local),
            ]
        );
        assert_eq!(EnvVarSource::LocalOverride.label(), "local override");
    }

    #[test]
    fn test_an_unknown_environment_says_which_ones_exist() {
        let v = seeded();
        let err = v.registry.list("pathors", "prod").unwrap_err().to_string();
        assert!(err.contains("has no environment `prod`"), "{err}");
        assert!(err.contains("it has dev"), "{err}");

        // `.err()` rather than `.unwrap_err()`: `MergedEnv` has no `Debug`, on
        // purpose, and that is worth keeping even in a test.
        let err = v
            .registry
            .merged("pathors", "prod")
            .err()
            .unwrap()
            .to_string();
        assert!(err.contains("has no environment `prod`"), "{err}");

        let v = vault();
        v.registry.register("fresh", "dev").unwrap();
        let err = v.registry.list("fresh", "dev").unwrap_err().to_string();
        assert!(err.contains("it has none yet"), "{err}");
    }

    // --- both-or-neither ----------------------------------------------------

    #[test]
    fn test_a_keystore_failure_rolls_the_metadata_back() {
        let v = vault_with(MemoryKeystore::failing_put());
        v.registry.register("pathors", "dev").unwrap();
        let before = std::fs::read_to_string(v.registry.path()).unwrap();

        let err = format!(
            "{:#}",
            v.registry
                .set_local("pathors", "dev", "NEVER", "stored")
                .unwrap_err()
        );
        assert!(err.contains("metadata rolled back"), "{err}");

        // The environment was never created, and the file is byte-identical.
        assert_eq!(std::fs::read_to_string(v.registry.path()).unwrap(), before);
        assert!(v
            .registry
            .get("pathors")
            .unwrap()
            .unwrap()
            .environments
            .is_empty());
        assert!(v.store.is_empty());
    }

    #[test]
    fn test_a_failed_pull_leaves_the_previous_synced_names_in_place() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("projects.json");
        let store = Arc::new(MemoryKeystore::new());
        let ok = registry_at(dir.path(), Box::new(Shared(store.clone())));
        ok.register("pathors", "dev").unwrap();
        ok.replace_synced(
            "pathors",
            "dev",
            [("KEEP".to_string(), "1".to_string())]
                .into_iter()
                .collect(),
            Utc::now(),
        )
        .unwrap();
        let before = std::fs::read_to_string(&path).unwrap();

        let broken = registry_at(dir.path(), Box::new(MemoryKeystore::failing_put()));
        assert!(broken
            .replace_synced(
                "pathors",
                "dev",
                [("NEW".to_string(), "2".to_string())].into_iter().collect(),
                Utc::now(),
            )
            .is_err());

        assert_eq!(std::fs::read_to_string(&path).unwrap(), before);
        assert_eq!(ok.merged("pathors", "dev").unwrap().vars["KEEP"], "1");
    }

    // --- the file -----------------------------------------------------------

    #[test]
    fn test_a_malformed_registry_is_an_error_not_an_empty_one() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("projects.json");
        std::fs::write(&path, "{ this is not json").unwrap();
        let registry = registry_at(dir.path(), Box::new(MemoryKeystore::new()));
        let err = registry.projects().unwrap_err().to_string();
        assert!(
            err.contains("not a readable patchbay project registry"),
            "{err}"
        );
    }

    #[test]
    fn test_a_newer_file_version_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("projects.json");
        std::fs::write(&path, r#"{"version":99,"projects":[]}"#).unwrap();
        let registry = registry_at(dir.path(), Box::new(MemoryKeystore::new()));
        let err = registry.projects().unwrap_err().to_string();
        assert!(err.contains("newer patchbay"), "{err}");
    }

    #[test]
    fn test_a_hand_trimmed_file_still_parses() {
        // Only the fields a human would keep: no `environments`, no `sync` —
        // plus a stray `root`, which is what a file written before projects
        // became portable looks like. Unknown fields are ignored, so no
        // migration code is needed for it.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("projects.json");
        std::fs::write(
            &path,
            r#"{
  "version": 1,
  "projects": [
    {
      "id": "pathors",
      "root": "/Users/x/repos/pathors",
      "default_env": "dev",
      "created_at": "2026-08-13T00:00:00Z"
    }
  ]
}"#,
        )
        .unwrap();

        let registry = registry_at(dir.path(), Box::new(MemoryKeystore::new()));
        let projects = registry.projects().unwrap();
        assert_eq!(projects.len(), 1);
        assert!(projects[0].environments.is_empty());
        assert!(projects[0].sync.is_none());

        // And a project with no sync does not grow one on rewrite — while the
        // stale `root` is dropped rather than carried forward.
        registry.set_local("pathors", "dev", "A", "1").unwrap();
        let rewritten = std::fs::read_to_string(&path).unwrap();
        assert!(!rewritten.contains("\"sync\""), "{rewritten}");
        assert!(!rewritten.contains("\"root\""), "{rewritten}");
        assert!(rewritten.contains("\"synced_at\": null"), "{rewritten}");
    }

    // --- the attachment file ------------------------------------------------

    #[cfg(unix)]
    #[test]
    fn test_the_attachment_file_is_owner_only_too() {
        use std::os::unix::fs::PermissionsExt;
        let v = seeded();
        let mode = std::fs::metadata(v.registry.attachments_path())
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "mode was {:o}", mode & 0o777);
    }

    #[test]
    fn test_a_malformed_attachment_file_is_an_error_naming_it() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("attachments.json"), "{ nope").unwrap();
        let registry = registry_at(dir.path(), Box::new(MemoryKeystore::new()));

        let err = registry.attachments().unwrap_err().to_string();
        assert!(
            err.contains("not a readable patchbay attachment list"),
            "{err}"
        );
        assert!(err.contains("attachments.json"), "{err}");
        // The projects file is a separate story and still reads fine.
        assert!(registry.projects().unwrap().is_empty());
    }

    #[test]
    fn test_a_newer_attachment_file_version_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("attachments.json"),
            r#"{"version":99,"attachments":[]}"#,
        )
        .unwrap();
        let registry = registry_at(dir.path(), Box::new(MemoryKeystore::new()));
        let err = registry.attachments().unwrap_err().to_string();
        assert!(err.contains("newer patchbay"), "{err}");
    }

    #[test]
    fn test_the_attachment_file_is_the_shape_it_documents() {
        let v = vault();
        v.registry.register("pathors", "dev").unwrap();
        v.registry.attach("/repos/b", "pathors").unwrap();
        v.registry.attach("/repos/a", "pathors").unwrap();

        let raw = std::fs::read_to_string(v.registry.attachments_path()).unwrap();
        let value: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(value["version"], 1);
        // Sorted by root, whatever order they were attached in.
        assert_eq!(value["attachments"][0]["root"], "/repos/a");
        assert_eq!(value["attachments"][0]["project"], "pathors");
        assert_eq!(value["attachments"][1]["root"], "/repos/b");

        // An empty file is an empty list, not a parse error.
        std::fs::write(v.registry.attachments_path(), "").unwrap();
        assert!(v.registry.attachments().unwrap().is_empty());
    }

    #[test]
    fn test_an_unreadable_keychain_blob_names_the_account() {
        let v = seeded();
        v.store
            .put("env:pathors/dev/local", "not json at all")
            .unwrap();
        let err = v
            .registry
            .merged("pathors", "dev")
            .err()
            .unwrap()
            .to_string();
        assert!(err.contains("env:pathors/dev/local"), "{err}");
        assert!(err.contains("pb env"), "{err}");
    }

    #[test]
    fn test_keychain_accounts_cannot_collide_with_key_ids() {
        assert_eq!(
            keychain_account("pathors", "dev", EnvLayer::Synced),
            "env:pathors/dev/synced"
        );
        assert_eq!(
            keychain_account("pathors", "production", EnvLayer::Local),
            "env:pathors/production/local"
        );
        // Whatever a key id is, it is a slug — so it can never look like this.
        assert!(crate::keys::validate_id("env:pathors/dev/local").is_err());
    }

    // --- validation ---------------------------------------------------------

    #[test]
    fn test_var_name_validation() {
        for good in ["A", "_", "_x9", "DATABASE_URL", "a_b_C_1"] {
            assert!(
                validate_var_name(good).is_ok(),
                "`{good}` should be allowed"
            );
        }
        for bad in ["", "1UP", "HAS-DASH", "has space", "A.B", "ÜBER"] {
            assert!(
                validate_var_name(bad).is_err(),
                "`{bad}` should be rejected"
            );
        }
    }

    // --- dotenv -------------------------------------------------------------

    #[test]
    fn test_parse_dotenv_covers_the_dialect_people_actually_write() {
        let parsed = parse_dotenv(
            "# a comment\n\
             \n\
             PLAIN=value\n\
             SPACED =  trimmed  \n\
             export EXPORTED=yes\n\
             SINGLE='literal $NOT_EXPANDED \\n'\n\
             DOUBLE=\"line\\nbreak\\ttab \\\"quoted\\\" back\\\\slash\"\n\
             EMPTY=\n\
             HASH=hunter#2\n\
             QUOTED_THEN_COMMENT='v' # trailing comment\n\
             REGEXISH=\"\\d+\"\n",
        )
        .unwrap();

        let vars: BTreeMap<String, String> = parsed.iter().cloned().collect();
        assert_eq!(vars["PLAIN"], "value");
        assert_eq!(vars["SPACED"], "trimmed");
        assert_eq!(vars["EXPORTED"], "yes");
        assert_eq!(vars["SINGLE"], "literal $NOT_EXPANDED \\n");
        assert_eq!(vars["DOUBLE"], "line\nbreak\ttab \"quoted\" back\\slash");
        assert_eq!(vars["EMPTY"], "");
        // `#` inside a bare value is part of the value, not a comment.
        assert_eq!(vars["HASH"], "hunter#2");
        assert_eq!(vars["QUOTED_THEN_COMMENT"], "v");
        assert_eq!(vars["REGEXISH"], "\\d+");
        // File order is preserved for the caller that wants it.
        assert_eq!(parsed[0].0, "PLAIN");
    }

    #[test]
    fn test_parse_dotenv_errors_name_the_line_and_never_the_value() {
        let cases = [
            ("A=1\nthis is not a pair\n", 2, "not `NAME=value`"),
            ("A=1\n\nB='unterminated\n", 3, "unterminated"),
            ("B=\"unterminated\n", 1, "unterminated"),
            ("A=1\n1BAD=2\n", 2, "line 2:"),
            ("A='x' then junk\n", 1, "trailing text"),
        ];
        for (text, line, needle) in cases {
            let err = parse_dotenv(text).unwrap_err().to_string();
            assert!(err.contains(needle), "{err}");
            assert!(err.contains(&format!("line {line}")), "{err}");
        }

        // The offending line's text is never echoed — it is the likeliest place
        // for a secret to be.
        let err = parse_dotenv("DATABASE_URL postgres://user:hunter2@db\n")
            .unwrap_err()
            .to_string();
        assert!(!err.contains("hunter2"), "{err}");
    }

    #[test]
    fn test_render_dotenv_round_trips_through_the_parser() {
        let vars: BTreeMap<String, String> = [
            ("PLAIN", "value"),
            ("SPACES", "a b c"),
            ("QUOTE", "it's got one"),
            ("BOTH", "it's \"quoted\""),
            ("DOLLAR", "$NOT_EXPANDED `nor this`"),
            ("BACKSLASH", "C:\\path\\to"),
            ("MULTILINE", "first\nsecond\twide"),
            ("EMPTY", ""),
            ("HASH", "a # b"),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();

        let text = render_dotenv(&vars);
        assert!(text.ends_with('\n'));
        // Sorted, one per line.
        let names: Vec<&str> = text.lines().map(|l| l.split_once('=').unwrap().0).collect();
        let mut sorted = names.clone();
        sorted.sort();
        assert_eq!(names, sorted);
        assert!(text.contains(r"QUOTE='it'\''s got one'"), "{text}");

        let back: BTreeMap<String, String> = parse_dotenv(&text).unwrap().into_iter().collect();
        assert_eq!(back, vars);

        assert_eq!(render_dotenv(&BTreeMap::new()), "");
    }
}
