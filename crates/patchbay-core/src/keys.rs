//! The key vault: a registry for standalone API keys and tokens.
//!
//! The probes in [`crate::probes`] cover credentials some CLI already tracks.
//! This module covers the ones nothing tracks: the Cloudflare token pasted into
//! a GitHub Actions secret, the provider key wired into an automation, the
//! service token an AI agent created halfway through a task. They exist, they
//! expire, and until now the machine had no idea they were there.
//!
//! **The split.** Two stores, deliberately:
//!
//! * *Metadata* — who issued it, what it is for, when it expires, its last four
//!   characters — lives in `~/.config/patchbay/keys.json`. Readable, greppable,
//!   diffable, and worthless to an attacker.
//! * *The value* lives in the OS keychain, behind [`crate::keystore::Keystore`],
//!   and is never written to disk by patchbay.
//!
//! Every write keeps the two in step: metadata first, keychain second, and a
//! keychain failure rolls the metadata back, so the registry never claims a key
//! whose value was never stored.

use std::path::{Path, PathBuf};

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

use crate::keystore::{Keystore, SecurityCliKeystore};
use crate::paths::Paths;

/// Schema version of `keys.json`. Bump on an incompatible change.
const FILE_VERSION: u32 = 1;

/// Upper bound on an id, so the table stays readable and the keychain account
/// stays sane.
const MAX_ID_LEN: usize = 64;

/// A key inside this window is close enough to expiry to be worth saying out
/// loud, on the board and in every MCP answer.
const EXPIRING_SOON_DAYS: i64 = 30;

// ---------------------------------------------------------------------------
// model
// ---------------------------------------------------------------------------

/// How healthy a key's lifetime looks. Derived from `expires_at` and the clock
/// in one place, so the CLI, the MCP server and the panel never disagree about
/// what "expiring soon" means.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyExpiryState {
    /// Past its expiry.
    Expired,
    /// Expires within [`EXPIRING_SOON_DAYS`] days.
    ExpiringSoon,
    /// Has an expiry, comfortably far out.
    Valid,
    /// No expiry recorded — either it never expires, or nobody said.
    NoExpiry,
}

impl KeyExpiryState {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Expired => "expired",
            Self::ExpiringSoon => "expiring soon",
            Self::Valid => "valid",
            Self::NoExpiry => "no expiry",
        }
    }

    /// Whether this state deserves the user's attention.
    pub fn needs_attention(&self) -> bool {
        matches!(self, Self::Expired | Self::ExpiringSoon)
    }
}

/// The tool whose login a key of this provider sits alongside.
///
/// The single source of truth for provider↔tool linking: the board uses it to
/// show registered keys next to the CLI they belong with, so a Cloudflare token
/// used for direct API calls appears on the same row as `wrangler`'s login even
/// though no CLI has ever heard of it.
///
/// Unknown providers map to `None` and simply do not appear on the board — the
/// vault is free-form on purpose, and an unrecognised provider is not an error.
pub fn tool_for_provider(provider: &str) -> Option<&'static str> {
    match provider.trim().to_ascii_lowercase().as_str() {
        "cloudflare" | "cf" => Some("wrangler"),
        "github" | "gh" => Some("gh"),
        "gcp" | "google" | "google-cloud" | "gcloud" => Some("gcloud"),
        "aws" | "amazon" => Some("aws"),
        "azure" | "az" => Some("az"),
        "infisical" => Some("infisical"),
        _ => None,
    }
}

/// One registered key. **Metadata only** — this struct never carries the secret
/// value, and `last4` is the only thing derived from it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct KeyEntry {
    /// Slug, unique across the registry, e.g. `"cf-gh-actions-deploy"`.
    pub id: String,
    /// Who issued the key: `"cloudflare"`, `"github"`, `"openai"`. Free-form.
    pub provider: String,
    /// Display name.
    pub label: String,
    /// What it is used for, e.g. "deploy from GitHub Actions in repo X".
    pub purpose: Option<String>,
    /// Granted scopes / permissions, as the issuer names them.
    pub scopes: Vec<String>,
    pub created_at: DateTime<Utc>,
    /// `None` means the key does not expire, or the expiry is unknown.
    pub expires_at: Option<DateTime<Utc>>,
    /// Last 4 characters of the secret, so a human can match a registry entry
    /// against a token shown in a provider's dashboard.
    pub last4: String,
    /// Who registered it: `"cli"`, `"mcp:<client>"`, `"gui"`.
    pub source: String,
    /// Base URL of the instance this key is for, when the provider is not a
    /// single global service: `https://pathors.grafana.net` for a Grafana
    /// service-account token. Verification needs it — there is no one address
    /// to ask about a self-hosted instance.
    ///
    /// Omitted from the JSON when absent, and defaulted on the way in, so a
    /// `keys.json` written before this field existed keeps parsing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
}

impl KeyEntry {
    /// Time left before expiry. `None` when the key has no known expiry;
    /// negative when it has already expired.
    pub fn time_to_expiry(&self, now: DateTime<Utc>) -> Option<Duration> {
        self.expires_at.map(|at| at - now)
    }

    pub fn is_expired(&self, now: DateTime<Utc>) -> bool {
        matches!(self.expires_at, Some(at) if at <= now)
    }

    /// How this key's lifetime looks right now.
    pub fn expiry_state(&self, now: DateTime<Utc>) -> KeyExpiryState {
        match self.expires_at {
            None => KeyExpiryState::NoExpiry,
            Some(at) if at <= now => KeyExpiryState::Expired,
            Some(at) if at - now <= Duration::days(EXPIRING_SOON_DAYS) => {
                KeyExpiryState::ExpiringSoon
            }
            Some(_) => KeyExpiryState::Valid,
        }
    }

    /// The compact form that rides along on a [`crate::types::ToolStatus`].
    pub fn as_ref_at(&self, now: DateTime<Utc>) -> crate::types::KeyRef {
        crate::types::KeyRef {
            id: self.id.clone(),
            label: self.label.clone(),
            last4: self.last4.clone(),
            expires_at: self.expires_at,
            expiry_state: self.expiry_state(now),
        }
    }

    /// The tool this key belongs beside on the board, if any.
    pub fn linked_tool(&self) -> Option<&'static str> {
        tool_for_provider(&self.provider)
    }
}

/// The fields needed to register a key. The secret is passed separately to
/// [`KeyRegistry::add`] so it never becomes part of a struct that could be
/// serialized, logged or debug-printed by accident.
#[derive(Debug, Clone)]
pub struct NewKey {
    pub id: String,
    pub provider: String,
    pub label: String,
    pub purpose: Option<String>,
    pub scopes: Vec<String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub source: String,
    /// Instance URL, for providers that have more than one address.
    pub endpoint: Option<String>,
}

impl NewKey {
    /// Minimal registration: everything else is optional and defaults to the
    /// least surprising thing (`label` = id, `provider` = "unknown").
    pub fn new(id: impl Into<String>, source: impl Into<String>) -> Self {
        let id = id.into();
        Self {
            provider: "unknown".to_string(),
            label: id.clone(),
            id,
            purpose: None,
            scopes: Vec::new(),
            expires_at: None,
            source: source.into(),
            endpoint: None,
        }
    }

    pub fn provider(mut self, provider: impl Into<String>) -> Self {
        self.provider = provider.into();
        self
    }

    pub fn label(mut self, label: impl Into<String>) -> Self {
        self.label = label.into();
        self
    }

    pub fn purpose(mut self, purpose: Option<String>) -> Self {
        self.purpose = purpose;
        self
    }

    pub fn scopes(mut self, scopes: Vec<String>) -> Self {
        self.scopes = scopes;
        self
    }

    pub fn expires_at(mut self, at: Option<DateTime<Utc>>) -> Self {
        self.expires_at = at;
        self
    }

    /// The instance this key belongs to. Trailing slashes are trimmed so
    /// `https://x.grafana.net/` and `https://x.grafana.net` are one endpoint.
    pub fn endpoint(mut self, endpoint: Option<String>) -> Self {
        self.endpoint = endpoint.map(|e| normalize_endpoint(&e));
        self
    }
}

/// Trim trailing slashes and surrounding whitespace so an endpoint can be
/// joined to an API path without producing a double slash.
pub fn normalize_endpoint(endpoint: &str) -> String {
    endpoint.trim().trim_end_matches('/').to_string()
}

/// A partial metadata update. `None` leaves a field alone; `Some(None)` on the
/// nullable fields clears it.
#[derive(Debug, Clone, Default)]
pub struct KeyPatch {
    pub provider: Option<String>,
    pub label: Option<String>,
    pub purpose: Option<Option<String>>,
    pub scopes: Option<Vec<String>>,
    pub expires_at: Option<Option<DateTime<Utc>>>,
    pub endpoint: Option<Option<String>>,
}

impl KeyPatch {
    pub fn is_empty(&self) -> bool {
        self.provider.is_none()
            && self.label.is_none()
            && self.purpose.is_none()
            && self.scopes.is_none()
            && self.expires_at.is_none()
            && self.endpoint.is_none()
    }
}

/// On-disk shape of `keys.json`.
#[derive(Debug, Serialize, Deserialize)]
struct KeyFile {
    version: u32,
    keys: Vec<KeyEntry>,
}

// ---------------------------------------------------------------------------
// registry
// ---------------------------------------------------------------------------

/// The vault: a metadata file plus a [`Keystore`] for the values.
///
/// Stateless between calls — the file is re-read on every operation, so a key
/// added by the CLI is immediately visible to a running MCP server.
pub struct KeyRegistry {
    path: PathBuf,
    store: Box<dyn Keystore>,
}

impl KeyRegistry {
    /// Bind to an explicit metadata path and keystore. Tests use this with a
    /// tempdir and [`crate::keystore::MemoryKeystore`].
    pub fn new(path: impl Into<PathBuf>, store: Box<dyn Keystore>) -> Self {
        Self {
            path: path.into(),
            store,
        }
    }

    /// Bind to the location [`Paths`] reports, with the given keystore.
    pub fn with_paths(paths: &Paths, store: Box<dyn Keystore>) -> Self {
        Self::new(paths.keys_file(), store)
    }

    /// The real vault on this machine: `~/.config/patchbay/keys.json` plus the
    /// macOS Keychain.
    pub fn detect() -> anyhow::Result<Self> {
        let paths = Paths::detect()?;
        Ok(Self::with_paths(
            &paths,
            Box::new(SecurityCliKeystore::new()),
        ))
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn store_name(&self) -> &'static str {
        self.store.describe()
    }

    // --- reads --------------------------------------------------------------

    /// Every registered key, oldest registration first. A missing file is an
    /// empty vault, not an error.
    pub fn list(&self) -> anyhow::Result<Vec<KeyEntry>> {
        Ok(self.load()?.keys)
    }

    /// One entry, or `None` when nothing is registered under that id.
    pub fn get(&self, id: &str) -> anyhow::Result<Option<KeyEntry>> {
        Ok(self.list()?.into_iter().find(|k| k.id == id))
    }

    /// Keys expiring in the next `days` days, soonest first. Already-expired
    /// keys are included — they are the most urgent thing the caller could be
    /// asking about. Keys with no known expiry are never included.
    pub fn expiring_within(&self, days: i64) -> anyhow::Result<Vec<KeyEntry>> {
        Ok(expiring_within_at(&self.list()?, Utc::now(), days))
    }

    /// The secret value. The **only** method that returns credential material;
    /// every caller is expected to gate it (the CLI puts it straight on the
    /// clipboard, the MCP server requires an explicit environment flag).
    pub fn get_secret(&self, id: &str) -> anyhow::Result<String> {
        // Look in the metadata first so an unknown id gets the good error
        // message rather than a bare keychain miss.
        let entry = self
            .get(id)?
            .ok_or_else(|| anyhow::anyhow!("no key registered as `{id}`"))?;
        self.store.get(&entry.id)?.ok_or_else(|| {
            anyhow::anyhow!(
                "`{id}` is registered but its value is missing from the {}; \
                 re-add it with the current secret, or remove the entry",
                self.store.describe()
            )
        })
    }

    // --- writes -------------------------------------------------------------

    /// Register a key: metadata to disk, value to the keystore.
    ///
    /// Both or neither. The metadata file is written first; if the keystore
    /// then refuses, the file is restored to exactly what it was and the error
    /// is returned, so the registry can never advertise a key whose value was
    /// never stored.
    ///
    /// A duplicate id is an error unless `overwrite` is set, in which case the
    /// entry is replaced wholesale (including `created_at` — replacing the
    /// secret is a rotation, and the registration date of a rotated key is the
    /// date of the rotation).
    pub fn add(&self, new: NewKey, secret: &str, overwrite: bool) -> anyhow::Result<KeyEntry> {
        validate_id(&new.id)?;
        if secret.is_empty() {
            anyhow::bail!("refusing to register `{}` with an empty secret", new.id);
        }

        let mut file = self.load()?;
        let existing = file.keys.iter().position(|k| k.id == new.id);
        if existing.is_some() && !overwrite {
            anyhow::bail!(
                "a key is already registered as `{}`; pick another id, or overwrite it \
                 deliberately (`pb key add {} --overwrite`) if you are rotating it",
                new.id,
                new.id
            );
        }

        let entry = KeyEntry {
            id: new.id,
            provider: new.provider,
            label: new.label,
            purpose: new.purpose,
            scopes: new.scopes,
            created_at: Utc::now(),
            expires_at: new.expires_at,
            last4: last4(secret),
            source: new.source,
            endpoint: new.endpoint.as_deref().map(normalize_endpoint),
        };

        match existing {
            Some(at) => file.keys[at] = entry.clone(),
            None => file.keys.push(entry.clone()),
        }

        // Snapshot for the rollback below, taken before anything is written.
        let previous = self.read_raw()?;
        self.save(&file)?;
        if let Err(e) = self.store.put(&entry.id, secret) {
            self.restore(previous.as_deref()).map_err(|restore_err| {
                // Two failures at once: report both, and say plainly that the
                // file is now out of step with the keychain.
                anyhow::anyhow!(
                    "{e}; AND the metadata rollback failed: {restore_err}. \
                     `{}` may be listed in {} without a stored value — remove it with \
                     `pb key rm {}`",
                    entry.id,
                    self.path.display(),
                    entry.id
                )
            })?;
            return Err(e.context(format!(
                "could not store the value for `{}`; metadata rolled back, nothing was registered",
                entry.id
            )));
        }
        Ok(entry)
    }

    /// Change metadata without touching the secret. `last4`, `id` and
    /// `created_at` are immutable: they describe the stored value, and changing
    /// them here would make the registry lie about it.
    pub fn update_metadata(&self, id: &str, patch: KeyPatch) -> anyhow::Result<KeyEntry> {
        let mut file = self.load()?;
        let entry = file
            .keys
            .iter_mut()
            .find(|k| k.id == id)
            .ok_or_else(|| anyhow::anyhow!("no key registered as `{id}`"))?;

        if let Some(provider) = patch.provider {
            entry.provider = provider;
        }
        if let Some(label) = patch.label {
            entry.label = label;
        }
        if let Some(purpose) = patch.purpose {
            entry.purpose = purpose;
        }
        if let Some(scopes) = patch.scopes {
            entry.scopes = scopes;
        }
        if let Some(expires_at) = patch.expires_at {
            entry.expires_at = expires_at;
        }
        if let Some(endpoint) = patch.endpoint {
            entry.endpoint = endpoint.as_deref().map(normalize_endpoint);
        }
        let updated = entry.clone();
        self.save(&file)?;
        Ok(updated)
    }

    /// Unregister a key: metadata entry and stored value both go.
    ///
    /// Same both-or-neither rule as [`Self::add`], in reverse. A value that is
    /// already absent from the keystore is not an error — that half-state is
    /// exactly what this call is for.
    pub fn remove(&self, id: &str) -> anyhow::Result<KeyEntry> {
        let mut file = self.load()?;
        let at = file
            .keys
            .iter()
            .position(|k| k.id == id)
            .ok_or_else(|| anyhow::anyhow!("no key registered as `{id}`"))?;
        let entry = file.keys.remove(at);

        let previous = self.read_raw()?;
        self.save(&file)?;
        if let Err(e) = self.store.delete(&entry.id) {
            self.restore(previous.as_deref())?;
            return Err(e.context(format!(
                "could not delete the stored value for `{id}`; the registry entry was kept"
            )));
        }
        Ok(entry)
    }

    // --- file plumbing ------------------------------------------------------

    fn read_raw(&self) -> anyhow::Result<Option<String>> {
        match std::fs::read_to_string(&self.path) {
            Ok(text) => Ok(Some(text)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(anyhow::anyhow!(
                "could not read {}: {e}",
                self.path.display()
            )),
        }
    }

    fn load(&self) -> anyhow::Result<KeyFile> {
        let Some(text) = self.read_raw()? else {
            return Ok(KeyFile {
                version: FILE_VERSION,
                keys: Vec::new(),
            });
        };
        if text.trim().is_empty() {
            return Ok(KeyFile {
                version: FILE_VERSION,
                keys: Vec::new(),
            });
        }
        // A malformed vault is a hard error, not an empty vault: silently
        // starting over would let the next `add` overwrite the whole registry.
        let file: KeyFile = serde_json::from_str(&text).map_err(|e| {
            anyhow::anyhow!(
                "{} is not a readable patchbay key registry: {e}",
                self.path.display()
            )
        })?;
        if file.version > FILE_VERSION {
            anyhow::bail!(
                "{} was written by a newer patchbay (file version {}, this build understands {}); \
                 upgrade rather than risk rewriting it",
                self.path.display(),
                file.version,
                FILE_VERSION
            );
        }
        Ok(file)
    }

    /// Write the registry atomically: temp file in the same directory, `0600`,
    /// then rename over the target.
    fn save(&self, file: &KeyFile) -> anyhow::Result<()> {
        let body = serde_json::to_string_pretty(&KeyFile {
            version: FILE_VERSION,
            keys: file.keys.clone(),
        })?;
        self.write_atomic(&body)
    }

    fn restore(&self, previous: Option<&str>) -> anyhow::Result<()> {
        match previous {
            Some(text) => self.write_atomic(text),
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

    fn write_atomic(&self, body: &str) -> anyhow::Result<()> {
        let dir = self
            .path
            .parent()
            .ok_or_else(|| anyhow::anyhow!("{} has no parent directory", self.path.display()))?;
        std::fs::create_dir_all(dir)
            .map_err(|e| anyhow::anyhow!("could not create {}: {e}", dir.display()))?;

        let tmp = self.path.with_extension("json.tmp");
        std::fs::write(&tmp, body)
            .map_err(|e| anyhow::anyhow!("could not write {}: {e}", tmp.display()))?;
        // Metadata is not secret, but it is nobody else's business either.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))
                .map_err(|e| anyhow::anyhow!("could not chmod {}: {e}", tmp.display()))?;
        }
        std::fs::rename(&tmp, &self.path).map_err(|e| {
            let _ = std::fs::remove_file(&tmp);
            anyhow::anyhow!("could not replace {}: {e}", self.path.display())
        })
    }
}

// ---------------------------------------------------------------------------
// free functions
// ---------------------------------------------------------------------------

/// Last four characters of the secret (fewer if it is shorter). Characters,
/// not bytes, so a non-ASCII secret cannot panic on a slice boundary.
pub fn last4(secret: &str) -> String {
    let chars: Vec<char> = secret.chars().collect();
    chars[chars.len().saturating_sub(4)..].iter().collect()
}

/// The pure core of [`KeyRegistry::expiring_within`], with `now` injected.
pub fn expiring_within_at(entries: &[KeyEntry], now: DateTime<Utc>, days: i64) -> Vec<KeyEntry> {
    let horizon = now + Duration::days(days);
    let mut hits: Vec<KeyEntry> = entries
        .iter()
        .filter(|k| matches!(k.expires_at, Some(at) if at <= horizon))
        .cloned()
        .collect();
    hits.sort_by_key(|k| k.expires_at);
    hits
}

/// Ids are lowercase slugs. Beyond keeping the board readable, this is what
/// keeps an id from being mistaken for an option when it is handed to
/// `security` as an argument.
pub fn validate_id(id: &str) -> anyhow::Result<()> {
    if id.is_empty() {
        anyhow::bail!("a key id cannot be empty");
    }
    if id.len() > MAX_ID_LEN {
        anyhow::bail!("key id `{id}` is longer than {MAX_ID_LEN} characters");
    }
    if id.chars().any(|c| c.is_ascii_uppercase()) {
        anyhow::bail!(
            "key ids are lowercase slugs; try `{}`",
            id.to_ascii_lowercase()
        );
    }
    if !id
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
    {
        anyhow::bail!("key id `{id}` must start with a letter or digit");
    }
    if let Some(bad) = id
        .chars()
        .find(|c| !(c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '-' | '_' | '.')))
    {
        anyhow::bail!(
            "key id `{id}` contains `{bad}`; use lowercase letters, digits, `-`, `_` and `.`"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keystore::MemoryKeystore;
    use std::sync::Arc;

    /// A registry over a tempdir with a fake keystore. Nothing here touches the
    /// real `$HOME` or the real keychain.
    struct Vault {
        _dir: tempfile::TempDir,
        registry: KeyRegistry,
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
        let registry = KeyRegistry::with_paths(&paths, Box::new(Shared(store.clone())));
        Vault {
            _dir: dir,
            registry,
            store,
        }
    }

    fn vault() -> Vault {
        vault_with(MemoryKeystore::new())
    }

    fn sample(id: &str) -> NewKey {
        NewKey::new(id, "cli")
            .provider("cloudflare")
            .label("CF deploy token")
            .purpose(Some("deploy from GitHub Actions in repo X".into()))
            .scopes(vec!["workers:edit".into(), "zone:read".into()])
    }

    #[test]
    fn test_add_writes_metadata_and_secret_separately() {
        let v = vault();
        let entry = v
            .registry
            .add(sample("cf-gh-actions-deploy"), "abcd-EFGH-1234", false)
            .unwrap();

        assert_eq!(entry.last4, "1234");
        assert_eq!(entry.provider, "cloudflare");
        assert_eq!(entry.scopes, vec!["workers:edit", "zone:read"]);
        assert_eq!(entry.source, "cli");

        // Metadata is on disk and readable back.
        let listed = v.registry.list().unwrap();
        assert_eq!(listed, vec![entry.clone()]);

        // The secret went to the keystore and NOT to the file.
        assert_eq!(
            v.store.get("cf-gh-actions-deploy").unwrap().as_deref(),
            Some("abcd-EFGH-1234")
        );
        let raw = std::fs::read_to_string(v.registry.path()).unwrap();
        assert!(
            !raw.contains("abcd-EFGH-1234"),
            "the secret leaked into the metadata file: {raw}"
        );
        assert!(raw.contains("\"last4\": \"1234\""), "{raw}");
    }

    #[cfg(unix)]
    #[test]
    fn test_metadata_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let v = vault();
        v.registry.add(sample("k"), "secret-9999", false).unwrap();
        let mode = std::fs::metadata(v.registry.path())
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "mode was {:o}", mode & 0o777);
    }

    #[test]
    fn test_empty_vault_is_not_an_error() {
        let v = vault();
        assert!(v.registry.list().unwrap().is_empty());
        assert!(v.registry.get("nope").unwrap().is_none());
        assert!(!v.registry.path().exists());
    }

    #[test]
    fn test_duplicate_id_is_refused_and_changes_nothing() {
        let v = vault();
        v.registry.add(sample("dup"), "first-1111", false).unwrap();

        let err = v
            .registry
            .add(sample("dup"), "second-2222", false)
            .unwrap_err()
            .to_string();
        assert!(err.contains("already registered"), "{err}");
        assert!(err.contains("--overwrite"), "{err}");

        // The original survived, value included.
        let entries = v.registry.list().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].last4, "1111");
        assert_eq!(v.store.get("dup").unwrap().as_deref(), Some("first-1111"));
    }

    #[test]
    fn test_overwrite_replaces_both_halves() {
        let v = vault();
        v.registry.add(sample("dup"), "first-1111", false).unwrap();
        let entry = v
            .registry
            .add(
                NewKey::new("dup", "mcp:claude").provider("github"),
                "second-2222",
                true,
            )
            .unwrap();

        assert_eq!(entry.last4, "2222");
        assert_eq!(entry.provider, "github");
        assert_eq!(entry.source, "mcp:claude");
        assert_eq!(v.registry.list().unwrap().len(), 1);
        assert_eq!(v.store.get("dup").unwrap().as_deref(), Some("second-2222"));
    }

    #[test]
    fn test_keystore_failure_rolls_the_metadata_back() {
        let v = vault_with(MemoryKeystore::failing_put());
        let err = v
            .registry
            .add(sample("doomed"), "never-stored", false)
            .unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("metadata rolled back"), "{msg}");

        // Nothing registered, and no file left behind at all: the vault was
        // empty before, so the rollback has to take the file with it.
        assert!(v.registry.list().unwrap().is_empty());
        assert!(!v.registry.path().exists());
        assert!(v.store.is_empty());
    }

    #[test]
    fn test_keystore_failure_rolls_back_to_the_previous_contents() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("keys.json");

        // One good key through a working store...
        let ok = KeyRegistry::new(&path, Box::new(MemoryKeystore::new()));
        ok.add(sample("keeper"), "keep-0001", false).unwrap();
        let before = std::fs::read_to_string(&path).unwrap();

        // ...then a failing store over the same file.
        let broken = KeyRegistry::new(&path, Box::new(MemoryKeystore::failing_put()));
        assert!(broken.add(sample("doomed"), "nope-0002", false).is_err());

        assert_eq!(std::fs::read_to_string(&path).unwrap(), before);
        let entries = ok.list().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].id, "keeper");
    }

    #[test]
    fn test_remove_takes_both_halves() {
        let v = vault();
        v.registry.add(sample("gone"), "bye-4321", false).unwrap();
        let removed = v.registry.remove("gone").unwrap();

        assert_eq!(removed.id, "gone");
        assert!(v.registry.list().unwrap().is_empty());
        assert!(!v.store.contains("gone"));
    }

    #[test]
    fn test_remove_unknown_id_is_a_clear_error() {
        let v = vault();
        let err = v.registry.remove("ghost").unwrap_err().to_string();
        assert!(err.contains("no key registered as `ghost`"), "{err}");
    }

    #[test]
    fn test_failed_keystore_delete_keeps_the_entry() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("keys.json");
        KeyRegistry::new(&path, Box::new(MemoryKeystore::new()))
            .add(sample("stuck"), "val-7777", false)
            .unwrap();

        let broken = KeyRegistry::new(&path, Box::new(MemoryKeystore::failing_delete()));
        let err = format!("{:#}", broken.remove("stuck").unwrap_err());
        assert!(err.contains("registry entry was kept"), "{err}");
        assert_eq!(broken.list().unwrap().len(), 1);
    }

    #[test]
    fn test_get_secret_round_trips_and_reports_a_missing_value() {
        let v = vault();
        v.registry
            .add(sample("k"), "top-secret-8888", false)
            .unwrap();
        assert_eq!(v.registry.get_secret("k").unwrap(), "top-secret-8888");

        // Metadata without a stored value: the error has to say so, and say
        // what to do about it.
        v.store.delete("k").unwrap();
        let err = v.registry.get_secret("k").unwrap_err().to_string();
        assert!(err.contains("missing from the"), "{err}");

        let err = v.registry.get_secret("nope").unwrap_err().to_string();
        assert!(err.contains("no key registered as `nope`"), "{err}");
    }

    #[test]
    fn test_update_metadata_leaves_the_secret_alone() {
        let v = vault();
        let original = v.registry.add(sample("k"), "value-5555", false).unwrap();

        let updated = v
            .registry
            .update_metadata(
                "k",
                KeyPatch {
                    label: Some("renamed".into()),
                    purpose: Some(None),
                    expires_at: Some(Some(Utc::now() + Duration::days(30))),
                    ..Default::default()
                },
            )
            .unwrap();

        assert_eq!(updated.label, "renamed");
        assert_eq!(updated.purpose, None);
        assert!(updated.expires_at.is_some());
        // Immutable facts about the stored value survive.
        assert_eq!(updated.last4, original.last4);
        assert_eq!(updated.created_at, original.created_at);
        assert_eq!(updated.provider, original.provider);
        assert_eq!(v.registry.get_secret("k").unwrap(), "value-5555");

        let err = v
            .registry
            .update_metadata("ghost", KeyPatch::default())
            .unwrap_err()
            .to_string();
        assert!(err.contains("no key registered"), "{err}");
    }

    #[test]
    fn test_expiring_within_includes_expired_and_sorts_soonest_first() {
        let now = DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let at = |d: i64| -> Option<DateTime<Utc>> { Some(now + Duration::days(d)) };

        let entry = |id: &str, expires: Option<DateTime<Utc>>| KeyEntry {
            id: id.to_string(),
            provider: "p".into(),
            label: id.to_string(),
            purpose: None,
            scopes: vec![],
            created_at: now,
            expires_at: expires,
            last4: "0000".into(),
            source: "cli".into(),
            endpoint: None,
        };

        let entries = vec![
            entry("never", None),
            entry("far", at(90)),
            entry("soon", at(3)),
            entry("already-expired", at(-10)),
            entry("edge", at(30)),
        ];

        let hits = expiring_within_at(&entries, now, 30);
        let ids: Vec<&str> = hits.iter().map(|k| k.id.as_str()).collect();
        assert_eq!(ids, vec!["already-expired", "soon", "edge"]);

        let ids: Vec<String> = expiring_within_at(&entries, now, 1)
            .into_iter()
            .map(|k| k.id)
            .collect();
        assert_eq!(ids, vec!["already-expired"]);

        assert!(expiring_within_at(&[entry("never", None)], now, 3650).is_empty());
    }

    #[test]
    fn test_expiry_helpers_on_an_entry() {
        let now = Utc::now();
        let mut e = KeyEntry {
            id: "k".into(),
            provider: "p".into(),
            label: "k".into(),
            purpose: None,
            scopes: vec![],
            created_at: now,
            expires_at: None,
            last4: "0000".into(),
            source: "cli".into(),
            endpoint: None,
        };
        assert!(e.time_to_expiry(now).is_none());
        assert!(!e.is_expired(now));

        e.expires_at = Some(now - Duration::hours(1));
        assert!(e.is_expired(now));
        assert!(e.time_to_expiry(now).unwrap() < Duration::zero());
    }

    #[test]
    fn test_a_keys_json_written_before_endpoints_existed_still_parses() {
        // The exact shape v0.1.0 wrote: no `endpoint` key anywhere. This is the
        // regression guard for adding a field to a file format users already
        // have on disk.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("keys.json");
        std::fs::write(
            &path,
            r#"{
  "version": 1,
  "keys": [
    {
      "id": "cf-gh-actions-deploy",
      "provider": "cloudflare",
      "label": "CF deploy token",
      "purpose": "deploy from GitHub Actions",
      "scopes": ["workers:edit"],
      "created_at": "2026-08-13T09:56:53.467618Z",
      "expires_at": "2027-01-01T00:00:00Z",
      "last4": "1234",
      "source": "cli"
    }
  ]
}"#,
        )
        .unwrap();

        let registry = KeyRegistry::new(&path, Box::new(MemoryKeystore::new()));
        let entries = registry.list().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].id, "cf-gh-actions-deploy");
        assert_eq!(entries[0].endpoint, None);

        // And a key with no endpoint does not grow one in the file on rewrite.
        registry
            .update_metadata(
                "cf-gh-actions-deploy",
                KeyPatch {
                    label: Some("renamed".into()),
                    ..Default::default()
                },
            )
            .unwrap();
        let rewritten = std::fs::read_to_string(&path).unwrap();
        assert!(!rewritten.contains("endpoint"), "{rewritten}");
    }

    #[test]
    fn test_an_endpoint_round_trips_and_is_normalized() {
        let v = vault();
        let entry = v
            .registry
            .add(
                NewKey::new("grafana-pathors", "cli")
                    .provider("grafana")
                    // Trailing slash and stray whitespace are what people paste.
                    .endpoint(Some("  https://pathors.grafana.net/  ".into())),
                "glsa-1234",
                false,
            )
            .unwrap();
        assert_eq!(
            entry.endpoint.as_deref(),
            Some("https://pathors.grafana.net")
        );

        let reopened = KeyRegistry::new(v.registry.path(), Box::new(MemoryKeystore::new()));
        assert_eq!(
            reopened.list().unwrap()[0].endpoint.as_deref(),
            Some("https://pathors.grafana.net")
        );
        // It is in the JSON only because this key has one.
        let raw = std::fs::read_to_string(v.registry.path()).unwrap();
        assert!(
            raw.contains("\"endpoint\": \"https://pathors.grafana.net\""),
            "{raw}"
        );
    }

    #[test]
    fn test_endpoint_can_be_patched_and_cleared() {
        let v = vault();
        v.registry
            .add(
                NewKey::new("g", "cli").provider("grafana"),
                "glsa-1234",
                false,
            )
            .unwrap();

        let updated = v
            .registry
            .update_metadata(
                "g",
                KeyPatch {
                    endpoint: Some(Some("https://x.grafana.net/".into())),
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(updated.endpoint.as_deref(), Some("https://x.grafana.net"));

        let cleared = v
            .registry
            .update_metadata(
                "g",
                KeyPatch {
                    endpoint: Some(None),
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(cleared.endpoint, None);
    }

    #[test]
    fn test_provider_to_tool_mapping_is_the_single_source_of_truth() {
        let expected = [
            ("cloudflare", Some("wrangler")),
            ("cf", Some("wrangler")),
            ("github", Some("gh")),
            ("gh", Some("gh")),
            ("gcp", Some("gcloud")),
            ("google", Some("gcloud")),
            ("google-cloud", Some("gcloud")),
            ("gcloud", Some("gcloud")),
            ("aws", Some("aws")),
            ("amazon", Some("aws")),
            ("azure", Some("az")),
            ("az", Some("az")),
            ("infisical", Some("infisical")),
            // Free-form providers are normal, and simply do not link.
            ("openai", None),
            ("stripe", None),
            // Grafana has no CLI patchbay probes, so its keys deliberately
            // link to nothing and live in the vault view alone.
            ("grafana", None),
            ("unknown", None),
            ("", None),
        ];
        for (provider, tool) in expected {
            assert_eq!(tool_for_provider(provider), tool, "provider `{provider}`");
        }

        // Case and stray whitespace are what people actually type.
        assert_eq!(tool_for_provider("CloudFlare"), Some("wrangler"));
        assert_eq!(tool_for_provider("  GitHub  "), Some("gh"));

        // Every tool named here must be a real probe key, or the key would be
        // filed against a row that does not exist.
        let dir = tempfile::tempdir().unwrap();
        let board = crate::Registry::all(Paths::for_test(dir.path()));
        let known = board.tool_names();
        for (provider, tool) in expected {
            if let Some(tool) = tool {
                assert!(
                    known.contains(&tool),
                    "`{provider}` maps to unknown `{tool}`"
                );
            }
        }
    }

    #[test]
    fn test_linked_tool_reads_the_entrys_own_provider() {
        let v = vault();
        let entry = v
            .registry
            .add(sample("cf-api"), "value-1234", false)
            .unwrap();
        assert_eq!(entry.linked_tool(), Some("wrangler"));

        let other = v
            .registry
            .add(NewKey::new("o", "cli").provider("openai"), "v-1234", false)
            .unwrap();
        assert_eq!(other.linked_tool(), None);
    }

    #[test]
    fn test_expiry_state_buckets() {
        let now = Utc::now();
        let with = |expires: Option<DateTime<Utc>>| KeyEntry {
            id: "k".into(),
            provider: "cloudflare".into(),
            label: "k".into(),
            purpose: None,
            scopes: vec![],
            created_at: now,
            expires_at: expires,
            last4: "1234".into(),
            source: "cli".into(),
            endpoint: None,
        };

        assert_eq!(with(None).expiry_state(now), KeyExpiryState::NoExpiry);
        assert_eq!(
            with(Some(now - Duration::minutes(1))).expiry_state(now),
            KeyExpiryState::Expired
        );
        assert_eq!(
            with(Some(now + Duration::days(3))).expiry_state(now),
            KeyExpiryState::ExpiringSoon
        );
        // The boundary belongs to the warning, not to the all-clear.
        assert_eq!(
            with(Some(now + Duration::days(EXPIRING_SOON_DAYS))).expiry_state(now),
            KeyExpiryState::ExpiringSoon
        );
        assert_eq!(
            with(Some(now + Duration::days(EXPIRING_SOON_DAYS + 1))).expiry_state(now),
            KeyExpiryState::Valid
        );

        assert!(KeyExpiryState::Expired.needs_attention());
        assert!(KeyExpiryState::ExpiringSoon.needs_attention());
        assert!(!KeyExpiryState::Valid.needs_attention());
        assert!(!KeyExpiryState::NoExpiry.needs_attention());
        assert_eq!(KeyExpiryState::ExpiringSoon.label(), "expiring soon");
    }

    #[test]
    fn test_key_ref_is_metadata_only() {
        let v = vault();
        let entry = v
            .registry
            .add(sample("cf-api"), "super-secret-9876", false)
            .unwrap();
        let key_ref = entry.as_ref_at(Utc::now());

        assert_eq!(key_ref.id, "cf-api");
        assert_eq!(key_ref.last4, "9876");
        let json = serde_json::to_string(&key_ref).unwrap();
        assert!(!json.contains("super-secret"), "{json}");
        // The projection carries no purpose/scopes/source: it is a board chip,
        // not a second copy of the entry.
        assert!(!json.contains("purpose"), "{json}");
    }

    #[test]
    fn test_last4_handles_short_and_unicode_secrets() {
        assert_eq!(last4("abcdefgh"), "efgh");
        assert_eq!(last4("ab"), "ab");
        assert_eq!(last4(""), "");
        assert_eq!(last4("kéy-ø∆x9"), "ø∆x9");
    }

    #[test]
    fn test_empty_secret_is_refused() {
        let v = vault();
        let err = v
            .registry
            .add(sample("k"), "", false)
            .unwrap_err()
            .to_string();
        assert!(err.contains("empty secret"), "{err}");
        assert!(!v.registry.path().exists());
    }

    #[test]
    fn test_id_validation() {
        assert!(validate_id("cf-gh-actions-deploy").is_ok());
        assert!(validate_id("openai.prod_2").is_ok());
        assert!(validate_id("9lives").is_ok());

        for bad in [
            "",
            "-leading",
            "has space",
            "sla/sh",
            "semi;colon",
            "--flag",
        ] {
            assert!(validate_id(bad).is_err(), "`{bad}` should be rejected");
        }
        let err = validate_id("CF-Deploy").unwrap_err().to_string();
        assert!(err.contains("cf-deploy"), "{err}");
        assert!(validate_id(&"x".repeat(MAX_ID_LEN + 1)).is_err());
    }

    #[test]
    fn test_add_rejects_a_bad_id_before_touching_anything() {
        let v = vault();
        assert!(v
            .registry
            .add(NewKey::new("Bad Id", "cli"), "s3cr3t", false)
            .is_err());
        assert!(!v.registry.path().exists());
        assert!(v.store.is_empty());
    }

    #[test]
    fn test_a_malformed_registry_is_an_error_not_an_empty_vault() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("keys.json");
        std::fs::write(&path, "{ this is not json").unwrap();
        let registry = KeyRegistry::new(&path, Box::new(MemoryKeystore::new()));
        let err = registry.list().unwrap_err().to_string();
        assert!(
            err.contains("not a readable patchbay key registry"),
            "{err}"
        );
    }

    #[test]
    fn test_a_newer_file_version_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("keys.json");
        std::fs::write(&path, r#"{"version":99,"keys":[]}"#).unwrap();
        let registry = KeyRegistry::new(&path, Box::new(MemoryKeystore::new()));
        let err = registry.list().unwrap_err().to_string();
        assert!(err.contains("newer patchbay"), "{err}");
    }

    #[test]
    fn test_entries_survive_a_round_trip_through_the_file() {
        let v = vault();
        let expires = Utc::now() + Duration::days(400);
        v.registry
            .add(
                sample("round-trip").expires_at(Some(expires)),
                "value-6666",
                false,
            )
            .unwrap();

        // A second registry over the same path sees exactly the same entry.
        let reopened = KeyRegistry::new(v.registry.path(), Box::new(MemoryKeystore::new()));
        let entries = reopened.list().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].id, "round-trip");
        assert_eq!(
            entries[0].purpose.as_deref(),
            Some("deploy from GitHub Actions in repo X")
        );
        assert_eq!(entries[0].expires_at, Some(expires));
    }
}
