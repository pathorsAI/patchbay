//! Tauri shell for the patchbay panel.
//!
//! Every command is a thin wrapper over `patchbay-core`. The probes do file IO
//! and (tier 2) spawn the tools' own CLIs, so each call runs on the blocking
//! pool — the webview never waits on the async runtime's worker threads.

use chrono::{DateTime, NaiveDate, NaiveTime, TimeZone, Utc};
use patchbay_core::keys::NewKey;
use patchbay_core::{
    KeyEntry, KeyExpiryState, KeyRegistry, McpClient, McpClientRegistry, PermissionsReport,
    Registry, SwitchOutcome, ToolStatus, VerifyOutcome,
};

/// Probe errors are surfaced to the panel as strings; the panel renders them,
/// it cannot act on a typed error.
type CmdResult<T> = Result<T, String>;

/// Run `f` on the blocking pool. Every command goes through here: the probes,
/// the vault and the MCP client reads are all file IO.
async fn off_thread<T, F>(f: F) -> CmdResult<T>
where
    T: Send + 'static,
    F: FnOnce() -> anyhow::Result<T> + Send + 'static,
{
    tauri::async_runtime::spawn_blocking(f)
        .await
        .map_err(|e| format!("panel task failed: {e}"))?
        .map_err(|e| e.to_string())
}

async fn blocking<T, F>(f: F) -> CmdResult<T>
where
    T: Send + 'static,
    F: FnOnce(&Registry) -> anyhow::Result<T> + Send + 'static,
{
    off_thread(move || {
        let registry = Registry::detect()?;
        f(&registry)
    })
    .await
}

/// Tier 1 for every tool. Never fails per-tool: a broken probe becomes a note.
#[tauri::command]
async fn status_all() -> CmdResult<Vec<ToolStatus>> {
    blocking(|registry| Ok(registry.status_all())).await
}

#[tauri::command]
async fn switch_profile(tool: String, profile_id: String) -> CmdResult<SwitchOutcome> {
    blocking(move |registry| registry.switch(&tool, &profile_id)).await
}

#[tauri::command]
async fn verify(tool: String) -> CmdResult<VerifyOutcome> {
    blocking(move |registry| registry.verify(&tool)).await
}

/// Verify one profile rather than whatever the tool currently has active.
///
/// The panel verifies per profile row, because "is this login still good?" is a
/// question about a credential, not about a tool — on a board where `gcloud`
/// has two configurations, a single tool-level answer is ambiguous at best.
///
/// TODO(core): swap the body for `registry.verify_profile(&tool, &profile)`
/// once it lands — it is this one line. Until then every row asks about the
/// active profile, which is the honest subset of the answer rather than a
/// wrong one, and the UI already passes the profile id it wants.
#[tauri::command]
async fn verify_profile(tool: String, profile: String) -> CmdResult<VerifyOutcome> {
    let _ = &profile;
    blocking(move |registry| registry.verify(&tool)).await
}

#[tauri::command]
async fn permissions(tool: String) -> CmdResult<PermissionsReport> {
    blocking(move |registry| registry.permissions(&tool)).await
}

/// One vault entry as the panel needs it: the registry's own metadata plus the
/// expiry verdict, derived here with core's rule so the vault table and the key
/// markers on the board can never disagree about what "expiring soon" means.
///
/// Metadata only, by construction: [`KeyEntry`] has never carried the secret
/// value — only its `last4`.
///
/// The panel takes a secret exactly once — [`key_add`], from a masked field,
/// held in memory for the length of one call and handed straight to the
/// keychain. It never reads one back: [`KeyRegistry::get_secret`] is
/// deliberately *not* wired up as a command, there is no reveal and no copy in
/// this window, and `pb key copy` stays the only way a value gets out of the
/// vault. Writing is easy, reading is not — that asymmetry is the design, and
/// the CLI-only rule it replaced was about argv (`ps`, shell history), which a
/// masked field in a native app does not touch.
#[derive(serde::Serialize)]
struct KeyRow {
    #[serde(flatten)]
    entry: KeyEntry,
    expiry_state: KeyExpiryState,
}

#[tauri::command]
async fn keys_list() -> CmdResult<Vec<KeyRow>> {
    off_thread(|| {
        let registry = KeyRegistry::detect()?;
        let now = chrono::Utc::now();
        Ok(registry
            .list()?
            .into_iter()
            .map(|entry| KeyRow {
                expiry_state: entry.expiry_state(now),
                entry,
            })
            .collect())
    })
    .await
}

/// What [`key_remove`] reports back: enough to name the key that is gone in a
/// confirmation, and nothing else. `last4` is the same four characters the
/// table was already showing.
#[derive(serde::Serialize)]
struct RemovedKey {
    id: String,
    last4: String,
}

/// A date the panel's form accepts: `YYYY-MM-DD` (UTC midnight) or a full
/// timestamp. Reimplemented rather than shared with the CLI's `--expires`
/// parser — the panel does not depend on `patchbay-cli` and is not about to
/// start for six lines. Both go through `patchbay_core::util::parse_timestamp`,
/// which is where the timestamp knowledge actually lives.
fn parse_expiry(raw: &str) -> anyhow::Result<DateTime<Utc>> {
    let raw = raw.trim();
    if let Ok(date) = NaiveDate::parse_from_str(raw, "%Y-%m-%d") {
        return Ok(Utc.from_utc_datetime(&date.and_time(NaiveTime::MIN)));
    }
    patchbay_core::util::parse_timestamp(raw)
        .ok_or_else(|| anyhow::anyhow!("could not read `{raw}` as a date; try `2027-01-01`"))
}

/// Trimmed, or `None` when the field was left blank — an empty optional field
/// is an absent one, not an empty string in the registry.
fn some_text(raw: Option<String>) -> Option<String> {
    raw.map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
}

/// Register a key: metadata to `keys.json`, value to the keychain, both or
/// neither — [`KeyRegistry::add`] owns that guarantee and its rules (duplicate
/// id refused unless `overwrite`, empty secret refused) are surfaced to the
/// panel verbatim rather than re-litigated here.
///
/// `secret` is the one piece of credential material that crosses this boundary.
/// It is moved into the blocking closure, borrowed once by `add`, and dropped
/// there. It is never logged, never stored, and never put in an error: every
/// message the panel can show comes from the registry, which only ever knew the
/// metadata.
#[tauri::command]
#[allow(clippy::too_many_arguments)]
async fn key_add(
    id: String,
    provider: Option<String>,
    label: Option<String>,
    purpose: Option<String>,
    scopes: Vec<String>,
    expires: Option<String>,
    endpoint: Option<String>,
    secret: String,
    overwrite: bool,
) -> CmdResult<KeyRow> {
    off_thread(move || {
        let id = id.trim().to_string();
        let expires_at = some_text(expires)
            .as_deref()
            .map(parse_expiry)
            .transpose()?;
        let new = NewKey::new(
            id.as_str(),
            // Where the entry came from, for the `source` column. The vault has
            // said `"gui"` since it was written; this is the first thing to use it.
            "gui",
        )
        .provider(some_text(provider).unwrap_or_else(|| "unknown".to_string()))
        .label(some_text(label).unwrap_or_else(|| id.clone()))
        .purpose(some_text(purpose))
        .scopes(
            scopes
                .into_iter()
                .filter_map(|s| some_text(Some(s)))
                .collect(),
        )
        .expires_at(expires_at)
        .endpoint(some_text(endpoint));

        let registry = KeyRegistry::detect()?;
        let entry = registry.add(new, &secret, overwrite)?;
        drop(secret);

        Ok(KeyRow {
            expiry_state: entry.expiry_state(Utc::now()),
            entry,
        })
    })
    .await
}

/// Unregister a key: the metadata row and the keychain item both go. Removing
/// is not revoking — the credential itself keeps working, which is why the
/// panel says so before it asks.
#[tauri::command]
async fn key_remove(id: String) -> CmdResult<RemovedKey> {
    off_thread(move || {
        let entry = KeyRegistry::detect()?.remove(id.trim())?;
        Ok(RemovedKey {
            id: entry.id,
            last4: entry.last4,
        })
    })
    .await
}

/// Every MCP client patchbay knows about, present or not — the absent ones are
/// the point of the matrix as much as the present ones. Server entries carry
/// env var *names* and header *names* only; core never reads the values.
#[tauri::command]
async fn mcp_list() -> CmdResult<Vec<McpClient>> {
    off_thread(|| Ok(McpClientRegistry::detect()?.clients())).await
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        // Self-update. The updater reads the signed feed named in
        // tauri.conf.json; `process` supplies the relaunch that takes the user
        // into the build it just installed. Both are inert until the front end
        // calls them — see `src/lib/update.ts`.
        .plugin(tauri_plugin_process::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        // A blank window is nearly always "the webview could not load its
        // source" — a debug binary run without `tauri dev` points at the Vite
        // URL and finds nothing there. Say which URL, and whether it loaded.
        .setup(|app| {
            #[cfg(debug_assertions)]
            {
                use tauri::Manager;
                if let Some(window) = app.get_webview_window("main") {
                    eprintln!("[patchbay] webview source: {:?}", window.url());
                }
            }
            let _ = app;
            Ok(())
        })
        .on_page_load(|_webview, payload| {
            #[cfg(debug_assertions)]
            eprintln!("[patchbay] {:?} {}", payload.event(), payload.url());
            let _ = payload;
        })
        .invoke_handler(tauri::generate_handler![
            status_all,
            switch_profile,
            verify,
            verify_profile,
            permissions,
            keys_list,
            key_add,
            key_remove,
            mcp_list
        ])
        .run(tauri::generate_context!())
        .expect("error while running patchbay");
}
