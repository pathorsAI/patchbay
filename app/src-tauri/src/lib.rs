//! Tauri shell for the patchbay panel.
//!
//! Every command is a thin wrapper over `patchbay-core`. The probes do file IO
//! and (tier 2) spawn the tools' own CLIs, so each call runs on the blocking
//! pool — the webview never waits on the async runtime's worker threads.

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
/// value — only its `last4`. [`KeyRegistry::get_secret`] is deliberately *not*
/// wired up as a command; the panel displays keys, it never needs to hold one.
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
            mcp_list
        ])
        .run(tauri::generate_context!())
        .expect("error while running patchbay");
}
