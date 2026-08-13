//! Tauri shell for the patchbay panel.
//!
//! Every command is a thin wrapper over `patchbay-core`. The probes do file IO
//! and (tier 2) spawn the tools' own CLIs, so each call runs on the blocking
//! pool — the webview never waits on the async runtime's worker threads.

use patchbay_core::{PermissionsReport, Registry, SwitchOutcome, ToolStatus, VerifyOutcome};

/// Probe errors are surfaced to the panel as strings; the panel renders them,
/// it cannot act on a typed error.
type CmdResult<T> = Result<T, String>;

async fn blocking<T, F>(f: F) -> CmdResult<T>
where
    T: Send + 'static,
    F: FnOnce(&Registry) -> anyhow::Result<T> + Send + 'static,
{
    tauri::async_runtime::spawn_blocking(move || {
        let registry = Registry::detect()?;
        f(&registry)
    })
    .await
    .map_err(|e| format!("panel task failed: {e}"))?
    .map_err(|e| e.to_string())
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

#[tauri::command]
async fn permissions(tool: String) -> CmdResult<PermissionsReport> {
    blocking(move |registry| registry.permissions(&tool)).await
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
            permissions
        ])
        .run(tauri::generate_context!())
        .expect("error while running patchbay");
}
