//! `patchbay-mcp` — an MCP stdio server exposing patchbay to AI agents.
//!
//! stdout is the JSON-RPC channel and nothing else may be written there.
//! Every diagnostic in this binary goes to stderr.
//!
//! Run it directly to talk JSON-RPC over stdin/stdout, or register it with an
//! MCP client:
//!
//! ```jsonc
//! { "mcpServers": { "patchbay": { "command": "patchbay-mcp" } } }
//! ```

mod envs;
mod keys;
mod mcp_clients;
mod migrate;
mod server;

use rmcp::transport::stdio;
use rmcp::ServiceExt;

use server::PatchbayServer;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // A GUI MCP client (Claude Desktop, an IDE) spawns this server with
    // launchd's bare PATH, under which every `which gcloud` fails. Adopt the
    // login shell's PATH before the first probe can resolve a binary.
    patchbay_core::adopt_login_shell_path();
    // Detect once: the probe set is bound to this machine's config paths, and
    // each probe re-reads its files on every call, so nothing goes stale.
    let registry = patchbay_core::Registry::detect()?;
    // The key vault: metadata file plus the OS keychain, re-read per call.
    let keys = patchbay_core::KeyRegistry::detect()?;
    // The MCP client board: other tools' config files, re-read per call.
    let clients = patchbay_core::McpClientRegistry::detect()?;
    // The project env vault: projects.json plus the OS keychain, re-read per
    // call, so a `pb env pull` from a terminal is visible here immediately.
    let envs = patchbay_core::EnvRegistry::detect()?;

    let service = PatchbayServer::new(registry, keys, clients, envs)
        .serve(stdio())
        .await
        .inspect_err(|e| eprintln!("patchbay-mcp: failed to start: {e}"))?;

    service.waiting().await?;
    Ok(())
}
