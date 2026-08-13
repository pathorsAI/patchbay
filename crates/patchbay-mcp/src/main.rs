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

mod server;

use rmcp::transport::stdio;
use rmcp::ServiceExt;

use server::PatchbayServer;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Detect once: the probe set is bound to this machine's config paths, and
    // each probe re-reads its files on every call, so nothing goes stale.
    let registry = patchbay_core::Registry::detect()?;

    let service = PatchbayServer::new(registry)
        .serve(stdio())
        .await
        .inspect_err(|e| eprintln!("patchbay-mcp: failed to start: {e}"))?;

    service.waiting().await?;
    Ok(())
}
