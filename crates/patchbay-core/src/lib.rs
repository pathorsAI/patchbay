//! patchbay-core — a status board for the CLI logins on a developer machine.
//!
//! Each supported tool has a [`Probe`] that reads that tool's own local state
//! files (INI, YAML, TOML, JSON, SQLite) and reports profiles, which one is
//! active, and when the credential expires. Reads are file-only and take
//! milliseconds; anything that must execute a CLI or reach the network is a
//! separate, explicitly-requested tier-2 call.
//!
//! ```no_run
//! use patchbay_core::Registry;
//!
//! let registry = Registry::detect()?;
//! for status in registry.status_all() {
//!     println!("{}: {:?}", status.tool, status.active);
//! }
//! # Ok::<(), anyhow::Error>(())
//! ```
//!
//! **Secret handling.** patchbay reports *metadata about* credentials. Token,
//! secret and passphrase values are never copied into [`ToolStatus`], never
//! logged, and never included in error messages — probes parse only the fields
//! they need (expiry, scopes, account) and drop the rest.
//!
//! The one deliberate exception is the **key vault** ([`keys`]): standalone API
//! keys that no CLI tracks, which the user (or an AI agent) hands to patchbay on
//! purpose. Even there the split holds — metadata goes to a JSON file, the value
//! goes straight to the OS keychain ([`keystore`]), and
//! [`KeyRegistry::get_secret`] is the single, gated way back out.

pub mod keys;
pub mod keystore;
pub mod mcp_clients;
pub mod paths;
pub mod probe;
pub mod probes;
pub mod registry;
pub mod types;
pub mod util;

pub use keys::{KeyEntry, KeyPatch, KeyRegistry, NewKey};
pub use keystore::Keystore;
pub use mcp_clients::{
    McpClient, McpClientRegistry, McpServerEntry, McpTransport, ServerSpec, TransportSpec,
};
pub use paths::Paths;
pub use probe::Probe;
pub use registry::Registry;
pub use types::{
    ConnectionState, PermissionsReport, Profile, SwitchOutcome, ToolCategory, ToolStatus,
    VerifyOutcome,
};
