//! Moving a developer machine, honestly.
//!
//! The problem with "just copy your dotfiles" is that roughly half of a
//! developer's logins are not in dotfiles: they are in the OS keychain, in a
//! device-registered session, or in a key that *is* the machine's identity.
//! Copying those either does nothing or does something worse than nothing. The
//! problem with "just log in again" is the other half — the ones that are plain
//! files, that would have worked, and that you now spend an afternoon
//! re-creating from memory.
//!
//! So patchbay does the hybrid, and says which is which:
//!
//! * [`policy`] classifies every tool on the board — `Portable`, `DeviceBound`
//!   or `PointerOnly` — with the reason in the table.
//! * [`export`] copies what can move into one encrypted [`bundle`], and writes
//!   a [`manifest`] plus a generated [`setup`] guide beside it *inside* the
//!   same file.
//! * [`import`] puts it back, backing up anything it would replace, and never
//!   writing twice.
//! * [`plan`] re-reads the new machine and turns the rest into a checklist with
//!   an exact command per line — the half an AI agent can actually work.
//!
//! Two rules run through all of it. **No secret value ever leaves the encrypted
//! payload**: not into the manifest, not into `SETUP.md`, not into a log line,
//! an error or an MCP response. And **every file is located through
//! [`crate::paths::Paths`]**, on both machines independently, so an export from
//! a machine with `AWS_CONFIG_FILE` set reads the right file and an import into
//! a machine with its own override writes the right one.

pub mod bundle;
pub mod export;
pub mod import;
pub mod manifest;
pub mod plan;
pub mod policy;
pub mod setup;

pub use bundle::{peek_version, Payload, BUNDLE_EXTENSION};
pub use export::{
    check_destination, cloud_service, default_file_name, ExportReport, Exporter, KeySelection,
};
pub use import::{EnvProjectResult, FileOutcome, ImportOptions, ImportReport, Importer};
pub use manifest::{
    EnvEnvironmentRecord, EnvProjectRecord, EnvSyncRecord, Manifest, ManifestKind, SetupItem,
    SetupStatus, ToolRecord, BUNDLE_VERSION,
};
pub use plan::{plan, recheck};
pub use policy::{policy_for, Location, Portability, PortabilityKind, ToolPolicy, POLICIES};
