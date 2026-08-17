//! The per-tool adapter contract.

use crate::types::{PermissionScope, PermissionsReport, SwitchOutcome, ToolStatus, VerifyOutcome};

/// One developer CLI's auth state, as patchbay sees it.
///
/// Operations are split into two tiers:
///
/// * **tier 1** — [`Probe::status`]. Reads local state files only. No process
///   spawning, no network. Must stay in the low-milliseconds so the whole board
///   can be rendered on every prompt.
/// * **tier 2** — [`Probe::verify`], [`Probe::permissions`] and the scoped
///   variants beside them. May execute the tool's own CLI, which may in turn
///   hit the network. Seconds, not milliseconds. Only run when explicitly
///   asked.
///
/// [`Probe::switch`] mutates state and may exec the tool's CLI.
///
/// Every method returns `Ok` for the ordinary "this tool cannot do that" case —
/// `Err` is reserved for patchbay itself failing. A missing or malformed config
/// file is reported through [`ToolStatus::notes`], never as an error, so one
/// broken tool cannot take down the board.
pub trait Probe: Send + Sync {
    /// Stable tool key, e.g. `"gcloud"`.
    fn tool(&self) -> &'static str;

    /// Tier 1: read local state files.
    fn status(&self) -> anyhow::Result<ToolStatus>;

    /// Change the tool's active profile.
    fn switch(&self, profile_id: &str) -> anyhow::Result<SwitchOutcome>;

    /// Tier 2: check the credential actually works.
    ///
    /// Where the tool has an active profile, prefer delegating to
    /// [`Probe::verify_profile`] rather than refusing: "which one did you
    /// mean" is a question patchbay can usually answer for itself.
    fn verify(&self) -> anyhow::Result<VerifyOutcome>;

    /// Tier 2: check one specific profile.
    ///
    /// For several tools the meaningful unit is the profile, not the tool: an
    /// rclone remote, an ssh host, a kubectl context. The default delegates to
    /// [`Probe::verify`], which is right for tools where the distinction is
    /// meaningless (one login, one answer).
    ///
    /// Implementors: run the check for `profile_id` yourself. Handing back a
    /// command for the user to paste is not an answer — if a CLI has to be
    /// invoked, patchbay invokes it.
    fn verify_profile(&self, _profile_id: &str) -> anyhow::Result<VerifyOutcome> {
        self.verify()
    }

    /// Tier 2: report what the active credential is allowed to do.
    fn permissions(&self) -> anyhow::Result<PermissionsReport>;

    /// Tier 2: the scopes this tool's permissions can be read against.
    ///
    /// Empty — the default — means "one credential, one answer": ask
    /// [`Probe::permissions`] and be done. A non-empty list means the question
    /// is only well-formed once a scope is named, because the grants live on
    /// the resource rather than on the credential (GCP IAM is the type case:
    /// roles are per project, and the same account can be owner of one and a
    /// stranger to the next).
    ///
    /// This is tier 2 like its neighbours — enumerating scopes may execute the
    /// tool's CLI — so callers must treat it as a click, not a page load.
    fn permission_scopes(&self) -> anyhow::Result<Vec<PermissionScope>> {
        Ok(Vec::new())
    }

    /// Tier 2: report the credential's permissions within one scope.
    ///
    /// The default ignores `scope_id` and delegates to [`Probe::permissions`],
    /// which is right for every tool that reports no scopes: there is nothing
    /// to narrow.
    ///
    /// Implementors: resolve it yourself. Same rule as
    /// [`Probe::verify_profile`] — if a CLI has to be invoked, patchbay
    /// invokes it.
    fn permissions_in(&self, _scope_id: &str) -> anyhow::Result<PermissionsReport> {
        self.permissions()
    }
}

/// Helper for probes with no switch path.
pub fn unsupported_switch(tool: &'static str, reason: &str, hint: Option<&str>) -> SwitchOutcome {
    SwitchOutcome::Unsupported {
        tool: tool.to_string(),
        reason: reason.to_string(),
        hint: hint.map(|h| h.to_string()),
    }
}

/// Helper for probes with no verify path.
pub fn unsupported_verify(tool: &'static str, reason: &str, hint: Option<&str>) -> VerifyOutcome {
    VerifyOutcome::Unsupported {
        tool: tool.to_string(),
        reason: reason.to_string(),
        hint: hint.map(|h| h.to_string()),
    }
}

/// `UnknownProfile` populated from the probe's own status, so callers get the
/// list of ids they could have used.
pub fn unknown_profile(tool: &'static str, profile_id: &str, status: &ToolStatus) -> SwitchOutcome {
    SwitchOutcome::UnknownProfile {
        tool: tool.to_string(),
        profile_id: profile_id.to_string(),
        available: status.profiles.iter().map(|p| p.id.clone()).collect(),
    }
}
