//! The set of probes patchbay knows about, and the entry points the CLI, the
//! MCP server and the app all go through.

use crate::paths::Paths;
use crate::probe::Probe;
use crate::probes;
use crate::types::{PermissionsReport, SwitchOutcome, ToolStatus, VerifyOutcome};

pub struct Registry {
    probes: Vec<Box<dyn Probe>>,
}

impl Registry {
    /// Every probe, bound to the given paths.
    pub fn all(paths: Paths) -> Self {
        Self {
            probes: vec![
                Box::new(probes::gcloud::GcloudProbe::new(paths.clone())),
                Box::new(probes::aws::AwsProbe::new(paths.clone())),
                Box::new(probes::gh::GhProbe::new(paths.clone())),
                Box::new(probes::infisical::InfisicalProbe::new(paths.clone())),
                Box::new(probes::kubectl::KubectlProbe::new(paths.clone())),
                Box::new(probes::wrangler::WranglerProbe::new(paths.clone())),
                Box::new(probes::rclone::RcloneProbe::new(paths.clone())),
                Box::new(probes::az::AzProbe::new(paths)),
            ],
        }
    }

    /// Probes bound to the real machine.
    pub fn detect() -> anyhow::Result<Self> {
        Ok(Self::all(Paths::detect()?))
    }

    pub fn tool_names(&self) -> Vec<&'static str> {
        self.probes.iter().map(|p| p.tool()).collect()
    }

    pub fn get(&self, tool: &str) -> Option<&dyn Probe> {
        self.probes
            .iter()
            .find(|p| p.tool() == tool)
            .map(|p| p.as_ref())
    }

    fn require(&self, tool: &str) -> anyhow::Result<&dyn Probe> {
        self.get(tool).ok_or_else(|| {
            anyhow::anyhow!(
                "unknown tool `{}`; known tools: {}",
                tool,
                self.tool_names().join(", ")
            )
        })
    }

    /// Tier 1 for every tool. Infallible by construction: a probe that errors
    /// becomes a status carrying the error as a note, so one broken tool never
    /// blanks the board.
    pub fn status_all(&self) -> Vec<ToolStatus> {
        self.probes
            .iter()
            .map(|p| {
                p.status().unwrap_or_else(|e| {
                    let mut status = ToolStatus::empty(p.tool(), false);
                    status.note(format!("probe failed: {e}"));
                    status
                })
            })
            .collect()
    }

    pub fn status(&self, tool: &str) -> anyhow::Result<ToolStatus> {
        self.require(tool)?.status()
    }

    pub fn switch(&self, tool: &str, profile_id: &str) -> anyhow::Result<SwitchOutcome> {
        self.require(tool)?.switch(profile_id)
    }

    pub fn verify(&self, tool: &str) -> anyhow::Result<VerifyOutcome> {
        self.require(tool)?.verify()
    }

    pub fn permissions(&self, tool: &str) -> anyhow::Result<PermissionsReport> {
        self.require(tool)?.permissions()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_status_all_covers_every_tool_on_an_empty_machine() {
        let dir = tempfile::tempdir().unwrap();
        let registry = Registry::all(Paths::for_test(dir.path()));
        let all = registry.status_all();
        assert_eq!(all.len(), 8);
        for status in &all {
            assert!(!status.installed, "{} should look absent", status.tool);
            assert!(
                status.profiles.is_empty(),
                "{} leaked profiles",
                status.tool
            );
        }
    }

    #[test]
    fn test_unknown_tool_is_a_clear_error() {
        let dir = tempfile::tempdir().unwrap();
        let registry = Registry::all(Paths::for_test(dir.path()));
        let err = registry.status("nope").unwrap_err().to_string();
        assert!(err.contains("unknown tool"), "{err}");
        assert!(err.contains("gcloud"), "{err}");
    }
}
