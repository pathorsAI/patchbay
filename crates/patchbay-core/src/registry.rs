//! The set of probes patchbay knows about, and the entry points the CLI, the
//! MCP server and the app all go through.

use crate::paths::Paths;
use crate::probe::Probe;
use crate::probes;
use crate::types::{PermissionsReport, SwitchOutcome, ToolStatus, VerifyOutcome};

pub struct Registry {
    probes: Vec<Box<dyn Probe>>,
    /// Kept so [`Registry::status_all`] can surface problems with patchbay's
    /// own config (see [`Paths::config_warnings`]).
    paths: Paths,
}

impl Registry {
    /// Every probe, bound to the given paths. Grouped by category, matching
    /// the order the panel's sidebar lists them in.
    pub fn all(paths: Paths) -> Self {
        Self {
            probes: vec![
                // cloud
                Box::new(probes::gcloud::GcloudProbe::new(paths.clone())),
                Box::new(probes::aws::AwsProbe::new(paths.clone())),
                Box::new(probes::az::AzProbe::new(paths.clone())),
                Box::new(probes::firebase::FirebaseProbe::new(paths.clone())),
                Box::new(probes::neon::NeonProbe::new(paths.clone())),
                Box::new(probes::supabase::SupabaseProbe::new(paths.clone())),
                Box::new(probes::flyctl::FlyctlProbe::new(paths.clone())),
                Box::new(probes::doctl::DoctlProbe::new(paths.clone())),
                // code
                Box::new(probes::gh::GhProbe::new(paths.clone())),
                Box::new(probes::npm::NpmProbe::new(paths.clone())),
                // secrets
                Box::new(probes::infisical::InfisicalProbe::new(paths.clone())),
                Box::new(probes::op::OpProbe::new(paths.clone())),
                // cluster
                Box::new(probes::kubectl::KubectlProbe::new(paths.clone())),
                // edge
                Box::new(probes::wrangler::WranglerProbe::new(paths.clone())),
                Box::new(probes::vercel::VercelProbe::new(paths.clone())),
                // storage
                Box::new(probes::rclone::RcloneProbe::new(paths.clone())),
                // containers
                Box::new(probes::docker::DockerProbe::new(paths.clone())),
                // network
                Box::new(probes::tailscale::TailscaleProbe::new(paths.clone())),
                Box::new(probes::ssh::SshProbe::new(paths.clone())),
                // payments
                Box::new(probes::stripe::StripeProbe::new(paths.clone())),
                // ai
                Box::new(probes::ollama::OllamaProbe::new(paths.clone())),
                Box::new(probes::huggingface::HuggingfaceProbe::new(paths.clone())),
                Box::new(probes::claude::ClaudeProbe::new(paths.clone())),
            ],
            paths,
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
        let mut all: Vec<ToolStatus> = self
            .probes
            .iter()
            .map(|p| {
                p.status().unwrap_or_else(|e| {
                    let mut status = ToolStatus::empty(p.tool(), false);
                    status.note(format!("probe failed: {e}"));
                    status
                })
            })
            .collect();

        // A broken patchbay config is about patchbay, not about any one tool,
        // and the data model has no global slot for it. It goes on the first
        // status only — repeating it 23 times would drown the board and, for
        // an agent reading list_connections, cost 23 copies of the same
        // sentence. The message names itself, so it does not read as a
        // complaint about that tool.
        if let Some(first) = all.first_mut() {
            for warning in self.paths.config_warnings() {
                first.note(warning.clone());
            }
        }
        all
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
        assert_eq!(all.len(), 23);
        for status in &all {
            assert!(!status.installed, "{} should look absent", status.tool);
            assert!(
                status.profiles.is_empty(),
                "{} leaked profiles",
                status.tool
            );
            assert!(
                status.notes.is_empty(),
                "{} is noisy on a machine that has nothing: {:?}",
                status.tool,
                status.notes
            );
        }
    }

    #[test]
    fn test_tool_keys_are_unique() {
        let dir = tempfile::tempdir().unwrap();
        let registry = Registry::all(Paths::for_test(dir.path()));
        let mut names = registry.tool_names();
        names.sort_unstable();
        let count = names.len();
        names.dedup();
        assert_eq!(names.len(), count, "duplicate tool key in the registry");
    }

    #[test]
    fn test_every_tool_is_categorised() {
        let dir = tempfile::tempdir().unwrap();
        let registry = Registry::all(Paths::for_test(dir.path()));
        for status in registry.status_all() {
            assert_ne!(
                status.category,
                crate::types::ToolCategory::Other,
                "{} has no category",
                status.tool
            );
        }
    }

    #[test]
    fn test_a_broken_patchbay_config_is_reported_on_the_board() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join(".config/patchbay")).unwrap();
        std::fs::write(
            dir.path().join(".config/patchbay/config.toml"),
            "[paths]\nnot_a_tool = \"/x\"\n",
        )
        .unwrap();
        let registry = Registry::all(Paths::for_test(dir.path()).load_config());
        let all = registry.status_all();
        assert!(all[0]
            .notes
            .iter()
            .any(|n| n.contains("patchbay config: unknown key `not_a_tool`")));
        // Once, not once per tool.
        let carriers = all
            .iter()
            .filter(|s| s.notes.iter().any(|n| n.contains("unknown key")))
            .count();
        assert_eq!(carriers, 1);
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
