//! `kubectl` — contexts from the kubeconfig.
//!
//! Reads every file in `$KUBECONFIG` (`:`-separated, merged by kubectl) or
//! `~/.kube/config` when unset. Contexts have no expiry of their own: a context
//! points at a user, and that user is often an `exec` credential plugin
//! (`gke-gcloud-auth-plugin`, `aws eks get-token`) that mints short-lived
//! tokens on demand. That indirection is recorded in `meta.auth` because it is
//! exactly what breaks when you switch the *other* tool's profile.

use serde::Deserialize;

use crate::paths::Paths;
use crate::probe::{unknown_profile, unsupported_switch, unsupported_verify, Probe};
use crate::types::{PermissionsReport, Profile, SwitchOutcome, ToolStatus, VerifyOutcome};
use crate::util::{read_text, run};

pub struct KubectlProbe {
    paths: Paths,
}

#[derive(Deserialize)]
struct KubeConfig {
    #[serde(default, rename = "current-context")]
    current_context: Option<String>,
    #[serde(default)]
    contexts: Vec<NamedContext>,
    #[serde(default)]
    users: Vec<NamedUser>,
}

#[derive(Deserialize)]
struct NamedContext {
    name: String,
    #[serde(default)]
    context: ContextBody,
}

#[derive(Default, Deserialize)]
struct ContextBody {
    #[serde(default)]
    cluster: Option<String>,
    #[serde(default)]
    user: Option<String>,
    #[serde(default)]
    namespace: Option<String>,
}

#[derive(Deserialize)]
struct NamedUser {
    name: String,
    #[serde(default)]
    user: UserBody,
}

/// Only the *shape* of the credential is read. `token`, `client-key-data` and
/// `password` have no fields here, so they are discarded during parsing.
#[derive(Default, Deserialize)]
struct UserBody {
    #[serde(default)]
    exec: Option<ExecConfig>,
    #[serde(default, rename = "auth-provider")]
    auth_provider: Option<AuthProvider>,
}

#[derive(Deserialize)]
struct ExecConfig {
    #[serde(default)]
    command: Option<String>,
}

#[derive(Deserialize)]
struct AuthProvider {
    #[serde(default)]
    name: Option<String>,
}

impl KubectlProbe {
    pub const TOOL: &'static str = "kubectl";

    pub fn new(paths: Paths) -> Self {
        Self { paths }
    }
}

impl Probe for KubectlProbe {
    fn tool(&self) -> &'static str {
        Self::TOOL
    }

    fn status(&self) -> anyhow::Result<ToolStatus> {
        let candidates = self.paths.kube_configs();
        let installed = self.paths.has_binary("kubectl") || candidates.iter().any(|p| p.exists());
        let mut status = ToolStatus::empty(Self::TOOL, installed);
        for note in self.paths.path_notes("kubeconfig") {
            status.note(note);
        }

        for path in &candidates {
            // A real trap seen in the wild: ~/.kube/config exists but is a
            // *directory* full of per-cluster yaml files, which makes every
            // kubectl call fail until KUBECONFIG is set.
            if path.is_dir() {
                status.note(format!(
                    "{} is a directory, not a kubeconfig file; kubectl will fail until KUBECONFIG points at the files inside it",
                    path.display()
                ));
                continue;
            }
            let text = match read_text(path) {
                Ok(Some(text)) => text,
                Ok(None) => continue,
                Err(e) => {
                    status.note(e);
                    continue;
                }
            };
            let config: KubeConfig = match serde_yaml_ng::from_str(&text) {
                Ok(config) => config,
                Err(e) => {
                    status.note(format!("{} is not valid YAML ({e})", path.display()));
                    continue;
                }
            };

            for named in config.contexts {
                if status.profiles.iter().any(|p| p.id == named.name) {
                    // kubectl's merge rule: first file wins.
                    continue;
                }
                let user = named.context.user.clone();
                let user_body = user
                    .as_ref()
                    .and_then(|name| config.users.iter().find(|u| &u.name == name));
                let auth = match user_body.map(|u| &u.user) {
                    Some(UserBody {
                        exec: Some(exec), ..
                    }) => format!(
                        "exec plugin ({})",
                        exec.command.as_deref().unwrap_or("unnamed")
                    ),
                    Some(UserBody {
                        auth_provider: Some(provider),
                        ..
                    }) => format!(
                        "auth-provider ({})",
                        provider.name.as_deref().unwrap_or("unnamed")
                    ),
                    Some(_) => "static credential in kubeconfig".to_string(),
                    None => "unknown".to_string(),
                };

                status.profiles.push(
                    Profile::new(&named.name)
                        .with_meta("cluster", named.context.cluster.clone())
                        .with_meta("user", user)
                        .with_meta("namespace", named.context.namespace.clone())
                        .with_meta("auth", auth)
                        .with_meta("source", path.display().to_string()),
                );
            }

            if status.active.is_none() {
                status.active = config.current_context.filter(|c| !c.is_empty());
            }
        }

        if let Some(active) = &status.active {
            if !status.profiles.iter().any(|p| &p.id == active) {
                status.note(format!(
                    "current-context is `{active}` but no context with that name is defined"
                ));
            }
        }

        // Exec plugins are why "I switched gcloud accounts and kubectl broke".
        let exec_contexts: Vec<&str> = status
            .profiles
            .iter()
            .filter(|p| {
                p.meta
                    .get("auth")
                    .and_then(|v| v.as_str())
                    .is_some_and(|a| a.starts_with("exec plugin"))
            })
            .map(|p| p.id.as_str())
            .collect();
        if !exec_contexts.is_empty() {
            status.note(format!(
                "{} context(s) mint tokens through an exec credential plugin, so they inherit whichever cloud account is active: {}",
                exec_contexts.len(),
                exec_contexts.join(", ")
            ));
        }

        Ok(status)
    }

    fn switch(&self, profile_id: &str) -> anyhow::Result<SwitchOutcome> {
        let status = self.status()?;
        if !status.profiles.iter().any(|p| p.id == profile_id) {
            return Ok(unknown_profile(Self::TOOL, profile_id, &status));
        }
        if !self.paths.may_exec() {
            return Ok(unsupported_switch(
                Self::TOOL,
                "command execution is disabled for this probe",
                Some(&format!("kubectl config use-context {profile_id}")),
            ));
        }

        let out = run("kubectl", &["config", "use-context", profile_id])?;
        Ok(if out.ok {
            SwitchOutcome::Switched {
                tool: Self::TOOL.to_string(),
                profile_id: profile_id.to_string(),
                detail: out.message(),
                notes: vec![
                    "this rewrites current-context in the kubeconfig, so every shell on this machine follows".to_string(),
                ],
            }
        } else {
            SwitchOutcome::Failed {
                tool: Self::TOOL.to_string(),
                profile_id: profile_id.to_string(),
                detail: out.message(),
            }
        })
    }

    fn verify(&self) -> anyhow::Result<VerifyOutcome> {
        if !self.paths.may_exec() || !self.paths.has_binary("kubectl") {
            return Ok(unsupported_verify(
                Self::TOOL,
                "the kubectl CLI is not available on PATH",
                Some("kubectl auth whoami"),
            ));
        }
        // Cheap, authenticated, and does not need list permission on anything.
        let out = run("kubectl", &["auth", "whoami"])?;
        Ok(if out.ok {
            VerifyOutcome::Valid {
                tool: Self::TOOL.to_string(),
                detail: out.message(),
            }
        } else {
            VerifyOutcome::Invalid {
                tool: Self::TOOL.to_string(),
                detail: out.message(),
            }
        })
    }

    fn permissions(&self) -> anyhow::Result<PermissionsReport> {
        Ok(PermissionsReport::unsupported(
            Self::TOOL,
            "RBAC permissions are per-namespace and per-resource; patchbay does not enumerate them",
            Some("kubectl auth can-i --list"),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    const CONFIG: &str = r#"
apiVersion: v1
kind: Config
current-context: prod
contexts:
  - name: prod
    context:
      cluster: prod-cluster
      user: gke-user
      namespace: default
  - name: local
    context:
      cluster: k3d
      user: k3d-user
users:
  - name: gke-user
    user:
      exec:
        apiVersion: client.authentication.k8s.io/v1beta1
        command: gke-gcloud-auth-plugin
  - name: k3d-user
    user:
      client-certificate-data: ZmFrZS1maXh0dXJl
      client-key-data: ZmFrZS1maXh0dXJlLWtleQ==
"#;

    fn fixture(rel: &str, body: &str) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().to_path_buf();
        let path = home.join(rel);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, body).unwrap();
        (dir, home)
    }

    #[test]
    fn test_contexts_current_context_and_exec_plugins() {
        let (_dir, home) = fixture(".kube/config", CONFIG);
        let status = KubectlProbe::new(Paths::for_test(&home)).status().unwrap();
        let ids: Vec<_> = status.profiles.iter().map(|p| p.id.as_str()).collect();
        assert_eq!(ids, vec!["prod", "local"]);
        assert_eq!(status.active.as_deref(), Some("prod"));
        assert_eq!(status.profiles[0].meta["cluster"], "prod-cluster");
        assert_eq!(status.profiles[0].meta["namespace"], "default");
        assert_eq!(
            status.profiles[0].meta["auth"],
            "exec plugin (gke-gcloud-auth-plugin)"
        );
        assert_eq!(
            status.profiles[1].meta["auth"],
            "static credential in kubeconfig"
        );
        assert!(status
            .notes
            .iter()
            .any(|n| n.contains("exec credential plugin")));

        // Embedded client key data must never be carried along.
        let json = serde_json::to_string(&status).unwrap();
        assert!(!json.contains("ZmFrZS1maXh0dXJlLWtleQ"), "{json}");
    }

    #[test]
    fn test_kubeconfig_env_merges_files_first_wins() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a.yaml");
        let b = dir.path().join("b.yaml");
        fs::write(
            &a,
            "current-context: one\ncontexts:\n  - name: one\n    context:\n      cluster: c1\n",
        )
        .unwrap();
        fs::write(
            &b,
            "current-context: two\ncontexts:\n  - name: two\n    context:\n      cluster: c2\n  - name: one\n    context:\n      cluster: shadowed\n",
        )
        .unwrap();

        let paths = Paths::for_test(dir.path())
            .with_env("KUBECONFIG", &format!("{}:{}", a.display(), b.display()));
        let status = KubectlProbe::new(paths).status().unwrap();
        let ids: Vec<_> = status.profiles.iter().map(|p| p.id.as_str()).collect();
        assert_eq!(ids, vec!["one", "two"]);
        assert_eq!(status.active.as_deref(), Some("one"));
        assert_eq!(status.profiles[0].meta["cluster"], "c1");
    }

    #[test]
    fn test_config_path_that_is_a_directory_is_called_out() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join(".kube/config")).unwrap();
        let status = KubectlProbe::new(Paths::for_test(dir.path()))
            .status()
            .unwrap();
        assert!(status.installed);
        assert!(status.profiles.is_empty());
        assert!(status.notes.iter().any(|n| n.contains("is a directory")));
    }

    #[test]
    fn test_missing_config_is_installed_with_zero_contexts() {
        let dir = tempfile::tempdir().unwrap();
        let status = KubectlProbe::new(Paths::for_test(dir.path()))
            .status()
            .unwrap();
        assert!(status.profiles.is_empty());
        assert!(status.active.is_none());
        assert!(status.notes.is_empty());
    }

    #[test]
    fn test_malformed_yaml_and_dangling_current_context() {
        let (_dir, home) = fixture(".kube/config", "\tnot: [valid yaml");
        let status = KubectlProbe::new(Paths::for_test(&home)).status().unwrap();
        assert!(status.notes.iter().any(|n| n.contains("not valid YAML")));

        let (_dir, home) = fixture(".kube/config", "current-context: ghost\ncontexts: []\n");
        let status = KubectlProbe::new(Paths::for_test(&home)).status().unwrap();
        assert!(status
            .notes
            .iter()
            .any(|n| n.contains("no context with that name")));
    }
}
