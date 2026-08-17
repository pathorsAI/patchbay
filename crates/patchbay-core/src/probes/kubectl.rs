//! `kubectl` — contexts from the kubeconfig.
//!
//! Resolution order: every file in `$KUBECONFIG` (`:`-separated, merged by
//! kubectl), else `~/.kube/config` as a file, else — the pattern this machine
//! and plenty of others use — `~/.kube/config` as a *directory* of per-cluster
//! yaml files, which is scanned non-recursively and merged the same way.
//!
//! Contexts have no credential of their own: a context points at a user, and
//! that user is often an `exec` credential plugin (`gke-gcloud-auth-plugin`,
//! `aws eks get-token`) that mints short-lived tokens on demand. That
//! indirection is recorded in `meta.auth` because it is exactly what breaks
//! when you switch the *other* tool's profile.
//!
//! It also decides the expiry, which is [`Expiry::Unknown`] in every case and
//! for a different reason each time — an exec plugin's deadline belongs to
//! whichever cloud CLI it shells out to, an embedded client certificate has one
//! this probe does not parse. Never [`Expiry::NoExpiry`]: nothing here is
//! eternal by design, patchbay simply does not hold the clock.

use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::paths::Paths;
use crate::probe::{exec_disabled_switch, unknown_profile, unsupported_verify, Probe};
use crate::types::{Expiry, PermissionsReport, Profile, SwitchOutcome, ToolStatus, VerifyOutcome};
use crate::util::read_text;

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

/// One `~/.kube/config`-is-a-directory expansion, kept so the note at the end
/// can name the files that actually parsed.
struct DirScan {
    dir: PathBuf,
    /// Files that parsed as YAML, in scan order.
    parsed: Vec<PathBuf>,
    /// Of those, the ones that defined at least one context, with their own
    /// `current-context`.
    with_contexts: Vec<(PathBuf, Option<String>)>,
}

/// The `*.yaml`/`*.yml` files directly inside `dir`, sorted by name so the
/// first-file-wins merge is deterministic. Anything else in there — the
/// `gke_gcloud_auth_plugin_cache` blob, lock files, subdirectories — is not a
/// kubeconfig and is left alone.
fn kubeconfig_files_in(dir: &Path) -> std::io::Result<Vec<PathBuf>> {
    let mut files: Vec<PathBuf> = std::fs::read_dir(dir)?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|p| p.is_file())
        .filter(|p| {
            matches!(
                p.extension().and_then(|e| e.to_str()),
                Some("yaml") | Some("yml")
            )
        })
        .collect();
    files.sort();
    Ok(files)
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
            status.push_note(note);
        }

        // A real trap seen in the wild: ~/.kube/config exists but is a
        // *directory* full of per-cluster yaml files. kubectl itself fails on
        // that, but the contexts are right there — read them rather than
        // reporting zero, and tell the operator how to make their shell agree.
        let mut sources: Vec<(PathBuf, Option<usize>)> = Vec::new();
        let mut scans: Vec<DirScan> = Vec::new();
        for path in &candidates {
            if path.is_dir() {
                match kubeconfig_files_in(path) {
                    Ok(files) => {
                        let index = scans.len();
                        scans.push(DirScan {
                            dir: path.clone(),
                            parsed: Vec::new(),
                            with_contexts: Vec::new(),
                        });
                        sources.extend(files.into_iter().map(|f| (f, Some(index))));
                    }
                    Err(e) => status.problem(format!(
                        "{} is a directory that could not be listed ({e})",
                        path.display()
                    )),
                }
            } else {
                sources.push((path.clone(), None));
            }
        }

        // `current-context` from the first file that names one — but only for
        // files kubectl would itself merge. Directory scans decide separately.
        let mut active: Option<String> = None;

        for (path, scan) in &sources {
            let path = path.as_path();
            let text = match read_text(path) {
                Ok(Some(text)) => text,
                Ok(None) => continue,
                Err(e) => {
                    status.problem(e);
                    continue;
                }
            };
            let config: KubeConfig = match serde_yaml_ng::from_str(&text) {
                Ok(config) => config,
                Err(e) => {
                    status.problem(format!("{} is not valid YAML ({e})", path.display()));
                    continue;
                }
            };

            let current = config.current_context.clone().filter(|c| !c.is_empty());
            let has_contexts = !config.contexts.is_empty();
            match scan {
                Some(index) => {
                    scans[*index].parsed.push(path.to_path_buf());
                    if has_contexts {
                        scans[*index]
                            .with_contexts
                            .push((path.to_path_buf(), current));
                    }
                }
                None => {
                    if active.is_none() {
                        active = current;
                    }
                }
            }

            for named in config.contexts {
                if status.profiles.iter().any(|p| p.id == named.name) {
                    // kubectl's merge rule: first file wins.
                    continue;
                }
                let user = named.context.user.clone();
                let user_body = user
                    .as_ref()
                    .and_then(|name| config.users.iter().find(|u| &u.name == name));
                // How the context authenticates decides where its expiry lives,
                // so the two are read off the same user entry.
                let (auth, expiry) = match user_body.map(|u| &u.user) {
                    Some(UserBody {
                        exec: Some(exec), ..
                    }) => (
                        format!(
                            "exec plugin ({})",
                            exec.command.as_deref().unwrap_or("unnamed")
                        ),
                        Expiry::unknown("with the cloud CLI the exec plugin calls"),
                    ),
                    Some(UserBody {
                        auth_provider: Some(provider),
                        ..
                    }) => (
                        format!(
                            "auth-provider ({})",
                            provider.name.as_deref().unwrap_or("unnamed")
                        ),
                        Expiry::unknown("in the auth provider's own token cache"),
                    ),
                    Some(_) => (
                        "static credential in kubeconfig".to_string(),
                        Expiry::unknown("in the credential embedded in the kubeconfig"),
                    ),
                    None => (
                        "unknown".to_string(),
                        Expiry::unknown("no user entry for this context"),
                    ),
                };

                status.profiles.push(
                    Profile::new(&named.name)
                        .expiry(expiry)
                        .with_meta("cluster", named.context.cluster.clone())
                        .with_meta("user", user)
                        .with_meta("namespace", named.context.namespace.clone())
                        .with_meta("auth", auth)
                        .with_meta("source", path.display().to_string()),
                );
            }
        }

        for scan in &scans {
            match scan.with_contexts.len() {
                // Nothing usable in there: the old failure mode, unchanged.
                0 => status.problem(format!(
                    "{} is a directory, not a kubeconfig file, and no *.yaml/*.yml file inside it defines any context; kubectl will fail until KUBECONFIG points at a real config",
                    scan.dir.display()
                )),
                // Exactly one file carries contexts, so its own
                // `current-context` is unambiguously the active one.
                1 => {
                    if active.is_none() {
                        active = scan.with_contexts[0].1.clone();
                    }
                }
                // Each file carries its own `current-context`, so there is no
                // single active context to report.
                _ => {
                    active = None;
                    status.warn(
                        "multiple kubeconfig files; no single current context (set KUBECONFIG to choose)",
                    );
                }
            }

            if !scan.with_contexts.is_empty() {
                let list: Vec<String> = scan
                    .parsed
                    .iter()
                    .map(|p| p.display().to_string())
                    .collect();
                status.problem(format!(
                    "{} is a directory of kubeconfigs, not a kubeconfig file; patchbay merged them, but kubectl in your shell will not until you set: export KUBECONFIG={}",
                    scan.dir.display(),
                    list.join(":")
                ));
            }
        }

        status.active = active;

        if let Some(active) = &status.active {
            if !status.profiles.iter().any(|p| &p.id == active) {
                status.problem(format!(
                    "current-context is `{active}` but no context with that name is defined"
                ));
            }
        }

        // Exec plugins are why "I switched gcloud accounts and kubectl broke".
        // Which contexts they are is already in `meta.auth`, so the list of
        // names is dropped; the consequence is not derivable from anything on
        // the profile, so it stays — once, in one clause.
        let exec_contexts = status
            .profiles
            .iter()
            .filter(|p| {
                p.meta
                    .get("auth")
                    .and_then(|v| v.as_str())
                    .is_some_and(|a| a.starts_with("exec plugin"))
            })
            .count();
        if exec_contexts > 0 {
            status.warn(format!(
                "{exec_contexts} context(s) mint tokens through an exec credential plugin, so they follow whichever cloud account is active"
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
            return Ok(exec_disabled_switch(
                Self::TOOL,
                Some(&format!("kubectl config use-context {profile_id}")),
            ));
        }

        let out = self
            .paths
            .run("kubectl", &["config", "use-context", profile_id])?;
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
        let out = self.paths.run("kubectl", &["auth", "whoami"])?;
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
    use crate::types::NoteKind;
    use std::fs;
    use std::path::PathBuf;

    /// The kind recorded for the one note containing `needle`.
    fn kind_of(status: &ToolStatus, needle: &str) -> NoteKind {
        status
            .notes
            .iter()
            .find(|n| n.text.contains(needle))
            .unwrap_or_else(|| panic!("no note containing {needle:?}: {:?}", status.notes))
            .kind
    }

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
        // No context dates its own credential, and none of them is eternal
        // either: each says where the clock it cannot see actually lives.
        assert_eq!(
            status.profiles[0].expiry,
            Expiry::unknown("with the cloud CLI the exec plugin calls")
        );
        assert_eq!(
            status.profiles[1].expiry,
            Expiry::unknown("in the credential embedded in the kubeconfig")
        );
        assert!(status.profiles.iter().all(|p| p.expires_at().is_none()));

        // "…and switching gcloud moves them" is not on any profile, so it is
        // still said out loud — as a warning, without re-listing the contexts.
        let inherit = status
            .notes
            .iter()
            .find(|n| n.text.contains("exec credential plugin"))
            .expect("expected the exec-plugin caveat");
        assert_eq!(inherit.kind, NoteKind::Warn);
        assert!(inherit.text.contains('1'), "{}", inherit.text);
        assert!(!inherit.text.contains("prod"), "{}", inherit.text);

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
    fn test_config_path_that_is_an_empty_directory_is_called_out() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join(".kube/config")).unwrap();
        let status = KubectlProbe::new(Paths::for_test(dir.path()))
            .status()
            .unwrap();
        assert!(status.installed);
        assert!(status.profiles.is_empty());
        assert!(status
            .notes
            .iter()
            .any(|n| n.text.contains("is a directory")));
        // kubectl itself cannot read this at all, so it is not a caveat.
        assert_eq!(kind_of(&status, "is a directory"), NoteKind::Problem);
    }

    /// The layout on a real machine: `~/.kube/config` is a directory of
    /// per-cluster kubeconfigs next to files that are not kubeconfigs at all.
    fn config_dir_fixture() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join(".kube/config");
        fs::create_dir_all(&config).unwrap();
        fs::write(
            config.join("pathors-tw.yaml"),
            "current-context: tw\ncontexts:\n  - name: tw\n    context:\n      cluster: gke-tw\n      user: gke-user\nusers:\n  - name: gke-user\n    user:\n      exec:\n        command: gke-gcloud-auth-plugin\n",
        )
        .unwrap();
        fs::write(
            config.join("llm-cluster.yaml"),
            "current-context: llm\ncontexts:\n  - name: llm\n    context:\n      cluster: llm\n      user: llm-user\n  - name: tw\n    context:\n      cluster: shadowed\n",
        )
        .unwrap();
        // Not a kubeconfig, and not even a yaml file: gcloud drops it there.
        fs::write(
            config.join("gke_gcloud_auth_plugin_cache"),
            r#"{"current_context":"tw","access_token":"ya29.SECRET"}"#,
        )
        .unwrap();
        // A yaml file that is not a kubeconfig at all.
        fs::write(config.join("scratch.yaml"), "\tnot: [valid yaml").unwrap();
        (dir, config)
    }

    #[test]
    fn test_config_directory_is_scanned_and_merged() {
        let (dir, config) = config_dir_fixture();
        let status = KubectlProbe::new(Paths::for_test(dir.path()))
            .status()
            .unwrap();

        // Sorted by filename, so llm-cluster.yaml is merged first and wins the
        // duplicate `tw` context.
        let ids: Vec<_> = status.profiles.iter().map(|p| p.id.as_str()).collect();
        assert_eq!(ids, vec!["llm", "tw"]);
        assert_eq!(status.profiles[1].meta["cluster"], "shadowed");
        assert_eq!(
            status.profiles[0].meta["source"],
            config.join("llm-cluster.yaml").display().to_string()
        );
        assert_eq!(
            status.profiles[1].meta["source"],
            config.join("llm-cluster.yaml").display().to_string()
        );

        // Two files carry contexts, each with its own current-context.
        assert!(status.active.is_none());
        assert!(status.notes.iter().any(|n| n.text
            == "multiple kubeconfig files; no single current context (set KUBECONFIG to choose)"));

        // The junk yaml is named and skipped; the non-yaml cache file is not
        // touched at all, so its token can never leak into the report.
        assert!(status
            .notes
            .iter()
            .any(|n| n.text.contains("scratch.yaml") && n.text.contains("not valid YAML")));
        assert_eq!(kind_of(&status, "scratch.yaml"), NoteKind::Problem);
        let json = serde_json::to_string(&status).unwrap();
        assert!(!json.contains("ya29.SECRET"), "{json}");
        assert!(!json.contains("gke_gcloud_auth_plugin_cache"), "{json}");

        // And the fix for the shell is spelled out, listing only what parsed.
        let hint = status
            .notes
            .iter()
            .find(|n| n.text.contains("export KUBECONFIG="))
            .expect("expected a KUBECONFIG hint");
        assert!(hint.text.contains(&format!(
            "export KUBECONFIG={}:{}",
            config.join("llm-cluster.yaml").display(),
            config.join("pathors-tw.yaml").display()
        )));
    }

    #[test]
    fn test_config_directory_with_one_kubeconfig_keeps_its_current_context() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join(".kube/config");
        fs::create_dir_all(&config).unwrap();
        fs::write(config.join("only.yaml"), CONFIG).unwrap();
        fs::write(config.join("gke_gcloud_auth_plugin_cache"), "{}").unwrap();

        let status = KubectlProbe::new(Paths::for_test(dir.path()))
            .status()
            .unwrap();
        let ids: Vec<_> = status.profiles.iter().map(|p| p.id.as_str()).collect();
        assert_eq!(ids, vec!["prod", "local"]);
        assert_eq!(status.active.as_deref(), Some("prod"));
        assert_eq!(
            status.profiles[0].meta["source"],
            config.join("only.yaml").display().to_string()
        );
        assert!(!status
            .notes
            .iter()
            .any(|n| n.text.contains("no single current context")));
    }

    #[test]
    fn test_a_real_config_file_is_preferred_over_directory_scanning() {
        let (_dir, home) = fixture(".kube/config", CONFIG);
        let status = KubectlProbe::new(Paths::for_test(&home)).status().unwrap();
        assert_eq!(status.active.as_deref(), Some("prod"));
        assert!(!status
            .notes
            .iter()
            .any(|n| n.text.contains("is a directory")));
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
        assert!(status
            .notes
            .iter()
            .any(|n| n.text.contains("not valid YAML")));
        assert_eq!(kind_of(&status, "not valid YAML"), NoteKind::Problem);

        let (_dir, home) = fixture(".kube/config", "current-context: ghost\ncontexts: []\n");
        let status = KubectlProbe::new(Paths::for_test(&home)).status().unwrap();
        assert!(status
            .notes
            .iter()
            .any(|n| n.text.contains("no context with that name")));
        // A dangling current-context is a broken kubeconfig, not a caveat.
        assert_eq!(
            kind_of(&status, "no context with that name"),
            NoteKind::Problem
        );
    }

    #[test]
    fn test_execution_being_switched_off_is_not_a_reason_kubectl_cannot_switch() {
        let (_dir, home) = fixture(".kube/config", CONFIG);
        match KubectlProbe::new(Paths::for_test(&home))
            .switch("local")
            .unwrap()
        {
            SwitchOutcome::ExecDisabled { tool, hint } => {
                assert_eq!(tool, "kubectl");
                assert_eq!(hint.as_deref(), Some("kubectl config use-context local"));
            }
            other => panic!("expected ExecDisabled, got {other:?}"),
        }
    }
}
