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
use crate::types::{
    Expiry, Note, PermissionScope, PermissionsReport, Profile, SwitchOutcome, ToolStatus,
    VerifyOutcome,
};
use crate::util::{read_text, CmdOutput};

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

    /// The namespaces an RBAC question can be asked about.
    ///
    /// RBAC grants live on the namespace, not on the credential — the same
    /// context can be admin of one and a stranger to the next — so "what may I
    /// do" is only a question once a namespace is named.
    ///
    /// Two sources, deliberately combined:
    ///
    /// * **the kubeconfig**, through [`Probe::status`]: every context's
    ///   `namespace`, plus the current context's own. This costs no exec, and
    ///   it is the only source that survives the layout this probe already
    ///   handles — where `~/.kube/config` is a *directory* of per-cluster
    ///   files, `kubectl config view` fails outright (`error: ... is a
    ///   directory`) exactly where patchbay's own parse has the answer.
    /// * **`kubectl get namespaces`**, when the cluster answers: a cluster
    ///   almost always has namespaces no kubeconfig ever names, and those are
    ///   the ones worth offering. It needs cluster access *and* `list` on
    ///   namespaces, so failing is ordinary rather than exceptional — the
    ///   kubeconfig-derived list stands, and [`Probe::permissions_in`] is what
    ///   says out loud why the cluster could not be reached.
    fn permission_scopes(&self) -> anyhow::Result<Vec<PermissionScope>> {
        let status = self.status()?;
        let active = current_namespace(&status);

        let mut names: Vec<String> = status
            .profiles
            .iter()
            .filter_map(|p| p.meta.get("namespace").and_then(|v| v.as_str()))
            .filter(|n| !n.is_empty())
            .map(str::to_string)
            .collect();
        names.extend(active.clone());

        if self.paths.may_exec() && self.paths.has_binary("kubectl") {
            // Deliberately `.ok()`: an unreachable cluster is not an error
            // here, it is just a shorter list.
            let out = self
                .paths
                .run("kubectl", &["get", "namespaces", "-o", "json"])
                .ok();
            if let Some(out) = out.filter(|o| o.ok) {
                if let Ok(json) = serde_json::from_str::<serde_json::Value>(&out.stdout) {
                    let items = json.get("items").and_then(|v| v.as_array());
                    for item in items.into_iter().flatten() {
                        if let Some(name) = item
                            .pointer("/metadata/name")
                            .and_then(|v| v.as_str())
                            .filter(|n| !n.is_empty())
                        {
                            names.push(name.to_string());
                        }
                    }
                }
            }
        }

        names.sort();
        names.dedup();
        Ok(names
            .into_iter()
            .map(|name| PermissionScope {
                active: Some(&name) == active.as_ref(),
                label: name.clone(),
                id: name,
            })
            .collect())
    }

    /// What the current context may do in one namespace.
    ///
    /// `kubectl auth can-i --list` is a `SelfSubjectRulesReview`: the API
    /// server answers for whoever the request authenticates as, which is the
    /// only identity patchbay could honestly report on anyway. Every way this
    /// can fail — no kubeconfig, a credential plugin that will not mint a
    /// token, a cluster behind a VPN that is down, an authorizer that refuses
    /// the review itself — comes back as a `supported: false` report carrying
    /// one sentence, never a raw kubectl dump. The real ones are worth seeing:
    /// a stale GKE login answers in twenty lines of nested klog output.
    fn permissions_in(&self, scope_id: &str) -> anyhow::Result<PermissionsReport> {
        let status = self.status()?;
        let context = status.active.clone();
        // The kubeconfig's user for the current context. Not necessarily the
        // name the API server knows it by — that is `kubectl auth whoami`, a
        // second exec for a field this one already fills usefully.
        let subject = current_context(&status)
            .and_then(|p| p.meta.get("user"))
            .and_then(|v| v.as_str())
            .map(str::to_string);

        let report = |supported: bool, scopes: Vec<String>, notes: Vec<Note>| PermissionsReport {
            tool: Self::TOOL.to_string(),
            supported,
            subject: subject.clone(),
            scopes,
            notes,
            hint: None,
            scope: Some(scope_id.to_string()),
        };

        if !self.paths.may_exec() || !self.paths.has_binary("kubectl") {
            let mut out = PermissionsReport::unsupported(
                Self::TOOL,
                "the kubectl CLI is not available on PATH, so patchbay cannot ask the API server what this context may do",
                Some(&format!("kubectl auth can-i --list --namespace {scope_id}")),
            );
            out.subject = subject;
            out.scope = Some(scope_id.to_string());
            return Ok(out);
        }

        // `-o json` is tried first and is expected to fail on most installs:
        // kubectl 1.32 answers `unknown shorthand flag: 'o' in -o` from its own
        // flag parser, before it opens a socket, so the attempt costs a process
        // and no network. The day a release grows the flag, patchbay gets the
        // structured answer with no change here.
        let attempt = self.paths.run(
            "kubectl",
            &[
                "auth",
                "can-i",
                "--list",
                "--namespace",
                scope_id,
                "-o",
                "json",
            ],
        )?;
        let (out, structured) = if attempt.ok {
            (attempt, true)
        } else if rejected_the_flag(&attempt) {
            let table = self.paths.run(
                "kubectl",
                &["auth", "can-i", "--list", "--namespace", scope_id],
            )?;
            (table, false)
        } else {
            (attempt, false)
        };

        if !out.ok {
            return Ok(report(
                false,
                Vec::new(),
                vec![Note::problem(cluster_failure(
                    context.as_deref(),
                    scope_id,
                    &out,
                ))],
            ));
        }

        let parsed = if structured {
            parse_rules_json(&out.stdout)
        } else {
            parse_rules_table(&out.stdout)
        };
        let Some((mut rules, incomplete)) = parsed else {
            return Ok(report(
                false,
                Vec::new(),
                vec![Note::problem(format!(
                    "kubectl answered `auth can-i --list` in a shape patchbay does not recognise, so the rules for `{scope_id}` could not be read"
                ))],
            ));
        };
        rules.sort();
        rules.dedup();

        let mut notes = vec![Note::info(format!(
            "what the API server says this context may do in namespace `{scope_id}`; cluster-wide grants that reach into it are folded in, and rules only a non-RBAC authorizer would allow are not visible to this question"
        ))];
        if incomplete {
            notes.push(Note::warn(
                "the API server marked this list incomplete, so it is a floor and not the whole grant",
            ));
        }
        if rules.is_empty() {
            notes.push(Note::info(format!(
                "no rule allows this context anything in `{scope_id}` — the namespace may not exist, or nothing is bound to this identity there"
            )));
        }
        Ok(report(true, rules, notes))
    }

    /// "What may this context do", with no namespace named.
    ///
    /// The current context already names one (kubectl's own default is
    /// `default` when it sets none), so this resolves it and hands over — the
    /// same move [`Probe::verify`] makes with the active profile.
    fn permissions(&self) -> anyhow::Result<PermissionsReport> {
        let status = self.status()?;
        match current_namespace(&status) {
            Some(namespace) => self.permissions_in(&namespace),
            None => Ok(PermissionsReport::unsupported(
                Self::TOOL,
                "RBAC is granted per namespace and there is no current context to take one from — pick a context first",
                Some("kubectl config use-context <name>"),
            )),
        }
    }
}

/// The profile for `current-context`, if it is one this kubeconfig defines.
fn current_context(status: &ToolStatus) -> Option<&Profile> {
    let active = status.active.as_ref()?;
    status.profiles.iter().find(|p| &p.id == active)
}

/// The namespace the current context works in — `default` when it names none,
/// which is kubectl's own rule, not a guess.
fn current_namespace(status: &ToolStatus) -> Option<String> {
    let context = current_context(status)?;
    Some(
        context
            .meta
            .get("namespace")
            .and_then(|v| v.as_str())
            .filter(|n| !n.is_empty())
            .unwrap_or("default")
            .to_string(),
    )
}

/// Whether kubectl refused the *flag* rather than the request — the one
/// failure that is worth retrying in the older output mode.
fn rejected_the_flag(out: &CmdOutput) -> bool {
    let text = format!("{} {}", out.stderr, out.stdout).to_lowercase();
    text.contains("unknown shorthand flag")
        || text.contains("unknown flag")
        || text.contains("flag provided but not defined")
}

/// `SelfSubjectRulesReview` JSON, if that is what this is.
///
/// Returns the readable rules and whether the API server flagged the list as
/// incomplete. `None` means the output was not a rules review at all, which is
/// a different answer from "a rules review granting nothing".
fn parse_rules_json(text: &str) -> Option<(Vec<String>, bool)> {
    let json: serde_json::Value = serde_json::from_str(text).ok()?;
    let status = json.get("status")?;
    let resource_rules = status.get("resourceRules").and_then(|v| v.as_array());
    let non_resource_rules = status.get("nonResourceRules").and_then(|v| v.as_array());
    if resource_rules.is_none() && non_resource_rules.is_none() {
        return None;
    }

    let strings = |rule: &serde_json::Value, key: &str| -> Vec<String> {
        rule.get(key)
            .and_then(|v| v.as_array())
            .map(|items| {
                items
                    .iter()
                    .filter_map(|v| v.as_str())
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default()
    };

    let mut out = Vec::new();
    for rule in resource_rules.into_iter().flatten() {
        let verbs = strings(rule, "verbs");
        let names = strings(rule, "resourceNames");
        let groups = strings(rule, "apiGroups");
        for resource in strings(rule, "resources") {
            // An empty api group is core/v1, where the bare name is the one
            // people type: `pods`, not `pods.`.
            if groups.is_empty() {
                out.push(rule_line(&verbs, &resource, &names));
                continue;
            }
            for group in &groups {
                let target = if group.is_empty() || group == "*" {
                    resource.clone()
                } else {
                    format!("{resource}.{group}")
                };
                out.push(rule_line(&verbs, &target, &names));
            }
        }
    }
    for rule in non_resource_rules.into_iter().flatten() {
        let verbs = strings(rule, "verbs");
        for url in strings(rule, "nonResourceURLs") {
            out.push(rule_line(&verbs, &url, &[]));
        }
    }

    let incomplete = status
        .get("incomplete")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    out.retain(|line| !line.is_empty());
    Some((out, incomplete))
}

/// The table `auth can-i --list` actually prints.
///
/// Columns are padded to the widest cell *including the header*, so the header
/// gives the start offset of every column and the cells can be sliced out. That
/// matters because splitting on whitespace cannot work here: a verb list prints
/// as `[get list watch]`, spaces and all.
fn parse_rules_table(text: &str) -> Option<(Vec<String>, bool)> {
    let mut header: Option<&str> = None;
    let mut rows: Vec<&str> = Vec::new();
    let mut incomplete = false;
    for line in text.lines() {
        if header.is_none() {
            // kubectl prints warnings above the table; the header is the line
            // that names the columns.
            if line.contains("Resources") && line.contains("Verbs") {
                header = Some(line);
            } else if line.to_lowercase().contains("incomplete") {
                incomplete = true;
            }
            continue;
        }
        rows.push(line);
    }
    let starts = column_starts(
        header?,
        &["Resources", "Non-Resource URLs", "Resource Names", "Verbs"],
    )?;

    let mut out = Vec::new();
    for row in rows {
        if row.trim().is_empty() {
            continue;
        }
        let cells = cells(row, &starts);
        let verbs = bracket_list(&cells[3]);
        if verbs.is_empty() {
            continue;
        }
        let names = bracket_list(&cells[2]);
        let resources = cells[0].clone();
        let target = if resources.is_empty() {
            bracket_list(&cells[1]).join(",")
        } else {
            resources
        };
        if target.is_empty() {
            continue;
        }
        out.push(rule_line(&verbs, &target, &names));
    }
    Some((out, incomplete))
}

/// Where each named column begins, in characters. `None` if the header does not
/// carry all of them in order — which means this is not the table we think.
fn column_starts(header: &str, names: &[&str]) -> Option<Vec<usize>> {
    let chars: Vec<char> = header.chars().collect();
    let mut starts = Vec::with_capacity(names.len());
    let mut from = 0usize;
    for name in names {
        let want: Vec<char> = name.chars().collect();
        let last = chars.len().checked_sub(want.len())?;
        let at = (from..=last).find(|&i| chars[i..i + want.len()] == want[..])?;
        starts.push(at);
        from = at + want.len();
    }
    Some(starts)
}

/// One row sliced at the header's column offsets. Character-indexed so a
/// non-ASCII resource name cannot panic the slice.
fn cells(row: &str, starts: &[usize]) -> Vec<String> {
    let chars: Vec<char> = row.chars().collect();
    starts
        .iter()
        .enumerate()
        .map(|(i, &start)| {
            let start = start.min(chars.len());
            let end = starts
                .get(i + 1)
                .copied()
                .unwrap_or(chars.len())
                .clamp(start, chars.len());
            chars[start..end]
                .iter()
                .collect::<String>()
                .trim()
                .to_string()
        })
        .collect()
}

/// `[get list watch]` as the three verbs it is. A cell with no brackets is
/// split on whitespace anyway rather than dropped.
fn bracket_list(cell: &str) -> Vec<String> {
    let inner = cell
        .trim()
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .unwrap_or(cell);
    inner
        .split_whitespace()
        .flat_map(|item| item.split(','))
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(str::to_string)
        .collect()
}

/// One rule as a line worth reading: `get,list,watch pods`.
fn rule_line(verbs: &[String], target: &str, names: &[String]) -> String {
    if verbs.is_empty() || target.is_empty() {
        return String::new();
    }
    let verbs = verbs.join(",");
    if names.is_empty() {
        format!("{verbs} {target}")
    } else {
        format!("{verbs} {target}/{}", names.join(","))
    }
}

/// One sentence for a kubectl that did not answer, and what ends it.
///
/// The real failures here are not one-liners. A GKE context whose gcloud login
/// has gone stale answers with twenty lines: klog headers, a nested
/// `config-helper` transcript, gcloud's own four-line "Please run:" block, and
/// only then the sentence that matters. Pasting that into a note hands back
/// three tools' errors instead of an answer.
fn cluster_failure(context: Option<&str>, namespace: &str, out: &CmdOutput) -> String {
    let text = if out.stderr.trim().is_empty() {
        out.stdout.trim()
    } else {
        out.stderr.trim()
    };
    let lower = text.to_lowercase();
    let which = match context {
        Some(context) => format!("context `{context}`"),
        None => "the current context".to_string(),
    };

    if lower.contains("no configuration has been provided")
        || lower.contains("is a directory")
        || lower.contains("context was not found")
        || lower.contains("current-context is not set")
    {
        return format!(
            "kubectl could not load a usable kubeconfig, so {which} was never asked — point KUBECONFIG at a real config file"
        );
    }
    if lower.contains("getting credentials")
        || lower.contains("credential plugin")
        || (lower.contains("executable") && lower.contains("failed"))
    {
        let plugin = match credential_plugin(text) {
            Some(name) => format!("the `{name}` credential plugin"),
            None => "an exec credential plugin".to_string(),
        };
        return format!(
            "{which} mints its token through {plugin} and that plugin failed, so nothing could be read — re-authenticate the cloud account it draws on"
        );
    }
    if lower.contains("unable to connect to the server")
        || lower.contains("connection refused")
        || lower.contains("no route to host")
        || lower.contains("i/o timeout")
        || lower.contains("dial tcp")
    {
        return format!(
            "the cluster behind {which} is not reachable from this machine, so its RBAC could not be read — check the network or VPN, and that the cluster is still running"
        );
    }
    if lower.contains("forbidden")
        || lower.contains("is not allowed")
        || lower.contains("unauthorized")
    {
        return format!(
            "{which} may not run a SelfSubjectRulesReview in namespace `{namespace}`, so the API server will not say what it is allowed to do there"
        );
    }
    format!("{which}: {}", headline(text))
}

/// The exec plugin named in `exec: executable NAME failed`.
fn credential_plugin(text: &str) -> Option<String> {
    let after = text.split("executable ").nth(1)?;
    let name = after.split_whitespace().next()?;
    (!name.is_empty()).then(|| name.to_string())
}

/// kubectl's first meaningful line, without the klog header or `error: `.
///
/// klog writes `F0817 16:03:11.318203   24358 cred.go:150] ` in front of the
/// message, which names a line of Go and tells the reader nothing.
fn headline(text: &str) -> String {
    text.lines()
        .map(strip_klog)
        .map(str::trim)
        .find(|line| !line.is_empty())
        .map(|line| {
            line.strip_prefix("error: ")
                .or_else(|| line.strip_prefix("Error: "))
                .unwrap_or(line)
                .to_string()
        })
        .unwrap_or_else(|| "kubectl failed without saying why".to_string())
}

/// `E0817 16:03:12.784648   24461 memcache.go:265] msg` -> `msg`.
fn strip_klog(line: &str) -> &str {
    let mut chars = line.chars();
    let severity = chars.next();
    if !matches!(severity, Some('I' | 'W' | 'E' | 'F')) {
        return line;
    }
    if !chars.clone().take(4).all(|c| c.is_ascii_digit()) {
        return line;
    }
    match line.split_once("] ") {
        Some((_prefix, rest)) => rest,
        None => line,
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

    // -----------------------------------------------------------------
    // permissions
    // -----------------------------------------------------------------

    fn probe_with(home: &Path, exec: std::sync::Arc<crate::util::FakeExec>) -> KubectlProbe {
        KubectlProbe::new(Paths::for_test(home).with_exec(exec))
    }

    fn fake(exec: crate::util::FakeExec) -> std::sync::Arc<crate::util::FakeExec> {
        std::sync::Arc::new(exec)
    }

    /// What `kubectl auth can-i --list` prints: columns padded to the widest
    /// cell, and verb lists with spaces *inside* the brackets — which is why
    /// this cannot be parsed by splitting on whitespace.
    const CAN_I_TABLE: &str = concat!(
        "Resources                                       Non-Resource URLs   Resource Names   Verbs\n",
        "selfsubjectaccessreviews.authorization.k8s.io   []                  []               [create]\n",
        "pods                                            []                  []               [get list watch]\n",
        "secrets                                         []                  [app-secret]     [get]\n",
        "                                                [/healthz]          []               [get]\n",
        "*.*                                             []                  []               [*]\n",
    );

    /// The `SelfSubjectRulesReview` a kubectl that grew `-o json` would print.
    const CAN_I_JSON: &str = r#"{
      "kind": "SelfSubjectRulesReview",
      "status": {
        "incomplete": false,
        "resourceRules": [
          {"verbs": ["get","list","watch"], "apiGroups": [""], "resources": ["pods"]},
          {"verbs": ["get"], "apiGroups": ["apps"], "resources": ["deployments"]},
          {"verbs": ["get"], "apiGroups": [""], "resources": ["secrets"], "resourceNames": ["app-secret"]}
        ],
        "nonResourceRules": [
          {"verbs": ["get"], "nonResourceURLs": ["/healthz"]}
        ]
      }
    }"#;

    /// kubectl 1.32's answer to `-o json`, from its own flag parser.
    const UNKNOWN_FLAG: &str =
        "error: unknown shorthand flag: 'o' in -o\nSee 'kubectl auth can-i --help' for usage.\n";

    /// A GKE context whose gcloud login has gone stale, verbatim from this
    /// machine. Three tools' errors nested inside each other.
    const STALE_PLUGIN: &str = "F0817 16:03:11.318203   24358 cred.go:150] print credential failed with error: failed to retrieve access token: failure while executing gcloud, with args [config config-helper --format=json]: exit status 1 (err: ERROR: (gcloud.config.config-helper) There was a problem refreshing your current auth tokens: Reauthentication failed. cannot prompt during non-interactive execution.\nPlease run:\n\n  $ gcloud auth login\n\nto obtain new credentials.\n)\nUnable to connect to the server: getting credentials: exec: executable gke-gcloud-auth-plugin failed with exit code 1\n";

    #[test]
    fn test_namespace_scopes_merge_the_kubeconfig_with_the_live_list() {
        let (_dir, home) = fixture(".kube/config", CONFIG);
        let exec = fake(crate::util::FakeExec::new().on(
            "get namespaces",
            true,
            r#"{"items":[
                 {"metadata":{"name":"default"}},
                 {"metadata":{"name":"kube-system"}},
                 {"metadata":{"name":"web"}}
               ]}"#,
            "",
        ));

        let scopes = probe_with(&home, exec).permission_scopes().unwrap();
        let ids: Vec<&str> = scopes.iter().map(|s| s.id.as_str()).collect();
        assert_eq!(ids, vec!["default", "kube-system", "web"], "{scopes:?}");
        // `prod` is current-context and works in `default`.
        assert!(scopes[0].active, "{scopes:?}");
        assert!(!scopes[1].active);
    }

    #[test]
    fn test_namespace_scopes_survive_a_cluster_that_will_not_answer() {
        // The list is shorter, not absent: the kubeconfig still names one, and
        // saying why the cluster is unreachable is `permissions_in`'s job.
        let (_dir, home) = fixture(".kube/config", CONFIG);
        let exec =
            fake(crate::util::FakeExec::new().on("get namespaces", false, "", "Unable to connect"));

        let scopes = probe_with(&home, exec).permission_scopes().unwrap();
        let ids: Vec<&str> = scopes.iter().map(|s| s.id.as_str()).collect();
        assert_eq!(ids, vec!["default"], "{scopes:?}");
        assert!(scopes[0].active);
    }

    #[test]
    fn test_scopes_are_listed_where_kubectl_cannot_read_its_own_config() {
        // `~/.kube/config` as a directory: kubectl's loader refuses it outright,
        // so `kubectl config view` would answer nothing here. patchbay's own
        // parse is what makes a picker possible at all.
        let (dir, _config) = config_dir_fixture();
        let exec = fake(crate::util::FakeExec::new());

        let scopes = probe_with(dir.path(), exec).permission_scopes().unwrap();
        assert!(scopes.is_empty(), "no context names a namespace");

        // And one that does still comes through without any exec at all.
        let (_dir, home) = fixture(".kube/config", CONFIG);
        let exec = fake(crate::util::FakeExec::new());
        let scopes = probe_with(&home, exec.clone()).permission_scopes().unwrap();
        assert_eq!(scopes.len(), 1);
        assert_eq!(scopes[0].id, "default");
    }

    #[test]
    fn test_the_table_form_is_parsed_when_this_kubectl_has_no_json_output() {
        let (_dir, home) = fixture(".kube/config", CONFIG);
        // First match wins, so the `-o json` attempt is answered first.
        let exec = fake(
            crate::util::FakeExec::new()
                .on("-o json", false, "", UNKNOWN_FLAG)
                .on("auth can-i", true, CAN_I_TABLE, ""),
        );

        let report = probe_with(&home, exec.clone())
            .permissions_in("web")
            .unwrap();
        assert!(report.supported, "{report:?}");
        assert_eq!(report.scope.as_deref(), Some("web"));
        assert_eq!(report.subject.as_deref(), Some("gke-user"));
        assert_eq!(
            report.scopes,
            vec![
                "* *.*",
                "create selfsubjectaccessreviews.authorization.k8s.io",
                "get /healthz",
                "get secrets/app-secret",
                "get,list,watch pods",
            ]
        );

        // Two calls: the probe, then the form this kubectl actually has.
        let calls = exec.calls();
        assert_eq!(calls.len(), 2, "{calls:?}");
        assert!(calls[0].args.contains(&"-o".to_string()));
        assert!(!calls[1].args.contains(&"-o".to_string()));
        assert!(calls[1].args.contains(&"web".to_string()));
    }

    #[test]
    fn test_json_output_is_used_and_costs_only_one_call_where_it_exists() {
        let (_dir, home) = fixture(".kube/config", CONFIG);
        let exec = fake(crate::util::FakeExec::new().on("-o json", true, CAN_I_JSON, ""));

        let report = probe_with(&home, exec.clone())
            .permissions_in("default")
            .unwrap();
        assert!(report.supported);
        assert_eq!(
            report.scopes,
            vec![
                "get /healthz",
                "get deployments.apps",
                "get secrets/app-secret",
                "get,list,watch pods",
            ]
        );
        assert_eq!(exec.calls().len(), 1, "no fallback was needed");
    }

    #[test]
    fn test_a_namespace_granting_nothing_is_a_fact_not_an_empty_pane() {
        let (_dir, home) = fixture(".kube/config", CONFIG);
        let header = CAN_I_TABLE.lines().next().unwrap();
        let exec = fake(
            crate::util::FakeExec::new()
                .on("-o json", false, "", UNKNOWN_FLAG)
                .on("auth can-i", true, &format!("{header}\n"), ""),
        );

        let report = probe_with(&home, exec).permissions_in("locked").unwrap();
        assert!(report.supported);
        assert!(report.scopes.is_empty());
        assert!(
            report
                .notes
                .iter()
                .any(|n| n.text.contains("no rule allows")),
            "{:?}",
            report.notes
        );
    }

    #[test]
    fn test_a_stale_credential_plugin_is_one_sentence_not_twenty_lines() {
        let (_dir, home) = fixture(".kube/config", CONFIG);
        let exec = fake(crate::util::FakeExec::new().on("auth can-i", false, "", STALE_PLUGIN));

        let report = probe_with(&home, exec).permissions_in("default").unwrap();
        assert!(!report.supported);
        assert!(report.scopes.is_empty());
        let notes = report
            .notes
            .iter()
            .map(|n| n.text.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        assert_eq!(notes.lines().count(), 1, "{notes}");
        assert!(notes.contains("gke-gcloud-auth-plugin"), "{notes}");
        assert!(notes.contains("prod"), "{notes}");
        // Not a paste of three other tools' errors.
        assert!(!notes.contains("Please run"), "{notes}");
        assert!(!notes.contains("F0817"), "{notes}");
        assert!(!notes.contains("cred.go"), "{notes}");
    }

    #[test]
    fn test_an_unreachable_cluster_says_so_instead_of_dumping_a_dial_error() {
        let (_dir, home) = fixture(".kube/config", CONFIG);
        let exec = fake(crate::util::FakeExec::new().on(
            "auth can-i",
            false,
            "",
            "Unable to connect to the server: dial tcp 10.0.0.1:443: i/o timeout\n",
        ));

        let report = probe_with(&home, exec).permissions_in("default").unwrap();
        assert!(!report.supported);
        let notes = report
            .notes
            .iter()
            .map(|n| n.text.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        assert_eq!(notes.lines().count(), 1, "{notes}");
        assert!(notes.contains("not reachable"), "{notes}");
        assert!(!notes.contains("dial tcp"), "{notes}");
    }

    #[test]
    fn test_a_refused_rules_review_names_the_namespace_it_was_refused_in() {
        let (_dir, home) = fixture(".kube/config", CONFIG);
        let exec = fake(crate::util::FakeExec::new().on(
            "auth can-i",
            false,
            "",
            "Error from server (Forbidden): selfsubjectrulesreviews.authorization.k8s.io is forbidden: User \"viewer\" cannot create resource \"selfsubjectrulesreviews\" in API group \"authorization.k8s.io\" at the cluster scope\n",
        ));

        let report = probe_with(&home, exec).permissions_in("payments").unwrap();
        assert!(!report.supported);
        let notes = report
            .notes
            .iter()
            .map(|n| n.text.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        assert_eq!(notes.lines().count(), 1, "{notes}");
        assert!(notes.contains("payments"), "{notes}");
        assert!(notes.contains("may not run"), "{notes}");
    }

    #[test]
    fn test_output_in_a_shape_we_do_not_know_degrades_to_a_note() {
        let (_dir, home) = fixture(".kube/config", CONFIG);
        let exec = fake(crate::util::FakeExec::new().on(
            "auth can-i",
            true,
            "yes, obviously, you can do whatever you like\n",
            "",
        ));

        let report = probe_with(&home, exec).permissions_in("default").unwrap();
        assert!(!report.supported);
        assert!(report.scopes.is_empty());
        assert!(
            report
                .notes
                .iter()
                .any(|n| n.text.contains("does not recognise")),
            "{:?}",
            report.notes
        );
    }

    #[test]
    fn test_without_kubectl_the_command_is_handed_over_intact() {
        let (_dir, home) = fixture(".kube/config", CONFIG);
        let report = KubectlProbe::new(Paths::for_test(&home))
            .permissions_in("web")
            .unwrap();
        assert!(!report.supported);
        assert_eq!(report.scope.as_deref(), Some("web"));
        let hint = report.hint.unwrap();
        assert_eq!(hint, "kubectl auth can-i --list --namespace web");
        assert!(!hint.contains('<'), "{hint}");
    }

    #[test]
    fn test_permissions_resolves_the_current_contexts_namespace() {
        let (_dir, home) = fixture(".kube/config", CONFIG);
        let exec = fake(
            crate::util::FakeExec::new()
                .on("-o json", false, "", UNKNOWN_FLAG)
                .on("auth can-i", true, CAN_I_TABLE, ""),
        );

        let report = probe_with(&home, exec.clone()).permissions().unwrap();
        assert_eq!(report.scope.as_deref(), Some("default"));
        assert!(exec.last().unwrap().args.contains(&"default".to_string()));
    }

    #[test]
    fn test_a_context_that_names_no_namespace_uses_kubectls_own_default() {
        let (_dir, home) = fixture(
            ".kube/config",
            "current-context: local\ncontexts:\n  - name: local\n    context:\n      cluster: k3d\n      user: k3d-user\n",
        );
        let exec = fake(
            crate::util::FakeExec::new()
                .on("-o json", false, "", UNKNOWN_FLAG)
                .on("auth can-i", true, CAN_I_TABLE, ""),
        );

        let report = probe_with(&home, exec.clone()).permissions().unwrap();
        assert_eq!(report.scope.as_deref(), Some("default"));
        assert_eq!(report.subject.as_deref(), Some("k3d-user"));
    }

    #[test]
    fn test_with_no_current_context_there_is_nothing_to_ask_about() {
        let (_dir, home) = fixture(".kube/config", "contexts: []\n");
        let exec = fake(crate::util::FakeExec::new());

        let report = probe_with(&home, exec.clone()).permissions().unwrap();
        assert!(!report.supported);
        assert!(
            report
                .notes
                .iter()
                .any(|n| n.text.contains("pick a context")),
            "{:?}",
            report.notes
        );
        assert!(exec.calls().is_empty(), "nothing to ask");
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
