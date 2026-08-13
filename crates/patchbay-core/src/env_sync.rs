//! Pulling a project's synced layer from Infisical.
//!
//! One direction only. This module reads the remote and replaces the synced
//! layer of one environment ([`crate::envs::EnvRegistry::replace_synced`]); it
//! has no push, and adding one would break the promise the local layer rests
//! on. Whatever is in `local` stays on this machine.
//!
//! **The account guard is the reason this module is more than four lines.** The
//! `infisical` CLI's active user is machine-global — one field in
//! `~/.infisical/infisical-config.json`, shared by every shell, every project
//! and every agent on the box. An `infisical export` therefore runs as whoever
//! logged in last, not as whoever the project belongs to, and when those differ
//! the API answers with a 403 whose text is actively misleading: *"project does
//! not belong to your selected organization"*, which reads as a permissions
//! problem with the project rather than the wrong login. So the pull records
//! the account it expects, checks it *before* spending a subprocess, and when
//! they disagree it says both addresses and the command that fixes it.

use std::collections::BTreeMap;

use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::envs::{validate_var_name, EnvRegistry, EnvVarSource, ProjectEntry};
use crate::paths::Paths;
use crate::probes::infisical;

/// The wrong-organization 403 the API returns when the active login is not the
/// one the project belongs to.
const WRONG_ORG: &str = "does not belong to your selected organization";

/// What a pull did. Names and counts only — no values, so this is safe to
/// serialize into an MCP response or a `--json` CLI output.
#[derive(Debug, Clone, Serialize)]
pub struct PullOutcome {
    /// The patchbay environment that was replaced.
    pub env: String,
    /// The remote's slug for it, which is not always the same thing.
    pub remote_env: String,
    /// How many variables the synced layer now holds.
    pub count: usize,
    /// Local names that shadow a synced one, after this pull.
    pub overridden: Vec<String>,
    /// Anything the user should know: skipped names, duplicates, overrides.
    pub notes: Vec<String>,
}

/// One secret as `infisical export --format json` reports it.
///
/// Verified against infisical CLI 0.43: a JSON array of objects with `key` and
/// `value` string fields, plus `_id`, `workspace`, `type`, `tags` and others
/// that change between releases and are deliberately ignored here.
#[derive(Deserialize)]
struct RemoteSecret {
    key: String,
    value: String,
}

/// Replace one environment's synced layer with what the remote holds.
pub fn pull(
    paths: &Paths,
    registry: &EnvRegistry,
    project: &ProjectEntry,
    env: &str,
) -> anyhow::Result<PullOutcome> {
    let Some(sync) = &project.sync else {
        anyhow::bail!(
            "no sync configured for `{}`; link it with `pb env link --project-id <infisical \
             project id>`",
            project.id
        );
    };
    if sync.provider != "infisical" {
        anyhow::bail!(
            "`{}` is linked to `{}`, which patchbay cannot pull from; the only provider today is \
             `infisical`",
            project.id,
            sync.provider
        );
    }

    // Before the subprocess, not after: running as the wrong user costs a
    // network round trip and answers with a lie (see the module docs).
    match infisical::active_account(paths)? {
        None => anyhow::bail!(
            "no infisical login on this machine; run `infisical login`, then `pb use infisical {}`",
            sync.account
        ),
        Some(active) if active != sync.account => anyhow::bail!(
            "`{}` is linked to the infisical account `{}`, but `{active}` is the active login on \
             this machine; the infisical CLI has one active user for the whole machine, so switch \
             first: `pb use infisical {}`",
            project.id,
            sync.account,
            sync.account
        ),
        Some(_) => {}
    }

    if !paths.may_exec() || !paths.has_binary("infisical") {
        anyhow::bail!(
            "the infisical CLI is not available on PATH; install it, or export the values by hand \
             and import them with `pb env import`"
        );
    }

    let remote_env = sync.remote_env(env);
    let mut args: Vec<String> = vec![
        "export".into(),
        "--projectId".into(),
        sync.project_id.clone(),
        "--env".into(),
        remote_env.clone(),
        "--format".into(),
        "json".into(),
        // Without it the CLI decorates stdout with its own banner, and stdout
        // has to stay parseable JSON.
        "--silent".into(),
    ];
    if let Some(domain) = &sync.domain {
        args.push("--domain".into());
        args.push(domain.clone());
    }
    let argv: Vec<&str> = args.iter().map(String::as_str).collect();
    let out = paths.run_env("infisical", &argv, &[])?;

    if !out.ok {
        // stderr **only**. On some failure modes — a partial export, a broken
        // pipe — stdout can already hold secret material, and an error message
        // is the one string guaranteed to be logged, printed and pasted.
        let mut detail = first_lines(&out.stderr);
        if out.stderr.contains(WRONG_ORG) {
            detail.push_str(&format!(
                " — that 403 usually means the wrong login: this project belongs to `{}`, so run \
                 `pb use infisical {}` and try again",
                sync.account, sync.account
            ));
        }
        anyhow::bail!(
            "`infisical export` failed for `{}/{env}` (remote environment `{remote_env}`): {detail}",
            project.id
        );
    }

    let secrets: Vec<RemoteSecret> = serde_json::from_str(&out.stdout).map_err(|e| {
        anyhow::anyhow!(
            "unexpected `infisical export` output for `{}/{env}` ({e}); patchbay expects the JSON \
             array that `infisical export --format json` produces",
            project.id
        )
    })?;

    let mut notes = Vec::new();
    let mut vars: BTreeMap<String, String> = BTreeMap::new();
    let mut duplicated: Vec<String> = Vec::new();
    for secret in secrets {
        // A name the shell could not export is skipped, not fatal: one odd key
        // in a shared project must not stop everyone else's pull.
        if let Err(e) = validate_var_name(&secret.key) {
            notes.push(format!("skipped a remote name: {e}"));
            continue;
        }
        if vars.insert(secret.key.clone(), secret.value).is_some()
            && !duplicated.contains(&secret.key)
        {
            duplicated.push(secret.key);
        }
    }
    if !duplicated.is_empty() {
        notes.push(format!(
            "the remote returned {} more than once; the last value won",
            duplicated
                .iter()
                .map(|k| format!("`{k}`"))
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }

    let count = vars.len();
    registry.replace_synced(&project.id, env, vars, Utc::now())?;

    let overridden: Vec<String> = registry
        .list(&project.id, env)?
        .into_iter()
        .filter(|var| var.source == EnvVarSource::LocalOverride)
        .map(|var| var.name)
        .collect();
    if !overridden.is_empty() {
        notes.push(format!(
            "{} local override{} synced values: {} — `pb env diff` shows them",
            overridden.len(),
            if overridden.len() == 1 {
                " shadows"
            } else {
                "s shadow"
            },
            overridden.join(", ")
        ));
    }

    Ok(PullOutcome {
        env: env.to_string(),
        remote_env,
        count,
        overridden,
        notes,
    })
}

/// stderr condensed to one line for an error message. Blank lines dropped, the
/// rest joined — the infisical CLI spreads a single failure over several.
fn first_lines(stderr: &str) -> String {
    let text: Vec<&str> = stderr
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();
    if text.is_empty() {
        return "no output".to_string();
    }
    text.join("; ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envs::{keychain_account, EnvLayer, SyncConfig};
    use crate::keystore::{Keystore, MemoryKeystore};
    use crate::util::FakeExec;
    use std::sync::Arc;

    /// The shape `infisical export --format json` really produces, extra fields
    /// and all.
    const EXPORT: &str = r#"[
      {"_id":"6a1","workspace":"3ab516bd","environment":"dev","type":"shared","tags":[],
       "key":"DATABASE_URL","value":"postgres://remote/db"},
      {"_id":"6a2","workspace":"3ab516bd","environment":"dev","type":"shared","tags":[],
       "key":"API_KEY","value":"remote-key"}
    ]"#;

    /// A tempdir home with an infisical login, a tempdir registry with a linked
    /// project, and a scripted exec. Nothing real is touched.
    struct Rig {
        _home: tempfile::TempDir,
        _dir: tempfile::TempDir,
        paths: Paths,
        registry: EnvRegistry,
        exec: Arc<FakeExec>,
        store: Arc<MemoryKeystore>,
    }

    struct Shared(Arc<MemoryKeystore>);

    impl Keystore for Shared {
        fn put(&self, id: &str, secret: &str) -> anyhow::Result<()> {
            self.0.put(id, secret)
        }
        fn get(&self, id: &str) -> anyhow::Result<Option<String>> {
            self.0.get(id)
        }
        fn delete(&self, id: &str) -> anyhow::Result<bool> {
            self.0.delete(id)
        }
        fn describe(&self) -> &'static str {
            self.0.describe()
        }
    }

    /// `active` is the machine-global infisical login; `None` writes no config
    /// file at all, which is what "never logged in" looks like.
    fn rig(active: Option<&str>, exec: FakeExec) -> Rig {
        let home = tempfile::tempdir().unwrap();
        if let Some(active) = active {
            std::fs::create_dir_all(home.path().join(".infisical")).unwrap();
            std::fs::write(
                home.path().join(".infisical/infisical-config.json"),
                format!(
                    r#"{{"loggedInUserEmail":"{active}","LoggedInUserDomain":"https://app.infisical.com/api","loggedInUsers":[{{"email":"{active}","domain":"https://app.infisical.com/api"}}],"vaultBackendType":"file","vaultBackendPassphrase":"ZmFrZQ=="}}"#
                ),
            )
            .unwrap();
        }
        let exec = Arc::new(exec);
        let paths = Paths::for_test(home.path()).with_exec(exec.clone());

        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(MemoryKeystore::new());
        let registry = EnvRegistry::new(
            dir.path().join("projects.json"),
            Box::new(Shared(store.clone())),
        );
        registry
            .register("pathors", "/repos/pathors", "dev")
            .unwrap();

        Rig {
            _home: home,
            _dir: dir,
            paths,
            registry,
            exec,
            store,
        }
    }

    impl Rig {
        fn link(&self, sync: SyncConfig) -> ProjectEntry {
            self.registry.set_sync("pathors", sync).unwrap()
        }

        fn synced_blob(&self, env: &str) -> BTreeMap<String, String> {
            let raw = self
                .store
                .get(&keychain_account("pathors", env, EnvLayer::Synced))
                .unwrap()
                .expect("no synced item");
            serde_json::from_str(&raw).unwrap()
        }
    }

    fn sync_for(account: &str) -> SyncConfig {
        SyncConfig {
            provider: "infisical".into(),
            project_id: "3ab516bd-248c-4be7-8f1a-bda73fe69d50".into(),
            account: account.into(),
            domain: None,
            env_map: BTreeMap::new(),
        }
    }

    #[test]
    fn test_a_pull_replaces_the_synced_layer_and_runs_the_expected_command() {
        let rig = rig(
            Some("contact@pathors.com"),
            FakeExec::new().on("export", true, EXPORT, "exported 2 secrets\n"),
        );
        let project = rig.link(sync_for("contact@pathors.com"));

        let outcome = pull(&rig.paths, &rig.registry, &project, "dev").unwrap();
        assert_eq!(outcome.env, "dev");
        assert_eq!(outcome.remote_env, "dev");
        assert_eq!(outcome.count, 2);
        assert!(outcome.overridden.is_empty());
        assert!(outcome.notes.is_empty(), "{:?}", outcome.notes);

        let call = rig.exec.last().unwrap();
        assert_eq!(call.bin, "infisical");
        assert_eq!(
            call.args,
            vec![
                "export",
                "--projectId",
                "3ab516bd-248c-4be7-8f1a-bda73fe69d50",
                "--env",
                "dev",
                "--format",
                "json",
                "--silent",
            ]
        );

        assert_eq!(
            rig.synced_blob("dev"),
            [
                ("API_KEY".to_string(), "remote-key".to_string()),
                (
                    "DATABASE_URL".to_string(),
                    "postgres://remote/db".to_string()
                ),
            ]
            .into_iter()
            .collect()
        );
        // Names on disk, values not.
        let raw = std::fs::read_to_string(rig.registry.path()).unwrap();
        assert!(raw.contains("DATABASE_URL"), "{raw}");
        assert!(!raw.contains("postgres://remote/db"), "{raw}");
        assert!(!raw.contains("remote-key"), "{raw}");

        // The outcome is safe to serialize: no values in it either.
        let json = serde_json::to_string(&outcome).unwrap();
        assert!(!json.contains("remote-key"), "{json}");
    }

    #[test]
    fn test_the_env_map_and_domain_reach_the_command_line() {
        let rig = rig(
            Some("contact@pathors.com"),
            FakeExec::new().on("export", true, EXPORT, ""),
        );
        let mut sync = sync_for("contact@pathors.com");
        sync.domain = Some("https://eu.infisical.com/api".into());
        sync.env_map = [("production".to_string(), "prod".to_string())]
            .into_iter()
            .collect();
        let project = rig.link(sync);

        let outcome = pull(&rig.paths, &rig.registry, &project, "production").unwrap();
        assert_eq!(outcome.env, "production");
        assert_eq!(outcome.remote_env, "prod");

        let line = rig.exec.last().unwrap().line();
        assert!(line.contains("--env prod"), "{line}");
        assert!(
            line.contains("--domain https://eu.infisical.com/api"),
            "{line}"
        );
        // patchbay's own name for the environment is what the vault records.
        assert!(rig
            .registry
            .get("pathors")
            .unwrap()
            .unwrap()
            .env("production")
            .is_some());
    }

    #[test]
    fn test_the_wrong_active_account_refuses_before_spending_a_subprocess() {
        let rig = rig(
            Some("someone.else@example.com"),
            FakeExec::new().on("export", true, EXPORT, ""),
        );
        let project = rig.link(sync_for("contact@pathors.com"));

        let err = pull(&rig.paths, &rig.registry, &project, "dev")
            .unwrap_err()
            .to_string();
        assert!(err.contains("contact@pathors.com"), "{err}");
        assert!(err.contains("someone.else@example.com"), "{err}");
        assert!(
            err.contains("pb use infisical contact@pathors.com"),
            "{err}"
        );

        // The guard is the point: nothing ran, and nothing was stored.
        assert!(rig.exec.calls().is_empty(), "{:?}", rig.exec.calls());
        assert!(rig.store.is_empty());
    }

    #[test]
    fn test_no_login_at_all_says_how_to_get_one() {
        let rig = rig(None, FakeExec::new().on("export", true, EXPORT, ""));
        let project = rig.link(sync_for("contact@pathors.com"));

        let err = pull(&rig.paths, &rig.registry, &project, "dev")
            .unwrap_err()
            .to_string();
        assert!(err.contains("no infisical login on this machine"), "{err}");
        assert!(err.contains("infisical login"), "{err}");
        assert!(rig.exec.calls().is_empty());
    }

    #[test]
    fn test_an_unlinked_project_names_the_command_that_links_it() {
        let rig = rig(
            Some("contact@pathors.com"),
            FakeExec::new().on("export", true, EXPORT, ""),
        );
        let project = rig.registry.get("pathors").unwrap().unwrap();

        let err = pull(&rig.paths, &rig.registry, &project, "dev")
            .unwrap_err()
            .to_string();
        assert!(err.contains("no sync configured for `pathors`"), "{err}");
        assert!(err.contains("pb env link"), "{err}");
    }

    #[test]
    fn test_without_the_cli_the_pull_says_so_instead_of_failing_obscurely() {
        // No scripted exec at all: `Paths::for_test` reports no binaries and
        // refuses to execute, exactly like a machine without infisical.
        let home = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(home.path().join(".infisical")).unwrap();
        std::fs::write(
            home.path().join(".infisical/infisical-config.json"),
            r#"{"loggedInUserEmail":"contact@pathors.com"}"#,
        )
        .unwrap();
        let paths = Paths::for_test(home.path());

        let dir = tempfile::tempdir().unwrap();
        let registry = EnvRegistry::new(
            dir.path().join("projects.json"),
            Box::new(MemoryKeystore::new()),
        );
        registry
            .register("pathors", "/repos/pathors", "dev")
            .unwrap();
        let project = registry
            .set_sync("pathors", sync_for("contact@pathors.com"))
            .unwrap();

        let err = pull(&paths, &registry, &project, "dev")
            .unwrap_err()
            .to_string();
        assert!(err.contains("not available on PATH"), "{err}");
        assert!(err.contains("pb env import"), "{err}");
    }

    #[test]
    fn test_a_403_from_the_wrong_organization_gets_the_account_hint() {
        let rig = rig(
            Some("contact@pathors.com"),
            FakeExec::new().on(
                "export",
                false,
                // stdout on a failed export is never shown; if it were, this
                // would be the leak.
                "partial-secret-material",
                "error: CallGetSecretsV3: Unsuccessful response [403]\nproject does not belong to \
                 your selected organization\n",
            ),
        );
        let project = rig.link(sync_for("contact@pathors.com"));

        let err = pull(&rig.paths, &rig.registry, &project, "dev")
            .unwrap_err()
            .to_string();
        assert!(err.contains("403"), "{err}");
        assert!(err.contains("usually means the wrong login"), "{err}");
        assert!(
            err.contains("pb use infisical contact@pathors.com"),
            "{err}"
        );
        assert!(!err.contains("partial-secret-material"), "{err}");
        // A failed pull replaces nothing.
        assert!(rig.store.is_empty());
    }

    #[test]
    fn test_output_that_is_not_the_documented_shape_is_an_error() {
        let rig = rig(
            Some("contact@pathors.com"),
            FakeExec::new().on("export", true, "not json at all", ""),
        );
        let project = rig.link(sync_for("contact@pathors.com"));

        let err = pull(&rig.paths, &rig.registry, &project, "dev")
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("unexpected `infisical export` output"),
            "{err}"
        );
        assert!(rig.store.is_empty());
    }

    #[test]
    fn test_duplicates_and_unusable_names_are_noted_not_fatal() {
        let rig = rig(
            Some("contact@pathors.com"),
            FakeExec::new().on(
                "export",
                true,
                r#"[{"key":"A","value":"first"},
                    {"key":"A","value":"last"},
                    {"key":"not a name","value":"x"},
                    {"key":"B","value":"ok"}]"#,
                "",
            ),
        );
        let project = rig.link(sync_for("contact@pathors.com"));

        let outcome = pull(&rig.paths, &rig.registry, &project, "dev").unwrap();
        assert_eq!(outcome.count, 2);
        assert_eq!(rig.synced_blob("dev")["A"], "last");
        assert!(
            outcome
                .notes
                .iter()
                .any(|n| n.contains("`A`") && n.contains("last value won")),
            "{:?}",
            outcome.notes
        );
        assert!(
            outcome
                .notes
                .iter()
                .any(|n| n.contains("skipped a remote name")),
            "{:?}",
            outcome.notes
        );
    }

    #[test]
    fn test_local_overrides_survive_a_pull_and_are_reported() {
        let rig = rig(
            Some("contact@pathors.com"),
            FakeExec::new().on("export", true, EXPORT, ""),
        );
        let project = rig.link(sync_for("contact@pathors.com"));
        rig.registry
            .set_local("pathors", "dev", "DATABASE_URL", "postgres://localhost")
            .unwrap();

        let outcome = pull(&rig.paths, &rig.registry, &project, "dev").unwrap();
        assert_eq!(outcome.overridden, vec!["DATABASE_URL"]);
        assert!(
            outcome
                .notes
                .iter()
                .any(|n| n.contains("1 local override shadows") && n.contains("pb env diff")),
            "{:?}",
            outcome.notes
        );

        // The pull took the remote value into the synced layer and left the
        // local one exactly where it was — which is what makes it in effect.
        assert_eq!(
            rig.synced_blob("dev")["DATABASE_URL"],
            "postgres://remote/db"
        );
        let merged = rig.registry.merged("pathors", "dev").unwrap();
        assert_eq!(merged.vars["DATABASE_URL"], "postgres://localhost");
        assert_eq!(merged.vars["API_KEY"], "remote-key");
    }
}
