//! `supabase` — an access token that normally is not on disk at all.
//!
//! Not installed on this machine; verified against the CLI's source
//! (`apps/cli-go/internal/utils/{access_token,supabase_home,profile}.go` and
//! the TypeScript rewrite's `credentials.layer.ts`). The lookup order the CLI
//! itself uses is:
//!
//! 1. `SUPABASE_ACCESS_TOKEN` in the environment
//! 2. the OS keyring, service `Supabase CLI`
//! 3. `~/.supabase/access-token` — a plaintext fallback for keyring-less machines
//!
//! So the common, healthy case has **nothing** for a file probe to find. That
//! is reported as `installed: true` with no profile and a note pointing at
//! `verify`, not as "logged out".
//!
//! `~/.supabase/access-token` holds the raw token and nothing else, so it is
//! never opened — only its existence and mode are used. `~/.supabase/profile`
//! holds an environment name (`supabase`, `supabase-staging`, …) and is safe to
//! read; note that a Supabase "profile" selects an *API environment*, not an
//! account. There is no expiry anywhere: Supabase tokens are long-lived with
//! server-side revocation (ADR 0008).

use serde::Deserialize;

use crate::paths::Paths;
use crate::probe::{unsupported_switch, unsupported_verify, Probe};
use crate::probes::cli_verify;
use crate::types::{
    ActiveConcept, Expiry, PermissionsReport, Profile, SwitchOutcome, ToolStatus, VerifyOutcome,
};
use crate::util::read_text;

pub struct SupabaseProbe {
    paths: Paths,
}

impl SupabaseProbe {
    pub const TOOL: &'static str = "supabase";
    /// The CLI's own default profile name.
    const DEFAULT_PROFILE: &'static str = "supabase";

    pub fn new(paths: Paths) -> Self {
        Self { paths }
    }

    /// What the token can see, in one clause.
    ///
    /// A Supabase token has no "whoami": it carries the full rights of the
    /// account that made it, and the only identity the API will hand back is
    /// the set of organisations and projects it reaches. So that is what is
    /// reported — the org slug where the projects agree on one, and enough
    /// project names to recognise the account by.
    ///
    /// **An empty list is a success, not a failure.** The CLI builds the array
    /// by appending to a nil slice, so a brand-new account serialises as `null`
    /// rather than `[]`; both mean "the token worked and owns no projects", and
    /// reading either as a broken login would be wrong.
    fn describe_projects(stdout: &str) -> Option<String> {
        let value: serde_json::Value = serde_json::from_str(stdout.trim()).ok()?;
        let projects: Vec<Project> = match value {
            serde_json::Value::Null => Vec::new(),
            serde_json::Value::Array(items) => items
                .into_iter()
                .filter_map(|item| serde_json::from_value(item).ok())
                .collect(),
            _ => return None,
        };
        if projects.is_empty() {
            return Some("no projects on this account".to_string());
        }

        let mut orgs: Vec<&str> = projects
            .iter()
            .filter_map(|p| p.organization_slug.as_deref())
            .collect();
        orgs.sort_unstable();
        orgs.dedup();

        let named: Vec<&str> = projects
            .iter()
            .filter_map(|p| p.name.as_deref())
            .take(3)
            .collect();
        let count = projects.len();
        let plural = if count == 1 { "" } else { "s" };
        let mut summary = format!("{count} project{plural}");
        if !named.is_empty() {
            let more = count.saturating_sub(named.len());
            summary.push_str(&format!(" ({}", named.join(", ")));
            if more > 0 {
                summary.push_str(&format!(", +{more}"));
            }
            summary.push(')');
        }
        match orgs.as_slice() {
            [only] => summary.push_str(&format!(" in org {only}")),
            [] => {}
            many => summary.push_str(&format!(" across {} orgs", many.len())),
        }
        Some(summary)
    }
}

/// The two fields of a project row that say whose account this is. Everything
/// else the CLI returns — region, status, database host, timestamps — is
/// inventory, not identity.
#[derive(Deserialize)]
struct Project {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    organization_slug: Option<String>,
}

impl Probe for SupabaseProbe {
    fn tool(&self) -> &'static str {
        Self::TOOL
    }

    fn status(&self) -> anyhow::Result<ToolStatus> {
        let home = self.paths.supabase_home();
        let token_file = home.join("access-token");
        let installed = self.paths.has_binary("supabase") || home.is_dir();
        let mut status = ToolStatus::empty(Self::TOOL, installed);
        for note in self.paths.path_notes("supabase") {
            status.push_note(note);
        }

        if !installed {
            return Ok(status);
        }

        // The profile file names an API environment, not an account.
        let profile_name = match read_text(&home.join("profile")) {
            Ok(Some(text)) => {
                let name = text.trim().to_string();
                (!name.is_empty()).then_some(name)
            }
            Ok(None) => None,
            Err(e) => {
                status.problem(e);
                None
            }
        };
        let profile_name = profile_name.unwrap_or_else(|| Self::DEFAULT_PROFILE.to_string());

        // Existence only. The file *is* the token; it is never opened.
        let on_disk = token_file.is_file();
        let in_env = self.paths.env("SUPABASE_ACCESS_TOKEN").is_some();

        if in_env {
            status.warn(
                "SUPABASE_ACCESS_TOKEN is set in the environment and wins over both the keyring \
                 and the fallback file",
            );
        }

        if on_disk || in_env {
            status.profiles.push(
                Profile::new(&profile_name)
                    .label(format!("{profile_name} environment"))
                    // Long-lived with server-side revocation (ADR 0008).
                    .expiry(Expiry::NoExpiry)
                    .with_meta(
                        "token_storage",
                        if in_env {
                            "environment"
                        } else {
                            "~/.supabase/access-token"
                        },
                    )
                    .with_meta("environment", profile_name.as_str()),
            );
            status.active = Some(profile_name.clone());
            if on_disk {
                status.warn(
                    "the access token is in the plaintext fallback file rather than the OS \
                     keyring; the CLI only falls back like this when the keyring is unavailable",
                );
            }
        } else {
            status.info(
                "supabase keeps its access token in the OS keyring (service `Supabase CLI`), \
                 which patchbay does not read; a missing fallback file is the normal, healthy \
                 case rather than a logged-out one",
            );
        }

        status.active_concept = ActiveConcept::not_applicable(
            "a supabase profile selects an API environment, not an account",
        );

        Ok(status)
    }

    fn switch(&self, _profile_id: &str) -> anyhow::Result<SwitchOutcome> {
        Ok(unsupported_switch(
            Self::TOOL,
            "supabase has one token per environment and no account switch; re-authenticate to \
             change accounts",
            Some("supabase login"),
        ))
    }

    fn verify(&self) -> anyhow::Result<VerifyOutcome> {
        if !self.paths.may_exec() || !self.paths.has_binary("supabase") {
            return Ok(unsupported_verify(
                Self::TOOL,
                "the supabase CLI is not available on PATH",
                Some("supabase projects list"),
            ));
        }

        // This is the one probe where verify is not a nicety: the token
        // normally lives in the OS keyring, which patchbay does not read, so
        // tier 1 genuinely cannot say whether there is a login at all. Only the
        // CLI can answer, and `projects list` is the cheapest thing that makes
        // it try. `--output json` is a global flag on this CLI.
        let out = self
            .paths
            .run("supabase", &["projects", "list", "--output", "json"])?;
        if !out.ok {
            return Ok(cli_verify::failure_outcome(
                Self::TOOL,
                &out,
                "Supabase",
                "supabase login",
            ));
        }

        Ok(match Self::describe_projects(&out.stdout) {
            Some(summary) => VerifyOutcome::Valid {
                tool: Self::TOOL.to_string(),
                detail: format!("Supabase accepted the token: {summary}"),
            },
            None => VerifyOutcome::Valid {
                tool: Self::TOOL.to_string(),
                detail: "Supabase accepted the token, but `supabase projects list --output json` \
                         did not parse"
                    .to_string(),
            },
        })
    }

    fn permissions(&self) -> anyhow::Result<PermissionsReport> {
        Ok(PermissionsReport::unsupported(
            Self::TOOL,
            "a Supabase access token carries the full rights of the account that created it; \
             there is no scope list to read",
            Some("the account tokens page of the Supabase dashboard"),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::NoteKind;
    use std::fs;

    #[test]
    fn test_keyring_backed_login_is_not_reported_as_logged_out() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join(".supabase")).unwrap();
        let status = SupabaseProbe::new(Paths::for_test(dir.path()))
            .status()
            .unwrap();
        assert!(status.installed);
        assert!(status.profiles.is_empty());
        // The healthy case must not read as an alarm.
        let keyring = status
            .notes
            .iter()
            .find(|n| n.text.contains("OS keyring"))
            .expect("the keyring path is explained");
        assert_eq!(keyring.kind, NoteKind::Info);
        assert_eq!(status.alarming_notes().count(), 0);
    }

    #[test]
    fn test_fallback_file_is_detected_but_never_opened() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        fs::create_dir_all(home.join(".supabase")).unwrap();
        fs::write(
            home.join(".supabase/access-token"),
            "sbp_fakefixture0000000000000000000000000000",
        )
        .unwrap();
        fs::write(home.join(".supabase/profile"), "supabase-staging\n").unwrap();

        let status = SupabaseProbe::new(Paths::for_test(home)).status().unwrap();
        assert_eq!(status.active.as_deref(), Some("supabase-staging"));
        assert_eq!(status.profiles.len(), 1);
        assert_eq!(
            status.profiles[0].meta["token_storage"],
            "~/.supabase/access-token"
        );
        // Supabase tokens are revoked, not expired.
        assert_eq!(status.profiles[0].expiry, Expiry::NoExpiry);
        let fallback = status
            .notes
            .iter()
            .find(|n| n.text.contains("plaintext fallback"))
            .expect("the plaintext fallback file is called out");
        assert_eq!(fallback.kind, NoteKind::Warn);
        // "a profile is an environment, not an account" is a property now.
        assert_eq!(
            status.active_concept,
            ActiveConcept::not_applicable(
                "a supabase profile selects an API environment, not an account"
            )
        );
        assert!(!status
            .notes
            .iter()
            .any(|n| n.text.contains("not an account")));

        let json = serde_json::to_string(&status).unwrap();
        assert!(!json.contains("sbp_fakefixture"), "{json}");
    }

    #[test]
    fn test_environment_token_wins_and_is_labelled() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join(".supabase")).unwrap();
        let paths = Paths::for_test(dir.path())
            .with_env("SUPABASE_ACCESS_TOKEN", "sbp_fakefixtureenvtoken");
        let status = SupabaseProbe::new(paths).status().unwrap();
        assert_eq!(status.active.as_deref(), Some("supabase"));
        assert_eq!(status.profiles[0].meta["token_storage"], "environment");
        let env = status
            .notes
            .iter()
            .find(|n| n.text.contains("SUPABASE_ACCESS_TOKEN"))
            .expect("the env token is called out");
        assert_eq!(env.kind, NoteKind::Warn);
        let json = serde_json::to_string(&status).unwrap();
        assert!(!json.contains("sbp_fakefixtureenvtoken"), "{json}");
    }

    #[test]
    fn test_supabase_home_override_and_absent_machine() {
        let dir = tempfile::tempdir().unwrap();
        let status = SupabaseProbe::new(Paths::for_test(dir.path()))
            .status()
            .unwrap();
        assert!(!status.installed);
        assert!(status.notes.is_empty());

        let elsewhere = dir.path().join("custom");
        fs::create_dir_all(&elsewhere).unwrap();
        fs::write(elsewhere.join("access-token"), "sbp_fixture").unwrap();
        let paths =
            Paths::for_test(dir.path()).with_env("SUPABASE_HOME", elsewhere.to_str().unwrap());
        let status = SupabaseProbe::new(paths).status().unwrap();
        assert!(status.installed);
        assert_eq!(status.profiles.len(), 1);
    }

    // ---------------------------------------------------------------- verify

    fn probe_with(
        home: &std::path::Path,
        exec: std::sync::Arc<crate::util::FakeExec>,
    ) -> SupabaseProbe {
        SupabaseProbe::new(Paths::for_test(home).with_exec(exec))
    }

    const PROJECTS: &str = r#"[
      { "id": "aaaa", "name": "pathors-prod", "organization_id": "org1",
        "organization_slug": "pathors", "region": "ap-northeast-1",
        "status": "ACTIVE_HEALTHY", "linked": true },
      { "id": "bbbb", "name": "pathors-stage", "organization_id": "org1",
        "organization_slug": "pathors", "region": "ap-northeast-1",
        "status": "ACTIVE_HEALTHY", "linked": false }
    ]"#;

    #[test]
    fn test_verify_answers_the_question_tier_one_cannot() {
        // The token normally lives in the OS keyring, so status has no profile
        // to show; only the CLI can say whether there is a login.
        let dir = tempfile::tempdir().unwrap();
        let exec = std::sync::Arc::new(crate::util::FakeExec::new().on(
            "projects list",
            true,
            PROJECTS,
            "",
        ));
        let outcome = probe_with(dir.path(), exec.clone()).verify().unwrap();
        assert_eq!(
            exec.last().unwrap().line(),
            "supabase projects list --output json"
        );
        match outcome {
            VerifyOutcome::Valid { detail, .. } => {
                assert!(detail.contains("2 projects"), "{detail}");
                assert!(detail.contains("pathors-prod"), "{detail}");
                assert!(detail.contains("in org pathors"), "{detail}");
                assert_eq!(detail.lines().count(), 1, "{detail}");
            }
            other => panic!("expected Valid, got {other:?}"),
        }
    }

    #[test]
    fn test_an_account_with_no_projects_is_a_working_token() {
        // The Go CLI appends into a nil slice, so an empty result serialises as
        // `null`. Reading either shape as a broken login would be wrong.
        let dir = tempfile::tempdir().unwrap();
        for empty in ["null", "[]"] {
            let exec = std::sync::Arc::new(crate::util::FakeExec::new().on(
                "projects list",
                true,
                empty,
                "",
            ));
            match probe_with(dir.path(), exec).verify().unwrap() {
                VerifyOutcome::Valid { detail, .. } => {
                    assert!(detail.contains("no projects"), "{empty} -> {detail}");
                }
                other => panic!("expected Valid for {empty}, got {other:?}"),
            }
        }
    }

    #[test]
    fn test_logged_out_rejected_and_offline_get_three_different_answers() {
        let dir = tempfile::tempdir().unwrap();

        let logged_out = std::sync::Arc::new(crate::util::FakeExec::new().on(
            "projects list",
            false,
            "",
            "Access token not provided. Supply an access token by running supabase login or setting the SUPABASE_ACCESS_TOKEN environment variable.\n",
        ));
        match probe_with(dir.path(), logged_out).verify().unwrap() {
            VerifyOutcome::Invalid { detail, .. } => {
                assert!(detail.contains("not logged in"), "{detail}");
                assert!(detail.contains("supabase login"), "{detail}");
            }
            other => panic!("expected Invalid, got {other:?}"),
        }

        let rejected = std::sync::Arc::new(crate::util::FakeExec::new().on(
            "projects list",
            false,
            "",
            "Unexpected error retrieving projects: {\"message\":\"Unauthorized\"}\n",
        ));
        match probe_with(dir.path(), rejected).verify().unwrap() {
            VerifyOutcome::Invalid { detail, .. } => {
                assert!(detail.contains("rejected"), "{detail}");
                assert_eq!(detail.lines().count(), 1, "{detail}");
            }
            other => panic!("expected Invalid, got {other:?}"),
        }

        // The CLI resolves through its own DNS-over-HTTPS dialer and says so.
        let offline = std::sync::Arc::new(crate::util::FakeExec::new().on(
            "projects list",
            false,
            "",
            "failed to list projects: failed to dial native: dial tcp: lookup api.supabase.com: no such host\nfailed to dial fallback: context deadline exceeded\n",
        ));
        match probe_with(dir.path(), offline).verify().unwrap() {
            VerifyOutcome::Unsupported { reason, .. } => {
                assert!(reason.contains("could not reach Supabase"), "{reason}");
            }
            other => panic!("expected Unsupported, got {other:?}"),
        }
    }

    #[test]
    fn test_unreadable_output_degrades_instead_of_panicking() {
        let dir = tempfile::tempdir().unwrap();
        for junk in ["", "not json", "{\"unexpected\": true}", "[[[["] {
            let exec = std::sync::Arc::new(crate::util::FakeExec::new().on(
                "projects list",
                true,
                junk,
                "",
            ));
            match probe_with(dir.path(), exec).verify().unwrap() {
                VerifyOutcome::Valid { detail, .. } => {
                    assert!(detail.contains("did not parse"), "{junk:?} -> {detail}");
                }
                other => panic!("expected Valid for {junk:?}, got {other:?}"),
            }
        }

        // Rows of an unfamiliar shape are skipped, not fatal.
        let exec = std::sync::Arc::new(crate::util::FakeExec::new().on(
            "projects list",
            true,
            "[{\"id\": \"aaaa\"}]",
            "",
        ));
        match probe_with(dir.path(), exec).verify().unwrap() {
            VerifyOutcome::Valid { detail, .. } => {
                assert!(detail.contains("1 project"), "{detail}")
            }
            other => panic!("expected Valid, got {other:?}"),
        }
    }

    #[test]
    fn test_verify_without_the_binary_stays_unsupported() {
        let dir = tempfile::tempdir().unwrap();
        match SupabaseProbe::new(Paths::for_test(dir.path()))
            .verify()
            .unwrap()
        {
            VerifyOutcome::Unsupported { reason, hint, .. } => {
                assert!(reason.contains("not available on PATH"), "{reason}");
                assert_eq!(hint.as_deref(), Some("supabase projects list"));
            }
            other => panic!("expected Unsupported, got {other:?}"),
        }
    }
}
