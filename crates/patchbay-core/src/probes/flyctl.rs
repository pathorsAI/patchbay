//! `flyctl` — Fly.io's single flat config.
//!
//! Not installed on this machine; verified against the CLI's source
//! (`helpers/config.go`, `internal/config/config.go`). `FLY_CONFIG_DIR`, else
//! `~/.fly`, holding `config.yml`:
//!
//! ```yaml
//! access_token: FlyV1 fm2_...
//! metrics_token: ...
//! send_metrics: true
//! auto_update: true
//! last_login: 2026-08-11T09:14:22.481773+08:00
//! ```
//!
//! Two things worth knowing, both encoded below:
//!
//! * **No organisation is recorded.** `fly` is org-centric in use, but the org
//!   comes from `--org` / `FLY_ORG` at run time and is never written here. The
//!   probe must not invent one from a project's `fly.toml`, which is a
//!   different thing entirely.
//! * **`last_login` is not an expiry.** Fly tokens are macaroons that may carry
//!   their own expiry *inside the token string*, and reading that would mean
//!   reading the secret. So the expiry is `Unknown`, pointing at the token.
//!
//! The binary is installed as `flyctl` and almost always aliased to `fly`;
//! both names are checked.

use serde::Deserialize;

use crate::paths::Paths;
use crate::probe::{unsupported_switch, unsupported_verify, Probe};
use crate::probes::cli_verify;
use crate::types::{
    ActiveConcept, Expiry, PermissionsReport, Profile, SwitchOutcome, ToolStatus, VerifyOutcome,
};
use crate::util::{parse_timestamp, read_text};

pub struct FlyctlProbe {
    paths: Paths,
}

/// `access_token` and `metrics_token` are presence-only.
#[derive(Deserialize, Default)]
struct Config {
    #[serde(default)]
    access_token: Option<serde::de::IgnoredAny>,
    #[serde(default)]
    metrics_token: Option<serde::de::IgnoredAny>,
    #[serde(default)]
    last_login: Option<String>,
    #[serde(default)]
    auto_update: Option<bool>,
}

impl FlyctlProbe {
    pub const TOOL: &'static str = "flyctl";
    const PROFILE_ID: &'static str = "default";

    pub fn new(paths: Paths) -> Self {
        Self { paths }
    }

    /// Whichever name is on PATH. `fly` is the one Fly's own docs and installer
    /// use; `flyctl` is the package name and is still what some installs leave
    /// behind, so both are tried.
    fn binary(&self) -> Option<&'static str> {
        if !self.paths.may_exec() {
            return None;
        }
        ["fly", "flyctl"]
            .into_iter()
            .find(|bin| self.paths.has_binary(bin))
    }

    /// The identity out of `fly auth whoami`, in either shape.
    ///
    /// With `--json` the answer is `{"email": "…"}`; without it, or on a
    /// version that ignores the flag, it is the bare address on one line. Both
    /// are accepted so that the flag's real job — suppressing the interactive
    /// login — does not also become a parsing dependency.
    fn parse_whoami(stdout: &str) -> Option<String> {
        if let Some(email) = serde_json::from_str::<serde_json::Value>(stdout.trim())
            .ok()
            .and_then(|v| v.get("email")?.as_str().map(str::to_string))
            .filter(|e| !e.trim().is_empty())
        {
            return Some(email);
        }
        let line = stdout.lines().map(str::trim).find(|l| !l.is_empty())?;
        let line = line
            .split_once(':')
            .map(|(_, rest)| rest.trim())
            .filter(|rest| !rest.is_empty())
            .unwrap_or(line);
        // A line of pure punctuation is not a name.
        line.chars()
            .any(char::is_alphanumeric)
            .then(|| line.to_string())
    }
}

impl Probe for FlyctlProbe {
    fn tool(&self) -> &'static str {
        Self::TOOL
    }

    fn status(&self) -> anyhow::Result<ToolStatus> {
        let path = self.paths.fly_config();
        let installed =
            self.paths.has_binary("flyctl") || self.paths.has_binary("fly") || path.is_file();
        let mut status = ToolStatus::empty(Self::TOOL, installed);
        for note in self.paths.path_notes("fly") {
            status.push_note(note);
        }

        let text = match read_text(&path) {
            Ok(Some(text)) => text,
            Ok(None) => return Ok(status),
            Err(e) => {
                status.problem(e);
                return Ok(status);
            }
        };

        let config: Config = match serde_yaml_ng::from_str(&text) {
            Ok(config) => config,
            Err(e) => {
                status.problem(format!("fly config.yml is not valid YAML ({e})"));
                return Ok(status);
            }
        };

        if self.paths.env("FLY_ACCESS_TOKEN").is_some() || self.paths.env("FLY_API_TOKEN").is_some()
        {
            status.warn("a Fly token is set in the environment and overrides the stored one");
        }

        if config.access_token.is_none() {
            status.info(format!(
                "{} exists but holds no access_token; flyctl is not logged in",
                path.display()
            ));
            return Ok(status);
        }

        let last_login = config.last_login.as_deref().and_then(parse_timestamp);

        status.profiles.push(
            Profile::new(Self::PROFILE_ID)
                .label("fly.io login")
                // Deliberately not last_login: see the module docs.
                .expiry(Expiry::unknown("inside the macaroon token"))
                .with_meta("last_login", last_login.map(|at| at.to_rfc3339()))
                .with_meta("has_metrics_token", config.metrics_token.is_some())
                .with_meta("auto_update", config.auto_update)
                .with_meta("source", path.display().to_string()),
        );
        status.active = Some(Self::PROFILE_ID.to_string());
        status.active_concept = ActiveConcept::not_applicable(
            "flyctl has one flat config with no profiles to choose between",
        );

        // Not the same claim as the one above: the org is a fact about what is
        // *absent* from the file, and a reader who sees no org needs to know
        // patchbay did not lose it.
        status.info(
            "no organisation is recorded on disk; the org comes from --org or FLY_ORG at run \
             time",
        );
        status.warn("the Fly token is a macaroon stored in plain text in config.yml");

        Ok(status)
    }

    fn switch(&self, _profile_id: &str) -> anyhow::Result<SwitchOutcome> {
        Ok(unsupported_switch(
            Self::TOOL,
            "flyctl stores a single token with no profile concept; re-authenticate to change \
             accounts",
            Some("fly auth login"),
        ))
    }

    fn verify(&self) -> anyhow::Result<VerifyOutcome> {
        let Some(bin) = self.binary() else {
            return Ok(unsupported_verify(
                Self::TOOL,
                "the fly CLI is not available on PATH",
                Some("fly auth whoami"),
            ));
        };

        // **`--json` is here to stop a prompt, not to make parsing nicer.**
        // `fly auth whoami` runs through `RequireSession`, which offers an
        // interactive browser login when there is no token; the literal flag is
        // one of the three things that disarm that gate (a non-TTY and `CI=1`
        // being the others, neither of which patchbay can rely on). A verify
        // that opens a browser and waits is worse than no verify.
        let out = self.paths.run(bin, &["auth", "whoami", "--json"])?;
        if !out.ok {
            return Ok(cli_verify::failure_outcome(
                Self::TOOL,
                &out,
                "Fly.io",
                "fly auth login",
            ));
        }

        Ok(match Self::parse_whoami(&out.stdout) {
            Some(who) => VerifyOutcome::Valid {
                tool: Self::TOOL.to_string(),
                detail: format!("Fly.io accepted the macaroon for {who}"),
            },
            // Exit 0 means Fly answered, so the token is live; only the name is
            // missing. `whoami` says nothing about org membership either way —
            // the org comes from --org at run time, so none is claimed here.
            None => VerifyOutcome::Valid {
                tool: Self::TOOL.to_string(),
                detail: "Fly.io accepted the macaroon, but `fly auth whoami` named no user"
                    .to_string(),
            },
        })
    }

    fn permissions(&self) -> anyhow::Result<PermissionsReport> {
        Ok(PermissionsReport::unsupported(
            Self::TOOL,
            "a Fly macaroon carries its own caveats inside the token, which patchbay will not \
             read; org membership decides the rest",
            Some("fly orgs list"),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::NoteKind;
    use std::fs;
    use std::path::PathBuf;

    fn fixture(body: &str) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().to_path_buf();
        fs::create_dir_all(home.join(".fly")).unwrap();
        fs::write(home.join(".fly/config.yml"), body).unwrap();
        (dir, home)
    }

    const CONFIG: &str = "access_token: FlyV1 fm2_fakefixturemacaroon\n\
                          metrics_token: fake-fixture-metrics\n\
                          send_metrics: true\n\
                          auto_update: true\n\
                          last_login: 2026-08-11T09:14:22.481773+08:00\n";

    #[test]
    fn test_login_without_inventing_an_expiry_or_an_org() {
        let (_dir, home) = fixture(CONFIG);
        let status = FlyctlProbe::new(Paths::for_test(&home)).status().unwrap();
        assert_eq!(status.active.as_deref(), Some("default"));
        let profile = &status.profiles[0];
        // last_login is not an expiry, and the real one is inside the macaroon.
        assert_eq!(profile.expires_at(), None, "last_login is not an expiry");
        assert_eq!(
            profile.expiry,
            Expiry::unknown("inside the macaroon token"),
            "the reason has to name where the deadline actually lives"
        );
        assert_eq!(
            profile.meta["last_login"],
            "2026-08-11T01:14:22.481773+00:00"
        );
        assert_eq!(profile.meta["has_metrics_token"], true);
        assert!(profile.meta.get("org").is_none());
        let org = status
            .notes
            .iter()
            .find(|n| n.text.contains("no organisation"))
            .expect("the absent org is still explained");
        assert_eq!(org.kind, NoteKind::Info);
        // A plaintext macaroon on disk is a warning.
        let plaintext = status
            .notes
            .iter()
            .find(|n| n.text.contains("plain text"))
            .expect("the plaintext token is called out");
        assert_eq!(plaintext.kind, NoteKind::Warn);
        // "there is only one login" is a property now, not a note.
        assert!(status.active_concept.is_not_applicable());
        assert!(!status.notes.iter().any(|n| n.text.contains("no profiles")));

        let json = serde_json::to_string(&status).unwrap();
        assert!(!json.contains("fm2_fakefixturemacaroon"), "{json}");
        assert!(!json.contains("fake-fixture-metrics"), "{json}");
    }

    #[test]
    fn test_environment_token_is_flagged() {
        let (_dir, home) = fixture(CONFIG);
        let paths = Paths::for_test(&home).with_env("FLY_ACCESS_TOKEN", "fake-fixture-env");
        let status = FlyctlProbe::new(paths).status().unwrap();
        let note = status
            .notes
            .iter()
            .find(|n| n.text.contains("environment"))
            .expect("the env token is called out");
        assert_eq!(note.kind, NoteKind::Warn);
        let json = serde_json::to_string(&status).unwrap();
        assert!(!json.contains("fake-fixture-env"), "{json}");
    }

    #[test]
    fn test_config_dir_override_is_followed_and_noted() {
        let dir = tempfile::tempdir().unwrap();
        let elsewhere = dir.path().join("fly-config");
        fs::create_dir_all(&elsewhere).unwrap();
        fs::write(elsewhere.join("config.yml"), CONFIG).unwrap();
        let paths =
            Paths::for_test(dir.path()).with_env("FLY_CONFIG_DIR", elsewhere.to_str().unwrap());
        let status = FlyctlProbe::new(paths).status().unwrap();
        assert_eq!(status.profiles.len(), 1);
        assert!(status
            .notes
            .iter()
            .any(|n| n.text.contains("$FLY_CONFIG_DIR=")));
    }

    #[test]
    fn test_missing_malformed_and_tokenless() {
        let dir = tempfile::tempdir().unwrap();
        let status = FlyctlProbe::new(Paths::for_test(dir.path()))
            .status()
            .unwrap();
        assert!(!status.installed);
        assert!(status.profiles.is_empty());
        assert!(status.notes.is_empty());

        let (_dir, home) = fixture("access_token: [unclosed\n");
        let status = FlyctlProbe::new(Paths::for_test(&home)).status().unwrap();
        let malformed = status
            .notes
            .iter()
            .find(|n| n.text.contains("not valid YAML"))
            .expect("the parse failure is reported");
        assert_eq!(malformed.kind, NoteKind::Problem);

        let (_dir, home) = fixture("send_metrics: true\n");
        let status = FlyctlProbe::new(Paths::for_test(&home)).status().unwrap();
        assert!(status.profiles.is_empty());
        // Logged out is a state, not a fault: the board already says
        // Disconnected, so the note stays quiet.
        let logged_out = status
            .notes
            .iter()
            .find(|n| n.text.contains("not logged in"))
            .expect("the logged-out state is explained");
        assert_eq!(logged_out.kind, NoteKind::Info);
    }

    // ---------------------------------------------------------------- verify

    fn probe_with(
        home: &std::path::Path,
        exec: std::sync::Arc<crate::util::FakeExec>,
    ) -> FlyctlProbe {
        FlyctlProbe::new(Paths::for_test(home).with_exec(exec))
    }

    #[test]
    fn test_verify_reports_the_account_fly_names() {
        let (_dir, home) = fixture(CONFIG);
        let exec = std::sync::Arc::new(crate::util::FakeExec::new().on(
            "auth whoami",
            true,
            "{\n    \"email\": \"dev@example.com\"\n}\n",
            "",
        ));
        let outcome = probe_with(&home, exec.clone()).verify().unwrap();
        // The flag is load-bearing: without it `whoami` may offer a browser
        // login instead of failing.
        assert_eq!(exec.last().unwrap().line(), "fly auth whoami --json");
        match outcome {
            VerifyOutcome::Valid { detail, .. } => {
                assert!(detail.contains("dev@example.com"), "{detail}");
                // No org may be invented: fly records none, and --org decides
                // it at run time.
                assert!(!detail.to_lowercase().contains("org"), "{detail}");
            }
            other => panic!("expected Valid, got {other:?}"),
        }
    }

    #[test]
    fn test_both_answer_shapes_reduce_to_the_identity() {
        for shape in [
            "{\"email\": \"dev@example.com\"}",
            "Current user: dev@example.com\n",
            "dev@example.com\n",
        ] {
            assert_eq!(
                FlyctlProbe::parse_whoami(shape),
                Some("dev@example.com".to_string()),
                "{shape}"
            );
        }
        assert_eq!(FlyctlProbe::parse_whoami("{\"email\": \"\"}"), None);
    }

    #[test]
    fn test_logged_out_revoked_and_offline_get_three_different_answers() {
        let (_dir, home) = fixture(CONFIG);

        let logged_out = std::sync::Arc::new(crate::util::FakeExec::new().on(
            "auth whoami",
            false,
            "",
            "Error: No access token available. Please login with 'flyctl auth login'\n",
        ));
        match probe_with(&home, logged_out).verify().unwrap() {
            VerifyOutcome::Invalid { detail, .. } => {
                assert!(detail.contains("not logged in"), "{detail}");
                assert!(detail.contains("fly auth login"), "{detail}");
            }
            other => panic!("expected Invalid, got {other:?}"),
        }

        let revoked = std::sync::Arc::new(crate::util::FakeExec::new().on(
            "auth whoami",
            false,
            "",
            "Error: failed to fetch user: 401 Unauthorized\n",
        ));
        match probe_with(&home, revoked).verify().unwrap() {
            VerifyOutcome::Invalid { detail, .. } => {
                assert!(detail.contains("rejected"), "{detail}");
                assert_eq!(detail.lines().count(), 1, "{detail}");
            }
            other => panic!("expected Invalid, got {other:?}"),
        }

        let offline = std::sync::Arc::new(crate::util::FakeExec::new().on(
            "auth whoami",
            false,
            "",
            "Error: Post \"https://api.fly.io/graphql\": dial tcp: lookup api.fly.io: no such host\n",
        ));
        match probe_with(&home, offline).verify().unwrap() {
            VerifyOutcome::Unsupported { reason, .. } => {
                assert!(reason.contains("could not reach Fly.io"), "{reason}");
            }
            other => panic!("expected Unsupported, got {other:?}"),
        }
    }

    #[test]
    fn test_unreadable_output_degrades_instead_of_panicking() {
        let (_dir, home) = fixture(CONFIG);
        for junk in ["", "\n \n", ":"] {
            let exec =
                std::sync::Arc::new(crate::util::FakeExec::new().on("auth whoami", true, junk, ""));
            match probe_with(&home, exec).verify().unwrap() {
                VerifyOutcome::Valid { detail, .. } => {
                    assert!(detail.contains("named no user"), "{junk:?} -> {detail}");
                }
                other => panic!("expected Valid for {junk:?}, got {other:?}"),
            }
        }
    }

    #[test]
    fn test_verify_without_the_binary_stays_unsupported() {
        let (_dir, home) = fixture(CONFIG);
        match FlyctlProbe::new(Paths::for_test(&home)).verify().unwrap() {
            VerifyOutcome::Unsupported { reason, hint, .. } => {
                assert!(reason.contains("not available on PATH"), "{reason}");
                assert_eq!(hint.as_deref(), Some("fly auth whoami"));
            }
            other => panic!("expected Unsupported, got {other:?}"),
        }
    }
}
