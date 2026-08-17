//! `neon` — the Neon Postgres CLI's OAuth grant.
//!
//! **The rename trap.** The binary was renamed `neonctl` -> `neon`, but the
//! config directory kept the old name. Verified empirically with `neon`
//! 2.38.2 on this machine: the binary is `neon` (with `neonctl` still installed
//! as an alias) and the state is `~/.config/neonctl/credentials.json`. The
//! probe therefore looks for either binary and reads the `neonctl` directory.
//!
//! `credentials.json` (shape verified empirically) holds
//! `{ access_token, refresh_token, id_token, scope, token_type, expires_in,
//! expires_at, user_id }`. `expires_at` is epoch **milliseconds**; the three
//! token fields are never named by the parser at all.
//!
//! That `expires_at` is only the login's expiry when the grant is *not*
//! offline-scoped. With `offline`/`offline_access` in the scope list the CLI
//! refreshes the access token itself on the next command, so the timestamp
//! describes an hour-long token nobody has to think about — reported as an
//! expiry it puts a live login on the board as "expired 12d". Offline-scoped
//! grants are therefore [`Expiry::Refreshable`], which carries that hourly
//! clock without letting it count as a deadline.
//!
//! `NEON_API_KEY` in the environment overrides the file entirely, which is how
//! CI runs the CLI — worth a note, because the file's expiry then describes a
//! credential nothing is using.

use serde::Deserialize;

use crate::paths::Paths;
use crate::probe::{unsupported_switch, unsupported_verify, Probe};
use crate::probes::cli_verify;
use crate::types::{
    Expiry, Note, PermissionsReport, Profile, SwitchOutcome, ToolStatus, VerifyOutcome,
};
use crate::util::{parse_epoch_millis, read_text};

pub struct NeonProbe {
    paths: Paths,
}

/// `access_token` / `refresh_token` / `id_token` are deliberately not fields.
#[derive(Deserialize)]
struct Credentials {
    #[serde(default)]
    expires_at: Option<i64>,
    #[serde(default)]
    scope: Option<String>,
    #[serde(default)]
    user_id: Option<String>,
    #[serde(default)]
    token_type: Option<String>,
}

impl NeonProbe {
    pub const TOOL: &'static str = "neon";
    const PROFILE_ID: &'static str = "default";

    pub fn new(paths: Paths) -> Self {
        Self { paths }
    }

    /// Neon writes the scope list as one space-separated string.
    fn scopes(raw: Option<&str>) -> Vec<String> {
        raw.map(|s| s.split_whitespace().map(str::to_string).collect())
            .unwrap_or_default()
    }

    /// Whichever of the two names is installed — see the rename trap in the
    /// module header. `neon` first, because that is the current one.
    fn binary(&self) -> Option<&'static str> {
        if !self.paths.may_exec() {
            return None;
        }
        ["neon", "neonctl"]
            .into_iter()
            .find(|bin| self.paths.has_binary(bin))
    }
}

/// The half of `neon me --output json` worth naming. The response also carries
/// an avatar URL per auth account, which is bulk with no bearing on identity,
/// and `auth_accounts`, which repeats the same person once per provider.
#[derive(Deserialize, Default)]
struct Me {
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    login: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    plan: Option<String>,
}

impl Me {
    /// The identity in one clause, however much of it Neon actually sent.
    fn describe(&self) -> String {
        let who = self
            .email
            .clone()
            .or_else(|| self.login.clone())
            .or_else(|| self.name.clone())
            .or_else(|| self.id.clone())
            .unwrap_or_else(|| "an account it would not name".to_string());
        match (&self.login, &self.plan) {
            (Some(login), Some(plan)) if Some(login) != self.email.as_ref() => {
                format!("{who} (login {login}, {plan} plan)")
            }
            (_, Some(plan)) => format!("{who} ({plan} plan)"),
            _ => who,
        }
    }
}

impl Probe for NeonProbe {
    fn tool(&self) -> &'static str {
        Self::TOOL
    }

    fn status(&self) -> anyhow::Result<ToolStatus> {
        let path = self.paths.neon_dir().join("credentials.json");
        // Both names are current: `neon` is the CLI, `neonctl` the old alias.
        let installed =
            self.paths.has_binary("neon") || self.paths.has_binary("neonctl") || path.is_file();
        let mut status = ToolStatus::empty(Self::TOOL, installed);
        for note in self.paths.path_notes("neon") {
            status.push_note(note);
        }

        if self.paths.env("NEON_API_KEY").is_some() {
            status.warn(
                "NEON_API_KEY is set in the environment and overrides the stored login; the CLI \
                 will use that key regardless of what is on disk",
            );
        }

        let text = match read_text(&path) {
            Ok(Some(text)) => text,
            Ok(None) => return Ok(status),
            Err(e) => {
                status.problem(e);
                return Ok(status);
            }
        };

        let credentials: Credentials = match serde_json::from_str(&text) {
            Ok(credentials) => credentials,
            Err(e) => {
                status.problem(format!("credentials.json is not valid JSON ({e})"));
                return Ok(status);
            }
        };

        let expires_at = credentials.expires_at.and_then(parse_epoch_millis);
        if credentials.expires_at.is_some() && expires_at.is_none() {
            status.problem("expires_at is present but is not a usable timestamp".to_string());
        }

        let scopes = Self::scopes(credentials.scope.as_deref());
        let refreshable = scopes.iter().any(|s| s.starts_with("offline"));

        // Only a grant that cannot refresh itself has a deadline a human has to
        // meet; see the module header. An offline-scoped grant keeps its hourly
        // clock inside `Refreshable`, where nothing treats it as one.
        let expiry = match (refreshable, expires_at) {
            (true, access_token_expires) => Expiry::Refreshable {
                access_token_expires,
            },
            (false, Some(at)) => Expiry::At(at),
            (false, None) => Expiry::unknown("not recorded in credentials.json"),
        };

        status.profiles.push(
            Profile::new(Self::PROFILE_ID)
                .label(match &credentials.user_id {
                    Some(id) => format!("neon user {id}"),
                    None => "neon oauth login".to_string(),
                })
                .expiry(expiry)
                .with_meta("user_id", credentials.user_id.clone())
                .with_meta("token_type", credentials.token_type.clone())
                .with_meta("scopes", scopes)
                .with_meta("refreshable", refreshable)
                .with_meta("source", path.display().to_string()),
        );
        status.active = Some(Self::PROFILE_ID.to_string());

        Ok(status)
    }

    fn switch(&self, _profile_id: &str) -> anyhow::Result<SwitchOutcome> {
        Ok(unsupported_switch(
            Self::TOOL,
            "neon holds a single OAuth grant with no profile concept; re-authenticate to change \
             accounts",
            Some("neon auth"),
        ))
    }

    fn verify(&self) -> anyhow::Result<VerifyOutcome> {
        let Some(bin) = self.binary() else {
            return Ok(unsupported_verify(
                Self::TOOL,
                "the neon CLI is not available on PATH",
                Some("neon me"),
            ));
        };

        // **The reason this gate exists.** `neon me` does not fail when there
        // is no credential: the CLI starts its OAuth flow, opens a browser and
        // waits for the callback. A verify that hangs a spinner until the user
        // logs in is worse than no verify, so the one state that would trigger
        // it is answered from tier 1 instead — exactly the shape gcloud uses
        // for an uncredentialed account.
        let credentialed = self.paths.neon_dir().join("credentials.json").is_file()
            || self.paths.env("NEON_API_KEY").is_some();
        if !credentialed {
            return Ok(VerifyOutcome::Invalid {
                tool: Self::TOOL.to_string(),
                detail: "no stored Neon credential on this machine — run `neon auth`".to_string(),
            });
        }

        let out = self.paths.run(bin, &["me", "--output", "json"])?;
        if !out.ok {
            return Ok(cli_verify::failure_outcome(
                Self::TOOL,
                &out,
                "Neon",
                "neon auth",
            ));
        }

        let me: Me = match serde_json::from_str(&out.stdout) {
            Ok(me) => me,
            Err(e) => {
                // Exit 0, so Neon answered and the grant works; only the shape
                // of the answer is unfamiliar.
                return Ok(VerifyOutcome::Valid {
                    tool: Self::TOOL.to_string(),
                    detail: format!(
                        "Neon accepted the login, but `neon me --output json` did not parse ({e})"
                    ),
                });
            }
        };

        Ok(VerifyOutcome::Valid {
            tool: Self::TOOL.to_string(),
            detail: format!("Neon accepted the login for {}", me.describe()),
        })
    }

    fn permissions(&self) -> anyhow::Result<PermissionsReport> {
        let status = self.status()?;
        let Some(profile) = status.profiles.first() else {
            return Ok(PermissionsReport::unsupported(
                Self::TOOL,
                "neon is not logged in",
                Some("neon auth"),
            ));
        };
        let scopes: Vec<String> = profile
            .meta
            .get("scopes")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        Ok(PermissionsReport {
            tool: Self::TOOL.to_string(),
            supported: true,
            subject: profile
                .meta
                .get("user_id")
                .and_then(|v| v.as_str())
                .map(str::to_string),
            scopes,
            notes: vec![Note::info(
                "scopes come from the local OAuth grant; membership of each Neon organisation \
                 decides what those scopes can actually reach",
            )],
            hint: Some("neon auth".to_string()),
            scope: None,
        })
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
        fs::create_dir_all(home.join(".config/neonctl")).unwrap();
        fs::write(home.join(".config/neonctl/credentials.json"), body).unwrap();
        (dir, home)
    }

    // Key set copied from a real credentials.json; values are invented.
    fn credentials(expires_at: i64) -> String {
        format!(
            r#"{{
              "access_token": "fake-fixture-access",
              "expires_in": 3600,
              "id_token": "fake-fixture-id",
              "refresh_token": "fake-fixture-refresh",
              "scope": "openid offline offline_access urn:neoncloud:projects:read",
              "token_type": "bearer",
              "expires_at": {expires_at},
              "user_id": "0a1b2c3d-0000-4444-8888-abcdefabcdef"
            }}"#
        )
    }

    /// The same credentials without the two offline scopes: an access token
    /// that really is the whole login.
    fn credentials_without_offline(expires_at: i64) -> String {
        credentials(expires_at).replace("openid offline offline_access ", "openid ")
    }

    #[test]
    fn test_grant_scopes_and_no_expiry_for_a_grant_that_refreshes_itself() {
        let (_dir, home) = fixture(&credentials(1785611828464));
        let status = NeonProbe::new(Paths::for_test(&home)).status().unwrap();
        assert_eq!(status.active.as_deref(), Some("default"));
        let profile = &status.profiles[0];
        assert!(profile.expires_at().is_none());
        assert_eq!(
            profile.expiry,
            Expiry::Refreshable {
                access_token_expires: parse_epoch_millis(1785611828464)
            }
        );
        assert_eq!(profile.meta["scopes"][0], "openid");
        assert_eq!(profile.meta["refreshable"], true);
        assert_eq!(profile.meta["token_type"], "bearer");

        let json = serde_json::to_string(&status).unwrap();
        for secret in [
            "fake-fixture-access",
            "fake-fixture-id",
            "fake-fixture-refresh",
        ] {
            assert!(!json.contains(secret), "leaked {secret}");
        }
    }

    #[test]
    fn test_a_long_stale_offline_grant_is_not_a_dead_login() {
        // 2021-01-01 in milliseconds — an hourly token five years past, which
        // read as the login's expiry parked neon permanently in the board's
        // expired tally.
        let (_dir, home) = fixture(&credentials(1609459200000));
        let status = NeonProbe::new(Paths::for_test(&home)).status().unwrap();
        assert!(status.profiles[0].expires_at().is_none());
        // The hour is still on the record, just not as a deadline.
        assert_eq!(
            status.profiles[0].expiry,
            Expiry::Refreshable {
                access_token_expires: parse_epoch_millis(1609459200000)
            }
        );
        assert_eq!(
            status.connection_state(),
            crate::types::ConnectionState::Connected
        );
    }

    #[test]
    fn test_a_grant_that_cannot_refresh_keeps_its_expiry() {
        // No offline scope: when this hour is up the login really is over, so
        // the timestamp is the answer rather than noise.
        let (_dir, home) = fixture(&credentials_without_offline(1785611828464));
        let status = NeonProbe::new(Paths::for_test(&home)).status().unwrap();
        assert_eq!(status.profiles[0].meta["refreshable"], false);
        assert_eq!(
            status.profiles[0].expires_at().unwrap().to_rfc3339(),
            "2026-08-01T19:17:08.464+00:00"
        );
        assert!(matches!(status.profiles[0].expiry, Expiry::At(_)));
    }

    #[test]
    fn test_api_key_in_the_environment_is_flagged() {
        let (_dir, home) = fixture(&credentials(1785611828464));
        let paths = Paths::for_test(&home).with_env("NEON_API_KEY", "fake-fixture-key");
        let status = NeonProbe::new(paths).status().unwrap();
        // An env var silently overriding the stored login is a surprise, not a
        // breakage: warn.
        assert!(status
            .notes
            .iter()
            .any(|n| n.kind == NoteKind::Warn && n.text.contains("NEON_API_KEY")));
        let json = serde_json::to_string(&status).unwrap();
        assert!(!json.contains("fake-fixture-key"), "{json}");
    }

    #[test]
    fn test_missing_and_malformed() {
        let dir = tempfile::tempdir().unwrap();
        let status = NeonProbe::new(Paths::for_test(dir.path()))
            .status()
            .unwrap();
        assert!(!status.installed);
        assert!(status.profiles.is_empty());
        assert!(status.notes.is_empty());

        let (_dir, home) = fixture("{\"expires_at\":");
        let status = NeonProbe::new(Paths::for_test(&home)).status().unwrap();
        assert!(status.installed);
        assert!(status.profiles.is_empty());
        assert!(status
            .notes
            .iter()
            .any(|n| n.kind == NoteKind::Problem && n.text.contains("not valid JSON")));
    }

    #[test]
    fn test_an_unusable_expires_at_is_a_problem() {
        // Far outside the range a millisecond timestamp can represent.
        let (_dir, home) = fixture(
            r#"{ "access_token": "fake", "scope": "openid", "expires_at": 9223372036854775807 }"#,
        );
        let status = NeonProbe::new(Paths::for_test(&home)).status().unwrap();
        assert!(status.notes.iter().any(|n| n.kind == NoteKind::Problem
            && n.text
                .contains("expires_at is present but is not a usable timestamp")));
    }

    // ---------------------------------------------------------------- verify

    fn probe_with(
        home: &std::path::Path,
        exec: std::sync::Arc<crate::util::FakeExec>,
    ) -> NeonProbe {
        NeonProbe::new(Paths::for_test(home).with_exec(exec))
    }

    /// `neon me --output json` on this machine, minus the avatar URLs.
    const ME: &str = r#"{
      "email": "dev@example.com",
      "id": "0a1b2c3d-0000-4444-8888-abcdefabcdef",
      "login": "devlogin",
      "name": "Dev",
      "projects_limit": 0,
      "plan": "free"
    }"#;

    #[test]
    fn test_verify_reports_the_account_neon_names() {
        let (_dir, home) = fixture(&credentials(1785611828464));
        let exec = std::sync::Arc::new(crate::util::FakeExec::new().on("me", true, ME, ""));
        let outcome = probe_with(&home, exec.clone()).verify().unwrap();
        assert_eq!(exec.last().unwrap().line(), "neon me --output json");
        match outcome {
            VerifyOutcome::Valid { detail, .. } => {
                assert!(detail.contains("dev@example.com"), "{detail}");
                assert!(detail.contains("devlogin"), "{detail}");
                assert!(detail.contains("free"), "{detail}");
            }
            other => panic!("expected Valid, got {other:?}"),
        }
    }

    #[test]
    fn test_no_stored_credential_is_answered_without_opening_a_browser() {
        // `neon me` with nothing on disk starts the OAuth flow and waits for a
        // browser callback. Tier 1 already knows the answer, so nothing runs.
        let dir = tempfile::tempdir().unwrap();
        let exec = std::sync::Arc::new(crate::util::FakeExec::new().on("me", true, ME, ""));
        match probe_with(dir.path(), exec.clone()).verify().unwrap() {
            VerifyOutcome::Invalid { detail, .. } => {
                assert!(detail.contains("neon auth"), "{detail}");
            }
            other => panic!("expected Invalid, got {other:?}"),
        }
        assert!(exec.calls().is_empty(), "nothing may be executed here");
    }

    #[test]
    fn test_an_api_key_in_the_environment_is_credential_enough_to_run() {
        let dir = tempfile::tempdir().unwrap();
        let exec = std::sync::Arc::new(crate::util::FakeExec::new().on("me", true, ME, ""));
        let paths = Paths::for_test(dir.path())
            .with_env("NEON_API_KEY", "fake-fixture-key")
            .with_exec(exec.clone());
        assert!(matches!(
            NeonProbe::new(paths).verify().unwrap(),
            VerifyOutcome::Valid { .. }
        ));
        assert_eq!(exec.calls().len(), 1);
    }

    #[test]
    fn test_a_revoked_grant_and_an_outage_get_different_answers() {
        let (_dir, home) = fixture(&credentials(1785611828464));

        let revoked = std::sync::Arc::new(crate::util::FakeExec::new().on(
            "me",
            false,
            "",
            "ERROR: Authentication failed: 401 Unauthorized\n",
        ));
        match probe_with(&home, revoked).verify().unwrap() {
            VerifyOutcome::Invalid { detail, .. } => {
                assert!(detail.contains("neon auth"), "{detail}");
                assert_eq!(detail.lines().count(), 1, "{detail}");
            }
            other => panic!("expected Invalid, got {other:?}"),
        }

        let offline = std::sync::Arc::new(crate::util::FakeExec::new().on(
            "me",
            false,
            "",
            "ERROR: request to https://console.neon.tech/api/v2/users/me failed: getaddrinfo EAI_AGAIN console.neon.tech\n",
        ));
        match probe_with(&home, offline).verify().unwrap() {
            VerifyOutcome::Unsupported { reason, .. } => {
                assert!(reason.contains("could not reach Neon"), "{reason}");
            }
            other => panic!("expected Unsupported, got {other:?}"),
        }
    }

    #[test]
    fn test_unparseable_json_degrades_instead_of_panicking() {
        let (_dir, home) = fixture(&credentials(1785611828464));
        let exec = std::sync::Arc::new(crate::util::FakeExec::new().on(
            "me",
            true,
            "Warning: a new version is available\n{ not json",
            "",
        ));
        match probe_with(&home, exec).verify().unwrap() {
            VerifyOutcome::Valid { detail, .. } => {
                assert!(detail.contains("did not parse"), "{detail}");
            }
            other => panic!("expected Valid, got {other:?}"),
        }

        // Valid JSON of an unexpected shape is not a crash either.
        let exec = std::sync::Arc::new(crate::util::FakeExec::new().on("me", true, "{}", ""));
        match probe_with(&home, exec).verify().unwrap() {
            VerifyOutcome::Valid { detail, .. } => {
                assert!(detail.contains("would not name"), "{detail}");
            }
            other => panic!("expected Valid, got {other:?}"),
        }
    }

    #[test]
    fn test_verify_without_the_binary_stays_unsupported() {
        let (_dir, home) = fixture(&credentials(1785611828464));
        match NeonProbe::new(Paths::for_test(&home)).verify().unwrap() {
            VerifyOutcome::Unsupported { reason, hint, .. } => {
                assert!(reason.contains("not available on PATH"), "{reason}");
                assert_eq!(hint.as_deref(), Some("neon me"));
            }
            other => panic!("expected Unsupported, got {other:?}"),
        }
    }

    #[test]
    fn test_credentials_without_an_expiry_degrade_to_unknown() {
        let (_dir, home) = fixture(r#"{ "access_token": "fake", "scope": "openid" }"#);
        let status = NeonProbe::new(Paths::for_test(&home)).status().unwrap();
        assert_eq!(status.profiles.len(), 1);
        assert!(status.profiles[0].expires_at().is_none());
        assert_eq!(
            status.profiles[0].expiry,
            Expiry::unknown("not recorded in credentials.json")
        );
        assert_eq!(status.profiles[0].meta["refreshable"], false);
    }
}
