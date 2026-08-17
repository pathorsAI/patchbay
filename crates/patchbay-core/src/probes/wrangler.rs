//! `wrangler` — the Cloudflare OAuth grant on disk.
//!
//! Wrangler keeps one global login at
//! `~/Library/Preferences/.wrangler/config/default.toml`, with the older
//! `~/.wrangler/config/default.toml` still present on machines that predate the
//! move. Presence of the file means "logged in", and `scopes` gives a real
//! permissions list.
//!
//! `expiration_time` dates the *access* token. Where a `refresh_token` sits
//! beside it, wrangler renews that silently on the next command, so the
//! timestamp is not when the login stops working — reported as the profile's
//! expiry it put a live grant on the board as "expired 154d". That grant is
//! [`Expiry::Refreshable`], carrying the timestamp as the access token's own
//! clock and nothing more. Only a grant with no refresh token gets
//! [`Expiry::At`], because there the deadline really is the login's.
//!
//! `oauth_token` and `refresh_token` are typed as [`serde::de::IgnoredAny`]:
//! serde confirms the keys exist and throws the values away, so no Cloudflare
//! token is ever held in memory beyond the parser's stack.

use serde::Deserialize;

use crate::paths::Paths;
use crate::probe::{unsupported_switch, unsupported_verify, Probe};
use crate::probes::cli_verify;
use crate::types::{
    Expiry, Note, PermissionsReport, Profile, SwitchOutcome, ToolStatus, VerifyOutcome,
};
use crate::util::{parse_timestamp, read_text};

pub struct WranglerProbe {
    paths: Paths,
}

#[derive(Deserialize)]
struct WranglerConfig {
    #[serde(default)]
    oauth_token: Option<serde::de::IgnoredAny>,
    #[serde(default)]
    refresh_token: Option<serde::de::IgnoredAny>,
    #[serde(default)]
    api_token: Option<serde::de::IgnoredAny>,
    #[serde(default)]
    expiration_time: Option<String>,
    #[serde(default)]
    scopes: Vec<String>,
}

impl WranglerProbe {
    pub const TOOL: &'static str = "wrangler";
    /// The single login wrangler supports, named so it has a stable id.
    const PROFILE_ID: &'static str = "default";

    pub fn new(paths: Paths) -> Self {
        Self { paths }
    }

    /// One sentence out of `wrangler whoami`'s several screens.
    ///
    /// The real output is a version banner, a progress line, an English
    /// sentence naming the token type and email, a box-drawn table of accounts,
    /// and a scope list — none of which belongs in a `detail` verbatim. What
    /// the user needs is the identity, so they can hold it against what the
    /// board claimed: the email, the token type, and the accounts it reaches.
    ///
    /// Every part is optional. Cloudflare has reworded this output before, and
    /// a reword must cost a thinner sentence, never a failed verify.
    fn describe_whoami(text: &str) -> String {
        let mut parts = Vec::new();
        if let Some(kind) = Self::token_kind(text) {
            parts.push(kind);
        }
        if let Some(email) = Self::email(text) {
            parts.push(format!("for {email}"));
        }
        let accounts = Self::accounts(text);
        if !accounts.is_empty() {
            parts.push(format!("on {}", accounts.join(", ")));
        }
        if parts.is_empty() {
            // Exit 0 means Cloudflare answered, so the token does work; only
            // the identity is missing. Saying so beats inventing either half.
            return "Cloudflare accepted the token, but patchbay could not read an account out of \
                    `wrangler whoami`"
                .to_string();
        }
        format!("Cloudflare accepted the {}", parts.join(" "))
    }

    /// `You are logged in with an OAuth Token, associated with the email x@y.`
    fn email(text: &str) -> Option<String> {
        let (_, rest) = text.split_once("associated with the email")?;
        let email = rest
            .split_whitespace()
            .next()?
            .trim_end_matches(['.', '!', ',', '"', '\''])
            .to_string();
        (!email.is_empty() && email.contains('@')).then_some(email)
    }

    /// "OAuth Token" / "API Token", lower-cased, from the same sentence.
    fn token_kind(text: &str) -> Option<String> {
        let lower = text.to_lowercase();
        if lower.contains("oauth token") {
            Some("OAuth token".to_string())
        } else if lower.contains("api token") {
            Some("API token".to_string())
        } else {
            None
        }
    }

    /// Account names out of the box-drawn `Account Name | Account ID` table.
    ///
    /// Parsed defensively: a row is a `│`-delimited line with exactly two
    /// non-empty cells, the header is dropped by name, and anything else is
    /// simply not a row. Account **ids** are read past and never reported —
    /// they are the noisy half and the sentence has no room for them.
    fn accounts(text: &str) -> Vec<String> {
        text.lines()
            .filter(|line| line.contains('│'))
            .filter_map(|line| {
                let cells: Vec<&str> = line
                    .split('│')
                    .map(str::trim)
                    .filter(|c| !c.is_empty())
                    .collect();
                match cells.as_slice() {
                    [name, _id] if *name != "Account Name" => Some((*name).to_string()),
                    _ => None,
                }
            })
            .collect()
    }
}

impl Probe for WranglerProbe {
    fn tool(&self) -> &'static str {
        Self::TOOL
    }

    fn status(&self) -> anyhow::Result<ToolStatus> {
        let candidates = self.paths.wrangler_candidates();
        let present: Vec<_> = candidates.iter().filter(|p| p.is_file()).collect();
        let installed = self.paths.has_binary("wrangler") || !present.is_empty();
        let mut status = ToolStatus::empty(Self::TOOL, installed);
        for note in self.paths.path_notes("wrangler") {
            status.push_note(note);
        }

        let Some(path) = present.first().copied() else {
            return Ok(status);
        };
        if present.len() > 1 {
            status.info(format!(
                "two wrangler configs exist; reading {} and ignoring {}",
                path.display(),
                present[1].display()
            ));
        }

        let text = match read_text(path) {
            Ok(Some(text)) => text,
            Ok(None) => return Ok(status),
            Err(e) => {
                status.problem(e);
                return Ok(status);
            }
        };

        let config: WranglerConfig = match toml::from_str(&text) {
            Ok(config) => config,
            Err(e) => {
                status.problem(format!("{} is not valid TOML ({e})", path.display()));
                return Ok(status);
            }
        };

        if config.oauth_token.is_none() && config.api_token.is_none() {
            status.info(format!(
                "{} exists but holds no token; wrangler is not logged in",
                path.display()
            ));
            return Ok(status);
        }

        let expires_at = config.expiration_time.as_deref().and_then(parse_timestamp);
        if config.expiration_time.is_some() && expires_at.is_none() {
            status.problem("expiration_time is present but could not be parsed".to_string());
        }
        let refreshable = config.refresh_token.is_some();

        // Only a grant wrangler cannot renew for you has a deadline a human has
        // to meet; see the module header. With nothing to renew it and no
        // timestamp either — an API token, normally — the deadline is the
        // dashboard's business and is not on this machine at all.
        let expiry = match (refreshable, expires_at) {
            (true, access_token_expires) => Expiry::Refreshable {
                access_token_expires,
            },
            (false, Some(at)) => Expiry::At(at),
            (false, None) => Expiry::unknown("in the Cloudflare dashboard"),
        };

        status.profiles.push(
            Profile::new(Self::PROFILE_ID)
                .label(if config.api_token.is_some() {
                    "cloudflare api token"
                } else {
                    "cloudflare oauth login"
                })
                .expiry(expiry)
                .with_meta(
                    "auth_type",
                    if config.api_token.is_some() {
                        "api_token"
                    } else {
                        "oauth"
                    },
                )
                .with_meta("scopes", config.scopes.clone())
                .with_meta("refreshable", refreshable)
                .with_meta("source", path.display().to_string()),
        );
        status.active = Some(Self::PROFILE_ID.to_string());

        Ok(status)
    }

    fn switch(&self, _profile_id: &str) -> anyhow::Result<SwitchOutcome> {
        Ok(unsupported_switch(
            Self::TOOL,
            "wrangler holds a single global login with no profile concept; re-authenticate to change accounts",
            Some("wrangler logout && wrangler login"),
        ))
    }

    fn verify(&self) -> anyhow::Result<VerifyOutcome> {
        if !self.paths.may_exec() || !self.paths.has_binary("wrangler") {
            return Ok(unsupported_verify(
                Self::TOOL,
                "the wrangler CLI is not available on PATH",
                Some("wrangler whoami"),
            ));
        }

        let out = self.paths.run("wrangler", &["whoami"])?;
        if !out.ok {
            return Ok(cli_verify::failure_outcome(
                Self::TOOL,
                &out,
                "Cloudflare",
                "wrangler login",
            ));
        }

        // wrangler puts the banner on stderr and the report on stdout, but
        // which half lands where has moved between majors; read both.
        let text = format!("{}\n{}", out.stdout, out.stderr);

        // Exit 0 is not the answer on its own: logged out, `wrangler whoami`
        // prints "You are not authenticated." and still succeeds.
        if cli_verify::says_logged_out(&text) {
            return Ok(VerifyOutcome::Invalid {
                tool: Self::TOOL.to_string(),
                detail: "not logged in — run `wrangler login`".to_string(),
            });
        }

        Ok(VerifyOutcome::Valid {
            tool: Self::TOOL.to_string(),
            detail: Self::describe_whoami(&text),
        })
    }

    fn permissions(&self) -> anyhow::Result<PermissionsReport> {
        let status = self.status()?;
        let Some(profile) = status.profiles.first() else {
            return Ok(PermissionsReport::unsupported(
                Self::TOOL,
                "wrangler is not logged in",
                Some("wrangler login"),
            ));
        };
        // Scopes come straight from the local grant — no network needed.
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
                .get("auth_type")
                .and_then(|v| v.as_str())
                .map(str::to_string),
            scopes,
            notes: vec![Note::info(
                "scopes are read from the local OAuth grant; account-level API token permissions are not visible here",
            )],
            hint: Some("re-run `wrangler login` to request a different scope set".to_string()),
            scope: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::NoteKind;
    use std::fs;
    use std::path::Path;

    const NEW_PATH: &str = "Library/Preferences/.wrangler/config/default.toml";
    const OLD_PATH: &str = ".wrangler/config/default.toml";

    fn write(home: &Path, rel: &str, body: &str) {
        let path = home.join(rel);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, body).unwrap();
    }

    // Invented token values: nothing here resembles a real Cloudflare grant.
    fn config(expiry: &str) -> String {
        format!(
            "oauth_token = \"fake-fixture-oauth\"\nexpiration_time = \"{expiry}\"\nrefresh_token = \"fake-fixture-refresh\"\nscopes = [ \"account:read\", \"workers:write\" ]\n"
        )
    }

    /// The same grant with nothing to renew it: then the deadline is real.
    fn config_without_refresh(expiry: &str) -> String {
        format!(
            "oauth_token = \"fake-fixture-oauth\"\nexpiration_time = \"{expiry}\"\nscopes = [ \"account:read\", \"workers:write\" ]\n"
        )
    }

    #[test]
    fn test_scopes_without_touching_the_token() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().to_path_buf();
        write(&home, NEW_PATH, &config("2030-03-13T10:24:29.685Z"));

        let status = WranglerProbe::new(Paths::for_test(&home)).status().unwrap();
        assert_eq!(status.active.as_deref(), Some("default"));
        assert_eq!(status.profiles.len(), 1);
        let profile = &status.profiles[0];
        assert_eq!(profile.meta["auth_type"], "oauth");
        assert_eq!(profile.meta["refreshable"], true);
        assert_eq!(profile.meta["scopes"][1], "workers:write");

        let json = serde_json::to_string(&status).unwrap();
        assert!(!json.contains("fake-fixture-oauth"), "{json}");
        assert!(!json.contains("fake-fixture-refresh"), "{json}");
    }

    #[test]
    fn test_new_location_wins_and_the_duplicate_is_reported() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().to_path_buf();
        write(
            &home,
            NEW_PATH,
            &config_without_refresh("2030-01-01T00:00:00Z"),
        );
        write(
            &home,
            OLD_PATH,
            &config_without_refresh("2029-01-01T00:00:00Z"),
        );

        let status = WranglerProbe::new(Paths::for_test(&home)).status().unwrap();
        assert_eq!(
            status.profiles[0].expires_at().unwrap().to_rfc3339(),
            "2030-01-01T00:00:00+00:00"
        );
        assert!(status
            .notes
            .iter()
            .any(|n| n.kind == NoteKind::Info && n.text.contains("two wrangler configs")));
    }

    #[test]
    fn test_legacy_location_is_used_when_it_is_the_only_one() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().to_path_buf();
        write(&home, OLD_PATH, &config("2030-01-01T00:00:00Z"));
        let status = WranglerProbe::new(Paths::for_test(&home)).status().unwrap();
        assert_eq!(status.profiles.len(), 1);
        assert!(status.profiles[0].meta["source"]
            .as_str()
            .unwrap()
            .ends_with(OLD_PATH));
    }

    #[test]
    fn test_a_renewable_grant_is_not_expired_however_old_its_access_token_is() {
        // The exact shape from a real machine: an `expiration_time` five months
        // past beside a refresh token, which the board reported as
        // "expired 154d" for a login `wrangler deploy` would have used fine.
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().to_path_buf();
        write(&home, NEW_PATH, &config("2020-01-01T00:00:00Z"));
        let status = WranglerProbe::new(Paths::for_test(&home)).status().unwrap();
        // The state says it outright now, and the stale hour rides along in it
        // rather than being reported as the login's deadline.
        assert_eq!(
            status.profiles[0].expiry,
            Expiry::Refreshable {
                access_token_expires: parse_timestamp("2020-01-01T00:00:00Z")
            }
        );
        assert!(status.profiles[0].expires_at().is_none());
        assert_eq!(
            status.connection_state(),
            crate::types::ConnectionState::Connected
        );
    }

    #[test]
    fn test_a_grant_with_nothing_to_renew_it_keeps_its_expiry() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().to_path_buf();
        write(
            &home,
            NEW_PATH,
            &config_without_refresh("2030-03-13T10:24:29.685Z"),
        );
        let status = WranglerProbe::new(Paths::for_test(&home)).status().unwrap();
        assert_eq!(status.profiles[0].meta["refreshable"], false);
        assert_eq!(
            status.profiles[0].expires_at().unwrap().to_rfc3339(),
            "2030-03-13T10:24:29.685+00:00"
        );
        assert!(matches!(status.profiles[0].expiry, Expiry::At(_)));
    }

    #[test]
    fn test_an_api_token_has_no_deadline_this_machine_can_see() {
        // No refresh token and no expiration_time: whatever expiry the token
        // has was set in the dashboard and is not written here.
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().to_path_buf();
        write(&home, NEW_PATH, "api_token = \"fake-fixture-api\"\n");
        let status = WranglerProbe::new(Paths::for_test(&home)).status().unwrap();
        assert_eq!(
            status.profiles[0].expiry,
            Expiry::unknown("in the Cloudflare dashboard")
        );
        assert!(status.profiles[0].expires_at().is_none());
    }

    #[test]
    fn test_missing_and_malformed() {
        let dir = tempfile::tempdir().unwrap();
        let status = WranglerProbe::new(Paths::for_test(dir.path()))
            .status()
            .unwrap();
        assert!(!status.installed);
        assert!(status.profiles.is_empty());

        let home = dir.path().to_path_buf();
        write(&home, NEW_PATH, "this is not = = toml [[[");
        let status = WranglerProbe::new(Paths::for_test(&home)).status().unwrap();
        assert!(status.installed);
        assert!(status.profiles.is_empty());
        assert!(status
            .notes
            .iter()
            .any(|n| n.kind == NoteKind::Problem && n.text.contains("not valid TOML")));
    }

    #[test]
    fn test_an_unparseable_expiration_time_is_a_problem() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().to_path_buf();
        write(&home, NEW_PATH, &config("the thirteenth of never"));
        let status = WranglerProbe::new(Paths::for_test(&home)).status().unwrap();
        assert!(status.notes.iter().any(|n| n.kind == NoteKind::Problem
            && n.text
                .contains("expiration_time is present but could not be parsed")));
        // Still refreshable, just with no access-token clock to report.
        assert_eq!(
            status.profiles[0].expiry,
            Expiry::Refreshable {
                access_token_expires: None
            }
        );
    }

    #[test]
    fn test_tokenless_config_is_not_a_login() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().to_path_buf();
        write(&home, NEW_PATH, "scopes = []\n");
        let status = WranglerProbe::new(Paths::for_test(&home)).status().unwrap();
        assert!(status.profiles.is_empty());
        assert!(status
            .notes
            .iter()
            .any(|n| n.text.contains("not logged in")));
    }

    // ---------------------------------------------------------------- verify

    /// verify never reads the filesystem, so the fixture home stays empty and
    /// only the scripted exec decides the answer.
    fn probe_with(
        exec: std::sync::Arc<crate::util::FakeExec>,
    ) -> (tempfile::TempDir, WranglerProbe) {
        let dir = tempfile::tempdir().unwrap();
        let probe = WranglerProbe::new(Paths::for_test(dir.path()).with_exec(exec));
        (dir, probe)
    }

    /// `wrangler whoami` on this machine, verbatim apart from the ids.
    const WHOAMI: &str = "\n ⛅️ wrangler 4.105.0\n\
        ───────────────────────────────\n\
        Getting User settings...\n\
        👋 You are logged in with an OAuth Token, associated with the email dev@example.com.\n\
        ┌──────────────┬──────────────────────────────────┐\n\
        │ Account Name │ Account ID                       │\n\
        ├──────────────┼──────────────────────────────────┤\n\
        │ Cerana       │ 00000000000000000000000000000001 │\n\
        ├──────────────┼──────────────────────────────────┤\n\
        │ Pathors      │ 00000000000000000000000000000002 │\n\
        └──────────────┴──────────────────────────────────┘\n\
        🔓 Token Permissions:\n\
        - account (read)\n";

    #[test]
    fn test_verify_reports_the_email_and_the_accounts_wrangler_names() {
        let exec = std::sync::Arc::new(crate::util::FakeExec::new().on("whoami", true, WHOAMI, ""));
        let (_dir, probe) = probe_with(exec.clone());
        let outcome = probe.verify().unwrap();
        assert_eq!(exec.last().unwrap().line(), "wrangler whoami");
        match outcome {
            VerifyOutcome::Valid { detail, .. } => {
                assert!(detail.contains("dev@example.com"), "{detail}");
                assert!(detail.contains("OAuth token"), "{detail}");
                assert!(
                    detail.contains("Cerana") && detail.contains("Pathors"),
                    "{detail}"
                );
                // The header row is not an account.
                assert!(!detail.contains("Account Name"), "{detail}");
                assert_eq!(detail.lines().count(), 1, "{detail}");
            }
            other => panic!("expected Valid, got {other:?}"),
        }
    }

    #[test]
    fn test_a_zero_exit_that_says_not_authenticated_is_not_a_working_login() {
        // The trap: `wrangler whoami` succeeds when logged out.
        let exec = std::sync::Arc::new(crate::util::FakeExec::new().on(
            "whoami",
            true,
            "You are not authenticated. Please run `wrangler login`.\n",
            "",
        ));
        let (_dir, probe) = probe_with(exec);
        match probe.verify().unwrap() {
            VerifyOutcome::Invalid { detail, .. } => {
                assert!(detail.contains("wrangler login"), "{detail}");
            }
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    #[test]
    fn test_a_rejected_token_and_an_outage_are_told_apart() {
        let rejected = std::sync::Arc::new(crate::util::FakeExec::new().on(
            "whoami",
            false,
            "",
            "✘ [ERROR] A request to the Cloudflare API failed.\n  Unable to authenticate request [code: 10000]\n",
        ));
        let (_dir, probe) = probe_with(rejected);
        match probe.verify().unwrap() {
            VerifyOutcome::Invalid { detail, .. } => {
                assert!(detail.contains("wrangler login"), "{detail}");
                assert_eq!(detail.lines().count(), 1, "{detail}");
            }
            other => panic!("expected Invalid, got {other:?}"),
        }

        let offline = std::sync::Arc::new(crate::util::FakeExec::new().on(
            "whoami",
            false,
            "",
            "✘ [ERROR] getaddrinfo ENOTFOUND api.cloudflare.com\n",
        ));
        let (_dir, probe) = probe_with(offline);
        match probe.verify().unwrap() {
            // An outage must never be filed as a dead login.
            VerifyOutcome::Unsupported { reason, .. } => {
                assert!(reason.contains("could not reach Cloudflare"), "{reason}");
            }
            other => panic!("expected Unsupported, got {other:?}"),
        }
    }

    #[test]
    fn test_unreadable_output_degrades_instead_of_panicking() {
        // Cloudflare rewords this output regularly; a reword costs a thinner
        // sentence, not a crash and not a false negative.
        for junk in ["", "\u{0}\u{1}│││", "┌─┐\n│ only one cell │\n└─┘"] {
            let exec =
                std::sync::Arc::new(crate::util::FakeExec::new().on("whoami", true, junk, ""));
            let (_dir, probe) = probe_with(exec);
            match probe.verify().unwrap() {
                VerifyOutcome::Valid { detail, .. } => {
                    assert!(detail.contains("could not read an account"), "{detail}");
                }
                other => panic!("expected Valid, got {other:?}"),
            }
        }

        // Same on the failure side: no message, still a sentence.
        let exec = std::sync::Arc::new(crate::util::FakeExec::new().on("whoami", false, "", ""));
        let (_dir, probe) = probe_with(exec);
        match probe.verify().unwrap() {
            VerifyOutcome::Invalid { detail, .. } => {
                assert!(detail.contains("without saying why"), "{detail}");
            }
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    #[test]
    fn test_verify_without_the_binary_stays_unsupported() {
        let dir = tempfile::tempdir().unwrap();
        match WranglerProbe::new(Paths::for_test(dir.path()))
            .verify()
            .unwrap()
        {
            VerifyOutcome::Unsupported { reason, hint, .. } => {
                assert!(reason.contains("not available on PATH"), "{reason}");
                assert_eq!(hint.as_deref(), Some("wrangler whoami"));
            }
            other => panic!("expected Unsupported, got {other:?}"),
        }
    }

    #[test]
    fn test_permissions_reads_scopes_from_the_local_grant() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().to_path_buf();
        write(&home, NEW_PATH, &config("2030-01-01T00:00:00Z"));
        let report = WranglerProbe::new(Paths::for_test(&home))
            .permissions()
            .unwrap();
        assert!(report.supported);
        assert_eq!(report.scopes, vec!["account:read", "workers:write"]);
    }
}
