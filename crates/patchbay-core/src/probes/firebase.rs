//! `firebase` — the Google login `firebase-tools` keeps in its configstore.
//!
//! Path and shape verified **empirically** on macOS at
//! `~/.config/configstore/firebase-tools.json` (the `configstore` npm package,
//! which is XDG-aware). The interesting keys:
//!
//! * `user` — the decoded id-token claims of the primary account. `email` is
//!   the only field patchbay takes.
//! * `tokens` — `{ expires_at (epoch **milliseconds**), refresh_token,
//!   access_token, scopes, scope, ... }`. `access_token` is never named at all;
//!   `refresh_token` is [`serde::de::IgnoredAny`], so its presence is known and
//!   its value is not. Only the expiry and the scope list are read.
//! * `additionalAccounts` — `[{ user, tokens }]` for `firebase login:add`.
//! * `activeProjects` — a project alias per working directory, which is why
//!   patchbay reports the *account*, not the project, as the profile.
//!
//! `tokens.expires_at` dates an hour-long OAuth access token, not the login:
//! where a `refresh_token` sits beside it, firebase-tools mints a new one
//! silently on the next command. Every ordinary login is therefore
//! [`Expiry::Refreshable`], which carries that hourly clock without letting it
//! count as a deadline — what ends the session is the refresh token being
//! revoked, and nothing here records when that happens. Only a grant with no
//! refresh token gets [`Expiry::At`], because then the hour really is the whole
//! login. The alternative is a board that says "expired 235d" about an account
//! you used this morning.

use serde::Deserialize;

use crate::paths::Paths;
use crate::probe::{unsupported_switch, unsupported_verify, Probe};
use crate::probes::cli_verify;
use crate::types::{
    Expiry, Note, PermissionsReport, Profile, SwitchOutcome, ToolStatus, VerifyOutcome,
};
use crate::util::{parse_epoch_millis, read_text};

pub struct FirebaseProbe {
    paths: Paths,
}

#[derive(Deserialize, Default)]
struct Store {
    #[serde(default)]
    user: Option<User>,
    #[serde(default)]
    tokens: Option<Tokens>,
    #[serde(default, rename = "additionalAccounts")]
    additional_accounts: Vec<Account>,
    #[serde(default, rename = "activeProjects")]
    active_projects: std::collections::BTreeMap<String, String>,
}

#[derive(Deserialize)]
struct Account {
    #[serde(default)]
    user: Option<User>,
    #[serde(default)]
    tokens: Option<Tokens>,
}

#[derive(Deserialize)]
struct User {
    #[serde(default)]
    email: Option<String>,
}

/// `access_token` and `id_token` are deliberately absent from this struct: what
/// serde never names, it never holds. `refresh_token` is named but typed
/// [`serde::de::IgnoredAny`], which is the same guarantee — the field records
/// only that a refresh token is *there*, which is what decides whether the
/// hour-long access token expiry means anything.
#[derive(Deserialize)]
struct Tokens {
    #[serde(default)]
    expires_at: Option<i64>,
    #[serde(default)]
    refresh_token: Option<serde::de::IgnoredAny>,
    #[serde(default)]
    scopes: Vec<String>,
}

impl Tokens {
    fn refreshable(&self) -> bool {
        self.refresh_token.is_some()
    }
}

impl FirebaseProbe {
    pub const TOOL: &'static str = "firebase";

    pub fn new(paths: Paths) -> Self {
        Self { paths }
    }

    /// What a `login:list` answer is and — just as importantly — is not. The
    /// caveat travels with every success detail rather than being left for the
    /// user to infer from a green tick.
    const CHECK_CAVEAT: &'static str =
        "firebase-tools names the account it will use (`login:list` reads the local store, so it \
         does not prove Google still accepts the grant)";

    /// `firebase login:list`, reduced to the email addresses it names.
    ///
    /// `Ok(Err(outcome))` is the "already answered" case — no binary, or the
    /// CLI failed — so callers can return it unchanged.
    ///
    /// **Why not `--json`.** `firebase login:list --json` does answer, and its
    /// answer embeds the live `access_token` and `refresh_token` of every
    /// account. Parsing it would put Google refresh tokens in patchbay's memory
    /// and one careless error path away from a log line. The plain text prints
    /// email addresses and nothing else, so the text is what gets parsed.
    fn login_list(&self) -> anyhow::Result<Result<Vec<String>, VerifyOutcome>> {
        if !self.paths.may_exec() || !self.paths.has_binary("firebase") {
            return Ok(Err(unsupported_verify(
                Self::TOOL,
                "the firebase CLI is not available on PATH",
                Some("firebase login:list"),
            )));
        }
        // `--non-interactive` is belt and braces: login:list never prompts, but
        // a future firebase-tools that decides to must fail rather than block a
        // spinner forever.
        let out = self
            .paths
            .run("firebase", &["login:list", "--non-interactive"])?;
        if !out.ok {
            return Ok(Err(cli_verify::failure_outcome(
                Self::TOOL,
                &out,
                "firebase-tools",
                "firebase login",
            )));
        }
        Ok(Ok(Self::parse_login_list(&out.stdout)))
    }

    /// The emails out of `login:list`, primary first.
    ///
    /// The real output is `Logged in as a@b.com`, optionally followed by an
    /// `Other accounts:` block of indented addresses. Rather than depend on
    /// that layout surviving, this takes every `@`-shaped word in order and
    /// de-duplicates — `Logged in as` is simply where the first one appears.
    fn parse_login_list(stdout: &str) -> Vec<String> {
        let mut emails: Vec<String> = Vec::new();
        for word in stdout.split_whitespace() {
            let candidate = word.trim_matches(|c: char| !c.is_ascii_graphic() || c == ',');
            let is_email = candidate.contains('@')
                && !candidate.starts_with('@')
                && !candidate.ends_with('@')
                && candidate.contains('.');
            if is_email && !emails.iter().any(|e| e == candidate) {
                emails.push(candidate.to_string());
            }
        }
        emails
    }

    fn profile(email: &str, tokens: Option<&Tokens>) -> Profile {
        // The hour is only the truth for a grant that cannot refresh itself.
        let refreshable = tokens.is_some_and(Tokens::refreshable);
        let access_token_expires = tokens
            .and_then(|t| t.expires_at)
            .and_then(parse_epoch_millis);
        let expiry = match (refreshable, access_token_expires) {
            (true, access_token_expires) => Expiry::Refreshable {
                access_token_expires,
            },
            (false, Some(at)) => Expiry::At(at),
            (false, None) => Expiry::unknown("not recorded in the firebase-tools configstore"),
        };
        Profile::new(email)
            .expiry(expiry)
            .with_meta(
                "scopes",
                tokens.map(|t| t.scopes.clone()).unwrap_or_default(),
            )
            .with_meta("refreshable", refreshable)
            .with_meta("auth", "google oauth")
    }
}

impl Probe for FirebaseProbe {
    fn tool(&self) -> &'static str {
        Self::TOOL
    }

    fn status(&self) -> anyhow::Result<ToolStatus> {
        let path = self.paths.firebase_config();
        let installed = self.paths.has_binary("firebase") || path.is_file();
        let mut status = ToolStatus::empty(Self::TOOL, installed);
        for note in self.paths.path_notes("firebase") {
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

        let store: Store = match serde_json::from_str(&text) {
            Ok(store) => store,
            Err(e) => {
                status.problem(format!("firebase-tools.json is not valid JSON ({e})"));
                return Ok(status);
            }
        };

        if let Some(email) = store.user.as_ref().and_then(|u| u.email.clone()) {
            status
                .profiles
                .push(Self::profile(&email, store.tokens.as_ref()).with_meta("primary", true));
            status.active = Some(email);
        }
        for account in &store.additional_accounts {
            let Some(email) = account.user.as_ref().and_then(|u| u.email.clone()) else {
                continue;
            };
            if status.profiles.iter().any(|p| p.id == email) {
                continue;
            }
            status
                .profiles
                .push(Self::profile(&email, account.tokens.as_ref()).with_meta("primary", false));
        }

        if status.profiles.is_empty() {
            if !store.active_projects.is_empty() {
                status.info(
                    "firebase-tools has project aliases on this machine but no logged-in account",
                );
            }
            return Ok(status);
        }

        if !store.active_projects.is_empty() {
            status.info(format!(
                "the active Firebase project is per-directory ({} recorded); the profile above is \
                 the account, not the project",
                store.active_projects.len()
            ));
        }
        if !store.additional_accounts.is_empty() {
            status.info(
                "extra accounts from `firebase login:add` are selected per command with \
                 `--account`, not globally",
            );
        }

        Ok(status)
    }

    fn switch(&self, _profile_id: &str) -> anyhow::Result<SwitchOutcome> {
        // firebase-tools has no global account switch: `--account` is a
        // per-invocation flag, and `firebase login` is interactive.
        Ok(unsupported_switch(
            Self::TOOL,
            "firebase-tools selects an account per command rather than globally",
            Some("firebase --account <email> <command>"),
        ))
    }

    fn verify(&self) -> anyhow::Result<VerifyOutcome> {
        let accounts = match self.login_list()? {
            Ok(accounts) => accounts,
            Err(outcome) => return Ok(outcome),
        };
        let Some((primary, others)) = accounts.split_first() else {
            return Ok(VerifyOutcome::Invalid {
                tool: Self::TOOL.to_string(),
                detail: "firebase-tools holds no account — run `firebase login`".to_string(),
            });
        };
        let also = if others.is_empty() {
            String::new()
        } else {
            format!(" (also {})", others.join(", "))
        };
        Ok(VerifyOutcome::Valid {
            tool: Self::TOOL.to_string(),
            detail: format!("{}: {primary}{also}", Self::CHECK_CAVEAT),
        })
    }

    /// One named account, checked against the list the CLI itself keeps.
    ///
    /// firebase-tools has no global active account — `--account` picks one per
    /// command — so the question worth answering per profile is whether the CLI
    /// still holds a login for that address at all.
    fn verify_profile(&self, profile_id: &str) -> anyhow::Result<VerifyOutcome> {
        let accounts = match self.login_list()? {
            Ok(accounts) => accounts,
            Err(outcome) => return Ok(outcome),
        };
        Ok(
            if accounts.iter().any(|a| a.eq_ignore_ascii_case(profile_id)) {
                VerifyOutcome::Valid {
                    tool: Self::TOOL.to_string(),
                    detail: format!("{}: {profile_id}", Self::CHECK_CAVEAT),
                }
            } else {
                VerifyOutcome::Invalid {
                    tool: Self::TOOL.to_string(),
                    detail: format!(
                        "firebase-tools holds no login for {profile_id} — run `firebase login:add`"
                    ),
                }
            },
        )
    }

    fn permissions(&self) -> anyhow::Result<PermissionsReport> {
        let status = self.status()?;
        let Some(profile) = status
            .active
            .as_ref()
            .and_then(|id| status.profiles.iter().find(|p| &p.id == id))
        else {
            return Ok(PermissionsReport::unsupported(
                Self::TOOL,
                "firebase-tools is not logged in",
                Some("firebase login"),
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
            subject: Some(profile.id.clone()),
            scopes,
            notes: vec![Note::info(
                "these are the OAuth scopes of the local grant; what you may actually do is \
                 decided by the account's IAM roles on each Firebase project",
            )],
            hint: Some("firebase login --reauth".to_string()),
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
        fs::create_dir_all(home.join(".config/configstore")).unwrap();
        fs::write(home.join(".config/configstore/firebase-tools.json"), body).unwrap();
        (dir, home)
    }

    // Shape mirrors a real store; every token value is invented.
    const STORE: &str = r#"{
      "user": { "email": "dev@example.com", "sub": "1015", "email_verified": true },
      "tokens": {
        "expires_at": 1766355597325,
        "refresh_token": "fake-fixture-refresh",
        "access_token": "fake-fixture-access",
        "id_token": "fake-fixture-id",
        "scopes": ["email", "https://www.googleapis.com/auth/cloud-platform"]
      },
      "additionalAccounts": [
        { "user": { "email": "ops@example.com" }, "tokens": { "expires_at": 1766355597325, "access_token": "fake-fixture-second", "refresh_token": "fake-fixture-second-refresh" } }
      ],
      "activeProjects": { "/work/app": "app-prod", "/work/site": "site-dev" }
    }"#;

    #[test]
    fn test_primary_and_additional_accounts() {
        let (_dir, home) = fixture(STORE);
        let status = FirebaseProbe::new(Paths::for_test(&home)).status().unwrap();
        let ids: Vec<_> = status.profiles.iter().map(|p| p.id.as_str()).collect();
        assert_eq!(ids, vec!["dev@example.com", "ops@example.com"]);
        assert_eq!(status.active.as_deref(), Some("dev@example.com"));
        assert_eq!(status.profiles[0].meta["primary"], true);
        assert_eq!(status.profiles[0].meta["scopes"][0], "email");
        assert!(status
            .notes
            .iter()
            .any(|n| n.kind == NoteKind::Info && n.text.contains("per-directory")));
        assert!(status
            .notes
            .iter()
            .any(|n| n.kind == NoteKind::Info && n.text.contains("--account")));
        // Nothing here is worth alarming anyone about.
        assert_eq!(status.alarming_notes().count(), 0);
    }

    #[test]
    fn test_an_hourly_token_beside_a_refresh_token_is_not_the_logins_expiry() {
        // `expires_at` in STORE is 2025-12-21 — long past, and reported as the
        // profile's expiry it put a working account on the board as "expired
        // 235d" and counted it among the tool's dead logins.
        let (_dir, home) = fixture(STORE);
        let status = FirebaseProbe::new(Paths::for_test(&home)).status().unwrap();
        assert!(status.profiles.iter().all(|p| p.expires_at().is_none()));
        // The state carries the hour it really has; nothing reads it as a
        // deadline.
        assert!(status.profiles.iter().all(|p| p.expiry
            == Expiry::Refreshable {
                access_token_expires: parse_epoch_millis(1766355597325)
            }));
        assert!(status
            .profiles
            .iter()
            .all(|p| p.meta["refreshable"] == true));
        assert_eq!(
            status.connection_state(),
            crate::types::ConnectionState::Connected
        );
    }

    #[test]
    fn test_a_grant_with_no_refresh_token_keeps_the_hour_it_really_has() {
        let (_dir, home) = fixture(
            r#"{ "user": { "email": "dev@example.com" },
                 "tokens": { "expires_at": 1766355597325, "access_token": "fake-fixture-access" } }"#,
        );
        let status = FirebaseProbe::new(Paths::for_test(&home)).status().unwrap();
        assert_eq!(status.profiles[0].meta["refreshable"], false);
        // epoch milliseconds, not seconds.
        assert_eq!(
            status.profiles[0].expires_at().unwrap().to_rfc3339(),
            "2025-12-21T22:19:57.325+00:00"
        );
        assert!(matches!(status.profiles[0].expiry, Expiry::At(_)));
    }

    #[test]
    fn test_an_account_with_no_tokens_at_all_has_an_unknown_expiry() {
        let (_dir, home) = fixture(r#"{ "user": { "email": "dev@example.com" } }"#);
        let status = FirebaseProbe::new(Paths::for_test(&home)).status().unwrap();
        assert_eq!(
            status.profiles[0].expiry,
            Expiry::unknown("not recorded in the firebase-tools configstore")
        );
    }

    #[test]
    fn test_no_token_material_reaches_the_output() {
        let (_dir, home) = fixture(STORE);
        let status = FirebaseProbe::new(Paths::for_test(&home)).status().unwrap();
        let json = serde_json::to_string(&status).unwrap();
        for secret in [
            "fake-fixture-refresh",
            "fake-fixture-access",
            "fake-fixture-id",
            "fake-fixture-second",
        ] {
            assert!(!json.contains(secret), "leaked {secret}");
        }
    }

    #[test]
    fn test_projects_without_a_login() {
        let (_dir, home) = fixture(r#"{ "activeProjects": { "/work/app": "app-prod" } }"#);
        let status = FirebaseProbe::new(Paths::for_test(&home)).status().unwrap();
        assert!(status.installed);
        assert!(status.profiles.is_empty());
        assert!(status
            .notes
            .iter()
            .any(|n| n.kind == NoteKind::Info && n.text.contains("no logged-in account")));
    }

    #[test]
    fn test_missing_and_malformed() {
        let dir = tempfile::tempdir().unwrap();
        let status = FirebaseProbe::new(Paths::for_test(dir.path()))
            .status()
            .unwrap();
        assert!(!status.installed);
        assert!(status.profiles.is_empty());

        let (_dir, home) = fixture("{ \"user\": ");
        let status = FirebaseProbe::new(Paths::for_test(&home)).status().unwrap();
        assert!(status.installed);
        assert!(status
            .notes
            .iter()
            .any(|n| n.kind == NoteKind::Problem && n.text.contains("not valid JSON")));
    }

    // ---------------------------------------------------------------- verify

    fn probe_with(
        home: &std::path::Path,
        exec: std::sync::Arc<crate::util::FakeExec>,
    ) -> FirebaseProbe {
        FirebaseProbe::new(Paths::for_test(home).with_exec(exec))
    }

    #[test]
    fn test_verify_reports_the_accounts_the_cli_itself_lists() {
        let (_dir, home) = fixture(STORE);
        let exec = std::sync::Arc::new(crate::util::FakeExec::new().on(
            "login:list",
            true,
            "Logged in as dev@example.com\n\nOther accounts:\n  ops@example.com\n",
            "",
        ));
        let outcome = probe_with(&home, exec.clone()).verify().unwrap();
        assert_eq!(
            exec.last().unwrap().line(),
            "firebase login:list --non-interactive"
        );
        match outcome {
            VerifyOutcome::Valid { detail, .. } => {
                assert!(detail.contains("dev@example.com"), "{detail}");
                assert!(detail.contains("ops@example.com"), "{detail}");
                // The caveat travels with the tick: this is a local read.
                assert!(detail.contains("local store"), "{detail}");
                assert_eq!(detail.lines().count(), 1, "{detail}");
            }
            other => panic!("expected Valid, got {other:?}"),
        }
    }

    #[test]
    fn test_verify_profile_answers_for_the_account_it_was_asked_about() {
        let (_dir, home) = fixture(STORE);
        let listing = "Logged in as dev@example.com\n\nOther accounts:\n  ops@example.com\n";
        let exec =
            std::sync::Arc::new(crate::util::FakeExec::new().on("login:list", true, listing, ""));
        let probe = probe_with(&home, exec);
        assert!(matches!(
            probe.verify_profile("ops@example.com").unwrap(),
            VerifyOutcome::Valid { .. }
        ));
        match probe.verify_profile("stranger@example.com").unwrap() {
            VerifyOutcome::Invalid { detail, .. } => {
                assert!(detail.contains("firebase login:add"), "{detail}");
            }
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    #[test]
    fn test_an_empty_listing_is_a_logged_out_answer() {
        let (_dir, home) = fixture(STORE);
        let exec = std::sync::Arc::new(crate::util::FakeExec::new().on(
            "login:list",
            true,
            "No accounts to list\n",
            "",
        ));
        match probe_with(&home, exec).verify().unwrap() {
            VerifyOutcome::Invalid { detail, .. } => {
                assert!(detail.contains("firebase login"), "{detail}");
            }
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    #[test]
    fn test_a_failing_cli_becomes_one_sentence_not_a_stack_trace() {
        let (_dir, home) = fixture(STORE);
        let exec = std::sync::Arc::new(crate::util::FakeExec::new().on(
            "login:list",
            false,
            "",
            "Error: Failed to authenticate, have you run firebase login?\n    at requireAuth (/usr/lib/node_modules/firebase-tools/lib/requireAuth.js:52:11)\n    at async Command.prepare\n",
        ));
        match probe_with(&home, exec).verify().unwrap() {
            VerifyOutcome::Invalid { detail, .. } => {
                assert!(detail.contains("firebase login"), "{detail}");
                // Not a paste of somebody else's stack.
                assert!(!detail.contains("at requireAuth"), "{detail}");
                assert_eq!(detail.lines().count(), 1, "{detail}");
            }
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    #[test]
    fn test_unreadable_output_degrades_instead_of_panicking() {
        let (_dir, home) = fixture(STORE);
        for junk in ["", "@\n@@\n", "Logged in as\n", "\u{0}\u{1}\u{2}"] {
            let exec =
                std::sync::Arc::new(crate::util::FakeExec::new().on("login:list", true, junk, ""));
            match probe_with(&home, exec).verify().unwrap() {
                VerifyOutcome::Invalid { detail, .. } => {
                    assert!(detail.contains("firebase login"), "{junk:?} -> {detail}");
                }
                other => panic!("expected Invalid for {junk:?}, got {other:?}"),
            }
        }
    }

    #[test]
    fn test_verify_without_the_binary_stays_unsupported() {
        let (_dir, home) = fixture(STORE);
        match FirebaseProbe::new(Paths::for_test(&home)).verify().unwrap() {
            VerifyOutcome::Unsupported { reason, hint, .. } => {
                assert!(reason.contains("not available on PATH"), "{reason}");
                assert_eq!(hint.as_deref(), Some("firebase login:list"));
            }
            other => panic!("expected Unsupported, got {other:?}"),
        }
    }

    #[test]
    fn test_permissions_reports_the_local_grant() {
        let (_dir, home) = fixture(STORE);
        let report = FirebaseProbe::new(Paths::for_test(&home))
            .permissions()
            .unwrap();
        assert!(report.supported);
        assert_eq!(report.subject.as_deref(), Some("dev@example.com"));
        assert_eq!(report.scopes.len(), 2);

        let dir = tempfile::tempdir().unwrap();
        let report = FirebaseProbe::new(Paths::for_test(dir.path()))
            .permissions()
            .unwrap();
        assert!(!report.supported);
    }
}
