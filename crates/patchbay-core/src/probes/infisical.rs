//! `infisical` — logged-in users in `~/.infisical/infisical-config.json`.
//!
//! The JWT itself lives in the configured vault backend (keychain or an
//! encrypted file), not in this config, so every profile's expiry is
//! [`crate::types::Expiry::Unknown`] naming that backend. The config
//! also holds a `vaultBackendPassphrase`; the struct below deliberately has no
//! field for it, so it is dropped during parsing and can never reach a caller.
//!
//! **Switching.** `infisical user switch` is an arrow-key picker with no
//! non-interactive form, so patchbay writes the config itself. All the picker
//! does is repoint two fields — `loggedInUserEmail`, and `LoggedInUserDomain`
//! to the matching entry's domain — at one of the `loggedInUsers` already in
//! the file. No credential moves: every user's JWT stays where it was, in the
//! vault backend.
//!
//! The write goes through [`crate::util`]'s backup-and-atomic-rename machinery
//! and edits a parsed [`serde_json::Value`], never a re-serialized [`Config`].
//! That is not a stylistic choice: this file holds `vaultBackendPassphrase`,
//! and rendering the typed struct back out would silently delete it and lock
//! the user out of their own vault.

use serde::Deserialize;
use serde_json::Value;

use crate::paths::Paths;
use crate::probe::{unknown_profile, unsupported_verify, Probe};
use crate::types::{Expiry, PermissionsReport, Profile, SwitchOutcome, ToolStatus, VerifyOutcome};
use crate::util::{backup, read_text, serialize_json_preserving_style, write_atomic};

pub struct InfisicalProbe {
    paths: Paths,
}

#[derive(Deserialize)]
struct Config {
    #[serde(default, rename = "loggedInUserEmail")]
    logged_in_user_email: Option<String>,
    #[serde(default, rename = "LoggedInUserDomain")]
    logged_in_user_domain: Option<String>,
    #[serde(default, rename = "loggedInUsers")]
    logged_in_users: Vec<LoggedInUser>,
    #[serde(default, rename = "vaultBackendType")]
    vault_backend_type: Option<String>,
}

#[derive(Deserialize)]
struct LoggedInUser {
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    domain: Option<String>,
}

/// The account the `infisical` CLI would act as right now, or `None` when
/// nobody is logged in on this machine.
///
/// Machine-global state, and the reason [`crate::env_sync`] needs it: an
/// `infisical export` runs as whoever this says, not as whoever the caller had
/// in mind. A missing config is a normal "never logged in" answer, not an
/// error; a *malformed* one is an error, because guessing would be worse.
pub fn active_account(paths: &Paths) -> anyhow::Result<Option<String>> {
    let path = paths.infisical_config();
    let Some(text) = read_text(&path).map_err(anyhow::Error::msg)? else {
        return Ok(None);
    };
    let config: Config = serde_json::from_str(&text)
        .map_err(|e| anyhow::anyhow!("{} is not valid JSON ({e})", path.display()))?;
    Ok(config
        .logged_in_user_email
        .filter(|email| !email.trim().is_empty()))
}

impl InfisicalProbe {
    pub const TOOL: &'static str = "infisical";
    /// The field naming the active account.
    const ACTIVE_EMAIL: &'static str = "loggedInUserEmail";
    /// Its domain. Capitalised differently from every neighbouring key — that
    /// is Infisical's spelling, not a typo, and it has to be matched exactly.
    const ACTIVE_DOMAIN: &'static str = "LoggedInUserDomain";
    const USERS: &'static str = "loggedInUsers";

    pub fn new(paths: Paths) -> Self {
        Self { paths }
    }

    /// `(email, domain)` for every entry in `loggedInUsers`, in file order.
    /// This list — not the profile list on the status — is what a switch is
    /// allowed to target: the status also synthesises a profile for an active
    /// account missing from the array, and switching to one of those would
    /// write a pointer to a user whose JWT was never stored.
    fn logged_in_users(config: &Value) -> Vec<(String, Option<String>)> {
        config
            .get(Self::USERS)
            .and_then(Value::as_array)
            .map(|users| {
                users
                    .iter()
                    .filter_map(|user| {
                        let email = user.get("email")?.as_str()?.to_string();
                        let domain = user
                            .get("domain")
                            .and_then(Value::as_str)
                            .map(|d| d.to_string());
                        Some((email, domain))
                    })
                    .collect()
            })
            .unwrap_or_default()
    }
}

impl Probe for InfisicalProbe {
    fn tool(&self) -> &'static str {
        Self::TOOL
    }

    fn status(&self) -> anyhow::Result<ToolStatus> {
        let path = self.paths.infisical_config();
        let installed = self.paths.has_binary("infisical") || path.is_file();
        let mut status = ToolStatus::empty(Self::TOOL, installed);
        for note in self.paths.path_notes("infisical") {
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

        let config: Config = match serde_json::from_str(&text) {
            Ok(config) => config,
            Err(e) => {
                status.problem(format!("infisical-config.json is not valid JSON ({e})"));
                return Ok(status);
            }
        };

        // The JWT — and with it the only copy of its deadline — lives in the
        // vault backend the config names, which patchbay does not open.
        let expiry = Expiry::unknown(format!(
            "in the {} vault backend",
            config.vault_backend_type.as_deref().unwrap_or("configured")
        ));

        for user in &config.logged_in_users {
            let Some(email) = &user.email else { continue };
            status.profiles.push(
                Profile::new(email)
                    .expiry(expiry.clone())
                    .with_meta("domain", user.domain.clone())
                    .with_meta("vault_backend", config.vault_backend_type.clone()),
            );
        }

        if let Some(active) = &config.logged_in_user_email {
            if !status.profiles.iter().any(|p| &p.id == active) {
                // The active account is not always mirrored into the list.
                status.profiles.push(
                    Profile::new(active)
                        .expiry(expiry.clone())
                        .with_meta("domain", config.logged_in_user_domain.clone())
                        .with_meta("vault_backend", config.vault_backend_type.clone()),
                );
            }
            status.active = Some(active.clone());
        }

        Ok(status)
    }

    /// Repoint the config at another logged-in user, the way the picker would.
    fn switch(&self, profile_id: &str) -> anyhow::Result<SwitchOutcome> {
        let path = self.paths.infisical_config();
        let Some(text) = read_text(&path).map_err(anyhow::Error::msg)? else {
            return Ok(SwitchOutcome::Failed {
                tool: Self::TOOL.to_string(),
                profile_id: profile_id.to_string(),
                detail: format!(
                    "{} does not exist; log in with `infisical login` first",
                    path.display()
                ),
            });
        };
        let mut config: Value = serde_json::from_str(&text).map_err(|e| {
            anyhow::anyhow!(
                "{} is not valid JSON ({e}); refusing to rewrite it",
                path.display()
            )
        })?;
        if !config.is_object() {
            anyhow::bail!(
                "{} is not a JSON object; refusing to rewrite it",
                path.display()
            );
        }

        let users = Self::logged_in_users(&config);
        let Some((email, domain)) = users.iter().find(|(email, _)| email == profile_id) else {
            // Not in `loggedInUsers`, so there is no stored login to switch to.
            // Reported through the status so the caller gets the same shape and
            // the same available-ids list as every other probe.
            let mut status = self.status()?;
            status
                .profiles
                .retain(|p| users.iter().any(|(e, _)| e == &p.id));
            return Ok(unknown_profile(Self::TOOL, profile_id, &status));
        };

        let already_active = config
            .get(Self::ACTIVE_EMAIL)
            .and_then(Value::as_str)
            .is_some_and(|active| active == email);

        let mut notes = Vec::new();
        let object = config.as_object_mut().expect("checked above");
        object.insert(Self::ACTIVE_EMAIL.to_string(), Value::String(email.clone()));
        match domain {
            Some(domain) => {
                object.insert(
                    Self::ACTIVE_DOMAIN.to_string(),
                    Value::String(domain.clone()),
                );
            }
            // No domain on the entry: leave the existing pointer alone rather
            // than blanking it, and say so.
            None => notes.push(format!(
                "`{email}` has no domain recorded in {}, so {} was left as it was",
                Self::USERS,
                Self::ACTIVE_DOMAIN
            )),
        }

        // Written back in the shape the file already had — the Infisical CLI
        // writes one compact line, and reformatting it would turn a two-field
        // edit into a whole-file diff.
        let body = serialize_json_preserving_style(&config, Some(&text));
        let backup_path = backup(&path)?;
        write_atomic(&path, &body)?;

        // Verification without a subprocess: `infisical user` is a picker like
        // `user switch`, and `login status` can prompt for the vault passphrase
        // on the file backend — neither is safe to drive from here. Re-reading
        // the file confirms the part patchbay is actually responsible for.
        match read_text(&path).map_err(anyhow::Error::msg)? {
            Some(written) => {
                let back: Value = serde_json::from_str(&written).map_err(|e| {
                    anyhow::anyhow!("wrote {} but could not read it back ({e})", path.display())
                })?;
                let landed = back.get(Self::ACTIVE_EMAIL).and_then(Value::as_str);
                if landed != Some(email.as_str()) {
                    anyhow::bail!(
                        "wrote {} but it still reports `{}` as the active user",
                        path.display(),
                        landed.unwrap_or("nothing")
                    );
                }
            }
            None => anyhow::bail!("wrote {} but it is no longer readable", path.display()),
        }

        if already_active {
            notes.push(format!("`{email}` was already the active user"));
        }
        notes.push(
            "switched; run `infisical login status` to confirm the JWT for this user is still \
             valid — patchbay repoints the config, it cannot renew a login"
                .to_string(),
        );
        if let Some(saved) = &backup_path {
            notes.push(format!("previous config saved to {}", saved.display()));
        }

        Ok(SwitchOutcome::Switched {
            tool: Self::TOOL.to_string(),
            profile_id: email.clone(),
            detail: format!(
                "set {} to `{email}` in {}",
                Self::ACTIVE_EMAIL,
                path.display()
            ),
            notes,
        })
    }

    fn verify(&self) -> anyhow::Result<VerifyOutcome> {
        if !self.paths.may_exec() || !self.paths.has_binary("infisical") {
            return Ok(unsupported_verify(
                Self::TOOL,
                "the infisical CLI is not available on PATH",
                Some("infisical login status"),
            ));
        }
        let out = self.paths.run("infisical", &["login", "status"])?;
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
            "Infisical permissions are per-project roles held server-side; patchbay does not query the API",
            Some("check the member's role in the Infisical project settings"),
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
        fs::create_dir_all(home.join(".infisical")).unwrap();
        fs::write(home.join(".infisical/infisical-config.json"), body).unwrap();
        (dir, home)
    }

    #[test]
    fn test_users_and_active_email() {
        let (_dir, home) = fixture(
            r#"{"loggedInUserEmail":"b@example.com","LoggedInUserDomain":"https://app.infisical.com/api","loggedInUsers":[{"email":"a@example.com","domain":"https://app.infisical.com/api"},{"email":"b@example.com","domain":"https://eu.infisical.com/api"}],"vaultBackendType":"file","vaultBackendPassphrase":"ZmFrZS1maXh0dXJl"}"#,
        );
        let status = InfisicalProbe::new(Paths::for_test(&home))
            .status()
            .unwrap();
        let ids: Vec<_> = status.profiles.iter().map(|p| p.id.as_str()).collect();
        assert_eq!(ids, vec!["a@example.com", "b@example.com"]);
        assert_eq!(status.active.as_deref(), Some("b@example.com"));
        assert_eq!(
            status.profiles[1].meta["domain"],
            "https://eu.infisical.com/api"
        );
        // The paragraph that used to say this is now the expiry state, and it
        // names the backend the JWT actually went into.
        assert!(status
            .profiles
            .iter()
            .all(|p| p.expiry == Expiry::unknown("in the file vault backend")
                && p.expires_at().is_none()));
        assert!(!status
            .notes
            .iter()
            .any(|n| n.text.contains("vault backend")));

        // The vault passphrase must never survive parsing.
        let json = serde_json::to_string(&status).unwrap();
        assert!(!json.contains("ZmFrZS1maXh0dXJl"), "{json}");
        assert!(!json.to_lowercase().contains("passphrase"), "{json}");
    }

    #[test]
    fn test_active_account_reads_the_machine_global_login() {
        let (_dir, home) = fixture(
            r#"{"loggedInUserEmail":"b@example.com","loggedInUsers":[{"email":"a@example.com"},{"email":"b@example.com"}],"vaultBackendPassphrase":"ZmFrZQ=="}"#,
        );
        assert_eq!(
            active_account(&Paths::for_test(&home)).unwrap().as_deref(),
            Some("b@example.com")
        );

        // Never logged in: no file, or a file with no active account.
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(active_account(&Paths::for_test(dir.path())).unwrap(), None);
        let (_dir, home) = fixture(r#"{"loggedInUsers":[]}"#);
        assert_eq!(active_account(&Paths::for_test(&home)).unwrap(), None);

        // Unreadable is an error, not a silent "logged out".
        let (_dir, home) = fixture("{ this is not json");
        let err = active_account(&Paths::for_test(&home))
            .unwrap_err()
            .to_string();
        assert!(err.contains("not valid JSON"), "{err}");
    }

    #[test]
    fn test_active_user_missing_from_the_list_is_still_a_profile() {
        let (_dir, home) =
            fixture(r#"{"loggedInUserEmail":"solo@example.com","loggedInUsers":[]}"#);
        let status = InfisicalProbe::new(Paths::for_test(&home))
            .status()
            .unwrap();
        assert_eq!(status.profiles.len(), 1);
        assert_eq!(status.active.as_deref(), Some("solo@example.com"));
    }

    #[test]
    fn test_missing_and_malformed() {
        let dir = tempfile::tempdir().unwrap();
        let status = InfisicalProbe::new(Paths::for_test(dir.path()))
            .status()
            .unwrap();
        assert!(!status.installed);
        assert!(status.profiles.is_empty());

        let (_dir, home) = fixture("{ this is not json");
        let status = InfisicalProbe::new(Paths::for_test(&home))
            .status()
            .unwrap();
        assert!(status.installed);
        assert!(status.profiles.is_empty());
        assert!(status
            .notes
            .iter()
            .any(|n| n.kind == NoteKind::Problem && n.text.contains("not valid JSON")));
    }

    /// The real shape of this file on a two-account machine, pretty-printed
    /// the way the CLI writes it, unknown keys and all.
    const TWO_USERS: &str = r#"{
  "loggedInUserEmail": "contact@example.com",
  "LoggedInUserDomain": "https://app.infisical.com/api",
  "loggedInUsers": [
    {
      "email": "cerana@example.com",
      "domain": "https://eu.infisical.com/api"
    },
    {
      "email": "contact@example.com",
      "domain": "https://app.infisical.com/api"
    }
  ],
  "vaultBackendType": "file",
  "vaultBackendPassphrase": "ZmFrZS1maXh0dXJl",
  "somethingPatchbayHasNeverHeardOf": { "nested": [1, 2, 3] }
}
"#;

    fn config_at(home: &std::path::Path) -> serde_json::Value {
        let text = fs::read_to_string(home.join(".infisical/infisical-config.json")).unwrap();
        serde_json::from_str(&text).unwrap()
    }

    #[test]
    fn test_switch_repoints_both_fields_and_touches_nothing_else() {
        let (_dir, home) = fixture(TWO_USERS);
        let probe = InfisicalProbe::new(Paths::for_test(&home));
        let before = config_at(&home);

        match probe.switch("cerana@example.com").unwrap() {
            SwitchOutcome::Switched {
                profile_id, notes, ..
            } => {
                assert_eq!(profile_id, "cerana@example.com");
                assert!(
                    notes.iter().any(|n| n.contains("infisical login status")),
                    "{notes:?}"
                );
            }
            other => panic!("expected Switched, got {other:?}"),
        }

        let after = config_at(&home);
        assert_eq!(after["loggedInUserEmail"], "cerana@example.com");
        assert_eq!(after["LoggedInUserDomain"], "https://eu.infisical.com/api");

        // Everything else is byte-for-byte the same value it was. The
        // passphrase is the one that matters: re-serializing the typed Config
        // would drop it and lock the user out of their own vault.
        for key in [
            "loggedInUsers",
            "vaultBackendType",
            "vaultBackendPassphrase",
            "somethingPatchbayHasNeverHeardOf",
        ] {
            assert_eq!(after[key], before[key], "`{key}` was modified");
        }
        // ...and exactly two keys differ, no more.
        let changed: Vec<&str> = before
            .as_object()
            .unwrap()
            .keys()
            .filter(|k| before[k.as_str()] != after[k.as_str()])
            .map(|k| k.as_str())
            .collect();
        assert_eq!(changed, vec!["loggedInUserEmail", "LoggedInUserDomain"]);
        assert_eq!(
            before.as_object().unwrap().len(),
            after.as_object().unwrap().len(),
            "the key set changed"
        );
    }

    #[test]
    fn test_switch_round_trip_restores_the_original_exactly() {
        let (_dir, home) = fixture(TWO_USERS);
        let probe = InfisicalProbe::new(Paths::for_test(&home));
        let original = config_at(&home);

        probe.switch("cerana@example.com").unwrap();
        probe.switch("contact@example.com").unwrap();

        assert_eq!(
            config_at(&home),
            original,
            "the round trip was not lossless"
        );
        assert_eq!(
            probe.status().unwrap().active.as_deref(),
            Some("contact@example.com")
        );
    }

    #[test]
    fn test_switch_writes_a_backup_first() {
        let (_dir, home) = fixture(TWO_USERS);
        let path = home.join(".infisical/infisical-config.json");
        InfisicalProbe::new(Paths::for_test(&home))
            .switch("cerana@example.com")
            .unwrap();

        let saved = crate::util::backup_path(&path);
        assert!(saved.is_file(), "no backup at {}", saved.display());
        // The backup is the file as it was before this write.
        let restored: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&saved).unwrap()).unwrap();
        assert_eq!(restored["loggedInUserEmail"], "contact@example.com");
    }

    #[test]
    fn test_switch_refuses_an_email_that_has_never_logged_in() {
        let (_dir, home) = fixture(TWO_USERS);
        let probe = InfisicalProbe::new(Paths::for_test(&home));
        let before = fs::read_to_string(home.join(".infisical/infisical-config.json")).unwrap();

        match probe.switch("stranger@example.com").unwrap() {
            SwitchOutcome::UnknownProfile { available, .. } => {
                assert_eq!(available, vec!["cerana@example.com", "contact@example.com"]);
            }
            other => panic!("expected UnknownProfile, got {other:?}"),
        }
        // A refusal writes nothing at all — not even a backup.
        assert_eq!(
            fs::read_to_string(home.join(".infisical/infisical-config.json")).unwrap(),
            before
        );
        assert!(!crate::util::backup_path(&home.join(".infisical/infisical-config.json")).exists());
    }

    #[test]
    fn test_an_active_user_absent_from_the_list_is_not_a_switch_target() {
        // The status synthesises a profile for this account so the board is
        // honest about what is active; it is still not something to switch TO,
        // because there is no stored login behind it.
        let (_dir, home) = fixture(
            r#"{"loggedInUserEmail":"solo@example.com","loggedInUsers":[{"email":"other@example.com","domain":"https://app.infisical.com/api"}]}"#,
        );
        let probe = InfisicalProbe::new(Paths::for_test(&home));
        assert!(probe
            .status()
            .unwrap()
            .profiles
            .iter()
            .any(|p| p.id == "solo@example.com"));

        match probe.switch("solo@example.com").unwrap() {
            SwitchOutcome::UnknownProfile { available, .. } => {
                assert_eq!(available, vec!["other@example.com"]);
            }
            other => panic!("expected UnknownProfile, got {other:?}"),
        }
    }

    #[test]
    fn test_switching_to_the_already_active_user_says_so_and_stays_valid() {
        let (_dir, home) = fixture(TWO_USERS);
        let probe = InfisicalProbe::new(Paths::for_test(&home));
        let before = config_at(&home);

        match probe.switch("contact@example.com").unwrap() {
            SwitchOutcome::Switched { notes, .. } => {
                assert!(
                    notes.iter().any(|n| n.contains("already the active user")),
                    "{notes:?}"
                );
            }
            other => panic!("expected Switched, got {other:?}"),
        }
        assert_eq!(config_at(&home), before);
    }

    #[test]
    fn test_a_user_without_a_domain_keeps_the_existing_pointer() {
        let (_dir, home) = fixture(
            r#"{"loggedInUserEmail":"a@example.com","LoggedInUserDomain":"https://app.infisical.com/api","loggedInUsers":[{"email":"a@example.com","domain":"https://app.infisical.com/api"},{"email":"b@example.com"}]}"#,
        );
        let probe = InfisicalProbe::new(Paths::for_test(&home));
        match probe.switch("b@example.com").unwrap() {
            SwitchOutcome::Switched { notes, .. } => {
                assert!(
                    notes.iter().any(|n| n.contains("no domain recorded")),
                    "{notes:?}"
                );
            }
            other => panic!("expected Switched, got {other:?}"),
        }
        let after = config_at(&home);
        assert_eq!(after["loggedInUserEmail"], "b@example.com");
        // Left alone rather than blanked.
        assert_eq!(after["LoggedInUserDomain"], "https://app.infisical.com/api");
    }

    #[test]
    fn test_switch_without_a_config_file_explains_itself() {
        let dir = tempfile::tempdir().unwrap();
        match InfisicalProbe::new(Paths::for_test(dir.path()))
            .switch("a@example.com")
            .unwrap()
        {
            SwitchOutcome::Failed { detail, .. } => {
                assert!(detail.contains("infisical login"), "{detail}");
            }
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    #[test]
    fn test_switch_refuses_to_rewrite_a_malformed_config() {
        let (_dir, home) = fixture("{ this is not json");
        let err = InfisicalProbe::new(Paths::for_test(&home))
            .switch("a@example.com")
            .unwrap_err()
            .to_string();
        assert!(err.contains("refusing to rewrite it"), "{err}");
        assert_eq!(
            fs::read_to_string(home.join(".infisical/infisical-config.json")).unwrap(),
            "{ this is not json"
        );
    }
}
