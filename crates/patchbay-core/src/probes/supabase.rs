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

use crate::paths::Paths;
use crate::probe::{unsupported_switch, unsupported_verify, Probe};
use crate::types::{PermissionsReport, Profile, SwitchOutcome, ToolStatus, VerifyOutcome};
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
            status.note(note);
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
                status.note(e);
                None
            }
        };
        let profile_name = profile_name.unwrap_or_else(|| Self::DEFAULT_PROFILE.to_string());

        // Existence only. The file *is* the token; it is never opened.
        let on_disk = token_file.is_file();
        let in_env = self.paths.env("SUPABASE_ACCESS_TOKEN").is_some();

        if in_env {
            status.note(
                "SUPABASE_ACCESS_TOKEN is set in the environment and wins over both the keyring \
                 and the fallback file"
                    .to_string(),
            );
        }

        if on_disk || in_env {
            status.profiles.push(
                Profile::new(&profile_name)
                    .label(format!("{profile_name} environment"))
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
                status.note(
                    "the access token is in the plaintext fallback file rather than the OS \
                     keyring; the CLI only falls back like this when the keyring is unavailable"
                        .to_string(),
                );
            }
        } else {
            status.note(
                "supabase keeps its access token in the OS keyring (service `Supabase CLI`), \
                 which patchbay does not read; a missing fallback file is the normal, healthy \
                 case rather than a logged-out one"
                    .to_string(),
            );
        }

        status.note(
            "a supabase `profile` selects an API environment, not an account; there is no \
             multi-account concept and tokens carry no expiry on disk"
                .to_string(),
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
        // `supabase projects list` is the cheapest authenticated call, but it
        // is a network round trip against an account patchbay has not been
        // asked to touch. Left to the human until it earns its place.
        Ok(unsupported_verify(
            Self::TOOL,
            "patchbay does not run supabase yet; the token is in the keyring, so only the CLI can \
             answer whether it still works",
            Some("supabase projects list"),
        ))
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
        assert!(status.notes.iter().any(|n| n.contains("OS keyring")));
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
        assert!(status.profiles[0].expires_at.is_none());
        assert!(status
            .notes
            .iter()
            .any(|n| n.contains("plaintext fallback")));

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
}
