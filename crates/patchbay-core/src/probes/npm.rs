//! `npm` — registries you hold a token for, from `~/.npmrc`.
//!
//! Verified against npm's own `npmrc` documentation (npm 12). The file is ini,
//! but the auth lines are *not* in sections: they are top-level keys prefixed
//! with a "nerf dart" — the registry URI minus its scheme:
//!
//! ```ini
//! @myorg:registry=https://npm.example.com/myorg
//! //registry.npmjs.org/:_authToken=npm_...
//! //npm.example.com/myorg/:_authToken=npm_...
//! //npm.example.com/:username=dev
//! ```
//!
//! Profiles are those registries. The label is the registry, and the value
//! after `=` is never read — except for one shape that must be distinguished:
//! `${NPM_TOKEN}` is npm's environment interpolation, meaning the token is not
//! on disk at all. Reporting that as "token on disk" would be wrong, so the
//! probe checks whether the value *is* a `${...}` reference without keeping it.
//!
//! npm has no active registry (`registry=` sets a default, scopes route the
//! rest) and no OS keychain integration, so `active` is `None` — which is the
//! correct answer rather than a missing one, hence
//! [`crate::types::ActiveConcept::NotApplicable`] — and the token on disk
//! carries no deadline of its own.

use std::collections::BTreeMap;

use crate::paths::Paths;
use crate::probe::{unsupported_switch, unsupported_verify, Probe};
use crate::types::{
    ActiveConcept, Expiry, PermissionsReport, Profile, SwitchOutcome, ToolStatus, VerifyOutcome,
};
use crate::util::read_text;

pub struct NpmProbe {
    paths: Paths,
}

/// Auth fields npm scopes to a registry. `_authToken`, `_auth` and `_password`
/// are secrets; the rest are identifiers or paths.
const AUTH_FIELDS: &[&str] = &[
    "_authToken",
    "_auth",
    "_password",
    "username",
    "email",
    "certfile",
    "keyfile",
    "cafile",
];

const SECRET_FIELDS: &[&str] = &["_authToken", "_auth", "_password"];

/// What a registry line tells us about where the credential lives.
#[derive(Debug, Default, PartialEq)]
struct RegistryAuth {
    fields: Vec<String>,
    /// Any secret field whose value is a `${VAR}` reference.
    indirect: bool,
    /// Any secret field with a literal value in the file.
    on_disk: bool,
}

impl NpmProbe {
    pub const TOOL: &'static str = "npm";

    pub fn new(paths: Paths) -> Self {
        Self { paths }
    }

    /// Split `//registry.npmjs.org/:_authToken` into registry and field.
    fn split_nerf_dart(key: &str) -> Option<(String, String)> {
        let rest = key.strip_prefix("//")?;
        let (registry, field) = rest.rsplit_once(':')?;
        let field = field.trim();
        AUTH_FIELDS
            .iter()
            .find(|f| f.eq_ignore_ascii_case(field))
            .map(|f| (format!("//{registry}"), (*f).to_string()))
    }

    /// Parse the auth-relevant half of an npmrc.
    ///
    /// Returns the per-registry auth summary and the `@scope:registry=` map.
    /// npmrc has no sections in practice, so this is a flat line scan rather
    /// than the shared INI parser (which drops keys that precede a header).
    fn parse(text: &str) -> (BTreeMap<String, RegistryAuth>, BTreeMap<String, String>) {
        let mut registries: BTreeMap<String, RegistryAuth> = BTreeMap::new();
        let mut scopes: BTreeMap<String, String> = BTreeMap::new();

        for raw in text.lines() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
                continue;
            }
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            let key = key.trim();
            let value = value.trim();

            if let Some((registry, field)) = Self::split_nerf_dart(key) {
                let entry = registries.entry(registry).or_default();
                if !entry.fields.contains(&field) {
                    entry.fields.push(field.clone());
                }
                if SECRET_FIELDS.iter().any(|f| f.eq_ignore_ascii_case(&field)) {
                    // The one property of the value we are allowed to know.
                    if value.starts_with("${") && value.ends_with('}') {
                        entry.indirect = true;
                    } else if !value.is_empty() {
                        entry.on_disk = true;
                    }
                }
                continue;
            }
            if let Some(scope) = key.strip_suffix(":registry") {
                if scope.starts_with('@') {
                    scopes.insert(scope.to_string(), value.to_string());
                }
            }
        }
        (registries, scopes)
    }
}

impl Probe for NpmProbe {
    fn tool(&self) -> &'static str {
        Self::TOOL
    }

    fn status(&self) -> anyhow::Result<ToolStatus> {
        let path = self.paths.npmrc();
        let installed = self.paths.has_binary("npm") || path.is_file();
        let mut status = ToolStatus::empty(Self::TOOL, installed);
        for note in self.paths.path_notes("npm") {
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

        let (registries, scopes) = Self::parse(&text);
        let mut plaintext = Vec::new();
        for (registry, auth) in &registries {
            if auth.on_disk {
                plaintext.push(registry.clone());
            }
            // Which scopes route to this registry, matched on the nerf dart.
            let routed: Vec<String> = scopes
                .iter()
                .filter(|(_, url)| {
                    let dart = url
                        .split_once("://")
                        .map(|(_, rest)| format!("//{rest}"))
                        .unwrap_or_else(|| url.to_string());
                    dart.trim_end_matches('/') == registry.trim_end_matches('/')
                })
                .map(|(scope, _)| scope.clone())
                .collect();

            status.profiles.push(
                Profile::new(registry.as_str())
                    .label(registry.trim_start_matches("//").trim_end_matches('/'))
                    // An .npmrc line is a bare token: nothing in the file dates
                    // it, and npm never asks you to renew it.
                    .expiry(Expiry::NoExpiry)
                    .with_meta("auth_fields", auth.fields.clone())
                    .with_meta(
                        "credential_storage",
                        if auth.indirect {
                            "environment variable referenced from .npmrc"
                        } else if auth.on_disk {
                            ".npmrc"
                        } else {
                            "none"
                        },
                    )
                    .with_meta("scopes", routed),
            );
        }

        if status.profiles.is_empty() {
            return Ok(status);
        }

        status.active_concept = ActiveConcept::not_applicable(
            "the default comes from `registry=` and scoped packages route by `@scope:registry`",
        );
        if !plaintext.is_empty() {
            status.warn(format!(
                "tokens for {} are stored in plain text in .npmrc (npm has no keychain \
                 integration); `${{VAR}}` values are read from the environment instead",
                plaintext.join(", ")
            ));
        }

        Ok(status)
    }

    fn switch(&self, _profile_id: &str) -> anyhow::Result<SwitchOutcome> {
        Ok(unsupported_switch(
            Self::TOOL,
            "npm has no active registry to switch; every registry is used concurrently, chosen by \
             the package's scope",
            Some("npm config set @scope:registry <url>"),
        ))
    }

    fn verify(&self) -> anyhow::Result<VerifyOutcome> {
        Ok(unsupported_verify(
            Self::TOOL,
            "verification needs a specific registry, which this call has no way to name",
            Some("npm whoami --registry <url>"),
        ))
    }

    fn permissions(&self) -> anyhow::Result<PermissionsReport> {
        Ok(PermissionsReport::unsupported(
            Self::TOOL,
            "an npm token's rights live with the registry that issued it, not in .npmrc",
            Some("npm token list"),
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
        fs::write(home.join(".npmrc"), body).unwrap();
        (dir, home)
    }

    const NPMRC: &str = "\
; a comment
registry=https://registry.npmjs.org/
@myorg:registry=https://npm.example.com/myorg
//registry.npmjs.org/:_authToken=npm_fakefixturetoken
//npm.example.com/myorg/:_authToken=${NPM_TOKEN}
//npm.example.com/:username=dev
//npm.example.com/:_password=ZmFrZWZpeHR1cmU=
";

    #[test]
    fn test_registries_with_tokens_become_profiles() {
        let (_dir, home) = fixture(NPMRC);
        let status = NpmProbe::new(Paths::for_test(&home)).status().unwrap();
        let ids: Vec<_> = status.profiles.iter().map(|p| p.id.as_str()).collect();
        assert_eq!(
            ids,
            vec![
                "//npm.example.com/",
                "//npm.example.com/myorg/",
                "//registry.npmjs.org/"
            ]
        );
        assert!(status.active.is_none());
        // Empty by design: npm routes by scope, it does not select a registry.
        assert!(status.active_concept.is_not_applicable());
        assert!(status
            .profiles
            .iter()
            .all(|p| p.expiry == Expiry::NoExpiry && p.expires_at().is_none()));

        let npmjs = status
            .profiles
            .iter()
            .find(|p| p.id.contains("npmjs"))
            .unwrap();
        assert_eq!(npmjs.label, "registry.npmjs.org");
        assert_eq!(npmjs.meta["credential_storage"], ".npmrc");
        assert_eq!(npmjs.meta["auth_fields"][0], "_authToken");
    }

    #[test]
    fn test_env_interpolation_is_not_reported_as_a_token_on_disk() {
        let (_dir, home) = fixture(NPMRC);
        let status = NpmProbe::new(Paths::for_test(&home)).status().unwrap();
        let scoped = status
            .profiles
            .iter()
            .find(|p| p.id == "//npm.example.com/myorg/")
            .unwrap();
        assert_eq!(
            scoped.meta["credential_storage"],
            "environment variable referenced from .npmrc"
        );
        // The scope that routes there is joined onto the registry.
        assert_eq!(scoped.meta["scopes"][0], "@myorg");
        // The plaintext warning names only the registries that really have one.
        let warning = status
            .notes
            .iter()
            .find(|n| n.text.contains("plain text"))
            .unwrap();
        assert_eq!(warning.kind, NoteKind::Warn);
        assert!(
            warning.text.contains("//registry.npmjs.org/"),
            "{warning:?}"
        );
        assert!(!warning.text.contains("myorg/"), "{warning:?}");
    }

    #[test]
    fn test_no_token_value_reaches_the_output() {
        let (_dir, home) = fixture(NPMRC);
        let status = NpmProbe::new(Paths::for_test(&home)).status().unwrap();
        let json = serde_json::to_string(&status).unwrap();
        for secret in ["npm_fakefixturetoken", "ZmFrZWZpeHR1cmU=", "NPM_TOKEN"] {
            assert!(!json.contains(secret), "leaked {secret} in {json}");
        }
    }

    #[test]
    fn test_missing_and_tokenless_and_garbage() {
        let dir = tempfile::tempdir().unwrap();
        let status = NpmProbe::new(Paths::for_test(dir.path())).status().unwrap();
        assert!(!status.installed);
        assert!(status.profiles.is_empty());
        assert!(status.notes.is_empty());

        // A config with settings but no auth is a normal, quiet state.
        let (_dir, home) = fixture("save-exact=true\nregistry=https://registry.npmjs.org/\n");
        let status = NpmProbe::new(Paths::for_test(&home)).status().unwrap();
        assert!(status.profiles.is_empty());
        assert!(status.notes.is_empty());

        let (_dir, home) = fixture("<<<<<<< HEAD\nnot an npmrc at all\n");
        let status = NpmProbe::new(Paths::for_test(&home)).status().unwrap();
        assert!(status.profiles.is_empty());
    }

    #[test]
    fn test_userconfig_override_is_followed_and_noted() {
        let dir = tempfile::tempdir().unwrap();
        let elsewhere = dir.path().join("ci.npmrc");
        fs::write(&elsewhere, "//registry.npmjs.org/:_authToken=npm_fixture\n").unwrap();
        let paths = Paths::for_test(dir.path())
            .with_env("NPM_CONFIG_USERCONFIG", elsewhere.to_str().unwrap());
        let status = NpmProbe::new(paths).status().unwrap();
        assert_eq!(status.profiles.len(), 1);
        assert!(status
            .notes
            .iter()
            .any(|n| n.text.contains("$NPM_CONFIG_USERCONFIG=")));
    }

    #[test]
    fn test_split_nerf_dart() {
        assert_eq!(
            NpmProbe::split_nerf_dart("//registry.npmjs.org/:_authToken"),
            Some((
                "//registry.npmjs.org/".to_string(),
                "_authToken".to_string()
            ))
        );
        // Path-scoped registries keep their path.
        assert_eq!(
            NpmProbe::split_nerf_dart("//npm.example.com/a/b/:_auth"),
            Some(("//npm.example.com/a/b/".to_string(), "_auth".to_string()))
        );
        // Not an auth field, and not a nerf dart at all.
        assert!(NpmProbe::split_nerf_dart("//npm.example.com/:strict-ssl").is_none());
        assert!(NpmProbe::split_nerf_dart("registry").is_none());
    }
}
