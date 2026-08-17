//! `aws` — shared config/credentials INI plus the SSO token cache.
//!
//! Profiles come from `~/.aws/config` (`[default]` and `[profile NAME]`) and
//! `~/.aws/credentials` (`[NAME]`). Only SSO profiles have a knowable deadline:
//! it lives in `~/.aws/sso/cache/*.json`, and is the one case here that is a
//! real [`Expiry::At`]. Static access keys are [`Expiry::NoExpiry`] — they do
//! not expire by design, which is a different claim from "patchbay could not
//! find out". An assumed-role profile is neither: the CLI mints the session
//! itself and caches it where this probe does not look.
//!
//! The AWS CLI has no persistent "active profile" on disk: it is the
//! `AWS_PROFILE` environment variable, defaulting to `default`. That is why
//! switching is deliberately unsupported — a child process cannot change its
//! parent shell's environment.

use std::collections::BTreeMap;
use std::path::Path;

use chrono::{DateTime, Utc};

use crate::paths::Paths;
use crate::probe::{unsupported_switch, unsupported_verify, Probe};
use crate::types::{
    Expiry, Note, PermissionsReport, Profile, SwitchOutcome, ToolStatus, VerifyOutcome,
};
use crate::util::{parse_timestamp, read_text, CmdOutput, Ini};

pub struct AwsProbe {
    paths: Paths,
}

#[derive(Default)]
struct Entry {
    in_config: bool,
    in_credentials: bool,
    region: Option<String>,
    sso_start_url: Option<String>,
    sso_account_id: Option<String>,
    sso_role_name: Option<String>,
    sso_session: Option<String>,
    has_sso: bool,
    has_static_keys: bool,
    role_arn: Option<String>,
}

impl Entry {
    fn kind(&self) -> &'static str {
        if self.has_sso {
            "sso"
        } else if self.role_arn.is_some() {
            "assume-role"
        } else if self.has_static_keys {
            "static-keys"
        } else {
            "unknown"
        }
    }
}

/// One `~/.aws/sso/cache/*.json` entry, reduced to what patchbay may keep.
/// The `accessToken` field in these files is never deserialized.
struct SsoCacheEntry {
    start_url: Option<String>,
    expires_at: DateTime<Utc>,
}

impl AwsProbe {
    pub const TOOL: &'static str = "aws";

    pub fn new(paths: Paths) -> Self {
        Self { paths }
    }

    fn load_ini(path: &Path, notes: &mut Vec<Note>) -> Option<Ini> {
        match read_text(path) {
            Ok(Some(text)) => Some(Ini::parse(&text)),
            Ok(None) => None,
            Err(e) => {
                notes.push(Note::problem(e));
                None
            }
        }
    }

    /// SSO token cache, newest first. Files that are not token caches (role
    /// credential caches, junk) are skipped silently.
    fn sso_cache(dir: &Path) -> Vec<SsoCacheEntry> {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return Vec::new();
        };
        let mut out: Vec<SsoCacheEntry> = entries
            .filter_map(Result::ok)
            .filter(|e| e.path().extension().is_some_and(|ext| ext == "json"))
            .filter_map(|e| {
                let text = read_text(&e.path()).ok().flatten()?;
                let json: serde_json::Value = serde_json::from_str(&text).ok()?;
                let expires_at = json
                    .get("expiresAt")
                    .and_then(|v| v.as_str())
                    .and_then(parse_timestamp)?;
                Some(SsoCacheEntry {
                    start_url: json
                        .get("startUrl")
                        .and_then(|v| v.as_str())
                        .map(str::to_string),
                    expires_at,
                })
            })
            .collect();
        out.sort_by_key(|e| std::cmp::Reverse(e.expires_at));
        out
    }
}

impl Probe for AwsProbe {
    fn tool(&self) -> &'static str {
        Self::TOOL
    }

    fn status(&self) -> anyhow::Result<ToolStatus> {
        let config_path = self.paths.aws_config();
        let credentials_path = self.paths.aws_credentials();
        let installed =
            self.paths.has_binary("aws") || config_path.is_file() || credentials_path.is_file();
        let mut status = ToolStatus::empty(Self::TOOL, installed);
        for note in self.paths.path_notes("aws_config") {
            status.push_note(note);
        }
        for note in self.paths.path_notes("aws_credentials") {
            status.push_note(note);
        }

        // BTreeMap so the board is stable across runs.
        let mut entries: BTreeMap<String, Entry> = BTreeMap::new();

        if let Some(ini) = Self::load_ini(&config_path, &mut status.notes) {
            for section in &ini.sections {
                // `[default]`, `[profile work]`, and `[sso-session x]` which is
                // not a profile.
                let name = if section.name == "default" {
                    "default".to_string()
                } else if let Some(rest) = section.name.strip_prefix("profile ") {
                    rest.trim().to_string()
                } else {
                    continue;
                };
                let entry = entries.entry(name).or_default();
                entry.in_config = true;
                entry.region = section.get("region").map(str::to_string);
                entry.sso_start_url = section.get("sso_start_url").map(str::to_string);
                entry.sso_account_id = section.get("sso_account_id").map(str::to_string);
                entry.sso_role_name = section.get("sso_role_name").map(str::to_string);
                entry.sso_session = section.get("sso_session").map(str::to_string);
                entry.has_sso = section.has_prefix("sso_");
                entry.role_arn = section.get("role_arn").map(str::to_string);
                entry.has_static_keys |= section.get("aws_access_key_id").is_some();
            }
        }

        if let Some(ini) = Self::load_ini(&credentials_path, &mut status.notes) {
            for section in &ini.sections {
                let entry = entries.entry(section.name.clone()).or_default();
                entry.in_credentials = true;
                // Presence only — key ids and secrets are never stored.
                entry.has_static_keys |= section.get("aws_access_key_id").is_some();
                if entry.region.is_none() {
                    entry.region = section.get("region").map(str::to_string);
                }
            }
        }

        let cache = Self::sso_cache(&self.paths.aws_sso_cache_dir());

        for (name, entry) in entries {
            // Only SSO profiles have a cached session that expires. Match on
            // the start URL when we can, else fall back to the newest token.
            let sso_expires_at = if entry.has_sso {
                let matched = entry.sso_start_url.as_ref().and_then(|url| {
                    cache
                        .iter()
                        .find(|c| c.start_url.as_deref() == Some(url.as_str()))
                });
                matched.or(cache.first()).map(|c| c.expires_at)
            } else {
                None
            };

            // One credential kind, one expiry state. Reading them all as
            // `None` used to make a static key that never expires and an SSO
            // profile nobody has logged into today indistinguishable.
            let expiry = match entry.kind() {
                "sso" => match sso_expires_at {
                    Some(at) => Expiry::At(at),
                    // Configured for SSO with nothing in the token cache: there
                    // is no session yet, so there is no date to report.
                    None => Expiry::unknown("no cached SSO session"),
                },
                // The CLI assumes the role itself and caches the short-lived
                // session in ~/.aws/cli/cache, which this probe does not read.
                "assume-role" => Expiry::unknown("in the CLI's assumed-role credential cache"),
                "static-keys" => Expiry::NoExpiry,
                _ => Expiry::unknown("no credential for this profile in ~/.aws"),
            };

            let source = match (entry.in_config, entry.in_credentials) {
                (true, true) => "config+credentials",
                (true, false) => "config",
                _ => "credentials",
            };

            status.profiles.push(
                Profile::new(&name)
                    .expiry(expiry)
                    .with_meta("type", entry.kind())
                    .with_meta("source", source)
                    .with_meta("region", entry.region.clone())
                    .with_meta("sso_start_url", entry.sso_start_url.clone())
                    .with_meta("sso_session", entry.sso_session.clone())
                    .with_meta("sso_account_id", entry.sso_account_id.clone())
                    .with_meta("sso_role_name", entry.sso_role_name.clone())
                    .with_meta("role_arn", entry.role_arn.clone()),
            );
        }

        // Active profile is environment state, not file state. Only the
        // override is worth a note: `AWS_PROFILE` unset and `default` in effect
        // is how the CLI is supposed to behave, and saying so made the ordinary
        // path look like something had happened.
        match self.paths.env("AWS_PROFILE") {
            Some(name) => {
                status.active = Some(name.to_string());
                if status.profiles.iter().any(|p| p.id == name) {
                    status.warn(format!(
                        "AWS_PROFILE is set to `{name}`, so that profile is in effect rather than `default`"
                    ));
                } else {
                    status.problem(format!(
                        "AWS_PROFILE is set to `{name}` but no such profile exists in ~/.aws"
                    ));
                }
            }
            None => {
                if status.profiles.iter().any(|p| p.id == "default") {
                    status.active = Some("default".to_string());
                } else if !status.profiles.is_empty() {
                    status.problem(
                        "AWS_PROFILE is not set and there is no `default` profile; aws commands will fail until you export one",
                    );
                }
            }
        }

        Ok(status)
    }

    fn switch(&self, profile_id: &str) -> anyhow::Result<SwitchOutcome> {
        // Deliberately unsupported: the active profile is an environment
        // variable in the caller's shell, which no child process can change.
        Ok(unsupported_switch(
            Self::TOOL,
            "the active AWS profile is the AWS_PROFILE environment variable, which patchbay cannot set in your shell",
            Some(&format!("export AWS_PROFILE={profile_id}")),
        ))
    }

    fn verify(&self) -> anyhow::Result<VerifyOutcome> {
        if !self.paths.may_exec() || !self.paths.has_binary("aws") {
            return Ok(unsupported_verify(
                Self::TOOL,
                "the aws CLI is not available on PATH",
                Some("aws sts get-caller-identity"),
            ));
        }
        let out = self
            .paths
            .run("aws", &["sts", "get-caller-identity", "--output", "json"])?;
        Ok(if out.ok {
            let arn = serde_json::from_str::<serde_json::Value>(&out.stdout)
                .ok()
                .and_then(|v| v.get("Arn").and_then(|a| a.as_str()).map(str::to_string))
                .unwrap_or_else(|| "credentials accepted".to_string());
            VerifyOutcome::Valid {
                tool: Self::TOOL.to_string(),
                detail: arn,
            }
        } else {
            VerifyOutcome::Invalid {
                tool: Self::TOOL.to_string(),
                detail: out.message(),
            }
        })
    }

    /// Who this credential is, and what is attached to it.
    ///
    /// No scope picker: unlike a GCP project or an Azure subscription, an AWS
    /// credential's permissions are not asked *about* somewhere — the identity
    /// is what it is, and [`Probe::permission_scopes`] stays empty.
    ///
    /// Two steps, and the first one always works when the credentials do:
    /// `sts:GetCallerIdentity` needs no permission at all, so the identity is
    /// knowable even where nothing else is. Reading the *policies* then needs
    /// `iam:ListAttachedUserPolicies`, which is itself a permission and one
    /// most keys are not granted. A refusal there is reported as a refusal —
    /// "the identity is X, and this credential may not read its own policies"
    /// is a true and useful answer, where "no permissions" would be a lie.
    fn permissions(&self) -> anyhow::Result<PermissionsReport> {
        if !self.paths.may_exec() || !self.paths.has_binary("aws") {
            return Ok(PermissionsReport::unsupported(
                Self::TOOL,
                "the aws CLI is not available on PATH, so patchbay cannot ask who this credential is",
                Some("aws sts get-caller-identity"),
            ));
        }

        let out = self
            .paths
            .run("aws", &["sts", "get-caller-identity", "--output", "json"])?;
        if !out.ok {
            return Ok(report(
                false,
                None,
                Vec::new(),
                vec![Note::problem(sts_failure(&out))],
            ));
        }
        let arn = serde_json::from_str::<serde_json::Value>(&out.stdout)
            .ok()
            .and_then(|v| v.get("Arn").and_then(|a| a.as_str()).map(str::to_string));
        let Some(arn) = arn.filter(|a| !a.is_empty()) else {
            return Ok(report(
                false,
                None,
                Vec::new(),
                vec![
                    Note::problem("aws sts get-caller-identity answered without an Arn, so patchbay cannot tell which identity to read policies for"),
                ],
            ));
        };

        let user = match Identity::of(&arn) {
            Identity::User(name) => name,
            // An assumed role has no user policies at all: the grants live on
            // the role. Asking `list-attached-user-policies` about it cannot
            // succeed, so the role is named instead of a call being wasted on
            // a denial that would read like a permissions fact.
            Identity::AssumedRole(role) => {
                return Ok(report(
                    false,
                    Some(arn),
                    Vec::new(),
                    vec![Note::info(format!(
                        "this credential is the assumed role `{role}`, not an IAM user, so it has no user policies — its permissions are the role's, and reading those needs `iam:ListAttachedRolePolicies`"
                    ))],
                )
                .with_hint(&format!(
                    "aws iam list-attached-role-policies --role-name {role}"
                )));
            }
            Identity::Root => {
                return Ok(report(
                    true,
                    Some(arn),
                    vec!["*  (account root)".to_string()],
                    vec![
                        Note::warn("this is the account root user, which is allowed everything in the account and cannot be restricted by IAM policy — day-to-day work should not be using it"),
                    ],
                ));
            }
            Identity::Other => {
                return Ok(report(
                    false,
                    Some(arn.clone()),
                    Vec::new(),
                    vec![Note::info(format!(
                        "`{arn}` is neither an IAM user nor an assumed role, so patchbay has no policy list to read for it"
                    ))],
                ));
            }
        };

        let attached = self.read_policies(
            "list-attached-user-policies",
            &user,
            "iam:ListAttachedUserPolicies",
        )?;
        let inline = self.read_policies("list-user-policies", &user, "iam:ListUserPolicies")?;

        let mut scopes = Vec::new();
        let mut notes = Vec::new();
        for read in [&attached, &inline] {
            if let PolicyRead::Ok(names) = read {
                scopes.extend(names.iter().cloned());
            }
        }

        match (&attached, &inline) {
            // The case the old wording was hand-waving at, said plainly.
            (PolicyRead::Refused(missing), PolicyRead::Refused(_)) => {
                return Ok(report(
                    false,
                    Some(arn.clone()),
                    Vec::new(),
                    vec![Note::info(format!(
                        "the identity is `{arn}`, but its policies are not readable from here: listing them needs `{missing}`, which is itself a permission and one this credential does not hold"
                    ))],
                ));
            }
            (PolicyRead::Failed(detail), _) | (_, PolicyRead::Failed(detail)) => {
                return Ok(report(
                    false,
                    Some(arn.clone()),
                    Vec::new(),
                    vec![Note::problem(format!(
                        "the identity is `{arn}`, but {detail}"
                    ))],
                ));
            }
            _ => {
                if let PolicyRead::Refused(missing) = &attached {
                    notes.push(Note::warn(format!(
                        "managed policies are missing from this list: reading them needs `{missing}`, which this credential does not hold"
                    )));
                }
                if let PolicyRead::Refused(missing) = &inline {
                    notes.push(Note::warn(format!(
                        "inline policies are missing from this list: reading them needs `{missing}`, which this credential does not hold"
                    )));
                }
            }
        }

        scopes.sort();
        scopes.dedup();
        notes.push(Note::info(
            "the policies attached to the user, not what they add up to — patchbay does not evaluate the policy documents, and an SCP or permissions boundary can still deny what they allow",
        ));
        if scopes.is_empty() && notes.len() == 1 {
            notes.push(Note::info(format!(
                "`{arn}` has no policy attached directly — it may still get everything it can do from an IAM group, which this does not list"
            )));
        }
        Ok(report(true, Some(arn), scopes, notes))
    }
}

/// What one `aws iam list-*-policies` call came back with. A refusal is its own
/// case: it is a fact about the credential, not a failure to read one.
enum PolicyRead {
    Ok(Vec<String>),
    /// The credential lacks the named IAM action.
    Refused(String),
    Failed(String),
}

impl AwsProbe {
    /// One `aws iam list-…-policies` call, with a denial kept apart from a
    /// break. `action` is the IAM permission the call needs, which is the only
    /// useful thing to say when it is refused.
    fn read_policies(
        &self,
        subcommand: &str,
        user: &str,
        action: &str,
    ) -> anyhow::Result<PolicyRead> {
        let out = self.paths.run(
            "aws",
            &["iam", subcommand, "--user-name", user, "--output", "json"],
        )?;
        if !out.ok {
            let text = format!("{} {}", out.stderr, out.stdout).to_lowercase();
            if text.contains("accessdenied")
                || text.contains("not authorized to perform")
                || text.contains("explicit deny")
            {
                return Ok(PolicyRead::Refused(action.to_string()));
            }
            return Ok(PolicyRead::Failed(format!(
                "`aws iam {subcommand}` failed: {}",
                headline(&out)
            )));
        }

        let Ok(json) = serde_json::from_str::<serde_json::Value>(&out.stdout) else {
            return Ok(PolicyRead::Failed(format!(
                "`aws iam {subcommand}` answered with something that is not JSON"
            )));
        };
        // Managed policies come back as objects with a name; inline ones as
        // bare strings. Both are marked so the two never read as one kind.
        let mut names = Vec::new();
        if let Some(items) = json.get("AttachedPolicies").and_then(|v| v.as_array()) {
            for item in items {
                if let Some(name) = item.get("PolicyName").and_then(|v| v.as_str()) {
                    names.push(name.to_string());
                }
            }
        }
        if let Some(items) = json.get("PolicyNames").and_then(|v| v.as_array()) {
            for item in items.iter().filter_map(|v| v.as_str()) {
                names.push(format!("{item} (inline)"));
            }
        }
        Ok(PolicyRead::Ok(names))
    }
}

/// What kind of thing the caller's ARN names. The distinction decides whether
/// there is a user policy list to ask for at all.
enum Identity {
    User(String),
    AssumedRole(String),
    Root,
    Other,
}

impl Identity {
    fn of(arn: &str) -> Self {
        // arn:partition:service:region:account:resource — the resource itself
        // may contain colons, so the split stops at six.
        let parts: Vec<&str> = arn.splitn(6, ':').collect();
        let Some(resource) = parts.get(5) else {
            return Identity::Other;
        };
        if *resource == "root" {
            return Identity::Root;
        }
        // A user may sit under a path: `user/eng/alice` is `--user-name alice`.
        if let Some(rest) = resource.strip_prefix("user/") {
            return match rest.rsplit('/').next().filter(|n| !n.is_empty()) {
                Some(name) => Identity::User(name.to_string()),
                None => Identity::Other,
            };
        }
        if let Some(rest) = resource.strip_prefix("assumed-role/") {
            return match rest.split('/').next().filter(|n| !n.is_empty()) {
                Some(role) => Identity::AssumedRole(role.to_string()),
                None => Identity::Other,
            };
        }
        Identity::Other
    }
}

fn report(
    supported: bool,
    subject: Option<String>,
    scopes: Vec<String>,
    notes: Vec<Note>,
) -> PermissionsReport {
    PermissionsReport {
        tool: AwsProbe::TOOL.to_string(),
        supported,
        subject,
        scopes,
        notes,
        hint: None,
        scope: None,
    }
}

trait WithHint {
    fn with_hint(self, hint: &str) -> Self;
}

impl WithHint for PermissionsReport {
    fn with_hint(mut self, hint: &str) -> Self {
        self.hint = Some(hint.to_string());
        self
    }
}

/// One sentence for a `get-caller-identity` that did not answer.
///
/// This is the call that works whenever the credentials do, so a failure here
/// is always about the credentials themselves — which of the four ways they can
/// be unusable is the whole content of the answer.
fn sts_failure(out: &CmdOutput) -> String {
    let text = format!("{} {}", out.stderr, out.stdout).to_lowercase();
    if text.contains("unable to locate credentials")
        || text.contains("you must specify a region")
        || text.contains("could not be found")
    {
        return "no AWS credentials are in effect, so there is no identity to read policies for — export AWS_PROFILE, or run `aws sso login` for an SSO profile".to_string();
    }
    if text.contains("expired") || text.contains("token has expired") {
        return "the credentials in effect have expired — run `aws sso login` for an SSO profile, or refresh whatever mints them".to_string();
    }
    if text.contains("invalidclienttokenid")
        || text.contains("signaturedoesnotmatch")
        || text.contains("authfailure")
        || text.contains("security token included in the request is invalid")
    {
        return "the access key in effect is not valid any more — it was deleted or deactivated in IAM".to_string();
    }
    if text.contains("accessdenied") {
        return "the credentials in effect may not even call `sts:GetCallerIdentity`, which usually means a service control policy or a permissions boundary is blocking them".to_string();
    }
    format!(
        "aws could not say who this credential is: {}",
        headline(out)
    )
}

/// The AWS CLI's first meaningful line. Its errors start with a blank line and
/// the `An error occurred (Code) when calling …` sentence, which is the useful
/// part and is kept whole.
fn headline(out: &CmdOutput) -> String {
    let text = if out.stderr.trim().is_empty() {
        out.stdout.trim()
    } else {
        out.stderr.trim()
    };
    let line = text
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .unwrap_or("aws failed without saying why");
    line.strip_prefix("error: ")
        .or_else(|| line.strip_prefix("Error: "))
        .unwrap_or(line)
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::NoteKind;
    use std::fs;
    use std::path::PathBuf;

    struct Fixture {
        _dir: tempfile::TempDir,
        home: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let home = dir.path().to_path_buf();
            fs::create_dir_all(home.join(".aws/sso/cache")).unwrap();
            Self { _dir: dir, home }
        }

        fn write(&self, rel: &str, body: &str) -> &Self {
            let path = self.home.join(rel);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, body).unwrap();
            self
        }

        fn probe(&self) -> AwsProbe {
            AwsProbe::new(Paths::for_test(&self.home))
        }
    }

    #[test]
    fn test_profiles_from_both_files_are_merged() {
        let fx = Fixture::new();
        fx.write(
            ".aws/config",
            "[default]\nregion = us-east-1\n\n[profile work]\nregion = ap-northeast-1\nsso_start_url = https://example.awsapps.com/start\nsso_account_id = 111122223333\nsso_role_name = Admin\n\n[sso-session corp]\nsso_region = us-east-1\n",
        )
        .write(
            ".aws/credentials",
            "[default]\naws_access_key_id = AKIAFAKEFIXTUREKEY\naws_secret_access_key = fake-fixture-secret\n",
        );

        let status = fx.probe().status().unwrap();
        let ids: Vec<_> = status.profiles.iter().map(|p| p.id.as_str()).collect();
        assert_eq!(ids, vec!["default", "work"]);

        let default = &status.profiles[0];
        assert_eq!(default.meta["source"], "config+credentials");
        assert_eq!(default.meta["type"], "static-keys");
        // Not "we could not find out": a static key does not expire at all.
        assert_eq!(default.expiry, Expiry::NoExpiry);
        assert!(default.expires_at().is_none());

        let work = &status.profiles[1];
        assert_eq!(work.meta["type"], "sso");
        assert_eq!(work.meta["sso_account_id"], "111122223333");
        // `[sso-session corp]` is not a profile.
        assert!(!ids.contains(&"corp"));

        // No secret material anywhere in the serialized status.
        let json = serde_json::to_string(&status).unwrap();
        assert!(!json.contains("AKIAFAKEFIXTUREKEY"), "{json}");
        assert!(!json.contains("fake-fixture-secret"), "{json}");
    }

    #[test]
    fn test_sso_expiry_is_matched_by_start_url() {
        let fx = Fixture::new();
        fx.write(
            ".aws/config",
            "[profile work]\nsso_start_url = https://work.awsapps.com/start\nsso_role_name = Admin\n\n[profile other]\nsso_start_url = https://other.awsapps.com/start\n",
        )
        .write(
            ".aws/sso/cache/aaa.json",
            r#"{"startUrl":"https://work.awsapps.com/start","expiresAt":"2030-01-01T00:00:00Z","accessToken":"fake-fixture-token"}"#,
        )
        .write(
            ".aws/sso/cache/bbb.json",
            r#"{"startUrl":"https://other.awsapps.com/start","expiresAt":"2029-01-01T00:00:00Z","accessToken":"fake-fixture-token"}"#,
        )
        .write(".aws/sso/cache/junk.json", "{not json")
        .write(".aws/sso/cache/notacache.json", r#"{"hello":"world"}"#);

        let status = fx.probe().status().unwrap();
        let work = status.profiles.iter().find(|p| p.id == "work").unwrap();
        let other = status.profiles.iter().find(|p| p.id == "other").unwrap();
        // A cached SSO session is the one aws credential with a real deadline.
        assert_eq!(
            work.expires_at().unwrap().to_rfc3339(),
            "2030-01-01T00:00:00+00:00"
        );
        assert!(matches!(work.expiry, Expiry::At(_)));
        assert_eq!(
            other.expires_at().unwrap().to_rfc3339(),
            "2029-01-01T00:00:00+00:00"
        );

        let json = serde_json::to_string(&status).unwrap();
        assert!(!json.contains("fake-fixture-token"), "{json}");
    }

    #[test]
    fn test_active_follows_aws_profile_env() {
        let fx = Fixture::new();
        fx.write(".aws/config", "[default]\n\n[profile work]\n");

        // Set -> that profile wins, and an environment variable quietly
        // overriding the stored default is worth an amber note.
        let probe = AwsProbe::new(Paths::for_test(&fx.home).with_env("AWS_PROFILE", "work"));
        let status = probe.status().unwrap();
        assert_eq!(status.active.as_deref(), Some("work"));
        let override_note = status
            .notes
            .iter()
            .find(|n| n.text.contains("AWS_PROFILE is set to `work`"))
            .expect("expected the override to be named");
        assert_eq!(override_note.kind, NoteKind::Warn);

        // Unset -> default, silently: that is how the CLI is meant to behave.
        let status = fx.probe().status().unwrap();
        assert_eq!(status.active.as_deref(), Some("default"));
        assert!(
            !status.notes.iter().any(|n| n.text.contains("AWS_PROFILE")),
            "{:?}",
            status.notes
        );

        // Set to something that does not exist -> a dangling reference.
        let probe = AwsProbe::new(Paths::for_test(&fx.home).with_env("AWS_PROFILE", "ghost"));
        let status = probe.status().unwrap();
        assert_eq!(status.active.as_deref(), Some("ghost"));
        let dangling = status
            .notes
            .iter()
            .find(|n| n.text.contains("no such profile"))
            .expect("expected the dangling profile to be flagged");
        assert_eq!(dangling.kind, NoteKind::Problem);
    }

    #[test]
    fn test_no_profile_at_all_is_a_problem_not_a_shrug() {
        let fx = Fixture::new();
        fx.write(".aws/config", "[profile work]\n");
        let status = fx.probe().status().unwrap();
        assert!(status.active.is_none());
        let note = status
            .notes
            .iter()
            .find(|n| n.text.contains("aws commands will fail"))
            .expect("expected the missing default to be flagged");
        assert_eq!(note.kind, NoteKind::Problem);
    }

    #[test]
    fn test_each_credential_kind_gets_the_expiry_state_that_is_true_of_it() {
        let fx = Fixture::new();
        fx.write(
            ".aws/config",
            "[profile keys]\nregion = us-east-1\n\n[profile role]\nrole_arn = arn:aws:iam::111122223333:role/Admin\nsource_profile = keys\n\n[profile sso]\nsso_start_url = https://example.awsapps.com/start\nsso_role_name = Admin\n\n[profile empty]\nregion = us-east-1\n",
        )
        .write(
            ".aws/credentials",
            "[keys]\naws_access_key_id = AKIAFAKEFIXTUREKEY\naws_secret_access_key = fake-fixture-secret\n",
        );

        let status = fx.probe().status().unwrap();
        let expiry = |id: &str| {
            status
                .profiles
                .iter()
                .find(|p| p.id == id)
                .unwrap_or_else(|| panic!("no profile {id}"))
                .expiry
                .clone()
        };
        assert_eq!(expiry("keys"), Expiry::NoExpiry);
        // No token cached, so an SSO profile has no deadline to report yet —
        // which is unknown, not "never".
        assert_eq!(expiry("sso"), Expiry::unknown("no cached SSO session"));
        assert!(matches!(expiry("role"), Expiry::Unknown { .. }));
        assert!(matches!(expiry("empty"), Expiry::Unknown { .. }));
        // None of the three non-`At` states is ever reported as a deadline.
        assert!(status.soonest_expiry().is_none());
    }

    #[test]
    fn test_missing_files_are_quiet() {
        let dir = tempfile::tempdir().unwrap();
        let status = AwsProbe::new(Paths::for_test(dir.path())).status().unwrap();
        assert!(!status.installed);
        assert!(status.profiles.is_empty());
        assert!(status.active.is_none());
        assert!(status.notes.is_empty());
    }

    #[test]
    fn test_malformed_config_does_not_fail_the_probe() {
        let fx = Fixture::new();
        fx.write(
            ".aws/config",
            "]]] garbage [[[\nno = section\n[profile ok]\nregion = us-east-1\n",
        );
        let status = fx.probe().status().unwrap();
        let ids: Vec<_> = status.profiles.iter().map(|p| p.id.as_str()).collect();
        assert_eq!(ids, vec!["ok"]);
    }

    // -----------------------------------------------------------------
    // permissions
    // -----------------------------------------------------------------

    impl Fixture {
        fn probe_with(&self, exec: std::sync::Arc<crate::util::FakeExec>) -> AwsProbe {
            AwsProbe::new(Paths::for_test(&self.home).with_exec(exec))
        }
    }

    fn fake(exec: crate::util::FakeExec) -> std::sync::Arc<crate::util::FakeExec> {
        std::sync::Arc::new(exec)
    }

    const USER_ARN: &str = "arn:aws:iam::111122223333:user/alice";
    const AS_USER: &str = r#"{"UserId":"AIDAFAKEFIXTURE","Account":"111122223333","Arn":"arn:aws:iam::111122223333:user/alice"}"#;
    const AS_SSO_ROLE: &str = r#"{"UserId":"AROAFAKEFIXTURE:alice@example.com","Account":"111122223333","Arn":"arn:aws:sts::111122223333:assumed-role/AWSReservedSSO_Admin_1a2b3c/alice@example.com"}"#;

    /// The refusal at the centre of this: listing your own policies is itself a
    /// permission, and most keys are not granted it.
    const LIST_DENIED: &str = "\nAn error occurred (AccessDenied) when calling the ListAttachedUserPolicies operation: User: arn:aws:iam::111122223333:user/alice is not authorized to perform: iam:ListAttachedUserPolicies on resource: user alice because no identity-based policy allows the iam:ListAttachedUserPolicies action\n";

    #[test]
    fn test_aws_offers_no_scope_picker_because_the_identity_is_what_it_is() {
        let fx = Fixture::new();
        let exec = fake(crate::util::FakeExec::new());
        assert!(fx
            .probe_with(exec.clone())
            .permission_scopes()
            .unwrap()
            .is_empty());
        assert!(exec.calls().is_empty());
    }

    #[test]
    fn test_the_attached_and_inline_policies_of_a_user_are_read() {
        let fx = Fixture::new();
        let exec = fake(
            crate::util::FakeExec::new()
                .on("get-caller-identity", true, AS_USER, "")
                .on(
                    "list-attached-user-policies",
                    true,
                    r#"{"AttachedPolicies":[
                         {"PolicyName":"ReadOnlyAccess","PolicyArn":"arn:aws:iam::aws:policy/ReadOnlyAccess"},
                         {"PolicyName":"DeployBot","PolicyArn":"arn:aws:iam::111122223333:policy/DeployBot"}
                       ],"IsTruncated":false}"#,
                    "",
                )
                .on(
                    "list-user-policies",
                    true,
                    r#"{"PolicyNames":["s3-scratch"],"IsTruncated":false}"#,
                    "",
                ),
        );

        let report = fx.probe_with(exec.clone()).permissions().unwrap();
        assert!(report.supported, "{report:?}");
        assert_eq!(report.subject.as_deref(), Some(USER_ARN));
        // Inline is marked, because an inline policy is a different thing from
        // a managed one with the same name.
        assert_eq!(
            report.scopes,
            vec!["DeployBot", "ReadOnlyAccess", "s3-scratch (inline)"]
        );
        assert_eq!(report.scope, None, "aws answers once, for the credential");
        assert!(
            report
                .notes
                .iter()
                .any(|n| n.text.contains("does not evaluate")),
            "{:?}",
            report.notes
        );

        // The path segment is not part of `--user-name`.
        let args = exec.calls()[1].args.clone();
        assert!(args.contains(&"alice".to_string()), "{args:?}");
    }

    #[test]
    fn test_a_user_with_nothing_attached_is_told_about_groups_not_left_blank() {
        let fx = Fixture::new();
        let exec = fake(
            crate::util::FakeExec::new()
                .on("get-caller-identity", true, AS_USER, "")
                .on(
                    "list-attached-user-policies",
                    true,
                    r#"{"AttachedPolicies":[]}"#,
                    "",
                )
                .on("list-user-policies", true, r#"{"PolicyNames":[]}"#, ""),
        );

        let report = fx.probe_with(exec).permissions().unwrap();
        assert!(report.supported);
        assert!(report.scopes.is_empty());
        assert!(
            report.notes.iter().any(|n| n.text.contains("IAM group")),
            "{:?}",
            report.notes
        );
    }

    #[test]
    fn test_a_denied_policy_read_is_reported_as_a_denial_not_as_no_permissions() {
        // The whole point of this probe's honesty: `iam:ListAttachedUserPolicies`
        // is a permission most keys lack, and an empty list would read as "this
        // credential can do nothing", which is the opposite of what is known.
        let fx = Fixture::new();
        let exec = fake(
            crate::util::FakeExec::new()
                .on("get-caller-identity", true, AS_USER, "")
                .on("list-", false, "", LIST_DENIED),
        );

        let report = fx.probe_with(exec).permissions().unwrap();
        assert!(!report.supported, "a refusal is not a reading");
        assert_eq!(
            report.subject.as_deref(),
            Some(USER_ARN),
            "identity resolved"
        );
        assert!(report.scopes.is_empty());
        let notes = report
            .notes
            .iter()
            .map(|n| n.text.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        assert_eq!(notes.lines().count(), 1, "{notes}");
        assert!(notes.contains("iam:ListAttachedUserPolicies"), "{notes}");
        assert!(notes.contains("not readable"), "{notes}");
        // Not a paste of the AWS CLI's own sentence.
        assert!(!notes.contains("An error occurred"), "{notes}");
    }

    #[test]
    fn test_one_refused_call_shrinks_the_answer_rather_than_voiding_it() {
        let fx = Fixture::new();
        let exec = fake(
            crate::util::FakeExec::new()
                .on(
                    "list-attached-user-policies",
                    true,
                    r#"{"AttachedPolicies":[{"PolicyName":"ReadOnlyAccess"}]}"#,
                    "",
                )
                .on("list-user-policies", false, "", LIST_DENIED)
                .on("get-caller-identity", true, AS_USER, ""),
        );

        let report = fx.probe_with(exec).permissions().unwrap();
        assert!(report.supported);
        assert_eq!(report.scopes, vec!["ReadOnlyAccess"]);
        assert!(
            report
                .notes
                .iter()
                .any(|n| n.text.contains("inline policies are missing")
                    && n.text.contains("iam:ListUserPolicies")),
            "{:?}",
            report.notes
        );
    }

    #[test]
    fn test_an_sso_role_is_named_instead_of_being_asked_a_question_it_cannot_answer() {
        let fx = Fixture::new();
        let exec =
            fake(crate::util::FakeExec::new().on("get-caller-identity", true, AS_SSO_ROLE, ""));

        let report = fx.probe_with(exec.clone()).permissions().unwrap();
        assert!(!report.supported);
        assert!(report.subject.unwrap().contains("assumed-role"));
        let notes = report
            .notes
            .iter()
            .map(|n| n.text.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(notes.contains("AWSReservedSSO_Admin_1a2b3c"), "{notes}");
        assert!(notes.contains("no user policies"), "{notes}");
        assert_eq!(
            report.hint.as_deref(),
            Some("aws iam list-attached-role-policies --role-name AWSReservedSSO_Admin_1a2b3c")
        );
        // The call that could not have worked was never made.
        assert_eq!(exec.calls().len(), 1, "{:?}", exec.calls());
    }

    #[test]
    fn test_expired_credentials_are_one_sentence_about_the_credentials() {
        let fx = Fixture::new();
        let exec = fake(crate::util::FakeExec::new().on(
            "get-caller-identity",
            false,
            "",
            "\nAn error occurred (ExpiredToken) when calling the GetCallerIdentity operation: The security token included in the request is expired\n",
        ));

        let report = fx.probe_with(exec.clone()).permissions().unwrap();
        assert!(!report.supported);
        assert!(report.subject.is_none(), "there is no identity to name");
        let notes = report
            .notes
            .iter()
            .map(|n| n.text.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        assert_eq!(notes.lines().count(), 1, "{notes}");
        assert!(notes.contains("expired"), "{notes}");
        assert_eq!(exec.calls().len(), 1, "nothing to list policies for");
    }

    #[test]
    fn test_unparseable_identity_output_degrades_to_a_note() {
        let fx = Fixture::new();
        let exec = fake(crate::util::FakeExec::new().on(
            "get-caller-identity",
            true,
            "you are alice, probably\n",
            "",
        ));

        let report = fx.probe_with(exec).permissions().unwrap();
        assert!(!report.supported);
        assert!(report.scopes.is_empty());
        assert!(
            report
                .notes
                .iter()
                .any(|n| n.text.contains("without an Arn")),
            "{:?}",
            report.notes
        );
    }

    #[test]
    fn test_unparseable_policy_output_degrades_to_a_note() {
        let fx = Fixture::new();
        let exec = fake(
            crate::util::FakeExec::new()
                .on("get-caller-identity", true, AS_USER, "")
                .on("list-", true, "policies, probably\n", ""),
        );

        let report = fx.probe_with(exec).permissions().unwrap();
        assert!(!report.supported);
        let notes = report
            .notes
            .iter()
            .map(|n| n.text.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(notes.contains(USER_ARN), "the identity is still known");
        assert!(notes.contains("not JSON"), "{notes}");
    }

    #[test]
    fn test_without_aws_the_command_is_handed_over() {
        let fx = Fixture::new();
        let report = fx.probe().permissions().unwrap();
        assert!(!report.supported);
        assert_eq!(report.hint.as_deref(), Some("aws sts get-caller-identity"));
    }

    #[test]
    fn test_switch_is_unsupported_with_an_actionable_hint() {
        let dir = tempfile::tempdir().unwrap();
        match AwsProbe::new(Paths::for_test(dir.path()))
            .switch("work")
            .unwrap()
        {
            SwitchOutcome::Unsupported { hint, .. } => {
                assert_eq!(hint.as_deref(), Some("export AWS_PROFILE=work"));
            }
            other => panic!("expected Unsupported, got {other:?}"),
        }
    }
}
