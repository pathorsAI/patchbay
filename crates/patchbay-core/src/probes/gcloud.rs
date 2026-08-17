//! `gcloud` — configurations, credentialed accounts, and the ADC trap.
//!
//! State read (all under `~/.config/gcloud`, or `$CLOUDSDK_CONFIG`):
//!
//! | file | what |
//! |---|---|
//! | `active_config` | plain text: name of the active configuration |
//! | `configurations/config_<name>` | INI: `[core] account/project`, `[compute] region/zone` |
//! | `credentials.db` | SQLite: which accounts have stored credentials |
//! | `application_default_credentials.json` | ADC — a *separate* credential that does not follow configuration switches |
//!
//! Profiles are configurations.
//!
//! **Expiry is deliberately unknown.** `access_tokens.db` is right there and it
//! has a `token_expiry` column, so it looks like the answer — it is not. That
//! column dates a one-hour OAuth access token that gcloud refreshes silently on
//! the next call, so reading it as the profile's expiry marks a perfectly good
//! login "expired 3d" the moment you stop using it, and a login you made *this
//! second* is already inside the board's 24h attention window. What actually
//! ends a gcloud session is the refresh token being revoked or an org
//! reauthentication policy firing, and neither is written to this machine.
//! So `expires_at` stays `None` — unknown, as it genuinely is — and
//! [`Probe::verify_profile`] is what answers "does this still work?".

use std::path::Path;

use rusqlite::{Connection, OpenFlags};

use crate::paths::Paths;
use crate::probe::{unknown_profile, unsupported_switch, unsupported_verify, Probe};
use crate::types::{
    PermissionScope, PermissionsReport, Profile, SwitchOutcome, ToolStatus, VerifyOutcome,
};
use crate::util::{read_text, CmdOutput, Ini};

pub struct GcloudProbe {
    paths: Paths,
}

/// What `application_default_credentials.json` tells us. Never its token.
struct Adc {
    account: Option<String>,
    quota_project: Option<String>,
}

/// Which account a `verify` is actually about — resolved before anything runs.
enum AccountLookup {
    Found {
        account: String,
        credentialed: bool,
    },
    /// The configuration exists but sets no `core/account`.
    NoAccount,
    NoSuchProfile {
        available: Vec<String>,
    },
}

impl GcloudProbe {
    pub const TOOL: &'static str = "gcloud";

    pub fn new(paths: Paths) -> Self {
        Self { paths }
    }

    /// Accounts with stored credentials. Only `account_id` is ever read — the
    /// `value` blob holds the actual refresh token and is never touched.
    fn credentialed_accounts(dir: &Path, notes: &mut Vec<String>) -> Vec<String> {
        let path = dir.join("credentials.db");
        if !path.is_file() {
            return Vec::new();
        }
        match read_key_column(&path, "credentials", "account_id") {
            Ok(rows) => rows,
            Err(e) => {
                notes.push(format!("could not read credentials.db ({e})"));
                Vec::new()
            }
        }
    }

    /// The account a configuration names, and whether it has credentials.
    ///
    /// Both verify paths need this and neither should guess: an id that is not
    /// a configuration, a configuration with no `core/account`, and an account
    /// with nothing in `credentials.db` are three different answers.
    fn account_for(&self, profile_id: &str) -> anyhow::Result<AccountLookup> {
        let status = self.status()?;
        let Some(profile) = status.profiles.iter().find(|p| p.id == profile_id) else {
            return Ok(AccountLookup::NoSuchProfile {
                available: status.profiles.iter().map(|p| p.id.clone()).collect(),
            });
        };
        let Some(account) = profile
            .meta
            .get("account")
            .and_then(|v| v.as_str())
            .map(str::to_string)
        else {
            return Ok(AccountLookup::NoAccount);
        };
        let credentialed =
            profile.meta.get("account_credentialed") != Some(&serde_json::Value::Bool(false));
        Ok(AccountLookup::Found {
            account,
            credentialed,
        })
    }

    /// `core/account` and `core/project` of the active configuration.
    ///
    /// Both permission paths start here: an IAM question is only well-formed
    /// once it names *who* and *where*, and gcloud keeps both in the same INI
    /// file `status` already parses.
    fn active_meta(&self) -> anyhow::Result<(Option<String>, Option<String>)> {
        let status = self.status()?;
        let active = status
            .active
            .as_ref()
            .and_then(|a| status.profiles.iter().find(|p| &p.id == a));
        let meta = |key: &str| {
            active
                .and_then(|p| p.meta.get(key))
                .and_then(|v| v.as_str())
                .map(str::to_string)
        };
        Ok((meta("account"), meta("project")))
    }

    fn read_adc(&self, notes: &mut Vec<String>) -> Option<Adc> {
        let path = self
            .paths
            .gcloud_dir()
            .join("application_default_credentials.json");
        if !path.is_file() {
            return None;
        }
        // Parse only the two identifying fields; client_secret / refresh_token
        // in this file are deliberately never bound to a variable.
        match read_text(&path) {
            Ok(Some(text)) => match serde_json::from_str::<serde_json::Value>(&text) {
                // gcloud writes `"account": ""` for user ADC, so an empty
                // string means "not recorded", not "account named empty".
                Ok(json) => Some(Adc {
                    account: json
                        .get("account")
                        .and_then(|v| v.as_str())
                        .filter(|s| !s.is_empty())
                        .map(str::to_string),
                    quota_project: json
                        .get("quota_project_id")
                        .and_then(|v| v.as_str())
                        .filter(|s| !s.is_empty())
                        .map(str::to_string),
                }),
                Err(_) => {
                    notes.push(
                        "application_default_credentials.json exists but is not valid JSON"
                            .to_string(),
                    );
                    Some(Adc {
                        account: None,
                        quota_project: None,
                    })
                }
            },
            Ok(None) => None,
            Err(e) => {
                notes.push(e);
                Some(Adc {
                    account: None,
                    quota_project: None,
                })
            }
        }
    }
}

impl Probe for GcloudProbe {
    fn tool(&self) -> &'static str {
        Self::TOOL
    }

    fn status(&self) -> anyhow::Result<ToolStatus> {
        let dir = self.paths.gcloud_dir();
        let installed = self.paths.has_binary("gcloud") || dir.is_dir();
        let mut status = ToolStatus::empty(Self::TOOL, installed);
        for note in self.paths.path_notes("gcloud") {
            status.note(note);
        }

        let active = match read_text(&dir.join("active_config")) {
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

        let credentialed = Self::credentialed_accounts(&dir, &mut status.notes);

        // Configurations are the profiles.
        let config_dir = dir.join("configurations");
        let mut used_accounts: Vec<String> = Vec::new();
        if config_dir.is_dir() {
            let mut entries: Vec<_> = std::fs::read_dir(&config_dir)
                .map(|rd| rd.filter_map(Result::ok).collect())
                .unwrap_or_default();
            entries.sort_by_key(|e| e.file_name());

            for entry in entries {
                let file_name = entry.file_name();
                let Some(name) = file_name.to_str().and_then(|n| n.strip_prefix("config_")) else {
                    continue;
                };
                let text = match read_text(&entry.path()) {
                    Ok(Some(text)) => text,
                    Ok(None) => continue,
                    Err(e) => {
                        status.note(e);
                        continue;
                    }
                };
                let ini = Ini::parse(&text);
                let core = ini.section("core");
                let compute = ini.section("compute");
                let account = core.and_then(|s| s.get("account")).map(str::to_string);
                if let Some(account) = &account {
                    used_accounts.push(account.clone());
                }

                // No `.expires_at(...)`: see the module header. gcloud writes no
                // date this machine can read that means "the login stopped
                // working".
                let profile = Profile::new(name)
                    .with_meta("account", account.clone())
                    .with_meta("project", core.and_then(|s| s.get("project")))
                    .with_meta("region", compute.and_then(|s| s.get("region")))
                    .with_meta("zone", compute.and_then(|s| s.get("zone")))
                    .with_meta(
                        "account_credentialed",
                        account
                            .as_ref()
                            .map(|a| credentialed.iter().any(|c| c == a)),
                    );
                status.profiles.push(profile);
            }
        }

        // Say why every row reads "no expiry" — otherwise the honest answer
        // looks like a probe that forgot to fill the field in.
        if !status.profiles.is_empty() {
            status.note(
                "gcloud records no expiry for a login: the token cache in access_tokens.db holds a one-hour access token that refreshes silently, and revocation or an org reauthentication policy is decided server-side — verify a profile to find out whether it still works"
                    .to_string(),
            );
        }

        if let Some(active) = &active {
            if !status.profiles.iter().any(|p| &p.id == active) {
                status.note(format!(
                    "active_config names `{active}` but there is no configurations/config_{active}"
                ));
            }
            // The account the active configuration points at must actually
            // have credentials, or every gcloud call will prompt for login.
            if let Some(profile) = status.profiles.iter().find(|p| &p.id == active) {
                if profile.meta.get("account_credentialed") == Some(&serde_json::Value::Bool(false))
                {
                    let account = profile
                        .meta
                        .get("account")
                        .and_then(|v| v.as_str())
                        .unwrap_or("?");
                    status.note(format!(
                        "active configuration `{active}` uses account {account}, which has no stored credentials (run `gcloud auth login {account}`)"
                    ));
                }
            }
        }
        status.active = active.clone();

        // Credentialed accounts that no configuration points at: available to
        // switch to, but invisible from the configuration list alone.
        let unused: Vec<&String> = credentialed
            .iter()
            .filter(|a| !used_accounts.contains(a))
            .collect();
        if !unused.is_empty() {
            status.note(format!(
                "credentialed accounts not used by any configuration: {}",
                unused
                    .iter()
                    .map(|s| s.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }

        // The ADC trap: a second, independent credential that client libraries,
        // Terraform and most SDKs use — and which `configurations activate`
        // does not touch.
        if let Some(adc) = self.read_adc(&mut status.notes) {
            let mut note = "application default credentials (ADC) exist".to_string();
            if let Some(account) = &adc.account {
                note.push_str(&format!(" for {account}"));
            }
            if let Some(project) = &adc.quota_project {
                note.push_str(&format!(" (quota project {project})"));
            }
            note.push_str(
                "; ADC is separate from the active configuration and does NOT follow `gcloud config configurations activate` — client libraries and Terraform keep using it until you run `gcloud auth application-default login`",
            );
            status.note(note);

            if let (Some(adc_account), Some(active)) = (&adc.account, &status.active) {
                let config_account = status
                    .profiles
                    .iter()
                    .find(|p| &p.id == active)
                    .and_then(|p| p.meta.get("account"))
                    .and_then(|v| v.as_str());
                if let Some(config_account) = config_account {
                    if config_account != adc_account {
                        status.note(format!(
                            "ADC mismatch: configuration `{active}` uses {config_account} but ADC is {adc_account}"
                        ));
                    }
                }
            }
        }

        Ok(status)
    }

    fn switch(&self, profile_id: &str) -> anyhow::Result<SwitchOutcome> {
        let status = self.status()?;
        if !status.profiles.iter().any(|p| p.id == profile_id) {
            return Ok(unknown_profile(Self::TOOL, profile_id, &status));
        }
        if !self.paths.may_exec() {
            return Ok(unsupported_switch(
                Self::TOOL,
                "command execution is disabled for this probe",
                Some(&format!(
                    "gcloud config configurations activate {profile_id}"
                )),
            ));
        }

        let out = self.paths.run(
            "gcloud",
            &["config", "configurations", "activate", profile_id],
        )?;
        if !out.ok {
            return Ok(SwitchOutcome::Failed {
                tool: Self::TOOL.to_string(),
                profile_id: profile_id.to_string(),
                detail: out.message(),
            });
        }

        // Re-read so the caller is told about the ADC state *after* the switch.
        let mut notes = vec![
            "application default credentials do not follow this switch; if you use client libraries, Terraform, or anything reading ADC, run `gcloud auth application-default login` as well".to_string(),
        ];
        if let Ok(after) = self.status() {
            notes.extend(
                after.notes.into_iter().filter(|n| {
                    n.starts_with("ADC mismatch") || n.contains("no stored credentials")
                }),
            );
        }
        Ok(SwitchOutcome::Switched {
            tool: Self::TOOL.to_string(),
            profile_id: profile_id.to_string(),
            detail: format!("gcloud config configurations activate {profile_id}"),
            notes,
        })
    }

    /// The active configuration, checked as itself.
    ///
    /// "verify gcloud" can only mean the configuration that is active, so this
    /// resolves it and hands over to [`Probe::verify_profile`] rather than
    /// running an unattributed check whose answer names no account.
    fn verify(&self) -> anyhow::Result<VerifyOutcome> {
        let status = self.status()?;
        let Some(active) = status.active.clone() else {
            return Ok(unsupported_verify(
                Self::TOOL,
                "no active configuration to verify",
                Some("gcloud config configurations activate <name>"),
            ));
        };
        self.verify_profile(&active)
    }

    /// One configuration, checked as the account *it* names.
    ///
    /// `--account` is the whole point: without it every row on the board asks
    /// about whichever configuration happens to be active, so a broken profile
    /// looks fine and a working one inherits the active profile's failure. The
    /// flag is per-invocation, so checking a profile never activates it.
    fn verify_profile(&self, profile_id: &str) -> anyhow::Result<VerifyOutcome> {
        let (account, credentialed) = match self.account_for(profile_id)? {
            AccountLookup::Found {
                account,
                credentialed,
            } => (account, credentialed),
            AccountLookup::NoSuchProfile { available } => {
                return Ok(unsupported_verify(
                    Self::TOOL,
                    &format!(
                        "no configuration called `{profile_id}`; configurations: {}",
                        available.join(", ")
                    ),
                    Some("gcloud config configurations list"),
                ));
            }
            AccountLookup::NoAccount => {
                return Ok(VerifyOutcome::Invalid {
                    tool: Self::TOOL.to_string(),
                    detail: format!(
                        "configuration `{profile_id}` sets no account, so there is nothing to check — run `gcloud config configurations activate {profile_id} && gcloud auth login`"
                    ),
                });
            }
        };

        // Already answered by tier 1: no row in credentials.db means no
        // credential to mint from, and gcloud would only tell us the same thing
        // a second later and a subprocess more expensively.
        if !credentialed {
            return Ok(VerifyOutcome::Invalid {
                tool: Self::TOOL.to_string(),
                detail: format!(
                    "{account} has no stored credentials on this machine — run `gcloud auth login {account}`"
                ),
            });
        }

        if !self.paths.may_exec() || !self.paths.has_binary("gcloud") {
            return Ok(unsupported_verify(
                Self::TOOL,
                "the gcloud CLI is not available on PATH",
                Some(&format!(
                    "gcloud auth print-access-token --account={account}"
                )),
            ));
        }

        // Mints/refreshes an access token for that one account: the cheapest
        // honest liveness check. The token itself is discarded, never parsed.
        let out = self.paths.run(
            "gcloud",
            &[
                "auth",
                "print-access-token",
                "--account",
                &account,
                "--quiet",
            ],
        )?;
        Ok(if out.ok {
            VerifyOutcome::Valid {
                tool: Self::TOOL.to_string(),
                detail: format!("`{profile_id}` ({account}) minted an access token"),
            }
        } else {
            VerifyOutcome::Invalid {
                tool: Self::TOOL.to_string(),
                detail: auth_failure(&account, &out),
            }
        })
    }

    /// The projects an IAM question can be asked about.
    ///
    /// A Google account has no permissions of its own — the grants live on the
    /// resource, so "what may I do" only becomes a question once a project is
    /// named. This enumerates the ones this login can see, which is what lets
    /// the panel offer a picker instead of a blank where the answer should be.
    ///
    /// Tier 2: it runs `gcloud projects list`, so nothing calls it on the way
    /// in. An empty list is the honest answer to every way this can fail to
    /// enumerate — no gcloud on PATH, a login that cannot list projects — and
    /// [`Probe::permissions`] is what then says why out loud.
    fn permission_scopes(&self) -> anyhow::Result<Vec<PermissionScope>> {
        if !self.paths.may_exec() || !self.paths.has_binary("gcloud") {
            return Ok(Vec::new());
        }
        let (_, active_project) = self.active_meta()?;

        let out = self
            .paths
            .run("gcloud", &["projects", "list", "--format=json", "--quiet"])?;
        let mut scopes: Vec<PermissionScope> = Vec::new();
        if out.ok {
            if let Ok(serde_json::Value::Array(items)) =
                serde_json::from_str::<serde_json::Value>(&out.stdout)
            {
                for item in items {
                    let Some(id) = item.get("projectId").and_then(|v| v.as_str()) else {
                        continue;
                    };
                    // Projects pending deletion are still listed and cannot be
                    // usefully inspected; offering one is offering a dead end.
                    let live = item
                        .get("lifecycleState")
                        .and_then(|v| v.as_str())
                        .is_none_or(|s| s == "ACTIVE");
                    if !live {
                        continue;
                    }
                    let label = item
                        .get("name")
                        .and_then(|v| v.as_str())
                        .filter(|s| !s.is_empty())
                        .unwrap_or(id);
                    scopes.push(PermissionScope {
                        id: id.to_string(),
                        label: label.to_string(),
                        active: active_project.as_deref() == Some(id),
                    });
                }
            }
        }

        // `resourcemanager.projects.list` is a separate grant from being able
        // to read a project you already work in every day, so the configured
        // project can be missing from its own list. It is the one the user is
        // most likely to ask about, so it goes in regardless.
        if let Some(project) = &active_project {
            if !scopes.iter().any(|s| &s.id == project) {
                scopes.insert(
                    0,
                    PermissionScope {
                        id: project.clone(),
                        label: project.clone(),
                        active: true,
                    },
                );
            }
        }
        Ok(scopes)
    }

    /// The active account's IAM roles on one project.
    ///
    /// Note what this is *not*: the roles are read for the account the active
    /// configuration names, on the project named here. Those two are usually
    /// the same project, and deliberately do not have to be — "what would I be
    /// able to do over there" is the question worth being able to ask.
    fn permissions_in(&self, scope_id: &str) -> anyhow::Result<PermissionsReport> {
        let (account, _) = self.active_meta()?;
        let Some(account) = account else {
            return Ok(PermissionsReport::unsupported(
                Self::TOOL,
                "no active configuration with an account, so there is no identity to resolve roles for",
                None,
            ));
        };

        if !self.paths.may_exec() || !self.paths.has_binary("gcloud") {
            // The one honest last resort: with no gcloud to run, patchbay
            // cannot answer, so it hands over the line it would have run. The
            // quoting matters here and only here — this string is for a shell,
            // and unquoted `bindings[].members` is a glob that zsh refuses
            // before gcloud ever starts. The exec path below passes the same
            // values as argv, where no shell ever sees them.
            let mut report = PermissionsReport::unsupported(
                Self::TOOL,
                "the gcloud CLI is not available on PATH, so patchbay cannot read the IAM policy itself",
                Some(&format!(
                    "gcloud projects get-iam-policy {scope_id} --flatten='bindings[].members' --filter='bindings.members:{account}'"
                )),
            );
            report.subject = Some(account);
            report.scope = Some(scope_id.to_string());
            return Ok(report);
        }

        let out = self.paths.run(
            "gcloud",
            &[
                "projects",
                "get-iam-policy",
                scope_id,
                "--flatten=bindings[].members",
                &format!("--filter=bindings.members:{account}"),
                "--format=json",
                "--quiet",
            ],
        )?;
        if !out.ok {
            // A refusal is an answer about this project — "you may not read
            // its policy" is itself a permissions fact — so it comes back as a
            // report naming the project, not as an error that blanks the pane.
            //
            // Through `auth_failure` for the same reason `verify` is: gcloud
            // answers a reauth with four lines of shell instructions, and
            // pasting those into a note is handing back someone else's error
            // instead of an answer.
            let detail = auth_failure(&account, &out);
            return Ok(PermissionsReport {
                tool: Self::TOOL.to_string(),
                supported: false,
                subject: Some(account),
                scopes: Vec::new(),
                notes: vec![format!(
                    "could not read the IAM policy of {scope_id} — {detail}"
                )],
                hint: None,
                scope: Some(scope_id.to_string()),
            });
        }

        let mut roles = match serde_json::from_str::<serde_json::Value>(&out.stdout) {
            Ok(json) => {
                let mut roles = Vec::new();
                collect_roles(&json, &account, &mut roles);
                roles
            }
            Err(e) => {
                return Ok(PermissionsReport {
                    tool: Self::TOOL.to_string(),
                    supported: false,
                    subject: Some(account),
                    scopes: Vec::new(),
                    notes: vec![format!(
                        "gcloud returned something that is not the IAM policy JSON patchbay expects ({e})"
                    )],
                    hint: None,
                    scope: Some(scope_id.to_string()),
                });
            }
        };
        roles.sort();
        roles.dedup();

        let mut notes =
            vec!["project-level bindings only; org/folder inheritance not shown".to_string()];
        if roles.is_empty() {
            notes.push(format!(
                "{account} holds no role granted directly on {scope_id} — it may still reach it through a role inherited from the organisation or folder, or through a group"
            ));
        }
        Ok(PermissionsReport {
            tool: Self::TOOL.to_string(),
            supported: true,
            subject: Some(account),
            scopes: roles,
            notes,
            hint: None,
            scope: Some(scope_id.to_string()),
        })
    }

    /// "What may this login do", with no project named.
    ///
    /// The active configuration already names one, so this resolves it and
    /// hands over to [`Probe::permissions_in`] — the same move
    /// [`Probe::verify`] makes with the active profile. Only a configuration
    /// with no `core/project` has nothing to resolve, and that is the one case
    /// this answers with a "pick one" rather than a reading.
    fn permissions(&self) -> anyhow::Result<PermissionsReport> {
        let (account, project) = self.active_meta()?;
        if let Some(project) = project {
            return self.permissions_in(&project);
        }

        let mut report = PermissionsReport::unsupported(
            Self::TOOL,
            "IAM roles are granted per project, and the active configuration sets no `core/project` — pick a project to read its policy",
            (!self.paths.may_exec() || !self.paths.has_binary("gcloud")).then_some(
                "gcloud projects get-iam-policy <project> --flatten='bindings[].members' --filter='bindings.members:<account>'",
            ),
        );
        report.subject = account;
        Ok(report)
    }
}

/// Every role the JSON grants `account`, at any nesting.
///
/// Two shapes arrive here. `--flatten=bindings[].members` yields one record per
/// (role, member) pair with `bindings` an object; a policy read without it has
/// `bindings` as an array of `{role, members[]}`. Rather than commit to either,
/// this walks for objects carrying a `role` — and where a record still lists
/// its members, checks them, so a role the account does not hold can never be
/// reported as one it does even if the server-side `--filter` were dropped.
fn collect_roles(value: &serde_json::Value, account: &str, out: &mut Vec<String>) {
    match value {
        serde_json::Value::Array(items) => {
            for item in items {
                collect_roles(item, account, out);
            }
        }
        serde_json::Value::Object(map) => {
            if let Some(role) = map.get("role").and_then(|v| v.as_str()) {
                if members_include(map.get("members"), account) {
                    out.push(role.to_string());
                }
            }
            for nested in map.values() {
                collect_roles(nested, account, out);
            }
        }
        _ => {}
    }
}

/// Whether an IAM `members` value names this account.
///
/// Members are prefixed by principal type — `user:a@example.com`,
/// `serviceAccount:…` — so a bare comparison would match nothing. No members
/// field at all means the record did not record them, not that it excludes the
/// account: gcloud's own filter already made that call.
fn members_include(members: Option<&serde_json::Value>, account: &str) -> bool {
    fn one(member: &serde_json::Value, account: &str) -> bool {
        member
            .as_str()
            .is_some_and(|m| m == account || m.ends_with(&format!(":{account}")))
    }
    match members {
        None | Some(serde_json::Value::Null) => true,
        Some(serde_json::Value::Array(items)) => items.iter().any(|m| one(m, account)),
        Some(other) => one(other, account),
    }
}

/// One sentence for a failed `print-access-token`, plus the command that ends
/// it.
///
/// gcloud answers a reauth failure with four lines of shell instructions; the
/// panel joins those into `…non-interactive execution.; Please run:; $ gcloud
/// auth login; to obtain…`, which is a paste of someone else's error, not an
/// answer. The three failures worth naming get named; anything else keeps
/// gcloud's own first line, minus the prefix that only repeats the command
/// patchbay just ran.
fn auth_failure(account: &str, out: &CmdOutput) -> String {
    let text = if out.stderr.trim().is_empty() {
        out.stdout.trim()
    } else {
        out.stderr.trim()
    };
    let lower = text.to_lowercase();

    if lower.contains("reauthentication") || lower.contains("rapt") {
        return format!(
            "{account} needs an interactive re-login: Google asked to reauthenticate and patchbay cannot answer that prompt — run `gcloud auth login {account}`"
        );
    }
    if lower.contains("invalid_grant") || lower.contains("revoked") {
        return format!(
            "{account}'s stored credential was revoked or has expired — run `gcloud auth login {account}`"
        );
    }
    if lower.contains("does not have any valid credentials")
        || lower.contains("do not currently have an active account")
    {
        return format!(
            "{account} has no usable stored credential — run `gcloud auth login {account}`"
        );
    }
    format!("{account}: {}", headline(text))
}

/// gcloud's first meaningful line, without `ERROR: (gcloud.some.command) `.
fn headline(text: &str) -> String {
    let line = text
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .unwrap_or("gcloud failed without saying why");
    let line = line.strip_prefix("ERROR: ").unwrap_or(line);
    match line
        .strip_prefix('(')
        .and_then(|rest| rest.split_once(") "))
    {
        Some((_command, rest)) => rest.trim().to_string(),
        None => line.to_string(),
    }
}

/// Read one column from a SQLite table, defensively.
///
/// The database is opened read-only, and the table and column are checked via
/// `PRAGMA table_info` before querying, so a gcloud schema change degrades to
/// "nothing known" instead of an error. Only the named column is ever selected
/// — the `value` blob beside it in `credentials` is the refresh token.
fn read_key_column(path: &Path, table: &str, key_column: &str) -> rusqlite::Result<Vec<String>> {
    let conn = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI,
    )?;

    let mut columns: Vec<String> = Vec::new();
    {
        let mut stmt = conn.prepare(&format!("PRAGMA table_info(\"{table}\")"))?;
        let rows = stmt.query_map([], |row| row.get::<_, String>(1))?;
        for row in rows {
            columns.push(row?);
        }
    }
    if !columns.iter().any(|c| c == key_column) {
        return Ok(Vec::new());
    }

    let mut stmt = conn.prepare(&format!("SELECT \"{key_column}\" FROM \"{table}\""))?;
    let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;

    let mut out = Vec::new();
    for row in rows {
        out.push(row?);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    /// Builds a fake `~/.config/gcloud`. All credential material in fixtures is
    /// invented — no real token ever appears in this repository.
    struct Fixture {
        _dir: tempfile::TempDir,
        home: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let home = dir.path().to_path_buf();
            fs::create_dir_all(home.join(".config/gcloud/configurations")).unwrap();
            Self { _dir: dir, home }
        }

        fn gcloud(&self) -> PathBuf {
            self.home.join(".config/gcloud")
        }

        fn config(&self, name: &str, body: &str) -> &Self {
            fs::write(
                self.gcloud()
                    .join("configurations")
                    .join(format!("config_{name}")),
                body,
            )
            .unwrap();
            self
        }

        fn active(&self, name: &str) -> &Self {
            fs::write(self.gcloud().join("active_config"), format!("{name}\n")).unwrap();
            self
        }

        fn credentials_db(&self, accounts: &[&str]) -> &Self {
            let conn = Connection::open(self.gcloud().join("credentials.db")).unwrap();
            conn.execute(
                "CREATE TABLE credentials (account_id TEXT PRIMARY KEY, value BLOB)",
                [],
            )
            .unwrap();
            for account in accounts {
                conn.execute(
                    "INSERT INTO credentials VALUES (?1, ?2)",
                    rusqlite::params![account, "fake-not-a-real-credential"],
                )
                .unwrap();
            }
            self
        }

        fn tokens_db(&self, rows: &[(&str, &str)]) -> &Self {
            let conn = Connection::open(self.gcloud().join("access_tokens.db")).unwrap();
            conn.execute(
                "CREATE TABLE access_tokens (account_id TEXT PRIMARY KEY, access_token TEXT, token_expiry TIMESTAMP)",
                [],
            )
            .unwrap();
            for (account, expiry) in rows {
                conn.execute(
                    "INSERT INTO access_tokens VALUES (?1, ?2, ?3)",
                    rusqlite::params![account, "fake-access-token", expiry],
                )
                .unwrap();
            }
            self
        }

        fn probe(&self) -> GcloudProbe {
            GcloudProbe::new(Paths::for_test(&self.home))
        }
    }

    #[test]
    fn test_happy_path_configurations_and_accounts() {
        let fx = Fixture::new();
        fx.config(
            "default",
            "[core]\naccount = a@example.com\nproject = proj-a\n",
        )
        .config(
            "work",
            "[core]\naccount = b@example.com\nproject = proj-b\n\n[compute]\nregion = asia-east1\nzone = asia-east1-b\n",
        )
        .active("work")
        .credentials_db(&["a@example.com", "b@example.com"])
        .tokens_db(&[("b@example.com", "2030-01-02 03:04:05.123456")]);

        let status = fx.probe().status().unwrap();
        assert_eq!(status.active.as_deref(), Some("work"));
        assert_eq!(status.profiles.len(), 2);

        let work = status.profiles.iter().find(|p| p.id == "work").unwrap();
        assert_eq!(work.meta["account"], "b@example.com");
        assert_eq!(work.meta["project"], "proj-b");
        assert_eq!(work.meta["region"], "asia-east1");
        assert_eq!(work.meta["account_credentialed"], true);
    }

    #[test]
    fn test_the_hourly_token_cache_is_never_reported_as_the_login_expiring() {
        // The regression this guards: `access_tokens.db` dates a one-hour
        // access token. Read as the profile's expiry it marks a working login
        // "expired 15h" the moment you stop running gcloud for an afternoon,
        // and — because a *fresh* token is one hour out — parks the whole tool
        // inside the board's 24h attention window permanently.
        let fx = Fixture::new();
        fx.config("work", "[core]\naccount = b@example.com\n")
            .active("work")
            .credentials_db(&["b@example.com"])
            .tokens_db(&[("b@example.com", "2000-01-02 03:04:05.123456")]);

        let status = fx.probe().status().unwrap();
        let work = status.profiles.iter().find(|p| p.id == "work").unwrap();
        assert!(work.expires_at.is_none());
        assert_eq!(
            status.connection_state(),
            crate::types::ConnectionState::Connected
        );
        assert!(
            status.notes.iter().any(|n| n.contains("records no expiry")),
            "{:?}",
            status.notes
        );
    }

    #[test]
    fn test_adc_note_is_always_raised_and_mismatch_is_called_out() {
        let fx = Fixture::new();
        fx.config("work", "[core]\naccount = b@example.com\n")
            .active("work");
        fs::write(
            fx.gcloud().join("application_default_credentials.json"),
            r#"{"account":"other@example.com","quota_project_id":"proj-q","type":"authorized_user","refresh_token":"fake-fixture-value"}"#,
        )
        .unwrap();

        let status = fx.probe().status().unwrap();
        let notes = status.notes.join("\n");
        assert!(notes.contains("ADC"), "{notes}");
        assert!(notes.contains("proj-q"), "{notes}");
        assert!(notes.contains("does NOT follow"), "{notes}");
        assert!(notes.contains("ADC mismatch"), "{notes}");
        // Never leak the credential itself.
        assert!(!notes.contains("fake-fixture-value"), "{notes}");
    }

    #[test]
    fn test_adc_with_an_empty_account_field_does_not_claim_a_mismatch() {
        // Real user ADC files carry `"account": ""`; that means "not recorded",
        // and must not render as `ADC is ` or a false mismatch.
        let fx = Fixture::new();
        fx.config("work", "[core]\naccount = b@example.com\n")
            .active("work");
        fs::write(
            fx.gcloud().join("application_default_credentials.json"),
            r#"{"account":"","client_id":"fake","refresh_token":"fake-fixture-value","type":"authorized_user"}"#,
        )
        .unwrap();

        let status = fx.probe().status().unwrap();
        let notes = status.notes.join("\n");
        assert!(notes.contains("(ADC) exist;"), "{notes}");
        assert!(!notes.contains("ADC mismatch"), "{notes}");
        assert!(!notes.contains("exist for "), "{notes}");
    }

    #[test]
    fn test_missing_everything_is_not_installed_and_not_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let probe = GcloudProbe::new(Paths::for_test(dir.path()));
        let status = probe.status().unwrap();
        assert!(!status.installed);
        assert!(status.profiles.is_empty());
        assert!(status.active.is_none());
        assert!(status.notes.is_empty());
    }

    #[test]
    fn test_malformed_files_degrade_to_notes() {
        let fx = Fixture::new();
        fx.config("broken", "this is not ini\n\0\0").active("ghost");
        // A corrupt SQLite file must not take the board down.
        fs::write(fx.gcloud().join("credentials.db"), b"not a database").unwrap();
        fs::write(fx.gcloud().join("access_tokens.db"), b"not a database").unwrap();

        let status = fx.probe().status().unwrap();
        assert_eq!(status.active.as_deref(), Some("ghost"));
        let notes = status.notes.join("\n");
        assert!(notes.contains("no configurations/config_ghost"), "{notes}");
        assert!(notes.contains("credentials.db"), "{notes}");
        // The unparseable config still shows up, just with no metadata.
        let broken = status.profiles.iter().find(|p| p.id == "broken").unwrap();
        assert!(broken.meta.get("account").is_none());
    }

    #[test]
    fn test_schema_drift_in_credentials_degrades_instead_of_erroring() {
        let fx = Fixture::new();
        fx.config("work", "[core]\naccount = b@example.com\n")
            .active("work");
        // The table is there but gcloud renamed the column out from under us.
        let conn = Connection::open(fx.gcloud().join("credentials.db")).unwrap();
        conn.execute(
            "CREATE TABLE credentials (id TEXT PRIMARY KEY, value BLOB)",
            [],
        )
        .unwrap();
        drop(conn);

        let status = fx.probe().status().unwrap();
        let work = status.profiles.iter().find(|p| p.id == "work").unwrap();
        assert_eq!(work.meta["account_credentialed"], false);
    }

    #[test]
    fn test_active_account_without_credentials_is_flagged() {
        let fx = Fixture::new();
        fx.config("work", "[core]\naccount = ghost@example.com\n")
            .active("work")
            .credentials_db(&["someone@example.com"]);

        let status = fx.probe().status().unwrap();
        let notes = status.notes.join("\n");
        assert!(notes.contains("no stored credentials"), "{notes}");
        assert!(notes.contains("not used by any configuration"), "{notes}");
    }

    /// A fixture with two configurations and one of them active — the shape the
    /// per-profile verify bug hid in.
    fn two_configs() -> Fixture {
        let fx = Fixture::new();
        fx.config("default", "[core]\naccount = a@example.com\n")
            .config("work", "[core]\naccount = b@example.com\n")
            .active("work")
            .credentials_db(&["a@example.com", "b@example.com"]);
        fx
    }

    fn probe_with(fx: &Fixture, exec: std::sync::Arc<crate::util::FakeExec>) -> GcloudProbe {
        GcloudProbe::new(Paths::for_test(&fx.home).with_exec(exec))
    }

    #[test]
    fn test_verify_profile_checks_that_profiles_account_not_the_active_one() {
        let fx = two_configs();
        let exec = std::sync::Arc::new(crate::util::FakeExec::new().on("", true, "fake-token", ""));
        // `default` is not active: before --account, this asked about work's
        // account and filed the answer under default's row.
        let outcome = probe_with(&fx, exec.clone())
            .verify_profile("default")
            .unwrap();

        let call = exec.last().unwrap();
        assert!(
            call.args.contains(&"--account".to_string())
                && call.args.contains(&"a@example.com".to_string()),
            "{:?}",
            call.args
        );
        match outcome {
            VerifyOutcome::Valid { detail, .. } => assert!(detail.contains("a@example.com")),
            other => panic!("expected Valid, got {other:?}"),
        }
    }

    #[test]
    fn test_tool_level_verify_resolves_the_active_configuration() {
        let fx = two_configs();
        let exec = std::sync::Arc::new(crate::util::FakeExec::new().on("", true, "fake-token", ""));
        let outcome = probe_with(&fx, exec.clone()).verify().unwrap();

        assert!(exec
            .last()
            .unwrap()
            .args
            .contains(&"b@example.com".to_string()));
        match outcome {
            VerifyOutcome::Valid { detail, .. } => {
                assert!(
                    detail.contains("work") && detail.contains("b@example.com"),
                    "{detail}"
                );
            }
            other => panic!("expected Valid, got {other:?}"),
        }
    }

    #[test]
    fn test_a_reauth_failure_becomes_one_sentence_and_the_command_that_ends_it() {
        let fx = two_configs();
        // gcloud's real answer, verbatim: four lines of shell instructions.
        let stderr = "ERROR: (gcloud.auth.print-access-token) There was a problem refreshing your current auth tokens: Reauthentication failed. cannot prompt during non-interactive execution.\nPlease run:\n\n  $ gcloud auth login\n\nto obtain new credentials.\n";
        let exec = std::sync::Arc::new(crate::util::FakeExec::new().on("", false, "", stderr));
        match probe_with(&fx, exec).verify_profile("work").unwrap() {
            VerifyOutcome::Invalid { detail, .. } => {
                assert!(detail.contains("b@example.com"), "{detail}");
                assert!(
                    detail.contains("gcloud auth login b@example.com"),
                    "{detail}"
                );
                // Not a paste of someone else's error.
                assert!(!detail.contains("ERROR:"), "{detail}");
                assert!(!detail.contains("Please run"), "{detail}");
                assert_eq!(detail.lines().count(), 1, "{detail}");
            }
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    #[test]
    fn test_an_uncredentialed_account_is_answered_without_running_anything() {
        let fx = Fixture::new();
        fx.config("ghost", "[core]\naccount = ghost@example.com\n")
            .active("ghost")
            .credentials_db(&["someone@example.com"]);
        let exec = std::sync::Arc::new(crate::util::FakeExec::new());

        match probe_with(&fx, exec.clone())
            .verify_profile("ghost")
            .unwrap()
        {
            VerifyOutcome::Invalid { detail, .. } => {
                assert!(
                    detail.contains("gcloud auth login ghost@example.com"),
                    "{detail}"
                );
            }
            other => panic!("expected Invalid, got {other:?}"),
        }
        assert!(exec.calls().is_empty(), "tier 1 already knew the answer");
    }

    #[test]
    fn test_verify_of_an_unknown_configuration_lists_the_real_ones() {
        let fx = two_configs();
        let exec = std::sync::Arc::new(crate::util::FakeExec::new());
        match probe_with(&fx, exec).verify_profile("nope").unwrap() {
            VerifyOutcome::Unsupported { reason, .. } => {
                assert!(
                    reason.contains("default") && reason.contains("work"),
                    "{reason}"
                );
            }
            other => panic!("expected Unsupported, got {other:?}"),
        }
    }

    /// A configuration with a project, an account, and credentials — the shape
    /// every IAM question is asked from.
    fn with_project() -> Fixture {
        let fx = Fixture::new();
        fx.config(
            "work",
            "[core]\naccount = b@example.com\nproject = proj-b\n",
        )
        .active("work")
        .credentials_db(&["b@example.com"]);
        fx
    }

    /// The policy `gcloud projects get-iam-policy --flatten=bindings[].members
    /// --format=json` actually prints: one record per (role, member) pair.
    const FLATTENED_POLICY: &str = r#"[
      {"bindings": {"members": "user:b@example.com", "role": "roles/viewer"},
       "etag": "BwXyz", "version": 1},
      {"bindings": {"members": "user:b@example.com", "role": "roles/run.admin"},
       "etag": "BwXyz", "version": 1}
    ]"#;

    #[test]
    fn test_permissions_without_gcloud_falls_back_to_a_shell_safe_line() {
        // The one case a copyable command is the honest answer: nothing to run.
        let fx = with_project();

        let report = fx.probe().permissions().unwrap();
        let hint = report.hint.unwrap();
        assert_eq!(report.subject.as_deref(), Some("b@example.com"));
        assert_eq!(report.scope.as_deref(), Some("proj-b"));
        assert!(
            hint.contains("proj-b") && hint.contains("b@example.com"),
            "{hint}"
        );
        assert!(!hint.contains('<'), "{hint}");
        // Unquoted, `bindings[].members` is a glob and zsh refuses to run it.
        assert!(hint.contains("--flatten='bindings[].members'"), "{hint}");
    }

    #[test]
    fn test_permission_scopes_lists_projects_and_flags_the_configured_one() {
        let fx = with_project();
        let exec = std::sync::Arc::new(crate::util::FakeExec::new().on(
            "projects list",
            true,
            r#"[
              {"projectId": "proj-a", "name": "Alpha", "lifecycleState": "ACTIVE"},
              {"projectId": "proj-b", "name": "Beta", "lifecycleState": "ACTIVE"},
              {"projectId": "proj-dead", "name": "Gone", "lifecycleState": "DELETE_REQUESTED"}
            ]"#,
            "",
        ));

        let scopes = probe_with(&fx, exec).permission_scopes().unwrap();
        let ids: Vec<&str> = scopes.iter().map(|s| s.id.as_str()).collect();
        // A project pending deletion is a dead end, not a choice.
        assert_eq!(ids, vec!["proj-a", "proj-b"], "{scopes:?}");
        assert_eq!(scopes[1].label, "Beta");
        assert!(
            scopes[1].active,
            "the configured project is the default one"
        );
        assert!(!scopes[0].active);
    }

    #[test]
    fn test_the_configured_project_is_offered_even_when_it_is_not_listable() {
        // `resourcemanager.projects.list` is its own grant: an account can work
        // in a project every day and never see it in `projects list`.
        let fx = with_project();
        let exec = std::sync::Arc::new(crate::util::FakeExec::new().on(
            "projects list",
            true,
            r#"[{"projectId": "proj-a", "name": "Alpha", "lifecycleState": "ACTIVE"}]"#,
            "",
        ));

        let scopes = probe_with(&fx, exec).permission_scopes().unwrap();
        let configured = scopes.iter().find(|s| s.id == "proj-b").expect("proj-b");
        assert!(configured.active);
    }

    #[test]
    fn test_a_probe_with_no_scope_reader_reports_none_and_ignores_the_scope() {
        // The 24 probes that never opted in: `permission_scopes` is empty, and
        // `permissions_in` is `permissions` with the argument thrown away, so
        // a scoped caller cannot get a different (or worse, a wrong) answer.
        let dir = tempfile::tempdir().unwrap();
        let probe = crate::probes::gh::GhProbe::new(Paths::for_test(dir.path()));
        assert!(probe.permission_scopes().unwrap().is_empty());
        assert_eq!(
            probe.permissions_in("anything-at-all").unwrap(),
            probe.permissions().unwrap()
        );
    }

    #[test]
    fn test_permissions_reads_the_active_projects_roles_rather_than_handing_over_a_command() {
        let fx = with_project();
        let exec = std::sync::Arc::new(crate::util::FakeExec::new().on(
            "get-iam-policy",
            true,
            FLATTENED_POLICY,
            "",
        ));

        let report = probe_with(&fx, exec.clone()).permissions().unwrap();
        assert!(report.supported);
        assert_eq!(report.subject.as_deref(), Some("b@example.com"));
        assert_eq!(report.scope.as_deref(), Some("proj-b"));
        assert_eq!(report.scopes, vec!["roles/run.admin", "roles/viewer"]);
        // The panel operates the tool; it does not hand out a line to paste.
        assert_eq!(report.hint, None);
        assert!(
            report.notes.iter().any(|n| n.contains("org/folder")),
            "{:?}",
            report.notes
        );

        // No shell is involved, so the filter goes as one argv item, unquoted.
        let call = exec.last().unwrap();
        assert!(
            call.args
                .contains(&"--flatten=bindings[].members".to_string()),
            "{:?}",
            call.args
        );
        assert!(
            call.args
                .contains(&"--filter=bindings.members:b@example.com".to_string()),
            "{:?}",
            call.args
        );
        assert!(call.args.contains(&"proj-b".to_string()), "{:?}", call.args);
    }

    #[test]
    fn test_permissions_in_reads_a_project_other_than_the_configured_one() {
        let fx = with_project();
        let exec = std::sync::Arc::new(crate::util::FakeExec::new().on(
            "get-iam-policy",
            true,
            r#"[{"bindings": {"members": "user:b@example.com", "role": "roles/owner"}}]"#,
            "",
        ));

        let report = probe_with(&fx, exec.clone())
            .permissions_in("other-project")
            .unwrap();
        assert_eq!(report.scope.as_deref(), Some("other-project"));
        assert_eq!(report.scopes, vec!["roles/owner"]);
        assert!(exec
            .last()
            .unwrap()
            .args
            .contains(&"other-project".to_string()));
    }

    #[test]
    fn test_a_role_held_by_somebody_else_is_never_reported_as_yours() {
        // Belt and braces over gcloud's own `--filter`: the member list decides.
        let fx = with_project();
        let exec = std::sync::Arc::new(crate::util::FakeExec::new().on(
            "get-iam-policy",
            true,
            r#"[
              {"bindings": {"members": ["user:b@example.com"], "role": "roles/viewer"}},
              {"bindings": {"members": ["user:someone-else@example.com"], "role": "roles/owner"}}
            ]"#,
            "",
        ));

        let report = probe_with(&fx, exec).permissions_in("proj-b").unwrap();
        assert_eq!(report.scopes, vec!["roles/viewer"]);
    }

    #[test]
    fn test_no_direct_binding_is_answered_as_a_fact_not_as_an_empty_pane() {
        let fx = with_project();
        let exec =
            std::sync::Arc::new(crate::util::FakeExec::new().on("get-iam-policy", true, "[]", ""));

        let report = probe_with(&fx, exec).permissions_in("proj-b").unwrap();
        assert!(report.supported);
        assert!(report.scopes.is_empty());
        assert!(
            report.notes.iter().any(|n| n.contains("no role granted")),
            "{:?}",
            report.notes
        );
    }

    #[test]
    fn test_a_refused_iam_read_is_a_report_about_that_project_not_an_error() {
        let fx = with_project();
        let stderr = "ERROR: (gcloud.projects.get-iam-policy) User [b@example.com] does not have permission to access projects instance [proj-b] (or it may not exist): Policy retrieval failed.\n";
        let exec = std::sync::Arc::new(crate::util::FakeExec::new().on(
            "get-iam-policy",
            false,
            "",
            stderr,
        ));

        let report = probe_with(&fx, exec).permissions_in("proj-b").unwrap();
        assert!(!report.supported);
        assert_eq!(report.scope.as_deref(), Some("proj-b"));
        assert!(report.scopes.is_empty());
        let notes = report.notes.join("\n");
        assert!(notes.contains("proj-b"), "{notes}");
        assert!(notes.contains("does not have permission"), "{notes}");
        // gcloud's own `ERROR: (command)` prefix only repeats what we ran.
        assert!(!notes.contains("ERROR:"), "{notes}");
    }

    #[test]
    fn test_a_reauth_during_an_iam_read_is_one_sentence_not_four_lines_of_shell() {
        // The same four-line answer `verify` already flattens. Pasting it into
        // a note would be handing back someone else's error, not an answer.
        let fx = with_project();
        let stderr = "ERROR: (gcloud.projects.get-iam-policy) There was a problem refreshing your current auth tokens: Reauthentication failed. cannot prompt during non-interactive execution.\nPlease run:\n\n  $ gcloud auth login\n\nto obtain new credentials.\n";
        let exec = std::sync::Arc::new(crate::util::FakeExec::new().on(
            "get-iam-policy",
            false,
            "",
            stderr,
        ));

        let report = probe_with(&fx, exec).permissions_in("proj-b").unwrap();
        let notes = report.notes.join("\n");
        assert_eq!(notes.lines().count(), 1, "{notes}");
        assert!(notes.contains("proj-b"), "{notes}");
        assert!(notes.contains("gcloud auth login b@example.com"), "{notes}");
        assert!(!notes.contains("Please run"), "{notes}");
    }

    #[test]
    fn test_unparseable_iam_output_degrades_to_a_note() {
        let fx = with_project();
        let exec = std::sync::Arc::new(crate::util::FakeExec::new().on(
            "get-iam-policy",
            true,
            "Updated IAM policy, probably",
            "",
        ));

        let report = probe_with(&fx, exec).permissions_in("proj-b").unwrap();
        assert!(!report.supported);
        assert!(report.scopes.is_empty());
        assert!(!report.notes.is_empty());
    }

    #[test]
    fn test_a_configuration_with_no_project_asks_for_one_instead_of_guessing() {
        let fx = Fixture::new();
        fx.config("work", "[core]\naccount = b@example.com\n")
            .active("work")
            .credentials_db(&["b@example.com"]);
        let exec = std::sync::Arc::new(crate::util::FakeExec::new());

        let report = probe_with(&fx, exec.clone()).permissions().unwrap();
        assert!(!report.supported);
        assert!(
            report.notes.iter().any(|n| n.contains("pick a project")),
            "{:?}",
            report.notes
        );
        // gcloud is available, so there is nothing to paste — the picker is it.
        assert_eq!(report.hint, None);
        assert!(exec.calls().is_empty(), "nothing to read a policy for");
    }

    #[test]
    fn test_switch_to_unknown_profile_lists_the_real_ones() {
        let fx = Fixture::new();
        fx.config("work", "[core]\naccount = b@example.com\n");
        match fx.probe().switch("nope").unwrap() {
            SwitchOutcome::UnknownProfile { available, .. } => {
                assert_eq!(available, vec!["work".to_string()]);
            }
            other => panic!("expected UnknownProfile, got {other:?}"),
        }
    }
}
