//! `az` — Azure subscriptions from `~/.azure/azureProfile.json`.
//!
//! Profiles are subscriptions (id = subscription id), and the one with
//! `isDefault` is active. Azure writes this file with a UTF-8 BOM, which
//! [`read_text`] strips.
//!
//! Tokens live in a separate MSAL cache (keychain-backed on macOS), so every
//! subscription's expiry is [`Expiry::Unknown`] — there is a deadline, it is
//! simply not written anywhere this probe reads. That is the whole of what the
//! probe used to say in a note.

use serde::Deserialize;

use crate::paths::Paths;
use crate::probe::{exec_disabled_switch, unknown_profile, Probe};
use crate::types::{
    Expiry, Note, PermissionScope, PermissionsReport, Profile, SwitchOutcome, ToolStatus,
    VerifyOutcome,
};
use crate::util::{read_text, CmdOutput};

pub struct AzProbe {
    paths: Paths,
}

#[derive(Deserialize)]
struct AzureProfile {
    #[serde(default)]
    subscriptions: Vec<Subscription>,
}

#[derive(Deserialize)]
struct Subscription {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    state: Option<String>,
    #[serde(default, rename = "isDefault")]
    is_default: bool,
    #[serde(default, rename = "tenantId")]
    tenant_id: Option<String>,
    #[serde(default, rename = "tenantDefaultDomain")]
    tenant_default_domain: Option<String>,
    #[serde(default, rename = "environmentName")]
    environment_name: Option<String>,
    #[serde(default)]
    user: Option<User>,
}

#[derive(Deserialize)]
struct User {
    #[serde(default)]
    name: Option<String>,
    #[serde(default, rename = "type")]
    kind: Option<String>,
}

impl AzProbe {
    pub const TOOL: &'static str = "az";

    pub fn new(paths: Paths) -> Self {
        Self { paths }
    }

    /// Accept a subscription id or its display name — humans and agents both
    /// tend to reach for the name.
    fn resolve(status: &ToolStatus, profile_id: &str) -> Option<String> {
        status
            .profiles
            .iter()
            .find(|p| p.id == profile_id)
            .or_else(|| {
                status
                    .profiles
                    .iter()
                    .find(|p| p.label.eq_ignore_ascii_case(profile_id))
            })
            .map(|p| p.id.clone())
    }
}

impl Probe for AzProbe {
    fn tool(&self) -> &'static str {
        Self::TOOL
    }

    fn status(&self) -> anyhow::Result<ToolStatus> {
        let path = self.paths.azure_profile();
        let installed = self.paths.has_binary("az") || path.is_file();
        let mut status = ToolStatus::empty(Self::TOOL, installed);
        for note in self.paths.path_notes("azure") {
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

        let profile: AzureProfile = match serde_json::from_str(&text) {
            Ok(profile) => profile,
            Err(e) => {
                status.problem(format!("azureProfile.json is not valid JSON ({e})"));
                return Ok(status);
            }
        };

        let mut disabled = Vec::new();
        for subscription in profile.subscriptions {
            let Some(id) = subscription.id else { continue };
            let name = subscription.name.clone().unwrap_or_else(|| id.clone());
            if subscription
                .state
                .as_deref()
                .is_some_and(|s| !s.eq_ignore_ascii_case("Enabled"))
            {
                disabled.push(name.clone());
            }
            if subscription.is_default {
                status.active = Some(id.clone());
            }
            status.profiles.push(
                Profile::new(&id)
                    .label(&name)
                    .expiry(Expiry::unknown("in the Azure MSAL cache"))
                    .with_meta(
                        "user",
                        subscription.user.as_ref().and_then(|u| u.name.clone()),
                    )
                    .with_meta(
                        "user_type",
                        subscription.user.as_ref().and_then(|u| u.kind.clone()),
                    )
                    .with_meta("state", subscription.state.clone())
                    .with_meta("tenant_id", subscription.tenant_id.clone())
                    .with_meta("tenant_domain", subscription.tenant_default_domain.clone())
                    .with_meta("environment", subscription.environment_name.clone()),
            );
        }

        if !status.profiles.is_empty() {
            if status.active.is_none() {
                status.warn(
                    "no subscription is marked as default; `az` commands will need --subscription",
                );
            }
            if !disabled.is_empty() {
                status.warn(format!(
                    "subscriptions not in the Enabled state: {}",
                    disabled.join(", ")
                ));
            }
        }

        Ok(status)
    }

    fn switch(&self, profile_id: &str) -> anyhow::Result<SwitchOutcome> {
        let status = self.status()?;
        let Some(id) = Self::resolve(&status, profile_id) else {
            return Ok(unknown_profile(Self::TOOL, profile_id, &status));
        };
        if !self.paths.may_exec() {
            return Ok(exec_disabled_switch(
                Self::TOOL,
                Some(&format!("az account set --subscription {id}")),
            ));
        }

        let out = self
            .paths
            .run("az", &["account", "set", "--subscription", &id])?;
        Ok(if out.ok {
            SwitchOutcome::Switched {
                tool: Self::TOOL.to_string(),
                profile_id: id.clone(),
                detail: format!("az account set --subscription {id}"),
                notes: vec![
                    "this changes the default subscription only; the signed-in account and tenant are unchanged".to_string(),
                ],
            }
        } else {
            SwitchOutcome::Failed {
                tool: Self::TOOL.to_string(),
                profile_id: id,
                detail: out.message(),
            }
        })
    }

    fn verify(&self) -> anyhow::Result<VerifyOutcome> {
        if !self.paths.may_exec() || !self.paths.has_binary("az") {
            return Ok(crate::probe::unsupported_verify(
                Self::TOOL,
                "the az CLI is not available on PATH",
                Some("az account get-access-token"),
            ));
        }
        // `--output none` keeps the minted token off stdout entirely.
        let out = self
            .paths
            .run("az", &["account", "get-access-token", "--output", "none"])?;
        Ok(if out.ok {
            VerifyOutcome::Valid {
                tool: Self::TOOL.to_string(),
                detail: "the active subscription minted an access token".to_string(),
            }
        } else {
            VerifyOutcome::Invalid {
                tool: Self::TOOL.to_string(),
                detail: out.message(),
            }
        })
    }

    /// The subscriptions an RBAC question can be asked about.
    ///
    /// Unlike gcloud's, this list costs nothing: `azureProfile.json` already
    /// holds every subscription this login has been shown, and
    /// [`Probe::status`] already parses it. So the picker fills in without a
    /// subprocess, without the network, and — the part that matters — without
    /// needing whatever grant would let the account enumerate them live.
    fn permission_scopes(&self) -> anyhow::Result<Vec<PermissionScope>> {
        let status = self.status()?;
        Ok(status
            .profiles
            .iter()
            .map(|profile| PermissionScope {
                id: profile.id.clone(),
                label: profile.label.clone(),
                active: status.active.as_ref() == Some(&profile.id),
            })
            .collect())
    }

    /// The signed-in user's role assignments in one subscription.
    ///
    /// `--all` is what makes this honest rather than flattering: without it the
    /// answer is only the assignments made *on the subscription itself*, and a
    /// Contributor on one resource group would come back as holding nothing.
    /// With it, the narrower grants arrive too — and are labelled with the
    /// scope they are actually on, because "Contributor" on one resource group
    /// is a very different fact from "Contributor" across the subscription.
    fn permissions_in(&self, scope_id: &str) -> anyhow::Result<PermissionsReport> {
        let status = self.status()?;
        let Some(subscription) = Self::resolve(&status, scope_id) else {
            let mut report = PermissionsReport::unsupported(
                Self::TOOL,
                &format!(
                    "`{scope_id}` is not a subscription this machine is signed in to; known subscriptions: {}",
                    status
                        .profiles
                        .iter()
                        .map(|p| p.label.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
                Some("az account list --refresh --output table"),
            );
            report.scope = Some(scope_id.to_string());
            return Ok(report);
        };
        let profile = status.profiles.iter().find(|p| p.id == subscription);
        let label = profile
            .map(|p| p.label.clone())
            .unwrap_or_else(|| subscription.clone());
        let user = profile
            .and_then(|p| p.meta.get("user"))
            .and_then(|v| v.as_str())
            .map(str::to_string);

        let Some(user) = user else {
            let mut report = PermissionsReport::unsupported(
                Self::TOOL,
                &format!(
                    "`{label}` records no signed-in user, so there is no identity to resolve role assignments for"
                ),
                Some("az login"),
            );
            report.scope = Some(subscription);
            return Ok(report);
        };

        if !self.paths.may_exec() || !self.paths.has_binary("az") {
            let mut report = PermissionsReport::unsupported(
                Self::TOOL,
                "the az CLI is not available on PATH, so patchbay cannot read the role assignments itself",
                Some(&format!(
                    "az role assignment list --assignee {user} --subscription {subscription} --all --include-inherited"
                )),
            );
            report.subject = Some(user);
            report.scope = Some(subscription);
            return Ok(report);
        }

        // `--only-show-errors` keeps az's upgrade nag and its Microsoft Graph
        // warnings off stderr, so what is left there is the actual failure.
        let out = self.paths.run(
            "az",
            &[
                "role",
                "assignment",
                "list",
                "--assignee",
                &user,
                "--subscription",
                &subscription,
                "--all",
                "--include-inherited",
                "--output",
                "json",
                "--only-show-errors",
            ],
        )?;

        let report = |supported: bool, scopes: Vec<String>, notes: Vec<Note>| PermissionsReport {
            tool: Self::TOOL.to_string(),
            supported,
            subject: Some(user.clone()),
            scopes,
            notes,
            hint: None,
            scope: Some(subscription.clone()),
        };

        if !out.ok {
            return Ok(report(
                false,
                Vec::new(),
                vec![Note::problem(az_failure(&user, &label, &out))],
            ));
        }

        let Ok(serde_json::Value::Array(items)) =
            serde_json::from_str::<serde_json::Value>(&out.stdout)
        else {
            return Ok(report(
                false,
                Vec::new(),
                vec![Note::problem(format!(
                    "az returned something that is not the role assignment list patchbay expects, so the roles in `{label}` could not be read"
                ))],
            ));
        };

        let mut roles = Vec::new();
        let mut narrower = false;
        let mut inherited = false;
        for item in items {
            let Some(role) = item
                .get("roleDefinitionName")
                .and_then(|v| v.as_str())
                .filter(|r| !r.is_empty())
            else {
                continue;
            };
            let scope = item.get("scope").and_then(|v| v.as_str()).unwrap_or("");
            match narrower_scope(scope, &subscription) {
                None => roles.push(role.to_string()),
                Some(where_) => {
                    if where_.starts_with("management group") || where_ == "the tenant root" {
                        inherited = true;
                    } else {
                        narrower = true;
                    }
                    roles.push(format!("{role} on {where_}"));
                }
            }
        }
        roles.sort();
        roles.dedup();

        let mut notes = vec![Note::info(
            "role assignments only; an Entra directory role such as Global Administrator is a separate grant and does not appear here",
        )];
        if narrower {
            notes.push(Note::info(
                "a role listed `on <resource>` is granted there and nowhere else in the subscription",
            ));
        }
        if inherited {
            notes.push(Note::info(
                "a role listed `on management group …` is inherited from above the subscription and applies to every subscription under it",
            ));
        }
        if roles.is_empty() {
            notes.push(Note::info(format!(
                "{user} holds no role assignment in `{label}` — access may still come through a group, which `--assignee` does not expand without Microsoft Graph access"
            )));
        }
        Ok(report(true, roles, notes))
    }

    /// "What may this login do", with no subscription named.
    ///
    /// The default subscription is the one every `az` command already uses, so
    /// that is the one this answers about. Only a profile with nothing marked
    /// default has nothing to resolve.
    fn permissions(&self) -> anyhow::Result<PermissionsReport> {
        let status = self.status()?;
        match status.active.clone() {
            Some(subscription) => self.permissions_in(&subscription),
            None => Ok(PermissionsReport::unsupported(
                Self::TOOL,
                "Azure RBAC is granted per scope and no subscription is marked as default — pick one to read its role assignments",
                Some("az account set --subscription <name-or-id>"),
            )),
        }
    }
}

/// Where an assignment's scope sits relative to the subscription being asked
/// about. `None` means "the subscription itself", which needs no qualifier.
fn narrower_scope(scope: &str, subscription: &str) -> Option<String> {
    let whole = format!("/subscriptions/{subscription}");
    if scope.is_empty() || scope.eq_ignore_ascii_case(&whole) {
        return None;
    }
    if let Some(rest) = strip_prefix_ci(scope, &format!("{whole}/")) {
        return Some(rest.to_string());
    }
    if let Some(group) = strip_prefix_ci(scope, "/providers/Microsoft.Management/managementGroups/")
    {
        return Some(format!("management group {group}"));
    }
    if scope == "/" {
        return Some("the tenant root".to_string());
    }
    Some(scope.to_string())
}

/// Azure is inconsistent about the case of resource ids, so prefixes are
/// matched without it.
fn strip_prefix_ci<'a>(text: &'a str, prefix: &str) -> Option<&'a str> {
    text.get(..prefix.len())
        .filter(|head| head.eq_ignore_ascii_case(prefix))
        .and_then(|_| text.get(prefix.len()..))
}

/// One sentence for an `az role assignment list` that did not answer.
///
/// The three failures worth telling apart are a login that has lapsed, a login
/// that is fine but may not read the policy, and a login that cannot be
/// resolved through Microsoft Graph at all — because `--assignee` looks the
/// user up there first, and that lookup is its own permission.
fn az_failure(user: &str, label: &str, out: &CmdOutput) -> String {
    let text = if out.stderr.trim().is_empty() {
        out.stdout.trim()
    } else {
        out.stderr.trim()
    };
    let lower = text.to_lowercase();

    if lower.contains("please run 'az login'")
        || lower.contains("please run \"az login\"")
        || lower.contains("run 'az login' to setup account")
        || lower.contains("refresh token has expired")
        || lower.contains("interaction_required")
        || lower.contains("aadsts")
    {
        return format!("this machine is not signed in as {user} any longer — run `az login`");
    }
    if lower.contains("insufficient privileges to complete the operation")
        || (lower.contains("graph") && lower.contains("forbidden"))
        || lower.contains("directoryobject")
    {
        return format!(
            "{user} cannot be looked up in Microsoft Entra, which `--assignee` needs before it can filter — ask an admin for the principal's object id and use `--assignee-object-id`"
        );
    }
    if lower.contains("authorizationfailed")
        || lower.contains("does not have authorization")
        || lower.contains("forbidden")
    {
        return format!(
            "{user} may not read role assignments in `{label}` — that needs Microsoft.Authorization/roleAssignments/read there, which this login does not hold"
        );
    }
    if lower.contains("subscriptionnotfound") || lower.contains("was not found") {
        return format!(
            "`{label}` is not a subscription this login can reach any more — run `az account list --refresh`"
        );
    }
    format!("{user}: {}", headline(text))
}

/// az's first meaningful line, without the `ERROR: ` its CLI prefixes.
fn headline(text: &str) -> String {
    let line = text
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .unwrap_or("az failed without saying why");
    line.strip_prefix("ERROR: ").unwrap_or(line).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::NoteKind;
    use std::fs;
    use std::path::PathBuf;

    /// Every note's text on one blob, for `contains` assertions.
    fn note_text(status: &ToolStatus) -> String {
        status
            .notes
            .iter()
            .map(|n| n.text.as_str())
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn fixture(body: &str) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().to_path_buf();
        fs::create_dir_all(home.join(".azure")).unwrap();
        fs::write(home.join(".azure/azureProfile.json"), body).unwrap();
        (dir, home)
    }

    const PROFILE: &str = r#"{"installationId":"fake","subscriptions":[
      {"id":"11111111-1111-1111-1111-111111111111","name":"Students","state":"Disabled","user":{"name":"a@example.com","type":"user"},"isDefault":false,"tenantId":"tttt","tenantDefaultDomain":"example.com","environmentName":"AzureCloud"},
      {"id":"22222222-2222-2222-2222-222222222222","name":"Production","state":"Enabled","user":{"name":"b@example.com","type":"user"},"isDefault":true,"tenantId":"uuuu","environmentName":"AzureCloud"}
    ]}"#;

    #[test]
    fn test_subscriptions_and_default() {
        let (_dir, home) = fixture(PROFILE);
        let status = AzProbe::new(Paths::for_test(&home)).status().unwrap();
        assert_eq!(status.profiles.len(), 2);
        assert_eq!(
            status.active.as_deref(),
            Some("22222222-2222-2222-2222-222222222222")
        );
        assert_eq!(status.profiles[0].label, "Students");
        assert_eq!(status.profiles[0].meta["user"], "a@example.com");
        assert_eq!(status.profiles[0].meta["tenant_domain"], "example.com");
        // The expiry exists; it lives in the MSAL cache. That is now the
        // profile's own state rather than a sentence in `notes`.
        assert!(status
            .profiles
            .iter()
            .all(|p| p.expiry == Expiry::unknown("in the Azure MSAL cache")));
        assert!(status.profiles.iter().all(|p| p.expires_at().is_none()));
        assert!(!note_text(&status).contains("MSAL"), "{:?}", status.notes);

        let disabled = status
            .notes
            .iter()
            .find(|n| n.text.contains("not in the Enabled state"))
            .expect("expected the disabled subscription to be named");
        assert_eq!(disabled.kind, NoteKind::Warn);
    }

    #[test]
    fn test_bom_prefixed_file_parses() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().to_path_buf();
        fs::create_dir_all(home.join(".azure")).unwrap();
        let mut bytes = vec![0xEF, 0xBB, 0xBF];
        bytes.extend_from_slice(PROFILE.as_bytes());
        fs::write(home.join(".azure/azureProfile.json"), bytes).unwrap();

        let status = AzProbe::new(Paths::for_test(&home)).status().unwrap();
        assert_eq!(status.profiles.len(), 2);
    }

    #[test]
    fn test_switch_accepts_id_or_display_name() {
        let (_dir, home) = fixture(PROFILE);
        let probe = AzProbe::new(Paths::for_test(&home));
        let status = probe.status().unwrap();
        assert_eq!(
            AzProbe::resolve(&status, "Students").as_deref(),
            Some("11111111-1111-1111-1111-111111111111")
        );
        assert_eq!(
            AzProbe::resolve(&status, "11111111-1111-1111-1111-111111111111").as_deref(),
            Some("11111111-1111-1111-1111-111111111111")
        );
        assert!(AzProbe::resolve(&status, "nope").is_none());
        assert!(matches!(
            probe.switch("nope").unwrap(),
            SwitchOutcome::UnknownProfile { .. }
        ));
    }

    #[test]
    fn test_no_default_subscription_is_flagged() {
        let (_dir, home) = fixture(
            r#"{"subscriptions":[{"id":"abc","name":"Only","state":"Enabled","isDefault":false}]}"#,
        );
        let status = AzProbe::new(Paths::for_test(&home)).status().unwrap();
        assert!(status.active.is_none());
        let note = status
            .notes
            .iter()
            .find(|n| n.text.contains("no subscription is marked as default"))
            .expect("expected the missing default to be flagged");
        // Nothing is broken — every command just has to name a subscription.
        assert_eq!(note.kind, NoteKind::Warn);
    }

    // -----------------------------------------------------------------
    // permissions
    // -----------------------------------------------------------------

    const PROD: &str = "22222222-2222-2222-2222-222222222222";

    fn probe_with(home: &PathBuf, exec: std::sync::Arc<crate::util::FakeExec>) -> AzProbe {
        AzProbe::new(Paths::for_test(home).with_exec(exec))
    }

    fn fake(exec: crate::util::FakeExec) -> std::sync::Arc<crate::util::FakeExec> {
        std::sync::Arc::new(exec)
    }

    /// The shape `az role assignment list --all --include-inherited` really
    /// prints, trimmed to the fields patchbay reads.
    const ASSIGNMENTS: &str = r#"[
      {"principalName":"b@example.com","principalType":"User",
       "roleDefinitionName":"Owner",
       "scope":"/subscriptions/22222222-2222-2222-2222-222222222222"},
      {"principalName":"b@example.com","principalType":"User",
       "roleDefinitionName":"Contributor",
       "scope":"/subscriptions/22222222-2222-2222-2222-222222222222/resourceGroups/web"},
      {"principalName":"b@example.com","principalType":"User",
       "roleDefinitionName":"Reader",
       "scope":"/providers/Microsoft.Management/managementGroups/corp"}
    ]"#;

    #[test]
    fn test_the_subscription_list_costs_no_subprocess() {
        // The whole point of az's scope list: `azureProfile.json` already has
        // it, so unlike gcloud there is nothing to run and nothing to be
        // refused. A picker that needs a grant to populate is no picker.
        let (_dir, home) = fixture(PROFILE);
        let exec = fake(crate::util::FakeExec::new());

        let scopes = probe_with(&home, exec.clone()).permission_scopes().unwrap();
        assert!(exec.calls().is_empty(), "{:?}", exec.calls());
        assert_eq!(scopes.len(), 2);
        assert_eq!(scopes[0].label, "Students");
        assert_eq!(scopes[1].id, PROD);
        assert!(scopes[1].active, "the default subscription opens the box");
        assert!(!scopes[0].active);
    }

    #[test]
    fn test_role_assignments_are_read_for_that_subscriptions_signed_in_user() {
        let (_dir, home) = fixture(PROFILE);
        let exec =
            fake(crate::util::FakeExec::new().on("role assignment list", true, ASSIGNMENTS, ""));

        let report = probe_with(&home, exec.clone())
            .permissions_in(PROD)
            .unwrap();
        assert!(report.supported, "{report:?}");
        assert_eq!(report.subject.as_deref(), Some("b@example.com"));
        assert_eq!(report.scope.as_deref(), Some(PROD));
        assert_eq!(
            report.scopes,
            vec![
                "Contributor on resourceGroups/web",
                "Owner",
                "Reader on management group corp",
            ]
        );
        assert_eq!(report.hint, None, "patchbay ran it; nothing to paste");

        // `--all` is what makes the resource-group grant visible at all.
        let args = exec.last().unwrap().args;
        assert!(args.contains(&"--all".to_string()), "{args:?}");
        assert!(
            args.contains(&"--include-inherited".to_string()),
            "{args:?}"
        );
        assert!(args.contains(&"b@example.com".to_string()), "{args:?}");
        assert!(args.contains(&PROD.to_string()), "{args:?}");
    }

    #[test]
    fn test_a_role_on_one_resource_group_is_never_reported_as_the_subscription() {
        // "Contributor" across a subscription and "Contributor" on one resource
        // group are different facts, and the second is the one people
        // over-read. The scope goes in the label, and the note says what the
        // label means.
        let (_dir, home) = fixture(PROFILE);
        let exec =
            fake(crate::util::FakeExec::new().on("role assignment list", true, ASSIGNMENTS, ""));

        let report = probe_with(&home, exec).permissions_in(PROD).unwrap();
        assert!(report
            .scopes
            .contains(&"Contributor on resourceGroups/web".to_string()));
        assert!(!report.scopes.contains(&"Contributor".to_string()));
        let notes = report
            .notes
            .iter()
            .map(|n| n.text.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(notes.contains("granted there and nowhere else"), "{notes}");
        assert!(notes.contains("inherited from above"), "{notes}");
    }

    #[test]
    fn test_no_assignment_is_answered_as_a_fact_not_as_an_empty_pane() {
        let (_dir, home) = fixture(PROFILE);
        let exec = fake(crate::util::FakeExec::new().on("role assignment list", true, "[]", ""));

        let report = probe_with(&home, exec).permissions_in(PROD).unwrap();
        assert!(report.supported);
        assert!(report.scopes.is_empty());
        let notes = report
            .notes
            .iter()
            .map(|n| n.text.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(notes.contains("holds no role assignment"), "{notes}");
        // A group membership is the usual reason, and it is not a denial.
        assert!(notes.contains("group"), "{notes}");
    }

    #[test]
    fn test_a_refused_read_is_distinguished_from_a_lapsed_login() {
        let (_dir, home) = fixture(PROFILE);

        let denied = "ERROR: (AuthorizationFailed) The client 'b@example.com' with object id 'cac0311a' does not have authorization to perform action 'Microsoft.Authorization/roleAssignments/read' over scope '/subscriptions/2222' or the scope is invalid.\n";
        let exec = fake(crate::util::FakeExec::new().on("role assignment list", false, "", denied));
        let report = probe_with(&home, exec).permissions_in(PROD).unwrap();
        assert!(!report.supported);
        assert_eq!(report.subject.as_deref(), Some("b@example.com"));
        let notes = report
            .notes
            .iter()
            .map(|n| n.text.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        assert_eq!(notes.lines().count(), 1, "{notes}");
        assert!(notes.contains("may not read role assignments"), "{notes}");
        assert!(notes.contains("Production"), "{notes}");
        assert!(!notes.contains("ERROR:"), "{notes}");

        let logged_out = "ERROR: Please run 'az login' to setup account.\n";
        let exec =
            fake(crate::util::FakeExec::new().on("role assignment list", false, "", logged_out));
        let report = probe_with(&home, exec).permissions_in(PROD).unwrap();
        let notes = report
            .notes
            .iter()
            .map(|n| n.text.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        assert_eq!(notes.lines().count(), 1, "{notes}");
        assert!(notes.contains("az login"), "{notes}");
        assert!(!notes.contains("may not read"), "{notes}");
    }

    #[test]
    fn test_a_graph_lookup_that_is_refused_names_the_flag_that_bypasses_it() {
        // `--assignee` resolves the UPN through Microsoft Entra first, and that
        // lookup is its own permission — a failure there is not a failure to
        // hold roles.
        let (_dir, home) = fixture(PROFILE);
        let exec = fake(crate::util::FakeExec::new().on(
            "role assignment list",
            false,
            "",
            "ERROR: Insufficient privileges to complete the operation.\n",
        ));

        let report = probe_with(&home, exec).permissions_in(PROD).unwrap();
        assert!(!report.supported);
        let notes = report
            .notes
            .iter()
            .map(|n| n.text.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        assert_eq!(notes.lines().count(), 1, "{notes}");
        assert!(notes.contains("--assignee-object-id"), "{notes}");
    }

    #[test]
    fn test_unparseable_output_degrades_to_a_note() {
        let (_dir, home) = fixture(PROFILE);
        let exec = fake(crate::util::FakeExec::new().on(
            "role assignment list",
            true,
            "Role assignments, probably\n",
            "",
        ));

        let report = probe_with(&home, exec).permissions_in(PROD).unwrap();
        assert!(!report.supported);
        assert!(report.scopes.is_empty());
        assert!(!report.notes.is_empty());
    }

    #[test]
    fn test_without_az_the_command_is_handed_over_with_real_values() {
        let (_dir, home) = fixture(PROFILE);
        let report = AzProbe::new(Paths::for_test(&home))
            .permissions_in(PROD)
            .unwrap();
        assert!(!report.supported);
        assert_eq!(report.subject.as_deref(), Some("b@example.com"));
        let hint = report.hint.unwrap();
        assert!(
            hint.contains("b@example.com") && hint.contains(PROD),
            "{hint}"
        );
        assert!(!hint.contains('<'), "{hint}");
    }

    #[test]
    fn test_permissions_resolves_the_default_subscription_and_accepts_a_name() {
        let (_dir, home) = fixture(PROFILE);
        let exec = fake(crate::util::FakeExec::new().on("role assignment list", true, "[]", ""));
        let report = probe_with(&home, exec.clone()).permissions().unwrap();
        assert_eq!(report.scope.as_deref(), Some(PROD));

        // A display name is what a human types, so it resolves too.
        let exec = fake(crate::util::FakeExec::new().on("role assignment list", true, "[]", ""));
        let report = probe_with(&home, exec).permissions_in("Students").unwrap();
        assert_eq!(
            report.scope.as_deref(),
            Some("11111111-1111-1111-1111-111111111111")
        );
        assert_eq!(report.subject.as_deref(), Some("a@example.com"));
    }

    #[test]
    fn test_an_unknown_subscription_lists_the_real_ones_without_running_anything() {
        let (_dir, home) = fixture(PROFILE);
        let exec = fake(crate::util::FakeExec::new());

        let report = probe_with(&home, exec.clone())
            .permissions_in("nope")
            .unwrap();
        assert!(!report.supported);
        let notes = report
            .notes
            .iter()
            .map(|n| n.text.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            notes.contains("Students") && notes.contains("Production"),
            "{notes}"
        );
        assert!(exec.calls().is_empty());
    }

    #[test]
    fn test_missing_and_malformed() {
        let dir = tempfile::tempdir().unwrap();
        let status = AzProbe::new(Paths::for_test(dir.path())).status().unwrap();
        assert!(!status.installed);
        assert!(status.profiles.is_empty());

        let (_dir, home) = fixture("{\"subscriptions\": [ truncated");
        let status = AzProbe::new(Paths::for_test(&home)).status().unwrap();
        assert!(status.profiles.is_empty());
        let note = status
            .notes
            .iter()
            .find(|n| n.text.contains("not valid JSON"))
            .expect("expected the unparseable profile to be flagged");
        assert_eq!(note.kind, NoteKind::Problem);
    }

    #[test]
    fn test_execution_being_switched_off_is_not_a_reason_az_cannot_switch() {
        let (_dir, home) = fixture(PROFILE);
        match AzProbe::new(Paths::for_test(&home))
            .switch("Students")
            .unwrap()
        {
            SwitchOutcome::ExecDisabled { tool, hint } => {
                assert_eq!(tool, "az");
                assert_eq!(
                    hint.as_deref(),
                    Some("az account set --subscription 11111111-1111-1111-1111-111111111111")
                );
            }
            other => panic!("expected ExecDisabled, got {other:?}"),
        }
    }
}
