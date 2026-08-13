//! `SETUP.md` — the instructions that ride inside the bundle.
//!
//! Written at export time, on purpose. The machine you are moving *to* may have
//! no patchbay, no `pb`, and no idea what a `.pbx` file is; the one thing it
//! will have is the bundle. So the bundle carries its own instructions,
//! starting with how to install the tool that reads it.
//!
//! Same rule as the manifest it is generated from: **no secret values.** It is
//! rendered from a [`Manifest`], which cannot contain any.

use super::manifest::Manifest;
use super::policy::{policy_for, PortabilityKind};

/// The whole document, as Markdown.
pub fn render(manifest: &Manifest) -> String {
    let mut out = String::new();
    let date = manifest.created_at.format("%Y-%m-%d %H:%M UTC");
    out.push_str(&format!(
        "# Moving to this machine\n\n\
         Exported {date} by patchbay {} on {}.\n\n\
         This bundle is encrypted with the passphrase you were given. It holds the credential \
         files that survive a machine move, plus a list of the ones that do not.\n\n",
        manifest.source.patchbay_version, manifest.source.os
    ));

    out.push_str(
        "## 1. Get patchbay onto this machine\n\n\
         ```sh\n\
         # CLI + MCP server (Apple silicon; use x86_64-apple-darwin on Intel)\n\
         tag=v0.1.0; arch=aarch64-apple-darwin; tmp=$(mktemp -d)\n\
         curl -fsSL \"https://github.com/pathorsAI/patchbay/releases/download/$tag/pb-$tag-$arch.tar.gz\" \\\n\
         \x20 | tar xz -C \"$tmp\"\n\
         sudo mv \"$tmp/pb\" /usr/local/bin/\n\
         ```\n\n\
         Or build it: `git clone https://github.com/pathorsAI/patchbay && cd patchbay && \
         cargo install --path crates/patchbay-cli`.\n\n",
    );

    out.push_str(
        "## 2. Import\n\n\
         ```sh\n\
         pb import patchbay-*.pbx --dry-run   # see the plan, write nothing\n\
         pb import patchbay-*.pbx             # do it\n\
         ```\n\n\
         Existing files are never overwritten silently: each one is copied to \
         `<path>.patchbay-bak` first. Running the import twice produces the same machine.\n\n\
         Then delete the bundle from both machines.\n\n",
    );

    // --- what travelled ----------------------------------------------------
    let carried: Vec<&super::manifest::ToolRecord> = manifest
        .tools
        .iter()
        .filter(|t| !t.carried.is_empty())
        .collect();
    out.push_str("## 3. What travelled\n\n");
    if carried.is_empty() {
        out.push_str("Nothing — this bundle carries no credential files.\n\n");
    } else {
        out.push_str("| tool | what | restored to |\n|---|---|---|\n");
        for record in &carried {
            for location in &record.carried {
                out.push_str(&format!(
                    "| `{}` | {} | resolved on this machine from `{}` |\n",
                    record.tool,
                    location.describe(),
                    location.key()
                ));
            }
        }
        out.push('\n');
    }

    // --- what did not ------------------------------------------------------
    out.push_str("## 4. What you have to do by hand\n\n");
    if manifest.gaps.is_empty() {
        out.push_str("Nothing outstanding.\n\n");
    } else {
        out.push_str(
            "Work these one at a time, and re-check after each. `pb plan` re-reads this machine \
             and tells you what is still open; an AI agent with patchbay's MCP server can drive \
             the same list with `plan_setup` and `mark_setup_done`.\n\n",
        );
        for item in &manifest.gaps {
            let browser = if item.needs_browser {
                " *(opens a browser — a human has to do this one)*"
            } else {
                ""
            };
            out.push_str(&format!("- **{}** — {}{browser}\n", item.tool, item.what));
            if !item.command.is_empty() {
                out.push_str(&format!("  ```sh\n  {}\n  ```\n", item.command));
            }
            for detail in &item.detail {
                out.push_str(&format!("  <sub>{detail}</sub>\n"));
            }
        }
        out.push('\n');
    }

    // --- install list ------------------------------------------------------
    let missing: Vec<&super::manifest::ToolRecord> =
        manifest.tools.iter().filter(|t| t.installed).collect();
    if !missing.is_empty() {
        out.push_str(
            "## 5. CLIs this machine will need\n\n\
             Everything that was installed on the old machine. Skip what you do not want.\n\n\
             ```sh\n",
        );
        for record in &missing {
            if let Some(policy) = policy_for(&record.tool) {
                out.push_str(&format!("{:<12} # {}\n", policy.install, record.tool));
            }
        }
        out.push_str("```\n\n");
    }

    // --- keys --------------------------------------------------------------
    if !manifest.keys.is_empty() {
        let included = manifest.keys.iter().filter(|k| k.included).count();
        out.push_str(&format!(
            "## 6. Key vault\n\n{} of {} registered keys travelled with their values; the rest \
             are listed by metadata only (id, provider, last 4 characters) and have to be \
             re-created from the issuer.\n\n\
             | id | provider | last4 | value travelled |\n|---|---|---|---|\n",
            included,
            manifest.keys.len()
        ));
        for key in &manifest.keys {
            out.push_str(&format!(
                "| `{}` | {} | …{} | {} |\n",
                key.id,
                key.provider,
                key.last4,
                if key.included { "yes" } else { "no" }
            ));
        }
        out.push('\n');
    }

    out.push_str(
        "---\n\n\
         patchbay never copies an SSH private key, and never moves a credential the OS keychain \
         is holding. Anything in the list above marked device-bound is bound for a reason.\n",
    );
    out
}

/// A one-line summary of a tool's portability, for the CLI's export output.
pub fn portability_label(kind: PortabilityKind) -> &'static str {
    match kind {
        PortabilityKind::Portable => "portable",
        PortabilityKind::DeviceBound => "device-bound",
        PortabilityKind::PointerOnly => "pointer-only",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migrate::manifest::{
        KeyRecord, McpRecord, SetupItem, Source, ToolRecord, BUNDLE_VERSION,
    };
    use crate::migrate::policy::Location;
    use crate::types::{Profile, ToolCategory};
    use chrono::Utc;

    fn manifest() -> Manifest {
        Manifest {
            version: BUNDLE_VERSION,
            created_at: Utc::now(),
            source: Source {
                patchbay_version: "0.1.0".into(),
                os: "macos".into(),
            },
            tools: vec![
                ToolRecord {
                    tool: "aws".into(),
                    category: ToolCategory::Cloud,
                    installed: true,
                    portability: PortabilityKind::Portable,
                    reason: String::new(),
                    profiles: vec![Profile::new("default")],
                    active: Some("default".into()),
                    carried: vec![Location::AwsConfig, Location::AwsCredentials],
                    subject: None,
                    scopes: vec![],
                    notes: vec![],
                },
                ToolRecord {
                    tool: "gh".into(),
                    category: ToolCategory::Code,
                    installed: true,
                    portability: PortabilityKind::DeviceBound,
                    reason: "keychain".into(),
                    profiles: vec![Profile::new("github.com/octocat")],
                    active: Some("github.com/octocat".into()),
                    carried: vec![],
                    subject: Some("octocat".into()),
                    scopes: vec!["repo".into()],
                    notes: vec![],
                },
            ],
            keys: vec![KeyRecord {
                id: "cf-api".into(),
                provider: "cloudflare".into(),
                label: "CF".into(),
                purpose: None,
                scopes: vec![],
                expires_at: None,
                last4: "9876".into(),
                included: false,
            }],
            mcp: vec![McpRecord {
                client: "cursor".into(),
                name: "grafana".into(),
                summary: "stdio uvx (1 arg)".into(),
                env_keys: vec!["GRAFANA_TOKEN".into()],
                header_keys: vec![],
                carried: true,
            }],
            gaps: vec![SetupItem::new("tool:gh", "gh", "log in to gh as `octocat`")
                .command("gh auth login", true)
                .detail("the OAuth token lives in the OS keychain")],
        }
    }

    #[test]
    fn test_setup_md_tells_a_machine_with_no_patchbay_what_to_do_first() {
        let md = render(&manifest());
        // Install instructions come before the import instructions.
        let install = md.find("Get patchbay onto this machine").unwrap();
        let import = md.find("## 2. Import").unwrap();
        assert!(install < import, "{md}");
        assert!(md.contains("pb import"), "{md}");
        assert!(md.contains("--dry-run"), "{md}");
        assert!(md.contains(".patchbay-bak"), "{md}");
    }

    #[test]
    fn test_setup_md_lists_each_gap_with_its_exact_command() {
        let md = render(&manifest());
        assert!(md.contains("gh auth login"), "{md}");
        assert!(md.contains("opens a browser"), "{md}");
        assert!(md.contains("brew install gh"), "{md}");
        assert!(md.contains("AWS access keys"), "{md}");
        // Key metadata, marked as not travelled.
        assert!(md.contains("`cf-api`"), "{md}");
        assert!(md.contains("…9876"), "{md}");
    }

    #[test]
    fn test_setup_md_has_no_secret_in_it() {
        let md = render(&manifest());
        for forbidden in ["glsa_", "ghp_", "aws_secret_access_key", "BEGIN OPENSSH"] {
            assert!(!md.contains(forbidden), "`{forbidden}` in SETUP.md:\n{md}");
        }
    }

    #[test]
    fn test_an_empty_machine_still_renders() {
        let mut manifest = manifest();
        manifest.tools.clear();
        manifest.keys.clear();
        manifest.gaps.clear();
        let md = render(&manifest);
        assert!(md.contains("Nothing outstanding"), "{md}");
        assert!(md.contains("carries no credential files"), "{md}");
    }

    #[test]
    fn test_portability_labels() {
        assert_eq!(portability_label(PortabilityKind::Portable), "portable");
        assert_eq!(
            portability_label(PortabilityKind::DeviceBound),
            "device-bound"
        );
        assert_eq!(
            portability_label(PortabilityKind::PointerOnly),
            "pointer-only"
        );
    }
}
