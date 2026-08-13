//! Curated advisories: renames, removals, end-of-life dates.
//!
//! A version number cannot tell you that `huggingface-cli` stopped existing or
//! that the CLI you are typing has a new name. That knowledge is editorial, so
//! it lives in a hand-maintained table rather than being derived from anything.
//!
//! Because the table is static data, advisories surface on the tier-1 board
//! regardless of whether the version cache is warm — no exec, no network, no
//! waiting.
//!
//! # The rules for adding an entry
//!
//! 1. **Every entry carries a source URL in a comment.** If it cannot be
//!    sourced to vendor documentation, release notes or an official blog post,
//!    it does not go in. An issue title or a code comment is not a source: the
//!    frequently-repeated "`tailscale up` is deprecated" fails this bar and is
//!    deliberately absent.
//! 2. **Say what the vendor says, not what sounds dramatic.** Neon renamed
//!    `neonctl` to `neon` and explicitly kept the old name working; calling it
//!    "deprecated" would be false, so the entry says "renamed, old name still
//!    works".
//! 3. **Gate it.** `applies_when` keeps an advisory off the boards it does not
//!    concern — the AWS CLI v1 end-of-support notice is meaningless to someone
//!    on v2.

use std::cmp::Ordering;

use serde::{Deserialize, Serialize};

/// What kind of news this is. Drives both wording and exit codes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AdvisoryKind {
    /// The command has a new name. The old one may or may not still work; the
    /// message says which.
    Renamed {
        to: String,
        /// When the rename landed, if the vendor dated it.
        since: Option<String>,
    },
    /// Something is gone as of a given version, and this is what replaces it.
    Removed {
        in_version: String,
        replacement: String,
    },
    /// Still installable, no longer looked after.
    Unmaintained { note: String },
    /// Worth knowing, nothing to do today.
    Info,
}

impl AdvisoryKind {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Renamed { .. } => "renamed",
            Self::Removed { .. } => "removed",
            Self::Unmaintained { .. } => "unmaintained",
            Self::Info => "info",
        }
    }
}

/// One notice about one tool on this machine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Advisory {
    pub tool: String,
    pub kind: AdvisoryKind,
    /// One paragraph a human can act on, in plain words.
    pub message: String,
    /// Where the claim comes from. Every shipped advisory has one.
    pub url: Option<String>,
}

impl Advisory {
    /// Whether this is bad enough that `pb check-updates` should exit non-zero.
    ///
    /// A rename you can keep ignoring is not; something that has been removed
    /// or abandoned is.
    pub fn is_blocking(&self) -> bool {
        matches!(
            self.kind,
            AdvisoryKind::Removed { .. } | AdvisoryKind::Unmaintained { .. }
        )
    }
}

/// What an `applies_when` predicate gets to look at.
#[derive(Debug, Clone, Copy, Default)]
pub struct AdvisoryContext<'a> {
    /// The version the tool reports, when patchbay knows it.
    pub installed_version: Option<&'a str>,
    /// Which of the tool's known binary names are actually on `PATH`. This is
    /// how "you are still typing the old name" is detected.
    pub binaries: &'a [&'a str],
}

impl<'a> AdvisoryContext<'a> {
    pub fn new(installed_version: Option<&'a str>, binaries: &'a [&'a str]) -> Self {
        Self {
            installed_version,
            binaries,
        }
    }

    /// Is this binary name on `PATH`?
    pub fn has_binary(&self, name: &str) -> bool {
        self.binaries.contains(&name)
    }

    /// The leading numeric component of the installed version, if any.
    pub fn major(&self) -> Option<u64> {
        let v = self.installed_version?;
        v.trim()
            .trim_start_matches('v')
            .split('.')
            .next()?
            .parse()
            .ok()
    }

    /// Installed version >= `floor`. `false` when the version is unknown — an
    /// advisory must never fire on a guess.
    pub fn at_least(&self, floor: &str) -> bool {
        matches!(
            self.installed_version
                .and_then(|v| crate::versions::compare(v, floor)),
            Some(Ordering::Greater | Ordering::Equal)
        )
    }

    /// Installed version < `ceiling`. `false` when the version is unknown.
    pub fn below(&self, ceiling: &str) -> bool {
        matches!(
            self.installed_version
                .and_then(|v| crate::versions::compare(v, ceiling)),
            Some(Ordering::Less)
        )
    }
}

/// A table row: the advisory, plus the condition under which it is relevant.
pub struct AdvisoryRule {
    pub tool: &'static str,
    pub kind: fn() -> AdvisoryKind,
    pub message: &'static str,
    pub url: &'static str,
    /// Return `true` when this machine is actually affected.
    pub applies_when: fn(&AdvisoryContext) -> bool,
}

/// Every advisory patchbay ships.
///
/// Small on purpose. A board that cries wolf gets ignored, and the failure this
/// feature exists to prevent — finding out only when something breaks — is not
/// helped by inventing warnings.
pub const ADVISORIES: &[AdvisoryRule] = &[
    // Neon renamed the CLI to `neon` in the 2026-07-03 changelog entry. The
    // vendor is explicit that this is NOT a deprecation: "If you already use
    // `neonctl`, nothing changes: it's the same CLI, `neonctl` still works as a
    // command, and no migration or re-authentication is needed." The Homebrew
    // formula is still called `neonctl`, which is why patchbay's brew mapping
    // uses the old name too.
    // https://neon.com/docs/changelog/2026-07-03
    AdvisoryRule {
        tool: "neon",
        kind: || AdvisoryKind::Renamed {
            to: "neon".to_string(),
            since: Some("2026-07-03".to_string()),
        },
        message: "The Neon CLI is now invoked as `neon`. Your machine still has the older \
                  `neonctl` name on PATH — it keeps working (Neon kept it as an alias, and the \
                  Homebrew formula is still called `neonctl`), but new docs and examples all say \
                  `neon`.",
        url: "https://neon.com/docs/reference/cli-install",
        // Only worth saying when the OLD name is what is on PATH. Someone who
        // only has `neon` has nothing to learn here.
        applies_when: |ctx| ctx.has_binary("neonctl"),
    },
    // `hf` arrived in huggingface_hub 0.34.0 (2025-07-25); `huggingface-cli`
    // was removed outright in 1.0.0 (2025-10-27): "This release marks the end
    // of an era with the complete removal of the `huggingface-cli` command."
    // https://huggingface.co/docs/huggingface_hub/en/concepts/migration
    AdvisoryRule {
        tool: "huggingface",
        kind: || AdvisoryKind::Removed {
            in_version: "1.0.0".to_string(),
            replacement: "hf".to_string(),
        },
        message: "`huggingface-cli` was removed in huggingface_hub 1.0.0 and replaced by `hf`. \
                  This machine still has the old command, so upgrading the hub package will break \
                  any script that calls it. Switch those to `hf` first, then \
                  `pip install -U huggingface_hub`.",
        url: "https://huggingface.co/docs/huggingface_hub/en/concepts/migration",
        // The old binary being present is precisely the problem; a machine that
        // already has `hf` has nothing to do.
        applies_when: |ctx| ctx.has_binary("huggingface-cli"),
    },
    // Announced 2026-01-15: AWS CLI v1 entered maintenance mode on 2026-07-15
    // and reaches end of support on 2027-07-15.
    // https://aws.amazon.com/blogs/developer/cli-v1-maintenance-mode-announcement
    AdvisoryRule {
        tool: "aws",
        kind: || AdvisoryKind::Unmaintained {
            note: "maintenance mode since 2026-07-15, end of support 2027-07-15".to_string(),
        },
        message: "This is AWS CLI v1, which entered maintenance mode on 2026-07-15 and loses \
                  support entirely on 2027-07-15 — it gets no new features and no new service \
                  support. Migrate to AWS CLI v2.",
        url: "https://aws.amazon.com/blogs/developer/cli-v1-maintenance-mode-announcement",
        // Version-gated: irrelevant, and actively confusing, on v2.
        applies_when: |ctx| ctx.major() == Some(1),
    },
    // "1Password CLI 1 is deprecated as of October 1, 2024."
    // https://www.1password.dev/cli/upgrade/
    AdvisoryRule {
        tool: "op",
        kind: || AdvisoryKind::Unmaintained {
            note: "deprecated since 2024-10-01".to_string(),
        },
        message: "This is 1Password CLI v1, deprecated since 2024-10-01. v2 changed the command \
                  structure, so scripts need updating as part of the move.",
        url: "https://www.1password.dev/cli/upgrade/",
        applies_when: |ctx| ctx.major() == Some(1),
    },
    // The in-tree `gcp` and `azure` client auth provider plugins were
    // deprecated in Kubernetes 1.22 and removed in 1.26, from both client-go
    // and kubectl. Users on 1.26+ with an old kubeconfig hit
    // "error: The gcp auth plugin has been removed".
    // https://docs.cloud.google.com/kubernetes-engine/docs/deprecations/auth-plugin
    AdvisoryRule {
        tool: "kubectl",
        kind: || AdvisoryKind::Removed {
            in_version: "1.26".to_string(),
            replacement: "gke-gcloud-auth-plugin (GKE) or kubelogin (AKS)".to_string(),
        },
        message: "kubectl 1.26 removed the built-in `gcp` and `azure` auth provider plugins. A \
                  kubeconfig entry still using one fails with \"the gcp auth plugin has been \
                  removed\"; GKE clusters need `gke-gcloud-auth-plugin` and AKS clusters need \
                  `kubelogin` as an exec credential plugin instead.",
        url: "https://docs.cloud.google.com/kubernetes-engine/docs/deprecations/auth-plugin",
        applies_when: |ctx| ctx.at_least("1.26"),
    },
];

/// The advisories that apply to one tool on this machine.
pub fn advisories_for(tool: &str, ctx: &AdvisoryContext) -> Vec<Advisory> {
    ADVISORIES
        .iter()
        .filter(|rule| rule.tool == tool && (rule.applies_when)(ctx))
        .map(|rule| Advisory {
            tool: rule.tool.to_string(),
            kind: (rule.kind)(),
            message: rule.message.to_string(),
            url: Some(rule.url.to_string()),
        })
        .collect()
}

/// Whether any tool has an advisory at all, without building the strings —
/// used to skip the `PATH` lookups that populate the context.
pub fn has_rules(tool: &str) -> bool {
    ADVISORIES.iter().any(|rule| rule.tool == tool)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx<'a>(version: Option<&'a str>, binaries: &'a [&'a str]) -> AdvisoryContext<'a> {
        AdvisoryContext::new(version, binaries)
    }

    // --- the gates ----------------------------------------------------------

    #[test]
    fn test_neon_advisory_fires_only_while_the_old_name_is_on_path() {
        // The motivating case: `neonctl` still installed.
        let old = advisories_for("neon", &ctx(Some("2.38.2"), &["neon", "neonctl"]));
        assert_eq!(old.len(), 1);
        assert!(matches!(old[0].kind, AdvisoryKind::Renamed { .. }));
        // Neon kept the old name working, so this must not read as a deadline.
        assert!(
            old[0].message.contains("keeps working"),
            "{}",
            old[0].message
        );
        assert!(
            !old[0].is_blocking(),
            "a supported alias is not an emergency"
        );

        // Only the new name: nothing to say.
        assert!(advisories_for("neon", &ctx(Some("2.38.2"), &["neon"])).is_empty());
        // Not installed at all: nothing to say.
        assert!(advisories_for("neon", &ctx(None, &[])).is_empty());
    }

    #[test]
    fn test_huggingface_advisory_fires_on_the_removed_binary_and_blocks() {
        let old = advisories_for("huggingface", &ctx(Some("0.35.0"), &["huggingface-cli"]));
        assert_eq!(old.len(), 1);
        assert_eq!(
            old[0].kind,
            AdvisoryKind::Removed {
                in_version: "1.0.0".into(),
                replacement: "hf".into()
            }
        );
        assert!(old[0].is_blocking());

        // Already migrated to `hf`: silent.
        assert!(advisories_for("huggingface", &ctx(Some("1.2.0"), &["hf"])).is_empty());
    }

    #[test]
    fn test_version_gated_advisories_never_fire_on_the_wrong_major() {
        // AWS CLI v1 is in maintenance mode; v2 is not.
        let v1 = advisories_for("aws", &ctx(Some("1.29.0"), &["aws"]));
        assert_eq!(v1.len(), 1);
        assert!(v1[0].is_blocking());
        assert!(advisories_for("aws", &ctx(Some("2.32.6"), &["aws"])).is_empty());

        // 1Password CLI, same shape.
        assert_eq!(advisories_for("op", &ctx(Some("1.12.4"), &["op"])).len(), 1);
        assert!(advisories_for("op", &ctx(Some("2.30.0"), &["op"])).is_empty());
    }

    #[test]
    fn test_an_unknown_version_never_triggers_a_version_gated_advisory() {
        // The tool is installed but would not say what it is: guessing here
        // would put a scary, possibly wrong warning on the board.
        assert!(advisories_for("aws", &ctx(None, &["aws"])).is_empty());
        assert!(advisories_for("op", &ctx(None, &["op"])).is_empty());
        assert!(advisories_for("kubectl", &ctx(None, &["kubectl"])).is_empty());
    }

    #[test]
    fn test_kubectl_auth_plugin_advisory_uses_a_floor_not_an_exact_match() {
        // Removed in 1.26, so everything at or above it is affected.
        assert!(advisories_for("kubectl", &ctx(Some("1.26.0"), &["kubectl"])).len() == 1);
        assert!(advisories_for("kubectl", &ctx(Some("v1.32.2"), &["kubectl"])).len() == 1);
        assert!(advisories_for("kubectl", &ctx(Some("1.36.3"), &["kubectl"])).len() == 1);
        // Below the floor: the plugin is still there.
        assert!(advisories_for("kubectl", &ctx(Some("1.25.9"), &["kubectl"])).is_empty());
        // The classic lexicographic trap: "1.9" must not read as newer than "1.26".
        assert!(advisories_for("kubectl", &ctx(Some("1.9.0"), &["kubectl"])).is_empty());
    }

    // --- the context helpers ------------------------------------------------

    #[test]
    fn test_context_version_helpers() {
        let c = ctx(Some("v1.32.2"), &[]);
        assert_eq!(c.major(), Some(1));
        assert!(c.at_least("1.26"));
        assert!(c.at_least("1.32.2"), "at_least is inclusive");
        assert!(!c.at_least("1.33"));
        assert!(c.below("2.0"));
        assert!(!c.below("1.0"));

        // Unknown version: every predicate is false, never a panic.
        let unknown = ctx(None, &[]);
        assert_eq!(unknown.major(), None);
        assert!(!unknown.at_least("1.0"));
        assert!(!unknown.below("99.0"));

        // Unparseable version: same.
        let weird = ctx(Some("10.2p1"), &[]);
        assert_eq!(weird.major(), Some(10));
        assert!(
            !weird.at_least("1.0"),
            "a non-numeric build is not compared"
        );
    }

    #[test]
    fn test_has_binary_is_exact_not_a_prefix_match() {
        let c = ctx(None, &["neonctl"]);
        assert!(c.has_binary("neonctl"));
        assert!(
            !c.has_binary("neon"),
            "`neon` is a prefix of `neonctl`, not a match"
        );
    }

    // --- the table itself ---------------------------------------------------

    #[test]
    fn test_every_advisory_is_sourced_and_names_a_real_tool() {
        let dir = tempfile::tempdir().unwrap();
        let registry = crate::Registry::all(crate::Paths::for_test(dir.path()));
        let known = registry.tool_names();
        for rule in ADVISORIES {
            assert!(
                known.contains(&rule.tool),
                "advisory for `{}`, which is not a registered tool",
                rule.tool
            );
            assert!(
                rule.url.starts_with("https://"),
                "{} has no source URL",
                rule.tool
            );
            assert!(
                rule.message.len() > 40,
                "{}'s message is too terse to act on",
                rule.tool
            );
            assert!(has_rules(rule.tool));
        }
        assert!(
            !has_rules("gh"),
            "gh has no advisories and should not claim any"
        );
    }

    #[test]
    fn test_an_advisory_round_trips_through_json_with_a_readable_shape() {
        let advisory =
            &advisories_for("huggingface", &ctx(Some("0.35.0"), &["huggingface-cli"]))[0];
        let json = serde_json::to_value(advisory).unwrap();
        assert_eq!(json["tool"], "huggingface");
        assert_eq!(json["kind"]["type"], "removed");
        assert_eq!(json["kind"]["in_version"], "1.0.0");
        assert_eq!(json["kind"]["replacement"], "hf");
        assert!(json["url"].as_str().unwrap().starts_with("https://"));

        let back: Advisory = serde_json::from_value(json).unwrap();
        assert_eq!(&back, advisory);
    }

    #[test]
    fn test_kind_labels() {
        assert_eq!(AdvisoryKind::Info.label(), "info");
        assert_eq!(
            AdvisoryKind::Renamed {
                to: "neon".into(),
                since: None
            }
            .label(),
            "renamed"
        );
    }
}
