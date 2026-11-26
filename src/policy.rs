//! Policy layer — parses anoint.toml for suppressions and enforcement settings.

use crate::code_audit::{AuditThreshold, BullshitKind};
use crate::suggestions::Impact;
use anyhow::Context;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

/// Top-level policy configuration loaded from anoint.toml.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    /// Suppress non-overlap recommendations for these packages.
    #[serde(default)]
    pub ignore_packages: Vec<String>,

    /// Override the default fail-on severity thresholds.
    #[serde(default)]
    pub fail_on: Vec<Impact>,

    /// Per-package suggestion suppressions.
    #[serde(default)]
    pub packages: HashMap<String, PackagePolicy>,

    /// Global settings.
    #[serde(default)]
    pub settings: PolicySettings,

    /// Bullshit detector code-audit suppressions.
    #[serde(default)]
    pub code_audit: CodeAuditPolicy,
    /// Reviewed exceptions for a specific package and exact overlapping provider set.
    #[serde(default)]
    pub allow_overlap: Vec<OverlapException>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OverlapException {
    pub package: String,
    pub providers: Vec<String>,
    pub reason: String,
}

/// Per-package policy overrides.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct PackagePolicy {
    /// Suppress non-overlap suggestions for this dependency.
    #[serde(default)]
    pub suppress: bool,
}

/// Global policy settings.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct PolicySettings {
    /// Whether to run in offline mode by default.
    #[serde(default)]
    pub offline: bool,

    /// Whether to include dev-dependencies in analysis by default.
    #[serde(default)]
    pub all_targets: bool,
    /// Gate capability overlaps independently of impact levels.
    #[serde(default)]
    pub fail_on_overlap: bool,

    /// Optional minimum confidence for source audit findings.
    #[serde(default)]
    pub min_confidence: Option<AuditThreshold>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct CodeAuditPolicy {
    /// Suppress findings in package-relative paths containing any of these strings.
    #[serde(default)]
    pub ignore_paths: Vec<String>,

    /// Suppress findings with these kind names, e.g. "`UnwrapAbuse`".
    #[serde(default)]
    pub ignore_kinds: Vec<BullshitKind>,

    /// Include test-only items and test, example and benchmark targets.
    #[serde(default)]
    pub include_tests: bool,
}

/// Load policy from a anoint.toml file at the given path.
/// Returns an error if the file is missing, unreadable, or invalid.
///
/// # Errors
/// Returns an error for missing or unreadable files, invalid TOML, or invalid overlap exceptions.
pub fn try_load_policy(path: &Path) -> anyhow::Result<Policy> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("failed to read policy {}", path.display()))?;
    let policy: Policy = toml_edit::de::from_str(&content)
        .with_context(|| format!("failed to parse policy {}", path.display()))?;
    anyhow::ensure!(
        policy
            .code_audit
            .ignore_paths
            .iter()
            .all(|pattern| !pattern.trim().is_empty()),
        "code_audit.ignore_paths must not contain empty patterns"
    );
    for entry in &policy.allow_overlap {
        if entry.package.trim().is_empty()
            || entry.reason.trim().is_empty()
            || entry.providers.len() != 2
            || entry.providers.iter().any(|p| p.trim().is_empty())
            || entry
                .providers
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                != entry.providers.len()
        {
            anyhow::bail!(
                "invalid allow_overlap in {}: provide package, exactly two distinct providers, and a reason",
                path.display()
            );
        }
    }
    Ok(policy)
}

/// Filter suggestions based on policy rules.
/// - Removes suggestions for ignored packages.
/// - Applies per-package suppressions.
#[must_use = "Returns the filtered findings"]
pub fn apply_policy(
    suggestions: Vec<crate::suggestions::Suggestion>,
    policy: &Policy,
) -> Vec<crate::suggestions::Suggestion> {
    suggestions
        .into_iter()
        .filter(|s| {
            if s.kind == crate::suggestions::SuggestionKind::CapabilityOverlap {
                let providers: std::collections::BTreeSet<_> =
                    suggestion_crates(&s.current).collect();
                return !policy.allow_overlap.iter().any(|entry| {
                    s.package.as_deref() == Some(entry.package.as_str())
                        && providers == entry.providers.iter().map(String::as_str).collect()
                        && !entry.reason.trim().is_empty()
                });
            }
            // Check ignore_packages
            if suggestion_crates(&s.current)
                .any(|name| policy.ignore_packages.iter().any(|ignored| ignored == name))
            {
                return false;
            }

            // Check per-package suppress
            for pkg_name in s.current.split('+').map(str::trim) {
                if let Some(pkg_policy) = policy.packages.get(pkg_name)
                    && pkg_policy.suppress
                {
                    return false;
                }
            }

            true
        })
        .collect()
}

fn suggestion_crates(current: &str) -> impl Iterator<Item = &str> {
    current.split('+').map(str::trim)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_policy_from_string() -> anyhow::Result<()> {
        let toml_content = r#"
ignore_packages = ["ignored_dep"]

[packages.foo]
suppress = true
"#;
        let policy: Policy = toml_edit::de::from_str(toml_content)?;
        assert!(policy.ignore_packages.iter().any(|i| i == "ignored_dep"));
        assert!(policy.packages.get("foo").is_some_and(|p| p.suppress));
        Ok(())
    }

    #[test]
    fn rejects_unknown_policy_fields_and_audit_kinds() {
        for input in [
            "unknown = true",
            "fail_on = [\"critical\"]",
            "[settings]\nfail_on_overlaps = true",
            "[packages.foo]\npin_version = \"1.0\"",
            "[code_audit]\nignore_kinds = [\"UnwarpAbuse\"]",
        ] {
            assert!(toml_edit::de::from_str::<Policy>(input).is_err(), "{input}");
        }
    }

    #[test]
    fn explicit_zero_confidence_is_distinct_from_default() -> anyhow::Result<()> {
        let policy: Policy = toml_edit::de::from_str("[settings]\nmin_confidence = 0.0")?;
        let config = crate::code_audit::config_from_policy(Some(&policy));
        assert_eq!(config.confidence_threshold.get(), 0.0);
        assert!(
            crate::code_audit::config_from_policy(None)
                .confidence_threshold
                .get()
                > 0.0
        );
        Ok(())
    }

    #[test]
    fn policy_deserialization_rejects_invalid_confidence() {
        for value in ["nan", "inf", "-0.1", "1.1"] {
            assert!(
                toml_edit::de::from_str::<Policy>(&format!("[settings]\nmin_confidence = {value}"))
                    .is_err()
            );
        }
    }

    #[test]
    fn test_apply_policy_suppress() {
        let policy = Policy {
            packages: HashMap::from_iter([(
                "lazy_static".to_string(),
                PackagePolicy { suppress: true },
            )]),
            ..Default::default()
        };

        let suggestions = vec![crate::suggestions::Suggestion {
            kind: crate::suggestions::SuggestionKind::StdReplacement,
            current: "lazy_static".into(),
            recommended: "std::sync::LazyLock".into(),
            reason: "built-in since 1.80".into(),
            condition: None,
            source: "test".into(),
            impact: crate::suggestions::Impact::High,
            confidence: crate::suggestions::Confidence::High,
            migration_risk: crate::suggestions::MigrationRisk::Low,
            evidence_source: crate::suggestions::EvidenceSource::Heuristic,
            package: None,
        }];

        let filtered = apply_policy(suggestions, &policy);
        assert!(
            filtered.is_empty(),
            "suppressed suggestion should be removed"
        );
    }

    #[test]
    fn test_apply_policy_does_not_truncate_findings() {
        let policy = Policy::default();

        let suggestions: Vec<_> = (0..5)
            .map(|i| crate::suggestions::Suggestion {
                kind: crate::suggestions::SuggestionKind::ModernAlternative,
                current: format!("dep_{}", i),
                recommended: format!("new_dep_{}", i),
                reason: "test".into(),
                condition: None,
                source: "test".into(),
                impact: crate::suggestions::Impact::Low,
                confidence: crate::suggestions::Confidence::Medium,
                migration_risk: crate::suggestions::MigrationRisk::Medium,
                evidence_source: crate::suggestions::EvidenceSource::Heuristic,
                package: None,
            })
            .collect();

        let filtered = apply_policy(suggestions, &policy);
        assert_eq!(filtered.len(), 5, "must retain all gate findings");
    }

    #[test]
    fn test_ignore_packages_matches_exact_crate_tokens() {
        let policy = Policy {
            ignore_packages: vec!["rand".to_string()],
            ..Default::default()
        };

        let suggestions = vec![
            crate::suggestions::Suggestion {
                kind: crate::suggestions::SuggestionKind::ModernAlternative,
                current: "rand".into(),
                recommended: "getrandom".into(),
                reason: "test".into(),
                condition: None,
                source: "test".into(),
                impact: crate::suggestions::Impact::Low,
                confidence: crate::suggestions::Confidence::Medium,
                migration_risk: crate::suggestions::MigrationRisk::Medium,
                evidence_source: crate::suggestions::EvidenceSource::Heuristic,
                package: None,
            },
            crate::suggestions::Suggestion {
                kind: crate::suggestions::SuggestionKind::ModernAlternative,
                current: "fastrand".into(),
                recommended: "rand".into(),
                reason: "test".into(),
                condition: None,
                source: "test".into(),
                impact: crate::suggestions::Impact::Low,
                confidence: crate::suggestions::Confidence::Medium,
                migration_risk: crate::suggestions::MigrationRisk::Medium,
                evidence_source: crate::suggestions::EvidenceSource::Heuristic,
                package: None,
            },
        ];

        let filtered = apply_policy(suggestions, &policy);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].current, "fastrand");
    }
}
