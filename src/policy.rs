//! Policy layer — parses anoint.toml for custom rules, overrides, and enforcement settings.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

/// Top-level policy configuration loaded from anoint.toml.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Policy {
    /// Custom suggestion rules to add or override defaults.
    #[serde(default)]
    pub rules: Vec<PolicyRule>,

    /// Packages to exclude from analysis entirely.
    #[serde(default)]
    pub ignore_packages: Vec<String>,

    /// Override the default fail-on severity thresholds.
    #[serde(default)]
    pub fail_on: Option<Vec<String>>,

    /// Per-package overrides (e.g., pin a version, suppress specific rules).
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
pub struct OverlapException {
    pub package: String,
    pub providers: Vec<String>,
    pub reason: String,
}

/// A custom rule from anoint.toml.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    /// Crate name or combo pattern (e.g., "`reqwest+serde_json`").
    pub pattern: String,

    /// Recommended replacement.
    pub replacement: String,

    /// Reason for the suggestion.
    pub reason: String,

    /// Kind of suggestion. Defaults to "`modern_alternative`" if omitted.
    #[serde(default = "default_rule_kind")]
    pub kind: String,

    /// Optional condition (e.g., "version < 0.12").
    pub condition: Option<String>,
}

fn default_rule_kind() -> String {
    "modern_alternative".to_string()
}

/// Per-package policy overrides.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PackagePolicy {
    /// Suppress all suggestions for this package.
    #[serde(default)]
    pub suppress: bool,

    /// Pin to a specific version (prevents upgrade suggestions).
    pub pin_version: Option<String>,

    /// Custom reason for keeping the current dependency.
    pub keep_reason: Option<String>,
}

/// Global policy settings.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
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

    /// Reserved confidence threshold for future machine-assisted suggestions.
    #[serde(default)]
    pub min_confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CodeAuditPolicy {
    /// Suppress findings in paths containing any of these strings.
    #[serde(default)]
    pub ignore_paths: Vec<String>,

    /// Suppress findings with these kind names, e.g. "`UnwrapAbuse`".
    #[serde(default)]
    pub ignore_kinds: Vec<String>,

    /// Also scan tests/, examples/, and benches/ (default: false — src/ only).
    #[serde(default)]
    pub include_tests: bool,
}

/// Load policy from a anoint.toml file at the given path.
/// Returns None if the file does not exist or cannot be parsed.
#[must_use = "Returns the policy if it could be read"]
pub fn load_policy(path: &Path) -> Option<Policy> {
    try_load_policy(path).ok()
}

/// Load policy from a anoint.toml file at the given path.
/// Returns an error if the file is missing, unreadable, or invalid.
///
/// # Errors
/// Returns an error for missing or unreadable files, invalid TOML, or invalid overlap exceptions.
pub fn try_load_policy(path: &Path) -> anyhow::Result<Policy> {
    let content = fs::read_to_string(path)
        .map_err(|err| anyhow::anyhow!("failed to read policy {}: {err}", path.display()))?;
    let policy: Policy = toml_edit::de::from_str(&content)
        .map_err(|err| anyhow::anyhow!("failed to parse policy {}: {err}", path.display()))?;
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
/// - Applies per-package suppress/pin overrides.
#[must_use = "Returns the filtered findings"]
pub fn apply_policy(
    suggestions: Vec<crate::suggestions::Suggestion>,
    policy: &Policy,
) -> Vec<crate::suggestions::Suggestion> {
    let filtered: Vec<_> = suggestions
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
        .collect();

    filtered
}

fn suggestion_crates(current: &str) -> impl Iterator<Item = &str> {
    current.split('+').map(str::trim)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_policy_from_string() {
        let toml_content = r#"
ignore_packages = ["ignored_dep"]

[[rules]]
pattern = "old_crate"
replacement = "new_crate"
reason = "old_crate is unmaintained"
kind = "modern_alternative"

[packages.foo]
suppress = true
"#;
        let policy: Policy = toml_edit::de::from_str(toml_content).unwrap();
        assert_eq!(policy.rules.len(), 1);
        assert_eq!(policy.rules[0].pattern, "old_crate");
        assert!(policy.ignore_packages.iter().any(|i| i == "ignored_dep"));
        assert!(policy.packages.get("foo").unwrap().suppress);
    }

    #[test]
    fn test_apply_policy_suppress() {
        let policy = Policy {
            packages: HashMap::from_iter([(
                "lazy_static".to_string(),
                PackagePolicy {
                    suppress: true,
                    pin_version: None,
                    keep_reason: None,
                },
            )]),
            ..Default::default()
        };

        let suggestions = vec![crate::suggestions::Suggestion {
            kind: crate::suggestions::SuggestionKind::StdReplacement,
            current: "lazy_static".into(),
            recommended: "std::sync::LazyLock".into(),
            reason: "built-in since 1.80".into(),
            source: "test".into(),
            impact: crate::suggestions::Impact::High,
            confidence: crate::suggestions::Confidence::High,
            migration_risk: crate::suggestions::MigrationRisk::Low,
            autofix_safety: crate::suggestions::AutofixSafety::ManualOnly,
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
                source: "test".into(),
                impact: crate::suggestions::Impact::Low,
                confidence: crate::suggestions::Confidence::Medium,
                migration_risk: crate::suggestions::MigrationRisk::Medium,
                autofix_safety: crate::suggestions::AutofixSafety::ManualOnly,
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
                source: "test".into(),
                impact: crate::suggestions::Impact::Low,
                confidence: crate::suggestions::Confidence::Medium,
                migration_risk: crate::suggestions::MigrationRisk::Medium,
                autofix_safety: crate::suggestions::AutofixSafety::ManualOnly,
                evidence_source: crate::suggestions::EvidenceSource::Heuristic,
                package: None,
            },
            crate::suggestions::Suggestion {
                kind: crate::suggestions::SuggestionKind::ModernAlternative,
                current: "fastrand".into(),
                recommended: "rand".into(),
                reason: "test".into(),
                source: "test".into(),
                impact: crate::suggestions::Impact::Low,
                confidence: crate::suggestions::Confidence::Medium,
                migration_risk: crate::suggestions::MigrationRisk::Medium,
                autofix_safety: crate::suggestions::AutofixSafety::ManualOnly,
                evidence_source: crate::suggestions::EvidenceSource::Heuristic,
                package: None,
            },
        ];

        let filtered = apply_policy(suggestions, &policy);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].current, "fastrand");
    }
}
