//! Suggestion engine — rule-based recommendations from blessed.rs mappings.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::parser::ResolvedDep;

/// A modernization suggestion for a specific dependency.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Suggestion {
    pub kind: SuggestionKind,
    pub current: String,
    pub recommended: String,
    pub reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub condition: Option<String>,
    pub source: String,
    pub impact: Impact,
    pub confidence: Confidence,
    pub migration_risk: MigrationRisk,
    pub evidence_source: EvidenceSource,
    /// Workspace member that triggered this suggestion (root-only runs use `None`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub package: Option<String>,
}

/// The type of suggestion.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum SuggestionKind {
    /// Replace with a modern alternative crate.
    ModernAlternative,
    /// Enable a built-in feature to drop a separate dependency.
    FeatureOptimization,
    /// Replace with a std equivalent (e.g., `LazyLock`).
    StdReplacement,
    /// Consolidate multiple crates doing the same thing.
    ComboWin,
    /// Multiple independent providers of a curated capability.
    CapabilityOverlap,
    /// Crate is unmaintained — switch to maintained fork/successor.
    Unmaintained,
}

/// Impact level of a suggestion.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum Impact {
    High,
    Medium,
    Low,
}

/// Confidence level for a recommendation.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum Confidence {
    High,
    Medium,
    Low,
}

/// Estimated migration risk for applying a recommendation.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum MigrationRisk {
    High,
    Medium,
    Low,
}

/// Primary evidence behind a recommendation.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum EvidenceSource {
    BlessedRs,
    RustSec,
    StdDocs,
    CrateDocs,
    CratesIo,
    Heuristic,
}

/// The embedded blessed.rs-based rule database.
/// Each rule maps a current pattern to a recommended modern alternative.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub pattern: String,
    /// Inspect reachable dependencies, not only direct declarations.
    #[serde(default)]
    pub include_transitive: bool,
    pub replacement: String,
    pub kind: SuggestionKind,
    pub reason: String,
    pub source: String,
    pub condition: Option<String>,
    #[serde(default = "default_confidence")]
    pub confidence: Confidence,
    #[serde(default = "default_migration_risk")]
    pub migration_risk: MigrationRisk,
    #[serde(default = "default_evidence_source")]
    pub evidence_source: EvidenceSource,
}

/// Derive impact from suggestion kind.
const fn impact_for(kind: SuggestionKind) -> Impact {
    match kind {
        SuggestionKind::Unmaintained | SuggestionKind::StdReplacement => Impact::High,
        SuggestionKind::ModernAlternative
        | SuggestionKind::ComboWin
        | SuggestionKind::CapabilityOverlap => Impact::Medium,
        SuggestionKind::FeatureOptimization => Impact::Low,
    }
}

const fn default_confidence() -> Confidence {
    Confidence::Medium
}

const fn default_migration_risk() -> MigrationRisk {
    MigrationRisk::Medium
}

const fn default_evidence_source() -> EvidenceSource {
    EvidenceSource::Heuristic
}

/// Load the reviewed, version-controlled rule database. Live cache entries must not change CI results.
///
/// # Errors
/// Returns an error if the embedded suggestion database is invalid JSON.
pub fn load_rules() -> serde_json::Result<Vec<Rule>> {
    serde_json::from_str(include_str!("../data/suggestions.json"))
}

/// Analyze resolved dependencies against the reviewed rules and organization catalog.
///
/// Single and combo patterns match exact package names. Transitive matching is
/// opt-in per rule. Conditions are human-review requirements, not executable
/// predicates or claims about source usage.
/// # Errors
/// Returns an error if the embedded organization policy cannot be decoded.
pub fn analyze(
    deps: &[ResolvedDep],
    rules: &[Rule],
    package_label: Option<&str>,
) -> serde_json::Result<Vec<Suggestion>> {
    let direct_names: HashSet<&str> = deps
        .iter()
        .filter(|d| d.is_direct())
        .map(|d| d.name.as_str())
        .collect();

    let reachable_names: HashSet<_> = deps.iter().map(|dep| dep.name.as_str()).collect();
    let mut suggestions = Vec::new();
    for rule in rules {
        let names = if rule.include_transitive {
            &reachable_names
        } else {
            &direct_names
        };
        let matched = rule
            .pattern
            .split('+')
            .all(|name| names.contains(name.trim()));
        if matched {
            suggestions.push(Suggestion {
                kind: rule.kind,
                current: rule.pattern.clone(),
                recommended: rule.replacement.clone(),
                reason: rule.reason.clone(),
                condition: rule.condition.clone(),
                source: rule.source.clone(),
                impact: impact_for(rule.kind),
                confidence: rule.confidence,
                migration_risk: rule.migration_risk,
                evidence_source: rule.evidence_source,
                package: package_label.map(String::from),
            });
        }
    }

    suggestions.extend(crate::organization::analyze(deps, package_label)?);
    Ok(suggestions)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_rules() {
        let rules = load_rules().unwrap();
        assert!(
            rules.len() >= 15,
            "should load at least 15 rules, got {}",
            rules.len()
        );

        // Spot-check a known rule
        let lazy = rules.iter().find(|r| r.pattern == "lazy_static").unwrap();
        assert_eq!(lazy.replacement, "std::sync::LazyLock");
        assert!(matches!(lazy.kind, SuggestionKind::StdReplacement));
    }

    #[test]
    fn test_analyze_single_crate_match() {
        let rules = load_rules().unwrap();
        let deps = vec![
            ResolvedDep {
                name: "lazy_static".into(),
                version: "1.5.0".into(),
                enabled_features: vec![],
                available_features: vec![],
                source: Some("registry".into()),
                repository: None,

                direct_kinds: vec![cargo_metadata::DependencyKind::Normal],
            },
            ResolvedDep {
                name: "serde".into(),
                version: "1.0.0".into(),
                enabled_features: vec![],
                available_features: vec![],
                source: Some("registry".into()),
                repository: None,

                direct_kinds: vec![cargo_metadata::DependencyKind::Normal],
            },
        ];

        let suggestions = analyze(&deps, &rules, None).unwrap();
        assert_eq!(suggestions.len(), 1);
        assert_eq!(suggestions[0].current, "lazy_static");
        assert_eq!(suggestions[0].recommended, "std::sync::LazyLock");
        assert_eq!(suggestions[0].impact, Impact::High);
    }

    #[test]
    fn test_analyze_combo_match() {
        let deps = vec![
            ResolvedDep {
                name: "reqwest".into(),
                version: "0.12.0".into(),
                enabled_features: vec![],
                available_features: vec![],
                source: Some("registry".into()),
                repository: None,

                direct_kinds: vec![cargo_metadata::DependencyKind::Normal],
            },
            ResolvedDep {
                name: "some_unused_crate".into(),
                version: "1.0.0".into(),
                enabled_features: vec![],
                available_features: vec![],
                source: Some("registry".into()),
                repository: None,

                direct_kinds: vec![cargo_metadata::DependencyKind::Normal],
            },
        ];

        // Exercise a reviewed combination independently of the current directory.
        let custom_rule = Rule {
            pattern: "reqwest+some_unused_crate".into(),
            include_transitive: false,
            replacement: "reqwest with some feature".into(),
            kind: SuggestionKind::FeatureOptimization,
            reason: "".into(),
            source: "".into(),
            condition: Some("verify API and feature compatibility".into()),
            confidence: Confidence::High,
            migration_risk: MigrationRisk::Low,
            evidence_source: EvidenceSource::Heuristic,
        };

        let suggestions: Vec<_> = analyze(&deps, &[custom_rule], None)
            .unwrap()
            .into_iter()
            .filter(|s| s.current == "reqwest+some_unused_crate")
            .collect();
        assert_eq!(suggestions.len(), 1);
        assert_eq!(suggestions[0].current, "reqwest+some_unused_crate");
        assert!(matches!(
            suggestions[0].kind,
            SuggestionKind::FeatureOptimization
        ));
        assert_eq!(suggestions[0].impact, Impact::Low);
        assert_eq!(
            suggestions[0].condition.as_deref(),
            Some("verify API and feature compatibility")
        );
    }

    #[test]
    fn test_analyze_combo_partial_no_match() {
        let rules = load_rules().unwrap();
        // Only reqwest present, no serde_json — combo should NOT fire
        let deps = vec![ResolvedDep {
            name: "reqwest".into(),
            version: "0.12.0".into(),
            enabled_features: vec![],
            available_features: vec![],
            source: Some("registry".into()),
            repository: None,

            direct_kinds: vec![cargo_metadata::DependencyKind::Normal],
        }];

        let suggestions = analyze(&deps, &rules, None).unwrap();
        assert!(
            !suggestions
                .iter()
                .any(|s| s.kind == SuggestionKind::ComboWin),
            "combo rule should not fire with only one of the pair"
        );
    }

    #[test]
    fn test_analyze_ignores_transitive() {
        let rules = load_rules().unwrap();
        let deps = vec![ResolvedDep {
            name: "lazy_static".into(),
            version: "1.5.0".into(),
            enabled_features: vec![],
            available_features: vec![],
            source: Some("registry".into()),
            repository: None,

            direct_kinds: vec![], // transitive — should be ignored
        }];

        let suggestions = analyze(&deps, &rules, None).unwrap();
        assert!(
            suggestions.is_empty(),
            "transitive deps should not trigger suggestions"
        );
    }

    #[test]
    fn test_analyze_multiple_matches() {
        let rules = load_rules().unwrap();
        let deps = vec![
            ResolvedDep {
                name: "lazy_static".into(),
                version: "1.5.0".into(),
                enabled_features: vec![],
                available_features: vec![],
                source: Some("registry".into()),
                repository: None,

                direct_kinds: vec![cargo_metadata::DependencyKind::Normal],
            },
            ResolvedDep {
                name: "structopt".into(),
                version: "0.3.0".into(),
                enabled_features: vec![],
                available_features: vec![],
                source: Some("registry".into()),
                repository: None,

                direct_kinds: vec![cargo_metadata::DependencyKind::Normal],
            },
            ResolvedDep {
                name: "memmap".into(),
                version: "0.7.0".into(),
                enabled_features: vec![],
                available_features: vec![],
                source: Some("registry".into()),
                repository: None,

                direct_kinds: vec![cargo_metadata::DependencyKind::Normal],
            },
        ];

        let suggestions = analyze(&deps, &rules, None).unwrap();
        assert_eq!(suggestions.len(), 3);

        let names: Vec<&str> = suggestions.iter().map(|s| s.current.as_str()).collect();
        assert!(names.contains(&"lazy_static"));
        assert!(names.contains(&"structopt"));
        assert!(names.contains(&"memmap"));
    }

    #[test]
    fn test_analyze_clean_project() {
        let rules = load_rules().unwrap();
        // Modern deps that shouldn't trigger any rules
        let deps = vec![
            ResolvedDep {
                name: "clap".into(),
                version: "4.5.0".into(),
                enabled_features: vec!["derive".into()],
                available_features: vec![],
                source: Some("registry".into()),
                repository: None,

                direct_kinds: vec![cargo_metadata::DependencyKind::Normal],
            },
            ResolvedDep {
                name: "serde".into(),
                version: "1.0.0".into(),
                enabled_features: vec!["derive".into()],
                available_features: vec![],
                source: Some("registry".into()),
                repository: None,

                direct_kinds: vec![cargo_metadata::DependencyKind::Normal],
            },
        ];

        let suggestions = analyze(&deps, &rules, None).unwrap();
        assert!(
            suggestions.is_empty(),
            "modern deps should not trigger any suggestions"
        );
    }

    #[test]
    fn test_impact_derivation() {
        assert_eq!(impact_for(SuggestionKind::Unmaintained), Impact::High);
        assert_eq!(impact_for(SuggestionKind::StdReplacement), Impact::High);
        assert_eq!(
            impact_for(SuggestionKind::ModernAlternative),
            Impact::Medium
        );
        assert_eq!(impact_for(SuggestionKind::ComboWin), Impact::Medium);
        assert_eq!(impact_for(SuggestionKind::FeatureOptimization), Impact::Low);
    }
    #[test]
    fn unmaintained_fxhash_is_reported_transitively() {
        let dep = ResolvedDep {
            name: "fxhash".into(),
            version: "0.2.1".into(),
            enabled_features: vec![],
            available_features: vec![],
            source: None,
            repository: None,

            direct_kinds: vec![],
        };
        let findings = analyze(&[dep], &load_rules().expect("embedded rules"), None)
            .expect("organization policy");
        assert!(findings.iter().any(|f| f.current == "fxhash"
            && f.kind == SuggestionKind::Unmaintained
            && f.evidence_source == EvidenceSource::RustSec));
    }
}
