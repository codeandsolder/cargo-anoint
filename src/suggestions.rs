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
    pub source: String,
    pub impact: Impact,
    pub confidence: Confidence,
    pub migration_risk: MigrationRisk,
    pub autofix_safety: AutofixSafety,
    pub evidence_source: EvidenceSource,
    /// Workspace member that triggered this suggestion (root-only runs use `None`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub package: Option<String>,
}

impl Suggestion {
    /// Whether this suggestion can be auto-applied by editing Cargo.toml only.
    /// Only suggestions explicitly marked as Cargo.toml-only are eligible.
    #[must_use = "Use the result to decide whether editing the manifest is sufficient"]
    pub const fn is_auto_fixable(&self) -> bool {
        matches!(self.autofix_safety, AutofixSafety::CargoTomlOnly)
    }
}

/// The type of suggestion.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
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
    /// A workload-sensitive or indirect independent-provider overlap; never a focused gate failure.
    AdvisoryOverlap,
    /// Crate is unmaintained — switch to maintained fork/successor.
    Unmaintained,
}

/// Impact level of a suggestion.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum Impact {
    High,
    Medium,
    Low,
}

/// Confidence level for a recommendation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Confidence {
    High,
    Medium,
    Low,
}

/// Estimated migration risk for applying a recommendation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum MigrationRisk {
    High,
    Medium,
    Low,
}

/// Whether cargo-anoint may safely apply the suggestion itself.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AutofixSafety {
    /// Safe to apply by changing Cargo.toml only.
    CargoTomlOnly,
    /// Requires source review or source edits.
    ManualOnly,
}

/// Primary evidence behind a recommendation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
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
    #[serde(default = "default_autofix_safety")]
    pub autofix_safety: AutofixSafety,
    #[serde(default = "default_evidence_source")]
    pub evidence_source: EvidenceSource,
}

/// Derive impact from suggestion kind.
const fn impact_for(kind: &SuggestionKind) -> Impact {
    match kind {
        SuggestionKind::Unmaintained | SuggestionKind::StdReplacement => Impact::High,
        SuggestionKind::ModernAlternative
        | SuggestionKind::ComboWin
        | SuggestionKind::CapabilityOverlap
        | SuggestionKind::AdvisoryOverlap => Impact::Medium,
        SuggestionKind::FeatureOptimization => Impact::Low,
    }
}

const fn default_confidence() -> Confidence {
    Confidence::Medium
}

const fn default_migration_risk() -> MigrationRisk {
    MigrationRisk::Medium
}

const fn default_autofix_safety() -> AutofixSafety {
    AutofixSafety::ManualOnly
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

use std::fs;
/// Analyze resolved dependencies against the rule database.
///
/// Matching strategies:
/// - **Single-crate** rules (pattern has no `+`): fire if a direct dep has that name.
/// - **Combo** rules (pattern contains `+`): fire if ALL named crates are present
///   as direct deps.
use std::path::Path;

///
/// # Errors
/// Returns an error if the embedded organization policy cannot be decoded.
pub fn analyze(
    manifest_path: Option<&Path>,
    deps: &[ResolvedDep],
    rules: &[Rule],
) -> serde_json::Result<Vec<Suggestion>> {
    analyze_for_package(manifest_path, deps, rules, None)
}

/// Like [`analyze`], but tags each suggestion with `package` for workspace output.
///
/// # Errors
/// Returns an error if the embedded organization policy cannot be decoded.
pub fn analyze_for_package(
    manifest_path: Option<&Path>,
    deps: &[ResolvedDep],
    rules: &[Rule],
    package_label: Option<&str>,
) -> serde_json::Result<Vec<Suggestion>> {
    let direct_names: HashSet<&str> = deps
        .iter()
        .filter(|d| d.is_direct)
        .map(|d| d.name.as_str())
        .collect();

    let mut suggestions = Vec::new();

    for rule in rules {
        let matched = if rule.pattern.contains('+') {
            // Combo rule: all named crates must be present
            let all_present = rule
                .pattern
                .split('+')
                .all(|name| direct_names.contains(name.trim()));

            if all_present {
                // For FeatureOptimization combo rules (like `reqwest+serde_json`),
                // check if the second crate is actually used directly in the codebase.
                // If it is, we shouldn't recommend dropping it.
                if rule.kind == SuggestionKind::FeatureOptimization {
                    let parts: Vec<&str> = rule.pattern.split('+').collect();
                    if parts.len() == 2 {
                        let extra_crate = parts[1].trim();
                        if is_crate_used_in_source(manifest_path, extra_crate) {
                            continue;
                        }
                    }
                }
                true
            } else {
                false
            }
        } else {
            // Single-crate rule: exact name match
            direct_names.contains(rule.pattern.as_str())
                || (rule.include_transitive && deps.iter().any(|dep| dep.name == rule.pattern))
        };

        if matched {
            suggestions.push(Suggestion {
                kind: rule.kind.clone(),
                current: rule.pattern.clone(),
                recommended: rule.replacement.clone(),
                reason: rule.reason.clone(),
                source: rule.source.clone(),
                impact: impact_for(&rule.kind),
                confidence: rule.confidence.clone(),
                migration_risk: rule.migration_risk.clone(),
                autofix_safety: rule.autofix_safety.clone(),
                evidence_source: rule.evidence_source.clone(),
                package: package_label.map(String::from),
            });
        }
    }

    suggestions.extend(crate::organization::analyze(deps, package_label)?);
    Ok(suggestions)
}

/// Review provider divergence across selected workspace members.
///
/// # Errors
/// Returns an error if the embedded organization policy cannot be decoded.
pub fn analyze_workspace(
    snapshots: &[crate::parser::PackageResult],
) -> serde_json::Result<Vec<Suggestion>> {
    crate::organization::analyze_workspace(snapshots)
}

/// Recursively scans `.rs` files in the project to determine if the crate is imported or used.
/// Checks `src`, `tests`, `benches`, and `examples` directories relative to the `manifest_path`.
fn is_crate_used_in_source(manifest_path: Option<&Path>, crate_name: &str) -> bool {
    let base_dir = manifest_path
        .and_then(|p| p.parent())
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));

    let crate_ident = crate_name.replace('-', "_");

    // We check for some common usage patterns of the crate identifier
    let patterns = [
        format!("use {crate_ident}::"),
        format!("use {crate_ident};"),
        format!("{crate_ident}::"),
        format!("{crate_ident}!"),
    ];

    let dirs_to_check = ["src", "tests", "benches", "examples"];

    for dir_name in dirs_to_check {
        let dir_path = base_dir.join(dir_name);
        if !dir_path.exists() || !dir_path.is_dir() {
            continue;
        }

        if scan_dir_for_patterns(&dir_path, &patterns) {
            return true;
        }
    }

    false
}

fn scan_dir_for_patterns(dir: &Path, patterns: &[String]) -> bool {
    let Ok(entries) = fs::read_dir(dir) else {
        return false;
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if scan_dir_for_patterns(&path, patterns) {
                return true;
            }
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs")
            && let Ok(contents) = fs::read_to_string(&path)
        {
            for pattern in patterns {
                if contents.contains(pattern) {
                    return true;
                }
            }
        }
    }

    false
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
    fn reviewed_modernization_rules_are_unique_and_manual_only() {
        let rules = load_rules().expect("embedded rules");
        let mut patterns = HashSet::new();
        for rule in &rules {
            assert!(
                patterns.insert(&rule.pattern),
                "duplicate rule: {}",
                rule.pattern
            );
        }
        for name in [
            "memoffset",
            "fs2",
            "array-macro",
            "wee_alloc",
            "proc-macro-error",
            "proc-macro-error2",
            "rustls-pemfile",
            "im-rc",
            "winapi",
            "unsafe-libyaml",
            "rust_socketio",
        ] {
            let rule = rules
                .iter()
                .find(|rule| rule.pattern == name)
                .expect("reviewed rule");
            assert_eq!(rule.autofix_safety, AutofixSafety::ManualOnly);
            assert!(rule.include_transitive);
            assert!(rule.source.starts_with("https://"));
        }
        for name in ["proc-macro-error", "proc-macro-error2"] {
            let rule = rules
                .iter()
                .find(|rule| rule.pattern == name)
                .expect("diagnostic rule");
            assert_eq!(rule.kind, SuggestionKind::Unmaintained);
            assert_eq!(rule.replacement, "syn::Error / manyhow");
        }
    }

    #[test]
    fn modernization_advice_respects_direct_and_transitive_scope() {
        let rules = load_rules().expect("embedded rules");
        for is_direct in [false, true] {
            let deps: Vec<_> = [
                "memoffset",
                "proc-macro-error2",
                "version_check",
                "natord",
                "num-traits",
            ]
            .into_iter()
            .map(|name| ResolvedDep {
                name: name.into(),
                version: "0.1.0".into(),
                enabled_features: vec![],
                available_features: vec![],
                source: Some("registry".into()),
                repository: None,
                is_direct,
                normal_dependencies: vec![],
                direct_kinds: if is_direct {
                    vec![cargo_metadata::DependencyKind::Normal]
                } else {
                    vec![]
                },
            })
            .collect();
            let findings = analyze_for_package(None, &deps, &rules, Some("consumer"))
                .expect("embedded policy");
            for name in ["memoffset", "proc-macro-error2"] {
                assert!(findings.iter().any(|finding| finding.current == name
                    && finding.package.as_deref() == Some("consumer")));
            }
            for name in ["version_check", "natord"] {
                assert_eq!(
                    findings.iter().any(|finding| finding.current == name),
                    is_direct
                );
            }
            assert!(
                !findings
                    .iter()
                    .any(|finding| finding.current == "num-traits")
            );
            assert!(findings.iter().all(|finding| !finding.is_auto_fixable()
                && finding.kind != SuggestionKind::CapabilityOverlap));
        }
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
                is_direct: true,
                normal_dependencies: vec![],
                direct_kinds: vec![cargo_metadata::DependencyKind::Normal],
            },
            ResolvedDep {
                name: "serde".into(),
                version: "1.0.0".into(),
                enabled_features: vec![],
                available_features: vec![],
                source: Some("registry".into()),
                repository: None,
                is_direct: true,
                normal_dependencies: vec![],
                direct_kinds: vec![cargo_metadata::DependencyKind::Normal],
            },
        ];

        let suggestions = analyze(None, &deps, &rules).unwrap();
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
                is_direct: true,
                normal_dependencies: vec![],
                direct_kinds: vec![cargo_metadata::DependencyKind::Normal],
            },
            ResolvedDep {
                // Use a crate name that definitely isn't used in this test file
                name: "some_unused_crate".into(),
                version: "1.0.0".into(),
                enabled_features: vec![],
                available_features: vec![],
                source: Some("registry".into()),
                repository: None,
                is_direct: true,
                normal_dependencies: vec![],
                direct_kinds: vec![cargo_metadata::DependencyKind::Normal],
            },
        ];

        // Create a custom rule to avoid triggering the usage grep for real dependencies
        let custom_rule = Rule {
            pattern: "reqwest+some_unused_crate".into(),
            include_transitive: false,
            replacement: "reqwest with some feature".into(),
            kind: SuggestionKind::FeatureOptimization,
            reason: "".into(),
            source: "".into(),
            condition: None,
            confidence: Confidence::High,
            migration_risk: MigrationRisk::Low,
            autofix_safety: AutofixSafety::CargoTomlOnly,
            evidence_source: EvidenceSource::Heuristic,
        };

        let suggestions: Vec<_> = analyze(None, &deps, &[custom_rule])
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
            is_direct: true,
            normal_dependencies: vec![],
            direct_kinds: vec![cargo_metadata::DependencyKind::Normal],
        }];

        let suggestions = analyze(None, &deps, &rules).unwrap();
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
            is_direct: false,
            normal_dependencies: vec![],
            direct_kinds: vec![], // transitive — should be ignored
        }];

        let suggestions = analyze(None, &deps, &rules).unwrap();
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
                is_direct: true,
                normal_dependencies: vec![],
                direct_kinds: vec![cargo_metadata::DependencyKind::Normal],
            },
            ResolvedDep {
                name: "structopt".into(),
                version: "0.3.0".into(),
                enabled_features: vec![],
                available_features: vec![],
                source: Some("registry".into()),
                repository: None,
                is_direct: true,
                normal_dependencies: vec![],
                direct_kinds: vec![cargo_metadata::DependencyKind::Normal],
            },
            ResolvedDep {
                name: "memmap".into(),
                version: "0.7.0".into(),
                enabled_features: vec![],
                available_features: vec![],
                source: Some("registry".into()),
                repository: None,
                is_direct: true,
                normal_dependencies: vec![],
                direct_kinds: vec![cargo_metadata::DependencyKind::Normal],
            },
        ];

        let suggestions = analyze(None, &deps, &rules).unwrap();
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
                is_direct: true,
                normal_dependencies: vec![],
                direct_kinds: vec![cargo_metadata::DependencyKind::Normal],
            },
            ResolvedDep {
                name: "serde".into(),
                version: "1.0.0".into(),
                enabled_features: vec!["derive".into()],
                available_features: vec![],
                source: Some("registry".into()),
                repository: None,
                is_direct: true,
                normal_dependencies: vec![],
                direct_kinds: vec![cargo_metadata::DependencyKind::Normal],
            },
        ];

        let suggestions = analyze(None, &deps, &rules).unwrap();
        assert!(
            suggestions.is_empty(),
            "modern deps should not trigger any suggestions"
        );
    }

    #[test]
    fn test_impact_derivation() {
        assert_eq!(impact_for(&SuggestionKind::Unmaintained), Impact::High);
        assert_eq!(impact_for(&SuggestionKind::StdReplacement), Impact::High);
        assert_eq!(
            impact_for(&SuggestionKind::ModernAlternative),
            Impact::Medium
        );
        assert_eq!(impact_for(&SuggestionKind::ComboWin), Impact::Medium);
        assert_eq!(
            impact_for(&SuggestionKind::FeatureOptimization),
            Impact::Low
        );
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
            is_direct: false,
            normal_dependencies: vec![],
            direct_kinds: vec![],
        };
        let findings = analyze(None, &[dep], &load_rules().expect("embedded rules"))
            .expect("organization policy");
        assert!(findings.iter().any(|f| f.current == "fxhash"
            && f.kind == SuggestionKind::Unmaintained
            && f.evidence_source == EvidenceSource::RustSec));
    }
}
