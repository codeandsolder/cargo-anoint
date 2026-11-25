//! Curated organization preferences and potential capability overlaps.
use std::collections::BTreeSet;

use serde::Deserialize;

use crate::parser::ResolvedDep;
use crate::suggestions::{
    AutofixSafety, Confidence, EvidenceSource, Impact, MigrationRisk, Suggestion, SuggestionKind,
};

#[derive(Deserialize)]
struct Policy {
    forks: Vec<Fork>,
    capabilities: Vec<Capability>,
    preferences: Vec<Preference>,
    feature_preferences: Vec<FeaturePreference>,
}

#[derive(Deserialize)]
struct Fork {
    repository: String,
    packages: Vec<String>,
}

#[derive(Deserialize)]
struct Capability {
    name: String,
    providers: Vec<String>,
    #[serde(default)]
    complementary_pairs: Vec<[String; 2]>,
    preferred: String,
    notes: String,
}

#[derive(Deserialize)]
struct Preference {
    packages: Vec<String>,
    preferred: String,
    notes: String,
}

#[derive(Deserialize)]
struct FeaturePreference {
    package: String,
    preferred_feature: String,
    competing_features: Vec<String>,
    preferred: String,
    notes: String,
}

/// Cargo's resolved source is authoritative: repository metadata is often inherited
/// unchanged from upstream. Local/workspace packages have no source and cannot
/// be attributed to a remote based on their name alone.
fn git_repository(source: &str) -> Option<&str> {
    let url = source.strip_prefix("git+")?;
    let base = url.split(['?', '#']).next()?;
    Some(base.trim_end_matches('/').trim_end_matches(".git"))
}

fn preferred_source(source: &str, repository: &str) -> bool {
    let Some(url) = git_repository(source) else {
        return false;
    };
    [
        "https://github.com/",
        "ssh://git@github.com/",
        "git://github.com/",
    ]
    .iter()
    .filter_map(|prefix| url.strip_prefix(prefix))
    .any(|path| path.eq_ignore_ascii_case(&format!("codeandsolder/{repository}")))
}

fn finding(
    current: String,
    recommended: String,
    reason: String,
    kind: SuggestionKind,
    package: Option<&str>,
) -> Suggestion {
    Suggestion {
        kind,
        current,
        recommended,
        reason,
        source: "codeandsolder dependency policy".into(),
        impact: Impact::Medium,
        confidence: Confidence::Medium,
        migration_risk: MigrationRisk::High,
        autofix_safety: AutofixSafety::ManualOnly,
        evidence_source: EvidenceSource::Heuristic,
        package: package.map(str::to_owned),
    }
}

pub fn analyze(deps: &[ResolvedDep], package: Option<&str>) -> serde_json::Result<Vec<Suggestion>> {
    let policy: Policy = serde_json::from_str(include_str!("../data/organization.json"))?;
    let direct: Vec<_> = deps.iter().filter(|dep| dep.is_direct).collect();
    let names: BTreeSet<&str> = direct.iter().map(|dep| dep.name.as_str()).collect();
    let mut results = Vec::new();

    for fork in &policy.forks {
        for name in &fork.packages {
            let sources: BTreeSet<_> = deps
                .iter()
                .filter(|dep| &dep.name == name)
                .filter_map(|dep| dep.source.as_deref().map(|source| (dep.is_direct, source)))
                .filter(|(_, source)| !preferred_source(source, &fork.repository))
                .map(|(direct, source)| {
                    format!("{}: {source}", if direct { "direct" } else { "transitive" })
                })
                .collect();
            if !sources.is_empty() {
                results.push(finding(
                    name.clone(),
                    format!("{name} from https://github.com/codeandsolder/{}", fork.repository),
                    format!("Prefer the maintained organization fork when applicable; resolved non-preferred source(s): {}. Verify the fork's API, features, and revision; for transitive dependencies inspect the owning dependency or a source-compatible Cargo patch.", sources.into_iter().collect::<Vec<_>>().join(", ")),
                    SuggestionKind::ModernAlternative,
                    package,
                ));
            }
        }
    }

    for preference in &policy.preferences {
        for name in &preference.packages {
            if names.contains(name.as_str()) {
                results.push(finding(
                    name.clone(),
                    preference.preferred.clone(),
                    preference.notes.clone(),
                    SuggestionKind::ModernAlternative,
                    package,
                ));
            }
        }
    }

    for preference in &policy.feature_preferences {
        for dep in &direct {
            if dep.name == preference.package
                && dep
                    .available_features
                    .contains(&preference.preferred_feature)
                && !dep.enabled_features.contains(&preference.preferred_feature)
                && preference
                    .competing_features
                    .iter()
                    .any(|feature| dep.enabled_features.contains(feature))
            {
                results.push(finding(
                    dep.name.clone(),
                    preference.preferred.clone(),
                    preference.notes.clone(),
                    SuggestionKind::FeatureOptimization,
                    package,
                ));
            }
        }
    }

    append_overlap_findings(&policy.capabilities, &direct, package, &mut results);
    Ok(results)
}

fn append_overlap_findings(
    capabilities: &[Capability],
    direct: &[&ResolvedDep],
    package: Option<&str>,
    results: &mut Vec<Suggestion>,
) {
    for capability in capabilities {
        let mut reported = BTreeSet::new();
        for kind in [
            cargo_metadata::DependencyKind::Normal,
            cargo_metadata::DependencyKind::Development,
            cargo_metadata::DependencyKind::Build,
        ] {
            let present: Vec<_> = capability
                .providers
                .iter()
                .filter(|name| {
                    direct
                        .iter()
                        .any(|dep| dep.name == **name && dep.direct_kinds.contains(&kind))
                })
                .map(String::as_str)
                .collect();
            for (i, left) in present.iter().enumerate() {
                for right in &present[i + 1..] {
                    if capability.complementary_pairs.iter().any(|pair| {
                        (pair[0] == *left && pair[1] == *right)
                            || (pair[1] == *left && pair[0] == *right)
                    }) {
                        continue;
                    }
                    let current = format!("{left}+{right}");
                    if reported.insert(current.clone()) {
                        results.push(finding(
                            current,
                            capability.preferred.clone(),
                            format!(
                                "Potential overlapping {} providers. {}",
                                capability.name, capability.notes
                            ),
                            SuggestionKind::CapabilityOverlap,
                            package,
                        ));
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dep(name: &str, source: Option<&str>, direct: bool) -> ResolvedDep {
        ResolvedDep {
            name: name.into(),
            version: "1.0.0".into(),
            enabled_features: vec![],
            available_features: vec![],
            source: source.map(str::to_owned),
            repository: Some("https://github.com/upstream/project".into()),
            is_direct: direct,
            direct_kinds: if direct {
                vec![cargo_metadata::DependencyKind::Normal]
            } else {
                vec![]
            },
        }
    }

    #[test]
    fn verifies_resolved_source_not_repository_metadata() {
        let good = dep(
            "wreq",
            Some("git+https://github.com/codeandsolder/wreq-exp.git?rev=abc#abc"),
            true,
        );
        assert!(analyze(&[good], None).unwrap().is_empty());
        let upstream = dep(
            "wreq",
            Some("git+https://github.com/0x676e67/wreq#abc"),
            true,
        );
        assert_eq!(analyze(&[upstream], None).unwrap().len(), 1);
        let registry = dep(
            "btls",
            Some("registry+https://github.com/rust-lang/crates.io-index"),
            true,
        );
        assert_eq!(analyze(&[registry], None).unwrap().len(), 1);
        assert!(
            analyze(&[dep("btls", None, true)], None)
                .unwrap()
                .is_empty()
        );
        assert!(!preferred_source(
            "git+https://github.com/codeandsolder/wreq-exp-imposter#abc",
            "wreq-exp"
        ));
    }

    #[test]
    fn reports_independent_providers_but_not_layers() {
        let findings = analyze(
            &[
                dep("wreq", None, true),
                dep("reqwest", None, true),
                dep("hyper", None, true),
                dep("axum", None, true),
                dep("ureq", None, false),
            ],
            Some("app"),
        )
        .unwrap();
        let combos: Vec<_> = findings
            .iter()
            .filter(|f| f.kind == SuggestionKind::CapabilityOverlap)
            .collect();
        assert_eq!(combos.len(), 1);
        assert_eq!(combos[0].current, "wreq+reqwest");
        assert_eq!(combos[0].package.as_deref(), Some("app"));
        assert!(!combos[0].is_auto_fixable());
        assert!(
            analyze(
                &[
                    dep("btls", None, true),
                    dep("btls-sys", None, true),
                    dep("tokio-btls", None, true)
                ],
                None
            )
            .unwrap()
            .is_empty()
        );
    }
}
