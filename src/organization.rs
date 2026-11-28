//! Curated organization preferences and potential capability overlaps.
use std::collections::{BTreeMap, BTreeSet};

use serde::Deserialize;

use crate::parser::{PackageResult, ResolvedDep};
use crate::suggestions::{
    AutofixSafety, Confidence, EvidenceSource, Impact, MigrationRisk, Suggestion, SuggestionKind,
};
use cargo_metadata::DependencyKind;

#[derive(Deserialize)]
struct Policy {
    forks: Vec<Fork>,
    capabilities: Vec<Capability>,
    preferences: Vec<Preference>,
    feature_preferences: Vec<FeaturePreference>,
    #[serde(default)]
    version_families: Vec<VersionFamily>,
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
    /// A provider that exposes this capability only when all listed features are enabled.
    #[serde(default)]
    provider_features: BTreeMap<String, Vec<String>>,
    #[serde(default)]
    complementary_pairs: Vec<[String; 2]>,
    /// Absent: gate all non-complementary direct pairs. Present: gate only listed pairs.
    #[serde(default)]
    gate_pairs: Option<Vec<[String; 2]>>,
    #[serde(default)]
    wrappers: Vec<ProviderWrapper>,
    preferred: String,
    notes: String,
}

#[derive(Deserialize)]
struct ProviderWrapper {
    package: String,
    repository: String,
}

#[derive(Deserialize)]
struct Preference {
    packages: Vec<String>,
    #[serde(default)]
    include_transitive: bool,
    #[serde(default)]
    satisfied_repository: Option<String>,
    preferred: String,
    notes: String,
}

#[derive(Deserialize)]
struct FeaturePreference {
    package: String,
    #[serde(default)]
    preferred_feature: Option<String>,
    #[serde(default)]
    include_transitive: bool,
    competing_features: Vec<String>,
    preferred: String,
    notes: String,
}

#[derive(Deserialize)]
struct VersionFamily {
    name: String,
    members: Vec<VersionFamilyMember>,
    notes: String,
}

#[derive(Deserialize)]
struct VersionFamilyMember {
    package: String,
    version_component: usize,
}

fn version_component(version: &str, component: usize) -> Option<u64> {
    version
        .split(['-', '+'])
        .next()?
        .split('.')
        .nth(component)?
        .parse()
        .ok()
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
    let mut results = Vec::new();
    append_fork_findings(&policy.forks, deps, package, &mut results);
    append_preference_findings(&policy, deps, package, &mut results);
    append_version_findings(&policy.version_families, deps, package, &mut results);
    append_overlap_findings(&policy.capabilities, &direct, package, &mut results);
    Ok(results)
}

fn append_fork_findings(
    forks: &[Fork],
    deps: &[ResolvedDep],
    package: Option<&str>,
    results: &mut Vec<Suggestion>,
) {
    for fork in forks {
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
}

fn append_preference_findings(
    policy: &Policy,
    deps: &[ResolvedDep],
    package: Option<&str>,
    results: &mut Vec<Suggestion>,
) {
    for preference in &policy.preferences {
        for name in &preference.packages {
            if deps.iter().any(|dep| {
                &dep.name == name
                    && (dep.is_direct || preference.include_transitive)
                    && !preference
                        .satisfied_repository
                        .as_ref()
                        .is_some_and(|repository| {
                            dep.source
                                .as_deref()
                                .is_some_and(|source| preferred_source(source, repository))
                        })
            }) {
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
        for dep in deps {
            if dep.name == preference.package
                && (dep.is_direct || preference.include_transitive)
                && preference
                    .preferred_feature
                    .as_ref()
                    .is_none_or(|feature| dep.available_features.contains(feature))
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
}

fn append_version_findings(
    families: &[VersionFamily],
    deps: &[ResolvedDep],
    package: Option<&str>,
    results: &mut Vec<Suggestion>,
) {
    // Cargo metadata may include optional or target-specific packages. These
    // findings describe the selected resolution, not guaranteed compiled units.
    let mut versions = BTreeMap::<&str, BTreeSet<&str>>::new();
    for dep in deps {
        versions.entry(&dep.name).or_default().insert(&dep.version);
    }
    for (name, resolved) in &versions {
        if resolved.len() > 1 {
            let mut suggestion = finding(
                (*name).to_owned(),
                "one compatible resolved version where upstream constraints permit".into(),
                format!(
                    "Multiple versions in the reachable Cargo resolution: {}. Inspect inverse dependency trees, enabled features and target/build/dev roles before consolidating; do not force incompatible APIs.",
                    resolved.iter().copied().collect::<Vec<_>>().join(", ")
                ),
                SuggestionKind::ModernAlternative,
                package,
            );
            suggestion.impact = Impact::Low;
            results.push(suggestion);
        }
    }
    for family in families {
        let mut generations = BTreeMap::<u64, BTreeSet<String>>::new();
        let mut members = BTreeSet::new();
        for member in &family.members {
            if let Some(resolved) = versions.get(member.package.as_str()) {
                for version in resolved {
                    if let Some(generation) = version_component(version, member.version_component) {
                        generations
                            .entry(generation)
                            .or_default()
                            .insert(format!("{}@{version}", member.package));
                        members.insert(member.package.as_str());
                    }
                }
            }
        }
        if generations.len() > 1 && members.len() > 1 {
            let details = generations
                .values()
                .map(|group| group.iter().cloned().collect::<Vec<_>>().join(", "))
                .collect::<Vec<_>>()
                .join("; ");
            let mut suggestion = finding(
                members.into_iter().collect::<Vec<_>>().join("+"),
                format!("one compatible {}", family.name),
                format!(
                    "Resolved release generations differ: {details}. {}",
                    family.notes
                ),
                SuggestionKind::ModernAlternative,
                package,
            );
            suggestion.impact = Impact::Low;
            results.push(suggestion);
        }
    }
}

const ROLES: [DependencyKind; 3] = [
    DependencyKind::Normal,
    DependencyKind::Development,
    DependencyKind::Build,
];

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct ProviderOrigin<'a> {
    name: &'a str,
    version: &'a str,
    source: Option<&'a str>,
}

impl<'a> From<&'a ResolvedDep> for ProviderOrigin<'a> {
    fn from(dep: &'a ResolvedDep) -> Self {
        Self {
            name: &dep.name,
            version: &dep.version,
            source: dep.source.as_deref(),
        }
    }
}

type ProviderSelections<'a> = BTreeMap<&'a str, BTreeSet<ProviderOrigin<'a>>>;

fn pair_matches(pair: &[String; 2], left: &str, right: &str) -> bool {
    (pair[0] == left && pair[1] == right) || (pair[1] == left && pair[0] == right)
}

fn independent_origins(a: &BTreeSet<ProviderOrigin<'_>>, b: &BTreeSet<ProviderOrigin<'_>>) -> bool {
    a.iter().any(|origin| b.iter().any(|other| origin != other))
}

impl Capability {
    fn gates_pair(&self, left: &str, right: &str) -> bool {
        self.gate_pairs
            .as_ref()
            .is_none_or(|pairs| pairs.iter().any(|pair| pair_matches(pair, left, right)))
    }

    fn pairs(&self) -> impl Iterator<Item = (&str, &str)> {
        self.providers
            .iter()
            .enumerate()
            .flat_map(move |(i, left)| {
                self.providers[i + 1..].iter().filter_map(move |right| {
                    (!self
                        .complementary_pairs
                        .iter()
                        .any(|pair| pair_matches(pair, left, right)))
                    .then_some((left.as_str(), right.as_str()))
                })
            })
    }

    fn selections<'a>(
        &'a self,
        deps: &[&'a ResolvedDep],
        role: DependencyKind,
    ) -> ProviderSelections<'a> {
        let mut selected = BTreeMap::<_, BTreeSet<_>>::new();
        for dep in deps.iter().filter(|dep| dep.direct_kinds.contains(&role)) {
            if self.providers.contains(&dep.name)
                && self
                    .provider_features
                    .get(&dep.name)
                    .is_none_or(|required| {
                        required
                            .iter()
                            .all(|feature| dep.enabled_features.contains(feature))
                    })
            {
                selected
                    .entry(dep.name.as_str())
                    .or_default()
                    .insert(ProviderOrigin::from(*dep));
            }
            if self.wrappers.iter().any(|wrapper| {
                wrapper.package == dep.name
                    && dep
                        .source
                        .as_deref()
                        .is_some_and(|source| preferred_source(source, &wrapper.repository))
            }) {
                for provider in self
                    .providers
                    .iter()
                    .filter(|name| dep.normal_dependencies.contains(name))
                {
                    selected
                        .entry(provider.as_str())
                        .or_default()
                        .insert(ProviderOrigin::from(*dep));
                }
            }
        }
        selected
    }
}

fn describe_origins(provider: &str, origins: &BTreeSet<ProviderOrigin<'_>>) -> String {
    format!(
        "{provider} via {}",
        origins
            .iter()
            .map(|origin| origin.name)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>()
            .join(", ")
    )
}

fn append_overlap_findings(
    capabilities: &[Capability],
    direct: &[&ResolvedDep],
    package: Option<&str>,
    results: &mut Vec<Suggestion>,
) {
    for capability in capabilities {
        let selections: Vec<_> = ROLES
            .iter()
            .map(|role| capability.selections(direct, *role))
            .collect();
        for (left, right) in capability.pairs() {
            let mut independent = Vec::new();
            let mut direct_pair = false;
            for selected in &selections {
                if let (Some(a), Some(b)) = (selected.get(left), selected.get(right)) {
                    // A single wrapper choosing both transports is not two independently selected dependencies.
                    if independent_origins(a, b) {
                        direct_pair |= a.iter().any(|origin| origin.name == left)
                            && b.iter().any(|origin| origin.name == right);
                        independent.push(format!(
                            "{}; {}",
                            describe_origins(left, a),
                            describe_origins(right, b)
                        ));
                    }
                }
            }
            if independent.is_empty() {
                continue;
            }
            independent.sort();
            independent.dedup();
            let advisory = !capability.gates_pair(left, right) || !direct_pair;
            results.push(finding(
                format!("{left}+{right}"),
                capability.preferred.clone(),
                format!(
                    "Potential overlapping {} providers. {} Selections: {}.",
                    capability.name,
                    capability.notes,
                    independent.join("; ")
                ),
                if advisory {
                    SuggestionKind::AdvisoryOverlap
                } else {
                    SuggestionKind::CapabilityOverlap
                },
                package,
            ));
        }
    }
}

/// Report independently selected providers in different selected workspace members.
/// This does not establish that the members link into a common executable.
pub fn analyze_workspace(snapshots: &[PackageResult]) -> serde_json::Result<Vec<Suggestion>> {
    let policy: Policy = serde_json::from_str(include_str!("../data/organization.json"))?;
    let mut findings = Vec::new();
    if snapshots.len() < 2 {
        return Ok(findings);
    }
    for capability in &policy.capabilities {
        let per_role = ROLES.map(|role| {
            snapshots
                .iter()
                .map(|snap| {
                    let direct: Vec<_> = snap.deps.iter().filter(|dep| dep.is_direct).collect();
                    (snap.name.as_str(), capability.selections(&direct, role))
                })
                .collect::<Vec<_>>()
        });
        for (left, right) in capability.pairs() {
            let mut witnesses = BTreeSet::new();
            for (role, members) in ROLES.into_iter().zip(&per_role) {
                let left_members: Vec<_> = members
                    .iter()
                    .filter_map(|(name, selected)| {
                        selected.get(left).map(|origins| (*name, origins))
                    })
                    .collect();
                let right_members: Vec<_> = members
                    .iter()
                    .filter_map(|(name, selected)| {
                        selected.get(right).map(|origins| (*name, origins))
                    })
                    .collect();
                // Only report pairs chosen by distinct members through distinct resolved selectors.
                // A shared wrapper that itself uses two providers is not independent selection.
                let mut left_witnesses = BTreeSet::new();
                let mut right_witnesses = BTreeSet::new();
                for (a, a_origins) in &left_members {
                    for (b, b_origins) in &right_members {
                        if a != b && independent_origins(a_origins, b_origins) {
                            left_witnesses.insert((*a, describe_origins(left, a_origins)));
                            right_witnesses.insert((*b, describe_origins(right, b_origins)));
                        }
                    }
                }
                if !left_witnesses.is_empty() {
                    let display = |witnesses: BTreeSet<(&str, String)>| {
                        witnesses
                            .into_iter()
                            .map(|(name, origin)| format!("{name} ({origin})"))
                            .collect::<Vec<_>>()
                            .join(", ")
                    };
                    witnesses.insert(format!(
                        "{role:?}: {} vs {}",
                        display(left_witnesses),
                        display(right_witnesses)
                    ));
                }
            }
            if !witnesses.is_empty() {
                findings.push(finding(
                    format!("{left}+{right}"),
                    capability.preferred.clone(),
                    format!("Workspace provider divergence ({}). {} Distinct member selections, not proof of a shared binary: {}.", capability.name, capability.notes, witnesses.into_iter().collect::<Vec<_>>().join("; ")),
                    SuggestionKind::AdvisoryOverlap,
                    None,
                ));
            }
        }
    }
    Ok(findings)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn analyze(deps: &[ResolvedDep], package: Option<&str>) -> Vec<Suggestion> {
        super::analyze(deps, package).expect("embedded policy must decode")
    }

    fn dep(name: &str, source: Option<&str>, direct: bool) -> ResolvedDep {
        ResolvedDep {
            name: name.into(),
            version: "1.0.0".into(),
            enabled_features: vec![],
            available_features: vec![],
            source: source.map(str::to_owned),
            repository: Some("https://github.com/upstream/project".into()),
            is_direct: direct,
            normal_dependencies: vec![],
            direct_kinds: if direct {
                vec![cargo_metadata::DependencyKind::Normal]
            } else {
                vec![]
            },
        }
    }

    #[test]
    fn workload_sensitive_capabilities_are_advisory_and_role_scoped() {
        for (left, right) in [
            ("rustc-hash", "ahash"),
            ("ignore", "walkdir"),
            ("log", "tracing"),
            ("git2", "gix"),
            ("chrono", "jiff"),
            ("redb", "rusqlite"),
            ("argon2", "argon2-rust"),
            ("step-p21", "cadmpeg-codec-step"),
            ("tokio", "compio-runtime"),
            ("glob", "globset"),
            ("shlex", "brush-parser"),
            ("nix", "rustix"),
            ("similar", "imara-diff"),
            ("tokio-tungstenite", "fastwebsockets"),
        ] {
            let first = dep(left, None, true);
            let mut second = dep(right, None, true);
            let pair = format!("{left}+{right}");
            let hits = analyze(&[first.clone(), second.clone()], Some("app"));
            assert!(
                hits.iter()
                    .any(|f| f.kind == SuggestionKind::AdvisoryOverlap
                        && f.current == pair
                        && !f.is_auto_fixable()),
                "{pair}"
            );
            assert!(
                hits.iter()
                    .all(|f| f.kind != SuggestionKind::CapabilityOverlap),
                "{pair}"
            );
            second.direct_kinds = vec![DependencyKind::Development];
            assert!(
                !analyze(&[first, second], Some("app"))
                    .iter()
                    .any(|f| f.kind == SuggestionKind::AdvisoryOverlap && f.current == pair)
            );
        }
    }

    #[test]
    fn websocket_client_capability_requires_enabled_feature_and_same_role() {
        let mut http = dep("wreq", None, true);
        let mut ws = dep("tokio-tungstenite", None, true);
        let overlaps = |deps: &[ResolvedDep]| {
            analyze(deps, Some("app")).into_iter().any(|f| {
                f.kind == SuggestionKind::AdvisoryOverlap && f.current == "wreq+tokio-tungstenite"
            })
        };
        assert!(!overlaps(&[http.clone(), ws.clone()]));
        http.enabled_features.push("ws".into());
        assert!(overlaps(&[http.clone(), ws.clone()]));
        ws.direct_kinds = vec![DependencyKind::Development];
        assert!(!overlaps(&[http, ws]));
    }

    #[test]
    fn previous_gate_remains_and_complementary_layers_do_not_overlap() {
        for (a, b) in [
            ("fxhash", "rustc-hash"),
            ("tokio", "smol"),
            ("wreq", "reqwest"),
        ] {
            let results = analyze(&[dep(a, None, true), dep(b, None, true)], None);
            assert_eq!(
                results
                    .iter()
                    .filter(|f| f.kind == SuggestionKind::CapabilityOverlap)
                    .count(),
                1
            );
            assert!(
                results
                    .iter()
                    .all(|f| f.kind != SuggestionKind::AdvisoryOverlap)
            );
        }
        for (a, b) in [
            ("hashbrown", "rustc-hash"),
            ("log", "env_logger"),
            ("tracing", "tracing-subscriber"),
            ("glob", "walkdir"),
            ("jsonwebtoken", "jsonwebtoken-btls"),
            ("regex", "oxc_regular_expression"),
            ("compio", "compio-runtime"),
            ("jiff", "web-time"),
            ("sqlx", "rusqlite"),
        ] {
            assert!(
                analyze(&[dep(a, None, true), dep(b, None, true)], None)
                    .iter()
                    .all(|f| !matches!(
                        f.kind,
                        SuggestionKind::AdvisoryOverlap | SuggestionKind::CapabilityOverlap
                    )),
                "{a}+{b}"
            );
        }
    }

    const LURKMOAR_SOURCE: &str = "git+https://github.com/codeandsolder/lurkmoar-rs?rev=abc#abc";

    #[test]
    fn wrapper_provider_is_based_on_resolved_active_child_and_source() {
        let mut wrapper = dep("lurkmoar", Some(LURKMOAR_SOURCE), true);
        let reqwest = dep("reqwest", None, true);
        let wreq = dep("wreq", None, false);
        let overlaps = |deps: &[ResolvedDep]| {
            analyze(deps, Some("app"))
                .into_iter()
                .filter(|f| {
                    matches!(
                        f.kind,
                        SuggestionKind::AdvisoryOverlap | SuggestionKind::CapabilityOverlap
                    )
                })
                .collect::<Vec<_>>()
        };
        // A transitive wreq anywhere in the graph does not establish wrapper provenance.
        assert!(overlaps(&[wrapper.clone(), reqwest.clone(), wreq.clone()]).is_empty());
        wrapper.normal_dependencies = vec!["wreq".into()];
        let results = overlaps(&[wrapper.clone(), reqwest.clone(), wreq.clone()]);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].kind, SuggestionKind::AdvisoryOverlap);
        assert_eq!(results[0].current, "wreq+reqwest");
        assert!(results[0].reason.contains("wreq via lurkmoar"));

        // The old telemetry client used ureq, not wreq. No competing provider
        // when the application independently chose ureq too.
        wrapper.normal_dependencies = vec!["ureq".into()];
        assert!(overlaps(&[wrapper.clone(), dep("ureq", None, true), wreq.clone()]).is_empty());
        let results = overlaps(&[wrapper.clone(), reqwest.clone()]);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].current, "reqwest+ureq");
        wrapper.source = Some("git+https://github.com/other/lurkmoar-rs#abc".into());
        assert!(overlaps(&[wrapper.clone(), reqwest.clone()]).is_empty());

        wrapper.source = Some(LURKMOAR_SOURCE.into());
        wrapper.direct_kinds = vec![DependencyKind::Build];
        assert!(overlaps(&[wrapper, reqwest]).is_empty());
    }

    fn snapshot(name: &str, deps: Vec<ResolvedDep>) -> PackageResult {
        PackageResult {
            name: name.into(),
            version: "1.0.0".into(),
            manifest_path: format!("{name}/Cargo.toml").into(),
            deps,
        }
    }

    #[test]
    fn workspace_divergence_is_not_a_direct_provider_gate() -> serde_json::Result<()> {
        let first = snapshot("geometry", vec![dep("ahash", None, true)]);
        let second = snapshot("mesh", vec![dep("rustc-hash", None, true)]);
        let findings = analyze_workspace(&[first.clone(), second.clone()])?;
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind, SuggestionKind::AdvisoryOverlap);
        assert!(findings[0].package.is_none());
        assert!(findings[0].reason.contains("geometry (ahash via ahash)"));
        assert!(
            findings[0]
                .reason
                .contains("mesh (rustc-hash via rustc-hash)")
        );
        assert!(analyze_workspace(std::slice::from_ref(&first))?.is_empty());
        let mut dev_only = second.clone();
        dev_only.deps[0].direct_kinds = vec![DependencyKind::Development];
        assert!(analyze_workspace(&[first.clone(), dev_only])?.is_empty());
        let mut already_reported = first.clone();
        already_reported.deps.push(dep("rustc-hash", None, true));
        assert_eq!(analyze_workspace(&[already_reported, second])?.len(), 1);

        let mut wrapper = dep("lurkmoar", Some(LURKMOAR_SOURCE), true);
        wrapper.normal_dependencies = vec!["wreq".into()];
        let findings = analyze_workspace(&[
            snapshot("metrics", vec![wrapper]),
            snapshot("updater", vec![dep("ureq", None, true)]),
        ])?;
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].current, "wreq+ureq");
        assert!(findings[0].reason.contains("metrics (wreq via lurkmoar)"));
        let mut shared = dep("lurkmoar", Some(LURKMOAR_SOURCE), true);
        shared.normal_dependencies = vec!["wreq".into(), "ureq".into()];
        assert!(
            analyze_workspace(&[
                snapshot("one", vec![shared.clone()]),
                snapshot("two", vec![shared]),
            ])?
            .is_empty()
        );
        Ok(())
    }

    #[test]
    fn verifies_resolved_source_not_repository_metadata() {
        let good = dep(
            "wreq",
            Some("git+https://github.com/codeandsolder/wreq-exp.git?rev=abc#abc"),
            true,
        );
        assert!(analyze(&[good], None).is_empty());
        let upstream = dep(
            "wreq",
            Some("git+https://github.com/0x676e67/wreq#abc"),
            true,
        );
        assert_eq!(analyze(&[upstream], None).len(), 1);
        let registry = dep(
            "btls",
            Some("registry+https://github.com/rust-lang/crates.io-index"),
            true,
        );
        assert_eq!(analyze(&[registry], None).len(), 1);
        assert!(analyze(&[dep("btls", None, true)], None).is_empty());
        assert!(!preferred_source(
            "git+https://github.com/codeandsolder/wreq-exp-imposter#abc",
            "wreq-exp"
        ));
    }

    #[test]
    fn retired_fontations_fork_is_not_recommended() {
        let registry = Some("registry+https://github.com/rust-lang/crates.io-index");
        let deps = ["font-types", "read-fonts", "skrifa", "write-fonts", "skera"]
            .map(|name| dep(name, registry, false));
        assert!(analyze(&deps, Some("pdf-redox")).is_empty());
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
        );
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
            .is_empty()
        );
    }
    #[test]
    fn normalized_stack_detects_transitive_backends_and_adapters() {
        let removed = [
            "rouille",
            "tiny_http",
            "reqwest",
            "ureq",
            "ureq-proto",
            "opendal-http-transport-reqwest",
            "openssl",
            "openssl-sys",
            "native-tls",
            "tokio-native-tls",
            "hyper-tls",
            "rustls",
            "tokio-rustls",
            "hyper-rustls",
            "rustls-platform-verifier",
            "rustls-webpki",
            "aws-lc-rs",
            "aws-lc-sys",
            "ring",
            "rsa",
            "miniz_oxide",
            "libmount",
            "version-compare",
            "h2",
            "ruzstd",
            "webpki-roots",
        ];
        let deps: Vec<_> = removed.iter().map(|name| dep(name, None, false)).collect();
        let findings = analyze(&deps, Some("application"));
        for name in removed {
            assert!(findings.iter().any(|f| f.current == name), "missing {name}");
        }
        assert!(findings.iter().all(|f| !f.is_auto_fixable()));
    }

    #[test]
    fn backend_feature_rules_detect_mixed_and_transitive_features() {
        let mut flate = dep("flate2", None, false);
        flate.available_features = vec!["zlib-rs".into(), "rust_backend".into()];
        flate.enabled_features = flate.available_features.clone();
        let mut jwt = dep("jsonwebtoken", None, false);
        jwt.enabled_features = vec!["aws_lc_rs".into()];
        let findings = analyze(&[flate.clone(), jwt.clone()], None);
        for name in ["flate2", "jsonwebtoken"] {
            assert!(
                findings
                    .iter()
                    .any(|f| f.current == name && f.kind == SuggestionKind::FeatureOptimization)
            );
        }
        flate.enabled_features = vec!["zlib-rs".into()];
        jwt.enabled_features.clear();
        assert!(analyze(&[flate, jwt], None).is_empty());
    }

    #[test]
    fn lru_and_dashboard_preferences() {
        let mut leptos = dep("leptos_axum", None, false);
        leptos.enabled_features = vec!["default".into()];
        let findings = analyze(
            &[
                dep("linked-hash-map", None, true),
                dep("chrono", None, true),
                leptos,
            ],
            None,
        );
        for name in ["linked-hash-map", "chrono", "leptos_axum"] {
            assert!(
                findings
                    .iter()
                    .any(|finding| finding.current == name && !finding.is_auto_fixable())
            );
        }
    }

    #[test]
    fn unused_format_features_have_conditional_recommendations() {
        let mut jwt = dep("jsonwebtoken", None, false);
        jwt.enabled_features = vec!["use_pem".into()];
        let mut object = dep("object", None, false);
        object.enabled_features = vec!["compression".into()];
        let findings = analyze(&[jwt, object], None);
        assert_eq!(findings.len(), 2);
        assert!(
            findings
                .iter()
                .all(|f| f.kind == SuggestionKind::FeatureOptimization && !f.is_auto_fixable())
        );
    }

    #[test]
    fn standalone_removed_wrapper_preferences() {
        for name in [
            "libmount",
            "version-compare",
            "ruzstd",
            "h2",
            "simple_asn1",
            "webpki-roots",
        ] {
            assert!(
                analyze(&[dep(name, None, true)], None)
                    .iter()
                    .any(|f| f.current == name)
            );
        }
        assert!(
            analyze(
                &[dep(
                    "jsonwebtoken-btls",
                    Some("git+https://github.com/codeandsolder/btls-fast.git?rev=abc#abc"),
                    true
                )],
                None
            )
            .is_empty()
        );
        assert!(analyze(&[dep("http2", Some("git+https://github.com/codeandsolder/cargo-patches.git?tag=wreq-transport-v0.0.1#abc"), true)], None).is_empty());
    }

    #[test]
    fn mount_wrappers_are_not_equivalent_to_every_syscall_binding() {
        let findings = analyze(&[dep("nix", None, true), dep("rustix", None, true)], None);
        assert!(
            !findings
                .iter()
                .any(|f| f.kind == SuggestionKind::CapabilityOverlap)
        );
        let findings = analyze(&[dep("nix", None, true), dep("libmount", None, true)], None);
        assert!(
            findings
                .iter()
                .any(|f| f.kind == SuggestionKind::CapabilityOverlap)
        );
    }
    #[test]
    fn shared_patch_satisfies_source_specific_preference() {
        let patched = dep(
            "compression-codecs",
            Some(
                "git+https://github.com/codeandsolder/cargo-patches.git?branch=generated/compression-backend#abc",
            ),
            false,
        );
        let registry = dep(
            "compression-codecs",
            Some("registry+https://github.com/rust-lang/crates.io-index"),
            false,
        );
        assert!(analyze(std::slice::from_ref(&patched), None).is_empty());
        assert!(
            analyze(&[patched, registry], None)
                .iter()
                .any(|finding| finding.current == "compression-codecs")
        );
    }

    #[test]
    fn reports_version_splits_without_gating_the_resolution() {
        let mut old = dep("wasmparser", None, false);
        old.version = "0.248.0".into();
        let mut new = old.clone();
        new.version = "0.263.0".into();
        let mut wat = dep("wat", None, true);
        wat.version = "1.263.0".into();
        let mut wast = dep("wast", None, false);
        wast.version = "263.0.0".into();
        assert!(analyze(&[new.clone(), wat.clone(), wast.clone()], None).is_empty());
        let findings = analyze(&[old, new, wat, wast], None);
        assert_eq!(findings.len(), 2);
        assert!(findings.iter().all(|f| f.impact == Impact::Low
            && f.kind != SuggestionKind::CapabilityOverlap
            && !f.is_auto_fixable()));
        assert!(
            findings
                .iter()
                .any(|f| f.current == "wasmparser" && f.reason.contains("0.248.0"))
        );
    }
}
