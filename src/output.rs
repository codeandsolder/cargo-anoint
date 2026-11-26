//! Output layer — renders the modernization report to the terminal
//! with colored output, emojis, and actionable links.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::hash::BuildHasher;
use std::path::Path;

use cargo_metadata::semver::Version;
use colored::Colorize;
use serde::Serialize;

use crate::code_audit::{CodeAuditReport, kind_label};
use crate::intel::CrateIntel;
use crate::suggestions::{Confidence, Impact, MigrationRisk, SuggestionKind};
use crate::suggestions::{EvidenceSource, Suggestion};

fn print_suggestion_detail<S: BuildHasher>(
    suggestion: &Suggestion,
    intel: &HashMap<String, CrateIntel, S>,
    registry_names: &HashSet<&str>,
) {
    let icon = if suggestion.kind == SuggestionKind::Unmaintained {
        "⚠️"
    } else {
        "•"
    };

    let impact_tag = match suggestion.impact {
        Impact::High => "[HIGH]".red().bold(),
        Impact::Medium => "[MED]".yellow().bold(),
        Impact::Low => "[LOW]".dimmed(),
    };
    let confidence_tag = match suggestion.confidence {
        Confidence::High => "[HIGH confidence]".green().bold(),
        Confidence::Medium => "[MED confidence]".yellow(),
        Confidence::Low => "[LOW confidence]".red(),
    };
    let risk_tag = match suggestion.migration_risk {
        MigrationRisk::High => "[HIGH risk]".red().bold(),
        MigrationRisk::Medium => "[MED risk]".yellow(),
        MigrationRisk::Low => "[LOW risk]".green(),
    };
    let verb = match suggestion.confidence {
        Confidence::High => "→",
        Confidence::Medium | Confidence::Low => "→ consider",
    };

    println!(
        " {icon} {impact_tag} {} {verb} {}",
        suggestion.current.yellow(),
        suggestion.recommended.green(),
    );
    println!(
        "   {confidence_tag} {risk_tag} {}",
        format!("evidence: {}", evidence_label(suggestion.evidence_source)).dimmed()
    );
    println!("   {}", suggestion.reason.dimmed());
    if let Some(condition) = &suggestion.condition {
        println!("   Review condition: {condition}");
    }

    for crate_name in suggestion.current.split('+').map(str::trim) {
        if registry_names.contains(crate_name)
            && let Some(info) = intel.get(crate_name)
        {
            let mut enrichment = format!("   latest: v{}", info.latest_version);
            if let Some(recent) = info.recent_downloads {
                enrichment.push_str(", ");
                enrichment.push_str(&format_downloads(recent));
                enrichment.push_str(" recent downloads");
            }
            println!("   {}", enrichment.dimmed());
        }
    }
}

/// One workspace member’s dependency suggestions shown in plain text reports.
#[derive(Debug)]
pub struct PackageSuggestionView<'a> {
    pub name: &'a str,
    pub version: &'a Version,
    pub manifest_path: &'a Path,
    pub suggestions: &'a [Suggestion],
    /// Names backed exclusively by crates.io packages in this member's resolved graph.
    pub registry_names: HashSet<&'a str>,
}

/// Render modernization output for one or many packages (`--workspace` / `--package` use multi headers).
fn use_multi_headers(packages: &[PackageSuggestionView<'_>]) -> bool {
    if packages.len() > 1 {
        return true;
    }
    packages
        .first()
        .is_some_and(|p| p.suggestions.iter().any(|s| s.package.is_some()))
}

pub fn render_packages_modernization<S: BuildHasher>(
    packages: &[PackageSuggestionView<'_>],
    intel: &HashMap<String, CrateIntel, S>,
) {
    let all_empty = packages.iter().all(|p| p.suggestions.is_empty());

    if all_empty {
        println!(
            "{}",
            "✅ Your dependencies are already blessed! Nothing to modernize.".green()
        );
        return;
    }

    let multi = use_multi_headers(packages);

    if multi {
        for p in packages {
            if p.suggestions.is_empty() {
                continue;
            }
            println!(
                "{}",
                format!(
                    "📦 {} v{} ({})",
                    p.name,
                    p.version,
                    p.manifest_path.display()
                )
                .bold()
            );
            println!();
            for suggestion in p.suggestions {
                print_suggestion_detail(suggestion, intel, &p.registry_names);
            }
            println!();
        }
    } else {
        let p = &packages[0];
        println!(
            "{}",
            format!("🚀 Modernization report for {} v{}", p.name, p.version).bold()
        );
        println!();
        for suggestion in p.suggestions {
            print_suggestion_detail(suggestion, intel, &p.registry_names);
        }
    }

    let high_count = packages
        .iter()
        .flat_map(|p| p.suggestions)
        .filter(|s| matches!(s.impact, Impact::High))
        .count();

    println!();
    println!(
        "{}",
        format!(
            "{high_count} high-impact recommendation{} available. Review migrations before editing dependencies.",
            if high_count == 1 { "" } else { "s" }
        )
        .bold()
    );
}

const fn suggestion_kind_slug(kind: SuggestionKind) -> &'static str {
    match kind {
        SuggestionKind::ModernAlternative => "modern_alternative",
        SuggestionKind::FeatureOptimization => "feature_opt",
        SuggestionKind::StdReplacement => "std_replace",
        SuggestionKind::ComboWin => "combo_win",
        SuggestionKind::CapabilityOverlap => "capability_overlap",
        SuggestionKind::Unmaintained => "unmaintained",
    }
}

/// Paste-friendly condensed output (`--summary`).
pub fn render_summary(scan_stats: &[(&str, usize, usize)], suggestions: &[&Suggestion]) {
    const MAX: usize = 14;
    let pkg_ct = scan_stats.len();
    println!(
        "{}",
        format!(
            "📊 Summary — scanned {pkg_ct} workspace member{}",
            if pkg_ct == 1 { "" } else { "s" }
        )
        .bold()
    );
    for (name, direct_ct, total_ct) in scan_stats {
        println!(
            "   • {} — {direct_ct} direct deps, {total_ct} total in resolve",
            name.bold()
        );
    }

    let mut hi = 0usize;
    let mut med = 0usize;
    let mut low = 0usize;
    for s in suggestions {
        match s.impact {
            Impact::High => hi += 1,
            Impact::Medium => med += 1,
            Impact::Low => low += 1,
        }
    }

    println!();
    println!("Suggestions after policy: {}", suggestions.len());
    println!("By impact — high: {hi}, medium: {med}, low: {low}");

    let mut kind_counts = HashMap::<&'static str, usize>::new();
    for s in suggestions {
        *kind_counts.entry(suggestion_kind_slug(s.kind)).or_default() += 1;
    }
    let mut kind_pairs: Vec<_> = kind_counts.into_iter().collect();
    kind_pairs.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(b.0)));
    if !kind_pairs.is_empty() {
        println!(
            "By kind — {}",
            kind_pairs
                .iter()
                .map(|(k, c)| format!("{k}: {c}"))
                .collect::<Vec<_>>()
                .join(", ")
        );
    }

    println!();
    println!("{}", "Top patterns:".bold());
    let mut patterns: Vec<String> = suggestions
        .iter()
        .map(|s| format!("{} → {}", s.current, s.recommended))
        .collect();
    patterns.sort();
    patterns.dedup();
    for line in patterns.iter().take(MAX) {
        println!("   • {line}");
    }
    if patterns.len() > MAX {
        println!("   … and {} more", patterns.len() - MAX);
    }

    println!();
    println!(
        "{}",
        "All migrations require manual review; this scan does not edit manifests or Rust sources."
            .dimmed()
    );
}

const fn evidence_label(source: EvidenceSource) -> &'static str {
    match source {
        EvidenceSource::BlessedRs => "blessed.rs",
        EvidenceSource::RustSec => "RustSec",
        EvidenceSource::StdDocs => "std docs",
        EvidenceSource::CrateDocs => "crate docs",
        EvidenceSource::CratesIo => "crates.io",
        EvidenceSource::Heuristic => "heuristic",
    }
}

pub fn render_code_audit_report(report: &CodeAuditReport, verbose: bool) {
    println!();
    println!("{}", "🧨 Bullshit detector code audit".bold());
    println!(
        "{}",
        format!(
            "Scanned {} Rust file{}.",
            report.files_scanned,
            if report.files_scanned == 1 { "" } else { "s" }
        )
        .dimmed()
    );

    if report.is_clean() {
        println!("{}", "✅ No bullshit detected in Rust source.".green());
        return;
    }

    println!(
        "{}",
        format!(
            "🚨 Bullshit detected: {} finding{} · heat {:.1}",
            report.alerts.len(),
            if report.alerts.len() == 1 { "" } else { "s" },
            report.alerts.iter().map(|a| a.severity).sum::<f32>() * 10.0
        )
        .red()
        .bold()
    );

    let mut counts = HashMap::<&'static str, usize>::new();
    for alert in &report.alerts {
        *counts.entry(kind_label(alert.kind)).or_default() += 1;
    }
    let mut counts: Vec<_> = counts.into_iter().collect();
    counts.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(b.0)));
    let summary = counts
        .iter()
        .map(|(kind, count)| format!("{kind}: {count}"))
        .collect::<Vec<_>>()
        .join(", ");
    println!("{}", summary.dimmed());
    println!();

    let shown = if verbose {
        report.alerts.len()
    } else {
        report.alerts.len().min(5)
    };

    for alert in report.alerts.iter().take(shown) {
        println!(
            " {} {} {}:{}:{}",
            "•".red(),
            kind_label(alert.kind).yellow().bold(),
            alert.file.display().to_string().dimmed(),
            alert.line,
            alert.column
        );
        println!("   {}", alert.why_bs);
        println!("   {}", format!("Fix: {}", alert.suggestion).green());
        if !alert.context_snippet.is_empty() {
            println!("   {}", alert.context_snippet.dimmed());
        }
    }

    if !verbose && report.alerts.len() > shown {
        println!();
        println!(
            "{}",
            format!(
                "Showing top {shown}. Run with --verbose for all {} findings, or --json for machine output.",
                report.alerts.len()
            )
            .dimmed()
        );
    }
}

/// Format download counts in a human-readable way (e.g., "1.2M", "456K").
fn format_downloads(count: u64) -> String {
    if count >= 1_000_000 {
        format_scaled_count(count, 1_000_000, "M")
    } else if count >= 1_000 {
        format_scaled_count(count, 1_000, "K")
    } else {
        count.to_string()
    }
}

fn format_scaled_count(count: u64, scale: u64, suffix: &str) -> String {
    let whole = count / scale;
    let tenth = ((count % scale) * 10 + scale / 2) / scale;
    format!("{}.{}{suffix}", whole + tenth / 10, tenth % 10)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_downloads() {
        assert_eq!(format_downloads(0), "0");
        assert_eq!(format_downloads(500), "500");
        assert_eq!(format_downloads(1_500), "1.5K");
        assert_eq!(format_downloads(1_200_000), "1.2M");
        assert_eq!(format_downloads(100_000_000), "100.0M");
    }
}

#[derive(Serialize)]
pub struct JsonPackageOutput<'a> {
    pub name: &'a str,
    pub version: &'a Version,
    pub manifest_path: String,
    pub dependency_suggestions: &'a [Suggestion],
}

/// Machine-readable report: `cargo_anoint_version`, `workspace_scan`, `packages`, optional `code_audit`.
#[derive(Serialize)]
pub struct JsonReportUnified<'a> {
    pub cargo_anoint_version: &'a str,
    pub workspace_scan: bool,
    pub packages: Vec<JsonPackageOutput<'a>>,
    pub code_audit: Option<&'a CodeAuditReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hardcoded_values: Option<&'a [crate::bs_detector::BSHit]>,
    pub security_advisories: crate::advisories::AdvisoryReport,
}

pub fn render_advisories(report: &crate::advisories::AdvisoryReport) {
    use crate::advisories::AdvisoryReport;
    let advisories = match report {
        AdvisoryReport::Skipped => return,
        AdvisoryReport::Unavailable { error } => {
            eprintln!("OSV advisory check unavailable: {error}");
            return;
        }
        AdvisoryReport::Complete { checked, findings } => {
            println!("OSV checked {checked} direct crates.io package versions.");
            findings
        }
    };
    if advisories.is_empty() {
        return;
    }
    println!();
    println!("{}", "🔒 Security advisories".bold());
    for hit in advisories {
        let count = hit.advisories.len();
        println!(
            "  {} {} {}",
            "⚠".yellow(),
            format!("{} {}", hit.crate_name, hit.version)
                .yellow()
                .bold(),
            format!("({count} advisory{})", if count == 1 { "" } else { "ies" }).dimmed()
        );
        for adv in &hit.advisories {
            let cve_tag = adv.cve().map_or_default(|c| format!(" · {c}"));
            println!(
                "     {} {}{}",
                adv.id.red().bold(),
                adv.summary.dimmed(),
                cve_tag.dimmed()
            );
        }
    }
    println!();
    println!("{}", "  Run `cargo audit` for patch guidance.".dimmed());
}

/// Write a machine-readable report to stdout.
/// # Errors
/// Returns serialization or output I/O errors.
pub fn render_unified_json(report: &JsonReportUnified<'_>) -> anyhow::Result<()> {
    write_json(report)
}

fn write_json(value: &impl Serialize) -> anyhow::Result<()> {
    use std::io::Write;
    let mut out = std::io::stdout().lock();
    serde_json::to_writer_pretty(&mut out, value)?;
    writeln!(out)?;
    Ok(())
}

#[derive(Serialize)]
struct SarifRoot {
    version: &'static str,
    #[serde(rename = "$schema")]
    schema: &'static str,
    runs: Vec<SarifRun>,
}

#[derive(Serialize)]
struct SarifRun {
    tool: SarifTool,
    #[serde(rename = "originalUriBaseIds")]
    original_uri_base_ids: BTreeMap<&'static str, SarifArtifactLocation>,
    results: Vec<SarifResult>,
}

#[derive(Serialize)]
struct SarifTool {
    driver: SarifDriver,
}

#[derive(Serialize)]
struct SarifDriver {
    name: &'static str,
    version: &'static str,
    #[serde(rename = "informationUri")]
    information_uri: &'static str,
    rules: Vec<SarifRule>,
}

#[derive(Serialize)]
struct SarifRule {
    id: String,
    name: String,
    #[serde(rename = "shortDescription")]
    short_description: SarifMessage,
}

#[derive(Serialize)]
struct SarifResult {
    #[serde(rename = "ruleId")]
    rule_id: String,
    level: &'static str,
    message: SarifMessage,
    locations: Vec<SarifLocation>,
}

#[derive(Serialize)]
struct SarifLocation {
    #[serde(rename = "physicalLocation")]
    physical_location: SarifPhysicalLocation,
}

#[derive(Serialize)]
struct SarifPhysicalLocation {
    #[serde(rename = "artifactLocation")]
    artifact_location: SarifArtifactLocation,
    region: SarifRegion,
}

#[derive(Serialize)]
struct SarifArtifactLocation {
    uri: String,
    #[serde(rename = "uriBaseId", skip_serializing_if = "Option::is_none")]
    uri_base_id: Option<&'static str>,
}

#[derive(Serialize)]
struct SarifRegion {
    #[serde(rename = "startLine")]
    start_line: usize,
}

#[derive(Serialize)]
struct SarifMessage {
    text: String,
}

/// Render SARIF to stdout.
/// # Errors
/// Returns serialization or output I/O errors.
pub fn render_sarif(report: &CodeAuditReport, root: &Path) -> anyhow::Result<()> {
    write_json(&build_sarif(report, root)?)
}

fn sarif_location(path: &Path, root: &url::Url) -> anyhow::Result<SarifArtifactLocation> {
    let absolute = url::Url::from_file_path(path).map_err(|()| {
        anyhow::anyhow!(
            "cannot represent source path as file URI: {}",
            path.display()
        )
    })?;
    let (uri, uri_base_id) = absolute.as_str().strip_prefix(root.as_str()).map_or_else(
        || (absolute.to_string(), None),
        |relative| (format!("./{relative}"), Some("%SRCROOT%")),
    );
    Ok(SarifArtifactLocation { uri, uri_base_id })
}

fn build_sarif(report: &CodeAuditReport, root: &Path) -> anyhow::Result<SarifRoot> {
    let root = url::Url::from_directory_path(root).map_err(|()| {
        anyhow::anyhow!(
            "cannot represent source root as file URI: {}",
            root.display()
        )
    })?;

    // Collect unique rule IDs for the driver rules table
    let mut rule_descriptions: BTreeMap<String, String> = BTreeMap::new();
    for alert in &report.alerts {
        rule_descriptions
            .entry(format!("{:?}", alert.kind))
            .or_insert_with(|| alert.why_bs.clone());
    }

    let rules: Vec<SarifRule> = rule_descriptions
        .iter()
        .map(|(id, desc)| SarifRule {
            id: id.clone(),
            name: id.clone(),
            short_description: SarifMessage { text: desc.clone() },
        })
        .collect();

    let results: Vec<SarifResult> = report
        .alerts
        .iter()
        .map(|a| {
            Ok(SarifResult {
                rule_id: format!("{:?}", a.kind),
                level: "warning",
                message: SarifMessage {
                    text: format!("{} — {}", a.why_bs, a.suggestion),
                },
                locations: vec![SarifLocation {
                    physical_location: SarifPhysicalLocation {
                        artifact_location: sarif_location(&a.file, &root)?,
                        region: SarifRegion { start_line: a.line },
                    },
                }],
            })
        })
        .collect::<anyhow::Result<_>>()?;

    Ok(SarifRoot {
        version: "2.1.0",
        schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        runs: vec![SarifRun {
            tool: SarifTool {
                driver: SarifDriver {
                    name: "cargo-anoint",
                    version: env!("CARGO_PKG_VERSION"),
                    information_uri: "https://github.com/codeandsolder/cargo-anoint",
                    rules,
                },
            },
            original_uri_base_ids: BTreeMap::from([(
                "%SRCROOT%",
                SarifArtifactLocation {
                    uri: root.to_string(),
                    uri_base_id: None,
                },
            )]),
            results,
        }],
    })
}

#[cfg(test)]
mod sarif_tests {
    use super::*;

    #[test]
    fn artifact_locations_are_encoded_and_external_paths_are_absolute() -> anyhow::Result<()> {
        let directory = tempfile::tempdir()?;
        let root = directory.path().canonicalize()?.join("source");
        let base =
            url::Url::from_directory_path(&root).map_err(|()| anyhow::anyhow!("test URI"))?;
        let local = sarif_location(&root.join("żółć #.rs"), &base)?;
        assert_eq!(local.uri_base_id, Some("%SRCROOT%"));
        assert_eq!(local.uri, "./%C5%BC%C3%B3%C5%82%C4%87%20%23.rs");
        let external = sarif_location(&root.with_file_name("source-other").join("lib.rs"), &base)?;
        assert_eq!(external.uri_base_id, None);
        assert!(external.uri.starts_with("file:"));
        Ok(())
    }
}
