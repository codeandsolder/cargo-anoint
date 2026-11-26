use std::collections::HashMap;
use std::collections::HashSet;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::Parser;
use colored::Colorize;

mod cli;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let args = cli::Cli::parse();

    match args.command {
        cli::Commands::Anoint(command) => match command.command {
            Some(cli::AnointSubcommand::Bs(opts)) => run_code_audit_command(&opts),
            None => run_anoint_command(&command.opts).await,
        },
        cli::Commands::Bs(opts) => run_code_audit_command(&opts),
    }
}

fn resolution_options(opts: &cli::AnointOpts) -> cargo_anoint::parser::ResolutionOptions {
    cargo_anoint::parser::ResolutionOptions {
        all_features: opts.all_features,
        features: opts.features.clone(),
        no_default_features: opts.no_default_features,
        target: opts.target.clone(),
    }
}

const fn use_tagged_suggestions(opts: &cli::AnointOpts) -> bool {
    opts.workspace || !opts.package.is_empty()
}

fn unique_direct_registry_dependency_versions<'a>(
    snapshots: impl Iterator<Item = &'a cargo_anoint::parser::PackageResult>,
) -> Vec<(&'a str, &'a str)> {
    let mut seen = std::collections::HashSet::new();
    snapshots
        .flat_map(|snapshot| snapshot.deps.iter())
        .filter(|dependency| {
            dependency.is_direct()
                && matches!(
                    dependency.source.as_deref(),
                    Some(
                        "registry+https://github.com/rust-lang/crates.io-index"
                            | "sparse+https://index.crates.io/"
                    )
                )
        })
        .filter_map(|dependency| {
            let key = (dependency.name.as_str(), dependency.version.as_str());
            seen.insert(key).then_some(key)
        })
        .collect()
}

fn maybe_fail_on_exit(
    suggestions: &[&cargo_anoint::suggestions::Suggestion],
    levels: &HashSet<cargo_anoint::suggestions::Impact>,
    fail_on_overlap: bool,
) -> Result<()> {
    if fail_on_overlap
        && suggestions
            .iter()
            .any(|s| s.kind == cargo_anoint::suggestions::SuggestionKind::CapabilityOverlap)
    {
        bail!("exiting with non-zero status: potential overlapping dependency providers");
    }
    if suggestions
        .iter()
        .any(|suggestion| levels.contains(&suggestion.impact))
    {
        bail!("exiting with non-zero status: at least one dependency suggestion matched --fail-on");
    }
    Ok(())
}

async fn run_anoint_command(opts: &cli::AnointOpts) -> Result<()> {
    reject_invalid_flag_combinations(opts)?;
    if opts.init_ci {
        return run_init_ci(opts.manifest_path.as_deref());
    }
    if opts.init_hooks {
        return run_init_hooks(opts.manifest_path.as_deref());
    }
    if let Some(ref pattern) = opts.explain {
        return run_explain(pattern);
    }
    if opts.feedback {
        return run_feedback_command(opts);
    }

    let manifest = opts.manifest_path.as_deref();
    let policy = load_policy(opts.policy.as_deref(), manifest)?;

    let levels = if opts.fail_on.is_empty() {
        policy
            .as_ref()
            .map_or(&[][..], |policy| policy.fail_on.as_slice())
    } else {
        &opts.fail_on
    };
    let fail_levels: HashSet<_> = levels.iter().copied().collect();

    if opts.update_rules {
        anyhow::ensure!(
            !opts.offline
                && !policy
                    .as_ref()
                    .is_some_and(|policy| policy.settings.offline),
            "cannot fetch candidate rules in offline mode"
        );
        let candidates = cargo_anoint::updater::update_rules().await?;
        println!("{}", serde_json::to_string_pretty(&candidates)?);
        return Ok(());
    }
    let scan = DependencyScan::new(opts, policy.as_ref())?;
    if opts.summary {
        scan.summary();
    } else if opts.json {
        scan.render_json(opts).await?;
    } else {
        scan.render_text(opts).await?;
    }
    maybe_fail_on_exit(
        &scan.suggestions().collect::<Vec<_>>(),
        &fail_levels,
        opts.fail_on_overlap || policy.as_ref().is_some_and(|p| p.settings.fail_on_overlap),
    )
}

struct PackageScan {
    snapshot: cargo_anoint::parser::PackageResult,
    suggestions: Vec<cargo_anoint::suggestions::Suggestion>,
}

struct DependencyScan {
    packages: Vec<PackageScan>,
    code_audit_config: cargo_anoint::code_audit::CodeAuditConfig,
    offline: bool,
}

impl DependencyScan {
    fn new(opts: &cli::AnointOpts, policy: Option<&cargo_anoint::policy::Policy>) -> Result<Self> {
        let manifest = opts.manifest_path.as_deref();
        let tagged =
            use_tagged_suggestions(opts) || policy.is_some_and(|p| !p.allow_overlap.is_empty());
        let effective_all_targets =
            opts.all_targets || policy.is_some_and(|p| p.settings.all_targets);
        let snapshots = cargo_anoint::parser::get_package_snapshots(
            manifest,
            opts.workspace,
            &opts.package,
            effective_all_targets,
            &resolution_options(opts),
        )?;
        let rules = cargo_anoint::suggestions::load_rules()?;

        let mut packages = Vec::with_capacity(snapshots.len());
        for snap in snapshots {
            let raw = cargo_anoint::suggestions::analyze(
                &snap.deps,
                &rules,
                tagged.then_some(snap.name.as_str()),
            )?;
            packages.push(PackageScan {
                snapshot: snap,
                suggestions: apply_policy(raw, policy),
            });
        }

        Ok(Self {
            packages,
            code_audit_config: cargo_anoint::code_audit::config_from_policy(policy),
            offline: opts.offline || policy.is_some_and(|p| p.settings.offline),
        })
    }

    fn snapshots(&self) -> impl Iterator<Item = &cargo_anoint::parser::PackageResult> {
        self.packages.iter().map(|package| &package.snapshot)
    }

    fn suggestions(&self) -> impl Iterator<Item = &cargo_anoint::suggestions::Suggestion> {
        self.packages
            .iter()
            .flat_map(|package| &package.suggestions)
    }

    fn audit(&self) -> Result<cargo_anoint::code_audit::CodeAuditReport> {
        let reports = self
            .snapshots()
            .map(|s| {
                cargo_anoint::code_audit::scan_project(
                    Some(&s.manifest_path),
                    &self.code_audit_config,
                )
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(cargo_anoint::code_audit::merge_reports(reports))
    }

    fn summary(&self) {
        let stats: Vec<_> = self
            .snapshots()
            .map(|s| {
                (
                    s.name.as_str(),
                    s.deps.iter().filter(|d| d.is_direct()).count(),
                    s.deps.len(),
                )
            })
            .collect();
        println!("🙏 cargo-anoint v{}", env!("CARGO_PKG_VERSION"));
        println!();
        cargo_anoint::output::render_summary(&stats, &self.suggestions().collect::<Vec<_>>());
        println!();
    }

    async fn render_json(&self, opts: &cli::AnointOpts) -> Result<()> {
        let packages_for_json: Vec<cargo_anoint::output::JsonPackageOutput<'_>> = self
            .packages
            .iter()
            .map(
                |PackageScan {
                     snapshot: snap,
                     suggestions: sug,
                 }| cargo_anoint::output::JsonPackageOutput {
                    name: snap.name.as_str(),
                    version: snap.version.as_str(),
                    manifest_path: snap.manifest_path.display().to_string(),
                    dependency_suggestions: sug.as_slice(),
                },
            )
            .collect();

        let merged_audit = if opts.audit_code {
            Some(self.audit()?)
        } else {
            None
        };
        let advisories_for_json = self.advisory_report(opts).await;
        let report = cargo_anoint::output::JsonReportUnified {
            cargo_anoint_version: env!("CARGO_PKG_VERSION"),
            workspace_scan: opts.workspace || self.packages.len() > 1,
            packages: packages_for_json,
            code_audit: merged_audit.as_ref(),
            hardcoded_values: None,
            security_advisories: advisories_for_json,
        };
        cargo_anoint::output::render_unified_json(&report)?;
        Ok(())
    }

    async fn advisory_report(
        &self,
        opts: &cli::AnointOpts,
    ) -> cargo_anoint::advisories::AdvisoryReport {
        use cargo_anoint::advisories::{AdvisoryReport, fetch_advisories_batch_for_versions};
        if self.offline || opts.no_advisories {
            return AdvisoryReport::Skipped;
        }
        let dependencies = unique_direct_registry_dependency_versions(self.snapshots());
        match fetch_advisories_batch_for_versions(&dependencies).await {
            Ok(findings) => AdvisoryReport::Complete {
                checked: dependencies.len(),
                findings,
            },
            Err(error) => AdvisoryReport::Unavailable {
                error: format!("{error:#}"),
            },
        }
    }

    async fn fetch_intel(&self) -> HashMap<String, cargo_anoint::intel::CrateIntel> {
        if self.offline {
            return HashMap::new();
        }
        let crate_names: Vec<&str> = self
            .suggestions()
            .flat_map(|s| s.current.split('+'))
            .collect();
        if crate_names.is_empty() {
            return HashMap::new();
        }

        if let Ok(client) = cargo_anoint::intel::IntelClient::new().await {
            println!("{}", "🌐 Fetching live intelligence...".dimmed());
            let (result, failed) = client.fetch_bulk_intel(&crate_names).await;
            if failed > 0 {
                println!(
                    "{}",
                    format!("⚠️  Live data unavailable for {failed} crate(s)")
                        .yellow()
                        .dimmed()
                );
            }
            println!();
            result
        } else {
            println!(
                "{}",
                "⚠️  Could not initialize live intelligence (continuing without)"
                    .yellow()
                    .dimmed()
            );
            println!();
            HashMap::new()
        }
    }

    async fn render_text(&self, opts: &cli::AnointOpts) -> Result<()> {
        println!("🙏 cargo-anoint v{}", env!("CARGO_PKG_VERSION"));
        println!();
        print_dependency_summary(&self.snapshots().collect::<Vec<_>>());
        let intel = self.fetch_intel().await;
        let views: Vec<cargo_anoint::output::PackageSuggestionView<'_>> = self
            .packages
            .iter()
            .map(
                |PackageScan {
                     snapshot: snap,
                     suggestions: sug,
                 }| cargo_anoint::output::PackageSuggestionView {
                    name: snap.name.as_str(),
                    version: snap.version.as_str(),
                    manifest_path: snap.manifest_path.as_path(),
                    suggestions: sug.as_slice(),
                },
            )
            .collect();

        cargo_anoint::output::render_packages_modernization(&views, &intel);

        cargo_anoint::output::render_advisories(&self.advisory_report(opts).await);

        if opts.audit_code {
            cargo_anoint::output::render_code_audit_report(&self.audit()?, opts.verbose);
        }
        Ok(())
    }
}

fn print_dependency_summary(snapshots: &[&cargo_anoint::parser::PackageResult]) {
    println!("📋 Scanning dependencies...");
    println!();

    if let [snap] = snapshots {
        let deps = &snap.deps;
        let direct: Vec<_> = deps.iter().filter(|d| d.is_direct()).collect();
        let transitive_count = deps.len() - direct.len();

        println!(
            "{}",
            format!("📦 Direct dependencies ({})", direct.len()).bold()
        );
        for dep in &direct {
            let features_str = if dep.enabled_features.is_empty() {
                String::new()
            } else {
                format!(" [{}]", dep.enabled_features.join(", "))
            };
            println!(
                "  {} {} {}{}",
                "•".green(),
                dep.name.bold(),
                dep.version.dimmed(),
                features_str.dimmed()
            );
        }

        println!();
        println!(
            "{}",
            format!("📎 Transitive dependencies ({transitive_count})").dimmed()
        );

        println!();
        println!(
            "{}",
            format!("Found {} direct deps, {} total.", direct.len(), deps.len()).bold()
        );
    } else {
        for snap in snapshots {
            let direct = snap.deps.iter().filter(|d| d.is_direct()).count();
            let total = snap.deps.len();
            println!(
                "  {} {} v{} — {direct} direct, {total} total ({})",
                "•".green(),
                snap.name.bold(),
                snap.version.dimmed(),
                snap.manifest_path.display().to_string().dimmed()
            );
        }
        println!();
        let total_direct: usize = snapshots
            .iter()
            .map(|s| s.deps.iter().filter(|d| d.is_direct()).count())
            .sum();
        let total_all: usize = snapshots.iter().map(|s| s.deps.len()).sum();
        println!(
            "{}",
            format!(
                "Workspace: {} members · {total_direct} direct deps (sum) · {total_all} resolved rows (sum).",
                snapshots.len()
            )
            .bold()
        );
    }

    println!();
}

fn run_feedback_command(opts: &cli::AnointOpts) -> Result<()> {
    let manifest = opts.manifest_path.as_deref();
    let policy = load_policy(opts.policy.as_deref(), manifest)?;
    let code_audit_config = cargo_anoint::code_audit::config_from_policy(policy.as_ref());

    let deps = cargo_anoint::parser::get_deps(manifest)?;
    let direct_count = deps.iter().filter(|d| d.is_direct()).count();

    let rules = cargo_anoint::suggestions::load_rules()?;
    let suggestions = apply_policy(
        cargo_anoint::suggestions::analyze(&deps, &rules, None)?,
        policy.as_ref(),
    );

    let report = cargo_anoint::code_audit::scan_project(manifest, &code_audit_config)?;

    cargo_anoint::feedback::emit_feedback_stdout(
        env!("CARGO_PKG_VERSION"),
        manifest,
        direct_count,
        deps.len(),
        &suggestions,
        &report,
    );
    Ok(())
}

fn run_code_audit_command(opts: &cli::CodeAuditOpts) -> Result<()> {
    if let Some(threshold) = opts.fail_on_confidence {
        anyhow::ensure!(
            (0.0..=1.0).contains(&threshold),
            "--fail-on-confidence must be between 0 and 1"
        );
    }
    let manifest = opts.manifest_path.as_deref();
    let policy = load_policy(opts.policy.as_deref(), manifest)?;
    let mut code_audit_config = cargo_anoint::code_audit::config_from_policy(policy.as_ref());
    if opts.include_tests {
        code_audit_config.include_tests = true;
    }
    if let Some(threshold) = opts.fail_on_confidence {
        code_audit_config.confidence_threshold =
            code_audit_config.confidence_threshold.min(threshold);
    }
    let audit = cargo_anoint::code_audit::scan_project_with_options(
        manifest,
        &code_audit_config,
        cargo_anoint::code_audit::AuditOptions {
            diff_only: opts.diff,
            hardcoded: opts.hardcoded,
        },
    )?;
    let report = audit.report;

    if opts.sarif {
        cargo_anoint::output::render_sarif(&report)?;
    } else if opts.json {
        let unified = cargo_anoint::output::JsonReportUnified {
            cargo_anoint_version: env!("CARGO_PKG_VERSION"),
            workspace_scan: false,
            packages: Vec::new(),
            code_audit: Some(&report),
            hardcoded_values: audit.hardcoded_values.as_deref(),
            security_advisories: cargo_anoint::advisories::AdvisoryReport::Skipped,
        };
        cargo_anoint::output::render_unified_json(&unified)?;
    } else {
        println!("🙏 cargo-anoint v{}", env!("CARGO_PKG_VERSION"));
        cargo_anoint::output::render_code_audit_report(&report, opts.verbose);
        if let Some(hits) = &audit.hardcoded_values {
            println!();
            cargo_anoint::bs_detector::render_bs_hits(hits);
        }
    }

    if let Some(threshold) = opts.fail_on_confidence {
        let gated_count = report
            .alerts
            .iter()
            .filter(|a| a.confidence >= threshold)
            .count();
        if gated_count > 0 {
            eprintln!(
                "cargo-anoint: {gated_count} finding(s) at confidence >= {threshold:.2}; exiting with non-zero status."
            );
            std::process::exit(1);
        }
    }

    Ok(())
}

fn load_policy(
    explicit_path: Option<&Path>,
    manifest_path: Option<&Path>,
) -> Result<Option<cargo_anoint::policy::Policy>> {
    explicit_path.map_or_else(
        || {
            let path = default_policy_path(manifest_path);
            if path.try_exists()? {
                cargo_anoint::policy::try_load_policy(&path).map(Some)
            } else {
                Ok(None)
            }
        },
        |path| cargo_anoint::policy::try_load_policy(path).map(Some),
    )
}

fn default_policy_path(manifest_path: Option<&Path>) -> PathBuf {
    manifest_path
        .and_then(Path::parent)
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
        .join("anoint.toml")
}

const INIT_CI_WORKFLOW: &str = r"name: cargo-anoint

on:
  push:
    branches: [main]
  pull_request:

jobs:
  bless:
    runs-on: ubuntu-latest
    permissions:
      security-events: write  # required for upload-sarif

    steps:
      - uses: actions/checkout@v4

      - name: Set up Rust toolchain
        uses: dtolnay/rust-toolchain@nightly-2026-11-19

      - name: Cache Rust dependencies
        uses: Swatinem/rust-cache@v2

      - name: Install cargo-anoint
        run: cargo install --git https://github.com/codeandsolder/cargo-anoint --locked

      - name: Dependency modernization check
        run: cargo anoint --workspace --fail-on-overlap --offline

      - name: Code audit (SARIF)
        run: cargo anoint bs --sarif > anoint-audit.sarif
        continue-on-error: true

      - name: Upload SARIF to GitHub code scanning
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: anoint-audit.sarif
";

fn write_new_file(path: &Path, contents: &str, executable: bool) -> Result<()> {
    use std::io::Write;

    let parent = path.parent().context("file has no parent directory")?;
    std::fs::create_dir_all(parent)
        .with_context(|| format!("failed to create {}", parent.display()))?;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(if executable { 0o755 } else { 0o644 });
    }
    #[cfg(not(unix))]
    let _ = executable;
    let mut file = match options.open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            return Err(error).with_context(|| format!("{} already exists", path.display()));
        }
        Err(error) => {
            return Err(error).with_context(|| format!("failed to create {}", path.display()));
        }
    };
    file.write_all(contents.as_bytes())
        .with_context(|| format!("failed to write {}", path.display()))
}

fn run_init_ci(manifest_path: Option<&Path>) -> Result<()> {
    let base = manifest_path
        .and_then(Path::parent)
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));

    let workflow_dir = base.join(".github").join("workflows");
    let workflow_path = workflow_dir.join("anoint.yml");

    write_new_file(&workflow_path, INIT_CI_WORKFLOW, false)?;

    println!("🙏 Created {}", workflow_path.display());
    println!("   Commit and push to enable cargo-anoint CI.");
    println!();
    println!("   The workflow:");
    println!("     • Gates merges on curated potential capability overlaps");
    println!("     • Uploads code-audit findings as SARIF (GitHub code scanning / PR annotations)");
    println!();
    println!(
        "   Tip: add fail_on = [\"high\"] to anoint.toml to enforce the gate without repeating the flag."
    );

    Ok(())
}

fn run_init_hooks(manifest_path: Option<&Path>) -> Result<()> {
    let base = manifest_path
        .and_then(Path::parent)
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));

    let output = std::process::Command::new("git")
        .args([
            "rev-parse",
            "--path-format=absolute",
            "--git-path",
            "hooks/pre-commit",
        ])
        .current_dir(base)
        .output()
        .context("failed to resolve Git hook path")?;
    anyhow::ensure!(
        output.status.success(),
        "cannot resolve pre-commit hook: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    let path = std::str::from_utf8(&output.stdout)?;
    let hook_path = Path::new(
        path.strip_suffix('\n')
            .context("invalid Git hook path response")?,
    );
    let hook_script = "#!/bin/sh\ncargo anoint bs --fail-on-confidence 0.8\n";
    write_new_file(hook_path, hook_script, true)?;

    println!("🙏 Created {}", hook_path.display());
    println!("   The hook runs `cargo anoint bs --fail-on-confidence 0.8` before each commit.");
    println!();
    println!("   Tip: adjust the threshold or add --policy to suppress known findings.");

    Ok(())
}

fn run_explain(pattern: &str) -> Result<()> {
    use colored::Colorize;

    let rules = cargo_anoint::suggestions::load_rules()?;
    let pattern_lower = pattern.to_lowercase();
    let matches: Vec<_> = rules
        .iter()
        .filter(|r| r.pattern.to_lowercase().contains(&pattern_lower))
        .collect();

    if matches.is_empty() {
        bail!(
            "No rule found for '{pattern}'. Run `cargo anoint` on a project to see active suggestions."
        );
    }

    println!("🙏 cargo-anoint — explain: {}", pattern.bold());

    for rule in matches {
        println!();
        println!("  {:<16} {}", "Pattern:".bold(), rule.pattern);
        println!("  {:<16} {}", "Replace with:".bold(), rule.replacement);
        println!("  {:<16} {:?}", "Kind:".bold(), rule.kind);
        println!("  {:<16} {:?}", "Confidence:".bold(), rule.confidence);
        println!(
            "  {:<16} {:?}",
            "Migration risk:".bold(),
            rule.migration_risk
        );
        if let Some(ref cond) = rule.condition {
            println!("  {:<16} {cond}", "Condition:".bold());
        }
        println!("  {:<16} {}", "Source:".bold(), rule.source);
        println!();
        println!("  {}", "Why:".bold());
        for line in textwrap_rule(&rule.reason) {
            println!("    {line}");
        }
    }

    Ok(())
}

fn textwrap_rule(s: &str) -> Vec<String> {
    const WIDTH: usize = 72;
    let mut lines = Vec::new();
    let mut current = String::new();
    for word in s.split_whitespace() {
        if current.is_empty() {
            current.push_str(word);
        } else if current.len() + 1 + word.len() <= WIDTH {
            current.push(' ');
            current.push_str(word);
        } else {
            lines.push(std::mem::take(&mut current));
            current = word.to_string();
        }
    }
    if !current.is_empty() {
        lines.push(current);
    }
    lines
}

fn apply_policy(
    suggestions: Vec<cargo_anoint::suggestions::Suggestion>,
    policy: Option<&cargo_anoint::policy::Policy>,
) -> Vec<cargo_anoint::suggestions::Suggestion> {
    match policy {
        Some(policy) => cargo_anoint::policy::apply_policy(suggestions, policy),
        None => suggestions,
    }
}

fn reject_invalid_flag_combinations(opts: &cli::AnointOpts) -> Result<()> {
    if opts.json && opts.update_rules {
        bail!("--json cannot be combined with --update-rules");
    }
    let maintenance_modes = [
        opts.init_ci,
        opts.init_hooks,
        opts.explain.is_some(),
        opts.update_rules,
    ];
    anyhow::ensure!(
        maintenance_modes
            .into_iter()
            .filter(|selected| *selected)
            .count()
            <= 1,
        "select only one maintenance command"
    );
    if maintenance_modes.into_iter().any(|selected| selected) {
        anyhow::ensure!(
            !opts.feedback && !opts.summary && !opts.json,
            "maintenance commands cannot be combined with reporting modes"
        );
        anyhow::ensure!(
            !opts.fail_on_overlap && opts.fail_on.is_empty(),
            "maintenance commands cannot be combined with dependency gates"
        );
        anyhow::ensure!(
            !opts.audit_code
                && !opts.workspace
                && opts.package.is_empty()
                && !opts.all_targets
                && !opts.all_features
                && !opts.no_default_features
                && opts.features.is_empty()
                && opts.target.is_none(),
            "maintenance commands cannot be combined with dependency or source scan selection"
        );
    }

    if opts.feedback {
        if opts.fail_on_overlap
            || !opts.fail_on.is_empty()
            || opts.all_targets
            || opts.all_features
            || opts.no_default_features
            || !opts.features.is_empty()
            || opts.target.is_some()
        {
            bail!("--feedback cannot be combined with overlap gating or feature/target selection");
        }
        if opts.json {
            bail!("--feedback cannot be combined with --json");
        }
        if opts.update_rules {
            bail!("--feedback cannot be combined with --update-rules");
        }
        if opts.summary {
            bail!("--feedback cannot be combined with --summary");
        }
        if opts.audit_code {
            bail!("--feedback always includes the code audit; do not combine with --audit-code");
        }
        if opts.workspace || !opts.package.is_empty() {
            bail!(
                "--feedback analyzes the workspace root crate only — omit `--workspace` and `--package`"
            );
        }
    }
    if opts.summary {
        if opts.json {
            bail!("--summary cannot be combined with --json");
        }
        if opts.update_rules {
            bail!("--summary cannot be combined with --update-rules");
        }
        if opts.audit_code {
            bail!("--summary cannot be combined with --audit-code");
        }
    }

    Ok(())
}
