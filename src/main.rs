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

fn unique_direct_dependency_versions(
    snapshots: &[cargo_anoint::parser::PackageResult],
) -> Vec<(&str, &str)> {
    let mut seen = std::collections::HashSet::new();
    snapshots
        .iter()
        .flat_map(|snapshot| snapshot.deps.iter())
        .filter(|dependency| dependency.is_direct)
        .filter_map(|dependency| {
            let key = (dependency.name.as_str(), dependency.version.as_str());
            seen.insert(key).then_some(key)
        })
        .collect()
}

fn parse_fail_on_levels(
    raw: &[String],
) -> Result<Option<HashSet<cargo_anoint::suggestions::Impact>>> {
    if raw.is_empty() {
        return Ok(None);
    }
    let mut out = HashSet::new();
    for part in raw {
        let p = part.trim().to_ascii_lowercase();
        if p.is_empty() {
            continue;
        }
        match p.as_str() {
            "low" => {
                out.insert(cargo_anoint::suggestions::Impact::Low);
            }
            "medium" => {
                out.insert(cargo_anoint::suggestions::Impact::Medium);
            }
            "high" | "critical" => {
                out.insert(cargo_anoint::suggestions::Impact::High);
            }
            other => {
                bail!(
                    "unknown --fail-on level {other:?} (expected low, medium, high, or critical)"
                );
            }
        }
    }
    if out.is_empty() {
        return Ok(None);
    }
    Ok(Some(out))
}

fn dependency_fail_triggered(
    suggestions: &[cargo_anoint::suggestions::Suggestion],
    levels: &HashSet<cargo_anoint::suggestions::Impact>,
) -> bool {
    suggestions.iter().any(|s| levels.contains(&s.impact))
}

fn maybe_fail_on_exit(
    suggestions: &[cargo_anoint::suggestions::Suggestion],
    levels: Option<&HashSet<cargo_anoint::suggestions::Impact>>,
    fail_on_overlap: bool,
) -> Result<()> {
    if fail_on_overlap
        && suggestions
            .iter()
            .any(|s| s.kind == cargo_anoint::suggestions::SuggestionKind::CapabilityOverlap)
    {
        bail!("exiting with non-zero status: potential overlapping dependency providers");
    }
    if let Some(set) = levels
        && dependency_fail_triggered(suggestions, set)
    {
        bail!("exiting with non-zero status: at least one dependency suggestion matched --fail-on");
    }
    Ok(())
}

async fn run_anoint_command(opts: &cli::AnointOpts) -> Result<()> {
    if opts.init_ci {
        return run_init_ci(opts.manifest_path.as_deref());
    }
    if opts.init_hooks {
        return run_init_hooks(opts.manifest_path.as_deref());
    }
    if let Some(ref pattern) = opts.explain {
        return run_explain(pattern);
    }
    reject_invalid_flag_combinations(opts)?;
    reject_unfinished_flags(opts)?;
    if opts.feedback {
        return run_feedback_command(opts);
    }

    let manifest = opts.manifest_path.as_deref();
    let policy = load_policy(opts.policy.as_deref(), manifest)?;

    let effective_fail_on: Vec<String> = if opts.fail_on.is_empty() {
        policy
            .as_ref()
            .and_then(|p| p.fail_on.clone())
            .unwrap_or_default()
    } else {
        opts.fail_on.clone()
    };
    let fail_levels = parse_fail_on_levels(&effective_fail_on)?;

    if opts.update_rules {
        cargo_anoint::updater::update_rules().await?;
        println!(
            "Candidate rules fetched; review changes using the update-suggestions binary before committing."
        );
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
        &scan.all,
        fail_levels.as_ref(),
        opts.fail_on_overlap || policy.as_ref().is_some_and(|p| p.settings.fail_on_overlap),
    )
}

struct DependencyScan {
    snapshots: Vec<cargo_anoint::parser::PackageResult>,
    per_package: Vec<Vec<cargo_anoint::suggestions::Suggestion>>,
    all: Vec<cargo_anoint::suggestions::Suggestion>,
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

        let mut per_pkg_suggestions: Vec<Vec<cargo_anoint::suggestions::Suggestion>> = Vec::new();
        for snap in &snapshots {
            let mpath = snap.manifest_path.as_path();
            let raw = if tagged {
                cargo_anoint::suggestions::analyze_for_package(
                    Some(mpath),
                    &snap.deps,
                    &rules,
                    Some(snap.name.as_str()),
                )?
            } else {
                cargo_anoint::suggestions::analyze(Some(mpath), &snap.deps, &rules)?
            };
            per_pkg_suggestions.push(apply_policy(raw, policy));
        }

        let all = per_pkg_suggestions.iter().flatten().cloned().collect();
        Ok(Self {
            snapshots,
            per_package: per_pkg_suggestions,
            all,
            code_audit_config: cargo_anoint::code_audit::config_from_policy(policy),
            offline: opts.offline || policy.is_some_and(|p| p.settings.offline),
        })
    }

    fn audit(&self) -> Result<cargo_anoint::code_audit::CodeAuditReport> {
        let reports = self
            .snapshots
            .iter()
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
            .snapshots
            .iter()
            .map(|s| {
                (
                    s.name.as_str(),
                    s.deps.iter().filter(|d| d.is_direct).count(),
                    s.deps.len(),
                )
            })
            .collect();
        println!("🙏 cargo-anoint v{}", env!("CARGO_PKG_VERSION"));
        println!();
        cargo_anoint::output::render_summary(&stats, &self.all);
        println!();
    }

    async fn render_json(&self, opts: &cli::AnointOpts) -> Result<()> {
        let packages_for_json: Vec<cargo_anoint::output::JsonPackageOutput<'_>> = self
            .snapshots
            .iter()
            .zip(self.per_package.iter())
            .map(|(snap, sug)| cargo_anoint::output::JsonPackageOutput {
                name: snap.name.as_str(),
                version: snap.version.as_str(),
                manifest_path: snap.manifest_path.display().to_string(),
                dependency_suggestions: sug.as_slice(),
            })
            .collect();

        let merged_audit = if opts.audit_code {
            Some(self.audit()?)
        } else {
            None
        };
        let advisories_for_json = if !self.offline && !opts.no_advisories {
            let dependencies = unique_direct_dependency_versions(&self.snapshots);
            cargo_anoint::advisories::fetch_advisories_batch_for_versions(&dependencies).await
        } else {
            Vec::new()
        };
        let report = cargo_anoint::output::JsonReportUnified {
            cargo_anoint_version: env!("CARGO_PKG_VERSION"),
            workspace_scan: opts.workspace || self.snapshots.len() > 1,
            packages: packages_for_json,
            code_audit: merged_audit.as_ref(),
            hardcoded_values: None,
            security_advisories: advisories_for_json,
        };
        cargo_anoint::output::render_unified_json(&report);
        Ok(())
    }

    async fn fetch_intel(&self) -> HashMap<String, cargo_anoint::intel::CrateIntel> {
        if !self.offline && !self.all.is_empty() {
            let crate_names: Vec<&str> =
                self.all.iter().flat_map(|s| s.current.split('+')).collect();

            if let Ok(client) = cargo_anoint::intel::IntelClient::new() {
                println!("{}", "🌐 Fetching live intelligence...".dimmed());
                let result = client.fetch_bulk_intel(&crate_names).await;
                if result.is_empty() && !crate_names.is_empty() {
                    println!(
                        "{}",
                        "⚠️  Live data unavailable (offline or rate-limited)"
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
        } else {
            HashMap::new()
        }
    }

    async fn render_text(&self, opts: &cli::AnointOpts) -> Result<()> {
        println!("🙏 cargo-anoint v{}", env!("CARGO_PKG_VERSION"));
        println!();
        if opts.fix {
            if opts.dry_run {
                println!(
                    "🔍 Dry-run — previewing Cargo.toml edits only (no writes, no `cargo update`)"
                );
                println!(
                "{}",
                "   `--fix` never modifies Rust sources; manifests may get a `.toml.bak` when applied."
                    .dimmed()
            );
            } else {
                println!(
                    "{}",
                    "🔧 Applying Cargo.toml autofixes (Rust source is never touched)".bold()
                );
            }
            println!();
        }

        print_dependency_summary(&self.snapshots);
        let intel = self.fetch_intel().await;
        let views: Vec<cargo_anoint::output::PackageSuggestionView<'_>> = self
            .snapshots
            .iter()
            .zip(self.per_package.iter())
            .map(|(snap, sug)| cargo_anoint::output::PackageSuggestionView {
                name: snap.name.as_str(),
                version: snap.version.as_str(),
                manifest_path: snap.manifest_path.as_path(),
                suggestions: sug.as_slice(),
            })
            .collect();

        cargo_anoint::output::render_packages_modernization(&views, &intel);

        // Security advisory check (osv.dev) — one batch call for all direct deps
        if !self.offline && !opts.no_advisories {
            let direct_dependencies = unique_direct_dependency_versions(&self.snapshots);
            if !direct_dependencies.is_empty() {
                let hits = cargo_anoint::advisories::fetch_advisories_batch_for_versions(
                    &direct_dependencies,
                )
                .await;
                cargo_anoint::output::render_advisories(&hits);
            }
        }

        if opts.audit_code {
            cargo_anoint::output::render_code_audit_report(&self.audit()?, opts.verbose);
        }
        self.apply_fixes(opts)
    }

    fn apply_fixes(&self, opts: &cli::AnointOpts) -> Result<()> {
        if opts.fix && !self.all.is_empty() {
            println!();
            for (snap, pkg_sugs) in self.snapshots.iter().zip(&self.per_package) {
                if pkg_sugs.is_empty() {
                    continue;
                }
                println!(
                    "{}",
                    format!(
                        "── Autofix: {} ({}) ──",
                        snap.name,
                        snap.manifest_path.display()
                    )
                    .dimmed()
                );
                cargo_anoint::fix::apply(pkg_sugs, &snap.manifest_path, opts.dry_run)?;
            }
        }

        Ok(())
    }
}

fn print_dependency_summary(snapshots: &[cargo_anoint::parser::PackageResult]) {
    println!("📋 Scanning dependencies...");
    println!();

    if let [snap] = snapshots {
        let deps = &snap.deps;
        let direct: Vec<_> = deps.iter().filter(|d| d.is_direct).collect();
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
            let direct = snap.deps.iter().filter(|d| d.is_direct).count();
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
            .map(|s| s.deps.iter().filter(|d| d.is_direct).count())
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
    let direct_count = deps.iter().filter(|d| d.is_direct).count();

    let rules = cargo_anoint::suggestions::load_rules()?;
    let suggestions = apply_policy(
        cargo_anoint::suggestions::analyze(manifest, &deps, &rules)?,
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
    let manifest = opts.manifest_path.as_deref();
    let policy = load_policy(opts.policy.as_deref(), manifest)?;
    let mut code_audit_config = cargo_anoint::code_audit::config_from_policy(policy.as_ref());
    if opts.include_tests {
        code_audit_config.include_tests = true;
    }
    let report = if opts.diff {
        cargo_anoint::code_audit::scan_git_diff(manifest, &code_audit_config)?
    } else {
        cargo_anoint::code_audit::scan_project(manifest, &code_audit_config)?
    };

    let bs_hits = if opts.hardcoded {
        let root = manifest
            .and_then(Path::parent)
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        cargo_anoint::bs_detector::scan_dir(root)?
    } else {
        Vec::new()
    };

    if opts.sarif {
        cargo_anoint::output::render_sarif(&report);
    } else if opts.json {
        let unified = cargo_anoint::output::JsonReportUnified {
            cargo_anoint_version: env!("CARGO_PKG_VERSION"),
            workspace_scan: false,
            packages: Vec::new(),
            code_audit: Some(&report),
            hardcoded_values: if opts.hardcoded { Some(&bs_hits) } else { None },
            security_advisories: Vec::new(),
        };
        cargo_anoint::output::render_unified_json(&unified);
    } else {
        println!("🙏 cargo-anoint v{}", env!("CARGO_PKG_VERSION"));
        cargo_anoint::output::render_code_audit_report(&report, opts.verbose);
        if opts.hardcoded {
            println!();
            cargo_anoint::bs_detector::render_bs_hits(&bs_hits);
        }
    }

    if opts.fix {
        apply_code_audit_fixes(&report, opts.dry_run)?;
    }

    if let Some(threshold) = opts.fail_on_confidence {
        let gated_count = report
            .alerts
            .iter()
            .filter(|a| f64::from(a.confidence) >= threshold)
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
            if path.exists() {
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

fn run_init_ci(manifest_path: Option<&Path>) -> Result<()> {
    let base = manifest_path
        .and_then(Path::parent)
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));

    let workflow_dir = base.join(".github").join("workflows");
    let workflow_path = workflow_dir.join("anoint.yml");

    if workflow_path.exists() {
        bail!(
            "{} already exists — delete it first to regenerate.",
            workflow_path.display()
        );
    }

    std::fs::create_dir_all(&workflow_dir)
        .with_context(|| format!("failed to create {}", workflow_dir.display()))?;
    std::fs::write(&workflow_path, INIT_CI_WORKFLOW)
        .with_context(|| format!("failed to write {}", workflow_path.display()))?;

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
    use std::os::unix::fs::PermissionsExt;

    let base = manifest_path
        .and_then(Path::parent)
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));

    let git_root_output = std::process::Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .current_dir(base)
        .output()
        .context("failed to run git rev-parse (is this a git repository?)")?;

    if !git_root_output.status.success() {
        bail!("not inside a git repository — cannot install a pre-commit hook");
    }

    let git_root = Path::new(std::str::from_utf8(&git_root_output.stdout)?.trim());
    let hooks_dir = git_root.join(".git").join("hooks");
    let hook_path = hooks_dir.join("pre-commit");

    if hook_path.exists() {
        bail!(
            "{} already exists — delete it first to regenerate.",
            hook_path.display()
        );
    }

    std::fs::create_dir_all(&hooks_dir)
        .with_context(|| format!("failed to create {}", hooks_dir.display()))?;

    let hook_script = "#!/bin/sh\ncargo anoint bs --fail-on-confidence 0.8\n";
    std::fs::write(&hook_path, hook_script)
        .with_context(|| format!("failed to write {}", hook_path.display()))?;
    std::fs::set_permissions(&hook_path, std::fs::Permissions::from_mode(0o755))
        .with_context(|| format!("failed to chmod {}", hook_path.display()))?;

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

fn apply_code_audit_fixes(
    report: &cargo_anoint::code_audit::CodeAuditReport,
    dry_run: bool,
) -> Result<()> {
    use std::collections::BTreeSet;

    let files_to_fix: BTreeSet<&std::path::PathBuf> = report
        .alerts
        .iter()
        .filter(|a| a.kind == cargo_anoint::code_audit::BullshitKind::UnwrapAbuse)
        .map(|a| &a.file)
        .collect();

    if files_to_fix.is_empty() {
        return Ok(());
    }

    let mut total_replacements = 0usize;

    for file in &files_to_fix {
        let contents = std::fs::read_to_string(file)
            .with_context(|| format!("failed to read {}", file.display()))?;

        let count = contents.matches(".unwrap()").count();
        if count == 0 {
            continue;
        }

        if dry_run {
            println!(
                "   {} {count} .unwrap() → .expect(\"TODO: handle this\") in {}",
                "would replace".dimmed(),
                file.display()
            );
        } else {
            let backup = file.with_extension("rs.bak");
            std::fs::write(&backup, &contents)
                .with_context(|| format!("failed to write backup {}", backup.display()))?;

            let modified = contents.replace(".unwrap()", ".expect(\"TODO: handle this\")");
            std::fs::write(file, &modified)
                .with_context(|| format!("failed to write {}", file.display()))?;
        }

        total_replacements += count;
    }

    if dry_run {
        println!(
            "🔍 Dry-run: {total_replacements} .unwrap() call(s) across {} file(s) would be replaced (no files written).",
            files_to_fix.len()
        );
        println!("   Remove --dry-run to apply the fixes.");
    } else {
        println!(
            "🙏 Fixed {total_replacements} .unwrap() call(s) across {} file(s). Backups written as *.rs.bak.",
            files_to_fix.len()
        );
        println!("   Review each .expect() and replace the TODO with a real reason.");
    }

    Ok(())
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
    if opts.feedback {
        if opts.fail_on_overlap
            || opts.all_features
            || opts.no_default_features
            || !opts.features.is_empty()
            || opts.target.is_some()
        {
            bail!("--feedback cannot be combined with overlap gating or feature/target selection");
        }
        if opts.fix {
            bail!("--feedback cannot be combined with --fix");
        }
        if opts.dry_run {
            bail!("--feedback cannot be combined with --dry-run");
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
        if opts.fix {
            bail!("--summary cannot be combined with --fix");
        }
        if opts.update_rules {
            bail!("--summary cannot be combined with --update-rules");
        }
        if opts.audit_code {
            bail!("--summary cannot be combined with --audit-code");
        }
        if opts.dry_run {
            bail!(
                "--summary cannot be combined with --dry-run (use `--fix --dry-run` on a normal run)"
            );
        }
    }
    if opts.dry_run && !opts.fix {
        bail!("--dry-run requires --fix");
    }
    if opts.json && opts.fix {
        bail!("--json cannot be combined with --fix");
    }
    if opts.json && opts.update_rules {
        bail!("--json cannot be combined with --update-rules");
    }

    Ok(())
}

fn reject_unfinished_flags(opts: &cli::AnointOpts) -> Result<()> {
    if opts.llm {
        bail!("--llm is not implemented in cargo-anoint yet");
    }

    Ok(())
}
