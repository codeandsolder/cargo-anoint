//! Static Rust code audit for suspicious complexity and brittle patterns.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::LazyLock;

use anyhow::{Context, Result, bail};
use regex::Regex;
use serde::{Deserialize, Serialize};
use tree_sitter::{Node, Parser};

use crate::bs_detector::{BSHit, inspect_literal};

const MAX_FILE_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
pub enum BullshitKind {
    FakeComplexity,
    OverEngineering,
    ArcAbuse,
    RwLockAbuse,
    SleepAbuse,
    UnwrapAbuse,
    MutexAbuse,
    TodoUnimplemented,
    RefCellAbuse,
    BoolComparison,
    StringAntiPattern,
    DiscardedError,
    LossyUtf8,
}

impl BullshitKind {
    const fn label(self) -> &'static str {
        match self {
            Self::FakeComplexity => "fake complexity",
            Self::OverEngineering => "over-engineering",
            Self::ArcAbuse => "Arc abuse",
            Self::RwLockAbuse => "RwLock abuse",
            Self::SleepAbuse => "sleep abuse",
            Self::UnwrapAbuse => "unwrap abuse",
            Self::MutexAbuse => "mutex abuse",
            Self::TodoUnimplemented => "todo/unimplemented",
            Self::RefCellAbuse => "RefCell abuse",
            Self::BoolComparison => "redundant bool comparison",
            Self::StringAntiPattern => "string anti-pattern",
            Self::DiscardedError => "discarded error",
            Self::LossyUtf8 => "lossy UTF-8 conversion",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BullshitAlert {
    pub kind: BullshitKind,
    pub confidence: f32,
    pub severity: f32,
    pub file: PathBuf,
    pub line: usize,
    /// One-based UTF-8 byte column.
    pub column: usize,
    pub context_snippet: String,
    pub why_bs: String,
    pub suggestion: String,
}

#[derive(Debug, Clone)]
pub struct CodeAuditConfig {
    pub confidence_threshold: f32,
    pub max_file_bytes: u64,
    pub ignore_paths: Vec<String>,
    pub ignore_kinds: HashSet<BullshitKind>,
    /// Include test-only items and conventional test, example and benchmark trees.
    pub include_tests: bool,
}

impl Default for CodeAuditConfig {
    fn default() -> Self {
        Self {
            confidence_threshold: 0.60,
            max_file_bytes: MAX_FILE_BYTES,
            ignore_paths: Vec::new(),
            ignore_kinds: HashSet::new(),
            include_tests: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeAuditReport {
    pub files_scanned: usize,
    pub alerts: Vec<BullshitAlert>,
}

impl CodeAuditReport {
    #[must_use = "Use the result to determine whether any findings remain"]
    pub const fn is_clean(&self) -> bool {
        self.alerts.is_empty()
    }
}

/// Concatenate workspace member audits into one report (sums `files_scanned`, merges alerts).
#[must_use = "Returns the combined report"]
pub fn merge_reports(reports: Vec<CodeAuditReport>) -> CodeAuditReport {
    let mut files_scanned = 0usize;
    let mut alerts = Vec::new();
    for r in reports {
        files_scanned += r.files_scanned;
        alerts.extend(r.alerts);
    }
    CodeAuditReport {
        files_scanned,
        alerts,
    }
}

/// Audit the selected package or workspace source tree.
/// # Errors
/// Returns an error if source discovery, reading, or scanning fails.
pub fn scan_project(
    manifest_path: Option<&Path>,
    config: &CodeAuditConfig,
) -> Result<CodeAuditReport> {
    Ok(scan_project_with_options(manifest_path, config, AuditOptions::default())?.report)
}

/// Optional scan modes for a single source traversal.
#[derive(Debug, Default, Clone, Copy)]
pub struct AuditOptions {
    /// Restrict findings to tracked lines changed since HEAD.
    pub diff_only: bool,
    /// Include hardcoded-value findings.
    pub hardcoded: bool,
}

/// Results of a source traversal.
#[derive(Debug)]
pub struct ProjectAudit {
    /// Source quality findings.
    pub report: CodeAuditReport,
    /// Hardcoded-value findings, if requested.
    pub hardcoded_values: Option<Vec<BSHit>>,
}

/// Audit with optional Git diff and hardcoded-value analysis.
/// # Errors
/// Returns an error if source discovery, Git diff collection, reading, or scanning fails.
pub fn scan_project_with_options(
    manifest_path: Option<&Path>,
    config: &CodeAuditConfig,
    options: AuditOptions,
) -> Result<ProjectAudit> {
    let diff_filter = if options.diff_only {
        let base_dir = project_base_dir(manifest_path).canonicalize()?;
        Some(DiffFilter::from_git_diff(&base_dir)?)
    } else {
        None
    };
    let mut hardcoded_values = options.hardcoded.then(Vec::new);
    let mut files = source_files(manifest_path, config)?;
    if let Some(filter) = &diff_filter {
        files.retain(|file| filter.contains_file(file));
    }

    let mut alerts = Vec::new();
    for file in &files {
        let size = fs::metadata(file)?.len();
        anyhow::ensure!(
            size <= config.max_file_bytes,
            "Rust source {} is {size} bytes, exceeding the audit limit of {} bytes; exclude it explicitly if intended",
            file.display(),
            config.max_file_bytes
        );
        let code = fs::read_to_string(file)
            .with_context(|| format!("failed to read {}", file.display()))?;
        let mut masks = parse_ignored_ranges(
            &code,
            config.include_tests,
            options.hardcoded.then_some(file.as_path()),
        )?;
        let mut file_alerts = scan_masked_code(&code, file, config, &masks)?;
        if let Some(hits) = &mut hardcoded_values {
            let mut file_hits = std::mem::take(&mut masks.hardcoded);
            if let Some(filter) = &diff_filter {
                file_hits.retain(|hit| filter.includes(file, hit.line));
            }
            hits.extend(file_hits);
        }
        if let Some(filter) = &diff_filter {
            file_alerts.retain(|alert| filter.includes(file, alert.line));
        }
        alerts.extend(file_alerts);
    }

    alerts.sort_by(|a, b| {
        b.severity
            .total_cmp(&a.severity)
            .then_with(|| a.file.cmp(&b.file))
            .then_with(|| a.line.cmp(&b.line))
    });

    Ok(ProjectAudit {
        report: CodeAuditReport {
            files_scanned: files.len(),
            alerts,
        },
        hardcoded_values,
    })
}

///
/// # Errors
/// Returns an error if the regular expressions used for scanning cannot be initialized.
pub fn scan_code(
    code: &str,
    file: impl Into<PathBuf>,
    config: &CodeAuditConfig,
) -> Result<Vec<BullshitAlert>> {
    let file = file.into();
    if is_ignored_path(&file, config) {
        return Ok(Vec::new());
    }

    let masks = parse_ignored_ranges(code, config.include_tests, None)?;
    scan_masked_code(code, &file, config, &masks)
}

fn scan_masked_code(
    code: &str,
    file: &Path,
    config: &CodeAuditConfig,
    masks: &SourceMasks,
) -> Result<Vec<BullshitAlert>> {
    let masked = mask_ranges(code, masks.excluded.iter().chain(&masks.literals).copied())?;
    let mut alerts = Vec::new();

    let locations = LineIndex::new(&masked);
    scan_regex_patterns(&masked, file, &locations, &mut alerts)?;
    scan_function_complexity(&masked, file, &locations, &masks.functions, &mut alerts);
    for &start in &masks.discarded_results {
        alerts.push(make_alert(
            BullshitKind::DiscardedError,
            0.76,
            file,
            &masked,
            &locations,
            start,
            start,
            "Calling .ok() as a statement discards the result and can hide an error.",
            "Propagate, handle or explicitly document the failure policy.",
        ));
    }

    alerts.retain(|alert| alert.confidence >= config.confidence_threshold);
    alerts.retain(|alert| !config.ignore_kinds.contains(&alert.kind));
    dedupe_alerts(&mut alerts);
    Ok(alerts)
}

#[must_use = "Returns the effective audit configuration"]
pub fn config_from_policy(policy: Option<&crate::policy::Policy>) -> CodeAuditConfig {
    let mut config = CodeAuditConfig::default();
    if let Some(policy) = policy {
        config
            .ignore_paths
            .clone_from(&policy.code_audit.ignore_paths);
        config.ignore_kinds = policy.code_audit.ignore_kinds.iter().copied().collect();
        if let Some(threshold) = policy.settings.min_confidence {
            config.confidence_threshold = threshold;
        }
        if policy.code_audit.include_tests {
            config.include_tests = true;
        }
    }
    config
}

fn project_base_dir(manifest_path: Option<&Path>) -> &Path {
    manifest_path
        .and_then(Path::parent)
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

fn is_ignored_path(path: &Path, config: &CodeAuditConfig) -> bool {
    let path = path.to_string_lossy();
    config
        .ignore_paths
        .iter()
        .any(|pattern| path.contains(pattern))
}

fn source_files(
    manifest_path: Option<&Path>,
    config: &CodeAuditConfig,
) -> Result<BTreeSet<PathBuf>> {
    let base = project_base_dir(manifest_path).canonicalize()?;
    let default_manifest = base.join("Cargo.toml");
    let manifest = manifest_path.unwrap_or(&default_manifest);
    let mut files = BTreeSet::new();
    if !manifest.try_exists()? {
        anyhow::ensure!(
            manifest_path.is_none(),
            "manifest {} does not exist",
            manifest.display()
        );
        collect_rust_files(&base, &base, None, config, &mut files)?;
        return Ok(files);
    }

    // Cargo already understands virtual workspaces, inherited settings,
    // explicit target paths and custom build scripts. No dependency resolution
    // is needed to discover the package source layout.
    let manifest = manifest.canonicalize()?;
    let metadata = cargo_metadata::MetadataCommand::new()
        .manifest_path(&manifest)
        .no_deps()
        .exec()
        .context("discover Cargo source layout")?;
    let selected = metadata
        .packages
        .iter()
        .find(|pkg| pkg.manifest_path.as_std_path() == manifest);
    let packages: Vec<_> = selected.map_or_else(|| metadata.workspace_packages(), |pkg| vec![pkg]);
    for package in packages {
        let root = package
            .manifest_path
            .as_std_path()
            .parent()
            .context("package manifest has no parent")?;
        let target_dir = metadata.target_directory.as_std_path();
        let mut package_files = BTreeSet::new();
        collect_rust_files(root, root, Some(target_dir), config, &mut package_files)?;
        let mut included_targets = BTreeSet::new();
        for target in &package.targets {
            use cargo_metadata::TargetKind;
            let path = target.src_path.as_std_path();
            let test_only = target.kind.iter().all(|kind| {
                matches!(
                    kind,
                    TargetKind::Test | TargetKind::Bench | TargetKind::Example
                )
            });
            if !config.include_tests && test_only {
                package_files.remove(path);
            } else if !is_ignored_path(path, config) {
                included_targets.insert(path.to_path_buf());
            }
        }
        package_files.extend(included_targets);
        files.extend(package_files);
    }
    Ok(files)
}

fn collect_rust_files(
    root: &Path,
    dir: &Path,
    target_dir: Option<&Path>,
    config: &CodeAuditConfig,
    files: &mut BTreeSet<PathBuf>,
) -> Result<()> {
    for entry in fs::read_dir(dir).with_context(|| format!("failed to read {}", dir.display()))? {
        let entry = entry?;
        let path = entry.path();
        if is_ignored_path(&path, config) {
            continue;
        }
        let name = entry.file_name();
        let name = name.to_string_lossy();
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            if should_skip_dir(&name)
                || target_dir == Some(path.as_path())
                || (!config.include_tests
                    && dir == root
                    && matches!(name.as_ref(), "tests" | "examples" | "benches"))
                || (target_dir.is_some() && path.join("Cargo.toml").try_exists()?)
            {
                continue;
            }
            collect_rust_files(root, &path, target_dir, config, files)?;
        } else if file_type.is_file() && path.extension().is_some_and(|ext| ext == "rs") {
            files.insert(path);
        }
    }
    Ok(())
}

fn should_skip_dir(name: &str) -> bool {
    name.starts_with('.')
        || matches!(
            name,
            "target" | "vendor" | "node_modules" | "dist" | "third_party"
        )
}

#[derive(Debug)]
struct DiffFilter {
    base_dir: PathBuf,
    changed_lines: HashMap<PathBuf, Vec<(usize, usize)>>,
}

impl DiffFilter {
    fn from_git_diff(base_dir: &Path) -> Result<Self> {
        let names = git_diff(base_dir, &["--name-only", "-z"], None)?;
        let mut changed_lines = HashMap::new();
        for name in names
            .split(|byte| *byte == 0)
            .filter(|name| !name.is_empty())
        {
            let path =
                PathBuf::from(std::str::from_utf8(name).context("Git diff path is not UTF-8")?);
            if path.extension().is_none_or(|ext| ext != "rs") {
                continue;
            }
            let diff_bytes = git_diff(
                base_dir,
                &["--unified=0", "--no-ext-diff", "--no-textconv"],
                Some(&path),
            )?;
            let ranges: Vec<_> = String::from_utf8(diff_bytes)
                .context("Git patch is not UTF-8")?
                .lines()
                .filter_map(parse_hunk_new_range)
                .collect();
            if !ranges.is_empty() {
                changed_lines.insert(path, ranges);
            }
        }
        Ok(Self {
            base_dir: base_dir.to_path_buf(),
            changed_lines,
        })
    }

    fn relative_path(&self, path: &Path) -> PathBuf {
        normalize_diff_path(path.strip_prefix(&self.base_dir).unwrap_or(path))
    }

    fn contains_file(&self, path: &Path) -> bool {
        self.changed_lines.contains_key(&self.relative_path(path))
    }

    fn includes(&self, file: &Path, line: usize) -> bool {
        self.changed_lines
            .get(&self.relative_path(file))
            .is_some_and(|ranges| {
                ranges
                    .iter()
                    .any(|(start, end)| line >= *start && line <= *end)
            })
    }
}

fn git_diff(base_dir: &Path, args: &[&str], path: Option<&Path>) -> Result<Vec<u8>> {
    let mut command = Command::new("git");
    command
        .arg("--literal-pathspecs")
        .arg("-C")
        .arg(base_dir)
        .args(["diff", "HEAD", "--relative", "--no-renames", "--no-color"])
        .args(args)
        .arg("--");
    if let Some(path) = path {
        command.arg(path);
    }
    let output = command.output().context("run git diff HEAD")?;
    if !output.status.success() {
        bail!(
            "git diff failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(output.stdout)
}

fn parse_hunk_new_range(line: &str) -> Option<(usize, usize)> {
    let hunk = line.strip_prefix("@@ ")?;
    let plus = hunk.split_whitespace().find(|part| part.starts_with('+'))?;
    let plus = plus.trim_start_matches('+');
    let (start, count) = plus
        .split_once(',')
        .map_or((plus, Some(1)), |(start, count)| {
            (start, count.parse::<usize>().ok())
        });
    let start = start.parse::<usize>().ok()?;
    let count = count?;
    if count == 0 {
        None
    } else {
        Some((start, start.checked_add(count - 1)?))
    }
}

fn normalize_diff_path(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::CurDir => {}
            other => normalized.push(other.as_os_str()),
        }
    }
    normalized
}

#[derive(Default)]
struct SourceMasks {
    excluded: Vec<(usize, usize)>,
    literals: Vec<(usize, usize)>,
    functions: Vec<FunctionComplexity>,
    discarded_results: Vec<usize>,
    hardcoded: Vec<BSHit>,
}

struct FunctionComplexity {
    start: usize,
    score: usize,
}

fn parse_ignored_ranges(
    code: &str,
    include_tests: bool,
    hardcoded_path: Option<&Path>,
) -> Result<SourceMasks> {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_rust::LANGUAGE.into())
        .map_err(|err| anyhow::anyhow!("failed to load Rust tree-sitter grammar: {err}"))?;
    let tree = parser
        .parse(code, None)
        .ok_or_else(|| anyhow::anyhow!("tree-sitter failed to parse Rust source"))?;

    let mut ranges = SourceMasks::default();
    collect_ignored_ranges(
        tree.root_node(),
        code.as_bytes(),
        include_tests,
        hardcoded_path,
        &mut ranges,
    );
    Ok(ranges)
}

fn collect_ignored_ranges(
    node: Node<'_>,
    code: &[u8],
    include_tests: bool,
    hardcoded_path: Option<&Path>,
    ranges: &mut SourceMasks,
) -> usize {
    let kind = node.kind();
    let span = (node.start_byte(), node.end_byte());
    if let Some(path) = hardcoded_path {
        inspect_literal(node, code, path, &mut ranges.hardcoded);
    }
    if matches!(kind, "line_comment" | "block_comment") {
        ranges.excluded.push(span);
        return 0;
    }
    if matches!(
        kind,
        "string_literal" | "raw_string_literal" | "char_literal"
    ) {
        ranges.literals.push(span);
        return 0;
    }

    if kind == "expression_statement"
        && node
            .named_child(0)
            .is_some_and(|expr| method_name(expr, code) == Some("ok"))
    {
        ranges.discarded_results.push(node.start_byte());
    }
    let mut score = decision_weight(node, code);
    let mut cursor = node.walk();
    if !include_tests && matches!(kind, "source_file" | "declaration_list" | "block") {
        let mut test_only = false;
        for child in node.named_children(&mut cursor) {
            match child.kind() {
                "attribute_item" => {
                    test_only |= is_test_attr(child, code);
                    collect_ignored_ranges(child, code, include_tests, hardcoded_path, ranges);
                }
                "line_comment" | "block_comment" => {
                    ranges.excluded.push((child.start_byte(), child.end_byte()));
                }
                _ if test_only => {
                    ranges.excluded.push((child.start_byte(), child.end_byte()));
                    test_only = false;
                }
                _ => {
                    score +=
                        collect_ignored_ranges(child, code, include_tests, hardcoded_path, ranges)
                }
            }
        }
    } else {
        for child in node.named_children(&mut cursor) {
            score += collect_ignored_ranges(child, code, include_tests, hardcoded_path, ranges);
        }
    }
    if kind == "function_item" {
        ranges.functions.push(FunctionComplexity {
            start: node.start_byte(),
            score,
        });
        // Nested functions are independent units, not part of their parent's score.
        0
    } else {
        score
    }
}

fn decision_weight(node: Node<'_>, code: &[u8]) -> usize {
    match node.kind() {
        "if_expression" | "match_arm" | "for_expression" | "while_expression"
        | "loop_expression" | "try_expression" | "let_condition" => 1,
        "binary_expression" => usize::from(
            node.child_by_field_name("operator")
                .and_then(|op| op.utf8_text(code).ok())
                .is_some_and(|op| matches!(op, "&&" | "||")),
        ),
        "call_expression" => {
            usize::from(matches!(method_name(node, code), Some("unwrap" | "expect"))) * 2
        }
        _ => 0,
    }
}

fn method_name<'a>(node: Node<'_>, code: &'a [u8]) -> Option<&'a str> {
    node.child_by_field_name("function")
        .filter(|function| function.kind() == "field_expression")
        .and_then(|function| function.child_by_field_name("field"))
        .and_then(|field| field.utf8_text(code).ok())
}

fn is_test_attr(node: Node<'_>, code: &[u8]) -> bool {
    node.utf8_text(code).is_ok_and(|text| {
        let t: String = text.chars().filter(|c| !c.is_whitespace()).collect();
        matches!(t.as_str(), "#[test]" | "#[cfg(test)]")
            || ["#[tokio::test", "#[async_std::test"].iter().any(|prefix| {
                t.strip_prefix(prefix)
                    .is_some_and(|rest| rest.starts_with('(') || rest == "]")
            })
    })
}

fn mask_ranges(code: &str, ranges: impl IntoIterator<Item = (usize, usize)>) -> Result<String> {
    let mut bytes = code.as_bytes().to_vec();
    for (start, end) in ranges {
        let range = bytes
            .get_mut(start..end)
            .context("invalid tree-sitter source range")?;
        for byte in range {
            if *byte != b'\n' {
                *byte = b' ';
            }
        }
    }
    String::from_utf8(bytes).context("source masking produced invalid UTF-8")
}

struct RegexRule {
    regex: Regex,
    kind: BullshitKind,
    confidence: f32,
    why: &'static str,
    suggestion: &'static str,
}

fn compile_regex_rules() -> Result<Vec<RegexRule>, regex::Error> {
    let patterns = [
        (
            r"\bArc\s*<\s*(?:\w+::)*RwLock\s*<",
            BullshitKind::OverEngineering,
            0.86,
            "Arc<RwLock<...>> is often shared mutable state wearing a tuxedo.",
            "Try explicit ownership, message passing, or a narrower shared state boundary.",
        ),
        (
            r"\bArc\s*<\s*(?:\w+::)*Mutex\s*<",
            BullshitKind::OverEngineering,
            0.82,
            "Arc<Mutex<...>> can be valid, but it is also a classic complexity magnet.",
            "Check whether ownership can stay local or the locked data can be smaller.",
        ),
        (
            r"\bMutex\s*<\s*(?:\w+::)*HashMap\s*<",
            BullshitKind::MutexAbuse,
            0.76,
            "A Mutex<HashMap<...>> is a blunt concurrency primitive.",
            "Consider sharding, DashMap, or reducing shared mutable state.",
        ),
        (
            r"\bRwLock\s*<",
            BullshitKind::RwLockAbuse,
            0.64,
            "RwLock adds coordination cost and can hide unclear ownership.",
            "Use it only when read-heavy sharing is real and measured.",
        ),
        (
            r"\b(std::thread::sleep|tokio::time::sleep)\s*\(",
            BullshitKind::SleepAbuse,
            0.78,
            "Sleep calls are often timing bullshit instead of synchronization.",
            "Replace sleeps with explicit readiness, timeouts, retries, or test clocks.",
        ),
        (
            r"\bArc\s*<\s*(?:\w+::)*(?:String\b|Vec\s*<|Box\s*<)",
            BullshitKind::ArcAbuse,
            0.62,
            "Arc<String>, Arc<Vec<...>>, or Arc<Box<...>> wraps a value type in shared ownership — often unnecessary.",
            "Use Arc<str> instead of Arc<String>, or reconsider whether sharing is needed at all.",
        ),
        (
            r"\b(todo|unimplemented)\s*!\s*[(\[{]",
            BullshitKind::TodoUnimplemented,
            0.75,
            "todo!() or unimplemented!() will panic at runtime if reached in production.",
            "Return a Result or Option instead; replace the placeholder with a real implementation or a meaningful error.",
        ),
        (
            r"\.\s*(?:unwrap|expect)\s*\(",
            BullshitKind::UnwrapAbuse,
            0.72,
            "unwrap or expect may panic at runtime.",
            "Propagate with ?, handle None/Err explicitly, or encode the invariant in the type.",
        ),
        (
            r"(?:==|!=)\s*(?:true|false)\b",
            BullshitKind::BoolComparison,
            0.68,
            "Comparing a boolean expression to a boolean literal can be redundant.",
            "Use the expression or its negation when both operands are booleans.",
        ),
        (
            r"\.\s*(?:to_string|to_owned)\s*\(\s*\)\s*\.\s*as_str\s*\(",
            BullshitKind::StringAntiPattern,
            0.74,
            "An owned string is immediately borrowed; check whether the allocation is necessary.",
            "Borrow an existing string or pass a &str directly when possible.",
        ),
        (
            r"\bfrom_utf8_lossy\s*\(",
            BullshitKind::LossyUtf8,
            0.70,
            "Lossy UTF-8 conversion replaces invalid bytes. Verify that loss is intentional.",
            "Use checked UTF-8 conversion or raw bytes when exact preservation is required.",
        ),
        (
            r"\bRefCell\s*<",
            BullshitKind::RefCellAbuse,
            0.60,
            "RefCell<T> defers borrow checking to runtime — a panic will occur if borrow rules are violated.",
            "Consider restructuring to use compile-time borrows, or Cell<T> for Copy types.",
        ),
    ];

    patterns
        .into_iter()
        .map(|(pattern, kind, confidence, why, suggestion)| {
            Ok(RegexRule {
                regex: Regex::new(pattern)?,
                kind,
                confidence,
                why,
                suggestion,
            })
        })
        .collect()
}

fn scan_regex_patterns(
    code: &str,
    file: &Path,
    locations: &LineIndex,
    alerts: &mut Vec<BullshitAlert>,
) -> Result<()> {
    static RULES: LazyLock<Result<Vec<RegexRule>, regex::Error>> =
        LazyLock::new(compile_regex_rules);
    let rules = RULES
        .as_ref()
        .map_err(|error| anyhow::anyhow!("invalid audit regex: {error}"))?;
    for rule in rules {
        for mat in rule.regex.find_iter(code) {
            alerts.push(make_alert(
                rule.kind,
                rule.confidence,
                file,
                code,
                locations,
                mat.start(),
                mat.end(),
                rule.why,
                rule.suggestion,
            ));
        }
    }
    Ok(())
}

fn scan_function_complexity(
    code: &str,
    file: &Path,
    locations: &LineIndex,
    functions: &[FunctionComplexity],
    alerts: &mut Vec<BullshitAlert>,
) {
    for function in functions.iter().filter(|function| function.score >= 6) {
        let confidence =
            (f32::from(u8::try_from(function.score).unwrap_or(u8::MAX)) / 24.0).clamp(0.66, 0.95);
        alerts.push(make_alert(
            BullshitKind::FakeComplexity, confidence, file, code, locations,
            function.start, function.start,
            &format!("Function syntactic decision score is {}; review whether its complexity is necessary.", function.score),
            "Split the function around decisions, loops, and side effects when it improves clarity.",
        ));
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "Diagnostic construction carries source location and explanatory text"
)]
fn make_alert(
    kind: BullshitKind,
    confidence: f32,
    file: &Path,
    code: &str,
    locations: &LineIndex,
    start: usize,
    end: usize,
    why_bs: &str,
    suggestion: &str,
) -> BullshitAlert {
    let (line, column) = locations.locate(start);
    BullshitAlert {
        kind,
        confidence,
        severity: confidence,
        file: file.to_path_buf(),
        line,
        column,
        context_snippet: snippet(code, start, end),
        why_bs: why_bs.to_string(),
        suggestion: suggestion.to_string(),
    }
}

// Byte columns remain accurate even when non-ASCII literal bytes have been masked.
struct LineIndex(Vec<usize>);

impl LineIndex {
    fn new(code: &str) -> Self {
        Self(
            std::iter::once(0)
                .chain(
                    code.bytes()
                        .enumerate()
                        .filter_map(|(offset, byte)| (byte == b'\n').then_some(offset + 1)),
                )
                .collect(),
        )
    }

    fn locate(&self, offset: usize) -> (usize, usize) {
        let line = self.0.partition_point(|start| *start <= offset);
        (line, offset - self.0[line - 1] + 1)
    }
}

fn snippet(code: &str, start: usize, end: usize) -> String {
    let line_start = code[..start].rfind('\n').map_or(0, |idx| idx + 1);
    let line_end = code[end..].find('\n').map_or(code.len(), |idx| end + idx);
    code[line_start..line_end].trim().to_string()
}

fn dedupe_alerts(alerts: &mut Vec<BullshitAlert>) {
    alerts.sort_by(|a, b| {
        a.file
            .cmp(&b.file)
            .then_with(|| a.line.cmp(&b.line))
            .then_with(|| a.column.cmp(&b.column))
            .then_with(|| a.kind.cmp(&b.kind))
    });
    alerts.dedup_by(|a, b| {
        a.file == b.file && a.line == b.line && a.column == b.column && a.kind == b.kind
    });
}

#[must_use = "Returns the display label for the finding"]
pub const fn kind_label(kind: BullshitKind) -> &'static str {
    kind.label()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> CodeAuditConfig {
        CodeAuditConfig::default()
    }

    #[test]
    fn detects_unwrap_and_sleep() {
        let code = r#"
fn main() {
    let value = thing().unwrap();
    std::thread::sleep(std::time::Duration::from_millis(10));
}
"#;
        let alerts = scan_code(code, "src/main.rs", &config()).unwrap();
        assert!(alerts.iter().any(|a| a.kind == BullshitKind::UnwrapAbuse));
        assert!(alerts.iter().any(|a| a.kind == BullshitKind::SleepAbuse));
    }

    #[test]
    fn detects_shared_mutable_state() {
        let code = "type Store = Arc<RwLock<HashMap<String, String>>>;";
        let alerts = scan_code(code, "src/lib.rs", &config()).unwrap();
        assert!(
            alerts
                .iter()
                .any(|a| a.kind == BullshitKind::OverEngineering)
        );
    }

    #[test]
    fn detects_fake_complexity() {
        let code = r#"
fn tangled(x: usize) -> usize {
    if x > 1 { if x > 2 { if x > 3 { if x > 4 { if x > 5 { return x; }}}}}
    match x { 0 => 1, 1 => 2, _ => 3 }
}
"#;
        let alerts = scan_code(code, "src/lib.rs", &config()).unwrap();
        assert!(
            alerts
                .iter()
                .any(|a| a.kind == BullshitKind::FakeComplexity)
        );
    }

    #[test]
    fn detects_multiline_panics_and_uses_byte_columns() -> Result<()> {
        let source = "fn f() { let x = \"ż\"; value .\n unwrap ( ); value.expect(\"msg\"); }";
        let findings = scan_code(source, "lib.rs", &config())?;
        let panic_findings: Vec<_> = findings
            .iter()
            .filter(|finding| finding.kind == BullshitKind::UnwrapAbuse)
            .collect();
        assert_eq!(panic_findings.len(), 2);
        assert_eq!(panic_findings[0].line, 1);
        assert_eq!(
            panic_findings[0].column,
            source.find(" .").context("fixture")? + 2
        );
        assert_eq!(panic_findings[1].line, 2);
        Ok(())
    }

    #[test]
    fn complexity_does_not_consume_bodyless_trait_methods_or_nested_functions() -> Result<()> {
        let source = r#"trait T { fn f(&self); }
pub const fn simple() {
    fn nested(x: u32) {
        if x > 1 {} if x > 2 {} if x > 3 {}
        if x > 4 {} if x > 5 {} if x > 6 {}
    }
}
pub const fn other(x: u32) {
    if x > 1 {} if x > 2 {} if x > 3 {}
    if x > 4 {} if x > 5 {} if x > 6 {}
}
"#;
        let findings = scan_code(source, "lib.rs", &config())?;
        let lines: Vec<_> = findings
            .iter()
            .filter(|finding| finding.kind == BullshitKind::FakeComplexity)
            .map(|finding| finding.line)
            .collect();
        assert_eq!(lines, vec![3, 8]);
        Ok(())
    }

    #[test]
    fn detects_discarded_statements_not_used_or_propagated_values() -> Result<()> {
        let source = r#"fn f() {
    let optional = call().ok();
    let _ = call()?;
    call()
        .ok();
    consume(call().ok());
}"#;
        let findings = scan_code(source, "lib.rs", &config())?;
        let lines: Vec<_> = findings
            .iter()
            .filter(|finding| finding.kind == BullshitKind::DiscardedError)
            .map(|finding| finding.line)
            .collect();
        assert_eq!(lines, vec![4]);
        Ok(())
    }

    #[test]
    fn ignores_patterns_in_strings_and_comments() {
        let code = r#"
fn main() {
    let text = "Arc<RwLock<HashMap<String, String>>> and thing().unwrap()";
    // std::thread::sleep(std::time::Duration::from_millis(10));
}
"#;
        let alerts = scan_code(code, "src/main.rs", &config()).unwrap();
        assert!(
            alerts.is_empty(),
            "strings/comments should not produce bullshit alerts: {alerts:?}"
        );
    }

    #[test]
    fn policy_suppresses_kind_and_path() {
        let mut cfg = config();
        cfg.ignore_kinds.insert(BullshitKind::UnwrapAbuse);
        let alerts = scan_code("fn main() { thing().unwrap(); }", "src/main.rs", &cfg).unwrap();
        assert!(alerts.is_empty());

        let mut cfg = config();
        cfg.ignore_paths.push("generated".to_string());
        let alerts = scan_code(
            "fn main() { thing().unwrap(); }",
            "src/generated/main.rs",
            &cfg,
        )
        .unwrap();
        assert!(alerts.is_empty());
    }

    #[test]
    fn includes_only_actual_test_items_when_requested() -> Result<()> {
        let source = r#"#[cfg(test)]
// comment between attribute and item
#[allow(dead_code)]
fn only_test() { value().unwrap(); }
#[cfg(any(test, feature = "enabled"))]
fn production_feature() { value().unwrap(); }
#[tokio::test]
async fn async_test() { value().unwrap(); }
fn production() { value().unwrap(); }
"#;
        let lines = |cfg: &CodeAuditConfig| -> Result<Vec<usize>> {
            Ok(scan_code(source, "src/lib.rs", cfg)?
                .iter()
                .filter(|alert| alert.kind == BullshitKind::UnwrapAbuse)
                .map(|alert| alert.line)
                .collect())
        };
        assert_eq!(lines(&config())?, vec![6, 9]);
        assert_eq!(
            lines(&CodeAuditConfig {
                include_tests: true,
                ..config()
            })?,
            vec![4, 6, 8, 9]
        );
        Ok(())
    }

    #[test]
    fn source_discovery_respects_cargo_targets_and_nested_packages() -> Result<()> {
        let tmp = tempfile::tempdir()?;
        let root = tmp.path();
        let manifest = root.join("Cargo.toml");
        fs::write(
            &manifest,
            r#"[package]
name = "audit-targets"
version = "0.1.0"
edition = "2024"
build = "custom/build.rs"

[lib]
path = "src/lib.rs"

[[bin]]
name = "custom"
path = "custom/main.rs"

[[test]]
name = "outside"
path = "custom/check.rs"
"#,
        )?;
        for directory in ["src", "custom", "tests", "target", "nested"] {
            fs::create_dir(root.join(directory))?;
        }
        fs::write(
            root.join("nested/Cargo.toml"),
            "[package]\nname = \"nested\"\nversion = \"0.1.0\"",
        )?;
        for file in [
            "src/lib.rs",
            "custom/main.rs",
            "custom/build.rs",
            "custom/check.rs",
            "tests/integration.rs",
            "target/generated.rs",
            "nested/other.rs",
        ] {
            fs::write(root.join(file), "fn f() { value().unwrap(); }")?;
        }
        let report = scan_project(Some(&manifest), &config())?;
        let names: BTreeSet<_> = report
            .alerts
            .iter()
            .map(|alert| alert.file.strip_prefix(root).map(Path::to_path_buf))
            .collect::<std::result::Result<_, _>>()?;
        assert_eq!(
            names,
            ["src/lib.rs", "custom/main.rs", "custom/build.rs"]
                .into_iter()
                .map(PathBuf::from)
                .collect()
        );
        assert_eq!(report.files_scanned, 3);
        let report = scan_project(
            Some(&manifest),
            &CodeAuditConfig {
                include_tests: true,
                ..config()
            },
        )?;
        assert_eq!(report.files_scanned, 5);
        Ok(())
    }

    #[test]
    fn oversized_source_is_not_silently_clean() -> Result<()> {
        let tmp = tempfile::tempdir()?;
        let manifest = tmp.path().join("Cargo.toml");
        fs::write(
            &manifest,
            "[package]\nname = \"large-source\"\nversion = \"0.1.0\"\n[lib]\npath = \"lib.rs\"",
        )?;
        fs::write(tmp.path().join("lib.rs"), "fn f() { value().unwrap(); }")?;
        let cfg = CodeAuditConfig {
            max_file_bytes: 8,
            ..config()
        };
        assert!(scan_project(Some(&manifest), &cfg).is_err());
        Ok(())
    }

    #[test]
    fn hardcoded_scan_uses_same_test_and_comment_exclusions() -> Result<()> {
        let tmp = tempfile::tempdir()?;
        let manifest = tmp.path().join("Cargo.toml");
        fs::write(
            &manifest,
            "[package]\nname = \"hardcoded-scope\"\nversion = \"0.1.0\"\n[lib]\npath = \"lib.rs\"",
        )?;
        fs::write(
            tmp.path().join("lib.rs"),
            r#"// let x = 99999;
#[cfg(test)]
fn test_only() { let x = 98765; }
fn production() { let x = 87654; }
"#,
        )?;
        let audit = scan_project_with_options(
            Some(&manifest),
            &config(),
            AuditOptions {
                hardcoded: true,
                ..AuditOptions::default()
            },
        )?;
        let hits = audit.hardcoded_values.context("hardcoded scan requested")?;
        assert_eq!(
            hits.iter()
                .map(|hit| hit.value.as_str())
                .collect::<Vec<_>>(),
            vec!["87654"]
        );
        Ok(())
    }

    #[test]
    fn parses_diff_changed_ranges() {
        let diff = r#"diff --git a/src/main.rs b/src/main.rs
index 111..222 100644
--- a/src/main.rs
+++ b/src/main.rs
@@ -1,0 +2,3 @@
+fn main() {
+    thing().unwrap();
+}
"#;
        let changed: Vec<_> = diff.lines().filter_map(parse_hunk_new_range).collect();
        assert_eq!(changed, vec![(2, 4)]);
    }
}
