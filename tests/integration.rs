//! Integration tests for cargo-anoint.
//!
//! Uses `assert_cmd` to run the binary and check stdout/exit codes.

use assert_cmd::Command;
use predicates::prelude::*;

fn cargo_anoint_cmd() -> Command {
    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("cargo-anoint"));
    cmd.arg("anoint");
    cmd
}

/// Running `cargo-anoint bless` in our own project should succeed and print
/// the version header plus a dependency summary.
#[test]
fn test_bless_reports_deps() {
    cargo_anoint_cmd()
        .assert()
        .success()
        .stdout(predicate::str::contains("cargo-anoint v"))
        .stdout(predicate::str::contains("Direct dependencies"))
        .stdout(predicate::str::contains("Found"));
}

/// Running with --help should print usage information.
#[test]
fn test_help_flag() {
    cargo_anoint_cmd()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("Anoint your dependencies"));
}

#[test]
fn test_planned_flags_remain_hidden_from_help() {
    cargo_anoint_cmd()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("--all-targets"))
        .stdout(predicate::str::contains("--llm").not());
}

#[test]
fn test_fail_on_unknown_level_exits_nonzero() {
    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("cargo-anoint"));
    cmd.arg("anoint").arg("--fail-on=bogus");
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("unknown --fail-on level"));
}

#[test]
fn test_fail_on_high_exits_nonzero_with_suggestions() {
    use std::fs;
    use tempfile::TempDir;

    let tmp = TempDir::new().expect("temp dir");
    let manifest = tmp.path().join("Cargo.toml");

    fs::write(
        &manifest,
        r#"[package]
name = "fail-on-high"
version = "0.1.0"
edition = "2021"

[dependencies]
lazy_static = "1"
"#,
    )
    .expect("write Cargo.toml");

    fs::create_dir_all(tmp.path().join("src")).expect("create src");
    fs::write(tmp.path().join("src/main.rs"), "fn main() {}").expect("write main.rs");

    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("cargo-anoint"));
    cmd.arg("anoint")
        .arg("--manifest-path")
        .arg(&manifest)
        .arg("--offline")
        .arg("--fail-on=high");
    cmd.assert().failure().stderr(predicate::str::contains(
        "exiting with non-zero status: at least one dependency suggestion matched --fail-on",
    ));
}

#[test]
fn test_policy_fail_on_gates_without_cli_flag() {
    use std::fs;
    use tempfile::TempDir;

    let tmp = TempDir::new().expect("temp dir");
    let manifest = tmp.path().join("Cargo.toml");
    let policy_path = tmp.path().join("anoint.toml");

    fs::write(
        &manifest,
        r#"[package]
name = "gate-test"
version = "0.1.0"
edition = "2021"

[dependencies]
lazy_static = "1"
"#,
    )
    .expect("write Cargo.toml");
    fs::create_dir_all(tmp.path().join("src")).expect("create src");
    fs::write(tmp.path().join("src/main.rs"), "fn main() {}").expect("write main.rs");

    fs::write(&policy_path, "fail_on = [\"high\"]\n").expect("write anoint.toml");

    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("cargo-anoint"));
    cmd.arg("anoint")
        .arg("--manifest-path")
        .arg(&manifest)
        .arg("--policy")
        .arg(&policy_path)
        .arg("--offline");

    cmd.assert().failure().stderr(predicate::str::contains(
        "exiting with non-zero status: at least one dependency suggestion matched --fail-on",
    ));
}

#[test]
fn test_json_update_rules_combination_exits_nonzero() {
    cargo_anoint_cmd()
        .arg("--json")
        .arg("--update-rules")
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "--json cannot be combined with --update-rules",
        ));
}

#[test]
fn test_feedback_prints_block() {
    cargo_anoint_cmd()
        .arg("--feedback")
        .assert()
        .success()
        .stdout(predicate::str::contains("cargo-anoint feedback block"))
        .stdout(predicate::str::contains("version:"))
        .stdout(predicate::str::contains("direct_deps:"))
        .stdout(predicate::str::contains("code_audit_findings:"))
        .stdout(predicate::str::contains("top_hotspots:"));
}

#[test]
fn test_explicit_missing_policy_exits_nonzero() {
    cargo_anoint_cmd()
        .arg("--policy")
        .arg("missing-anoint.toml")
        .assert()
        .failure()
        .stderr(predicate::str::contains("missing-anoint.toml"));
}

#[test]
fn test_invalid_default_policy_exits_nonzero() {
    use std::fs;
    use tempfile::TempDir;

    let tmp = TempDir::new().expect("temp dir");
    let manifest = tmp.path().join("Cargo.toml");
    fs::write(
        &manifest,
        r#"[package]
name = "invalid-policy"
version = "0.1.0"
edition = "2021"

[dependencies]
"#,
    )
    .expect("write Cargo.toml");
    fs::create_dir_all(tmp.path().join("src")).expect("create src");
    fs::write(tmp.path().join("src/main.rs"), "fn main() {}\n").expect("write main.rs");
    fs::write(tmp.path().join("anoint.toml"), "not valid toml =").expect("write anoint.toml");

    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("cargo-anoint"));
    cmd.arg("anoint")
        .arg("--manifest-path")
        .arg(&manifest)
        .arg("--offline");
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("TOML"));
}

// ── Real-world project tests ────────────────────────────────────────

/// End-to-end test: create a temp Rust project with known outdated deps,
/// run cargo-anoint, and verify it detects them all.
#[test]
fn test_real_project_with_outdated_deps() {
    use std::fs;
    use tempfile::TempDir;

    let tmp = TempDir::new().expect("temp dir");
    let manifest = tmp.path().join("Cargo.toml");

    // Write a Cargo.toml with deps we know our rules catch
    fs::write(
        &manifest,
        r#"[package]
name = "test-outdated"
version = "0.1.0"
edition = "2021"

[dependencies]
lazy_static = "1"
structopt = "0.3"
memmap = "0.7"
"#,
    )
    .expect("write Cargo.toml");

    // Create minimal src so cargo metadata works
    fs::create_dir_all(tmp.path().join("src")).expect("create src");
    fs::write(tmp.path().join("src/main.rs"), "fn main() {}").expect("write main.rs");

    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("cargo-anoint"));
    cmd.arg("anoint")
        .arg("--manifest-path")
        .arg(&manifest)
        .arg("--offline"); // skip network for determinism

    let output = cmd.output().expect("run cargo-anoint");
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(
        output.status.success(),
        "cargo-anoint should exit 0: {}",
        stdout
    );
    assert!(stdout.contains("lazy_static"), "should detect lazy_static");
    assert!(stdout.contains("structopt"), "should detect structopt");
    assert!(stdout.contains("memmap"), "should detect memmap");
}

/// Recommendations must never modify the manifest or offer automatic migration.
#[test]
fn test_scan_outdated_project_is_read_only() {
    use std::fs;
    use tempfile::TempDir;

    let tmp = TempDir::new().expect("temp dir");
    let manifest = tmp.path().join("Cargo.toml");

    fs::write(
        &manifest,
        r#"[package]
name = "test-fixable"
version = "0.1.0"
edition = "2021"

[dependencies]
reqwest = { path = "crates/reqwest" }
serde_json = { path = "crates/serde_json" }
serde = { path = "crates/serde" }
serde_derive = { path = "crates/serde_derive" }
"#,
    )
    .expect("write Cargo.toml");

    fs::create_dir_all(tmp.path().join("src")).expect("create src");
    fs::write(tmp.path().join("src/main.rs"), "fn main() {}").expect("write main.rs");
    for (name, extra) in [
        ("reqwest", "[features]\njson = []\n"),
        ("serde", "[features]\nderive = []\n"),
        ("serde_json", ""),
        ("serde_derive", ""),
    ] {
        let crate_dir = tmp.path().join("crates").join(name);
        fs::create_dir_all(crate_dir.join("src")).expect("create path crate src");
        fs::write(crate_dir.join("src/lib.rs"), "").expect("write path crate lib");
        fs::write(
            crate_dir.join("Cargo.toml"),
            format!(
                "[package]\nname = \"{name}\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n{extra}"
            ),
        )
        .expect("write path crate manifest");
    }

    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("cargo-anoint"));
    cmd.arg("anoint")
        .arg("--manifest-path")
        .arg(&manifest)
        .arg("--offline");

    let original = fs::read_to_string(&manifest).expect("read original manifest");
    let output = cmd.output().expect("run cargo-anoint");
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(output.status.success(), "should exit 0: {}", stdout);
    assert_eq!(
        fs::read_to_string(&manifest).expect("read manifest after scan"),
        original
    );
    assert!(
        !stdout.contains("--fix"),
        "unsafe automatic edits must not be offered"
    );
    assert!(
        !stdout.contains("reqwest+serde_json"),
        "JSON helpers do not replace serde_json"
    );
    assert!(
        stdout.contains("serde_derive"),
        "should list serde_derive for feature optimization"
    );
    assert!(!manifest.with_extension("toml.bak").exists());
}

#[test]
fn test_bless_skips_code_audit_by_default() {
    use std::fs;
    use tempfile::TempDir;

    let tmp = TempDir::new().expect("temp dir");
    let manifest = tmp.path().join("Cargo.toml");

    fs::write(
        &manifest,
        r#"[package]
name = "test-bs"
version = "0.1.0"
edition = "2021"

[dependencies]
"#,
    )
    .expect("write Cargo.toml");

    fs::create_dir_all(tmp.path().join("src")).expect("create src");
    fs::write(
        tmp.path().join("src/main.rs"),
        r#"fn main() {
    let value = std::env::var("NOPE").unwrap();
    std::thread::sleep(std::time::Duration::from_millis(10));
    println!("{}", value);
}
"#,
    )
    .expect("write main.rs");

    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("cargo-anoint"));
    cmd.arg("anoint")
        .arg("--manifest-path")
        .arg(&manifest)
        .arg("--offline");

    let output = cmd.output().expect("run cargo-anoint");
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(output.status.success(), "should exit 0: {}", stdout);
    assert!(!stdout.contains("Bullshit detector code audit"));
    assert!(!stdout.contains("unwrap abuse"));
    assert!(!stdout.contains("sleep abuse"));
}

#[test]
fn test_audit_code_flag_runs_code_audit() {
    use std::fs;
    use tempfile::TempDir;

    let tmp = TempDir::new().expect("temp dir");
    let manifest = tmp.path().join("Cargo.toml");

    fs::write(
        &manifest,
        r#"[package]
name = "test-audit-code"
version = "0.1.0"
edition = "2021"

[dependencies]
"#,
    )
    .expect("write Cargo.toml");

    fs::create_dir_all(tmp.path().join("src")).expect("create src");
    fs::write(
        tmp.path().join("src/main.rs"),
        r#"fn main() {
    let value = std::env::var("NOPE").unwrap();
    std::thread::sleep(std::time::Duration::from_millis(10));
    println!("{}", value);
}
"#,
    )
    .expect("write main.rs");

    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("cargo-anoint"));
    cmd.arg("anoint")
        .arg("--manifest-path")
        .arg(&manifest)
        .arg("--offline")
        .arg("--audit-code");

    let output = cmd.output().expect("run cargo-anoint");
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(output.status.success(), "should exit 0: {}", stdout);
    assert!(stdout.contains("Bullshit detector code audit"));
    assert!(stdout.contains("unwrap abuse"));
    assert!(stdout.contains("sleep abuse"));
}

#[test]
fn test_no_audit_code_remains_accepted_as_noop() {
    let output = cargo_anoint_cmd()
        .arg("--offline")
        .arg("--no-audit-code")
        .output()
        .expect("run cargo-anoint");
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(output.status.success(), "should exit 0: {}", stdout);
    assert!(!stdout.contains("Bullshit detector code audit"));
}

#[test]
fn test_direct_bs_subcommand_runs_code_audit_only() {
    use std::fs;
    use tempfile::TempDir;

    let tmp = TempDir::new().expect("temp dir");
    let manifest = tmp.path().join("Cargo.toml");

    fs::write(
        &manifest,
        r#"[package]
name = "test-bs-only"
version = "0.1.0"
edition = "2021"

[dependencies]
"#,
    )
    .expect("write Cargo.toml");

    fs::create_dir_all(tmp.path().join("src")).expect("create src");
    fs::write(
        tmp.path().join("src/lib.rs"),
        "pub fn bad() { thing().unwrap(); }\n",
    )
    .expect("write lib.rs");

    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("cargo-anoint"));
    cmd.arg("bs").arg("--manifest-path").arg(&manifest);

    let output = cmd.output().expect("run cargo-anoint bs");
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(output.status.success(), "should exit 0: {}", stdout);
    assert!(stdout.contains("Bullshit detector code audit"));
    assert!(stdout.contains("unwrap abuse"));
    assert!(!stdout.contains("Direct dependencies"));
}

#[test]
fn test_cargo_style_bs_subcommand_runs_code_audit_only() {
    use std::fs;
    use tempfile::TempDir;

    let tmp = TempDir::new().expect("temp dir");
    let manifest = tmp.path().join("Cargo.toml");

    fs::write(
        &manifest,
        r#"[package]
name = "test-cargo-style-bs"
version = "0.1.0"
edition = "2021"

[dependencies]
"#,
    )
    .expect("write Cargo.toml");

    fs::create_dir_all(tmp.path().join("src")).expect("create src");
    fs::write(
        tmp.path().join("src/lib.rs"),
        "pub fn bad() { thing().unwrap(); }\n",
    )
    .expect("write lib.rs");

    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("cargo-anoint"));
    cmd.arg("anoint")
        .arg("bs")
        .arg("--manifest-path")
        .arg(&manifest);

    let output = cmd.output().expect("run cargo-anoint bless bs");
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(output.status.success(), "should exit 0: {}", stdout);
    assert!(stdout.contains("Bullshit detector code audit"));
    assert!(stdout.contains("unwrap abuse"));
    assert!(!stdout.contains("Direct dependencies"));
}

#[test]
fn test_summary_prints_heading_and_counts() {
    use std::fs;
    use tempfile::TempDir;

    let tmp = TempDir::new().expect("temp dir");
    let manifest = tmp.path().join("Cargo.toml");

    fs::write(
        &manifest,
        r#"[package]
name = "summary-test"
version = "0.1.0"
edition = "2021"

[dependencies]
lazy_static = "1"
"#,
    )
    .expect("write Cargo.toml");

    fs::create_dir_all(tmp.path().join("src")).expect("create src");
    fs::write(tmp.path().join("src/main.rs"), "fn main() {}\n").expect("write main.rs");

    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("cargo-anoint"));
    cmd.arg("anoint")
        .arg("--manifest-path")
        .arg(&manifest)
        .arg("--offline")
        .arg("--summary");

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Summary"))
        .stdout(predicate::str::contains("Suggestions after policy"));
}

#[test]
fn test_workspace_flag_lists_members_and_lazy_static_hit() {
    use std::fs;
    use tempfile::TempDir;

    let tmp = TempDir::new().expect("temp dir");

    fs::write(
        tmp.path().join("Cargo.toml"),
        r#"[workspace]
members = ["crates/alpha", "crates/bravo"]
resolver = "2"
"#,
    )
    .expect("write workspace Cargo.toml");

    for (rel, deps) in [
        (
            "crates/alpha",
            r#"lazy_static = "1"

"#,
        ),
        ("crates/bravo", ""),
    ] {
        let dir = tmp.path().join(rel);
        fs::create_dir_all(dir.join("src")).expect("create pkg src");
        fs::write(
            dir.join("Cargo.toml"),
            format!(
                r#"[package]
name = "{}"
version = "0.1.0"
edition = "2021"

[dependencies]
{deps}"#,
                rel.trim_start_matches("crates/"),
                deps = deps,
            ),
        )
        .expect("write member Cargo.toml");
        fs::write(dir.join("src/lib.rs"), "").expect("write lib.rs");
    }

    let root_manifest = tmp.path().join("Cargo.toml");
    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("cargo-anoint"));
    cmd.arg("anoint")
        .arg("--manifest-path")
        .arg(&root_manifest)
        .arg("--workspace")
        .arg("--offline");

    cmd.assert().success().stdout(
        predicate::str::contains("Workspace: 2 members")
            .and(predicate::str::contains("lazy_static")),
    );
}

#[test]
fn test_json_contains_dependency_section_and_null_code_audit_by_default() {
    use std::fs;
    use tempfile::TempDir;

    let tmp = TempDir::new().expect("temp dir");
    let manifest = tmp.path().join("Cargo.toml");

    fs::write(
        &manifest,
        r#"[package]
name = "test-json"
version = "0.1.0"
edition = "2021"

[dependencies]
lazy_static = "1"
"#,
    )
    .expect("write Cargo.toml");

    fs::create_dir_all(tmp.path().join("src")).expect("create src");
    fs::write(
        tmp.path().join("src/main.rs"),
        "fn main() { thing().unwrap(); }\n",
    )
    .expect("write main.rs");

    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("cargo-anoint"));
    cmd.arg("anoint")
        .arg("--manifest-path")
        .arg(&manifest)
        .arg("--offline")
        .arg("--json");

    let output = cmd.output().expect("run cargo-anoint json");
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(output.status.success(), "should exit 0: {}", stdout);
    assert!(stdout.contains("\"cargo_anoint_version\""));
    assert!(stdout.contains("\"workspace_scan\""));
    assert!(stdout.contains("\"packages\""));
    assert!(stdout.contains("\"dependency_suggestions\""));
    assert!(stdout.contains("\"code_audit\": null"));
    assert!(stdout.contains("lazy_static"));
    assert!(!stdout.contains("UnwrapAbuse"));
}

#[test]
fn test_json_with_audit_code_contains_code_audit_section() {
    use std::fs;
    use tempfile::TempDir;

    let tmp = TempDir::new().expect("temp dir");
    let manifest = tmp.path().join("Cargo.toml");

    fs::write(
        &manifest,
        r#"[package]
name = "test-json-audit"
version = "0.1.0"
edition = "2021"

[dependencies]
lazy_static = "1"
"#,
    )
    .expect("write Cargo.toml");

    fs::create_dir_all(tmp.path().join("src")).expect("create src");
    fs::write(
        tmp.path().join("src/main.rs"),
        "fn main() { thing().unwrap(); }\n",
    )
    .expect("write main.rs");

    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("cargo-anoint"));
    cmd.arg("anoint")
        .arg("--manifest-path")
        .arg(&manifest)
        .arg("--offline")
        .arg("--json")
        .arg("--audit-code");

    let output = cmd.output().expect("run cargo-anoint json");
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(output.status.success(), "should exit 0: {}", stdout);
    assert!(stdout.contains("\"cargo_anoint_version\""));
    assert!(stdout.contains("\"packages\""));
    assert!(stdout.contains("\"dependency_suggestions\""));
    assert!(stdout.contains("\"code_audit\""));
    assert!(stdout.contains("lazy_static"));
    assert!(stdout.contains("UnwrapAbuse"));
}

#[test]
fn test_code_audit_summary_hides_extra_findings_without_verbose() {
    use std::fs;
    use tempfile::TempDir;

    let tmp = TempDir::new().expect("temp dir");
    let manifest = tmp.path().join("Cargo.toml");
    fs::write(
        &manifest,
        r#"[package]
name = "test-summary"
version = "0.1.0"
edition = "2021"

[dependencies]
"#,
    )
    .expect("write Cargo.toml");
    fs::create_dir_all(tmp.path().join("src")).expect("create src");
    fs::write(
        tmp.path().join("src/main.rs"),
        "fn main() {\nthing().unwrap();\nthing().unwrap();\nthing().unwrap();\nthing().unwrap();\nthing().unwrap();\nthing().unwrap();\n}\n",
    )
    .expect("write main.rs");

    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("cargo-anoint"));
    cmd.arg("bs").arg("--manifest-path").arg(&manifest);
    let output = cmd.output().expect("run cargo-anoint bs");
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(output.status.success(), "should exit 0: {}", stdout);
    assert!(stdout.contains("Showing top 5"));

    let mut verbose = Command::new(assert_cmd::cargo::cargo_bin!("cargo-anoint"));
    verbose
        .arg("bs")
        .arg("--manifest-path")
        .arg(&manifest)
        .arg("--verbose");
    let output = verbose.output().expect("run cargo-anoint bs --verbose");
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(output.status.success(), "should exit 0: {}", stdout);
    assert!(!stdout.contains("Showing top 5"));
}

#[test]
fn test_code_audit_policy_suppresses_findings() {
    use std::fs;
    use tempfile::TempDir;

    let tmp = TempDir::new().expect("temp dir");
    let manifest = tmp.path().join("Cargo.toml");
    let policy = tmp.path().join("anoint.toml");
    fs::write(
        &manifest,
        r#"[package]
name = "test-policy"
version = "0.1.0"
edition = "2021"

[dependencies]
"#,
    )
    .expect("write Cargo.toml");
    fs::write(
        &policy,
        r#"[code_audit]
ignore_kinds = ["UnwrapAbuse"]
"#,
    )
    .expect("write anoint.toml");
    fs::create_dir_all(tmp.path().join("src")).expect("create src");
    fs::write(
        tmp.path().join("src/main.rs"),
        "fn main() { thing().unwrap(); }\n",
    )
    .expect("write main.rs");

    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("cargo-anoint"));
    cmd.arg("bs")
        .arg("--manifest-path")
        .arg(&manifest)
        .arg("--policy")
        .arg(&policy);
    let output = cmd.output().expect("run cargo-anoint bs");
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(output.status.success(), "should exit 0: {}", stdout);
    assert!(stdout.contains("No bullshit detected"));
}

#[test]
fn test_bs_diff_only_reports_changed_lines() {
    use std::fs;
    use std::process::Command as StdCommand;
    use tempfile::TempDir;

    let tmp = TempDir::new().expect("temp dir");
    let manifest = tmp.path().join("Cargo.toml");
    let src = tmp.path().join("src/main.rs");

    fs::write(
        &manifest,
        r#"[package]
name = "test-diff"
version = "0.1.0"
edition = "2021"

[dependencies]
"#,
    )
    .expect("write Cargo.toml");
    fs::create_dir_all(tmp.path().join("src")).expect("create src");
    fs::write(&src, "fn main() {\n    println!(\"clean\");\n}\n").expect("write main.rs");

    assert!(
        StdCommand::new("git")
            .arg("init")
            .current_dir(tmp.path())
            .status()
            .expect("git init")
            .success()
    );
    assert!(
        StdCommand::new("git")
            .args(["add", "."])
            .current_dir(tmp.path())
            .status()
            .expect("git add")
            .success()
    );
    assert!(
        StdCommand::new("git")
            .args([
                "-c",
                "user.name=Test",
                "-c",
                "user.email=test@example.com",
                "-c",
                "commit.gpgsign=false",
                "commit",
                "-m",
                "initial",
            ])
            .current_dir(tmp.path())
            .status()
            .expect("git commit")
            .success()
    );

    fs::write(
        &src,
        "fn main() {\n    println!(\"clean\");\n    thing().unwrap();\n}\n",
    )
    .expect("modify main.rs");

    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("cargo-anoint"));
    cmd.arg("bs")
        .arg("--manifest-path")
        .arg(&manifest)
        .arg("--diff");
    let output = cmd.output().expect("run cargo-anoint bs --diff");
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(output.status.success(), "should exit 0: {}", stdout);
    assert!(stdout.contains("unwrap abuse"));
}

#[test]
fn test_package_flag_filters_workspace_member() {
    use std::fs;
    use tempfile::TempDir;

    let tmp = TempDir::new().expect("temp dir");

    fs::write(
        tmp.path().join("Cargo.toml"),
        r#"[workspace]
members = ["alpha", "bravo"]
resolver = "2"
"#,
    )
    .expect("write root Cargo.toml");

    // alpha has lazy_static (should trigger a suggestion)
    let alpha = tmp.path().join("alpha");
    fs::create_dir_all(alpha.join("src")).expect("create alpha/src");
    fs::write(
        alpha.join("Cargo.toml"),
        r#"[package]
name = "alpha"
version = "0.1.0"
edition = "2021"

[dependencies]
lazy_static = "1"
"#,
    )
    .expect("write alpha Cargo.toml");
    fs::write(alpha.join("src/lib.rs"), "").expect("write alpha lib.rs");

    // bravo has no outdated deps
    let bravo = tmp.path().join("bravo");
    fs::create_dir_all(bravo.join("src")).expect("create bravo/src");
    fs::write(
        bravo.join("Cargo.toml"),
        r#"[package]
name = "bravo"
version = "0.1.0"
edition = "2021"

[dependencies]
"#,
    )
    .expect("write bravo Cargo.toml");
    fs::write(bravo.join("src/lib.rs"), "").expect("write bravo lib.rs");

    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("cargo-anoint"));
    cmd.arg("anoint")
        .arg("--manifest-path")
        .arg(tmp.path().join("Cargo.toml"))
        .arg("--package=alpha")
        .arg("--offline");

    let output = cmd.output().expect("run cargo-anoint --package alpha");
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(output.status.success(), "should exit 0: {}", stdout);
    assert!(
        stdout.contains("lazy_static"),
        "alpha's lazy_static should appear: {}",
        stdout
    );
}

#[test]
fn test_explicit_policy_flag_suppresses_suggestion() {
    use std::fs;
    use tempfile::TempDir;

    let tmp = TempDir::new().expect("temp dir");
    let manifest = tmp.path().join("Cargo.toml");
    let policy_path = tmp.path().join("anoint.toml");

    fs::write(
        &manifest,
        r#"[package]
name = "policy-test"
version = "0.1.0"
edition = "2021"

[dependencies]
lazy_static = "1"
"#,
    )
    .expect("write Cargo.toml");

    fs::create_dir_all(tmp.path().join("src")).expect("create src");
    fs::write(tmp.path().join("src/main.rs"), "fn main() {}").expect("write main.rs");

    fs::write(
        &policy_path,
        r#"ignore_packages = ["lazy_static"]
"#,
    )
    .expect("write anoint.toml");

    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("cargo-anoint"));
    cmd.arg("anoint")
        .arg("--manifest-path")
        .arg(&manifest)
        .arg("--policy")
        .arg(&policy_path)
        .arg("--offline");

    let output = cmd.output().expect("run cargo-anoint --policy");
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(
        output.status.success(),
        "should exit 0 even when suggestions exist: {}",
        stdout
    );
    assert!(
        stdout.contains("already blessed"),
        "policy should suppress the lazy_static suggestion: {}",
        stdout
    );
}

#[test]
fn test_bs_hardcoded_flag_reports_hardcoded_values() {
    use std::fs;
    use tempfile::TempDir;

    let tmp = TempDir::new().expect("temp dir");
    let manifest = tmp.path().join("Cargo.toml");

    fs::write(
        &manifest,
        r#"[package]
name = "hardcoded-test"
version = "0.1.0"
edition = "2021"

[dependencies]
"#,
    )
    .expect("write Cargo.toml");

    fs::create_dir_all(tmp.path().join("src")).expect("create src");
    fs::write(
        tmp.path().join("src/main.rs"),
        "fn main() { let ip = \"192.168.1.100\"; let _ = ip; }\n",
    )
    .expect("write main.rs");

    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("cargo-anoint"));
    cmd.arg("bs")
        .arg("--manifest-path")
        .arg(&manifest)
        .arg("--hardcoded");

    let output = cmd.output().expect("run cargo-anoint bs --hardcoded");
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(output.status.success(), "should exit 0: {}", stdout);
    assert!(
        stdout.contains("192.168.1.100"),
        "hardcoded IP should be detected: {}",
        stdout
    );
}

#[test]
fn test_bs_sarif_flag_outputs_valid_sarif() {
    use std::fs;
    use tempfile::TempDir;

    let tmp = TempDir::new().expect("temp dir");
    let manifest = tmp.path().join("Cargo.toml");

    fs::write(
        &manifest,
        r#"[package]
name = "sarif-test"
version = "0.1.0"
edition = "2021"

[dependencies]
"#,
    )
    .expect("write Cargo.toml");

    fs::create_dir_all(tmp.path().join("src")).expect("create src");
    fs::write(
        tmp.path().join("src/main.rs"),
        "fn main() { let x: Option<u32> = None; let _ = x.unwrap(); }\n",
    )
    .expect("write main.rs");

    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("cargo-anoint"));
    cmd.arg("bs")
        .arg("--manifest-path")
        .arg(&manifest)
        .arg("--sarif");

    let output = cmd.output().expect("run cargo-anoint bs --sarif");
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(output.status.success(), "should exit 0: {}", stdout);

    let sarif: serde_json::Value =
        serde_json::from_str(&stdout).expect("--sarif output must be valid JSON");

    assert_eq!(
        sarif["version"].as_str().unwrap_or(""),
        "2.1.0",
        "SARIF version must be 2.1.0"
    );
    assert!(
        sarif["runs"].is_array(),
        "SARIF must have a 'runs' array: {}",
        stdout
    );
    let driver_name = &sarif["runs"][0]["tool"]["driver"]["name"];
    assert_eq!(
        driver_name.as_str().unwrap_or(""),
        "cargo-anoint",
        "driver name must be cargo-anoint"
    );
}

#[test]
fn test_bs_min_confidence_in_policy_suppresses_low_confidence_findings() {
    use std::fs;
    use tempfile::TempDir;

    let tmp = TempDir::new().expect("temp dir");
    let manifest = tmp.path().join("Cargo.toml");

    fs::write(
        &manifest,
        r#"[package]
name = "min-conf-test"
version = "0.1.0"
edition = "2021"

[dependencies]
"#,
    )
    .expect("write Cargo.toml");

    fs::create_dir_all(tmp.path().join("src")).expect("create src");
    // unwrap() triggers UnwrapAbuse at ~0.80 confidence; setting threshold to 0.99 should suppress it
    fs::write(
        tmp.path().join("src/main.rs"),
        "fn main() { let x: Option<u32> = None; let _ = x.unwrap(); }\n",
    )
    .expect("write main.rs");

    let policy_path = tmp.path().join("anoint.toml");
    fs::write(&policy_path, "[settings]\nmin_confidence = 0.99\n").expect("write anoint.toml");

    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("cargo-anoint"));
    cmd.arg("bs")
        .arg("--manifest-path")
        .arg(&manifest)
        .arg("--policy")
        .arg(&policy_path);

    let output = cmd
        .output()
        .expect("run cargo-anoint bs with min_confidence policy");
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(output.status.success(), "should exit 0: {}", stdout);
    assert!(
        !stdout.contains("UnwrapAbuse") && !stdout.contains("unwrap"),
        "high threshold should suppress unwrap findings: {}",
        stdout
    );
}

#[test]
fn test_bs_fail_on_confidence_exits_nonzero_when_findings_present() {
    use std::fs;
    use tempfile::TempDir;

    let tmp = TempDir::new().expect("temp dir");
    let manifest = tmp.path().join("Cargo.toml");

    fs::write(
        &manifest,
        r#"[package]
name = "fail-conf-test"
version = "0.1.0"
edition = "2021"

[dependencies]
"#,
    )
    .expect("write Cargo.toml");

    fs::create_dir_all(tmp.path().join("src")).expect("create src");
    fs::write(
        tmp.path().join("src/main.rs"),
        "fn main() { let x: Option<u32> = None; let _ = x.unwrap(); }\n",
    )
    .expect("write main.rs");

    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("cargo-anoint"));
    cmd.arg("bs")
        .arg("--manifest-path")
        .arg(&manifest)
        .arg("--fail-on-confidence")
        .arg("0.5");

    let output = cmd
        .output()
        .expect("run cargo-anoint bs --fail-on-confidence");
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        !output.status.success(),
        "should exit non-zero when findings meet confidence threshold"
    );
    assert!(
        stderr.contains("exiting with non-zero status"),
        "stderr should mention exit reason: {}",
        stderr
    );
}

#[test]
fn test_init_ci_creates_workflow_file() {
    use std::fs;
    use tempfile::TempDir;

    let tmp = TempDir::new().expect("temp dir");
    let manifest = tmp.path().join("Cargo.toml");

    fs::write(
        &manifest,
        r#"[package]
name = "init-ci-test"
version = "0.1.0"
edition = "2021"

[dependencies]
"#,
    )
    .expect("write Cargo.toml");

    // First run — should create the file
    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("cargo-anoint"));
    cmd.arg("anoint")
        .arg("--manifest-path")
        .arg(&manifest)
        .arg("--init-ci");

    let output = cmd.output().expect("run cargo anoint --init-ci");
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(
        output.status.success(),
        "first run should exit 0: {}",
        stdout
    );

    let workflow_path = tmp
        .path()
        .join(".github")
        .join("workflows")
        .join("anoint.yml");
    assert!(
        workflow_path.exists(),
        ".github/workflows/anoint.yml should be created"
    );

    let contents = fs::read_to_string(&workflow_path).expect("read workflow file");
    assert!(
        contents.contains("upload-sarif"),
        "workflow should include SARIF upload step"
    );
    assert!(
        contents.contains("--fail-on-overlap"),
        "workflow should include --fail-on-overlap"
    );
    assert!(
        contents.contains("rust-cache"),
        "workflow should include Rust dependency caching"
    );

    // Second run — should fail because file already exists
    let mut cmd2 = Command::new(assert_cmd::cargo::cargo_bin!("cargo-anoint"));
    cmd2.arg("anoint")
        .arg("--manifest-path")
        .arg(&manifest)
        .arg("--init-ci");

    let output2 = cmd2.output().expect("run cargo anoint --init-ci again");
    assert!(
        !output2.status.success(),
        "second run should exit non-zero (file already exists)"
    );
    let stderr2 = String::from_utf8_lossy(&output2.stderr);
    assert!(
        stderr2.contains("already exists"),
        "error should mention file already exists: {}",
        stderr2
    );
}

#[test]
fn test_explain_flag_shows_rule_details() {
    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("cargo-anoint"));
    cmd.arg("anoint").arg("--explain").arg("lazy_static");

    let output = cmd
        .output()
        .expect("run cargo anoint --explain lazy_static");
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(output.status.success(), "should exit 0: {}", stdout);
    assert!(
        stdout.contains("LazyLock"),
        "should mention the replacement: {}",
        stdout
    );
    assert!(
        stdout.contains("StdReplacement"),
        "should show the kind: {}",
        stdout
    );
}

#[test]
fn test_explain_flag_unknown_pattern_exits_nonzero() {
    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("cargo-anoint"));
    cmd.arg("anoint")
        .arg("--explain")
        .arg("this_crate_does_not_exist_xyz");

    let output = cmd.output().expect("run cargo anoint --explain unknown");
    assert!(
        !output.status.success(),
        "unknown pattern should exit non-zero"
    );
}

#[test]
fn test_bs_rejects_panic_preserving_autofix() -> anyhow::Result<()> {
    let tmp = tempfile::TempDir::new()?;
    let src = tmp.path().join("main.rs");
    let original = "fn main() { let _ = None::<u32>.unwrap(); }";
    std::fs::write(&src, original)?;
    for command in ["bs", "anoint"] {
        for flag in ["--fix", "--dry-run"] {
            Command::new(assert_cmd::cargo::cargo_bin!("cargo-anoint"))
                .current_dir(tmp.path())
                .args([command, flag])
                .assert()
                .failure();
        }
    }
    assert_eq!(std::fs::read_to_string(&src)?, original);
    assert!(!src.with_extension("rs.bak").exists());
    Ok(())
}

#[test]
fn test_bs_detects_bool_comparison() {
    use std::fs;
    use tempfile::TempDir;

    let tmp = TempDir::new().expect("temp dir");
    let manifest = tmp.path().join("Cargo.toml");

    fs::write(
        &manifest,
        r#"[package]
name = "bool-cmp-test"
version = "0.1.0"
edition = "2021"

[dependencies]
"#,
    )
    .expect("write Cargo.toml");

    fs::create_dir_all(tmp.path().join("src")).expect("create src");
    fs::write(
        tmp.path().join("src/main.rs"),
        "fn main() { let x = true; if x == true { println!(\"yes\"); } }\n",
    )
    .expect("write main.rs");

    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("cargo-anoint"));
    cmd.arg("bs").arg("--manifest-path").arg(&manifest);

    let output = cmd.output().expect("run cargo-anoint bs");
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(output.status.success(), "should exit 0: {}", stdout);
    assert!(
        stdout.contains("redundant bool"),
        "should flag redundant bool comparison: {}",
        stdout
    );
}

#[test]
fn test_bs_detects_string_anti_pattern() {
    use std::fs;
    use tempfile::TempDir;

    let tmp = TempDir::new().expect("temp dir");
    let manifest = tmp.path().join("Cargo.toml");

    fs::write(
        &manifest,
        r#"[package]
name = "string-ap-test"
version = "0.1.0"
edition = "2021"

[dependencies]
"#,
    )
    .expect("write Cargo.toml");

    fs::create_dir_all(tmp.path().join("src")).expect("create src");
    fs::write(
        tmp.path().join("src/main.rs"),
        "fn takes_str(s: &str) { println!(\"{s}\"); }\nfn main() { let x = 42u32; takes_str(x.to_string().as_str()); }\n",
    )
    .expect("write main.rs");

    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("cargo-anoint"));
    cmd.arg("bs").arg("--manifest-path").arg(&manifest);

    let output = cmd.output().expect("run cargo-anoint bs");
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(output.status.success(), "should exit 0: {}", stdout);
    assert!(
        stdout.contains("string anti-pattern"),
        "should flag .to_string().as_str() anti-pattern: {}",
        stdout
    );
}

#[test]
fn test_explain_openssl_rule() {
    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("cargo-anoint"));
    cmd.arg("anoint").arg("--explain").arg("openssl");

    let output = cmd.output().expect("run cargo anoint --explain openssl");
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(output.status.success(), "should exit 0: {}", stdout);
    assert!(
        stdout.contains("btls-fast"),
        "should mention btls-fast as replacement: {}",
        stdout
    );
    assert!(
        stdout.contains("ModernAlternative"),
        "should show ModernAlternative kind: {}",
        stdout
    );
}

#[test]
fn test_simple_logger_rule_fires() {
    use std::fs;
    use tempfile::TempDir;

    let tmp = TempDir::new().expect("temp dir");
    let manifest = tmp.path().join("Cargo.toml");

    fs::write(
        &manifest,
        r#"[package]
name = "simple-logger-test"
version = "0.1.0"
edition = "2021"

[dependencies]
simple_logger = "4"
"#,
    )
    .expect("write Cargo.toml");

    fs::create_dir_all(tmp.path().join("src")).expect("create src");
    fs::write(tmp.path().join("src/main.rs"), "fn main() {}\n").expect("write main.rs");

    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("cargo-anoint"));
    cmd.arg("anoint")
        .arg("--manifest-path")
        .arg(&manifest)
        .arg("--offline");

    let output = cmd.output().expect("run cargo-anoint");
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(output.status.success(), "should exit 0: {}", stdout);
    assert!(
        stdout.contains("simple_logger"),
        "should flag simple_logger: {}",
        stdout
    );
    assert!(
        stdout.contains("tracing"),
        "should suggest tracing: {}",
        stdout
    );
}

#[test]
fn test_bs_detects_discarded_error_ok_statement() {
    use std::fs;
    use tempfile::TempDir;

    let tmp = TempDir::new().expect("temp dir");
    let manifest = tmp.path().join("Cargo.toml");

    fs::write(
        &manifest,
        r#"[package]
name = "discard-err-test"
version = "0.1.0"
edition = "2021"

[dependencies]
"#,
    )
    .expect("write Cargo.toml");

    fs::create_dir_all(tmp.path().join("src")).expect("create src");
    fs::write(
        tmp.path().join("src/main.rs"),
        "use std::fs;\nfn main() { fs::remove_file(\"tmp\").ok(); }\n",
    )
    .expect("write main.rs");

    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("cargo-anoint"));
    cmd.arg("bs").arg("--manifest-path").arg(&manifest);

    let output = cmd.output().expect("run cargo-anoint bs");
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(output.status.success(), "should exit 0: {}", stdout);
    assert!(
        stdout.contains("discarded error"),
        "should flag .ok() as discarded error: {}",
        stdout
    );
}

#[test]
fn test_bs_detects_lossy_utf8() {
    use std::fs;
    use tempfile::TempDir;

    let tmp = TempDir::new().expect("temp dir");
    let manifest = tmp.path().join("Cargo.toml");

    fs::write(
        &manifest,
        r#"[package]
name = "lossy-utf8-test"
version = "0.1.0"
edition = "2021"

[dependencies]
"#,
    )
    .expect("write Cargo.toml");

    fs::create_dir_all(tmp.path().join("src")).expect("create src");
    fs::write(
        tmp.path().join("src/main.rs"),
        "fn main() { let b: &[u8] = b\"hello\"; println!(\"{}\", String::from_utf8_lossy(b)); }\n",
    )
    .expect("write main.rs");

    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("cargo-anoint"));
    cmd.arg("bs").arg("--manifest-path").arg(&manifest);

    let output = cmd.output().expect("run cargo-anoint bs");
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(output.status.success(), "should exit 0: {}", stdout);
    assert!(
        stdout.contains("lossy UTF-8"),
        "should flag from_utf8_lossy: {}",
        stdout
    );
}

#[test]
fn test_no_advisories_flag_accepted() {
    cargo_anoint_cmd().arg("--no-advisories").assert().success();
}

#[test]
fn test_advisories_skipped_in_offline_mode() {
    use std::fs;
    use tempfile::TempDir;

    let tmp = TempDir::new().expect("temp dir");
    let manifest = tmp.path().join("Cargo.toml");

    fs::write(
        &manifest,
        r#"[package]
name = "offline-adv-test"
version = "0.1.0"
edition = "2021"

[dependencies]
serde = "1"
"#,
    )
    .expect("write Cargo.toml");

    fs::create_dir_all(tmp.path().join("src")).expect("create src");
    fs::write(tmp.path().join("src/main.rs"), "fn main() {}\n").expect("write main.rs");

    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("cargo-anoint"));
    cmd.arg("anoint")
        .arg("--manifest-path")
        .arg(&manifest)
        .arg("--offline");

    let output = cmd.output().expect("run cargo-anoint --offline");
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(output.status.success(), "should exit 0: {}", stdout);
    assert!(
        !stdout.contains("Security advisories"),
        "offline mode should not fetch advisories: {}",
        stdout
    );
}

// A capability gate must operate on the selected resolution, not the union of
// workspace packages, feature configurations, or dependency roles.
#[test]
fn overlap_gate_respects_feature_target_kind_and_exact_exception() {
    use std::fs;
    use tempfile::TempDir;

    let tmp = TempDir::new().expect("temp dir");
    let root = tmp.path();
    fs::create_dir(root.join("src")).expect("src");
    fs::write(root.join("src/lib.rs"), "").expect("lib");
    fs::write(
        root.join("Cargo.toml"),
        r#"
[package]
name = "anoint-fixture"
version = "0.1.0"
edition = "2021"
[workspace]
exclude = ["wreq", "reqwest", "ureq", "hyper", "axum"]
[features]
second-client = ["dep:reqwest"]
[dependencies]
wreq = { path = "wreq" }
hyper = { path = "hyper" }
axum = { path = "axum" }
[dev-dependencies]
ureq = { path = "ureq" }
[target.'cfg(windows)'.dependencies]
reqwest = { path = "reqwest", optional = true }
"#,
    )
    .expect("manifest");
    for name in ["wreq", "reqwest", "ureq", "hyper", "axum"] {
        fs::create_dir_all(root.join(name).join("src")).expect("crate src");
        fs::write(root.join(name).join("src/lib.rs"), "").expect("crate lib");
        fs::write(
            root.join(name).join("Cargo.toml"),
            format!("[package]\nname = \"{name}\"\nversion = \"0.1.0\"\nedition = \"2021\"\n"),
        )
        .expect("crate manifest");
    }
    let run = |extra: &[&str]| {
        let mut cmd = cargo_anoint_cmd();
        cmd.current_dir(root)
            .args([
                "--offline",
                "--workspace",
                "--json",
                "--all-targets",
                "--fail-on-overlap",
            ])
            .args(extra);
        cmd.output().expect("run gate")
    };
    assert!(
        run(&[]).status.success(),
        "disabled optional dependency and different dev role should not trigger"
    );
    let linux = run(&[
        "--features",
        "second-client",
        "--target",
        "x86_64-unknown-linux-gnu",
    ]);
    assert!(
        linux.status.success(),
        "Windows-only dependency should not trigger on Linux: {}",
        String::from_utf8_lossy(&linux.stderr)
    );
    let windows = run(&[
        "--features",
        "second-client",
        "--target",
        "x86_64-pc-windows-msvc",
    ]);
    assert!(
        !windows.status.success(),
        "two active HTTP clients must trigger"
    );
    let report: serde_json::Value = serde_json::from_slice(&windows.stdout).expect("JSON output");
    let findings = report["packages"][0]["dependency_suggestions"]
        .as_array()
        .expect("findings");
    assert!(
        findings
            .iter()
            .any(|f| f["kind"] == "CapabilityOverlap" && f["current"] == "wreq+reqwest")
    );
    fs::write(
        root.join("anoint.toml"),
        r#"
[[allow_overlap]]
package = "anoint-fixture"
providers = ["reqwest", "wreq"]
reason = "Independent compatibility fixture for a deliberate comparison"
"#,
    )
    .expect("exception");
    assert!(
        run(&[
            "--features",
            "second-client",
            "--target",
            "x86_64-pc-windows-msvc"
        ])
        .status
        .success(),
        "exact reviewed exception"
    );
    fs::write(
        root.join("anoint.toml"),
        r#"
[[allow_overlap]]
package = "some-other-package"
providers = ["reqwest", "wreq"]
reason = "Not this package"
"#,
    )
    .expect("unrelated exception");
    assert!(
        !run(&[
            "--features",
            "second-client",
            "--target",
            "x86_64-pc-windows-msvc"
        ])
        .status
        .success(),
        "exception must not apply to unrelated packages"
    );
}
