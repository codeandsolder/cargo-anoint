# CLI reference

Invoked as `cargo anoint …` once `cargo-anoint` is on your `PATH` (`cargo install --git https://github.com/codeandsolder/cargo-anoint`).

## Subcommands

| Invocation | Meaning |
|------------|---------|
| `cargo anoint` | Dependency scan + optional code audit (`--audit-code`), JSON, workspace flags. |
| `cargo anoint bs` | Code audit only (`--diff`, `--json`, `--sarif`, `--manifest-path`, `--policy`, `--verbose`). |
| `cargo anoint … bs …` | Nested `AnointSubcommand::Bs` — audit-only shortcut. |

## Paste-friendly vs machine output

| Flag | Shows | Typical use |
|------|-------|--------------|
| *(default)* | Full report + optional live intel | Day-to-day triage |
| `--feedback` | Version, dep totals, suggestion counts, code-audit hotspot list | Paste into GitHub issues — **never** emits your graph's crate listing or full suggestion rationale |
| `--summary` | Per-member dep counts + impact tallies + short pattern bullets | Paste into chats (skips intel fetch entirely) |
| `--json` | Structured JSON (**`cargo_anoint_version`**, **`workspace_scan`**, **`packages[]`**, **`code_audit`**, **`security_advisories`**) | Scripts / CI |

**Mutual exclusion:** **`--feedback`**, **`--summary`**, **`--json`**, **`--audit-code`** combinations are constrained as in `cargo anoint --help` (e.g. **`--feedback`** forbids **`--workspace`/`--package`**; **`--summary`** forbids **`--audit-code`**).

## `cargo anoint` flags

| Flag | Description |
|------|-------------|
| `--manifest-path=PATH` | Workspace root or package `Cargo.toml` (defaults to cwd). Virtual `[workspace]` roots work with **`--workspace`**. |
| `--offline` | Skip crates.io / osv.dev intelligence fetches. Reviewed embedded rules still apply. Also settable via `anoint.toml` `[settings].offline`. |
| `--no-advisories` | Skip the osv.dev advisory check even when online. |
| `--json` | Print unified JSON; cannot combine with **`--update-rules`**, **`--feedback`**, **`--summary`**. |
| `--feedback` | Privacy-minded aggregate feedback block (**root crate only**). |
| `--summary` | Short dependency summary (**no intel**). Cannot combine with **`--audit-code`**. |
| `--fail-on=L[,…]` | Exit **non-zero** if any retained suggestion's **`impact`** is in **`{low, medium, high}`**. |
| `--workspace` | Analyze **every** `workspace.members` entry once. |
| `--package=P[,…]` | Restrict to exact workspace member **`[package].name`** values (comma-separated). Empty names are errors. |
| `--audit-code` | Run the detector on each scanned member manifest and merge results (sums file counts / alerts). |
| `--all-targets` | Include `[dev-dependencies]` and `[build-dependencies]` in analysis (default: normal deps only). Also settable via `anoint.toml` `[settings].all_targets = true`. |
| `--update-rules` | Fetch and print candidate blessed-derived rules for manual review. |
| `--init-ci` | Write a starter GitHub Actions workflow to `.github/workflows/anoint.yml` and exit. |
| `--init-hooks` | Write Git’s configured `hooks/pre-commit` that runs `cargo anoint bs --fail-on-confidence 0.8` before each commit, and exit. |
| `--explain=PATTERN` | Show full details for a suggestion rule — kind, confidence, migration risk, reason, source. Fuzzy-matches on pattern name. Exits non-zero if no rule is found. |
| `--policy=PATH` | Explicit **`anoint.toml`** (otherwise auto-discovered next to the manifest directory). |
| `--verbose` | Dump every bullshit finding (text mode). |

### JSON shape (0.3+)

Top-level fields:

- **`cargo_anoint_version`**: string (`env!("CARGO_PKG_VERSION")` of the binary).
- **`workspace_scan`**: `true` when **`--workspace`** was used or multiple members were analyzed.
- **`packages`**: array of `{ name, version, manifest_path, dependency_suggestions }` where **`dependency_suggestions`** is the list of **`Suggestion`** structs. Impact values are lowercase; optional `condition` text states what must be reviewed before applying the recommendation.
- **`code_audit`**: `null` unless **`--audit-code`** (bless) populated the merged report, or **`cargo anoint bs --json`** with code-audit output.
- **`security_advisories`**: object with `status` (`skipped`, `complete`, or `unavailable`). Complete reports include `checked` and `findings` with exact crates.io versions; unavailable reports include an error.

`cargo anoint bs --json` uses **`packages: []`** plus **`code_audit`**.

## `cargo anoint bs` flags

| Flag | Description |
|------|-------------|
| `--manifest-path=PATH` | Path to the `Cargo.toml` whose source tree should be audited. |
| `--policy=PATH` | Explicit `anoint.toml` for code-audit suppressions. |
| `--json` | Output findings as unified JSON (`code_audit` key). |
| `--sarif` | Output findings as SARIF 2.1.0 JSON (for `upload-sarif` in GitHub Actions). |
| `--diff` | Audit only tracked lines changed in `git diff HEAD`, including hardcoded findings when requested. |
| `--include-tests` | Include test-only source items and conventional test, example and benchmark trees. |
| `--hardcoded` | Also inspect parsed Rust literals for nontrivial numbers, named credentials, timing expressions, IPs, URLs and absolute paths. Findings require review. |
| `--fail-on-confidence=FLOAT` | Exit non-zero if any retained source-quality finding has confidence ≥ this value (0.0–1.0); lowers the reporting threshold if necessary. Hardcoded findings have no confidence score. |
| `--verbose` | Show every finding instead of a concise summary. |

By default, the audit discovers Cargo package roots and declared targets without resolving dependencies, scans Rust source within each selected root (including build scripts and custom source directories), and excludes nested packages, generated/vendor directories and conventional test-only targets. A standalone directory without Cargo.toml is also supported. Oversized source fails the scan instead of being silently skipped. Directory symlinks are not traversed. Ignore-path substrings are matched against package-relative paths (external targets use their full paths); empty patterns are rejected. Modules reached only through paths outside the package root are not recursively discovered.

## Policy file (`anoint.toml`)

See repository README → **Policy File** section. Applies to both modernization filtering and bullshit detector ignores.

Relevant `[code_audit]` fields:

```toml
[code_audit]
ignore_paths = ["src/generated"]
ignore_kinds = ["UnwrapAbuse"]
include_tests = true   # equivalent to --include-tests on the CLI
```
