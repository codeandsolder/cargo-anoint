# Architecture overview

`cargo-anoint` is a normal Cargo subcommand binary (`cargo anoint`). The library crate (`cargo_anoint`) holds the pipeline; `src/main.rs` wires CLI → library.

## Module map (matches docs.rs)

| Module | Role |
|--------|------|
| `parser` | `cargo_metadata` — resolved dependency tree, direct vs transitive, features |
| `suggestions` | Reviewed embedded `data/suggestions.json` rules; local caches do not affect analysis. Match deps and output `Suggestion` values |
| `policy` | Optional `anoint.toml` — ignore packages, limits, code-audit filters |
| `intel` | Optional crates.io metadata (cached under `~/.cache/cargo-anoint/`); skipped when `--offline` or `[settings].offline` |
| `advisories` | Optional osv.dev batch advisory lookup for exact resolved direct-dependency versions; skipped when `--offline` or `--no-advisories`; non-fatal |
| `feedback` | `--feedback` — aggregate counts + code-audit "hotspots" without listing crate names or hitting the network |
| `output` | Human-readable reports, JSON helpers (`JsonReportUnified`), code-audit summary, advisory rendering |
| `updater` | `cargo anoint --update-rules` — fetch candidate rules from blessed.rs JSON for manual review |
| `code_audit` | Static bullshit-detector pass; discovers package source roots and targets using Cargo metadata; masks comments, literals and test-only items via tree-sitter; shares source traversal and diff filtering with the optional hardcoded-value scanner |
| `bs_detector` | Hardcoded-value scanner (`--hardcoded`): Rust syntax-tree literals, named credential bindings, timing expressions, IPs, URLs and absolute paths |

## Typical `cargo anoint` flow

1. Parse CLI (`src/cli.rs`) → validate flag combinations (`main.rs`).
2. Resolve deps (`parser`).
3. Load rules (`suggestions::load_rules`) → analyze (`suggestions::analyze`) → apply policy (`policy`).
4. If not `--offline` / not policy-offline and there are direct deps, bulk-fetch security advisories for their exact resolved versions (`advisories::fetch_advisories_batch_for_versions`); non-fatal.
5. If not `--offline` and there are suggestions, bulk-fetch live intel (`intel`).
6. Print modernization report (`output::render_packages_modernization`).
7. If `--audit-code`, scan sources (`code_audit::scan_project`) and print findings (`output::render_code_audit_report`).

`cargo anoint bs` / `cargo anoint … bs …` skips dependency linting and runs only `code_audit` (optionally `--diff` for changed lines vs `HEAD`, `--sarif` for GitHub code scanning).

## Data flow boundaries

- **Trust metadata** on suggestions (`impact`, `confidence`, `migration_risk`, `evidence_source`) is rule-driven. All recommendations require manual review; dependency scans do not rewrite manifests.
- **Code audit** discovers Cargo target paths without dependency resolution, scans selected package source trees and uses tree-sitter-rust to mask comments, literals and test-only items before running heuristic detectors. Hardcoded findings use the same syntax-tree walk, source selection and diff filtering. Code quality rules are heuristics rather than type-resolved diagnoses.
- **`cargo anoint bs`** is read-only; findings require an explicit, semantics-preserving source change.
- **`--feedback`** always runs suggestion analysis + full code audit for the chosen manifest but does **not** perform crates.io/osv.dev fetches — intended for voluntary, low-leak summaries.
