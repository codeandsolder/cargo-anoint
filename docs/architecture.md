# Architecture overview

`cargo-anoint` is a normal Cargo subcommand binary (`cargo anoint`). The library crate (`cargo_anoint`) holds the pipeline; `src/main.rs` wires CLI → library.

## Module map (matches docs.rs)

| Module | Role |
|--------|------|
| `parser` | `cargo_metadata` — resolved dependency tree, direct vs transitive, features |
| `suggestions` | Reviewed embedded `data/suggestions.json` rules; local caches do not affect analysis. Match deps and output `Suggestion` values |
| `policy` | Optional `anoint.toml` — ignore packages, limits, code-audit filters |
| `intel` | Optional crates.io + GitHub metadata (cached under `~/.cache/cargo-anoint/`); skipped when `--offline` or `[settings].offline` |
| `advisories` | Optional osv.dev batch advisory lookup for exact resolved direct-dependency versions; skipped when `--offline` or `--no-advisories`; non-fatal |
| `feedback` | `--feedback` — aggregate counts + code-audit "hotspots" without listing crate names or hitting the network |
| `output` | Human-readable reports, JSON helpers (`JsonReportUnified`), code-audit summary, advisory rendering |
| `updater` | `cargo anoint --update-rules` — fetch candidate rules from blessed.rs JSON for manual review |
| `code_audit` | Static bullshit-detector pass; scans `src/` by default; `#[test]`/`#[cfg(test)]` blocks masked via tree-sitter; opt in to `tests/`/`examples/`/`benches/` with `--include-tests` |
| `bs_detector` | Hardcoded-value scanner (`--hardcoded`): magic numbers, API keys, IPs, URLs, credentials |

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
- **Code audit** scans `src/` only by default; uses tree-sitter-rust to parse and mask string literals, comments, and test blocks before running line-pattern detectors.
- **`cargo anoint bs`** is read-only; findings require an explicit, semantics-preserving source change.
- **`--feedback`** always runs suggestion analysis + full code audit for the chosen manifest but does **not** perform crates.io/GitHub/osv.dev fetches — intended for voluntary, low-leak summaries.
