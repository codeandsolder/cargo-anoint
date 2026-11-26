# Contributing

By participating in this project you agree to abide by the
[Code of Conduct](../CODE_OF_CONDUCT.md).

## Build & test

```sh
cargo build --locked
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked
```

## Rules data

Suggestions ship from the reviewed catalog `data/suggestions.json`. Use `cargo run -- --update-rules` to fetch and print candidate blessed.rs rules. Review candidates manually; do not merge live data into the catalog automatically. Local policy and project-preferred forks remain authoritative.

Validate candidate matches, replacement rationale, conditions, confidence and migration risk. Add regression tests for new policy behavior.

The shared strict Rust CI gate also applies; a local Clippy run is not a substitute for that gate.

## Documentation & releases

1. **Before** tagging: update `README.md`, this `docs/` tree as needed, and `changelog.md`.
2. Bump `version` in `Cargo.toml`; commit with a clear message.
3. Open PR to `main` (branch protections may require signed commits — check repo rules).
4. After merge: tag `vX.Y.Z` on the release commit when it matches what you publish.
5. The scanner-release workflow builds the repository distribution; this package has `publish = false`.

User-agent strings for outbound HTTP now follow `cargo-anoint/` + `CARGO_PKG_VERSION` (`intel`, `updater`).
