# cargo-anoint

A source-aware Cargo dependency policy checker maintained by codeandsolder,
forked from [Ruffian-L/cargo-bless](https://github.com/Ruffian-L/cargo-bless)
(MIT). It recommends reviewed dependency choices and detects potential
functional overlap between independently selected direct dependencies.

## Install and run

```sh
cargo install --git https://github.com/codeandsolder/cargo-anoint --locked
cargo anoint --workspace --offline
cargo anoint --workspace --offline --json --fail-on-overlap
```

The tool uses the repository's dated nightly compiler, asynchronous wreq-exp,
 and btls-fast. It requires a native C/C++ toolchain for BoringSSL.

For CI, install from a reviewed commit with `--rev`. Pass
`--target <target-triple>` and the same `--features` /
`--no-default-features` as the corresponding build. Default feature selection
is Cargo's normal resolution; `--all-features` is an explicit union scan.
Without `--target`, Cargo resolves dependencies for all supported targets,
so mutually exclusive platform providers may appear together. Repeat the
gate for relevant configurations rather than assuming all features coexist.

`--offline` skips live registry intelligence and OSV requests. Cargo metadata
still needs access to the resolved dependency graph. Use Cargo's offline
configuration after fetching dependencies if network isolation is required.

## Organization policy

[The organization catalog](data/organization.json) is the source of truth:

- Fork preferences match reachable resolved Cargo package names and Git source
  URLs, including transitive sources (not the package's repository metadata, which can still name upstream).
- HTTP clients prefer `wreq` from `codeandsolder/wreq-exp`; native TLS
  recommendations prefer `btls`, `btls-sys` and `tokio-btls` from
  `codeandsolder/btls-fast` where applicable.
- Same-name fork recommendations cover the reviewed package families in
  zlib-rs-fast, quiche-fast, fast-socks5-fast, hayro, oxc, step-p21-fast,
  yarugc-rs, planetmap, waffle, ngspice-rs-fast and zipp-fast.
- Capability overlap checks are per workspace member and dependency role.
  They report individual provider pairs, excluding known complementary layers.
  A crate reachable only transitively is not treated as an independent direct
  provider. Local path packages have no authoritative remote source.
- `--all-targets` adds build and development roles; it does not combine them
  with the normal role into one provider set.

A preference is an advisory recommendation, not an unconditional replacement.
A capability overlap requests consolidation or an explicit justification.
All built-in suggestions require manual review; neither source rewrites nor
manifest-only automatic migrations are inferred from names.

## Focused CI gate

`--fail-on-overlap` fails on unsuppressed curated capability overlaps, independently
of other modernization suggestions or `--fail-on` impact filters. JSON reports
contain `kind: "CapabilityOverlap"` and the exact two provider names in
`current`. To document legitimate coexistence, place an `anoint.toml` beside
the workspace manifest:

```toml
[settings]
fail_on_overlap = true

[[allow_overlap]]
package = "my-package"
providers = ["wreq", "reqwest"]
reason = "Benchmark comparing two independent client implementations"
```

The exception applies only to the named workspace member and exact unordered
pair. A general ignored dependency does not silently bypass the capability
gate. The gate is independent of unused-dependency, duplicate-version and
security checks.

## Reviewed upstream recommendations

[The embedded modernization rules](data/suggestions.json) are versioned and
reviewed; a local rule cache cannot silently change CI results. The manual
candidate generator is inherited from upstream and can be used to review
blessed.rs updates; automatic rule commits and upstream package publication
are disabled. Do not apply blanket migration advice without checking source,
features and API requirements.

The upstream code-audit and live intelligence commands remain available
for separate use. See `cargo anoint --help` and `cargo anoint bs --help`.

## Development

```sh
cargo fmt --all -- --check
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
```

The original project and license attribution are preserved in
[LICENSE-MIT](LICENSE-MIT) and the historical [changelog](changelog.md).
