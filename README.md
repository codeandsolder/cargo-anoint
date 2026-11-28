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
- Selected backend and adapter preferences inspect reachable transitive packages
  and enabled features as well as direct dependencies. For example, JWT crypto
  should use the organization `jsonwebtoken-btls` provider with built-in
  providers disabled; Flate2 should select zlib-rs without a second backend.
  These are advisory findings, not independent-provider overlap failures.
- Capability overlap checks are per workspace member and dependency role.
  They report individual provider pairs, excluding known complementary layers.
  A crate reachable only transitively is not treated as an independent direct
  provider. Reviewed organization wrappers may expose an active immediate
  normal dependency as an advisory provider selection, using the resolved
  source rather than guessing from the wrapper name or latest revision.
  Local path packages have no authoritative remote source. Feature-conditioned
  providers are counted only with the relevant enabled capability (e.g. Wreq `ws`).
- Workload-sensitive capabilities (hashers, traversal, logging, Git, date/time,
  persistence, Argon2, STEP, completion I/O, glob matching, shell arguments,
  WebSockets, syscall wrappers, text diff) are advisory-only for the focused
  gate. Provider divergence between selected workspace members is also advisory,
  because different members need not link into the same executable.
  JSON reports list these in `workspace_suggestions`; same-member advisories
  remain in the member's `dependency_suggestions`. Both use
  `kind: "AdvisoryOverlap"`. See [reviewed choices](docs/semantic-overlap-policy.md).
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
security checks. `AdvisoryOverlap` does not trigger `--fail-on-overlap`
(ordinary explicit `--fail-on` severity filters still apply).
Use the same member-specific exception for advisory pairs, or separately:

```toml
[[allow_workspace_overlap]]
providers = ["ahash", "rustc-hash"]
reason = "Distinct programs with independently benchmarked key distributions"
```

Workspace exceptions do not suppress a member-level overlap.

## Reviewed upstream recommendations

[The embedded modernization rules](data/suggestions.json) are versioned and
reviewed; a local rule cache cannot silently change CI results. The manual
candidate generator is inherited from upstream and can be used to review
blessed.rs updates; automatic rule commits and upstream package publication
are disabled. Do not apply blanket migration advice without checking source,
features and API requirements.

The fleet release-age review adds source-linked native Rust replacements and
maintained successors. These findings are advisory and manual-only: age alone
is not a migration rule. Transitive rules identify dependencies for review at
the owning package; usage-dependent recommendations can remain direct-only.
Intentional benchmark competitors should be retained when they are part of the
measurement design.

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
