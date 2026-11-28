# Semantic provider overlap policy

Reviewed 2026-11-28. The versioned [organization catalog](../data/organization.json)
is executable policy; this document records why the choices are conditional.
A declaration/resolved edge identifies a potential overlap, not equivalent behavior,
a guaranteed linked binary, or a recommendation to remove a benchmark oracle.

## Reviewed provider choices

| Capability | Current evidence and default direction | When to retain a different provider |
| --- | --- | --- |
| In-memory hash tables | [rustc-hash](https://docs.rs/rustc-hash/latest/rustc_hash/) 2.x is a fast non-cryptographic hasher used in the compiler; [AHash](https://docs.rs/crate/ahash/latest), [Foldhash](https://docs.rs/foldhash/latest/foldhash/) (the [Hashbrown](https://docs.rs/crate/hashbrown/latest) default) and [RapidHash](https://docs.rs/rapidhash/latest/rapidhash/) are competing choices. Prefer existing rustc-hash for trusted numeric keys after representative measurement. [Rust performance book](https://nnethercote.github.io/perf-book/hashing.html) explains the workload dependence. | Preserve HashDoS resistance (e.g. standard randomized HashMap), seeding and deterministic ordering requirements. Hashbrown is a collection, not an independent hasher. Old fxhash remains subject to its existing [RustSec maintenance advisory](https://rustsec.org/advisories/RUSTSEC-2025-0057.html) and focused successor gate. |
| Recursive traversal | [ignore::WalkBuilder](https://docs.rs/ignore/latest/ignore/struct.WalkBuilder.html) supplies ignore-aware and parallel traversal; [walkdir](https://docs.rs/walkdir/latest/walkdir/struct.WalkDir.html) exposes explicit depth/order/open-file/symlink controls. Prefer the already required walker if semantics can be preserved; use ignore for ignore-aware scans. | A separate glob matcher is not a walker. Preserve hidden-file, ignore, sorting, error and symlink behavior; test path authorization and root-following separately. |
| Logging | [tracing](https://docs.rs/tracing/latest/tracing/struct.Event.html) supports structured fields and spans. [tracing-log](https://docs.rs/tracing-log/latest/tracing_log/) documents facade bridging and its recursion risks. Prefer tracing for application instrumentation. | A public library facade, bridge, filter or subscriber is not a second application instrumentation system. Do not remove log/trace compatibility on upstream-facing APIs without examining callers. |
| Git implementation | [gitoxide / gix](https://docs.rs/crate/gitoxide/latest) is Rust-native and provides a [git2 migration reference](https://docs.rs/gix/latest/gix/?search=git2). [git2](https://docs.rs/crate/git2/latest) wraps libgit2, including native dependencies. Prefer gix where the required operations are implemented. | Preserve auth, trust, config, transport, submodules, worktree/index/object-format and fetch/push semantics. Do not treat different versions as full operation parity. |
| Calendar / wall clock | [Jiff comparison](https://docs.rs/jiff/latest/jiff/_documentation/comparison/index.html) covers timezone and serialization semantics. [RustSec RUSTSEC-2026-0543](https://rustsec.org/advisories/RUSTSEC-2026-0543.html) reports chrono unmaintained. Prefer Jiff for calendrical/time-zone work; standard Instant/Duration for elapsed time. | Fixed-offset wire types, no_std, WASM, formatting, range and serde compatibility can require a different type. |
| Embedded persistence | [redb](https://docs.rs/redb/latest/redb/) is pure-Rust ACID KV, [heed](https://docs.rs/heed/latest/heed/) wraps LMDB, [Fjall](https://docs.rs/crate/fjall/latest) is LSM-based, [rusqlite](https://docs.rs/crate/rusqlite/latest) wraps SQLite. Use SQL when relational query/index semantics are required; compare actual KV workload with existing engine. | Durability, ordered scans, write amplification, transactions, writer contention, tail latency, migration and on-disk recovery matter. See the organization's separate [interim benchmark evidence](https://app.notion.com/p/402f74be9020818ca021f30dec760b7f) and [methodology](https://github.com/codeandsolder/all-db-bench-rs). |
| Argon2 | [RustCrypto argon2](https://docs.rs/argon2/latest/argon2/) supports the three Argon2 variants and the password-hash API; [argon2-rust](https://docs.rs/argon2-rust/latest/argon2_rust/) is a reference-C port with a different API and parallel/raw hashing options. [rust-argon2](https://docs.rs/rust-argon2/latest/argon2/) is another independent implementation. Prefer an existing provider with the exact semantics and measured throughput. | Independent conformance oracle, password-hash traits, version/PHC/parameter support, zeroization, constant-time verification, raw/preallocated workloads. No universal performance claim. |
| STEP Part 21 | [step-p21](https://docs.rs/crate/step-p21/latest) provides syntax and entity tables; the [organization fork](https://github.com/codeandsolder/step-p21-fast) is already the native reader dependency. [Cadmpeg codec](https://docs.rs/crate/cadmpeg-codec-step/latest) provides a CAD IR reader/writer; [cadmpeg-step](https://docs.rs/cadmpeg-step/latest/cadmpeg_step/) covers the same format. | Use independent differential readers for geometry, topology, assembly and loss-reporting checks. Native writer and a complete CAD codec are not interchangeable without corpus evidence. |
| Completion I/O | [Compio](https://docs.rs/crate/compio/latest) is completion-based; Tokio handles general asynchronous orchestration. Compio's facade and runtime crate are complementary. | Dedicated disk I/O, io_uring/IOCP, ownership/lifetime and network/timer runtime integration. Existing general-runtime direct-pair gates remain unchanged. |

| Glob matching | `glob`, `globset`, `wax`, `fast-glob`, `glob-match`: compare syntax, path semantics, encoding and multi-pattern needs; not equivalent to walking. | Ignore-aware path traversal and filename glob matching are distinct. |
| Shell argument processing | `shlex`, `shell-words`, `shellwords`, `brush-parser`, `shellish_parse`: investigate shared lexical operations, not just package names. | Full shell AST parsing and literal argv quoting are distinct contracts. |
| WebSocket transport | `wreq` with `ws`, `tokio-tungstenite`, `async-tungstenite`, `tokio-websockets`, `fastwebsockets`, `soketto`, `websocket`. Prefer shared HTTP/TLS client when appropriate. | Test servers and separate server frameworks may be necessary. Wreq without `ws` is not a WebSocket provider. |
| Unix syscall wrappers | `nix`, `rustix`: consolidate only after checking required syscall coverage. | User/group lookup, platform-specific calls and already-transitive dependencies may justify both. |
| Text diff | `similar`, `diff`, `diffy`, `imara-diff`: compare edit scripts, input granularity and patch handling. | Computing a diff and applying a patch need not use the same library. |

The organization's October 23 interim database results (not a final publication
ranking) favor SurrealKV/Fjall/RocksDB on the complete sync generalist matrix,
redb/heed on ordered scans, and SQLite/Turso on relational record workloads.
Results depend strongly on durability and concurrency; redb is not the universal
default. Use actual current workload measurements before migration.

## Fleet evidence and implementation boundary

- Monstertruck healing uses AHashSet and FxHashMap; many other members use Fx.
  The native STEP reader and feature-gated Cadmpeg comparison deliberately differ.
- SentinelO2 uses both WalkDir and WalkBuilder for different operations; check
  traversal behavior, not glob syntax.
- Searxrs2 uses redb for persistence/statistics and rusqlite for relational search
  history. Evaluate a single SQLite engine with a workload benchmark; no automatic
  removal.
- Cargo-ephemeral declares gix/git2 and Jiff/time; operation coverage matters.
- Challenge-solvers uses argon2-rust in its protocol implementation and RustCrypto
  argon2 as a development/reference dependency. Keep the independent oracle.
- sccache uses Compio for disk completion and Tokio for orchestration.
- Lurkmoar has changed transports across revisions. The random-utils lockfile at
  b021474a pins db56ab80 (ureq); certifex-minimus-rs at 24152755 pins 0c49fad8 (wreq)
  alongside reqwest. Thus latest-head lookup alone would produce the wrong result.
  The checker only recognizes reviewed wrapper packages from the authoritative
  resolved organization Git source and their active immediate normal child edges.
  It never treats arbitrary transitive packages as independently selected providers.

## Reporting contract

Normal, development and build dependency roles are never mixed. The existing
direct-pair gate remains for the previously gated pairs. New workload-sensitive
pairs and resolved wrapper overlaps emit `AdvisoryOverlap`, with manual-only
migration guidance. A wrapper alone selecting two transports is not two separate
direct choices. Distinct source/version selections through different wrappers or
wrapper revisions are tracked separately.

Multi-member scans report actual distinct member/provider selections in
`workspace_suggestions`, without asserting that members link into one program.
A pair can appear both in a member and across members when both facts hold.
Reviewed exact member exceptions and workspace exceptions are independent.
Tests cover target/role separation, optional edges, source provenance, ordinary
transitive packages, shared wrappers, gate semantics and explicit exceptions.

JWT consolidation and JS textual-regex removal require separate implementation
work. The current JWT adapter and Oxc regex parser are not competing engines.
