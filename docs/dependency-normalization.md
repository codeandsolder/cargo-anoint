# Dependency normalization catalog

The sccache-deduplicated HTTP/TLS/dependency migration informed these organization rules.
The catalog flags alternative implementations, not incidental leaves removed as a
consequence of changing a parent dependency.

| Removed or superseded family | Policy |
|---|---|
| rouille, tiny_http | Axum server framework |
| reqwest, ureq, ureq-proto, opendal-http-transport-reqwest | Wreq; migrate OpenDAL using HttpTransport |
| openssl, openssl-sys, native-tls, tokio-native-tls, hyper-tls, rustls, tokio-rustls, hyper-rustls, rustls-platform-verifier, rustls-webpki | btls-fast where native TLS is appropriate |
| aws-lc-rs, aws-lc-sys, ring | Avoid duplicate native crypto; jsonwebtoken-btls feature policy for JWT |
| miniz_oxide | zlib-rs-fast; configure Flate2 backend and resolved source |
| h2 | Wreq http2 fork where applicable; distinct transport may require h2 |
| libmount | Nix/Rustix mount APIs |
| version-compare | SemVer for semantic versions |
| ruzstd | Avoid unused object compression or consolidate with Zstd where appropriate |
| simple_asn1 | Disable unused JWT PEM support; independent ASN.1 parsing remains legitimate |
| webpki-roots | Match certificate store and root representation to the selected TLS stack |

Incidental release graph removals: adler2, num-bigint, quick-error,
simd-adler32, time-macros, twox-hash, untrusted, utf8-zero and void.
These are recorded for audit completeness; none is an independent HTTP/TLS or
compression implementation. Do not generate a global replacement rule for these
names merely because a former parent dependency used them. They may remain
legitimate in unrelated projects. Disabling the owning feature or migrating
the owning implementation is the correct way to remove them.


## Reqsign signing consolidation

The native Reqsign patch family replaces RustCrypto RSA signing with btls-fast
in core, Azure Storage and Google. Prefer the same-source patched family for
compatible native consumers; do not mix their key types. The `rsa` preference
also detects transitive use.

Additional incidental fleet graph removals: aes, base64ct, block-padding, cbc,
cipher, der, inout, lazy_static, libm, num-bigint-dig, num-integer, num-iter,
pbkdf2, pem-rfc7468, pkcs1, pkcs5, pkcs8, salsa20, scrypt, spki and subtle.
These remain legitimate in other cryptographic and numerical workloads; the
RSA migration removes the now-unused key parsing and arithmetic chain, not
all uses of these primitives globally.


## LRU and dashboard consolidation

Prefer `lru` for recency-based caching rather than maintaining a second
linked-hash-map-backed LRU. Weighted storage requires explicit capacity
accounting and admission/eviction behavior. Prefer Jiff for compatible date/time
operations when already in the graph. Disable Leptos Axum default features when
the application only uses ordinary HTTP/SSE server functions; ensure actual
Tokio filesystem, synchronization and Tower HTTP services stay enabled.
This removes WebSocket-specific tungstenite, tokio-tungstenite, data-encoding
and the old SHA1 version from the sccache native release; these remain legitimate
when WebSockets are actually used.
