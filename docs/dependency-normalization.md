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
