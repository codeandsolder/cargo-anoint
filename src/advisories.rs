//! Security advisory integration via the osv.dev batch API.
//!
//! Checks direct crates.io dependencies against the OSV database (which includes
//! `RustSec` advisories) in a single HTTP call. Failures are distinguished from an empty advisory result.

use std::time::Duration;

use anyhow::{Context, Result, ensure};
use cargo_metadata::semver::Version;
use serde::{Deserialize, Serialize};

const OSV_BATCH_URL: &str = "https://api.osv.dev/v1/querybatch";
const USER_AGENT: &str = concat!(
    "cargo-anoint/",
    env!("CARGO_PKG_VERSION"),
    " (https://github.com/codeandsolder/cargo-anoint)"
);

/// A single security advisory for a crate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Advisory {
    pub id: String,
    pub summary: String,
    pub aliases: Vec<String>,
}

impl Advisory {
    /// Return the first CVE alias if one is present.
    pub fn cve(&self) -> Option<&str> {
        self.aliases
            .iter()
            .find(|a| a.starts_with("CVE-"))
            .map(String::as_str)
    }
}

/// All advisories found for a specific crate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrateAdvisories {
    pub crate_name: String,
    pub version: String,
    pub advisories: Vec<Advisory>,
}

// ── osv.dev wire types ───────────────────────────────────────────────────────

#[derive(Serialize)]
struct OsvBatchRequest {
    queries: Vec<OsvPackageQuery>,
}

#[derive(Serialize)]
struct OsvPackageQuery {
    version: String,
    package: OsvPackage,
}

#[derive(Serialize)]
struct OsvPackage {
    name: String,
    ecosystem: &'static str,
}

#[derive(Deserialize, Default)]
struct OsvBatchResponse {
    results: Vec<OsvResultItem>,
}

#[derive(Deserialize, Default)]
struct OsvResultItem {
    #[serde(default)]
    vulns: Vec<OsvVuln>,
}

#[derive(Deserialize)]
struct OsvVuln {
    id: String,
    #[serde(default)]
    summary: Option<String>,
    #[serde(default)]
    aliases: Vec<String>,
}

/// Fetch advisories that affect the exact resolved crate versions.
///
/// # Errors
/// Returns an error for transport, HTTP, decoding or inconsistent response failures.
/// Each tuple is `(crate_name, resolved_version)`. OSV uses the version to
/// filter out historical advisories that do not affect the installed release.
pub async fn fetch_advisories_batch_for_versions(
    crate_versions: &[(&str, &Version)],
) -> Result<Vec<CrateAdvisories>> {
    fetch_advisories(versioned_queries(crate_versions)).await
}

fn versioned_queries(crate_versions: &[(&str, &Version)]) -> Vec<OsvPackageQuery> {
    crate_versions
        .iter()
        .map(|(name, version)| OsvPackageQuery {
            version: version.to_string(),
            package: OsvPackage {
                name: name.to_string(),
                ecosystem: "crates.io",
            },
        })
        .collect()
}

async fn fetch_advisories(queries: Vec<OsvPackageQuery>) -> Result<Vec<CrateAdvisories>> {
    if queries.is_empty() {
        return Ok(Vec::new());
    }
    let client = wreq::Client::builder()
        .user_agent(USER_AGENT)
        .timeout(Duration::from_secs(10))
        .build()
        .context("build OSV client")?;
    let request = OsvBatchRequest { queries };
    let response = client
        .post(OSV_BATCH_URL)
        .json(&request)
        .send()
        .await
        .and_then(wreq::Response::error_for_status)
        .context("query OSV batch")?;
    let batch = response
        .json::<OsvBatchResponse>()
        .await
        .context("decode OSV batch")?;
    match_results(request, batch)
}

fn match_results(
    request: OsvBatchRequest,
    batch: OsvBatchResponse,
) -> Result<Vec<CrateAdvisories>> {
    ensure!(
        request.queries.len() == batch.results.len(),
        "OSV returned {} results for {} queries",
        batch.results.len(),
        request.queries.len()
    );
    Ok(request
        .queries
        .into_iter()
        .zip(batch.results)
        .filter(|(_, result)| !result.vulns.is_empty())
        .map(|(query, result)| CrateAdvisories {
            crate_name: query.package.name,
            version: query.version,
            advisories: result
                .vulns
                .into_iter()
                .map(|v| Advisory {
                    id: v.id,
                    summary: v.summary.unwrap_or_else(|| "No details available.".into()),
                    aliases: v.aliases,
                })
                .collect(),
        })
        .collect())
}

/// Outcome of an optional online advisory check.
#[derive(Debug, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum AdvisoryReport {
    Skipped,
    Complete {
        checked: usize,
        findings: Vec<CrateAdvisories>,
    },
    Unavailable {
        error: String,
    },
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versioned_queries_serialize_the_exact_version() {
        let request = OsvBatchRequest {
            queries: versioned_queries(&[("anyhow", &Version::new(1, 0, 103))]),
        };

        let json = serde_json::to_value(request).expect("serialize OSV request");
        assert_eq!(json["queries"][0]["version"], "1.0.103");
        assert_eq!(json["queries"][0]["package"]["name"], "anyhow");
        assert_eq!(json["queries"][0]["package"]["ecosystem"], "crates.io");
    }

    #[test]
    fn incomplete_batch_is_not_a_clean_scan() -> Result<()> {
        let request = OsvBatchRequest {
            queries: versioned_queries(&[("anyhow", &Version::new(1, 0, 103))]),
        };
        let response = serde_json::from_str(r#"{"results":[]}"#)?;
        assert!(match_results(request, response).is_err());
        Ok(())
    }

    #[test]
    fn findings_keep_the_queried_version() -> Result<()> {
        let request = OsvBatchRequest {
            queries: versioned_queries(&[
                ("example", &Version::new(1, 0, 0)),
                ("example", &Version::new(2, 0, 0)),
            ]),
        };
        let response =
            serde_json::from_str(r#"{"results":[{"vulns":[{"id":"RUSTSEC-example"}]},{}]}"#)?;
        let findings = match_results(request, response)?;
        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings.first().map(|hit| hit.version.as_str()),
            Some("1.0.0")
        );
        Ok(())
    }
}
