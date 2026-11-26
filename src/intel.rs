//! Live intelligence layer — fetches metadata from crates.io
//! to assess freshness, popularity, and maintenance status.
//!
//! All network operations are **non-fatal** for the CLI: failures are reported and the
//! tool continues with whatever data it has.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::fs;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

const USER_AGENT: &str = concat!(
    "cargo-anoint/",
    env!("CARGO_PKG_VERSION"),
    " (https://github.com/codeandsolder/cargo-anoint)"
);
const CACHE_TTL_SECS: u64 = 3600; // 1 hour

// ── Public types ─────────────────────────────────────────────────────

/// Live metadata for a single crate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrateIntel {
    pub name: String,
    pub latest_version: String,
    pub downloads: u64,
    pub recent_downloads: Option<u64>,
    pub last_updated: String,
    pub repository_url: Option<String>,
    pub description: Option<String>,
}

/// Cache wrapper that tracks when data was fetched.
#[derive(Debug, Serialize, Deserialize)]
struct CacheEntry<T> {
    data: T,
    fetched_at: u64,
}

impl<T> CacheEntry<T> {
    fn is_fresh(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        now.checked_sub(self.fetched_at)
            .is_some_and(|age| age < CACHE_TTL_SECS)
    }

    fn new(data: T) -> Self {
        let fetched_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Self { data, fetched_at }
    }
}

// ── IntelClient ──────────────────────────────────────────────────────

/// Client for fetching live dependency intelligence.
pub struct IntelClient {
    last_crates_io_request: Option<Instant>,
    http: wreq::Client,
    cache_dir: Option<PathBuf>,
}

impl IntelClient {
    /// Create a new `IntelClient` with crates.io API access and disk cache.
    ///
    /// # Errors
    /// Returns an error if the HTTP client cannot be constructed.
    pub async fn new(mut cache_dir: Option<PathBuf>) -> Result<Self> {
        let http = wreq::Client::builder()
            .user_agent(USER_AGENT)
            .timeout(Duration::from_secs(10))
            .build()
            .context("failed to create HTTP client")?;

        if let Some(dir) = &cache_dir
            && let Err(err) = fs::create_dir_all(dir).await
        {
            eprintln!(
                "⚠️  Could not create cache directory at {}: {err}. Continuing without cache.",
                dir.display()
            );
            cache_dir = None;
        }

        Ok(Self {
            last_crates_io_request: None,
            http,
            cache_dir,
        })
    }

    /// Fetch live intel for a crate. Checks disk cache first (1hr TTL).
    ///
    /// # Errors
    /// Returns an error for invalid crate names, failed requests, or invalid registry responses.
    async fn fetch_crate_intel(&mut self, name: &str) -> Result<CrateIntel> {
        anyhow::ensure!(
            !name.is_empty()
                && name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_')),
            "invalid crate name"
        );
        // Check cache
        let cache_path = self
            .cache_dir
            .as_ref()
            .map(|dir| dir.join(format!("{name}.json")));

        if let Some(path) = &cache_path
            && let Ok(contents) = fs::read_to_string(path).await
            && let Ok(entry) = serde_json::from_str::<CacheEntry<CrateIntel>>(&contents)
            && entry.is_fresh()
        {
            return Ok(entry.data);
        }

        // Cache miss or stale — fetch from crates.io
        if let Some(previous) = self.last_crates_io_request {
            tokio::time::sleep(Duration::from_secs(1).saturating_sub(previous.elapsed())).await;
        }
        self.last_crates_io_request = Some(Instant::now());
        let response = self
            .http
            .get(format!("https://crates.io/api/v1/crates/{name}"))
            .send()
            .await
            .and_then(wreq::Response::error_for_status)
            .with_context(|| format!("failed to fetch crate info for {name}"))?;
        let response: RegistryResponse = response
            .json()
            .await
            .context("failed to decode crates.io response")?;

        let crate_data = response.crate_data;
        let intel = CrateIntel {
            name: name.to_string(),
            latest_version: crate_data.max_version,
            downloads: crate_data.downloads,
            recent_downloads: crate_data.recent_downloads,
            last_updated: crate_data.updated_at,
            repository_url: crate_data.repository,
            description: crate_data.description,
        };

        // Write to cache (best-effort)
        if let Some(path) = &cache_path {
            let entry = CacheEntry::new(&intel);
            if let Ok(json) = serde_json::to_string_pretty(&entry) {
                let _ = fs::write(path, json).await;
            }
        }

        Ok(intel)
    }

    /// Fetch intel for all unique crate names, returning what we can get.
    /// Return the number of unique requests that failed alongside successful results.
    pub async fn fetch_bulk_intel(
        &mut self,
        crate_names: &[&str],
    ) -> (HashMap<String, CrateIntel>, usize) {
        let mut failed = 0;
        let mut intel = HashMap::new();
        let mut seen = HashSet::new();
        for name in crate_names.iter().map(|name| name.trim()) {
            if !seen.insert(name) {
                continue;
            }
            if let Ok(info) = self.fetch_crate_intel(name).await {
                intel.insert(name.to_string(), info);
            } else {
                failed += 1;
            }
        }
        (intel, failed)
    }
}

#[derive(Deserialize)]
struct RegistryResponse {
    #[serde(rename = "crate")]
    crate_data: RegistryCrate,
}

#[derive(Deserialize)]
struct RegistryCrate {
    max_version: String,
    downloads: u64,
    recent_downloads: Option<u64>,
    updated_at: String,
    repository: Option<String>,
    description: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn registry_response_matches_crates_io_wire_format() {
        let response: RegistryResponse = serde_json::from_str(r#"{"crate":{"max_version":"1.2.3","downloads":42,"recent_downloads":null,"updated_at":"2026-11-01T12:00:00Z","repository":"https://github.com/example/example","description":null},"versions":[{"num":"1.2.3","yanked":false}]}"#).unwrap();
        assert_eq!(response.crate_data.downloads, 42);
        assert_eq!(response.crate_data.updated_at, "2026-11-01T12:00:00Z");
        assert_eq!(response.crate_data.max_version, "1.2.3");
        assert_eq!(response.crate_data.recent_downloads, None);
    }

    #[test]
    fn test_cache_entry_fresh() {
        let entry = CacheEntry::new("some data".to_string());
        assert!(entry.is_fresh());
    }

    #[test]
    fn test_cache_entry_stale() {
        let entry = CacheEntry {
            data: "old data".to_string(),
            fetched_at: 0, // epoch = definitely stale
        };
        assert!(!entry.is_fresh());
    }

    #[test]
    fn future_cache_entry_is_stale() {
        let entry = CacheEntry {
            data: (),
            fetched_at: u64::MAX,
        };
        assert!(!entry.is_fresh());
    }

    #[test]
    fn test_cache_entry_roundtrip() {
        let intel = CrateIntel {
            name: "serde".into(),
            latest_version: "1.0.228".into(),
            downloads: 100_000_000,
            recent_downloads: Some(5_000_000),
            last_updated: "2026-01-15T12:00:00Z".into(),
            repository_url: Some("https://github.com/serde-rs/serde".into()),
            description: Some("A serialization framework".into()),
        };
        let entry = CacheEntry::new(intel);
        let json = serde_json::to_string(&entry).unwrap();
        let roundtrip: CacheEntry<CrateIntel> = serde_json::from_str(&json).unwrap();
        assert_eq!(roundtrip.data.name, "serde");
        assert_eq!(roundtrip.data.downloads, 100_000_000);
        assert!(roundtrip.is_fresh());
    }

    #[test]
    fn test_cache_disk_write_and_read() {
        let tmp = TempDir::new().unwrap();
        let cache_path = tmp.path().join("test_crate.json");

        let intel = CrateIntel {
            name: "test_crate".into(),
            latest_version: "0.1.0".into(),
            downloads: 42,
            recent_downloads: None,
            last_updated: "2026-02-27T00:00:00Z".into(),
            repository_url: None,
            description: None,
        };

        // Write
        let entry = CacheEntry::new(intel);
        let json = serde_json::to_string_pretty(&entry).unwrap();
        fs::write(&cache_path, &json).unwrap();

        // Read back
        let contents = fs::read_to_string(&cache_path).unwrap();
        let loaded: CacheEntry<CrateIntel> = serde_json::from_str(&contents).unwrap();
        assert_eq!(loaded.data.name, "test_crate");
        assert!(loaded.is_fresh());
    }

    #[tokio::test]
    async fn test_fetch_bulk_intel() {
        let tmp = TempDir::new().unwrap();

        let mut client = IntelClient::new(Some(tmp.path().to_path_buf()))
            .await
            .unwrap();

        // Inject successful cache hit
        let intel = CrateIntel {
            name: "test_success".into(),
            latest_version: "1.0.0".into(),
            downloads: 100,
            recent_downloads: None,
            last_updated: "2026-02-27T00:00:00Z".into(),
            repository_url: None,
            description: None,
        };
        let entry = CacheEntry::new(intel);
        let json = serde_json::to_string_pretty(&entry).unwrap();
        tokio::fs::write(tmp.path().join("test_success.json"), json)
            .await
            .unwrap();

        // Fetch one that succeeds and one that fails (cache miss and fake crate)
        let (results, failed) = client
            .fetch_bulk_intel(&["test_success", "invalid/crate"])
            .await;

        // Validate
        assert_eq!(results.len(), 1);
        assert_eq!(failed, 1);
        assert!(results.contains_key("test_success"));
        assert_eq!(results.get("test_success").unwrap().name, "test_success");
    }

    /// Live network test — run with `cargo test -- --ignored`
    #[tokio::test]
    #[ignore]
    async fn test_live_fetch_serde() {
        let mut client = IntelClient::new(None).await.expect("client should init");
        let intel = client
            .fetch_crate_intel("serde")
            .await
            .expect("should fetch serde");
        assert_eq!(intel.name, "serde");
        assert!(intel.downloads > 0);
        println!(
            "serde: v{}, {} downloads",
            intel.latest_version, intel.downloads
        );
    }
}
