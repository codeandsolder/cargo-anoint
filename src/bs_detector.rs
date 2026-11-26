//! BS Detector — finds hardcoded bullshit values in Rust source files.
//!
//! Scans source text for:
//! - Magic numbers (non-trivial numeric literals)
//! - Hardcoded URLs
//! - API keys / tokens / secrets
//! - File paths
//! - IP addresses
//! - Hardcoded credentials

use std::path::Path;

use colored::Colorize;
use serde::{Deserialize, Serialize};

/// A detected hardcoded value.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BSHit {
    /// File path where the hit was found.
    pub file: String,
    /// Line number (1-based).
    pub line: usize,
    /// Category of the BS.
    pub category: BSCategory,
    /// The matched value.
    pub value: String,
    /// Suggested fix or note.
    pub suggestion: String,
}

/// Categories of hardcoded bullshit.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum BSCategory {
    MagicNumber,
    HardcodedUrl,
    ApiKeyOrToken,
    FilePath,
    IpAddress,
    HardcodedCredential,
    HardcodedTimeout,
}

impl std::fmt::Display for BSCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MagicNumber => write!(f, "magic-number"),
            Self::HardcodedUrl => write!(f, "hardcoded-url"),
            Self::ApiKeyOrToken => write!(f, "api-key-or-token"),
            Self::FilePath => write!(f, "file-path"),
            Self::IpAddress => write!(f, "ip-address"),
            Self::HardcodedCredential => write!(f, "hardcoded-credential"),
            Self::HardcodedTimeout => write!(f, "hardcoded-timeout"),
        }
    }
}

struct Patterns {
    ip_check: regex::Regex,
    numbers: regex::Regex,
    urls: regex::Regex,
    keys: regex::Regex,
    paths: regex::Regex,
    ips: regex::Regex,
    credentials: regex::Regex,
    timeouts: regex::Regex,
}

impl Patterns {
    fn new() -> Result<Self, regex::Error> {
        Ok(Self {
            ip_check: regex::Regex::new(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")?,
            numbers: regex::Regex::new(r"\b(\d{3,}|\d+\.\d+)\b")?,
            urls: regex::Regex::new(r#"(https?://[^\s"'`<>\)\]]+)"#)?,
            keys: regex::Regex::new(
                r#"(?i)(api[_-]?key|token|secret|password|passwd|auth[_-]?token)\s*=\s*["']([^"']+)["']"#,
            )?,
            paths: regex::Regex::new(r#"["'](/[a-zA-Z0-9_/.-]+)["']"#)?,
            ips: regex::Regex::new(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")?,
            credentials: regex::Regex::new(
                r#"(?i)(password|passwd|pwd)\s*[:=]\s*["']([^"']{3,})["']"#,
            )?,
            timeouts: regex::Regex::new(
                r"(?i)(timeout|duration|interval|delay)\s*[:=]\s*(\d+)\s*(ms|seconds?|minutes?|hours?)?",
            )?,
        })
    }
}

pub(crate) struct HardcodedScanner(Patterns);

impl HardcodedScanner {
    pub(crate) fn new() -> Result<Self, regex::Error> {
        Ok(Self(Patterns::new()?))
    }

    pub(crate) fn scan(&self, source: &str, path: &Path) -> Vec<BSHit> {
        let mut hits = Vec::new();
        for (index, line) in source.lines().enumerate() {
            check_line(path, index + 1, line, &mut hits, &self.0);
        }
        hits
    }
}

/// Check a single line for hardcoded bullshit.
fn check_line(
    path: &Path,
    line_num: usize,
    line: &str,
    hits: &mut Vec<BSHit>,
    patterns: &Patterns,
) {
    let trimmed = line.trim();

    // Skip comments (but still check doc comments for URLs)
    if trimmed.starts_with("//") && !trimmed.starts_with("///") && !trimmed.starts_with("//!") {
        return;
    }

    detect_magic_numbers(path, line_num, trimmed, hits, patterns);
    detect_hardcoded_urls(path, line_num, trimmed, hits, patterns);
    detect_api_keys(path, line_num, trimmed, hits, patterns);
    detect_file_paths(path, line_num, trimmed, hits, patterns);
    detect_ip_addresses(path, line_num, trimmed, hits, patterns);
    detect_credentials(path, line_num, trimmed, hits, patterns);
    detect_hardcoded_timeouts(path, line_num, trimmed, hits, patterns);
}

/// Detect magic numbers — numeric literals that aren't 0, 1, -1, 2, or common constants.
fn detect_magic_numbers(
    path: &Path,
    line_num: usize,
    line: &str,
    hits: &mut Vec<BSHit>,
    patterns: &Patterns,
) {
    // Skip lines that are clearly defining a constant
    if line.contains("const ") || line.contains("static ") {
        return;
    }
    if patterns.ip_check.is_match(line) {
        return;
    }

    // Match numeric literals (integers and floats)
    let re = &patterns.numbers;
    for cap in re.captures_iter(line) {
        let value = &cap[1];

        // Skip common non-magic values
        let skip_values = [
            "2024", "2025", "2026", // years
            "1970", // epoch
            "1000", "10000", "100000", // powers of 10
            "255", "256", "512", "1024", // byte sizes
            "80", "443", "8080", "8443", // common ports (handled elsewhere)
        ];

        if skip_values.contains(&value) {
            continue;
        }

        hits.push(BSHit {
            file: path.display().to_string(),
            line: line_num,

            category: BSCategory::MagicNumber,
            value: value.to_string(),
            suggestion: "Extract to a named constant with a descriptive name".to_string(),
        });
    }
}

/// Detect hardcoded URLs.
fn detect_hardcoded_urls(
    path: &Path,
    line_num: usize,
    line: &str,
    hits: &mut Vec<BSHit>,
    patterns: &Patterns,
) {
    let re = &patterns.urls;
    for cap in re.captures_iter(line) {
        let url = &cap[1];

        // Skip documentation URLs and common non-problematic ones
        if line.starts_with("///") || line.starts_with("//!") {
            continue;
        }
        if url.contains("doc.rust-lang.org")
            || url.contains("crates.io")
            || url.contains("github.com")
            || url.contains("example.com")
        {
            continue;
        }

        hits.push(BSHit {
            file: path.display().to_string(),
            line: line_num,

            category: BSCategory::HardcodedUrl,
            value: url.to_string(),
            suggestion: "Move to a config file or environment variable".to_string(),
        });
    }
}

/// Detect API keys, tokens, and secrets.
fn detect_api_keys(
    path: &Path,
    line_num: usize,
    line: &str,
    hits: &mut Vec<BSHit>,
    patterns: &Patterns,
) {
    let re = &patterns.keys;

    for cap in re.captures_iter(line) {
        let value = &cap[2];

        // Skip placeholder values
        if value.is_empty()
            || value.contains("YOUR_")
            || value.contains("REPLACE_")
            || value.contains("CHANGE_ME")
            || value == "..."
            || value == "xxx"
        {
            continue;
        }

        hits.push(BSHit {
            file: path.display().to_string(),
            line: line_num,

            category: BSCategory::ApiKeyOrToken,
            value: format!("{}=***", &cap[1]),
            suggestion: "Use an environment variable or secrets manager".to_string(),
        });
    }
}

/// Detect hardcoded file paths.
fn detect_file_paths(
    path: &Path,
    line_num: usize,
    line: &str,
    hits: &mut Vec<BSHit>,
    patterns: &Patterns,
) {
    let re = &patterns.paths;
    for cap in re.captures_iter(line) {
        let p = &cap[1];

        // Skip common non-problematic paths
        if p.starts_with("/usr/") || p.starts_with("/etc/") || p.starts_with("/var/") {
            continue;
        }
        if p == "/" || p == "." || p == ".." {
            continue;
        }

        hits.push(BSHit {
            file: path.display().to_string(),
            line: line_num,

            category: BSCategory::FilePath,
            value: p.to_string(),
            suggestion: "Use a config file or environment variable for paths".to_string(),
        });
    }
}

/// Detect hardcoded IP addresses.
fn detect_ip_addresses(
    path: &Path,
    line_num: usize,
    line: &str,
    hits: &mut Vec<BSHit>,
    patterns: &Patterns,
) {
    let re = &patterns.ips;
    for cap in re.captures_iter(line) {
        let ip = &cap[1];

        // Skip localhost and common non-problematic IPs
        if ip == "127.0.0.1" || ip.starts_with("0.") || ip == "255.255.255.255" {
            continue;
        }

        hits.push(BSHit {
            file: path.display().to_string(),
            line: line_num,

            category: BSCategory::IpAddress,
            value: ip.to_string(),
            suggestion: "Use a hostname or configuration setting instead of hardcoded IP"
                .to_string(),
        });
    }
}

/// Detect hardcoded credentials (passwords in strings).
fn detect_credentials(
    path: &Path,
    line_num: usize,
    line: &str,
    hits: &mut Vec<BSHit>,
    patterns: &Patterns,
) {
    let re = &patterns.credentials;

    for cap in re.captures_iter(line) {
        let value = &cap[2];

        // Skip placeholders
        if value.contains("YOUR_") || value.contains("REPLACE_") || value == "..." {
            continue;
        }

        hits.push(BSHit {
            file: path.display().to_string(),
            line: line_num,

            category: BSCategory::HardcodedCredential,
            value: format!("{}=***", &cap[1]),
            suggestion:
                "NEVER hardcode credentials. Use environment variables or a secrets manager."
                    .to_string(),
        });
    }
}

/// Detect hardcoded timeouts/durations that should be configurable.
fn detect_hardcoded_timeouts(
    path: &Path,
    line_num: usize,
    line: &str,
    hits: &mut Vec<BSHit>,
    patterns: &Patterns,
) {
    let re = &patterns.timeouts;

    for cap in re.captures_iter(line) {
        let value = &cap[2];

        // Skip trivial values
        if value == "0" || value == "1" {
            continue;
        }

        hits.push(BSHit {
            file: path.display().to_string(),
            line: line_num,

            category: BSCategory::HardcodedTimeout,
            value: format!("{value} {}", cap.get(3).map_or("", |m| m.as_str())),
            suggestion: "Make timeouts configurable via environment variables or config files"
                .to_string(),
        });
    }
}

/// Render BS hits to stdout.
pub fn render_bs_hits(hits: &[BSHit]) {
    if hits.is_empty() {
        println!("{}", "✅ No hardcoded bullshit detected!".green());
        return;
    }

    println!(
        "{}",
        format!("🚨 Found {} hardcoded value(s):", hits.len())
            .red()
            .bold()
    );
    println!();

    for hit in hits {
        let cat_tag = match hit.category {
            BSCategory::MagicNumber => "[MAGIC]".yellow(),
            BSCategory::HardcodedUrl => "[URL]".cyan(),
            BSCategory::ApiKeyOrToken => "[KEY]".red(),
            BSCategory::FilePath => "[PATH]".magenta(),
            BSCategory::IpAddress => "[IP]".blue(),
            BSCategory::HardcodedCredential => "[CRED]".red().bold(),
            BSCategory::HardcodedTimeout => "[TIMEOUT]".yellow(),
        };

        println!(
            "  {cat_tag} {}:{} → {}",
            hit.file.dimmed(),
            hit.line.to_string().dimmed(),
            hit.value.yellow()
        );
        println!("    💡 {}", hit.suggestion.dimmed());
    }

    println!();
    let cred_count = hits
        .iter()
        .filter(|h| matches!(h.category, BSCategory::HardcodedCredential))
        .count();
    if cred_count > 0 {
        println!(
            "{}",
            format!("⚠️  {cred_count} hardcoded credential(s) found — this is a security risk!")
                .red()
                .bold()
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check_line(path: &Path, line_num: usize, line: &str, hits: &mut Vec<BSHit>) {
        super::check_line(path, line_num, line, hits, &Patterns::new().unwrap());
    }

    #[test]
    fn test_detect_magic_number() {
        let mut hits = Vec::new();
        check_line(
            Path::new("test.rs"),
            1,
            "let buffer_size = 4096;",
            &mut hits,
        );
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].category, BSCategory::MagicNumber);
        assert_eq!(hits[0].value, "4096");
    }

    #[test]
    fn test_skip_common_numbers() {
        let mut hits = Vec::new();
        check_line(Path::new("test.rs"), 1, "let x = 1024;", &mut hits);
        assert!(hits.is_empty(), "1024 should be skipped");

        check_line(Path::new("test.rs"), 2, "let year = 2025;", &mut hits);
        assert!(hits.is_empty(), "2025 should be skipped");
    }

    #[test]
    fn test_detect_hardcoded_url() {
        let mut hits = Vec::new();
        check_line(
            Path::new("test.rs"),
            1,
            "let url = \"https://api.example-service.com/v1/data\";",
            &mut hits,
        );
        assert_eq!(
            hits.iter()
                .filter(|h| matches!(h.category, BSCategory::HardcodedUrl))
                .count(),
            1
        );
    }

    #[test]
    fn test_skip_doc_urls() {
        let mut hits = Vec::new();
        check_line(
            Path::new("test.rs"),
            1,
            "/// See https://doc.rust-lang.org/std for more",
            &mut hits,
        );
        assert!(hits.is_empty(), "doc URLs should be skipped");
    }

    #[test]
    fn test_detect_api_key() {
        let mut hits = Vec::new();
        check_line(
            Path::new("test.rs"),
            1,
            r#"let api_key = "sk-abc123def456";"#,
            &mut hits,
        );
        assert_eq!(
            hits.iter()
                .filter(|h| matches!(h.category, BSCategory::ApiKeyOrToken))
                .count(),
            1
        );
    }

    #[test]
    fn test_skip_placeholder_api_key() {
        let mut hits = Vec::new();
        check_line(
            Path::new("test.rs"),
            1,
            r#"let api_key = "YOUR_API_KEY_HERE";"#,
            &mut hits,
        );
        assert!(hits.is_empty(), "placeholder keys should be skipped");
    }

    #[test]
    fn test_detect_hardcoded_credential() {
        let mut hits = Vec::new();
        check_line(
            Path::new("test.rs"),
            1,
            r#"let password = "super_secret_123";"#,
            &mut hits,
        );
        assert_eq!(
            hits.iter()
                .filter(|h| matches!(h.category, BSCategory::HardcodedCredential))
                .count(),
            1
        );
    }

    #[test]
    fn test_detect_ip_address() {
        let mut hits = Vec::new();
        check_line(
            Path::new("test.rs"),
            1,
            "let host = \"192.168.1.100\";",
            &mut hits,
        );
        assert_eq!(
            hits.iter()
                .filter(|h| matches!(h.category, BSCategory::IpAddress))
                .count(),
            1
        );
    }

    #[test]
    fn test_skip_localhost() {
        let mut hits = Vec::new();
        check_line(
            Path::new("test.rs"),
            1,
            "let host = \"127.0.0.1\";",
            &mut hits,
        );
        assert!(hits.is_empty(), "localhost should be skipped");
    }

    #[test]
    fn test_detect_hardcoded_timeout() {
        let mut hits = Vec::new();
        check_line(Path::new("test.rs"), 1, "let timeout = 5000ms;", &mut hits);
        assert_eq!(
            hits.iter()
                .filter(|h| matches!(h.category, BSCategory::HardcodedTimeout))
                .count(),
            1
        );
    }
}
