//! BS Detector — finds hardcoded bullshit values in Rust source files.
//!
//! Inspects Rust syntax-tree literals for:
//! - Magic numbers (non-trivial numeric literals)
//! - Hardcoded URLs
//! - API keys / tokens / secrets
//! - File paths
//! - IP addresses
//! - Hardcoded credentials

use std::net::IpAddr;
use std::path::Path;
use tree_sitter::Node;

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

/// Inspect a literal already visited by the shared syntax-tree walk.
pub(crate) fn inspect_literal(node: Node<'_>, source: &[u8], path: &Path, hits: &mut Vec<BSHit>) {
    if !matches!(
        node.kind(),
        "integer_literal" | "float_literal" | "string_literal" | "raw_string_literal"
    ) {
        return;
    }
    let Ok(text) = node.utf8_text(source) else {
        return;
    };
    let finding = match node.kind() {
        "integer_literal" | "float_literal" => inspect_number(node, text, source),
        "string_literal" | "raw_string_literal" => inspect_string(node, text, source),
        _ => None,
    };
    if let Some((category, value, suggestion)) = finding {
        hits.push(BSHit {
            file: path.display().to_string(),
            line: node.start_position().row + 1,
            category,
            value,
            suggestion: suggestion.to_owned(),
        });
    }
}

type Finding = (BSCategory, String, &'static str);

/// Follow only transparent expression wrappers, not arbitrary enclosing expressions.
fn literal_expression(mut node: Node<'_>) -> Node<'_> {
    while let Some(parent) = node.parent().filter(|parent| {
        matches!(
            parent.kind(),
            "parenthesized_expression" | "unary_expression" | "negative_literal"
        )
    }) {
        node = parent;
    }
    node
}

fn binding_name<'a>(node: Node<'_>, source: &'a [u8]) -> Option<&'a str> {
    let expr = literal_expression(node);
    let parent = expr.parent()?;
    let field = match parent.kind() {
        "let_declaration" => "pattern",
        "const_item" | "static_item" => "name",
        "field_initializer" => "field",
        "assignment_expression" => "left",
        _ => return None,
    };
    let value_field = if parent.kind() == "assignment_expression" {
        "right"
    } else {
        "value"
    };
    if parent.child_by_field_name(value_field)? != expr {
        return None;
    }
    let name = parent.child_by_field_name(field)?;
    let name = if name.kind() == "field_expression" {
        name.child_by_field_name("field")?
    } else {
        name
    };
    if !matches!(name.kind(), "identifier" | "field_identifier") {
        return None;
    }
    name.utf8_text(source).ok()
}

fn is_named_constant(node: Node<'_>) -> bool {
    let expr = literal_expression(node);
    expr.parent().is_some_and(|parent| {
        matches!(parent.kind(), "const_item" | "static_item")
            && parent.child_by_field_name("value") == Some(expr)
    })
}

fn inspect_number(node: Node<'_>, text: &str, source: &[u8]) -> Option<Finding> {
    if is_named_constant(node) {
        return None;
    }
    let value = numeric_value(text)?;
    if value <= 2.0 && value.fract().abs() < f64::EPSILON {
        return None;
    }
    let timeout = binding_name(node, source).is_some_and(|name| {
        let name = name.to_ascii_lowercase();
        ["timeout", "duration", "interval", "delay"]
            .iter()
            .any(|part| name.split('_').any(|word| word == *part))
    }) || duration_argument(node, source);
    if timeout {
        return Some((
            BSCategory::HardcodedTimeout,
            text.to_owned(),
            "Review whether the timing policy should be a named default or explicit configuration.",
        ));
    }
    if node.kind() == "float_literal" || value >= 100.0 {
        return Some((
            BSCategory::MagicNumber,
            text.to_owned(),
            "Review whether a named constant would clarify the value's meaning.",
        ));
    }
    None
}

// Used only for magnitude classification; the finding retains the exact source literal.
fn numeric_value(text: &str) -> Option<f64> {
    let text = text.replace('_', "");
    let (radix, digits) = if let Some(digits) = text.strip_prefix("0x") {
        (16, digits)
    } else if let Some(digits) = text.strip_prefix("0o") {
        (8, digits)
    } else if let Some(digits) = text.strip_prefix("0b") {
        (2, digits)
    } else {
        let number = [
            "u128", "i128", "usize", "isize", "u64", "i64", "u32", "i32", "u16", "i16", "u8", "i8",
            "f64", "f32",
        ]
        .iter()
        .find_map(|suffix| text.strip_suffix(suffix))
        .unwrap_or(&text);
        return number.parse().ok();
    };
    // Hexadecimal f32/f64 may be digits, not a suffix. Only integer suffixes apply.
    let mut value = 0.0_f64;
    for digit in digits.chars().map_while(|ch| ch.to_digit(radix)) {
        value = value.mul_add(f64::from(radix), f64::from(digit));
    }
    Some(value)
}

fn duration_argument(node: Node<'_>, source: &[u8]) -> bool {
    let Some(args) = literal_expression(node)
        .parent()
        .filter(|parent| parent.kind() == "arguments")
    else {
        return false;
    };
    let Some(call) = args
        .parent()
        .filter(|parent| parent.kind() == "call_expression")
    else {
        return false;
    };
    let Some(function) = call
        .child_by_field_name("function")
        .and_then(|function| function.utf8_text(source).ok())
    else {
        return false;
    };
    let mut segments = function.rsplit("::").map(str::trim);
    matches!(
        (segments.next(), segments.next()),
        (
            Some(
                "from_secs"
                    | "from_millis"
                    | "from_micros"
                    | "from_nanos"
                    | "from_secs_f32"
                    | "from_secs_f64"
            ),
            Some("Duration")
        )
    )
}

fn inspect_string(node: Node<'_>, text: &str, source: &[u8]) -> Option<Finding> {
    // Preserve escapes rather than guessing at invalid or byte-string contents.
    let (prefix, rest) = text.split_once('"')?;
    let end = rest.rfind('"')?;
    let content = rest.get(..end)?;
    if content.is_empty() || prefix.starts_with('b') || prefix.starts_with('c') {
        return None;
    }
    if let Some(name) = binding_name(node, source) {
        let lower = name.to_ascii_lowercase();
        let category = if lower
            .split('_')
            .any(|part| matches!(part, "password" | "passwd" | "pwd"))
        {
            Some(BSCategory::HardcodedCredential)
        } else if lower.ends_with("api_key")
            || lower.ends_with("apikey")
            || lower
                .split('_')
                .any(|part| matches!(part, "token" | "secret"))
        {
            Some(BSCategory::ApiKeyOrToken)
        } else {
            None
        };
        if let Some(category) = category {
            return (!is_placeholder(content)).then(|| {
                (
                    category,
                    format!("{name}=***"),
                    "Use an explicit credential provider or secret store.",
                )
            });
        }
    }
    if content.starts_with("https://") || content.starts_with("http://") {
        return Some((
            BSCategory::HardcodedUrl,
            content.to_owned(),
            "Review whether this is a fixed protocol endpoint or should be configurable.",
        ));
    }
    if let Ok(ip) = content.parse::<IpAddr>() {
        return (!ip.is_loopback() && !ip.is_unspecified()).then(|| {
            (
                BSCategory::IpAddress,
                content.to_owned(),
                "Review whether this address should be configurable.",
            )
        });
    }
    if content.starts_with('/') && content.len() > 1
        || content
            .as_bytes()
            .get(1..3)
            .is_some_and(|bytes| matches!(bytes, b":\\" | b":/"))
    {
        return Some((
            BSCategory::FilePath,
            content.to_owned(),
            "Review whether this absolute path is platform-specific or should be configurable.",
        ));
    }
    None
}

fn is_placeholder(content: &str) -> bool {
    content.starts_with("YOUR_")
        || content.starts_with("REPLACE_")
        || matches!(content, "CHANGE_ME" | "..." | "xxx")
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
    use anyhow::Result;

    fn scan(body: &str) -> Result<Vec<BSHit>> {
        let source = format!("fn fixture() {{\n{body}\n}}");
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&tree_sitter_rust::LANGUAGE.into())?;
        let tree = parser
            .parse(&source, None)
            .ok_or_else(|| anyhow::anyhow!("parse fixture"))?;
        let mut stack = vec![tree.root_node()];
        let mut hits = Vec::new();
        while let Some(node) = stack.pop() {
            inspect_literal(node, source.as_bytes(), Path::new("test.rs"), &mut hits);
            stack.extend(node.named_children(&mut node.walk()));
        }
        hits.sort_by_key(|hit| hit.line);
        Ok(hits)
    }

    #[test]
    fn numeric_literals_not_string_contents_or_constant_definitions() -> Result<()> {
        let hits = scan(
            r#"
            const BUFFER: usize = 8192;
            let label = "12345 v1.2.3";
            let literal = 4_096usize;
            let hex = 0xfeed_u32;
            let binary = 0b1111_1111;
            let tiny = 2;
            let year = 2026;
            let ratio = 3.14f32;
            let small = 0.03f64;
        "#,
        )?;
        let values: Vec<_> = hits.iter().map(|hit| hit.value.as_str()).collect();
        assert_eq!(
            values,
            [
                "4_096usize",
                "0xfeed_u32",
                "0b1111_1111",
                "2026",
                "3.14f32",
                "0.03f64"
            ]
        );
        Ok(())
    }

    #[test]
    fn detects_ip_literals_and_absolute_paths_without_matching_versions() -> Result<()> {
        let hits = scan(
            r##"
            let host = "192.168.1.100";
            let ipv6 = "2001:db8::1";
            let invalid = "999.999.999.999";
            let loopback = "127.0.0.1";
            let version = "1.2.3.4.5";
            let path = "/home/build";
            let windows = r#"C:\build"#;
        "##,
        )?;
        assert_eq!(
            hits.iter()
                .filter(|hit| hit.category == BSCategory::IpAddress)
                .count(),
            2
        );
        assert_eq!(
            hits.iter()
                .filter(|hit| hit.category == BSCategory::FilePath)
                .count(),
            2
        );
        Ok(())
    }

    #[test]
    fn detects_multiline_typed_credentials_without_leaking_value() -> Result<()> {
        let hits = scan(
            r##"
            const API_KEY: &str =
                r#"https://example.com/12345"#;
            let password: &str = "fake_123";
            let api_key = "YOUR_API_KEY";
            let url = "https://api.example-service.com/v1/data";
        "##,
        )?;
        assert_eq!(hits.len(), 3);
        assert_eq!(hits[0].category, BSCategory::ApiKeyOrToken);
        assert_eq!(hits[0].value, "API_KEY=***");
        assert_eq!(hits[1].category, BSCategory::HardcodedCredential);
        assert_eq!(hits[1].value, "password=***");
        assert_eq!(hits[2].category, BSCategory::HardcodedUrl);
        Ok(())
    }

    #[test]
    fn detects_actual_timing_expressions_without_duplicate_numeric_findings() -> Result<()> {
        let hits = scan("let timeout: u64 = 5000; let delay = Duration::from_millis(750);")?;
        assert_eq!(hits.len(), 2);
        assert!(
            hits.iter()
                .all(|hit| hit.category == BSCategory::HardcodedTimeout)
        );
        Ok(())
    }
}
