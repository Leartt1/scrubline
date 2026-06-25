//! Load user-supplied redaction patterns from a TOML rules file.
//!
//! ```toml
//! [[pattern]]
//! kind = "internal-token"
//! regex = "INT-[0-9]{8}"
//!
//! [[pattern]]
//! kind = "employee-id"
//! regex = "EMP[0-9]{6}"
//! ```
//!
//! These are compiled and appended to the built-in named patterns.

use regex::Regex;
use serde::Deserialize;

#[derive(Deserialize)]
struct RawConfig {
    #[serde(default)]
    pattern: Vec<RawPattern>,
}

#[derive(Deserialize)]
struct RawPattern {
    kind: String,
    regex: String,
}

/// Parse a TOML rules document into compiled `(kind, regex)` patterns. Returns a
/// human-readable error on invalid TOML or an uncompilable regex.
pub fn parse_rules(toml_src: &str) -> Result<Vec<(String, Regex)>, String> {
    let raw: RawConfig = toml::from_str(toml_src).map_err(|e| format!("invalid rules file: {e}"))?;
    let mut rules = Vec::with_capacity(raw.pattern.len());
    for p in raw.pattern {
        let re = Regex::new(&p.regex)
            .map_err(|e| format!("invalid regex for '{}': {e}", p.kind))?;
        rules.push((p.kind, re));
    }
    Ok(rules)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_custom_patterns() {
        let src = "[[pattern]]\nkind = \"internal-token\"\nregex = \"INT-[0-9]{8}\"\n";
        let rules = parse_rules(src).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].0, "internal-token");
        assert!(rules[0].1.is_match("INT-12345678"));
    }

    #[test]
    fn empty_document_yields_no_rules() {
        assert!(parse_rules("").unwrap().is_empty());
    }

    #[test]
    fn rejects_uncompilable_regex() {
        let src = "[[pattern]]\nkind = \"bad\"\nregex = \"[unclosed\"\n";
        let err = parse_rules(src).unwrap_err();
        assert!(err.contains("bad"), "error should name the offending kind: {err}");
    }

    #[test]
    fn rejects_invalid_toml() {
        assert!(parse_rules("this is not = valid = toml").is_err());
    }
}
