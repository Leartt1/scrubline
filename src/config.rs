//! Load user-supplied redaction patterns from a TOML rules file.
//!
//! ```toml
//! keys = ["x-internal-token", "vault_secret"]
//!
//! [[pattern]]
//! kind = "internal-token"
//! regex = "INT-[0-9]{8}"
//!
//! [[pattern]]
//! kind = "employee-id"
//! regex = "EMP[0-9]{6}"
//! ```
//!
//! Patterns are compiled and appended to the built-in named patterns; keys are
//! added to the structured (JSON/logfmt) sensitive-key set.

use regex::Regex;
use serde::Deserialize;

/// The parsed contents of a rules file: extra patterns and extra sensitive keys.
#[derive(Debug, Default)]
pub struct RulesFile {
    pub patterns: Vec<(String, Regex)>,
    pub keys: Vec<String>,
}

#[derive(Deserialize)]
struct RawConfig {
    #[serde(default)]
    pattern: Vec<RawPattern>,
    #[serde(default)]
    keys: Vec<String>,
}

#[derive(Deserialize)]
struct RawPattern {
    kind: String,
    regex: String,
}

/// Parse a TOML rules document into compiled patterns and extra keys. Returns a
/// human-readable error on invalid TOML or an uncompilable regex.
pub fn parse_rules(toml_src: &str) -> Result<RulesFile, String> {
    let raw: RawConfig =
        toml::from_str(toml_src).map_err(|e| format!("invalid rules file: {e}"))?;
    let mut patterns = Vec::with_capacity(raw.pattern.len());
    for p in raw.pattern {
        let re =
            Regex::new(&p.regex).map_err(|e| format!("invalid regex for '{}': {e}", p.kind))?;
        patterns.push((p.kind, re));
    }
    Ok(RulesFile {
        patterns,
        keys: raw.keys,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_custom_patterns() {
        let src = "[[pattern]]\nkind = \"internal-token\"\nregex = \"INT-[0-9]{8}\"\n";
        let rules = parse_rules(src).unwrap();
        assert_eq!(rules.patterns.len(), 1);
        assert_eq!(rules.patterns[0].0, "internal-token");
        assert!(rules.patterns[0].1.is_match("INT-12345678"));
    }

    #[test]
    fn parses_custom_keys() {
        let src = "keys = [\"x-internal-token\", \"vault_secret\"]\n";
        let rules = parse_rules(src).unwrap();
        assert_eq!(rules.keys, vec!["x-internal-token", "vault_secret"]);
        assert!(rules.patterns.is_empty());
    }

    #[test]
    fn empty_document_yields_no_rules() {
        let rules = parse_rules("").unwrap();
        assert!(rules.patterns.is_empty());
        assert!(rules.keys.is_empty());
    }

    #[test]
    fn rejects_uncompilable_regex() {
        let src = "[[pattern]]\nkind = \"bad\"\nregex = \"[unclosed\"\n";
        let err = parse_rules(src).unwrap_err();
        assert!(
            err.contains("bad"),
            "error should name the offending kind: {err}"
        );
    }

    #[test]
    fn rejects_invalid_toml() {
        assert!(parse_rules("this is not = valid = toml").is_err());
    }
}
