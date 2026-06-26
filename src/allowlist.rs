//! An allowlist of values that must never be redacted — the escape hatch for
//! false positives.
//!
//! One entry per line. Blank lines and `#` comments are ignored. A line of the
//! form `re:PATTERN` is a regex (matched anywhere in the value); any other line
//! is an exact literal value.
//!
//! ```text
//! # never redact our public sandbox key
//! pk_test_PUBLISHABLE
//! re:^EMP0+$
//! ```

use std::collections::HashSet;

use regex::Regex;

/// A set of literal values and regexes that suppress redaction.
#[derive(Default)]
pub struct Allowlist {
    literals: HashSet<String>,
    regexes: Vec<Regex>,
}

impl Allowlist {
    /// True if nothing is allowlisted (so callers can skip the check entirely).
    pub fn is_empty(&self) -> bool {
        self.literals.is_empty() && self.regexes.is_empty()
    }

    /// True if `value` should be left untouched (exact literal or any regex).
    pub fn is_allowed(&self, value: &str) -> bool {
        self.literals.contains(value) || self.regexes.iter().any(|r| r.is_match(value))
    }
}

/// Parse an allowlist document. Returns an error on an uncompilable `re:` line.
pub fn parse_allowlist(src: &str) -> Result<Allowlist, String> {
    let mut list = Allowlist::default();
    for (i, raw) in src.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(pattern) = line.strip_prefix("re:") {
            let re = Regex::new(pattern)
                .map_err(|e| format!("allowlist line {}: invalid regex: {e}", i + 1))?;
            list.regexes.push(re);
        } else {
            list.literals.insert(line.to_string());
        }
    }
    Ok(list)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_exact_literals() {
        let a = parse_allowlist("pk_test_PUBLIC\nknown-false-positive").unwrap();
        assert!(a.is_allowed("pk_test_PUBLIC"));
        assert!(a.is_allowed("known-false-positive"));
        assert!(!a.is_allowed("pk_live_SECRET"));
    }

    #[test]
    fn allows_regex_entries() {
        let a = parse_allowlist("re:^EMP0+$").unwrap();
        assert!(a.is_allowed("EMP000000"));
        assert!(!a.is_allowed("EMP123456"));
    }

    #[test]
    fn ignores_blank_lines_and_comments() {
        let a = parse_allowlist("# a comment\n\n  value  \n").unwrap();
        assert!(a.is_allowed("value"));
        assert!(!a.is_empty());
    }

    #[test]
    fn empty_document_is_empty() {
        assert!(parse_allowlist("").unwrap().is_empty());
    }

    #[test]
    fn rejects_invalid_regex() {
        assert!(parse_allowlist("re:[unclosed").is_err());
    }
}
