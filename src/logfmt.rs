//! Structured redaction for logfmt lines (`key=value key2="quoted value"`).
//!
//! We tokenize `key=value` pairs and, for any key the [`crate::keys`] set marks
//! sensitive, return a [`Span`] covering the value — the inner content for a
//! quoted value (so the quotes survive), or the whole token when unquoted.

use crate::keys::is_sensitive_key;
use crate::span::Span;

/// Return value spans for every sensitive key found in a logfmt `line`.
pub fn sensitive_spans(line: &str) -> Vec<Span> {
    let bytes = line.as_bytes();
    let len = bytes.len();
    let mut spans = Vec::new();
    let mut i = 0;

    while i < len {
        // Skip inter-pair whitespace.
        while i < len && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= len {
            break;
        }

        // Read the key: up to '=' or whitespace.
        let key_start = i;
        while i < len && bytes[i] != b'=' && !bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        let key = &line[key_start..i];

        // A key not followed by '=' is a bare boolean flag — no value to redact.
        if i >= len || bytes[i] != b'=' {
            continue;
        }
        i += 1; // consume '='

        // Read the value: quoted (keep the quotes) or unquoted (until whitespace).
        let (val_start, val_end) = if i < len && bytes[i] == b'"' {
            let content_start = i + 1;
            let mut j = content_start;
            while j < len {
                match bytes[j] {
                    b'\\' => j += 2, // skip an escaped char (e.g. \")
                    b'"' => break,   // closing quote
                    _ => j += 1,
                }
            }
            let content_end = j.min(len);
            i = if j < len { j + 1 } else { len }; // step past closing quote
            (content_start, content_end)
        } else {
            let start = i;
            while i < len && !bytes[i].is_ascii_whitespace() {
                i += 1;
            }
            (start, i)
        };

        if val_end > val_start && is_sensitive_key(key) {
            spans.push(Span::new(val_start, val_end, key.to_ascii_lowercase()));
        }
    }

    spans
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::span::redact_spans;

    fn redact(line: &str) -> String {
        redact_spans(line, &sensitive_spans(line))
    }

    #[test]
    fn redacts_unquoted_sensitive_value() {
        assert_eq!(
            redact("a=1 token=ghp_X b=2"),
            "a=1 token=[REDACTED:token] b=2"
        );
    }

    #[test]
    fn redacts_inside_quotes_keeping_them() {
        assert_eq!(
            redact(r#"password="hunter two" u=bob"#),
            r#"password="[REDACTED:password]" u=bob"#
        );
    }

    #[test]
    fn redacts_multiple_sensitive_keys() {
        assert_eq!(
            redact("token=abc secret=xyz"),
            "token=[REDACTED:token] secret=[REDACTED:secret]"
        );
    }

    #[test]
    fn leaves_non_sensitive_pairs_untouched() {
        assert_eq!(redact("user=bob status=200"), "user=bob status=200");
    }

    #[test]
    fn ignores_bare_boolean_keys() {
        assert_eq!(redact("debug token=abc"), "debug token=[REDACTED:token]");
    }

    #[test]
    fn handles_escaped_quote_inside_quoted_value() {
        assert_eq!(
            redact(r#"secret="a\"b" x=1"#),
            r#"secret="[REDACTED:secret]" x=1"#
        );
    }

    #[test]
    fn passes_through_plain_text_with_no_pairs() {
        assert_eq!(redact("just some words"), "just some words");
    }

    #[test]
    fn skips_empty_values() {
        assert_eq!(redact("token= x=1"), "token= x=1");
    }
}
