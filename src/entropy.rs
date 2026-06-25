//! Entropy detector: catch unknown high-entropy secrets that no named pattern
//! recognizes, while staying conservative to avoid masking UUIDs, git SHAs, and
//! content hashes.
//!
//! The whole design bias is toward *few false positives*: we only consider long
//! tokens, skip shapes that are almost always identifiers (hex hashes, UUIDs),
//! require a mix of character classes, and demand high Shannon entropy. We would
//! rather miss an exotic token (a named pattern or the structured layer often
//! catches it anyway) than redact a commit SHA in someone's build log.

use crate::detector::Detector;
use crate::span::Span;

/// Minimum token length considered; real secrets are long, ids/words are often
/// short.
const MIN_LEN: usize = 20;
/// Minimum Shannon entropy (bits/char) to flag. Random base64 sits near 5–6;
/// 3.5 is a deliberately conservative floor combined with the other guards.
const MIN_ENTROPY: f64 = 3.5;
/// Minimum distinct character classes among {lower, upper, digit}. Random
/// secret tokens almost always mix all three; the false-positive traps (k8s pod
/// names, dashed hashes, paths) are typically just lowercase + digits, so
/// requiring three is what separates secrets from infra noise.
const MIN_CLASSES: usize = 3;

/// Flags long, high-entropy, mixed-charset tokens that no named pattern matched.
pub struct EntropyDetector {
    min_len: usize,
    min_entropy: f64,
}

impl Default for EntropyDetector {
    fn default() -> Self {
        EntropyDetector { min_len: MIN_LEN, min_entropy: MIN_ENTROPY }
    }
}

impl Detector for EntropyDetector {
    fn kind(&self) -> &str {
        "high-entropy"
    }

    fn find(&self, text: &str) -> Vec<Span> {
        let bytes = text.as_bytes();
        let len = bytes.len();
        let mut spans = Vec::new();
        let mut i = 0;
        while i < len {
            if !is_token_byte(bytes[i]) {
                i += 1;
                continue;
            }
            let start = i;
            while i < len && is_token_byte(bytes[i]) {
                i += 1;
            }
            let token = &text[start..i];
            if self.is_secret(token) {
                spans.push(Span::new(start, i, "high-entropy"));
            }
        }
        spans
    }
}

impl EntropyDetector {
    /// A token is treated as a secret only if it clears every conservative gate.
    fn is_secret(&self, token: &str) -> bool {
        token.len() >= self.min_len
            && !is_uuid(token)
            && !is_hex(token)
            && class_count(token) >= MIN_CLASSES
            && shannon_entropy(token) >= self.min_entropy
    }
}

/// Bytes that make up a candidate token: alphanumerics plus the punctuation used
/// by base64/url-safe encodings and common token formats.
fn is_token_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=' | b'_' | b'-')
}

/// True if `s` is a canonical 8-4-4-4-12 hex UUID.
fn is_uuid(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() != 36 {
        return false;
    }
    b.iter().enumerate().all(|(i, &c)| match i {
        8 | 13 | 18 | 23 => c == b'-',
        _ => c.is_ascii_hexdigit(),
    })
}

/// True if every character of a non-empty `s` is a hex digit (any case) — the
/// shape of git SHAs, md5/sha hashes, and many opaque ids.
fn is_hex(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|c| c.is_ascii_hexdigit())
}

/// Count how many of {lowercase, uppercase, digit} appear in `s`.
fn class_count(s: &str) -> usize {
    let mut lower = false;
    let mut upper = false;
    let mut digit = false;
    for c in s.chars() {
        if c.is_ascii_lowercase() {
            lower = true;
        } else if c.is_ascii_uppercase() {
            upper = true;
        } else if c.is_ascii_digit() {
            digit = true;
        }
    }
    lower as usize + upper as usize + digit as usize
}

/// Shannon entropy of `s` in bits per character, computed over its bytes.
/// Empty strings have zero entropy.
pub fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for &b in s.as_bytes() {
        counts[b as usize] += 1;
    }
    let len = s.len() as f64;
    let mut h = 0.0;
    for &c in counts.iter() {
        if c > 0 {
            let p = c as f64 / len;
            h -= p * p.log2();
        }
    }
    h
}

#[cfg(test)]
mod tests {
    use super::*;

    fn close(a: f64, b: f64) -> bool {
        (a - b).abs() < 1e-9
    }

    #[test]
    fn empty_string_has_zero_entropy() {
        assert_eq!(shannon_entropy(""), 0.0);
    }

    #[test]
    fn single_repeated_char_has_zero_entropy() {
        assert_eq!(shannon_entropy("aaaaaa"), 0.0);
    }

    #[test]
    fn four_uniform_chars_have_two_bits() {
        assert!(close(shannon_entropy("abcd"), 2.0));
    }

    #[test]
    fn two_chars_each_half_have_one_bit() {
        assert!(close(shannon_entropy("aabb"), 1.0));
    }

    // --- shape guards ---

    #[test]
    fn recognizes_uuid_shape() {
        assert!(is_uuid("550e8400-e29b-41d4-a716-446655440000"));
        assert!(!is_uuid("not-a-uuid"));
        assert!(!is_uuid("550e8400e29b41d4a716446655440000")); // no dashes
    }

    #[test]
    fn recognizes_hex_strings() {
        assert!(is_hex("9fceb02d0ae598e95dc970b74767f19372d61af8"));
        assert!(is_hex("DEADBEEF"));
        assert!(!is_hex("g9fceb02")); // g is not hex
        assert!(!is_hex(""));
    }

    #[test]
    fn counts_character_classes() {
        assert_eq!(class_count("abcdef"), 1);
        assert_eq!(class_count("abcDEF"), 2);
        assert_eq!(class_count("abcDEF123"), 3);
        assert_eq!(class_count("123456"), 1);
    }

    // --- detector behavior ---

    fn redact(text: &str) -> String {
        let d = EntropyDetector::default();
        crate::span::redact_spans(text, &d.find(text))
    }

    #[test]
    fn flags_high_entropy_mixed_token() {
        let secret = "Xy9aB7cD3eF1gH5jK2mN4pQ6rS8tU0vW";
        assert_eq!(redact(&format!("token {secret} end")), "token [REDACTED:high-entropy] end");
    }

    #[test]
    fn skips_git_sha() {
        let line = "deploy 9fceb02d0ae598e95dc970b74767f19372d61af8 done";
        assert_eq!(redact(line), line);
    }

    #[test]
    fn skips_uuid() {
        let line = "request 550e8400-e29b-41d4-a716-446655440000 ok";
        assert_eq!(redact(line), line);
    }

    #[test]
    fn skips_short_tokens() {
        let line = "code abc123 ref de456f";
        assert_eq!(redact(line), line);
    }

    #[test]
    fn skips_long_single_class_word() {
        let line = "thisisalonglowercasewordwithnodigitsatall";
        assert_eq!(redact(line), line);
    }

    #[test]
    fn skips_ordinary_sentence() {
        let line = "the deployment finished successfully without any errors today";
        assert_eq!(redact(line), line);
    }

    #[test]
    fn skips_two_class_pod_name() {
        // lowercase + digits only: a real k8s pod name must not be redacted.
        let line = "pod nginx-7d8b49557c-x2vfq Running on node-3";
        assert_eq!(redact(line), line);
    }

    #[test]
    fn skips_dashed_hex_traceparent() {
        let line = "trace 00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01";
        assert_eq!(redact(line), line);
    }
}
