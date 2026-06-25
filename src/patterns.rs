//! Named-pattern detectors: secrets with a recognizable shape.
//!
//! Each entry is a `(kind, regex)` pair. Patterns are deliberately
//! prefix-anchored or structurally distinctive (a token prefix, a PEM header, a
//! credentialed URI) so they fire on real secrets and stay quiet on ordinary
//! log noise like UUIDs and git SHAs. Unstructured high-entropy tokens are the
//! entropy detector's job (day 3), not these.

use regex::Regex;

use crate::detector::Detector;
use crate::span::Span;

/// Runs a set of named regex patterns over each line.
pub struct PatternDetector {
    patterns: Vec<(&'static str, Regex)>,
}

impl PatternDetector {
    pub fn new(patterns: Vec<(&'static str, Regex)>) -> Self {
        PatternDetector { patterns }
    }
}

impl Default for PatternDetector {
    fn default() -> Self {
        PatternDetector::new(default_patterns())
    }
}

impl Detector for PatternDetector {
    fn kind(&self) -> &str {
        "named-pattern"
    }

    fn find(&self, text: &str) -> Vec<Span> {
        let mut spans = Vec::new();
        for (kind, re) in &self.patterns {
            for m in re.find_iter(text) {
                spans.push(Span::new(m.start(), m.end(), *kind));
            }
        }
        spans
    }
}

/// The built-in named-secret patterns. Each kind names what was found; the
/// regex must match the full secret so the whole thing is masked.
pub fn default_patterns() -> Vec<(&'static str, Regex)> {
    let raw: &[(&str, &str)] = &[
        ("aws-access-key", r"(?:AKIA|ASIA)[A-Z0-9]{16}"),
        ("github-token", r"gh[pousr]_[A-Za-z0-9]{36,255}"),
        ("gitlab-pat", r"glpat-[A-Za-z0-9_-]{20,}"),
        ("slack-token", r"xox[baprs]-[A-Za-z0-9-]{10,}"),
        ("stripe-key", r"[sr]k_(?:live|test)_[A-Za-z0-9]{10,}"),
        ("google-api-key", r"AIza[A-Za-z0-9_-]{35}"),
        ("jwt", r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*"),
        ("private-key", r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"),
        ("credential-uri", r"[a-zA-Z][a-zA-Z0-9+.-]*://[^:@\s/]*:[^@\s/]+@\S+"),
        ("email", r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
    ];
    raw.iter()
        .map(|(kind, pat)| (*kind, Regex::new(pat).expect("built-in pattern must compile")))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::span::redact_spans;

    fn redact(text: &str) -> String {
        let d = PatternDetector::default();
        redact_spans(text, &d.find(text))
    }

    // Test fixtures split each token prefix from its body via concat!(), so no
    // contiguous secret-shaped literal exists in the source for GitHub's secret
    // scanner to flag. The compiler rejoins them, so the detectors see the real
    // shape.

    #[test]
    fn masks_aws_access_key() {
        let key = concat!("AKIA", "IOSFODNN7EXAMPLE");
        assert_eq!(redact(&format!("key {key} end")), "key [REDACTED:aws-access-key] end");
    }

    #[test]
    fn masks_github_token() {
        let token = concat!("ghp_", "abcdefghijklmnopqrstuvwxyz0123456789");
        assert_eq!(redact(token), "[REDACTED:github-token]");
    }

    #[test]
    fn masks_gitlab_pat() {
        let pat = concat!("glpat", "-abcdefghij0123456789");
        assert_eq!(redact(pat), "[REDACTED:gitlab-pat]");
    }

    #[test]
    fn masks_slack_token() {
        let token = concat!("xoxb", "-0123456789abcd");
        assert_eq!(redact(token), "[REDACTED:slack-token]");
    }

    #[test]
    fn masks_stripe_key() {
        let key = concat!("sk_", "live_0123456789abc");
        assert_eq!(redact(key), "[REDACTED:stripe-key]");
    }

    #[test]
    fn masks_google_api_key() {
        let key = concat!("AIza", "abcdefghijklmnopqrstuvwxyz012345678");
        assert_eq!(redact(key), "[REDACTED:google-api-key]");
    }

    #[test]
    fn masks_jwt() {
        let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
        assert_eq!(redact(&format!("token={jwt}")), "token=[REDACTED:jwt]");
    }

    #[test]
    fn masks_pem_private_key_header() {
        assert_eq!(redact("-----BEGIN RSA PRIVATE KEY-----"), "[REDACTED:private-key]");
    }

    #[test]
    fn masks_credentialed_uri() {
        assert_eq!(
            redact("dsn postgres://admin:s3cr3t@db.internal/app ok"),
            "dsn [REDACTED:credential-uri] ok"
        );
    }

    #[test]
    fn masks_email() {
        assert_eq!(redact("from alice@example.com today"), "from [REDACTED:email] today");
    }

    #[test]
    fn leaves_uuid_untouched() {
        let line = "request 550e8400-e29b-41d4-a716-446655440000 done";
        assert_eq!(redact(line), line);
    }

    #[test]
    fn leaves_git_sha_untouched() {
        let line = "deploy 9fceb02d0ae598e95dc970b74767f19372d61af8";
        assert_eq!(redact(line), line);
    }

    #[test]
    fn leaves_plain_text_untouched() {
        let line = "deploy finished in 4.2s, 0 errors";
        assert_eq!(redact(line), line);
    }
}
