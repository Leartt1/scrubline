//! The per-line redaction pipeline: structured layer first, then value detectors.
//!
//! For each line:
//!   * JSON object/array  -> structurally redact sensitive keys (re-serialized),
//!     then run value detectors over the result.
//!   * everything else     -> collect logfmt sensitive-key value spans plus every
//!     detector's spans, and mask them in one pass (overlaps collapse).

use crate::allowlist::Allowlist;
use crate::detector::Detector;
use crate::json::{redact_json_reported, redact_json_with};
use crate::logfmt;
use crate::mask::Mask;
use crate::span::{Span, redact_spans_reported, redact_spans_with};

/// Holds the configured detectors, mask style, and allowlist, and applies the
/// full redaction pipeline.
pub struct Engine {
    detectors: Vec<Box<dyn Detector>>,
    mask: Mask,
    allow: Allowlist,
}

impl Engine {
    /// Build an engine that masks with `[REDACTED:<kind>]` labels.
    pub fn new(detectors: Vec<Box<dyn Detector>>) -> Self {
        Engine::with_mask(detectors, Mask::Labeled)
    }

    /// Build an engine with a specific mask style.
    pub fn with_mask(detectors: Vec<Box<dyn Detector>>, mask: Mask) -> Self {
        Engine {
            detectors,
            mask,
            allow: Allowlist::default(),
        }
    }

    /// Set an allowlist of values that must never be redacted.
    pub fn with_allowlist(mut self, allow: Allowlist) -> Self {
        self.allow = allow;
        self
    }

    /// Redact a single line, returning the cleaned text (no trailing newline
    /// handling — the caller owns line framing).
    pub fn redact_line(&self, line: &str) -> String {
        if let Some(structured) = redact_json_with(line, &self.mask, &self.allow) {
            let mut spans = self.detector_spans(&structured);
            self.retain_allowed(&structured, &mut spans);
            return redact_spans_with(&structured, &spans, &self.mask);
        }

        let mut spans = logfmt::sensitive_spans(line);
        spans.extend(self.detector_spans(line));
        self.retain_allowed(line, &mut spans);
        redact_spans_with(line, &spans, &self.mask)
    }

    /// Redact a single line and report the kind of every redaction applied (for
    /// `--stats`). Same pipeline as [`Engine::redact_line`].
    pub fn redact_line_report(&self, line: &str) -> (String, Vec<String>) {
        if let Some((structured, mut kinds)) = redact_json_reported(line, &self.mask, &self.allow) {
            let mut spans = self.detector_spans(&structured);
            self.retain_allowed(&structured, &mut spans);
            let (out, more) = redact_spans_reported(&structured, &spans, &self.mask);
            kinds.extend(more);
            return (out, kinds);
        }

        let mut spans = logfmt::sensitive_spans(line);
        spans.extend(self.detector_spans(line));
        self.retain_allowed(line, &mut spans);
        redact_spans_reported(line, &spans, &self.mask)
    }

    /// Drop any span whose matched text is allowlisted, so it is left untouched.
    fn retain_allowed(&self, text: &str, spans: &mut Vec<Span>) {
        if self.allow.is_empty() {
            return;
        }
        spans.retain(|s| !self.allow.is_allowed(&text[s.start..s.end]));
    }

    /// Redact a possibly multi-line `text`, preserving `\n` line breaks. Used by
    /// the hook integration, where a single field (a command, tool output) can
    /// span several lines.
    pub fn redact_text(&self, text: &str) -> String {
        text.split('\n')
            .map(|line| self.redact_line(line))
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn detector_spans(&self, text: &str) -> Vec<Span> {
        self.detectors.iter().flat_map(|d| d.find(text)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detector::LiteralDetector;
    use crate::patterns::PatternDetector;

    fn engine_with(detectors: Vec<Box<dyn Detector>>) -> Engine {
        Engine::new(detectors)
    }

    #[test]
    fn structurally_redacts_json_without_detectors() {
        let e = engine_with(vec![]);
        assert_eq!(
            e.redact_line(r#"{"token":"x"}"#),
            r#"{"token":"[REDACTED:token]"}"#
        );
    }

    #[test]
    fn structurally_redacts_logfmt_without_detectors() {
        let e = engine_with(vec![]);
        assert_eq!(
            e.redact_line("level=info token=abc"),
            "level=info token=[REDACTED:token]"
        );
    }

    #[test]
    fn applies_detectors_on_plaintext() {
        let e = engine_with(vec![Box::new(LiteralDetector::new(
            "ghp_SECRET",
            "github-token",
        ))]);
        assert_eq!(
            e.redact_line("see ghp_SECRET here"),
            "see [REDACTED:github-token] here"
        );
    }

    #[test]
    fn applies_detectors_inside_json_non_sensitive_values() {
        let e = engine_with(vec![Box::new(LiteralDetector::new(
            "ghp_SECRET",
            "github-token",
        ))]);
        assert_eq!(
            e.redact_line(r#"{"msg":"ghp_SECRET"}"#),
            r#"{"msg":"[REDACTED:github-token]"}"#
        );
    }

    #[test]
    fn structured_span_wins_when_it_overlaps_a_detector() {
        let e = engine_with(vec![Box::new(LiteralDetector::new(
            "ghp_SECRET",
            "github-token",
        ))]);
        assert_eq!(e.redact_line("token=ghp_SECRET"), "token=[REDACTED:token]");
    }

    #[test]
    fn leaves_clean_lines_unchanged() {
        let e = engine_with(vec![Box::new(LiteralDetector::new(
            "ghp_SECRET",
            "github-token",
        ))]);
        assert_eq!(e.redact_line("all good here"), "all good here");
    }

    #[test]
    fn allowlist_suppresses_matching_detector_span() {
        let allow = crate::allowlist::parse_allowlist("ghp_SECRET").unwrap();
        let e = Engine::new(vec![Box::new(LiteralDetector::new(
            "ghp_SECRET",
            "github-token",
        ))])
        .with_allowlist(allow);
        assert_eq!(e.redact_line("see ghp_SECRET here"), "see ghp_SECRET here");
    }

    #[test]
    fn allowlist_suppresses_json_value_but_not_others() {
        let allow = crate::allowlist::parse_allowlist("public-value").unwrap();
        let e = Engine::new(vec![]).with_allowlist(allow);
        assert_eq!(
            e.redact_line(r#"{"token":"public-value"}"#),
            r#"{"token":"public-value"}"#
        );
        assert_eq!(
            e.redact_line(r#"{"token":"secret-value"}"#),
            r#"{"token":"[REDACTED:token]"}"#
        );
    }

    #[test]
    fn reports_kinds_from_both_layers() {
        let e = Engine::new(vec![Box::new(PatternDetector::default())]);
        // structured key (authorization) + a value detector hit (aws key)
        let line = "{\"authorization\":\"x\",\"note\":\"AKIAIOSFODNN7EXAMPLE\"}";
        let (_, kinds) = e.redact_line_report(line);
        assert!(kinds.contains(&"authorization".to_string()));
        assert!(kinds.contains(&"aws-access-key".to_string()));
    }

    #[test]
    fn redact_text_redacts_each_line_preserving_breaks() {
        let e = Engine::new(vec![]);
        let input = "user=bob\npassword=secret\nall good";
        assert_eq!(
            e.redact_text(input),
            "user=bob\npassword=[REDACTED:password]\nall good"
        );
    }

    #[test]
    fn applies_mask_style_across_json_and_logfmt() {
        let e = Engine::with_mask(vec![], Mask::Fixed("##".into()));
        assert_eq!(e.redact_line("{\"token\":\"x\"}"), "{\"token\":\"##\"}");
        assert_eq!(e.redact_line("password=secret"), "password=##");
    }
}
