//! The per-line redaction pipeline: structured layer first, then value detectors.
//!
//! For each line:
//!   * JSON object/array  -> structurally redact sensitive keys (re-serialized),
//!     then run value detectors over the result.
//!   * everything else     -> collect logfmt sensitive-key value spans plus every
//!     detector's spans, and mask them in one pass (overlaps collapse).

use crate::detector::Detector;
use crate::json::redact_json_with;
use crate::logfmt;
use crate::mask::Mask;
use crate::span::{Span, redact_spans_with};

/// Holds the configured detectors and mask style, and applies the full
/// redaction pipeline.
pub struct Engine {
    detectors: Vec<Box<dyn Detector>>,
    mask: Mask,
}

impl Engine {
    /// Build an engine that masks with `[REDACTED:<kind>]` labels.
    pub fn new(detectors: Vec<Box<dyn Detector>>) -> Self {
        Engine::with_mask(detectors, Mask::Labeled)
    }

    /// Build an engine with a specific mask style.
    pub fn with_mask(detectors: Vec<Box<dyn Detector>>, mask: Mask) -> Self {
        Engine { detectors, mask }
    }

    /// Redact a single line, returning the cleaned text (no trailing newline
    /// handling — the caller owns line framing).
    pub fn redact_line(&self, line: &str) -> String {
        if let Some(structured) = redact_json_with(line, &self.mask) {
            let spans = self.detector_spans(&structured);
            return redact_spans_with(&structured, &spans, &self.mask);
        }

        let mut spans = logfmt::sensitive_spans(line);
        spans.extend(self.detector_spans(line));
        redact_spans_with(line, &spans, &self.mask)
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
        assert_eq!(e.redact_line("level=info token=abc"), "level=info token=[REDACTED:token]");
    }

    #[test]
    fn applies_detectors_on_plaintext() {
        let e = engine_with(vec![Box::new(LiteralDetector::new("ghp_SECRET", "github-token"))]);
        assert_eq!(e.redact_line("see ghp_SECRET here"), "see [REDACTED:github-token] here");
    }

    #[test]
    fn applies_detectors_inside_json_non_sensitive_values() {
        let e = engine_with(vec![Box::new(LiteralDetector::new("ghp_SECRET", "github-token"))]);
        assert_eq!(
            e.redact_line(r#"{"msg":"ghp_SECRET"}"#),
            r#"{"msg":"[REDACTED:github-token]"}"#
        );
    }

    #[test]
    fn structured_span_wins_when_it_overlaps_a_detector() {
        let e = engine_with(vec![Box::new(LiteralDetector::new("ghp_SECRET", "github-token"))]);
        assert_eq!(e.redact_line("token=ghp_SECRET"), "token=[REDACTED:token]");
    }

    #[test]
    fn leaves_clean_lines_unchanged() {
        let e = engine_with(vec![Box::new(LiteralDetector::new("ghp_SECRET", "github-token"))]);
        assert_eq!(e.redact_line("all good here"), "all good here");
    }

    #[test]
    fn redact_text_redacts_each_line_preserving_breaks() {
        let e = Engine::new(vec![]);
        let input = "user=bob\npassword=secret\nall good";
        assert_eq!(e.redact_text(input), "user=bob\npassword=[REDACTED:password]\nall good");
    }

    #[test]
    fn applies_mask_style_across_json_and_logfmt() {
        let e = Engine::with_mask(vec![], Mask::Fixed("##".into()));
        assert_eq!(e.redact_line("{\"token\":\"x\"}"), "{\"token\":\"##\"}");
        assert_eq!(e.redact_line("password=secret"), "password=##");
    }
}
