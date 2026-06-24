//! Byte-span based redaction: turn detected sensitive regions into masked text.

/// A region of the input flagged as sensitive, identified by byte offsets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Span {
    /// Inclusive start byte offset into the source line.
    pub start: usize,
    /// Exclusive end byte offset into the source line.
    pub end: usize,
    /// What kind of secret this is (e.g. `"github-token"`), shown in the marker.
    pub kind: String,
}

impl Span {
    pub fn new(start: usize, end: usize, kind: impl Into<String>) -> Self {
        Span { start, end, kind: kind.into() }
    }
}

/// Replace every span in `text` with `[REDACTED:<kind>]`, leaving the rest intact.
///
/// Spans may arrive in any order; overlapping spans are collapsed (the earliest
/// start wins, later overlapping spans are dropped) so the output is never
/// double-masked or corrupted.
pub fn redact_spans(text: &str, spans: &[Span]) -> String {
    if spans.is_empty() {
        return text.to_string();
    }
    let mut ordered: Vec<&Span> = spans.iter().collect();
    ordered.sort_by_key(|s| (s.start, s.end));

    let mut out = String::with_capacity(text.len());
    let mut cursor = 0usize;
    for span in ordered {
        if span.start < cursor {
            // Overlaps a region we already redacted; skip it.
            continue;
        }
        out.push_str(&text[cursor..span.start]);
        out.push_str("[REDACTED:");
        out.push_str(&span.kind);
        out.push(']');
        cursor = span.end;
    }
    out.push_str(&text[cursor..]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replaces_single_span_with_kind_marker() {
        let text = "token=ghp_ABC123 ok";
        let spans = vec![Span::new(6, 16, "github-token")];
        assert_eq!(redact_spans(text, &spans), "token=[REDACTED:github-token] ok");
    }

    #[test]
    fn passes_text_through_unchanged_when_no_spans() {
        let text = "nothing secret here";
        assert_eq!(redact_spans(text, &[]), text);
    }

    #[test]
    fn replaces_multiple_spans_in_one_line() {
        let text = "a=ghp_AAA b=AKIAZZZ";
        let spans = vec![
            Span::new(2, 9, "github-token"),
            Span::new(12, 19, "aws-key"),
        ];
        assert_eq!(
            redact_spans(text, &spans),
            "a=[REDACTED:github-token] b=[REDACTED:aws-key]"
        );
    }

    #[test]
    fn accepts_spans_in_any_order() {
        let text = "a=ghp_AAA b=AKIAZZZ";
        let spans = vec![
            Span::new(12, 19, "aws-key"),
            Span::new(2, 9, "github-token"),
        ];
        assert_eq!(
            redact_spans(text, &spans),
            "a=[REDACTED:github-token] b=[REDACTED:aws-key]"
        );
    }

    #[test]
    fn collapses_overlapping_spans_keeping_first() {
        let text = "secretvalue tail";
        let spans = vec![
            Span::new(0, 11, "wide"),
            Span::new(3, 8, "inner"),
        ];
        assert_eq!(redact_spans(text, &spans), "[REDACTED:wide] tail");
    }

    #[test]
    fn respects_utf8_byte_boundaries() {
        // "héllo " is 7 bytes (é = 2 bytes), token starts at byte 7.
        let text = "héllo ghp_SECRET!";
        let start = text.find("ghp_").unwrap();
        let end = start + "ghp_SECRET".len();
        let spans = vec![Span::new(start, end, "github-token")];
        assert_eq!(redact_spans(text, &spans), "héllo [REDACTED:github-token]!");
    }
}
