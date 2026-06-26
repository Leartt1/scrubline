//! Byte-span based redaction: turn detected sensitive regions into masked text.

use crate::mask::Mask;

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
        Span {
            start,
            end,
            kind: kind.into(),
        }
    }
}

/// Replace every span in `text` with `[REDACTED:<kind>]`, leaving the rest intact.
pub fn redact_spans(text: &str, spans: &[Span]) -> String {
    redact_spans_with(text, spans, &Mask::Labeled)
}

/// Replace every span in `text` using `mask`, leaving the rest intact.
///
/// Spans may arrive in any order. Overlapping (or touching) spans are merged
/// into their **union** and masked once, labeled with the earliest-starting
/// span's kind. Merging — rather than dropping later spans — guarantees that no
/// part of a secret can leak when two detectors flag overlapping regions.
pub fn redact_spans_with(text: &str, spans: &[Span], mask: &Mask) -> String {
    redact_spans_reported(text, spans, mask).0
}

/// Like [`redact_spans_with`], but also returns the kind label of each masked
/// group (one per redaction emitted), for `--stats` accounting.
pub fn redact_spans_reported(text: &str, spans: &[Span], mask: &Mask) -> (String, Vec<String>) {
    if spans.is_empty() {
        return (text.to_string(), Vec::new());
    }
    let mut ordered: Vec<&Span> = spans.iter().collect();
    ordered.sort_by_key(|s| (s.start, s.end));

    let mut out = String::with_capacity(text.len());
    let mut kinds = Vec::new();
    let mut cursor = 0usize;
    let mut i = 0;
    while i < ordered.len() {
        let span = ordered[i];
        if span.end <= cursor {
            // Fully inside a region we already masked.
            i += 1;
            continue;
        }
        let group_start = span.start.max(cursor);
        let kind = &span.kind; // earliest-starting span owns the label
        let mut group_end = span.end;
        let mut j = i + 1;
        while j < ordered.len() && ordered[j].start <= group_end {
            group_end = group_end.max(ordered[j].end);
            j += 1;
        }
        out.push_str(&text[cursor..group_start]);
        out.push_str(&mask.render(kind));
        kinds.push(kind.clone());
        cursor = group_end;
        i = j;
    }
    out.push_str(&text[cursor..]);
    (out, kinds)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replaces_single_span_with_kind_marker() {
        let text = "token=ghp_ABC123 ok";
        let spans = vec![Span::new(6, 16, "github-token")];
        assert_eq!(
            redact_spans(text, &spans),
            "token=[REDACTED:github-token] ok"
        );
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
        let spans = vec![Span::new(0, 11, "wide"), Span::new(3, 8, "inner")];
        assert_eq!(redact_spans(text, &spans), "[REDACTED:wide] tail");
    }

    #[test]
    fn merges_overlapping_spans_into_their_union() {
        // The second span starts inside the first but extends past it; the tail
        // must not leak.
        let text = "0123456789 rest";
        let spans = vec![Span::new(0, 5, "a"), Span::new(3, 10, "b")];
        assert_eq!(redact_spans(text, &spans), "[REDACTED:a] rest");
    }

    #[test]
    fn reports_one_kind_per_masked_group() {
        let text = "a=ghp_AAA b=AKIAZZZ";
        let spans = vec![
            Span::new(2, 9, "github-token"),
            Span::new(12, 19, "aws-key"),
        ];
        let (_, kinds) = redact_spans_reported(text, &spans, &Mask::Labeled);
        assert_eq!(
            kinds,
            vec!["github-token".to_string(), "aws-key".to_string()]
        );
    }

    #[test]
    fn applies_a_fixed_mask_when_requested() {
        let text = "token=ghp_ABC123 ok";
        let spans = vec![Span::new(6, 16, "github-token")];
        assert_eq!(
            redact_spans_with(text, &spans, &Mask::Fixed("####".into())),
            "token=#### ok"
        );
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
