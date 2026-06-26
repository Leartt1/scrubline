//! The detection plug point: anything that can find sensitive spans in a line.

use crate::span::Span;

/// A value-level secret detector. Given a line of text, report every byte-range
/// that looks sensitive. Implementors are the named-pattern detectors (Day 2)
/// and the entropy detector (Day 3); the engine runs them all over each line.
pub trait Detector: Send + Sync {
    /// Stable identifier shown in the redaction marker (e.g. `"github-token"`).
    fn kind(&self) -> &str;

    /// Return every sensitive span found in `text`, in order of appearance.
    fn find(&self, text: &str) -> Vec<Span>;
}

/// Finds every occurrence of a fixed literal. Used to exercise the engine before
/// the real pattern detectors exist; also handy for user-supplied exact strings.
pub struct LiteralDetector {
    needle: String,
    kind: String,
}

impl LiteralDetector {
    pub fn new(needle: impl Into<String>, kind: impl Into<String>) -> Self {
        LiteralDetector {
            needle: needle.into(),
            kind: kind.into(),
        }
    }
}

impl Detector for LiteralDetector {
    fn kind(&self) -> &str {
        &self.kind
    }

    fn find(&self, text: &str) -> Vec<Span> {
        if self.needle.is_empty() {
            return Vec::new();
        }
        text.match_indices(&self.needle)
            .map(|(start, m)| Span::new(start, start + m.len(), self.kind.clone()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_every_occurrence_of_the_literal() {
        let d = LiteralDetector::new("SECRET", "test-secret");
        let spans = d.find("a SECRET and SECRET");
        assert_eq!(
            spans,
            vec![
                Span::new(2, 8, "test-secret"),
                Span::new(13, 19, "test-secret"),
            ]
        );
    }

    #[test]
    fn finds_nothing_when_absent() {
        let d = LiteralDetector::new("SECRET", "test-secret");
        assert_eq!(d.find("all clear here"), Vec::<Span>::new());
    }
}
