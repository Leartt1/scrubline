//! How a detected secret is rendered once masked.

/// The replacement style applied to every redacted span.
#[derive(Debug, Clone)]
pub enum Mask {
    /// `[REDACTED:<kind>]` — labels what kind of secret was found.
    Labeled,
    /// A fixed string (e.g. `********`) that reveals neither the kind nor the
    /// original length.
    Fixed(String),
}

impl Mask {
    /// The text that replaces a span of the given `kind`.
    pub fn render(&self, kind: &str) -> String {
        match self {
            Mask::Labeled => format!("[REDACTED:{kind}]"),
            Mask::Fixed(s) => s.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labeled_includes_the_kind() {
        assert_eq!(Mask::Labeled.render("token"), "[REDACTED:token]");
    }

    #[test]
    fn fixed_ignores_the_kind() {
        assert_eq!(Mask::Fixed("########".into()).render("token"), "########");
    }
}
