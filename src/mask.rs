//! How a detected secret is rendered once masked.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

/// The replacement style applied to every redacted span.
#[derive(Debug, Clone)]
pub enum Mask {
    /// `[REDACTED:<kind>]` — labels what kind of secret was found.
    Labeled,
    /// A fixed string (e.g. `********`) that reveals neither the kind nor the
    /// original length.
    Fixed(String),
    /// `[REDACTED:<kind>:<hash>]` — a short, stable, non-reversible tag so the
    /// same secret can be correlated across a log without exposing its value.
    Hashed,
    /// `****<last 4>` — reveals only the last four characters, like a card
    /// number, for cases where a tail is enough to recognize the value.
    Partial,
}

impl Mask {
    /// The text that replaces a secret of the given `kind` whose original text
    /// is `value`. `value` is ignored by the kind/label styles and used by the
    /// hash and partial styles.
    pub fn render(&self, kind: &str, value: &str) -> String {
        match self {
            Mask::Labeled => format!("[REDACTED:{kind}]"),
            Mask::Fixed(s) => s.clone(),
            Mask::Hashed => format!("[REDACTED:{kind}:{}]", short_hash(value)),
            Mask::Partial => partial(value),
        }
    }
}

/// A short, stable, non-cryptographic correlation tag for `value`. Deterministic
/// across runs of the same binary, so equal secrets render to equal tags.
fn short_hash(value: &str) -> String {
    let mut hasher = DefaultHasher::new();
    value.hash(&mut hasher);
    format!("{:06x}", hasher.finish() & 0xff_ffff)
}

/// `****` followed by the last four characters of `value` (or all of it masked
/// if it is four characters or shorter).
fn partial(value: &str) -> String {
    let chars: Vec<char> = value.chars().collect();
    if chars.len() <= 4 {
        return "*".repeat(chars.len().max(1));
    }
    let tail: String = chars[chars.len() - 4..].iter().collect();
    format!("****{tail}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labeled_includes_the_kind() {
        assert_eq!(
            Mask::Labeled.render("token", "ghp_secret"),
            "[REDACTED:token]"
        );
    }

    #[test]
    fn fixed_ignores_kind_and_value() {
        assert_eq!(
            Mask::Fixed("########".into()).render("token", "ghp_secret"),
            "########"
        );
    }

    #[test]
    fn hashed_is_stable_and_kind_tagged() {
        let a = Mask::Hashed.render("token", "ghp_secret");
        let b = Mask::Hashed.render("token", "ghp_secret");
        let c = Mask::Hashed.render("token", "different");
        assert_eq!(a, b, "same value must hash the same");
        assert_ne!(a, c, "different values should differ");
        assert!(a.starts_with("[REDACTED:token:"));
    }

    #[test]
    fn partial_reveals_last_four() {
        assert_eq!(
            Mask::Partial.render("k", "sk_live_0123456789cdef"),
            "****cdef"
        );
    }

    #[test]
    fn partial_masks_short_values_entirely() {
        assert_eq!(Mask::Partial.render("k", "abc"), "***");
    }
}
