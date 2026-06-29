//! Structured redaction for JSON log lines.
//!
//! serde_json doesn't expose byte offsets, so (unlike the logfmt layer) this
//! parses the line, walks it, replaces the value of any sensitive key with a
//! marker string, and re-serializes. `preserve_order` keeps the original field
//! order so the line stays recognizable.

use crate::allowlist::Allowlist;
use crate::keys::KeySet;
use crate::mask::Mask;
use serde_json::Value;

/// If `line` is a JSON object or array, return it with sensitive values masked
/// with a `[REDACTED:<key>]` label. `None` for non-JSON lines.
pub fn redact_json(line: &str) -> Option<String> {
    redact_json_with(line, &Mask::Labeled, &Allowlist::default(), &KeySet::default())
}

/// If `line` is a JSON object or array, return it with every sensitive value
/// masked using `mask` (skipping allowlisted values). Returns `None` for
/// anything that isn't a JSON object/array so plain text and logfmt fall through
/// to other layers untouched.
pub fn redact_json_with(
    line: &str,
    mask: &Mask,
    allow: &Allowlist,
    keys: &KeySet,
) -> Option<String> {
    redact_json_reported(line, mask, allow, keys).map(|(out, _)| out)
}

/// Like [`redact_json_with`], but also returns the kind (lowercased key) of each
/// value masked, for `--stats` accounting.
pub fn redact_json_reported(
    line: &str,
    mask: &Mask,
    allow: &Allowlist,
    keys: &KeySet,
) -> Option<(String, Vec<String>)> {
    let trimmed = line.trim();
    // Only objects/arrays — never mask a bare scalar line like `42` or `true`.
    if !(trimmed.starts_with('{') || trimmed.starts_with('[')) {
        return None;
    }
    let mut value: Value = serde_json::from_str(trimmed).ok()?;
    let mut kinds = Vec::new();
    redact_value(&mut value, mask, allow, keys, &mut kinds);
    let out = serde_json::to_string(&value).ok()?;
    Some((out, kinds))
}

/// Walk `value`; when a key is sensitive, replace its entire value subtree with
/// a marker so nested secrets can't leak. Records each masked key in `kinds`.
fn redact_value(
    value: &mut Value,
    mask: &Mask,
    allow: &Allowlist,
    keys: &KeySet,
    kinds: &mut Vec<String>,
) {
    match value {
        Value::Object(map) => {
            for (key, child) in map.iter_mut() {
                if keys.is_sensitive(key) {
                    let value_str = match &*child {
                        Value::String(s) => s.clone(),
                        other => other.to_string(),
                    };
                    if allow.is_allowed(&value_str) {
                        continue; // explicitly allowlisted — leave it alone
                    }
                    let kind = key.to_ascii_lowercase();
                    *child = Value::String(mask.render(&kind, &value_str));
                    kinds.push(kind);
                } else {
                    redact_value(child, mask, allow, keys, kinds);
                }
            }
        }
        Value::Array(items) => {
            for item in items.iter_mut() {
                redact_value(item, mask, allow, keys, kinds);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn masks_sensitive_value_in_flat_object() {
        assert_eq!(
            redact_json(r#"{"user":"bob","token":"ghp_X"}"#).unwrap(),
            r#"{"user":"bob","token":"[REDACTED:token]"}"#
        );
    }

    #[test]
    fn masks_whole_subtree_under_sensitive_key() {
        assert_eq!(
            redact_json(r#"{"credentials":{"u":"a","p":"b"}}"#).unwrap(),
            r#"{"credentials":"[REDACTED:credentials]"}"#
        );
    }

    #[test]
    fn recurses_into_non_sensitive_objects() {
        assert_eq!(
            redact_json(r#"{"data":{"password":"x"}}"#).unwrap(),
            r#"{"data":{"password":"[REDACTED:password]"}}"#
        );
    }

    #[test]
    fn handles_arrays_of_objects() {
        assert_eq!(
            redact_json(r#"[{"token":"a"},{"token":"b"}]"#).unwrap(),
            r#"[{"token":"[REDACTED:token]"},{"token":"[REDACTED:token]"}]"#
        );
    }

    #[test]
    fn masks_non_string_sensitive_values() {
        assert_eq!(
            redact_json(r#"{"password":1234}"#).unwrap(),
            r#"{"password":"[REDACTED:password]"}"#
        );
    }

    #[test]
    fn preserves_field_order_and_key_case() {
        assert_eq!(
            redact_json(r#"{"Authorization":"Bearer x","z":1}"#).unwrap(),
            r#"{"Authorization":"[REDACTED:authorization]","z":1}"#
        );
    }

    #[test]
    fn returns_none_for_plain_text() {
        assert_eq!(redact_json("just some words"), None);
        assert_eq!(redact_json("level=info msg=ok"), None);
    }

    #[test]
    fn returns_none_for_invalid_json() {
        assert_eq!(redact_json(r#"{"a":}"#), None);
    }
}
