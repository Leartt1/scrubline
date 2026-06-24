//! Shared set of sensitive field names for structured (JSON/logfmt) redaction.
//!
//! This is the heart of scrubline's wedge: instead of guessing from a value's
//! shape, we redact the VALUE of any field whose NAME is sensitive — so a
//! plain-looking password or an opaque session id is masked just as reliably as
//! a token with a recognizable prefix.

/// Field names whose value is always redacted, regardless of the value's shape.
/// Compared case-insensitively with `-`/`_` treated as equivalent.
pub const SENSITIVE_KEYS: &[&str] = &[
    "authorization",
    "auth",
    "password",
    "passwd",
    "pwd",
    "secret",
    "client_secret",
    "token",
    "access_token",
    "refresh_token",
    "id_token",
    "api_key",
    "apikey",
    "x_api_key",
    "private_key",
    "cookie",
    "set_cookie",
    "session",
    "sessionid",
    "credentials",
];

/// True if `key` names a sensitive field. Matching ignores surrounding
/// whitespace and case, and treats `-` and `_` as the same character, so
/// `api-key`, `api_key`, and `API_KEY` all match.
pub fn is_sensitive_key(key: &str) -> bool {
    let norm = normalize(key);
    SENSITIVE_KEYS.iter().any(|k| *k == norm)
}

fn normalize(key: &str) -> String {
    key.trim().to_ascii_lowercase().replace('-', "_")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_known_keys_case_insensitively() {
        assert!(is_sensitive_key("Authorization"));
        assert!(is_sensitive_key("PASSWORD"));
        assert!(is_sensitive_key("token"));
    }

    #[test]
    fn treats_hyphen_and_underscore_as_equivalent() {
        assert!(is_sensitive_key("api-key"));
        assert!(is_sensitive_key("api_key"));
        assert!(is_sensitive_key("X-API-Key"));
        assert!(is_sensitive_key("set-cookie"));
    }

    #[test]
    fn ignores_surrounding_whitespace() {
        assert!(is_sensitive_key("  secret  "));
    }

    #[test]
    fn rejects_non_sensitive_keys() {
        assert!(!is_sensitive_key("email"));
        assert!(!is_sensitive_key("user"));
        assert!(!is_sensitive_key("status"));
    }
}
