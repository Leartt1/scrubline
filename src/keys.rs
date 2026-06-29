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
    "private_token",
    "cookie",
    "set_cookie",
    "session",
    "sessionid",
    "session_token",
    "auth_token",
    "x_auth_token",
    "api_token",
    "db_password",
    "secret_key",
    "access_key",
    "credentials",
];

/// True if `key` names a built-in sensitive field. Matching ignores surrounding
/// whitespace and case, and treats `-` and `_` as the same character, so
/// `api-key`, `api_key`, and `API_KEY` all match.
pub fn is_sensitive_key(key: &str) -> bool {
    let norm = normalize(key);
    SENSITIVE_KEYS.iter().any(|k| *k == norm)
}

fn normalize(key: &str) -> String {
    key.trim().to_ascii_lowercase().replace('-', "_")
}

/// The set of sensitive field names: the built-ins plus any user-supplied extras
/// (from a `--rules` file or config). Used by the structured (JSON/logfmt)
/// redaction layers.
#[derive(Default)]
pub struct KeySet {
    extra: std::collections::HashSet<String>,
}

impl KeySet {
    /// Build from extra key names (normalized the same way as the built-ins).
    pub fn with_extra(keys: impl IntoIterator<Item = String>) -> Self {
        KeySet {
            extra: keys.into_iter().map(|k| normalize(&k)).collect(),
        }
    }

    /// True if `key` is sensitive — a built-in or a user-supplied extra.
    pub fn is_sensitive(&self, key: &str) -> bool {
        is_sensitive_key(key) || self.extra.contains(&normalize(key))
    }
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

    #[test]
    fn keyset_matches_builtins_and_extras() {
        let ks = KeySet::with_extra(["x-internal-token".to_string(), "vault_secret".to_string()]);
        assert!(ks.is_sensitive("password")); // built-in
        assert!(ks.is_sensitive("X-Internal-Token")); // extra, case/hyphen-insensitive
        assert!(ks.is_sensitive("vault-secret"));
        assert!(!ks.is_sensitive("user"));
    }

    #[test]
    fn default_keyset_has_only_builtins() {
        let ks = KeySet::default();
        assert!(ks.is_sensitive("token"));
        assert!(!ks.is_sensitive("x-internal-token"));
    }

    #[test]
    fn matches_expanded_sensitive_keys() {
        for key in [
            "session_token",
            "auth_token",
            "db_password",
            "secret_key",
            "access_key",
            "private_token",
            "x-auth-token",
            "api_token",
        ] {
            assert!(is_sensitive_key(key), "expected '{key}' to be sensitive");
        }
    }
}
