//! User defaults from a scrubline config file.
//!
//! Loaded from `$SCRUBLINE_CONFIG`, else `$XDG_CONFIG_HOME/scrubline/config.toml`,
//! else `~/.config/scrubline/config.toml`. Every field is optional, and CLI
//! flags always override the config.
//!
//! ```toml
//! no_entropy = false
//! mask = "hash"            # labeled | hash | partial
//! rules = "team-rules.toml"
//! allow = "allowlist.txt"
//! keys = ["x-internal-token"]
//! ```

use std::path::PathBuf;

use serde::Deserialize;

/// Parsed config-file defaults. Absent fields are `None`/empty.
#[derive(Debug, Default, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AppConfig {
    pub no_entropy: Option<bool>,
    pub mask: Option<String>,
    pub rules: Option<PathBuf>,
    pub allow: Option<PathBuf>,
    #[serde(default)]
    pub keys: Vec<String>,
}

/// Parse a config document, returning a readable error on invalid TOML or an
/// unknown key.
pub fn parse_config(toml_src: &str) -> Result<AppConfig, String> {
    toml::from_str(toml_src).map_err(|e| format!("invalid config file: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_all_fields() {
        let src = r#"
            no_entropy = true
            mask = "hash"
            rules = "r.toml"
            allow = "a.txt"
            keys = ["x-internal"]
        "#;
        let c = parse_config(src).unwrap();
        assert_eq!(c.no_entropy, Some(true));
        assert_eq!(c.mask.as_deref(), Some("hash"));
        assert_eq!(c.rules, Some(PathBuf::from("r.toml")));
        assert_eq!(c.allow, Some(PathBuf::from("a.txt")));
        assert_eq!(c.keys, vec!["x-internal"]);
    }

    #[test]
    fn empty_config_is_all_defaults() {
        assert_eq!(parse_config("").unwrap(), AppConfig::default());
    }

    #[test]
    fn rejects_unknown_keys() {
        assert!(parse_config("nope = true").is_err());
    }

    #[test]
    fn rejects_invalid_toml() {
        assert!(parse_config("mask = ").is_err());
    }
}
