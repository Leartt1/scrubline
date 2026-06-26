//! Claude Code hook mode: strip secrets from tool I/O before the model sees it.
//!
//! Claude Code passes a JSON payload on stdin and reads a JSON response on
//! stdout (processed only on exit 0). We dispatch on `hook_event_name`:
//!
//!   * `PreToolUse`       -> redact strings in `tool_input`, return `updatedInput`
//!   * `PostToolUse`      -> redact the tool result, return `updatedToolOutput`
//!   * `UserPromptSubmit` -> can't rewrite the prompt; warn via `additionalContext`
//!
//! When nothing is redacted we return `{}` so the tool call proceeds untouched.

use serde_json::{Value, json};

use crate::engine::Engine;

/// Process one hook payload (`input` is the raw stdin JSON) and return the JSON
/// response to print on stdout. Never errors: malformed or unknown payloads
/// yield `{}` so we never break the agent's tool call.
pub fn run_hook(engine: &Engine, input: &str) -> String {
    let payload: Value = match serde_json::from_str(input) {
        Ok(v) => v,
        Err(_) => return "{}".to_string(),
    };
    match payload.get("hook_event_name").and_then(Value::as_str) {
        Some("PreToolUse") => handle_pre_tool_use(engine, &payload),
        Some("PostToolUse") => handle_post_tool_use(engine, &payload),
        Some("UserPromptSubmit") => handle_user_prompt_submit(engine, &payload),
        _ => "{}".to_string(),
    }
}

fn handle_pre_tool_use(engine: &Engine, payload: &Value) -> String {
    if let Some(tool_input) = payload.get("tool_input") {
        let mut redacted = tool_input.clone();
        if redact_strings(engine, &mut redacted) {
            return json!({
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "updatedInput": redacted,
                }
            })
            .to_string();
        }
    }
    "{}".to_string()
}

fn handle_post_tool_use(engine: &Engine, payload: &Value) -> String {
    // The result field has varied across versions/tools; accept either name and
    // any shape (string or structured), redacting every string within it.
    let result = payload
        .get("tool_response")
        .or_else(|| payload.get("tool_output"));
    if let Some(result) = result {
        let mut redacted = result.clone();
        if redact_strings(engine, &mut redacted) {
            return json!({
                "hookSpecificOutput": {
                    "hookEventName": "PostToolUse",
                    "updatedToolOutput": redacted,
                }
            })
            .to_string();
        }
    }
    "{}".to_string()
}

fn handle_user_prompt_submit(engine: &Engine, payload: &Value) -> String {
    let text = payload
        .get("prompt")
        .or_else(|| payload.get("user_message"))
        .and_then(Value::as_str)
        .unwrap_or("");
    let redacted = engine.redact_text(text);
    let count = redacted.matches("[REDACTED:").count();
    if count > 0 {
        let msg = format!(
            "scrubline detected {count} potential secret(s) in this prompt. \
             Avoid pasting live credentials, and rotate anything already shared."
        );
        return json!({
            "hookSpecificOutput": {
                "hookEventName": "UserPromptSubmit",
                "additionalContext": msg,
            }
        })
        .to_string();
    }
    "{}".to_string()
}

/// Recursively redact every JSON string within `value` in place. Returns true if
/// anything changed.
fn redact_strings(engine: &Engine, value: &mut Value) -> bool {
    match value {
        Value::String(s) => {
            let cleaned = engine.redact_text(s);
            if cleaned != *s {
                *s = cleaned;
                true
            } else {
                false
            }
        }
        Value::Array(items) => {
            let mut changed = false;
            for v in items.iter_mut() {
                if redact_strings(engine, v) {
                    changed = true;
                }
            }
            changed
        }
        Value::Object(map) => {
            let mut changed = false;
            for (_, v) in map.iter_mut() {
                if redact_strings(engine, v) {
                    changed = true;
                }
            }
            changed
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entropy::EntropyDetector;
    use crate::patterns::PatternDetector;

    fn engine() -> Engine {
        Engine::new(vec![
            Box::new(PatternDetector::default()),
            Box::new(EntropyDetector::default()),
        ])
    }

    fn parse(s: &str) -> Value {
        serde_json::from_str(s).expect("hook output must be valid JSON")
    }

    #[test]
    fn pre_tool_use_redacts_command_into_updated_input() {
        let token = concat!("ghp_", "abcdefghijklmnopqrstuvwxyz0123456789");
        let payload = json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": { "command": format!("git push with {token}") },
        })
        .to_string();

        let v = parse(&run_hook(&engine(), &payload));
        let cmd = v["hookSpecificOutput"]["updatedInput"]["command"]
            .as_str()
            .unwrap();
        assert_eq!(v["hookSpecificOutput"]["hookEventName"], "PreToolUse");
        assert!(cmd.contains("[REDACTED:github-token]"));
        assert!(!cmd.contains(token));
    }

    #[test]
    fn post_tool_use_redacts_result_into_updated_tool_output() {
        let payload = json!({
            "hook_event_name": "PostToolUse",
            "tool_name": "Bash",
            "tool_response": "USER=alice\npassword=leakedpw\nDONE",
        })
        .to_string();

        let v = parse(&run_hook(&engine(), &payload));
        let out = v["hookSpecificOutput"]["updatedToolOutput"]
            .as_str()
            .unwrap();
        assert!(out.contains("[REDACTED:password]"));
        assert!(!out.contains("leakedpw"));
    }

    #[test]
    fn post_tool_use_accepts_tool_output_field_name() {
        let payload = json!({
            "hook_event_name": "PostToolUse",
            "tool_output": "password=leakedpw",
        })
        .to_string();

        let v = parse(&run_hook(&engine(), &payload));
        let out = v["hookSpecificOutput"]["updatedToolOutput"]
            .as_str()
            .unwrap();
        assert!(!out.contains("leakedpw"));
    }

    #[test]
    fn user_prompt_submit_adds_advisory_context_without_rewriting() {
        let token = concat!("ghp_", "abcdefghijklmnopqrstuvwxyz0123456789");
        let payload = json!({
            "hook_event_name": "UserPromptSubmit",
            "prompt": format!("deploy using {token} now"),
        })
        .to_string();

        let v = parse(&run_hook(&engine(), &payload));
        let ctx = v["hookSpecificOutput"]["additionalContext"]
            .as_str()
            .unwrap();
        assert_eq!(v["hookSpecificOutput"]["hookEventName"], "UserPromptSubmit");
        assert!(ctx.contains("secret"));
        // We must NOT claim to rewrite the prompt.
        assert!(v["hookSpecificOutput"].get("updatedInput").is_none());
    }

    #[test]
    fn clean_tool_input_returns_empty_object() {
        let payload = json!({
            "hook_event_name": "PreToolUse",
            "tool_input": { "command": "ls -la /tmp" },
        })
        .to_string();
        assert_eq!(run_hook(&engine(), &payload), "{}");
    }

    #[test]
    fn non_json_input_is_a_safe_noop() {
        assert_eq!(run_hook(&engine(), "this is not json"), "{}");
    }

    #[test]
    fn unknown_event_is_a_safe_noop() {
        let payload = json!({ "hook_event_name": "Notification" }).to_string();
        assert_eq!(run_hook(&engine(), &payload), "{}");
    }
}
