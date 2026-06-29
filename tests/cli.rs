//! End-to-end tests: pipe input through the real compiled binary.

use std::io::Write;
use std::process::{Command, Stdio};

fn run(input: &str) -> String {
    run_with(&[], input)
}

fn run_with(args: &[&str], input: &str) -> String {
    let mut child = Command::new(env!("CARGO_BIN_EXE_scrubline"))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn scrubline");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(input.as_bytes())
        .expect("write stdin");
    let output = child.wait_with_output().expect("wait");
    String::from_utf8(output.stdout).expect("utf8 stdout")
}

#[test]
fn redacts_json_secret_from_stdin() {
    assert_eq!(
        run("{\"token\":\"ghp_X\"}\n"),
        "{\"token\":\"[REDACTED:token]\"}\n"
    );
}

#[test]
fn redacts_logfmt_and_keeps_clean_lines() {
    assert_eq!(
        run("level=info password=hunter2\nplain line\n"),
        "level=info password=[REDACTED:password]\nplain line\n"
    );
}

#[test]
fn preserves_final_line_without_trailing_newline() {
    assert_eq!(run("token=abc"), "token=[REDACTED:token]");
}

#[test]
fn passes_through_a_stream_unchanged_when_clean() {
    let input = "starting up\nlistening on :8080\nrequest ok\n";
    assert_eq!(run(input), input);
}

#[test]
fn redacts_named_pattern_secret_in_free_text() {
    // Split so no contiguous token literal exists in source (secret scanners).
    let token = concat!("ghp_", "abcdefghijklmnopqrstuvwxyz0123456789");
    assert_eq!(
        run(&format!("error: leaked {token} in handler\n")),
        "error: leaked [REDACTED:github-token] in handler\n"
    );
}

#[test]
fn mask_char_replaces_label_with_fixed_mask() {
    assert_eq!(
        run_with(&["--mask-char", "#"], "token=abc\n"),
        "token=########\n"
    );
}

#[test]
fn redacts_high_entropy_token_by_default() {
    let secret = "Xy9aB7cD3eF1gH5jK2mN4pQ6rS8tU0vW";
    assert_eq!(
        run(&format!("api responded {secret}\n")),
        "api responded [REDACTED:high-entropy]\n"
    );
}

#[test]
fn no_entropy_flag_disables_entropy_detection() {
    let secret = "Xy9aB7cD3eF1gH5jK2mN4pQ6rS8tU0vW";
    let line = format!("api responded {secret}\n");
    assert_eq!(run_with(&["--no-entropy"], &line), line);
}

#[test]
fn stats_flag_writes_json_summary_to_stderr() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_scrubline"))
        .arg("--stats")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn scrubline");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"token=abc\nclean line\npassword=secret\n")
        .unwrap();
    let out = child.wait_with_output().unwrap();
    let stdout = String::from_utf8(out.stdout).unwrap();
    let stderr = String::from_utf8(out.stderr).unwrap();

    // The cleaned stream still goes to stdout untouched by the summary.
    assert!(
        stdout.contains("token=[REDACTED:token]"),
        "stdout: {stdout}"
    );
    // The summary goes to stderr as JSON.
    assert!(stderr.contains("\"lines\":3"), "stderr: {stderr}");
    assert!(stderr.contains("\"redactions\":2"), "stderr: {stderr}");
    assert!(stderr.contains("token"), "stderr: {stderr}");
}

#[test]
fn hash_flag_emits_stable_kind_tagged_hash() {
    let out = run_with(&["--hash"], "token=abc\n");
    assert!(out.starts_with("token=[REDACTED:token:"), "got: {out}");
    assert!(out.trim_end().ends_with(']'), "got: {out}");
}

#[test]
fn partial_flag_reveals_last_four() {
    assert_eq!(
        run_with(&["--partial"], "token=abcdef1234\n"),
        "token=****1234\n"
    );
}

#[test]
fn allow_file_suppresses_redaction() {
    let path = format!("{}/allow.txt", env!("CARGO_TARGET_TMPDIR"));
    std::fs::write(&path, "abcdef1234\n").unwrap();
    assert_eq!(
        run_with(&["--allow", &path], "token=abcdef1234\n"),
        "token=abcdef1234\n"
    );
}

#[test]
fn rules_file_adds_custom_patterns() {
    let path = format!("{}/rules.toml", env!("CARGO_TARGET_TMPDIR"));
    std::fs::write(
        &path,
        "[[pattern]]\nkind = \"emp-id\"\nregex = \"EMP[0-9]{6}\"\n",
    )
    .unwrap();
    let out = run_with(&["--rules", &path], "user EMP123456 logged in\n");
    assert_eq!(out, "user [REDACTED:emp-id] logged in\n");
}

#[test]
fn hook_mode_redacts_pre_tool_use_command() {
    let token = concat!("ghp_", "abcdefghijklmnopqrstuvwxyz0123456789");
    let payload =
        format!(r#"{{"hook_event_name":"PreToolUse","tool_input":{{"command":"push {token}"}}}}"#);
    let out = run_with(&["--hook"], &payload);
    assert!(out.contains("updatedInput"), "got: {out}");
    assert!(out.contains("[REDACTED:github-token]"), "got: {out}");
    assert!(!out.contains(token), "token leaked: {out}");
}

#[test]
fn completions_subcommand_emits_a_script() {
    let out = run_with(&["completions", "bash"], "");
    assert!(
        out.contains("scrubline"),
        "expected a completion script, got: {out}"
    );
    assert!(!out.is_empty());
}
