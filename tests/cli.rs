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

fn run_env(envs: &[(&str, &str)], args: &[&str], input: &str) -> String {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_scrubline"));
    cmd.args(args);
    for (k, v) in envs {
        cmd.env(k, v);
    }
    let mut child = cmd
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
    String::from_utf8(child.wait_with_output().expect("wait").stdout).expect("utf8")
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

fn run_status(args: &[&str], input: &str) -> (String, i32) {
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
    let out = child.wait_with_output().expect("wait");
    (
        String::from_utf8(out.stdout).expect("utf8"),
        out.status.code().unwrap_or(-1),
    )
}

#[test]
fn fail_on_match_exits_2_when_secret_found() {
    let (stdout, code) = run_status(&["--fail-on-match"], "token=abc\nclean\n");
    // The cleaned stream is still produced...
    assert_eq!(stdout, "token=[REDACTED:token]\nclean\n");
    // ...but the exit code signals a leak.
    assert_eq!(code, 2);
}

#[test]
fn fail_on_match_exits_0_when_clean() {
    let (stdout, code) = run_status(&["--fail-on-match"], "all clean here\nnothing secret\n");
    assert_eq!(stdout, "all clean here\nnothing secret\n");
    assert_eq!(code, 0);
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

#[test]
fn rules_file_adds_custom_keys() {
    let path = format!("{}/keys.toml", env!("CARGO_TARGET_TMPDIR"));
    std::fs::write(&path, "keys = [\"x-internal-token\"]\n").unwrap();
    assert_eq!(
        run_with(&["--rules", &path], "x-internal-token=hush user=bob\n"),
        "x-internal-token=[REDACTED:x-internal-token] user=bob\n"
    );
}

#[test]
fn file_arg_redacts_to_stdout_without_changing_the_file() {
    let path = format!("{}/input.log", env!("CARGO_TARGET_TMPDIR"));
    std::fs::write(&path, "token=abc\nclean line\n").unwrap();
    assert_eq!(
        run_with(&[&path], ""),
        "token=[REDACTED:token]\nclean line\n"
    );
    // the source file is untouched without --in-place
    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        "token=abc\nclean line\n"
    );
}

#[test]
fn in_place_rewrites_the_file() {
    let path = format!("{}/inplace.log", env!("CARGO_TARGET_TMPDIR"));
    std::fs::write(&path, "password=secret\nok\n").unwrap();
    assert_eq!(run_with(&["--in-place", &path], ""), "");
    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        "password=[REDACTED:password]\nok\n"
    );
}

#[test]
fn in_place_without_files_is_an_error() {
    let (_out, code) = run_status(&["--in-place"], "");
    assert_ne!(code, 0);
}

#[test]
fn config_file_sets_defaults_and_cli_overrides() {
    let path = format!("{}/config.toml", env!("CARGO_TARGET_TMPDIR"));
    std::fs::write(&path, "no_entropy = true\nmask = \"hash\"\n").unwrap();
    let secret = "Xy9aB7cD3eF1gH5jK2mN4pQ6rS8tU0vW";

    // Config turns entropy off and selects the hash mask.
    let out = run_env(
        &[("SCRUBLINE_CONFIG", &path)],
        &[],
        &format!("tok {secret} password=secret\n"),
    );
    assert!(
        out.contains(secret),
        "entropy should be off via config: {out}"
    );
    assert!(
        out.contains("[REDACTED:password:"),
        "hash mask via config: {out}"
    );

    // A CLI mask flag overrides the config's mask.
    let out2 = run_env(
        &[("SCRUBLINE_CONFIG", &path)],
        &["--mask-char", "#"],
        "password=secret\n",
    );
    assert_eq!(out2, "password=########\n");
}
