//! End-to-end tests: pipe input through the real compiled binary.

use std::io::Write;
use std::process::{Command, Stdio};

fn run(input: &str) -> String {
    let mut child = Command::new(env!("CARGO_BIN_EXE_scrubline"))
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
