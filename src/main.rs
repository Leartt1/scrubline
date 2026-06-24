//! scrubline binary: read a stream on stdin, mask secrets, write to stdout.
//!
//! Lines are processed and flushed one at a time, so secrets are masked live as
//! they scroll and the whole stream is never held in memory.

use std::io::{self, BufRead, BufWriter, Write};
use std::process::ExitCode;

use clap::Parser;

use scrubline::detector::Detector;
use scrubline::engine::Engine;
use scrubline::mask::Mask;
use scrubline::patterns::PatternDetector;

/// Number of mask characters used for `--mask-char`, chosen to hide the original
/// secret's length rather than reveal it.
const MASK_WIDTH: usize = 8;

/// Secrets and PII never leave the pipe — a streaming redaction filter.
#[derive(Parser)]
#[command(name = "scrubline", version, about, long_about = None)]
struct Cli {
    /// Replace each secret with this character (repeated) instead of a
    /// `[REDACTED:<kind>]` label.
    #[arg(long, value_name = "CHAR")]
    mask_char: Option<char>,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let mask = match cli.mask_char {
        Some(c) => Mask::Fixed(c.to_string().repeat(MASK_WIDTH)),
        None => Mask::Labeled,
    };
    let engine = Engine::with_mask(default_detectors(), mask);
    match run(&engine) {
        Ok(()) => ExitCode::SUCCESS,
        // A closed downstream pipe (e.g. `... | head`) is a normal way to stop.
        Err(e) if e.kind() == io::ErrorKind::BrokenPipe => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("scrubline: {e}");
            ExitCode::FAILURE
        }
    }
}

/// The value detectors run on every line. Named-pattern detection is active; the
/// entropy detector arrives on day 3. The structured (JSON/logfmt) layer runs
/// regardless of this list.
fn default_detectors() -> Vec<Box<dyn Detector>> {
    vec![Box::new(PatternDetector::default())]
}

fn run(engine: &Engine) -> io::Result<()> {
    let stdin = io::stdin();
    let mut reader = stdin.lock();
    let stdout = io::stdout();
    let mut out = BufWriter::new(stdout.lock());

    let mut line = String::new();
    loop {
        line.clear();
        if reader.read_line(&mut line)? == 0 {
            break; // EOF
        }
        let (content, terminator) = split_terminator(&line);
        let cleaned = engine.redact_line(content);
        out.write_all(cleaned.as_bytes())?;
        out.write_all(terminator.as_bytes())?;
        out.flush()?; // emit each line as soon as it is cleaned
    }
    Ok(())
}

/// Split a read line into its content and its line terminator (`\n`, `\r\n`, or
/// none for a final unterminated line) so we redact content only and re-emit the
/// terminator verbatim.
fn split_terminator(line: &str) -> (&str, &str) {
    if let Some(rest) = line.strip_suffix('\n') {
        if let Some(rest) = rest.strip_suffix('\r') {
            (rest, "\r\n")
        } else {
            (rest, "\n")
        }
    } else {
        (line, "")
    }
}
