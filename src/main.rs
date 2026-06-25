//! scrubline binary: read a stream on stdin, mask secrets, write to stdout.
//!
//! Lines are processed and flushed one at a time, so secrets are masked live as
//! they scroll and the whole stream is never held in memory.

use std::io::{self, BufRead, BufWriter, Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;

use scrubline::config;
use scrubline::detector::Detector;
use scrubline::engine::Engine;
use scrubline::entropy::EntropyDetector;
use scrubline::mask::Mask;
use scrubline::patterns::{self, PatternDetector};

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

    /// Disable the heuristic entropy detector (named patterns and structured
    /// redaction still run). Use this if high-entropy values trip false
    /// positives in your logs.
    #[arg(long)]
    no_entropy: bool,

    /// Run as a Claude Code hook: read a hook JSON payload on stdin and write a
    /// hook JSON response that redacts secrets from tool input/output before the
    /// model sees them. Dispatches on the payload's `hook_event_name`.
    #[arg(long)]
    hook: bool,

    /// Load additional named patterns from a TOML rules file (each `[[pattern]]`
    /// has a `kind` and a `regex`). Merged with the built-in patterns.
    #[arg(long, value_name = "FILE")]
    rules: Option<PathBuf>,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let mask = match cli.mask_char {
        Some(c) => Mask::Fixed(c.to_string().repeat(MASK_WIDTH)),
        None => Mask::Labeled,
    };
    let detectors = match build_detectors(&cli) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("scrubline: {e}");
            return ExitCode::FAILURE;
        }
    };
    let engine = Engine::with_mask(detectors, mask);

    let result = if cli.hook { run_hook_mode(&engine) } else { run(&engine) };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        // A closed downstream pipe (e.g. `... | head`) is a normal way to stop.
        Err(e) if e.kind() == io::ErrorKind::BrokenPipe => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("scrubline: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Read a Claude Code hook payload from stdin and write the JSON response. Exit 0
/// so Claude Code processes the response; on any trouble we still emit `{}` so a
/// hook failure never blocks the agent.
fn run_hook_mode(engine: &Engine) -> io::Result<()> {
    let mut input = String::new();
    io::stdin().lock().read_to_string(&mut input)?;
    let response = scrubline::hook::run_hook(engine, &input);
    let stdout = io::stdout();
    let mut out = stdout.lock();
    out.write_all(response.as_bytes())?;
    out.flush()
}

/// Build the value detectors: built-in named patterns plus any from `--rules`,
/// then the entropy heuristic unless disabled. The structured (JSON/logfmt)
/// layer runs regardless of this list. Returns an error if the rules file can't
/// be read or parsed.
fn build_detectors(cli: &Cli) -> Result<Vec<Box<dyn Detector>>, String> {
    let mut patterns = patterns::default_patterns();
    if let Some(path) = &cli.rules {
        let src = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read rules file {}: {e}", path.display()))?;
        patterns.extend(config::parse_rules(&src)?);
    }

    let mut detectors: Vec<Box<dyn Detector>> = vec![Box::new(PatternDetector::new(patterns))];
    if !cli.no_entropy {
        detectors.push(Box::new(EntropyDetector::default()));
    }
    Ok(detectors)
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
