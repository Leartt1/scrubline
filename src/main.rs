//! scrubline binary: read a stream on stdin, mask secrets, write to stdout.
//!
//! Lines are processed and flushed one at a time, so secrets are masked live as
//! they scroll and the whole stream is never held in memory.

use std::collections::BTreeMap;
use std::io::{self, BufRead, BufWriter, Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::Shell;
use serde_json::json;

use scrubline::allowlist::{self, Allowlist};
use scrubline::appconfig::{self, AppConfig};
use scrubline::config::{self, RulesFile};
use scrubline::detector::Detector;
use scrubline::engine::Engine;
use scrubline::entropy::EntropyDetector;
use scrubline::keys::KeySet;
use scrubline::mask::Mask;
use scrubline::patterns::{self, PatternDetector};

/// Number of mask characters used for `--mask-char`, chosen to hide the original
/// secret's length rather than reveal it.
const MASK_WIDTH: usize = 8;

/// Secrets and PII never leave the pipe — a streaming redaction filter.
#[derive(Parser)]
#[command(name = "scrubline", version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,

    /// Replace each secret with this character (repeated) instead of a
    /// `[REDACTED:<kind>]` label.
    #[arg(long, value_name = "CHAR", conflicts_with_all = ["hash", "partial"])]
    mask_char: Option<char>,

    /// Replace each secret with `[REDACTED:<kind>:<hash>]`, a stable tag so equal
    /// secrets correlate across the log without exposing the value.
    #[arg(long, conflicts_with_all = ["partial"])]
    hash: bool,

    /// Replace each secret with `****` followed by its last four characters.
    #[arg(long)]
    partial: bool,

    /// Never redact values listed in this file (one per line; `re:PATTERN` for a
    /// regex). The escape hatch for false positives.
    #[arg(long, value_name = "FILE")]
    allow: Option<PathBuf>,

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

    /// At end of stream, write a JSON redaction summary (line count, total
    /// redactions, and counts per kind) to stderr. The cleaned stream on stdout
    /// is unaffected.
    #[arg(long)]
    stats: bool,

    /// Exit with status 2 if any secret was found (the cleaned stream is still
    /// written). Lets a pipeline fail a build that leaks secrets.
    #[arg(long)]
    fail_on_match: bool,
}

#[derive(Subcommand)]
enum Command {
    /// Print a shell completion script (bash, zsh, fish, elvish, powershell).
    Completions {
        /// Shell to generate completions for.
        shell: Shell,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    if let Some(Command::Completions { shell }) = cli.command {
        let mut cmd = Cli::command();
        clap_complete::generate(shell, &mut cmd, "scrubline", &mut io::stdout());
        return ExitCode::SUCCESS;
    }

    let engine = match setup_engine(&cli) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("scrubline: {e}");
            return ExitCode::FAILURE;
        }
    };

    let result = if cli.hook {
        run_hook_mode(&engine).map(|()| false)
    } else {
        run(&engine, cli.stats, cli.fail_on_match)
    };
    match result {
        // With --fail-on-match, finding a secret is a non-zero exit (CI gate).
        Ok(found) if cli.fail_on_match && found => ExitCode::from(2),
        Ok(_) => ExitCode::SUCCESS,
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

/// Resolve config + CLI into a ready engine. CLI flags override config-file
/// defaults; rules-file and config keys merge.
fn setup_engine(cli: &Cli) -> Result<Engine, String> {
    let app = load_config()?;

    let rules_path = cli.rules.clone().or_else(|| app.rules.clone());
    let allow_path = cli.allow.clone().or_else(|| app.allow.clone());
    let no_entropy = cli.no_entropy || app.no_entropy.unwrap_or(false);
    let mask = resolve_mask(cli, &app)?;

    let rules = load_rules(&rules_path)?;
    let allow = load_allowlist(&allow_path)?;

    let mut patterns = patterns::default_patterns();
    patterns.extend(rules.patterns);
    let mut detectors: Vec<Box<dyn Detector>> = vec![Box::new(PatternDetector::new(patterns))];
    if !no_entropy {
        detectors.push(Box::new(EntropyDetector::default()));
    }

    let mut keys = app.keys;
    keys.extend(rules.keys);

    Ok(Engine::with_mask(detectors, mask)
        .with_allowlist(allow)
        .with_keys(KeySet::with_extra(keys)))
}

/// Choose the mask style: CLI flags win, then the config's `mask`, then labeled.
fn resolve_mask(cli: &Cli, app: &AppConfig) -> Result<Mask, String> {
    if cli.hash {
        return Ok(Mask::Hashed);
    }
    if cli.partial {
        return Ok(Mask::Partial);
    }
    if let Some(c) = cli.mask_char {
        return Ok(Mask::Fixed(c.to_string().repeat(MASK_WIDTH)));
    }
    match app.mask.as_deref() {
        None | Some("labeled") => Ok(Mask::Labeled),
        Some("hash") => Ok(Mask::Hashed),
        Some("partial") => Ok(Mask::Partial),
        Some(other) => Err(format!(
            "invalid mask {other:?} in config (expected labeled, hash, or partial)"
        )),
    }
}

/// Load the rules file (extra patterns + keys), or an empty one if unset.
fn load_rules(path: &Option<PathBuf>) -> Result<RulesFile, String> {
    match path {
        Some(p) => {
            let src = std::fs::read_to_string(p)
                .map_err(|e| format!("cannot read rules file {}: {e}", p.display()))?;
            config::parse_rules(&src)
        }
        None => Ok(RulesFile::default()),
    }
}

/// Load an allowlist file, or an empty allowlist if unset.
fn load_allowlist(path: &Option<PathBuf>) -> Result<Allowlist, String> {
    match path {
        Some(p) => {
            let src = std::fs::read_to_string(p)
                .map_err(|e| format!("cannot read allow file {}: {e}", p.display()))?;
            allowlist::parse_allowlist(&src)
        }
        None => Ok(Allowlist::default()),
    }
}

/// Load the config file from `$SCRUBLINE_CONFIG` or the default location.
fn load_config() -> Result<AppConfig, String> {
    match config_path() {
        Some(p) => {
            let src = std::fs::read_to_string(&p)
                .map_err(|e| format!("cannot read config {}: {e}", p.display()))?;
            appconfig::parse_config(&src)
        }
        None => Ok(AppConfig::default()),
    }
}

/// The config-file path: `$SCRUBLINE_CONFIG` (used even if missing, so a typo is
/// reported), else the XDG/`~/.config` default (used only if it exists).
fn config_path() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("SCRUBLINE_CONFIG") {
        return Some(PathBuf::from(p));
    }
    let base = match std::env::var_os("XDG_CONFIG_HOME") {
        Some(x) => PathBuf::from(x),
        None => PathBuf::from(std::env::var_os("HOME")?).join(".config"),
    };
    let path = base.join("scrubline/config.toml");
    path.exists().then_some(path)
}

/// Run the streaming filter. Returns whether any secret was redacted (for
/// `--fail-on-match`). When neither `stats` nor `track` is needed, uses the
/// allocation-free fast path.
fn run(engine: &Engine, stats: bool, fail_on_match: bool) -> io::Result<bool> {
    let stdin = io::stdin();
    let mut reader = stdin.lock();
    let stdout = io::stdout();
    let mut out = BufWriter::new(stdout.lock());

    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    let mut lines: u64 = 0;
    let mut redactions: u64 = 0;
    let track = stats || fail_on_match;

    let mut line = String::new();
    loop {
        line.clear();
        if reader.read_line(&mut line)? == 0 {
            break; // EOF
        }
        let (content, terminator) = split_terminator(&line);
        let cleaned = if track {
            let (cleaned, kinds) = engine.redact_line_report(content);
            lines += 1;
            redactions += kinds.len() as u64;
            for kind in kinds {
                *counts.entry(kind).or_default() += 1;
            }
            cleaned
        } else {
            engine.redact_line(content)
        };
        out.write_all(cleaned.as_bytes())?;
        out.write_all(terminator.as_bytes())?;
        out.flush()?; // emit each line as soon as it is cleaned
    }

    if stats {
        out.flush()?;
        let by_kind: serde_json::Map<String, serde_json::Value> =
            counts.into_iter().map(|(k, v)| (k, json!(v))).collect();
        let summary = json!({ "lines": lines, "redactions": redactions, "by_kind": by_kind });
        eprintln!("{summary}");
    }
    Ok(redactions > 0)
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
