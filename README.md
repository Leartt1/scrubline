# scrubline

[![CI](https://github.com/Leartt1/scrubline/actions/workflows/ci.yml/badge.svg)](https://github.com/Leartt1/scrubline/actions/workflows/ci.yml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

**Secrets and PII never leave the pipe.**

`scrubline` is a streaming redaction filter. Put it in front of any log stream
and it masks tokens, passwords, and PII **live, mid-pipe** — before they reach
your terminal, a GitHub issue, a pastebin, or an LLM's context window.

```console
$ kubectl logs api | scrubline
{"level":"info","msg":"login","authorization":"[REDACTED:authorization]","user":"bob"}
ts=2026-06-24 level=warn password="[REDACTED:password]" path=/health
```

It's not a scanner. `gitleaks` and `trufflehog` *find* secrets and report them.
`scrubline` *removes* them from a stream you're piping onward — and re-emits the
cleaned stream so the next stage never sees the original.

## Demo

`scrubline` masks five different kinds of secret in this log while leaving the
UUID, the commit SHA, and the Kubernetes pod name (the usual false-positive
traps) completely alone:

```console
$ scrubline < examples/messy.log
2026-06-24T10:15:01Z level=info msg="server started" port=8080
2026-06-24T10:15:02Z level=info user=alice request_id=550e8400-e29b-41d4-a716-446655440000
2026-06-24T10:15:03Z level=debug authorization="[REDACTED:authorization]"
2026-06-24T10:15:04Z level=warn msg="db connect" dsn=[REDACTED:credential-uri]
2026-06-24T10:15:05Z level=info commit=9fceb02d0ae598e95dc970b74767f19372d61af8 deploy=ok
2026-06-24T10:15:06Z level=error msg="email send failed" to=[REDACTED:email]
2026-06-24T10:15:07Z level=debug session_token=[REDACTED:high-entropy]
2026-06-24T10:15:08Z level=info pod=nginx-7d8b49557c-x2vfq status=Running
{"level":"info","msg":"login","password":"[REDACTED:password]","user":"bob"}

$ scrubline --stats < examples/messy.log > /dev/null
{"lines":9,"redactions":5,"by_kind":{"authorization":1,"credential-uri":1,"email":1,"high-entropy":1,"password":1}}
```

Run it yourself with [`examples/demo.sh`](examples/demo.sh).

---

## Why

Secrets end up in logs constantly: an `Authorization` header logged by a
middleware, a connection string in a stack trace, a token in a debug dump. The
moment that log leaves the machine, the secret leaves with it:

- you paste a log into a bug report or Slack,
- you tail prod logs into a terminal someone's screen-sharing,
- **you feed logs to an AI agent** and the model now has your production keys in
  its context.

`scrubline` sits in the pipe and makes sure the secret never gets that far.

> Your agent should never see your prod secrets.

## How it works

`scrubline` reads stdin one line at a time, redacts, and flushes immediately —
the full stream is never held in memory, so it works on infinite log tails.

Redaction runs in two layers:

1. **Structured, key-aware redaction (available now).** If a line is JSON or
   logfmt, `scrubline` masks the *value* of any sensitive field by its **key
   name** — `authorization`, `password`, `token`, `api_key`, `cookie`,
   `client_secret`, and friends (case-insensitive, `-`/`_` interchangeable). It
   doesn't matter what the value looks like: an opaque session id or a plain
   word in a `password` field is masked just as reliably as a tokened secret.
   For a sensitive key, the **entire value subtree** is masked, so nested
   secrets can't leak.

2. **Value detectors (available now).** Named-pattern detectors — **OpenAI and
   Anthropic keys**, AWS keys, GitHub (classic + fine-grained), GitLab, and Slack
   tokens, Stripe, Google, Twilio, SendGrid, and npm keys, JWTs, PEM private
   keys, credentialed URIs, and emails — catch secrets in free-text log
   messages, not just structured fields. A conservative Shannon-entropy detector
   then catches *unknown* high-entropy tokens, while deliberately leaving git
   SHAs, UUIDs, content hashes, and Kubernetes pod names alone. Turn it off with
   `--no-entropy`.

```console
# JSON: the whole sensitive subtree goes, field order is preserved
$ echo '{"db":{"password":1234,"host":"localhost"}}' | scrubline
{"db":{"password":"[REDACTED:password]","host":"localhost"}}

# logfmt: quoted values are masked in place, quotes kept
$ echo 'level=warn password="hunter two" api_key=sk_live_123 path=/x' | scrubline
level=warn password="[REDACTED:password]" api_key=[REDACTED:api_key] path=/x

# clean lines pass through untouched
$ echo 'listening on :8080' | scrubline
listening on :8080

# free-text secrets in a log message are caught too
$ echo 'pushed with ghp_abcdefghijklmnopqrstuvwxyz0123456789' | scrubline
pushed with [REDACTED:github-token]

# an unknown high-entropy token is caught by the entropy detector...
$ echo 'signed url sig=Xy9aB7cD3eF1gH5jK2mN4pQ6rS8tU0vW' | scrubline
signed url sig=[REDACTED:high-entropy]

# ...but a commit SHA and a pod name in the same line are left alone
$ echo 'pod nginx-7d8b49557c-x2vfq at 9fceb02d0ae598e95dc970b74767f19372d61af8' | scrubline
pod nginx-7d8b49557c-x2vfq at 9fceb02d0ae598e95dc970b74767f19372d61af8

# hide the kind and length entirely with --mask-char
$ echo 'token=s3cr3t' | scrubline --mask-char '*'
token=********
```

## Accuracy

The entropy detector is the part most likely to cause false positives, so it's
held to a measured standard. A precision/recall **benchmark runs as a test**
over a labeled corpus of realistic log lines — 21 secrets across every detector
path, plus 28 clean lines full of the usual traps (git SHAs, UUIDs, md5/sha
hashes, Kubernetes pod names, file paths, semver, W3C traceparents):

| metric | score |
|--------|------:|
| precision | **1.000** |
| recall | **1.000** |

```console
cargo test --test precision_recall -- --nocapture
```

Because it's a test with asserted floors (precision ≥ 0.97, recall ≥ 0.95), a
change that starts masking commit SHAs — or stops masking real secrets — fails
CI instead of shipping. The entropy detector only flags long tokens that mix
upper/lower/digits and clear an entropy floor, which is what keeps SHAs and pod
names safe.

## Performance

It's a streaming, single-pass filter — it never buffers the whole stream, so
memory is flat on an infinite tail. The named-pattern detectors are gated by a
single `RegexSet` scan, so a secret-free line (the common case) does no
per-pattern work. On a dev laptop that's **~95 MiB/s (over a million lines per
second)** through the full default stack:

```console
$ cargo run --release --example bench
scrubline throughput (default detectors)
  lines:      500000
  input:      42.3 MiB
  throughput: 97 MiB/s  (1142K lines/s)
```

## Use it with Claude Code

Coding agents read your logs, your `.env`, your command output — and whatever
they read goes into the model's context (and your provider's). scrubline runs as
a [Claude Code hook](https://code.claude.com/docs/en/hooks) and scrubs secrets
out of tool I/O *before the model sees them*.

Add to `.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      { "matcher": "*", "hooks": [{ "type": "command", "command": "scrubline", "args": ["--hook"] }] }
    ],
    "PostToolUse": [
      { "matcher": "*", "hooks": [{ "type": "command", "command": "scrubline", "args": ["--hook"] }] }
    ]
  }
}
```

- **PreToolUse** rewrites `tool_input` — a secret in a `Bash` command or a file
  write is masked before the tool runs.
- **PostToolUse** rewrites the tool result — a `cat .env` or an API response is
  masked before it returns to the model.

One binary handles every event; it dispatches on the payload's
`hook_event_name`. Given a `PostToolUse` payload, it returns:

```console
$ echo '{"hook_event_name":"PostToolUse","tool_response":"$ cat .env\nDATABASE_URL=postgres://app:s3cr3tP4ss@db:5432/main\nSTRIPE_KEY=sk_live_0123456789abcdef0123"}' | scrubline --hook
{"hookSpecificOutput":{"hookEventName":"PostToolUse","updatedToolOutput":"$ cat .env\nDATABASE_URL=[REDACTED:credential-uri]\nSTRIPE_KEY=[REDACTED:stripe-key]"}}
```

If nothing is sensitive, scrubline returns `{}` and the tool call proceeds
untouched — a hook failure can never block your agent.

> `UserPromptSubmit` is also supported, but Claude Code doesn't allow a hook to
> rewrite the prompt, so there scrubline only adds an advisory note.

## Custom patterns and keys

Have an internal token format or field name? Point `--rules` at a TOML file —
patterns join the built-in detectors, and `keys` join the structured
sensitive-key set:

```toml
# rules.toml
keys = ["x-internal-token", "vault_secret"]

[[pattern]]
kind = "employee-id"
regex = "EMP[0-9]{6}"

[[pattern]]
kind = "internal-token"
regex = "INT-[A-Za-z0-9]{20,}"
```

```console
$ echo 'user EMP123456 x-internal-token=hush' | scrubline --rules rules.toml
user [REDACTED:employee-id] x-internal-token=[REDACTED:x-internal-token]
```

## Configuration

Set defaults in a config file — `$SCRUBLINE_CONFIG`, else
`~/.config/scrubline/config.toml`. CLI flags always override it.

```toml
# config.toml
no_entropy = false
mask       = "hash"          # labeled | hash | partial
rules      = "team-rules.toml"
allow      = "allowlist.txt"
keys       = ["x-internal-token"]
```

## Install

From source (Rust toolchain required):

```console
cargo install --git https://github.com/Leartt1/scrubline
```

Or clone and build:

```console
git clone https://github.com/Leartt1/scrubline
cd scrubline
cargo build --release
# binary at ./target/release/scrubline
```

> A `crates.io` release and prebuilt binaries are coming.

Shell completions for bash, zsh, fish, elvish, and powershell:

```console
scrubline completions zsh > ~/.zfunc/_scrubline
```

## Usage

`scrubline` is a filter — pipe anything through it:

```console
my-app 2>&1 | scrubline
tail -f /var/log/app.log | scrubline
docker logs -f web | scrubline | tee cleaned.log
```

Line terminators (LF / CRLF) are preserved, and a closed downstream pipe
(`… | head`) exits cleanly.

Flags:

- `--mask-char <CHAR>` — replace secrets with a fixed run of one character
  instead of a `[REDACTED:<kind>]` label.
- `--hash` — replace each secret with `[REDACTED:<kind>:<hash>]`, a stable tag
  so equal secrets correlate across the log without exposing the value.
- `--partial` — replace each secret with `****` and its last four characters.
- `--allow <FILE>` — never redact values listed in this file (one per line;
  `re:PATTERN` for a regex). The escape hatch for false positives.
- `--no-entropy` — disable the heuristic entropy detector (named-pattern and
  structured redaction still run).
- `--rules <FILE>` — load extra named patterns from a TOML file.
- `--stats` — write a JSON redaction summary to stderr at end of stream.
- `--hook` — run as a Claude Code hook (see above).

`--mask-char`, `--hash`, and `--partial` are mutually exclusive.

```console
$ printf 'a=ghp_DEADBEEFdeadbeef0123456789ABCDEFwxyz b=ghp_DEADBEEFdeadbeef0123456789ABCDEFwxyz\n' | scrubline --hash
a=[REDACTED:github-token:501bcd] b=[REDACTED:github-token:501bcd]
```

## Roadmap

- [x] Streaming line filter, never buffers the stream
- [x] Structured key-aware redaction for JSON and logfmt
- [x] Named-pattern detectors (OpenAI, Anthropic, AWS, GitHub, GitLab, Slack, Stripe, Google, Twilio, SendGrid, npm, JWT, PEM keys, credentialed URIs, emails)
- [x] `--mask-char` and a real `--help`/`--version` CLI
- [x] Conservative entropy detector with a precision/recall benchmark (and `--no-entropy`)
- [x] Custom-pattern rules file (`--rules`)
- [x] Claude Code hook mode — strip secrets from tool I/O before they hit an agent's context
- [x] `--stats` JSON summary of what was redacted
- [ ] `crates.io` release and prebuilt binaries

## License

MIT or Apache-2.0, at your option.
