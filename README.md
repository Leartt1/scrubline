# scrubline

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

2. **Value detectors (available now).** Named-pattern detectors — AWS keys,
   GitHub/GitLab/Slack tokens, Stripe keys, Google API keys, JWTs, PEM private
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

## Custom patterns

Have an internal token format? Point `--rules` at a TOML file and your patterns
join the built-ins:

```toml
# rules.toml
[[pattern]]
kind = "employee-id"
regex = "EMP[0-9]{6}"

[[pattern]]
kind = "internal-token"
regex = "INT-[A-Za-z0-9]{20,}"
```

```console
$ echo 'user EMP123456 acting as service' | scrubline --rules rules.toml
user [REDACTED:employee-id] acting as service
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
- `--no-entropy` — disable the heuristic entropy detector (named-pattern and
  structured redaction still run).
- `--rules <FILE>` — load extra named patterns from a TOML file.
- `--hook` — run as a Claude Code hook (see above).

## Roadmap

- [x] Streaming line filter, never buffers the stream
- [x] Structured key-aware redaction for JSON and logfmt
- [x] Named-pattern detectors (AWS, GitHub, GitLab, Slack, Stripe, Google, JWT, PEM keys, credentialed URIs, emails)
- [x] `--mask-char` and a real `--help`/`--version` CLI
- [x] Conservative entropy detector with a precision/recall benchmark (and `--no-entropy`)
- [x] Custom-pattern rules file (`--rules`)
- [x] Claude Code hook mode — strip secrets from tool I/O before they hit an agent's context
- [ ] `--stats` JSON summary of what was redacted
- [ ] `crates.io` release and prebuilt binaries

## License

MIT or Apache-2.0, at your option.
