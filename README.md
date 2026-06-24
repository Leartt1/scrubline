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

2. **Value detectors (on the roadmap).** Named-pattern detectors (Stripe, AWS,
   GitHub, JWT, private keys, database URLs, …) and a tuned Shannon-entropy
   detector for unknown high-entropy tokens, for secrets that show up in
   free-text log messages rather than structured fields.

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

## Roadmap

- [x] Streaming line filter, never buffers the stream
- [x] Structured key-aware redaction for JSON and logfmt
- [ ] Named-pattern detectors (Stripe, AWS, GitHub, GitLab, Slack, JWT, PEM keys, DB URLs, emails)
- [ ] Tuned entropy detector with a published precision/recall benchmark
- [ ] `--mask-char`, `--json` summary, custom-pattern config file
- [ ] Claude Code `PreToolUse` hook mode — strip secrets before they hit an agent's context

## License

MIT or Apache-2.0, at your option.
