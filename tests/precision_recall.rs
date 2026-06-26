//! Precision/recall benchmark for the full default detector stack.
//!
//! A labeled corpus of realistic log lines — secrets that MUST be masked, and
//! clean lines (including the classic false-positive traps: git SHAs, UUIDs,
//! md5/sha hashes, k8s pod names, versions, paths) that must pass through
//! untouched. We measure how well scrubline separates the two and assert floors
//! so the numbers can never silently regress.
//!
//! Run `cargo test --test precision_recall -- --nocapture` to see the report.

use scrubline::engine::Engine;
use scrubline::entropy::EntropyDetector;
use scrubline::patterns::PatternDetector;

fn engine() -> Engine {
    Engine::new(vec![
        Box::new(PatternDetector::default()),
        Box::new(EntropyDetector::default()),
    ])
}

/// Lines that contain a secret, paired with the exact substring that must NOT
/// survive redaction. Provider-format tokens are assembled from split literals
/// so the corpus file itself doesn't trip secret scanners.
fn positives() -> Vec<(String, String)> {
    let aws = concat!("AKIA", "IOSFODNN7EXAMPLE");
    let github = concat!("ghp_", "abcdefghijklmnopqrstuvwxyz0123456789");
    let gitlab = concat!("glpat", "-abcdefghij0123456789");
    let slack = concat!("xoxb", "-0123456789abcdefghij");
    let stripe = concat!("sk_", "live_0123456789abcdef0123");
    let google = concat!("AIza", "SyA1bcdEfghIjklMnopQrstUvwxyz01234");
    let jwt =
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
    let ent1 = "Xy9aB7cD3eF1gH5jK2mN4pQ6rS8tU0vW";
    let ent2 = "Q8vN2mZ5kP7wL4xR9tB3hC6yF1dG0sJ";
    let ent3 = "8f3K-mP9xQ2w-Lr7Tn4Vb1Zc6Hy0Ms5dA";

    let mut v: Vec<(String, String)> = Vec::new();
    let mut pos = |line: String, secret: &str| v.push((line, secret.to_string()));

    // free-text named patterns
    pos(
        format!("level=error msg=\"auth failed\" aws_key={aws}"),
        aws,
    );
    pos(format!("webhook delivered with token {github}"), github);
    pos(format!("ci using {gitlab} to clone"), gitlab);
    pos(format!("slack notify failed token={slack}"), slack);
    pos(format!("charge created key={stripe}"), stripe);
    pos(format!("maps request denied key={google}"), google);
    pos(format!("decoded session={jwt}"), jwt);
    pos(
        "-----BEGIN RSA PRIVATE KEY-----".to_string(),
        "BEGIN RSA PRIVATE KEY",
    );
    pos(
        "connecting to postgres://app:s3cr3tP4ss@db.internal:5432/main".to_string(),
        "s3cr3tP4ss",
    );
    pos(
        "cache at redis://:r3disPwd9@cache:6379/0".to_string(),
        "r3disPwd9",
    );
    pos(
        "notify owner contact john.doe@example.com about outage".to_string(),
        "john.doe@example.com",
    );

    // structured (json / logfmt) — value must vanish
    pos(
        "{\"level\":\"info\",\"authorization\":\"Bearer abc.def.ghi\",\"u\":\"bob\"}".to_string(),
        "abc.def.ghi",
    );
    pos(
        "{\"db\":{\"password\":\"hunter2plzdont\",\"host\":\"db\"}}".to_string(),
        "hunter2plzdont",
    );
    pos(
        "{\"api_key\":\"qwerty-do-not-log-me\"}".to_string(),
        "qwerty-do-not-log-me",
    );
    pos(
        "{\"set-cookie\":\"sess=ZmFrZXNlc3Npb24; HttpOnly\"}".to_string(),
        "ZmFrZXNlc3Npb24",
    );
    pos(
        "ts=2026-06-24 level=warn password=\"corrleakhorse\" path=/x".to_string(),
        "corrleakhorse",
    );
    pos(
        "level=info token=tok_dontleakthisvalue user=bob".to_string(),
        "tok_dontleakthisvalue",
    );
    pos(
        "client_secret=verysecretclientvalue grant=code".to_string(),
        "verysecretclientvalue",
    );

    // unknown high-entropy tokens (entropy detector)
    pos(format!("api responded with bearer {ent1}"), ent1);
    pos(format!("internal token issued {ent2}"), ent2);
    pos(format!("signed url sig={ent3}"), ent3);

    v
}

/// Clean lines that must pass through completely untouched.
fn negatives() -> Vec<&'static str> {
    vec![
        "GET /api/v1/health 200 5ms",
        "commit 9fceb02d0ae598e95dc970b74767f19372d61af8 merged to main",
        "request 550e8400-e29b-41d4-a716-446655440000 completed",
        "pod nginx-7d8b49557c-x2vfq Running on node-3",
        "container 3f4a9c2b1e8d started",
        "md5 d41d8cd98f00b204e9800998ecf8427e verified",
        "sha256 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 ok",
        "listening on 127.0.0.1:8080",
        "build 1.4.2+20260624 ready",
        "elapsed=1532ms status=200 route=/users",
        "user_id=42 org_id=1007 plan=pro",
        "path=/var/lib/docker/overlay2/cachedir size=10240",
        "p99 12.4ms p50 3.1ms ratio 0.9942",
        "Mozilla/5.0 (X11; Linux x86_64) Firefox/126.0",
        "disk usage 87% of 512GB on /dev/sda1",
        "queue depth 1280 workers 16 idle 4",
        "ts=2026-06-24T10:15:30Z level=info msg=startup",
        "branch feature/add-login-page pushed by ci",
        "color=#1a2b3c size=14px weight=600",
        "order ORD-20260624-000457 created for cust 88",
        "lat=37.7749 lng=-122.4194 accuracy=5m",
        "kernel 6.8.0-31-generic x86_64 booted",
        "image alpine:3.20 pulled in 1.2s",
        "session rotated after 3600s of idle time",
        "trace parent 00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01",
        "GET /static/app.4f3c2b1a.js 200 from cache",
        "retry 3 of 5 after backoff 2000ms",
        "loaded 14 plugins in 312ms, 0 failed",
    ]
}

#[derive(Default)]
struct Metrics {
    tp: usize,
    fp: usize,
    misses: usize,
    tn: usize,
    fp_lines: Vec<String>,
    miss_lines: Vec<String>,
}

impl Metrics {
    fn precision(&self) -> f64 {
        let d = self.tp + self.fp;
        if d == 0 {
            1.0
        } else {
            self.tp as f64 / d as f64
        }
    }
    fn recall(&self) -> f64 {
        let d = self.tp + self.misses;
        if d == 0 {
            1.0
        } else {
            self.tp as f64 / d as f64
        }
    }
    fn f1(&self) -> f64 {
        let (p, r) = (self.precision(), self.recall());
        if p + r == 0.0 {
            0.0
        } else {
            2.0 * p * r / (p + r)
        }
    }
}

#[test]
fn precision_recall_meets_floor() {
    let e = engine();
    let mut m = Metrics::default();

    for (line, secret) in positives() {
        let out = e.redact_line(&line);
        if out.contains(&secret) {
            m.misses += 1;
            m.miss_lines.push(line);
        } else {
            m.tp += 1;
        }
    }

    for line in negatives() {
        let out = e.redact_line(line);
        if out == line {
            m.tn += 1;
        } else {
            m.fp += 1;
            m.fp_lines.push(format!("{line}  ->  {out}"));
        }
    }

    eprintln!("\n  scrubline precision/recall");
    eprintln!("  --------------------------");
    eprintln!(
        "  positives: {}   negatives: {}",
        m.tp + m.misses,
        m.fp + m.tn
    );
    eprintln!(
        "  TP={} FP={} FN(miss)={} TN={}",
        m.tp, m.fp, m.misses, m.tn
    );
    eprintln!("  precision: {:.3}", m.precision());
    eprintln!("  recall:    {:.3}", m.recall());
    eprintln!("  f1:        {:.3}", m.f1());
    if !m.fp_lines.is_empty() {
        eprintln!("  false positives:");
        for l in &m.fp_lines {
            eprintln!("    {l}");
        }
    }
    if !m.miss_lines.is_empty() {
        eprintln!("  missed secrets:");
        for l in &m.miss_lines {
            eprintln!("    {l}");
        }
    }
    eprintln!();

    assert!(
        m.precision() >= 0.97,
        "precision {:.3} below floor 0.97",
        m.precision()
    );
    assert!(
        m.recall() >= 0.95,
        "recall {:.3} below floor 0.95",
        m.recall()
    );
}
