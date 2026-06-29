//! Throughput micro-benchmark for the full default detector stack.
//!
//! Run with: `cargo run --release --example bench`
//!
//! Generates a realistic log (mostly clean lines, ~30% carrying a secret) and
//! measures how fast scrubline redacts it. Not a test — just a number.

use std::hint::black_box;
use std::time::Instant;

use scrubline::engine::Engine;
use scrubline::entropy::EntropyDetector;
use scrubline::patterns::PatternDetector;

fn main() {
    let engine = Engine::new(vec![
        Box::new(PatternDetector::default()),
        Box::new(EntropyDetector::default()),
    ]);

    // 10 representative lines: 7 clean (incl. the false-positive traps), 3 with
    // a real secret across different detector paths.
    let templates: &[&str] = &[
        "2026-06-24T10:15:01Z level=info msg=\"request handled\" route=/api/v1/users status=200 dur=12ms",
        "2026-06-24T10:15:02Z level=debug cache hit ratio 0.94 over 10000 requests",
        "2026-06-24T10:15:03Z level=info commit 9fceb02d0ae598e95dc970b74767f19372d61af8 deployed",
        "2026-06-24T10:15:04Z level=info pod nginx-7d8b49557c-x2vfq running on node-3",
        "2026-06-24T10:15:05Z level=info request 550e8400-e29b-41d4-a716-446655440000 completed",
        "2026-06-24T10:15:06Z level=warn slow query 1532ms on the users table",
        "2026-06-24T10:15:07Z level=info listening on 0.0.0.0:8080 and ready to serve",
        "2026-06-24T10:15:08Z level=error authorization=\"Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U\" rejected",
        "2026-06-24T10:15:09Z level=warn db dsn=postgres://app:s3cr3tP4ssw0rd@db.internal:5432/main",
        "2026-06-24T10:15:10Z level=info user contact alice@example.com profile updated",
    ];

    let lines = 500_000usize;
    let input: Vec<&str> = (0..lines).map(|i| templates[i % templates.len()]).collect();
    let bytes: usize = input.iter().map(|l| l.len() + 1).sum();

    // Warm up caches/branch predictors.
    for l in input.iter().take(2000) {
        black_box(engine.redact_line(l));
    }

    let start = Instant::now();
    let mut redactions = 0usize;
    for l in &input {
        let out = engine.redact_line(l);
        redactions += out.matches("[REDACTED").count();
        black_box(&out);
    }
    let secs = start.elapsed().as_secs_f64();

    let mib = bytes as f64 / (1024.0 * 1024.0);
    println!("scrubline throughput (default detectors)");
    println!("  lines:      {lines}");
    println!("  input:      {mib:.1} MiB");
    println!("  elapsed:    {secs:.3}s");
    println!(
        "  throughput: {:.0} MiB/s  ({:.0}K lines/s)",
        mib / secs,
        lines as f64 / secs / 1000.0
    );
    println!("  redactions: {redactions}");
}
