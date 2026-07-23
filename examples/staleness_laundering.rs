//! Staleness laundering — and the un-resettable clock that catches it.
//!
//! Companion to `SPEC-BACKING-AGE-v0.1` in the position-paper repo.
//!
//! HTTP solved this in 1997: RFC 9111 §4.2.3 makes a response's `Age` the
//! sum of its residence along the whole cache path — intermediate caches
//! never reset it. Agent pipelines forgot it: every derivation (an LLM
//! summary, a plan, a tool result) stamps its output "now", laundering the
//! age of the sources it derived from.
//!
//! This example runs the same 3-stage pipeline twice over a 90-day-old
//! memory source:
//!
//! - **naive**: each stage checks the age of its *immediate* input — every
//!   check passes, the stale plan executes silently;
//! - **backed**: each output carries the union of its inputs' [`BackingSet`]
//!   (the propagation rule: never reset on derivation) — the settlement
//!   gate sees the true source age and refuses.
//!
//! Then the privacy rule (spec §2.5): what crosses a trust boundary is
//! never the backing set (a provenance trace) but [`BoundaryAge`] — one
//! scalar, RFC 9111's degenerate form.
//!
//! Run with: `cargo run --example staleness_laundering`

use proof_of_context::backing::{AgePolicy, BackingEntry, BackingSet, BackingVerdict};

const DAY: u64 = 86_400;

/// A pipeline artifact: content, the instant it was produced, and the
/// backing it carries (empty in the naive world).
struct Artifact {
    label: &'static str,
    produced_at_secs: u64,
    backing: BackingSet,
}

fn main() {
    // Timeline: a repo-structure observation validated in April; the
    // pipeline runs in July, ~90 days later.
    let april = 1_744_800_000_u64;
    let july = april + 90 * DAY;

    // Policy: repo-structure claims may bear load for 7 days.
    let policy = AgePolicy {
        max_age_secs_by_class: [("repo-structure".to_string(), 7 * DAY)].into(),
        default_max_age_secs: None,
    };

    println!("== Staleness laundering demo ==");
    println!("source obs:44 (repo-structure) last validated: T0 (April)");
    println!("pipeline runs: T0 + 90 days (July); policy window: 7 days\n");

    // ---------------------------------------------------------------
    // World 1: naive pipeline — each stage checks its IMMEDIATE input.
    // ---------------------------------------------------------------
    println!("-- naive pipeline (checks immediate-input age only) --");

    let memory_read = Artifact {
        label: "memory read of obs:44",
        produced_at_secs: july, // read happens "now"
        backing: BackingSet::new(),
    };
    let summary = Artifact {
        label: "LLM summary",
        produced_at_secs: july + 2,
        backing: BackingSet::new(),
    };
    let plan = Artifact {
        label: "action plan",
        produced_at_secs: july + 5,
        backing: BackingSet::new(),
    };

    for (stage, input) in [
        (&summary, &memory_read),
        (&plan, &summary),
    ] {
        let immediate_age = stage.produced_at_secs - input.produced_at_secs;
        println!(
            "  {} <- {}: immediate-input age {}s <= window -> PASS",
            stage.label, input.label, immediate_age
        );
    }
    println!("  => plan EXECUTES against 90-day-old repo structure. Silently.\n");

    // ---------------------------------------------------------------
    // World 2: backed pipeline — outputs inherit the union of their
    // inputs' backing; attested_at never advances by derivation.
    // ---------------------------------------------------------------
    println!("-- backed pipeline (backing propagates, clock un-resettable) --");

    let memory_read = Artifact {
        label: "memory read of obs:44",
        produced_at_secs: july,
        backing: BackingSet::from_entries([BackingEntry {
            source_id: "obs:44".to_string(),
            attested_at_secs: april, // the VALIDATION instant, not the read
            class: "repo-structure".to_string(),
        }]),
    };
    // Each derivation: union of inputs' backing. No new entries (no new
    // sources consulted), no resets. Stages are transparent, like caches.
    let summary = Artifact {
        label: "LLM summary",
        produced_at_secs: july + 2,
        backing: memory_read.backing.union(&BackingSet::new()),
    };
    let plan = Artifact {
        label: "action plan",
        produced_at_secs: july + 5,
        backing: summary.backing.union(&BackingSet::new()),
    };

    let now = july + 5;
    println!(
        "  {}: produced {}s ago, backing max-age {} days",
        plan.label,
        now - plan.produced_at_secs,
        plan.backing.max_age_secs(now).unwrap() / DAY
    );
    match plan.backing.gate(&policy, now) {
        BackingVerdict::Fresh => println!("  => gate: FRESH (unexpected!)"),
        BackingVerdict::Stale(stale) => {
            println!("  => gate: STALE — refuse to settle. Targeted re-verification list:");
            for s in &stale {
                println!(
                    "     re-verify {} (class {}, age {} days, window {} days)",
                    s.entry.source_id,
                    s.entry.class,
                    s.age_secs / DAY,
                    s.limit_secs.map(|l| l / DAY).unwrap_or(0)
                );
            }
        }
    }

    // Re-validation — a new attestation event — is the ONLY refresh.
    let revalidated = BackingSet::from_entries([BackingEntry {
        source_id: "obs:44".to_string(),
        attested_at_secs: now - 60, // re-checked against ground truth just now
        class: "repo-structure".to_string(),
    }]);
    println!(
        "  after re-validating obs:44 against ground truth: gate = {:?}\n",
        revalidated.gate(&policy, now)
    );

    // ---------------------------------------------------------------
    // Privacy at the trust boundary (spec §2.5).
    // ---------------------------------------------------------------
    println!("-- trust boundary (privacy rule, spec §2.5) --");
    println!(
        "  full backing set (STAYS HOME - provenance trace): {} entr{}, sources {:?}",
        plan.backing.len(),
        if plan.backing.len() == 1 { "y" } else { "ies" },
        plan.backing.iter().map(|e| e.source_id.as_str()).collect::<Vec<_>>()
    );
    let boundary = plan.backing.to_boundary(now).unwrap();
    println!(
        "  what crosses the boundary: {}",
        serde_json::to_string(&boundary).unwrap()
    );
    println!("  (one scalar - RFC 9111's Age, the privacy-preserving degenerate form)");
}
