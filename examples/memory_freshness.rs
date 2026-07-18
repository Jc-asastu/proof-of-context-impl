//! Agent memory as persisted context — the third instantiation.
//!
//! Companion to `paper-poc-agent-memory-v0.1` in the position-paper repo.
//! Demonstrates that the renewal primitive transfers to agent memory with
//! zero new machinery:
//!
//! - the memory's **source set** is the context root,
//! - the **verification event** is the commit anchor,
//! - **source drift** is the canonical-root bump,
//! - the **read** is the settlement,
//! - **re-verification** is the recommit.
//!
//! The fact persists; the attestation renews. A read never hard-fails —
//! it returns the fact plus a verdict:
//!
//! - `StillValid`                   → serve, load-bearing.
//! - `ProtectedByProspectiveOnly`   → serve, flagged: sources drifted,
//!                                    grace window still open.
//! - `ExpiredRequireRecommit`       → serve as unverified; re-attest
//!                                    against current sources before the
//!                                    memory bears load again.
//!
//! Run with: `cargo run --example memory_freshness`

use ed25519_dalek::{Signer, SigningKey};
use proof_of_context::anchor::TripleAnchor;
use proof_of_context::attestation::{AttestationChain, AttestationVendor};
use proof_of_context::commitment::{CommitmentVerifier, FreshnessCommitment};
use proof_of_context::context::Hash32;
use proof_of_context::freshness::FreshnessThresholds;
use proof_of_context::mock::MockVerifier;
use proof_of_context::renewal::{Renewal, RenewalOutcome, WindowedRenewal};
use sha2::{Digest, Sha256};

/// A memory entry: an immutable fact derived from a declared source set.
/// The fact is never mutated or deleted by staleness — only its
/// attestation is renewed.
struct MemoryEntry {
    name: &'static str,
    fact: &'static str,
    /// The live attestation: a signed commitment binding the source-set
    /// root, the fact hash, and the verification anchor.
    attestation: FreshnessCommitment,
}

/// Canonical source-set root: SHA-256 over the sorted (id, content-hash)
/// pairs of every source the memory derives from. Any source affecting
/// validity that is omitted here is the §8 trivial-evasion vector.
fn source_set_root(sources: &[(&str, &str)]) -> Hash32 {
    let mut pairs: Vec<(&str, Hash32)> = sources
        .iter()
        .map(|(id, content)| {
            let mut h = Sha256::new();
            h.update(content.as_bytes());
            (*id, h.finalize().into())
        })
        .collect();
    pairs.sort_by(|a, b| a.0.cmp(b.0));

    let mut h = Sha256::new();
    for (id, content_hash) in pairs {
        h.update((id.len() as u64).to_le_bytes());
        h.update(id.as_bytes());
        h.update(content_hash);
    }
    h.finalize().into()
}

fn fact_hash(fact: &str) -> Hash32 {
    let mut h = Sha256::new();
    h.update(fact.as_bytes());
    h.finalize().into()
}

/// Attest (or re-attest) a fact against a source set at a verification
/// anchor. This is the memory-side committer: same signed object the
/// settlement papers use, produced at verify time instead of compute time.
fn attest(
    key: &SigningKey,
    sources: &[(&str, &str)],
    fact: &str,
    verified_at: TripleAnchor,
) -> FreshnessCommitment {
    let mut c = FreshnessCommitment {
        context_root: source_set_root(sources),
        anchor: verified_at,
        output_hash: fact_hash(fact),
        signature: [0u8; 64],
        public_key: key.verifying_key().to_bytes(),
        attestation_chain: AttestationChain {
            payload: b"memory-reverifier-software".to_vec(),
            vendor: AttestationVendor::MockSoftware,
        },
    };
    c.signature = key.sign(&c.signing_digest()).to_bytes();
    c
}

/// A read: settlement of the memory. Returns the fact regardless of
/// verdict — staleness demotes, it never destroys.
fn read(entry: &MemoryEntry, current_source_root: Hash32, now: &TripleAnchor,
        thresholds: &FreshnessThresholds) -> RenewalOutcome {
    let verdict = WindowedRenewal
        .evaluate(&entry.attestation, current_source_root, now, thresholds)
        .expect("renewal evaluation is total over well-formed commitments");
    let label = match verdict {
        RenewalOutcome::StillValid => "STILL VALID          — serve, load-bearing",
        RenewalOutcome::ProtectedByProspectiveOnly =>
            "PROTECTED (flagged)  — sources drifted, grace window open",
        RenewalOutcome::ExpiredRequireRecommit =>
            "EXPIRED              — serve unverified, re-attest before acting",
    };
    println!("  read @{:>5} [{}] {}", now.block_height, entry.name, label);
    println!("        fact: {:?}", entry.fact);
    verdict
}

fn main() {
    let thresholds = FreshnessThresholds::default_base_mainnet(); // max_fs = 300
    let key = SigningKey::from_bytes(&[7u8; 32]);

    // The memory derives from two sources: a config file and a spec.
    let sources_v1: &[(&str, &str)] =
        &[("config/deploy.toml", "region = \"us-east\""),
          ("docs/spec.md", "the deploy region is us-east")];

    // ── Write + attest at block 1_000 ────────────────────────────────────
    let entry = MemoryEntry {
        name: "deploy-region",
        fact: "the project deploys to us-east",
        attestation: attest(&key, sources_v1, "the project deploys to us-east",
                            TripleAnchor::new(1_000, 0, 0)),
    };
    MockVerifier::new().verify(&entry.attestation)
        .expect("attestation signature verifies");
    println!("attested [deploy-region] at block 1000 (Ed25519 verified)\n");

    // ── Read 1: sources unchanged ────────────────────────────────────────
    println!("sources unchanged:");
    let v = read(&entry, source_set_root(sources_v1),
                 &TripleAnchor::new(1_050, 0, 0), &thresholds);
    assert_eq!(v, RenewalOutcome::StillValid);

    // ── The world drifts: config edited, region moved ────────────────────
    let sources_v2: &[(&str, &str)] =
        &[("config/deploy.toml", "region = \"sa-east\""),
          ("docs/spec.md", "the deploy region is us-east")];
    let bumped_root = source_set_root(sources_v2);
    println!("\nsource drift: config/deploy.toml changed (root bumped)");

    // ── Read 2: drift within the grace window ────────────────────────────
    println!("read inside the f_s grace window:");
    let v = read(&entry, bumped_root, &TripleAnchor::new(1_200, 0, 0), &thresholds);
    assert_eq!(v, RenewalOutcome::ProtectedByProspectiveOnly);

    // ── Read 3: drift past the window ────────────────────────────────────
    println!("read past the window:");
    let v = read(&entry, bumped_root, &TripleAnchor::new(1_400, 0, 0), &thresholds);
    assert_eq!(v, RenewalOutcome::ExpiredRequireRecommit);

    // ── Recommit: re-verify the fact against current sources ─────────────
    // The re-verifier finds the world changed and revises the fact. The old
    // fact is not deleted — a real store appends; the attestation renews.
    let renewed = MemoryEntry {
        name: "deploy-region",
        fact: "the project deploys to sa-east",
        attestation: attest(&key, sources_v2, "the project deploys to sa-east",
                            TripleAnchor::new(1_400, 0, 0)),
    };
    println!("\nrecommitted against current sources at block 1400:");
    let v = read(&renewed, bumped_root, &TripleAnchor::new(1_410, 0, 0), &thresholds);
    assert_eq!(v, RenewalOutcome::StillValid);

    println!("\nthe fact persists; the attestation renews.");
}
