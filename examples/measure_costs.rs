//! Cost measurement for the paper's "Reference Implementation" section (v0.7).
//!
//! Reports throughput of the three hot primitives:
//!   - `ExecutionContextRoot::merkle_root` (one SHA-256 over the canonical preimage)
//!   - `MockCommitter::commit`            (merkle_root + signing digest + Ed25519 sign)
//!   - `MockVerifier::verify`             (Ed25519 verify + attestation check)
//!
//! Run with: `cargo run --release --example measure_costs`
//! The canonical *sizes* are computed by hand from the struct layout
//! (see the paper); this binary only measures wall-clock throughput, so the
//! paper can cite a real per-op cost with a machine + toolchain footnote.

use std::time::Instant;

use ed25519_dalek::SigningKey;
use rand::rngs::StdRng;
use rand::SeedableRng;

use proof_of_context::{
    anchor::TripleAnchor,
    commitment::{CommitmentVerifier, ContextCommitter},
    context::{
        AttentionImpl, ExecutionContextRoot, InferenceConfig, PrecisionMode, SamplingParams,
    },
    mock::{MockCommitter, MockVerifier},
};

fn sample_root() -> ExecutionContextRoot {
    ExecutionContextRoot {
        weights_hash: [0xAA; 32],
        tokenizer_hash: [0xBB; 32],
        system_prompt_hash: [0xCC; 32],
        sampling_params: SamplingParams { temperature: 0.7, top_k: 50, top_p: 0.9, seed: 42 },
        runtime_version: [0xDD; 32],
        attention_impl_id: AttentionImpl::FlashAttention2,
        precision_mode: PrecisionMode::Bf16,
        inference_config: InferenceConfig {
            max_tokens: 256,
            stop_sequences_root: [0xEE; 32],
            penalty_params_root: [0xFF; 32],
        },
        input_manifest_root: [0x11; 32],
        kv_cache_root: None,
    }
}

fn main() {
    let n: u32 = 200_000;
    let root = sample_root();
    let mut rng = StdRng::seed_from_u64(1);
    let committer = MockCommitter::new(SigningKey::generate(&mut rng), "measure");
    let verifier = MockVerifier::new();
    let anchor = TripleAnchor::new(1_000, 1_700_000_000_000_000_000, 60_000);

    // merkle_root
    let t = Instant::now();
    let mut acc = 0u8;
    for _ in 0..n {
        acc ^= root.merkle_root()[0];
    }
    let mr = t.elapsed();

    // commit (merkle_root + digest + Ed25519 sign); includes one cheap struct clone
    let t = Instant::now();
    for _ in 0..n {
        let c = committer.commit(root.clone(), [0x22; 32], anchor).unwrap();
        acc ^= c.context_root[0];
    }
    let commit = t.elapsed();

    // verify (Ed25519 verify + attestation check)
    let c = committer.commit(root.clone(), [0x22; 32], anchor).unwrap();
    let t = Instant::now();
    for _ in 0..n {
        verifier.verify(&c).unwrap();
    }
    let verify = t.elapsed();

    println!("iterations = {n}  (sink = {acc})");
    println!("merkle_root      : {:>8.3} us/op  ({:.0} op/s)", us(mr, n), ops(mr, n));
    println!("commit(sign)     : {:>8.3} us/op  ({:.0} op/s)", us(commit, n), ops(commit, n));
    println!("verify           : {:>8.3} us/op  ({:.0} op/s)", us(verify, n), ops(verify, n));

    #[cfg(all(feature = "oracle-fi", feature = "oracle-fm", feature = "darkpool-sol"))]
    measure_oracles(n);
}

/// Off-chain oracle primitive costs (pieza 1b / dark-pool). Run with:
/// `cargo run --release --example measure_costs --features "oracle-fi oracle-fm darkpool-sol"`
#[cfg(all(feature = "oracle-fi", feature = "oracle-fm", feature = "darkpool-sol"))]
fn measure_oracles(n: u32) {
    use ed25519_dalek::Signer;
    use proof_of_context::{
        canonical::canonical_hash,
        darkpool::{verify_party_contexts, DarkPoolThresholds, PartyContext, PartyRole},
        input_freshness::InputAttestation,
        model_registry::{ModelEpoch, ModelLineage, QuorumModelOracle, QuorumSignature},
        price_freshness::{PriceAttestation, PriceFreshnessOracle},
        mock::{MockCommitter as MC, MockVerifier as MV},
        commitment::ContextCommitter as _,
    };

    let mut rng = StdRng::seed_from_u64(7);
    let mut acc = 0u8;

    // (a) canonical_hash over a representative f_i manifest (1 source).
    let manifest = serde_json::json!({
        "sources": [{ "endpoint": "/api/v1/prices",
            "payload_hash": "5525810608ca0d5ec814d45159e4f11e09a533061f04f4193850b3ca2fc5c453",
            "source_id": "baseoracle:default" }],
        "version": "f_i/0.1"
    });
    let t = Instant::now();
    for _ in 0..n { acc ^= canonical_hash(&manifest)[0]; }
    let chash = t.elapsed();

    // (b) f_i witness: parse + Ed25519 verify of one BaseOracle attestation.
    let opkey = ed25519_dalek::SigningKey::generate(&mut rng);
    let att = {
        let base = InputAttestation {
            source_id: "baseoracle:default".into(), endpoint: "/api/v1/prices".into(),
            payload_hash: [0x55; 32], timestamp: "2025-04-29T12:33:00.000Z".into(),
            freshness_horizon_secs: 60, anchor_block_height: Some(1000),
            signature: None, public_key: None, freshness_type: "f_i".into(),
        };
        let sig = opkey.sign(base.signing_message().as_bytes());
        InputAttestation { signature: Some(sig.to_bytes()),
            public_key: Some(opkey.verifying_key().to_bytes()), ..base }
    };
    let t = Instant::now();
    for _ in 0..n { att.verify_signature().unwrap(); acc ^= att.payload_hash[0]; }
    let fi_verify = t.elapsed();

    // (c) f_m quorum: adopt a 2-epoch lineage under a 2-of-3 quorum (2 Ed25519 verifies).
    let pubs: Vec<ed25519_dalek::SigningKey> =
        (0..3).map(|_| ed25519_dalek::SigningKey::generate(&mut rng)).collect();
    let lineage = ModelLineage::new(vec![
        ModelEpoch { weights_hash: [0x10; 32], epoch: 0, activation_block: 100 },
        ModelEpoch { weights_hash: [0x11; 32], epoch: 1, activation_block: 200 },
    ]);
    let msg = lineage.signing_message();
    let sigs: Vec<QuorumSignature> = pubs[..2].iter().map(|k| QuorumSignature {
        public_key: k.verifying_key().to_bytes(), signature: k.sign(msg.as_bytes()).to_bytes(),
    }).collect();
    let pubset: Vec<[u8; 32]> = pubs.iter().map(|k| k.verifying_key().to_bytes()).collect();
    let t = Instant::now();
    for _ in 0..n {
        let mut o = QuorumModelOracle::new(pubset.clone(), 2);
        o.present_lineage(lineage.clone(), &sigs).unwrap();
        acc ^= o.lineage().is_some() as u8;
    }
    let fm_quorum = t.elapsed();

    // (d) multi-party gate: verify_party_contexts for 2 parties (full per-party gate).
    let root = sample_root();
    let committer = MC::new(ed25519_dalek::SigningKey::generate(&mut rng), "p");
    let drand = 5_015_631u64;
    let wall = proof_of_context::anchor::DRAND_GENESIS_UNIX + drand * 30;
    let anchor = TripleAnchor::new(1, (wall as u128) * 1_000_000_000, drand);
    let commitment = committer.commit(root.clone(), [0x22; 32], anchor).unwrap();
    let market = [0xA1; 32];
    let mut price_oracle = PriceFreshnessOracle::new(None);
    let pa = {
        let b = PriceAttestation { market_id: market, price: 65_000_000,
            price_as_of_secs: wall - 5, signature: None, public_key: None };
        let s = opkey.sign(b.signing_message().as_bytes());
        PriceAttestation { signature: Some(s.to_bytes()),
            public_key: Some(opkey.verifying_key().to_bytes()), ..b }
    };
    price_oracle.present_price(pa).unwrap();
    let parties = [
        PartyContext { role: PartyRole::Intent, commitment: commitment.clone(),
            root: root.clone(), market_id: market, quote_created_at_secs: wall - 10 },
        PartyContext { role: PartyRole::Response, commitment: commitment.clone(),
            root: root.clone(), market_id: market, quote_created_at_secs: wall - 8 },
    ];
    let verifier = MV::new();
    let th = DarkPoolThresholds::default();
    let t = Instant::now();
    for _ in 0..n {
        let r = verify_party_contexts(&verifier, &parties, &price_oracle, wall, &th).unwrap();
        acc ^= matches!(r, proof_of_context::darkpool::DarkPoolSettlement::Clear) as u8;
    }
    let dp_gate = t.elapsed();

    println!("--- oracle paths (sink = {acc}) ---");
    println!("canonical_hash   : {:>8.3} us/op  ({:.0} op/s)", us(chash, n), ops(chash, n));
    println!("f_i witness vfy  : {:>8.3} us/op  ({:.0} op/s)", us(fi_verify, n), ops(fi_verify, n));
    println!("f_m quorum 2of3  : {:>8.3} us/op  ({:.0} op/s)", us(fm_quorum, n), ops(fm_quorum, n));
    println!("darkpool gate x2 : {:>8.3} us/op  ({:.0} op/s)", us(dp_gate, n), ops(dp_gate, n));
}

fn us(d: std::time::Duration, n: u32) -> f64 {
    d.as_secs_f64() * 1e6 / f64::from(n)
}
fn ops(d: std::time::Duration, n: u32) -> f64 {
    f64::from(n) / d.as_secs_f64()
}
