//! Pieza 1b-i — real input-freshness (f_i) oracle tests.
//!
//! All software-key, no network. Mints BaseOracle-shaped `_poc` attestations
//! with in-memory Ed25519 keys, then exercises parsing, signature verification,
//! manifest-root reconstruction, the block-lag policy, and the settlement gate
//! end-to-end with a `SplitOracle { model: mock, input: real }`.
//!
//! The whole file is gated on `oracle-fi` so the default `cargo test` (which
//! lacks the `input_freshness` module) still compiles it as empty.
#![cfg(feature = "oracle-fi")]

use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::StdRng;
use rand::SeedableRng;
use serde_json::Value;

use proof_of_context::{
    anchor::{TripleAnchor, BASE_BLOCK_PERIOD_SECS, BASE_MAINNET_GENESIS_UNIX, DRAND_GENESIS_UNIX, DRAND_PERIOD_SECS},
    context::{
        AttentionImpl, ExecutionContextRoot, Hash32, InferenceConfig, PrecisionMode, SamplingParams,
    },
    freshness::{FreshnessThresholds, FreshnessType},
    input_freshness::{BaseOracleInputOracle, InputAttestation, InputFreshnessWitness},
    mock::{MockCanonicalStateOracle, MockCommitter, MockSettlementGate, MockVerifier},
    settle::{SettlementGate, SettlementResult},
    CanonicalStateOracle, ContextCommitter, PocError, SplitOracle,
};

// --- helpers ---------------------------------------------------------------

fn key(seed: u64) -> SigningKey {
    SigningKey::generate(&mut StdRng::seed_from_u64(seed))
}

/// Mint a BaseOracle-shaped `_poc` attestation, signing the exact canonical
/// signing message with `sk`.
fn make_poc(
    sk: &SigningKey,
    source_id: &str,
    endpoint: &str,
    payload_hash: Hash32,
    timestamp: &str,
    horizon: u64,
    block_height: Option<u64>,
) -> Value {
    let att = InputAttestation {
        source_id: source_id.to_owned(),
        endpoint: endpoint.to_owned(),
        payload_hash,
        timestamp: timestamp.to_owned(),
        freshness_horizon_secs: horizon,
        anchor_block_height: block_height,
        signature: None,
        public_key: None,
        freshness_type: "f_i".to_owned(),
    };
    let sig = sk.sign(att.signing_message().as_bytes());
    serde_json::json!({
        "version": "0.1",
        "freshness_type": "f_i",
        "source_id": source_id,
        "endpoint": endpoint,
        "timestamp": timestamp,
        "freshness_horizon_seconds": horizon,
        "payload_hash": hex::encode(payload_hash),
        "signature": hex::encode(sig.to_bytes()),
        "public_key": hex::encode(sk.verifying_key().to_bytes()),
        "anchors": { "server_timestamp": timestamp, "drand_round": Value::Null, "block_height": block_height },
    })
}

const TS: &str = "2025-04-29T12:33:00.000Z";

/// Fully internally-consistent commit anchor (see oracle_gating.rs).
fn consistent_anchor(drand_round: u64) -> TripleAnchor {
    let wall = DRAND_GENESIS_UNIX + drand_round * DRAND_PERIOD_SECS;
    let block = (wall - BASE_MAINNET_GENESIS_UNIX) / BASE_BLOCK_PERIOD_SECS;
    TripleAnchor::new(block, (wall as u128) * 1_000_000_000, drand_round)
}

fn now_at_block(block_height: u64) -> TripleAnchor {
    TripleAnchor::new(block_height, 0, 0)
}

fn root_with_manifest(input_manifest_root: Hash32) -> ExecutionContextRoot {
    ExecutionContextRoot {
        weights_hash: [0xAA; 32],
        tokenizer_hash: [0xBB; 32],
        system_prompt_hash: [0xCC; 32],
        sampling_params: SamplingParams { temperature: 0.7, top_k: 50, top_p: 0.9, seed: 1 },
        runtime_version: [0xDD; 32],
        attention_impl_id: AttentionImpl::FlashAttention2,
        precision_mode: PrecisionMode::Bf16,
        inference_config: InferenceConfig {
            max_tokens: 256,
            stop_sequences_root: [0xEE; 32],
            penalty_params_root: [0xFF; 32],
        },
        input_manifest_root,
        kv_cache_root: None,
    }
}

// --- parsing / signature ---------------------------------------------------

#[test]
fn signing_message_matches_baseoracle_format() {
    let att = InputAttestation {
        source_id: "baseoracle:test".into(),
        endpoint: "/api/v1/prices".into(),
        payload_hash: [0x11; 32],
        timestamp: TS.into(),
        freshness_horizon_secs: 60,
        anchor_block_height: None,
        signature: None,
        public_key: None,
        freshness_type: "f_i".into(),
    };
    // Insertion-order JSON, exactly as poc.js builds it (NOT key-sorted).
    let expected = "{\"payload_hash\":\"1111111111111111111111111111111111111111111111111111111111111111\",\"source_id\":\"baseoracle:test\",\"endpoint\":\"/api/v1/prices\",\"timestamp\":\"2025-04-29T12:33:00.000Z\",\"freshness_horizon_seconds\":60,\"freshness_type\":\"f_i\"}";
    assert_eq!(att.signing_message(), expected);
}

#[test]
fn valid_signature_verifies_and_tamper_fails() {
    let sk = key(1);
    let poc = make_poc(&sk, "baseoracle:test", "/api/v1/prices", [0x11; 32], TS, 60, Some(100));
    let att = InputAttestation::from_poc_json(&poc).unwrap();
    att.verify_signature().expect("valid signature must verify");

    // Flip a signature byte → InvalidSignature.
    let mut bad = att.clone();
    let mut sig = bad.signature.unwrap();
    sig[0] ^= 0xFF;
    bad.signature = Some(sig);
    assert_eq!(bad.verify_signature().unwrap_err(), PocError::InvalidSignature);
}

// --- manifest root ---------------------------------------------------------

#[test]
fn manifest_root_is_presentation_order_independent() {
    let sk = key(2);
    let a = make_poc(&sk, "baseoracle:a", "/api/v1/prices", [0x01; 32], TS, 60, Some(100));
    let b = make_poc(&sk, "baseoracle:b", "/api/v1/gas", [0x02; 32], TS, 60, Some(100));

    let w1 = InputFreshnessWitness::from_poc_blocks(&[a.clone(), b.clone()], None).unwrap();
    let w2 = InputFreshnessWitness::from_poc_blocks(&[b, a], None).unwrap();
    assert_eq!(w1.input_manifest_root(), w2.input_manifest_root());
}

#[test]
fn manifest_root_changes_with_payload_hash() {
    let sk = key(3);
    let a = make_poc(&sk, "baseoracle:a", "/api/v1/prices", [0x01; 32], TS, 60, Some(100));
    let a2 = make_poc(&sk, "baseoracle:a", "/api/v1/prices", [0x09; 32], TS, 60, Some(100));
    let r1 = InputFreshnessWitness::from_poc_blocks(&[a], None).unwrap().input_manifest_root();
    let r2 = InputFreshnessWitness::from_poc_blocks(&[a2], None).unwrap().input_manifest_root();
    assert_ne!(r1, r2);
}

// --- f_i lag (direct oracle) ----------------------------------------------

fn oracle_with(att_block: Option<u64>, horizon: u64, enforce: bool) -> (BaseOracleInputOracle, Hash32) {
    let sk = key(7);
    let poc = make_poc(&sk, "baseoracle:test", "/api/v1/prices", [0x11; 32], TS, horizon, att_block);
    let mut oracle = BaseOracleInputOracle::new(None).with_enforce_horizon(enforce);
    let root = oracle.present_witness(&[poc]).unwrap();
    (oracle, root)
}

#[test]
fn fresh_input_low_lag() {
    let (oracle, root) = oracle_with(Some(1_000), 600, true);
    let lag = oracle.input_lag_blocks(root, &now_at_block(1_003)).unwrap();
    assert_eq!(lag, 3);
}

#[test]
fn unknown_root_is_unavailable() {
    let (oracle, _root) = oracle_with(Some(1_000), 600, true);
    let err = oracle.input_lag_blocks([0x42; 32], &now_at_block(1_003)).unwrap_err();
    assert_eq!(err, PocError::OracleUnavailable);
}

#[test]
fn horizon_expiry_is_unavailable_but_optional() {
    // horizon 2s → 1 block; lag 5 > 1 → expired when enforced.
    let (oracle, root) = oracle_with(Some(1_000), 2, true);
    assert_eq!(
        oracle.input_lag_blocks(root, &now_at_block(1_005)).unwrap_err(),
        PocError::OracleUnavailable
    );
    // Same witness, enforcement off → lag returned (gate's max_fi bounds it).
    let (oracle2, root2) = oracle_with(Some(1_000), 2, false);
    assert_eq!(oracle2.input_lag_blocks(root2, &now_at_block(1_005)).unwrap(), 5);
}

#[test]
fn backwards_clock_saturates_to_zero() {
    // Attestation block is ahead of `now` → lag saturates to 0, no panic.
    let (oracle, root) = oracle_with(Some(1_010), 600, true);
    assert_eq!(oracle.input_lag_blocks(root, &now_at_block(1_005)).unwrap(), 0);
}

#[test]
fn null_block_without_real_anchors_is_unavailable() {
    // Without the real-anchors fallback, a null block anchor cannot be dated.
    let (oracle, root) = oracle_with(None, 600, true);
    let res = oracle.input_lag_blocks(root, &now_at_block(1_003));
    #[cfg(not(feature = "real-anchors"))]
    assert_eq!(res.unwrap_err(), PocError::OracleUnavailable);
    #[cfg(feature = "real-anchors")]
    {
        // With the fallback, the block is derived from TS; lag is a large but
        // finite number (TS ~2025 maps to a real Base block far below 1_003).
        assert!(res.is_ok());
    }
}

// --- end-to-end through the settlement gate --------------------------------

fn gate(
    oracle: BaseOracleInputOracle,
) -> MockSettlementGate<MockVerifier, SplitOracle<MockCanonicalStateOracle, BaseOracleInputOracle>> {
    MockSettlementGate::new(
        MockVerifier::new(),
        SplitOracle { model: MockCanonicalStateOracle::always_fresh(), input: oracle },
    )
}

#[test]
fn gate_clears_fresh_input() {
    let sk = key(10);
    let commit = consistent_anchor(5_015_631);
    // Attestation block a few behind the commit block (lag 5 ≤ max_fi 15).
    let poc = make_poc(&sk, "baseoracle:test", "/api/v1/prices", [0x11; 32], TS, 600, Some(commit.block_height - 5));

    let mut oracle = BaseOracleInputOracle::new(None);
    let manifest = oracle.present_witness(&[poc]).unwrap();
    let root = root_with_manifest(manifest);

    let committer = MockCommitter::new(key(11), "worker");
    let commitment = committer.commit(root.clone(), [0x22; 32], commit).unwrap();

    let now = now_at_block(commit.block_height + 1);
    let result = gate(oracle)
        .verify_and_settle(&commitment, &root, &now, &FreshnessThresholds::default_base_mainnet())
        .unwrap();
    assert_eq!(result, SettlementResult::Clear);
}

#[test]
fn gate_rejects_stale_input() {
    let sk = key(12);
    let commit = consistent_anchor(5_015_631);
    // Attestation 100 blocks behind → lag 100 > max_fi 15 → Input.
    let poc = make_poc(&sk, "baseoracle:test", "/api/v1/prices", [0x11; 32], TS, 6000, Some(commit.block_height - 100));

    let mut oracle = BaseOracleInputOracle::new(None);
    let manifest = oracle.present_witness(&[poc]).unwrap();
    let root = root_with_manifest(manifest);

    let committer = MockCommitter::new(key(13), "worker");
    let commitment = committer.commit(root.clone(), [0u8; 32], commit).unwrap();

    let now = now_at_block(commit.block_height);
    match gate(oracle)
        .verify_and_settle(&commitment, &root, &now, &FreshnessThresholds::default_base_mainnet())
        .unwrap()
    {
        SettlementResult::Rejected(v) => {
            assert!(v.contains(&FreshnessType::Input), "stale input must trip f_i: {v:?}");
            assert!(!v.contains(&FreshnessType::Model), "model is always_fresh: {v:?}");
        }
        SettlementResult::Clear => panic!("stale input must not clear"),
    }
}

#[test]
fn gate_rejects_manifest_mismatch() {
    // Witness presented under root R, but the committed/disclosed root carries
    // a DIFFERENT input_manifest_root → oracle lookup misses → Input stale.
    let sk = key(14);
    let commit = consistent_anchor(5_015_631);
    let poc = make_poc(&sk, "baseoracle:test", "/api/v1/prices", [0x11; 32], TS, 600, Some(commit.block_height - 1));

    let mut oracle = BaseOracleInputOracle::new(None);
    oracle.present_witness(&[poc]).unwrap();
    // Commit against an unrelated manifest root the oracle never saw.
    let root = root_with_manifest([0x77; 32]);

    let committer = MockCommitter::new(key(15), "worker");
    let commitment = committer.commit(root.clone(), [0u8; 32], commit).unwrap();

    let now = now_at_block(commit.block_height + 1);
    match gate(oracle)
        .verify_and_settle(&commitment, &root, &now, &FreshnessThresholds::default_base_mainnet())
        .unwrap()
    {
        SettlementResult::Rejected(v) => assert!(v.contains(&FreshnessType::Input)),
        SettlementResult::Clear => panic!("manifest mismatch must not clear"),
    }
}
