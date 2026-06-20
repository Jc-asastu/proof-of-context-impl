//! Pieza 1b-m — committee/quorum model-freshness (f_m) oracle tests.
//!
//! All software-key, no network. Builds a model lineage, has N publishers sign
//! its canonical snapshot, presents an M-of-N quorum, and exercises the
//! `model_epoch_distance` policy plus the settlement gate end-to-end with a
//! `SplitOracle { model: real quorum, input: mock-fresh }`.
#![cfg(feature = "oracle-fm")]

use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::StdRng;
use rand::SeedableRng;

use proof_of_context::{
    anchor::{TripleAnchor, BASE_BLOCK_PERIOD_SECS, BASE_MAINNET_GENESIS_UNIX, DRAND_GENESIS_UNIX, DRAND_PERIOD_SECS},
    context::{
        AttentionImpl, ExecutionContextRoot, Hash32, InferenceConfig, PrecisionMode, SamplingParams,
    },
    freshness::{FreshnessThresholds, FreshnessType},
    mock::{MockCanonicalStateOracle, MockCommitter, MockSettlementGate, MockVerifier},
    model_registry::{ModelEpoch, ModelLineage, QuorumModelOracle, QuorumSignature},
    settle::{SettlementGate, SettlementResult},
    CanonicalStateOracle, ContextCommitter, PocError, SplitOracle,
};

// --- helpers ---------------------------------------------------------------

fn key(seed: u64) -> SigningKey {
    SigningKey::generate(&mut StdRng::seed_from_u64(seed))
}

fn pk(k: &SigningKey) -> [u8; 32] {
    k.verifying_key().to_bytes()
}

fn sign_lineage(keys: &[&SigningKey], lineage: &ModelLineage) -> Vec<QuorumSignature> {
    let msg = lineage.signing_message();
    keys.iter()
        .map(|k| QuorumSignature {
            public_key: pk(k),
            signature: k.sign(msg.as_bytes()).to_bytes(),
        })
        .collect()
}

const WH_E0: [u8; 32] = [0x10; 32];
const WH_E1: [u8; 32] = [0x11; 32];
const WH_E2: [u8; 32] = [0x12; 32];

/// Three-epoch lineage activating at blocks 100/200/300.
fn lineage() -> ModelLineage {
    ModelLineage::new(vec![
        ModelEpoch { weights_hash: WH_E0, epoch: 0, activation_block: 100 },
        ModelEpoch { weights_hash: WH_E1, epoch: 1, activation_block: 200 },
        ModelEpoch { weights_hash: WH_E2, epoch: 2, activation_block: 300 },
    ])
}

/// 3 publishers, quorum 2-of-3.
fn publishers() -> (Vec<SigningKey>, Vec<[u8; 32]>) {
    let keys: Vec<SigningKey> = (0..3).map(|i| key(100 + i)).collect();
    let pks = keys.iter().map(pk).collect();
    (keys, pks)
}

fn at_block(block: u64) -> TripleAnchor {
    TripleAnchor::new(block, 0, 0)
}

// --- quorum adoption -------------------------------------------------------

#[test]
fn quorum_met_adopts_lineage() {
    let (keys, pks) = publishers();
    let mut oracle = QuorumModelOracle::new(pks, 2);
    let sigs = sign_lineage(&[&keys[0], &keys[1]], &lineage());
    oracle.present_lineage(lineage(), &sigs).expect("2-of-3 quorum must adopt");
    assert!(oracle.lineage().is_some());
}

#[test]
fn insufficient_quorum_rejected() {
    let (keys, pks) = publishers();
    let mut oracle = QuorumModelOracle::new(pks, 2);
    let sigs = sign_lineage(&[&keys[0]], &lineage()); // only 1 of required 2
    assert_eq!(
        oracle.present_lineage(lineage(), &sigs).unwrap_err(),
        PocError::OracleUnavailable
    );
}

#[test]
fn non_publisher_signature_does_not_count() {
    let (keys, pks) = publishers();
    let outsider = key(999); // not registered
    let mut oracle = QuorumModelOracle::new(pks, 2);
    // 1 registered + 1 outsider → only 1 counts → quorum (2) not met.
    let sigs = sign_lineage(&[&keys[0], &outsider], &lineage());
    assert_eq!(
        oracle.present_lineage(lineage(), &sigs).unwrap_err(),
        PocError::OracleUnavailable
    );
}

#[test]
fn signatures_over_a_different_lineage_fail() {
    let (keys, pks) = publishers();
    let mut oracle = QuorumModelOracle::new(pks, 2);
    // Sign the 3-epoch lineage, but present a tampered 2-epoch one.
    let sigs = sign_lineage(&[&keys[0], &keys[1]], &lineage());
    let tampered = ModelLineage::new(vec![
        ModelEpoch { weights_hash: WH_E0, epoch: 0, activation_block: 100 },
        ModelEpoch { weights_hash: WH_E1, epoch: 1, activation_block: 200 },
    ]);
    assert_eq!(
        oracle.present_lineage(tampered, &sigs).unwrap_err(),
        PocError::OracleUnavailable
    );
}

// --- epoch distance --------------------------------------------------------

fn adopted_oracle() -> QuorumModelOracle {
    let (keys, pks) = publishers();
    let mut oracle = QuorumModelOracle::new(pks, 2);
    let sigs = sign_lineage(&[&keys[0], &keys[1], &keys[2]], &lineage());
    oracle.present_lineage(lineage(), &sigs).unwrap();
    oracle
}

#[test]
fn current_model_distance_zero() {
    let oracle = adopted_oracle();
    // now past block 300 → canonical = e2; committed = e2 → distance 0.
    assert_eq!(oracle.model_epoch_distance(WH_E2, &at_block(350)).unwrap(), 0);
}

#[test]
fn one_epoch_behind_distance_one() {
    let oracle = adopted_oracle();
    // canonical at 350 = e2; committed = e1 → distance 1.
    assert_eq!(oracle.model_epoch_distance(WH_E1, &at_block(350)).unwrap(), 1);
}

#[test]
fn canonical_tracks_settlement_height() {
    let oracle = adopted_oracle();
    // At block 250 only e0,e1 are activated → canonical = e1; committed e1 → 0.
    assert_eq!(oracle.model_epoch_distance(WH_E1, &at_block(250)).unwrap(), 0);
    // committed e0 at block 250 → distance 1.
    assert_eq!(oracle.model_epoch_distance(WH_E0, &at_block(250)).unwrap(), 1);
}

#[test]
fn unknown_model_unavailable() {
    let oracle = adopted_oracle();
    assert_eq!(
        oracle.model_epoch_distance([0xAB; 32], &at_block(350)).unwrap_err(),
        PocError::OracleUnavailable
    );
}

#[test]
fn before_any_activation_unavailable() {
    let oracle = adopted_oracle();
    // now precedes the first activation (100) → nothing canonical yet.
    assert_eq!(
        oracle.model_epoch_distance(WH_E0, &at_block(50)).unwrap_err(),
        PocError::OracleUnavailable
    );
}

// --- end-to-end through the settlement gate --------------------------------

fn consistent_anchor(drand_round: u64) -> TripleAnchor {
    let wall = DRAND_GENESIS_UNIX + drand_round * DRAND_PERIOD_SECS;
    let block = (wall - BASE_MAINNET_GENESIS_UNIX) / BASE_BLOCK_PERIOD_SECS;
    TripleAnchor::new(block, (wall as u128) * 1_000_000_000, drand_round)
}

fn root_with_weights(weights_hash: Hash32) -> ExecutionContextRoot {
    ExecutionContextRoot {
        weights_hash,
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
        input_manifest_root: [0x11; 32],
        kv_cache_root: None,
    }
}

/// Build a lineage whose top epoch activates just below the commit block, so
/// `now` sees it as canonical. Returns the oracle + the canonical weights hash.
fn gate_oracle(commit_block: u64) -> (QuorumModelOracle, Hash32) {
    let (keys, pks) = publishers();
    let lin = ModelLineage::new(vec![
        ModelEpoch { weights_hash: WH_E0, epoch: 0, activation_block: commit_block - 50 },
        ModelEpoch { weights_hash: WH_E1, epoch: 1, activation_block: commit_block - 20 },
    ]);
    let sigs = sign_lineage(&[&keys[0], &keys[1]], &lin);
    let mut oracle = QuorumModelOracle::new(pks, 2);
    oracle.present_lineage(lin, &sigs).unwrap();
    (oracle, WH_E1)
}

fn gate(
    oracle: QuorumModelOracle,
) -> MockSettlementGate<MockVerifier, SplitOracle<QuorumModelOracle, MockCanonicalStateOracle>> {
    MockSettlementGate::new(
        MockVerifier::new(),
        SplitOracle { model: oracle, input: MockCanonicalStateOracle::always_fresh() },
    )
}

#[test]
fn gate_clears_current_model() {
    let commit = consistent_anchor(5_015_631);
    let (oracle, canonical_wh) = gate_oracle(commit.block_height);
    let root = root_with_weights(canonical_wh);

    let committer = MockCommitter::new(key(11), "worker");
    let commitment = committer.commit(root.clone(), [0x22; 32], commit).unwrap();

    let now = at_block(commit.block_height + 1);
    let result = gate(oracle)
        .verify_and_settle(&commitment, &root, &now, &FreshnessThresholds::default_base_mainnet())
        .unwrap();
    assert_eq!(result, SettlementResult::Clear);
}

#[test]
fn gate_rejects_stale_model() {
    // Lineage with 3 epochs; commit against the OLDEST → distance 2 > max_fm 1.
    let (keys, pks) = publishers();
    let commit = consistent_anchor(5_015_631);
    let b = commit.block_height;
    let lin = ModelLineage::new(vec![
        ModelEpoch { weights_hash: WH_E0, epoch: 0, activation_block: b - 60 },
        ModelEpoch { weights_hash: WH_E1, epoch: 1, activation_block: b - 40 },
        ModelEpoch { weights_hash: WH_E2, epoch: 2, activation_block: b - 20 },
    ]);
    let sigs = sign_lineage(&[&keys[0], &keys[1]], &lin);
    let mut oracle = QuorumModelOracle::new(pks, 2);
    oracle.present_lineage(lin, &sigs).unwrap();

    let root = root_with_weights(WH_E0); // two epochs behind canonical (e2)
    let committer = MockCommitter::new(key(12), "worker");
    let commitment = committer.commit(root.clone(), [0u8; 32], commit).unwrap();

    let now = at_block(b + 1);
    match gate(oracle)
        .verify_and_settle(&commitment, &root, &now, &FreshnessThresholds::default_base_mainnet())
        .unwrap()
    {
        SettlementResult::Rejected(v) => {
            assert!(v.contains(&FreshnessType::Model), "two epochs behind must trip f_m: {v:?}");
            assert!(!v.contains(&FreshnessType::Input), "input is always_fresh: {v:?}");
        }
        SettlementResult::Clear => panic!("stale model must not clear"),
    }
}
