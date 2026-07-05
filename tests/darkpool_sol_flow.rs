//! Pieza Solana brick 1 — multi-party dark-pool freshness gate tests.
//!
//! All software-key, no network. Simulates two agents (Intent + Response)
//! negotiating a dark-pool trade, each with its own proof-of-context
//! commitment + a presented market-price attestation, and checks that
//! `verify_party_contexts` clears iff every party's quote used fresh context,
//! attributing failures to the right party + freshness type.
#![cfg(feature = "darkpool-sol")]

use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::StdRng;
use rand::SeedableRng;

use proof_of_context::{
    anchor::{TripleAnchor, DRAND_GENESIS_UNIX, DRAND_PERIOD_SECS},
    context::{
        AttentionImpl, ExecutionContextRoot, InferenceConfig, PrecisionMode, SamplingParams,
    },
    freshness::FreshnessType,
    mock::{MockCommitter, MockVerifier},
    ContextCommitter, DarkPoolSettlement, DarkPoolThresholds, PartyContext, PartyRole,
    PriceAttestation, PriceFreshnessOracle, PocError,
};
use proof_of_context::darkpool::verify_party_contexts;

const MARKET_A: [u8; 32] = [0xA1; 32];
const ROUND: u64 = 5_015_631; // ~2025-04-29

fn key(seed: u64) -> SigningKey {
    SigningKey::generate(&mut StdRng::seed_from_u64(seed))
}

fn wall_of(drand_round: u64) -> u64 {
    DRAND_GENESIS_UNIX + drand_round * DRAND_PERIOD_SECS
}

/// Internally-consistent anchor: TEE wall-time derived from the Drand round.
fn consistent_anchor(drand_round: u64) -> TripleAnchor {
    let wall = wall_of(drand_round);
    TripleAnchor::new(1, (wall as u128) * 1_000_000_000, drand_round)
}

fn sample_root(seed: u64) -> ExecutionContextRoot {
    ExecutionContextRoot {
        weights_hash: [0xAA; 32],
        tokenizer_hash: [0xBB; 32],
        system_prompt_hash: [0xCC; 32],
        sampling_params: SamplingParams { temperature: 0.7, top_k: 50, top_p: 0.9, seed },
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

fn make_price_att(
    sk: &SigningKey,
    market_id: [u8; 32],
    price: u64,
    as_of_secs: u64,
) -> PriceAttestation {
    let mut att = PriceAttestation {
        market_id,
        price,
        price_as_of_secs: as_of_secs,
        signature: None,
        public_key: None,
    };
    let sig = sk.sign(att.signing_message().as_bytes());
    att.signature = Some(sig.to_bytes());
    att.public_key = Some(sk.verifying_key().to_bytes());
    att
}

/// Build a party with a fresh, internally-consistent commitment on MARKET_A.
fn party(role: PartyRole, seed: u64, quote_created_at_secs: u64) -> PartyContext {
    let committer = MockCommitter::new(key(seed), "agent");
    let root = sample_root(seed);
    let commitment = committer
        .commit(root.clone(), [0x22; 32], consistent_anchor(ROUND))
        .unwrap();
    PartyContext { role, commitment, root, market_id: MARKET_A, quote_created_at_secs }
}

fn oracle_with_price(operator: &SigningKey, as_of_secs: u64) -> PriceFreshnessOracle {
    let mut o = PriceFreshnessOracle::new(None);
    o.present_price(make_price_att(operator, MARKET_A, 65_000_000, as_of_secs))
        .unwrap();
    o
}

// --- tests -----------------------------------------------------------------

#[test]
fn two_agents_both_fresh_clears() {
    let now = wall_of(ROUND);
    let op = key(900);
    let oracle = oracle_with_price(&op, now - 5); // price 5s old
    let parties = [
        party(PartyRole::Intent, 1, now - 10),
        party(PartyRole::Response, 2, now - 8),
    ];
    let r = verify_party_contexts(&MockVerifier::new(), &parties, &oracle, now, &DarkPoolThresholds::default()).unwrap();
    assert_eq!(r, DarkPoolSettlement::Clear);
}

#[test]
fn one_party_stale_price_rejects() {
    // Stale price affects BOTH parties (shared market) — but this test uses a
    // per-party price by giving the Response party a different (stale) market.
    let now = wall_of(ROUND);
    let op = key(900);
    // Oracle has a FRESH price for MARKET_A and a STALE price for MARKET_B.
    let market_b = [0xB2; 32];
    let mut oracle = PriceFreshnessOracle::new(None);
    oracle.present_price(make_price_att(&op, MARKET_A, 65_000_000, now - 5)).unwrap();
    oracle.present_price(make_price_att(&op, market_b, 65_000_000, now - 120)).unwrap();

    let a = party(PartyRole::Intent, 1, now - 10); // MARKET_A, fresh
    let mut b = party(PartyRole::Response, 2, now - 8);
    b.market_id = market_b; // quoted against the stale market

    let r = verify_party_contexts(&MockVerifier::new(), &[a, b], &oracle, now, &DarkPoolThresholds::default()).unwrap();
    match r {
        DarkPoolSettlement::Rejected(v) => {
            assert_eq!(v.len(), 1, "only the stale party reported");
            assert_eq!(v[0].role, PartyRole::Response);
            assert!(v[0].violations.contains(&FreshnessType::Input));
        }
        DarkPoolSettlement::Clear => panic!("stale price must not clear"),
    }
}

#[test]
fn quote_too_old_rejects_settlement() {
    let now = wall_of(ROUND);
    let op = key(900);
    let oracle = oracle_with_price(&op, now - 5); // price fresh
    // Intent quote is older than the 600s window.
    let a = party(PartyRole::Intent, 1, now - 601);
    let b = party(PartyRole::Response, 2, now - 8);
    let r = verify_party_contexts(&MockVerifier::new(), &[a, b], &oracle, now, &DarkPoolThresholds::default()).unwrap();
    match r {
        DarkPoolSettlement::Rejected(v) => {
            assert_eq!(v.len(), 1);
            assert_eq!(v[0].role, PartyRole::Intent);
            assert!(v[0].violations.contains(&FreshnessType::Settlement));
            assert!(!v[0].violations.contains(&FreshnessType::Input), "price was fresh");
        }
        DarkPoolSettlement::Clear => panic!("stale quote must not clear"),
    }
}

#[test]
fn missing_price_for_market_is_input_stale() {
    let now = wall_of(ROUND);
    let oracle = PriceFreshnessOracle::new(None); // no price presented at all
    let parties = [party(PartyRole::Intent, 1, now - 10)];
    let r = verify_party_contexts(&MockVerifier::new(), &parties, &oracle, now, &DarkPoolThresholds::default()).unwrap();
    match r {
        DarkPoolSettlement::Rejected(v) => assert!(v[0].violations.contains(&FreshnessType::Input)),
        DarkPoolSettlement::Clear => panic!("unknown market must be treated as stale"),
    }
}

#[test]
fn inconsistent_anchor_is_computational() {
    let now = wall_of(ROUND);
    let op = key(900);
    let oracle = oracle_with_price(&op, now - 5);
    // Build a party whose commit anchor has TEE 120s off the Drand wall-time.
    let committer = MockCommitter::new(key(3), "agent");
    let root = sample_root(3);
    let tee_ns = ((wall_of(ROUND) + 120) as u128) * 1_000_000_000;
    let bad_anchor = TripleAnchor::new(1, tee_ns, ROUND);
    let commitment = committer.commit(root.clone(), [0u8; 32], bad_anchor).unwrap();
    let p = PartyContext { role: PartyRole::Intent, commitment, root, market_id: MARKET_A, quote_created_at_secs: now - 10 };

    let r = verify_party_contexts(&MockVerifier::new(), &[p], &oracle, now, &DarkPoolThresholds::default()).unwrap();
    match r {
        DarkPoolSettlement::Rejected(v) => assert!(v[0].violations.contains(&FreshnessType::Computational)),
        DarkPoolSettlement::Clear => panic!("inconsistent anchor must not clear"),
    }
}

#[test]
fn tampered_commitment_signature_errs_with_attribution() {
    let now = wall_of(ROUND);
    let op = key(900);
    let oracle = oracle_with_price(&op, now - 5);
    let mut p = party(PartyRole::Intent, 1, now - 10);
    p.commitment.signature[0] ^= 0xFF;
    let err = verify_party_contexts(&MockVerifier::new(), &[p], &oracle, now, &DarkPoolThresholds::default()).unwrap_err();
    assert_eq!(err.role, PartyRole::Intent, "integrity abort must name the failing party");
    assert_eq!(err.source, PocError::InvalidSignature);
}

#[test]
fn disclosed_root_mismatch_errs_with_attribution() {
    let now = wall_of(ROUND);
    let op = key(900);
    let oracle = oracle_with_price(&op, now - 5);
    let mut p = party(PartyRole::Response, 1, now - 10);
    p.root = sample_root(999); // different from what was committed
    let err = verify_party_contexts(&MockVerifier::new(), &[p], &oracle, now, &DarkPoolThresholds::default()).unwrap_err();
    assert_eq!(err.role, PartyRole::Response, "integrity abort must name the failing party");
    assert_eq!(err.source, PocError::RootMismatch);
}

#[test]
fn price_attestation_bad_signature_rejected() {
    let now = wall_of(ROUND);
    let op = key(900);
    let mut att = make_price_att(&op, MARKET_A, 65_000_000, now - 5);
    let mut sig = att.signature.unwrap();
    sig[0] ^= 0xFF;
    att.signature = Some(sig);
    let mut oracle = PriceFreshnessOracle::new(None);
    assert_eq!(oracle.present_price(att).unwrap_err(), PocError::InvalidSignature);
}

#[test]
fn operator_pin_enforced() {
    let now = wall_of(ROUND);
    let real_op = key(900);
    let impostor = key(901);
    let mut oracle = PriceFreshnessOracle::new(Some(real_op.verifying_key().to_bytes()));
    // Signed by the impostor (validly), but not the pinned operator.
    let att = make_price_att(&impostor, MARKET_A, 65_000_000, now - 5);
    assert_eq!(oracle.present_price(att).unwrap_err(), PocError::InvalidSignature);
}

#[test]
fn both_parties_stale_reports_both() {
    let now = wall_of(ROUND);
    let op = key(900);
    let market_b = [0xB2; 32];
    let mut oracle = PriceFreshnessOracle::new(None);
    oracle.present_price(make_price_att(&op, market_b, 65_000_000, now - 200)).unwrap(); // stale for B
    // A: fresh price missing for MARKET_A → Input stale. B: stale price on market_b → Input.
    // Give A a too-old quote so A trips Settlement, B trips Input.
    let a = party(PartyRole::Intent, 1, now - 700); // quote too old → Settlement; MARKET_A has no price → Input
    let mut b = party(PartyRole::Response, 2, now - 8);
    b.market_id = market_b;

    let r = verify_party_contexts(&MockVerifier::new(), &[a, b], &oracle, now, &DarkPoolThresholds::default()).unwrap();
    match r {
        DarkPoolSettlement::Rejected(v) => {
            assert_eq!(v.len(), 2, "both parties failing must be reported");
            let intent = v.iter().find(|pv| pv.role == PartyRole::Intent).unwrap();
            let resp = v.iter().find(|pv| pv.role == PartyRole::Response).unwrap();
            assert!(intent.violations.contains(&FreshnessType::Settlement));
            assert!(resp.violations.contains(&FreshnessType::Input));
        }
        DarkPoolSettlement::Clear => panic!("both stale must not clear"),
    }
}
