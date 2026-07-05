//! Mock backend — software-only implementations of the proof-of-context
//! traits, suitable for tests and development. **Not** suitable for
//! economic settlement: the attestation chain is a `MockSoftware` vendor
//! tag with no hardware trust root, and the signing key is a plain
//! Ed25519 keypair held in memory.
//!
//! The Phase 3 backend replaces this module with TDX + H100 attestation
//! and hardware-held keys.

use std::collections::HashMap;

use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::anchor::TripleAnchor;
use crate::attestation::{AttestationChain, AttestationVendor, AttestationVerifier};
use crate::commitment::{CommitmentVerifier, ContextCommitter, FreshnessCommitment};
use crate::context::{ExecutionContextRoot, Hash32};
use crate::error::PocError;
use crate::freshness::{FreshnessThresholds, FreshnessType};
use crate::oracle::CanonicalStateOracle;
use crate::settle::{SettlementGate, SettlementResult};

/// Software-only commitment producer — signs with an in-memory Ed25519 key.
pub struct MockCommitter {
    signing_key: SigningKey,
    identity: String,
}

impl MockCommitter {
    /// Construct a committer from an existing signing key.  Key generation
    /// is the caller's responsibility — the library deliberately does not
    /// depend on a randomness crate so that tests and integration stacks
    /// can choose their own RNG policy.
    pub fn new(signing_key: SigningKey, identity: impl Into<String>) -> Self {
        Self { signing_key, identity: identity.into() }
    }

    /// Return the committer's public verifying key (32 bytes).
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }
}

impl ContextCommitter for MockCommitter {
    fn commit(
        &self,
        root: ExecutionContextRoot,
        output_hash: Hash32,
        anchor: TripleAnchor,
    ) -> Result<FreshnessCommitment, PocError> {
        let context_root = root.merkle_root();

        // Build the canonical signing digest.
        let mut h = Sha256::new();
        h.update(context_root);
        h.update(anchor.block_height.to_le_bytes());
        h.update(anchor.tee_timestamp.to_le_bytes());
        h.update(anchor.drand_round.to_le_bytes());
        h.update(output_hash);
        let digest: [u8; 32] = h.finalize().into();

        // Sign the digest.
        let sig = self.signing_key.sign(&digest);
        let sig_bytes: [u8; 64] = sig.to_bytes();
        let pk_bytes: [u8; 32] = self.signing_key.verifying_key().to_bytes();

        Ok(FreshnessCommitment {
            context_root,
            anchor,
            output_hash,
            signature: sig_bytes,
            public_key: pk_bytes,
            attestation_chain: AttestationChain {
                payload: b"mock-software-attestation".to_vec(),
                vendor: AttestationVendor::MockSoftware,
            },
        })
    }

    fn identity(&self) -> &str {
        &self.identity
    }
}

/// Software-only commitment verifier — checks the Ed25519 signature and
/// accepts `MockSoftware` attestations unconditionally.  The production
/// verifier would replace the attestation check with TDX / H100 quote
/// validation against a known-good measurement registry.
pub struct MockVerifier;

impl MockVerifier {
    /// Construct the (stateless) software-only verifier.
    pub fn new() -> Self { Self }
}

impl Default for MockVerifier {
    fn default() -> Self { Self::new() }
}

impl CommitmentVerifier for MockVerifier {
    fn verify(&self, commitment: &FreshnessCommitment) -> Result<(), PocError> {
        // Reconstruct the canonical signing digest.
        let digest = commitment.signing_digest();

        let vk = VerifyingKey::from_bytes(&commitment.public_key)
            .map_err(|_| PocError::InvalidSignature)?;
        let sig = ed25519_dalek::Signature::from_bytes(&commitment.signature);

        vk.verify(&digest, &sig).map_err(|_| PocError::InvalidSignature)?;

        // Attestation chain: accept MockSoftware; reject anything else
        // in the mock verifier (because the mock does not know how to
        // parse hardware vendor formats).
        AttestationVerifier::verify(self, &commitment.attestation_chain)
    }
}

impl AttestationVerifier for MockVerifier {
    fn verify(&self, chain: &AttestationChain) -> Result<(), PocError> {
        if chain.vendor == AttestationVendor::MockSoftware {
            Ok(())
        } else {
            Err(PocError::InvalidAttestation)
        }
    }
}

/// Software-only settlement gate.  Combines signature/attestation
/// verification, context-disclosure binding, and the freshness predicates
/// the gate can decide at v0.3: `consistent` (internal-anchor agreement),
/// `f_m` and `f_i` (against a [`CanonicalStateOracle`]), and `f_s`.
///
/// `f_c` is **not** enforced: it is not measurable from `(A, now)` and is
/// handled structurally (commit-at-completion) — see the spec.
pub struct MockSettlementGate<V: CommitmentVerifier, O: CanonicalStateOracle> {
    verifier: V,
    oracle: O,
}

impl<V: CommitmentVerifier, O: CanonicalStateOracle> MockSettlementGate<V, O> {
    /// Construct a gate from a commitment verifier and a canonical-state
    /// oracle. The oracle answers `f_m`/`f_i`; the verifier answers
    /// signature + attestation.
    pub fn new(verifier: V, oracle: O) -> Self {
        Self { verifier, oracle }
    }
}

impl<V: CommitmentVerifier, O: CanonicalStateOracle> SettlementGate
    for MockSettlementGate<V, O>
{
    fn verify_and_settle(
        &self,
        commitment: &FreshnessCommitment,
        root: &ExecutionContextRoot,
        now: &TripleAnchor,
        thresholds: &FreshnessThresholds,
    ) -> Result<SettlementResult, PocError> {
        // 1. Signature + attestation verification.
        self.verifier.verify(commitment)?;

        // 2. Context binding (mechanism (i)): the disclosed root must hash to
        //    the committed context_root before we read any field from it.
        //    Aborts settlement — a mismatch means the worker disclosed a
        //    context different from what it signed.
        if root.merkle_root() != commitment.context_root {
            return Err(PocError::RootMismatch);
        }

        // Accumulate violations (no early return — a single commitment can be
        // stale on more than one axis, and the protocol wants every reason).
        let mut violations = Vec::new();

        // 3. consistent — internal agreement of the commit anchor's clocks.
        //    A tampered/desynced commit clock is attributed to Computational.
        if !commitment.anchor.internally_consistent(thresholds) {
            violations.push(FreshnessType::Computational);
        }

        // 4. f_s — commit must clear within max_fs_blocks. A backwards clock
        //    (now before commit) is itself a settlement-window violation.
        let fs_violation = now.block_height < commitment.anchor.block_height
            || now.block_height - commitment.anchor.block_height > thresholds.max_fs_blocks;
        if fs_violation {
            violations.push(FreshnessType::Settlement);
        }

        // 5. f_m — committed model vs canonical model at `now`. An oracle
        //    error (unknown / unregistered model) is treated as stale.
        let model_stale = match self.oracle.model_epoch_distance(root.weights_hash, now) {
            Ok(distance) => distance > thresholds.max_fm_epochs,
            Err(_) => true,
        };
        if model_stale {
            violations.push(FreshnessType::Model);
        }

        // 6. f_i — committed input-world state vs canonical at `now`. An
        //    oracle error (unknown input state) is treated as stale.
        let input_stale = match self.oracle.input_lag_blocks(root.input_manifest_root, now) {
            Ok(lag) => lag > thresholds.max_fi_blocks,
            Err(_) => true,
        };
        if input_stale {
            violations.push(FreshnessType::Input);
        }

        // No f_c check — deferred (commit-at-completion + f_s). See spec.

        if violations.is_empty() {
            Ok(SettlementResult::Clear)
        } else {
            Ok(SettlementResult::Rejected(violations))
        }
    }
}

/// Software-only canonical-state oracle for tests and demos.
///
/// Holds per-hash maps for model-epoch distance and input lag, each with an
/// optional default for hashes not in the map. A `None` default makes an
/// unknown hash return [`PocError::OracleUnavailable`] (the gate treats that
/// as stale); a `Some(d)` default returns `d` for any unknown hash.
///
/// **Not** a real oracle: it has no notion of an actual canonical lineage or
/// live input-world state. Pieza 1b replaces it with an on-chain model-root
/// registry (`f_m`) and BaseOracle (`f_i`).
pub struct MockCanonicalStateOracle {
    model_epochs: HashMap<Hash32, u64>,
    input_lags: HashMap<Hash32, u64>,
    default_model: Option<u64>,
    default_input: Option<u64>,
}

impl MockCanonicalStateOracle {
    /// An oracle that vouches every model and input as perfectly fresh
    /// (distance 0, lag 0) regardless of hash. Useful for tests that exercise
    /// other axes (signature, `f_s`) without tripping `f_m`/`f_i`.
    pub fn always_fresh() -> Self {
        Self {
            model_epochs: HashMap::new(),
            input_lags: HashMap::new(),
            default_model: Some(0),
            default_input: Some(0),
        }
    }

    /// An oracle that knows nothing by default: any hash not explicitly
    /// registered returns [`PocError::OracleUnavailable`]. Build it up with
    /// [`with_model_epoch`](Self::with_model_epoch) /
    /// [`with_input_lag`](Self::with_input_lag).
    pub fn strict() -> Self {
        Self {
            model_epochs: HashMap::new(),
            input_lags: HashMap::new(),
            default_model: None,
            default_input: None,
        }
    }

    /// Register a model-epoch distance for a specific weights hash.
    pub fn with_model_epoch(mut self, weights_hash: Hash32, distance: u64) -> Self {
        self.model_epochs.insert(weights_hash, distance);
        self
    }

    /// Register an input lag (in blocks) for a specific input-manifest root.
    pub fn with_input_lag(mut self, input_manifest_root: Hash32, lag: u64) -> Self {
        self.input_lags.insert(input_manifest_root, lag);
        self
    }

    /// Set the default model-epoch distance for unregistered hashes
    /// (`None` = return `OracleUnavailable`).
    pub fn with_default_model(mut self, distance: Option<u64>) -> Self {
        self.default_model = distance;
        self
    }

    /// Set the default input lag for unregistered hashes
    /// (`None` = return `OracleUnavailable`).
    pub fn with_default_input(mut self, lag: Option<u64>) -> Self {
        self.default_input = lag;
        self
    }
}

impl CanonicalStateOracle for MockCanonicalStateOracle {
    fn model_epoch_distance(
        &self,
        weights_hash: Hash32,
        _now: &TripleAnchor,
    ) -> Result<u64, PocError> {
        self.model_epochs
            .get(&weights_hash)
            .copied()
            .or(self.default_model)
            .ok_or(PocError::OracleUnavailable)
    }

    fn input_lag_blocks(
        &self,
        input_manifest_root: Hash32,
        _now: &TripleAnchor,
    ) -> Result<u64, PocError> {
        self.input_lags
            .get(&input_manifest_root)
            .copied()
            .or(self.default_input)
            .ok_or(PocError::OracleUnavailable)
    }
}
