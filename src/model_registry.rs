//! Real model-freshness (`f_m`) oracle — a committee/quorum model-lineage registry.
//!
//! Pieza 1b-m. Mirrors the witness-presented design of pieza 1b-i: instead of
//! trusting a single live service, the canonical model lineage is published as
//! a signed snapshot and **N publishers** attest it; this oracle adopts the
//! lineage only if an **M-of-N quorum** of registered publishers signed the
//! identical canonical-JSON snapshot (same hashing scheme as BaseOracle and the
//! f_i oracle). This is the trust model the paper's §7 constraint 8 leans
//! toward for model version ("critical context attested by a committee").
//!
//! The signatures are verified offline — no network at settlement. A future
//! on-chain registry (an `eth_call` reader) can populate the lineage behind the
//! same trait without changing the gate.
//!
//! Scope: this answers `f_m` only. Compose it with an input oracle via
//! [`crate::oracle::SplitOracle`] to gate `f_m` and `f_i` together. `f_c` is
//! deferred (see the gate). A real `Renewal::evaluate` is NOT implemented here:
//! the `Renewal` trait's signature carries neither the settlement `now` nor the
//! thresholds, so it cannot distinguish prospective-only protection from window
//! expiry — it needs a redesign before a faithful implementation (follow-up).

use std::collections::BTreeSet;

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde_json::Value;

use crate::anchor::TripleAnchor;
use crate::canonical::{canonical_hash, canonical_json};
use crate::context::Hash32;
use crate::error::PocError;
use crate::oracle::CanonicalStateOracle;

/// One canonical model version in the lineage: its weights hash, the published
/// epoch number, and the block height at which it became canonical.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelEpoch {
    /// Merkle/identity hash of the model weights for this epoch.
    pub weights_hash: Hash32,
    /// Published epoch number (monotone; used for ordering and as metadata).
    pub epoch: u64,
    /// Block height at which this epoch became the canonical model.
    pub activation_block: u64,
}

/// An ordered canonical model lineage. Epochs are held sorted ascending by
/// `epoch`; "version-epoch distance" is measured as the number of lineage
/// positions between two models (robust to non-contiguous epoch numbers).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ModelLineage {
    epochs: Vec<ModelEpoch>,
}

impl ModelLineage {
    /// Build a lineage from its epochs (sorted ascending by epoch number).
    pub fn new(mut epochs: Vec<ModelEpoch>) -> Self {
        epochs.sort_by_key(|e| e.epoch);
        Self { epochs }
    }

    /// The canonical-JSON `Value` of the lineage snapshot that publishers sign.
    fn canonical_value(&self) -> Value {
        let epochs: Vec<Value> = self
            .epochs
            .iter()
            .map(|e| {
                serde_json::json!({
                    "weights_hash": hex::encode(e.weights_hash),
                    "epoch": e.epoch,
                    "activation_block": e.activation_block,
                })
            })
            .collect();
        serde_json::json!({ "epochs": epochs, "version": "f_m/0.1" })
    }

    /// The canonical-JSON SHA-256 digest of the lineage snapshot.
    pub fn canonical_hash(&self) -> Hash32 {
        canonical_hash(&self.canonical_value())
    }

    /// The exact message bytes publishers sign over (the canonical-JSON string
    /// of the snapshot). Quorum signatures are verified against this.
    pub fn signing_message(&self) -> String {
        canonical_json(&self.canonical_value())
    }

    /// Lineage position (index) of a weights hash, if present.
    fn position_of(&self, weights_hash: &Hash32) -> Option<usize> {
        self.epochs.iter().position(|e| &e.weights_hash == weights_hash)
    }

    /// Position of the highest epoch whose activation block is at or before
    /// `block` — the canonical model at that settlement height.
    fn canonical_position_at(&self, block: u64) -> Option<usize> {
        self.epochs
            .iter()
            .enumerate()
            .filter(|(_, e)| e.activation_block <= block)
            .map(|(i, _)| i)
            .max()
    }
}

/// A publisher's Ed25519 signature over a lineage snapshot's signing message.
#[derive(Debug, Clone)]
pub struct QuorumSignature {
    /// The publisher's 32-byte Ed25519 public key.
    pub public_key: [u8; 32],
    /// The 64-byte signature over [`ModelLineage::signing_message`].
    pub signature: [u8; 64],
}

/// A committee/quorum `f_m` oracle. Adopts a model lineage only when an M-of-N
/// quorum of *registered, distinct* publishers signed the identical canonical
/// snapshot; then answers `model_epoch_distance` against it.
#[derive(Debug)]
pub struct QuorumModelOracle {
    publishers: BTreeSet<[u8; 32]>,
    threshold: usize,
    lineage: Option<ModelLineage>,
}

impl QuorumModelOracle {
    /// Construct with the registered publisher set and the quorum threshold
    /// `M` (number of distinct valid publisher signatures required). `M` should
    /// be `>= 1` and `<= publishers.len()`.
    pub fn new(publishers: impl IntoIterator<Item = [u8; 32]>, threshold: usize) -> Self {
        Self {
            publishers: publishers.into_iter().collect(),
            threshold,
            lineage: None,
        }
    }

    /// Verify that an M-of-N quorum of distinct registered publishers signed
    /// the canonical snapshot of `lineage`, then adopt it. Returns
    /// `Err(OracleUnavailable)` if the threshold is zero or the quorum is not
    /// met (signatures from unregistered keys, or that do not verify against
    /// this exact lineage, do not count).
    pub fn present_lineage(
        &mut self,
        lineage: ModelLineage,
        signatures: &[QuorumSignature],
    ) -> Result<(), PocError> {
        if self.threshold == 0 {
            return Err(PocError::OracleUnavailable);
        }
        let message = lineage.signing_message();
        let mut distinct_valid: BTreeSet<[u8; 32]> = BTreeSet::new();
        for sig in signatures {
            if !self.publishers.contains(&sig.public_key) {
                continue;
            }
            let Ok(vk) = VerifyingKey::from_bytes(&sig.public_key) else {
                continue;
            };
            if vk
                .verify(message.as_bytes(), &Signature::from_bytes(&sig.signature))
                .is_ok()
            {
                distinct_valid.insert(sig.public_key);
            }
        }
        if distinct_valid.len() < self.threshold {
            return Err(PocError::OracleUnavailable);
        }
        self.lineage = Some(lineage);
        Ok(())
    }

    /// The currently adopted lineage, if a quorum has been presented.
    pub fn lineage(&self) -> Option<&ModelLineage> {
        self.lineage.as_ref()
    }
}

impl CanonicalStateOracle for QuorumModelOracle {
    fn model_epoch_distance(
        &self,
        weights_hash: Hash32,
        now: &TripleAnchor,
    ) -> Result<u64, PocError> {
        let lineage = self.lineage.as_ref().ok_or(PocError::OracleUnavailable)?;
        // Unregistered model → not in the canonical lineage → stale/invalid.
        let committed = lineage
            .position_of(&weights_hash)
            .ok_or(PocError::OracleUnavailable)?;
        // No epoch is canonical yet at this settlement height.
        let canonical = lineage
            .canonical_position_at(now.block_height)
            .ok_or(PocError::OracleUnavailable)?;
        // A model at or ahead of canonical-at-now has distance 0 (fresh).
        Ok((canonical.saturating_sub(committed)) as u64)
    }

    fn input_lag_blocks(
        &self,
        _input_manifest_root: Hash32,
        _now: &TripleAnchor,
    ) -> Result<u64, PocError> {
        // f_i is out of scope for the model oracle; compose with an input
        // oracle (e.g. via SplitOracle) to answer it.
        Err(PocError::OracleUnavailable)
    }
}
