//! # proof-of-context
//!
//! Reference implementation of the proof-of-context primitive: an
//! attestation-as-settlement layer for decentralized machine learning.
//!
//! See the position paper at <https://github.com/asastuai/proof-of-context>
//! for the conceptual framework. This crate translates that framework into
//! Rust traits and types.
//!
//! **Status:** Phase 3a / v0.3 (pieza 1). The core primitives are implemented
//! with real cryptography — `ExecutionContextRoot::merkle_root` (SHA-256 over
//! the canonical preimage), Ed25519 commitment signing and verification — and
//! the settlement gate now enforces `consistent` (internal triple-anchor
//! agreement) plus `f_m`, `f_i` (against a [`oracle::CanonicalStateOracle`],
//! mocked) and `f_s`: integrity plus three of the four freshness types,
//! exercised end-to-end by a software-key test suite. `f_c` is deferred (not
//! measurable from the commitment; handled structurally via
//! commit-at-completion). The `f_i` axis now has a **real** oracle (pieza 1b-i,
//! behind `--features oracle-fi`): [`input_freshness::BaseOracleInputOracle`]
//! verifies witness-presented BaseOracle attestations and decides `f_i` from
//! their block anchor, composed with a model oracle via
//! [`oracle::SplitOracle`]. The `f_m` axis also has a **real** oracle (pieza
//! 1b-m, behind `--features oracle-fm`): [`model_registry::QuorumModelOracle`]
//! adopts a committee/quorum-signed model lineage and decides `f_m` against it.
//! With both features, `SplitOracle { model: QuorumModelOracle, input:
//! BaseOracleInputOracle }` gates `f_m` and `f_i` entirely against real oracles.
//! TEE-backed attestation and an on-chain registry source remain Phase 3b.
//! The [`renewal::Renewal`] trait carries the settlement clock and thresholds,
//! and [`renewal::WindowedRenewal`] implements prospective-only root-bump
//! semantics against the `f_s` window.
//!
//! The first **Solana**-targeted adapter ships behind `--features darkpool-sol`
//! ([`darkpool`] + [`price_freshness`]): a **seconds-native, multi-party** gate
//! for the SUR Solana agent-to-agent dark pool, where a negotiated trade clears
//! only if every agent's quote was made against fresh context. This is the
//! deployment target (the Base adapters are the EVM/reference path).
//!
//! ## One-sentence framing
//!
//! > PAL\*M attests that a computation happened correctly; proof-of-context
//! > makes those attestations economically perishable — binding freshness to
//! > settlement so that stale inferences cannot clear payment.
//!
//! ## Top-level crate layout
//!
//! - [`anchor`] — the three clocks (block height, TEE timestamp, Drand round).
//! - [`context`] — the execution-context root (what the commitment binds to).
//! - [`freshness`] — the four freshness types (`f_c`, `f_m`, `f_i`, `f_s`) and threshold parameters.
//! - [`commitment`] — a proof-of-context commitment and the [`ContextCommitter`] trait.
//! - [`oracle`] — the [`CanonicalStateOracle`] trait for `f_m`/`f_i` lookups.
//! - [`settle`] — the [`SettlementGate`] trait that refuses to clear stale commitments.
//! - [`renewal`] — the [`Renewal`] trait implementing prospective-only root bumps.
//! - [`attestation`] — TEE attestation chain verification hooks.
//! - [`error`] — shared error types.
//!
//! ## Minimal usage sketch (aspirational, not yet functional)
//!
//! ```ignore
//! use proof_of_context::{
//!     anchor::TripleAnchor,
//!     context::ExecutionContextRoot,
//!     commitment::ContextCommitter,
//!     settle::SettlementGate,
//!     freshness::FreshnessThresholds,
//! };
//!
//! // 1. Worker runs the inference and builds the context root.
//! let root: ExecutionContextRoot = /* build from runtime state */ todo!();
//!
//! // 2. Worker commits, anchoring against the three clocks.
//! let committer: Box<dyn ContextCommitter> = /* TEE-backed committer */ todo!();
//! let commitment = committer.commit(root, /* output bytes */ &[]).unwrap();
//!
//! // 3. At settlement time, the gate checks freshness against current clocks.
//! let gate: Box<dyn SettlementGate> = /* protocol-configured */ todo!();
//! let now: TripleAnchor = /* read current state */ todo!();
//! let thresholds = FreshnessThresholds::default_base_mainnet();
//! // `root` is disclosed at settlement so the gate can read weights/input
//! // hashes after binding it to the committed context_root.
//! if gate.is_settlement_eligible(&commitment, &root, &now, &thresholds).unwrap() {
//!     // Release payment.
//! }
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod anchor;
pub mod attestation;
pub mod backing;
pub mod commitment;
pub mod context;
pub mod error;
pub mod freshness;
pub mod mock;
pub mod oracle;
pub mod renewal;
pub mod settle;

/// Canonical-JSON SHA-256 (byte-identical to BaseOracle). Opt in with any of
/// `--features oracle-fi` / `oracle-fm` / `darkpool-sol`.
#[cfg(any(feature = "oracle-fi", feature = "oracle-fm", feature = "darkpool-sol"))]
pub mod canonical;

/// Real input-freshness (`f_i`) oracle over BaseOracle attestations (pieza
/// 1b-i). Opt in with `--features oracle-fi`.
#[cfg(feature = "oracle-fi")]
pub mod input_freshness;

/// Real model-freshness (`f_m`) oracle — a committee/quorum model-lineage
/// registry (pieza 1b-m). Opt in with `--features oracle-fm`.
#[cfg(feature = "oracle-fm")]
pub mod model_registry;

/// Seconds-based input-freshness (`f_i`) witness for a unix-seconds venue — the
/// SUR Solana price-as-of oracle. Opt in with `--features darkpool-sol`.
#[cfg(feature = "darkpool-sol")]
pub mod price_freshness;

/// Multi-party freshness gate for the SUR Solana agent-to-agent dark pool: a
/// negotiated trade clears iff every party's quote used fresh context. Opt in
/// with `--features darkpool-sol`.
#[cfg(feature = "darkpool-sol")]
pub mod darkpool;

/// Real-anchor clients (Drand + EVM RPC). Opt in with `--features real-anchors`.
#[cfg(feature = "real-anchors")]
pub mod clients;

pub use anchor::TripleAnchor;
pub use backing::{AgePolicy, BackingEntry, BackingSet, BackingVerdict, BoundaryAge, StaleEntry};
pub use commitment::{ContextCommitter, FreshnessCommitment};
pub use context::ExecutionContextRoot;
pub use error::PocError;
pub use freshness::{FreshnessThresholds, FreshnessType};
pub use oracle::{CanonicalStateOracle, SplitOracle};
pub use renewal::{Renewal, RenewalOutcome, WindowedRenewal};

#[cfg(feature = "oracle-fi")]
pub use input_freshness::{BaseOracleInputOracle, InputAttestation, InputFreshnessWitness};

#[cfg(feature = "oracle-fm")]
pub use model_registry::{ModelEpoch, ModelLineage, QuorumModelOracle, QuorumSignature};

#[cfg(feature = "darkpool-sol")]
pub use darkpool::{
    verify_party_contexts, DarkPoolSettlement, DarkPoolThresholds, PartyContext,
    PartyIntegrityError, PartyRole, PartyVerdict,
};
#[cfg(feature = "darkpool-sol")]
pub use price_freshness::{PriceAttestation, PriceFreshnessOracle};
pub use settle::{SettlementGate, SettlementResult};
