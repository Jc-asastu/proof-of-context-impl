//! Real input-freshness (`f_i`) oracle — witness-presented BaseOracle attestations.
//!
//! Pieza 1b-i. This is the first *real* [`CanonicalStateOracle`] axis: it
//! decides `f_i` against signed BaseOracle `_poc` attestations instead of a
//! mock. The architecture is **witness-presented** (no network at settlement):
//! the settlement caller presents the BaseOracle attestation(s) that backed an
//! inference's inputs; this oracle verifies each (Ed25519 signature over the
//! exact BaseOracle signing message), reconstructs the `input_manifest_root`
//! using the same canonical-JSON SHA-256 scheme ([`crate::canonical`]), indexes
//! the witness by that root, and answers `input_lag_blocks` from the
//! attestation's block anchor. A swapped or stale attestation set yields a
//! different root → the witness is not found → the gate treats it as stale.
//!
//! `f_m` (model freshness) is **not** handled here — compose this with a model
//! oracle via [`SplitOracle`]. This faithfully encodes "f_i real, f_m mocked".

use std::collections::HashMap;

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde_json::Value;

use crate::anchor::{TripleAnchor, BASE_BLOCK_PERIOD_SECS};
use crate::canonical::canonical_hash;
use crate::context::Hash32;
use crate::error::PocError;
use crate::oracle::CanonicalStateOracle;

/// One BaseOracle `_poc` attestation, parsed into typed form.
///
/// Mirrors the block produced by `BaseOracle/src/utils/poc.js` `attest()`.
/// The signature covers the canonical signing message (see
/// [`Self::signing_message`]), which binds `payload_hash`, `source_id`,
/// `endpoint`, `timestamp`, `freshness_horizon_secs`, and `freshness_type`.
#[derive(Debug, Clone)]
pub struct InputAttestation {
    /// Operator/source identifier, e.g. `"baseoracle:default"`.
    pub source_id: String,
    /// The endpoint path that produced the data, e.g. `"/api/v1/prices"`.
    pub endpoint: String,
    /// SHA-256 (canonical JSON) of the served payload.
    pub payload_hash: Hash32,
    /// The exact ISO-8601 timestamp string the operator signed over.
    pub timestamp: String,
    /// Operator-signed freshness horizon, in seconds.
    pub freshness_horizon_secs: u64,
    /// Base block height observed at signing time (`anchors.block_height`),
    /// when the triple anchor was enabled; `None` otherwise.
    pub anchor_block_height: Option<u64>,
    /// Ed25519 signature (64 bytes), or `None` if the operator signed nothing.
    pub signature: Option<[u8; 64]>,
    /// Ed25519 public key (32 bytes) of the signer, or `None`.
    pub public_key: Option<[u8; 32]>,
    /// Freshness type tag; must be `"f_i"` for an input attestation.
    pub freshness_type: String,
}

impl InputAttestation {
    /// Parse a `_poc` attestation block (the inner object, not the whole
    /// attested payload) into an [`InputAttestation`].
    pub fn from_poc_json(poc: &Value) -> Result<Self, PocError> {
        let s = |k: &'static str| -> Result<String, PocError> {
            poc.get(k)
                .and_then(Value::as_str)
                .map(str::to_owned)
                .ok_or(PocError::ContextRootMalformed(k))
        };
        let payload_hash_hex = s("payload_hash")?;
        let mut payload_hash = [0u8; 32];
        hex::decode_to_slice(&payload_hash_hex, &mut payload_hash)
            .map_err(|_| PocError::ContextRootMalformed("payload_hash"))?;

        let freshness_horizon_secs = poc
            .get("freshness_horizon_seconds")
            .and_then(Value::as_u64)
            .ok_or(PocError::ContextRootMalformed("freshness_horizon_seconds"))?;

        let anchor_block_height = poc
            .get("anchors")
            .and_then(|a| a.get("block_height"))
            .and_then(Value::as_u64);

        let signature = match poc.get("signature").and_then(Value::as_str) {
            Some(hex_sig) => {
                let mut buf = [0u8; 64];
                hex::decode_to_slice(hex_sig, &mut buf)
                    .map_err(|_| PocError::ContextRootMalformed("signature"))?;
                Some(buf)
            }
            None => None,
        };
        let public_key = match poc.get("public_key").and_then(Value::as_str) {
            Some(hex_pk) => {
                let mut buf = [0u8; 32];
                hex::decode_to_slice(hex_pk, &mut buf)
                    .map_err(|_| PocError::ContextRootMalformed("public_key"))?;
                Some(buf)
            }
            None => None,
        };

        Ok(Self {
            source_id: s("source_id")?,
            endpoint: s("endpoint")?,
            payload_hash,
            timestamp: s("timestamp")?,
            freshness_horizon_secs,
            anchor_block_height,
            signature,
            public_key,
            freshness_type: s("freshness_type")?,
        })
    }

    /// Reconstruct the exact BaseOracle signing message (`poc.js` lines
    /// 127-134): a JSON object with keys in **insertion order** (NOT sorted) —
    /// `payload_hash, source_id, endpoint, timestamp, freshness_horizon_seconds,
    /// freshness_type`. This differs from the canonical (key-sorted) hash, so
    /// it is built explicitly here.
    pub fn signing_message(&self) -> String {
        // serde_json renders each string with JSON escaping + quotes, matching
        // JSON.stringify; the horizon is an unquoted integer.
        let q = |s: &str| Value::String(s.to_owned()).to_string();
        format!(
            "{{\"payload_hash\":{},\"source_id\":{},\"endpoint\":{},\"timestamp\":{},\"freshness_horizon_seconds\":{},\"freshness_type\":{}}}",
            q(&hex::encode(self.payload_hash)),
            q(&self.source_id),
            q(&self.endpoint),
            q(&self.timestamp),
            self.freshness_horizon_secs,
            q(&self.freshness_type),
        )
    }

    /// Verify the Ed25519 signature over the canonical signing message.
    /// `Err(InvalidSignature)` if unsigned, malformed, or it does not verify.
    pub fn verify_signature(&self) -> Result<(), PocError> {
        let sig_bytes = self.signature.ok_or(PocError::InvalidSignature)?;
        let pk_bytes = self.public_key.ok_or(PocError::InvalidSignature)?;
        let vk = VerifyingKey::from_bytes(&pk_bytes).map_err(|_| PocError::InvalidSignature)?;
        let sig = Signature::from_bytes(&sig_bytes);
        vk.verify(self.signing_message().as_bytes(), &sig)
            .map_err(|_| PocError::InvalidSignature)
    }

    /// The block this attestation is "as of": the signed block anchor when
    /// present (lossless); otherwise, under `real-anchors`, derived from the
    /// signed ISO timestamp (lossy, `(secs - genesis) / block_period`). Without
    /// either, `Err(OracleUnavailable)` — the gate treats that as stale.
    fn as_of_block(&self) -> Result<u64, PocError> {
        if let Some(block) = self.anchor_block_height {
            return Ok(block);
        }
        #[cfg(feature = "real-anchors")]
        {
            let secs = parse_iso8601_utc_secs(&self.timestamp)?;
            let genesis = crate::anchor::BASE_MAINNET_GENESIS_UNIX;
            if secs >= genesis {
                return Ok((secs - genesis) / BASE_BLOCK_PERIOD_SECS);
            }
        }
        Err(PocError::OracleUnavailable)
    }
}

/// A bundle of input attestations backing one inference's inputs. Its
/// [`input_manifest_root`](Self::input_manifest_root) is the root the worker
/// committed to in its `ExecutionContextRoot.input_manifest_root`.
#[derive(Debug, Clone)]
pub struct InputFreshnessWitness {
    attestations: Vec<InputAttestation>,
}

impl InputFreshnessWitness {
    /// Build a witness from `_poc` blocks: every attestation must carry
    /// `freshness_type == "f_i"`, verify its signature, and (if
    /// `expected_pubkey` is given) match that operator. Rejects an empty set.
    pub fn from_poc_blocks(
        poc_blocks: &[Value],
        expected_pubkey: Option<[u8; 32]>,
    ) -> Result<Self, PocError> {
        if poc_blocks.is_empty() {
            return Err(PocError::ContextRootMalformed("empty witness"));
        }
        let mut attestations = Vec::with_capacity(poc_blocks.len());
        for block in poc_blocks {
            let att = InputAttestation::from_poc_json(block)?;
            if att.freshness_type != "f_i" {
                return Err(PocError::ContextRootMalformed("freshness_type != f_i"));
            }
            att.verify_signature()?;
            if let Some(expected) = expected_pubkey {
                if att.public_key != Some(expected) {
                    return Err(PocError::InvalidSignature);
                }
            }
            attestations.push(att);
        }
        Ok(Self { attestations })
    }

    /// Reconstruct the `input_manifest_root` over the attestation set, using
    /// the canonical-JSON SHA-256 scheme. Descriptors are pre-sorted by
    /// `(endpoint, payload_hash)` so the root is independent of presentation
    /// order. Single-source is just a one-element `sources` array.
    pub fn input_manifest_root(&self) -> Hash32 {
        let mut descriptors: Vec<&InputAttestation> = self.attestations.iter().collect();
        descriptors.sort_by(|a, b| {
            a.endpoint
                .cmp(&b.endpoint)
                .then_with(|| a.payload_hash.cmp(&b.payload_hash))
        });
        let sources: Vec<Value> = descriptors
            .iter()
            .map(|a| {
                serde_json::json!({
                    "endpoint": a.endpoint,
                    "payload_hash": hex::encode(a.payload_hash),
                    "source_id": a.source_id,
                })
            })
            .collect();
        let manifest = serde_json::json!({ "sources": sources, "version": "f_i/0.1" });
        canonical_hash(&manifest)
    }

    /// The "as-of" block governing this witness: the **minimum** block across
    /// sources (the stalest member governs). When `enforce_horizon`, any
    /// source whose block lag vs `now` exceeds its own signed horizon (in
    /// blocks) expires the whole witness → `Err(OracleUnavailable)`.
    fn as_of_block(&self, now: &TripleAnchor, enforce_horizon: bool) -> Result<u64, PocError> {
        let mut min_block: Option<u64> = None;
        for att in &self.attestations {
            let as_of = att.as_of_block()?;
            if enforce_horizon {
                let lag = now.block_height.saturating_sub(as_of);
                let horizon_blocks = att.freshness_horizon_secs / BASE_BLOCK_PERIOD_SECS;
                if lag > horizon_blocks {
                    return Err(PocError::OracleUnavailable);
                }
            }
            min_block = Some(min_block.map_or(as_of, |m| m.min(as_of)));
        }
        min_block.ok_or(PocError::OracleUnavailable)
    }
}

/// A real `f_i` oracle over presented BaseOracle witnesses. Holds verified
/// witnesses indexed by their `input_manifest_root`. `model_epoch_distance`
/// always errs (f_m is not this oracle's job — compose via [`SplitOracle`]).
#[derive(Debug, Default)]
pub struct BaseOracleInputOracle {
    witnesses: HashMap<Hash32, InputFreshnessWitness>,
    expected_pubkey: Option<[u8; 32]>,
    enforce_horizon: bool,
}

impl BaseOracleInputOracle {
    /// Construct an oracle that, by default, enforces each attestation's
    /// signed freshness horizon. Pass `expected_pubkey` to pin a single
    /// trusted operator (`None` accepts any well-signed attestation).
    pub fn new(expected_pubkey: Option<[u8; 32]>) -> Self {
        Self {
            witnesses: HashMap::new(),
            expected_pubkey,
            enforce_horizon: true,
        }
    }

    /// Toggle enforcement of the signed `freshness_horizon_seconds`. When off,
    /// only `max_fi_blocks` (the gate threshold) bounds staleness.
    pub fn with_enforce_horizon(mut self, enforce: bool) -> Self {
        self.enforce_horizon = enforce;
        self
    }

    /// Verify a set of `_poc` blocks, reconstruct their `input_manifest_root`,
    /// index the witness by it, and return the root. The caller confirms this
    /// equals the disclosed `ExecutionContextRoot.input_manifest_root`.
    pub fn present_witness(&mut self, poc_blocks: &[Value]) -> Result<Hash32, PocError> {
        let witness = InputFreshnessWitness::from_poc_blocks(poc_blocks, self.expected_pubkey)?;
        let root = witness.input_manifest_root();
        self.witnesses.insert(root, witness);
        Ok(root)
    }
}

impl CanonicalStateOracle for BaseOracleInputOracle {
    fn model_epoch_distance(
        &self,
        _weights_hash: Hash32,
        _now: &TripleAnchor,
    ) -> Result<u64, PocError> {
        // f_m is out of scope for the input-freshness oracle; compose with a
        // model oracle (e.g. via SplitOracle) to answer it.
        Err(PocError::OracleUnavailable)
    }

    fn input_lag_blocks(
        &self,
        input_manifest_root: Hash32,
        now: &TripleAnchor,
    ) -> Result<u64, PocError> {
        let witness = self
            .witnesses
            .get(&input_manifest_root)
            .ok_or(PocError::OracleUnavailable)?;
        let as_of = witness.as_of_block(now, self.enforce_horizon)?;
        Ok(now.block_height.saturating_sub(as_of))
    }
}

/// Parse the fixed `Date.prototype.toISOString()` form
/// (`YYYY-MM-DDTHH:MM:SS.sssZ`, always UTC) to Unix seconds. Fractional
/// seconds and the trailing `Z` are ignored. Only compiled when the
/// seconds→blocks fallback (a `real-anchors` concern) is in play.
#[cfg(feature = "real-anchors")]
fn parse_iso8601_utc_secs(ts: &str) -> Result<u64, PocError> {
    let bytes = ts.as_bytes();
    if bytes.len() < 19 {
        return Err(PocError::ContextRootMalformed("timestamp"));
    }
    let num = |range: std::ops::Range<usize>| -> Result<i64, PocError> {
        ts.get(range)
            .and_then(|s| s.parse::<i64>().ok())
            .ok_or(PocError::ContextRootMalformed("timestamp"))
    };
    let (year, month, day) = (num(0..4)?, num(5..7)?, num(8..10)?);
    let (hour, min, sec) = (num(11..13)?, num(14..16)?, num(17..19)?);

    // days_from_civil (Howard Hinnant): days since 1970-01-01 for a Gregorian date.
    let y = if month <= 2 { year - 1 } else { year };
    let era = (if y >= 0 { y } else { y - 399 }) / 400;
    let yoe = y - era * 400;
    let doy = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719_468;

    let total = days * 86_400 + hour * 3_600 + min * 60 + sec;
    u64::try_from(total).map_err(|_| PocError::ContextRootMalformed("timestamp"))
}
