//! Proof-of-context commitment and the committer trait.
//!
//! A commitment is the artifact a worker produces at the end of a
//! computation. It binds (a) the execution-context root, (b) the triple
//! anchor at commit time, (c) the output hash, and (d) a TEE attestation
//! chain into a single signed package.
//!
//! The commitment is what a settlement gate consumes when deciding
//! whether to clear payment.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::anchor::TripleAnchor;
use crate::attestation::AttestationChain;
use crate::context::{ExecutionContextRoot, Hash32};
use crate::error::PocError;

/// A signed proof-of-context commitment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FreshnessCommitment {
    /// Merkle root of the execution context (see [`ExecutionContextRoot`]).
    pub context_root: Hash32,
    /// The three clocks at commit time.
    pub anchor: TripleAnchor,
    /// Hash of the computation output (inference tokens, gradient blob, etc.).
    pub output_hash: Hash32,
    /// Ed25519 signature over the canonical digest
    /// `SHA-256(context_root || anchor || output_hash)`.
    /// Stored as 64 raw bytes (R || S); deserialized via
    /// `ed25519_dalek::Signature::from_bytes`.
    #[serde(with = "serde_bytes")]
    pub signature: [u8; 64],
    /// 32-byte Ed25519 public key that signed this commitment.
    #[serde(with = "serde_bytes")]
    pub public_key: [u8; 32],
    /// TEE attestation chain (e.g., TDX quote + H100 attestation report)
    /// that anchors the signing key identity.
    pub attestation_chain: AttestationChain,
}

impl FreshnessCommitment {
    /// Compute the canonical signing digest.
    ///
    /// Signing is done over `SHA-256(context_root || anchor_bytes || output_hash)`
    /// where `anchor_bytes` is the fixed-order concatenation of
    /// `block_height` (u64 LE) || `tee_timestamp` (u128 LE) ||
    /// `drand_round` (u64 LE).
    pub fn signing_digest(&self) -> Hash32 {
        let mut h = Sha256::new();
        h.update(self.context_root);
        h.update(self.anchor.block_height.to_le_bytes());
        h.update(self.anchor.tee_timestamp.to_le_bytes());
        h.update(self.anchor.drand_round.to_le_bytes());
        h.update(self.output_hash);
        h.finalize().into()
    }
}

/// Small helper module so serde can handle fixed-size byte arrays that
/// are not natively Serialize / Deserialize when the array length is > 32.
mod serde_bytes {
    use serde::de::{SeqAccess, Visitor};
    use serde::{Deserializer, Serializer};

    pub fn serialize<S, const N: usize>(bytes: &[u8; N], serializer: S) -> Result<S::Ok, S::Error>
    where S: Serializer {
        serializer.serialize_bytes(bytes)
    }

    pub fn deserialize<'de, D, const N: usize>(deserializer: D) -> Result<[u8; N], D::Error>
    where D: Deserializer<'de> {
        struct BytesVisitor<const N: usize>;
        impl<'de, const N: usize> Visitor<'de> for BytesVisitor<N> {
            type Value = [u8; N];
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(f, "byte array of length {}", N)
            }
            fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<Self::Value, E> {
                if v.len() != N { return Err(E::custom("wrong length")); }
                let mut arr = [0u8; N];
                arr.copy_from_slice(v);
                Ok(arr)
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let mut arr = [0u8; N];
                for byte in arr.iter_mut() {
                    *byte = seq.next_element()?
                        .ok_or_else(|| serde::de::Error::custom("short sequence"))?;
                }
                Ok(arr)
            }
        }
        deserializer.deserialize_bytes(BytesVisitor::<N>)
    }
}

/// A producer of commitments.
///
/// Implementations will typically wrap an enclave (TDX + H100) and
/// produce the signature / attestation chain from hardware. A mock
/// implementation may sign with a software key — useful for tests,
/// not for economic settlement.
pub trait ContextCommitter {
    /// Build and sign a commitment binding the given context root and
    /// output hash against the current anchor.
    fn commit(
        &self,
        root: ExecutionContextRoot,
        output_hash: Hash32,
        anchor: TripleAnchor,
    ) -> Result<FreshnessCommitment, PocError>;

    /// Return a human-readable identifier for this committer (for logs).
    fn identity(&self) -> &str;
}

/// A verifier that checks signature and attestation chain on a
/// commitment, independently of settlement-gating.
pub trait CommitmentVerifier {
    /// Return `Ok(())` if the commitment's signature verifies against the
    /// included public key and the attestation chain is valid.
    fn verify(&self, commitment: &FreshnessCommitment) -> Result<(), PocError>;
}
