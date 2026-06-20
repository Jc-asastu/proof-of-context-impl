//! Generates the canonical-JSON + SHA-256 golden values for the cross-language
//! wire-format test vectors (proof-of-context/test-vectors/v0.1.json). Run with:
//!
//!     cargo run --example gen_test_vectors --features oracle-fi
//!
//! It reuses the crate's own `canonical_hash`, so the emitted values are exactly
//! what the Rust verifier produces — other implementations (BaseOracle,
//! TrustLayer, Vigil, PayClaw) must reproduce them byte-for-byte.

use proof_of_context::canonical::{canonical_hash, canonical_json};
use serde_json::json;

fn main() {
    // f_i input manifest — sources pre-sorted by (endpoint, payload_hash).
    // The single source here quotes the v1-simple-flat price payload.
    let manifest = json!({
        "sources": [
            {
                "endpoint": "/api/v1/prices",
                "payload_hash": "5525810608ca0d5ec814d45159e4f11e09a533061f04f4193850b3ca2fc5c453",
                "source_id": "baseoracle:default"
            }
        ],
        "version": "f_i/0.1"
    });
    println!("FI_MANIFEST_JSON={}", canonical_json(&manifest));
    println!("FI_MANIFEST_HASH={}", hex::encode(canonical_hash(&manifest)));

    // f_i multi-source manifest — exercises the array pre-sort contract.
    // Sources here are shown in their REQUIRED post-pre-sort order: ascending by
    // (endpoint, payload_hash). "/api/v1/gas" < "/api/v1/prices".
    let manifest2 = json!({
        "sources": [
            {
                "endpoint": "/api/v1/gas",
                "payload_hash": "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
                "source_id": "baseoracle:default"
            },
            {
                "endpoint": "/api/v1/prices",
                "payload_hash": "5525810608ca0d5ec814d45159e4f11e09a533061f04f4193850b3ca2fc5c453",
                "source_id": "baseoracle:default"
            }
        ],
        "version": "f_i/0.1"
    });
    println!("FI_MANIFEST2_JSON={}", canonical_json(&manifest2));
    println!("FI_MANIFEST2_HASH={}", hex::encode(canonical_hash(&manifest2)));

    // f_m model lineage — epochs sorted ascending by epoch.
    let lineage = json!({
        "epochs": [
            { "weights_hash": "1010101010101010101010101010101010101010101010101010101010101010", "epoch": 0, "activation_block": 100 },
            { "weights_hash": "1111111111111111111111111111111111111111111111111111111111111111", "epoch": 1, "activation_block": 200 }
        ],
        "version": "f_m/0.1"
    });
    println!("FM_LINEAGE_JSON={}", canonical_json(&lineage));
    println!("FM_LINEAGE_HASH={}", hex::encode(canonical_hash(&lineage)));
}
