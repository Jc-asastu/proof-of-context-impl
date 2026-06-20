# ROADMAP

Phase numbering follows the Working Bible protocol used throughout the author's projects: each phase has a well-defined output, a gate for advancement, and explicit scope exclusions. Version numbers reflect the phase.

---

## Phase 1 — Scaffold (current, `v0.1.0-scaffold`)

**Output:** Rust crate that compiles with navigable module structure mapping one-to-one to paper sections; smoke tests verify constructibility of every public type; every stub method carries a `Phase 2:` doc comment explaining what it must do.

**Gate achieved:** `cargo build && cargo test` succeeds on a stock toolchain with no external dependencies.

**Explicitly out of scope:**
- Any actual cryptographic operation
- Any network I/O
- Any real TEE integration

---

## Phase 2 — Primitives (target `v0.2`)

**Goals:**
- Add `sha2` for Merkle commitments over `ExecutionContextRoot`
- Implement `merkle_root()` with the field order specified in paper §8
- Add `ed25519-dalek` and implement signature generation / verification
- Replace hand-rolled `PocError` with `thiserror`-based enum
- Add `serde` implementations to all public structs
- Implement `TripleAnchor::diverges_beyond` against `FreshnessThresholds`
- Ship a `MockCommitter` and `MockSettlementGate` pair with software keys that exercise the full commit → verify → settle → renew flow end-to-end in integration tests
- Publish to crates.io as `v0.2`

**Gate:** An integration test that walks a mock worker through committing, a verifier through checking, a settlement gate through clearing, a stale scenario through rejecting, and a root bump through triggering prospective-only protection — all with software keys.

**Explicitly out of scope:**
- TEE attestation
- Real Drand / block-height clients

---

## Phase 3 — TEE and network backends (target `v0.3`)

### Phase 3a — Network clients (LANDED, `v0.3.0-clients`)

**Output:**
- `clients::DrandHttpClient` — fetches the latest round from a public Drand mirror (Cloudflare default).
- `clients::BaseRpcClient` — fetches the latest block height via `eth_blockNumber` JSON-RPC.
- `clients::RealAnchorBuilder` — composes both into a live `TripleAnchor`. The TEE clock is filled with system time as a placeholder until Phase 3b.
- Feature-gated under `--features real-anchors` so the default build stays pure crypto + types with no HTTP deps.
- 3 integration tests with stub clients + 3 live tests (`#[ignore]`-gated) that hit real Drand and Base mainnet.

**Gate achieved:** `cargo test --features real-anchors --lib -- --ignored live` succeeds against live Drand mainnet and Base mainnet RPC.

### Pieza 1 — Oracle-gated freshness (LANDED, `v0.3.0`)

**Output:**
- `oracle::CanonicalStateOracle` trait + `MockCanonicalStateOracle`; gate enforces `consistent + f_m + f_i + f_s` (integrity + 3 of 4 freshness types) against the disclosed context root. `consistent` redefined to internal triple-anchor agreement; `f_c` deferred (commit-at-completion). 40 tests (default), 45 with `real-anchors`.

### Pieza 1b-i — Real input-freshness oracle (LANDED, `--features oracle-fi`)

**Output:**
- `canonical` module — canonical-JSON SHA-256 byte-identical to BaseOracle (cross-language vectors pinned).
- `input_freshness::BaseOracleInputOracle` — **witness-presented** real `f_i` oracle: verifies BaseOracle `_poc` attestations (Ed25519 + canonical hash), reconstructs the `input_manifest_root`, decides lag from `anchors.block_height`. No BaseOracle changes; no network at settlement.
- `input_freshness::SplitOracle` — composes "f_m mocked, f_i real" with zero gate change.
- 12 integration tests + canonical vectors; default build untouched (the module is feature-gated).

### Pieza 1b-m — Real model-freshness oracle (LANDED, `--features oracle-fm`)

**Decision taken:** committee/quorum trust model (paper §7 constraint 8).

**Output:**
- `model_registry::ModelLineage` — an ordered, canonical-JSON-hashed model lineage (`{weights_hash, epoch, activation_block}` per version), reusing the `canonical` module (shared with f_i).
- `model_registry::QuorumModelOracle` — adopts a lineage only when an **M-of-N quorum** of registered, distinct publishers signed the identical canonical snapshot (Ed25519, offline — no network at settlement). `model_epoch_distance` = canonical-position-at-`now` − committed-position; `Err(OracleUnavailable)` off-lineage or before any activation.
- Composes with the f_i oracle via `oracle::SplitOracle` (moved there from `input_freshness` so it is available without either feature). With both features, `SplitOracle { model: QuorumModelOracle, input: BaseOracleInputOracle }` gates `f_m`+`f_i` fully against real oracles.
- 11 integration tests + shared canonical vectors; default build untouched.

**Deferred (follow-ups):**
- An **on-chain registry source** (`eth_call` reader via the `clients` scaffold) behind the same lineage-adoption boundary — v1 is offline quorum-signed.
- A real `Renewal::evaluate`: the trait's signature `(commitment, current_canonical_root)` carries neither `now` nor thresholds, so it cannot distinguish prospective-only protection from window expiry. **Needs a trait redesign before a faithful implementation.**

### Phase 3b — TEE backend (pending)

**Goals:**
- TDX quote parser with platform-certificate-chain verification
- H100 attestation report parser
- Known-good measurement registry (hash set maintained in-crate or fetched from a trust anchor)
- Integration of TEE backend into a `TeeCommitter` that replaces the mock
- Empirical re-measurement of the triple-anchor skew thresholds in a live testnet

**Gate:** A worker running inside a TDX enclave on a live testnet commits, and a separate verifier node on the same testnet settles, with no mocks anywhere in the path.

**Explicitly out of scope:**
- Any mainnet deployment
- Tokenomics

---

## Phase 4 — SUR Protocol integration (target `v0.4`)

**Goals:**
- Wire proof-of-context into the SUR Protocol settlement rail ([github.com/asastuai/sur-protocol](https://github.com/asastuai/sur-protocol))
- Add a settlement-gating path for inference-priced trades in the A2A Dark Pool
- Smart-contract hooks on Base for reading the canonical execution-context root and publishing root bumps prospectively
- End-to-end demo: an agent purchases an inference from a worker, the worker commits, the protocol gates settlement, and payment clears via x402 if and only if the commitment is fresh

**Gate:** End-to-end demo on Base testnet showing (a) a fresh commitment clearing payment, (b) a stale commitment being rejected with the correct violated-freshness-type event, (c) a prospective-only root bump not retroactively griefing an in-flight commitment.

---

## Phase 5 — Production hardening (`v1.0`)

**Goals:**
- Full fuzz-test suite on the commitment / verification / renewal paths
- Formal verification or informal-but-careful security argument of the Merkle-root sufficiency for a given inference-runtime class
- Published audit report
- Production release on mainnet with a bounded-TVL alpha period
- Standalone deployment path independent of SUR (i.e., other protocols can adopt the crate as a library without pulling in SUR-specific assumptions)

**Gate:** Audit complete, mainnet-live on at least one counterparty pair, post-deployment write-up published.

---

## Notes on companion papers

This crate's development is expected to produce two companion artifacts beyond the position paper:

1. A **construction paper** that formally specifies the Merkle scheme, signature scheme, attestation-chain verification, and the correctness argument for each. Target: Phase 2 / 3.
2. A **deployment writeup** documenting the SUR integration, observed threshold calibrations under real load, and any deviations from the paper-defined defaults that production experience forced. Target: Phase 4.

Both are out of scope for Phase 1.
