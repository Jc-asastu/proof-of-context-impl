# ARCHITECTURE

This document maps the conceptual framework of the paper to the Rust module structure of this crate. Read alongside the position paper at [github.com/asastuai/proof-of-context](https://github.com/asastuai/proof-of-context) v0.9.

---

## Core claim the architecture encodes

Proof-of-context is a *composable settlement-gating layer* that sits on top of existing decentralized-ML verification primitives (proof-of-learning, zkML, TEE attestations, refereed delegation, inference-activation LSH). The layer binds every payable computation to a commitment over its runtime context state, indexes that commitment against the protocol-defined freshness horizon, and refuses settlement when the horizon has been crossed.

The architecture encodes this as a **three-layer separation of concerns**:

1. **Context.** What the commitment binds to. (`context`, `anchor`, `attestation`)
2. **Commitment.** How a worker proves they did the computation against a specific context. (`commitment`)
3. **Settlement.** Whether the commitment is fresh enough to pay against. (`settle`, `renewal`, `freshness`)

Each layer is a trait boundary so that alternate backends can plug in (TEE-only, zkVM-only, hybrid, or mocks for testing) without changing the upper layers.

---

## Module-by-module mapping

### `anchor` — `TripleAnchor`

Encodes the three-clock design from §7 constraint 6 of the paper. A triple anchor bundles a block height, a TEE-reported timestamp, and a Drand round. Each clock has orthogonal failure physics; divergence beyond skew tolerances is cause for slash.

**Honest threat model reminder** (paper §9.4, §11): the triple anchor is a defense against *accidental* skew and isolated single-clock failure *under* a valid TEE attestation chain. It is *not* a defense against a compromised enclave, which observes the other two clocks and can echo them. Attestation (`attestation`) verifies launch-time *code* integrity; a *timing-channel* compromise (TDXdown-class) passes attestation yet is caught by neither attestation nor the anchor — it is carried as the explicit honest-clock assumption (paper §9.4, (H3b)).

### `context` — `ExecutionContextRoot`

Encodes the execution-context root scope defined in §8. The fields are the minimum commitment surface:

- `weights_hash`, `tokenizer_hash`, `system_prompt_hash`
- `sampling_params` (temperature, top-k, top-p, seed)
- `runtime_version`, `inference_config`
- `attention_impl_id`, `precision_mode` — **attributed to TOPLOC** (Ong et al., arXiv:2501.16007) as attack-surface vectors
- `input_manifest_root` — the channel for `f_i` (input freshness)
- `kv_cache_root` — the channel for mode C4 (KV-cache staleness)

Any component that affects computation output and is not in this struct is a trivial evasion vector. Extending the scope is the most likely source of future breaking changes to the crate's types.

### `freshness` — `FreshnessType`, `FreshnessThresholds`

Encodes the four-freshness-type decomposition of §6:

- `f_c` Computational — commit latency
- `f_m` Model — version-epoch distance from canonical
- `f_i` Input — freshness of oracle/RAG/tool-call sources
- `f_s` Settlement — commit-to-clear window

`FreshnessThresholds` carries per-type horizons plus the three-clock skew parameters. Default values for Base mainnet are the empirically-justified ones from §9 of the paper.

### `commitment` — `FreshnessCommitment`, `ContextCommitter`, `CommitmentVerifier`

A `FreshnessCommitment` is the signed artifact a worker produces. It binds `(context_root, anchor, output_hash)` under a TEE-backed signature plus an attestation chain.

`ContextCommitter` is the producer trait (worker-side). `CommitmentVerifier` is the signature-and-attestation-chain-verification trait, independent of settlement gating (which is `settle`'s job).

### `oracle` — `CanonicalStateOracle`

Settlement-time canonical-state lookups for the two freshness predicates that need state external to the commitment: `model_epoch_distance` (`f_m`) and `input_lag_blocks` (`f_i`). `consistent` and `f_s` are decidable from the commitment and `now` alone; `f_m`/`f_i` are not. This is the surface the paper's **H4** assumption (an honest canonical-state oracle) attaches to. v0.3 ships the trait, `mock::MockCanonicalStateOracle`, and two **real** feature-gated oracles: `input_freshness::BaseOracleInputOracle` (`f_i`, witness-presented attestations, `--features oracle-fi`) and `model_registry::QuorumModelOracle` (`f_m`, M-of-N quorum-signed lineage, `--features oracle-fm`), composable per-axis via `SplitOracle`.

### `settle` — `SettlementGate`, `SettlementResult`

The gate that decides whether to clear payment. This is the *attestation-as-settlement* distinction of §3.6 made concrete: the gate consumes a commitment, the **disclosed** execution-context root (mechanism (i) — bound to the committed `context_root` before any field is read), the current anchor, and the thresholds, and returns either `Clear` or `Rejected(Vec<FreshnessType>)`. As of v0.3 it enforces `consistent` (internal triple-anchor agreement), `f_m` and `f_i` (against a `CanonicalStateOracle`), and `f_s` — integrity plus three of the four freshness types. `f_c` is deferred (not measurable from `(A, now)`; handled structurally via commit-at-completion). The violated freshness types are reported so the protocol can emit the correct refund or slash event.

### `renewal` — `Renewal`, `RenewalOutcome`

Implements the prospective-only root bump semantics of §7 constraint 5. When the canonical root bumps from `t` to `t+1`, in-flight commitments against `t` remain valid within their settlement window — they are not retroactively invalidated. The `Renewal::evaluate` method answers "is this commitment still a valid settlement instrument given the current canonical root?"

### `attestation` — `AttestationChain`, `AttestationVerifier`, `AttestationVendor`

Verifies the TEE attestation chain that anchors the commitment's signing key identity to a known-good enclave measurement. In v0.2 the chain is carried opaquely with a `MockSoftware` vendor tag; concrete parsers for TDX, SEV-SNP, and H100 attestation formats are a Phase-3 task.

### `error` — `PocError`

`PocError` is a `thiserror`-derived error enum (introduced in v0.2).

---

## Design invariants the crate enforces by shape

- **Commitment → Gate flow is one-directional.** A commitment is produced, then verified, then gated. Types don't permit settling a commitment without gating, and don't permit gating without verification (by trait bounds at call sites, enforced in future concrete wiring).
- **Threat model is consistent across modules.** The triple-anchor protects against accidental skew only; every doc comment in `anchor` says so. Attestation covers enclave *code* integrity; a *timing-channel* compromise (TDXdown-class) is covered by neither the anchor nor attestation, and is carried as the explicit honest-clock assumption (paper §9.4, (H3b)). No module silently upgrades the security claim.
- **Freshness is per-type, not scalar.** Rejection returns a vector of violated `FreshnessType`s, not a boolean or a score. This forces protocol authors to think about which axis failed and emit the appropriate economic event.
- **Settlement windows are explicit parameters.** `FreshnessThresholds` carries `max_fc_blocks`, `max_fm_epochs`, `max_fi_blocks`, `max_fs_blocks` as named fields. No implicit defaults hidden inside the gate.

---

## Phase status

Phase 2 (the first real-cryptography phase) landed in v0.2:

- `sha2` for Merkle commitments over `ExecutionContextRoot`
- `ed25519-dalek` for commitment signatures
- a concrete `MockCommitter` and `MockSettlementGate` exercising the full commit → verify → settle flow end-to-end with software keys (for tests, not for economic settlement)
- `thiserror` replacing the hand-rolled error enum
- Serde implementations on all public structs

Phase 3a / v0.3 (pieza 1) added the `CanonicalStateOracle` trait and wired `consistent` + `f_m` + `f_i` + `f_s` into the gate, with `consistent` redefined as internal triple-anchor agreement and `f_c` deferred. The Drand and JSON-RPC block-height clients landed under the `real-anchors` feature; the **real** `f_i` and `f_m` oracles landed as piezas 1b-i / 1b-m (feature-gated); the Solana dark-pool multi-party gate landed as brick 1 (`--features darkpool-sol`) with on-chain enforcement merged in sur-protocol-solana PR #1 (brick 3). Phase 3b pends: the TEE backend (TDX quote parser + H100 attestation verifier) and an on-chain registry source for the model lineage. Phase 4 is the SUR integration (Solana deployment target). See [`ROADMAP.md`](./ROADMAP.md).
