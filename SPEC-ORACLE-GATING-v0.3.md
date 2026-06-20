# SPEC — Pieza 1: Canonical-State Oracle + Freshness Gating (crate v0.3)

**Status:** ✅ **IMPLEMENTED** (crate v0.3.0). Both build gates cleared — v0.7 on ePrint + author approval. Shipped: `oracle::CanonicalStateOracle` + `mock::MockCanonicalStateOracle`; gate enforces `consistent` + `f_m` + `f_i` + `f_s` against the disclosed root; `consistent` redefined to internal triple-anchor agreement; `f_c` deferred. 40 tests pass (default), 45 with `real-anchors`; 7 new in `tests/oracle_gating.rs`. **Revised** after an independent design review surfaced an `f_c` measurability problem (see §4).
**Build target:** `proof-of-context` crate v0.3 (additive over v0.2).
**Decisions locked:** mock-first; context disclosure via mechanism (i); `consistent` redefined to internal-anchor agreement; **`f_c` deferred** (not measurable from current data — §4).

---

## 0. Goal & scope

Bring the settlement gate from enforcing `{Verify, consistent, fresh_s}` (v0.2) to enforcing **`{Verify, consistent, fresh_m, fresh_i, fresh_s}`** — the integrity check plus **three of the four freshness types** (model, input, settlement). `fresh_m`/`fresh_i` are decided against a `CanonicalStateOracle`, mocked for tests.

**`f_c` (computational freshness) is deliberately NOT enforced.** It is not measurable from what the commitment carries (only the commit anchor `A` and settlement time `now`; never `t_computation_done`). The "sat on the result" concern `f_c` names is handled **structurally** (commit-at-completion) and by `fresh_s`, not as a separate predicate. See §4.

**In scope (v0.3):**
- `CanonicalStateOracle` trait (`model_epoch_distance`, `input_lag_blocks`) + `MockCanonicalStateOracle`.
- Wire `fresh_m`, `fresh_i` into the gate.
- **Redefine `consistent`** as internal triple-anchor agreement (§4).
- Context disclosure (mechanism (i)): gate receives the revealed `ExecutionContextRoot`, recomputes `merkle_root()`, checks it equals `commitment.context_root` before reading any field.
- Tests demonstrating the gate enforces `consistent` + `fresh_m` + `fresh_i` + `fresh_s`.

**Out of scope (deferred):**
- `f_c` enforcement → commit-at-completion (in-enclave) or a TEE-attested completion timestamp; Phase 3b / paper v1.0.
- Real oracle — BaseOracle for `f_i`, on-chain model-root+epoch registry for `f_m` → **pieza 1b**.
- TEE-backed committer → Phase 3b. SUR integration → Phase 4.

---

## 1. The oracle interface (`src/oracle.rs`, new)

```rust
/// Settlement-time canonical-state lookups for the two freshness predicates
/// that require state external to the commitment. Pieza 1b implements this for
/// real (BaseOracle + on-chain model-root registry); v0.3 ships trait + mock.
pub trait CanonicalStateOracle {
    /// f_m: version-epoch distance between the committed model (by weights hash)
    /// and the canonical model at `now`. 0 = current; larger = staler.
    /// Err if the weights hash is not in the canonical lineage.
    fn model_epoch_distance(&self, weights_hash: Hash32, now: &TripleAnchor) -> Result<u64, PocError>;

    /// f_i: how many blocks the committed input-world state (by input-manifest
    /// root) lags the canonical input-world state at `now`.
    fn input_lag_blocks(&self, input_manifest_root: Hash32, now: &TripleAnchor) -> Result<u64, PocError>;
}
```

These are exactly the two channels §9 says need external state; `consistent`, `fresh_s` are decidable from `C`/`now` alone.

---

## 2. Gate extension (`src/settle.rs`, `src/mock.rs`)

`verify_and_settle` gains the **disclosed root**; the oracle is held by the gate (mirroring how `MockSettlementGate<V>` already holds its verifier):

```rust
fn verify_and_settle(
    &self,
    commitment: &FreshnessCommitment,
    root: &ExecutionContextRoot,   // NEW — disclosed context (mechanism (i))
    now: &TripleAnchor,
    thresholds: &FreshnessThresholds,
) -> Result<SettlementResult, PocError>;
```

`MockSettlementGate<V: CommitmentVerifier, O: CanonicalStateOracle>`, constructed `::new(verifier, oracle)`.

**Gate logic (v0.3):**
1. `verifier.verify(commitment)` — Ed25519 + attestation. *(existing)*
2. **Context binding:** `root.merkle_root() == commitment.context_root`; else `Err(PocError::RootMismatch)`. *(new — §3)*
3. `consistent` — internal triple-anchor agreement (§4). Violation → `Computational`.
4. `fresh_s` — `now.h − A.h ≤ max_fs_blocks`. Violation → `Settlement`. *(existing)*
5. `fresh_m` — `oracle.model_epoch_distance(root.weights_hash, now) ≤ max_fm_epochs`. Violation (or `Err`) → `Model`. *(new)*
6. `fresh_i` — `oracle.input_lag_blocks(root.input_manifest_root, now) ≤ max_fi_blocks`. Violation → `Input`. *(new)*

**No `fresh_c` check** (deferred — §4). Accumulate violations (no early-return — also fixes the v0.2 backwards-clock short-circuit). `Clear` iff empty.

New `PocError` variants: `RootMismatch`, `OracleUnavailable`. Policy: unknown model (`model_epoch_distance` → `Err`) maps to `Rejected([Model])` (an un-registered model is treated as stale/invalid); this is distinct from operational DA failure where §7 of the paper defaults to "favor the worker."

---

## 3. The crux: context disclosure (mechanism (i))

`fresh_m`/`fresh_i` need the gate to read `weights_hash` + `input_manifest_root`, but `FreshnessCommitment` carries only the **opaque** `context_root` hash. So the settlement caller discloses the `ExecutionContextRoot` struct; the gate recomputes `merkle_root()` and checks it matches the committed hash (step 2) **before** reading any field — preventing a worker from disclosing a fresh-looking context different from what it committed. Additive: a new gate argument; **no change to `FreshnessCommitment` / `SPEC-WIRE-FORMAT-v0.1` / the 5 reference impls.**

> Privacy note (open, see independent-review Q2): because the root is a **flat SHA-256** over all 10 fields, verifying the binding requires disclosing the full preimage (incl. `system_prompt_hash`). A true Merkle *tree* root would allow selective disclosure (reveal only `weights_hash` + `input_manifest_root` with proofs). Out of scope for v0.3; flagged for the wire-format's next revision if privacy at settlement matters.

---

## 4. `consistent` redefinition + `f_c` deferral (resolved — incorporates independent review)

Two findings, the second from an independent review:

**(a) `consistent` must be internal-anchor agreement, not `A`-vs-`now`.** v0.2 implements `consistent` as `¬diverges_beyond(A, now)` at skew ±2 blocks — but settlement is legitimately far from commit (up to `max_fs` = 300 blocks), so this makes `fresh_s` unreachable and is semantically wrong. **Fix:** `consistent` checks that the **three clocks of `A` agree with each other** within skew — a property of `A` alone, detecting a tampered/desynced commit clock:
- Drand → wall-time via `drand_wall_time_secs(ρ)` *(already in `anchor.rs`)*.
- TEE timestamp `τ` is wall-time (ns).
- Block height `h` → wall-time needs a block→time reference (Base genesis + `h × 2 s`).
Check pairwise agreement within the skew bounds. Under the **default** (pure-crypto) feature, no block→time reference is present → check **TEE ↔ Drand** only; with the `real-anchors` feature (Phase 3a, landed), include the block leg.

**(b) `f_c` is not measurable from `(A, now)` — defer it.** `f_c` (computation-done → submit) needs `t_computation_done`, which the commitment never carries. `now − A` is the **commit→settle** gap — that is `fresh_s`, not `f_c`. (This also corrects an overclaim in the published v0.7 §10.2, which called `fresh_c` "a block-height delta like `fresh_s`, simply not yet wired" — it is not; that delta *is* `fresh_s`. → v0.8 fix.) `f_c` is best understood not as a fourth co-equal dimension but as an **artifact of allowing a gap between computation and commitment.** Resolutions:
- **Commit-at-completion (preferred):** the TEE committer signs the output at the moment of production → commit ≈ completion → `f_c ≡ 0` by construction. "Sat on the result" is still caught: a worker who sits on the *signed* commitment and submits late shows up as large `now − A` → caught by `fresh_s`. No extra field. **Caveat:** only holds when the compute is *in-enclave* (the paper's TEE/H100 setting). For out-of-enclave compute, use —
- **TEE-attested `computation_completed_at` timestamp** (the independent review's option 2): allows `commit ≠ completion`, at the cost of a new attested field. Reserve for v1.0.
- Inferring `f_c` from the input-world-state block height (review's option 3): rejected — gives a lower bound on compute *start*, not completion, and needs a gameable duration estimate.

**Net for v0.3:** enforce `consistent` (fixed) + `fresh_m` + `fresh_i` + `fresh_s`. Defer `f_c`. The gate enforces **integrity + 3 of the 4 freshness types** — a big jump from v0.2's 1, honestly labeled (not "4/4").

---

## 5. Mock oracle + tests

`MockCanonicalStateOracle` (configurable epoch / per-hash map; configurable input lag) drives fresh/stale scenarios deterministically.

New integration tests (`tests/`):
- `all_fresh_clears` — consistent ok, `f_m`/`f_i` fresh, within `fresh_s` → `Clear`.
- `stale_model_rejected` — `model_epoch_distance > max_fm` → `Rejected` contains `Model`.
- `stale_input_rejected` — `input_lag_blocks > max_fi` → `Rejected` contains `Input`.
- `settled_late_rejected` — `now.h − A.h > max_fs` (the "sat on it" / late-settlement case, caught by `fresh_s`, not a separate `f_c`) → `Rejected` contains `Settlement`.
- `inconsistent_anchor_rejected` — `A`'s clocks disagree beyond skew (e.g., TEE vs Drand wall-time) → `Rejected` contains `Computational`.
- `disclosed_root_mismatch_errs` — disclosed root whose `merkle_root()` ≠ committed hash → `Err(RootMismatch)`.
- `unknown_model_rejected` — oracle `Err` on unknown weights hash → `Rejected([Model])`.
- Existing v0.2 tests updated where they relied on the old `A`-vs-`now` `consistent` semantics.

Gate demonstrates `consistent` + `f_m` + `f_i` + `fresh_s` end-to-end with software keys + a mock oracle.

---

## 6. What v0.3 does NOT touch
`SPEC-WIRE-FORMAT-v0.1`, `FreshnessCommitment`, the committer, the 5 reference impls. Additive: a new trait + module, a new gate argument, a new mock, new tests, plus the `consistent`-semantics fix.

---

## 7. Paper sync (v0.8 — not now)
- **The four-type taxonomy stays** (four real failure modes — good framework). What changes is the *measurability/enforcement* claim.
- §10.2: "enforces 2 of 4" → "enforces `consistent` + `f_m` + `f_i` + `f_s` against a (mock) canonical-state oracle; soundness of `f_m`/`f_i` still rests on **H4** (an honest real oracle), which the mock stands in for."
- §10.2: remove the `fresh_c`-is-a-block-delta-like-`fresh_s` line (overclaim). State that `f_c` is handled **structurally** via commit-at-completion + `fresh_s`, and that a distinct compute→commit measurement would need a TEE-attested completion timestamp (future).
- §9.2: redefine `consistent` to internal-anchor agreement; note `fresh_c`/`fresh_s` both reduce to `now − A` and `f_c` is therefore not a separate measured predicate today.
- Target: paper v0.8, or the standalone construction paper reserved for Phase 3/4.

---

## 8. Open questions for pieza 1b (real oracle)
1. **What is "canonical state" for SUR (first deployment)?** Which model lineage is canonical; what counts as canonical input-world state for inference-priced trades. *(Research, 2026-06: the only real model today is `claude-sonnet-4` in the EVM `intent-engine`; the model path on SUR-Solana is Phase-3 planned. Canonical input-world state = Pyth, addressed by wall-clock timestamp — impedance vs the crate's block-based freshness to bridge at Phase 4.)*
3. **BaseOracle reuse → DONE (pieza 1b-i):** mapped onto `input_lag_blocks` via the **witness-presented** `BaseOracleInputOracle` (`src/input_freshness.rs`, `--features oracle-fi`). Caller presents BaseOracle `_poc` attestations; oracle verifies Ed25519 + canonical-JSON SHA-256, reconstructs the `input_manifest_root`, reads `anchors.block_height`. No BaseOracle changes; no network at settlement. f_i now real, f_m still mock (composed via `SplitOracle`). 12 tests + canonical cross-language vectors pass.

2. **Oracle trust model → DECIDED + DONE (pieza 1b-m):** **committee/quorum** (§7.8). `model_registry::QuorumModelOracle` (`--features oracle-fm`) adopts a model lineage only on an M-of-N quorum of registered publishers signing the canonical snapshot; decides `f_m` by canonical-position distance at the settlement anchor. Offline (no network). 11 tests.

### Still open (beyond)
4. **On-chain model-root registry source:** the v1 oracle adopts an offline quorum-signed lineage; an `eth_call` reader (reuse the `clients` scaffold) can populate the same lineage boundary later. The **`Renewal` trait needs a redesign first** — its `(commitment, current_canonical_root)` signature lacks `now`/thresholds, so it cannot decide prospective-only-vs-expired; deferred until the trait carries the settlement clock + window.
5. **Selective disclosure / privacy (review Q2):** decide whether the execution-context root becomes a true Merkle tree, in coordination with the wire-format spec.
6. **`input_manifest_root` definition (pieza 1b-i default — confirm):** `{ sources: [{endpoint, payload_hash, source_id}], version: "f_i/0.1" }`, sources pre-sorted by `(endpoint, payload_hash)`, root = canonical-JSON SHA-256. The **array pre-sort is a new cross-language contract point** beyond `canonicalHash` (which sorts keys, not array elements) — must land in `proof-of-context/test-vectors/v0.1.json` before other implementations build f_i manifests.

---

## 9. Self-review
- **Placeholders:** none — signatures grounded in v0.2 types.
- **Consistency:** gate logic matches the refined §9 model (consistent = internal agreement; `f_c` deferred; `f_m`/`f_i` oracle-gated); deferred pieces match the paper's H4/Phase-3 boundaries.
- **Scope:** bounded and additive; the one model decision (§4) is resolved explicitly, incorporating the independent review.
- **Honesty:** `f_c` deferral is stated plainly (not "4/4"); the v0.7 §10.2 overclaim is owned and queued for v0.8.

---

*Spec ends. No code until v0.7 is on ePrint and the author approves.*
