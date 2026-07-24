# proof-of-context

> *PAL\*M attests that a computation happened correctly; Proof-of-Context makes those attestations economically perishable, binding freshness to settlement so stale inferences cannot clear payment.*

Reference implementation of the **proof-of-context** primitive: an *attestation-as-settlement* layer for decentralized machine learning.

**Position paper:** [github.com/asastuai/proof-of-context](https://github.com/asastuai/proof-of-context), v0.6 (22 April 2026). Please read the paper first; this crate encodes the architecture it names.

**Status:** `v0.3.0-clients`. Phase 2 shipped: SHA-256 Merkle commitments over the execution-context root, Ed25519 signing / verification, `MockCommitter`, `MockVerifier`, `MockSettlementGate` with pluggable verifier generic. **Phase 3a (this release) adds the real-anchor network clients**: live Drand round fetcher (Cloudflare mirror) and EVM block-RPC fetcher (`eth_blockNumber`), composable into a `TripleAnchor` against live mainnet. Feature-gated under `--features real-anchors`. Phase 3b (TDX + H100 attestation chain) is the next milestone.

---

## What this crate is for

Existing verification primitives in decentralized ML (proof-of-learning, zkML, TEE attestations, refereed delegation, inference-activation LSH) answer the question *"was the computation correct?"* They do not answer *"is it still worth settling on?"*

Proof-of-context sits on top of those primitives and gates payment against a *freshness commitment*: a signed bundle of `(execution_context_root, triple_anchor, output_hash)` that expires. If a worker's commitment has aged beyond the protocol-defined horizon when settlement is attempted, payment does not clear (regardless of whether the underlying math was correct).

This crate provides the Rust types and traits for building such a protocol layer.

## ◊ Architecture at a glance

Please see [`ARCHITECTURE.md`](./ARCHITECTURE.md) for the full mapping from paper sections to crate modules.

| Paper section | Module | Core type / trait |
|---|---|---|
| §6 — Four Freshness Types | `freshness` | `FreshnessType`, `FreshnessThresholds` |
| §7 constraint 6 — Triple Anchor | `anchor` | `TripleAnchor` |
| §8 — Execution-Context Root | `context` | `ExecutionContextRoot`, `merkle_root()` |
| §7 constraint 5 + §8 | `commitment` | `FreshnessCommitment`, `ContextCommitter` |
| §3.6 + §6 — Settlement gating | `settle` | `SettlementGate`, `SettlementResult` |
| §7 constraint 5 — Prospective-only bumps | `renewal` | `Renewal`, `RenewalOutcome` |
| §7 constraint 6 + §9 | `attestation` | `AttestationChain`, `AttestationVerifier` |

## Build and test

```bash
cargo build
cargo test

# Optional: enable the real-anchor clients (Drand + EVM RPC fetchers).
cargo build --features real-anchors
cargo test --features real-anchors

# Run live integration tests that hit Drand mainnet + Base RPC (opt-in):
cargo test --features real-anchors --lib -- --ignored live
```

The default build has no HTTP dependency. With `--features real-anchors` the
crate adds `ureq` + `serde_json` and exposes `clients::DrandHttpClient`,
`clients::BaseRpcClient`, and `clients::RealAnchorBuilder` for fetching live
clocks. Please see `tests/real_anchors_flow.rs` for an end-to-end example.

## EigenCloud case study

End-to-end demo positioning proof-of-context as the freshness layer above an `EigenCompute` / `EigenAI`-style verifiable-execution primitive:

```bash
cargo run --example eigencompute_freshness_receipt
```

The example walks the honest path, the stale path (where re-execution still agrees but the receipt has aged past its window), and the four cheating modalities from `Proof of Context applied to Verifiable Inference (v0.1)`:

- **M1** model substitution: caught by output-hash mismatch on canonical re-execution
- **M2** request mutation: caught by `ExecutionContextRoot` Merkle disagreement
- **M3** billing inflation: caught by output-hash binding to actual delivered bytes
- **M4** capacity falsification: caught by attestation-chain vendor / payload mismatch

Programmatic equivalents live in `tests/eigencompute_flow.rs`. The motivation: `EigenVerify-Objective` answers *"was the computation deterministic?"*. Proof-of-context answers the orthogonal economic question *"is the result still valid to settle on?"*.

## Multi-agent orchestration

Standalone runnable demo of a 3-agent orchestration pipeline that wires the proof-of-context primitives into an agent runtime:

```bash
cargo run --example multi_agent_orchestrator
```

The example covers:

- **Agent runtime**: a uniform `Agent` trait implemented by three concrete agents covering distinct patterns: I/O (`OraclePriceAgent`), pure compute (`DecisionAgent`), state mutation (`SettlementAgent`).
- **Orchestration**: a sequential `Orchestrator` that routes tasks between agents and threads a shared `MemoryStore` through them.
- **Reliability**: typed `AgentError::{Transient, Permanent}` driving retry with exponential backoff or short-circuit on permanent failure.
- **Observability**: pluggable `Observer` trait with default `ConsoleObserver` emitting structured events at every agent boundary.
- **Verifiability**: each successful agent step produces a `FreshnessCommitment`; the orchestrator chains the per-step commitments and seals the chain with a SHA-256 over the ordered signing digests.

Four scenarios run in sequence: honest path, retry-then-success (oracle fails twice then succeeds), permanent failure (oracle endpoint unreachable, pipeline short-circuits), and a chain-hash integrity check. Programmatic equivalents in `tests/multi_agent_orchestrator_flow.rs` (6 tests).

## Backing-Age: un-resettable source age for agent pipelines

`src/backing.rs` + `examples/staleness_laundering.rs` (spec: `SPEC-BACKING-AGE-v0.1.md` in the paper repo).

Agent pipelines launder staleness: every derivation (an LLM summary, a plan) stamps its output "now", resetting the age of the sources it derived from. HTTP solved this in 1997 — RFC 9111's `Age` header sums residence along the whole cache path. This module transfers that semantic to agent context:

- **`BackingSet`** — the sources an output transitively depends on, each with the instant it was last *validated against ground truth* (never the derivation instant). Propagation is set **union**, oldest-wins: stages are transparent, the clock is un-resettable.
- **`gate(policy)`** — evaluates *source* age at *settlement* time, per freshness class, fail-closed on unknown classes; a `Stale` verdict lists exactly which sources to re-verify (targeted, not re-verify-everything).
- **`BoundaryAge`** — the privacy rule, enforced by the type system: a backing set is a provenance trace and stays inside the trust domain; what crosses a boundary is one scalar (`max_age_secs`) — RFC 9111's degenerate form.

**v0.2a — signing (closes forgery):** `SignedBackingEntry` binds an entry to the source content it was validated against with a validator's Ed25519 signature; `TrustedValidators` + `SignedBackingSet::into_verified` reject entries not signed by a trusted key, so a stage cannot forge a fresh `attested_at` to launder staleness. It does **not** close *omission* (a stage can drop a signed entry) — that is the compound-attestation frontier (v0.2b, Forough et al. arXiv 2605.03213), documented as loudly as the forgery gap was. The forgery demo is in `examples/staleness_laundering.rs`.

Honest scope: windows are operator-chosen, not derived; v0.2a signs individual entries, not whole-set commitments. Lineage: RFC 9111, event-time/watermarks (Dataflow/Flink), TOCTOU-in-agents (arXiv 2508.17155), Copilot 2004. Run the demo: `cargo run --example staleness_laundering`. First deployment: `engram-live` (agent-memory freshness sidecar) gates STILL_VALID verdicts by attestation age with it.

## Roadmap

Please see [`ROADMAP.md`](./ROADMAP.md) for phased plans. Rough order:

1. **Scaffold (this release).** Traits, types, architectural bones.
2. **Primitives.** SHA-256 Merkle root for execution context; Ed25519 signing; in-process triple-anchor check.
3. **Mock backend.** Software-only committer + settlement gate that exercises the full flow end-to-end in tests.
4. **TEE backend.** TDX + H100 attestation chain verification hooked into the committer.
5. **Drand client.** Real fetch of Drand mainnet rounds; block-RPC client for anchor construction.
6. **SUR Protocol integration.** First deployment: wire proof-of-context into the SUR settlement rail (see [github.com/asastuai/sur-protocol](https://github.com/asastuai/sur-protocol)).

## License

Licensed under either of:

- MIT License ([LICENSE-MIT](./LICENSE-MIT))
- Apache License, Version 2.0 ([LICENSE-APACHE](./LICENSE-APACHE))

at your option. The position paper is released under CC BY 4.0; the code in this repository is released under the dual MIT / Apache-2.0 license that is standard for the Rust ecosystem.

## Author and contact

Juan Cruz Maisu, `juancmaisu@outlook.com`, [github.com/asastuai](https://github.com/asastuai).

---

## Body of work

This crate is part of an evolving body of work by Juan Cruz Maisu, independent researcher in Buenos Aires, Argentina:

- [Proof of Context (papers)](https://github.com/asastuai/proof-of-context): v0.6 framework + v0.1 applied to verifiable inference
- [Proof of Context reference implementation](https://github.com/asastuai/proof-of-context-impl): this crate
- [SUR Protocol](https://github.com/asastuai/sur-protocol): perp DEX with agent-native execution layer
- [Hermetic Computing](https://github.com/asastuai/kybalion): Rust framework formalizing hermetic principles as computational primitives
- [intent-cipher](https://crates.io/crates/intent-cipher): published crate, stream cipher with intent-keyed schedule

**Status:** open to research-engineering and applied-research roles in inference attestation, decentralized ML infrastructure, and agent-native systems. Remote, full-time, any timezone.

---

Juan Cruz Maisú ♥
