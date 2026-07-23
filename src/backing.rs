//! Backing-Age: un-resettable source-age propagation for agent pipelines
//! (SPEC-BACKING-AGE v0.1, extends SPEC-WIRE-FORMAT v0.1 `_poc` block).
//!
//! HTTP solved staleness laundering in 1997 with the `Age` header
//! (RFC 9111 §4.2.3: age is the sum of residence times along the path from
//! the origin — intermediate caches never reset it). Agent pipelines forgot
//! it: every LLM/tool derivation stamps its output "now", laundering the age
//! of the sources it derived from. This module makes the clock un-resettable:
//! an output's [`BackingSet`] is the **union** of its inputs' backing sets,
//! `attested_at` advances only by re-validation against the source — never by
//! derivation. Stages are transparent, exactly like caches in RFC 9111.
//!
//! Privacy (spec §2.5, normative): the full backing set is a provenance trace
//! and MUST NOT cross a trust boundary. What crosses is [`BoundaryAge`] — a
//! single scalar aggregate (the RFC 9111 degenerate form), produced by
//! [`BackingSet::to_boundary`]. The type system enforces the minimization:
//! `BoundaryAge` carries no source ids, no classes, no per-entry timestamps.
//!
//! Lineage, cited not claimed: RFC 9111 Age semantics · event-time/watermarks
//! (Dataflow/Flink) · TOCTOU in LLM agent chains (arXiv 2508.17155) ·
//! Copilot 2004 window-of-vulnerability · PoC framework v0.9.1. No theorem
//! claims: this is engineering transfer plus a working artifact.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// One backing claim: "this output transitively depends on `source_id`,
/// which was last validated against ground truth at `attested_at_secs`".
///
/// `attested_at_secs` is the *validation* instant (unix seconds), never the
/// derivation instant. `class` is an open-vocabulary freshness class
/// (e.g. `"repo-structure"`, `"user-preference"`, `"price"`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackingEntry {
    /// Canonical id of the source context (path hash, feed id, obs id).
    pub source_id: String,
    /// Unix seconds of the last validation of the source against ground
    /// truth. Only re-validation may advance it; derivation never does.
    pub attested_at_secs: u64,
    /// Open-vocabulary freshness class used by [`AgePolicy`] lookups.
    pub class: String,
}

/// The set of backing claims carried by a pipeline output, keyed by
/// `source_id`, deduplicated **oldest-wins** (conservative: when the same
/// source appears with two attestation times, the older one is kept).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackingSet {
    entries: BTreeMap<String, BackingEntry>,
}

/// Privacy-preserving boundary aggregate (spec §2.5 rule 2): the single
/// scalar allowed to cross a trust boundary by default. Deliberately
/// carries no source ids, classes, or per-entry timestamps.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BoundaryAge {
    /// Age in seconds of the *oldest* backing entry at emission time —
    /// the conservative bound a downstream gate needs.
    pub max_age_secs: u64,
}

/// Per-class maximum-age policy for [`BackingSet::gate`]. v0.1: operator-
/// chosen numbers (we make no claim of deriving them — see spec §2.4).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AgePolicy {
    /// Max tolerated age per class, in seconds.
    pub max_age_secs_by_class: BTreeMap<String, u64>,
    /// Fallback for classes absent from the map. `None` = fail-closed:
    /// an entry of unknown class is reported stale (conservative).
    pub default_max_age_secs: Option<u64>,
}

/// One stale finding: which source, how old it is, what the policy allowed.
/// This is what makes re-verification *targeted* (re-check only these).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StaleEntry {
    /// The offending backing entry.
    pub entry: BackingEntry,
    /// Its age at gate time, in seconds.
    pub age_secs: u64,
    /// The limit that was exceeded (`None` = unknown class, fail-closed).
    pub limit_secs: Option<u64>,
}

/// Gate verdict over a backing set at a given evaluation time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BackingVerdict {
    /// Every backing entry is within its class window.
    Fresh,
    /// At least one entry exceeded its window; the offending entries are
    /// listed so the caller can re-verify *only those*.
    Stale(Vec<StaleEntry>),
}

impl BackingEntry {
    /// Age of this entry at `now_secs`, saturating at zero (a validation
    /// timestamp in the future — clock skew — reads as age 0, never
    /// underflows).
    pub fn age_secs(&self, now_secs: u64) -> u64 {
        now_secs.saturating_sub(self.attested_at_secs)
    }
}

impl BackingSet {
    /// Empty set (an output with no world-state dependencies).
    pub fn new() -> Self {
        Self::default()
    }

    /// Build from entries, applying oldest-wins dedup by `source_id`.
    pub fn from_entries(entries: impl IntoIterator<Item = BackingEntry>) -> Self {
        let mut set = Self::new();
        for entry in entries {
            set.insert(entry);
        }
        set
    }

    /// Insert one entry. If `source_id` already present, the **older**
    /// `attested_at_secs` is kept (conservative merge). The class of the
    /// kept (older) entry is retained.
    pub fn insert(&mut self, entry: BackingEntry) {
        match self.entries.get(&entry.source_id) {
            Some(existing) if existing.attested_at_secs <= entry.attested_at_secs => {
                // Existing is older (or equal): keep it.
            }
            _ => {
                self.entries.insert(entry.source_id.clone(), entry);
            }
        }
    }

    /// The propagation rule (spec §2.2): union of backing sets,
    /// oldest-wins per source. This is what a stage calls to derive its
    /// output's backing from its inputs' backings. Stages add NO entry
    /// for themselves.
    pub fn union(&self, other: &Self) -> Self {
        let mut out = self.clone();
        for entry in other.entries.values() {
            out.insert(entry.clone());
        }
        out
    }

    /// Number of distinct backing sources.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True iff there are no backing entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Iterate entries in canonical (source_id) order.
    pub fn iter(&self) -> impl Iterator<Item = &BackingEntry> {
        self.entries.values()
    }

    /// Age of the oldest entry at `now_secs`; `None` for an empty set.
    pub fn max_age_secs(&self, now_secs: u64) -> Option<u64> {
        self.entries
            .values()
            .map(|entry| entry.age_secs(now_secs))
            .max()
    }

    /// Privacy boundary aggregate (spec §2.5): the only form that crosses
    /// a trust boundary by default. `None` for an empty set (nothing to
    /// report — and nothing to leak).
    pub fn to_boundary(&self, now_secs: u64) -> Option<BoundaryAge> {
        self.max_age_secs(now_secs)
            .map(|max_age_secs| BoundaryAge { max_age_secs })
    }

    /// Evaluate this backing set against `policy` at `now_secs`.
    ///
    /// - Empty set ⇒ [`BackingVerdict::Fresh`] (no world-state claims).
    /// - Entry class in the policy map ⇒ compare age to that limit.
    /// - Unknown class ⇒ use `default_max_age_secs`; if `None`, the entry
    ///   is reported stale with `limit_secs: None` (fail-closed).
    pub fn gate(&self, policy: &AgePolicy, now_secs: u64) -> BackingVerdict {
        let mut stale = Vec::new();
        for entry in self.entries.values() {
            let age_secs = entry.age_secs(now_secs);
            let limit = policy
                .max_age_secs_by_class
                .get(&entry.class)
                .copied()
                .or(policy.default_max_age_secs);
            match limit {
                Some(limit_secs) if age_secs <= limit_secs => {} // fresh
                Some(limit_secs) => stale.push(StaleEntry {
                    entry: entry.clone(),
                    age_secs,
                    limit_secs: Some(limit_secs),
                }),
                None => stale.push(StaleEntry {
                    entry: entry.clone(),
                    age_secs,
                    limit_secs: None, // unknown class, fail-closed
                }),
            }
        }
        if stale.is_empty() {
            BackingVerdict::Fresh
        } else {
            BackingVerdict::Stale(stale)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn e(source: &str, attested: u64, class: &str) -> BackingEntry {
        BackingEntry {
            source_id: source.to_string(),
            attested_at_secs: attested,
            class: class.to_string(),
        }
    }

    // ---------- age ----------

    #[test]
    fn age_is_now_minus_attested() {
        assert_eq!(e("a", 1_000, "c").age_secs(1_500), 500);
    }

    #[test]
    fn age_saturates_at_zero_on_clock_skew() {
        // attested "in the future" (skewed clock) must read 0, not underflow.
        assert_eq!(e("a", 2_000, "c").age_secs(1_500), 0);
    }

    // ---------- oldest-wins dedup ----------

    #[test]
    fn insert_same_source_keeps_oldest_attestation() {
        let mut s = BackingSet::new();
        s.insert(e("src", 1_000, "c"));
        s.insert(e("src", 5_000, "c")); // newer attestation of same source
        assert_eq!(s.len(), 1);
        assert_eq!(s.iter().next().unwrap().attested_at_secs, 1_000);

        // Same in reverse order: older inserted second still wins.
        let mut s2 = BackingSet::new();
        s2.insert(e("src", 5_000, "c"));
        s2.insert(e("src", 1_000, "c"));
        assert_eq!(s2.iter().next().unwrap().attested_at_secs, 1_000);
    }

    // ---------- union: the propagation rule ----------

    #[test]
    fn union_is_set_union_with_oldest_wins() {
        let a = BackingSet::from_entries([e("x", 100, "c1"), e("y", 200, "c2")]);
        let b = BackingSet::from_entries([e("y", 150, "c2"), e("z", 300, "c3")]);
        let u = a.union(&b);
        assert_eq!(u.len(), 3);
        let by_id: std::collections::BTreeMap<_, _> =
            u.iter().map(|en| (en.source_id.clone(), en.attested_at_secs)).collect();
        assert_eq!(by_id["x"], 100);
        assert_eq!(by_id["y"], 150); // oldest of {200, 150}
        assert_eq!(by_id["z"], 300);
    }

    /// Property (hand-rolled over a deterministic case matrix):
    /// union is commutative, associative, idempotent.
    #[test]
    fn union_properties_commutative_associative_idempotent() {
        let sets = [
            BackingSet::new(),
            BackingSet::from_entries([e("x", 100, "c")]),
            BackingSet::from_entries([e("x", 50, "c"), e("y", 200, "d")]),
            BackingSet::from_entries([e("y", 150, "d"), e("z", 10, "e")]),
        ];
        for a in &sets {
            assert_eq!(a.union(a), *a, "idempotent");
            for b in &sets {
                assert_eq!(a.union(b), b.union(a), "commutative");
                for c in &sets {
                    assert_eq!(
                        a.union(b).union(c),
                        a.union(&b.union(c)),
                        "associative"
                    );
                }
            }
        }
    }

    /// Property: propagation never rejuvenates — for every source in a
    /// union, its attested_at is the MIN of what the operands carried
    /// (ages only grow or stay through derivation, never shrink).
    #[test]
    fn union_never_rejuvenates_any_source() {
        let a = BackingSet::from_entries([e("x", 100, "c"), e("y", 900, "c")]);
        let b = BackingSet::from_entries([e("x", 700, "c"), e("y", 200, "c")]);
        let u = a.union(&b);
        for en in u.iter() {
            let in_a = a.iter().find(|p| p.source_id == en.source_id);
            let in_b = b.iter().find(|p| p.source_id == en.source_id);
            let min = in_a
                .iter()
                .chain(in_b.iter())
                .map(|p| p.attested_at_secs)
                .min()
                .unwrap();
            assert_eq!(en.attested_at_secs, min);
        }
    }

    // ---------- max age / boundary aggregate ----------

    #[test]
    fn max_age_is_age_of_oldest_entry() {
        let s = BackingSet::from_entries([e("x", 1_000, "c"), e("y", 400, "c")]);
        // now=1_500: ages are 500 and 1_100 → max 1_100 (oldest source).
        assert_eq!(s.max_age_secs(1_500), Some(1_100));
        assert_eq!(BackingSet::new().max_age_secs(1_500), None);
    }

    #[test]
    fn boundary_aggregate_is_scalar_max_age_only() {
        let s = BackingSet::from_entries([e("x", 1_000, "secret-class"), e("y", 400, "c")]);
        let b = s.to_boundary(1_500).unwrap();
        assert_eq!(b, BoundaryAge { max_age_secs: 1_100 });
        // Privacy §2.5 by type: BoundaryAge serializes to exactly one field —
        // no source ids, no classes, no per-entry timestamps can leak.
        let json = serde_json::to_value(&b).unwrap();
        let obj = json.as_object().unwrap();
        assert_eq!(obj.len(), 1);
        assert!(obj.contains_key("max_age_secs"));
        assert_eq!(BackingSet::new().to_boundary(1_500), None);
    }

    // ---------- gate ----------

    fn policy(pairs: &[(&str, u64)], default: Option<u64>) -> AgePolicy {
        AgePolicy {
            max_age_secs_by_class: pairs
                .iter()
                .map(|(k, v)| (k.to_string(), *v))
                .collect(),
            default_max_age_secs: default,
        }
    }

    #[test]
    fn gate_fresh_when_all_entries_within_class_windows() {
        let s = BackingSet::from_entries([e("x", 1_400, "fast"), e("y", 1_000, "slow")]);
        let p = policy(&[("fast", 200), ("slow", 600)], None);
        // now=1_500: x age 100 ≤ 200; y age 500 ≤ 600.
        assert_eq!(s.gate(&p, 1_500), BackingVerdict::Fresh);
    }

    #[test]
    fn gate_reports_only_the_stale_entries_targeted() {
        let s = BackingSet::from_entries([e("x", 1_400, "fast"), e("y", 500, "slow")]);
        let p = policy(&[("fast", 200), ("slow", 600)], None);
        // now=1_500: x fresh (100 ≤ 200); y stale (1_000 > 600).
        match s.gate(&p, 1_500) {
            BackingVerdict::Stale(list) => {
                assert_eq!(list.len(), 1);
                assert_eq!(list[0].entry.source_id, "y");
                assert_eq!(list[0].age_secs, 1_000);
                assert_eq!(list[0].limit_secs, Some(600));
            }
            v => panic!("expected Stale, got {v:?}"),
        }
    }

    #[test]
    fn gate_unknown_class_fails_closed_without_default() {
        let s = BackingSet::from_entries([e("x", 1_499, "mystery")]);
        let p = policy(&[("fast", 200)], None);
        match s.gate(&p, 1_500) {
            BackingVerdict::Stale(list) => {
                assert_eq!(list.len(), 1);
                assert_eq!(list[0].limit_secs, None); // fail-closed marker
            }
            v => panic!("expected Stale (fail-closed), got {v:?}"),
        }
    }

    #[test]
    fn gate_unknown_class_uses_default_when_present() {
        let s = BackingSet::from_entries([e("x", 1_400, "mystery")]);
        let p = policy(&[], Some(500));
        assert_eq!(s.gate(&p, 1_500), BackingVerdict::Fresh); // age 100 ≤ 500
    }

    #[test]
    fn gate_empty_set_is_fresh() {
        assert_eq!(
            BackingSet::new().gate(&policy(&[], None), 1_500),
            BackingVerdict::Fresh
        );
    }

    // ---------- THE POINT: laundering is caught ----------

    /// The laundering scenario the whole module exists for (spec §0):
    /// a summary derived "just now" from an old source LOOKS fresh by its
    /// own timestamp, but its backing carries the source age — and the
    /// gate catches it. Derivation at any later time never resets the age.
    #[test]
    fn staleness_laundering_is_caught_through_derivation_chain() {
        let april = 1_744_800_000_u64; // source last validated (unix secs)
        let july = april + 90 * 86_400; // ~90 days later

        // Stage 0: memory read carries its source backing.
        let memory = BackingSet::from_entries([e("obs:44", april, "repo-structure")]);
        // Stage 1: LLM summarizes "now" (July) — output inherits via union
        // with its (empty) other inputs. NO new entry, NO reset.
        let summary_backing = memory.union(&BackingSet::new());
        // Stage 2: another derivation, still no revalidation.
        let plan_backing = summary_backing.union(&BackingSet::new());

        // The plan was produced "seconds ago" in July, but its backing age
        // is ~90 days — and a 7-day repo-structure window catches it.
        let p = policy(&[("repo-structure", 7 * 86_400)], None);
        match plan_backing.gate(&p, july) {
            BackingVerdict::Stale(list) => {
                assert_eq!(list.len(), 1);
                assert_eq!(list[0].entry.source_id, "obs:44");
                assert_eq!(list[0].age_secs, 90 * 86_400);
            }
            v => panic!("laundering went uncaught: {v:?}"),
        }

        // Re-validation (a NEW attestation event) is the only thing that
        // refreshes: a set with the source re-attested in July gates Fresh.
        let revalidated = BackingSet::from_entries([e("obs:44", july - 60, "repo-structure")]);
        assert_eq!(revalidated.gate(&p, july), BackingVerdict::Fresh);
    }

    // ---------- wire ----------

    #[test]
    fn serde_roundtrip_preserves_backing_set() {
        let s = BackingSet::from_entries([e("x", 100, "c1"), e("y", 200, "c2")]);
        let json = serde_json::to_string(&s).unwrap();
        let back: BackingSet = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }
}
