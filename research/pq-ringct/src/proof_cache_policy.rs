//! Proof-payload reuse policy, independent of immutable program registration.
//!
//! FreshOnly never opens a cached proof, including proofs generated earlier in
//! the same trial. Explicit archival imports are also disallowed. Counters are
//! cumulative per pipeline and do not confer proof or registration authority.
use serde::Serialize;
use std::{
    collections::BTreeMap,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofCachePolicy {
    #[default]
    ReuseVerified,
    FreshOnly,
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum Family {
    Sources,
    Algebra,
    Crypto,
    Auxiliary,
    Outer,
}
impl Family {
    const ALL: [Self; 5] = [
        Self::Sources,
        Self::Algebra,
        Self::Crypto,
        Self::Auxiliary,
        Self::Outer,
    ];
    fn name(self) -> &'static str {
        match self {
            Self::Sources => "sources",
            Self::Algebra => "algebra",
            Self::Crypto => "crypto",
            Self::Auxiliary => "auxiliary",
            Self::Outer => "outer",
        }
    }
}

#[derive(Default)]
struct Counters {
    reads: AtomicU64,
    hits: AtomicU64,
    bypasses: AtomicU64,
    proof_attempts: AtomicU64,
    fresh_proofs: AtomicU64,
}
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct FamilyStatistics {
    /// Attempts to open cached proof payloads, including misses and errors.
    pub reads: u64,
    /// Cache artifacts accepted by the corresponding trusted verifier.
    pub hits: u64,
    pub bypasses: u64,
    pub proof_attempts: u64,
    pub fresh_proofs: u64,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CacheStatistics {
    pub policy: ProofCachePolicy,
    pub families: BTreeMap<&'static str, FamilyStatistics>,
}

/// Canonical diagnostic fingerprint of an actual registered preprocessing cap.
pub fn cap_identity(cap: &[[lattica_prover_p3::block_v2::machine::program::Val; 4]]) -> [u8; 32] {
    use p3_field::PrimeField64;
    use sha3::{Digest, Sha3_256};
    let mut hash = Sha3_256::new();
    hash.update(b"lattica-pq-preprocessing-cap-diagnostic-v1");
    hash.update((cap.len() as u64).to_le_bytes());
    for value in cap.iter().flatten() {
        hash.update(value.as_canonical_u64().to_le_bytes());
    }
    hash.finalize().into()
}

#[derive(Clone)]
pub(crate) struct Control {
    policy: ProofCachePolicy,
    counters: Arc<[Counters; 5]>,
}
impl Control {
    pub(crate) fn policy(&self) -> ProofCachePolicy {
        self.policy
    }
    pub(crate) fn new(policy: ProofCachePolicy) -> Self {
        Self {
            policy,
            counters: Arc::new(std::array::from_fn(|_| Counters::default())),
        }
    }
    pub(crate) fn allows_import(&self) -> bool {
        self.policy == ProofCachePolicy::ReuseVerified
    }
    pub(crate) fn read(&self, family: Family) -> bool {
        let counts = &self.counters[family as usize];
        if self.policy == ProofCachePolicy::FreshOnly {
            counts.bypasses.fetch_add(1, Ordering::Relaxed);
            false
        } else {
            counts.reads.fetch_add(1, Ordering::Relaxed);
            true
        }
    }
    pub(crate) fn hit(&self, family: Family) {
        self.counters[family as usize]
            .hits
            .fetch_add(1, Ordering::Relaxed);
    }
    pub(crate) fn attempt(&self, family: Family) {
        self.counters[family as usize]
            .proof_attempts
            .fetch_add(1, Ordering::Relaxed);
    }
    pub(crate) fn fresh(&self, family: Family) {
        self.counters[family as usize]
            .fresh_proofs
            .fetch_add(1, Ordering::Relaxed);
    }
    pub(crate) fn snapshot(&self) -> CacheStatistics {
        CacheStatistics {
            policy: self.policy,
            families: Family::ALL
                .into_iter()
                .map(|family| {
                    let value = &self.counters[family as usize];
                    (
                        family.name(),
                        FamilyStatistics {
                            reads: value.reads.load(Ordering::Relaxed),
                            hits: value.hits.load(Ordering::Relaxed),
                            bypasses: value.bypasses.load(Ordering::Relaxed),
                            proof_attempts: value.proof_attempts.load(Ordering::Relaxed),
                            fresh_proofs: value.fresh_proofs.load(Ordering::Relaxed),
                        },
                    )
                })
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fresh_policy_never_admits_reads_even_with_shared_counters() {
        let control = Control::new(ProofCachePolicy::FreshOnly);
        for family in Family::ALL {
            assert!(!control.read(family));
            assert!(!control.clone().read(family));
            control.attempt(family);
            control.fresh(family);
        }
        assert!(!control.allows_import());
        for value in control.snapshot().families.values() {
            assert_eq!(
                (
                    value.reads,
                    value.hits,
                    value.bypasses,
                    value.proof_attempts,
                    value.fresh_proofs
                ),
                (0, 0, 2, 1, 1)
            );
        }
    }
    #[test]
    fn legacy_policy_counts_failed_reads_separately_from_verified_hits() {
        let control = Control::new(ProofCachePolicy::default());
        assert!(control.read(Family::Outer));
        assert!(control.read(Family::Outer));
        control.hit(Family::Outer);
        assert!(control.allows_import());
        assert_eq!(
            control.snapshot().families["outer"],
            FamilyStatistics {
                reads: 2,
                hits: 1,
                ..Default::default()
            }
        );
    }
}
