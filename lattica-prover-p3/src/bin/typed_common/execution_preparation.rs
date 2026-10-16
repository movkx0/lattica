//! Immutable preparation owners consumed before the pool dispatches work.

use super::*;
use lattica_prover_p3::block_v2::execution::{
    dag::CandidateId, policy_context::PolicyContext, pool::PoolCoordinator,
    selection::PreparationStorage,
};

#[cfg(all(test, not(any(feature = "gpu", feature = "gpu-metal"))))]
#[path = "execution_preparation_diagnostic.rs"]
mod diagnostic;

pub(super) fn list<T>(count: usize) -> Result<Vec<T>, Error> {
    if !(1..=commitment::CAPACITY).contains(&count) {
        return Err("preparation list count".into());
    }
    let mut values = Vec::new();
    values.try_reserve_exact(count)?;
    if values.capacity() != count {
        return Err("preparation list capacity rounding".into());
    }
    Ok(values)
}

pub(super) fn check_lists(
    inputs: &Vec<PublicInput>,
    policies: &Vec<(ArtifactRef, Policy)>,
) -> Result<(), Error> {
    PreparationStorage::input_list_storage_bytes(inputs)?;
    PreparationStorage::policy_list_storage_bytes(policies)?;
    if inputs.len() != policies.len() {
        return Err("preparation policy/input count".into());
    }
    Ok(())
}

pub(super) struct Submitted {
    pub candidate: CandidateId,
    pub expected: Expected,
    pub jobs: usize,
}

/// The already-verified selection survives only until its matching request is
/// admitted. It owns the one selection/policy allocation already reserved by
/// KnownShared; no registry or proof buffer is cloned at this handoff.
pub(super) struct PoolPreparation {
    pub(super) expected: Expected,
    selection: Selection,
    policies: Vec<(ArtifactRef, Policy)>,
}

impl Prepared {
    pub(super) fn into_pool_parts(self) -> (typed_recursive::Registry<12>, PoolPreparation) {
        (
            self.registry,
            PoolPreparation {
                expected: self.expected,
                selection: self.selection,
                policies: self.policies,
            },
        )
    }
}

impl PoolPreparation {
    pub(super) fn root(&self) -> lattica_prover_p3::block_v2::execution::job::JobId {
        self.selection.root().id()
    }

    pub(super) fn seal_prefix_to_pool(
        self,
        pool: &mut PoolCoordinator,
        candidate: CandidateId,
        head: [u8; 32],
        now_ms: u64,
    ) -> Result<Submitted, Error> {
        PreparationStorage::policy_list_storage_bytes(&self.policies)?;
        let jobs = self.selection.jobs().len();
        let context = PolicyContext::new(head, self.policies)?;
        pool.seal_prefix_extension(candidate, &self.selection, context, head, now_ms)?;
        Ok(Submitted {
            candidate,
            expected: self.expected,
            jobs,
        })
    }

    pub(super) fn adopt_to_pool(
        self,
        pool: &mut PoolCoordinator,
        candidate: CandidateId,
        head: [u8; 32],
        now_ms: u64,
        prefix_only: bool,
    ) -> Result<Submitted, Error> {
        PreparationStorage::policy_list_storage_bytes(&self.policies)?;
        let jobs = self
            .selection
            .jobs()
            .filter(|job| !prefix_only || job.is_complete_non_root_subtree())
            .count();
        let context = PolicyContext::new(head, self.policies)?;
        if prefix_only {
            pool.adopt_prefix(&self.selection, context, candidate, head, now_ms)?;
        } else {
            pool.adopt_sealed(&self.selection, context, candidate, head, now_ms)?;
        }
        Ok(Submitted {
            candidate,
            expected: self.expected,
            jobs,
        })
    }

    /// The durable owner copies the inputs during submit. This consuming
    /// boundary releases the caller's proof Arcs and policies before
    /// the service can seal/dispatch the returned candidate.
    pub(super) fn submit_to_pool(
        self,
        pool: &mut PoolCoordinator,
        head: [u8; 32],
        deadline_ms: u64,
        now_ms: u64,
        prefix_only: bool,
    ) -> Result<Submitted, Error> {
        PreparationStorage::policy_list_storage_bytes(&self.policies)?;
        let jobs = self
            .selection
            .jobs()
            .filter(|job| !prefix_only || job.is_complete_non_root_subtree())
            .count();
        let context = PolicyContext::new(head, self.policies)?;
        let candidate = if prefix_only {
            pool.submit_prefix(&self.selection, context, head, deadline_ms, now_ms)?
        } else {
            pool.submit(&self.selection, context, head, deadline_ms, now_ms)?
        };
        Ok(Submitted {
            candidate,
            expected: self.expected,
            jobs,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn preparation_factories_bound_all_counts_before_allocation_and_check_list_agreement() {
        for count in 1..=commitment::CAPACITY {
            let inputs = list::<PublicInput>(count).unwrap();
            let mut policies = list::<(ArtifactRef, Policy)>(count).unwrap();
            assert_eq!(inputs.capacity(), count);
            assert_eq!(policies.capacity(), count);
            check_lists(&inputs, &policies).unwrap();
            let artifact = ArtifactRef::from_bytes(
                lattica_prover_p3::block_v2::execution::job::ArtifactKind::Wallet,
                &[1],
            )
            .unwrap();
            policies.push((artifact, Policy::JoinSplit));
            assert!(check_lists(&inputs, &policies).is_err());
        }
        for count in [0, commitment::CAPACITY + 1, usize::MAX] {
            assert!(list::<PublicInput>(count).is_err());
        }
        eprintln!("bounded_preparation_factory counts={} rejects_before_allocation=true exact_capacity=true", commitment::CAPACITY);
    }
}
