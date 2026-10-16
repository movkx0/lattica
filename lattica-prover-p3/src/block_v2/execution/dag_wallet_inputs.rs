//! Two safe admission boundaries share the same graph transition logic.
use super::*;

pub(super) enum WalletInputs<'a> {
    Detached(Vec<Vec<u8>>),
    Verified(&'a [VerifiedWalletPayload]),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block_v2::execution::job::test_support::{typed_pin, typed_wallet};

    fn dag(jobs: usize, artifact_bytes: usize, chain: [u8; 32]) -> Dag {
        Dag::new(typed_pin(), chain, 1, Limits {
            jobs, candidates: 4, attempts: 4, artifact_bytes,
            recovery_window_ms: 10,
            workers: Resources { ram_bytes: 16, vram_bytes: 0, scratch_bytes: 0, threads: 1 },
        }).unwrap()
    }

    #[test]
    fn shared_wallet_admission_preserves_first_artifacts_and_bounds_without_candidate() {
        let ticket = typed_wallet(1, 1, &[1, 2]);
        let job = Job::typed_pair(0, ticket, None).unwrap();
        let payload = VerifiedWalletPayload::new(ticket, vec![1, 2]).unwrap();
        let inputs = [payload.clone(), payload.clone()];
        let mut d = dag(4, MAX_PROOF_BYTES, [9; 32]);
        assert!(d.admit_verified_wallets(job.clone(), &inputs[..1], 0).is_err());
        assert_eq!(d.job_count(), 0);
        d.admit_verified_wallets(job.clone(), &inputs, 0).unwrap();
        assert_eq!(d.stored_bytes(), 4); // conservative charge for both handles
        assert!(d.ready().is_empty());
        assert!(d.candidates.is_empty());
        assert_eq!(d.resource_use(), Resources::default());
        assert_eq!(d.retained_storage().unwrap().artifact_bytes, 4);
        for bytes in &d.jobs[&job.id()].wallets {
            assert!(Arc::ptr_eq(bytes, payload.shared_bytes()));
        }
        let alternate = VerifiedWalletPayload::new(typed_wallet(1, 1, &[3, 4]), vec![3, 4]).unwrap();
        let same = Job::typed_pair(0, alternate.ticket(), None).unwrap();
        assert!(same.same_semantics(&job));
        assert_ne!(same.wallet_inputs(), job.wallet_inputs());
        assert!(d.admit_verified_wallets(job.clone(), &[alternate.clone(), alternate.clone()], 0).is_err());
        d.admit_verified_wallets(same, &[alternate.clone(), alternate], 0).unwrap();
        assert_eq!(d.job_count(), 1);
        assert_eq!(d.stored_bytes(), 4);
        for bytes in &d.jobs[&job.id()].wallets {
            assert!(Arc::ptr_eq(bytes, payload.shared_bytes()));
        }
        let weak = Arc::downgrade(payload.shared_bytes());
        drop(payload);
        drop(inputs);
        assert!(weak.upgrade().is_some());
        drop(d);
        assert!(weak.upgrade().is_none());
    }

    #[test]
    fn shared_and_detached_admission_keep_context_dependencies_and_quotas() {
        let ticket = typed_wallet(1, 1, &[1, 2]);
        let job = Job::typed_pair(0, ticket, None).unwrap();
        let payload = VerifiedWalletPayload::new(ticket, vec![1, 2]).unwrap();
        let inputs = [payload.clone(), payload];
        for mut d in [dag(4, MAX_PROOF_BYTES, [8; 32])] {
            assert!(d.admit_verified_wallets(job.clone(), &inputs, 0).is_err());
            assert!(d.admit(job.clone(), vec![vec![1, 2], vec![1, 2]], 0).is_err());
            assert_eq!(d.job_count(), 0);
            assert_eq!(d.stored_bytes(), 0);
        }
        let bytes = vec![1; MAX_PROOF_BYTES / 2 + 1];
        let large = VerifiedWalletPayload::new(typed_wallet(1, 1, &bytes), bytes).unwrap();
        let large_job = Job::typed_pair(0, large.ticket(), None).unwrap();
        let mut short = dag(4, MAX_PROOF_BYTES, [9; 32]);
        assert!(short.admit_verified_wallets(large_job, &[large.clone(), large], 0).is_err());
        assert_eq!(short.job_count(), 0);
        assert_eq!(short.stored_bytes(), 0);
        let mut d = dag(1, MAX_PROOF_BYTES, [9; 32]);
        let root = Job::finalize(&job).unwrap();
        assert!(d.admit_verified_wallets(root.clone(), &[], 0).is_err());
        assert!(d.admit_verified_wallets(job.clone(), &[], 0).is_err());
        assert!(d.admit(job.clone(), vec![vec![1, 2], vec![1, 0]], 0).is_err());
        d.admit_verified_wallets(job.clone(), &inputs, 0).unwrap();
        d.admit(job, vec![vec![1, 2], vec![1, 2]], 0).unwrap();
        assert!(d.admit_verified_wallets(root, &[], 0).is_err());
        assert_eq!(d.job_count(), 1);
        assert_eq!(d.stored_bytes(), 4);
        assert!(d.ready().is_empty());
    }
}

impl WalletInputs<'_> {
    pub(super) fn check(&self, job: &Job) -> Result<(), Error> {
        match self {
            Self::Detached(wallets) => {
                if wallets.len() != job.wallet_inputs().len() {
                    return Err("execution wallet input count".into());
                }
                for (identity, bytes) in job.wallet_inputs().iter().zip(wallets) {
                    identity.check_bytes(bytes)?;
                }
                Ok(())
            }
            Self::Verified(wallets) => VerifiedWalletPayload::check_job_inputs(job, wallets),
        }
    }

    pub(super) fn byte_len(&self) -> Result<usize, Error> {
        let sum = match self {
            Self::Detached(wallets) => wallets.iter().try_fold(0usize, |n, b| n.checked_add(b.len())),
            Self::Verified(wallets) => wallets.iter().try_fold(0usize, |n, b| n.checked_add(b.bytes().len())),
        };
        sum.ok_or_else(|| "execution store arithmetic".into())
    }

    pub(super) fn into_shared(self) -> Vec<Arc<[u8]>> {
        // Do not retain the caller's arbitrary outer Vec capacity. Verified
        // payloads already own bounded Arc slices; detached buffers are copied
        // into exact Arc allocations only after digest and graph admission.
        match self {
            Self::Detached(wallets) => {
                let mut retained = Vec::with_capacity(wallets.len());
                retained.extend(wallets.into_iter().map(Arc::from));
                retained
            }
            Self::Verified(wallets) => {
                let mut retained = Vec::with_capacity(wallets.len());
                retained.extend(wallets.iter().map(|input| Arc::clone(input.shared_bytes())));
                retained
            }
        }
    }
}
