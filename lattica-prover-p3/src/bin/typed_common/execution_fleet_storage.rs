//! Known shared owners reserved before coordinator per-job allowances.
//! Includes sequential registry approval, wallet decoding and verification.
//! Runtime/allocator costs remain separate. Ordinary admission still requires
//! a complete lifetime profile.

use super::*;
use lattica_prover_p3::block_v2::execution::{
    pool::{local::LocalPoolStorage, PoolStorage},
    selection::PreparationStorage,
};

// Repartition the unchanged physical coordinator allowance. The 128 profile
// reserves 687 MiB for one worker, leaving the existing 337 MiB per-job floor
// within 1 GiB. Reserve one additional MiB per additional worker for metadata.
// These are compiled ownership bounds, not a complete process lifetime claim.
pub(super) const COORDINATOR_SHARED_BYTES: u64 = if cfg!(feature = "block-v2-capacity-128") {
    687 << 20
} else {
    576 << 20
};
pub(super) const fn shared_reservation(workers: usize) -> u64 {
    if cfg!(feature = "block-v2-capacity-128") {
        (687 + workers.saturating_sub(1) as u64) << 20
    } else {
        COORDINATOR_SHARED_BYTES
    }
}

pub(super) struct KnownShared {
    workers: usize,
    pool_bytes: u64,
    selection_bytes: u64,
    shared_wallet_bytes: u64,
    endpoint_bytes: u64,
    preparation_bytes: u64,
    registry_wallet_bytes: u64,
    ingress_bytes: u64,
    report_bytes: u64,
    pool_timing_bytes: u64,
    pool_calibration_bytes: u64,
    pool_transition_bytes: u64,
}

impl KnownShared {
    pub fn new(workers: usize) -> Result<Self, Error> {
        Self::with_pool_mode(workers, false)
    }

    /// One preparation attached to a newly created DAG. Selection admission
    /// clones the verified wallet Arcs into that DAG; it never copies their
    /// payloads. Charge those bytes once, through the DAG artifact allowance,
    /// which is already reserved while preparation builds the selection.
    /// Keep both owners' metadata and every temporary buffer in the sum.
    /// Recovery and pools that can prepare another candidate cannot use this
    /// overlap: their existing DAG may own different wallet allocations.
    pub fn fresh_selection(workers: usize) -> Result<Self, Error> {
        let mut known = Self::new(workers)?;
        known.shared_wallet_bytes = (commitment::CAPACITY as u64)
            .checked_mul(profile::MAX_PROOF_BYTES as u64)
            .ok_or("shared wallet payload storage overflow")?;
        if known.shared_wallet_bytes > known.selection_bytes
            || known.shared_wallet_bytes > budget::ARTIFACT_BYTES
        {
            return Err("fresh selection exceeds shared wallet payload allowance".into());
        }
        Ok(known)
    }

    pub fn persistent(workers: usize) -> Result<Self, Error> {
        Self::with_pool_mode(workers, true)
    }

    fn with_pool_mode(workers: usize, persistent: bool) -> Result<Self, Error> {
        if !(1..=16).contains(&workers) {
            return Err("shared coordinator worker count".into());
        }
        // Capacity values only select the existing CLI metadata limits here;
        // they do not admit a worker or replace its physical assignment.
        let capacity = Resources {
            ram_bytes: 1,
            vram_bytes: 1,
            scratch_bytes: 1,
            threads: 1,
        };
        let mut limits = budget::limits(capacity, capacity)?;
        pool_service::configure_limits(&mut limits, !persistent);
        let durable = pool_service::journal_limits(!persistent)
            .durable_storage(limits, pool_service::store_limits(!persistent))?;
        Ok(Self {
            workers,
            pool_bytes: u64::try_from(PoolStorage::new(durable)?.total_bytes()?)?,
            selection_bytes: u64::try_from(Selection::storage_plan()?.total_bytes()?)?,
            shared_wallet_bytes: 0,
            // Reserve the persistent pool's larger launch inventory for either
            // shared execution mode; it is one owner across all local endpoints.
            endpoint_bytes: u64::try_from(
                LocalPoolStorage::new(LaunchLimits { records: 16384 }, workers)?.total_bytes()?,
            )?,
            preparation_bytes: u64::try_from(PreparationStorage::new()?.total_bytes()?)?,
            registry_wallet_bytes: u64::try_from(
                TypedRegistryContext::preparation_storage_bytes()?
            )?,
            ingress_bytes: u64::try_from(input::Storage::new()?.total_bytes()?)?,
            report_bytes: u64::try_from(pool_service::report_storage_bytes(workers)?)?,
            pool_timing_bytes: pool_timing::storage_bytes(workers)?,
            pool_calibration_bytes: pool_calibration::storage_bytes(),
            pool_transition_bytes: pool_transition::storage_bytes(),
        })
    }

    pub fn total_bytes(&self) -> Result<u64, Error> {
        let owners = [
            self.pool_bytes,
            self.selection_bytes,
            self.endpoint_bytes,
            self.preparation_bytes,
            self.registry_wallet_bytes,
            self.ingress_bytes,
            self.report_bytes,
            self.pool_timing_bytes,
            self.pool_calibration_bytes,
            self.pool_transition_bytes,
        ]
        .into_iter()
        .try_fold(0u64, |sum, bytes| -> Result<u64, Error> {
            sum.checked_add(bytes)
                .ok_or_else(|| "shared coordinator storage overflow".into())
        })?;
        owners
            .checked_sub(self.shared_wallet_bytes)
            .ok_or_else(|| "shared coordinator wallet overlap exceeds owners".into())
    }

    pub fn admit(&self, shared_bytes: u64) -> Result<(), Error> {
        if shared_bytes < shared_reservation(self.workers) || self.total_bytes()? > shared_bytes {
            return Err("coordinator shared reservation below known storage".into());
        }
        Ok(())
    }

    fn print(&self, prefix: &str, workers: usize) -> Result<(), Error> {
        println!(
            "{prefix} workers={workers} pool_bytes={} selection_bytes={} endpoint_bytes={} preparation_bytes={} registry_wallet_bytes={} ingress_bytes={} report_bytes={} pool_timing_bytes={} pool_calibration_bytes={} pool_transition_bytes={} shared_wallet_bytes={} known_bytes={} minimum_shared_bytes={}",
            self.pool_bytes,
            self.selection_bytes,
            self.endpoint_bytes,
            self.preparation_bytes,
            self.registry_wallet_bytes,
            self.ingress_bytes,
            self.report_bytes,
            self.pool_timing_bytes,
            self.pool_calibration_bytes,
            self.pool_transition_bytes,
            self.shared_wallet_bytes,
            self.total_bytes()?,
            shared_reservation(self.workers)
        );
        Ok(())
    }
}

pub(super) fn probe() -> Result<(), Error> {
    input::Storage::new()?.print("production_preparation_ingress")?;
    for workers in [1, 16] {
        let known = KnownShared::fresh_selection(workers)?;
        known.admit(shared_reservation(workers))?;
        known.print("production_coordinator_shared", workers)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(all(not(debug_assertions), target_arch = "x86_64"))]
    fn compiled_shared_owners_fit_the_reserved_floor_for_every_worker_count() {
        for workers in 1..=16 {
            let mut known = KnownShared::fresh_selection(workers).unwrap();
            known
                .print("candidate_coordinator_shared", workers)
                .unwrap();
            known.admit(shared_reservation(workers)).unwrap();
            assert!(known.admit(shared_reservation(workers) - 1).is_err());
            if workers == 1 || workers == 16 {
                known.print("bounded_coordinator_shared", workers).unwrap();
            }
            // Compiled component growth must fail even when the constant floor
            // is satisfied; a changed layout cannot silently consume job RAM.
            known.registry_wallet_bytes += COORDINATOR_SHARED_BYTES;
            assert!(known.admit(shared_reservation(workers)).is_err());
            known.registry_wallet_bytes -= COORDINATOR_SHARED_BYTES;
            known.preparation_bytes += COORDINATOR_SHARED_BYTES;
            assert!(known.admit(shared_reservation(workers)).is_err());
            known.pool_bytes = u64::MAX;
            assert!(known.total_bytes().is_err());
        }
        assert!(KnownShared::new(0).is_err());
        assert!(KnownShared::new(17).is_err());
    }

    #[test]
    #[cfg(not(all(not(debug_assertions), target_arch = "x86_64")))]
    fn unqualified_wallet_intake_model_cannot_admit_shared_storage() {
        assert!(KnownShared::new(1).is_err());
    }

    #[test]
    #[cfg(all(not(debug_assertions), target_arch = "x86_64"))]
    fn long_lived_pool_cannot_use_the_bounded_phase_storage_reservation() {
        let bounded = KnownShared::fresh_selection(1).unwrap();
        let persistent = KnownShared::persistent(1).unwrap();
        assert!(persistent.total_bytes().unwrap() > 1 << 30);
        assert!(persistent.admit(COORDINATOR_SHARED_BYTES).is_err());
        assert!(persistent.total_bytes().unwrap() > bounded.total_bytes().unwrap());
        bounded.admit(COORDINATOR_SHARED_BYTES).unwrap();
    }

    #[test]
    #[cfg(all(not(debug_assertions), target_arch = "x86_64"))]
    fn wallet_overlap_is_exact_and_requires_a_fresh_single_selection() {
        for workers in 1..=16 {
            let fresh = KnownShared::fresh_selection(workers).unwrap();
            let retained = KnownShared::new(workers).unwrap();
            let persistent = KnownShared::persistent(workers).unwrap();
            assert_eq!(retained.shared_wallet_bytes, 0);
            assert_eq!(persistent.shared_wallet_bytes, 0);
            assert_eq!(
                retained.total_bytes().unwrap() - fresh.total_bytes().unwrap(),
                (commitment::CAPACITY * profile::MAX_PROOF_BYTES) as u64
            );
            assert_eq!(fresh.selection_bytes, retained.selection_bytes);
            assert_eq!(fresh.pool_bytes, retained.pool_bytes);
            fresh.admit(shared_reservation(workers)).unwrap();
            assert!(persistent.admit(shared_reservation(workers)).is_err());
            if cfg!(feature = "block-v2-capacity-128") {
                assert!(retained.admit(shared_reservation(workers)).is_err());
            }
        }
    }
}
