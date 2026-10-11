//! Known shared owners reserved before coordinator per-job allowances.
//! Includes sequential registry approval, wallet decoding and verification.
//! Runtime/allocator costs remain separate. Ordinary admission still requires
//! a complete lifetime profile.

use super::*;
use lattica_prover_p3::block_v2::execution::{
    pool::{local::LocalPoolStorage, PoolStorage},
    selection::PreparationStorage,
    worker_budget::COORDINATOR_SHARED_BYTES,
};

pub(super) struct KnownShared {
    pool_bytes: u64,
    selection_bytes: u64,
    endpoint_bytes: u64,
    preparation_bytes: u64,
    registry_wallet_bytes: u64,
    ingress_bytes: u64,
    report_bytes: u64,
}

impl KnownShared {
    pub fn new(workers: usize) -> Result<Self, Error> {
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
        let limits = budget::limits(capacity, capacity)?;
        let durable = JournalLimits {
            snapshot_bytes: budget::SNAPSHOT_BYTES,
        }
        .durable_storage(
            limits,
            StoreLimits {
                bytes: budget::ARTIFACT_BYTES,
                entries: budget::ARTIFACT_ENTRIES,
            },
        )?;
        Ok(Self {
            pool_bytes: u64::try_from(PoolStorage::new(durable)?.total_bytes()?)?,
            selection_bytes: u64::try_from(Selection::storage_plan()?.total_bytes()?)?,
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
        })
    }

    pub fn total_bytes(&self) -> Result<u64, Error> {
        [
            self.pool_bytes,
            self.selection_bytes,
            self.endpoint_bytes,
            self.preparation_bytes,
            self.registry_wallet_bytes,
            self.ingress_bytes,
            self.report_bytes,
        ]
        .into_iter()
        .try_fold(0u64, |sum, bytes| {
            sum.checked_add(bytes)
                .ok_or_else(|| "shared coordinator storage overflow".into())
        })
    }

    pub fn admit(&self, shared_bytes: u64) -> Result<(), Error> {
        if shared_bytes < COORDINATOR_SHARED_BYTES || self.total_bytes()? > shared_bytes {
            return Err("coordinator shared reservation below known storage".into());
        }
        Ok(())
    }

    fn print(&self, prefix: &str, workers: usize) -> Result<(), Error> {
        println!("{prefix} workers={workers} pool_bytes={} selection_bytes={} endpoint_bytes={} preparation_bytes={} registry_wallet_bytes={} ingress_bytes={} report_bytes={} known_bytes={} minimum_shared_bytes={COORDINATOR_SHARED_BYTES}",
            self.pool_bytes, self.selection_bytes, self.endpoint_bytes, self.preparation_bytes, self.registry_wallet_bytes, self.ingress_bytes,
            self.report_bytes, self.total_bytes()?);
        Ok(())
    }
}

pub(super) fn probe() -> Result<(), Error> {
    input::Storage::new()?.print("production_preparation_ingress")?;
    for workers in [1, 16] {
        let known = KnownShared::new(workers)?;
        known.admit(COORDINATOR_SHARED_BYTES)?;
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
            let mut known = KnownShared::new(workers).unwrap();
            known.admit(COORDINATOR_SHARED_BYTES).unwrap();
            assert!(known.admit(COORDINATOR_SHARED_BYTES - 1).is_err());
            if workers == 1 || workers == 16 {
                known.print("bounded_coordinator_shared", workers).unwrap();
            }
            // Compiled component growth must fail even when the constant floor
            // is satisfied; a changed layout cannot silently consume job RAM.
            known.registry_wallet_bytes += COORDINATOR_SHARED_BYTES;
            assert!(known.admit(COORDINATOR_SHARED_BYTES).is_err());
            known.registry_wallet_bytes -= COORDINATOR_SHARED_BYTES;
            known.preparation_bytes += COORDINATOR_SHARED_BYTES;
            assert!(known.admit(COORDINATOR_SHARED_BYTES).is_err());
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
}
