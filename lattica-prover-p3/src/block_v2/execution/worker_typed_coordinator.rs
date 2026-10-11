//! Per-active-job coordinator storage, retained through independent CPU audit.
//!
//! Global DAG/store/cache metadata, persistent supervisors, caller construction,
//! stacks, allocator and OS costs need separate enclosing reservations. This
//! component is not a complete coordinator RSS or ordinary-pool admission plan.

use super::cached::{CompletedJob, Task};
use super::*;
#[cfg(test)]
use crate::block_v2::machine::backend::NATIVE_VERIFIER_COMPONENT_BYTES;
use crate::block_v2::{
    execution::{job::VerifiedNode, launch::MAX_TOKEN_BYTES, worker_budget},
    profile::MAX_PROOF_BYTES,
};
use core::mem::size_of;

const METADATA_BYTES: usize = 1 << 20;
const CONTROL_BYTES: usize = 64 << 10;
const ARC_HEADER_BYTES: usize = 2 * size_of::<usize>();
const INPUT_BYTES: usize = 2 * (MAX_PROOF_BYTES + ARC_HEADER_BYTES);
// The result frame can coexist with the publication Vec and its Arc conversion.
const PUBLICATION_BYTES: usize = 2 * (MAX_PROOF_BYTES + ARC_HEADER_BYTES);
// A caller creates a launch-binding request before dispatch creates its owned
// request. That duplicate can overlap collection, but is gone before publication
// in the fleet path; the serial path retains the caller's request instead. Take
// the larger of the second request and publication copies, not both lifetimes.
const TRANSIENT_BYTES: usize = if launch::MAX_REQUEST_BYTES > PUBLICATION_BYTES {
    launch::MAX_REQUEST_BYTES
} else {
    PUBLICATION_BYTES
};
pub(crate) const PACKET_HOST_BYTES: u64 = worker_budget::COORDINATOR_PACKET_BYTES;
#[cfg(test)]
pub(crate) const HOST_BYTES: u64 = worker_budget::COORDINATOR_JOB_BYTES;

fn add(a: usize, b: usize) -> Result<usize, Error> {
    a.checked_add(b)
        .ok_or_else(|| "typed coordinator storage overflow".into())
}

fn backing<T>(capacity: usize) -> Result<usize, Error> {
    capacity
        .checked_mul(size_of::<T>())
        .ok_or_else(|| "typed coordinator backing overflow".into())
}

fn metadata_bytes(
    job: &Job,
    dependencies: &Vec<Job>,
    manifest_capacity: usize,
    input_capacity: usize,
) -> Result<usize, Error> {
    if dependencies.len() > 2 {
        return Err("typed coordinator dependency bound".into());
    }
    let mut owned = add(size_of::<Assignment>(), job.owned_heap_bytes()?)?;
    owned = add(owned, backing::<Job>(dependencies.capacity())?)?;
    for child in dependencies {
        owned = add(owned, child.owned_heap_bytes()?)?;
    }
    owned = add(owned, backing::<ArtifactRef>(manifest_capacity)?)?;
    owned = add(owned, backing::<Arc<[u8]>>(input_capacity)?)?;
    // Also cover temporary reconstructed/expected Job clones. Their Vec clones
    // copy lengths, so counting the exported capacities three times is an upper
    // bound. Shared proof payloads are counted once, separately below.
    let copies = owned
        .checked_mul(3)
        .ok_or("typed coordinator metadata overflow")?;
    let controls = CONTROL_BYTES
        + size_of::<Task>()
        + size_of::<CompletedJob>()
        + size_of::<Output>()
        + size_of::<VerifiedNode>()
        + size_of::<packet::Request<&[u8]>>()
        + 2 * (size_of::<packet::Child>() + size_of::<ArtifactRef>() + size_of::<&[u8]>())
        + size_of::<launch::Token>()
        + MAX_TOKEN_BYTES;
    let total = add(copies, controls)?;
    if total > METADATA_BYTES {
        return Err("typed coordinator metadata allowance".into());
    }
    Ok(total)
}

#[derive(Debug)]
struct PacketPlan {
    bytes: usize,
}

impl PacketPlan {
    fn new(metadata: usize, inputs: usize, request: usize, result: usize) -> Result<Self, Error> {
        if metadata > METADATA_BYTES
            || inputs > INPUT_BYTES
            || request > launch::MAX_REQUEST_BYTES
            || result > packet::MAX_RESULT_BYTES
        {
            return Err("typed coordinator packet capacity".into());
        }
        Ok(Self {
            bytes: add(
                add(add(metadata, inputs)?, request)?,
                add(result, TRANSIENT_BYTES)?,
            )?,
        })
    }

    fn admit(&self, allowance: u64) -> Result<(), Error> {
        if self.bytes as u64 > allowance {
            return Err("typed coordinator packet allowance".into());
        }
        Ok(())
    }
}

pub(crate) fn admit_budget(bytes: u64) -> Result<(), Error> {
    PacketPlan::new(
        METADATA_BYTES,
        INPUT_BYTES,
        launch::MAX_REQUEST_BYTES,
        packet::MAX_RESULT_BYTES,
    )?
    .admit(PACKET_HOST_BYTES)?;
    worker_budget::admit_coordinator_job(bytes)
}

pub(super) fn admit_assignment(assignment: &Assignment) -> Result<(), Error> {
    admit_budget(assignment.resources.ram_bytes)?;
    if assignment.inputs.len() > 2 || assignment.manifest.len() > 2 {
        return Err("typed coordinator input bound".into());
    }
    let metadata = metadata_bytes(
        &assignment.job,
        &assignment.dependencies,
        assignment.manifest.capacity(),
        assignment.inputs.capacity(),
    )?;
    let mut inputs = 0;
    for input in &assignment.inputs {
        if input.len() > MAX_PROOF_BYTES {
            return Err("typed coordinator proof input bound".into());
        }
        inputs = add(inputs, add(input.len(), ARC_HEADER_BYTES)?)?;
    }
    PacketPlan::new(
        metadata,
        inputs,
        launch::MAX_REQUEST_BYTES,
        packet::MAX_RESULT_BYTES,
    )?
    .admit(PACKET_HOST_BYTES)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block_v2::execution::job::test_support::typed_wallet;

    #[test]
    fn coordinator_packet_overlap_and_job_floor_have_exact_boundaries() {
        let plan = PacketPlan::new(
            METADATA_BYTES,
            INPUT_BYTES,
            launch::MAX_REQUEST_BYTES,
            packet::MAX_RESULT_BYTES,
        )
        .unwrap();
        plan.admit(plan.bytes as u64).unwrap();
        assert!(plan.admit(plan.bytes as u64 - 1).is_err());
        plan.admit(PACKET_HOST_BYTES).unwrap();
        admit_budget(HOST_BYTES).unwrap();
        for bytes in [0, PACKET_HOST_BYTES, HOST_BYTES - 1] {
            assert!(admit_budget(bytes).is_err());
        }
        for capacities in [
            (METADATA_BYTES + 1, 0, 0, 0),
            (0, INPUT_BYTES + 1, 0, 0),
            (0, 0, launch::MAX_REQUEST_BYTES + 1, 0),
            (0, 0, 0, packet::MAX_RESULT_BYTES + 1),
            (usize::MAX, usize::MAX, usize::MAX, usize::MAX),
        ] {
            assert!(
                PacketPlan::new(capacities.0, capacities.1, capacities.2, capacities.3).is_err()
            );
        }
        eprintln!(
            "typed_coordinator_storage packet_maximum_bytes={} packet_allowance_bytes={PACKET_HOST_BYTES} decode_bytes={} verifier_bytes={NATIVE_VERIFIER_COMPONENT_BYTES} job_allowance_bytes={HOST_BYTES}",
            plan.bytes, codec::proofs::INPUT_STORAGE_LIMIT
        );
    }

    #[test]
    fn coordinator_census_charges_spare_vector_capacity_before_encoding() {
        let job = Job::typed_pair(0, typed_wallet(1, 1, &[1]), None).unwrap();
        let children = Vec::new();
        let baseline = metadata_bytes(&job, &children, 1, 1).unwrap();
        let spare = Vec::with_capacity(7);
        assert_eq!(
            metadata_bytes(&job, &spare, 3, 4).unwrap() - baseline,
            3 * (7 * size_of::<Job>() + 2 * size_of::<ArtifactRef>() + 3 * size_of::<Arc<[u8]>>())
        );
        let excessive = Vec::with_capacity(METADATA_BYTES / size_of::<Job>());
        assert!(metadata_bytes(&job, &excessive, 1, 1).is_err());
        assert!(metadata_bytes(&job, &children, usize::MAX, 1).is_err());
        assert!(metadata_bytes(&job, &children, 1, usize::MAX).is_err());
        eprintln!(
            "typed_coordinator_metadata baseline_bytes={baseline} limit_bytes={METADATA_BYTES}"
        );
    }
}
