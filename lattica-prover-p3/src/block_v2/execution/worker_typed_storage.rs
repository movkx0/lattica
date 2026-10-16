//! Protocol buffers and decoded inputs coexist with a typed session and prover.
//! Engine/driver storage, other caller-owned data and remaining OS stacks require
//! their enclosing allowances; this is not a complete lifetime plan.

use super::{packet, process, PreparedInputs, TypedWorker};
use crate::block_v2::execution::{
    job::ArtifactRef,
    launch::{Token, WorkerGate, MAX_REQUEST_BYTES, MAX_TOKEN_BYTES},
    policy_context::{PolicyContext, MAX_BYTES as MAX_CONTEXT_BYTES},
};
use crate::block_v2::{recursive::Error, typed_recursive::Policy};
use crate::host_memory::RETAINED_SYSTEM_HOST_BYTES;

pub(crate) const HOST_BYTES: u64 = 8 << 20;
// PreparedInputs retains decoded children until the proving call returns. Keep
// this allowance outside the cached session even for Empty jobs: later jobs may
// have children while reusing a PCS configured with the same budget.
pub(crate) const INPUT_HOST_BYTES: u64 = crate::block_v2::codec::proofs::INPUT_STORAGE_LIMIT as u64;
/// Registry setup precedes proving/cache retention. Reserve its payload beside
/// protocol/input/session ownership, without subtracting it from later proving RAM.
pub(crate) const STARTUP_HOST_BYTES: u64 = HOST_BYTES
    + INPUT_HOST_BYTES
    + RETAINED_SYSTEM_HOST_BYTES
    + crate::block_v2::execution::worker_budget::CALLER_STACK_HOST_BYTES
    + crate::block_v2::typed_recursive::storage::SESSION_HOST_BYTES
    + crate::block_v2::machine::programs::registry_setup::INITIAL_STORAGE_BYTES as u64;

pub(crate) fn admit_startup(total: u64, threads: u32) -> Result<(), Error> {
    let stacks = crate::block_v2::execution::worker_budget::rayon_stack_host_bytes(threads)?;
    if total
        < STARTUP_HOST_BYTES
            .checked_add(stacks)
            .ok_or("worker startup RAM overflow")?
    {
        return Err("typed worker RAM below registry startup payload".into());
    }
    Ok(())
}
const METADATA_BYTES: usize = 128 << 10;
pub(super) const MAX_JOB_BYTES: usize = MAX_REQUEST_BYTES + MAX_TOKEN_BYTES + 8;

// The native C caller retains its encoded input throughout the blocking serve
// call. Include the qualified caller's extra EOF-probe byte, plus the decoded
// launch path moved into the persistent service. These coexist with packets,
// decoded children and cached proving state; they are not startup-only inputs.
const NATIVE_BOOTSTRAP_BYTES: usize = crate::native_gpu::PUBLIC_WORKER_BOOTSTRAP_MAX_BYTES;
const NATIVE_INPUT_BYTES: usize = NATIVE_BOOTSTRAP_BYTES + 1 + NATIVE_BOOTSTRAP_BYTES;

pub(crate) fn check_native_inputs(
    bootstrap_bytes: usize,
    launch_capacity: usize,
) -> Result<(), Error> {
    if bootstrap_bytes > NATIVE_BOOTSTRAP_BYTES || launch_capacity > NATIVE_BOOTSTRAP_BYTES {
        return Err("native service retained input exceeds protocol allowance".into());
    }
    check_buffers(MAX_JOB_BYTES, packet::MAX_RESULT_BYTES)
}

fn metadata_bytes() -> Result<usize, Error> {
    if std::mem::needs_drop::<PolicyContext>() || std::mem::needs_drop::<process::Descriptor>() {
        return Err("typed protocol identity has unaccounted heap ownership".into());
    }
    // Includes the old/new context overlap, context decode/encode backing,
    // borrowed request descriptors, launch controls and fixed wire records.
    // Counting the session inline here also overlaps its separate allowance.
    let bytes = std::mem::size_of::<TypedWorker>()
        + std::mem::size_of::<PreparedInputs>()
        + 3 * std::mem::size_of::<PolicyContext>()
        + MAX_CONTEXT_BYTES
        + crate::block_v2::profile::MAX_TRANSACTIONS * std::mem::size_of::<(ArtifactRef, Policy)>()
        + 2 * (std::mem::size_of::<process::Descriptor>()
            + process::CONFIG_BYTES
            + process::SESSION_BYTES)
        + 2 * std::mem::size_of::<packet::Request<&[u8]>>()
        + 4 * std::mem::size_of::<packet::Child>()
        + 4 * std::mem::size_of::<ArtifactRef>()
        + 4 * std::mem::size_of::<&[u8]>()
        + 2 * std::mem::size_of::<Token>()
        + std::mem::size_of::<WorkerGate>()
        + (16 << 10);
    if bytes > METADATA_BYTES {
        return Err("typed protocol metadata allowance".into());
    }
    Ok(bytes)
}

#[derive(Debug)]
struct Footprint {
    metadata: usize,
    native_input: usize,
    packet: usize,
    result: usize,
}

impl Footprint {
    fn new(packet: usize, result: usize) -> Result<Self, Error> {
        if packet > MAX_JOB_BYTES || result > packet::MAX_RESULT_BYTES {
            return Err("typed protocol buffer capacity".into());
        }
        Ok(Self {
            metadata: metadata_bytes()?,
            native_input: NATIVE_INPUT_BYTES,
            packet,
            result,
        })
    }

    fn bytes(&self) -> u64 {
        (self.metadata + self.native_input + self.packet + self.result) as u64
    }

    fn admit(&self, limit: u64) -> Result<(), Error> {
        if self.bytes() > limit {
            return Err("typed protocol host allowance".into());
        }
        Ok(())
    }
}

pub(super) fn check_buffers(packet: usize, result: usize) -> Result<(), Error> {
    Footprint::new(packet, result)?.admit(HOST_BYTES)
}

/// Keep protocol, retained inputs, allocator reuse capacity and stacks outside
/// prover RAM. Retained allocator capacity may coexist with fresh allocations;
/// subtract it even for the first job so cached sessions keep one fixed budget.
/// Session construction subtracts its own fixed storage allowance afterwards.
pub(super) fn session_memory_bytes(total: u64, threads: u32) -> Result<u64, Error> {
    check_buffers(MAX_JOB_BYTES, packet::MAX_RESULT_BYTES)?;
    let stacks = crate::block_v2::execution::worker_budget::rayon_stack_host_bytes(threads)?;
    let session = total
        .checked_sub(HOST_BYTES)
        .and_then(|bytes| bytes.checked_sub(INPUT_HOST_BYTES))
        .and_then(|bytes| bytes.checked_sub(RETAINED_SYSTEM_HOST_BYTES))
        .and_then(|bytes| bytes.checked_sub(stacks))
        .and_then(|bytes| {
            bytes.checked_sub(crate::block_v2::execution::worker_budget::CALLER_STACK_HOST_BYTES)
        })
        .ok_or("typed worker protocol, decoded-input, retained allocator and stack allowance")?;
    crate::block_v2::typed_recursive::storage::active_memory_bytes(session, 0)?;
    Ok(session)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packet_and_result_overlap_has_exact_admission_and_capacity_bounds() {
        let full = Footprint::new(MAX_JOB_BYTES, packet::MAX_RESULT_BYTES).unwrap();
        full.admit(full.bytes()).unwrap();
        assert!(full.admit(full.bytes() - 1).is_err());
        full.admit(HOST_BYTES).unwrap();
        for (packet, result) in [
            (MAX_JOB_BYTES + 1, 0),
            (0, packet::MAX_RESULT_BYTES + 1),
            (usize::MAX, usize::MAX),
        ] {
            assert!(Footprint::new(packet, result).is_err());
        }
        eprintln!(
            "typed_protocol_storage metadata_bytes={} native_input_bytes={} packet_bytes={} result_bytes={} maximum_bytes={} allowance_bytes={HOST_BYTES}",
            full.metadata, full.native_input, full.packet, full.result, full.bytes()
        );
    }

    #[test]
    fn native_inputs_coexist_with_full_packet_result_and_decoded_children() {
        let full = Footprint::new(MAX_JOB_BYTES, packet::MAX_RESULT_BYTES).unwrap();
        let previous = (full.metadata + full.packet + full.result) as u64;
        assert!(full.admit(previous).is_err());
        assert_eq!(full.native_input, 2 * NATIVE_BOOTSTRAP_BYTES + 1);
        assert_eq!(full.bytes(), previous + full.native_input as u64);
        full.admit(HOST_BYTES).unwrap();
        check_native_inputs(NATIVE_BOOTSTRAP_BYTES, NATIVE_BOOTSTRAP_BYTES).unwrap();
        let total = 3 << 30;
        let stacks = crate::block_v2::execution::worker_budget::rayon_stack_host_bytes(4).unwrap();
        let session = session_memory_bytes(total, 4).unwrap();
        assert_eq!(
            session
                + HOST_BYTES
                + INPUT_HOST_BYTES
                + RETAINED_SYSTEM_HOST_BYTES
                + stacks
                + crate::block_v2::execution::worker_budget::CALLER_STACK_HOST_BYTES,
            total
        );
        assert!(full.bytes() + INPUT_HOST_BYTES + session <= total);
        eprintln!("typed_native_input_overlap encoded_backing_bytes={} launch_backing_bytes={} retained_bytes={} previous_protocol_bytes={previous} full_protocol_bytes={} protocol_allowance_bytes={HOST_BYTES} decoded_input_bytes={INPUT_HOST_BYTES} session_bytes={session}", NATIVE_BOOTSTRAP_BYTES + 1, NATIVE_BOOTSTRAP_BYTES, full.native_input, full.bytes());
    }

    #[test]
    fn native_input_admission_checks_capacity_and_rejects_oversized_backing() {
        use std::path::PathBuf;
        let mut boundary = PathBuf::with_capacity(NATIVE_BOOTSTRAP_BYTES);
        boundary.push("/tmp/native-launches");
        assert!(boundary.as_os_str().len() < boundary.capacity());
        for encoded in [0, 1, NATIVE_BOOTSTRAP_BYTES] {
            check_native_inputs(encoded, boundary.capacity()).unwrap();
        }
        let mut oversized = PathBuf::with_capacity(NATIVE_BOOTSTRAP_BYTES + 1);
        oversized.push("/tmp/native-launches");
        assert!(oversized.as_os_str().len() < NATIVE_BOOTSTRAP_BYTES);
        assert!(oversized.capacity() > NATIVE_BOOTSTRAP_BYTES);
        assert!(check_native_inputs(1, oversized.capacity()).is_err());
        for (encoded, launch) in [
            (NATIVE_BOOTSTRAP_BYTES + 1, 0),
            (usize::MAX, 0),
            (0, usize::MAX),
            (usize::MAX, usize::MAX),
        ] {
            assert!(check_native_inputs(encoded, launch).is_err());
        }
        eprintln!("typed_native_input_bounds boundary_acceptances=3 capacity_rejections=5 uses_path_capacity=true");
    }

    #[test]
    fn protocol_and_session_storage_leave_positive_prover_memory() {
        use crate::block_v2::typed_recursive::storage::SESSION_HOST_BYTES;
        let stacks = crate::block_v2::execution::worker_budget::rayon_stack_host_bytes(4).unwrap();
        let minimum = HOST_BYTES
            + INPUT_HOST_BYTES
            + RETAINED_SYSTEM_HOST_BYTES
            + SESSION_HOST_BYTES
            + stacks
            + crate::block_v2::execution::worker_budget::CALLER_STACK_HOST_BYTES;
        for total in [0, HOST_BYTES - 1, HOST_BYTES, minimum - 1, minimum] {
            assert!(session_memory_bytes(total, 4).is_err());
        }
        assert_eq!(
            session_memory_bytes(minimum + 1, 4).unwrap(),
            SESSION_HOST_BYTES + 1
        );
        let total = 3 << 30;
        let session = session_memory_bytes(total, 4).unwrap();
        assert_eq!(
            session
                + HOST_BYTES
                + INPUT_HOST_BYTES
                + RETAINED_SYSTEM_HOST_BYTES
                + stacks
                + crate::block_v2::execution::worker_budget::CALLER_STACK_HOST_BYTES,
            total
        );
        assert_eq!(INPUT_HOST_BYTES, 64 << 20);
        eprintln!("typed_worker_input_reservation assigned_bytes={total} protocol_bytes={HOST_BYTES} decoded_input_bytes={INPUT_HOST_BYTES} retained_system_bytes={RETAINED_SYSTEM_HOST_BYTES} session_bytes={session} active_bytes={} constant_across_empty_and_input_jobs=true", session - SESSION_HOST_BYTES);
    }

    #[test]
    fn rayon_stacks_overlap_startup_inputs_and_every_session() {
        use crate::block_v2::execution::worker_budget::rayon_stack_host_bytes;
        let total = 3 << 30;
        for threads in [1, 2, 4, 64] {
            let stacks = rayon_stack_host_bytes(threads).unwrap();
            assert!(admit_startup(STARTUP_HOST_BYTES + stacks - 1, threads).is_err());
            admit_startup(STARTUP_HOST_BYTES + stacks, threads).unwrap();
            let session = session_memory_bytes(total, threads).unwrap();
            assert_eq!(
                session
                    + stacks
                    + HOST_BYTES
                    + INPUT_HOST_BYTES
                    + RETAINED_SYSTEM_HOST_BYTES
                    + crate::block_v2::execution::worker_budget::CALLER_STACK_HOST_BYTES,
                total
            );
            eprintln!("typed_rayon_stack_reservation threads={threads} stack_host_bytes={stacks} assigned_bytes={total} session_bytes={session}");
        }
        assert!(session_memory_bytes(total, 0).is_err());
        assert!(session_memory_bytes(total, u32::MAX).is_err());
        assert!(admit_startup(total, 0).is_err());
        assert!(admit_startup(total, u32::MAX).is_err());
    }
}
