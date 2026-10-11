//! Protocol buffers and decoded inputs coexist with a typed session and prover.
//! Engine/driver storage, other caller-owned data and OS stacks still require
//! their enclosing allowances; this is not a complete lifetime plan.

use super::{packet, process, PreparedInputs, TypedWorker};
use crate::block_v2::execution::{
    job::ArtifactRef,
    launch::{Token, WorkerGate, MAX_REQUEST_BYTES, MAX_TOKEN_BYTES},
    policy_context::{PolicyContext, MAX_BYTES as MAX_CONTEXT_BYTES},
};
use crate::block_v2::{recursive::Error, typed_recursive::Policy};

pub(crate) const HOST_BYTES: u64 = 8 << 20;
// PreparedInputs retains decoded children until the proving call returns. Keep
// this allowance outside the cached session even for Empty jobs: later jobs may
// have children while reusing a PCS configured with the same budget.
pub(crate) const INPUT_HOST_BYTES: u64 = crate::block_v2::codec::proofs::INPUT_STORAGE_LIMIT as u64;
/// Registry setup precedes proving/cache retention. Reserve its payload beside
/// protocol/input/session ownership, without subtracting it from later proving RAM.
pub(crate) const STARTUP_HOST_BYTES: u64 = HOST_BYTES
    + INPUT_HOST_BYTES
    + crate::block_v2::typed_recursive::storage::SESSION_HOST_BYTES
    + crate::block_v2::machine::programs::registry_setup::INITIAL_STORAGE_BYTES as u64;

pub(crate) fn admit_startup(total: u64) -> Result<(), Error> {
    if total < STARTUP_HOST_BYTES {
        return Err("typed worker RAM below registry startup payload".into());
    }
    Ok(())
}
const METADATA_BYTES: usize = 128 << 10;
pub(super) const MAX_JOB_BYTES: usize = MAX_REQUEST_BYTES + MAX_TOKEN_BYTES + 8;

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
        + 64 * std::mem::size_of::<(ArtifactRef, Policy)>()
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
            packet,
            result,
        })
    }

    fn bytes(&self) -> u64 {
        (self.metadata + self.packet + self.result) as u64
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

/// Keep the entire maximum protocol and decoded-input overlap outside the session's prover RAM.
/// Session construction subtracts its own fixed storage allowance afterwards.
pub(super) fn session_memory_bytes(total: u64) -> Result<u64, Error> {
    check_buffers(MAX_JOB_BYTES, packet::MAX_RESULT_BYTES)?;
    let session = total
        .checked_sub(HOST_BYTES)
        .and_then(|bytes| bytes.checked_sub(INPUT_HOST_BYTES))
        .ok_or("typed worker protocol and decoded-input allowance")?;
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
            "typed_protocol_storage metadata_bytes={} packet_bytes={} result_bytes={} maximum_bytes={} allowance_bytes={HOST_BYTES}",
            full.metadata, full.packet, full.result, full.bytes()
        );
    }

    #[test]
    fn protocol_and_session_storage_leave_positive_prover_memory() {
        use crate::block_v2::typed_recursive::storage::SESSION_HOST_BYTES;
        let minimum = HOST_BYTES + INPUT_HOST_BYTES + SESSION_HOST_BYTES;
        for total in [0, HOST_BYTES - 1, HOST_BYTES, minimum - 1, minimum] {
            assert!(session_memory_bytes(total).is_err());
        }
        assert_eq!(
            session_memory_bytes(minimum + 1).unwrap(),
            SESSION_HOST_BYTES + 1
        );
        let total = 3 << 30;
        let session = session_memory_bytes(total).unwrap();
        assert_eq!(session + HOST_BYTES + INPUT_HOST_BYTES, total);
        assert_eq!(INPUT_HOST_BYTES, 64 << 20);
        eprintln!("typed_worker_input_reservation assigned_bytes={total} protocol_bytes={HOST_BYTES} decoded_input_bytes={INPUT_HOST_BYTES} session_bytes={session} active_bytes={} constant_across_empty_and_input_jobs=true", session - SESSION_HOST_BYTES);
    }
}
