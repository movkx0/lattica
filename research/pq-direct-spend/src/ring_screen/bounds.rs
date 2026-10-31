//! Payload admission, not an original quota receipt or a measured RSS peak.
//! See SOURCE_BOUNDS.md for the source inventory and non-overlapping phases.
use super::*;
use core::mem::size_of;
use ring::{Account, Poly, SignedPoly, Statement, Witness, RING_PAIRS};
use serde::Serialize;

#[derive(Clone, Copy, Serialize)]
pub(super) struct Staging {
    pub ring_backing_bytes: usize,
    pub native_parameter_bytes: usize,
    pub aes_stream_bytes: usize,
    pub inline_payload_bytes: usize,
    pub required_host_bytes: usize,
}

impl Staging {
    pub fn new() -> Result<Self> {
        let ring_backing_bytes = RING_PAIRS * size_of::<[Account; 2]>();
        let native_parameter_bytes = 7 * size_of::<[Poly; 4]>() + 4 * size_of::<[Poly; 3]>();
        let aes_stream_bytes = (7648usize * 4).div_ceil(16) * 16
            + (3366usize * 4).div_ceil(16) * 16
            + (1197usize * 4).div_ceil(16) * 16;
        // Count source locals plus return destinations, without move-elision
        // credit. Key and coin scratch are summed although calls are sequential.
        let inline_payload_bytes = 2 * size_of::<Statement>()
            + 2 * size_of::<Witness>()
            + 2 * size_of::<[Account; 2]>()
            + size_of::<[SignedPoly; 8]>()
            + size_of::<[SignedPoly; 9]>()
            + 2 * size_of::<[[Poly; 4]; 2]>()
            + 2 * size_of::<[[Poly; 5]; 2]>()
            + (8 + 4 + 4 + 9 + 5 + 4 + 4) * size_of::<Poly>()
            + size_of::<[u64; 64]>()
            + 4 * size_of::<[u8; 32]>()
            + 3 * size_of::<Vec<u8>>()
            + size_of::<crate::ring_native::Parameters>()
            + 2 * size_of::<aes::Aes256>()
            + 2 * size_of::<[u8; 16]>()
            + 2 * size_of::<sha3::Shake256>()
            + size_of::<sha3::Shake256Reader>()
            + 2 * size_of::<sha3::Sha3_256>()
            + ring::D
            + size_of::<SignedPoly>();
        let required_host_bytes = ring_backing_bytes
            .checked_add(native_parameter_bytes)
            .and_then(|n| n.checked_add(aes_stream_bytes))
            .and_then(|n| n.checked_add(inline_payload_bytes))
            .and_then(|n| n.checked_add(ring_circuit::verification::CALLER_ORCHESTRATION_BYTES))
            .ok_or(Error::ResourceLimit)?;
        if required_host_bytes > WORKER_HOST_BYTES {
            return Err(Error::ResourceLimit.into());
        }
        Ok(Self {
            ring_backing_bytes,
            native_parameter_bytes,
            aes_stream_bytes,
            inline_payload_bytes,
            required_host_bytes,
        })
    }
}

pub(super) fn orchestration(root_capacity: usize, paths: Option<&io::Paths>) -> Result<usize> {
    // The fixed upper bound admits path construction before allocation. Recheck
    // actual capacities before every fixture, compiler and GPU lifecycle.
    let path_bytes = paths.map_or(8 * (io::MAX_OUTPUT_BYTES + 64), io::Paths::capacity_bytes);
    let bytes = root_capacity
        + path_bytes
        + (io::MAX_OUTPUT_BYTES + 64)
        + 2 * size_of::<workflow::SuiteReport>()
        + 3 * size_of::<workflow::CaseReport>()
        + 2 * size_of::<fixtures::Manifest>()
        + size_of::<io::Paths>()
        + 2 * size_of::<Staging>()
        + 4 * size_of::<std::path::PathBuf>()
        + 6 * size_of::<std::time::Instant>()
        + 2 * size_of::<sha3::Sha3_256>()
        + (4 << 10); // inherited bounded stream/error/scalar allowance
    if bytes > ring_circuit::verification::CALLER_ORCHESTRATION_BYTES {
        return Err("screen owners exceed existing 32 KiB orchestration allowance".into());
    }
    // Native Witness survives compilation, but is destroyed before registered
    // proving. The complete compiler allowance plus all callers stays <=32 GiB.
    if CAPACITY.limits().required_host_bytes as usize
        + ring_circuit::verification::CALLER_ORCHESTRATION_BYTES
        + RING_PAIRS * size_of::<[Account; 2]>()
        + size_of::<Statement>()
        + size_of::<Witness>()
        > WORKER_HOST_BYTES
    {
        return Err(Error::ResourceLimit.into());
    }
    Ok(bytes)
}
