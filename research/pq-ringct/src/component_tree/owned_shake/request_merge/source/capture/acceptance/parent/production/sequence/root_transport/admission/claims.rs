//! Additive simultaneous decoder/packet/CPU storage and complete fixed callers.
use super::*;
use core::mem::{size_of, size_of_val};
use crate::component_tree::{commitment, Contract, EndpointContext, Kind, RegisteredVerifier};
use crate::execution::retained_resources::{Snapshot, WorkerAllowance};
use super::super::{RootTransportAction, RootTransportMeasurements, RetainedRootTransportReport};
use super::super::header::{
    RootHeaderValues, HeaderCheckedPacket, HeaderRefusal, HeaderProbeReport, HeaderProbeError,
};
use lattica_prover_p3::block_v2::machine::backend::RegisteredVerificationFailure;

fn frames<T>() -> AdmissionResult<usize> {
    size_of::<T>().checked_mul(16).ok_or(ParentCompileError::Overflow)
}

pub(super) fn fixed() -> AdmissionResult<Requirements> {
    let parts = [
        codec_frames::bytes()?,
        frames::<PreissuedRootTransport<'static, 'static, 'static>>()?,
        frames::<AdmissionResult<PreissuedRootTransport<'static, 'static, 'static>>>()?,
        frames::<RootTransportPlanReport>()?, frames::<AdmissionResult<RootTransportPlanReport>>()?,
        frames::<RootTransportAction<'static, 'static, 'static, 'static>>()?,
        frames::<RootTransportMeasurements>()?, frames::<AdmissionResult<RootTransportMeasurements>>()?,
        frames::<RetainedRootTransportReport<'static, 'static, 'static>>()?,
        frames::<AdmissionResult<RetainedRootTransportReport<'static, 'static, 'static>>>()?,
        frames::<Component<'static, 'static, 'static>>()?,
        frames::<AcceptedChild<'static, 'static, 'static>>()?,
        frames::<AcceptedParent<'static, 'static, 'static>>()?,
        frames::<NodeKey>()?, frames::<NodeProof>()?,
        frames::<&output::RetainedNodeOutput<'static>>()?,
        frames::<&RootTransportAction<'static, 'static, 'static, 'static>>()?,
        frames::<&PreissuedRootTransport<'static, 'static, 'static>>()?,
        frames::<&RetainedRootTransportReport<'static, 'static, 'static>>()?,
        frames::<&RootTransportMeasurements>()?, frames::<AdmissionResult<&RootTransportMeasurements>>()?,
        frames::<&NodeKey>()?, frames::<&NodeProof>()?, frames::<&RegisteredVerifier>()?,
        frames::<&ReservedShakeRequest>()?, frames::<&ParentSourceBound<'static, 'static>>()?,
        frames::<&RetiredHashxOuterOriginals<'static>>()?, frames::<&Ledger>()?,
        frames::<TransportEnvelope>()?, frames::<AdmissionResult<TransportEnvelope>>()?,
        frames::<core::result::Result<TransportEnvelope, crate::component_tree::owned_shake::transport_shape::Refusal>>()?,
        frames::<[HeightShape; HEIGHTS]>()?, frames::<HeightShape>()?, frames::<&HeightShape>()?,
        frames::<Option<&HeightShape>>()?, frames::<std::slice::Iter<'static, HeightShape>>()?,
        frames::<std::iter::Enumerate<std::slice::Iter<'static, HeightShape>>>()?,
        frames::<CpuEnvelope>()?, frames::<AdmissionResult<CpuEnvelope>>()?,
        frames::<lattica_prover_p3::block_v2::machine::verifier::batch::shape::RegisteredChildShape>()?,
        frames::<AdmissionResult<lattica_prover_p3::block_v2::machine::verifier::batch::shape::RegisteredChildShape>>()?,
        frames::<RootHeaderValues<'static>>()?, frames::<HeaderCheckedPacket<'static>>()?,
        frames::<core::result::Result<HeaderCheckedPacket<'static>, HeaderRefusal>>()?,
        frames::<HeaderRefusal>()?, frames::<core::result::Result<(), HeaderRefusal>>()?,
        frames::<core::result::Result<usize, HeaderRefusal>>()?,
        frames::<core::result::Result<u64, HeaderRefusal>>()?,
        frames::<HeaderProbeReport>()?, frames::<HeaderProbeError>()?,
        frames::<core::result::Result<HeaderProbeReport, HeaderProbeError>>()?,
        frames::<core::result::Result<(), HeaderProbeError>>()?,
        frames::<[(usize, u16); 4]>()?, frames::<std::array::IntoIter<(usize, u16), 4>>()?,
        frames::<[(usize, u64); 4]>()?, frames::<std::array::IntoIter<(usize, u64), 4>>()?,
        frames::<[(usize, u16, HeaderRefusal); 4]>()?,
        frames::<std::array::IntoIter<(usize, u16, HeaderRefusal), 4>>()?,
        frames::<[(usize, HeaderRefusal); 2]>()?,
        frames::<std::array::IntoIter<(usize, HeaderRefusal), 2>>()?,
        frames::<[(usize, u64, HeaderRefusal); 7]>()?,
        frames::<std::array::IntoIter<(usize, u64, HeaderRefusal), 7>>()?,
        frames::<[usize; 8]>()?, frames::<std::array::IntoIter<usize, 8>>()?,
        frames::<std::slice::Iter<'static, Val>>()?,
        frames::<std::iter::Enumerate<std::slice::Iter<'static, Val>>>()?,
        frames::<std::slice::Iter<'static, [Val; 4]>>()?,
        frames::<std::iter::Enumerate<std::slice::Iter<'static, [Val; 4]>>>()?,
        frames::<[u8; HEADER_BYTES]>()?, frames::<[Val; PUBLICS]>()?, frames::<[Val; HEADER]>()?,
        frames::<[[Val; 4]; CAP_ROOTS]>()?, frames::<&[Val; PUBLICS]>()?,
        frames::<&[[Val; 4]; CAP_ROOTS]>()?,
        frames::<core::result::Result<&[Val; PUBLICS], core::array::TryFromSliceError>>()?,
        frames::<&[u8]>()?, frames::<&mut [u8]>()?, frames::<Vec<u8>>()?,
        frames::<AdmissionResult<Vec<u8>>>()?,
        frames::<core::result::Result<&'static mut [u8], postcard::Error>>()?,
        frames::<postcard::Error>()?, frames::<std::collections::TryReserveError>()?,
        frames::<core::result::Result<(), std::collections::TryReserveError>>()?,
        frames::<RegisteredVerificationFailure>()?,
        frames::<core::result::Result<(), RegisteredVerificationFailure>>()?, frames::<String>()?,
        frames::<Spec>()?, frames::<[Spec; 3]>()?, frames::<Contract>()?, frames::<Kind>()?,
        frames::<crate::shake_air::Descriptor>()?, frames::<crate::aes_lane_air::Descriptor>()?,
        frames::<EndpointContext>()?, frames::<[Val; 8]>()?, frames::<[Val; 4]>()?,
        frames::<[u64; 4]>()?, frames::<[u8; 2]>()?, frames::<[u8; 8]>()?, frames::<[u8; 16]>()?,
        frames::<[(usize, [Val; 4]); 3]>()?, frames::<[(usize, u64); 6]>()?,
        frames::<std::array::IntoIter<(usize, [Val; 4]), 3>>()?,
        frames::<std::array::IntoIter<(usize, u64), 6>>()?,
        frames::<AdmissionResult<[Val; HEADER]>>()?, frames::<AdmissionResult<Spec>>()?,
        frames::<crate::component_tree::Result<Spec>>()?, frames::<crate::component_tree::Result<Contract>>()?,
        frames::<crate::component_tree::Error>()?,
        frames::<super::super::super::super::super::SourceNode>()?,
        frames::<[super::super::super::super::super::SourceNode; 2]>()?,
        frames::<AdmissionResult<([super::super::super::super::super::SourceNode; 2], [Spec; 3])>>()?,
        frames::<ParentAcceptanceReport>()?, frames::<ComponentReport>()?,
        frames::<Retirement>()?, frames::<HashxOuterStep>()?,
        frames::<Requirements>()?, frames::<AdmissionResult<Requirements>>()?,
        frames::<Reservation>()?,
        frames::<core::result::Result<Reservation, crate::execution::retained_resources::Error>>()?,
        frames::<Bytes>()?, frames::<Snapshot>()?, frames::<Ledger>()?, frames::<WorkerAllowance>()?,
        frames::<ParentCompileError>()?, frames::<AdmissionResult<()>>()?, frames::<AdmissionResult<usize>>()?,
        frames::<core::result::Result<u64, std::num::TryFromIntError>>()?,
        frames::<core::result::Result<usize, std::num::TryFromIntError>>()?,
        frames::<core::result::Result<usize, ExecutionError>>()?,
        frames::<core::result::Result<commitment::Digest, commitment::CommitmentError>>()?,
        frames::<p3_goldilocks::Poseidon2Goldilocks<8>>()?,
        frames::<std::time::Instant>()?, frames::<u128>()?, frames::<Option<u128>>()?,
        frames::<std::ops::Range<usize>>()?, frames::<std::slice::Chunks<'static, u64>>()?,
        frames::<std::iter::Enumerate<std::slice::Iter<'static, u64>>>()?,
        frames::<std::fmt::Arguments<'static>>()?,
        // Pinned header/probe scalar, option, slice/array iteration and integer
        // cursor/error/checked arithmetic forwarding. No heap-backed variants.
        frames::<[usize; 256]>()?, frames::<[u64; 32]>()?, frames::<[bool; 32]>()?,
        // Bounded codec diagnostics, Poseidon constants/helper state, complete
        // source-spec forwarding and ordinary destruction/byte-copy helpers.
        64 << 10,
    ];
    let external = [
        three_result_bytes(RetiredHashxOuterOriginals::check),
        result_bytes(RetiredHashxOuterOriginals::outer_step),
    ];
    let helper = size_of_val(&parts).checked_add(size_of_val(&external))
        .and_then(|n| n.checked_mul(16)).ok_or(ParentCompileError::Overflow)?;
    let host = parts.into_iter().try_fold(helper, |sum, part|
        sum.checked_add(part).ok_or(ParentCompileError::Overflow))?;
    let host = external.into_iter().try_fold(host, |sum, part|
        part.checked_mul(16).and_then(|part| sum.checked_add(part)).ok_or(ParentCompileError::Overflow))?;
    Ok(Requirements::single(Category::PhaseScratch, Bytes {
        host: u64::try_from(host).map_err(|_| ParentCompileError::Overflow)?, device: 0,
    }))
}

pub(super) fn payload(cpu: CpuEnvelope) -> AdmissionResult<Requirements> {
    if cpu.heights != HEIGHTS || cpu.bytes == 0 { return Err(ParentCompileError::Source); }
    // Full cumulative decoder backing includes canonical scratch even after it
    // is destroyed. Neither it nor the original proof is a replacement claim.
    let packets_and_decoder = PACKET_LIMIT.checked_mul(2)
        .and_then(|n| n.checked_add(DECODE_LIMIT)).ok_or(ParentCompileError::Overflow)?;
    let verifier = cpu.bytes.checked_add(RegisteredVerifier::classified_call_extra_bytes())
        .ok_or(ParentCompileError::Overflow)?;
    let mut result = Requirements::single(Category::PhaseScratch, Bytes {
        host: u64::try_from(packets_and_decoder).map_err(|_| ParentCompileError::Overflow)?, device: 0,
    });
    result.add(Category::IndependentVerifier, Bytes {
        host: u64::try_from(verifier).map_err(|_| ParentCompileError::Overflow)?, device: 0,
    }).map_err(|_| ParentCompileError::Overflow)?;
    Ok(result)
}
