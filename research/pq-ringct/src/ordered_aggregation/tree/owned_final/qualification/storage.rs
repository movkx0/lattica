//! Exact overlapping requested storage; allocator/stack RSS remain subject to
//! the enclosing unchanged worker/process limits. This is not admission itself.
use super::*;

pub(super) struct Limits {
    pub(super) envelope: geometry::TransportEnvelope,
    pub(super) packet_capacity: usize,
}
impl Limits {
    pub(super) fn from_source(merge: &MergeSource) -> OwnedResult<Self> {
        let (active, padded) = merge.rows();
        if active == 0 || active > padded || !(8..=ROW_LIMIT).contains(&padded)
            || !padded.is_power_of_two()
        { return Err(FinalFailure::Source); }
        // Every permitted actual height fits before dispatch. The actual final
        // program may be smaller than its immutable source upper bound.
        let envelope = geometry::TransportEnvelope::for_root().map_err(|_| FinalFailure::Source)?;
        let packet_capacity = add(packet::HEADER_BYTES, envelope.encoded_inner_bytes)?;
        if packet_capacity > profile::MAX_PROOF_BYTES
            || envelope.decoded_cumulative_bytes > codec::REGISTERED_PROOF_STORAGE_LIMIT_BYTES
        { return Err(FinalFailure::Capacity); }
        Ok(Self { envelope, packet_capacity })
    }
    pub(super) fn payload_bytes(&self) -> OwnedResult<usize> {
        // First packet remains immutable through disk and canonical checks.
        // Second retains its entire capacity through readback/re-encoding.
        // Decoder quota includes nested Vec headers/backing and its canonical
        // scratch even after that scratch drops. Original proof is separate.
        add(mul(2, self.packet_capacity)?, self.envelope.decoded_cumulative_bytes)
    }
}

pub(super) fn planning_frames() -> OwnedResult<usize> {
    let parts = [size_of::<Limits>(), size_of::<OwnedResult<Limits>>(),
        size_of::<Requirements>(), size_of::<OwnedResult<Requirements>>(),
        size_of::<[usize; 8]>()];
    add(geometry::planning_host_bytes().map_err(|_| FinalFailure::Overflow)?,
        mul(16, parts.into_iter().try_fold(core::mem::size_of_val(&parts), add)?)?)
}

pub(super) fn frames() -> OwnedResult<usize> {
    let parts = [
        size_of::<FinalQualificationReport>(), size_of::<OwnedResult<FinalQualificationReport>>(),
        size_of::<packet::Header<'static>>(), size_of::<[u8; packet::HEADER_BYTES]>(),
        size_of::<BatchProof>(), size_of::<RawProof<Config>>(),
        size_of::<[Val; PUBLIC_VALUES]>(), size_of::<profile::Challenge>(),
        size_of::<Vec<u8>>(), size_of::<OwnedResult<Vec<u8>>>(),
        size_of::<core::result::Result<&'static mut [u8], postcard::Error>>(),
        size_of::<OwnedResult<&'static [u8]>>(),
        size_of::<core::result::Result<(), RegisteredVerificationFailure>>(),
        size_of::<RegisteredVerificationFailure>(), size_of::<String>(),
        size_of::<core::result::Result<(), String>>(), size_of::<crate::ordered_aggregation::Error>(),
        size_of::<crate::ordered_aggregation::Result<()>>(),
        size_of::<Sha3_256>(), size_of::<sha3::digest::Output<Sha3_256>>(),
        size_of::<[u8; 32]>(), size_of::<Instant>(), size_of::<u128>(),
        size_of::<&Retained<FinalNode<'static>>>(), size_of::<&FinalPhasePlan<'static>>(),
        size_of::<&BatchKey>(), size_of::<&BatchProof>(), size_of::<&mut BatchProof>(),
        size_of::<&[LeafStatement]>(), size_of::<&ExecutionAccess<'static>>(),
        size_of::<PhaseBinding>(), size_of::<OwnedResult<PhaseBinding>>(),
        size_of::<std::collections::TryReserveError>(),
        size_of::<core::result::Result<(), std::collections::TryReserveError>>(),
        size_of::<core::result::Result<u64, core::num::TryFromIntError>>(),
        size_of::<core::result::Result<usize, core::num::TryFromIntError>>(),
        size_of::<std::slice::Iter<'static, Val>>(),
        size_of::<std::slice::Iter<'static, [Val; 4]>>(),
        size_of::<std::iter::Flatten<std::slice::Iter<'static, [Val; 4]>>>(),
        size_of::<std::array::IntoIter<usize, 8>>(),
        size_of::<std::array::IntoIter<&'static [u8; 32], 4>>(),
        size_of::<[usize; 32]>(), size_of::<[u64; 8]>(),
        size_of::<OwnedResult<()>>(), size_of::<OwnedResult<usize>>(),
    ];
    let callers = mul(16, parts.into_iter().try_fold(core::mem::size_of_val(&parts), add)?)?;
    [callers, planning_frames()?, codec_frames::host_bytes()?, disk::frames()?]
        .into_iter().try_fold(0, add)
}
