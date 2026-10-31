//! Independent pre-native scratch plus complete root-check forwarding frames.
use super::*;

fn frames<T>() -> RecheckResult<usize> {
    size_of::<T>()
        .checked_mul(8)
        .ok_or(ParentCompileError::Overflow)
}

pub(super) fn requirements(cpu: CpuEnvelope) -> RecheckResult<Requirements> {
    if cpu.heights != 18 || cpu.bytes == 0 {
        return Err(ParentCompileError::Source);
    }
    let parts = [
        frames::<PreissuedRootRecheck<'static, 'static, 'static>>()?,
        frames::<RecheckResult<PreissuedRootRecheck<'static, 'static, 'static>>>()?,
        frames::<RootPublicRecheckAction<'static, 'static, 'static, 'static>>()?,
        frames::<&RootPublicRecheckAction<'static, 'static, 'static, 'static>>()?,
        frames::<RootPublicRecheckReport>()?,
        frames::<RecheckResult<RootPublicRecheckReport>>()?,
        frames::<RootRecheckPlanReport>()?,
        frames::<RecheckResult<RootRecheckPlanReport>>()?,
        frames::<Component<'static, 'static, 'static>>()?,
        frames::<AcceptedChild<'static, 'static, 'static>>()?,
        frames::<AcceptedParent<'static, 'static, 'static>>()?,
        frames::<&AcceptedChild<'static, 'static, 'static>>()?,
        frames::<&output::RetainedNodeOutput<'static>>()?,
        frames::<&NodeKey>()?,
        frames::<&NodeProof>()?,
        frames::<&RegisteredVerifier>()?,
        frames::<&ReservedShakeRequest>()?,
        frames::<&RetiredHashxOuterOriginals<'static>>()?,
        frames::<&ParentSourceBound<'static, 'static>>()?,
        frames::<&Ledger>()?,
        frames::<&PreissuedRootRecheck<'static, 'static, 'static>>()?,
        frames::<&Spec>()?,
        frames::<&EndpointContext>()?,
        frames::<&[Val]>()?,
        frames::<[Val; PUBLICS]>()?,
        frames::<[Val; HEADER]>()?,
        frames::<RecheckResult<[Val; HEADER]>>()?,
        frames::<[Val; 8]>()?,
        frames::<[Val; 4]>()?,
        frames::<[u64; 4]>()?,
        frames::<[(usize, [Val; 4]); 3]>()?,
        frames::<[(usize, u64); 6]>()?,
        frames::<std::array::IntoIter<(usize, [Val; 4]), 3>>()?,
        frames::<std::array::IntoIter<(usize, u64), 6>>()?,
        frames::<std::ops::Range<usize>>()?,
        frames::<std::slice::Chunks<'static, u64>>()?,
        frames::<std::iter::Enumerate<std::slice::Iter<'static, u64>>>()?,
        frames::<Spec>()?,
        frames::<[Spec; 3]>()?,
        frames::<Contract>()?,
        frames::<Kind>()?,
        frames::<crate::shake_air::Descriptor>()?,
        frames::<crate::aes_lane_air::Descriptor>()?,
        frames::<super::super::super::super::SourceNode>()?,
        frames::<[super::super::super::super::SourceNode; 2]>()?,
        frames::<RecheckResult<([super::super::super::super::SourceNode; 2], [Spec; 3])>>()?,
        frames::<RecheckResult<Spec>>()?,
        frames::<crate::component_tree::Result<Spec>>()?,
        frames::<crate::component_tree::Result<Contract>>()?,
        frames::<crate::component_tree::Error>()?,
        frames::<ParentAcceptanceReport>()?,
        frames::<ComponentReport>()?,
        frames::<Retirement>()?,
        frames::<HashxOuterStep>()?,
        frames::<CpuEnvelope>()?,
        frames::<RecheckResult<CpuEnvelope>>()?,
        frames::<lattica_prover_p3::block_v2::machine::verifier::batch::shape::RegisteredChildShape>(
        )?,
        frames::<
            RecheckResult<
                lattica_prover_p3::block_v2::machine::verifier::batch::shape::RegisteredChildShape,
            >,
        >()?,
        frames::<core::result::Result<usize, ExecutionError>>()?,
        frames::<Requirements>()?,
        frames::<RecheckResult<Requirements>>()?,
        frames::<Reservation>()?,
        frames::<core::result::Result<Reservation, crate::execution::retained_resources::Error>>()?,
        frames::<Bytes>()?,
        frames::<Snapshot>()?,
        frames::<Ledger>()?,
        frames::<core::result::Result<Bytes, crate::execution::retained_resources::Error>>()?,
        frames::<ParentCompileError>()?,
        frames::<RecheckResult<()>>()?,
        frames::<RecheckResult<usize>>()?,
        frames::<RegisteredVerificationFailure>()?,
        frames::<core::result::Result<(), RegisteredVerificationFailure>>()?,
        frames::<String>()?,
        frames::<std::time::Instant>()?,
        frames::<u128>()?,
        frames::<Option<u128>>()?,
        frames::<[usize; 32]>()?,
        frames::<[bool; 16]>()?,
        frames::<core::result::Result<u64, std::num::TryFromIntError>>()?,
        frames::<core::result::Result<commitment::Digest, commitment::CommitmentError>>()?,
        frames::<p3_goldilocks::Poseidon2Goldilocks<8>>()?,
        // Fixed Poseidon constant/helper storage, source-spec recursive
        // forwarding (maximum four parents), bounded strings and checked-size
        // helper frames. Additive; no slot reuse/inlining/move credit.
        64 << 10,
    ];
    // Measure complete opaque A return layouts from function-item types.
    // These items are not invoked here and introduce no continuation API.
    let external = [
        three_result_bytes(RetiredHashxOuterOriginals::check),
        result_bytes(RetiredHashxOuterOriginals::outer_step),
    ];
    let helper = core::mem::size_of_val(&parts)
        .checked_add(core::mem::size_of_val(&external))
        .and_then(|n| n.checked_mul(8))
        .ok_or(ParentCompileError::Overflow)?;
    let caller = parts.into_iter().try_fold(helper, |sum, part| {
        sum.checked_add(part).ok_or(ParentCompileError::Overflow)
    })?;
    let caller = external.into_iter().try_fold(caller, |sum, part| {
        part.checked_mul(8)
            .and_then(|part| sum.checked_add(part))
            .ok_or(ParentCompileError::Overflow)
    })?;
    let verifier = cpu
        .bytes
        .checked_add(RegisteredVerifier::classified_call_extra_bytes())
        .ok_or(ParentCompileError::Overflow)?;
    let mut requirements = Requirements::single(
        Category::IndependentVerifier,
        Bytes {
            host: u64::try_from(verifier).map_err(|_| ParentCompileError::Overflow)?,
            device: 0,
        },
    );
    requirements
        .add(
            Category::PhaseScratch,
            Bytes {
                host: u64::try_from(caller).map_err(|_| ParentCompileError::Overflow)?,
                device: 0,
            },
        )
        .map_err(|_| ParentCompileError::Overflow)?;
    Ok(requirements)
}
