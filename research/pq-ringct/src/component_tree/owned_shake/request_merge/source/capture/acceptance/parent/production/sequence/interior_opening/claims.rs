//! Independent pre-native interior probe storage and complete caller frames.
//! Existing output/key/compiler/native reservations remain fully additive.
use super::*;
use core::mem::{size_of, size_of_val};

#[cfg(test)]
mod tests;

const FRAME_COPIES: usize = 8;

// Count every supplied layout and the complete arithmetic/census forwarding
// frames. No mutually exclusive path, move, inlining or stack-slot discount.
fn repeated_layout(parts: &[usize]) -> InteriorResult<usize> {
    let controls = size_of_val(parts)
        .checked_add(size_of::<&[usize]>())
        .and_then(|n| n.checked_add(size_of::<std::slice::Iter<'static, usize>>()))
        .and_then(|n| n.checked_add(size_of::<[usize; 16]>()))
        .and_then(|n| n.checked_add(size_of::<Option<usize>>()))
        .and_then(|n| n.checked_add(size_of::<InteriorResult<usize>>()))
        .and_then(|n| n.checked_add(size_of::<InteriorResult<Requirements>>()))
        .ok_or(ParentCompileError::Overflow)?;
    let sum = parts.iter().try_fold(controls, |sum, part| {
        sum.checked_add(*part).ok_or(ParentCompileError::Overflow)
    })?;
    sum.checked_mul(FRAME_COPIES)
        .ok_or(ParentCompileError::Overflow)
}

// This is added to the existing attempt claim under the same module gate,
// including its ordinary None path. It cannot depend on an already-created
// preissued owner, inspect a live state, or subtract another reservation.
pub(super) fn common_forwarding_host_bytes() -> InteriorResult<usize> {
    let parts = [
        size_of::<PreissuedInteriorChildOpening<'static, 'static, 'static>>(),
        size_of::<Option<PreissuedInteriorChildOpening<'static, 'static, 'static>>>(),
        size_of::<InteriorResult<PreissuedInteriorChildOpening<'static, 'static, 'static>>>(),
        size_of::<Result<PreissuedInteriorChildOpening<'static, 'static, 'static>>>(),
        size_of::<&PreissuedInteriorChildOpening<'static, 'static, 'static>>(),
        size_of::<&mut PreissuedInteriorChildOpening<'static, 'static, 'static>>(),
        size_of::<Option<&PreissuedInteriorChildOpening<'static, 'static, 'static>>>(),
        size_of::<Option<&mut PreissuedInteriorChildOpening<'static, 'static, 'static>>>(),
        size_of::<InteriorResult<&PreissuedInteriorChildOpening<'static, 'static, 'static>>>(),
        size_of::<InteriorResult<&mut PreissuedInteriorChildOpening<'static, 'static, 'static>>>(),
        size_of::<Result<&PreissuedInteriorChildOpening<'static, 'static, 'static>>>(),
        size_of::<Result<&mut PreissuedInteriorChildOpening<'static, 'static, 'static>>>(),
        size_of::<RetainedInteriorOpening>(),
        size_of::<Option<RetainedInteriorOpening>>(),
        size_of::<InteriorResult<RetainedInteriorOpening>>(),
        size_of::<&RetainedInteriorOpening>(),
        size_of::<&mut RetainedInteriorOpening>(),
        size_of::<Option<&RetainedInteriorOpening>>(),
        size_of::<Option<&mut RetainedInteriorOpening>>(),
        size_of::<InteriorResult<&RetainedInteriorOpening>>(),
        size_of::<fn(PreissuedInteriorChildOpening<'static, 'static, 'static>) -> RetainedInteriorOpening>(),
        size_of::<InteriorOpeningMeasurements>(),
        size_of::<Option<InteriorOpeningMeasurements>>(),
        size_of::<&InteriorOpeningMeasurements>(),
        size_of::<&mut InteriorOpeningMeasurements>(),
        size_of::<Option<&InteriorOpeningMeasurements>>(),
        size_of::<Option<&mut InteriorOpeningMeasurements>>(),
        size_of::<InteriorResult<InteriorOpeningMeasurements>>(),
        size_of::<InteriorResult<&InteriorOpeningMeasurements>>(),
        size_of::<InteriorResult<&mut InteriorOpeningMeasurements>>(),
        size_of::<Result<&mut InteriorOpeningMeasurements>>(),
        size_of::<InteriorOpeningPlanReport>(),
        size_of::<InteriorResult<InteriorOpeningPlanReport>>(),
        // Existing enclosing layouts also grow. Count them independently of
        // the maintained baseline census, including both transfer outcomes.
        size_of::<Attempt<'static, 'static, 'static, 'static>>(),
        size_of::<Result<Attempt<'static, 'static, 'static, 'static>>>(),
        size_of::<State<'static, 'static, 'static, 'static>>(),
        size_of::<&State<'static, 'static, 'static, 'static>>(),
        size_of::<&mut State<'static, 'static, 'static, 'static>>(),
        size_of::<Component<'static, 'static, 'static>>(),
        size_of::<&Component<'static, 'static, 'static>>(),
        size_of::<core::result::Result<Component<'static, 'static, 'static>, Failure>>(),
        size_of::<Failure>(),
        size_of::<&Failure>(),
        size_of::<Cause>(),
        size_of::<Error>(),
        size_of::<ParentCompileError>(),
        size_of::<Result<()>>(),
        size_of::<AttemptResult<()>>(),
        size_of::<InteriorResult<()>>(),
        size_of::<InteriorResult<usize>>(),
        size_of::<InteriorResult<Requirements>>(),
        size_of::<AcceptedChild<'static, 'static, 'static>>(),
        size_of::<[AcceptedChild<'static, 'static, 'static>; 2]>(),
        size_of::<Result<[AcceptedChild<'static, 'static, 'static>; 2]>>(),
        size_of::<&AcceptedChild<'static, 'static, 'static>>(),
        size_of::<&mut AcceptedChild<'static, 'static, 'static>>(),
        size_of::<(&mut AcceptedChild<'static, 'static, 'static>, &AcceptedChild<'static, 'static, 'static>)>(),
        size_of::<Option<&AcceptedParent<'static, 'static, 'static>>>(),
        size_of::<Option<&CompilerBank<'static, 'static, 'static, 'static>>>(),
        size_of::<&Ledger>(),
        size_of::<Reservation>(),
        size_of::<Requirements>(),
        size_of::<Bytes>(),
        size_of::<Phase>(),
        size_of::<Option<usize>>(),
        size_of::<[usize; 32]>(),
        size_of::<[bool; 16]>(),
        // Complete bounded Option::take/map, conversion, checked-add,
        // ordinary-drop and constructor/refusal forwarding helpers.
        16 << 10,
    ];
    repeated_layout(&parts)
}

pub(super) fn caller_requirement() -> InteriorResult<Requirements> {
    let parts = [
        size_of::<InteriorOpeningAction<'static, 'static, 'static, 'static>>(),
        size_of::<&InteriorOpeningAction<'static, 'static, 'static, 'static>>(),
        size_of::<OpeningMutation<'static, BatchProof<Config>>>(),
        size_of::<InteriorResult<OpeningMutation<'static, BatchProof<Config>>>>(),
        size_of::<&OpeningMutation<'static, BatchProof<Config>>>(),
        size_of::<&mut output::RetainedNodeOutput<'static>>(),
        size_of::<&output::RetainedNodeOutput<'static>>(),
        size_of::<*const output::RetainedNodeOutput<'static>>(),
        size_of::<*const ()>(),
        size_of::<&NodeKey>(),
        size_of::<&mut NodeProof>(),
        size_of::<&mut BatchProof<Config>>(),
        size_of::<&BatchProof<Config>>(),
        size_of::<&RegisteredVerifier>(),
        size_of::<&mut Challenge>(),
        size_of::<Option<&mut Challenge>>(),
        size_of::<Challenge>(),
        size_of::<[[Val; 4]; ROOTS]>(),
        size_of::<&ReservedShakeRequest>(),
        size_of::<&ParentSourceBound<'static, 'static>>(),
        size_of::<&RetiredHashxOuterOriginals<'static>>(),
        size_of::<Option<&RetiredHashxOuterOriginals<'static>>>(),
        size_of::<&AcceptedLeaf<'static, 'static, 'static>>(),
        size_of::<(&AcceptedChild<'static, 'static, 'static>, &AcceptedChild<'static, 'static, 'static>)>(),
        size_of::<(&AcceptedLeaf<'static, 'static, 'static>, &AcceptedLeaf<'static, 'static, 'static>)>(),
        size_of::<LeafAcceptanceReport>(),
        size_of::<&LeafAcceptanceReport>(),
        size_of::<Option<&LeafAcceptanceReport>>(),
        size_of::<InteriorResult<&LeafAcceptanceReport>>(),
        size_of::<Summary>(),
        size_of::<Option<&Summary>>(),
        size_of::<InteriorResult<&Summary>>(),
        size_of::<Retirement>(),
        size_of::<HashxOuterStep>(),
        size_of::<ComponentReport>(),
        size_of::<&Spec>(),
        size_of::<&EndpointContext>(),
        size_of::<&[Val]>(),
        size_of::<[Val; PUBLICS]>(),
        size_of::<[Val; HEADER]>(),
        size_of::<InteriorResult<[Val; HEADER]>>(),
        size_of::<[Val; 8]>(),
        size_of::<[Val; 4]>(),
        size_of::<[u64; 4]>(),
        size_of::<[(usize, [Val; 4]); 3]>(),
        size_of::<[(usize, u64); 6]>(),
        size_of::<std::array::IntoIter<(usize, [Val; 4]), 3>>(),
        size_of::<std::array::IntoIter<(usize, u64), 6>>(),
        size_of::<std::ops::Range<usize>>(),
        size_of::<std::ops::RangeInclusive<u32>>(),
        size_of::<std::slice::Chunks<'static, u64>>(),
        size_of::<std::iter::Enumerate<std::slice::Iter<'static, u64>>>(),
        size_of::<Spec>(),
        size_of::<[Spec; 3]>(),
        size_of::<crate::component_tree::Contract>(),
        size_of::<Kind>(),
        size_of::<crate::shake_air::Descriptor>(),
        size_of::<crate::aes_lane_air::Descriptor>(),
        size_of::<SourceNode>(),
        size_of::<[SourceNode; 2]>(),
        size_of::<InteriorResult<([SourceNode; 2], [Spec; 3])>>(),
        size_of::<InteriorResult<Spec>>(),
        size_of::<crate::component_tree::Result<Spec>>(),
        size_of::<crate::component_tree::Result<crate::component_tree::Contract>>(),
        size_of::<crate::component_tree::Error>(),
        size_of::<CpuEnvelope>(),
        size_of::<InteriorResult<CpuEnvelope>>(),
        size_of::<lattica_prover_p3::block_v2::machine::verifier::batch::shape::RegisteredChildShape>(),
        size_of::<InteriorResult<lattica_prover_p3::block_v2::machine::verifier::batch::shape::RegisteredChildShape>>(),
        size_of::<core::result::Result<usize, ExecutionError>>(),
        size_of::<core::result::Result<Reservation, crate::execution::retained_resources::Error>>(),
        size_of::<core::result::Result<Bytes, crate::execution::retained_resources::Error>>(),
        size_of::<Snapshot>(),
        size_of::<Ledger>(),
        size_of::<RegisteredVerificationFailure>(),
        size_of::<core::result::Result<(), RegisteredVerificationFailure>>(),
        size_of::<String>(),
        size_of::<std::time::Instant>(),
        size_of::<std::time::Duration>(),
        size_of::<[u128; 8]>(),
        size_of::<Option<u128>>(),
        size_of::<Option<u64>>(),
        size_of::<[u64; 8]>(),
        size_of::<core::result::Result<u64, std::num::TryFromIntError>>(),
        size_of::<core::result::Result<commitment::Digest, commitment::CommitmentError>>(),
        size_of::<p3_goldilocks::Poseidon2Goldilocks<8>>(),
        size_of::<std::fmt::Arguments<'static>>(),
        size_of::<std::io::Stderr>(),
        size_of::<std::io::StderrLock<'static>>(),
        size_of::<std::io::Result<()>>(),
        size_of::<[[usize; 3]; 8]>(),
        size_of::<[[u8; 39]; 8]>(),
        size_of::<[[u8; 20]; 8]>(),
        4096,
        // Fixed Poseidon/helper storage, all four source-parent recursion
        // frames, bounded formatting/diagnostic/drop/error helpers. This is
        // additive even to the classified verifier's own bounded diagnostic.
        64 << 10,
    ];
    // Function items supply complete opaque A result layouts without a call,
    // detached owner, visibility expansion, or admission through a new ledger.
    let external = [
        three_result_bytes(RetiredHashxOuterOriginals::check),
        result_bytes(RetiredHashxOuterOriginals::outer_step),
    ];
    let caller = repeated_layout(&parts)?;
    let opaque = repeated_layout(&external)?;
    let host = common_forwarding_host_bytes()?
        .checked_add(caller)
        .and_then(|n| n.checked_add(opaque))
        .ok_or(ParentCompileError::Overflow)?;
    Ok(Requirements::single(
        Category::PhaseScratch,
        Bytes {
            host: u64::try_from(host).map_err(|_| ParentCompileError::Overflow)?,
            device: 0,
        },
    ))
}

pub(super) fn verifier_requirement(cpu: CpuEnvelope) -> InteriorResult<Requirements> {
    // CpuEnvelope is private source-derived state, fixed by the preissued
    // owner's constructor. It covers every supported height, not merely the
    // height observed after a proof has already been generated.
    if cpu.heights != 18 || cpu.bytes == 0 {
        return Err(ParentCompileError::Source);
    }
    let host = cpu
        .bytes
        .checked_add(RegisteredVerifier::classified_call_extra_bytes())
        .ok_or(ParentCompileError::Overflow)?;
    Ok(Requirements::single(
        Category::IndependentVerifier,
        Bytes {
            host: u64::try_from(host).map_err(|_| ParentCompileError::Overflow)?,
            device: 0,
        },
    ))
}
