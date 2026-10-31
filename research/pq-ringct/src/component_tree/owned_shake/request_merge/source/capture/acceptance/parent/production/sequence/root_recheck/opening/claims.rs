//! Additive fixed caller storage. The existing root claim keeps the complete
//! all-height CPU verifier lifecycle and classified-call increment as well.
use super::*;
use core::mem::{size_of, size_of_val};

fn frames<T>() -> RecheckResult<usize> {
    size_of::<T>().checked_mul(8).ok_or(ParentCompileError::Overflow)
}

pub(super) fn additional_requirement() -> RecheckResult<Requirements> {
    let parts = [
        frames::<PreissuedRootOpening<'static, 'static, 'static>>()?,
        frames::<RecheckResult<PreissuedRootOpening<'static, 'static, 'static>>>()?,
        frames::<RetainedRootOpeningReport<'static, 'static, 'static>>()?,
        frames::<RecheckResult<RetainedRootOpeningReport<'static, 'static, 'static>>>()?,
        frames::<RootOpeningPlanReport>()?,
        frames::<RecheckResult<RootOpeningPlanReport>>()?,
        frames::<RootOpeningMeasurements>()?,
        frames::<RecheckResult<RootOpeningMeasurements>>()?,
        frames::<RootOpeningRecheckAction<'static, 'static, 'static, 'static>>()?,
        frames::<OpeningMutation<'static, BatchProof<Config>>>()?,
        frames::<RecheckResult<OpeningMutation<'static, BatchProof<Config>>>>()?,
        frames::<&RootOpeningRecheckAction<'static, 'static, 'static, 'static>>()?,
        frames::<&PreissuedRootOpening<'static, 'static, 'static>>()?,
        frames::<&RetainedRootOpeningReport<'static, 'static, 'static>>()?,
        frames::<&RootOpeningMeasurements>()?,
        frames::<RecheckResult<&RootOpeningMeasurements>>()?,
        frames::<&mut AcceptedChild<'static, 'static, 'static>>()?,
        frames::<&mut output::RetainedNodeOutput<'static>>()?,
        frames::<&mut NodeProof>()?,
        frames::<&mut BatchProof<Config>>()?,
        frames::<&BatchProof<Config>>()?,
        frames::<&mut Challenge>()?,
        frames::<Option<&mut Challenge>>()?,
        frames::<Challenge>()?,
        frames::<[[Val; 4]; ROOTS]>()?,
        frames::<*const ()>()?,
        frames::<*const output::RetainedNodeOutput<'static>>()?,
        frames::<&NodeKey>()?,
        frames::<&RegisteredVerifier>()?,
        frames::<&ReservedShakeRequest>()?,
        frames::<&Ledger>()?,
        frames::<Requirements>()?,
        frames::<RecheckResult<Requirements>>()?,
        frames::<Reservation>()?,
        frames::<core::result::Result<Reservation, crate::execution::retained_resources::Error>>()?,
        frames::<Bytes>()?,
        frames::<RegisteredVerificationFailure>()?,
        frames::<core::result::Result<(), RegisteredVerificationFailure>>()?,
        frames::<ParentCompileError>()?,
        frames::<RecheckResult<()>>()?,
        frames::<RecheckResult<usize>>()?,
        frames::<std::time::Instant>()?,
        frames::<u128>()?,
        frames::<Option<u128>>()?,
        frames::<[usize; 32]>()?,
        frames::<[u64; 8]>()?,
        frames::<[bool; 8]>()?,
        // Fixed helper/checked-arithmetic/drop forwarding and bounded
        // diagnostic overlap; no reuse, inlining or exclusive-branch credit.
        64 << 10,
    ];
    let helper = size_of_val(&parts).checked_mul(8).ok_or(ParentCompileError::Overflow)?;
    let host = parts.into_iter().try_fold(helper, |sum, part| {
        sum.checked_add(part).ok_or(ParentCompileError::Overflow)
    })?;
    Ok(Requirements::single(
        Category::PhaseScratch,
        Bytes { host: u64::try_from(host).map_err(|_| ParentCompileError::Overflow)?, device: 0 },
    ))
}
