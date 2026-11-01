//! Added complete enclosing ownership/caller frames; never shared payload quota.
use lattica_prover_p3::block_v2::machine::backend::identity_cpu::RegistrationReports;
use super::*;

fn frames<T>() -> Result<usize> {
    size_of::<T>().checked_mul(8).ok_or(Error::Shape)
}

fn unsafe_two_result_bytes<A, B, O>(_: unsafe fn(A, B) -> O) -> usize {
    size_of::<O>()
}

fn unsafe_four_result_bytes<A, B, C, D, O>(_: unsafe fn(A, B, C, D) -> O) -> usize {
    size_of::<O>()
}

fn four_result_bytes<A, B, C, D, O>(_: fn(A, B, C, D) -> O) -> usize {
    size_of::<O>()
}

pub(super) fn attempt_requirement() -> Result<Requirements> {
    let parts = [
        frames::<Attempt<'static, 'static, 'static, 'static>>()?,
        frames::<Result<Attempt<'static, 'static, 'static, 'static>>>()?,
        frames::<State<'static, 'static, 'static, 'static>>()?,
        frames::<Component<'static, 'static, 'static>>()?,
        frames::<core::result::Result<Component<'static, 'static, 'static>, Failure>>()?,
        frames::<Failure>()?,
        frames::<Cause>()?,
        frames::<bank::Failure>()?,
        frames::<AttemptResult<()>>()?,
        frames::<FutureLeaf<'static, 'static, 'static>>()?,
        frames::<Result<FutureLeaf<'static, 'static, 'static>>>()?,
        frames::<FirstProducer<'static, 'static, 'static>>()?,
        frames::<Option<FirstProducer<'static, 'static, 'static>>>()?,
        frames::<LeafCompletion<'static, 'static, 'static>>()?,
        frames::<Result<LeafCompletion<'static, 'static, 'static>>>()?,
        frames::<Support<'static>>()?,
        frames::<[Option<Support<'static>>; OUTER]>()?,
        frames::<[Option<FutureLeaf<'static, 'static, 'static>>; LEAVES]>()?,
        frames::<[Option<FutureHashxParent<'static, 'static, 'static>>; PARENTS]>()?,
        frames::<[Option<PreissuedHashxParent<'static, 'static, 'static>>; PARENTS]>()?,
        frames::<Result<FutureHashxParent<'static, 'static, 'static>>>()?,
        frames::<
            Result<(
                PreissuedHashxParent<'static, 'static, 'static>,
                PreissuedOuterBackend,
            )>,
        >()?,
        frames::<(
            PreissuedHashxParent<'static, 'static, 'static>,
            PreissuedOuterBackend,
        )>()?,
        frames::<AcceptedHashxParentCompletion<'static, 'static, 'static>>()?,
        frames::<Result<AcceptedHashxParentCompletion<'static, 'static, 'static>>>()?,
        frames::<[Option<AcceptedLeaf<'static, 'static, 'static>>; LEAVES]>()?,
        frames::<[Option<AcceptedParent<'static, 'static, 'static>>; PARENTS]>()?,
        frames::<AcceptedChild<'static, 'static, 'static>>()?,
        frames::<[AcceptedChild<'static, 'static, 'static>; 2]>()?,
        frames::<Result<[AcceptedChild<'static, 'static, 'static>; 2]>>()?,
        frames::<(
            AcceptedChild<'static, 'static, 'static>,
            AcceptedChild<'static, 'static, 'static>,
        )>()?,
        frames::<CompilerBank<'static, 'static, 'static, 'static>>()?,
        frames::<Option<CompilerBank<'static, 'static, 'static, 'static>>>()?,
        frames::<
            core::result::Result<
                CompilerBank<'static, 'static, 'static, 'static>,
                ParentCompileError,
            >,
        >()?,
        frames::<BankedLeaf<'static, 'static, 'static, 'static>>()?,
        frames::<
            core::result::Result<BankedLeaf<'static, 'static, 'static, 'static>, bank::Failure>,
        >()?,
        frames::<BankedParent<'static, 'static, 'static, 'static>>()?,
        frames::<
            core::result::Result<
                BankedParent<'static, 'static, 'static, 'static>,
                ParentCompileError,
            >,
        >()?,
        frames::<[&GroupCompilePlan<'static>; LEAVES]>()?,
        frames::<[Option<ReservedNativeChild<'static>>; NATIVE]>()?,
        frames::<[Option<ReservedNativeChild<'static>>; 2]>()?,
        frames::<Result<[Option<ReservedNativeChild<'static>>; 2]>>()?,
        frames::<Option<ReservedNativeChild<'static>>>()?,
        frames::<PendingNativeHashx<'static>>()?,
        frames::<Option<PendingNativeHashx<'static>>>()?,
        frames::<PreparedNativeHashx<'static>>()?,
        frames::<Option<PreparedNativeHashx<'static>>>()?,
        frames::<CompletedNativeHashx<'static>>()?,
        frames::<PreissuedHashxOuter<'static>>()?,
        frames::<RetiredHashxOuter<'static>>()?,
        frames::<PreparedHashxOuter<'static, 'static>>()?,
        frames::<ActiveHashxOuter<'static, 'static>>()?,
        frames::<RetiredHashxOuterOriginals<'static>>()?,
        frames::<Option<RetiredHashxOuterOriginals<'static>>>()?,
        frames::<[Option<PreissuedOuterBackend>; OUTER]>()?,
        frames::<[PreissuedOuterBackend; OUTER - 1]>()?,
        frames::<Result<PreissuedOuterBackend>>()?,
        frames::<[Phase; OUTER]>()?,
        frames::<[HashxOuterStep; OUTER]>()?,
        frames::<ComponentReport>()?,
        frames::<[Option<Summary>; LEAVES]>()?,
        frames::<[u128; LEAVES]>()?,
        frames::<[Option<LeafAcceptanceReport>; LEAVES]>()?,
        frames::<[Option<LeafParentCompilationReport>; PARENTS]>()?,
        frames::<[Option<ParentAcceptanceReport>; PARENTS]>()?,
        frames::<Summary>()?,
        frames::<LeafAcceptanceReport>()?,
        frames::<ParentAcceptanceReport>()?,
        frames::<LeafParentCompilationReport>()?,
        frames::<Phase>()?,
        frames::<HashxOuterStep>()?,
        frames::<OuterContinuationCapacity>()?,
        frames::<OuterSourceShape>()?,
        frames::<crate::component_tree::owned_shake::source_shape::Geometry>()?,
        frames::<core::result::Result<(), crate::component_tree::owned_shake::source_shape::Error>>(
        )?,
        frames::<OuterSourceEnvelope>()?,
        frames::<RegisteredGpuLimits>()?,
        frames::<PreissuedLeafAcceptance<'static, 'static, 'static>>()?,
        frames::<
            core::result::Result<
                PreissuedLeafAcceptance<'static, 'static, 'static>,
                ParentCompileError,
            >,
        >()?,
        frames::<CapturedLeafAcceptance<'static, 'static, 'static, 'static>>()?,
        frames::<
            core::result::Result<
                CapturedLeafAcceptance<'static, 'static, 'static, 'static>,
                ParentCompileError,
            >,
        >()?,
        frames::<core::result::Result<AcceptedLeaf<'static, 'static, 'static>, ParentCompileError>>(
        )?,
        frames::<output::PreissuedOutput<'static, 'static, 'static>>()?,
        frames::<
            core::result::Result<output::PreissuedOutput<'static, 'static, 'static>, output::Error>,
        >()?,
        frames::<output::OutputClaim<'static, 'static, 'static>>()?,
        frames::<
            core::result::Result<output::OutputClaim<'static, 'static, 'static>, output::Error>,
        >()?,
        frames::<output::RetainedNodeOutput<'static>>()?,
        frames::<core::result::Result<output::RetainedNodeOutput<'static>, output::Error>>()?,
        frames::<(
            output::RetainedNodeOutput<'static>,
            CapturedLeafAcceptance<'static, 'static, 'static, 'static>,
        )>()?,
        frames::<
            Result<(
                output::RetainedNodeOutput<'static>,
                CapturedLeafAcceptance<'static, 'static, 'static, 'static>,
            )>,
        >()?,
        frames::<RegisteredProgram>()?,
        frames::<(RegisteredProgram, RegistrationReports)>()?,
        frames::<core::result::Result<(RegisteredProgram, RegistrationReports), AdmissionError>>()?,
        frames::<(BatchProof<Config>, Report)>()?,
        frames::<core::result::Result<(BatchProof<Config>, Report), ExecutionError>>()?,
        frames::<NodeKey>()?,
        frames::<NodeProof>()?,
        frames::<Report>()?,
        frames::<RegistrationReports>()?,
        frames::<&Report>()?,
        frames::<Option<&Report>>()?,
        frames::<Request>()?,
        frames::<Retirement>()?,
        frames::<Ledger>()?,
        frames::<Reservation>()?,
        frames::<Requirements>()?,
        frames::<Result<Requirements>>()?,
        frames::<Snapshot>()?,
        frames::<Bytes>()?,
        frames::<Result<()>>()?,
        frames::<core::result::Result<(), ParentCompileError>>()?,
        frames::<core::result::Result<(), String>>()?,
        frames::<std::time::Instant>()?,
        frames::<&OwnedCompiledShake<'static>>()?,
        frames::<&CompiledLeafParent<'static, 'static, 'static>>()?,
        frames::<&ParentSourceBound<'static, 'static>>()?,
        frames::<&GroupSourceBound<'static>>()?,
        frames::<&GroupCompilePlan<'static>>()?,
        frames::<&mut State<'static, 'static, 'static, 'static>>()?,
        frames::<Option<&ReservedNativeChild<'static>>>()?,
        frames::<std::array::IntoIter<Phase, OUTER>>()?,
        frames::<std::iter::Skip<std::array::IntoIter<Phase, OUTER>>>()?,
        frames::<std::iter::Enumerate<std::iter::Copied<std::slice::Iter<'static, Phase>>>>()?,
        frames::<
            std::iter::Enumerate<
                std::slice::IterMut<'static, Option<ReservedNativeChild<'static>>>,
            >,
        >()?,
        frames::<
            std::iter::Enumerate<std::slice::Iter<'static, &'static GroupCompilePlan<'static>>>,
        >()?,
        frames::<std::slice::Iter<'static, Option<AcceptedLeaf<'static, 'static, 'static>>>>()?,
        frames::<std::slice::Iter<'static, Option<AcceptedParent<'static, 'static, 'static>>>>()?,
        frames::<[usize; 32]>()?,
        frames::<[bool; 16]>()?,
        #[cfg(test)]
        frames::<refusal::Probe>()?,
        #[cfg(test)]
        frames::<Option<refusal::Probe>>()?,
        #[cfg(test)]
        frames::<(usize, usize, usize)>()?,
        #[cfg(test)]
        frames::<&State<'static, 'static, 'static, 'static>>()?,
        #[cfg(test)]
        frames::<std::slice::Iter<'static, Option<ReservedNativeChild<'static>>>>()?,
        #[cfg(test)]
        frames::<std::slice::Iter<'static, Option<Support<'static>>>>()?,
        #[cfg(test)]
        frames::<std::slice::Iter<'static, Option<PreissuedHashxParent<'static, 'static, 'static>>>>(
        )?,
    ];
    // Function items are never executed. Count complete private Result layouts
    // from A without weakening the opacity of its lifecycle/error types.
    let external = [
        two_result_bytes(PendingNativeHashx::reserve_before_native),
        result_bytes(PendingNativeHashx::with_outer_sequence),
        unsafe_result_bytes(PendingNativeHashx::prepare),
        three_result_bytes(PreparedNativeHashx::check_outer_request),
        result_bytes(PreparedNativeHashx::outer_continuation_capacity),
        two_result_bytes(PreparedNativeHashx::bind_outer_backend),
        two_result_bytes(PreissuedHashxOuter::with_successors),
        unsafe_two_result_bytes(PreparedNativeHashx::produce_for_outer),
        three_result_bytes(CompletedNativeHashx::take_next_child),
        two_result_bytes(PreissuedHashxOuter::finish_native),
        unsafe_four_result_bytes(RetiredHashxOuter::bind),
        bind_result_bytes(RetiredHashxOuterOriginals::bind_successor),
        three_result_bytes(RetiredHashxOuterOriginals::check),
        result_bytes(RetiredHashxOuterOriginals::outer_step),
        unsafe_result_bytes(PreparedHashxOuter::start),
        result_bytes(ActiveHashxOuter::finish),
        three_result_bytes(OuterSourceEnvelope::inspect),
        four_result_bytes(OuterSourceShape::owned_shake),
        result_bytes(OuterSourceEnvelope::preissue),
        two_result_bytes(crate::opencl::Session::check_reserved_runtime),
    ];
    let helper = core::mem::size_of_val(&parts)
        .checked_add(core::mem::size_of_val(&external))
        .and_then(|n| n.checked_mul(8))
        .and_then(|n| n.checked_add(64 << 10))
        .ok_or(Error::Shape)?;
    let host = parts.into_iter().try_fold(helper, |sum, part| {
        sum.checked_add(part).ok_or(Error::Shape)
    })?;
    let host = external.into_iter().try_fold(host, |sum, part| {
        sum.checked_add(part.checked_mul(8).ok_or(Error::Shape)?)
            .ok_or(Error::Shape)
    })?;
    // Explicit shared forwarding census also covers the default None path.
    #[cfg(all(test, feature = "owned-native-shake", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
    let host = host.checked_add(
        super::interior_opening::common_forwarding_host_bytes().map_err(|_| Error::Shape)?
    ).ok_or(Error::Shape)?;
    Ok(Requirements::single(
        Category::PhaseScratch,
        Bytes {
            host: u64::try_from(host).map_err(|_| Error::Shape)?,
            device: 0,
        },
    ))
}
