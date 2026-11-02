use super::*;
pub(super) fn planning_frames() -> OwnedResult<usize> {
    // Construction keeps both the retained plan shells and the temporary
    // operation/caller frames alive. The latter are also explicitly admitted
    // by compiler_requirements and outer::caller_requirements during runtime.
    add(add(retained_planning_frames()?, caller_frames()?)?, planning_claim_frames()?)
}
pub(super) fn retained_planning_frames() -> OwnedResult<usize> {
    [bytes::<GraphParentPlan<'static, 'static>>(8)?, bytes::<GraphNodeSource<'static>>(16)?,
        bytes::<GraphChildSource<'static, 'static>>(16)?, bytes::<GraphSpan>(8)?,
        bytes::<GraphNodeReport>(8)?, bytes::<Requirements>(16)?, bytes::<Sha3_256>(4)?,
        bytes::<[usize; 24]>(8)?, bytes::<OwnedResult<GraphParentPlan<'static, 'static>>>(8)?,
    ].into_iter().try_fold(0, add)
}
// Additional forwarding frames for the outlined, allocation-free original
// validation. They are construction scratch, not one permanent copy per plan.
fn planning_claim_frames() -> OwnedResult<usize> {
    [bytes::<[&Reservation; 2]>(8)?, bytes::<&Ledger>(8)?,
        bytes::<Requirements>(32)?, bytes::<OwnedResult<Requirements>>(16)?,
        bytes::<crate::execution::retained_resources::Snapshot>(8)?,
        bytes::<crate::execution::retained_resources::WorkerAllowance>(8)?,
        bytes::<OwnedResult<()>>(8)?,
    ].into_iter().try_fold(0, add)
}
pub(super) fn caller_frames() -> OwnedResult<usize> {
    [bytes::<OwnedGraphCompiled<'static>>(8)?, bytes::<OwnedGraphNode<'static>>(8)?,
        bytes::<GraphParentCompileOperation<'static, 'static, 'static>>(8)?,
        bytes::<GraphParentOuterOperation<'static, 'static, 'static>>(8)?,
        bytes::<(GraphParentFailure, [Retained<OwnedGraphNode<'static>>; 2])>(8)?,
        bytes::<core::result::Result<GraphParentCompileOperation<'static, 'static, 'static>, (GraphParentFailure, [Retained<OwnedGraphNode<'static>>; 2])>>(8)?,
        bytes::<(GraphParentFailure, Retained<OwnedGraphCompiled<'static>>)>(8)?,
        bytes::<core::result::Result<GraphParentOuterOperation<'static, 'static, 'static>, (GraphParentFailure, Retained<OwnedGraphCompiled<'static>>)>>(8)?,
        bytes::<core::result::Result<PreissuedGraphParentOuter<'static, 'static, 'static>, crate::execution::workflow_resources::WorkflowError>>(8)?,
        bytes::<Retained<OwnedGraphNode<'static>>>(16)?, bytes::<Retained<OwnedGraphCompiled<'static>>>(8)?,
        bytes::<OwnedResult<OwnedGraphCompiled<'static>>>(8)?, bytes::<OwnedResult<OwnedGraphNode<'static>>>(8)?,
        bytes::<ProgramBuilder>(8)?, bytes::<ProofInputs>(8)?, bytes::<Spec>(8)?,
        bytes::<[Wire; PUBLIC_VALUES]>(8)?, bytes::<[[Wire; 4]; 64]>(8)?,
        bytes::<Vec<Wire>>(8)?, bytes::<Vec<Val>>(8)?, bytes::<Vec<[Val; 4]>>(8)?,
        bytes::<[u128; 8]>(8)?, bytes::<Instant>(8)?, bytes::<String>(8)?,
    bytes::<[Requirements; 4]>(8)?, bytes::<[Bytes; 4]>(8)?,
    ].into_iter().try_fold(64 << 10, add)
}
pub(super) fn compiler_requirements(left_rows: usize, right_rows: usize) -> OwnedResult<(Requirements, Requirements)> {
    let storage = PlanningStorage::for_children(PUBLIC_VALUES,
        &[source::registered_shape(left_rows)?, source::registered_shape(right_rows)?],
        source::construction()).map_err(|_| GraphParentFailure::Source)?;
    if storage.auxiliary_peak_bytes > source::AUXILIARY_BYTES { return Err(GraphParentFailure::Capacity); }
    Ok((combine(&[
        requirement(Category::SymbolicCompiler, add(source::PROGRAM_BYTES, bytes::<OwnedGraphCompiled<'static>>(8)?)?)?,
        requirement(Category::CompilerInputs, add(storage.input_backing_bytes, bytes::<Val>(2 * PUBLIC_VALUES)?)?)?,
    ])?, requirement(Category::PhaseScratch, add(storage.auxiliary_peak_bytes, caller_frames()?)?)?))
}

/// Builder tables, operation compaction and packing overlap remain charged
/// until compilation has returned and checked the actual immutable capacity.
/// Only the checked packed program survives in the output reservation.
pub(super) fn packed_compiler_requirements(source: GraphNodeSource<'_>,
    (output, mut scratch): (Requirements, Requirements), construction: usize) -> OwnedResult<(Requirements, Requirements)>
{
    let retained = source.retained_program_host_bytes()?;
    let temporary = construction.saturating_sub(retained);
    let mut packed = Requirements::default();
    for category in Category::ALL {
        let mut value = output.get(category);
        if category == Category::SymbolicCompiler {
            value.host = value.host.checked_sub(temporary as u64).ok_or(GraphParentFailure::Capacity)?;
        }
        packed.add(category, value).map_err(|_| GraphParentFailure::Overflow)?;
    }
    scratch.add(Category::PhaseScratch, Bytes { host: temporary as u64, device: 0 })
        .map_err(|_| GraphParentFailure::Overflow)?;
    Ok((packed, scratch))
}
pub(super) fn failure_requirements() -> OwnedResult<Requirements> {
    use crate::execution::workflow_resources::{OuterOwnedError, PhaseFailure};
    requirement(Category::Report, [bytes::<GraphParentFailure>(16)?,
        bytes::<PhaseFailure<GraphParentFailure>>(8)?, bytes::<OuterOwnedError>(16)?,
        bytes::<PhaseFailure<OuterOwnedError>>(8)?,
    ].into_iter().try_fold(0, add)?)
}

#[cfg(test)]
mod tests;
