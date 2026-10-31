//! Runtime descriptors and forwarding shells stay charged after close_planning.
//! Variable proof/compiler/request storage remains in its actual producer owners.
use super::*;
use crate::execution::{retained_resources::{Bytes, Category, Requirements},
    workflow_resources::{PhaseStep, SlotId}};
use crate::graph_tree::owned_parent::{AuxiliaryDependencies, EqualityDependencies};
use std::cell::Ref;
use core::mem::size_of;

pub(crate) fn retained_requirements() -> Result<Requirements> {
    Ok(Requirements::single(Category::RegisteredMetadata, Bytes {
        host: u64::try_from(forwarding_host_bytes()?).map_err(|_| WorkflowError::Overflow)?, device: 0,
    }))
}
fn forwarding_host_bytes() -> Result<usize> {
    macro_rules! shells {
        ($($ty:ty),+ $(,)?) => { [$(
            size_of::<$ty>(), size_of::<Option<$ty>>(),
            size_of::<RefCell<Option<$ty>>>(), size_of::<Ref<'static, Option<$ty>>>(),
            size_of::<RefMut<'static, Option<$ty>>>(),
            size_of::<Result<Ref<'static, Option<$ty>>>>(),
            size_of::<Result<RefMut<'static, Option<$ty>>>>(),
            size_of::<Result<&'static $ty>>(),
            size_of::<Result<&'static CaseOwnerSlot<'static, $ty>>>(),
            size_of::<Result<&'static RefCell<Option<$ty>>>>(),
            size_of::<std::slice::Iter<'static, CaseOwnerSlot<'static, $ty>>>(),
            size_of::<std::slice::Iter<'static, CaseOwnerSlot<'static, RefCell<Option<$ty>>>>>(),
        )+] };
    }
    let shells = shells!(FixedPlanResult<'static>, FixedOuterPlanResult<'static, 'static>,
        FixedCompiledResult<'static>, FixedOuterPreissueResult<'static, 'static, 'static>,
        ParametersPlanResult<'static, 'static>, ParametersPreissueResult<'static, 'static, 'static>,
        AuxiliaryPlanResult<'static, 'static>, AuxiliaryPreissueResult<'static, 'static, 'static>,
        EqualityPlanResult<'static, 'static>, EqualityPreissueResult<'static, 'static, 'static>,
        ParentPlanResult<'static, 'static>, ParentPreissueResult<'static, 'static, 'static>,
        GraphCompiledResult<'static>, GraphOuterResult<'static>,
        ShakeRequestResult<'static>, AesRequestResult<'static>,
        UniformNativeResult<'static>, SparseNativeResult<'static>, TranscriptNativeResult<'static>);
    let mut total = shells.into_iter().chain([
        size_of::<FixedRuntime<'static, 'static, 'static, 'static, 'static>>(),
        size_of::<ParametersRuntime<'static, 'static, 'static, 'static, 'static>>(),
        size_of::<AuxiliaryRuntime<'static, 'static, 'static, 'static, 'static>>(),
        size_of::<EqualityRuntime<'static, 'static, 'static, 'static, 'static>>(),
        size_of::<GraphOutputs<'static, 'static, 'static>>(),
        size_of::<[Option<&ParentOuterOutputs<'static, 'static>>; 43]>(),
        size_of::<[Option<&ParentOuterOutputs<'static, 'static>>; 11]>(),
        size_of::<std::iter::Enumerate<std::slice::Iter<'static, Option<&'static ParentOuterOutputs<'static, 'static>>>>>(),
        size_of::<std::iter::Flatten<std::slice::Iter<'static, Option<&'static ParentOuterOutputs<'static, 'static>>>>>(),
        size_of::<DirectInputs<'static, 'static, 'static>>(),
        size_of::<ParentRuntimes<'static, 'static>>(),
        size_of::<DriverGuard<'static, 'static, 'static>>(), size_of::<InitGuard<'static, 'static>>(),
        size_of::<Result<()>>(), size_of::<Result<PhaseBinding>>(),
        size_of::<(usize, GraphPhase)>(), size_of::<Result<(usize, GraphPhase)>>(),
        size_of::<(usize, usize)>(), size_of::<Result<(usize, usize)>>(),
        size_of::<Result<ProducerRoute>>(), size_of::<Result<usize>>(),
        size_of::<(PhaseBinding, SlotId)>(), size_of::<Result<(PhaseBinding, SlotId)>>(),
        size_of::<PhaseStep>(), size_of::<StepDispatch>(), size_of::<ProducerCounts>(),
        size_of::<bool>(), size_of::<*const ()>(), size_of::<Option<*const ()>>(), size_of::<[usize; 24]>(),
        size_of::<[Option<PhaseBinding>; 6]>(), size_of::<AuxiliaryDependencies>(),
        size_of::<EqualityDependencies>(), size_of::<WorkflowError>(),
        size_of::<std::cell::BorrowError>(), size_of::<std::cell::BorrowMutError>(),
        size_of::<crate::spend_pipeline::full_workflow::fresh_generation::FreshGenerationError>(),
        size_of::<core::result::Result<(), crate::spend_pipeline::full_workflow::fresh_generation::FreshGenerationError>>(),
        size_of::<std::iter::Enumerate<std::iter::Zip<std::slice::Iter<'static, StepDispatch>, std::slice::Iter<'static, PhaseStep>>>>(),
        size_of::<Result<&'static SourceOperationPlan<'static>>>(),
        size_of::<Result<&'static FixedLeafOuterPlan<'static, 'static>>>(),
        size_of::<Result<&'static ParametersPpGraphPlan<'static, 'static>>>(),
        size_of::<Result<&'static AuxiliaryGraphPlan<'static, 'static>>>(),
        size_of::<Result<&'static EqualityGraphPlan<'static, 'static>>>(),
        size_of::<Result<&'static GraphParentPlan<'static, 'static>>>(),
    ]).try_fold(0usize, |sum, part| sum.checked_add(part.checked_mul(8)
        .ok_or(WorkflowError::Overflow)?).ok_or(WorkflowError::Overflow))?;
    // All 32 independently scoped parent descriptors can coexist. They are not
    // charged as a maximum active descriptor or borrowed from planning scratch.
    total = total.checked_add(size_of::<ParentRuntime<'static, 'static, 'static, 'static, 'static>>()
        .checked_mul(32 * 8).ok_or(WorkflowError::Overflow)?).ok_or(WorkflowError::Overflow)?;
    Ok(total)
}
