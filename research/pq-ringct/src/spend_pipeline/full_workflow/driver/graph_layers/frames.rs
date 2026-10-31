use super::*;
use crate::graph_tree::owned_parent::GraphParentFailure;

/// Root adds this simultaneous caller census to the metadata construction
/// scratch before invoking any fixed/direct/parent driver function.
pub(crate) fn requirements() -> Result<Requirements> {
    let bytes = [
        stage_frame_bytes(),
        size_of::<Guard<'static, 'static>>(),
        size_of::<DirectDependencies<'static, 'static, 'static, 'static>>(),
        size_of::<DirectPlanTables<'static, 'static, 'static, 'static>>(),
        size_of::<LeafViews<'static, 'static>>(), size_of::<PriorParentLevels<'static, 'static>>(),
        size_of::<[Option<GraphChildSource<'static, 'static>>; 4]>(),
        size_of::<[GraphChildSource<'static, 'static>; 2]>(),
        size_of::<Result<GraphChildSource<'static, 'static>>>(),
        size_of::<core::result::Result<GraphChildSource<'static, 'static>, GraphParentFailure>>(),
        size_of::<MetadataMember<'static, 'static>>(), size_of::<Result<MetadataMember<'static, 'static>>>(),
        size_of::<AuxiliaryGraphSources<'static, 'static>>(),
        size_of::<Result<AuxiliaryGraphSources<'static, 'static>>>(),
        size_of::<AuxiliaryPreparedInventory<'static>>(),
        size_of::<core::result::Result<AuxiliaryPreparedInventory<'static>, GraphParentFailure>>(),
        size_of::<[&PreparedWorkflowSources<'static>; 8]>(),
        size_of::<[&SourceMetadataPlanningPlan<'static>; 8]>(), size_of::<[&CaseRetirementState; 8]>(),
        size_of::<[&OuterProofCache; 4]>(), size_of::<[&Ledger; 4]>(), size_of::<[&Request; 8]>(),
        size_of::<[&crate::graph_auxiliary::AuxiliaryRequest; 8]>(),
        size_of::<Result<&Request>>(), size_of::<Result<&crate::graph_auxiliary::AuxiliaryRequest>>(),
        size_of::<[usize; 256]>(), size_of::<[Requirements; 4]>(),
        size_of::<Result<()>>(), size_of::<Result<usize>>(), size_of::<Result<(usize, usize)>>(),
        size_of::<crate::graph_auxiliary::Role>(), size_of::<AuxiliaryGraphKind>(),
        size_of::<String>(), 128,
        size_of::<table::FixedPlanResult<'static>>(),
        size_of::<table::FixedOuterPlanResult<'static, 'static>>(),
        size_of::<Result<table::FixedOuterPlanResult<'static, 'static>>>(),
        size_of::<table::ParametersPlanResult<'static, 'static>>(),
        size_of::<Result<table::ParametersPlanResult<'static, 'static>>>(),
        size_of::<table::AuxiliaryPlanResult<'static, 'static>>(),
        size_of::<Result<table::AuxiliaryPlanResult<'static, 'static>>>(),
        // Auxiliary diagnostic helper: original slot and result references,
        // borrowed error, copied fixed cause and temporary mapped Results.
        size_of::<GraphParentFailure>(), size_of::<&GraphParentFailure>(),
        size_of::<WorkflowError>(),
        size_of::<&CaseOwnerSlot<'static, table::AuxiliaryPlanResult<'static, 'static>>>(),
        size_of::<&table::AuxiliaryPlanResult<'static, 'static>>(),
        size_of::<core::result::Result<&table::AuxiliaryPlanResult<'static, 'static>,
            crate::spend_pipeline::full_workflow::fresh_generation::FreshGenerationError>>(),
        size_of::<Result<&table::AuxiliaryPlanResult<'static, 'static>>>(),
        size_of::<core::result::Result<&crate::graph_tree::owned_parent::AuxiliaryGraphPlan<'static, 'static>,
            &GraphParentFailure>>(),
        size_of::<Result<&crate::graph_tree::owned_parent::AuxiliaryGraphPlan<'static, 'static>>>(),
        size_of::<table::EqualityPlanResult<'static, 'static>>(),
        size_of::<Result<table::EqualityPlanResult<'static, 'static>>>(),
        size_of::<table::ParentPlanResult<'static, 'static>>(),
        size_of::<Result<table::ParentPlanResult<'static, 'static>>>(),
    ].into_iter().try_fold(0usize, |sum, bytes| sum.checked_add(bytes))
        .and_then(|sum| sum.checked_mul(8)).ok_or(WorkflowError::Overflow)?;
    Ok(Requirements::single(Category::PhaseScratch, Bytes {
        host: u64::try_from(bytes).map_err(|_| WorkflowError::Overflow)?, device: 0,
    }))
}
