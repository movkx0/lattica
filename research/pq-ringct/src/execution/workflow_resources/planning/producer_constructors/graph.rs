//! Concrete graph constructors retain independent source/cache lifetimes.
//! Constructor authorization uses the original metadata/member lifetimes.
//! Only immutable payload borrows may shorten into the concrete output graph.
use super::*;
use crate::{graph_crypto::{OuterProofCache, PairedRequestPlan},
    graph_tree::owned_parent::{FixedLeafOuterPlan, EqualityGraphPlan, ParametersPpGraphPlan,
        AuxiliaryGraphPlan, AuxiliaryGraphSources, AuxiliaryPreparedInventory, GraphParentPlan,
        GraphChildSource, GraphParentFailure},
    spend_pipeline::full_workflow::{SourceOperationPlan, metadata_tables::graph as table}};

pub(super) fn requirements() -> Result<Requirements, WorkflowError> {
    scratch_frames(&[size_of::<MetadataMember<'static, 'static>>(),
        size_of::<[GraphChildSource<'static, 'static>; 2]>(),
        size_of::<AuxiliaryGraphSources<'static, 'static>>(),
        size_of::<AuxiliaryPreparedInventory<'static>>(),
        size_of::<Result<AuxiliaryPreparedInventory<'static>, GraphParentFailure>>(),
        size_of::<table::FixedPlanResult<'static>>(),
        size_of::<table::FixedOuterPlanResult<'static, 'static>>(),
        size_of::<Result<table::FixedOuterPlanResult<'static, 'static>, WorkflowError>>(),
        size_of::<table::EqualityPlanResult<'static, 'static>>(),
        size_of::<Result<table::EqualityPlanResult<'static, 'static>, WorkflowError>>(),
        size_of::<table::ParametersPlanResult<'static, 'static>>(),
        size_of::<Result<table::ParametersPlanResult<'static, 'static>, WorkflowError>>(),
        size_of::<table::AuxiliaryPlanResult<'static, 'static>>(),
        size_of::<Result<table::AuxiliaryPlanResult<'static, 'static>, WorkflowError>>(),
        size_of::<table::ParentPlanResult<'static, 'static>>(),
        size_of::<Result<table::ParentPlanResult<'static, 'static>, WorkflowError>>(),
        size_of::<[Requirements; 8]>(), size_of::<[Reservation; 2]>(),
        size_of::<Result<Requirements, GraphParentFailure>>(),
        size_of::<Result<Requirements, WorkflowError>>(),
        size_of::<Result<Reservation, crate::execution::retained_resources::Error>>(),
        size_of::<[usize; 8]>(), size_of::<[&SourceMetadataPlanningPlan<'static>; 8]>()])
}

impl WorkflowPlanning<'_> {
    fn check_graph_constructor_scratch(&self, inner: Requirements) -> Result<(), WorkflowError> {
        if !super::super::super::types::contains(self.scratch.requirements(), sum(inner, requirements()?)?) {
            return Err(WorkflowError::Planning);
        }
        Ok(())
    }

    pub(crate) fn derive_metadata_fixed<'metadata, 'source, 'a>(&mut self,
        plan: &SourceMetadataPlanningPlan<'metadata>, member: MetadataMember<'_, 'metadata>,
        compiler: &'source SourceOperationPlan<'a>, cache: &'source OuterProofCache)
        -> Result<table::FixedOuterPlanResult<'source, 'a>, WorkflowError>
    {
        self.begin_metadata_constructor(plan, member, ProducerFamily::Fixed, 0, 0)?;
        if !core::ptr::eq(compiler.sources(), member.prepared())
            || !core::ptr::eq(compiler.context(), plan.context())
        { return Err(WorkflowError::Identity); }
        self.check_graph_constructor_scratch(Requirements::default())?;
        let required = FixedLeafOuterPlan::planning_requirements().map_err(|_| WorkflowError::Planning)?;
        let original = self.original.split(required)?;
        let result = FixedLeafOuterPlan::derive_pre_reserved(compiler, cache, original, self.capability.ledger());
        if result.is_ok() { self.finish_metadata_constructor_success(); }
        Ok(result)
    }

    pub(crate) fn derive_metadata_equality<'metadata: 'a, 'source, 'a>(&mut self,
        plan: &SourceMetadataPlanningPlan<'metadata>, member: MetadataMember<'_, 'metadata>,
        ordinal: usize, cache: &'source OuterProofCache)
        -> Result<table::EqualityPlanResult<'source, 'a>, WorkflowError>
    {
        self.begin_metadata_constructor(plan, member, ProducerFamily::Equality, ordinal, 0)?;
        self.check_graph_constructor_scratch(EqualityGraphPlan::planning_scratch_requirements()
            .map_err(|_| WorkflowError::Planning)?)?;
        let required = EqualityGraphPlan::planning_requirements().map_err(|_| WorkflowError::Planning)?;
        let original = self.original.split(required)?;
        let result = EqualityGraphPlan::derive_pre_reserved(plan.scope(), member.prepared(), ordinal,
            cache, original, &self.scratch, self.capability.ledger());
        if result.is_ok() { self.finish_metadata_constructor_success(); }
        Ok(result)
    }

    pub(crate) fn derive_metadata_parameters<'metadata: 'a, 'source, 'a>(&mut self,
        plan: &SourceMetadataPlanningPlan<'metadata>, member: MetadataMember<'_, 'metadata>,
        ordinal: usize, request: &'source PairedRequestPlan<'a>, cache: &'source OuterProofCache)
        -> Result<table::ParametersPlanResult<'source, 'a>, WorkflowError>
    {
        self.begin_metadata_constructor(plan, member, ProducerFamily::Parameters, ordinal, 0)?;
        self.check_graph_constructor_scratch(ParametersPpGraphPlan::planning_scratch_requirements()
            .map_err(|_| WorkflowError::Planning)?)?;
        let required = ParametersPpGraphPlan::planning_requirements().map_err(|_| WorkflowError::Planning)?;
        let original = self.original.split(required)?;
        let result = ParametersPpGraphPlan::derive_pre_reserved(plan.scope(), member.prepared(), request,
            ordinal, cache, original, &self.scratch, self.capability.ledger());
        if result.is_ok() { self.finish_metadata_constructor_success(); }
        Ok(result)
    }

    pub(crate) fn derive_metadata_auxiliary<'metadata: 'a, 'source, 'a>(&mut self,
        plan: &SourceMetadataPlanningPlan<'metadata>, member: MetadataMember<'_, 'metadata>, ordinal: usize,
        sources: AuxiliaryGraphSources<'source, 'a>, cache: &'source OuterProofCache)
        -> Result<table::AuxiliaryPlanResult<'source, 'a>, WorkflowError>
    {
        self.begin_metadata_constructor(plan, member, ProducerFamily::Auxiliary, ordinal, 0)?;
        self.check_graph_constructor_scratch(AuxiliaryPreparedInventory::inspection_requirements()
            .map_err(|_| WorkflowError::Planning)?)?;
        let source: AuxiliaryPreparedInventory<'a> = AuxiliaryPreparedInventory::new(member.prepared(), ordinal)
            .map_err(|_| WorkflowError::Identity)?;
        source.validate_plans(sources, plan.context()).map_err(|_| WorkflowError::Identity)?;
        self.check_graph_constructor_scratch(source.planning_scratch_requirements()
            .map_err(|_| WorkflowError::Planning)?)?;
        let required = AuxiliaryGraphPlan::planning_requirements().map_err(|_| WorkflowError::Planning)?;
        let original = self.original.split(required)?;
        let result = AuxiliaryGraphPlan::derive_pre_reserved(plan.scope(), member.prepared(), sources,
            ordinal, cache, original, &self.scratch, self.capability.ledger());
        if result.is_ok() { self.finish_metadata_constructor_success(); }
        Ok(result)
    }

    pub(crate) fn derive_metadata_parent<'metadata, 'source, 'a>(&mut self,
        plan: &SourceMetadataPlanningPlan<'metadata>, level: usize, ordinal: usize,
        children: [GraphChildSource<'source, 'a>; 2], cache: &'source OuterProofCache)
        -> Result<table::ParentPlanResult<'source, 'a>, WorkflowError>
    {
        self.begin_metadata_parent(plan, level, ordinal)?;
        self.check_graph_constructor_scratch(GraphParentPlan::planning_scratch_requirements()
            .map_err(|_| WorkflowError::Planning)?)?;
        let required = GraphParentPlan::planning_requirements().map_err(|_| WorkflowError::Planning)?;
        let original = self.original.split(required)?;
        let result = GraphParentPlan::derive_pre_reserved(children, cache, original,
            &self.scratch, self.capability.ledger());
        if result.is_ok() { self.finish_metadata_constructor_success(); }
        Ok(result)
    }
}
