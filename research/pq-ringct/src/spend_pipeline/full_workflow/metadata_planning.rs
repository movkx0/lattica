//! Original-source producer construction budget, distinct from complete closure.
//! No proof, producer binding, final schedule, or execution permit is issued.
use super::{PreparedWorkflowSources, SourcePlanningPlan, SourceClosurePlanningPlan,
    ClosureError, ClosureInspection, closure_planning::{add, mul, sum, maximum, contains, host}};
use crate::{execution::{retained_resources::{Bytes, Category, Ledger, Requirements, Reservation},
        workflow_resources::SourceRetained, ProvingContext},
    graph_crypto::{OwnedAesRequestPlan, PairedRequestPlan, RequestDescriptor},
    graph_proofs::ComponentKind,
    graph_tree::{LeafKind, OperationFamily, owned_parent::{AuxiliaryPreparedInventory,
        EqualityGraphPlan, ParametersPpGraphPlan, FixedLeafOuterPlan, GraphParentPlan}},
    ordered_aggregation::{source::FinalAggregationPlan, owned_final::FinalPhasePlan}};
use core::mem::size_of;
type Result<T> = core::result::Result<T, ClosureError>;
mod providers;
mod tables;
mod inspection;
mod positions;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(usize)]
pub(crate) enum ProducerFamily {
    Source, Uniform, Sparse, Transcript, Affine, Ntt, Mul, GBound,
    Permutation, LinearMap, Fixed, Parameters, Auxiliary, Equality, Shake, Aes,
}
/// Fixed diagnostic position only. This carries no source, reservation, or
/// dispatch authority and never substitutes for the returned planning Result.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MetadataPlanningStage {
    Readiness,
    BootstrapContainment,
    ClosureInspection,
    SourceInspection,
    SourceFamily(ProducerFamily),
    SourceParents,
    SourceFinal,
    SourceStepCounts,
    Tables,
    RetainedPlan,
    TableTransfers,
    RetainedMetadata,
    RetainedConstructors,
    CompleteSlot,
    CompleteMetadata,
    CompleteInspection,
    ConstructorScratch,
    ControllerMetadata,
    Envelope,
    Complete,
}
const FAMILIES: usize = 16;
const LEVELS: usize = 32;

#[derive(Clone, Copy, Default)]
pub(crate) struct ProducerCounts {
    families: [usize; FAMILIES],
    parent_levels: [usize; LEVELS],
    shake_native: usize,
    shake_recursive: usize,
    aes_native: usize,
    aes_recursive: usize,
    steps: usize,
}
impl ProducerCounts {
    pub(crate) fn family(self, family: ProducerFamily) -> usize { self.families[family as usize] }
    pub(crate) fn parent_level(self, level: usize) -> Option<usize> { self.parent_levels.get(level).copied() }
    pub(crate) fn steps(self) -> usize { self.steps }
    pub(crate) fn shake_native(self) -> usize { self.shake_native }
    pub(crate) fn shake_recursive(self) -> usize { self.shake_recursive }
    pub(crate) fn aes_native(self) -> usize { self.aes_native }
    pub(crate) fn aes_recursive(self) -> usize { self.aes_recursive }
    fn add(&mut self, family: ProducerFamily, count: usize) -> Result<()> {
        self.families[family as usize] = add(self.family(family), count)?;
        Ok(())
    }
}

#[derive(Clone, Copy)]
struct ProducerRequirements { original: Requirements, construction: Requirements }

/// Exact original member references make counts observations of immutable
/// sources. They cannot be used to attach another source with equal geometry.
pub(crate) struct SourceMetadataPlanningPlan<'a> {
    scope: &'a SourcePlanningPlan<'a>,
    members: &'a [&'a SourceRetained<PreparedWorkflowSources<'a>>],
    ledger: Ledger,
    counts: ProducerCounts,
    inspection: ClosureInspection,
    constructors: Requirements,
    tables: Requirements,
    scratch: Requirements,
    planning: Requirements,
}

/// Issued only by the captured source plan. The member owner, original ordinal
/// and owning inventory survive by immutable borrow through construction/seal.
#[derive(Clone, Copy)]
pub(crate) struct MetadataMember<'plan, 'a> {
    plan: &'plan SourceMetadataPlanningPlan<'a>,
    ordinal: usize,
    prepared: &'a SourceRetained<PreparedWorkflowSources<'a>>,
}
impl<'a> MetadataMember<'_, 'a> {
    pub(crate) fn ordinal(self) -> usize { self.ordinal }
    pub(crate) fn prepared(self) -> &'a SourceRetained<PreparedWorkflowSources<'a>> { self.prepared }
    pub(crate) fn belongs_to(self, plan: &SourceMetadataPlanningPlan<'a>) -> bool {
        core::ptr::eq(self.plan, plan)
            && plan.members.get(self.ordinal).is_some_and(|member| core::ptr::eq(*member, self.prepared))
    }
}

impl<'a> SourceMetadataPlanningPlan<'a> {
    pub(crate) fn new(scope: &'a SourcePlanningPlan<'a>,
        members: &'a [&'a SourceRetained<PreparedWorkflowSources<'a>>], ledger: &Ledger,
        bootstrap: &Reservation, stage: &mut MetadataPlanningStage) -> Result<Self>
    {
        *stage = MetadataPlanningStage::BootstrapContainment;
        if !bootstrap.belongs_to(ledger)
            || !contains(bootstrap.requirements(), Self::inspection_requirements()?)
        { return Err(ClosureError::Resource); }
        // This existing checker validates exact N3/N4 member order, original
        // owners, context, source/code identity, and canonical leaf prefix.
        // Its MissingProducers observation is preserved until actual closure.
        *stage = MetadataPlanningStage::ClosureInspection;
        let inspection = SourceClosurePlanningPlan::inspect(scope, members, ledger, bootstrap)?;
        let mut result = Self { scope, members, ledger: ledger.clone(), counts: ProducerCounts::default(),
            inspection, constructors: Requirements::default(), tables: Requirements::default(),
            scratch: Self::inspection_requirements()?, planning: Requirements::default() };
        *stage = MetadataPlanningStage::SourceInspection;
        result.inspect_sources(stage)?;
        *stage = MetadataPlanningStage::Tables;
        result.tables = tables::requirements(result.counts, members.len())?;
        // The actual returned descriptor and member-array/frame census persist
        // independently of temporary construction storage after installation.
        *stage = MetadataPlanningStage::RetainedPlan;
        result.tables = sum(result.tables, Self::retained_requirements()?)?;
        *stage = MetadataPlanningStage::TableTransfers;
        result.tables = sum(result.tables,
            crate::execution::workflow_resources::producer_table_transfer_requirements(&result)
                .map_err(|_| ClosureError::Resource)?)?;
        *stage = MetadataPlanningStage::RetainedMetadata;
        result.tables = sum(result.tables,
            crate::execution::workflow_resources::producer_metadata_retained_requirements()
                .map_err(|_| ClosureError::Resource)?)?;
        *stage = MetadataPlanningStage::RetainedConstructors;
        result.tables = sum(result.tables,
            crate::execution::workflow_resources::producer_constructor_retained_requirements()
                .map_err(|_| ClosureError::Resource)?)?;
        *stage = MetadataPlanningStage::CompleteSlot;
        result.tables = sum(result.tables, super::closed_plan::complete_slot_requirements()?)?;
        *stage = MetadataPlanningStage::CompleteMetadata;
        result.constructors = sum(result.constructors,
            super::closed_plan::complete_metadata_requirements(&result)?)?;
        *stage = MetadataPlanningStage::CompleteInspection;
        result.scratch = maximum(result.scratch,
            super::closed_plan::complete_inspection_requirements()?);
        // Wrapper and inner constructor frames coexist. Add the wrapper
        // census to the serial inner maximum instead of taking its maximum.
        *stage = MetadataPlanningStage::ConstructorScratch;
        result.scratch = sum(result.scratch,
            crate::execution::workflow_resources::producer_constructor_requirements(&result)
                .map_err(|_| ClosureError::Resource)?)?;
        // Controller/cleanup backing remains in the unsplit original when
        // constructor/table/scheduler originals have moved to their owners.
        *stage = MetadataPlanningStage::ControllerMetadata;
        let slots = add(mul(result.counts.steps, 2)?, 1)?;
        result.tables = sum(result.tables, Requirements::single(Category::RegisteredMetadata,
            Bytes { host: crate::execution::workflow_resources::controller_bytes(slots)
                .map_err(|_| ClosureError::Resource)?, device: 0 }))?;
        *stage = MetadataPlanningStage::Envelope;
        result.planning = sum(sum(result.constructors, result.tables)?, result.scratch)?;
        *stage = MetadataPlanningStage::Complete;
        Ok(result)
    }

    fn include(&mut self, requirement: ProducerRequirements) -> Result<()> {
        self.constructors = sum(self.constructors, requirement.original)?;
        self.scratch = maximum(self.scratch, requirement.construction);
        Ok(())
    }
    pub(crate) fn member(&self, ordinal: usize) -> Result<MetadataMember<'_, 'a>> {
        let prepared = *self.members.get(ordinal).ok_or(ClosureError::Order)?;
        Ok(MetadataMember { plan: self, ordinal, prepared })
    }
    pub(crate) fn member_for(&self, prepared: &SourceRetained<PreparedWorkflowSources<'a>>)
        -> Result<MetadataMember<'_, 'a>>
    {
        let ordinal = self.members.iter().position(|member| core::ptr::eq(*member, prepared))
            .ok_or(ClosureError::Identity)?;
        self.member(ordinal)
    }
    pub(crate) fn context(&self) -> &'a ProvingContext { self.scope.context() }
    pub(crate) fn source_fingerprint(&self) -> [u8; 32] { self.scope.source_fingerprint() }
    pub(crate) fn compiled_source_fingerprint(&self) -> [u8; 32] { self.scope.compiled_source_fingerprint() }
    pub(crate) fn enclosing_bytes(&self) -> Bytes { self.scope.enclosing_bytes() }
    pub(crate) fn belongs_to(&self, ledger: &Ledger) -> bool {
        !self.members.is_empty() && self.members.iter().all(|member|
            member.belongs_to(ledger) && member.belongs_to(&self.ledger))
    }
    pub(crate) fn planning_requirements(&self) -> Requirements { self.planning }
    pub(crate) fn planning_scratch_requirements(&self) -> Requirements { self.scratch }
    pub(crate) fn counts(&self) -> ProducerCounts { self.counts }
    pub(crate) fn scope(&self) -> &'a SourcePlanningPlan<'a> { self.scope }
    pub(crate) fn ledger(&self) -> &Ledger { &self.ledger }
    pub(crate) fn members(&self) -> &'a [&'a SourceRetained<PreparedWorkflowSources<'a>>] { self.members }
    pub(crate) fn initial_inspection(&self) -> ClosureInspection { self.inspection }
}
