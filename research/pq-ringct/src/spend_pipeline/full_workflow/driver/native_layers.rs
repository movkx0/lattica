//! Concrete borrowed table layers for original native producer construction.
//! Root declares each owning table separately so later layers may borrow it.
use crate::{
    execution::{retained_resources::{Bytes, Category, Requirements},
        workflow_resources::{WorkflowError, WorkflowPlanning}},
    graph_auxiliary::{AuxiliaryRequest, Kind as AuxiliaryKind, Role},
    graph_crypto::OuterProofCache,
    graph_proofs::{ComponentKind, PlannedBatch},
    spend_pipeline::full_workflow::{
        metadata_planning::{MetadataMember, ProducerFamily, SourceMetadataPlanningPlan},
        metadata_tables::{native as native_tables, graph as graph_tables, algebra as algebra_tables},
        fresh_generation::case_lifetime::{CaseOwnerSlot, CaseOwnerTable, CaseRetirementState},
    },
};
use super::metadata_driver::{DriverStage, DriverAction, stage_frame_bytes};
use core::mem::size_of;

mod native;
mod blueprints;
mod compile;
mod compiler_views;
mod outer;
pub(crate) use native::fill_native_layer;
pub(crate) use blueprints::fill_blueprint_layer;
pub(crate) use compile::fill_compiler_layer;
pub(crate) use compiler_views::{NativeCompilerInputs, fill_compiler_views};
pub(crate) use outer::fill_outer_layer;

type Result<T> = core::result::Result<T, WorkflowError>;

/// Borrowed descriptors contain no producer payload or replacement owner.
#[derive(Clone, Copy)]
pub(crate) struct NativePlanTables<'tables, 'case, 'a> {
    pub(crate) source: &'tables native_tables::SourcePlanTable<'case, 'a>,
    pub(crate) uniform: &'tables native_tables::UniformPlanTable<'case, 'a>,
    pub(crate) sparse: &'tables native_tables::SparsePlanTable<'case, 'a>,
    pub(crate) transcript: &'tables native_tables::TranscriptPlanTable<'case, 'a>,
    pub(crate) affine: &'tables native_tables::AffinePlanTable<'case, 'a>,
    pub(crate) ntt: &'tables native_tables::NttPlanTable<'case, 'a>,
    pub(crate) mul: &'tables native_tables::MulPlanTable<'case, 'a>,
    pub(crate) g_bound: &'tables native_tables::GBoundPlanTable<'case, 'a>,
    pub(crate) permutation: &'tables native_tables::PermutationPlanTable<'case, 'a>,
    pub(crate) linear_map: &'tables native_tables::LinearMapPlanTable<'case, 'a>,
}

impl NativePlanTables<'_, '_, '_> {
    fn validate(&self, inventory: &SourceMetadataPlanningPlan<'_>, case: &CaseRetirementState) -> Result<()> {
        check_table(self.source, case, inventory.counts().family(ProducerFamily::Source))?;
        check_table(self.uniform, case, inventory.counts().family(ProducerFamily::Uniform))?;
        check_table(self.sparse, case, inventory.counts().family(ProducerFamily::Sparse))?;
        check_table(self.transcript, case, inventory.counts().family(ProducerFamily::Transcript))?;
        check_table(self.affine, case, inventory.counts().family(ProducerFamily::Affine))?;
        check_table(self.ntt, case, inventory.counts().family(ProducerFamily::Ntt))?;
        check_table(self.mul, case, inventory.counts().family(ProducerFamily::Mul))?;
        check_table(self.g_bound, case, inventory.counts().family(ProducerFamily::GBound))?;
        check_table(self.permutation, case, inventory.counts().family(ProducerFamily::Permutation))?;
        check_table(self.linear_map, case, inventory.counts().family(ProducerFamily::LinearMap))?;
        Ok(())
    }
    fn validate_empty(&self, inventory: &SourceMetadataPlanningPlan<'_>, case: &CaseRetirementState) -> Result<()> {
        self.validate(inventory, case)?;
        require_empty(self.source)?;
        require_empty(self.uniform)?;
        require_empty(self.sparse)?;
        require_empty(self.transcript)?;
        require_empty(self.affine)?;
        require_empty(self.ntt)?;
        require_empty(self.mul)?;
        require_empty(self.g_bound)?;
        require_empty(self.permutation)?;
        require_empty(self.linear_map)?;
        Ok(())
    }
    fn finish(&self) -> Result<()> {
        require_populated(self.source)?;
        require_populated(self.uniform)?;
        require_populated(self.sparse)?;
        require_populated(self.transcript)?;
        require_populated(self.affine)?;
        require_populated(self.ntt)?;
        require_populated(self.mul)?;
        require_populated(self.g_bound)?;
        require_populated(self.permutation)?;
        require_populated(self.linear_map)?;
        Ok(())
    }
}

/// Borrowed descriptors contain no producer payload or replacement owner.
#[derive(Clone, Copy)]
pub(crate) struct BlueprintTables<'tables, 'case, 'a> {
    pub(crate) source: &'tables graph_tables::SourceBlueprintTable<'case, 'a, 'a>,
    pub(crate) affine: &'tables algebra_tables::AffineBlueprintTable<'case, 'a, 'a>,
    pub(crate) ntt: &'tables algebra_tables::NttBlueprintTable<'case, 'a, 'a>,
    pub(crate) mul: &'tables algebra_tables::MulBlueprintTable<'case, 'a, 'a>,
    pub(crate) g_bound: &'tables algebra_tables::GBoundBlueprintTable<'case, 'a, 'a>,
    pub(crate) permutation: &'tables algebra_tables::PermutationBlueprintTable<'case, 'a, 'a>,
    pub(crate) linear_map: &'tables algebra_tables::LinearMapBlueprintTable<'case, 'a, 'a>,
}

impl BlueprintTables<'_, '_, '_> {
    fn validate(&self, inventory: &SourceMetadataPlanningPlan<'_>, case: &CaseRetirementState) -> Result<()> {
        check_table(self.source, case, inventory.counts().family(ProducerFamily::Source))?;
        check_table(self.affine, case, inventory.counts().family(ProducerFamily::Affine))?;
        check_table(self.ntt, case, inventory.counts().family(ProducerFamily::Ntt))?;
        check_table(self.mul, case, inventory.counts().family(ProducerFamily::Mul))?;
        check_table(self.g_bound, case, inventory.counts().family(ProducerFamily::GBound))?;
        check_table(self.permutation, case, inventory.counts().family(ProducerFamily::Permutation))?;
        check_table(self.linear_map, case, inventory.counts().family(ProducerFamily::LinearMap))?;
        Ok(())
    }
    fn validate_empty(&self, inventory: &SourceMetadataPlanningPlan<'_>, case: &CaseRetirementState) -> Result<()> {
        self.validate(inventory, case)?;
        require_empty(self.source)?;
        require_empty(self.affine)?;
        require_empty(self.ntt)?;
        require_empty(self.mul)?;
        require_empty(self.g_bound)?;
        require_empty(self.permutation)?;
        require_empty(self.linear_map)?;
        Ok(())
    }
    fn finish(&self) -> Result<()> {
        require_populated(self.source)?;
        require_populated(self.affine)?;
        require_populated(self.ntt)?;
        require_populated(self.mul)?;
        require_populated(self.g_bound)?;
        require_populated(self.permutation)?;
        require_populated(self.linear_map)?;
        Ok(())
    }
}

/// Borrowed descriptors contain no producer payload or replacement owner.
#[derive(Clone, Copy)]
pub(crate) struct CompilerPlanTables<'tables, 'case, 'a> {
    pub(crate) source: &'tables graph_tables::SourceCompilerPlanTable<'case, 'a>,
    pub(crate) affine: &'tables algebra_tables::AffineCompilerPlanTable<'case, 'a>,
    pub(crate) ntt: &'tables algebra_tables::NttCompilerPlanTable<'case, 'a>,
    pub(crate) mul: &'tables algebra_tables::MulCompilerPlanTable<'case, 'a>,
    pub(crate) g_bound: &'tables algebra_tables::GBoundCompilerPlanTable<'case, 'a>,
    pub(crate) permutation: &'tables algebra_tables::PermutationCompilerPlanTable<'case, 'a>,
    pub(crate) linear_map: &'tables algebra_tables::LinearMapCompilerPlanTable<'case, 'a>,
}

impl CompilerPlanTables<'_, '_, '_> {
    fn validate(&self, inventory: &SourceMetadataPlanningPlan<'_>, case: &CaseRetirementState) -> Result<()> {
        check_table(self.source, case, inventory.counts().family(ProducerFamily::Source))?;
        check_table(self.affine, case, inventory.counts().family(ProducerFamily::Affine))?;
        check_table(self.ntt, case, inventory.counts().family(ProducerFamily::Ntt))?;
        check_table(self.mul, case, inventory.counts().family(ProducerFamily::Mul))?;
        check_table(self.g_bound, case, inventory.counts().family(ProducerFamily::GBound))?;
        check_table(self.permutation, case, inventory.counts().family(ProducerFamily::Permutation))?;
        check_table(self.linear_map, case, inventory.counts().family(ProducerFamily::LinearMap))?;
        Ok(())
    }
    fn validate_empty(&self, inventory: &SourceMetadataPlanningPlan<'_>, case: &CaseRetirementState) -> Result<()> {
        self.validate(inventory, case)?;
        require_empty(self.source)?;
        require_empty(self.affine)?;
        require_empty(self.ntt)?;
        require_empty(self.mul)?;
        require_empty(self.g_bound)?;
        require_empty(self.permutation)?;
        require_empty(self.linear_map)?;
        Ok(())
    }
    fn finish(&self) -> Result<()> {
        require_populated(self.source)?;
        require_populated(self.affine)?;
        require_populated(self.ntt)?;
        require_populated(self.mul)?;
        require_populated(self.g_bound)?;
        require_populated(self.permutation)?;
        require_populated(self.linear_map)?;
        Ok(())
    }
}

/// Borrowed descriptors contain no producer payload or replacement owner.
#[derive(Clone, Copy)]
pub(crate) struct OuterPlanTables<'tables, 'case, 'source, 'a> {
    pub(crate) source: &'tables graph_tables::SourceOuterPlanTable<'case, 'source, 'a>,
    pub(crate) affine: &'tables algebra_tables::AffineOuterPlanTable<'case, 'source, 'a>,
    pub(crate) ntt: &'tables algebra_tables::NttOuterPlanTable<'case, 'source, 'a>,
    pub(crate) mul: &'tables algebra_tables::MulOuterPlanTable<'case, 'source, 'a>,
    pub(crate) g_bound: &'tables algebra_tables::GBoundOuterPlanTable<'case, 'source, 'a>,
    pub(crate) permutation: &'tables algebra_tables::PermutationOuterPlanTable<'case, 'source, 'a>,
    pub(crate) linear_map: &'tables algebra_tables::LinearMapOuterPlanTable<'case, 'source, 'a>,
}

impl OuterPlanTables<'_, '_, '_, '_> {
    fn validate(&self, inventory: &SourceMetadataPlanningPlan<'_>, case: &CaseRetirementState) -> Result<()> {
        check_table(self.source, case, inventory.counts().family(ProducerFamily::Source))?;
        check_table(self.affine, case, inventory.counts().family(ProducerFamily::Affine))?;
        check_table(self.ntt, case, inventory.counts().family(ProducerFamily::Ntt))?;
        check_table(self.mul, case, inventory.counts().family(ProducerFamily::Mul))?;
        check_table(self.g_bound, case, inventory.counts().family(ProducerFamily::GBound))?;
        check_table(self.permutation, case, inventory.counts().family(ProducerFamily::Permutation))?;
        check_table(self.linear_map, case, inventory.counts().family(ProducerFamily::LinearMap))?;
        Ok(())
    }
    fn validate_empty(&self, inventory: &SourceMetadataPlanningPlan<'_>, case: &CaseRetirementState) -> Result<()> {
        self.validate(inventory, case)?;
        require_empty(self.source)?;
        require_empty(self.affine)?;
        require_empty(self.ntt)?;
        require_empty(self.mul)?;
        require_empty(self.g_bound)?;
        require_empty(self.permutation)?;
        require_empty(self.linear_map)?;
        Ok(())
    }
    fn finish(&self) -> Result<()> {
        require_populated(self.source)?;
        require_populated(self.affine)?;
        require_populated(self.ntt)?;
        require_populated(self.mul)?;
        require_populated(self.g_bound)?;
        require_populated(self.permutation)?;
        require_populated(self.linear_map)?;
        Ok(())
    }
}

fn check_table<T>(table: &CaseOwnerTable<'_, T>, case: &CaseRetirementState, count: usize) -> Result<()> {
    if !table.belongs_to_case(case) || table.slots().len() != count {
        return Err(WorkflowError::Identity);
    }
    Ok(())
}

fn require_empty<T>(table: &CaseOwnerTable<'_, T>) -> Result<()> {
    if table.slots().iter().any(CaseOwnerSlot::is_initialized) {
        return Err(WorkflowError::Planning);
    }
    Ok(())
}

/// The whole original-bearing Result is moved into its already claimed slot.
/// Only a borrow of the installed Result can decide whether the driver stops.
fn install<T, E>(slot: &CaseOwnerSlot<'_, core::result::Result<T, E>>,
    result: core::result::Result<T, E>) -> Result<()>
{
    slot.install(result).map_err(|_| WorkflowError::Planning)?;
    match slot.get().map_err(|_| WorkflowError::Planning)? {
        Ok(_) => Ok(()),
        Err(_) => Err(WorkflowError::Source),
    }
}

fn successful<'view, T, E>(table: &'view CaseOwnerTable<'_, core::result::Result<T, E>>,
    ordinal: usize) -> Result<&'view T>
{
    table.get(ordinal).map_err(|_| WorkflowError::Identity)?
        .get().map_err(|_| WorkflowError::Planning)?
        .as_ref().map_err(|_| WorkflowError::Source)
}

fn require_populated<T, E>(table: &CaseOwnerTable<'_, core::result::Result<T, E>>) -> Result<()> {
    for ordinal in 0..table.slots().len() { let _ = successful(table, ordinal)?; }
    Ok(())
}

fn position<'a>(inventory: &SourceMetadataPlanningPlan<'a>, member: MetadataMember<'_, 'a>,
    family: ProducerFamily, ordinal: usize) -> Result<usize>
{
    inventory.source_position(member, family, ordinal).map_err(|_| WorkflowError::Identity)
}

fn auxiliary_family(request: &AuxiliaryRequest) -> Result<ProducerFamily> {
    match (request.kind(), request.role()) {
        (AuxiliaryKind::Uniform(crate::uniform_air::Kind::SampleG4), Role::SampleGUniform)
        | (AuxiliaryKind::Uniform(crate::uniform_air::Kind::ExpandAlpha2), Role::AlphaUniform) => Ok(ProducerFamily::Uniform),
        (AuxiliaryKind::Sparse(crate::sparse_air::Kind::AlphaPrime39), Role::AlphaSparse)
        | (AuxiliaryKind::Sparse(crate::sparse_air::Kind::ChallengeX44), Role::HashXSparse) => Ok(ProducerFamily::Sparse),
        (AuxiliaryKind::Transcript, Role::HashAlphaTranscript | Role::HashXTranscript) => Ok(ProducerFamily::Transcript),
        _ => Err(WorkflowError::Identity),
    }
}

fn algebra_family(batch: &PlannedBatch) -> Option<ProducerFamily> {
    match batch.kind() {
        ComponentKind::Affine { .. } => Some(ProducerFamily::Affine),
        ComponentKind::Ntt { .. } => Some(ProducerFamily::Ntt),
        ComponentKind::Mul { .. } => Some(ProducerFamily::Mul),
        ComponentKind::GBound { .. } => Some(ProducerFamily::GBound),
        ComponentKind::Permutation { .. } => Some(ProducerFamily::Permutation),
        ComponentKind::LinearMap { .. } => Some(ProducerFamily::LinearMap),
        ComponentKind::External => None,
    }
}

/// Constructors must see ready planning while they run. The exclusive guard
/// poisons it on every driver error or unwind without clearing constructor errors.
struct LayerGuard<'borrow, 'workflow> {
    planning: &'borrow mut WorkflowPlanning<'workflow>,
    completed: bool,
}
impl Drop for LayerGuard<'_, '_> {
    fn drop(&mut self) {
        if !self.completed { self.planning.poison_metadata_driver(); }
    }
}
fn run_layer<'workflow>(planning: &mut WorkflowPlanning<'workflow>,
    inventory: &SourceMetadataPlanningPlan<'_>, case: &CaseRetirementState,
    build: impl FnOnce(&mut WorkflowPlanning<'workflow>) -> Result<()>) -> Result<()>
{
    planning.validate_metadata_driver(inventory, case)?;
    let mut guard = LayerGuard { planning, completed: false };
    let result = build(&mut *guard.planning);
    if result.is_ok() {
        guard.planning.validate_metadata_driver(inventory, case)?;
        guard.completed = true;
    }
    result
}

/// Add this exact PhaseScratch census to the source constructor envelope before
/// any driver layer is invoked. It grants neither admission nor dispatch.
pub(crate) fn requirements() -> Result<Requirements> {
    let bytes = [
        stage_frame_bytes(),
        size_of::<NativePlanTables<'static, 'static, 'static>>(),
        size_of::<BlueprintTables<'static, 'static, 'static>>(),
        size_of::<CompilerPlanTables<'static, 'static, 'static>>(),
        size_of::<NativeCompilerInputs<'static>>(),
        size_of::<crate::spend_pipeline::full_workflow::ClosureError>(),
        size_of::<OuterPlanTables<'static, 'static, 'static, 'static>>(),
        size_of::<LayerGuard<'static, 'static>>(),
        size_of::<MetadataMember<'static, 'static>>(),
        size_of::<Result<MetadataMember<'static, 'static>>>(),
        size_of::<[usize; 128]>(), size_of::<[Requirements; 4]>(),
        size_of::<[&SourceMetadataPlanningPlan<'static>; 8]>(),
        size_of::<[&CaseRetirementState; 4]>(), size_of::<[&OuterProofCache; 4]>(),
        size_of::<Result<()>>(), size_of::<Result<usize>>(), size_of::<Result<ProducerFamily>>(),
        size_of::<Option<ProducerFamily>>(),
        size_of::<String>(), 128,
        size_of::<native_tables::SourcePlanResult<'static>>(),
        size_of::<Result<native_tables::SourcePlanResult<'static>>>(),
        size_of::<native_tables::UniformPlanResult<'static>>(),
        size_of::<Result<native_tables::UniformPlanResult<'static>>>(),
        size_of::<native_tables::SparsePlanResult<'static>>(),
        size_of::<Result<native_tables::SparsePlanResult<'static>>>(),
        size_of::<native_tables::TranscriptPlanResult<'static>>(),
        size_of::<Result<native_tables::TranscriptPlanResult<'static>>>(),
        size_of::<native_tables::AffinePlanResult<'static>>(),
        size_of::<Result<native_tables::AffinePlanResult<'static>>>(),
        size_of::<native_tables::NttPlanResult<'static>>(),
        size_of::<Result<native_tables::NttPlanResult<'static>>>(),
        size_of::<native_tables::MulPlanResult<'static>>(),
        size_of::<Result<native_tables::MulPlanResult<'static>>>(),
        size_of::<native_tables::GBoundPlanResult<'static>>(),
        size_of::<Result<native_tables::GBoundPlanResult<'static>>>(),
        size_of::<native_tables::PermutationPlanResult<'static>>(),
        size_of::<Result<native_tables::PermutationPlanResult<'static>>>(),
        size_of::<native_tables::LinearMapPlanResult<'static>>(),
        size_of::<Result<native_tables::LinearMapPlanResult<'static>>>(),
        size_of::<graph_tables::SourceBlueprintResult<'static, 'static>>(),
        size_of::<Result<graph_tables::SourceBlueprintResult<'static, 'static>>>(),
        size_of::<graph_tables::SourceCompilerPlanResult<'static>>(),
        size_of::<Result<graph_tables::SourceCompilerPlanResult<'static>>>(),
        size_of::<graph_tables::SourceOuterPlanResult<'static, 'static>>(),
        size_of::<Result<graph_tables::SourceOuterPlanResult<'static, 'static>>>(),
        size_of::<algebra_tables::AffineBlueprintResult<'static, 'static>>(),
        size_of::<Result<algebra_tables::AffineBlueprintResult<'static, 'static>>>(),
        size_of::<algebra_tables::AffineCompilerPlanResult<'static>>(),
        size_of::<Result<algebra_tables::AffineCompilerPlanResult<'static>>>(),
        size_of::<algebra_tables::AffineOuterPlanResult<'static, 'static>>(),
        size_of::<Result<algebra_tables::AffineOuterPlanResult<'static, 'static>>>(),
        size_of::<algebra_tables::NttBlueprintResult<'static, 'static>>(),
        size_of::<Result<algebra_tables::NttBlueprintResult<'static, 'static>>>(),
        size_of::<algebra_tables::NttCompilerPlanResult<'static>>(),
        size_of::<Result<algebra_tables::NttCompilerPlanResult<'static>>>(),
        size_of::<algebra_tables::NttOuterPlanResult<'static, 'static>>(),
        size_of::<Result<algebra_tables::NttOuterPlanResult<'static, 'static>>>(),
        size_of::<algebra_tables::MulBlueprintResult<'static, 'static>>(),
        size_of::<Result<algebra_tables::MulBlueprintResult<'static, 'static>>>(),
        size_of::<algebra_tables::MulCompilerPlanResult<'static>>(),
        size_of::<Result<algebra_tables::MulCompilerPlanResult<'static>>>(),
        size_of::<algebra_tables::MulOuterPlanResult<'static, 'static>>(),
        size_of::<Result<algebra_tables::MulOuterPlanResult<'static, 'static>>>(),
        size_of::<algebra_tables::GBoundBlueprintResult<'static, 'static>>(),
        size_of::<Result<algebra_tables::GBoundBlueprintResult<'static, 'static>>>(),
        size_of::<algebra_tables::GBoundCompilerPlanResult<'static>>(),
        size_of::<Result<algebra_tables::GBoundCompilerPlanResult<'static>>>(),
        size_of::<algebra_tables::GBoundOuterPlanResult<'static, 'static>>(),
        size_of::<Result<algebra_tables::GBoundOuterPlanResult<'static, 'static>>>(),
        size_of::<algebra_tables::PermutationBlueprintResult<'static, 'static>>(),
        size_of::<Result<algebra_tables::PermutationBlueprintResult<'static, 'static>>>(),
        size_of::<algebra_tables::PermutationCompilerPlanResult<'static>>(),
        size_of::<Result<algebra_tables::PermutationCompilerPlanResult<'static>>>(),
        size_of::<algebra_tables::PermutationOuterPlanResult<'static, 'static>>(),
        size_of::<Result<algebra_tables::PermutationOuterPlanResult<'static, 'static>>>(),
        size_of::<algebra_tables::LinearMapBlueprintResult<'static, 'static>>(),
        size_of::<Result<algebra_tables::LinearMapBlueprintResult<'static, 'static>>>(),
        size_of::<algebra_tables::LinearMapCompilerPlanResult<'static>>(),
        size_of::<Result<algebra_tables::LinearMapCompilerPlanResult<'static>>>(),
        size_of::<algebra_tables::LinearMapOuterPlanResult<'static, 'static>>(),
        size_of::<Result<algebra_tables::LinearMapOuterPlanResult<'static, 'static>>>(),
    ].into_iter().try_fold(0usize, |sum, part| sum.checked_add(part))
        .and_then(|sum| sum.checked_mul(8)).ok_or(WorkflowError::Overflow)?;
    Ok(Requirements::single(Category::PhaseScratch, Bytes {
        host: u64::try_from(bytes).map_err(|_| WorkflowError::Overflow)?, device: 0,
    }))
}
