//! Complete closure from original concrete producers. Counts only reserve
//! storage; the source/member/ordinal/dependency walk below proves coverage.
use super::*;
use crate::{
    graph_tree::{LeafKind, OperationFamily, owned_parent::{GraphChildSource, GraphNodeSource}},
    ordered_aggregation::owned_final::{FinalPhasePlan, FinalStepKind},
    spend_pipeline::full_workflow::{metadata_planning::{SourceMetadataPlanningPlan, ProducerFamily},
        fresh_generation::{FreshGenerationError, case_lifetime::{CaseRetirementState, CaseOwnerSlot}}},
};
use lattica_prover_p3::proving::Policy;
use crate::execution::generation_terminal::planning_startup::FreshPlanningContext;

pub(crate) mod tables;
mod families;
mod graph;
use dispatch::*;
use tables::*;

const PARENT_LEVELS: usize = 32;

/// Last bounded source-construction position, not proof or dispatch authority.
/// Static labels and scalar ordinals stay with the original failed Result.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CompleteStage {
    Gate(&'static str),
    Member { member: Option<usize>, family: Option<ProducerFamily>,
        ordinal: Option<usize>, action: &'static str },
    Parent { level: usize, member: Option<usize>, ordinal: Option<usize>, action: &'static str },
    Final { step: Option<usize>, action: &'static str },
    Memory { action: &'static str, details: CloseMemoryStage },
}
impl CompleteStage {
    fn action(&mut self, next: &'static str) {
        match self {
            Self::Gate(action) | Self::Member { action, .. }
                | Self::Parent { action, .. } | Self::Final { action, .. }
                | Self::Memory { action, .. } => *action = next,
        }
    }
}

/// One independently scoped, original owning table per nonempty tree level.
/// The fixed adapter array is created only after checking the actual source
/// heights. A matching numerical census never certifies any parent edge.
pub(crate) struct ParentTables<'a> {
    metadata: &'a SourceMetadataPlanningPlan<'a>,
    expected: [usize; PARENT_LEVELS],
    levels: [Option<&'a dyn ParentPlans>; PARENT_LEVELS],
}
impl<'a> ParentTables<'a> {
    pub(crate) fn new(metadata: &'a SourceMetadataPlanningPlan<'a>, scratch: &Reservation)
        -> Result<Self>
    {
        if !scratch.belongs_to(metadata.ledger())
            || !source::contains(scratch.requirements(), complete_inspection_requirements()?)
        { return Err(ClosureError::Resource); }
        // First check the source-derived height before constructing the array.
        for member in metadata.members() {
            let mut width = member.get().plan().leaves().len();
            if width < 3 { return Err(ClosureError::Coverage); }
            let mut height = 0;
            while width > 1 {
                height = add(height, 1)?;
                if height > PARENT_LEVELS { return Err(ClosureError::Coverage); }
                width = add(width / 2, width % 2)?;
            }
        }
        let mut result = Self { metadata, expected: [0; PARENT_LEVELS], levels: [None; PARENT_LEVELS] };
        for member in metadata.members() {
            let mut width = member.get().plan().leaves().len();
            let mut level = 0;
            while width > 1 {
                result.expected[level] = add(result.expected[level], width / 2)?;
                width = add(width / 2, width % 2)?;
                level += 1;
            }
        }
        for level in 0..PARENT_LEVELS {
            if metadata.counts().parent_level(level) != Some(result.expected[level]) {
                return Err(ClosureError::Coverage);
            }
        }
        Ok(result)
    }
    pub(crate) fn bind_level(&mut self, level: usize, table: &'a dyn ParentPlans) -> Result<()> {
        if self.expected.get(level).copied().is_none_or(|count| count == 0 || count != table.len())
            || self.levels.get(level).is_none_or(Option::is_some)
        { return Err(ClosureError::Coverage); }
        self.levels[level] = Some(table);
        Ok(())
    }
}

/// Borrowed descriptors only: every payload and constructor error remains in
/// its independently charged CaseOwnerTable. All fields are mandatory,
/// including empty-family owning tables, so extra or missing producers fail.
pub(crate) struct CompleteProducerTables<'a> {
    pub(crate) fixed: &'a dyn FixedPlans,
    pub(crate) fixed_outer: &'a dyn FixedOuterPlans,
    pub(crate) source_native: &'a dyn SourceNativePlans,
    pub(crate) source_blueprint: &'a dyn SourceBlueprints,
    pub(crate) source_compiler: &'a dyn SourceCompilerPlans,
    pub(crate) source_outer: &'a dyn SourceOuterPlans,
    pub(crate) uniform: &'a dyn UniformNativePlans,
    pub(crate) sparse: &'a dyn SparseNativePlans,
    pub(crate) transcript: &'a dyn TranscriptNativePlans,
    pub(crate) affine: &'a dyn AffineNativePlans,
    pub(crate) affine_blueprint: &'a dyn AffineBlueprints,
    pub(crate) affine_compiler: &'a dyn AffineCompilerPlans,
    pub(crate) affine_outer: &'a dyn AffineOuterPlans,
    pub(crate) ntt: &'a dyn NttNativePlans,
    pub(crate) ntt_blueprint: &'a dyn NttBlueprints,
    pub(crate) ntt_compiler: &'a dyn NttCompilerPlans,
    pub(crate) ntt_outer: &'a dyn NttOuterPlans,
    pub(crate) mul: &'a dyn MulNativePlans,
    pub(crate) mul_blueprint: &'a dyn MulBlueprints,
    pub(crate) mul_compiler: &'a dyn MulCompilerPlans,
    pub(crate) mul_outer: &'a dyn MulOuterPlans,
    pub(crate) g_bound: &'a dyn GBoundNativePlans,
    pub(crate) g_bound_blueprint: &'a dyn GBoundBlueprints,
    pub(crate) g_bound_compiler: &'a dyn GBoundCompilerPlans,
    pub(crate) g_bound_outer: &'a dyn GBoundOuterPlans,
    pub(crate) permutation: &'a dyn PermutationNativePlans,
    pub(crate) permutation_blueprint: &'a dyn PermutationBlueprints,
    pub(crate) permutation_compiler: &'a dyn PermutationCompilerPlans,
    pub(crate) permutation_outer: &'a dyn PermutationOuterPlans,
    pub(crate) linear_map: &'a dyn LinearMapNativePlans,
    pub(crate) linear_map_blueprint: &'a dyn LinearMapBlueprints,
    pub(crate) linear_map_compiler: &'a dyn LinearMapCompilerPlans,
    pub(crate) linear_map_outer: &'a dyn LinearMapOuterPlans,
    pub(crate) parameters: &'a dyn ParametersPlans,
    pub(crate) auxiliary: &'a dyn AuxiliaryPlans,
    pub(crate) equality: &'a dyn EqualityPlans,
    pub(crate) shake: &'a dyn ShakePlans,
    pub(crate) aes: &'a dyn AesPlans,
    pub(crate) parents: &'a ParentTables<'a>,
    pub(crate) final_contract: &'a dyn FinalContracts,
    pub(crate) final_source: &'a dyn FinalSources,
    pub(crate) final_plan: &'a dyn FinalPlans,
}

impl CompleteProducerTables<'_> {
    fn validate_case(&self, case: &CaseRetirementState) -> Result<()> {
        if !self.fixed.owns_case(case) { return Err(ClosureError::Identity); }
        if !self.fixed_outer.owns_case(case) { return Err(ClosureError::Identity); }
        if !self.source_native.owns_case(case) { return Err(ClosureError::Identity); }
        if !self.source_blueprint.owns_case(case) { return Err(ClosureError::Identity); }
        if !self.source_compiler.owns_case(case) { return Err(ClosureError::Identity); }
        if !self.source_outer.owns_case(case) { return Err(ClosureError::Identity); }
        if !self.uniform.owns_case(case) { return Err(ClosureError::Identity); }
        if !self.sparse.owns_case(case) { return Err(ClosureError::Identity); }
        if !self.transcript.owns_case(case) { return Err(ClosureError::Identity); }
        if !self.affine.owns_case(case) { return Err(ClosureError::Identity); }
        if !self.affine_blueprint.owns_case(case) { return Err(ClosureError::Identity); }
        if !self.affine_compiler.owns_case(case) { return Err(ClosureError::Identity); }
        if !self.affine_outer.owns_case(case) { return Err(ClosureError::Identity); }
        if !self.ntt.owns_case(case) { return Err(ClosureError::Identity); }
        if !self.ntt_blueprint.owns_case(case) { return Err(ClosureError::Identity); }
        if !self.ntt_compiler.owns_case(case) { return Err(ClosureError::Identity); }
        if !self.ntt_outer.owns_case(case) { return Err(ClosureError::Identity); }
        if !self.mul.owns_case(case) { return Err(ClosureError::Identity); }
        if !self.mul_blueprint.owns_case(case) { return Err(ClosureError::Identity); }
        if !self.mul_compiler.owns_case(case) { return Err(ClosureError::Identity); }
        if !self.mul_outer.owns_case(case) { return Err(ClosureError::Identity); }
        if !self.g_bound.owns_case(case) { return Err(ClosureError::Identity); }
        if !self.g_bound_blueprint.owns_case(case) { return Err(ClosureError::Identity); }
        if !self.g_bound_compiler.owns_case(case) { return Err(ClosureError::Identity); }
        if !self.g_bound_outer.owns_case(case) { return Err(ClosureError::Identity); }
        if !self.permutation.owns_case(case) { return Err(ClosureError::Identity); }
        if !self.permutation_blueprint.owns_case(case) { return Err(ClosureError::Identity); }
        if !self.permutation_compiler.owns_case(case) { return Err(ClosureError::Identity); }
        if !self.permutation_outer.owns_case(case) { return Err(ClosureError::Identity); }
        if !self.linear_map.owns_case(case) { return Err(ClosureError::Identity); }
        if !self.linear_map_blueprint.owns_case(case) { return Err(ClosureError::Identity); }
        if !self.linear_map_compiler.owns_case(case) { return Err(ClosureError::Identity); }
        if !self.linear_map_outer.owns_case(case) { return Err(ClosureError::Identity); }
        if !self.parameters.owns_case(case) { return Err(ClosureError::Identity); }
        if !self.auxiliary.owns_case(case) { return Err(ClosureError::Identity); }
        if !self.equality.owns_case(case) { return Err(ClosureError::Identity); }
        if !self.shake.owns_case(case) { return Err(ClosureError::Identity); }
        if !self.aes.owns_case(case) { return Err(ClosureError::Identity); }
        if !self.final_contract.owns_case(case) { return Err(ClosureError::Identity); }
        if !self.final_source.owns_case(case) { return Err(ClosureError::Identity); }
        if !self.final_plan.owns_case(case) { return Err(ClosureError::Identity); }
        for table in self.parents.levels.iter().flatten() {
            if !table.owns_case(case) { return Err(ClosureError::Identity); }
        }
        Ok(())
    }
}

/// Retains the original metadata reservation even if source inspection or a
/// later allocation fails. If construction progressed, all partial vectors
/// remain in the same owning Result until the case retirement barrier.
pub(crate) struct CompleteScheduleFailure<'a> {
    error: ClosureError,
    stage: CompleteStage,
    schedule: Option<SupportedSchedule<'a>>,
    original: Option<Reservation>,
}
impl CompleteScheduleFailure<'_> {
    pub(crate) fn error(&self) -> &ClosureError { &self.error }
    pub(crate) fn stage(&self) -> CompleteStage { self.stage }
}
pub(crate) type CompleteScheduleResult<'a> = core::result::Result<ClosedWorkflowPlan<'a>, CompleteScheduleFailure<'a>>;

/// Issued only by a successfully closed complete constructor. The borrowed
/// plan and exact metadata authority stay alive through bridge installation.
pub(crate) struct ValidatedCompleteInventory<'plan, 'a> {
    plan: &'plan ClosedWorkflowPlan<'a>,
}
impl<'plan, 'a> ValidatedCompleteInventory<'plan, 'a> {
    pub(crate) fn matches_metadata(&self, metadata: &SourceMetadataPlanningPlan<'_>) -> bool {
        matches!(self.plan.authority, ClosureAuthority::Complete(original)
            if core::ptr::eq(original, metadata))
    }
    pub(crate) fn closed_plan(&self) -> &'plan ClosedWorkflowPlan<'a> { self.plan }
    /// Exact source observations; the token is issued only for immutable complete authority.
    pub(crate) fn producer_counts(&self) -> crate::spend_pipeline::full_workflow::metadata_planning::ProducerCounts {
        match self.plan.authority {
            ClosureAuthority::Complete(original) => original.counts(),
            _ => unreachable!("validated complete inventory retains complete source authority"),
        }
    }
}

#[derive(Clone, Copy)]
pub(super) struct GraphRecord<'a> {
    member: usize,
    child: GraphChildSource<'a, 'a>,
}

pub(crate) fn complete_metadata_requirements(metadata: &SourceMetadataPlanningPlan<'_>) -> Result<Requirements> {
    let counts = metadata.counts();
    let requests = add(counts.family(ProducerFamily::Shake), counts.family(ProducerFamily::Aes))?;
    let schedule = schedule_metadata_requirements(counts.steps(), requests)?;
    // One immutable graph record per potential phase is a checked conservative
    // capacity. Only actual concrete graph producers can populate this vector.
    let graph = mul(counts.steps(), add(size_of::<GraphRecord<'static>>(), size_of::<StepDispatch>())?)?;
    let frames = [size_of::<CompleteProducerTables<'static>>(), size_of::<ParentTables<'static>>(),
        size_of::<CompleteScheduleFailure<'static>>(), size_of::<CompleteScheduleResult<'static>>(),
        size_of::<CompleteStage>(), size_of::<&mut CompleteStage>(),
        size_of::<PlanningAdmissionProjection>(), size_of::<Option<PlanningAdmissionProjection>>(),
        size_of::<ValidatedCompleteInventory<'static, 'static>>(), size_of::<ClosureAuthority<'static>>(),
        size_of::<GraphRecord<'static>>(), size_of::<families::Cursors>(),
        size_of::<Option<SupportedSchedule<'static>>>(), size_of::<Vec<GraphRecord<'static>>>(),
        size_of::<Result<ParentTables<'static>>>(),
    ].into_iter().try_fold(0, add)?;
    sum(schedule, Requirements::single(Category::RegisteredMetadata,
        source::host(add(mul(graph, 3)?, mul(frames, 8)?)?)?))
}

/// This original is kept separate from constructor storage: the entire Result
/// is installed into one concrete case slot before inspecting its status.
pub(crate) fn complete_slot_requirements() -> Result<Requirements> {
    CaseRetirementState::owner_slot_requirements::<CompleteScheduleResult<'static>>()
        .map_err(|_| ClosureError::Resource)
}

pub(crate) fn complete_inspection_requirements() -> Result<Requirements> {
    use lattica_prover_p3::block_v2::machine::{OuterSourceShape, RegisteredGpuOutputFootprint};
    let frames = [size_of::<CompleteProducerTables<'static>>(), size_of::<ParentTables<'static>>(),
        size_of::<families::Cursors>(), size_of::<GraphRecord<'static>>(),
        size_of::<CompleteStage>(), size_of::<&mut CompleteStage>(),
        size_of::<GraphChildSource<'static, 'static>>(), size_of::<GraphNodeSource<'static>>(),
        slot_policy::SELECTION_FRAME_BYTES,
        families::PARENT_READY_STATE_BYTES, graph::PARENT_READY_FRAME_BYTES,
        memory_diagnostics::FRAME_BYTES,
        size_of::<PlanningAdmissionTransition<'static, 'static>>(),
        size_of::<[&PlanningAdmissionTransition<'static, 'static>; 4]>(),
        size_of::<[PlanningAdmissionProjection; 4]>(), size_of::<Option<PlanningAdmissionProjection>>(),
        size_of::<Result<PlanningAdmissionProjection>>(),
        size_of::<core::result::Result<PlanningAdmissionProjection, crate::execution::workflow_resources::WorkflowError>>(),
        size_of::<[Option<PhaseBinding>; MAX_PHASE_INPUTS]>(), size_of::<[SlotId; MAX_PHASE_INPUTS]>(),
        size_of::<crate::graph_tree::owned_parent::AuxiliaryDependencies>(),
        size_of::<crate::ordered_aggregation::owned_final::FinalDependencies>(),
        size_of::<Result<PhaseBinding>>(), size_of::<Result<SlotId>>(), size_of::<Result<Requirements>>(),
        // Pure source output-footprint queries retain their returned descriptors,
        // per-height maxima and bounded refusal diagnostics before comparison.
        size_of::<OuterSourceShape>(), size_of::<core::result::Result<OuterSourceShape, String>>(),
        size_of::<RegisteredGpuOutputFootprint>(), size_of::<Option<RegisteredGpuOutputFootprint>>(),
        size_of::<core::result::Result<RegisteredGpuOutputFootprint, String>>(),
        size_of::<[Requirements; 4]>(), size_of::<[Bytes; 4]>(),
        size_of::<[usize; 16]>(), size_of::<[usize; PARENT_LEVELS]>(), size_of::<[u8; 32]>(),
        size_of::<StepDispatch>(), size_of::<ProducerRoute>(), size_of::<dispatch::CryptoRoute>(),
        size_of::<String>(), 128, // bounded original empty-slot error, including capacity
        size_of::<CompleteScheduleFailure<'static>>(), size_of::<CompleteScheduleResult<'static>>(),
    ].into_iter().try_fold(0, add)?;
    Ok(Requirements::single(Category::PhaseScratch, source::host(mul(frames, 8)?)?))
}

fn reserve<T>(values: &mut Vec<T>, count: usize) -> Result<()> {
    if !values.is_empty() || values.capacity() != 0 { return Err(ClosureError::Order); }
    values.try_reserve_exact(count).map_err(|_| ClosureError::Allocation)?;
    if values.capacity() != count { return Err(ClosureError::Allocation); }
    Ok(())
}

impl<'a> ClosedWorkflowPlan<'a> {
    pub(crate) fn derive_complete_pre_reserved(metadata: &'a SourceMetadataPlanningPlan<'a>,
        planning_slot: &CaseOwnerSlot<'_, core::result::Result<FreshPlanningContext<'_>, FreshGenerationError>>,
        tables: &'a CompleteProducerTables<'a>, original: Reservation, scratch: &Reservation,
        transition: &PlanningAdmissionTransition<'_, '_>,
        native_cache: &'a crate::graph_crypto::ProofCache,
        outer_cache: &'a crate::graph_crypto::OuterProofCache) -> CompleteScheduleResult<'a>
    {
        let mut failure = CompleteScheduleFailure { error: ClosureError::Source,
            stage: CompleteStage::Gate("identity"), schedule: None, original: Some(original) };
        let mut admission_projection = None;
        let built = (|| -> Result<()> {
            let ledger = metadata.ledger();
            if native_cache.policy() != crate::proof_cache_policy::ProofCachePolicy::FreshOnly
                || outer_cache.policy() != crate::proof_cache_policy::ProofCachePolicy::FreshOnly
                || metadata.context().policy() != Policy::GpuRequired || !metadata.belongs_to(ledger)
                || !scratch.belongs_to(ledger)
                || !source::contains(scratch.requirements(), complete_inspection_requirements()?)
                || !transition.matches_metadata(metadata)
                || !core::ptr::eq(tables.parents.metadata, metadata)
            { return Err(ClosureError::Identity); }
            failure.stage = CompleteStage::Gate("metadata_requirements");
            let held = failure.original.as_ref().ok_or(ClosureError::Resource)?;
            if !held.belongs_to(ledger) || held.requirements() != complete_metadata_requirements(metadata)? {
                return Err(ClosureError::Resource);
            }
            failure.stage = CompleteStage::Gate("case_identity");
            let case = planning_slot.metadata_case_state(metadata.scope(), ledger).map_err(|_| ClosureError::Identity)?;
            failure.stage = CompleteStage::Gate("table_identity");
            tables.validate_case(case)?;
            failure.stage = CompleteStage::Gate("final_table_lengths");
            if tables.final_contract.len() != 1 || tables.final_source.len() != 1 || tables.final_plan.len() != 1 {
                return Err(ClosureError::Coverage);
            }
            failure.stage = CompleteStage::Gate("final_source");
            let final_source = tables.final_source.plan(0)?;
            failure.stage = CompleteStage::Gate("final_contract");
            let final_contract = tables.final_contract.plan(0)?;
            failure.stage = CompleteStage::Gate("final_plan");
            let final_plan = tables.final_plan.plan(0)?;
            failure.stage = CompleteStage::Gate("final_identity");
            if !final_contract.matches_final_source(metadata, final_source, ledger)
                || !final_contract.matches_final_phase(metadata, final_plan, ledger)
                || !core::ptr::eq(final_plan.source(), final_source) || !final_plan.belongs_to(ledger)
                || !final_plan.fresh_only() { return Err(ClosureError::Identity); }
            failure.stage = CompleteStage::Gate("schedule_counts");
            let count = metadata.counts().steps();
            let requests = add(metadata.counts().family(ProducerFamily::Shake), metadata.counts().family(ProducerFamily::Aes))?;
            // Install the owning shell before the first allocation. A refusal
            // at any later reservation retains every earlier vector, together
            // with the original, in the full failed constructor Result.
            failure.schedule = Some(SupportedSchedule { scope: metadata.scope(), members: metadata.members(),
                fixed: &[], crypto: &[], final_source, slots: Vec::new(), live: Vec::new(),
                steps: Vec::new(), inputs: Vec::new(), roots: Vec::new(),
                fixed_slots: [None; 4], scratch: Requirements::default(),
                complete_tables: Some(tables), graph_nodes: Vec::new(), dispatch: Vec::new(),
                original: failure.original.take().ok_or(ClosureError::Resource)? });
            let schedule = failure.schedule.as_mut().ok_or(ClosureError::Resource)?;
            failure.stage = CompleteStage::Gate("reserve_slots");
            reserve(&mut schedule.slots, add(count, 1)?)?;
            failure.stage = CompleteStage::Gate("reserve_live");
            reserve(&mut schedule.live, add(count, 1)?)?;
            failure.stage = CompleteStage::Gate("reserve_steps");
            reserve(&mut schedule.steps, count)?;
            failure.stage = CompleteStage::Gate("reserve_inputs");
            reserve(&mut schedule.inputs, mul(count, MAX_PHASE_INPUTS)?)?;
            failure.stage = CompleteStage::Gate("reserve_roots");
            reserve(&mut schedule.roots, requests)?;
            failure.stage = CompleteStage::Gate("reserve_graph_nodes");
            reserve(&mut schedule.graph_nodes, count)?;
            failure.stage = CompleteStage::Gate("reserve_dispatch");
            reserve(&mut schedule.dispatch, count)?;
            failure.stage = CompleteStage::Gate("failure_slot");
            push(&mut schedule.slots, SlotSpec { requirements: Requirements::default() })?;
            push(&mut schedule.live, false)?;
            schedule.complete_members(tables, ledger, &mut failure.stage)?;
            schedule.validate_graph_roots(&mut failure.stage)?;
            schedule.complete_final(final_plan, ledger, &mut failure.stage)?;
            failure.stage = CompleteStage::Gate("complete_counts");
            if schedule.steps.len() != count || schedule.dispatch.len() != count { return Err(ClosureError::Coverage); }
            failure.stage = CompleteStage::Gate("final_topology");
            schedule.validate_final_topology()?;
            failure.stage = CompleteStage::Gate("close_memory");
            let mut memory = CloseMemoryStage::new();
            let closed = schedule.close_memory_for_admission(ledger, transition, Some(&mut memory));
            failure.stage = CompleteStage::Memory { action: "close_memory", details: memory };
            admission_projection = Some(closed?);
            Ok(())
        })();
        match built {
            Ok(()) => Ok(Self { authority: ClosureAuthority::Complete(metadata),
                schedule: failure.schedule.take().expect("successful complete construction owns schedule"),
                native_cache, outer_cache, admission_projection }),
            Err(error) => { failure.error = error; Err(failure) }
        }
    }
    pub(crate) fn requires_producer_metadata(&self) -> bool {
        matches!(self.authority, ClosureAuthority::Complete(_))
    }

    pub(crate) fn admission_projection(&self) -> Option<&PlanningAdmissionProjection> {
        self.admission_projection.as_ref()
    }

    pub(crate) fn validated_complete_inventory(&self) -> Result<ValidatedCompleteInventory<'_, 'a>> {
        if !matches!(self.authority, ClosureAuthority::Complete(_)) || self.schedule.complete_tables.is_none()
            || self.schedule.steps.last().map(|step| step.binding.kind()) != Some(PhaseKind::FinalVerify)
        { return Err(ClosureError::Coverage); }
        Ok(ValidatedCompleteInventory { plan: self })
    }
}

mod receipts;
pub(crate) use receipts::{DispatchVerificationIdentity, verification_identity_frame_bytes};
