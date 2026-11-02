//! One-shot original metadata installation and authenticated closure seal.
//! The source-construction budget is distinct from complete execution closure.
use super::*;
use crate::{execution::{generation_terminal::planning_startup::FreshPlanningContext,
        retained_resources::{Category, Requirements}},
    spend_pipeline::full_workflow::{ClosureError, PreparedWorkflowSources,
    metadata_planning::{MetadataPlanningStage, SourceMetadataPlanningPlan},
        fresh_generation::{FreshGenerationError,
            case_lifetime::{CaseOwnerSlot, CaseRetirementState}}}};
use core::mem::size_of;
mod admission_transition;
pub(crate) use admission_transition::{PlanningAdmissionTransition, PlanningAdmissionProjection};

pub(in crate::execution::workflow_resources) struct Installation {
    plan: *const (),
    scope: *const (),
    members: [*const (); 4],
    count: usize,
    case: *const (),
    issued_tables: [u64; 4],
    // Stage 0 counts constructors; SHAKE/AES stage 1 counts completed source
    // endpoints. Their inequality blocks every ordinary metadata continuation.
    pub(super) constructors: [usize; 48],
    pub(super) parents: [usize; 32],
    pub(super) final_source: bool,
    pub(super) final_plan: bool,
    pub(super) closed: bool,
    sealed: *const (),
}

impl Installation {
    fn matches(&self, plan: &SourceMetadataPlanningPlan<'_>) -> bool {
        self.plan == plan as *const _ as *const ()
            && self.scope == plan.scope() as *const _ as *const ()
            && self.count == plan.members().len()
            && plan.members().iter().enumerate().all(|(index, member)|
                self.members[index] == *member as *const _ as *const ())
    }
    pub(in crate::execution::workflow_resources) fn matches_closed(&self, plan: &ClosedWorkflowPlan<'_>) -> bool {
        !self.sealed.is_null() && self.sealed == plan as *const _ as *const ()
    }
}

/// Controller and forwarding frames survive all producer original splits.
pub(crate) fn producer_metadata_retained_requirements() -> Result<Requirements, WorkflowError> {
    let bytes = [size_of::<Installation>(), size_of::<Option<Installation>>(),
        size_of::<WorkflowPlanning<'static>>(), size_of::<GuardedPlanningOriginal<'static>>(),
        size_of::<Option<GuardedPlanningOriginal<'static>>>(),
        size_of::<Result<GuardedPlanningOriginal<'static>, WorkflowError>>(),
        size_of::<Option<Reservation>>(), size_of::<Option<&CaseRetirementState>>(),
        size_of::<core::result::Result<(), FreshGenerationError>>(),
        size_of::<Result<(), WorkflowError>>(),
        size_of::<Result<Requirements, WorkflowError>>(), size_of::<[Reservation; 4]>(),
        size_of::<[Requirements; 8]>(), size_of::<[Bytes; 4]>(), size_of::<[usize; 16]>(),
        size_of::<[&SourceMetadataPlanningPlan<'static>; 4]>(),
        size_of::<MetadataPlanningStage>(), size_of::<&mut MetadataPlanningStage>(),
        size_of::<Result<&CaseRetirementState, FreshGenerationError>>(),
        size_of::<crate::spend_pipeline::full_workflow::ValidatedCompleteInventory<'static, 'static>>(),
        size_of::<String>(), 128,
    ].into_iter().try_fold(0usize, |sum, part| sum.checked_add(part))
        .and_then(|sum| sum.checked_mul(8)).ok_or(WorkflowError::Overflow)?;
    Ok(Requirements::single(Category::RegisteredMetadata, Bytes {
        host: u64::try_from(bytes).map_err(|_| WorkflowError::Overflow)?, device: 0,
    }))
}

/// Pure bootstrap caller census; this never evaluates source bounds again.
pub(crate) fn producer_metadata_inspection_requirements() -> Result<Requirements, WorkflowError> {
    super::super::types::combine(Requirements::single(Category::PhaseScratch,
        producer_metadata_retained_requirements()?.total()?),
        super::super::source_endpoints::metadata_endpoint_query_requirements()?)
}

impl<'context> WorkflowPlanning<'context> {
    /// Query bounds under the already admitted source bootstrap scratch.
    /// The caller installs the entire Result before inspecting its status.
    pub(crate) fn plan_producer_metadata<'a>(&mut self, scope: &'a SourcePlanningPlan<'a>,
        members: &'a [&'a super::super::SourceRetained<PreparedWorkflowSources<'a>>],
        stage: &mut MetadataPlanningStage)
        -> Result<SourceMetadataPlanningPlan<'a>, ClosureError>
    {
        *stage = MetadataPlanningStage::Readiness;
        let ready = !self.failed && !self.closure_reserved && self.producer_metadata.is_none()
            && self.failed_source_pool.is_none()
            && self.capability.status() == crate::execution::phase_lifecycle::Status::Ready
            && core::ptr::eq(self.context, scope.context())
            && self.source == scope.source_fingerprint()
            && self.compiled_source == scope.compiled_source_fingerprint()
            && self.enclosing == scope.enclosing_bytes();
        self.failed = true;
        if !ready { return Err(ClosureError::Identity); }
        let result = SourceMetadataPlanningPlan::new(scope, members, self.capability.ledger(), &self.scratch, stage);
        if result.is_ok() { self.failed = false; }
        result
    }

    /// Bootstrap claims have issued no producer-metadata splits. Replace them
    /// once with the complete construction envelope; prepared source owners
    /// retain their separate original pools on this exact same ledger.
    pub(crate) fn reserve_producer_metadata<'case: 'context>(&mut self, plan: &SourceMetadataPlanningPlan<'_>,
        planning_slot: &crate::spend_pipeline::full_workflow::fresh_generation::case_lifetime::MetadataOwner<'_, 'case, '_>)
        -> Result<(), WorkflowError>
    {
        if self.failed || self.closure_reserved || self.producer_metadata.is_some()
            || self.failed_source_pool.is_some()
        { return Err(WorkflowError::Poisoned); }
        self.failed = true;
        let case = planning_slot.metadata_case_state(plan.scope(), self.capability.ledger())
            .map_err(|_| WorkflowError::Identity)?;
        if !core::ptr::eq(self.context, plan.context())
            || self.source != plan.source_fingerprint()
            || self.compiled_source != plan.compiled_source_fingerprint()
            || self.enclosing != plan.enclosing_bytes()
            || !plan.belongs_to(self.capability.ledger())
            || self.capability.status() != crate::execution::phase_lifecycle::Status::Ready
            || !matches!(plan.members().len(), 3 | 4)
        { return Err(WorkflowError::Identity); }
        let requirements = plan.planning_requirements();
        let scratch_requirements = plan.planning_scratch_requirements();
        if requirements.total()? == Bytes::ZERO || scratch_requirements.total()? == Bytes::ZERO {
            return Err(WorkflowError::Planning);
        }
        let mut members = [core::ptr::null(); 4];
        for (slot, member) in members.iter_mut().zip(plan.members()) {
            *slot = *member as *const _ as *const ();
        }
        // Attach before replacement: errors, moves and unwind keep the same
        // original guard, including a refused new metadata envelope.
        self.original.pin_case(case)?;
        let previous = self.original.requirements();
        let previous_scratch = self.scratch.requirements();
        drop(self.original.split(previous)?);
        drop(self.scratch.split(previous_scratch)?);
        let original = self.capability.ledger().admit_phase(requirements)?;
        self.original.replace_depleted(original, self.capability.ledger())?;
        self.scratch = self.original.split(scratch_requirements)?;
        let positions = self.original.split(plan.position_requirements().map_err(|_| WorkflowError::Planning)?)?;
        plan.initialize_positions(positions).map_err(|_| WorkflowError::Planning)?;
        self.producer_metadata = Some(Installation {
            plan: plan as *const _ as *const (), scope: plan.scope() as *const _ as *const (),
            members, count: plan.members().len(), case: case as *const _ as *const (),
            issued_tables: [0; 4], constructors: [0; 48], parents: [0; 32],
            final_source: false, final_plan: false, closed: false, sealed: core::ptr::null(),
        });
        // Construction may now consume original splits. Complete closure and
        // execution remain forbidden until the separate authenticated seal.
        self.failed = false;
        Ok(())
    }

    pub(super) fn check_metadata(&self, plan: &SourceMetadataPlanningPlan<'_>) -> Result<(), WorkflowError> {
        self.check_metadata_identity(plan)?;
        if !super::producer_constructors::crypto_endpoints_complete(
            &self.producer_metadata.as_ref().ok_or(WorkflowError::Identity)?.constructors)
        { return Err(WorkflowError::Sequence); }
        Ok(())
    }

    // Only the named endpoint gate may enter while one crypto source is pending.
    // This retains all original metadata, context, readiness and poison checks.
    pub(super) fn check_metadata_identity(&self, plan: &SourceMetadataPlanningPlan<'_>) -> Result<(), WorkflowError> {
        if self.failed || self.closure_reserved || self.failed_source_pool.is_some()
            || self.capability.status() != crate::execution::phase_lifecycle::Status::Ready
            || self.producer_metadata.as_ref().is_none_or(|installed| !installed.matches(plan))
            || !core::ptr::eq(self.context, plan.context())
            || self.source != plan.source_fingerprint()
            || self.compiled_source != plan.compiled_source_fingerprint()
            || self.enclosing != plan.enclosing_bytes()
            || !plan.belongs_to(self.capability.ledger())
        { return Err(WorkflowError::Identity); }
        Ok(())
    }

    pub(super) fn begin_metadata_table(&mut self, plan: &SourceMetadataPlanningPlan<'_>,
        case: &CaseRetirementState, table: usize) -> Result<(), WorkflowError>
    {
        let checked = self.check_metadata(plan);
        self.failed = true;
        checked?;
        if table >= 256 { return Err(WorkflowError::Planning); }
        let installed = self.producer_metadata.as_mut().ok_or(WorkflowError::Planning)?;
        if installed.case != case as *const _ as *const ()
            || installed.issued_tables[table / 64] & (1u64 << (table % 64)) != 0
        { return Err(WorkflowError::Identity); }
        installed.issued_tables[table / 64] |= 1u64 << (table % 64);
        Ok(())
    }

    pub(super) fn finish_metadata_table_success(&mut self) { self.failed = false; }

    pub(super) fn metadata_case_matches(&self, case: &CaseRetirementState) -> bool {
        self.original.is_pinned_to(case) && self.producer_metadata.as_ref().is_some_and(|installed|
            installed.case == case as *const _ as *const ())
    }

    /// Pure driver traversal/blueprint creation uses the complete already
    /// admitted inspection envelope. It cannot submit a caller budget or
    /// obtain a new original. Actual owning tables are separately checked by
    /// the driver against this same case before any slot is populated.
    pub(crate) fn validate_metadata_driver(&mut self, plan: &SourceMetadataPlanningPlan<'_>,
        case: &CaseRetirementState) -> Result<(), WorkflowError>
    {
        let checked = self.check_metadata(plan).and_then(|()| {
            if !self.metadata_case_matches(case)
                || !self.original.belongs_to(self.capability.ledger())
                || !self.scratch.belongs_to(self.capability.ledger())
                || !super::super::types::contains(self.scratch.requirements(), plan.planning_scratch_requirements())
            { return Err(WorkflowError::Identity); }
            Ok(())
        });
        if checked.is_err() { self.failed = true; }
        checked
    }

    /// Driver RAII uses this on an error or unwind. There is deliberately no
    /// driver API which clears failure or reopens a consumed constructor.
    pub(crate) fn poison_metadata_driver(&mut self) { self.failed = true; }

    /// This consumes no original and performs no admission. Only B's opaque
    /// token from a successfully validated complete typed graph may seal.
    pub(crate) fn seal_producer_metadata(&mut self, plan: &SourceMetadataPlanningPlan<'_>,
        complete: &crate::spend_pipeline::full_workflow::ValidatedCompleteInventory<'_, '_>)
        -> Result<(), WorkflowError>
    {
        let checked = self.check_metadata(plan);
        self.failed = true;
        checked?;
        if !complete.matches_metadata(plan)
            || !complete.closed_plan().belongs_to(self.capability.ledger())
            || !complete.closed_plan().fresh_only()
        { return Err(WorkflowError::Identity); }
        let installed = self.producer_metadata.as_mut().ok_or(WorkflowError::Planning)?;
        if !installed.closed || !installed.sealed.is_null() { return Err(WorkflowError::Planning); }
        installed.sealed = complete.closed_plan() as *const _ as *const ();
        self.closure_reserved = true;
        self.failed = false;
        Ok(())
    }
}
