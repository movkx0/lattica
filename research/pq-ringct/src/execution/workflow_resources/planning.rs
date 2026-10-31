use super::{
    owners::SlotPool,
    runtime::WorkflowAdmission,
    types::{WorkflowError, MAX_DEVICE_BYTES, MAX_HOST_BYTES, REGISTRY_BYTES},
};
use crate::{
    execution::{
        phase_lifecycle::PhaseCapability,
        retained_resources::{Bytes, Ledger, Reservation},
        ProvingContext,
    },
    graph_crypto::{PairedRequestPlan, Request, ShakeWrapperLayout},
    graph_tree::GraphContext,
    ordered_aggregation::{
        source::{FinalAggregationPlan, GraphSource},
        Plan as AggregatePlan,
    },
    spend_pipeline::full_workflow::{
        ClosedWorkflowPlan, SourceClosurePlanningPlan, SourcePlanningPlan,
    },
};
use lattica_prover_p3::proving::Policy;
use std::rc::Rc;
mod fresh;
mod guarded_original;
pub(crate) use guarded_original::GuardedPlanningOriginal;
#[cfg(not(debug_assertions))]
mod producer_metadata;
#[cfg(not(debug_assertions))]
mod producer_constructors;
#[cfg(not(debug_assertions))]
pub(crate) use producer_metadata::{producer_metadata_retained_requirements, producer_metadata_inspection_requirements};
#[cfg(not(debug_assertions))]
pub(crate) use producer_metadata::{PlanningAdmissionTransition, PlanningAdmissionProjection};
#[cfg(not(debug_assertions))]
pub(crate) use producer_constructors::{producer_constructor_requirements, producer_constructor_retained_requirements,
    CompleteSlotFailure, CompleteSlotResult, FinalContractResult, FinalContractTable, FinalContractFailure, OwnedFinalContract};

/// Planning authorization is not proving authorization. The concrete source
/// plan establishes the bound before any source metadata allocation. All B
/// plans consume original splits from this same context's original ledger.
pub(crate) struct WorkflowPlanning<'context> {
    // The metadata case pins this original through every nested caller scope.
    // Concrete plan owners keep their own splits; source owners remain backed
    // by their original claims or the legacy enclosing subtraction.
    pub(super) original: GuardedPlanningOriginal<'context>,
    pub(super) scratch: Reservation,
    pub(super) capability: PhaseCapability<'context>,
    pub(super) context: &'context ProvingContext,
    pub(super) source: [u8; 32],
    pub(super) compiled_source: [u8; 32],
    pub(super) enclosing: Bytes,
    pub(super) managed_device: u64,
    pub(super) failed: bool,
    pub(super) closure_reserved: bool,
    #[cfg(not(debug_assertions))]
    pub(super) producer_metadata: Option<producer_metadata::Installation>,
    // At most one source operation can fail: the capability cannot dispatch
    // again. This pool keeps its original claims until terminal cleanup.
    pub(super) failed_source_pool: Option<Rc<SlotPool>>,
}

impl<'context> WorkflowPlanning<'context> {
    pub(super) fn has_producer_metadata(&self) -> bool {
        #[cfg(not(debug_assertions))]
        { self.producer_metadata.is_some() }
        #[cfg(debug_assertions)]
        { false }
    }

    pub(crate) fn admit(
        plan: &SourcePlanningPlan<'context>,
    ) -> Result<Self, WorkflowError> {
        let context = plan.context();
        if context.policy() != Policy::GpuRequired {
            return Err(WorkflowError::Policy);
        }
        let source = plan.source_fingerprint();
        let compiled_source = plan.compiled_source_fingerprint();
        if compiled_source != crate::graph_proofs::compiled_source_fingerprint() {
            return Err(WorkflowError::Source);
        }
        let enclosing = plan.enclosing_bytes();
        if enclosing.host < REGISTRY_BYTES || !crate::host_memory_profile::HostMemoryProfile::valid_worker_ceiling(context.host_bytes()) {
            return Err(WorkflowError::Enclosing);
        }
        let capability = context.phase_capability(enclosing)?;
        let allowance = capability.ledger().snapshot().allowance;
        if allowance.device == 0 || allowance.device > MAX_DEVICE_BYTES {
            return Err(WorkflowError::BackendAllowance);
        }
        let managed_device = allowance
            .device
            .checked_add(enclosing.device)
            .ok_or(WorkflowError::Overflow)?;
        if managed_device > MAX_DEVICE_BYTES {
            return Err(WorkflowError::BackendAllowance);
        }
        let requirements = plan.planning_requirements();
        if requirements.total()? == Bytes::ZERO {
            return Err(WorkflowError::Planning);
        }
        // Source planning only; this original never becomes runtime authority.
        let mut original = capability.ledger().admit_phase(requirements)?;
        let scratch_requirements = plan.planning_scratch_requirements();
        if scratch_requirements.total()? == Bytes::ZERO {
            return Err(WorkflowError::Planning);
        }
        let scratch = original.split(scratch_requirements)?;
        Ok(Self {
            original: GuardedPlanningOriginal::new(original),
            scratch,
            capability,
            context,
            source,
            compiled_source,
            enclosing,
            managed_device,
            failed: false,
            closure_reserved: false,
            #[cfg(not(debug_assertions))]
            producer_metadata: None,
            failed_source_pool: None,
        })
    }

    /// The exact immutable source constructors have completed under their own
    /// original output pools. Before any recursive source plan or proof exists,
    /// replace unused bootstrap planning storage with the source-derived exact
    /// closure envelope on the SAME ledger/capability. No caller numeric budget
    /// or post-proof admission can enter this path.
    pub(crate) fn reserve_closure(
        &mut self,
        plan: &SourceClosurePlanningPlan<'_>,
    ) -> Result<(), WorkflowError> {
        if self.failed || self.closure_reserved || self.has_producer_metadata() || self.failed_source_pool.is_some() {
            return Err(WorkflowError::Poisoned);
        }
        self.failed = true;
        if !core::ptr::eq(self.context, plan.context())
            || self.source != plan.source_fingerprint()
            || self.compiled_source != plan.compiled_source_fingerprint()
            || self.enclosing != plan.enclosing_bytes()
            || !plan.belongs_to(self.capability.ledger())
            || self.capability.status() != crate::execution::phase_lifecycle::Status::Ready
        {
            return Err(WorkflowError::Identity);
        }
        let requirements = plan.planning_requirements();
        let scratch_requirements = plan.planning_scratch_requirements();
        if requirements.total()? == Bytes::ZERO || scratch_requirements.total()? == Bytes::ZERO {
            return Err(WorkflowError::Planning);
        }
        // No metadata derivation is allowed before closure_reserved, hence no
        // bootstrap original split can have escaped. Source output/failure
        // pools were split from separate borrowed phases and remain untouched.
        let original_requirements = self.original.requirements();
        let scratch_requirements_before = self.scratch.requirements();
        drop(self.original.split(original_requirements)?);
        drop(self.scratch.split(scratch_requirements_before)?);
        let original = self.capability.ledger().admit_phase(requirements)?;
        self.original.replace_depleted(original, self.capability.ledger())?;
        self.scratch = self.original.split(scratch_requirements)?;
        self.closure_reserved = true;
        self.failed = false;
        Ok(())
    }

    pub(crate) fn derive_paired_request<'request>(
        &mut self,
        request: &'request Request,
        context: GraphContext,
        layout: ShakeWrapperLayout,
    ) -> Result<PairedRequestPlan<'request>, WorkflowError> {
        if self.failed || !self.closure_reserved || self.has_producer_metadata() {
            return Err(WorkflowError::Poisoned);
        }
        let requirements = PairedRequestPlan::planning_requirements(request, layout)
            .map_err(|_| WorkflowError::Planning)?;
        let scratch = PairedRequestPlan::planning_scratch_requirements(request, layout)
            .map_err(|_| WorkflowError::Planning)?;
        if !super::types::contains(self.scratch.requirements(), scratch) {
            return Err(WorkflowError::Planning);
        }
        let original = self.original.split(requirements)?;
        PairedRequestPlan::derive_pre_reserved(
            request,
            context,
            layout,
            original,
            &self.scratch,
            self.capability.ledger(),
        )
        .map_err(|_| WorkflowError::Planning)
    }

    pub(crate) fn derive_aes_request<'request>(
        &mut self,
        request: &'request Request,
        context: GraphContext,
    ) -> Result<crate::graph_crypto::OwnedAesRequestPlan<'request>, WorkflowError> {
        use crate::graph_crypto::OwnedAesRequestPlan;
        if self.failed || !self.closure_reserved || self.has_producer_metadata() { return Err(WorkflowError::Poisoned); }
        let requirements = OwnedAesRequestPlan::planning_requirements(request)
            .map_err(|_| WorkflowError::Planning)?;
        let scratch = OwnedAesRequestPlan::planning_scratch_requirements(request)
            .map_err(|_| WorkflowError::Planning)?;
        if !super::types::contains(self.scratch.requirements(), scratch) {
            return Err(WorkflowError::Planning);
        }
        let original = self.original.split(requirements)?;
        OwnedAesRequestPlan::derive_pre_reserved(request, context, original,
            &self.scratch, self.capability.ledger()).map_err(|_| WorkflowError::Planning)
    }

    pub(crate) fn derive_final_aggregation<'source>(
        &mut self,
        scope: &'source AggregatePlan,
        graphs: &'source [GraphSource<'source>],
    ) -> Result<FinalAggregationPlan<'source>, WorkflowError> {
        if self.failed || !self.closure_reserved || self.has_producer_metadata() {
            return Err(WorkflowError::Poisoned);
        }
        let requirements = FinalAggregationPlan::planning_requirements()
            .map_err(|_| WorkflowError::Planning)?;
        let scratch = FinalAggregationPlan::planning_scratch_requirements()
            .map_err(|_| WorkflowError::Planning)?;
        if !super::types::contains(self.scratch.requirements(), scratch) {
            return Err(WorkflowError::Planning);
        }
        let original = self.original.split(requirements)?;
        FinalAggregationPlan::derive_pre_reserved(
            scope,
            graphs,
            original,
            &self.scratch,
            self.capability.ledger(),
        )
        .map_err(|_| WorkflowError::Planning)
    }

    /// A read-only identity check for source-plan assembly, not an issuer of
    /// numeric reservations or native dispatch permits.
    pub(crate) fn ledger(&self) -> &Ledger {
        self.capability.ledger()
    }

    pub(crate) fn close<'plan>(
        self,
        plan: &'plan ClosedWorkflowPlan<'plan>,
    ) -> Result<WorkflowAdmission<'plan, 'context>, WorkflowError> {
        WorkflowAdmission::from_planning(self, plan)
    }
}

#[cfg(all(feature = "full-workflow-experiment", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
mod final_aggregation;

#[cfg(all(feature = "full-workflow-experiment", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
mod producer_tables;
#[cfg(all(feature = "full-workflow-experiment", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
pub(crate) use producer_tables::{producer_table_transfer_requirements, TableTransferFailure, TableTransferResult};
