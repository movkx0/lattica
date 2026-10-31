//! Concrete original-claim bridge for whole-case planning. Root adds this new
//! module hook; no existing source planner or shared parent is edited here.
use super::{planning::WorkflowPlanning, SourceRetained};
use crate::{
    execution::phase_lifecycle::Status,
    graph_crypto::{OuterProofCache, ProofCache},
    ordered_aggregation::source::FinalAggregationPlan,
    spend_pipeline::full_workflow::{ClosedWorkflowPlan, ClosureError, ClosureInspection,
        CryptoRequestPlan, PreparedWorkflowSources, SourceClosurePlanningPlan,
        SourceOperationPlan, SourcePlanningPlan},
};

impl WorkflowPlanning<'_> {
    fn check_closure_source(&self, scope: &SourcePlanningPlan<'_>) -> Result<(), ClosureError> {
        if self.failed || self.closure_reserved || self.has_producer_metadata() || self.failed_source_pool.is_some()
            || self.capability.status() != Status::Ready
            || !core::ptr::eq(self.context, scope.context())
            || self.source != scope.source_fingerprint()
            || self.compiled_source != scope.compiled_source_fingerprint()
            || self.enclosing != scope.enclosing_bytes()
        { return Err(ClosureError::Identity); }
        Ok(())
    }

    /// Pure diagnostic. No plan/output allocation, Session transition or proof
    /// occurs; bootstrap inspection scratch must already be admitted by root.
    pub(crate) fn inspect_complete_case<'a>(&self, scope: &'a SourcePlanningPlan<'a>,
        members: &'a [&'a SourceRetained<PreparedWorkflowSources<'a>>])
        -> Result<ClosureInspection, ClosureError>
    {
        self.check_closure_source(scope)?;
        SourceClosurePlanningPlan::inspect(scope, members, self.capability.ledger(), &self.scratch)
    }

    pub(crate) fn plan_complete_case_metadata<'a>(&mut self, scope: &'a SourcePlanningPlan<'a>,
        members: &'a [&'a SourceRetained<PreparedWorkflowSources<'a>>])
        -> Result<SourceClosurePlanningPlan<'a>, ClosureError>
    {
        let result = self.check_closure_source(scope).and_then(|()|
            SourceClosurePlanningPlan::new(scope, members, self.capability.ledger(), &self.scratch));
        if result.is_err() { self.failed = true; }
        result
    }

    pub(crate) fn derive_closed_workflow<'a>(&mut self, closure: &'a SourceClosurePlanningPlan<'a>,
        fixed: &'a [&'a SourceOperationPlan<'a>], crypto: &'a [CryptoRequestPlan<'a>],
        final_source: &'a FinalAggregationPlan<'a>, native_cache: &'a ProofCache,
        outer_cache: &'a OuterProofCache) -> Result<ClosedWorkflowPlan<'a>, ClosureError>
    {
        let result = (|| {
            if self.failed || !self.closure_reserved || self.has_producer_metadata() || self.failed_source_pool.is_some()
                || self.capability.status() != Status::Ready
                || !core::ptr::eq(self.context, closure.context())
                || self.source != closure.source_fingerprint()
                || self.compiled_source != closure.compiled_source_fingerprint()
                || self.enclosing != closure.enclosing_bytes()
                || !closure.belongs_to(self.capability.ledger())
            { return Err(ClosureError::Identity); }
            let requirement = ClosedWorkflowPlan::planning_requirements(closure)?;
            let original = self.original.split(requirement).map_err(|_| ClosureError::Resource)?;
            ClosedWorkflowPlan::derive_pre_reserved(closure, fixed, crypto, final_source,
                original, native_cache, outer_cache)
        })();
        if result.is_err() { self.failed = true; }
        result
    }
}
