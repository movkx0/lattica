//! Take final-stage metadata only from the existing complete planning original.
use super::*;
use crate::{
    graph_crypto::OuterProofCache,
    graph_tree::owned_parent::GraphChildSource,
    ordered_aggregation::owned_final::FinalPhasePlan,
    recursive_aggregation::LeafStatement,
};

impl WorkflowPlanning<'_> {
    pub(crate) fn derive_final_phases<'source>(&mut self,
        source: &'source FinalAggregationPlan<'source>, statements: &'source [LeafStatement],
        graph_producers: &[GraphChildSource<'source, 'source>], cache: &'source OuterProofCache)
        -> Result<FinalPhasePlan<'source>, WorkflowError>
    {
        let result = (|| {
            if self.failed || !self.closure_reserved || self.has_producer_metadata() || self.failed_source_pool.is_some() {
                return Err(WorkflowError::Poisoned);
            }
            let requirements = FinalPhasePlan::planning_requirements().map_err(|_| WorkflowError::Planning)?;
            let scratch = FinalPhasePlan::planning_scratch_requirements().map_err(|_| WorkflowError::Planning)?;
            if !super::super::types::contains(self.scratch.requirements(), scratch) {
                return Err(WorkflowError::Planning);
            }
            let original = self.original.split(requirements)?;
            FinalPhasePlan::derive_pre_reserved(source, statements, graph_producers,
                cache, original, &self.scratch, self.capability.ledger()).map_err(|_| WorkflowError::Planning)
        })();
        if result.is_err() { self.failed = true; }
        result
    }
}
