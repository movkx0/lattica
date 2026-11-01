use super::*;

/// Each recursive frame declares one concrete owning parent family. The fixed
/// borrowed arrays can shorten their outer borrow at the next call; graph data
/// and every invariant runtime table retain their original lifetimes.
pub(super) fn run<'context, 'view, 'case, 'graph: 'view, const N: usize>(
    planning: WorkflowPlanning<'context>, metadata: &SourceMetadataPlanningPlan<'_>,
    startup: &CaseOwnerSlot<'_, core::result::Result<FreshPlanningContext<'_>, FreshGenerationError>>,
    batch: &CaseOwnerSlot<'_, FreshGenerationBatch<N>>, case: &'case CaseRetirementState,
    native_cache: &ProofCache, outer_cache: &OuterProofCache,
    leaves: LeafPlanTables<'view>, children: LeafViews<'view, 'graph>,
    ordinary: OrdinaryRuntimes<'view>,
    producer_levels: [Option<&'view dyn views::ParentPlans>; 32],
    child_levels: PriorParentLevels<'view, 'graph>,
    runtimes: ParentRuntimes<'view, 'graph>, graphs: GraphOutputs<'view, 'case, 'graph>,
    level: usize,
    stage: &mut DriverStage,
) -> Result<CompletedCaseSummary> {
    super::super::metadata_timing::phase(super::super::metadata_timing::Phase::Graph);
    stage.layer("parents");
    stage.level(level);
    let mut planning = PlanningGuard::new(planning);
    planning.get()?.validate_metadata_driver(metadata, case)?;
    if level > 32 || metadata.counts().parent_level(32).is_some() {
        return Err(WorkflowError::Sequence);
    }
    let count = if level == 32 { 0 } else {
        metadata.counts().parent_level(level).ok_or(WorkflowError::Sequence)?
    };
    if count == 0 {
        // A valid binary reduction has no later nonempty level after closure.
        for later in level..32 {
            if metadata.counts().parent_level(later) != Some(0)
                || producer_levels[later].is_some() || child_levels[later].is_some()
                || runtimes[later].is_some() || graphs.parents[later].is_some()
            { return Err(WorkflowError::Sequence); }
        }
        return final_stage::run(planning.into_inner()?, metadata, startup, batch, case,
            native_cache, outer_cache, leaves, children, ordinary, producer_levels,
            child_levels, runtimes, graphs, stage);
    }
    if producer_levels[level].is_some() || child_levels[level].is_some()
        || runtimes[level].is_some() || graphs.parents[level].is_some()
    { return Err(WorkflowError::Sequence); }

    stage.layer("metadata_parent_plans");
    stage.level(level);

    let parent_plans_result = planning.get()?.metadata_parent_plans(metadata, case, level);
    let parent_plans = table(&parent_plans_result)?;
    graph_layers::fill_parent_level(planning.get()?, metadata, case, level,
        children, child_levels, outer_cache, parent_plans, stage)?;
    stage.layer("metadata_parent_compiled_outputs");
    stage.level(level);
    let parent_compiled_result = planning.get()?.metadata_parent_compiled_outputs(metadata, case, level);
    let parent_compiled = table(&parent_compiled_result)?;
    stage.layer("metadata_parent_outer_outputs");
    stage.level(level);
    let parent_outer_result = planning.get()?.metadata_parent_outer_outputs(metadata, case, level);
    let parent_outer = table(&parent_outer_result)?;
    stage.layer("metadata_parent_preissues");
    stage.level(level);
    let parent_packets_result = planning.get()?.metadata_parent_preissues(metadata, case, level);
    let parent_packets = table(&parent_packets_result)?;
    let runtime = ParentRuntime { level, plans: parent_plans, compiled: parent_compiled,
        outer: parent_outer, packets: parent_packets };

    let mut next_producers: [Option<&dyn views::ParentPlans>; 32] = producer_levels;
    let mut next_children: PriorParentLevels<'_, 'graph> = child_levels;
    let mut next_runtimes: ParentRuntimes<'_, 'graph> = runtimes;
    let mut next_graphs: GraphOutputs<'_, 'case, 'graph> = graphs;
    next_producers[level] = Some(parent_plans);
    next_children[level] = Some(parent_plans);
    next_runtimes[level] = Some(&runtime);
    next_graphs.parents[level] = Some(parent_outer);
    let next = level.checked_add(1).ok_or(WorkflowError::Overflow)?;
    run(planning.into_inner()?, metadata, startup, batch, case, native_cache, outer_cache,
        leaves, children, ordinary, next_producers, next_children, next_runtimes,
        next_graphs, next, stage)
}
