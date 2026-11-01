use super::*;
use crate::spend_pipeline::full_workflow::closed_plan::CompleteScheduleResult;

// The failed schedule and its original reservation stay in the case slot.
// Only the fixed completion stage and closure error are copied for diagnostics.
fn install_complete<'case, 'a>(slot: &CaseOwnerSlot<'case, CompleteScheduleResult<'a>>,
    result: CompleteScheduleResult<'a>) -> Result<()>
{
    slot.install(result).map_err(|_| WorkflowError::Sequence)?;
    slot.get().map_err(|_| WorkflowError::Sequence)?.as_ref()
        .map_err(|failure| WorkflowError::CompleteSource {
            stage: failure.stage(), cause: *failure.error(),
        })?;
    Ok(())
}


fn graph_root<'view, 'graph: 'view>(metadata: &SourceMetadataPlanningPlan<'_>,
    parents: PriorParentLevels<'view, 'graph>, member: usize, stage: &mut DriverStage)
    -> Result<GraphChildSource<'view, 'graph>>
{
    stage.layer("graph_root");
    stage.member(member);
    let prepared = metadata.members().get(member).ok_or(WorkflowError::Identity)?.get();
    let expected = (0, prepared.plan().leaves().len());
    let mut found = None;
    for (level, table) in parents.into_iter().enumerate() {
        let Some(table) = table else { continue; };
        stage.level(level);
        for ordinal in 0..table.len() {
            stage.destination(ordinal);
            let child = table.child(ordinal, metadata.ledger())?;
            let source = child.source();
            if core::ptr::eq(source.graph_plan(), prepared.plan())
                && core::ptr::eq(source.context(), prepared.context())
                && source.span().interval() == expected
            {
                if found.is_some() { return Err(WorkflowError::Identity); }
                found = Some(child);
            }
        }
    }
    found.ok_or(WorkflowError::Identity)
}

pub(super) fn run<'view, 'case, 'graph: 'view, const N: usize>(
    planning: WorkflowPlanning<'_>, metadata: &SourceMetadataPlanningPlan<'_>,
    startup: &CaseOwnerSlot<'_, core::result::Result<FreshPlanningContext<'_>, FreshGenerationError>>,
    batch: &CaseOwnerSlot<'_, FreshGenerationBatch<N>>, case: &'case CaseRetirementState,
    native_cache: &ProofCache, outer_cache: &OuterProofCache,
    leaves: LeafPlanTables<'view>, _children: LeafViews<'view, 'graph>,
    ordinary: OrdinaryRuntimes<'view>,
    producer_levels: [Option<&'view dyn views::ParentPlans>; 32],
    child_levels: PriorParentLevels<'view, 'graph>,
    parent_runtimes: ParentRuntimes<'view, 'graph>, graphs: GraphOutputs<'view, 'case, 'graph>,
    stage: &mut DriverStage,
) -> Result<CompletedCaseSummary> {
    stage.layer("final_stage");
    super::super::metadata_timing::phase(super::super::metadata_timing::Phase::Final);
    let mut planning = PlanningGuard::new(planning);
    planning.get()?.validate_metadata_driver(metadata, case)?;
    if !matches!(N, 3 | 4) || metadata.members().len() != N {
        return Err(WorkflowError::Identity);
    }

    *stage = DriverStage::Call("derive_metadata_final_contract");

    let final_contract_result = planning.get()?.derive_metadata_final_contract(metadata, case);
    let final_contract = table(&final_contract_result)?;
    let contract = successful(final_contract, 0)?;
    *stage = DriverStage::Call("metadata_final_sources");
    let final_sources_result = planning.get()?.metadata_final_sources(metadata, case);
    let final_sources = table(&final_sources_result)?;
    empty_table(final_sources, case, 1)?;
    let source_slot = final_sources.slots().first().ok_or(WorkflowError::Slot)?;
    *stage = DriverStage::Call("derive_metadata_final_source");
    let source_result = planning.get()?.derive_metadata_final_source(metadata, contract)?;
    install(source_slot, source_result)?;
    let source = successful(final_sources, 0)?;

    *stage = DriverStage::Call("metadata_final_plans");

    let final_plans_result = planning.get()?.metadata_final_plans(metadata, case);
    let final_plans = table(&final_plans_result)?;
    empty_table(final_plans, case, 1)?;
    let phase_slot = final_plans.slots().first().ok_or(WorkflowError::Slot)?;
    let first = graph_root(metadata, child_levels, 0, stage)?;
    let second = graph_root(metadata, child_levels, 1, stage)?;
    let third = graph_root(metadata, child_levels, 2, stage)?;
    // Both branches retain a whole constructor Result until its original slot
    // owns it. No graph proof is created or consumed by this metadata pass.
    let phase_result = match N {
        3 => {
            *stage = DriverStage::Call("derive_metadata_final_phase_n3");
            planning.get()?.derive_metadata_final_phase(metadata, contract, source,
                &[first, second, third], outer_cache)?
        }
        4 => {
            let fourth = graph_root(metadata, child_levels, 3, stage)?;
            *stage = DriverStage::Call("derive_metadata_final_phase_n4");
            planning.get()?.derive_metadata_final_phase(metadata, contract, source,
                &[first, second, third, fourth], outer_cache)?
        }
        _ => return Err(WorkflowError::Identity),
    };
    install(phase_slot, phase_result)?;

    *stage = DriverStage::Call("metadata_final_compiled_outputs");

    let final_compiled_result = planning.get()?.metadata_final_compiled_outputs(metadata, case);
    let final_compiled = table(&final_compiled_result)?;
    *stage = DriverStage::Call("metadata_final_outer_outputs");
    let final_outer_result = planning.get()?.metadata_final_outer_outputs(metadata, case);
    let final_outer = table(&final_outer_result)?;
    *stage = DriverStage::Call("metadata_final_root");
    let final_root_result = planning.get()?.metadata_final_root(metadata, case);
    let final_root = table(&final_root_result)?;
    *stage = DriverStage::Call("metadata_final_verify_outputs");
    let final_verified_result = planning.get()?.metadata_final_verify_outputs(metadata, case);
    let final_verified = table(&final_verified_result)?;
    *stage = DriverStage::Call("metadata_final_preissues");
    let final_packets_result = planning.get()?.metadata_final_preissues(metadata, case);
    let final_packets = table(&final_packets_result)?;
    *stage = DriverStage::Call("metadata_final_driver_failure");
    let final_failure_result = planning.get()?.metadata_final_driver_failure(metadata, case);
    let final_failure = table(&final_failure_result)?;
    let final_runtime = FinalRuntime { plans: final_plans, compiled: final_compiled,
        outer: final_outer, root: final_root, verified: final_verified,
        packets: final_packets, failure: final_failure, graphs };
    let runtimes = RuntimeSet { native: ordinary.native, shake: ordinary.shake,
        aes: ordinary.aes, fixed: ordinary.fixed, parameters: ordinary.parameters,
        auxiliary: ordinary.auxiliary, equality: ordinary.equality,
        parents: parent_runtimes, graphs, final_runtime: &final_runtime };

    // Initialize every concrete result/packet cell exactly once before closure.
    *stage = DriverStage::Call("initialize_runtime_tables");
    runtimes.initialize(planning.get()?, metadata, case)?;
    *stage = DriverStage::Call("plan_metadata_parent_tables");
    let mut parent_tables_result = planning.get()?.plan_metadata_parent_tables(metadata);
    let parent_tables = parent_tables_result.as_mut().map_err(|_| WorkflowError::Planning)?;
    for (level, table) in producer_levels.into_iter().enumerate() {
        if let Some(table) = table {
            stage.layer("bind_parent_level");
            stage.level(level);
            parent_tables.bind_level(level, table).map_err(|_| WorkflowError::Identity)?;
        }
    }
    *stage = DriverStage::Call("complete_producer_projection");
    let producers = leaves.complete(parent_tables, final_contract, final_sources, final_plans);
    *stage = DriverStage::Call("metadata_complete_slot");
    let complete_slot_result = planning.get()?.metadata_complete_slot(metadata, case);
    let complete_slot = complete_slot_result.as_ref().map_err(|_| WorkflowError::Planning)?;
    *stage = DriverStage::Call("derive_metadata_complete");
    let complete_result = planning.get()?.derive_metadata_complete(metadata, startup,
        &producers, native_cache, outer_cache)?;
    install_complete(complete_slot, complete_result)?;

    // No callback is supplied. The coordinator's single concrete continuation
    // seals, proves, verifies, retires and completes the case while all actual
    // owning locals in every scope are still alive. Artifact and mutation
    // qualification remain separately reported by that continuation.
    super::super::metadata_timing::finish();
    *stage = DriverStage::Call("execute_constructed_case");
    let outcome = super::super::execution::execute_constructed_case(planning.into_inner()?, metadata,
        startup, batch, case, complete_slot, &runtimes, native_cache, outer_cache, stage);
    if outcome.is_ok() { *stage = DriverStage::Complete; }
    outcome
}
