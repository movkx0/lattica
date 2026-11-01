//! Single concrete continuation while all metadata and runtime owners are live.
use super::{runtime_dispatch::RuntimeSet, case_report::CompletedCaseSummary,
    metadata_driver::{DriverStage, RuntimeAction, runtime_stage_frame_bytes}};
use super::super::{metadata_planning::SourceMetadataPlanningPlan, closed_plan::{CompleteScheduleResult, ProducerRoute, CryptoOutput, GraphPhase, FinalOutput},
    fresh_generation::{FreshGenerationBatch, FreshGenerationError, case_lifetime::{CaseOwnerSlot, CaseRetirementState}}};
use crate::{execution::{workflow_resources::{WorkflowPlanning, WorkflowError}, generation_terminal::planning_startup::FreshPlanningContext},
    graph_crypto::{ProofCache, OuterProofCache}, proof_cache_policy::FamilyStatistics};
use std::time::Instant;
type Result<T> = core::result::Result<T, WorkflowError>;

/// Runtime initialization happens once in the construction scopes, before complete closure.
/// A successful result includes real independent final CPU verification and retirement.
/// Artifact and mutation qualification are reported separately, never inferred here.
pub(crate) fn execute_constructed_case<const N: usize>(
    mut planning: WorkflowPlanning<'_>, metadata: &SourceMetadataPlanningPlan<'_>,
    startup: &CaseOwnerSlot<'_, core::result::Result<FreshPlanningContext<'_>, FreshGenerationError>>,
    batch_slot: &CaseOwnerSlot<'_, FreshGenerationBatch<N>>, case: &CaseRetirementState,
    complete_slot: &CaseOwnerSlot<'_, CompleteScheduleResult<'_>>,
    runtimes: &RuntimeSet<'_, '_, '_>, native: &ProofCache, outer: &OuterProofCache,
    stage: &mut DriverStage,
) -> Result<CompletedCaseSummary> {
    stage.runtime(RuntimeAction::ReadBatch);
    let batch = batch_slot.get().map_err(|_| WorkflowError::Identity)?;
    stage.runtime(RuntimeAction::ReadStartup);
    let fresh = startup.get().map_err(|_| WorkflowError::Identity)?.as_ref().map_err(|_| WorkflowError::Identity)?;
    stage.runtime(RuntimeAction::ReadComplete);
    let closed = complete_slot.get().map_err(|_| WorkflowError::Empty)?.as_ref().map_err(|_| WorkflowError::Source)?;
    stage.runtime(RuntimeAction::ValidateInventory);
    let inventory = closed.validated_complete_inventory().map_err(|_| WorkflowError::Identity)?;
    stage.runtime(RuntimeAction::ValidateMembers);
    if !matches!(N, 3 | 4) || metadata.members().len() != N { return Err(WorkflowError::Identity); }
    let ledger = planning.ledger().clone();
    stage.runtime(RuntimeAction::SealMetadata);
    planning.seal_producer_metadata(metadata, &inventory)?;
    stage.runtime(RuntimeAction::SealCase);
    case.seal_complete_metadata(batch_slot, fresh, complete_slot).map_err(|_| WorkflowError::Identity)?;
    let generation_and_planning_ns = batch.started().elapsed().as_nanos();
    let started = Instant::now();
    stage.runtime(RuntimeAction::CloseAdmission);
    let mut workflow = planning.close(closed)?;
    let attempted = (|| {
        runtimes.preflight(&mut workflow, &inventory, metadata, case, stage)?;
        runtimes.preissue_all(&mut workflow, &inventory, metadata, case, stage)?;
        runtimes.execute_all(&mut workflow, &inventory, metadata, case, native, outer, stage)?;
        stage.runtime(RuntimeAction::FinalReport);
        let report = runtimes.final_runtime.final_report()?;
        stage.runtime(RuntimeAction::WorkflowSnapshot);
        let owned = fresh.context().owned_workflow_snapshot().map_err(|_| WorkflowError::Identity)?;
        stage.runtime(RuntimeAction::SourcePreparationSnapshot);
        let preparation = fresh.context().source_preparation_snapshot().map_err(|_| WorkflowError::Identity)?;
        Ok((report, owned, preparation))
    })();
    let (report, owned_observations, source_preparation) = match attempted {
        Ok(report) => report,
        Err(error) => {
            // Terminal cleanup can never re-enable execution or choose another layout.
            stage.runtime_abort(true);
            return match workflow.abort() {
                Ok(()) => { stage.runtime_abort(false); Err(error) },
                Err(cleanup) => Err(cleanup),
            };
        }
    };
    stage.runtime(RuntimeAction::FinishWorkflow);
    let completion = workflow.finish()?;
    stage.runtime(RuntimeAction::ConfirmCleanup);
    let cleanup = fresh.confirm_workflow_cleanup(&completion).map_err(|_| WorkflowError::Retired)?;
    stage.runtime(RuntimeAction::CompleteCase);
    case.complete(batch_slot, fresh, closed, &completion, &cleanup).map_err(|_| WorkflowError::Retired)?;
    let proving_and_verification_ns = started.elapsed().as_nanos();
    let mut native_proofs = 0usize; let mut recursive_proofs = 0usize;
    for d in closed.dispatch() {
        match d.producer() {
            ProducerRoute::Native { .. } | ProducerRoute::Crypto { output: CryptoOutput::Native(_), .. } => native_proofs += 1,
            ProducerRoute::Crypto { output: CryptoOutput::Outer(_), .. }
                | ProducerRoute::Fixed { phase: GraphPhase::Outer, .. }
                | ProducerRoute::Leaf { phase: GraphPhase::Outer, .. }
                | ProducerRoute::Direct { phase: GraphPhase::Outer, .. }
                | ProducerRoute::Parent { phase: GraphPhase::Outer, .. }
                | ProducerRoute::Final { output: FinalOutput::Outer(_), .. } => recursive_proofs += 1,
            _ => (),
        }
    }
    let peak = ledger.snapshot().peak;
    Ok(CompletedCaseSummary { metadata_wall: None, source_geometry_cache: None, metadata_planning: None, native_metadata_cache: None, transactions: N, native_proofs, recursive_proofs,
        completed_phases: closed.steps().len(), generation_and_planning_ns, proving_and_verification_ns,
        final_cpu_verification_ns: report.cpu_verification_ns, complete_workflow_ns: None,
        ledger_peak_host_bytes: peak.host, ledger_peak_device_bytes: peak.device,
        cache_statistics: None, cache_counter_scope: "instrumented-cache-paths",
        generation_session_id: batch.generation_session_id(), generation: batch.generation_totals(),
        source_preparation, owned_observations, qualification_scope: "final-aggregate",
        final_qualification: report.qualification,
        artifacts_qualified: report.qualification.artifact_round_trip,
        mutations_qualified: report.qualification.public_mutation_rejected
            && report.qualification.proof_mutation_rejected && report.qualification.decoded_positive_checks == 3,
    })
}

pub(crate) fn retained_requirements() -> Result<crate::execution::retained_resources::Requirements> {
    use core::mem::size_of;
    use crate::execution::{retained_resources::{Requirements, Category, Bytes, Ledger, Snapshot},
        workflow_resources::{WorkflowAdmission, WorkflowCompletionReceipt},
        generation_terminal::planning_startup::PlanningCleanupReceipt};
    use crate::execution::{owned_workflow_observation::{OwnedWorkflowSnapshot, SourcePreparationSnapshot}, generation_terminal::NativeGenerationTotals};
    use crate::ordered_aggregation::owned_final::{FinalReport, FinalQualificationReport};
    let host = [runtime_stage_frame_bytes(),
        size_of::<FinalReport>(), size_of::<FinalQualificationReport>(),
        size_of::<OwnedWorkflowSnapshot>(), size_of::<SourcePreparationSnapshot>(), size_of::<NativeGenerationTotals>(),
        size_of::<(FinalReport, OwnedWorkflowSnapshot, SourcePreparationSnapshot)>(),
        size_of::<Result<(FinalReport, OwnedWorkflowSnapshot, SourcePreparationSnapshot)>>(),
        size_of::<CompletedCaseSummary>(), size_of::<Result<CompletedCaseSummary>>(),
        size_of::<WorkflowPlanning<'static>>(), size_of::<WorkflowAdmission<'static, 'static>>(),
        size_of::<Result<WorkflowAdmission<'static, 'static>>>(), size_of::<WorkflowCompletionReceipt<'static>>(),
        size_of::<Result<WorkflowCompletionReceipt<'static>>>(),
        size_of::<PlanningCleanupReceipt<'static, 'static>>(), size_of::<Ledger>(), size_of::<Snapshot>(),
        size_of::<Instant>(), size_of::<Result<()>>(), size_of::<ProducerRoute>(),
        size_of::<[FamilyStatistics; 5]>(), size_of::<[usize; 8]>(),
    ].into_iter().try_fold(0usize, |a, b| a.checked_add(b)).and_then(|n| n.checked_mul(8)).ok_or(WorkflowError::Overflow)?;
    Ok(Requirements::single(Category::RegisteredMetadata, Bytes { host: u64::try_from(host).map_err(|_| WorkflowError::Overflow)?, device: 0 }))
}
