//! Fixed fresh N3/N4 entry. Every source dependency layer has a stable owner.
use super::super::{InitialNativeSource, SourcePlanningPlan, SourcePreparationError, ClosureError, PreparedWorkflowSources,
    bootstrap_layers::{self, GraphPlanResult, GraphSourceResult, PreparationPlanResult, PreparedSourceResult},
    metadata_planning::{SourceMetadataPlanningPlan, MetadataPlanningStage},
    fresh_generation::{FreshGenerationBatch, FreshGenerationError, caches::FreshProofCaches, case_lifetime::CaseRetirementState}};
use crate::{graph_crypto::ShakeWrapperLayout, execution::workflow_resources::{WorkflowPlanning, SourceRetained}};
use super::metadata_timing::{self, Phase};
type Result<T> = core::result::Result<T, FreshGenerationError>;
fn failed(message: &'static str) -> FreshGenerationError { FreshGenerationError::Resource(message) }

pub(crate) use super::case_report::CompletedCaseSummary;

macro_rules! fixed_case {
    ($name:ident, $n:literal, $first:literal, $preclaim:ident, $scope:ident, [$($index:literal),+]) => {
        pub(crate) fn $name(setup_seed: [u8; 32], context: [u8; 32], layout: ShakeWrapperLayout,
identity_limits: lattica_prover_p3::block_v2::machine::backend::identity_cpu::IdentityCpuOptions, host_profile: crate::host_memory_profile::HostMemoryProfile, planning_cache: bool,
metadata_cpu: lattica_prover_p3::block_v2::machine::verifier::batch::shape::MetadataCpuOptions) -> Result<CompletedCaseSummary> {
            let (mut summary, observation, started) = {
                #[cfg(test)]
                let input_started = std::time::Instant::now();
                let generated = FreshGenerationBatch::<$n>::generate_with_host_profile(setup_seed, context, $first, host_profile)?;
                #[cfg(test)]
                let native_input_generation_ns = input_started.elapsed().as_nanos();
                #[cfg(test)]
        super::metadata_profile::capture(&generated.views()?).map_err(|_| failed("metadata fixture capture failed"))?;
        let started = generated.started();
                let case = CaseRetirementState::prepare(&generated)?;
                let batch_slot = case.install_batch(generated)?;
                let mut startup = batch_slot.begin_planning()?;
                // These fixed entry/report frames remain charged through final context cleanup.
                let caches_owner = case.preclaim::<Result<FreshProofCaches>>()?;
                caches_owner.install(FreshProofCaches::new(batch_slot.get()?))?;
                let summary = {
                let batch = batch_slot.get()?;
                    let fresh = startup.get()?.as_ref().map_err(|_| failed("fresh planning startup refused"))?;
                // The fresh context's original 64 MiB metadata claim includes the
                // dedicated 1 MiB geometry sublimit before this scope is created.
                #[cfg(test)]
                let generation_and_startup_ns = input_started.elapsed().as_nanos();
                let metadata_clock = metadata_timing::Scope::begin().ok_or_else(|| failed("metadata clock scope"))?;
                let geometry_cache = if planning_cache {
                    Some(lattica_prover_p3::block_v2::machine::verifier::batch::shape::HeightEnvelopeCacheScope::begin_with_precomputed(
                        crate::graph_proofs::compiled_source_fingerprint()).map_err(|_| failed("geometry cache scope"))?)
                } else { None };
let native_metadata_cache = if planning_cache {
    Some(crate::component_tree::native_shape::cache::Scope::begin_with_precomputed(crate::graph_proofs::compiled_source_fingerprint())
        .map_err(|_| failed("native metadata cache scope"))?)
} else { None };
// Fixed scope statistics fit the existing metadata claim; every compiler cohort
// subdivides its caller's separately held source-planning reservation.
let metadata_planner = lattica_prover_p3::block_v2::machine::verifier::batch::shape::MetadataPlanningScope::begin(metadata_cpu)
    .map_err(|_| failed("metadata planning scope"))?;
                        // Declare owning layers before source planning takes its exact enclosing snapshot.
                    let views = case.preclaim::<Result<[InitialNativeSource<'_>; $n]>>()?;
                    let scope = case.preclaim::<core::result::Result<SourcePlanningPlan<'_>, SourcePreparationError>>()?;
                    let graph_plans = case.$preclaim::<GraphPlanResult<'_>>()?;
                    let graphs = case.$preclaim::<GraphSourceResult>()?;
                    let preparation_plans = case.$preclaim::<PreparationPlanResult<'_>>()?;
                    let prepared = case.$preclaim::<PreparedSourceResult<'_>>()?;
                    let members = case.preclaim::<[&SourceRetained<PreparedWorkflowSources<'_>>; $n]>()?;
                    let metadata = case.preclaim::<core::result::Result<SourceMetadataPlanningPlan<'_>, ClosureError>>()?;
                    views.install(batch.views())?;
                    let views = views.get()?.as_ref().map_err(|_| failed("fresh source views refused"))?;
                    let caches = caches_owner.get()?.as_ref().map_err(|_| failed("fresh proof controls refused"))?;
                    scope.install(SourcePlanningPlan::$scope(fresh, views, layout, batch)
                        .and_then(|plan| plan.with_identity_limits(identity_limits)))?;
                    let scope = scope.get()?.as_ref().map_err(|_| failed("fresh source scope refused"))?;
                    let metadata_owner = super::super::fresh_generation::case_lifetime::MetadataOwner::Fresh(&startup);
        let mut planning = WorkflowPlanning::admit_fresh(scope, fresh).map_err(|_| failed("fresh workflow planning admission refused"))?;
                    metadata_timing::phase(Phase::GraphSources);
                    bootstrap_layers::prepare_graph_layer(scope, &mut planning, &metadata_owner, graph_plans.get()?, graphs.get()?)?;
                    metadata_timing::phase(Phase::SourcePreparation);
                    bootstrap_layers::prepare_source_layer(scope, &mut planning, &metadata_owner, graphs.get()?, preparation_plans.get()?, prepared.get()?)?;
                    members.install([$(prepared.get()?.get($index)?.get()?.as_ref().map_err(|_| failed("fresh source preparation refused"))?),+])?;
                    metadata_timing::phase(Phase::Inventory);
                    let mut metadata_stage = MetadataPlanningStage::Readiness;
                    metadata.install(planning.plan_producer_metadata(scope, members.get()?, &mut metadata_stage))?;
                    let metadata = metadata.get()?.as_ref().map_err(|error| FreshGenerationError::ProducerMetadata { stage: metadata_stage, cause: *error })?;
                    metadata_timing::phase(Phase::Reservation);
                    planning.reserve_producer_metadata(metadata, &metadata_owner).map_err(|_| failed("producer metadata reservation refused"))?;
                    metadata_timing::phase(Phase::Constructors);
                    let mut driver_stage = super::metadata_driver::DriverStage::Readiness;
                    let outcome = super::metadata_driver::run(planning, metadata, &metadata_owner, Some(&batch_slot), &case, &caches.native, &caches.outer, &mut driver_stage);
                    #[cfg(test)]
                    if super::metadata_profile::active() && outcome.is_err() {
                        let complete = matches!(&outcome, Err(crate::execution::workflow_resources::WorkflowError::MetadataProfileComplete));
                        // Preserve explicitly incomplete diagnostics on a normal
                        // metadata refusal; only the final stop marks completion.
                        if !complete { metadata_timing::finish(); }
                        super::metadata_profile::record(complete, $n, native_input_generation_ns, generation_and_startup_ns,
                            metadata_clock.statistics().ok_or_else(|| failed("unfinished metadata clock"))?,
                            geometry_cache.as_ref().ok_or_else(|| failed("missing geometry profile cache"))?.statistics(),
                            native_metadata_cache.as_ref().ok_or_else(|| failed("missing native profile cache"))?.statistics(),
                            native_metadata_cache.as_ref().unwrap().miss_statistics(), metadata_planner.statistics())
                            .map_err(|_| failed("metadata profile report failed"))?;
                    }
                    let mut completed = outcome.map_err(|cause| FreshGenerationError::Workflow { stage: driver_stage, cause })?;
                    completed.metadata_wall = metadata_clock.statistics();
                    completed.cache_statistics = Some(caches.statistics());
                completed.source_geometry_cache = geometry_cache.as_ref().map(|scope| scope.statistics());
completed.metadata_planning = Some(metadata_planner.statistics());
completed.native_metadata_cache = native_metadata_cache.as_ref().map(|scope| scope.statistics());
                    completed
                };
                let observation = batch_slot.get()?.ledger_observation();
                // Every plan/source/verification borrow has ended. The cache,
                // batch and case owners still live until this outer scope ends.
                startup.finish_planning()?;
                drop(startup);
                (summary, observation, started)
            };
            // Only bounded numerical data and a read-only observer cross this
            // report boundary. Every original case owner has now dropped.
            let terminal = observation.confirm_empty()?;
            drop(observation);
            summary.ledger_peak_host_bytes = terminal.peak.host;
            summary.ledger_peak_device_bytes = terminal.peak.device;
            summary.complete_workflow_ns = Some(started.elapsed().as_nanos());
            Ok(summary)
        }
    };
}
fixed_case!(run_n3, 3, 0, preclaim_n3, fresh_n3, [0, 1, 2]);
fixed_case!(run_n4, 4, 3, preclaim_n4, fresh_n4, [0, 1, 2, 3]);
