//! Same concrete metadata constructors, with separately admitted fixture owners.
use super::{fixture, metadata_timing, record};
use crate::{execution::{generation_terminal::planning_startup::PlanningStartupPlan,
    workflow_resources::{WorkflowPlanning, SourceRetained, WorkflowError}},
    spend_pipeline::full_workflow::{SourcePlanningPlan, PreparedWorkflowSources,
        bootstrap_layers::{self, GraphPlanResult, GraphSourceResult, PreparationPlanResult, PreparedSourceResult},
        metadata_planning::{SourceMetadataPlanningPlan, MetadataPlanningStage},
        fresh_generation::{FreshGenerationError, caches::FreshProofCaches, case_lifetime::{CaseRetirementState, MetadataOwner}}}};
use metadata_timing::Phase;
type Result<T> = core::result::Result<T, FreshGenerationError>;
fn fail(message: &'static str) -> FreshGenerationError { FreshGenerationError::Resource(message) }

macro_rules! fixed_case { ($name:ident, $n:literal, $claim:ident, [$($index:literal),+]) => {
pub(super) fn $name(path: &std::path::Path) -> Result<()> {
    let began = std::time::Instant::now();
    // The fixture process deliberately retains every incomplete owner until
    // exit, including these roots. No generation/completion receipt is minted.
    let inputs = std::mem::ManuallyDrop::new(fixture::Inputs::<$n>::read(path).map_err(|_| fail("fixture load/verification"))?);
    let input_ns = began.elapsed().as_nanos();
    eprintln!("RINGCT_METADATA_FIXTURE_LOADED digest={:?} load_verify_ns={input_ns}", inputs.digest);
    super::set_fixture_load_ns(input_ns);
    let plan = PlanningStartupPlan::new().map_err(FreshGenerationError::Context)?;
    let original = inputs.ledger().admit_phase(plan.requirements().map_err(FreshGenerationError::Context)?)
        .map_err(|_| fail("fixture startup admission"))?;
    let startup = plan.start_fixture(original, inputs.ledger()).map_err(FreshGenerationError::Context)?;
    let case = CaseRetirementState::prepare_fixture(&startup, $n)?;
    let owner = MetadataOwner::Fixture { case: &case, startup: &startup };
    let caches_slot = case.preclaim::<Result<FreshProofCaches>>()?;
    caches_slot.install(FreshProofCaches::for_fixture(inputs.ledger()))?;
    let caches = caches_slot.get()?.as_ref().map_err(|_| fail("fixture caches"))?;
    let generation_and_startup_ns = began.elapsed().as_nanos();
    let clock = metadata_timing::Scope::begin().ok_or_else(|| fail("fixture metadata clock"))?;
    let source = crate::graph_proofs::compiled_source_fingerprint();
    use lattica_prover_p3::block_v2::machine::verifier::batch::shape;
    let geometry = shape::HeightEnvelopeCacheScope::begin_with_precomputed(source).map_err(|_| fail("fixture geometry cache"))?;
    let native = crate::component_tree::native_shape::cache::Scope::begin_with_precomputed(source).map_err(|_| fail("fixture native cache"))?;
    let planner = shape::MetadataPlanningScope::begin(shape::MetadataCpuOptions::workers(super::workers())
        .map_err(|_| fail("fixture worker count"))?).map_err(|_| fail("fixture metadata workers"))?;
    let views_slot = case.preclaim::<[crate::spend_pipeline::full_workflow::InitialNativeSource<'_>; $n]>()?;
    views_slot.install(inputs.views().map_err(|_| fail("fixture views"))?)?;
    let views = views_slot.get()?;
    let scope_slot = case.preclaim::<core::result::Result<SourcePlanningPlan<'_>, crate::spend_pipeline::full_workflow::SourcePreparationError>>()?;
    scope_slot.install(SourcePlanningPlan::fixture(&startup, views, crate::graph_crypto::ShakeWrapperLayout::PairedV1))?;
    let scope = scope_slot.get()?.as_ref().map_err(|_| fail("fixture source scope"))?;
    let graph_plans = case.$claim::<GraphPlanResult<'_>>()?;
    let graphs = case.$claim::<GraphSourceResult>()?;
    let prep_plans = case.$claim::<PreparationPlanResult<'_>>()?;
    let prepared = case.$claim::<PreparedSourceResult<'_>>()?;
    let members = case.preclaim::<[&SourceRetained<PreparedWorkflowSources<'_>>; $n]>()?;
    let metadata = case.preclaim::<core::result::Result<SourceMetadataPlanningPlan<'_>, super::super::super::ClosureError>>()?;
    let mut planning = WorkflowPlanning::admit_fixture(&scope, &startup).map_err(|_| fail("fixture source admission"))?;
    metadata_timing::phase(Phase::GraphSources);
    let early = bootstrap_layers::prepare_layers(&scope, &mut planning, &owner,
        graph_plans.get()?, graphs.get()?, prep_plans.get()?, prepared.get()?)?;
    members.install([$(prepared.get()?.get($index)?.get()?.as_ref().map_err(|_| fail("fixture member"))?),+])?;
    metadata_timing::phase(Phase::Inventory);
    let mut stage = MetadataPlanningStage::Readiness;
    metadata.install(planning.plan_producer_metadata(&scope, members.get()?, &mut stage))?;
    let metadata = metadata.get()?.as_ref().map_err(|error| FreshGenerationError::ProducerMetadata { stage, cause: *error })?;
    metadata_timing::phase(Phase::Reservation);
    planning.reserve_producer_metadata(metadata, &owner).map_err(|_| fail("fixture producer admission"))?;
    metadata_timing::phase(Phase::Constructors);
    let mut stage = super::super::metadata_driver::DriverStage::Readiness;
    let result = super::super::metadata_driver::run::<$n>(planning, metadata, &owner, None, &case, &caches.native, &caches.outer, &mut stage, early);
    let complete = matches!(result, Err(WorkflowError::MetadataProfileComplete));
    if !complete { metadata_timing::finish(); }
    record(complete, $n, 0, generation_and_startup_ns, clock.statistics().ok_or_else(|| fail("fixture clock unfinished"))?,
        geometry.statistics(), native.statistics(), native.miss_statistics(), planner.statistics()).map_err(|_| fail("fixture profile output"))?;
    if complete { Ok(()) } else { Err(FreshGenerationError::Workflow { stage, cause: result.err().unwrap_or(WorkflowError::Identity) }) }
}
}; }
fixed_case!(run_n3, 3, preclaim_n3, [0, 1, 2]);
fixed_case!(run_n4, 4, preclaim_n4, [0, 1, 2, 3]);
