//! Bounded complete-case observations; qualification flags require actual audits.
use serde::Serialize;
use crate::proof_cache_policy::FamilyStatistics;
use crate::execution::{owned_workflow_observation::{OwnedWorkflowSnapshot, SourcePreparationSnapshot}, generation_terminal::NativeGenerationTotals};
use crate::ordered_aggregation::owned_final::FinalQualificationReport;
/// Only fixed actual observations escape the original case owners.
#[derive(Serialize)]
pub(crate) struct CompletedCaseSummary {
    pub(crate) metadata_wall: Option<super::metadata_timing::Statistics>,
    pub(crate) source_geometry_cache: Option<lattica_prover_p3::block_v2::machine::verifier::batch::shape::HeightEnvelopeCacheStatistics>,
    pub(crate) metadata_planning: Option<lattica_prover_p3::block_v2::machine::verifier::batch::shape::MetadataPlanningStatistics>,
    pub(crate) native_metadata_cache: Option<crate::component_tree::native_shape::cache::Statistics>,
    pub(crate) transactions: usize,
    pub(crate) native_proofs: usize,
    pub(crate) recursive_proofs: usize,
    pub(crate) completed_phases: usize,
    pub(crate) generation_and_planning_ns: u128,
    pub(crate) proving_and_verification_ns: u128,
    pub(crate) final_cpu_verification_ns: u128,
    pub(crate) complete_workflow_ns: Option<u128>,
    pub(crate) ledger_peak_host_bytes: u64,
    pub(crate) ledger_peak_device_bytes: u64,
    pub(crate) cache_statistics: Option<[FamilyStatistics; 5]>,
    pub(crate) cache_counter_scope: &'static str,
    pub(crate) generation_session_id: u64,
    pub(crate) generation: NativeGenerationTotals,
    pub(crate) source_preparation: SourcePreparationSnapshot,
    pub(crate) owned_observations: OwnedWorkflowSnapshot,
    pub(crate) qualification_scope: &'static str,
    pub(crate) final_qualification: FinalQualificationReport,
    pub(crate) artifacts_qualified: bool,
    pub(crate) mutations_qualified: bool,
}
