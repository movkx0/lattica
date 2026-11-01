//! Explicit complete-workflow research entry; no production acceptance path.
use crate::{graph_crypto::ShakeWrapperLayout, spend_pipeline::full_workflow::driver::fresh_entry};
use serde::Serialize;
use std::io::Write;
use lattica_prover_p3::block_v2::machine::backend::identity_cpu::{IdentityCpuOptions};
use lattica_prover_p3::block_v2::machine::verifier::batch::shape::MetadataCpuOptions;

#[derive(Serialize)]
struct CaseEnvelope<'a> {
    schema: &'static str,
    layout: &'static str,
    proof_policy: &'static str,
    proving_policy: &'static str,
    identity_cpu: IdentityCpuOptions,
    metadata_cpu: MetadataCpuOptions,
    host_profile: crate::host_memory_profile::HostMemoryProfile,
    worker_host_bytes: u64,
    setup_seed: [u8; 32],
    context: [u8; 32],
    case: &'static str,
    report: &'a crate::spend_pipeline::full_workflow::driver::case_report::CompletedCaseSummary,
}

/// Run exactly one fresh N3 or N4 case under the external serialized resource guard.
/// The fixed report is emitted only after the concrete entry has completed cleanup.
pub fn run_case(
    transactions: usize,
    paired_shake: bool,
    setup_seed: [u8; 32],
    context: [u8; 32],
) -> Result<(), String> {
    run_case_with_preprocessing(transactions, paired_shake, setup_seed, context, IdentityCpuOptions::default())
}

pub fn run_case_with_preprocessing(transactions: usize, paired_shake: bool,
    setup_seed: [u8; 32], context: [u8; 32], identity_limits: IdentityCpuOptions) -> Result<(), String> {
    run_case_with_host_profile(transactions, paired_shake, setup_seed, context, identity_limits, crate::host_memory_profile::HostMemoryProfile::Standard)
}
pub fn run_case_with_host_profile(transactions: usize, paired_shake: bool,
    setup_seed: [u8; 32], context: [u8; 32], identity_limits: IdentityCpuOptions,
    host_profile: crate::host_memory_profile::HostMemoryProfile) -> Result<(), String> {
    run_case_with_options(transactions, paired_shake, setup_seed, context, identity_limits, host_profile, true)
}
pub fn run_case_with_options(transactions: usize, paired_shake: bool,
    setup_seed: [u8; 32], context: [u8; 32], identity_limits: IdentityCpuOptions,
    host_profile: crate::host_memory_profile::HostMemoryProfile, planning_cache: bool) -> Result<(), String> {
    run_case_with_planning(transactions, paired_shake, setup_seed, context, identity_limits,
        host_profile, planning_cache, MetadataCpuOptions::default())
}
pub fn run_case_with_planning(transactions: usize, paired_shake: bool,
    setup_seed: [u8; 32], context: [u8; 32], identity_limits: IdentityCpuOptions,
    host_profile: crate::host_memory_profile::HostMemoryProfile, planning_cache: bool,
    metadata_cpu: MetadataCpuOptions) -> Result<(), String> {
    let guarded_profile = std::env::var("LATTICA_RINGCT_HOST_PROFILE").unwrap_or_else(|_| "standard".into());
    if guarded_profile != host_profile.label() { return Err("runner/driver host-memory profile mismatch".into()); }
    let layout = if paired_shake {
        ShakeWrapperLayout::PairedV1
    } else {
        ShakeWrapperLayout::Singleton
    };
    let report = match transactions {
        3 => fresh_entry::run_n3(setup_seed, context, layout, identity_limits, host_profile, planning_cache, metadata_cpu),
        4 => fresh_entry::run_n4(setup_seed, context, layout, identity_limits, host_profile, planning_cache, metadata_cpu),
        _ => return Err("case must contain three or four transactions".into()),
    }
    .map_err(|error| format!("fresh workflow refused: {error:?}"))?;
    if report.complete_workflow_ns.is_none() || report.cache_statistics.is_none() {
        return Err("fresh workflow omitted terminal measurements".into());
    }
    let mut output = std::io::stdout().lock();
    output
        .write_all(b"RINGCT_FULL_WORKFLOW_CASE ")
        .map_err(|e| e.to_string())?;
    serde_json::to_writer(
        &mut output,
        &CaseEnvelope {
            schema: "lattica-research-ringct-complete-case-v2",
            layout: if paired_shake {
                "paired-v1"
            } else {
                "singleton"
            },
            proof_policy: "fresh-only",
            proving_policy: "gpu-required",
            identity_cpu: identity_limits,
            metadata_cpu,
        host_profile, worker_host_bytes: host_profile.worker_bytes(),
            setup_seed,
            context,
            case: if transactions == 3 { "n3" } else { "n4" },
            report: &report,
        },
    )
    .map_err(|e| e.to_string())?;
    output.write_all(b"\n").map_err(|e| e.to_string())?;
    output.flush().map_err(|e| e.to_string())
}
