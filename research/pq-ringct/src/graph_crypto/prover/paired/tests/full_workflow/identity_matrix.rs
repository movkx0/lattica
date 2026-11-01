//! CPU reference-source screening. This never grants complete runtime admission.
use super::*;
use lattica_prover_p3::block_v2::machine::{
    backend::identity_cpu::IdentityCpuOptions, verifier::batch::shape::HeightEnvelopeCacheScope,
};

/// Replay the source-declared lifetimes, without fabricating native or recursive
/// proof owners. GPU/PCS backend reservations and the whole-graph retained pool
/// are intentionally left to the real fresh workflow's complete admission.
fn source_lifetimes(
    plan: &PairedRequestPlan<'_>,
    ledger: &Ledger,
) -> core::result::Result<(usize, u64, u64, u64), String> {
    let mut native: Vec<Option<Reservation>> =
        (0..plan.request.segments().len()).map(|_| None).collect();
    let mut compiled: Vec<Option<Reservation>> = (0..plan.nodes.len()).map(|_| None).collect();
    let mut proofs: Vec<Option<Reservation>> = (0..plan.nodes.len()).map(|_| None).collect();
    let mut endpoint = None;
    let mut peak_compilers = 0;
    let mut peak_compiler_host = 0u64;
    let mut peak_prefix_host = 0u64;
    let mut peak_borrowed_program_host = 0u64;
    for step in plan.ordered_steps() {
        let scratch = ledger
            .admit_phase(step.facts.scratch)
            .map_err(|e| format!("source scratch: {e:?}"))?;
        let failure = ledger
            .admit_phase(step.facts.failure)
            .map_err(|e| format!("source failure: {e:?}"))?;
        let output = ledger
            .admit_phase(step.facts.output)
            .map_err(|e| format!("source output: {e:?}"))?;
        match step.kind {
            RequestStepKind::Endpoints => {
                assert!(endpoint.replace(output).is_none());
            }
            RequestStepKind::Native { index } => {
                assert!(native[index].replace(output).is_none());
            }
            RequestStepKind::Group { node } => {
                let span = plan.nodes[node].group.unwrap();
                for held in &mut native[span.first_segment..span.first_segment + span.segment_count]
                {
                    assert!(held.take().is_some());
                }
                assert!(compiled[node].replace(output).is_none());
            }
            RequestStepKind::Merge { node, left, right } => {
                assert!(proofs[left].take().is_some());
                assert!(proofs[right].take().is_some());
                assert!(compiled[node].replace(output).is_none());
            }
            RequestStepKind::Outer { node } => {
                let (cohort, count) = plan
                    .identity_cohort(node)
                    .map_err(|e| format!("cohort: {e:?}"))?;
                assert!(cohort[..count].iter().all(|&id| compiled[id].is_some()));
                if let Some(footprint) = plan
                    .identity_footprint(node)
                    .map_err(|e| format!("prefix footprint: {e:?}"))?
                {
                    peak_prefix_host = peak_prefix_host.max(footprint.host_bytes);
                    peak_borrowed_program_host =
                        peak_borrowed_program_host.max(footprint.borrowed_program_host_bytes);
                }
                assert!(compiled[node].take().is_some());
                assert!(proofs[node].replace(output).is_none());
            }
        }
        peak_compilers = peak_compilers.max(compiled.iter().filter(|v| v.is_some()).count());
        let held_compilers = compiled.iter().flatten().try_fold(0u64, |total, owner| {
            total
                .checked_add(owner.requirements().get(Category::SymbolicCompiler).host)
                .ok_or_else(|| "compiler storage sum overflow".to_string())
        })?;
        peak_compiler_host = peak_compiler_host.max(held_compilers);
        drop(failure);
        drop(scratch);
    }
    assert!(native.iter().all(Option::is_none));
    assert!(compiled.iter().all(Option::is_none));
    assert!(proofs[plan.root_id()].take().is_some());
    assert!(proofs.iter().all(Option::is_none));
    assert!(peak_compilers <= plan.identity_limits().max_streams());
    Ok((
        peak_compilers,
        peak_compiler_host,
        peak_prefix_host,
        peak_borrowed_program_host,
    ))
}

#[test]
#[ignore = "serialized CPU N3/N4 source matrix; seven native reference fixtures; no GPU or STARK proofs"]
fn full_workflow_identity_source_admission_matrix() {
    check_source_schedules(&[
        IdentityCpuOptions::workers(1).unwrap(),
        IdentityCpuOptions::workers(2).unwrap(),
        IdentityCpuOptions::workers(4).unwrap(),
        IdentityCpuOptions::workers(8).unwrap(),
        IdentityCpuOptions::workers(16).unwrap(),

    ]);
}

#[test]
#[ignore = "serialized CPU N3/N4 width-12 source screen; no GPU or STARK proofs"]
fn full_workflow_identity_width_twelve_source_admission() {
    check_source_schedules(&[IdentityCpuOptions::workers(12).unwrap()]);
}

#[test]
#[ignore = "serialized CPU N3/N4 width-16 source screen; no GPU or STARK proofs"]
fn full_workflow_identity_width_sixteen_source_admission() {
    check_source_schedules(&[IdentityCpuOptions::workers(16).unwrap()]);
}

fn check_source_schedules(schedules: &[IdentityCpuOptions]) {
    for (count, first) in [(3, 0), (4, 3)] {
        // Distinct reference transactions, never one graph multiplied by N.
        let inventories: Vec<_> = (first..first + count)
            .map(|i| inventory_at(i as u64))
            .collect();
        for &limits in schedules {
            // Numerical geometry only, scoped to this matrix row. This reduces
            // repeated CPU analysis; it is not a production cache benchmark.
            let cache =
                HeightEnvelopeCacheScope::begin(crate::graph_proofs::compiled_source_fingerprint())
                    .unwrap();
            let ledger = ledger();
            let cache_owner = ledger
                .reserve(
                    Category::RegisteredMetadata,
                    Bytes {
                        host: 1 << 20,
                        device: 0,
                    },
                )
                .unwrap();
            let mut requests = 0;
            let mut peak_compilers = 0;
            let mut peak_compiler_host = 0u64;
            let mut peak_prefix_host = 0u64;
            let mut peak_borrowed_program_host = 0u64;
            let mut refused = None;
            for (crypto, context) in &inventories {
                for request in crypto.requests() {
                    if !matches!(request.descriptor(), RequestDescriptor::Shake(_)) {
                        continue;
                    }
                    let attempt = (|| -> core::result::Result<(usize, u64, u64, u64), String> {
                        let metadata = PairedRequestPlan::planning_requirements(
                            request,
                            ShakeWrapperLayout::Singleton,
                        )
                        .map_err(|e| format!("metadata: {e:?}"))?;
                        let scratch = PairedRequestPlan::planning_scratch_requirements(
                            request,
                            ShakeWrapperLayout::Singleton,
                        )
                        .map_err(|e| format!("planning scratch: {e:?}"))?;
                        let scratch = ledger
                            .admit_phase(scratch)
                            .map_err(|e| format!("planning admission: {e:?}"))?;
                        let original = ledger
                            .admit_phase(metadata)
                            .map_err(|e| format!("metadata admission: {e:?}"))?;
                        let plan = PairedRequestPlan::derive_pre_reserved(
                            request,
                            context.clone(),
                            ShakeWrapperLayout::Singleton,
                            original,
                            &scratch,
                            &ledger,
                        )
                        .and_then(|p| p.with_identity_limits(limits))
                        .map_err(|e| format!("source plan: {e:?}"))?;
                        drop(scratch);
                        source_lifetimes(&plan, &ledger)
                    })();
                    match attempt {
                        Ok((peak, compiler_host, prefix_host, borrowed_program_host)) => {
                            requests += 1;
                            peak_compilers = peak_compilers.max(peak);
                            peak_compiler_host = peak_compiler_host.max(compiler_host);
                            peak_prefix_host = peak_prefix_host.max(prefix_host);
                            peak_borrowed_program_host =
                                peak_borrowed_program_host.max(borrowed_program_host);
                        }
                        Err(error) => {
                            refused = Some(error);
                            break;
                        }
                    }
                }
                if refused.is_some() {
                    break;
                }
            }
            let geometry = cache.statistics();
            drop(cache);
            drop(cache_owner);
            let terminal = ledger.snapshot();
            assert_eq!(terminal.current, Bytes::ZERO);
            println!(
                "IDENTITY_SOURCE_MATRIX {}",
                serde_json::json!({
                    "schema": "ringct-cpu-identity-source-matrix-v1", "transactions": count,
                    "first_fixture": first, "fixture_count": inventories.len(), "layout": "singleton",
                    "identity_cpu": limits, "requests": requests,
                    "source_lifetimes_admitted": refused.is_none(), "refusal": refused,
                    "peak_compilers": peak_compilers, "source_claim_peak_host_bytes": terminal.peak.host,
                    "compiler_construction_ceiling_bytes": source::PROGRAM_BYTES,
                    "peak_retained_compiler_host_bytes": peak_compiler_host,
                    "peak_prefix_incremental_host_bytes": peak_prefix_host,
                    "peak_prefix_borrowed_program_host_bytes": peak_borrowed_program_host,
                    "worker_host_bytes": 32u64 << 30, "managed_device_bytes": 8u64 << 30,
                    "source_geometry_cache": geometry, "terminal_empty": true,
                    "compiled_source_fingerprint": crate::graph_proofs::compiled_source_fingerprint(),
                    "gpu_dispatches": 0, "stark_proofs": 0, "complete_workflow_admitted": false,
                    "scope": "SHAKE source constructors and declared lifetimes; complete graph/backend admission remains required"
                })
            );
        }
    }
}
