use super::*;

fn comparison(workers: usize) {
    use lattica_prover_p3::block_v2::machine::verifier::batch::shape::{
        MetadataCpuOptions, MetadataPlanningScope,
    };
    assert_eq!(
        std::env::var("LATTICA_CPU_SCALING_PROFILE").as_deref(),
        Ok("1")
    );
    let _planner =
        MetadataPlanningScope::begin(MetadataCpuOptions::workers(workers).unwrap()).unwrap();
    let cache = cache::Scope::begin(crate::graph_proofs::compiled_source_fingerprint()).unwrap();
    use crate::execution::retained_resources::{Bytes, Category, Ledger, WorkerAllowance};
    let ledger = Ledger::new(WorkerAllowance {
        host: 4 << 30,
        device: 0,
    });
    let cases = base_catalogue();
    assert_eq!(cases.len(), 159);
    let mut original = 0;
    let mut session = native_shape::cohort::Session::default();
    let started = Instant::now();
    for group in cases.chunks(native_shape::cohort::MAX) {
        let descriptors: Vec<_> = group.iter().map(Case::descriptor).collect();
        let result = {
            let bytes = descriptors
                .iter()
                .map(|d| d.storage(limits()).unwrap().total_requested_bytes)
                .max()
                .unwrap();
            let held = ledger
                .reserve(
                    Category::PhaseScratch,
                    Bytes {
                        host: bytes as u64,
                        device: 0,
                    },
                )
                .unwrap();
            let requests: Vec<_> = descriptors
                .iter()
                .map(|&descriptor| native_shape::cohort::Request {
                    descriptor,
                    auxiliary: 512 << 20,
                })
                .collect();
            session
                .resolve(&requests, limits(), &held, &ledger)
                .unwrap()
                .into_iter()
                .zip(requests.iter())
                .map(|(b, &r)| b.map(|b| b.for_request(r, limits()).unwrap()))
                .collect::<Vec<_>>()
        };
        for (case, bound) in group.iter().zip(result) {
            let bound = bound.unwrap();
            original = original.max(bound.storage.total_requested_bytes);
            let expected = native_shape::precomputed::reference_values(case.descriptor().key());
            assert_eq!(values(bound)[..7], expected[..7], "{}", case.name);
        }
    }
    drop(session);
    let elapsed_ns = started.elapsed().as_nanos();
    let stats = cache.statistics();
    assert_eq!(stats.entries, 159);
    assert_eq!(stats.table_hits, 0);
    assert_eq!(stats.failed_computations, 0);
    let phase_peak = (ledger.snapshot().peak.host as usize).max(original);
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
    assert!(stats.peak_workers <= workers && stats.admitted_host_bytes_peak <= phase_peak);
    eprintln!(
        "CPU_SCALING_RESULT {}",
        serde_json::json!({
            "kind":"native", "workers":workers, "cases":159, "elapsed_ns":elapsed_ns,
            "counts_equal":true, "gpu_used":false, "cache":stats, "original_host_bytes":original,
            "phase_host_bytes_peak":phase_peak, "ledger_all_claims_released":true,
        })
    );
}

#[test]
#[ignore = "CPU-only perf comparison; serialized scaling guard required"]
fn native_cpu_scaling_4() {
    comparison(4);
}
#[test]
#[ignore = "CPU-only perf comparison; serialized scaling guard required"]
fn native_cpu_scaling_8() {
    comparison(8);
}
#[test]
#[ignore = "CPU-only perf comparison; serialized scaling guard required"]
fn native_cpu_scaling_16() {
    comparison(16);
}

#[test]
#[ignore = "CPU-only perf comparison; serialized scaling guard required"]
fn native_cpu_scaling_12() {
    comparison(12);
}
