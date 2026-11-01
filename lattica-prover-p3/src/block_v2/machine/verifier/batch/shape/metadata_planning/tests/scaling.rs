use super::*;

fn comparison(workers: usize) {
    assert_eq!(
        std::env::var("LATTICA_CPU_SCALING_PROFILE").as_deref(),
        Ok("1")
    );
    let planner =
        MetadataPlanningScope::begin(MetadataCpuOptions::workers(workers).unwrap()).unwrap();
    let cache = HeightEnvelopeCacheScope::begin([1; 32]).unwrap();
    let started = Instant::now();
    let values = [25, 28, 38, 46]
        .map(|public| verifier_height_envelope(public, 1 << 20, limits(), 512 << 20).unwrap());
    let elapsed_ns = started.elapsed().as_nanos();
    for value in values {
        assert_eq!(value.heights_enumerated, 18);
        assert_eq!(
            [
                value.operations.scalar,
                value.operations.cubic,
                value.operations.poseidon,
                value.wire_upper_bound,
                value.input_values_upper_bound,
                value.selection_hint_words_upper_bound,
            ],
            super::super::super::precomputed::reference_maxima(value.public_values)
        );
    }
    let stats = planner.statistics();
    assert_eq!(stats.heights_completed, 72);
    assert_eq!(stats.failed_envelopes, 0);
    assert_eq!(cache.statistics().table_hits, 0);
    assert!(stats.peak_active_workers <= workers);
    let original = values
        .iter()
        .map(|v| v.planning_storage.total_requested_bytes)
        .max()
        .unwrap();
    assert!(stats.admitted_host_bytes_peak <= original);
    eprintln!(
        "CPU_SCALING_RESULT {}",
        serde_json::json!({
            "kind":"registered", "workers":workers, "cases":72, "elapsed_ns":elapsed_ns,
            "counts_equal":true, "gpu_used":false, "planning":stats,
            "original_host_bytes":original, "cache":cache.statistics(),
        })
    );
}

#[test]
#[ignore = "CPU-only perf comparison; serialized scaling guard required"]
fn registered_cpu_scaling_4() {
    comparison(4);
}
#[test]
#[ignore = "CPU-only perf comparison; serialized scaling guard required"]
fn registered_cpu_scaling_8() {
    comparison(8);
}
#[test]
#[ignore = "CPU-only perf comparison; serialized scaling guard required"]
fn registered_cpu_scaling_16() {
    comparison(16);
}

#[test]
#[ignore = "CPU-only perf comparison; serialized scaling guard required"]
fn registered_cpu_scaling_12() { comparison(12); }
