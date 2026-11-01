use super::super::{verifier_height_envelope, HeightEnvelopeCacheScope, OperationCounts};
use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

fn limits() -> ConstructionLimits {
    ConstructionLimits {
        max_requested_program_bytes: 2 << 30,
        max_wires: crate::block_v2::machine::program::MAX_WIRES,
        max_input_values: 1 << 20,
    }
}
fn shape(public_values: usize, height: usize) -> RegisteredChildShape {
    RegisteredChildShape {
        public_values,
        height,
        preprocessing_cap_roots: 1
            << (height.ilog2() as usize + 1 + crate::block_v2::profile::LOG_BLOWUP)
                .min(crate::block_v2::profile::CAP_HEIGHT),
    }
}
fn storage() -> PlanningStorage {
    PlanningStorage::for_children(0, &[shape(28, 1 << 20)], limits()).unwrap()
}
fn fixture(storage: PlanningStorage) -> VerifierCoreBound {
    VerifierCoreBound {
        operations: OperationCounts::default(),
        wire_upper_bound: 0,
        input_values_upper_bound: 0,
        selection_hint_words_upper_bound: 0,
        active_rows_upper_bound: 0,
        padded_rows_upper_bound: 8,
        planner_requested_program_bytes_peak: 0,
        storage,
    }
}

#[test]
fn options_and_scope_are_bounded_and_unwinding_clears_scope() {
    for n in [0, 17, usize::MAX] {
        assert!(MetadataCpuOptions::workers(n).is_err());
    }
    assert!(MetadataCpuOptions::parse("auto").is_ok());
    assert!(MetadataCpuOptions::parse("gpu").is_err());
    let _ = std::panic::catch_unwind(|| {
        let scope = MetadataPlanningScope::begin(MetadataCpuOptions::workers(1).unwrap()).unwrap();
        assert_eq!(scope.statistics().worker_ceiling, 1);
        assert!(MetadataPlanningScope::begin(MetadataCpuOptions::default()).is_err());
        panic!("scope cleanup");
    });
    assert!(MetadataPlanningScope::begin(MetadataCpuOptions::default()).is_ok());
}

#[test]
fn every_width_fits_the_original_reservation_including_auxiliary_and_stacks() {
    let storage = storage();
    for ceiling in 1..=MAX_METADATA_WORKERS {
        for ready in 1..=MAX_HEIGHTS {
            let a = admit(ceiling, ready, storage, limits());
            assert!(a.width <= ceiling.min(ready));
            assert!(a.program_bytes > 0 && a.program_bytes <= limits().max_requested_program_bytes);
            assert!(a.total_bytes <= storage.total_requested_bytes);
            if a.width > 1 {
                assert_eq!(
                    a.total_bytes,
                    COORDINATOR_BYTES
                        + storage.symbolic_retained_bytes
                        + a.width
                            * (a.program_bytes
                                + storage.counting_worker_auxiliary_bytes().unwrap()
                                + THREAD_BYTES)
                );
            } else {
                assert_eq!(a.program_bytes, limits().max_requested_program_bytes);
            }
        }
    }
}

#[test]
fn split_byte_refusals_retry_only_after_joins_and_full_budget_refusals_fail() {
    let storage = storage();
    let cohort = std::sync::Mutex::new((0usize, 0usize));
    let mut stats = MetadataPlanningStatistics::default();
    let result = run_jobs(18, limits(), storage, 16, &mut stats, |_, cap| {
        {
            let mut cohort = cohort.lock().unwrap();
            if cohort.0 != cap {
                assert_eq!(cohort.1, 0);
                cohort.0 = cap;
            }
            cohort.1 += 1;
        }
        struct Retire<'a>(&'a std::sync::Mutex<(usize, usize)>);
        impl Drop for Retire<'_> {
            fn drop(&mut self) {
                self.0.lock().unwrap().1 -= 1;
            }
        }
        let _retire = Retire(&cohort);
        if cap < limits().max_requested_program_bytes {
            Err(CompileError::ResourceAdmission(SPLIT_BUDGET))
        } else {
            Ok(fixture(storage))
        }
    })
    .unwrap();
    assert_eq!(cohort.lock().unwrap().1, 0);
    assert_eq!(result.iter().flatten().count(), 18);
    assert!(stats.budget_reductions > 0);
    assert_eq!(stats.heights_completed, 18);
    assert!(stats.jobs_started > 18);
    let mut stats = MetadataPlanningStatistics::default();
    assert!(run_jobs(1, limits(), storage, 16, &mut stats, |_, _| Err(
        CompileError::ResourceAdmission("original byte cap")
    ))
    .is_err());
    assert_eq!(stats.budget_reductions, 0);
}

#[test]
fn errors_and_panics_join_every_started_job_and_return_no_envelope() {
    let storage = storage();
    for panic in [false, true] {
        let finished = AtomicUsize::new(0);
        let mut stats = MetadataPlanningStatistics::default();
        let result = run_jobs(18, limits(), storage, 4, &mut stats, |index, _| {
            // Mark completion during unwind too, making join-before-return observable.
            struct Done<'a>(&'a AtomicUsize);
            impl Drop for Done<'_> {
                fn drop(&mut self) {
                    self.0.fetch_add(1, Ordering::SeqCst);
                }
            }
            let _done = Done(&finished);
            if index == 0 {
                if panic {
                    panic!("injected compiler panic");
                }
                return Err(CompileError::Shape("injected invalid geometry"));
            }
            std::thread::sleep(std::time::Duration::from_millis(2));
            Ok(fixture(storage))
        });
        assert!(result.is_err());
        assert_eq!(finished.load(Ordering::SeqCst) as u64, stats.jobs_started);
        assert_eq!(stats.cohorts, 1);
        assert_eq!(stats.budget_reductions, 0);
    }
}

#[test]
fn real_parallel_geometry_matches_serial_and_preserves_error_classification() {
    let expected = verifier_height_envelope(28, 32, limits(), 512 << 20).unwrap();
    let scope = MetadataPlanningScope::begin(MetadataCpuOptions::default()).unwrap();
    assert_eq!(
        verifier_height_envelope(28, 32, limits(), 512 << 20).unwrap(),
        expected
    );
    assert_eq!(scope.statistics().heights_completed, 3);
    // Byte cap failures are the only scheduler retry marker. Input limits and
    // malformed source geometry must retain their original error, even split.
    let mut small = limits();
    small.max_input_values = 1;
    assert_ne!(
        super::super::verifier_core_bound_with_budget(
            0,
            &[shape(28, 8)],
            small,
            512 << 20,
            small.max_requested_program_bytes / 2
        ),
        Err(CompileError::ResourceAdmission(SPLIT_BUDGET))
    );
    assert_eq!(
        super::super::verifier_core_bound_with_budget(0, &[shape(28, 8)], limits(), 512 << 20, 1),
        Err(CompileError::ResourceAdmission(SPLIT_BUDGET))
    );
}

#[test]
#[ignore = "serialized CPU guard; exhaustive metadata parity and worker/cache measurements"]
fn metadata_cpu_worker_qualification() {
    assert_eq!(
        std::env::var("LATTICA_METADATA_CPU_QUALIFICATION").as_deref(),
        Ok("1")
    );
    assert!(
        physical_ceiling() >= 16,
        "qualification requires 16 physical cores"
    );
    super::super::precomputed::emit_identity();
    let mut materialized_ns = 0u128;
    let mut counted_ns = 0u128;
    let mut materialized_peak = 0usize;
    let mut counted_peak = 0usize;
    for public in [25, 28, 38, 46] {
        for log in 3..=20 {
            let shape = shape(public, 1 << log);
            let start = Instant::now();
            let full =
                super::super::materialized_core_bound(0, &[shape], limits(), 512 << 20).unwrap();
            materialized_ns += start.elapsed().as_nanos();
            materialized_peak = materialized_peak.max(full.planner_requested_program_bytes_peak);
            let start = Instant::now();
            let mut counted =
                super::super::verifier_core_bound(0, &[shape], limits(), 512 << 20).unwrap();
            counted_ns += start.elapsed().as_nanos();
            super::super::precomputed::emit_row(public, log, counted);
            counted_peak = counted_peak.max(counted.planner_requested_program_bytes_peak);
            assert!(
                counted.planner_requested_program_bytes_peak
                    < full.planner_requested_program_bytes_peak
            );
            counted.planner_requested_program_bytes_peak =
                full.planner_requested_program_bytes_peak;
            assert_eq!(
                counted, full,
                "metadata parity publics={public} height={}",
                shape.height
            );
        }
    }
    eprintln!(
        "METADATA_COUNTING_QUALIFICATION {}",
        serde_json::json!({
        "shapes": 72, "all_counts_equal": true, "materialized_ns": materialized_ns,
        "counted_ns": counted_ns, "materialized_peak_bytes": materialized_peak,
        "counted_peak_bytes": counted_peak, "gpu_used": false })
    );
    let mut baseline = None;
    for width in [1, 2, 4, 8, 16] {
        let planner =
            MetadataPlanningScope::begin(MetadataCpuOptions::workers(width).unwrap()).unwrap();
        let cache = HeightEnvelopeCacheScope::begin([1; 32]).unwrap();
        let start = Instant::now();
        let values = [25, 28, 38, 46]
            .map(|public| verifier_height_envelope(public, 1 << 20, limits(), 512 << 20).unwrap());
        let cold_ns = start.elapsed().as_nanos();
        if let Some(baseline) = baseline {
            let normalized = |v: [super::super::VerifierHeightEnvelope; 4]| {
                v.map(|mut e| {
                    // Allocation peaks vary with retained scratch, mathematical bounds do not.
                    e.planner_requested_program_bytes_peak = 0;
                    e
                })
            };
            assert_eq!(normalized(values), normalized(baseline));
        } else {
            baseline = Some(values);
        }
        let start = Instant::now();
        for value in values {
            assert_eq!(
                verifier_height_envelope(value.public_values, 1 << 20, limits(), 512 << 20)
                    .unwrap(),
                value
            );
        }
        let warm_ns = start.elapsed().as_nanos();
        let stats = planner.statistics();
        assert_eq!(stats.heights_completed, 72);
        assert_eq!(stats.symbolic_preparations, 4);
        assert_eq!(stats.failed_envelopes, 0);
        assert_eq!(cache.statistics().hits, 4);
        assert_eq!(cache.statistics().misses, 4);
        assert!(stats.peak_active_workers <= width);
        assert!(
            stats.admitted_host_bytes_peak
                <= storage().total_requested_bytes.max(
                    PlanningStorage::for_children(0, &[shape(46, 1 << 20)], limits())
                        .unwrap()
                        .total_requested_bytes
                )
        );
        if width > 1 {
            assert!(stats.peak_active_workers > 1);
        }
        eprintln!(
            "METADATA_CPU_QUALIFICATION {}",
            serde_json::json!({
            "workers": width, "shapes": 72, "cold_ns": cold_ns, "warm_ns": warm_ns,
            "original_host_bytes": PlanningStorage::for_children(0, &[shape(46, 1 << 20)], limits()).unwrap().total_requested_bytes,
            "counts_equal": true, "planning": stats, "cache": cache.statistics(), "gpu_used": false })
        );
    }
    if super::super::precomputed::available() {
        let planner = MetadataPlanningScope::begin(MetadataCpuOptions::default()).unwrap();
        let cache = HeightEnvelopeCacheScope::begin_with_precomputed([1; 32]).unwrap();
        let start = Instant::now();
        let values = [25, 28, 38, 46]
            .map(|public| verifier_height_envelope(public, 1 << 20, limits(), 512 << 20).unwrap());
        let elapsed = start.elapsed().as_nanos();
        assert_eq!(Some(values), baseline);
        assert_eq!(planner.statistics().jobs_started, 0);
        assert_eq!(planner.statistics().symbolic_preparations, 0);
        assert_eq!(cache.statistics().table_hits, 4);
        eprintln!(
            "METADATA_TABLE_QUALIFICATION {}",
            serde_json::json!({
            "envelopes": 4, "shapes": 72, "counts_equal": true, "elapsed_ns": elapsed,
            "planning": planner.statistics(), "cache": cache.statistics(), "gpu_used": false })
        );
    }
}

#[test]
fn full_original_cap_workers_do_not_retain_scratch_that_could_cause_false_refusals() {
    use crate::block_v2::machine::program::CountingWorkspace;
    let limits = ConstructionLimits {
        max_requested_program_bytes: 128 << 20,
        ..limits()
    };
    let storage = PlanningStorage::for_children(0, &[shape(28, 1 << 20)], limits).unwrap();
    let a = admit(2, 4, storage, limits);
    assert_eq!(a.width, 2);
    assert_eq!(a.program_bytes, limits.max_requested_program_bytes);
    let mut stats = MetadataPlanningStatistics::default();
    run_jobs(4, limits, storage, 2, &mut stats, |_, cap| {
        // No scheduler-owned retained workspace may already be active here.
        let _fresh = CountingWorkspace::begin(cap).unwrap();
        Ok(fixture(storage))
    })
    .unwrap();
    assert_eq!(stats.threads_spawned, 2);
    assert_eq!(stats.jobs_started, 4);
    assert_eq!(stats.workspace_reuses, 0);
}

mod scaling;

#[test]
fn automatic_native_ceiling_uses_physical_cores_and_explicit_requests_are_preserved() {
    let auto = MetadataCpuOptions::default();
    {
        let _scope = MetadataPlanningScope::begin(auto).unwrap();
        assert_eq!(metadata_cpu_worker_ceiling(), auto.max_workers());
        assert_eq!(native_metadata_cpu_worker_ceiling(), auto.max_workers());
    }
    let explicit = MetadataCpuOptions::workers(16).unwrap();
    let _scope = MetadataPlanningScope::begin(explicit).unwrap();
    assert_eq!(native_metadata_cpu_worker_ceiling(), explicit.max_workers());
}
