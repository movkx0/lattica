use super::*;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

fn limits() -> ConstructionLimits {
    ConstructionLimits {
        max_requested_program_bytes: 2 << 30,
        max_wires: MAX_WIRES,
        max_input_values: 1 << 20,
    }
}
fn fixture() -> NativeCoreBound {
    let storage = NativePlanningStorage::for_descriptor(
        NativeDescriptor::Sparse(sparse_air::Kind::AlphaPrime39),
        limits(),
    )
    .unwrap();
    NativeCoreBound {
        storage,
        counts: NativeCoreCounts {
            quotient_chunks: 1,
            operations: Default::default(),
            wires: 1,
            input_values: 1,
            selection_hint_words: 0,
            planner_requested_program_bytes_peak: 0,
        },
    }
}
#[test]
fn native_cohort_retries_only_byte_caps_and_joins_failures() {
    let value = fixture();
    let storage = [Some(value.storage); MAX];
    let original = value.storage.total_requested_bytes;
    for panic in [false, true] {
        let completed = AtomicUsize::new(0);
        let mut results = [None; MAX];
        let mut s = Statistics::default();
        let result = run(
            &storage,
            &[None; MAX],
            4,
            limits(),
            original,
            0,
            4,
            &mut results,
            &mut s,
            |_| Ok(()),
            |i, _, _| {
                completed.fetch_add(1, Ordering::SeqCst);
                if i == 0 {
                    if panic {
                        panic!("injected native failure");
                    }
                    return Err(CompileError::Shape("not retryable"));
                }
                Ok(value)
            },
        );
        assert!(result.is_err());
        assert_eq!(completed.load(Ordering::SeqCst), 4);
        assert_eq!(s.jobs_started, 4);
        assert_eq!(s.budget_reductions, 0);
        assert!(s.admitted_host_bytes_peak <= original);
    }
    let reduced = AtomicBool::new(false);
    let mut results = [None; MAX];
    let mut s = Statistics::default();
    run(
        &storage,
        &[None; MAX],
        4,
        limits(),
        original,
        0,
        4,
        &mut results,
        &mut s,
        |_| Ok(()),
        |_, _, cap| {
            if cap < limits().max_requested_program_bytes {
                reduced.store(true, Ordering::SeqCst);
                Err(CompileError::ResourceAdmission(
                    uni::shape::NATIVE_PROGRAM_BYTE_LIMIT,
                ))
            } else {
                Ok(value)
            }
        },
    )
    .unwrap();
    assert!(reduced.load(Ordering::SeqCst));
    assert!(s.budget_reductions > 0);
    assert!(results[..4].iter().all(|v| *v == Some(value)));
    assert!(s.admitted_host_bytes_peak <= original);
}
#[test]
fn native_cohort_deduplicates_and_preflights_before_cache() {
    let source = crate::graph_proofs::compiled_source_fingerprint();
    let cache = cache::Scope::begin(source).unwrap();
    let d = Descriptor::Native(NativeDescriptor::Sparse(sparse_air::Kind::AlphaPrime39));
    assert!(bounds(&[d, d], limits(), 0).is_err());
    assert_eq!(cache.statistics().misses, 0);
    let result = bounds(&[d, d], limits(), 512 << 20).unwrap();
    assert_eq!(result[0], result[1]);
    assert_eq!(cache.statistics().jobs_started, 1);
    assert_eq!(cache.statistics().entries, 1);
    let again = bounds(&[d, d], limits(), 512 << 20).unwrap();
    assert_eq!(again, result);
    assert_eq!(cache.statistics().jobs_started, 1);
    assert_eq!(cache.statistics().hits, 1);
}

#[test]
fn preparation_overlaps_lowering_and_drops_on_refusal() {
    let value = fixture();
    let prepared = AtomicUsize::new(0);
    let dropped = AtomicUsize::new(0);
    struct Owner<'a>(&'a AtomicUsize);
    impl Drop for Owner<'_> {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
    let mut results = [None; MAX];
    let mut stats = Statistics::default();
    run(
        &[Some(value.storage); MAX],
        &[None; MAX],
        4,
        limits(),
        value.storage.total_requested_bytes,
        0,
        4,
        &mut results,
        &mut stats,
        |_| {
            prepared.fetch_add(1, Ordering::SeqCst);
            Ok(Owner(&dropped))
        },
        |_, _, _| {
            assert!(prepared.load(Ordering::SeqCst) >= 1);
            Ok(value)
        },
    )
    .unwrap();
    assert_eq!(dropped.load(Ordering::SeqCst), 4);
    assert!(stats.admitted_host_bytes_peak <= value.storage.total_requested_bytes);
    let mut results = [None; MAX];
    let mut stats = Statistics::default();
    let result = run(
        &[Some(value.storage); MAX],
        &[None; MAX],
        4,
        limits(),
        value.storage.total_requested_bytes,
        0,
        4,
        &mut results,
        &mut stats,
        |i| {
            if i == 2 {
                Err(CompileError::Shape("injected preparation failure"))
            } else {
                Ok(Owner(&dropped))
            }
        },
        |_, _, _| Ok(value),
    );
    assert!(result.is_err());
    assert_eq!(stats.jobs_started, 2);
    assert_eq!(dropped.load(Ordering::SeqCst), 6);
}
#[test]
fn exact_allowance_requests_remain_separate_and_report_misses() {
    let cache = cache::Scope::begin(crate::graph_proofs::compiled_source_fingerprint()).unwrap();
    let d = Descriptor::Native(NativeDescriptor::Sparse(sparse_air::Kind::AlphaPrime39));
    let auxiliary = d.storage(limits()).unwrap().auxiliary_peak_bytes;
    let requests = [
        Request {
            descriptor: d,
            auxiliary,
        },
        Request {
            descriptor: d,
            auxiliary: 512 << 20,
        },
    ];
    let result = bounds_exact(&requests, limits()).unwrap();
    assert_eq!(result[0], result[1]);
    assert_eq!(cache.statistics().entries, 2);
    assert_eq!(cache.statistics().jobs_started, 2);
    assert_eq!(bounds_exact(&requests, limits()).unwrap(), result);
    assert_eq!(cache.statistics().hits, 2);
    let (families, misses) = cache.miss_statistics();
    assert_eq!(families[3].requests, 4);
    assert_eq!(families[3].cold_misses, 2);
    assert_eq!(families[3].cache_hits, 2);
    assert!(families[3].compile_ns > 0);
    assert_eq!(misses.iter().flatten().count(), 1);
    assert_eq!(misses[0].unwrap().occurrences, 2);
}

#[test]
fn direct_bound_is_exactly_bound_to_descriptor_limits_and_auxiliary() {
    let core = fixture();
    let request = Request {
        descriptor: Descriptor::Native(NativeDescriptor::Sparse(sparse_air::Kind::AlphaPrime39)),
        auxiliary: 512 << 20,
    };
    let bound = ResolvedBound {
        key: request.descriptor.key(),
        limits: limits(),
        auxiliary: request.auxiliary,
        core,
    };
    assert_eq!(bound.for_request(request, limits()).unwrap(), core);
    assert!(bound
        .for_request(
            Request {
                auxiliary: request.auxiliary - 1,
                ..request
            },
            limits()
        )
        .is_err());
    assert!(bound
        .for_request(
            request,
            ConstructionLimits {
                max_input_values: 1,
                ..limits()
            }
        )
        .is_err());
    let different = Request {
        descriptor: Descriptor::Other(OtherNativeDescriptor::PrivateProof),
        ..request
    };
    assert!(bound.for_request(different, limits()).is_err());
}
#[test]
fn scheduler_starts_largest_public_work_first_without_raising_original() {
    let value = fixture();
    let mut storage = [Some(value.storage); MAX];
    storage[2].as_mut().unwrap().geometry.width *= 10;
    let mut results = [None; MAX];
    let mut statistics = Statistics::default();
    let order = std::sync::Mutex::new(Vec::new());
    run(
        &storage,
        &[None; MAX],
        3,
        limits(),
        value.storage.total_requested_bytes,
        0,
        1,
        &mut results,
        &mut statistics,
        |_| Ok(()),
        |i, _, _| {
            order.lock().unwrap().push(i);
            Ok(value)
        },
    )
    .unwrap();
    assert_eq!(*order.lock().unwrap(), vec![2, 0, 1]);
    assert!(statistics.admitted_host_bytes_peak <= value.storage.total_requested_bytes);
}

#[test]
fn coordinator_prepares_while_prior_job_lowers_and_refills_slots() {
    use std::sync::{Condvar, Mutex};
    let state = (Mutex::new((false, false)), Condvar::new());
    let value = fixture();
    let mut results = [None; MAX];
    let mut stats = Statistics::default();
    run(
        &[Some(value.storage); MAX],
        &[None; MAX],
        5,
        limits(),
        value.storage.total_requested_bytes,
        0,
        2,
        &mut results,
        &mut stats,
        |i| {
            if i == 1 {
                let (mut observed, timeout) = state
                    .1
                    .wait_timeout_while(
                        state.0.lock().unwrap(),
                        std::time::Duration::from_secs(5),
                        |s| !s.0,
                    )
                    .unwrap();
                assert!(
                    !timeout.timed_out() && observed.0,
                    "lowering did not overlap preparation"
                );
                observed.1 = true;
                state.1.notify_all();
            }
            Ok(())
        },
        |i, _, _| {
            if i == 0 {
                let mut observed = state.0.lock().unwrap();
                observed.0 = true;
                state.1.notify_all();
                let (observed, timeout) = state
                    .1
                    .wait_timeout_while(observed, std::time::Duration::from_secs(5), |s| !s.1)
                    .unwrap();
                assert!(!timeout.timed_out() && observed.1);
            }
            Ok(value)
        },
    )
    .unwrap();
    assert_eq!(stats.threads_spawned, 2);
    assert_eq!(stats.jobs_started, 5);
    assert_eq!(stats.queue_refills, 3);
    assert!(stats.admitted_host_bytes_peak <= value.storage.total_requested_bytes);
    assert!(results[..5].iter().all(|r| *r == Some(value)));
}

#[test]
fn full_original_cap_slots_use_fresh_storage() {
    let limits = ConstructionLimits {
        max_requested_program_bytes: 8 << 20,
        ..limits()
    };
    let storage = NativePlanningStorage::for_descriptor(
        NativeDescriptor::Sparse(sparse_air::Kind::AlphaPrime39),
        limits,
    )
    .unwrap();
    let mut results = [None; MAX];
    let mut stats = Statistics::default();
    let value = fixture();
    run(
        &[Some(storage); MAX],
        &[None; MAX],
        4,
        limits,
        storage.total_requested_bytes,
        0,
        2,
        &mut results,
        &mut stats,
        |_| Ok(()),
        |_, _, cap| {
            assert_eq!(cap, limits.max_requested_program_bytes);
            let _fresh = CountingWorkspace::begin(cap).unwrap();
            Ok(value)
        },
    )
    .unwrap();
    assert_eq!(stats.threads_spawned, 2);
    assert_eq!(stats.jobs_started, 4);
    assert_eq!(stats.workspace_reuses, 0);
}
