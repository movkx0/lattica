use super::super::tests::{matrix, runtime, scalars, simple};
use super::*;
use crate::{block_v2::quotient_program::test_support::words, config::Val};
use p3_field::{PrimeCharacteristicRing, TwoAdicField};

fn identity() -> Identity {
    Identity {
        ordinal: 0,
        uuid: "GPU-test".into(),
        pci: "0000:01:00.0".into(),
        name: "test".into(),
        global_bytes: 16 << 30,
        compute_capability: 120,
        driver_api: 13040,
        max_threads: 1024,
        max_grid_x: i32::MAX as u32,
        shared_bytes: 49152,
        multiprocessors: 84,
        max_threads_per_multiprocessor: 1536,
    }
}

#[test]
fn cache_identity_covers_toolchain_target_options_generator_and_profile() {
    let identity = identity();
    let toolchain = ToolchainIdentity {
        version: [12, 9],
        library_instance: 100,
    };
    let options = compiler::options(120);
    let base = namespace(&identity, toolchain, &options, "generator", "kernels");
    assert_ne!(
        base,
        namespace(
            &Identity {
                compute_capability: 70,
                ..identity.clone()
            },
            toolchain,
            &options,
            "generator",
            "kernels"
        )
    );
    assert_ne!(
        base,
        namespace(
            &Identity {
                driver_api: 13041,
                ..identity.clone()
            },
            toolchain,
            &options,
            "generator",
            "kernels"
        )
    );
    assert_ne!(
        base,
        namespace(
            &Identity {
                uuid: "another GPU".into(),
                ..identity.clone()
            },
            toolchain,
            &options,
            "generator",
            "kernels"
        )
    );
    assert_ne!(
        base,
        namespace(
            &identity,
            ToolchainIdentity {
                version: [12, 8],
                ..toolchain
            },
            &options,
            "generator",
            "kernels"
        )
    );
    assert_ne!(
        base,
        namespace(
            &identity,
            ToolchainIdentity {
                library_instance: 101,
                ..toolchain
            },
            &options,
            "generator",
            "kernels"
        )
    );
    assert_ne!(
        base,
        namespace(
            &identity,
            toolchain,
            &compiler::options(70),
            "generator",
            "kernels"
        )
    );
    assert_ne!(
        base,
        namespace(&identity, toolchain, &options, "changed", "kernels")
    );
    assert_ne!(
        base,
        namespace(&identity, toolchain, &options, "generator", "changed")
    );
    assert_ne!(
        namespace(&identity, toolchain, &["ab".into(), "c".into()], "", ""),
        namespace(&identity, toolchain, &["a".into(), "bc".into()], "", "")
    );
    let p = simple(Extension::Cubic, 1);
    let first = key(base, [1; 32], &p, Specialization::Prefer);
    assert_ne!(first, key(base, [2; 32], &p, Specialization::Prefer));
    assert_ne!(first, key(base, [1; 32], &p, Specialization::Generic));
    assert_ne!(first, key([0; 32], [1; 32], &p, Specialization::Prefer));
}

#[test]
fn cache_program_keys_bind_every_layout_and_instruction_field() {
    let baseline = simple(Extension::Cubic, 1);
    let baseline = key([1; 32], [2; 32], &baseline, Specialization::Generic);
    for which in 0..14 {
        let mut p = simple(Extension::Cubic, 1);
        match which {
            0 => p.extension = Extension::Quadratic,
            1 => p.instructions.push(0),
            2 => p.registers += 1,
            3 => p.constraints += 1,
            4 => p.row_words += 1,
            5 => p.parameter_words += 1,
            6 => p.layout.preprocessed_width += 1,
            7 => p.layout.main_width += 1,
            8 => p.layout.num_public_values += 1,
            9 => p.layout.permutation_width += 1,
            10 => p.layout.num_permutation_challenges += 1,
            11 => p.layout.num_permutation_values += 1,
            12 => p.layout.num_periodic_columns += 1,
            13 => p.instructions[7] += 1,
            _ => unreachable!(),
        }
        assert_ne!(
            baseline,
            key([1; 32], [2; 32], &p, Specialization::Generic),
            "field {which}"
        );
    }
    let mut same = simple(Extension::Cubic, 1);
    same.instructions.reserve(1024);
    assert_eq!(
        baseline,
        key([1; 32], [2; 32], &same, Specialization::Generic)
    );
}

#[test]
fn cache_eviction_admission_preserves_pins_and_all_budget_boundaries() {
    let one = Retained {
        charge: Charge {
            host: 64,
            device: 128,
            modules: 1,
        },
        used: 1,
        reclaimable: true,
    };
    let two = Retained {
        charge: Charge {
            modules: 0,
            ..one.charge
        },
        used: 2,
        ..one
    };
    let mut entries = [None; MAX_ENTRIES];
    entries[0] = Some(one);
    entries[1] = Some(two);
    let global = Snapshot {
        public_programs: 2,
        public_program_bytes: 128,
        live_bytes: 264,
        allocations: 3,
        modules: 2,
        ..Snapshot::default()
    };
    let limits = CacheLimits {
        entries: 2,
        host_bytes: 128,
        device_bytes: 256,
    };
    let runtime = Limits {
        managed_bytes: 392,
        max_allocation_bytes: 128,
        max_modules: 3,
        max_allocations: 4,
        ..Limits::default()
    };
    let result = evictions(entries, global, one.charge, limits, runtime).unwrap();
    assert_eq!(result.iter().filter(|&&r| r).count(), 1);
    assert!(result[0]);
    entries[0].as_mut().unwrap().reclaimable = false;
    let result = evictions(entries, global, one.charge, limits, runtime).unwrap();
    assert_eq!(result.iter().filter(|&&r| r).count(), 1);
    assert!(result[1]);
    assert!(evictions(
        entries,
        global,
        one.charge,
        limits,
        Limits {
            max_modules: 2,
            ..runtime
        }
    )
    .is_err());
    entries[1].as_mut().unwrap().reclaimable = false;
    assert!(evictions(entries, global, one.charge, limits, runtime).is_err());
    entries[0].as_mut().unwrap().reclaimable = true;
    entries[1].as_mut().unwrap().reclaimable = true;
    let result = evictions(
        entries,
        global,
        Charge {
            host: 96,
            ..one.charge
        },
        limits,
        runtime,
    )
    .unwrap();
    assert_eq!(result.iter().filter(|&&r| r).count(), 2);
    assert!(evictions(
        entries,
        global,
        Charge {
            device: 129,
            ..one.charge
        },
        limits,
        runtime
    )
    .is_err());
    assert!(evictions(
        entries,
        Snapshot {
            public_program_bytes: MAX_PUBLIC_PROGRAM_BYTES,
            public_programs: MAX_PUBLIC_PROGRAMS,
            ..global
        },
        Charge {
            host: 129,
            ..one.charge
        },
        CacheLimits {
            host_bytes: MAX_PUBLIC_PROGRAM_BYTES,
            ..limits
        },
        runtime
    )
    .is_err());
    for invalid in [
        CacheLimits {
            entries: 0,
            ..limits
        },
        CacheLimits {
            entries: 33,
            ..limits
        },
        CacheLimits {
            host_bytes: 0,
            ..limits
        },
        CacheLimits {
            host_bytes: usize::MAX,
            ..limits
        },
        CacheLimits {
            device_bytes: 0,
            ..limits
        },
        CacheLimits {
            device_bytes: 393,
            ..limits
        },
    ] {
        assert!(invalid.validate(runtime).is_err());
    }
}

#[test]
#[ignore = "requires CUDA and NVRTC; run serially"]
fn cuda_cached_programs_reuse_code_but_keep_fresh_inputs_and_cpu_correctness() {
    use crate::block_v2::profile::Challenge as F;
    let runtime = runtime(2 << 20, 1 << 20);
    let evaluator = Quotients::new(&runtime).unwrap();
    for (mode, fallback) in [
        (Specialization::Generic, false),
        (Specialization::Prefer, false),
        (Specialization::Prefer, true),
    ] {
        let program = || {
            let mut p = simple(Extension::Cubic, 1);
            if fallback {
                p.registers = specialize::MAX_REGISTERS + 1;
            }
            Arc::new(p)
        };
        let prepared = evaluator.prepare_cached([1; 32], program(), mode).unwrap();
        assert_eq!(
            prepared.specialized.is_some(),
            mode == Specialization::Prefer && !fallback
        );
        let before = runtime.snapshot();
        let again = evaluator.prepare_cached([1; 32], program(), mode).unwrap();
        assert!(Arc::ptr_eq(&prepared, &again));
        assert_eq!(
            runtime.snapshot(),
            before,
            "hit must not compile, upload or allocate"
        );
        let alpha = scalars(&runtime, &[17, 19, 23]);
        for (shift, seed, order) in [(7, 17, RowOrder::Natural), (11, 37, RowOrder::BitReversed)] {
            let (main, values) = matrix(&runtime, 3, 1, Extension::Base, order, shift, seed);
            let output = evaluator
                .evaluate(
                    &prepared,
                    3,
                    QuotientInputs {
                        main: Some(&main),
                        preprocessed: None,
                        permutation: None,
                    },
                    &alpha,
                    None,
                )
                .unwrap();
            let expected: Vec<_> = values
                .iter()
                .enumerate()
                .flat_map(|(row, &value)| {
                    let x = Val::new(shift) * Val::two_adic_generator(3).exp_u64(row as u64);
                    words(F::from(
                        (value + Val::new(7)).square() / (x.exp_power_of_2(3) - Val::ONE),
                    ))
                })
                .collect();
            assert_eq!(output.read(output.spec.bytes()).unwrap(), expected);
        }
        let other_profile = evaluator.prepare_cached([2; 32], program(), mode).unwrap();
        assert!(!Arc::ptr_eq(&prepared, &other_profile));
        drop(other_profile);
        drop(again);
        drop(alpha);
        drop(prepared);
    }
    let stats = evaluator.prepared_cache_snapshot().unwrap();
    assert_eq!((stats.entries, stats.hits, stats.misses), (6, 3, 6));
    assert_eq!(runtime.snapshot().public_programs, 6);
    evaluator.clear_prepared_cache().unwrap();
    assert_eq!(runtime.snapshot().public_programs, 0);
    assert_eq!(runtime.snapshot().public_program_bytes, 0);
    assert_eq!(runtime.snapshot().live_bytes, 8);
    assert_eq!(runtime.snapshot().modules, 1);
}

#[test]
#[ignore = "requires CUDA and NVRTC; run serially"]
fn cuda_cache_evicts_lru_and_rejects_full_pinned_or_invalid_requests() {
    let runtime = runtime(64 << 10, 32 << 10);
    let evaluator = Quotients::with_cache_limits(
        &runtime,
        CacheLimits {
            entries: 2,
            host_bytes: 32 << 10,
            device_bytes: 400,
        },
    )
    .unwrap();
    let make = |constant: u64| {
        let mut p = simple(Extension::Cubic, 1);
        p.instructions[7] = constant;
        Arc::new(p)
    };
    let first = evaluator
        .prepare_cached([1; 32], make(7), Specialization::Generic)
        .unwrap();
    drop(first);
    drop(
        evaluator
            .prepare_cached([1; 32], make(8), Specialization::Generic)
            .unwrap(),
    );
    let first = evaluator
        .prepare_cached([1; 32], make(7), Specialization::Generic)
        .unwrap();
    drop(first);
    let third = evaluator
        .prepare_cached([1; 32], make(9), Specialization::Generic)
        .unwrap();
    let before = runtime.snapshot();
    let first = evaluator
        .prepare_cached([1; 32], make(7), Specialization::Generic)
        .unwrap();
    assert_eq!(
        runtime.snapshot(),
        before,
        "recently used entry survives eviction"
    );
    let cache = evaluator.prepared_cache_snapshot().unwrap();
    assert_eq!(
        (cache.entries, cache.hits, cache.misses, cache.evictions),
        (2, 2, 3, 1)
    );
    assert_eq!(cache.device_bytes, 400);
    assert!(evaluator
        .prepare_cached([1; 32], make(10), Specialization::Generic)
        .is_err());
    assert_eq!(runtime.snapshot(), before);
    assert_eq!(evaluator.prepared_cache_snapshot().unwrap().evictions, 1);
    let mut invalid = simple(Extension::Cubic, 1);
    invalid.instructions[0] = 999;
    assert!(evaluator
        .prepare_cached([1; 32], Arc::new(invalid), Specialization::Generic)
        .is_err());
    assert_eq!(runtime.snapshot(), before);
    // Clearing a cache does not revoke or prematurely uncharge pinned handles.
    evaluator.clear_prepared_cache().unwrap();
    assert_eq!(runtime.snapshot(), before);
    assert_eq!(evaluator.prepared_cache_snapshot().unwrap().entries, 0);
    drop(first);
    assert_eq!(runtime.snapshot().public_programs, 1);
    drop(third);
    assert_eq!(runtime.snapshot().public_programs, 0);
    assert_eq!(runtime.snapshot().live_bytes, 8);
}

#[test]
#[ignore = "requires CUDA and NVRTC; run serially"]
fn cuda_concurrent_cache_requests_prepare_once_and_account_external_handles() {
    let runtime = runtime(2 << 20, 1 << 20);
    let evaluator = Quotients::new(&runtime).unwrap();
    let barrier = std::sync::Barrier::new(6);
    let before = runtime.snapshot();
    let handles = std::thread::scope(|scope| {
        let jobs: Vec<_> = (0..6)
            .map(|_| {
                scope.spawn(|| {
                    barrier.wait();
                    evaluator
                        .prepare_cached(
                            [1; 32],
                            Arc::new(simple(Extension::Cubic, 1)),
                            Specialization::Prefer,
                        )
                        .unwrap()
                })
            })
            .collect();
        jobs.into_iter()
            .map(|job| job.join().unwrap())
            .collect::<Vec<_>>()
    });
    assert!(handles
        .iter()
        .all(|handle| Arc::ptr_eq(handle, &handles[0])));
    let after = runtime.snapshot();
    assert_eq!(after.modules, before.modules + 1);
    assert_eq!(after.allocations, before.allocations + 1);
    assert_eq!(after.uploaded_bytes - before.uploaded_bytes, 200);
    assert_eq!(after.public_programs, 1);
    let stats = evaluator.prepared_cache_snapshot().unwrap();
    assert_eq!((stats.entries, stats.hits, stats.misses), (1, 5, 1));
    drop(evaluator);
    assert_eq!(runtime.snapshot().public_programs, 1);
    assert_eq!(runtime.snapshot().live_bytes, 200);
    assert_eq!(runtime.snapshot().modules, 1);
    drop(handles);
    assert_eq!(runtime.snapshot().public_programs, 0);
    assert_eq!(runtime.snapshot().public_program_bytes, 0);
    assert_eq!(runtime.snapshot().live_bytes, 0);
    assert_eq!(runtime.snapshot().modules, 0);
}

#[test]
#[ignore = "requires CUDA and NVRTC; run serially"]
fn cuda_failed_runtime_rejects_cache_hits_and_misses_without_eviction() {
    let runtime = runtime(1 << 20, 1 << 20);
    let evaluator = Quotients::new(&runtime).unwrap();
    let program = Arc::new(simple(Extension::Cubic, 1));
    let handle = evaluator
        .prepare_cached([1; 32], program.clone(), Specialization::Generic)
        .unwrap();
    let before = runtime.snapshot();
    let cache = evaluator.prepared_cache_snapshot().unwrap();
    runtime.state.fail();
    assert!(evaluator
        .prepare_cached([1; 32], program.clone(), Specialization::Generic)
        .is_err());
    assert!(evaluator
        .prepare_cached([2; 32], program, Specialization::Generic)
        .is_err());
    assert_eq!(runtime.snapshot(), before);
    assert_eq!(evaluator.prepared_cache_snapshot().unwrap(), cache);
    evaluator.clear_prepared_cache().unwrap();
    assert_eq!(runtime.snapshot(), before);
    drop(handle);
    assert_eq!(runtime.snapshot().public_programs, 0);
    assert_eq!(runtime.snapshot().public_program_bytes, 0);
    assert_eq!(runtime.snapshot().live_bytes, 8);
}
