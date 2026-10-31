use super::*;

#[cfg(not(debug_assertions))]
#[test]
fn native_leaf_preflight_accepts_post_close_outer_residual_and_keeps_compile_zero() {
    use crate::execution::workflow_resources::WorkflowError;
    use crate::spend_pipeline::full_workflow::driver::native_runtime::check_leaf_backend;

    // Use the actual close_memory residual calculation. These are arithmetic
    // inputs only: no fabricated binding, closed plan or admission token.
    let allowance = Bytes { host: 32 << 30, device: 8 << 30 };
    let backend = outer_residual(allowance,
        Bytes { host: 3 << 30, device: 0 },
        Bytes { host: 5 << 30, device: 0 },
        Bytes { host: 2 << 30, device: 0 }, allowance.host).unwrap();
    assert_eq!(backend, Bytes { host: 22 << 30, device: 8 << 30 });
    assert!(check_leaf_backend(GraphPhase::Outer, backend).is_ok());
    assert!(check_leaf_backend(GraphPhase::Compile, Bytes::ZERO).is_ok());
    assert!(matches!(check_leaf_backend(GraphPhase::Compile, backend),
        Err(WorkflowError::BackendAllowance)));
    assert!(matches!(check_leaf_backend(GraphPhase::Outer, Bytes::ZERO),
        Err(WorkflowError::BackendAllowance)));
}

#[cfg(not(debug_assertions))]
#[test]
fn native_leaf_preflight_rejects_missing_or_out_of_bounds_gpu_allowances() {
    use crate::execution::workflow_resources::WorkflowError;
    use crate::spend_pipeline::full_workflow::driver::native_runtime::check_leaf_backend;

    for backend in [
        Bytes { host: 0, device: 8 << 30 },
        Bytes { host: (32 << 30) + 1, device: 8 << 30 },
        Bytes { host: 1 << 30, device: 0 },
        Bytes { host: 1 << 30, device: (8 << 30) - 1 },
        Bytes { host: 1 << 30, device: (8 << 30) + 1 },
    ] {
        assert!(matches!(check_leaf_backend(GraphPhase::Outer, backend),
            Err(WorkflowError::BackendAllowance)));
        assert!(matches!(check_leaf_backend(GraphPhase::Compile, backend),
            Err(WorkflowError::BackendAllowance)));
    }
}

#[test]
fn outer_residual_charges_retained_idle_pool_and_current_temporaries_before_selection() {
    let allowance = Bytes { host: 32 << 30, device: 8 << 30 };
    let retained = Bytes { host: 3 << 30, device: 0 };
    let pool = Bytes { host: 5 << 30, device: 0 };
    let scratch = Bytes { host: 2 << 30, device: 0 };
    assert_eq!(outer_residual(allowance, retained, pool, scratch, 32 << 30).unwrap(),
        Bytes { host: 22 << 30, device: 8 << 30 });
    assert_eq!(outer_residual(allowance, retained, pool, scratch, 20 << 30).unwrap().host, 20 << 30);
    assert!(outer_residual(allowance, retained, Bytes { host: 29 << 30, device: 0 }, scratch, 32 << 30).is_err());
    assert!(outer_residual(allowance, retained, Bytes { device: 1, ..pool }, scratch, 32 << 30).is_err());
    assert!(outer_residual(Bytes { host: (32 << 30) + 1, ..allowance }, retained, pool, scratch, 32 << 30).is_err());
}

#[test]
fn outer_residual_leaves_exact_space_for_the_real_pool_bookkeeping_owner() {
    let slots = [
        SlotSpec { requirements: Requirements::single(Category::Report, Bytes { host: 4096, device: 0 }) },
        SlotSpec { requirements: Requirements::single(Category::SymbolicCompiler, Bytes { host: 2 << 30, device: 0 }) },
    ];
    let (pool, bookkeeping) = admission_pool_requirements(&slots).unwrap();
    assert_eq!(pool.get(Category::SymbolicCompiler).host, 2 << 30);
    assert_eq!(pool.get(Category::Report).host, 4096);
    let book = bookkeeping.total().unwrap();
    assert!(book.host > 0);
    assert_eq!(book.device, 0);
    let complete_pool = sum(pool, bookkeeping).unwrap().total().unwrap();
    let allowance = Bytes { host: 32 << 30, device: 8 << 30 };
    let retained = Bytes { host: 1 << 30, device: 0 };
    let held = Bytes { host: 3 << 20, device: 0 };
    let backend = outer_residual(allowance, retained, complete_pool, held, allowance.host).unwrap();
    let active = Bytes { host: complete_pool.host + held.host + backend.host, device: backend.device };
    assert_eq!(active.host + retained.host, allowance.host);
    assert_eq!(check_combined_admission(allowance, retained, active), Ok(()));
    assert!(check_combined_admission(allowance, retained,
        Bytes { host: active.host + 1, ..active }).is_err());

    // The old omitted-bookkeeping residual would overfill actual preflight.
    let omitted = outer_residual(allowance, retained, pool.total().unwrap(), held, allowance.host).unwrap();
    assert!(check_combined_admission(allowance, retained,
        Bytes { host: complete_pool.host + held.host + omitted.host, device: omitted.device }).is_err());
}

#[test]
fn screen7_host_obstruction_survives_an_insufficient_real_scratch_release() {
    // Arithmetic regression only: these numbers never create a transition or
    // authorize subtracting a reservation. The typed owner tests cover that.
    let allowance = Bytes { host: 34_359_738_368, device: 8 << 30 };
    let observed_host = 8_273_630_038u64;
    let slots_host = 5_938_661_850u64;
    let fixed_host = 26_770_653_808u64;
    let bookkeeping = crate::execution::workflow_resources::closed_pool_requirements(2)
        .unwrap().total().unwrap();
    let active = Bytes { host: slots_host + bookkeeping.host + fixed_host, device: 8 << 30 };
    let minimum_release = observed_host + active.host - allowance.host;
    assert_eq!(minimum_release, 6_623_207_328 + bookkeeping.host);
    assert!(check_combined_admission(allowance,
        Bytes { host: observed_host - (3 << 30), device: 0 }, active).is_err());
    assert!(check_combined_admission(allowance,
        Bytes { host: observed_host - minimum_release + 1, device: 0 }, active).is_err());
    assert_eq!(check_combined_admission(allowance,
        Bytes { host: observed_host - minimum_release, device: 0 }, active), Ok(()));
    // A startup device original still counted outside the reunited phase
    // cannot coexist with its complete eight-GiB device claim.
    assert!(check_combined_admission(allowance,
        Bytes { host: observed_host - minimum_release, device: 1 }, active).is_err());
}

#[test]
fn combined_admission_refuses_overflow_without_saturating_to_credit() {
    let allowance = Bytes { host: 32 << 30, device: 8 << 30 };
    assert!(check_combined_admission(allowance, Bytes { host: 1, device: 0 },
        Bytes { host: u64::MAX, device: 0 }).is_err());
    assert!(check_combined_admission(allowance, Bytes { host: 0, device: 1 },
        Bytes { host: 0, device: u64::MAX }).is_err());
}

#[test]
fn scheduler_metadata_checks_all_collection_products_before_allocation() {
    assert!(schedule_metadata_requirements(usize::MAX, 1).is_err());
    assert!(schedule_metadata_requirements(1, usize::MAX).is_err());
    let small = schedule_metadata_requirements(10, 1).unwrap();
    let large = schedule_metadata_requirements(20, 2).unwrap();
    assert_eq!(small.total().unwrap().device, 0);
    assert!(large.get(Category::RegisteredMetadata).host > small.get(Category::RegisteredMetadata).host);
    assert_eq!(large.get(Category::PhaseScratch), Bytes::ZERO);
}

#[test]
fn source_geometry_and_crypto_proofs_cannot_erase_missing_final_producers() {
    use super::source::UnavailableProducers;
    for total in [3, 4] {
        let missing = UnavailableProducers { final_compile: total - 1,
            final_outer: total - 1, final_verifier: 1, ..UnavailableProducers::default() };
        assert_eq!(missing.require_complete(), Err(ClosureError::MissingProducers(missing)));
    }
}
