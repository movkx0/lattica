use super::*;

fn inventory(scope: CoverageScope) -> Capabilities {
    let mut caps = Capabilities::cpu(Profile::BlockV2Cubic, true, false)
        .scoped(scope, &[Stage::Preprocessing]);
    caps.set(Stage::Preprocessing, Backend::OpenCl);
    caps
}
fn required() -> Request {
    Request {
        policy: Policy::GpuRequired,
        emit_report: false,
    }
}
fn parent(slots: &[(&'static str, CoverageScope)]) -> Run {
    Run::request(
        "composition_test",
        required(),
        inventory(CoverageScope::ProofRequest),
        slots,
    )
    .unwrap()
}
fn receipt(run: &Run, calls: u64) {
    run.observe_device(Stage::Preprocessing, Backend::OpenCl, calls, 7)
        .unwrap();
}
fn cached() -> CachedScope {
    let run = Run::new("setup", required(), inventory(CoverageScope::Preprocessing)).unwrap();
    receipt(&run, 5);
    CachedScope::preprocessing(&run.finish(true).unwrap()).unwrap()
}

fn compilation() -> CachedScope {
    let run = Run::new(
        "compile",
        required(),
        inventory(CoverageScope::RegistryCompilation),
    )
    .unwrap();
    receipt(&run, 5);
    CachedScope::registry_compilation(&run.finish(true).unwrap()).unwrap()
}

#[test]
fn cached_compilation_marks_only_its_scope_without_replaying_arithmetic() {
    let cached = compilation();
    let run = parent(&[
        ("registry", CoverageScope::RegistryCompilation),
        ("proof", CoverageScope::RegisteredProof),
    ]);
    run.reuse_registry_compilation(&cached).unwrap();
    let proof = run
        .child("proof", "proof", inventory(CoverageScope::RegisteredProof))
        .unwrap();
    receipt(&proof, 2);
    proof.finish(true).unwrap();
    let report = run.finish(true).unwrap();
    assert!(report.stage_coverage_complete && report.components[0].cached);
    assert!(!report.components[1].cached);
    assert_eq!(report.observations.len(), 1);
    assert_eq!(report.observations[0].device_calls, 2);
    assert_eq!(report.observations[0].device_ns, 7);
}

#[test]
fn compilation_receipt_rejects_wrong_scope_failure_incomplete_and_lost_observation() {
    for reject in 0..4 {
        let run = Run::new(
            "compile",
            required(),
            inventory(CoverageScope::RegistryCompilation),
        )
        .unwrap();
        receipt(&run, 1);
        let mut changed = run.finish(true).unwrap();
        match reject {
            0 => changed.capabilities.scope = CoverageScope::Preprocessing,
            1 => changed.succeeded = false,
            2 => changed.stage_coverage_complete = false,
            3 => changed.observation_errors = 1,
            _ => unreachable!(),
        }
        assert!(CachedScope::registry_compilation(&changed).is_err());
    }
}

#[test]
fn cached_compilation_cannot_cross_scope_backend_profile_or_duplicate_slot() {
    let cached = compilation();
    let run = parent(&[("registry", CoverageScope::RegistryCompilation)]);
    run.reuse_registry_compilation(&cached).unwrap();
    assert!(run.reuse_registry_compilation(&cached).is_err());
    assert!(run.finish(true).is_err());
    let run = parent(&[("setup", CoverageScope::Preprocessing)]);
    assert!(run.reuse_preprocessing("setup", &cached).is_err());
    assert!(run.finish(true).is_err());
    let run = parent(&[("registry", CoverageScope::RegistryCompilation)]);
    assert!(run.reuse_registry_compilation(&self::cached()).is_err());
    assert!(run.finish(true).is_err());
    for cpu in [false, true] {
        let mut caps = inventory(CoverageScope::RegistryCompilation);
        if cpu {
            caps.set(Stage::Preprocessing, Backend::Cpu);
        } else {
            caps.profile = Profile::LegacyQuadratic;
        }
        let source = Run::new("foreign", Request::compatible(), caps).unwrap();
        if cpu {
            source
                .measure(Stage::Preprocessing, Backend::Cpu, || ())
                .unwrap();
        } else {
            receipt(&source, 1);
        }
        let foreign = CachedScope::registry_compilation(&source.finish(true).unwrap()).unwrap();
        let run = parent(&[("registry", CoverageScope::RegistryCompilation)]);
        assert!(run.reuse_registry_compilation(&foreign).is_err());
        assert!(run.finish(true).is_err());
    }
}

#[test]
fn overlapping_stage_receipts_cannot_cover_an_omitted_component() {
    let run = parent(&[
        ("first", CoverageScope::Preprocessing),
        ("second", CoverageScope::Preprocessing),
    ]);
    let child = run
        .child("first", "setup", inventory(CoverageScope::Preprocessing))
        .unwrap();
    receipt(&child, 1);
    child.finish(true).unwrap();
    let Error::IncompleteCoverage {
        missing,
        missing_components,
        ..
    } = run.finish(true).unwrap_err()
    else {
        panic!("missing component admitted")
    };
    assert!(missing.is_empty());
    assert_eq!(missing_components, ["second"]);
}

#[test]
fn cached_preprocessing_is_explicit_without_replaying_device_events() {
    let setup = cached();
    let run = parent(&[
        ("setup", CoverageScope::Preprocessing),
        ("proof", CoverageScope::RegisteredProof),
    ]);
    run.reuse_preprocessing("setup", &setup).unwrap();
    let child = run
        .child("proof", "proof", inventory(CoverageScope::RegisteredProof))
        .unwrap();
    receipt(&child, 2);
    child.finish(true).unwrap();
    let report = run.finish(true).unwrap();
    assert!(report.stage_coverage_complete);
    assert!(report.components[0].cached && !report.components[1].cached);
    assert_eq!(report.observations[0].device_calls, 2);
    assert_eq!(report.observations[0].device_ns, 7);
    let only_cache = parent(&[("setup", CoverageScope::Preprocessing)]);
    only_cache.reuse_preprocessing("setup", &setup).unwrap();
    assert!(matches!(
        only_cache.finish(true),
        Err(Error::IncompleteCoverage { .. })
    ));
}

#[test]
fn failed_and_unwound_children_preserve_work_without_json_reports() {
    for unwind in [false, true] {
        let run = parent(&[("setup", CoverageScope::Preprocessing)]);
        let child = run
            .child("setup", "setup", inventory(CoverageScope::Preprocessing))
            .unwrap();
        receipt(&child, 3);
        if unwind {
            assert!(
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
                    let _child = child;
                    panic!("injected failure after device work");
                }))
                .is_err()
            );
        } else {
            child.finish(false).unwrap();
        }
        let report = run.finish(false).unwrap();
        assert!(!report.succeeded && !report.components[0].succeeded);
        assert_eq!(report.observations[0].device_calls, 3);
        assert_eq!(report.observation_errors, 0);
    }
}

#[test]
fn duplicate_wrong_scope_and_foreign_profile_components_are_rejected() {
    for case in 0..3 {
        let run = parent(&[("setup", CoverageScope::Preprocessing)]);
        let valid = run
            .child("setup", "setup", inventory(CoverageScope::Preprocessing))
            .unwrap();
        let mut caps = inventory(CoverageScope::Preprocessing);
        if case == 1 {
            caps.scope = CoverageScope::Statement;
        }
        if case == 2 {
            caps.profile = Profile::LegacyQuadratic;
        }
        assert!(matches!(
            run.child("setup", "duplicate", caps),
            Err(Error::ComponentRejected)
        ));
        receipt(&valid, 1);
        valid.finish(true).unwrap();
        assert!(matches!(
            run.finish(true),
            Err(Error::IncompleteCoverage {
                observation_errors: 1,
                ..
            })
        ));
    }
}

#[test]
fn concurrent_children_merge_once_and_counter_overflow_rejects_completion() {
    for count in [2, u64::MAX] {
        let run = parent(&[
            ("a", CoverageScope::Preprocessing),
            ("b", CoverageScope::Preprocessing),
        ]);
        std::thread::scope(|threads| {
            for (id, n) in [("a", count), ("b", 1)] {
                let child = run
                    .child(id, "setup", inventory(CoverageScope::Preprocessing))
                    .unwrap();
                threads.spawn(move || {
                    receipt(&child, n);
                    child.finish(true).unwrap();
                });
            }
        });
        let result = run.finish(true);
        if count == u64::MAX {
            assert!(matches!(
                result,
                Err(Error::IncompleteCoverage {
                    observation_errors: 1,
                    ..
                })
            ));
        } else {
            let report = result.unwrap();
            assert_eq!(report.observations[0].device_calls, 3);
            assert_eq!(report.observations[0].device_ns, 14);
        }
    }
}

#[test]
fn outstanding_children_cannot_reopen_a_finished_parent() {
    let run = parent(&[("setup", CoverageScope::Preprocessing)]);
    let child = run
        .child("setup", "setup", inventory(CoverageScope::Preprocessing))
        .unwrap();
    let state = Arc::clone(&run.state);
    assert!(matches!(
        run.finish(true),
        Err(Error::IncompleteCoverage { .. })
    ));
    receipt(&child, 1);
    child.finish(true).unwrap();
    let state = state.lock().unwrap();
    assert!(state.finished && state.observations.is_empty() && state.components.is_empty());
}

#[test]
fn cpu_and_incomplete_cached_setup_cannot_complete_a_gpu_request() {
    let mut caps = inventory(CoverageScope::Preprocessing);
    caps.set(Stage::Preprocessing, Backend::Cpu);
    let cpu = Run::new("cpu", Request::compatible(), caps).unwrap();
    cpu.measure(Stage::Preprocessing, Backend::Cpu, || ())
        .unwrap();
    let cache = CachedScope::preprocessing(&cpu.finish(true).unwrap()).unwrap();
    let run = parent(&[("setup", CoverageScope::Preprocessing)]);
    assert!(matches!(
        run.reuse_preprocessing("setup", &cache),
        Err(Error::Unsupported { .. })
    ));
    assert!(run.finish(true).is_err());
    let incomplete = Run::new(
        "incomplete",
        Request::compatible(),
        inventory(CoverageScope::Preprocessing),
    )
    .unwrap();
    let cache = CachedScope::preprocessing(&incomplete.finish(true).unwrap()).unwrap();
    let run = parent(&[
        ("setup", CoverageScope::Preprocessing),
        ("proof", CoverageScope::RegisteredProof),
    ]);
    run.reuse_preprocessing("setup", &cache).unwrap();
    let proof = run
        .child("proof", "proof", inventory(CoverageScope::RegisteredProof))
        .unwrap();
    receipt(&proof, 1);
    proof.finish(true).unwrap();
    assert!(
        matches!(run.finish(true), Err(Error::IncompleteCoverage { missing_components, .. }) if missing_components == ["setup"])
    );
}

#[test]
fn malformed_plans_and_foreign_inventories_fail_before_work() {
    let scopes = [
        ("same", CoverageScope::Preprocessing),
        ("same", CoverageScope::Preprocessing),
    ];
    assert!(matches!(
        Run::request(
            "bad",
            required(),
            inventory(CoverageScope::ProofRequest),
            &scopes
        ),
        Err(Error::ComponentRejected)
    ));
    assert!(Run::request(
        "bad",
        required(),
        inventory(CoverageScope::ProofRequest),
        &[]
    )
    .is_err());
    let run = parent(&[("setup", CoverageScope::Preprocessing)]);
    let mut foreign = inventory(CoverageScope::Preprocessing);
    foreign.profile = Profile::LegacyQuadratic;
    assert!(matches!(
        run.child("setup", "foreign", foreign),
        Err(Error::ComponentRejected)
    ));
    let mut extra = inventory(CoverageScope::Preprocessing);
    extra.stages.push(StageCapability {
        stage: Stage::Scalar,
        backend: Backend::OpenCl,
    });
    assert!(matches!(
        run.child("setup", "extra", extra),
        Err(Error::ComponentRejected)
    ));
    assert!(run.finish(true).is_err());
}
