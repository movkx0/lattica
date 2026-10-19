use super::*;
use crate::{
    block_v2::machine::{backend::RegisteredVerifier, ProgramBuilder},
    cuda_compute::Limits,
    proving::Policy,
};
use p3_batch_stark::{verify_batch, ProverData};

const HOST: usize = 1 << 30;

fn request() -> Request {
    Request {
        policy: Policy::GpuRequired,
        emit_report: false,
    }
}

fn runtime() -> Runtime {
    Runtime::new(
        &std::env::var("LATTICA_GPU_DEVICE_UUID").unwrap(),
        Limits {
            managed_bytes: 256 << 20,
            max_allocation_bytes: 64 << 20,
            ..Limits::default()
        },
    )
    .unwrap()
}

fn air(constant: u64, publics: bool) -> MachineAir {
    let mut b = ProgramBuilder::new(usize::from(publics)).unwrap();
    let input = b.input();
    let c = b.constant(Val::from_u64(constant));
    let sum = b.add(input, c);
    if publics {
        b.assert_equal(sum, b.public(0).unwrap());
    }
    b.poseidon([input, c, sum, input, c, sum, input, c]);
    MachineAir::new(b.finish(Some(16)).unwrap())
}

fn key<'a>(air: &MachineAir, cap: &'a [[Val; 4]]) -> RegisteredKey<'a> {
    RegisteredKey {
        profile: Profile::BlockV2Cubic,
        height: air.program().height(),
        public_values: air.program().public_values(),
        witness_values: air.program().witness_values(),
        cap,
    }
}

fn input(publics: bool) -> MachineInputs<'static> {
    MachineInputs {
        public: if publics { &[10] } else { &[] },
        witness: &[3],
    }
}

#[test]
fn registered_components_require_complete_receipts_even_with_compatible_policy() {
    let run = Run::new(
        "empty_setup",
        Request::compatible(),
        BatchStarks::preprocessing_capabilities(),
    )
    .unwrap();
    assert!(finish(run, Ok(())).is_err());
}

#[test]
#[ignore = "requires CUDA; serial bounded service"]
fn cuda_registered_machine_authenticates_setup_and_returns_fresh_verified_proofs() {
    let runtime = runtime();
    let engine = Arc::new(BatchStarks::new(&runtime).unwrap());
    for publics in [true, false] {
        let air = air(7, publics);
        let cpu = super::super::tests::cpu();
        let data = ProverData::from_airs_and_degrees(&cpu, &[air.clone()], &[5]);
        let cap = &data.common.preprocessed.as_ref().unwrap().commitment;
        let baseline = runtime.snapshot();
        let oracle_calls = crate::proving::cpu_witness_oracle_calls();
        let (prepared, setup) = engine
            .prepare_registered(
                &air,
                key(&air, cap.roots()),
                request(),
                HOST,
                Specialization::Prefer,
            )
            .unwrap();
        assert!(setup.stage_coverage_complete && setup.succeeded);
        assert_eq!(setup.capabilities.scope(), CoverageScope::Preprocessing);
        assert_eq!(setup.observations.len(), 5);
        assert!(setup
            .observations
            .iter()
            .all(|o| o.backend == Backend::Cuda && o.device_calls > 0));
        assert_eq!(&prepared.preprocessing_cap().unwrap(), cap);
        let before = runtime.snapshot();
        let pv: Vec<_> = input(publics)
            .public
            .iter()
            .map(|&v| Val::from_u64(v))
            .collect();
        let verifier = RegisteredVerifier::from_trusted_cap(pv.len(), 16, cap.clone()).unwrap();
        let mut encoded = Vec::new();
        for _ in 0..2 {
            let output = prepared.prove(input(publics), request(), HOST).unwrap();
            let report = &output.report;
            assert!(report.succeeded && report.stage_coverage_complete);
            assert_eq!(report.capabilities.scope(), CoverageScope::RegisteredProof);
            assert_eq!(report.observations.len(), if publics { 15 } else { 14 });
            assert!(report
                .observations
                .iter()
                .all(|o| o.backend == Backend::Cuda
                    && o.device_calls > 0
                    && o.stage != Stage::Preprocessing));
            verify_batch(
                &cpu,
                &[air.clone()],
                &output.proof,
                &[pv.clone()],
                &data.common,
            )
            .unwrap();
            let bytes = postcard::to_allocvec(&output.proof).unwrap();
            assert_ne!(encoded, bytes);
            encoded = bytes;
            let production = postcard::from_bytes(&encoded).unwrap();
            verifier.verify(&production, &pv).unwrap();
            if publics {
                assert!(verifier.verify(&production, &[Val::from_u64(11)]).is_err());
            }
            assert_eq!(runtime.snapshot().live_bytes, before.live_bytes);
            assert_eq!(runtime.snapshot().allocations, before.allocations);
            assert_eq!(
                runtime.snapshot().public_program_bytes,
                before.public_program_bytes
            );
        }
        assert_eq!(crate::proving::cpu_witness_oracle_calls(), oracle_calls);
        drop(prepared);
        assert_eq!(runtime.snapshot().live_bytes, baseline.live_bytes);
        assert_eq!(
            runtime.snapshot().public_program_bytes,
            baseline.public_program_bytes
        );
    }
}

#[test]
#[ignore = "requires CUDA; serial bounded service"]
fn cuda_registered_setup_rejects_substituted_programs_keys_and_run_scopes() {
    let runtime = runtime();
    let engine = Arc::new(BatchStarks::new(&runtime).unwrap());
    let air = air(7, true);
    let cpu = super::super::tests::cpu();
    let data = ProverData::from_airs_and_degrees(&cpu, &[air.clone()], &[5]);
    let cap = &data.common.preprocessed.as_ref().unwrap().commitment;
    let approval = key(&air, cap.roots());
    let before = runtime.snapshot();
    for bad in [
        RegisteredKey {
            profile: Profile::LegacyQuadratic,
            ..approval
        },
        RegisteredKey {
            height: 32,
            ..approval
        },
        RegisteredKey {
            public_values: 0,
            ..approval
        },
        RegisteredKey {
            witness_values: 2,
            ..approval
        },
        RegisteredKey {
            cap: &[],
            ..approval
        },
    ] {
        assert!(engine
            .prepare_registered(&air, bad, request(), HOST, Specialization::Generic)
            .is_err());
        assert_eq!(runtime.snapshot(), before);
    }
    let cpu_only = Request {
        policy: Policy::CpuRequired,
        emit_report: false,
    };
    assert!(engine
        .prepare_registered(&air, approval, cpu_only, HOST, Specialization::Generic)
        .is_err());
    assert!(engine
        .prepare_registered(&air, approval, request(), 1, Specialization::Generic)
        .is_err());
    let wrong_scope = Run::new(
        "wrong_setup_scope",
        request(),
        capabilities(CoverageScope::Operation, &PREPROCESSING),
    )
    .unwrap();
    assert!(engine
        .prepare_registered_in_run(&air, approval, wrong_scope, HOST, Specialization::Generic)
        .is_err());
    assert_eq!(runtime.snapshot(), before);
    let mut altered = cap.roots().to_vec();
    altered[0][0] += Val::ONE;
    assert!(engine
        .prepare_registered(
            &air,
            RegisteredKey {
                cap: &altered,
                ..approval
            },
            request(),
            HOST,
            Specialization::Generic
        )
        .is_err());
    let other = self::air(8, true);
    assert!(engine
        .prepare_registered(&other, approval, request(), HOST, Specialization::Generic)
        .is_err());
    assert_eq!(runtime.snapshot().live_bytes, before.live_bytes);
    assert_eq!(runtime.snapshot().allocations, before.allocations);
    assert_eq!(
        runtime.snapshot().public_program_bytes,
        before.public_program_bytes
    );
    assert_eq!(runtime.snapshot().modules, before.modules);
    engine
        .prepare_registered(&air, approval, request(), HOST, Specialization::Generic)
        .unwrap();
}

#[test]
#[ignore = "requires CUDA; serial bounded service"]
fn cuda_registered_proof_rejects_invalid_requests_before_importing_private_seeds() {
    let runtime = runtime();
    let engine = Arc::new(BatchStarks::new(&runtime).unwrap());
    let air = air(7, true);
    let cpu = super::super::tests::cpu();
    let data = ProverData::from_airs_and_degrees(&cpu, &[air.clone()], &[5]);
    let cap = &data.common.preprocessed.as_ref().unwrap().commitment;
    let (prepared, _) = engine
        .prepare_registered(
            &air,
            key(&air, cap.roots()),
            request(),
            HOST,
            Specialization::Generic,
        )
        .unwrap();
    let before = runtime.snapshot();
    for bad in [
        MachineInputs {
            public: &[],
            witness: &[3],
        },
        MachineInputs {
            public: &[10],
            witness: &[],
        },
        MachineInputs {
            public: &[u64::MAX],
            witness: &[3],
        },
        MachineInputs {
            public: &[10],
            witness: &[u64::MAX],
        },
    ] {
        assert!(prepared.prove(bad, request(), HOST).is_err());
    }
    assert!(prepared.prove(input(true), request(), 1).is_err());
    assert!(prepared
        .prove(
            input(true),
            Request {
                policy: Policy::CpuRequired,
                emit_report: false
            },
            HOST
        )
        .is_err());
    for caps in [
        capabilities(CoverageScope::Operation, &Stage::ARITHMETIC),
        capabilities(CoverageScope::RegisteredProof, &[Stage::WitnessTrace]),
        Capabilities::cpu(Profile::LegacyQuadratic, false, true)
            .scoped(CoverageScope::RegisteredProof, &[Stage::WitnessTrace]),
    ] {
        let run = Run::new("wrong_proof_inventory", Request::compatible(), caps).unwrap();
        assert!(prepared.prove_in_run(input(true), run, HOST).is_err());
    }
    assert_eq!(runtime.snapshot(), before);
    let proof = prepared.prove(input(true), request(), HOST).unwrap();
    verify_batch(
        &cpu,
        &[air],
        &proof.proof,
        &[vec![Val::from_u64(10)]],
        &data.common,
    )
    .unwrap();
}

#[test]
#[ignore = "requires CUDA; serial bounded service"]
fn cuda_registered_failures_preserve_authenticated_setup_and_report_failure() {
    let runtime = runtime();
    let engine = Arc::new(BatchStarks::new(&runtime).unwrap());
    let air = air(7, true);
    let cpu = super::super::tests::cpu();
    let data = ProverData::from_airs_and_degrees(&cpu, &[air.clone()], &[5]);
    let cap = &data.common.preprocessed.as_ref().unwrap().commitment;
    let (prepared, _) = engine
        .prepare_registered(
            &air,
            key(&air, cap.roots()),
            request(),
            HOST,
            Specialization::Generic,
        )
        .unwrap();
    for fault in [
        prove::Fault::AfterTrace,
        prove::Fault::AfterPermutation,
        prove::Fault::AfterQuotient,
        prove::Fault::PanicAfterQuotient,
        prove::Fault::AfterPcs,
    ] {
        let caps = prepared.proof_capabilities();
        let stages: Vec<_> = caps.stages().iter().map(|c| c.stage).collect();
        let parent = Run::request(
            "registered_component_failure",
            request(),
            capabilities(CoverageScope::ProofRequest, &stages),
            &[("proof", CoverageScope::RegisteredProof)],
        )
        .unwrap();
        let child = parent.child("proof", "registered_proof", caps).unwrap();
        let before = runtime.snapshot();
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            prepared.prove_attempt(input(true), child, HOST, fault)
        }));
        assert!(outcome.is_err() || outcome.unwrap().is_err());
        let report = parent.finish(false).unwrap();
        assert!(!report.components[0].succeeded && !report.components[0].stage_coverage_complete);
        assert_eq!(runtime.snapshot().live_bytes, before.live_bytes);
        assert_eq!(runtime.snapshot().allocations, before.allocations);
        assert_eq!(&prepared.preprocessing_cap().unwrap(), cap);
        let fresh = prepared.prove(input(true), request(), HOST).unwrap();
        verify_batch(
            &cpu,
            &[air.clone()],
            &fresh.proof,
            &[vec![Val::from_u64(10)]],
            &data.common,
        )
        .unwrap();
    }
}

#[test]
#[ignore = "requires CUDA; serial bounded service"]
fn cuda_registered_cached_provenance_never_fabricates_fresh_work_or_bypasses_runtime_failure() {
    let runtime = runtime();
    let engine = Arc::new(BatchStarks::new(&runtime).unwrap());
    let air = air(7, true);
    let cpu = super::super::tests::cpu();
    let data = ProverData::from_airs_and_degrees(&cpu, &[air.clone()], &[5]);
    let cap = &data.common.preprocessed.as_ref().unwrap().commitment;
    let (prepared, _) = engine
        .prepare_registered(
            &air,
            key(&air, cap.roots()),
            request(),
            HOST,
            Specialization::Generic,
        )
        .unwrap();
    let parent = || {
        Run::request(
            "cached_preprocessing",
            request(),
            capabilities(CoverageScope::ProofRequest, &PREPROCESSING),
            &[("preprocessing", CoverageScope::Preprocessing)],
        )
        .unwrap()
    };
    let run = parent();
    let before = runtime.snapshot();
    prepared.reuse_preprocessing(&run).unwrap();
    assert_eq!(runtime.snapshot(), before);
    let report = run.finish(false).unwrap();
    assert!(report.observations.is_empty());
    assert!(
        report.components[0].cached
            && report.components[0].succeeded
            && report.components[0].stage_coverage_complete
    );
    let incomplete = parent();
    prepared.reuse_preprocessing(&incomplete).unwrap();
    assert!(incomplete.finish(true).is_err());
    let dead = parent();
    runtime.state.fail();
    assert!(prepared.reuse_preprocessing(&dead).is_err());
    assert!(prepared.prove(input(true), request(), HOST).is_err());
    assert!(prepared.preprocessing_cap().is_err());
    let report = dead.finish(false).unwrap();
    assert!(!report.components[0].started);
}
