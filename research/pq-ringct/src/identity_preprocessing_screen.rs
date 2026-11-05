//! Component screening on real recursive verifier programs. The child fixtures
//! are prepared outside the timer; these screens are not RingCT throughput.
use lattica_prover_p3::{
    block_v2::{
        gpu_hash,
        machine::{
            backend::{
                identity_cpu::{IdentityCpuContext, IdentityCpuOptions},
                RegisteredProgram,
            },
            program::{ConstructionLimits, ProofInputs, ScopedProgramBuilder, Val},
            verifier, MachineAir, Program,
        },
        quotient_pcs,
    },
    proving::{Policy, Request},
};
use p3_field::PrimeCharacteristicRing;
use std::{sync::Arc, time::Instant};

const HOST: u64 = 8 << 30;
// Leave the other half of the unchanged 32 GiB worker allowance for the
// backend, compiler helpers and enclosing state. Check before each new fixture.
const FIXTURE_POOL_HOST: u64 = 16 << 30;
const REQUEST: Request = Request {
    policy: Policy::GpuRequired,
    emit_report: false,
};
struct Fixture {
    program: Arc<Program>,
    public: Vec<Val>,
    witness: Vec<Val>,
    gpu_reference_identity: Option<[u64; 4]>,
}

fn fixture_host_bytes(fixture: &Fixture) -> u64 {
    let vectors = fixture
        .public
        .capacity()
        .checked_add(fixture.witness.capacity())
        .unwrap()
        .checked_mul(core::mem::size_of::<Val>())
        .unwrap();
    (fixture.program.retained_host_bytes().unwrap() as u64)
        .checked_add(vectors as u64)
        .unwrap()
        .checked_add(4096)
        .unwrap()
}

fn initialize() {
    let fusion = quotient_pcs::initialize_research_from_env().unwrap();
    quotient_pcs::initialize_gpu_quotient_from_env(true, fusion).unwrap();
    gpu_hash::initialize_from_env().unwrap();
    assert!(gpu_hash::initialize_resident_from_env().unwrap());
}

fn fixtures(count: usize) -> Vec<Fixture> {
    fixtures_with_public_values(count, 1)
}

fn fixtures_with_public_values(count: usize, public_values: usize) -> Vec<Fixture> {
    assert!(matches!(count, 5 | 9 | 17 | 25));
    assert!(matches!(public_values, 1 | 46));
    let mut fixtures = Vec::with_capacity(count);
    let mut retained_host = (fixtures.capacity() * core::mem::size_of::<Fixture>()) as u64;
    // Includes the next program's full compiler allowance, bounded input backing
    // and ownership frames. Refuse before creating that fixture if it cannot fit.
    let next_fixture = (2u64 << 30) + ((2u64 << 20) * core::mem::size_of::<Val>() as u64) + 4096;
    // The wide screens cover full cohorts and partial final cohorts.
    for index in 0..count as u64 {
        assert!(retained_host.checked_add(next_fixture).unwrap() <= FIXTURE_POOL_HOST);
        initialize();
        let mut child = ScopedProgramBuilder::new(1).unwrap();
        let public = child.public(0).unwrap();
        let witness = child.input();
        let constant = child.constant(Val::from_u64(3 + index));
        let value = child.add(witness, constant);
        child.assert_equal(public, value);
        // Match the native SHAKE segment height used by the full workflow.
        // This child is a machine STARK, not a SHAKE or RingCT transaction.
        let child = RegisteredProgram::new_with_cpu_identity(
            MachineAir::new(child.finish(Some(1 << 16)).unwrap()),
            HOST,
            REQUEST,
        )
        .unwrap();
        let public = [Val::from_u64(12 + index)];
        let proof = child
            .prove_with_request(&public, &[Val::from_u64(9)], REQUEST)
            .unwrap();
        child.verifier().verify(&proof, &public).unwrap();
        let limits = ConstructionLimits {
            max_requested_program_bytes: 2 << 30,
            max_wires: 1 << 26,
            max_input_values: 1 << 20,
        };
        // Each compiler is bounded independently; the enclosing retained fixture
        // pool is checked above without increasing the worker or backend limits.
        let mut builder =
            ScopedProgramBuilder::new_with_construction_limits(public_values, limits).unwrap();
        let outer_public = [builder.public(0).unwrap()];
        let mut public = public.to_vec();
        for i in 1..public_values {
            let value = Val::from_u64(100 + index + i as u64);
            let wire = builder.public(i).unwrap();
            let constant = builder.constant(value);
            builder.assert_equal(wire, constant);
            public.push(value);
        }
        let cap: Vec<_> = child
            .preprocessing_cap()
            .roots()
            .iter()
            .map(|root| root.map(|value| builder.constant(value)))
            .collect();
        let mut inputs = ProofInputs::default();
        verifier::batch::verify_with_bounded_cpu_symbolic(
            &mut builder,
            &mut inputs,
            child.air(),
            &outer_public,
            &cap,
            &proof,
        )
        .unwrap();
        let program = Arc::new(builder.finish(None).unwrap());
        assert!(program.height() <= 1 << 20 && program.retained_host_bytes().unwrap() <= 2 << 30);
        assert!(inputs.values.len() <= 1 << 20);
        // Test-only independent GPU oracle for an actual recursive verifier
        // program. It is outside every CPU scheduling measurement.
        let gpu_reference_identity = if index == 0 {
            let reference = RegisteredProgram::new_with_request(
                MachineAir::from_shared_program(Arc::clone(&program)),
                HOST,
                REQUEST,
            )
            .unwrap();
            Some(reference.id())
        } else {
            None
        };
        let fixture = Fixture {
            program,
            public,
            witness: inputs.values,
            gpu_reference_identity,
        };
        retained_host = retained_host
            .checked_add(fixture_host_bytes(&fixture))
            .unwrap();
        assert!(retained_host <= FIXTURE_POOL_HOST);
        fixtures.push(fixture);
        drop(child);
        gpu_hash::shutdown().unwrap();
    }
    fixtures
}

#[test]
#[ignore = "guarded CPU identity qualification with GPU preprocessing and fresh proofs"]
fn cpu_recursive_identity_worker_qualification() {
    let fixtures = fixtures(17);
    let context = IdentityCpuContext::new();
    let mut baseline = Vec::new();
    for width in [1, 2, 4, 8, 16] {
        let options = IdentityCpuOptions::workers(width).unwrap();
        assert_eq!(
            options.max_streams(),
            width,
            "qualification requires the requested physical cores"
        );
        let started = Instant::now();
        let mut reports = Vec::new();
        let mut identities = Vec::new();
        let mut verified = 0;
        for (cohort, group) in fixtures.chunks(width).enumerate() {
            initialize();
            let programs = group
                .iter()
                .enumerate()
                .map(|(i, f)| ((cohort * width + i) as u64, &f.program))
                .collect();
            let pending = context
                .plan_borrowed(options, programs, HOST, 0)
                .unwrap()
                .execute(REQUEST)
                .unwrap();
            gpu_hash::shutdown().unwrap();
            let (tokens, report) = pending.complete_after_retirement().unwrap();
            assert_eq!(report.effective_workers, group.len());
            if group.len() == width && width > 1 {
                assert_eq!(report.peak_active_workers, width);
            }
            for (fixture, token) in group.iter().zip(tokens) {
                initialize();
                let (registered, coverage) =
                    RegisteredProgram::new_with_cpu_identity_prefix_and_report(
                        MachineAir::from_shared_program(Arc::clone(&fixture.program)),
                        HOST,
                        REQUEST,
                        &context,
                        token.job(),
                        token,
                    )
                    .unwrap();
                assert_eq!(coverage.identity.policy, Policy::CpuRequired);
                assert_eq!(coverage.preprocessing.policy, Policy::GpuRequired);
                assert!(registered.identity_receipt().is_none());
                identities.push(registered.id());
                if let Some(reference) = fixture.gpu_reference_identity {
                    assert_eq!(
                        registered.id(),
                        reference,
                        "actual recursive GPU identity oracle"
                    );
                }
                if width == 16 && verified < 2 {
                    let proof = registered
                        .prove_with_request(&fixture.public, &fixture.witness, REQUEST)
                        .unwrap();
                    registered
                        .verifier()
                        .verify(&proof, &fixture.public)
                        .unwrap();
                    verified += 1;
                }
                drop(registered);
                gpu_hash::shutdown().unwrap();
            }
            reports.push(report);
        }
        if width == 1 {
            baseline = identities.clone();
        } else {
            assert_eq!(identities, baseline);
        }
        // Every width divides 16: measure the same sixteen-job full prefix
        // separately from the final one-job tail, using hash time only.
        let full_batches_hash_ns: u128 = reports[..reports.len() - 1]
            .iter()
            .map(|r| r.hash_wall_ns)
            .sum();
        let tail_hash_ns = reports.last().unwrap().hash_wall_ns;
        println!(
            "CPU_IDENTITY_QUALIFICATION {}",
            serde_json::json!({
                "schema": "ringct-cpu-identity-qualification-v2", "workers": width, "programs": fixtures.len(),
                "scope": "actual recursive metadata component, not whole RingCT workflow",
                "gpu_reference_programs": 1, "component_ns": started.elapsed().as_nanos(), "independent_cpu_verified_proofs": verified,
                "reports": reports, "identities": identities,
                "full_programs": 16, "tail_programs": 1,
                "full_batches_hash_ns": full_batches_hash_ns, "tail_hash_ns": tail_hash_ns,
                "total_hash_ns": full_batches_hash_ns + tail_hash_ns,
            })
        );
    }
}

#[test]
#[ignore = "guarded detailed serial CPU identity clocks on actual recursive verifier programs"]
fn cpu_recursive_serial_identity_diagnostic() {
    assert_eq!(
        std::env::var("LATTICA_RINGCT_FULL_WORKFLOW_PROFILE").as_deref(),
        Ok("detail"),
        "build with lattica-prover-p3/gpu-tuning and select detail profiling"
    );
    // Crypto outer programs expose 46 public fields. Keep the existing worker
    // screen's one-public fixtures unchanged; this diagnostic also exercises
    // the quotient shape observed in the complete workflow's crypto outers.
    let fixtures = fixtures_with_public_values(5, 46);
    for (index, fixture) in fixtures.iter().enumerate() {
        initialize();
        eprintln!("SERIAL_IDENTITY_BEGIN {index}");
        let started = Instant::now();
        let (registered, registration_reports) =
            RegisteredProgram::new_with_cpu_identity_and_report(
                MachineAir::from_shared_program(Arc::clone(&fixture.program)),
                HOST,
                REQUEST,
            )
            .unwrap();
        let registration_ns = started.elapsed().as_nanos();
        eprintln!("SERIAL_IDENTITY_END {index}");
        assert_eq!(registration_reports.identity.policy, Policy::CpuRequired);
        assert_eq!(
            registration_reports.preprocessing.policy,
            Policy::GpuRequired
        );
        assert!(registration_reports
            .identity
            .observations
            .iter()
            .all(|observation| {
                observation.backend == lattica_prover_p3::proving::Backend::Cpu
                    && observation.device_calls == 0
            }));
        if let Some(reference) = fixture.gpu_reference_identity {
            assert_eq!(
                registered.id(),
                reference,
                "independent GPU identity oracle"
            );
        }
        let verified = index < 2;
        let mut proof_wall_ns = None;
        let mut verification_ns = None;
        let mut proof_report = None;
        if verified {
            let started = Instant::now();
            let (proof, report) = registered
                .prove_with_request_and_report(&fixture.public, &fixture.witness, REQUEST)
                .unwrap();
            proof_wall_ns = Some(started.elapsed().as_nanos());
            assert_eq!(report.policy, Policy::GpuRequired);
            assert!(report.succeeded && report.stage_coverage_complete);
            assert!(!report.completion_rejected);
            assert_eq!(report.observation_errors, 0);
            let started = Instant::now();
            registered
                .verifier()
                .verify(&proof, &fixture.public)
                .unwrap();
            let mut changed_public = fixture.public.clone();
            changed_public[0] += Val::ONE;
            assert!(registered
                .verifier()
                .verify(&proof, &changed_public)
                .is_err());
            verification_ns = Some(started.elapsed().as_nanos());
            proof_report = Some(report);
        }
        eprintln!(
            "SERIAL_IDENTITY_DIAGNOSTIC {}",
            serde_json::json!({
                "schema": "ringct-serial-cpu-identity-diagnostic-v1",
                "scope": "actual recursive metadata component, not whole RingCT workflow",
                "program": index,
                "height": fixture.program.height(),
                "public_values": fixture.public.len(),
                "registration_ns": registration_ns,
                "cpu_identity_ns": registration_reports.identity.elapsed_ns,
                "gpu_preprocessing_ns": registration_reports.preprocessing.elapsed_ns,
                "identity": registered.id(),
                "gpu_reference_checked": fixture.gpu_reference_identity.is_some(),
                "independent_cpu_verified_proof": verified,
                "changed_public_rejected": verified,
                "proof_wall_ns": proof_wall_ns,
                "verification_ns": verification_ns,
                "proof_report": proof_report,
                "complete_workflow": false,
            })
        );
        drop(registered);
        gpu_hash::shutdown().unwrap();
    }
    eprintln!("SERIAL_IDENTITY_COMPLETE programs=5 gpu_oracles=1 verified=2 mutations_rejected=2 complete_workflow=false");
}
