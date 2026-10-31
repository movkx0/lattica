//! Component screening on two real recursive verifier programs. The child
//! fixtures are prepared outside the timer; this is not RingCT throughput.
use lattica_prover_p3::{
    block_v2::{
        gpu_hash,
        machine::{
            backend::{
                identity_batch::{IdentityBatchContext, IdentityBatchLimits},
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
const REQUEST: Request = Request {
    policy: Policy::GpuRequired,
    emit_report: false,
};
struct Fixture {
    program: Arc<Program>,
    public: Vec<Val>,
    witness: Vec<Val>,
}

fn initialize() {
    let fusion = quotient_pcs::initialize_research_from_env().unwrap();
    quotient_pcs::initialize_gpu_quotient_from_env(true, fusion).unwrap();
    gpu_hash::initialize_from_env().unwrap();
    assert!(gpu_hash::initialize_resident_from_env().unwrap());
}

fn fixtures() -> Vec<Fixture> {
    let mut fixtures = Vec::new();
    for index in 0..2 {
        initialize();
        let mut child = ScopedProgramBuilder::new(1).unwrap();
        let public = child.public(0).unwrap();
        let witness = child.input();
        let constant = child.constant(Val::from_u64(3 + index));
        let value = child.add(witness, constant);
        child.assert_equal(public, value);
        // Match the native SHAKE segment height used by the full workflow.
        // This child is a machine STARK, not a SHAKE or RingCT transaction.
        let child = RegisteredProgram::new_with_request(
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
        // Explicit source compiler/input limits; enclosing two fixtures plus
        // an 8 GiB backend fit inside the existing 32 GiB worker allowance.
        let mut builder = ScopedProgramBuilder::new_with_construction_limits(1, limits).unwrap();
        let outer_public = [builder.public(0).unwrap()];
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
        fixtures.push(Fixture {
            program,
            public: public.to_vec(),
            witness: inputs.values,
        });
        drop(child);
        gpu_hash::shutdown().unwrap();
    }
    fixtures
}

#[derive(serde::Serialize)]
struct Measurement {
    schema: &'static str,
    scope: &'static str,
    repetition: usize,
    schedule: &'static str,
    programs: usize,
    fresh_recursive_proofs: usize,
    active_rows: usize,
    padded_rows: usize,
    prefix_analysis_ns: u128,
    prefix_hash_ns: u128,
    prefix_device_ns: u128,
    setup_ns: u128,
    proving_ns: u128,
    cpu_verification_ns: u128,
    component_ns: u128,
    identities: Vec<[u64; 4]>,
}

fn measure(fixtures: &[Fixture], repetition: usize, batched: bool) -> Measurement {
    let started = Instant::now();
    let context = IdentityBatchContext::new();
    let mut tokens = Vec::new();
    let mut result = Measurement {
        schema: "recursive-identity-component-screen-v1",
        scope: "component-only; child fixture generation excluded; no RingCT throughput claim",
        repetition,
        schedule: if batched { "batched-v1" } else { "serial" },
        programs: fixtures.len(),
        fresh_recursive_proofs: 0,
        active_rows: 0,
        padded_rows: 0,
        prefix_analysis_ns: 0,
        prefix_hash_ns: 0,
        prefix_device_ns: 0,
        setup_ns: 0,
        proving_ns: 0,
        cpu_verification_ns: 0,
        component_ns: 0,
        identities: Vec::new(),
    };
    if batched {
        initialize();
        let plan = context
            .plan(
                IdentityBatchLimits::batched(2).unwrap(),
                fixtures
                    .iter()
                    .enumerate()
                    .map(|(job, fixture)| (job as u64, Arc::clone(&fixture.program)))
                    .collect(),
                HOST,
                8 << 30,
            )
            .unwrap();
        let pending = plan.execute(REQUEST).unwrap();
        gpu_hash::shutdown().unwrap();
        let (completed, report) = pending.complete_after_retirement().unwrap();
        result.prefix_analysis_ns = report.analysis_ns;
        result.prefix_hash_ns = report.hash_wall_ns;
        result.prefix_device_ns = report.device_ns;
        tokens = completed;
    }
    for (job, fixture) in fixtures.iter().enumerate() {
        initialize();
        let setup = Instant::now();
        let air = MachineAir::from_shared_program(Arc::clone(&fixture.program));
        let registered = if batched {
            RegisteredProgram::new_with_identity_prefix_and_report(
                air,
                HOST,
                REQUEST,
                &context,
                job as u64,
                tokens.remove(0),
            )
            .unwrap()
            .0
        } else {
            RegisteredProgram::new_with_request(air, HOST, REQUEST).unwrap()
        };
        result.setup_ns += setup.elapsed().as_nanos();
        result.identities.push(registered.id());
        result.active_rows += fixture.program.active_rows();
        result.padded_rows += fixture.program.height();
        let proving = Instant::now();
        let proof = registered
            .prove_with_request(&fixture.public, &fixture.witness, REQUEST)
            .unwrap();
        result.proving_ns += proving.elapsed().as_nanos();
        let verification = Instant::now();
        registered
            .verifier()
            .verify(&proof, &fixture.public)
            .unwrap();
        let mut changed = fixture.public.clone();
        changed[0] += Val::ONE;
        assert!(registered.verifier().verify(&proof, &changed).is_err());
        result.cpu_verification_ns += verification.elapsed().as_nanos();
        result.fresh_recursive_proofs += 1;
        drop(registered);
        // Preserve actual kernel selection evidence before retiring the epoch.
        println!(
            "PUBLIC_HASH_EXECUTION {}",
            serde_json::to_string(&gpu_hash::public_hash_execution().unwrap().unwrap()).unwrap()
        );
        gpu_hash::shutdown().unwrap();
    }
    assert!(tokens.is_empty());
    result.component_ns = started.elapsed().as_nanos();
    result
}

#[test]
#[ignore = "serialized guarded GPU component screen; includes three alternating comparisons"]
fn gpu_recursive_identity_preprocessing_component_screen() {
    let fixtures = fixtures();
    let mut identity = None;
    for repetition in 0..3 {
        for batched in if repetition % 2 == 0 {
            [false, true]
        } else {
            [true, false]
        } {
            let measured = measure(&fixtures, repetition, batched);
            if let Some(expected) = &identity {
                assert_eq!(&measured.identities, expected);
            } else {
                identity = Some(measured.identities.clone());
            }
            println!(
                "IDENTITY_COMPONENT_SCREEN {}",
                serde_json::to_string(&measured).unwrap()
            );
        }
    }
}
