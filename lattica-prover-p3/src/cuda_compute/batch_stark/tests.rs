use super::*;
use crate::{
    block_v2::machine::ProgramBuilder,
    config::{Challenger, Dft},
    cuda_compute::Limits,
};
use p3_batch_stark::{verify_batch, ProverData};
use p3_commit::ExtensionMmcs;
use p3_fri::HidingFriPcs;

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
fn rng(seed: u8) -> ChaCha20Rng {
    ChaCha20Rng::from_seed([seed; 32])
}
fn cpu() -> super::super::NativeStarkConfig<Challenge> {
    let permutation = p3_goldilocks::default_goldilocks_poseidon2_8();
    let mmcs = ValMmcs::new(
        crate::config::MyHash::new(permutation.clone()),
        crate::config::MyCompress::new(permutation.clone()),
        profile::CAP_HEIGHT,
        rng(0),
    );
    super::super::NativeStarkConfig::new(
        HidingFriPcs::new(
            Dft::default(),
            mmcs.clone(),
            profile::fri(ExtensionMmcs::new(mmcs)),
            crate::config::NUM_RANDOM_CODEWORDS,
            rng(31),
        ),
        Challenger::new(permutation),
    )
}
fn air(log: u32, publics: bool) -> MachineAir {
    let mut b = ProgramBuilder::new(usize::from(publics)).unwrap();
    let a = b.input();
    let c = b.input();
    let product = b.mul(a, c);
    let inverse = b.inverse(product);
    let identity = b.mul(product, inverse);
    let one = b.constant(Val::ONE);
    b.assert_equal(identity, one);
    if publics {
        b.assert_equal(product, b.public(0).unwrap());
    }
    b.poseidon([a, c, product, inverse, one, a, c, product]);
    MachineAir::new(b.finish(Some(1 << log)).unwrap())
}
fn randoms(engine: &BatchStarks, seed: u8) -> [super::super::DeviceRandom; 3] {
    std::array::from_fn(|i| engine.randoms.import(rng(seed + i as u8)).unwrap())
}
fn random(streams: &[super::super::DeviceRandom; 3]) -> StarkRandomness<'_> {
    StarkRandomness {
        masks: &streams[0],
        commitments: &streams[1],
        fri: &streams[2],
    }
}
fn clone_proof(proof: &NativeBatchProof) -> NativeBatchProof {
    postcard::from_bytes(&postcard::to_allocvec(proof).unwrap()).unwrap()
}

fn prove_case(logs: &[u32], publics: bool) {
    let runtime = runtime();
    let engine = BatchStarks::new(&runtime).unwrap();
    let airs: Vec<_> = logs.iter().map(|&log| air(log, publics)).collect();
    let refs: Vec<_> = airs.iter().collect();
    let baseline = runtime.snapshot();
    let prepared = engine
        .prepare(&refs, 1 << 30, Specialization::Prefer)
        .unwrap();
    let cpu = cpu();
    let degree: Vec<_> = logs.iter().map(|&log| log as usize + 1).collect();
    // CPU rebuilds both deterministic preprocessing and its salted commitment
    // from the immutable programs; it never trusts GPU-produced common data.
    let data = ProverData::from_airs_and_degrees(&cpu, &airs, &degree);
    assert_eq!(
        prepared.preprocessing_cap().unwrap(),
        data.common.preprocessed.as_ref().unwrap().commitment
    );
    let public: &[u64] = if publics { &[12] } else { &[] };
    let inputs = vec![
        MachineInputs {
            public,
            witness: &[3, 4]
        };
        logs.len()
    ];
    let pv = vec![
        public
            .iter()
            .copied()
            .map(Val::from_u64)
            .collect::<Vec<_>>();
        logs.len()
    ];
    let before = runtime.snapshot();
    let mut encoded = Vec::new();
    for seed in [41, 51] {
        let streams = randoms(&engine, seed);
        let proof = engine
            .prove(&prepared, &inputs, random(&streams), 64 << 20)
            .unwrap();
        verify_batch(&cpu, &airs, &proof, &pv, &data.common).unwrap();
        assert_eq!(proof.degree_bits, degree);
        assert!(proof
            .lookup_terminals
            .iter()
            .all(|t| t.as_ref().unwrap().0 == Challenge::ZERO));
        let bytes = postcard::to_allocvec(&proof).unwrap();
        if !encoded.is_empty() {
            assert_ne!(encoded, bytes);
        }
        encoded = bytes;
        let decoded: NativeBatchProof = postcard::from_bytes(&encoded).unwrap();
        verify_batch(&cpu, &airs, &decoded, &pv, &data.common).unwrap();
        if logs.len() == 1 {
            // The application's existing registered verifier accepts the same
            // wire artifact with an independently CPU-authenticated program cap.
            let verifier = crate::block_v2::machine::backend::RegisteredVerifier::from_trusted_cap(
                public.len(),
                1 << logs[0],
                data.common
                    .preprocessed
                    .as_ref()
                    .unwrap()
                    .commitment
                    .clone(),
            )
            .unwrap();
            let production: p3_batch_stark::BatchProof<profile::Config> =
                postcard::from_bytes(&encoded).unwrap();
            let before_verify = runtime.snapshot();
            verifier.verify(&production, &pv[0]).unwrap();
            assert_eq!(runtime.snapshot(), before_verify);
        }
        let mut bad = clone_proof(&proof);
        bad.lookup_terminals[0].as_mut().unwrap().0 += Challenge::ONE;
        assert!(verify_batch(&cpu, &airs, &bad, &pv, &data.common).is_err());
        let mut bad = clone_proof(&proof);
        bad.opened_values.instances[0].permutation_local[0] += Challenge::ONE;
        assert!(verify_batch(&cpu, &airs, &bad, &pv, &data.common).is_err());
        let mut bad = clone_proof(&proof);
        bad.opened_values.instances[0]
            .base_opened_values
            .preprocessed_local
            .as_mut()
            .unwrap()[0] += Challenge::ONE;
        assert!(verify_batch(&cpu, &airs, &bad, &pv, &data.common).is_err());
        if publics {
            let mut wrong = pv.clone();
            wrong[0][0] += Val::ONE;
            assert!(verify_batch(&cpu, &airs, &proof, &wrong, &data.common).is_err());
        }
        if logs.len() > 1 {
            let mut bad = clone_proof(&proof);
            bad.opened_values.instances.swap(0, 1);
            assert!(verify_batch(&cpu, &airs, &bad, &pv, &data.common).is_err());
        }
        for stream in &streams {
            assert!(stream.check_live().is_ok());
        }
        drop(streams);
        assert_eq!(runtime.snapshot().live_bytes, before.live_bytes);
        assert_eq!(runtime.snapshot().allocations, before.allocations);
    }
    drop(prepared);
    assert_eq!(runtime.snapshot().live_bytes, baseline.live_bytes);
    assert_eq!(
        runtime.snapshot().public_program_bytes,
        baseline.public_program_bytes
    );
}

#[test]
#[ignore = "requires CUDA; serial bounded service"]
fn cuda_machine_batch_single_production_proof_matches_cpu_verifier() {
    prove_case(&[4], true);
}

#[test]
#[ignore = "requires CUDA; serial bounded service"]
fn cuda_machine_batch_mixed_heights_match_cpu_verifier() {
    prove_case(&[5, 4, 6], true);
}

#[test]
#[ignore = "requires CUDA; serial bounded service"]
fn cuda_machine_batch_without_public_inputs_matches_cpu_verifier() {
    prove_case(&[4], false);
}

#[test]
#[ignore = "requires CUDA; serial bounded service"]
fn cuda_machine_batch_rejects_inputs_before_private_work() {
    let runtime = runtime();
    let engine = BatchStarks::new(&runtime).unwrap();
    let air = air(4, true);
    let before = runtime.snapshot();
    assert!(engine
        .prepare(&[], 1 << 30, Specialization::Generic)
        .is_err());
    assert!(engine.prepare(&[&air], 1, Specialization::Generic).is_err());
    assert!(engine
        .prepare(&[&air; 9], 1 << 30, Specialization::Generic)
        .is_err());
    assert_eq!(runtime.snapshot(), before);
    let prepared = engine
        .prepare(&[&air], 1 << 30, Specialization::Generic)
        .unwrap();
    let streams = randoms(&engine, 41);
    let before = runtime.snapshot();
    for inputs in [
        vec![],
        vec![MachineInputs {
            public: &[12],
            witness: &[3],
        }],
        vec![MachineInputs {
            public: &[u64::MAX],
            witness: &[3, 4],
        }],
    ] {
        assert!(engine
            .prove(&prepared, &inputs, random(&streams), 64 << 20)
            .is_err());
        assert_eq!(runtime.snapshot(), before);
    }
    let input = [MachineInputs {
        public: &[12],
        witness: &[3, 4],
    }];
    assert!(engine
        .prove(&prepared, &input, random(&streams), 1)
        .is_err());
    assert_eq!(runtime.snapshot(), before);
    for stream in &streams {
        assert!(stream.check_live().is_ok());
    }
    assert!(prepared.preprocessing_cap().is_ok());
}

#[test]
#[ignore = "requires CUDA; serial bounded service"]
fn cuda_machine_batch_failures_retire_all_families_and_allow_fresh_retry() {
    let runtime = runtime();
    let engine = BatchStarks::new(&runtime).unwrap();
    let air = air(4, true);
    let input = [MachineInputs {
        public: &[12],
        witness: &[3, 4],
    }];
    for fault in [
        prove::Fault::None,
        prove::Fault::AfterTrace,
        prove::Fault::AfterPermutation,
        prove::Fault::AfterQuotient,
        prove::Fault::PanicAfterQuotient,
        prove::Fault::AfterPcs,
    ] {
        let prepared = engine
            .prepare(&[&air], 1 << 30, Specialization::Generic)
            .unwrap();
        let streams = randoms(&engine, 41);
        let before = runtime.snapshot();
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let attempt_input = if matches!(fault, prove::Fault::None) {
                [MachineInputs {
                    public: &[13],
                    witness: &[3, 4],
                }]
            } else {
                input
            };
            engine.prove_impl(&prepared, &attempt_input, random(&streams), 64 << 20, fault)
        }));
        assert!(outcome.is_err() || outcome.unwrap().is_err());
        for stream in &streams {
            assert!(stream.check_live().is_err());
        }
        assert!(prepared.preprocessing_cap().is_err());
        assert_eq!(runtime.snapshot().live_bytes, before.live_bytes);
        assert_eq!(runtime.snapshot().allocations, before.allocations);
        let before = runtime.snapshot();
        assert!(engine
            .prove(&prepared, &input, random(&streams), 64 << 20)
            .is_err());
        assert_eq!(runtime.snapshot(), before);
    }
    let prepared = engine
        .prepare(&[&air], 1 << 30, Specialization::Generic)
        .unwrap();
    let streams = randoms(&engine, 51);
    let proof = engine
        .prove(&prepared, &input, random(&streams), 64 << 20)
        .unwrap();
    let cpu = cpu();
    let data = ProverData::from_airs_and_degrees(&cpu, &[air.clone()], &[5]);
    verify_batch(
        &cpu,
        &[air],
        &proof,
        &[vec![Val::from_u64(12)]],
        &data.common,
    )
    .unwrap();
}

#[test]
#[ignore = "requires CUDA; serial bounded service"]
fn cuda_machine_batch_records_all_sixteen_arithmetic_stages() {
    use crate::proving::{
        Backend, Capabilities, CoverageScope, Policy, Profile, Request, Run, Stage,
    };
    let runtime = runtime();
    let engine = BatchStarks::new(&runtime).unwrap();
    let air = air(5, true);
    let mut capabilities = Capabilities::cpu(Profile::BlockV2Cubic, true, true)
        .scoped(CoverageScope::Operation, &Stage::ARITHMETIC);
    for stage in Stage::ARITHMETIC {
        capabilities.set(stage, Backend::Cuda);
    }
    let run = Run::new(
        "cuda_machine_batch",
        Request {
            policy: Policy::GpuRequired,
            emit_report: false,
        },
        capabilities,
    )
    .unwrap();
    let calls = crate::proving::cpu_witness_oracle_calls();
    let proof = runtime
        .reported(&run, || {
            let prepared = engine.prepare(&[&air], 1 << 30, Specialization::Prefer)?;
            let streams = randoms(&engine, 41);
            engine.prove(
                &prepared,
                &[MachineInputs {
                    public: &[12],
                    witness: &[3, 4],
                }],
                random(&streams),
                64 << 20,
            )
        })
        .unwrap();
    assert_eq!(crate::proving::cpu_witness_oracle_calls(), calls);
    let report = run.finish(true).unwrap();
    assert!(report.stage_coverage_complete, "{report:?}");
    eprintln!(
        "cuda_machine_batch_stage_receipts {}",
        serde_json::to_string(&report).unwrap()
    );
    let cpu = cpu();
    let data = ProverData::from_airs_and_degrees(&cpu, &[air.clone()], &[6]);
    let before = runtime.snapshot();
    verify_batch(
        &cpu,
        &[air],
        &proof,
        &[vec![Val::from_u64(12)]],
        &data.common,
    )
    .unwrap();
    assert_eq!(
        runtime.snapshot(),
        before,
        "independent verifier must not execute CUDA"
    );
}

#[test]
#[ignore = "requires CUDA; serial bounded service"]
fn cuda_committed_batch_quotient_admits_all_prefixes_and_retires_every_family() {
    let runtime = runtime();
    let engine = BatchStarks::new(&runtime).unwrap();
    let air = air(4, true);
    let prepared = engine
        .prepare(&[&air], 1 << 30, Specialization::Generic)
        .unwrap();
    let i = &prepared.instances[0];
    let execution = engine
        .witnesses
        .generate(&i.witness, &[12], &[3, 4], 1 << 20)
        .unwrap();
    let main_random = randoms(&engine, 41);
    let perm_random = randoms(&engine, 51);
    let challenge = runtime
        .allocate(i.layout.num_permutation_challenges * 3)
        .unwrap();
    challenge.write(0, &vec![7; challenge.len()]).unwrap();
    let lookup = engine
        .lookups
        .generate(
            &i.lookup,
            &execution.trace,
            Some(i.preprocessing.matrix()),
            execution.public.as_ref(),
            &challenge,
            Extension::Cubic,
        )
        .unwrap();
    let commit = |trace, streams: &[super::super::DeviceRandom; 3]| {
        let trace = engine
            .hiding
            .prepare_trace(trace, &streams[0], i.log_lde(parameters()), 16)
            .unwrap();
        engine
            .hiding
            .commit_batch(
                &engine.commitments,
                &[HidingInput::Trace(&trace)],
                &streams[1],
                parameters().cap_height,
            )
            .unwrap()
    };
    let main = commit(&execution.trace, &main_random);
    let perm = commit(&lookup.trace, &perm_random);
    let make = |commitment, columns, extension| {
        Some(CommittedMatrix {
            commitment,
            index: 0,
            columns,
            extension,
        })
    };
    let inputs = [
        make(&main, i.layout.main_width, Extension::Base),
        make(
            &prepared.preprocessing,
            i.layout.preprocessed_width,
            Extension::Base,
        ),
        make(&perm, i.layout.permutation_width, Extension::Cubic),
    ];
    let alpha = runtime.allocate(3).unwrap();
    alpha.write(0, &[7, 11, 13]).unwrap();
    let evaluate = |inputs, log| {
        engine.hiding.evaluate_committed_quotient(
            &engine.quotients,
            &i.quotient,
            inputs,
            i.log_rows,
            log,
            &alpha,
            None,
        )
    };
    let before = runtime.snapshot();
    for index in 0..3 {
        let mut bad = inputs;
        bad[index].as_mut().unwrap().columns += 1;
        assert!(evaluate(bad, 9).is_err());
        assert_eq!(runtime.snapshot(), before);
        let mut bad = inputs;
        bad[index].as_mut().unwrap().index = 1;
        assert!(evaluate(bad, 9).is_err());
        assert_eq!(runtime.snapshot(), before);
    }
    let mut bad = inputs;
    bad[2].as_mut().unwrap().extension = Extension::Base;
    assert!(evaluate(bad, 9).is_err());
    assert_eq!(runtime.snapshot(), before);
    // Leave enough room for the largest individual extraction, but not their
    // aggregate. Rejection must precede allocations, kernels or family mutation.
    let sizes: Vec<_> = inputs
        .iter()
        .flatten()
        .map(|input| {
            let shape = input.commitment.opening_shape(0).unwrap();
            shape.prefix.rows() * input.columns * input.extension.degree() * 8
        })
        .collect();
    let remaining = *sizes.iter().max().unwrap() + 8;
    assert!(remaining < sizes.iter().sum());
    let mut pressure = Vec::new();
    loop {
        let excess =
            runtime.state.budget.limits.managed_bytes - runtime.snapshot().live_bytes - remaining;
        if excess == 0 {
            break;
        }
        pressure.push(runtime.allocate(excess.min(64 << 20) / 8).unwrap());
    }
    let pressured = runtime.snapshot();
    assert!(evaluate(inputs, 9).is_err());
    assert_eq!(runtime.snapshot(), pressured);
    drop(pressure);
    for stream in main_random.iter().chain(&perm_random) {
        assert!(stream.check_live().is_ok());
    }
    assert!(prepared.preprocessing_cap().is_ok());
    // Once extraction starts, a bad evaluator parameter layout fails closed for
    // all three commitments, including their separate salt/masking families.
    let before = runtime.snapshot();
    assert!(evaluate(inputs, 9).is_err());
    assert_eq!(runtime.snapshot().live_bytes, before.live_bytes);
    assert_eq!(runtime.snapshot().allocations, before.allocations);
    for streams in [&main_random, &perm_random] {
        assert!(streams[0].check_live().is_err());
        assert!(streams[1].check_live().is_err());
        assert!(streams[2].check_live().is_ok()); // unrelated FRI family
    }
    assert!(prepared.preprocessing_cap().is_err());
}
