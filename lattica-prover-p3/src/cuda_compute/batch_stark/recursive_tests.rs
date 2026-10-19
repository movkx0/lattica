//! Opt-in real-recursion qualification. Run the CUDA producer in a 3 GiB
//! service, then the independent CPU audit in a separate 24 GiB service.
//! These tests exchange only final proof artifacts from the public demo wallet.
//! No registered worker routing or transaction-throughput claim is made here.
use super::*;
use crate::{
    block_v2::{
        commitment::Context,
        leaf::ContextJoinSplitAir,
        machine::{
            backend::RegisteredVerifier, program::ProofInputs, verifier::uni, ProgramBuilder,
        },
    },
    cuda_compute::{DeviceRandom, Limits, Starks, Wallets},
    joinsplit_air as js,
    proving::{Backend, Capabilities, CoverageScope, Policy, Profile, Request, Run, Stage},
};
use p3_field::PrimeField64;
use std::{io::Write, path::PathBuf, time::Instant};

mod registered;

const MANAGED: usize = 7 << 30;
const ALLOCATION: usize = 1 << 30;
const HOST: usize = 1 << 30;

fn directory() -> PathBuf {
    let path = PathBuf::from(
        std::env::var("LATTICA_CUDA_RECURSIVE_ARTIFACTS")
            .expect("set LATTICA_CUDA_RECURSIVE_ARTIFACTS to a fresh artifact directory"),
    );
    assert!(path.is_absolute() && path.is_dir());
    path
}

fn write<T: serde::Serialize>(name: &str, value: &T) {
    let bytes = postcard::to_allocvec(value).unwrap();
    assert!(bytes.len() <= profile::MAX_PROOF_BYTES);
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(directory().join(name))
        .unwrap()
        .write_all(&bytes)
        .unwrap();
}

fn read<T: serde::de::DeserializeOwned>(name: &str) -> T {
    let path = directory().join(name);
    assert!(std::fs::metadata(&path).unwrap().len() <= profile::MAX_PROOF_BYTES as u64);
    postcard::from_bytes(&std::fs::read(path).unwrap()).unwrap()
}

fn run(name: &'static str, preprocessing: bool) -> Run {
    let stages: Vec<_> = Stage::ARITHMETIC
        .into_iter()
        .filter(|s| preprocessing || !matches!(s, Stage::Preprocessing | Stage::Lookup))
        .collect();
    let mut capabilities = Capabilities::cpu(Profile::BlockV2Cubic, preprocessing, preprocessing)
        .scoped(CoverageScope::Operation, &stages);
    for stage in stages {
        capabilities.set(stage, Backend::Cuda);
    }
    Run::new(
        name,
        Request {
            policy: Policy::GpuRequired,
            emit_report: false,
        },
        capabilities,
    )
    .unwrap()
}

fn randoms(randoms: &Arc<Randoms>) -> [DeviceRandom; 3] {
    std::array::from_fn(|_| {
        randoms
            .import(ChaCha20Rng::from_rng(&mut rand::rng()))
            .unwrap()
    })
}

fn random(streams: &[DeviceRandom; 3]) -> StarkRandomness<'_> {
    StarkRandomness {
        masks: &streams[0],
        commitments: &streams[1],
        fri: &streams[2],
    }
}

fn compile(proof: &p3_uni_stark::Proof<profile::Config>, publics: usize) -> (MachineAir, Vec<Val>) {
    let mut builder = ProgramBuilder::new(publics).unwrap();
    let public: Vec<_> = (0..publics).map(|i| builder.public(i).unwrap()).collect();
    let mut inputs = ProofInputs::default();
    uni::verify(
        &mut builder,
        &mut inputs,
        &ContextJoinSplitAir,
        js::HEIGHT,
        &public,
        proof,
    )
    .unwrap();
    let program = builder.finish(None).unwrap();
    eprintln!(
        "recursive wallet rows={} height={} wires={} inputs={}",
        program.active_rows(),
        program.height(),
        program.wire_count(),
        inputs.values.len()
    );
    (MachineAir::new(program), inputs.values)
}

fn inner(runtime: &Runtime) -> (p3_uni_stark::Proof<profile::Config>, Vec<Val>) {
    let wallets = Wallets::new(runtime).unwrap();
    let starks = Starks::new(runtime).unwrap();
    let random_engine = Randoms::new(runtime).unwrap();
    let prepared = starks
        .prepare::<Challenge, _>(
            &ContextJoinSplitAir,
            js::HEIGHT.ilog2(),
            HOST,
            Specialization::Prefer,
        )
        .unwrap();
    let run = run("cuda_recursive_inner_wallet", false);
    let calls = crate::proving::cpu_witness_oracle_calls();
    let (proof, public) = runtime
        .reported(&run, || {
            let frame = wallets.joinsplit(&js::demo_witness(), HOST, &run)?;
            let context = Context {
                profile_id: profile::CANDIDATE_PROFILE_ID,
                chain_id: [19; 32],
            };
            let context = context.to_fields();
            let public = runtime.allocate(frame.public.len() + context.len())?;
            public.copy_from(0, &frame.public, 0, frame.public.len())?;
            public.write(frame.public.len(), &context)?;
            let streams = randoms(&random_engine);
            let proof = starks.prove(
                &prepared,
                &frame.trace,
                Some(&public),
                random(&streams),
                HOST,
            )?;
            let mut words = vec![0; public.len()];
            public.read(0, &mut words)?;
            Ok((
                proof,
                words.into_iter().map(Val::from_u64).collect::<Vec<_>>(),
            ))
        })
        .unwrap();
    assert_eq!(crate::proving::cpu_witness_oracle_calls(), calls);
    let report = run.finish(true).unwrap();
    assert!(report.stage_coverage_complete);
    eprintln!(
        "LATTICA_CUDA_RECURSIVE_INNER {}",
        serde_json::to_string(&report).unwrap()
    );
    let proof = postcard::from_bytes(&postcard::to_allocvec(&proof).unwrap()).unwrap();
    p3_uni_stark::verify(
        &profile::make_config(),
        &ContextJoinSplitAir,
        &proof,
        &public,
    )
    .unwrap();
    (proof, public)
}

#[test]
#[ignore = "large real recursion; opt-in artifact directory and bounded serial CUDA service"]
fn cuda_recursive_wallet_produces_native_outer_proof() {
    let _ = directory();
    let started = Instant::now();
    let runtime = Runtime::new(
        &std::env::var("LATTICA_GPU_DEVICE_UUID").unwrap(),
        Limits {
            managed_bytes: MANAGED,
            max_allocation_bytes: ALLOCATION,
            ..Limits::default()
        },
    )
    .unwrap();
    let (proof, public) = inner(&runtime);
    // All inner modules and private allocations are retired before outer setup.
    assert_eq!(runtime.snapshot().modules, 0);
    assert_eq!(runtime.snapshot().live_bytes, 0);
    write("inner.postcard", &proof);
    write("public.postcard", &public);
    let (air, witness) = compile(&proof, public.len());
    let public: Vec<_> = public.iter().map(PrimeField64::as_canonical_u64).collect();
    let witness: Vec<_> = witness.iter().map(PrimeField64::as_canonical_u64).collect();
    let engine = BatchStarks::new(&runtime).unwrap();
    let run = run("cuda_recursive_outer_wallet_verifier", true);
    let before = runtime.snapshot();
    let calls = crate::proving::cpu_witness_oracle_calls();
    let (outer, cap) = runtime
        .reported(&run, || {
            let preparation = Instant::now();
            let prepared = engine.prepare(&[&air], HOST, Specialization::Prefer)?;
            eprintln!(
                "LATTICA_CUDA_RECURSIVE_PREPARED {}",
                serde_json::json!({
                    "seconds": preparation.elapsed().as_secs_f64(), "snapshot": runtime.snapshot(),
                })
            );
            let cap = prepared.preprocessing_cap()?;
            let streams = randoms(&engine.randoms);
            let proving = Instant::now();
            let outer = engine.prove(
                &prepared,
                &[MachineInputs {
                    public: &public,
                    witness: &witness,
                }],
                random(&streams),
                HOST,
            )?;
            eprintln!(
                "LATTICA_CUDA_RECURSIVE_PROVED {}",
                serde_json::json!({
                    "seconds": proving.elapsed().as_secs_f64(), "snapshot": runtime.snapshot(),
                })
            );
            Ok((outer, cap))
        })
        .unwrap();
    assert_eq!(crate::proving::cpu_witness_oracle_calls(), calls);
    let report = run.finish(true).unwrap();
    assert!(report.stage_coverage_complete);
    assert_eq!(report.observations.len(), 16);
    assert_eq!(runtime.snapshot().live_bytes, before.live_bytes);
    assert_eq!(runtime.snapshot().allocations, before.allocations);
    assert_eq!(
        runtime.snapshot().public_program_bytes,
        before.public_program_bytes
    );
    write("outer.postcard", &outer);
    // This is an untrusted candidate; only the CPU audit may authenticate it.
    write("candidate-cap.postcard", &cap);
    eprintln!(
        "LATTICA_CUDA_RECURSIVE_PRODUCER {}",
        serde_json::json!({
            "seconds": started.elapsed().as_secs_f64(), "report": report,
            "snapshot": runtime.snapshot(), "identity": runtime.identity(),
            "managed_bytes": MANAGED, "max_allocation_bytes": ALLOCATION,
            "host_allowance": HOST, "independent_cpu_audit_pending": true,
        })
    );
}

#[test]
#[ignore = "independent CPU preprocessing rebuild; opt-in artifacts and 24 GiB bounded service"]
fn cuda_recursive_wallet_artifacts_pass_independent_cpu_audit() {
    let started = Instant::now();
    let proof: p3_uni_stark::Proof<profile::Config> = read("inner.postcard");
    let public: Vec<Val> = read("public.postcard");
    assert_eq!(public.len(), ContextJoinSplitAir.num_public_values());
    p3_uni_stark::verify(
        &profile::make_config(),
        &ContextJoinSplitAir,
        &proof,
        &public,
    )
    .unwrap();
    let (air, witness) = compile(&proof, public.len());
    air.program().evaluate(&public, &witness).unwrap();
    let mut bad_public = public.clone();
    bad_public[js::PI_FEE] += Val::ONE;
    assert!(air.program().evaluate(&bad_public, &witness).is_err());
    let mut bad_inner = proof;
    bad_inner.opened_values.quotient_chunks[0][0] += Challenge::ONE;
    let (_, bad_witness) = compile(&bad_inner, public.len());
    assert_eq!(bad_witness.len(), witness.len());
    assert!(air.program().evaluate(&public, &bad_witness).is_err());
    let height = air.program().height();
    // CPU-only reference PCS, with the production deterministic PUBLIC salts.
    // No GPU-produced preprocessing, cap, or common data is trusted by this setup.
    let cpu = super::tests::cpu();
    let preparation = Instant::now();
    let data = p3_batch_stark::ProverData::from_airs_and_degrees(
        &cpu,
        &[air],
        &[height.ilog2() as usize + 1],
    );
    let trusted_cap = data
        .common
        .preprocessed
        .as_ref()
        .unwrap()
        .commitment
        .clone();
    drop(data);
    assert_eq!(trusted_cap, read::<Cap>("candidate-cap.postcard"));
    eprintln!(
        "LATTICA_CUDA_RECURSIVE_CPU_SETUP seconds={}",
        preparation.elapsed().as_secs_f64()
    );
    let verifier = RegisteredVerifier::from_trusted_cap(public.len(), height, trusted_cap).unwrap();
    let outer: p3_batch_stark::BatchProof<profile::Config> = read("outer.postcard");
    verifier.verify(&outer, &public).unwrap();
    assert!(verifier.verify(&outer, &bad_public).is_err());
    let mut altered = outer;
    altered.opened_values.instances[0]
        .base_opened_values
        .quotient_chunks[0][0] += Challenge::ONE;
    assert!(verifier.verify(&altered, &public).is_err());
    eprintln!(
        "LATTICA_CUDA_RECURSIVE_AUDITED {}",
        serde_json::json!({
            "seconds": started.elapsed().as_secs_f64(), "height": height,
            "independent_cpu_preprocessing": true, "registered_cpu_verifier": true,
            "altered_inner_proof_rejected": true, "altered_public_rejected": true,
            "altered_outer_proof_rejected": true,
        })
    );
}
