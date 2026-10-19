use super::*;
use crate::{
    block_v2::{codec, commitment, machine::compiler_constants::Constants},
    cuda_compute::Limits as DeviceLimits,
};
use p3_batch_stark::ProverData;

fn runtime() -> Runtime {
    Runtime::new(
        &std::env::var("LATTICA_GPU_DEVICE_UUID").unwrap(),
        DeviceLimits {
            managed_bytes: 256 << 20,
            max_allocation_bytes: 64 << 20,
            ..DeviceLimits::default()
        },
    )
    .unwrap()
}
fn limits() -> Limits {
    Limits {
        construction: ConstructionLimits {
            program_host_bytes: 64 << 20,
            wires: 1 << 18,
            input_values: 1 << 15,
        },
    }
}

fn registry<const N: usize>() -> Registry<N> {
    let height = 2048;
    let mut caps: programs::Caps<N> =
        std::array::from_fn(|_| vec![[Val::ZERO; 4]; 1 << profile::CAP_HEIGHT]);
    let compiled = programs::empty(height, &caps).unwrap();
    let air = MachineAir::new(compiled.program.pad_to(height).unwrap());
    let config = profile::preprocessing_config();
    let data = ProverData::from_airs_and_degrees(&config, &[air], &[height.ilog2() as usize + 1]);
    caps[programs::EMPTY as usize - 1] = data
        .common
        .preprocessed
        .as_ref()
        .unwrap()
        .commitment
        .roots()
        .to_vec();
    Registry { height, caps }
}

fn empty_family<const N: usize>(runtime: &Runtime) {
    let registry = registry::<N>();
    let profile = registry.id().unwrap();
    let mut session =
        Session::new_cuda(registry.clone(), profile, 1 << 30, runtime, limits()).unwrap();
    let before = crate::proving::cpu_witness_oracle_calls();
    let first = session.empty([47; 32], commitment::DEPTH).unwrap();
    let second = session.empty([47; 32], commitment::DEPTH).unwrap();
    assert_eq!(crate::proving::cpu_witness_oracle_calls(), before);
    assert_eq!((session.stats().setups, session.stats().hits), (1, 1));
    assert_ne!(
        codec::encode_node(&first).unwrap(),
        codec::encode_node(&second).unwrap(),
        "cached setup must not cache private randomness"
    );
    registry.verify(profile, &first, &first.public).unwrap();
    registry.verify(profile, &second, &second.public).unwrap();
    let expected = first.public;
    let mut changed = expected;
    changed[programs::ROOT] += Val::ONE;
    assert!(registry.verify(profile, &first, &changed).is_err());
    let mut tampered = first;
    tampered.proof.opened_values.instances[0].permutation_local[0] += profile::Challenge::ONE;
    assert!(session.verify_registered(&tampered, &expected).is_err());
    assert!(session.merge(&tampered, &second).is_err());
    if N != 5 {
        assert!(session.finalize(&second).is_err());
    }
    session.clear();
    let third = session.empty([48; 32], 1).unwrap();
    assert_eq!(session.stats().setups, 2);
    drop(session);
    assert_eq!(runtime.snapshot().live_bytes, 0);
    assert_eq!(runtime.snapshot().public_program_bytes, 0);
    registry.verify(profile, &third, &third.public).unwrap();
    eprintln!(
        "cuda_typed_empty_family keys={N} verified=3 cached=1 rebuilt=1 tampering_rejected=true"
    );
}

#[test]
#[ignore = "requires CUDA and bounded serial service"]
fn cuda_typed_empty_requests_authenticate_all_registry_families_and_cached_proofs() {
    let runtime = runtime();
    empty_family::<5>(&runtime);
    empty_family::<6>(&runtime);
    empty_family::<12>(&runtime);
}

#[test]
#[ignore = "requires CUDA and bounded serial service"]
fn cuda_typed_rejects_wrong_registry_program_and_insufficient_construction_budget() {
    let runtime = runtime();
    let registry = registry::<12>();
    let profile = registry.id().unwrap();
    let before = runtime.snapshot();
    assert!(Session::new_cuda(registry.clone(), [0; 32], 1 << 30, &runtime, limits()).is_err());
    assert_eq!(runtime.snapshot(), before);
    assert!(Session::new_cuda(registry.clone(), profile, 1 << 20, &runtime, limits()).is_err());
    assert_eq!(runtime.snapshot(), before);
    let mut wrong = registry.clone();
    wrong.caps[1][0][0] += Val::ONE;
    let pin = wrong.id().unwrap();
    let mut session = Session::new_cuda(wrong, pin, 1 << 30, &runtime, limits()).unwrap();
    let baseline = runtime.snapshot();
    assert!(session.empty([41; 32], 0).is_err());
    assert_eq!(session.cached.len(), 0);
    assert_eq!(session.stats().setups, 0);
    assert_eq!(runtime.snapshot().live_bytes, baseline.live_bytes);
    assert_eq!(
        runtime.snapshot().public_program_bytes,
        baseline.public_program_bytes
    );
    drop(session);

    let tiny = Limits {
        construction: ConstructionLimits {
            program_host_bytes: 256,
            wires: 32,
            input_values: 32,
        },
    };
    let mut session =
        Session::new_cuda(registry.clone(), profile, 1 << 30, &runtime, tiny).unwrap();
    let baseline = runtime.snapshot();
    assert!(session.empty([41; 32], 0).is_err());
    assert_eq!(session.cached.len(), 0);
    assert_eq!(runtime.snapshot().live_bytes, baseline.live_bytes);
    drop(session);

    let mut session = Session::new_cuda(registry, profile, 1 << 30, &runtime, limits()).unwrap();
    session.configure_cache(2, 1).unwrap();
    let node = session.empty([41; 32], 0).unwrap();
    let cap = session.cached[0].registered.retained_source_bytes();
    assert!(cap > 0);
    // Cached entries retain their exact source identity. A same-mode program
    // substitution must fail before setup reuse or new private randomness.
    let mut changed = programs::empty(session.registry.height, &session.registry.caps).unwrap();
    changed.program = crate::block_v2::machine::ProgramBuilder::new(PUBLIC_VALUES)
        .unwrap()
        .finish(Some(2048))
        .unwrap();
    let backend = session.backend.clone();
    assert!(backend
        .request("cuda_changed_source", |run| session.prove(
            run,
            programs::EMPTY,
            changed,
            node.public
        ))
        .is_err());
    assert_eq!(session.stats().hits, 0);
    let another = programs::empty(session.registry.height, &session.registry.caps).unwrap();
    let mut public = node.public;
    public[programs::MODE] = Val::from_u64(programs::MERGE);
    let backend = session.backend.clone();
    let error = backend
        .request("cuda_idle_source", |run| {
            session.prove(run, programs::MERGE, another, public)
        })
        .err()
        .expect("an idle cached source must fit the reserved host allowance");
    assert_eq!(
        error.to_string(),
        "CUDA idle source cache exceeds reserved host allowance"
    );
    assert_eq!(session.cached.len(), 1);
    assert_eq!(session.stats().setups, 1);
}

#[test]
#[ignore = "requires CUDA and bounded serial service"]
fn cuda_typed_construction_limits_reject_before_large_builder_allocations() {
    use crate::block_v2::machine::{
        compiler_constants::ConstructionLimits, program::ScopedProgramBuilder,
    };
    let runtime = runtime();
    let limits = ConstructionLimits {
        program_host_bytes: 1024,
        wires: 24,
        input_values: 24,
    };
    let context = PublicArithmetic::with_construction(&runtime, 1 << 16, Some(limits)).unwrap();
    let run = Run::new(
        "cuda_bounded_builder",
        Request::compatible(),
        PublicArithmetic::capabilities(Stage::Preprocessing).unwrap(),
    )
    .unwrap();
    let constants = Constants::cuda(&context, &run);
    assert!(ScopedProgramBuilder::with_constants(25, constants).is_err());
    let mut builder = ScopedProgramBuilder::with_constants(23, constants).unwrap();
    builder.input();
    builder.input();
    assert!(builder.finish(None).is_err());
    assert!(run.finish(false).unwrap().observations.is_empty());
}
