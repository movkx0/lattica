use super::*;

#[test]
#[ignore = "requires OpenCL GPU, retained trees, <=3 GiB cgroup and zero swap"]
fn gpu_quotient_pipeline_matches_cpu_matrices_caps_and_openings() {
    let _shutdown = engine::TestShutdownGuard;
    assert_eq!(
        std::env::var("LATTICA_V2_GPU_RETAIN_TREES").as_deref(),
        Ok("1")
    );
    // Large staging exercises the actual parallel decode branch when requested,
    // while the 8192-row input also crosses the multi-kernel NTT boundary.
    engine::initialize_mode(
        Limits {
            managed_bytes: 256 << 20,
            tile_bytes: 32 << 20,
            staging_bytes: 8 << 20,
        },
        engine::TransferMode::Serial,
    )
    .unwrap();
    for (height, chunks, width) in [
        (8usize, 2usize, 3usize),
        (32, 4, 1),
        (64, 16, 3),
        (8192, 2, 3),
    ] {
        let domain = Domain::new(Val::from_u64(7), (height * chunks).ilog2() as usize).unwrap();
        let domains = domain.split_domains(chunks);
        let matrices = domain.split_evals(chunks, matrix(height * chunks, width, 19));
        let (reference, _) = candidate(true);
        let (gpu, gpu_mmcs) = candidate(true);
        // All rejected admissions precede hiding and salt draws. The exact
        // comparison below also checks that rejection did not advance RNGs.
        assert!(gpu.commit_quotient_evaluations(vec![]).is_err());
        assert!(gpu
            .commit_quotient_evaluations(vec![(domains.clone(), vec![])])
            .is_err());
        assert!(gpu
            .commit_quotient_evaluations(vec![
                (domains.clone(), matrices.clone()),
                (domains.clone(), matrices.clone()),
            ])
            .is_err());
        let mut overlap = domains.clone();
        overlap[1] = overlap[0];
        assert!(gpu
            .commit_quotient_evaluations(vec![(overlap, matrices.clone())])
            .is_err());
        let cpu_mmcs = (*mmcs(false).cpu).clone();
        let ldes =
            reference.get_quotient_ldes(domains.iter().copied().zip(matrices.clone()), chunks);
        compare(
            &cpu_mmcs,
            &gpu_mmcs,
            cpu_mmcs.commit(ldes),
            gpu.commit_quotient_evaluations(vec![(domains, matrices)])
                .unwrap(),
        );
    }
    let stats = engine::report("GPU quotient differential").unwrap();
    assert_eq!(stats.quotient_lde_commits, 4);
    if std::env::var("LATTICA_V2_GPU_PARALLEL_READBACK").as_deref() == Ok("1") {
        assert!(stats.lde_parallel_decode_bytes > 0);
        assert!(stats.lde_parallel_decode_chunks > 0);
    }
}

#[test]
#[ignore = "requires OpenCL GPU, retained trees, <=3 GiB cgroup and zero swap"]
fn gpu_quotient_pipeline_proof_matches_upstream_and_cpu_verifies() {
    quotient_proof_equivalence(false);
}
#[test]
#[ignore = "requires OpenCL GPU, retained trees, <=3 GiB cgroup and zero swap"]
fn gpu_compact_quotient_pipeline_preserves_full_proof_bytes() {
    quotient_proof_equivalence(true);
}
fn quotient_proof_equivalence(compact: bool) {
    use crate::block_v2::machine::{MachineAir, ProgramBuilder};
    use p3_batch_stark::{prove_batch, verify_batch, ProverData as BatchData, StarkInstance};
    let _shutdown = engine::TestShutdownGuard;
    initialize();
    let mut builder = ProgramBuilder::new(1).unwrap();
    let public = builder.public(0).unwrap();
    let input = builder.input();
    let square = builder.mul(input, input);
    builder.assert_equal(square, public);
    let air = MachineAir::new(builder.finish(Some(64)).unwrap());
    let public = vec![Val::from_u64(9)];
    let trace = air.trace(&public, &[Val::from_u64(3)]).unwrap();
    let data = BatchData::from_airs_and_degrees(
        &profile::preprocessing_config(),
        core::slice::from_ref(&air),
        &[7],
    );
    let instances = [StarkInstance {
        air: &air,
        trace: &trace,
        public_values: public.clone(),
    }];
    let config = || {
        profile::Config::new(
            if compact {
                candidate(true).0.with_gpu_openings().unwrap()
            } else {
                candidate(true).0
            },
            Challenger::new(default_goldilocks_poseidon2_8()),
        )
    };
    // One PoW search thread makes upstream's first valid nonce deterministic.
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(1)
        .build()
        .unwrap();
    let (reference, actual) = pool.install(|| {
        let reference = prove_batch(&config(), &instances, &data);
        if compact {
            crate::block_v2::resident_pcs::enable_compact_for_test();
        }
        (
            reference,
            crate::block_v2::gpu_quotient_prover::prove_batch(
                &config(),
                &instances,
                &data,
                |data| CandidateMmcs::release_quotient_prefix(data),
                |pcs, groups| pcs.commit_quotient_evaluations(groups).unwrap(),
            ),
        )
    });
    assert_eq!(
        postcard::to_allocvec(&reference).unwrap(),
        postcard::to_allocvec(&actual).unwrap()
    );
    verify_batch(
        &profile::make_config(),
        core::slice::from_ref(&air),
        &actual,
        &[public],
        &data.common,
    )
    .unwrap();
    assert!(verify_batch(
        &profile::make_config(),
        &[air],
        &actual,
        &[vec![Val::from_u64(10)]],
        &data.common
    )
    .is_err());
}

#[cfg(feature = "gpu-metal")]
#[test]
#[ignore = "Apple GPU memory coordination; isolated process"]
fn gpu_apple_shared_preprocessing_preserves_proofs_and_private_randomness() {
    use crate::block_v2::machine::{MachineAir, ProgramBuilder, backend::RegisteredProgram};
    let mut builder = ProgramBuilder::new(1).unwrap();
    let public_wire = builder.public(0).unwrap();
    let input = builder.input();
    let square = builder.mul(input, input);
    builder.assert_equal(square, public_wire);
    let air = MachineAir::new(builder.finish(Some(64)).unwrap());
    let reference = RegisteredProgram::new(air.clone()).unwrap();
    let verifier = reference.verifier();
    let cap = reference.preprocessing_cap().clone();
    drop(reference);
    let dir = std::env::temp_dir().join(format!("lattica-apple-memory-proof-{}", std::process::id()));
    crate::block_v2::apple_memory::private_directory(&dir).unwrap();
    for (name, value) in [
        ("LATTICA_V2_GPU_HASH", "1"), ("LATTICA_V2_GPU_MANAGED_BYTES", "268435456"),
        ("LATTICA_V2_GPU_RESIDENT_LDE", "1"), ("LATTICA_V2_GPU_OPENINGS", "1"),
        ("LATTICA_V2_GPU_QUOTIENT_LDE", "1"), ("LATTICA_V2_GPU_COMPACT_PROVER_DATA", "1"),
        ("LATTICA_V2_GPU_OPENING_COMPACT", "1"), ("LATTICA_V2_GPU_DIRECT_READBACK", "1"),
        ("LATTICA_APPLE_MEMORY_RECLAIM", "1"), ("LATTICA_APPLE_PHASE_SLOTS", "2"),
        ("LATTICA_APPLE_LDE_SCRATCH_BYTES", "2097152"),
        ("LATTICA_APPLE_QUERY_SCRATCH_BYTES", "65536"), ("LATTICA_APPLE_LATE_PHASE_SLOTS", "1"),
        ("LATTICA_APPLE_COMPACT_SALTS", "1"), ("LATTICA_APPLE_QUERY_PHASE_SLOTS", "1"),
    ] { std::env::set_var(name, value); }
    std::env::set_var("LATTICA_APPLE_SHARED_PREPROCESSING_DIR", dir.join("shared"));
    std::env::set_var("LATTICA_APPLE_PHASE_DIR", dir.join("phases"));
    crate::block_v2::gpu_hash::initialize_from_env().unwrap();
    crate::block_v2::resident_pcs::initialize_research_from_env().unwrap();
    let _shutdown = engine::TestShutdownGuard;
    let first = RegisteredProgram::new(air.clone()).unwrap();
    let second = RegisteredProgram::new(air).unwrap();
    assert_eq!(first.preprocessing_cap(), &cap);
    assert_eq!(second.preprocessing_cap(), &cap);
    let public = [Val::from_u64(9)];
    let witness = [Val::from_u64(3)];
    let a = first.prove(&public, &witness).unwrap();
    let b = second.prove(&public, &witness).unwrap();
    verifier.verify(&a, &public).unwrap();
    verifier.verify(&b, &public).unwrap();
    assert!(verifier.verify(&b, &[Val::from_u64(10)]).is_err());
    assert_ne!(postcard::to_allocvec(&a.commitments).unwrap(), postcard::to_allocvec(&b.commitments).unwrap(),
        "independent witness proofs must use fresh private randomness");
    assert_eq!(std::fs::read_dir(dir.join("shared")).unwrap().filter(|p| p.as_ref().unwrap().path().extension().is_some_and(|x| x == "prefix")).count(), 1);
    drop((first, second));
    std::fs::remove_dir_all(dir).unwrap();
}
