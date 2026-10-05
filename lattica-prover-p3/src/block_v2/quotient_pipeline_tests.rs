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
