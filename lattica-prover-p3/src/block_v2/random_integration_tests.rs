//! Controlled proof-level RNG routing, independent of environment activation.
use super::*;
use crate::block_v2::{
    gpu_hash::device::{DeviceSession, Extension, MatrixSpec, RowOrder},
    quotient_pcs,
};
use p3_field::PrimeField64;

fn cpu() -> CandidatePcs {
    let base = mmcs(false);
    CandidatePcs::new(
        Default::default(),
        base.clone(),
        profile::fri(profile::ChallengeMmcs::new(base)),
        profile::NUM_RANDOM_CODEWORDS,
        ChaCha20Rng::from_seed([43; 32]),
    )
    .with_fused_quotients(ChaCha20Rng::from_seed([47; 32]))
}

fn compare(
    expected: (Commitment, ProverData<RowMajorMatrix<Val>>),
    actual: (Commitment, ProverData<RowMajorMatrix<Val>>),
    session: &DeviceSession,
) {
    assert_eq!(expected.0, actual.0);
    let mut gpu = mmcs(true);
    gpu.device_only = true;
    let height = gpu.get_matrix_heights(&actual.1)[0];
    let indices = [0, height - 1, height / 3, height / 3];
    let queries = gpu
        .open_owned_queries(session, &actual.1, &indices, 64 << 20)
        .unwrap();
    for (index, query) in indices.into_iter().zip(queries) {
        assert_eq!(
            postcard::to_allocvec(&mmcs(false).open_batch(index, &expected.1)).unwrap(),
            postcard::to_allocvec(&query).unwrap()
        );
    }
}

#[test]
#[ignore = "requires OpenCL GPU, device-only PCS and a <=3 GiB zero-swap service"]
fn gpu_randomness_selection_admission_and_active_clones_preserve_reference_draws() {
    quotient_pcs::initialize_gpu_quotient_from_env(true, true).unwrap();
    let _shutdown = engine::TestShutdownGuard;
    initialize();
    let before = engine::report("GPU randomness selection before").unwrap();
    assert!(cpu().with_gpu_randomness().is_err());
    assert!(candidate(false)
        .0
        .with_gpu_openings()
        .unwrap()
        .with_gpu_randomness()
        .is_err());
    let original = candidate(true).0.with_gpu_openings().unwrap();
    assert!(original.clone().with_gpu_randomness().is_err());
    drop(original);
    let started = candidate(true).0.with_gpu_openings().unwrap();
    assert!(started
        .commit_main_device(Vec::<(crate::block_v2::gpu_hash::device::DomainSpec, _)>::new())
        .is_err());
    assert!(started.with_gpu_randomness().is_err());
    let after = engine::report("GPU randomness selection after").unwrap();
    assert_eq!(after.uploaded_bytes, before.uploaded_bytes);
    assert_eq!(after.allocations, before.allocations);

    let gpu = candidate(true)
        .0
        .with_gpu_openings()
        .unwrap()
        .with_gpu_randomness()
        .unwrap();
    let session = gpu.quotient_session().unwrap();
    let seeded = session.stats();
    assert_eq!(seeded.random_streams, 4);
    assert_eq!(seeded.uploaded_bytes, 128);
    let gpu = gpu.with_gpu_randomness().unwrap(); // No reseed on identical selection.
    assert_eq!(session.stats(), seeded);
    let shared = gpu.clone();
    let cpu = cpu();
    let trace = matrix(8, 3, 19);
    let spec = MatrixSpec::new(3, 3, Extension::Base, RowOrder::Natural, 1).unwrap();
    let words: Vec<_> = trace.values.iter().map(|v| v.as_canonical_u64()).collect();
    let input = session.upload(spec, &words).unwrap();
    let foreign_session = DeviceSession::new().unwrap();
    let foreign = foreign_session.upload(spec, &words).unwrap();
    let domain = Domain::new(Val::ONE, 4).unwrap();
    let before = session.stats();
    assert!(gpu
        .commit_main_device(Vec::<(crate::block_v2::gpu_hash::device::DomainSpec, _)>::new())
        .is_err());
    assert!(gpu.commit_main_device(vec![(domain, foreign)]).is_err());
    assert!(gpu
        .commit_main_device(vec![(
            Domain::new(Val::from_u64(7), 4).unwrap(),
            session.alias_private(&input).unwrap()
        )])
        .is_err());
    assert!(gpu.commit_preprocessing_device(vec![]).is_err());
    assert_eq!(session.stats(), before);
    for pcs in [&gpu, &shared, &gpu] {
        compare(
            cpu.commit([(domain, trace.clone())]),
            pcs.commit_main_device(vec![(domain, session.alias_private(&input).unwrap())])
                .unwrap(),
            &session,
        );
        compare(
            cpu.get_opt_randomization_poly_commitment([domain, domain])
                .unwrap(),
            pcs.get_opt_randomization_poly_commitment([domain, domain])
                .unwrap(),
            &session,
        );
    }
    assert_eq!(session.stats().random_streams, 4);
    assert!(session.stats().random_fields > 0);
}
