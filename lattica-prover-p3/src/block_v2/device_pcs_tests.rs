//! Device-only PCS admission must precede hiding and salt draws. The independent
//! CPU PCS below also checks the randomization stream after rejected requests.
use super::*;
use crate::block_v2::{gpu_hash::device::DeviceSession, resident_pcs::ResidentState};

#[test]
#[ignore = "requires OpenCL GPU, device-only PCS flags and a <=3 GiB zero-swap service"]
fn device_pcs_admission_rejects_before_hiding_and_salt_draws() {
    crate::block_v2::quotient_pcs::initialize_gpu_quotient_from_env(true, true).unwrap();
    assert!(crate::block_v2::quotient_pcs::gpu_pcs_device_only_enabled());
    let _shutdown = engine::TestShutdownGuard;
    initialize();
    let make = || {
        let mmcs = mmcs(true);
        ResidentState::new(
            Default::default(),
            mmcs.clone(),
            profile::fri(profile::ChallengeMmcs::new(mmcs)),
            profile::NUM_RANDOM_CODEWORDS,
            ChaCha20Rng::from_seed([43; 32]),
            64 << 20,
        )
        .unwrap()
    };
    let domain = Domain::new(Val::ONE, 4).unwrap();
    let inputs = [(domain, matrix(8, 3, 2))];

    // Legacy quotient entry points must fail before consuming their inputs or
    // streams, rather than delegating to the inner CPU PCS in this mode.
    {
        use std::panic::{catch_unwind, AssertUnwindSafe};
        let (pcs, mmcs) = candidate(true);
        let pcs = pcs.with_gpu_openings().unwrap();
        let domains = Domain::new(Val::GENERATOR, 5).unwrap().split_domains(2);
        let evaluations: Vec<_> = domains.iter().map(|d| (*d, matrix(16, 3, 9))).collect();
        let before = engine::report("device PCS before rejected host interfaces").unwrap();
        assert!(catch_unwind(AssertUnwindSafe(|| pcs.get_quotient_ldes(evaluations, 2))).is_err());
        assert!(
            catch_unwind(AssertUnwindSafe(|| pcs.commit_ldes(vec![matrix(32, 3, 9)]))).is_err()
        );
        assert!(pcs
            .commit_quotient_evaluations(vec![(domains, vec![matrix(16, 3, 9); 2])])
            .err()
            .unwrap()
            .contains("host PCS arithmetic"));
        let after = engine::report("device PCS after rejected host interfaces").unwrap();
        assert_eq!(after.uploaded_bytes, before.uploaded_bytes);
        assert_eq!(after.allocations, before.allocations);
        let (cpu, cpu_mmcs) = reference();
        compare_device(
            &cpu_mmcs,
            &mmcs,
            &pcs.quotient_session().unwrap(),
            <CpuPcs as Pcs<Challenge, Challenger>>::commit(&cpu, inputs.clone()),
            pcs.commit(inputs.clone()),
        );
    }

    // Selecting only the committer must not start a private proof, even though
    // public preprocessing can be built before an opening consumer is selected.
    let missing = make();
    let before = engine::report("device PCS admission before missing consumer").unwrap();
    assert!(missing
        .commit(inputs.clone(), false)
        .err()
        .unwrap()
        .contains("owned GPU consumers"));
    assert!(missing
        .randomization([domain])
        .err()
        .unwrap()
        .contains("owned GPU consumers"));
    let after = engine::report("device PCS admission after missing consumer").unwrap();
    assert_eq!(before.uploaded_bytes, after.uploaded_bytes);
    assert_eq!(before.allocations, after.allocations);
    // Explicitly exercise the original CPU interface with the same shared RNG
    // after rejection; this is an oracle, never a production fallback.
    let (cpu, cpu_mmcs) = reference();
    compare(
        &cpu_mmcs,
        &missing.mmcs,
        <CpuPcs as Pcs<Challenge, Challenger>>::commit(&cpu, inputs.clone()),
        <crate::block_v2::resident_pcs::ResidentInner as Pcs<Challenge, Challenger>>::commit(
            &missing.inner,
            inputs.clone(),
        ),
    );
    drop(missing);

    let (cpu, cpu_mmcs) = reference();
    let mut state = make();
    state.enable_gpu_openings().unwrap();
    let session = state.device_session.as_ref().unwrap().clone();
    let taller = Domain::new(Val::ONE, 5).unwrap();
    let before = engine::report("device PCS admission before invalid requests").unwrap();
    assert!(state.commit([], false).is_err());
    assert!(state.commit([(domain, matrix(4, 3, 2))], false).is_err());
    assert!(state
        .commit(
            [(domain, matrix(8, 3, 2)), (taller, matrix(16, 3, 2))],
            false
        )
        .is_err());
    assert!(state.randomization([domain, taller]).is_err());
    state.host_budget = 1;
    assert!(state
        .commit(inputs.clone(), false)
        .err()
        .unwrap()
        .contains("staging"));
    assert!(state
        .randomization([domain])
        .err()
        .unwrap()
        .contains("staging"));
    state.host_budget = 64 << 20;
    // A resident FRI/random polynomial domain is rejected before materializing
    // it on either host or device when the aggregate GPU plan cannot fit.
    assert!(state
        .randomization([Domain::new(Val::ONE, 22).unwrap()])
        .is_err());

    let raw = matrix(16, 3, 7);
    assert!(state
        .mmcs
        .commit_resident_retained_owned(
            vec![(domain, raw.clone())],
            profile::LOG_BLOWUP,
            64 << 20,
            None,
            0,
            None
        )
        .is_err());
    assert!(state
        .mmcs
        .commit_resident_retained_owned(
            vec![(domain, raw.clone())],
            profile::LOG_BLOWUP - 1,
            64 << 20,
            None,
            0,
            Some((&session, false))
        )
        .is_err());
    assert!(state
        .mmcs
        .commit_resident_retained_owned(
            vec![(domain, raw)],
            profile::LOG_BLOWUP + 1,
            64 << 20,
            Some(&[matrix(8, 3, 7)]),
            0,
            Some((&session, false))
        )
        .is_err());
    let after = engine::report("device PCS admission after invalid requests").unwrap();
    assert_eq!(after.uploaded_bytes, before.uploaded_bytes);
    assert_eq!(after.downloaded_bytes, before.downloaded_bytes);
    assert_eq!(after.allocations, before.allocations);
    for _ in 0..2 {
        let expected = <CpuPcs as Pcs<Challenge, Challenger>>::commit(&cpu, inputs.clone());
        let actual = state.commit(inputs.clone(), false).unwrap();
        compare_device(&cpu_mmcs, &state.mmcs, &session, expected, actual);
        let expected =
            <CpuPcs as Pcs<Challenge, Challenger>>::get_opt_randomization_poly_commitment(
                &cpu,
                [domain],
            )
            .unwrap();
        let actual = state.randomization([domain]).unwrap();
        compare_device(&cpu_mmcs, &state.mmcs, &session, expected, actual);
    }
}

pub(super) fn compare_device(
    cpu: &ValMmcs,
    gpu: &CandidateMmcs,
    session: &DeviceSession,
    expected: (Commitment, CpuData),
    actual: (Commitment, ProverData<RowMajorMatrix<Val>>),
) {
    assert_eq!(expected.0, actual.0);
    assert!(matches!(actual.1, ProverData::DeviceOnly { .. }));
    assert_eq!(
        cpu.get_matrix_heights(&expected.1),
        gpu.get_matrix_heights(&actual.1)
    );
    let height = gpu.get_matrix_heights(&actual.1)[0];
    let dimensions: Vec<_> = cpu
        .get_matrices(&expected.1)
        .iter()
        .map(|m| m.dimensions())
        .collect();
    let indices = [0, height - 1, height / 3, height / 3];
    let queries = gpu
        .open_owned_queries(session, &actual.1, &indices, 8 << 20)
        .unwrap();
    for (index, query) in indices.into_iter().zip(queries) {
        cpu.verify_batch(
            &actual.0,
            &dimensions,
            index,
            BatchOpeningRef::new(&query.opened_values, &query.opening_proof),
        )
        .unwrap();
        assert_eq!(
            postcard::to_allocvec(&cpu.open_batch(index, &expected.1)).unwrap(),
            postcard::to_allocvec(&query).unwrap()
        );
    }
}
