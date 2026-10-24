use super::*;
use crate::{
    g_bound_air::{join::RegisteredGBoundAir, GBoundAir},
    linear_map_air::{LinearMapAir, LinearMapDescriptor, LinearMapInput, RegisteredLinearMapAir},
    ntt_air::{NttAir, RegisteredNttAir},
    permutation_air::{
        PermutationAir, PermutationInput, PermutationKind, RegisteredPermutationAir,
    },
    poly_air::{MulAir, RegisteredMulAir},
    rust_verify::committed_backend::PolynomialKind,
};
use lattica_prover_p3::proving::{Backend, Policy, Report, Request, Stage};

fn periodic_matches(air: &(impl BaseAir<Val> + PeriodicSource)) {
    let expected = air.periodic_columns();
    assert_eq!(air.column_count(), expected.len());
    assert_eq!(air.column_len(expected.len()), None);
    for (index, column) in expected.iter().enumerate() {
        assert_eq!(
            air.column_len(index),
            Some(column.len()),
            "periodic column {index}"
        );
        let mut actual = vec![Val::NEG_ONE; column.len()];
        air.fill_column(index, &mut actual).unwrap();
        assert_eq!(&actual, column, "periodic column {index}");
        assert!(air
            .fill_column(index, &mut actual[..column.len() - 1])
            .is_err());
    }
}

#[test]
fn bounded_periodic_sources_match_all_original_air_schedules() {
    for modulus in [Q, QHAT] {
        for count in [1, 2, 4] {
            for kind in [
                AffineKind::Add,
                AffineKind::Sub,
                AffineKind::SignedToCanonical { bound: 565 },
            ] {
                periodic_matches(&AffineAir::new(kind, modulus, count).unwrap());
            }
        }
        for count in [1, 3] {
            periodic_matches(&NttAir::new(modulus, count).unwrap());
            periodic_matches(&MulAir::new(modulus, count).unwrap());
        }
        let kind = PolynomialKind::Canonical { modulus };
        let descriptor = LinearMapDescriptor::new(
            vec![kind; 2],
            kind,
            vec![[1; D], [-2; D]],
            core::array::from_fn(|i| i as i64 % 11 - 5),
        )
        .unwrap();
        periodic_matches(&LinearMapAir::new(descriptor));
    }
    for kind in [
        PermutationKind::AutomorphismQ,
        PermutationKind::InverseChallenge,
    ] {
        periodic_matches(&PermutationAir::new(kind));
    }
    for bound in [6_825_771, 1_137_628] {
        periodic_matches(&GBoundAir::new(bound).unwrap());
    }
    let signed = PolynomialKind::Signed { bound: 565 };
    let descriptor = LinearMapDescriptor::new(
        vec![signed; 2],
        PolynomialKind::Signed { bound: 1130 },
        vec![[1; D], [-1; D]],
        [0; D],
    )
    .unwrap();
    periodic_matches(&LinearMapAir::new(descriptor));
}

#[test]
fn native_arithmetic_gpu_entry_rejects_cpu_policy_before_initialization() {
    let key = RegisteredAffineAir::new(AffineKind::Add, Q, 1).unwrap();
    let inputs = [AffineInput::Binary {
        left: [0; D],
        right: [0; D],
    }];
    for policy in [Policy::Compatible, Policy::CpuRequired] {
        assert!(key
            .prove_gpu(
                &inputs,
                1 << 30,
                Request {
                    policy,
                    emit_report: false
                }
            )
            .is_err());
    }
}

fn assert_receipts(report: &Report) {
    assert!(report.succeeded && report.stage_coverage_complete);
    assert_eq!(report.observation_errors, 0);
    assert!(report.components.is_empty());
    for stage in Stage::ARITHMETIC
        .into_iter()
        .filter(|s| *s != Stage::Lookup)
    {
        assert!(
            report.observations.iter().any(|o| o.stage == stage
                && o.backend == Backend::OpenCl
                && o.completed_calls > 0
                && o.device_calls > 0
                && o.calls == o.completed_calls),
            "missing {stage:?}"
        );
    }
}

#[test]
#[ignore = "real GPU native proofs; requires release build, explicit environment and exclusive bounded OpenCL session"]
fn native_gpu_arithmetic_proofs_match_cpu_roots_and_reject_mutated_publics() {
    assert!(!cfg!(debug_assertions));
    let session = crate::opencl::Session::start(crate::opencl::Limits {
        host_bytes: 8 << 30,
        device_bytes: 8 << 30,
        max_rows: 4096,
    })
    .unwrap();
    let request = Request {
        policy: Policy::GpuRequired,
        emit_report: false,
    };
    macro_rules! check {
        ($key:expr,$inputs:expr) => {{
            let key = $key;
            let inputs = $inputs;
            let expected = key.air().generate(&inputs).unwrap().public_values;
            let (mut artifact, report) = key.prove_gpu(&inputs, 2 << 30, request).unwrap();
            assert_eq!(artifact.public_values.as_slice(), expected.as_slice());
            assert_receipts(&report);
            artifact.public_values[0] += Val::ONE;
            assert!(key.verify(&artifact).is_err());
        }};
    }
    for modulus in [Q, QHAT] {
        let a = core::array::from_fn(|i| {
            if i % 3 == 0 {
                modulus - 1
            } else {
                (i as u64 * 7919) % modulus
            }
        });
        let b = core::array::from_fn(|i| {
            if i % 3 == 1 {
                modulus - 1
            } else {
                (i as u64 * 3571) % modulus
            }
        });
        for kind in [AffineKind::Add, AffineKind::Sub] {
            check!(
                RegisteredAffineAir::new(kind, modulus, 2).unwrap(),
                vec![AffineInput::Binary { left: a, right: b }; 2]
            );
        }
        check!(
            RegisteredAffineAir::new(AffineKind::SignedToCanonical { bound: 565 }, modulus, 1)
                .unwrap(),
            vec![AffineInput::Signed(core::array::from_fn(|i| [
                -565, 0, 565
            ][i % 3]))]
        );
        check!(RegisteredNttAir::new(modulus, 3).unwrap(), vec![a, b, a]);
        let key = RegisteredMulAir::new(modulus, 3).unwrap();
        let left = [a, b, a];
        let right = [b, a, b];
        let expected = key.air().generate(&left, &right).unwrap().public_values;
        let (mut artifact, report) = key.prove_gpu(&left, &right, 2 << 30, request).unwrap();
        assert_eq!(artifact.public_values, expected);
        assert_receipts(&report);
        artifact.public_values[0] += Val::ONE;
        assert!(key.verify(&artifact).is_err());
        let kind = PolynomialKind::Canonical { modulus };
        let descriptor = LinearMapDescriptor::new(
            vec![kind; 2],
            kind,
            vec![[1; D], [-2; D]],
            core::array::from_fn(|i| i as i64 % 11 - 5),
        )
        .unwrap();
        check!(
            RegisteredLinearMapAir::new(descriptor),
            vec![LinearMapInput::Canonical(a), LinearMapInput::Canonical(b)]
        );
    }
    check!(
        RegisteredPermutationAir::new(PermutationKind::AutomorphismQ),
        PermutationInput::Canonical(core::array::from_fn(|i| (i as u64 * 7919) % Q))
    );
    check!(
        RegisteredPermutationAir::new(PermutationKind::InverseChallenge),
        PermutationInput::Signed(core::array::from_fn(|i| [-1, 0, 1][i % 3]))
    );
    let signed = PolynomialKind::Signed { bound: 565 };
    let descriptor = LinearMapDescriptor::new(
        vec![signed; 2],
        PolynomialKind::Signed { bound: 1130 },
        vec![[1; D], [-1; D]],
        [0; D],
    )
    .unwrap();
    check!(
        RegisteredLinearMapAir::new(descriptor),
        vec![
            LinearMapInput::Signed([565; D]),
            LinearMapInput::Signed([-565; D])
        ]
    );
    for bound in [6_825_771, 1_137_628] {
        let key = RegisteredGBoundAir::new(bound).unwrap();
        let mut f = [0; D];
        f[0] = 1;
        f[255] = -1;
        let mut x = [0; D];
        x[1] = 1;
        let expected = key.air().generate(&f, &x).unwrap().public_values;
        let (mut artifact, report) = key.prove_gpu(&f, &x, 2 << 30, request).unwrap();
        assert_eq!(artifact.public_values, expected);
        assert_receipts(&report);
        artifact.public_values[0] += Val::ONE;
        assert!(key.verify(&artifact).is_err());
        f[0] = i64::MAX;
        assert!(key.prove_gpu(&f, &x, 2 << 30, request).is_err());
    }
    let invalid = [AffineInput::Binary {
        left: [Q; D],
        right: [0; D],
    }];
    assert!(RegisteredAffineAir::new(AffineKind::Add, Q, 1)
        .unwrap()
        .prove_gpu(&invalid, 2 << 30, request)
        .is_err());
    // No retry or replacement proof is accepted after the invalid witness.
    session.finish().unwrap();
}

#[cfg(feature = "native-trace-audit")]
#[test]
#[ignore = "requires exclusive admitted OpenCL resources; all arithmetic full-trace CPU/GPU differentials"]
fn native_gpu_arithmetic_full_traces_match_independent_cpu_witnesses() {
    use lattica_prover_p3::block_v2::native_gpu::audit_generated_trace;
    let session = crate::opencl::Session::start(crate::opencl::Limits {
        host_bytes: 8 << 30,
        device_bytes: 8 << 30,
        max_rows: 4096,
    })
    .unwrap();
    macro_rules! audit {
        ($entry:literal,$air:expr,$rows:expr,$inputs:expr) => {{
            let air = $air;
            let inputs = $inputs;
            let expected = air.generate(&inputs).unwrap();
            audit_generated_trace(
                $entry,
                $rows,
                air.width(),
                expected.public_values.len(),
                1 << 30,
                &expected.trace.values,
                &expected.public_values,
                |ctx| air.generate_gpu(ctx, &inputs),
            )
            .unwrap();
        }};
    }
    for modulus in [Q, QHAT] {
        let a = core::array::from_fn(|i| {
            if i % 3 == 0 {
                modulus - 1
            } else {
                (i as u64 * 7919) % modulus
            }
        });
        let b = core::array::from_fn(|i| {
            if i % 3 == 1 {
                modulus - 1
            } else {
                (i as u64 * 3571) % modulus
            }
        });
        for kind in [AffineKind::Add, AffineKind::Sub] {
            audit!(
                "pq_affine_trace_parity",
                AffineAir::new(kind, modulus, 2).unwrap(),
                1024,
                vec![AffineInput::Binary { left: a, right: b }; 2]
            );
        }
        audit!(
            "pq_affine_signed_trace_parity",
            AffineAir::new(AffineKind::SignedToCanonical { bound: 565 }, modulus, 1).unwrap(),
            512,
            vec![AffineInput::Signed(core::array::from_fn(|i| [
                -565, 0, 565
            ][i % 3]))]
        );
        audit!(
            "pq_ntt_trace_parity",
            NttAir::new(modulus, 3).unwrap(),
            4096,
            vec![a, b, a]
        );
        let air = MulAir::new(modulus, 3).unwrap();
        let left = [a, b, a];
        let right = [b, a, b];
        let expected = air.generate(&left, &right).unwrap();
        audit_generated_trace(
            "pq_mul_trace_parity",
            air.height,
            air.width(),
            expected.public_values.len(),
            1 << 30,
            &expected.trace.values,
            &expected.public_values,
            |ctx| air.generate_gpu(ctx, &left, &right),
        )
        .unwrap();
        let kind = PolynomialKind::Canonical { modulus };
        let descriptor = LinearMapDescriptor::new(
            vec![kind; 2],
            kind,
            vec![[1; D], [-2; D]],
            core::array::from_fn(|i| i as i64 % 11 - 5),
        )
        .unwrap();
        audit!(
            "pq_linear_map_trace_parity",
            LinearMapAir::new(descriptor),
            256,
            vec![LinearMapInput::Canonical(a), LinearMapInput::Canonical(b)]
        );
    }
    audit!(
        "pq_permutation_trace_parity",
        PermutationAir::new(PermutationKind::AutomorphismQ),
        256,
        PermutationInput::Canonical(core::array::from_fn(|i| (i as u64 * 7919) % Q))
    );
    audit!(
        "pq_inverse_challenge_trace_parity",
        PermutationAir::new(PermutationKind::InverseChallenge),
        256,
        PermutationInput::Signed(core::array::from_fn(|i| [-1, 0, 1][i % 3]))
    );
    let signed = PolynomialKind::Signed { bound: 565 };
    let descriptor = LinearMapDescriptor::new(
        vec![signed; 2],
        PolynomialKind::Signed { bound: 1130 },
        vec![[1; D], [-1; D]],
        [0; D],
    )
    .unwrap();
    audit!(
        "pq_signed_linear_map_trace_parity",
        LinearMapAir::new(descriptor),
        256,
        vec![
            LinearMapInput::Signed([565; D]),
            LinearMapInput::Signed([-565; D])
        ]
    );
    for bound in [6_825_771, 1_137_628] {
        let air = GBoundAir::new(bound).unwrap();
        let mut f = [0; D];
        f[0] = 1;
        f[255] = -1;
        let mut x = [0; D];
        x[1] = 1;
        let expected = air.generate(&f, &x).unwrap();
        audit_generated_trace(
            "pq_g_bound_trace_parity",
            crate::g_bound_air::HEIGHT,
            crate::g_bound_air::WIDTH,
            8,
            1 << 30,
            &expected.trace.values,
            &expected.public_values,
            |ctx| air.generate_gpu(ctx, &f, &x),
        )
        .unwrap();
    }
    drop(session);
}
