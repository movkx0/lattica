use super::*;
use crate::{
    permutation_air::{PermutationAir, PermutationInput, PermutationKind},
    poly_air::MulAir,
};
use lattica_prover_p3::{
    block_v2::native_gpu::{
        operations_arithmetic::{ArithmeticOperationSpec, CanonicalOperation, SignedOperation},
        with_operations,
    },
    proving::{Backend, Policy, Request, Stage},
};

#[test]
#[ignore = "real GPU raw arithmetic parity; release build, explicit environment, exclusive bounded OpenCL session"]
fn native_gpu_raw_arithmetic_matches_independent_cpu_and_rejects_invalid_inputs() {
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
    let signed: [i64; D] =
        core::array::from_fn(|i| [i64::MIN, i64::MAX, -565, -1, 0, 1, 565][i % 7]);
    let (_, report) = with_operations(1 << 20, request, |ctx| {
        for modulus in [Q, QHAT] {
            let left: [u64; D] = core::array::from_fn(|i| {
                [0, 1, modulus - 1, modulus / 2, (i as u64 * 7919) % modulus][i % 5]
            });
            let right: [u64; D] = core::array::from_fn(|i| {
                [modulus - 1, modulus / 2, 1, 0, (i as u64 * 3571) % modulus][i % 5]
            });
            let pair: Vec<_> = left.into_iter().chain(right).collect();
            for operation in [
                CanonicalOperation::Add,
                CanonicalOperation::Subtract,
                CanonicalOperation::Montgomery,
            ] {
                let spec = ArithmeticOperationSpec::canonical(operation, D, modulus)?;
                let result = ctx.arithmetic_output(&spec, &pair)?;
                let expected: Vec<_> = left
                    .iter()
                    .zip(right)
                    .map(|(&a, b)| match operation {
                        CanonicalOperation::Add => arithmetic::add(a, b, modulus),
                        CanonicalOperation::Subtract => arithmetic::sub(a, b, modulus),
                        CanonicalOperation::Montgomery => arithmetic::mont(a, b, modulus),
                    })
                    .collect();
                assert_eq!(result, expected, "scalar {operation:?}, modulus {modulus}");
            }
            let conversion = ArithmeticOperationSpec::signed_to_canonical(D, modulus)?;
            assert_eq!(
                ctx.arithmetic_output(&conversion, &signed.map(|v| v as u64))?,
                signed.map(|v| arithmetic::signed(v, modulus))
            );
            let inputs = [signed, signed.map(|v| v / 2), [0; D]];
            assert_eq!(
                NttAir::new(modulus, 3)
                    .unwrap()
                    .evaluate_gpu_operations(ctx, &inputs)?,
                inputs.map(|p| arithmetic::ntt(&p, modulus))
            );
            let left = [left, right, left];
            let right = [right, left[0], right];
            assert_eq!(
                MulAir::new(modulus, 3)
                    .unwrap()
                    .evaluate_gpu_operations(ctx, &left, &right)?,
                core::array::from_fn::<_, 3, _>(|i| arithmetic::mul(&left[i], &right[i], modulus))
            );
        }
        let left: [i64; 6] = [i64::MIN, i64::MAX, -1, 0, 1, -565];
        let right: [i64; 6] = [0, 0, -1, 0, -565, 565];
        let pair: Vec<_> = left.into_iter().chain(right).map(|v| v as u64).collect();
        let spec = ArithmeticOperationSpec::signed(SignedOperation::Subtract, left.len())?;
        assert_eq!(
            ctx.arithmetic_output(&spec, &pair)?,
            left.iter()
                .zip(right)
                .map(|(&a, b)| (a - b) as u64)
                .collect::<Vec<_>>()
        );
        let values: [i64; 6] = [i64::MAX, i64::MIN + 1, -565, -1, 0, 565];
        let spec = ArithmeticOperationSpec::signed(SignedOperation::Negate, values.len())?;
        assert_eq!(
            ctx.arithmetic_output(&spec, &values.map(|v| v as u64))?,
            values.map(|v| (-v) as u64)
        );
        let canonical: [u64; D] = core::array::from_fn(|i| (i as u64 * 7919) % Q);
        let result = PermutationAir::new(PermutationKind::AutomorphismQ)
            .evaluate_gpu_operations(ctx, &PermutationInput::Canonical(canonical))?;
        match result {
            PermutationInput::Canonical(actual) => assert_eq!(actual, arithmetic::aut(&canonical)),
            _ => panic!("wrong raw automorphism kind"),
        }
        let challenge: [i64; D] = core::array::from_fn(|i| [-1, 0, 1][i % 3]);
        let result = PermutationAir::new(PermutationKind::InverseChallenge)
            .evaluate_gpu_operations(ctx, &PermutationInput::Signed(challenge))?;
        match result {
            PermutationInput::Signed(actual) => {
                assert_eq!(actual, arithmetic::inverse_aut(&challenge))
            }
            _ => panic!("wrong raw signed permutation kind"),
        }
        Ok(())
    })
    .unwrap();
    assert!(report.succeeded && report.stage_coverage_complete);
    assert_eq!(report.observation_errors, 0);
    assert!(report.components.is_empty());
    assert!(report.observations.iter().any(|o| {
        o.stage == Stage::WitnessTrace
            && o.backend == Backend::OpenCl
            && o.completed_calls > 0
            && o.device_calls > 0
            && o.calls == o.completed_calls
    }));

    // Each failed operation poisons its own session. Even a callback that
    // deliberately ignores the returned error must not produce success.
    for (spec, raw) in [
        (
            ArithmeticOperationSpec::canonical(CanonicalOperation::Add, 1, Q).unwrap(),
            vec![Q, 0],
        ),
        (
            ArithmeticOperationSpec::canonical(CanonicalOperation::Montgomery, 1, QHAT).unwrap(),
            vec![0, QHAT],
        ),
        (
            ArithmeticOperationSpec::signed(SignedOperation::Negate, 1).unwrap(),
            vec![i64::MIN as u64],
        ),
        (
            ArithmeticOperationSpec::signed(SignedOperation::Subtract, 1).unwrap(),
            vec![i64::MIN as u64, 1],
        ),
        (
            ArithmeticOperationSpec::signed(SignedOperation::Subtract, 1).unwrap(),
            vec![i64::MAX as u64, (-1i64) as u64],
        ),
        (
            ArithmeticOperationSpec::signed_to_canonical(2, Q).unwrap(),
            vec![0],
        ),
    ] {
        assert!(with_operations(1 << 20, request, |ctx| {
            assert!(ctx.arithmetic_output(&spec, &raw).is_err());
            Ok(())
        })
        .is_err());
    }
    let spec = ArithmeticOperationSpec::canonical(CanonicalOperation::Add, 1, Q).unwrap();
    assert!(with_operations(8, request, |ctx| {
        assert!(ctx.admit_arithmetic_operation(&spec).is_err());
        Ok(())
    })
    .is_err());
    // Operation-only tests do not claim completed native commitments.
    drop(session);
}
