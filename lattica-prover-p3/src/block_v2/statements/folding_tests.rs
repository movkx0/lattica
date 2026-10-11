use super::*;
use crate::block_v2::machine::{
    compiler_constants::Constants,
    program::{Op, ScopedProgramBuilder, Val},
    programs,
    verifier::{CompileError, ProofInputs},
    ExecutionError, Program,
};
use p3_field::{BasedVectorSpace, Field, PrimeCharacteristicRing};

fn arithmetic_program(constants: Constants<'_>) -> Program {
    let mut b = ScopedProgramBuilder::with_constants(1, constants).unwrap();
    let public = b.public(0).unwrap();
    let values = [
        0,
        1,
        2,
        7,
        0xffff_ffff,
        0x8000_0000_0000_0000,
        0xffff_fffe_ffff_ffff,
        0xffff_ffff_0000_0000,
    ]
    .map(Val::new);
    for x in values {
        let a = b.constant(x);
        for y in values {
            let c = b.constant(y);
            let sum = b.add(a, c);
            let product = b.mul(a, c);
            assert_eq!(sum, b.constant(x + y));
            assert_eq!(product, b.constant(x * y));
            // Folded values are interned; repeating operations changes no wires.
            assert_eq!(sum, b.add(a, c));
            assert_eq!(product, b.mul(a, c));
        }
        if let Some(inverse) = x.try_inverse() {
            let result = b.inverse(a);
            assert_eq!(result, b.constant(inverse));
        }
    }
    // Exercise more distinct cubic operands than the entire bounded cache.
    for i in 0..160 {
        let av = [values[i % 8], values[(i / 8) % 8], Val::from_usize(i + 1)];
        let bv = [
            values[(i + 3) % 8],
            Val::from_usize(i + 2),
            values[(i / 8 + 5) % 8],
        ];
        let a = b.ext_constant(av);
        let c = b.ext_constant(bv);
        let x = profile::Challenge::from_basis_coefficients_slice(&av).unwrap();
        let y = profile::Challenge::from_basis_coefficients_slice(&bv).unwrap();
        let expected: [Val; 3] = (x * y).as_basis_coefficients_slice().try_into().unwrap();
        let product = b.ext_mul(a, c);
        assert_eq!(product, b.ext_constant(expected));
        assert_eq!(product, b.ext_mul(a, c));
        let expected: [Val; 3] = x
            .inverse()
            .as_basis_coefficients_slice()
            .try_into()
            .unwrap();
        let inverse = b.ext_inverse(a);
        assert_eq!(inverse, b.ext_constant(expected));
        assert_eq!(inverse, b.ext_inverse(a));
        // Preserve the base-scaling shortcut and zero/one simplifications.
        let scale = b.ext_constant([values[i % 8], Val::ZERO, Val::ZERO]);
        let scaled = b.ext_mul(a, scale);
        assert_eq!(scaled, b.ext_constant(av.map(|v| v * values[i % 8])));
    }
    let zero = b.constant(Val::ZERO);
    let one = b.constant(Val::ONE);
    assert_eq!(b.add(public, zero), public);
    assert_eq!(b.mul(public, one), public);
    assert_eq!(b.mul(public, zero), zero);
    b.assert_equal(public, one);
    b.finish(None).unwrap()
}

fn zero_inverse_program(constants: Constants<'_>) -> Program {
    let mut b = ScopedProgramBuilder::with_constants(0, constants).unwrap();
    let zero = b.constant(Val::ZERO);
    let base = b.inverse(zero);
    let cubic = b.ext_inverse([zero; 3]);
    assert_eq!(base, b.inverse(zero));
    assert_eq!(cubic, b.ext_inverse([zero; 3]));
    let program = b.finish(None).unwrap();
    assert_eq!(
        program
            .operations
            .iter()
            .filter(|op| matches!(op, Op::Inverse { .. }))
            .count(),
        1
    );
    assert_eq!(
        program
            .operations
            .iter()
            .filter(|op| matches!(op, Op::CubicInverse { .. }))
            .count(),
        1
    );
    assert_eq!(
        program.evaluate(&[], &[]).unwrap_err(),
        ExecutionError::Unsatisfied
    );
    program
}

#[test]
fn cpu_folding_preserves_arithmetic_interning_and_zero_inverse_instructions() {
    let program = arithmetic_program(Constants::cpu());
    program.evaluate(&[Val::ONE], &[]).unwrap();
    assert_eq!(
        program.evaluate(&[Val::ZERO], &[]).unwrap_err(),
        ExecutionError::Unsatisfied
    );
    zero_inverse_program(Constants::cpu());
}

#[test]
fn failed_folding_rejects_program_and_preserves_backend_cause() {
    use crate::proving::{Capabilities, Policy, Profile};
    let mut capabilities = Capabilities::cpu(Profile::BlockV2Cubic, true, true);
    for stage in Stage::ARITHMETIC {
        capabilities.set(stage, Backend::OpenCl);
    }
    let run = Run::new(
        "fold_rejected",
        Request {
            policy: Policy::GpuRequired,
            emit_report: false,
        },
        capabilities,
    )
    .unwrap();
    let builder = || {
        let mut b = ScopedProgramBuilder::with_constants(0, Constants::cpu_reported(&run)).unwrap();
        let a = b.constant(Val::ONE);
        b.add(a, a);
        let first_error = b.folding_failure().unwrap().clone();
        b.mul(a, a);
        b.inverse(a);
        b.ext_inverse([a; 3]);
        b.ext_mul([a; 3], [a; 3]);
        assert_eq!(b.folding_failure(), Some(&first_error));
        b
    };
    assert_eq!(
        builder().finish(Some(0)).err(),
        Some(ExecutionError::CompilerBackend)
    );
    let b = builder();
    let expected = b.folding_failure().unwrap().clone();
    assert!(matches!(expected, CompileError::Backend(_)));
    assert_eq!(
        programs::finish(b, ProofInputs::default()).err(),
        Some(expected)
    );
    assert!(run.finish(false).unwrap().observations.is_empty());
}

#[cfg(feature = "gpu")]
#[test]
#[ignore = "requires selected GPU witness backend and <=3 GiB zero-swap service"]
fn gpu_folding_preserves_programs_and_observations_after_failure() {
    use crate::block_v2::gpu_hash;
    let _shutdown = gpu_hash::TestShutdownGuard;
    super::tests::initialize();
    let reference = arithmetic_program(Constants::cpu());
    let zero_reference = zero_inverse_program(Constants::cpu());
    let (result, report) = operate_reported(
        Request::compatible(),
        "compiler_folding",
        Stage::Preprocessing,
        |derive| {
            assert!(arithmetic_program(derive.compiler_constants()) == reference);
            assert!(zero_inverse_program(derive.compiler_constants()) == zero_reference);
            Err::<(), Error>("injected failure after completed folding".into())
        },
    )
    .unwrap();
    assert_eq!(
        result.unwrap_err().to_string(),
        "injected failure after completed folding"
    );
    assert!(!report.succeeded && !report.stage_coverage_complete);
    assert_eq!(report.observations.len(), 1);
    let observation = &report.observations[0];
    assert_eq!(observation.backend, Backend::OpenCl);
    assert_eq!(observation.stage, Stage::Preprocessing);
    assert_eq!(observation.completed_calls, observation.calls);
    assert!(observation.completed_calls > 320 && observation.device_ns > 0);
    assert_eq!(observation.inclusive_ns, 0);
}

#[cfg(feature = "gpu")]
#[test]
#[ignore = "requires selected GPU witness backend and <=3 GiB zero-swap service"]
fn gpu_folding_cache_and_policy_rejection_do_not_launch_extra_work() {
    use crate::block_v2::gpu_hash::{self, device::DeviceSession};
    use crate::proving::{Capabilities, Policy, Profile};
    let _shutdown = gpu_hash::TestShutdownGuard;
    super::tests::initialize();
    let (result, report) = operate_reported(
        Request::compatible(),
        "compiler_fold_cache",
        Stage::Preprocessing,
        |derive| {
            let mut b =
                ScopedProgramBuilder::with_constants(0, derive.compiler_constants()).unwrap();
            let a = b.constant(Val::from_u64(17));
            let c = b.constant(Val::from_u64(29));
            let out = b.add(a, c);
            let before = gpu_hash::report("compiler folding snapshot").unwrap();
            for _ in 0..100 {
                assert_eq!(b.add(a, c), out);
            }
            let after = gpu_hash::report("compiler folding snapshot").unwrap();
            assert_eq!(before.allocations, after.allocations);
            assert_eq!(before.uploaded_bytes, after.uploaded_bytes);
            assert_eq!(before.downloaded_bytes, after.downloaded_bytes);
            b.finish(None).unwrap();
            Ok(())
        },
    )
    .unwrap();
    result.unwrap();
    assert_eq!(report.observations.len(), 1);
    assert_eq!(report.observations[0].completed_calls, 1);
    let session = DeviceSession::new().unwrap();
    let run = Run::new(
        "compiler_fold_rejected",
        Request {
            policy: Policy::CpuRequired,
            emit_report: false,
        },
        Capabilities::cpu(Profile::BlockV2Cubic, true, true),
    )
    .unwrap();
    let before = gpu_hash::report("compiler folding snapshot").unwrap();
    assert!(session.compiler_fold([0; 6], 5, &run).is_err());
    assert!(session.compiler_fold([u64::MAX; 6], 0, &run).is_err());
    let mut b = ScopedProgramBuilder::with_constants(0, Constants::device(&session, &run)).unwrap();
    let a = b.constant(Val::ONE);
    b.add(a, a);
    b.mul(a, a);
    b.ext_mul([a; 3], [a; 3]);
    b.ext_inverse([a; 3]);
    assert_eq!(b.finish(None).err(), Some(ExecutionError::CompilerBackend));
    let after = gpu_hash::report("compiler folding snapshot").unwrap();
    assert_eq!(before.allocations, after.allocations);
    assert_eq!(before.uploaded_bytes, after.uploaded_bytes);
    assert!(run.finish(false).unwrap().observations.is_empty());
}
