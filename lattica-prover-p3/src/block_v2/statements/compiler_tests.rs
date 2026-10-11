use super::*;
use crate::block_v2::machine::{compiler_constants::Constants, ProgramBuilder};
use p3_dft::{Radix2DitParallel, TwoAdicSubgroupDft};
use p3_field::{Field, PrimeCharacteristicRing, TwoAdicField};
use p3_matrix::dense::RowMajorMatrix;

fn arithmetic_conformance(constants: Constants<'_>, largest_period: usize) {
    for log in 0..=32 {
        assert_eq!(
            constants.inverse_generator(log).unwrap() * Val::two_adic_generator(log),
            Val::ONE
        );
    }
    for (first, last) in [
        (0, 0),
        (0, 6),
        (1, 12),
        (37, 100),
        (0xffff_fffe_ffff_ffc1, 0xffff_ffff_0000_0000),
    ] {
        let mut inverses = vec![Val::ZERO; (last - first + 1) as usize];
        constants
            .selectors_into(first, last, &mut inverses)
            .unwrap();
        for (i, inverse) in (first..=last).zip(inverses) {
            let denominator = (first..=last)
                .filter(|&j| i != j)
                .map(|j| Val::from_u64(i) - Val::from_u64(j))
                .product::<Val>();
            assert_eq!(denominator * inverse, Val::ONE);
        }
    }
    for n in [1, 2, 8, 64, largest_period] {
        let column: Vec<_> = (0..n)
            .map(|i| Val::from_u64((i as u64).wrapping_mul(0xf123_4567_89ab_cdef)))
            .collect();
        let expected =
            Radix2DitParallel::default().idft_batch(RowMajorMatrix::new(column.clone(), 1));
        let mut coefficients = vec![Val::ZERO; n];
        constants
            .periodic_into(&column, (n.ilog2() as usize).max(12), &mut coefficients)
            .unwrap();
        assert_eq!(coefficients, expected.values);
    }
    for log in [0, 1, 3, 12, 27] {
        for chunks in [1, 2, 4, 8, 16, 32] {
            let mut values = vec![Val::ZERO; chunks + chunks * chunks];
            constants.quotient_into(chunks, log, &mut values).unwrap();
            let (inverse_shifts, normalization) = values.split_at(chunks);
            let g = Val::two_adic_generator(log + chunks.ilog2() as usize);
            let shifts: Vec<_> = (0..chunks)
                .map(|i| Val::GENERATOR * g.exp_u64(i as u64))
                .collect();
            for i in 0..chunks {
                assert_eq!(shifts[i] * inverse_shifts[i], Val::ONE);
                for j in 0..chunks {
                    if i == j {
                        assert_eq!(normalization[i * chunks + j], Val::ZERO);
                    } else {
                        let denominator = (shifts[i] / shifts[j]).exp_u64(1 << log) - Val::ONE;
                        assert_eq!(denominator * normalization[i * chunks + j], Val::ONE);
                    }
                }
            }
        }
    }
}

#[test]
fn cpu_compiler_constants_satisfy_interpolation_and_normalization_identities() {
    arithmetic_conformance(Constants::cpu(), 128);
}

#[test]
fn compiler_constant_geometry_rejects_without_panicking() {
    let constants = Constants::cpu();
    rejected_output_storage(constants);
    let mut out = [Val::ONE; 1];
    assert!(constants.inverse_generator(usize::MAX).is_err());
    assert!(constants.selectors_into(3, 2, &mut out).is_err());
    assert!(constants.selectors_into(0, u64::MAX, &mut out).is_err());
    assert!(constants.periodic_into(&[], 3, &mut out).is_err());
    assert!(constants
        .periodic_into(&[Val::ONE; 3], 3, &mut out)
        .is_err());
    assert!(constants
        .periodic_into(&[Val::ONE; 2], 0, &mut out)
        .is_err());
    assert!(constants
        .periodic_into(&[Val::ONE], usize::MAX, &mut out)
        .is_err());
    for (chunks, log) in [(0, 0), (3, 2), (2, 32), (1, usize::MAX)] {
        assert!(constants.quotient_into(chunks, log, &mut out).is_err());
    }
    assert_eq!(out, [Val::ONE]);
}

fn rejected_output_storage(constants: Constants<'_>) {
    // Both short and long borrowed outputs reject before touching sentinels.
    for count in [0, 1, 3] {
        let mut out = vec![Val::ONE; count];
        assert!(constants.selectors_into(4, 5, &mut out).is_err());
        assert!(constants
            .periodic_into(&[Val::ONE; 2], 1, &mut out)
            .is_err());
        assert!(constants.quotient_into(1, 0, &mut out).is_err());
        #[cfg(any(feature = "gpu", feature = "gpu-metal"))]
        if let Constants::Device(session, run) = constants {
            // Exercise the device boundary independently of the outer checks.
            assert!(session
                .compiler_selectors_into(4, 5, &mut out, run)
                .is_err());
            assert!(session
                .compiler_periodic_into(&[Val::ONE; 2], 1, &mut out, run)
                .is_err());
            assert!(session.compiler_quotient_into(1, 0, &mut out, run).is_err());
        }
        assert_eq!(out, vec![Val::ONE; count]);
    }
}

#[test]
fn compiler_constant_tables_preserve_exact_subgroup_programs() {
    for log in 0..=32 {
        for len in 0..=log {
            let mut reference = ProgramBuilder::new(0).unwrap();
            let bits: Vec<_> = (0..len).map(|_| reference.input()).collect();
            let root = Val::two_adic_generator(log);
            let one = reference.constant(Val::ONE);
            let mut point = one;
            for (i, &bit) in bits.iter().enumerate() {
                let factor = reference.constant(root.exp_u64(1 << (len - 1 - i)));
                let selected = reference.select(bit, one, factor);
                point = reference.mul(point, selected);
            }
            let mut selected = ProgramBuilder::new(0).unwrap();
            let bits: Vec<_> = (0..len).map(|_| selected.input()).collect();
            assert_eq!(point, selected.subgroup_point(&bits, log).unwrap());
            assert!(reference.finish(None).unwrap() == selected.finish(None).unwrap());
        }
    }
    assert_eq!(Val::new(0x7fff_ffff_8000_0001) * Val::TWO, Val::ONE);
    assert_eq!(Val::new(0xffff_ffff_0000_0000) + Val::ONE, Val::ZERO);
}

#[cfg(feature = "gpu")]
#[test]
#[ignore = "requires selected GPU witness backend and <=3 GiB zero-swap service"]
fn gpu_compiler_constants_match_independent_identities_and_reject_before_upload() {
    use crate::block_v2::gpu_hash;
    let _shutdown = gpu_hash::TestShutdownGuard;
    super::tests::initialize();
    let mut expected_calls = 72 + 32 * 32;
    let (result, report) = operate_reported(
        Request::compatible(),
        "compiler_constant_conformance",
        Stage::Preprocessing,
        |derive| {
            let constants = derive.compiler_constants();
            arithmetic_conformance(constants, 1 << 16);
            use p3_air::BaseAir;
            for column in crate::joinsplit_air::JoinSplitAir
                .periodic_columns()
                .into_iter()
                .chain(crate::htlc_air::HtlcAir.periodic_columns())
            {
                let expected =
                    Radix2DitParallel::default().idft_batch(RowMajorMatrix::new(column.clone(), 1));
                let log = column.len().ilog2() as usize;
                expected_calls += (column.len().div_ceil(2048).pow(2)) as u64;
                let mut coefficients = vec![Val::ZERO; column.len()];
                constants
                    .periodic_into(&column, log, &mut coefficients)
                    .unwrap();
                assert_eq!(coefficients, expected.values);
            }
            let baseline = gpu_hash::report("compiler constants admission baseline").unwrap();
            rejected_output_storage(constants);
            assert!(constants
                .selectors_into(0, 64, &mut [Val::ONE; 65])
                .is_err());
            assert!(constants
                .periodic_into(&vec![Val::ONE; 1 << 17], 17, &mut vec![Val::ONE; 1 << 17])
                .is_err());
            assert!(constants
                .quotient_into(64, 12, &mut [Val::ONE; 64 + 64 * 64])
                .is_err());
            assert!(constants
                .quotient_into(32, 28, &mut [Val::ONE; 32 + 32 * 32])
                .is_err());
            let after = gpu_hash::report("compiler constants after admission").unwrap();
            assert_eq!(baseline.allocations, after.allocations);
            assert_eq!(baseline.uploaded_bytes, after.uploaded_bytes);
            assert_eq!(baseline.downloaded_bytes, after.downloaded_bytes);
            Err::<(), Error>("injected failure after compiler arithmetic".into())
        },
    )
    .unwrap();
    assert_eq!(
        result.unwrap_err().to_string(),
        "injected failure after compiler arithmetic"
    );
    assert!(!report.succeeded && !report.stage_coverage_complete);
    assert_eq!(report.observations.len(), 1);
    let observation = &report.observations[0];
    assert_eq!(observation.stage, Stage::Preprocessing);
    assert_eq!(observation.backend, Backend::OpenCl);
    assert_eq!(observation.calls, observation.completed_calls);
    assert_eq!(observation.completed_calls, expected_calls);
    assert!(observation.device_ns > 0);
    assert_eq!(observation.inclusive_ns, 0);
}

#[cfg(feature = "gpu")]
fn caps<const N: usize>() -> super::super::machine::programs::Caps<N> {
    core::array::from_fn(|_| vec![[Val::ZERO; 4]; 1 << profile::CAP_HEIGHT])
}

#[cfg(feature = "gpu")]
fn same_program(
    selected: super::super::machine::programs::Compiled,
    reference: super::super::machine::programs::Compiled,
) {
    assert!(
        selected.program == reference.program,
        "compiler program changed"
    );
    assert!(
        selected.witness == reference.witness,
        "compiler witness changed"
    );
}

#[cfg(feature = "gpu")]
#[test]
#[ignore = "requires selected GPU witness backend and <=3 GiB zero-swap service"]
fn gpu_compiler_constants_preserve_merge_and_finalizer_programs() {
    use crate::block_v2::{
        gpu_hash,
        machine::{programs, typed_finalizer, typed_pairs, verifier::template},
    };
    let _shutdown = gpu_hash::TestShutdownGuard;
    super::tests::initialize();
    let height = 64;
    // Shape templates only: these checks compare compilers, not proof validity.
    let proof = template::batch(&programs::shape(height).unwrap()).unwrap();
    let public = [Val::ZERO; PUBLIC_VALUES];
    fn merged<const N: usize>(
        height: usize,
        proof: &p3_batch_stark::BatchProof<profile::Config>,
        public: &[Val; PUBLIC_VALUES],
    ) {
        compile(height, N, |prefix| {
            same_program(
                programs::merge_with_registry(
                    height,
                    &caps::<N>(),
                    [public; 2],
                    [proof; 2],
                    Some(prefix),
                )?,
                programs::merge(height, &caps::<N>(), [public; 2], [proof; 2])?,
            );
            Ok(())
        })
        .unwrap();
    }
    merged::<3>(height, &proof, &public);
    merged::<5>(height, &proof, &public);
    merged::<6>(height, &proof, &public);
    merged::<12>(height, &proof, &public);
    compile(height, 6, |prefix| {
        same_program(
            typed_finalizer::compile_with_registry(height, &caps(), &public, &proof, Some(prefix))?,
            typed_finalizer::compile(height, &caps(), &public, &proof)?,
        );
        Ok(())
    })
    .unwrap();
    compile(height, 12, |prefix| {
        same_program(
            typed_pairs::finalize_with_registry(height, &caps(), &public, &proof, Some(prefix))?,
            typed_pairs::finalize(height, &caps(), &public, &proof)?,
        );
        Ok(())
    })
    .unwrap();
}

#[cfg(feature = "gpu")]
#[test]
#[ignore = "requires selected GPU witness backend and <=3 GiB zero-swap service"]
fn gpu_compiler_constants_preserve_periodic_uni_verifier_and_tamper_rejection() {
    use crate::block_v2::{
        gpu_hash,
        machine::{
            programs::Compiled,
            verifier::{uni, CompileError, ProofInputs},
        },
    };
    use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
    struct PeriodicCounter;
    impl crate::block_v2::machine::verifier::periodic::Source for PeriodicCounter {
        fn count(&self) -> usize {
            1
        }
        fn len(&self, index: usize) -> Option<usize> {
            (index == 0).then_some(8)
        }
        fn fill(&self, index: usize, output: &mut [Val]) -> Result<(), CompileError> {
            if index != 0 || output.len() != 8 {
                return Err(CompileError::Shape("test periodic source"));
            }
            for (i, value) in output.iter_mut().enumerate() {
                *value = Val::from_usize(i + 1);
            }
            Ok(())
        }
    }
    impl BaseAir<Val> for PeriodicCounter {
        fn width(&self) -> usize {
            1
        }
        fn num_public_values(&self) -> usize {
            1
        }
        fn num_periodic_columns(&self) -> usize {
            1
        }
        fn periodic_columns(&self) -> Vec<Vec<Val>> {
            vec![(1..=8).map(Val::from_u64).collect()]
        }
    }
    impl<AB: AirBuilder<F = Val>> Air<AB> for PeriodicCounter {
        fn eval(&self, b: &mut AB) {
            let main = b.main();
            let local: AB::Expr = main.current_slice()[0].into();
            let next: AB::Expr = main.next_slice()[0].into();
            let public: AB::Expr = b.public_values()[0].into();
            let periodic: AB::Expr = b.periodic_values()[0].into();
            b.when_first_row().assert_zero(local.clone() - public);
            b.when_transition().assert_zero(next - local - periodic);
        }
    }
    let _shutdown = gpu_hash::TestShutdownGuard;
    super::tests::initialize();
    let public = [Val::from_u64(37)];
    let mut value = public[0];
    let trace = RowMajorMatrix::new(
        (0..16)
            .map(|i| {
                let row = value;
                value += Val::from_usize(i % 8 + 1);
                row
            })
            .collect(),
        1,
    );
    let config = profile::make_config();
    let proof = p3_uni_stark::prove(&config, &PeriodicCounter, trace, &public);
    p3_uni_stark::verify(&config, &PeriodicCounter, &proof, &public).unwrap();
    let compile = |constants: Constants<'_>| {
        let mut b =
            crate::block_v2::machine::program::ScopedProgramBuilder::with_constants(1, constants)
                .unwrap();
        let public = [b.public(0).unwrap()];
        let mut inputs = ProofInputs::default();
        uni::verify_with_constants(
            &mut b,
            &mut inputs,
            &PeriodicCounter,
            16,
            &public,
            &proof,
            constants,
        )
        .unwrap();
        Compiled {
            program: b.finish(None).unwrap(),
            witness: inputs.values,
        }
    };
    let reference = compile(Constants::cpu());
    let (result, report) = operate_reported(
        Request::compatible(),
        "compiler_periodic_verifier",
        Stage::Preprocessing,
        |derive| Ok(compile(derive.compiler_constants())),
    )
    .unwrap();
    let selected = result.unwrap();
    assert!(selected.program == reference.program && selected.witness == reference.witness);
    selected
        .program
        .evaluate(&public, &selected.witness)
        .unwrap();
    let mut tampered = selected.witness.clone();
    tampered[0] += Val::ONE;
    assert!(selected.program.evaluate(&public, &tampered).is_err());
    assert!(report.succeeded && report.stage_coverage_complete);
    assert_eq!(
        report.capabilities.scope(),
        crate::proving::CoverageScope::RegistryCompilation
    );
    assert_eq!(report.observations.len(), 1);
    assert_eq!(report.observations[0].backend, Backend::OpenCl);
    assert!(report.observations[0].completed_calls > 3);
    assert!(report.observations[0].device_ns > 0);
}
