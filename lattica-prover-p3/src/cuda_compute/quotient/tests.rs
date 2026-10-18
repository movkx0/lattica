use super::*;
use crate::{
    block_v2::{
        pcs_field::FriExtension,
        quotient_program::test_support::{constant, program, words},
    },
    config::{MyCompress, MyHash, Val},
    cuda_compute::{Commitments, Transforms},
};
use p3_air::symbolic::{AirLayout, SymbolicExpressionExt};
use p3_field::{Algebra, Field, PrimeCharacteristicRing, PrimeField64, TwoAdicField};
use p3_symmetric::{CryptographicHasher, PseudoCompressionFunction};

fn runtime(managed: usize, allocation: usize) -> Runtime {
    Runtime::new(
        &std::env::var("LATTICA_GPU_DEVICE_UUID").unwrap(),
        Limits {
            managed_bytes: managed,
            max_allocation_bytes: allocation,
            ..Limits::default()
        },
    )
    .unwrap()
}

fn simple(extension: Extension, iterations: usize) -> Program {
    let mut instructions = vec![1, 0, 0, 0, 0, 0, 1, 7, 0, 0];
    for _ in 0..iterations {
        instructions.extend_from_slice(&[8, 0, 0, 1, 0, 10, 0, 0, 0, 0]);
    }
    instructions.extend_from_slice(&[16, 0, 0, 0, 0]);
    Program {
        extension,
        instructions,
        registers: 2,
        constraints: 1,
        layout: AirLayout {
            main_width: 1,
            ..AirLayout::default()
        },
        row_words: 2,
        parameter_words: 0,
    }
}

fn matrix(
    runtime: &Runtime,
    log: u32,
    width: usize,
    extension: Extension,
    order: RowOrder,
    shift: u64,
    seed: u64,
) -> (Matrix, Vec<Val>) {
    let spec = MatrixSpec::new(log, width, extension, order, shift).unwrap();
    let natural: Vec<u64> = (0..spec.words())
        .map(|i| {
            (i as u64)
                .wrapping_mul(0xffff_ffff_0000_0000)
                .wrapping_add(seed)
        })
        .collect();
    let w = width * extension.degree();
    let raw: Vec<u64> = (0..spec.rows())
        .flat_map(|row| {
            let at = if order == RowOrder::BitReversed && log != 0 {
                row.reverse_bits() >> (usize::BITS - log)
            } else {
                row
            };
            natural[at * w..(at + 1) * w].iter().copied()
        })
        .collect();
    (
        runtime.upload_matrix(spec, &raw).unwrap(),
        natural.into_iter().map(Val::from_u64).collect(),
    )
}

fn scalars(runtime: &Runtime, words: &[u64]) -> Buffer {
    let buffer = runtime.allocate(words.len()).unwrap();
    buffer.write(0, words).unwrap();
    buffer
}

#[test]
fn quotient_planner_charges_output_and_complete_tile_at_exact_boundary() {
    let p = simple(Extension::Cubic, 1);
    let limits = Limits {
        managed_bytes: 293,
        max_allocation_bytes: 192,
        ..Limits::default()
    };
    let plan = Plan::new(&p, 8, 5, limits).unwrap();
    assert_eq!(plan.rows, 1);
    assert_eq!(plan.peak_bytes, 293);
    assert_eq!(
        (
            plan.output_words,
            plan.weight_words,
            plan.input_words,
            plan.scratch_words
        ),
        (24, 3, 2, 6)
    );
    assert!(Plan::new(
        &p,
        8,
        5,
        Limits {
            managed_bytes: 292,
            ..limits
        }
    )
    .is_err());
    assert!(Plan::new(
        &p,
        8,
        5,
        Limits {
            max_allocation_bytes: 191,
            ..limits
        }
    )
    .is_err());
    for height in [0, 3, usize::MAX] {
        assert!(Plan::new(&p, height, 0, limits).is_err());
    }
    assert!(Plan::new(&p, 8, usize::MAX, limits).is_err());
    let limits = Limits {
        managed_bytes: 256 << 20,
        max_allocation_bytes: 128 << 20,
        ..Limits::default()
    };
    let plan = Plan::new(&p, 1 << 20, 0, limits).unwrap();
    assert_eq!(plan.rows, MAX_TILE_ROWS);
    assert!((plan.input_words + plan.scratch_words + plan.weight_words + 1) * 8 <= WORKSPACE_BYTES);
}

#[test]
fn shared_quotient_validation_rejects_bad_bounds_lifetimes_and_fold_order() {
    for extension in [Extension::Quadratic, Extension::Cubic] {
        simple(extension, 70).validate_quotient().unwrap();
        for code in [
            vec![],
            vec![0, 0, 1, 0],
            vec![18, 0, 0, 0, 0],
            vec![1, 0, 2, 0, 0],
            vec![2, 0, 1, 0, 0],
            vec![3, 0, 0, 0, 0],
            vec![4, 0, u64::MAX, 0, 0],
            vec![0, 2, 1, 0, 0],
            vec![8, 0, 0, 1, 0],
            vec![16, 0, 0, 0, 0],
            vec![0, 0, 1, 0, 0, 16, 0, 0, 1, 0],
            vec![0, 0, 1, 0, 0, 16, 0, 0, 0, 0, 16, 0, 0, 0, 0],
        ] {
            let mut p = simple(extension, 1);
            p.instructions = code;
            assert!(p.validate_quotient().is_err());
        }
        let mut p = simple(extension, 1);
        p.row_words = 1;
        assert!(p.validate_quotient().is_err());
        let mut p = simple(extension, 1);
        p.registers = usize::MAX;
        assert!(p.validate_quotient().is_err());
        let mut p = simple(extension, 1);
        p.constraints += 1;
        assert!(p.validate_quotient().is_err());
    }
    program::<crate::config::Challenge>()
        .validate_quotient()
        .unwrap();
    program::<crate::block_v2::profile::Challenge>()
        .validate_quotient()
        .unwrap();
}

fn conformance<F: FriExtension>()
where
    SymbolicExpressionExt<Val, F>: Algebra<F>,
{
    let runtime = runtime(64 << 20, 16 << 20);
    let evaluator = Quotients::new(&runtime).unwrap();
    let commits = Commitments::new(&runtime).unwrap();
    let p = Arc::new(program::<F>());
    let generic = evaluator
        .prepare(p.clone(), Specialization::Generic)
        .unwrap();
    let specialized = evaluator.prepare(p, Specialization::Prefer).unwrap();
    assert!(specialized.specialized.is_some());
    eprintln!(
        "cuda_quotient_specialized degree={} source_bytes={} local_bytes={} preparation_ns={}",
        F::DIMENSION,
        specialized.source_bytes,
        specialized.local_bytes,
        specialized.preparation_ns
    );
    let perm = p3_goldilocks::default_goldilocks_poseidon2_8();
    let hash = MyHash::new(perm.clone());
    let compress = MyCompress::new(perm);
    for (log_trace, log_quotient, shift) in [(0, 0, 7), (0, 3, 7), (3, 6, 11), (9, 15, 7)] {
        let (main, main_values) = matrix(
            &runtime,
            log_quotient,
            3,
            Extension::Base,
            RowOrder::BitReversed,
            shift,
            17,
        );
        let (pre, pre_values) = matrix(
            &runtime,
            log_quotient,
            2,
            Extension::Base,
            RowOrder::Natural,
            shift,
            19,
        );
        let (permutation, permutation_values) = matrix(
            &runtime,
            log_quotient,
            2,
            F::DEVICE_EXTENSION,
            RowOrder::BitReversed,
            shift,
            23,
        );
        let inputs = QuotientInputs {
            main: Some(&main),
            preprocessed: Some(&pre),
            permutation: Some(&permutation),
        };
        let public = [Val::new(31), Val::new(0xffff_ffff_0000_0000)];
        let challenges = [
            constant::<F>(),
            F::from_basis_coefficients_fn(|i| Val::new(17 + i as u64)),
        ];
        let terminal = F::from_basis_coefficients_fn(|i| Val::new(29 + i as u64));
        let parameter_words: Vec<u64> = public
            .iter()
            .map(PrimeField64::as_canonical_u64)
            .chain(challenges.into_iter().chain([terminal]).flat_map(words))
            .collect();
        let parameters = scalars(&runtime, &parameter_words);
        for alpha in [F::ZERO, F::ONE, constant::<F>()] {
            let alpha_buffer = scalars(&runtime, &words(alpha));
            let root = Val::two_adic_generator(log_quotient as usize);
            let last = Val::two_adic_generator(log_trace as usize).inverse();
            let height = 1usize << log_quotient;
            let expected: Vec<F> = (0..height)
                .map(|row| {
                    let next = (row + (1usize << (log_quotient - log_trace))) % height;
                    let m = &main_values[row * 3..row * 3 + 3];
                    let n = &main_values[next * 3..next * 3 + 3];
                    let pr = &pre_values[row * 2..row * 2 + 2];
                    let pn = &pre_values[next * 2..next * 2 + 2];
                    let x = Val::new(shift) * root.exp_u64(row as u64);
                    let z = x.exp_power_of_2(log_trace as usize) - Val::ONE;
                    let q_at = |r: usize, col: usize| {
                        F::from_basis_coefficients_fn(|i| {
                            permutation_values[(r * 2 + col) * F::DIMENSION + i]
                        })
                    };
                    [
                        F::from(-(m[0] + public[0]) * (n[1] - pn[0])),
                        -(q_at(next, 0) + challenges[0])
                            * (q_at(row, 1) - terminal + constant::<F>()),
                        F::from(z / (x - Val::ONE) * (pr[0] - m[2])),
                        (challenges[1] * q_at(row, 0) + constant::<F>()) * (z / (x - last)),
                        F::from((x - last) * (n[0] - m[1])),
                        (q_at(next, 1) + terminal) * (challenges[0] + F::from(m[0])),
                        F::from(public[1] - n[2]),
                    ]
                    .into_iter()
                    .fold(F::ZERO, |acc, constraint| acc * alpha + constraint)
                        / F::from(z)
                })
                .collect();
            assert!(expected.iter().any(|value| *value != F::ZERO));
            let expected_words: Vec<u64> = expected.iter().copied().flat_map(words).collect();
            let mut layer: Vec<[Val; 4]> = expected
                .iter()
                .map(|value| hash.hash_iter(value.as_basis_coefficients_slice().iter().copied()))
                .collect();
            while layer.len() > 1 {
                layer = layer
                    .chunks_exact(2)
                    .map(|pair| compress.compress([pair[0], pair[1]]))
                    .collect();
            }
            let expected_root: Vec<u64> = layer[0]
                .iter()
                .map(PrimeField64::as_canonical_u64)
                .collect();
            for prepared in [&generic, &specialized] {
                let before = runtime.snapshot();
                let quotient = evaluator
                    .evaluate(
                        prepared,
                        log_trace,
                        inputs,
                        &alpha_buffer,
                        Some(&parameters),
                    )
                    .unwrap();
                let after = runtime.snapshot();
                assert_eq!(after.uploaded_bytes, before.uploaded_bytes);
                assert_eq!(after.downloaded_bytes - before.downloaded_bytes, 8);
                assert_eq!(after.live_bytes - before.live_bytes, quotient.spec.bytes());
                let before_commit = runtime.snapshot();
                let tree = commits.commit(&[&quotient], 0).unwrap();
                assert_eq!(
                    runtime.snapshot().downloaded_bytes,
                    before_commit.downloaded_bytes
                );
                assert_eq!(
                    runtime.snapshot().uploaded_bytes,
                    before_commit.uploaded_bytes
                );
                assert_eq!(tree.cap(32).unwrap(), expected_root);
                assert_eq!(
                    quotient.read(quotient.spec.bytes()).unwrap(),
                    expected_words,
                    "log_trace={log_trace} log_quotient={log_quotient} specialized={}",
                    prepared.specialized.is_some()
                );
            }
            let before = runtime.snapshot();
            assert!(evaluator
                .evaluate(
                    &generic,
                    log_trace,
                    QuotientInputs {
                        preprocessed: None,
                        ..inputs
                    },
                    &alpha_buffer,
                    Some(&parameters)
                )
                .is_err());
            assert!(evaluator
                .evaluate(&generic, log_trace, inputs, &alpha_buffer, None)
                .is_err());
            assert!(evaluator
                .evaluate(
                    &generic,
                    log_quotient + 1,
                    inputs,
                    &alpha_buffer,
                    Some(&parameters)
                )
                .is_err());
            assert_eq!(runtime.snapshot(), before);
        }
    }
}

#[test]
#[ignore = "requires CUDA and NVRTC; run serially"]
fn cuda_quadratic_quotients_match_cpu_and_feed_resident_commitments() {
    conformance::<crate::config::Challenge>();
}

#[test]
#[ignore = "requires CUDA and NVRTC; run serially"]
fn cuda_cubic_quotients_match_cpu_and_feed_resident_commitments() {
    conformance::<crate::block_v2::profile::Challenge>();
}

#[test]
#[ignore = "requires CUDA and NVRTC; run serially"]
fn cuda_quotient_block_boundaries_fallback_and_invalid_domain() {
    use p3_dft::TwoAdicSubgroupDft;
    use p3_matrix::{dense::RowMajorMatrix, Matrix as _};
    let runtime = runtime(32 << 20, 8 << 20);
    let evaluator = Quotients::new(&runtime).unwrap();
    let transforms = Transforms::new(&runtime).unwrap();
    let (prefix, values) = matrix(&runtime, 3, 1, Extension::Base, RowOrder::Natural, 1, 17);
    let before_lde = runtime.snapshot();
    let main = transforms
        .lde(&prefix, 9, 7, RowOrder::BitReversed)
        .unwrap();
    assert_eq!(
        runtime.snapshot().downloaded_bytes,
        before_lde.downloaded_bytes
    );
    let cpu = crate::config::Dft::default()
        .coset_lde_batch(RowMajorMatrix::new(values, 1), 6, Val::new(7))
        .to_row_major_matrix();
    for extension in [Extension::Quadratic, Extension::Cubic] {
        let alpha = scalars(&runtime, &vec![17; extension.degree()]);
        for (iterations, fallback) in [(31, false), (32, false), (130, false), (130, true)] {
            let mut p = simple(extension, iterations);
            if fallback {
                p.registers = specialize::MAX_REGISTERS + 1;
            }
            let prepared = evaluator
                .prepare(Arc::new(p), Specialization::Prefer)
                .unwrap();
            assert_eq!(prepared.specialized.is_some(), !fallback);
            let inputs = QuotientInputs {
                main: Some(&main),
                preprocessed: None,
                permutation: None,
            };
            let output = evaluator
                .evaluate(&prepared, 3, inputs, &alpha, None)
                .unwrap();
            let words = output.read(output.spec.bytes()).unwrap();
            for row in 0..512 {
                let mut expected = cpu.values[row];
                for _ in 0..iterations {
                    expected = (expected + Val::new(7)).square();
                }
                let x = Val::new(7) * Val::two_adic_generator(9).exp_u64(row as u64);
                expected /= x.exp_power_of_2(3) - Val::ONE;
                assert_eq!(words[row * extension.degree()], expected.as_canonical_u64());
                assert!(
                    words[row * extension.degree() + 1..(row + 1) * extension.degree()]
                        .iter()
                        .all(|&word| word == 0)
                );
            }
        }
        let prepared = evaluator
            .prepare(Arc::new(simple(extension, 1)), Specialization::Generic)
            .unwrap();
        let (bad, _) = matrix(&runtime, 3, 1, Extension::Base, RowOrder::Natural, 1, 1);
        let before = runtime.snapshot();
        assert!(evaluator
            .evaluate(
                &prepared,
                2,
                QuotientInputs {
                    main: Some(&bad),
                    preprocessed: None,
                    permutation: None
                },
                &alpha,
                None
            )
            .is_err());
        assert_eq!(runtime.snapshot().live_bytes, before.live_bytes);
        assert_eq!(
            runtime.snapshot().downloaded_bytes - before.downloaded_bytes,
            8
        );
        let mut invalid = simple(extension, 1);
        invalid.instructions[2] = 999;
        let before = runtime.snapshot();
        assert!(evaluator
            .prepare(Arc::new(invalid), Specialization::Prefer)
            .is_err());
        assert_eq!(runtime.snapshot(), before);
    }
}

#[test]
#[ignore = "requires pinned NVRTC; does not require a GPU"]
fn cuda_quotient_generic_and_specialized_compile_for_volta_and_blackwell() {
    for capability in [70, 120] {
        assert!(!super::super::compiler::compile(SOURCE, capability)
            .unwrap()
            .is_empty());
        for extension in [Extension::Quadratic, Extension::Cubic] {
            let source = specialize::source(&simple(extension, 65), specialize::Backend::Cuda)
                .unwrap()
                .unwrap();
            assert!(source.len() <= specialize::MAX_SOURCE_BYTES);
            assert!(!super::super::compiler::compile(&source, capability)
                .unwrap()
                .is_empty());
        }
    }
}

#[test]
#[ignore = "requires CUDA and NVRTC; run serially"]
fn cuda_machine_logup_quotient_matches_upstream_batch_stark() {
    use crate::block_v2::{
        machine::{MachineAir, ProgramBuilder},
        profile,
    };
    use p3_air::BaseAir;
    use p3_field::coset::TwoAdicMultiplicativeCoset as Domain;
    use p3_lookup::{LogUpGadget, LookupProtocol, Lookups};
    use p3_matrix::dense::RowMajorMatrix;
    use p3_uni_stark::StarkGenericConfig;
    let runtime = runtime(128 << 20, 64 << 20);
    let evaluator = Quotients::new(&runtime).unwrap();
    let mut builder = ProgramBuilder::new(1).unwrap();
    let input = builder.input();
    let public = builder.public(0).unwrap();
    let square = builder.mul(input, input);
    builder.assert_equal(square, public);
    let air = MachineAir::new(builder.finish(Some(64)).unwrap());
    let layout = AirLayout::from_air::<Val>(&air);
    let gadget = LogUpGadget::new();
    let lookups = Lookups::<Val>::from_air::<profile::Challenge, _>(&air);
    let chunks =
        p3_batch_stark::symbolic::get_log_num_quotient_chunks::<Val, profile::Challenge, _, _>(
            &air, layout, &lookups, 1, &gadget,
        );
    let lookups = lookups.pack_same_bus(&gadget, 1 << chunks);
    assert!(!lookups.is_empty());
    let program = Arc::new(Program::compile(&air, layout, &lookups, &gadget).unwrap());
    program.validate_quotient().unwrap();
    let generic = evaluator
        .prepare(program.clone(), Specialization::Generic)
        .unwrap();
    let prepared = evaluator.prepare(program, Specialization::Prefer).unwrap();
    eprintln!("cuda_machine_quotient specialized={} instructions={} registers={} local_bytes={} preparation_ns={}", prepared.specialized.is_some(), prepared.program.instruction_count(), prepared.program.registers, prepared.local_bytes, prepared.preparation_ns);
    let (main, cpu_main) = matrix(
        &runtime,
        6,
        air.width(),
        Extension::Base,
        RowOrder::BitReversed,
        7,
        17,
    );
    let (pre, cpu_pre) = matrix(
        &runtime,
        6,
        air.preprocessed_width(),
        Extension::Base,
        RowOrder::Natural,
        7,
        19,
    );
    let perm_width = lookups.len() + 1;
    let (permutation, cpu_perm) = matrix(
        &runtime,
        6,
        perm_width,
        Extension::Cubic,
        RowOrder::BitReversed,
        7,
        23,
    );
    let challenges: Vec<profile::Challenge> = (0..lookups.len() * gadget.num_challenges())
        .map(|i| {
            <profile::Challenge as p3_field::BasedVectorSpace<Val>>::from_basis_coefficients_fn(
                |j| Val::from_u64((i * 19 + j + 7) as u64),
            )
        })
        .collect();
    let terminal = constant::<profile::Challenge>();
    let alpha = constant::<profile::Challenge>();
    let parameter_words: Vec<_> = [1]
        .into_iter()
        .chain(challenges.iter().copied().chain([terminal]).flat_map(words))
        .collect();
    let parameters = scalars(&runtime, &parameter_words);
    let alpha_buffer = scalars(&runtime, &words(alpha));
    let config = profile::make_config();
    let expected = p3_batch_stark::prover::quotient_values::<profile::Config, _, _, _>(
        config.pcs(),
        &air,
        &[Val::ONE],
        layout,
        Domain::new(Val::ONE, 3).unwrap(),
        Domain::new(Val::new(7), 6).unwrap(),
        &RowMajorMatrix::new(cpu_main, air.width()),
        Some(&RowMajorMatrix::new(cpu_perm, perm_width * 3)),
        &lookups,
        &[terminal],
        &gadget,
        &challenges,
        Some(&RowMajorMatrix::new(cpu_pre, air.preprocessed_width())),
        alpha,
    );
    let expected: Vec<u64> = expected.into_iter().flat_map(words).collect();
    for program in [&generic, &prepared] {
        let before = runtime.snapshot();
        let result = evaluator
            .evaluate(
                program,
                3,
                QuotientInputs {
                    main: Some(&main),
                    preprocessed: Some(&pre),
                    permutation: Some(&permutation),
                },
                &alpha_buffer,
                Some(&parameters),
            )
            .unwrap();
        assert_eq!(
            runtime.snapshot().downloaded_bytes - before.downloaded_bytes,
            8
        );
        assert_eq!(runtime.snapshot().uploaded_bytes, before.uploaded_bytes);
        assert_eq!(result.read(result.spec.bytes()).unwrap(), expected);
    }
}
