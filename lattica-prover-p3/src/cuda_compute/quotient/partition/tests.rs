use super::super::tests::{matrix, oracle, runtime, scalars, simple};
use super::*;
use crate::{
    block_v2::{
        pcs_field::FriExtension,
        quotient_program::test_support::{constant, program_with_main_width, words},
    },
    config::{MyCompress, MyHash, Val},
    cuda_compute::Commitments,
};
use p3_air::symbolic::SymbolicExpressionExt;
use p3_dft::TwoAdicSubgroupDft;
use p3_field::{Algebra, PrimeCharacteristicRing, PrimeField64};
use p3_matrix::{dense::RowMajorMatrix, Matrix as _};
use p3_symmetric::{CryptographicHasher, PseudoCompressionFunction};

#[test]
fn extracted_partition_admission_releases_each_source_before_the_next_expansion() {
    let program = program_with_main_width::<crate::block_v2::profile::Challenge>(64);
    let inputs = [
        (64, Extension::Base),
        (2, Extension::Base),
        (2, Extension::Cubic),
    ]
    .map(|(width, extension)| {
        Some(MatrixSpec::new(19, width, extension, RowOrder::BitReversed, 7).unwrap())
    });
    let live = 2 << 30;
    let source_bytes = inputs
        .iter()
        .flatten()
        .map(|spec| spec.bytes())
        .sum::<usize>();
    let limits = Limits {
        managed_bytes: 7 << 30,
        max_allocation_bytes: 1 << 30,
        ..Limits::default()
    };
    let extracted =
        PartitionPlan::with_sources(&program, inputs, 18, 21, 7, live, limits, true).unwrap();
    let retained =
        PartitionPlan::new(&program, inputs, 18, 21, 7, live + source_bytes, limits).unwrap();
    assert!(extracted.peak_bytes < retained.peak_bytes);
    let bounded = Limits {
        managed_bytes: extracted.peak_bytes,
        ..limits
    };
    assert!(PartitionPlan::with_sources(&program, inputs, 18, 21, 7, live, bounded, true).is_ok());
    assert!(PartitionPlan::new(&program, inputs, 18, 21, 7, live + source_bytes, bounded).is_err());
    let alias =
        PartitionPlan::with_sources(&program, inputs, 18, 19, 7, live, limits, true).unwrap();
    assert_eq!(alias.expansion_peak_bytes, live + source_bytes);
    assert!(alias.evaluation_peak_bytes > alias.expansion_peak_bytes);
    let mut invalid = inputs;
    invalid[0].as_mut().unwrap().order = RowOrder::Natural;
    assert!(PartitionPlan::with_sources(&program, invalid, 18, 21, 7, live, limits, true).is_err());
}

#[test]
fn partition_admission_charges_all_retained_storage_and_aliases_one_coset() {
    let p = simple(Extension::Cubic, 1);
    let input = MatrixSpec::new(3, 1, Extension::Base, RowOrder::Natural, 7).unwrap();
    let inputs = [Some(input), None, None];
    // Five pre-existing bytes, 192 output bytes, 32 static bytes, one 64-byte
    // evaluation row. A full-height single coset does not copy its input.
    let limits = Limits {
        managed_bytes: 293,
        max_allocation_bytes: 192,
        ..Limits::default()
    };
    let plan = PartitionPlan::new(&p, inputs, 3, 3, 7, 5, limits).unwrap();
    assert_eq!((plan.cosets, plan.part_log, plan.peak_bytes), (1, 3, 293));
    assert_eq!(plan.expansion_peak_bytes, 5);
    assert!(PartitionPlan::new(
        &p,
        inputs,
        3,
        3,
        7,
        5,
        Limits {
            managed_bytes: 292,
            ..limits
        }
    )
    .is_err());

    // Two cosets retain a 384-byte final result, a 64-byte expansion and a
    // 192-byte component result alongside the same static/evaluation scratch.
    let limits = Limits {
        managed_bytes: 741,
        max_allocation_bytes: 384,
        ..limits
    };
    let plan = PartitionPlan::new(&p, inputs, 3, 4, 7, 5, limits).unwrap();
    assert_eq!((plan.cosets, plan.part_log, plan.peak_bytes), (2, 3, 741));
    assert_eq!(plan.expansion_peak_bytes, 581);
    assert_eq!(plan.evaluation_peak_bytes, 741);
    assert!(PartitionPlan::new(
        &p,
        inputs,
        3,
        4,
        7,
        5,
        Limits {
            managed_bytes: 740,
            ..limits
        }
    )
    .is_err());
    assert!(PartitionPlan::new(
        &p,
        inputs,
        3,
        4,
        7,
        5,
        Limits {
            max_allocation_bytes: 383,
            ..limits
        }
    )
    .is_err());
}

#[test]
fn partition_admission_rejects_incompatible_domains_and_overflow() {
    let p = simple(Extension::Cubic, 1);
    let input = MatrixSpec::new(3, 1, Extension::Base, RowOrder::Natural, 7).unwrap();
    let inputs = [Some(input), None, None];
    for (trace, quotient, shift, live) in [
        (5, 4, 7, 0),
        (3, 32, 7, 0),
        (3, 2, 7, 0),
        (3, 4, 11, 0),
        (3, 4, 0, 0),
        (3, 4, GOLDILOCKS_MODULUS, 0),
        (3, 4, 7, usize::MAX),
        (3, 12, 7, 0),
    ] {
        assert!(
            PartitionPlan::new(&p, inputs, trace, quotient, shift, live, Limits::default())
                .is_err()
        );
    }
    assert!(PartitionPlan::new(&p, [None; 3], 3, 4, 7, 0, Limits::default()).is_err());
    assert!(PartitionPlan::new(
        &p,
        [Some(input), Some(input), None],
        3,
        4,
        7,
        0,
        Limits::default()
    )
    .is_err());
    assert_eq!(
        PartitionPlan::new(&p, inputs, 3, 11, 7, 0, Limits::default())
            .unwrap()
            .cosets,
        256
    );
}

// Input evaluations are on shift * H. Interpolation yields coefficients in
// that scaled variable, so the independent DFT extends them with relative
// shift one. This does not use the CUDA transform or its partition planner.
pub(super) fn extend(values: Vec<Val>, width: usize, added_bits: u32) -> Vec<Val> {
    crate::config::Dft::default()
        .coset_lde_batch(
            RowMajorMatrix::new(values, width),
            added_bits as usize,
            Val::ONE,
        )
        .to_row_major_matrix()
        .values
}

fn conformance<F: FriExtension>()
where
    SymbolicExpressionExt<Val, F>: Algebra<F>,
{
    let runtime = runtime(2 << 20, 512 << 10);
    let transforms = Transforms::new(&runtime).unwrap();
    let evaluator = Quotients::new(&runtime).unwrap();
    let commits = Commitments::new(&runtime).unwrap();
    let permutation = p3_goldilocks::default_goldilocks_poseidon2_8();
    let hash = MyHash::new(permutation.clone());
    let compress = MyCompress::new(permutation);
    let public = [Val::new(31), Val::new(0xffff_ffff_0000_0000)];
    let challenges = [
        constant::<F>(),
        F::from_basis_coefficients_fn(|i| Val::new(17 + i as u64)),
    ];
    let terminal = F::from_basis_coefficients_fn(|i| Val::new(29 + i as u64));
    let alpha = constant::<F>();
    let alpha_buffer = scalars(&runtime, &words(alpha));
    let parameters = scalars(
        &runtime,
        &public
            .iter()
            .map(PrimeField64::as_canonical_u64)
            .chain(challenges.into_iter().chain([terminal]).flat_map(words))
            .collect::<Vec<_>>(),
    );
    for (log_trace, log_quotient, prefix_logs, width, shift) in [
        (0, 0, [0, 0, 0], 3, 7),
        (1, 4, [0, 1, 2], 3, 11),
        (3, 6, [3, 4, 2], 3, 7),
        (3, 4, [4, 2, 3], 3, 11),
        (4, 13, [4, 5, 3], 64, 7),
    ] {
        let p = Arc::new(program_with_main_width::<F>(width));
        let generic = evaluator
            .prepare(p.clone(), Specialization::Generic)
            .unwrap();
        let specialized = evaluator.prepare(p, Specialization::Prefer).unwrap();
        assert!(specialized.specialized.is_some());
        let (main, main_values) = matrix(
            &runtime,
            prefix_logs[0],
            width,
            Extension::Base,
            RowOrder::BitReversed,
            shift,
            17,
        );
        let (pre, pre_values) = matrix(
            &runtime,
            prefix_logs[1],
            2,
            Extension::Base,
            RowOrder::Natural,
            shift,
            19,
        );
        let (perm, perm_values) = matrix(
            &runtime,
            prefix_logs[2],
            2,
            F::DEVICE_EXTENSION,
            RowOrder::BitReversed,
            shift,
            23,
        );
        let inputs = QuotientInputs {
            main: Some(&main),
            preprocessed: Some(&pre),
            permutation: Some(&perm),
        };
        let expected = oracle(
            log_trace,
            log_quotient,
            shift,
            width,
            &extend(main_values, width, log_quotient - prefix_logs[0]),
            &extend(pre_values, 2, log_quotient - prefix_logs[1]),
            &extend(perm_values, 2 * F::DIMENSION, log_quotient - prefix_logs[2]),
            public,
            challenges,
            terminal,
            alpha,
        );
        let expected_words: Vec<_> = expected.iter().copied().flat_map(words).collect();
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
        let expected_root: Vec<_> = layer[0]
            .iter()
            .map(PrimeField64::as_canonical_u64)
            .collect();
        if width == 64 {
            let before = runtime.snapshot();
            // Full main LDE needs 4 MiB in a single allocation, exceeding both
            // the 2 MiB total budget and the 512 KiB allocation ceiling.
            assert!(transforms
                .lde(&main, log_quotient, shift, RowOrder::Natural)
                .is_err());
            assert_eq!(before, runtime.snapshot());
        }
        let original_main = main.read(main.spec.bytes()).unwrap();
        let original_pre = pre.read(pre.spec.bytes()).unwrap();
        let original_perm = perm.read(perm.spec.bytes()).unwrap();
        for prepared in [&generic, &specialized] {
            let before = runtime.snapshot();
            let plan = PartitionPlan::new(
                &prepared.program,
                [Some(main.spec), Some(pre.spec), Some(perm.spec)],
                log_trace,
                log_quotient,
                shift,
                before.live_bytes,
                runtime.state.budget.limits,
            )
            .unwrap();
            let quotient = evaluator
                .evaluate_partitioned(
                    &transforms,
                    prepared,
                    log_trace,
                    log_quotient,
                    shift,
                    inputs,
                    &alpha_buffer,
                    Some(&parameters),
                )
                .unwrap();
            let after = runtime.snapshot();
            assert_eq!(after.live_bytes - before.live_bytes, quotient.spec.bytes());
            let descriptor_bytes = if plan.cosets == 1 {
                0
            } else {
                (plan.cosets + 1) * 8
            };
            assert_eq!(
                after.downloaded_bytes - before.downloaded_bytes,
                (descriptor_bytes + plan.cosets * 8) as u64
            );
            assert!(after.peak_bytes <= before.peak_bytes.max(plan.peak_bytes));
            let tree = commits.commit(&[&quotient], 0).unwrap();
            assert_eq!(runtime.snapshot().downloaded_bytes, after.downloaded_bytes);
            assert_eq!(tree.cap(32).unwrap(), expected_root);
            assert_eq!(quotient.spec, plan.output);
            assert_eq!(
                quotient.read(quotient.spec.bytes()).unwrap(),
                expected_words,
                "trace={log_trace} quotient={log_quotient} width={width} specialized={}",
                prepared.specialized.is_some()
            );
            drop(tree);
            drop(quotient);
            assert_eq!(runtime.snapshot().live_bytes, before.live_bytes);
        }
        assert_eq!(main.read(main.spec.bytes()).unwrap(), original_main);
        assert_eq!(pre.read(pre.spec.bytes()).unwrap(), original_pre);
        assert_eq!(perm.read(perm.spec.bytes()).unwrap(), original_perm);
    }
    assert_eq!(runtime.snapshot().pending_commands, 0);
}

#[test]
#[ignore = "requires CUDA and NVRTC; run serially"]
fn cuda_partitioned_quadratic_quotients_match_cpu_under_bounded_memory() {
    conformance::<crate::config::Challenge>();
}

#[test]
#[ignore = "requires CUDA and NVRTC; run serially"]
fn cuda_partitioned_cubic_quotients_match_cpu_under_bounded_memory() {
    conformance::<crate::block_v2::profile::Challenge>();
}

#[test]
#[ignore = "requires CUDA and NVRTC; run serially"]
fn cuda_partition_rejects_bad_requests_without_work_and_preserves_resources() {
    let runtime = runtime(16 << 10, 4 << 10);
    let transforms = Transforms::new(&runtime).unwrap();
    let evaluator = Quotients::new(&runtime).unwrap();
    let p = evaluator
        .prepare(
            Arc::new(simple(Extension::Cubic, 1)),
            Specialization::Generic,
        )
        .unwrap();
    let alpha = scalars(&runtime, &[17, 19, 23]);
    let (main, _) = matrix(&runtime, 3, 1, Extension::Base, RowOrder::Natural, 7, 17);
    let inputs = QuotientInputs {
        main: Some(&main),
        preprocessed: None,
        permutation: None,
    };
    let original = main.read(main.spec.bytes()).unwrap();
    let before = runtime.snapshot();
    for (trace, quotient, shift) in [
        (5, 4, 7),
        (3, 32, 7),
        (3, 2, 7),
        (3, 4, 11),
        (3, 4, 0),
        (3, 12, 7),
        (3, 8, 7),
    ] {
        assert!(evaluator
            .evaluate_partitioned(
                &transforms,
                &p,
                trace,
                quotient,
                shift,
                inputs,
                &alpha,
                None
            )
            .is_err());
        assert_eq!(runtime.snapshot(), before);
    }
    assert!(evaluator
        .evaluate_partitioned(
            &transforms,
            &p,
            3,
            4,
            7,
            QuotientInputs {
                main: None,
                ..inputs
            },
            &alpha,
            None
        )
        .is_err());
    assert!(evaluator
        .evaluate_partitioned(&transforms, &p, 3, 4, 7, inputs, &alpha, Some(&alpha))
        .is_err());
    assert!(evaluator
        .evaluate_partitioned(&transforms, &p, 3, 4, 7, inputs, &main.buffer, None)
        .is_err());
    assert_eq!(runtime.snapshot(), before);
    assert_eq!(main.read(main.spec.bytes()).unwrap(), original);

    // A nontrivial root intersects the full domain only in a later coset.
    // Domain validity is public GPU arithmetic and may read its descriptor;
    // rejection must still retire temporary storage and keep inputs intact.
    let shift = roots::root(4);
    let (bad_domain, _) = matrix(
        &runtime,
        3,
        1,
        Extension::Base,
        RowOrder::BitReversed,
        shift,
        23,
    );
    let bad_values = bad_domain.read(bad_domain.spec.bytes()).unwrap();
    let before = runtime.snapshot();
    assert!(evaluator
        .evaluate_partitioned(
            &transforms,
            &p,
            3,
            4,
            shift,
            QuotientInputs {
                main: Some(&bad_domain),
                ..inputs
            },
            &alpha,
            None
        )
        .is_err());
    let after = runtime.snapshot();
    assert_eq!(after.live_bytes, before.live_bytes);
    assert_eq!(after.allocations, before.allocations);
    assert_eq!(after.pending_commands, 0);
    assert_eq!(after.downloaded_bytes - before.downloaded_bytes, 24);
    assert_eq!(
        bad_domain.read(bad_domain.spec.bytes()).unwrap(),
        bad_values
    );

    // The resource budget admits only a direct one-coset evaluation. Fill the
    // rest with a live allocation and ensure no input/output copy is needed.
    let minimum = 8 * 3 * 8 + 4 * 8 + 8 * 8;
    let mut filler = Vec::new();
    let mut remaining = (16 * 1024 - runtime.snapshot().live_bytes - minimum) / 8;
    while remaining != 0 {
        let words = remaining.min(512);
        filler.push(runtime.allocate(words).unwrap());
        remaining -= words;
    }
    let before = runtime.snapshot();
    let result = evaluator
        .evaluate_partitioned(&transforms, &p, 3, 3, 7, inputs, &alpha, None)
        .unwrap();
    assert_eq!(
        runtime.snapshot().live_bytes - before.live_bytes,
        result.spec.bytes()
    );
    assert_eq!(runtime.snapshot().copied_bytes, before.copied_bytes);
    drop(result);
    drop(filler);
}
