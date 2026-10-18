use super::*;
use crate::{
    config::{Dft, Val},
    gpu_matrix::{Extension, GOLDILOCKS_MODULUS as P},
};
use p3_dft::TwoAdicSubgroupDft;
use p3_field::{Field, PrimeCharacteristicRing, PrimeField64};
use p3_matrix::{dense::RowMajorMatrix, Matrix as _};

fn spec(log: u32, width: usize, extension: Extension, order: RowOrder, shift: u64) -> MatrixSpec {
    MatrixSpec::new(log, width, extension, order, shift).unwrap()
}

fn physical(row: usize, log: u32, order: RowOrder) -> usize {
    if order == RowOrder::Natural || log == 0 {
        row
    } else {
        row.reverse_bits() >> (usize::BITS - log)
    }
}

fn raw_words(count: usize) -> Vec<u64> {
    (0..count)
        .map(|i| match i % 7 {
            0 => 0,
            1 => 1,
            2 => P - 1,
            3 => P,
            4 => u64::MAX,
            _ => (i as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15),
        })
        .collect()
}

fn test_runtime(managed_bytes: usize, max_allocation_bytes: usize) -> Runtime {
    Runtime::new(
        &std::env::var("LATTICA_GPU_DEVICE_UUID").unwrap(),
        Limits {
            managed_bytes,
            max_allocation_bytes,
            ..Limits::default()
        },
    )
    .unwrap()
}

#[test]
fn transform_plans_charge_both_buffers_and_constants_before_allocation() {
    let input = spec(8, 1, Extension::Base, RowOrder::Natural, 11);
    let limits = Limits {
        managed_bytes: 1 << 20,
        max_allocation_bytes: 4096,
        ..Limits::default()
    };
    let live = 71 + input.bytes();
    let plan = storage_plan(input, 8, live, limits).unwrap();
    assert_eq!(plan.peak_bytes, live + 2 * input.bytes() + (8 + 8 + 2) * 8);
    assert!(storage_plan(input, 8, usize::MAX, limits).is_err());
    assert!(storage_plan(
        input,
        8,
        live,
        Limits {
            managed_bytes: plan.peak_bytes - 1,
            ..limits
        }
    )
    .is_err());
    assert!(storage_plan(
        input,
        8,
        live,
        Limits {
            max_allocation_bytes: input.bytes() - 1,
            ..limits
        }
    )
    .is_err());
    for (log, shift) in [(7, 1), (32, 1), (8, 0), (8, P)] {
        assert!(geometry(input, log, shift, RowOrder::Natural).is_err());
    }
    assert!(linear_launch(0).is_err());
    assert!(linear_launch(usize::MAX).is_err());
}

#[test]
fn ntt_tiles_cover_supported_shapes_with_bounded_shared_memory() {
    for log_rows in 1..=25 {
        for width in [1, 3, 8, 16, 17, 31, 255, 512, 4096] {
            for shared in [8192, 16384, 49152] {
                let groups = ntt_groups(log_rows, width, shared).unwrap();
                assert_eq!(groups.iter().map(|g| g.stages).sum::<u32>(), log_rows);
                let mut end = 0;
                for group in groups {
                    assert_eq!(group.first, end);
                    end += group.stages;
                    assert!(group.stages > 0);
                    assert!(group.log_columns <= 4);
                    assert!(group.launch.shared_bytes <= shared);
                    assert!(group.launch.threads <= 256 && group.launch.blocks > 0);
                }
            }
        }
    }
    assert_eq!(
        ntt_groups(31, 1, 49152)
            .unwrap()
            .iter()
            .map(|g| g.stages)
            .sum::<u32>(),
        31
    );
    for (log, width, shared) in [
        (0, 1, 49152),
        (32, 1, 49152),
        (1, 0, 49152),
        (1, usize::MAX, 49152),
        (1, 1, 8191),
        (31, u32::MAX as usize, 49152),
    ] {
        assert!(ntt_groups(log, width, shared).is_err());
    }
}

#[test]
#[ignore = "requires CUDA and pinned NVRTC; run serially after proof benchmarks"]
fn cuda_lde_matches_cpu_cosets_orders_extensions_and_memory_bounds() {
    let runtime = test_runtime(64 << 20, 32 << 20);
    let transforms = Transforms::new(&runtime).unwrap();
    for (log_input, log_output, columns) in [
        (0, 0, 3),
        (0, 3, 1),
        (3, 3, 7),
        (3, 8, 2),
        (9, 13, 5),
        (13, 14, 1),
    ] {
        for extension in [Extension::Base, Extension::Quadratic, Extension::Cubic] {
            let width = columns * extension.degree();
            let raw = raw_words((1usize << log_input) * width);
            for (input_shift, output_shift) in [(1, 1), (11, 7), (P - 1, P - 2)] {
                let values = raw.iter().map(|w| Val::from_u64(*w)).collect();
                let expected = Dft::default()
                    .coset_lde_batch(
                        RowMajorMatrix::new(values, width),
                        (log_output - log_input) as usize,
                        Val::from_u64(output_shift) * Val::from_u64(input_shift).inverse(),
                    )
                    .to_row_major_matrix();
                for input_order in [RowOrder::Natural, RowOrder::BitReversed] {
                    let words: Vec<_> = (0..1usize << log_input)
                        .flat_map(|row| {
                            let at = physical(row, log_input, input_order) * width;
                            raw[at..at + width].iter().copied()
                        })
                        .collect();
                    let input = runtime
                        .upload_matrix(
                            spec(log_input, columns, extension, input_order, input_shift),
                            &words,
                        )
                        .unwrap();
                    for output_order in [RowOrder::Natural, RowOrder::BitReversed] {
                        let before = runtime.snapshot();
                        let output = transforms
                            .lde(&input, log_output, output_shift, output_order)
                            .unwrap();
                        let after = runtime.snapshot();
                        assert_eq!(after.downloaded_bytes, before.downloaded_bytes);
                        assert_eq!(
                            after.uploaded_bytes - before.uploaded_bytes,
                            ((log_input.max(1) + log_output.max(1)) * 8) as u64
                        );
                        assert!(after.completed_commands > before.completed_commands);
                        assert_eq!(
                            after.live_bytes,
                            input.spec().bytes() + output.spec().bytes()
                        );
                        assert!(output.read(output.spec().bytes() - 1).is_err());
                        let actual = output.read(output.spec().bytes()).unwrap();
                        for row in 0..output.spec().rows() {
                            let at = physical(row, log_output, output_order) * width;
                            let reference: Vec<_> = expected.values[at..at + width]
                                .iter()
                                .map(|v| v.as_canonical_u64())
                                .collect();
                            assert_eq!(&actual[row*width..(row+1)*width], reference,
                                "logs={log_input}/{log_output} shifts={input_shift}/{output_shift} orders={input_order:?}/{output_order:?} row={row}");
                        }
                    }
                    assert_eq!(input.read(input.spec().bytes()).unwrap(), words);
                    let before = runtime.snapshot();
                    assert!(transforms.lde(&input, 30, 7, RowOrder::Natural).is_err());
                    assert_eq!(runtime.snapshot(), before);
                }
            }
        }
    }
    assert_eq!(runtime.snapshot().live_bytes, 0);
    runtime.finish().unwrap();
}

#[test]
#[ignore = "requires CUDA and pinned NVRTC; run serially after proof benchmarks"]
fn cuda_queries_match_cpu_with_bounded_tiles_and_no_prefix_downloads() {
    let runtime = test_runtime(6 << 20, 1 << 20);
    let transforms = Transforms::new(&runtime).unwrap();
    for (log_input, log_output, width) in [
        (0, 0, 1),
        (0, 4, 7),
        (4, 4, 33),
        (5, 10, 31),
        (6, 12, 97),
        (9, 14, 17),
    ] {
        let raw = raw_words((1usize << log_input) * width);
        let expected = Dft::default()
            .lde_batch(
                RowMajorMatrix::new(raw.iter().map(|w| Val::from_u64(*w)).collect(), width),
                (log_output - log_input) as usize,
            )
            .to_row_major_matrix();
        let words: Vec<_> = (0..1usize << log_input)
            .flat_map(|row| {
                let at = physical(row, log_input, RowOrder::BitReversed) * width;
                raw[at..at + width].iter().copied()
            })
            .collect();
        let height = 1usize << log_output;
        let indices: Vec<_> = [height - 1, 0, height / 2, 0]
            .into_iter()
            .chain((0..252).map(|i| i * 31337 % height))
            .collect();
        for shift in [1, 7, 11] {
            let input = runtime
                .upload_matrix(
                    spec(
                        log_input,
                        width,
                        Extension::Base,
                        RowOrder::BitReversed,
                        shift,
                    ),
                    &words,
                )
                .unwrap();
            let before = runtime.snapshot();
            let rows = transforms
                .query_rows(&input, log_output, &indices, 32 << 20)
                .unwrap();
            let after = runtime.snapshot();
            assert_eq!(
                after.uploaded_bytes - before.uploaded_bytes,
                ((log_input.max(1) + log_output.max(1)) as usize + indices.len()) as u64 * 8
            );
            assert_eq!(
                after.downloaded_bytes - before.downloaded_bytes,
                (indices.len() * width * 8) as u64
            );
            assert_eq!(after.live_bytes, before.live_bytes);
            assert!(
                rows.workspace_bytes + before.live_bytes
                    <= runtime.state.budget.limits.managed_bytes
            );
            if log_output >= 12 {
                assert!(rows.tiles > 1);
            }
            for (&index, row) in indices.iter().zip(rows.values.chunks_exact(width)) {
                let at = physical(index, log_output, RowOrder::BitReversed) * width;
                let reference: Vec<_> = expected.values[at..at + width]
                    .iter()
                    .map(|v| v.as_canonical_u64())
                    .collect();
                assert_eq!(
                    row, reference,
                    "logs={log_input}/{log_output} width={width} index={index} shift={shift}"
                );
            }
            assert_eq!(input.read(input.spec().bytes()).unwrap(), words);
            let before = runtime.snapshot();
            for (log, queries, host) in [
                (log_output, &[][..], usize::MAX),
                (log_output, &[height][..], usize::MAX),
                (26, &[0][..], usize::MAX),
                (log_output, &[0][..], 0),
            ] {
                assert!(transforms.query_rows(&input, log, queries, host).is_err());
                assert_eq!(runtime.snapshot(), before);
            }
            if log_output == 14 && shift == 11 {
                let mut ballast = Vec::new();
                while runtime.state.budget.limits.managed_bytes - runtime.snapshot().live_bytes
                    > 1024
                {
                    let bytes = (runtime.state.budget.limits.managed_bytes
                        - runtime.snapshot().live_bytes
                        - 1024)
                        .min(runtime.state.budget.limits.max_allocation_bytes);
                    ballast.push(runtime.allocate(bytes / 8).unwrap());
                }
                let before = runtime.snapshot();
                assert!(transforms
                    .query_rows(&input, log_output, &indices, 32 << 20)
                    .is_err());
                assert_eq!(runtime.snapshot(), before);
                drop(ballast);
                assert_eq!(
                    transforms
                        .query_rows(&input, log_output, &indices, 32 << 20)
                        .unwrap()
                        .values,
                    rows.values
                );
            }
        }
    }
    assert_eq!(runtime.snapshot().live_bytes, 0);
    runtime.finish().unwrap();
}

#[test]
#[ignore = "requires pinned NVRTC but no GPU context"]
fn cuda_transform_source_compiles_for_volta_and_blackwell() {
    for capability in [70, 120] {
        assert!(!super::super::compiler::compile(SOURCE, capability)
            .unwrap()
            .is_empty());
    }
}
