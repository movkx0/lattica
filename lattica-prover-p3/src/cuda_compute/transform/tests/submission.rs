use super::*;

#[test]
#[ignore = "requires CUDA GPU and NVRTC 12.9; run serially after timing"]
fn cuda_batched_transforms_match_cpu_at_command_capacity_boundaries() {
    let (log_input, log_output, columns) = (13, 14, 2);
    let extension = Extension::Cubic;
    let width = columns * extension.degree();
    let raw = raw_words((1 << log_input) * width);
    let values = raw.iter().map(|word| Val::from_u64(*word)).collect();
    let expected = Dft::default()
        .coset_lde_batch(
            RowMajorMatrix::new(values, width),
            (log_output - log_input) as usize,
            Val::from_u64(7) * Val::from_u64(11).inverse(),
        )
        .to_row_major_matrix();
    for limit in [1, 2] {
        let runtime = Runtime::new(
            &std::env::var("LATTICA_GPU_DEVICE_UUID").unwrap(),
            Limits {
                managed_bytes: 64 << 20,
                max_allocation_bytes: 32 << 20,
                max_pending: limit,
                ..Limits::default()
            },
        )
        .unwrap();
        let transforms = Transforms::new(&runtime).unwrap();
        for input_order in [RowOrder::Natural, RowOrder::BitReversed] {
            let words = (0..1usize << log_input)
                .flat_map(|row| {
                    let at = physical(row, log_input, input_order) * width;
                    raw[at..at + width].iter().copied()
                })
                .collect::<Vec<_>>();
            let input = runtime
                .upload_matrix(spec(log_input, columns, extension, input_order, 11), &words)
                .unwrap();
            for output_order in [RowOrder::Natural, RowOrder::BitReversed] {
                let output = transforms.lde(&input, log_output, 7, output_order).unwrap();
                assert_eq!(runtime.snapshot().pending_commands, 0);
                let actual = output.read(output.spec().bytes()).unwrap();
                for row in 0..1usize << log_output {
                    let at = physical(row, log_output, output_order) * width;
                    for column in 0..width {
                        assert_eq!(
                            actual[at + column],
                            expected.values[row * width + column].as_canonical_u64()
                        );
                    }
                }
            }
        }
        drop(transforms);
        let retired = runtime.retire().unwrap();
        assert_eq!(retired.peak_event_pairs, limit);
        assert_eq!(retired.pending_commands, 0);
        assert_eq!(retired.event_pairs, 0);
    }
}
