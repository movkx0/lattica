use super::*;

#[test]
#[ignore = "requires CUDA and NVRTC; run serially"]
fn cuda_twiddle_tables_match_cpu_across_large_groups_at_exact_memory_budget() {
    let input_spec = spec(14, 31, Extension::Base, RowOrder::Natural, 11);
    let output_spec = spec(17, 31, Extension::Base, RowOrder::Natural, 7);
    let raw = raw_words(input_spec.words());
    let expected = Dft::default()
        .coset_lde_batch(
            RowMajorMatrix::new(raw.iter().map(|word| Val::from_u64(*word)).collect(), 31),
            3,
            Val::from_u64(7) * Val::from_u64(11).inverse(),
        )
        .to_row_major_matrix();
    let plan = storage_plan(
        input_spec,
        17,
        input_spec.bytes(),
        Limits {
            managed_bytes: 256 << 20,
            max_allocation_bytes: 128 << 20,
            ..Limits::default()
        },
    )
    .unwrap();
    let runtime = test_runtime(plan.peak_bytes, output_spec.bytes());
    let transforms = Transforms::new(&runtime).unwrap();
    let input = runtime.upload_matrix(input_spec, &raw).unwrap();
    for order in [RowOrder::Natural, RowOrder::BitReversed] {
        let before = runtime.snapshot();
        let output = transforms.lde(&input, 17, 7, order).unwrap();
        let after = runtime.snapshot();
        assert_eq!(after.downloaded_bytes, before.downloaded_bytes);
        assert_eq!(after.uploaded_bytes - before.uploaded_bytes, (14 + 17) * 8);
        assert_eq!(after.live_bytes, input_spec.bytes() + output_spec.bytes());
        assert_eq!(after.peak_bytes, plan.peak_bytes);
        let actual = output.read(output_spec.bytes()).unwrap();
        for row in 0..output_spec.rows() {
            let at = physical(row, 17, order) * 31;
            for column in 0..31 {
                assert_eq!(
                    actual[row * 31 + column],
                    expected.values[at + column].as_canonical_u64()
                );
            }
        }
        drop(output);
        assert_eq!(runtime.snapshot().live_bytes, input_spec.bytes());
    }
    drop(input);
    assert_eq!(runtime.snapshot().live_bytes, 0);
    runtime.finish().unwrap();
}
