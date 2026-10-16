use super::*;

fn vector(log: u32, extension: Extension) -> MatrixSpec {
    MatrixSpec::new(log, 1, extension, RowOrder::BitReversed, 1).unwrap()
}
#[test]
fn fold_and_alias_plans_cover_both_fields_and_all_supported_arities() {
    for extension in [Extension::Quadratic, Extension::Cubic] {
        let input = vector(5, extension);
        for arity in 1..=4 {
            let output = fold_output(input, arity).unwrap();
            assert_eq!(output.rows(), 32 >> arity);
            let paired = leaves(input, arity).unwrap();
            assert_eq!(paired.bytes(), input.bytes());
            assert_eq!(paired.columns(), 1 << arity);
            let bytes = output.bytes();
            assert_eq!(
                vector_output(output, 4096, 4096 + bytes, bytes)
                    .unwrap()
                    .peak_bytes,
                4096 + bytes
            );
            assert!(vector_output(output, 4096, 4096 + bytes - 1, bytes).is_err());
            assert!(vector_output(output, 4096, 4096 + bytes, bytes - 1).is_err());
        }
    }
    for arity in [0, 5, usize::MAX] {
        assert!(fold_output(vector(5, Extension::Cubic), arity).is_err());
    }
    assert!(leaves(vector(1, Extension::Quadratic), 2).is_err());
    assert!(fold_output(vector(5, Extension::Base), 1).is_err());
    assert!(vector_output(
        vector(5, Extension::Cubic),
        usize::MAX,
        usize::MAX,
        usize::MAX
    )
    .is_err());
}
#[test]
fn gather_checks_indices_and_output_as_distinct_allocations_and_keeps_output_allowance() {
    let input = MatrixSpec::new(5, 16, Extension::Quadratic, RowOrder::BitReversed, 1).unwrap();
    assert!(GatherShape::new(input, 3, 767).is_err());
    let shape = GatherShape::new(input, 3, 768).unwrap();
    let plan = shape.plan(100, 892, 768).unwrap();
    assert_eq!(plan.peak_bytes, 892); // 100 live + 768 output + 24 indices.
    assert_eq!(plan.host_output_bytes, 768);
    assert_eq!(plan.host_temporary_bytes, 24);
    assert!(shape.plan(100, 891, 768).is_err());
    assert!(shape.plan(100, 892, 767).is_err());
    for queries in [0, 4097, usize::MAX] {
        assert!(GatherShape::new(input, queries, usize::MAX).is_err());
    }
    assert!(shape.plan(usize::MAX, usize::MAX, usize::MAX).is_err());
}
#[test]
fn final_polynomial_plans_include_constant_gather_and_all_interpolation_buffers() {
    let constant = FinalShape::new(vector(4, Extension::Cubic), 4, 0, 24).unwrap();
    let plan = constant.plan(100, 132, 24).unwrap();
    assert_eq!((plan.host_output_bytes, plan.host_temporary_bytes), (24, 8));
    assert!(constant.plan(100, 131, 24).is_err());
    assert!(constant.plan(100, 132, 23).is_err());
    let shape = FinalShape::new(vector(7, Extension::Quadratic), 4, 3, 128).unwrap();
    let plan = shape.plan(100, 396, 128).unwrap(); // 2*128 + 3*8 roots + 16 parameters.
    assert_eq!(
        (plan.host_output_bytes, plan.host_temporary_bytes),
        (128, 24)
    );
    assert!(shape.plan(100, 395, 128).is_err());
    assert!(shape.plan(100, 396, 127).is_err());
    assert!(FinalShape::new(vector(7, Extension::Quadratic), 4, 3, 127).is_err());
}
#[test]
fn final_geometry_rejects_wrong_domains_before_storage() {
    for (blowup, len) in [(4, 2), (usize::MAX, 3), (0, 17)] {
        assert!(FinalShape::new(vector(7, Extension::Cubic), blowup, len, usize::MAX).is_err());
    }
    assert!(FinalShape::new(vector(4, Extension::Base), 4, 0, usize::MAX).is_err());
    let natural = MatrixSpec::new(4, 1, Extension::Cubic, RowOrder::Natural, 1).unwrap();
    assert!(FinalShape::new(natural, 4, 0, usize::MAX).is_err());
}

#[test]
#[cfg(feature = "gpu")]
#[ignore = "requires OpenCL GPU; run serially in a <=3 GiB zero-swap service"]
fn gpu_fri_storage_rejects_before_device_work_and_preserves_gather_order() {
    use crate::block_v2::gpu_hash::engine;
    let _shutdown = engine::TestShutdownGuard;
    engine::initialize_mode(
        engine::Limits {
            managed_bytes: 64 << 20,
            tile_bytes: 8 << 20,
            staging_bytes: 1 << 20,
        },
        engine::TransferMode::Serial,
    )
    .unwrap();
    let session = DeviceSession::new().unwrap();
    let spec = MatrixSpec::new(4, 3, Extension::Base, RowOrder::Natural, 1).unwrap();
    let values: Vec<u64> = (0..48).collect();
    let input = session.upload(spec, &values).unwrap();
    let before = session.stats();
    assert!(session.gather_rows(&input, &[], 96).is_err());
    assert!(session.gather_rows(&input, &[16], 96).is_err());
    assert!(session.gather_rows(&input, &[15, 0, 15, 2], 95).is_err());
    assert_eq!(before, session.stats());
    assert_eq!(
        session.gather_rows(&input, &[15, 0, 15, 2], 96).unwrap(),
        [45, 46, 47, 0, 1, 2, 45, 46, 47, 6, 7, 8]
    );
    let wide = MatrixSpec::new(0, 16384, Extension::Base, RowOrder::Natural, 1).unwrap();
    let input = session.upload(wide, &vec![0; wide.words()]).unwrap();
    let before = session.stats();
    assert!(session
        .gather_rows(&input, &vec![0; 4096], usize::MAX)
        .is_err());
    assert_eq!(before, session.stats());
    eprintln!("gpu_fri_storage_rejected_before_work=true duplicate_query_order_preserved=true");
}
