use super::*;

fn spec(first_block: usize, blocks: usize, output_len: usize) -> AesTraceSpec {
    AesTraceSpec { domain: u64::MAX, start_counter: u32::MAX, output_len, first_block, blocks }
}

#[test]
fn serial_aes_source_preserves_partial_tails_counter_wrap_and_exact_trace_storage() {
    let plan = AesPreparationPlan::new(spec(0, 5, 80)).unwrap();
    let geometry = plan.geometry();
    assert_eq!((geometry.rows(), geometry.width(), geometry.public_values()), (8192, 417, 12));
    assert_eq!((geometry.periodic_columns(), geometry.periodic_length()), (31, 64));
    assert_eq!((geometry.domain(), geometry.start_counter()), (u64::MAX, u32::MAX));
    assert_eq!((geometry.first_block(), geometry.blocks(), geometry.output_len()), (0, 5, 80));
    assert_eq!(geometry.kernel_kind(), 0);
    let device = plan.trace_device();
    // The maintained GPU checkpoint fixture has 662 words for five real and
    // eight padded blocks. Include AES prefix, table and all five owners.
    assert_eq!(device.trace_bytes(), 8192 * 417 * 8);
    assert_eq!(device.public_bytes(), 12 * 8);
    assert_eq!(device.source_bytes(), 32 * 8);
    assert_eq!(device.scratch_bytes(), 17_750 * 8);
    assert_eq!(device.geometry_bytes(), 12 * 8);
    assert_eq!(device.generation_peak_bytes(), device.trace_bytes() + device.public_bytes()
        + device.source_bytes() + device.scratch_bytes() + device.geometry_bytes());
    assert_eq!(device.generated_output_bytes().unwrap(), device.trace_bytes() + device.public_bytes());
    let later = AesPreparationPlan::new(spec(64, 5, 16 * 69 - 7)).unwrap();
    assert_eq!(later.trace_device().scratch_bytes() - device.scratch_bytes(), 64 * 16 * 8);
    assert_eq!(later.host(), plan.host());
    assert_eq!(AesPreparationPlan::new(spec(0, 64, 16 * 64)).unwrap().geometry().rows(), 65536);
}

#[test]
fn source_refuses_wrong_segments_before_any_recorder_or_gpu_exists() {
    for descriptor in [spec(0, 0, 16), spec(0, 65, 65 * 16), spec(1, 1, 16), spec(0, 2, 16)] {
        assert_eq!(AesPreparationPlan::new(descriptor), Err(Error::Segment));
    }
    assert_eq!(AesPreparationPlan::new(spec(0, 1, 0)), Err(Error::Length));
    assert_eq!(AesPreparationPlan::new(spec(0, 1, u32::MAX as usize + 1)), Err(Error::Length));
    assert_eq!(AesPreparationPlan::new(spec(usize::MAX, 1, 16)), Err(Error::Overflow));
    assert!(AesPreparationPlan::new(spec(0, 1, 1)).is_ok());
}

#[test]
fn preparation_is_allocation_free_and_keeps_every_host_component_additive() {
    let (plan, measured) = crate::spill_alloc::allocation_requests::measure(||
        AesPreparationPlan::new(spec(0, 64, 1024)).unwrap());
    assert_eq!((measured.calls, measured.bytes, measured.overflow), (0, 0, false));
    let host = plan.host();
    assert_eq!(host.periodic_staging_bytes(), 49_848);
    assert_eq!(host.prepared_partition_bytes().unwrap(), (192 << 20) + 49_848);
    assert_eq!(host.required_host_bytes(), host.symbolic_compiler_bytes() + host.periodic_staging_bytes()
        + host.air_callback_heap_bytes() + host.public_readback_and_conversion_bytes()
        + host.trace_upload_staging_bytes() + host.trace_matrix_backing_bytes() + host.explicit_owner_bytes()
        + plan.configuration().required_host_bytes() + plan.planner().required_host_bytes());
}
