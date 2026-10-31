use super::*;

fn spec(input_len: usize, output_len: usize, first: usize, count: usize) -> ShakeTraceSpec {
    ShakeTraceSpec {
        input_len,
        output_len,
        first_permutation: first,
        permutations: count,
    }
}

#[test]
fn geometry_keeps_padding_and_partial_squeezing_singleton() {
    // Two complete absorption blocks, one padding block, then two complete
    // squeeze blocks and a final partial block. Native segmentation is intact.
    let descriptor = spec(272, 409, 0, 2);
    let pair = ShakePreparationPlan::batch(descriptor).unwrap();
    assert_eq!(pair.geometry().kernel_kind(), 3);
    assert_eq!(
        (pair.geometry().rows(), pair.geometry().width()),
        (8192, 518)
    );
    let padding = ShakePreparationPlan::singleton(spec(272, 409, 2, 1)).unwrap();
    assert_eq!(padding.geometry().kernel_kind(), 2);
    assert_eq!(
        (padding.geometry().rows(), padding.geometry().width()),
        (4096, 517)
    );
    assert_eq!(
        ShakePreparationPlan::batch(spec(272, 409, 1, 2)),
        Err(Error::Transition)
    );
    assert_eq!(
        ShakePreparationPlan::batch(spec(272, 409, 2, 1)),
        Err(Error::Transition)
    );
    assert!(ShakePreparationPlan::batch(spec(272, 409, 3, 2)).is_ok());
    assert!(ShakePreparationPlan::singleton(spec(272, 409, 5, 1)).is_ok());
    assert_eq!(
        ShakePreparationPlan::batch(spec(272, 409, 4, 2)),
        Err(Error::Transition)
    );
    assert_eq!(
        ShakePreparationPlan::singleton(spec(272, 409, 6, 1)),
        Err(Error::Segment)
    );
}

#[test]
fn zero_output_exact_rate_and_campaign_limits_match_native_geometry() {
    let empty = ShakePreparationPlan::singleton(spec(0, 0, 0, 1)).unwrap();
    assert_eq!(empty.trace_device().source_bytes(), 8);
    assert_eq!(empty.geometry().trace_spec().output_len, 0);
    assert_eq!(empty.trace_device().public_bytes(), 216 * 8);
    assert_eq!(
        ShakePreparationPlan::batch(spec(0, 0, 0, 1)),
        Err(Error::Transition)
    );
    // Full first output is produced during final absorption; it cannot join
    // the homogeneous squeezing batch even when exactly rate-sized.
    assert!(ShakePreparationPlan::singleton(spec(0, 136, 0, 1)).is_ok());
    assert_eq!(
        ShakePreparationPlan::singleton(spec(0, 136, 1, 1)),
        Err(Error::Segment)
    );
    assert!(ShakePreparationPlan::batch(spec(0, 272, 1, 1)).is_ok());
    assert_eq!(
        ShakePreparationPlan::batch(spec(0, 271, 1, 1)),
        Err(Error::Transition)
    );
    assert!(ShakePreparationPlan::batch(spec(136 * 256, 0, 0, 256)).is_ok());
    assert_eq!(
        ShakePreparationPlan::batch(spec(136 * 512, 0, 0, 512)),
        Err(Error::RowLimit)
    );
    assert_eq!(
        ShakePreparationPlan::batch(spec(136 * 3, 0, 0, 3)),
        Err(Error::Transition)
    );
    assert_eq!(
        ShakePreparationPlan::singleton(spec(0, 0, 0, 0)),
        Err(Error::Segment)
    );
    assert_eq!(
        ShakePreparationPlan::singleton(spec(0, 0, 0, 2)),
        Err(Error::Segment)
    );
    assert_eq!(
        ShakePreparationPlan::singleton(spec(0, 0, usize::MAX, 1)),
        Err(Error::Overflow)
    );
    assert_eq!(
        ShakePreparationPlan::singleton(spec(u32::MAX as usize + 1, 0, 0, 1)),
        Err(Error::Length)
    );
    assert_eq!(
        ShakePreparationPlan::singleton(spec(0, u32::MAX as usize + 1, 0, 1)),
        Err(Error::Length)
    );
}

#[test]
fn five_trace_owners_and_retained_preparation_have_separate_additive_censuses() {
    let a = ShakePreparationPlan::singleton(spec(0, 0, 0, 1)).unwrap();
    let b = ShakePreparationPlan::batch(spec(136 * 8, 0, 0, 8)).unwrap();
    assert_eq!(a.host(), b.host());
    let d = b.trace_device();
    assert_eq!(d.trace_bytes(), 8 * 4096 * 518 * 8);
    assert_eq!(d.source_bytes(), 136 * 8 * 8);
    assert_eq!(d.scratch_bytes(), (8 * 133 + 216) * 8);
    assert_eq!(
        d.generation_peak_bytes(),
        d.trace_bytes()
            + d.public_bytes()
            + d.source_bytes()
            + d.scratch_bytes()
            + d.geometry_bytes()
    );
    assert_eq!(
        d.generated_output_bytes().unwrap(),
        d.trace_bytes() + d.public_bytes()
    );
    assert_eq!(d.largest_allocation_bytes(), d.trace_bytes());
    let h = a.host();
    assert_eq!(h.periodic_staging_bytes(), 132_048);
    assert_eq!(h.prepared_partition_bytes().unwrap(), (192 << 20) + 132_048);
    assert!(h.air_callback_heap_bytes() > 0);
    assert!(h.trace_matrix_backing_bytes() > 0);
    assert_eq!(
        h.required_host_bytes(),
        h.symbolic_compiler_bytes()
            + h.periodic_staging_bytes()
            + h.air_callback_heap_bytes()
            + h.public_readback_and_conversion_bytes()
            + h.trace_upload_staging_bytes()
            + h.trace_matrix_backing_bytes()
            + h.explicit_owner_bytes()
            + a.configuration().required_host_bytes()
            + a.planner().required_host_bytes()
    );
    // Configuration includes its own runtime partition, without pretending
    // the generic runtime reservation covers caller-owned seed/config payload.
    let c = a.configuration();
    assert_eq!(c.permutation_backing_bytes(), 7 * 688);
    assert!(c.owned_seed_and_configuration_bytes() >= 192 + size_of::<[ChaCha20Rng; 3]>());
    assert!(c.opening_runtime_host_partition_bytes() > 0);
    assert_eq!(
        c.required_host_bytes(),
        c.permutation_backing_bytes()
            + c.cpu_mmcs_backing_bytes()
            + c.shared_rng_backing_bytes()
            + c.empty_dft_cache_backing_bytes()
            + c.resident_state_backing_bytes()
            + c.device_rng_backing_bytes()
            + c.opening_runtime_host_partition_bytes()
            + c.owned_seed_and_configuration_bytes()
    );
    assert!(a.planner().original_json_requests_bytes() > 0);
    assert!(a.planner().required_host_bytes() > a.planner().maintained_bounded_planner_bytes());
}

#[test]
fn planner_report_literals_fit_the_source_fixed_string_census() {
    // A changed fixed report label must not silently escape the JSON census.
    // Failure diagnostics (containing spaces) use PlannerResources' separate
    // 4096-byte scratch. Keys, phase names and schema contain these characters.
    let sources = [
        include_str!("../../../gpu_hash/engine/device/wallet/proof_storage/phases.rs"),
        include_str!("../../../gpu_hash/engine/device/wallet/proof_storage/phases/inputs.rs"),
        include_str!("../../../gpu_hash/engine/device/wallet/proof_storage/phases/commitments.rs"),
        include_str!("../../../gpu_hash/engine/device/wallet/proof_storage/phases/fri.rs"),
        include_str!("../../../gpu_hash/engine/device/wallet/proof_storage/phases/randomness.rs"),
        include_str!("../../../gpu_hash/engine/device/wallet/proof_storage/phases/operations.rs"),
    ];
    for source in sources {
        for literal in source.split('"').skip(1).step_by(2) {
            if !literal.is_empty()
                && literal
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
            {
                assert!(literal.len() <= 64, "changed planner label: {literal}");
            }
        }
    }
}

#[test]
fn commitment_report_arrays_have_explicit_backing_in_both_json_copies() {
    // Pin the existing source-owned field type so changing it cannot silently
    // leave a three-item array allowance in the original-report census.
    let storage = include_str!("../../../gpu_hash/engine/device/commit_storage.rs");
    assert!(storage.contains("pub allocation_bytes: [usize; 3]"));
    assert_eq!(
        commitment_array_requests().unwrap(),
        11 * (3 * size_of::<serde_json::Value>() + size_of::<Vec<serde_json::Value>>())
    );
    assert!(legacy_json_requests().unwrap() > 2 * commitment_array_requests().unwrap());
}
