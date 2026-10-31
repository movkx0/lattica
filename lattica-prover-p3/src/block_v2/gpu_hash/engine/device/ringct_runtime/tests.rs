use super::*;

fn canonical() -> [Option<&'static [u8]>; 61] {
    let mut values: [Option<&[u8]>; 61] = [None; 61];
    values[..18].fill(Some(b"1"));
    values[18] = Some(b"gpu-required");
    values[19] = Some(b"8589934592");
    values[20] = Some(b"4294967296");
    values[21] = Some(b"25769803776");
    values[22] = Some(b"device");
    values[23] = Some(b"baseline");
    values[24] = Some(b"8");
    values[46] = Some(b"0");
    values[47] = Some(b"GPU-00000000-0000-0000-0000-000000000001");
    values
}

fn check(values: &[Option<&[u8]>; 61]) -> Result<(), Error> {
    check_profile(TreeProfile::Device, values)
}

fn check_profile(tree_profile: TreeProfile, values: &[Option<&[u8]>; 61]) -> Result<(), Error> {
    validate_values(tree_profile, |key| {
        let index = KEYS
            .iter()
            .position(|tracked| *tracked == key)
            .ok_or(Error::Configuration)?;
        Ok(values[index])
    })
}

fn outer_host() -> [Option<&'static [u8]>; 61] {
    let mut values = canonical();
    values[KEYS
        .iter()
        .position(|key| *key == c"LATTICA_V2_GPU_RETAINED_TREE_STORAGE")
        .unwrap()] = Some(b"host");
    values[KEYS
        .iter()
        .position(|key| *key == c"LATTICA_V2_GPU_RETAINED_TREE_HOST_BYTES")
        .unwrap()] = Some(b"8589934592");
    values
}

#[test]
fn outer_host_profile_is_explicit_exact_and_cannot_relax_device_default() {
    let device = canonical();
    let host = outer_host();
    assert_eq!(check(&device), Ok(()));
    assert_eq!(check_profile(TreeProfile::OuterHostV1, &host), Ok(()));
    assert_eq!(check(&host), Err(Error::Configuration));
    assert_eq!(
        check_profile(TreeProfile::OuterHostV1, &device),
        Err(Error::Configuration)
    );
    let budget = KEYS
        .iter()
        .position(|key| *key == c"LATTICA_V2_GPU_RETAINED_TREE_HOST_BYTES")
        .unwrap();
    for wrong in [
        None,
        Some(&b""[..]),
        Some(&b"0"[..]),
        Some(&b"8589934591"[..]),
        Some(&b"8589934593"[..]),
        Some(&b"34359738368"[..]),
    ] {
        let mut changed = host;
        changed[budget] = wrong;
        assert_eq!(
            check_profile(TreeProfile::OuterHostV1, &changed),
            Err(Error::Configuration)
        );
    }
    // Every non-tree selector remains identical to the original fixed profile.
    for key in [
        c"LATTICA_V2_WORKER_BUDGET",
        c"LATTICA_WALLET_WORKER_BUDGET",
        c"LATTICA_V2_GPU_CONTEXT_BYTES",
        c"LATTICA_V2_HOST_OUTPUT_BYTES",
        c"RAYON_NUM_THREADS",
        c"LATTICA_V2_GPU_RETAIN_TREES",
        c"LATTICA_V2_GPU_QUERY_GATHER",
    ] {
        let mut changed = host;
        changed[KEYS.iter().position(|tracked| *tracked == key).unwrap()] = Some(b"invalid");
        assert_eq!(
            check_profile(TreeProfile::OuterHostV1, &changed),
            Err(Error::Configuration)
        );
    }
}

#[test]
fn same_engine_policy_requires_exact_device_limits_and_tree_profile() {
    let device = engine::retained_storage::Selection {
        mode: engine::RetainedTreeStorageMode::Device,
        host_bytes: 0,
    };
    let host = engine::retained_storage::Selection {
        mode: engine::RetainedTreeStorageMode::HostBacking,
        host_bytes: OUTER_TREE_HOST,
    };
    let limits = engine::Limits {
        managed_bytes: MANAGED,
        tile_bytes: 128 << 20,
        staging_bytes: STAGING,
    };
    for (profile, trees) in [
        (TreeProfile::Device, device),
        (TreeProfile::OuterHostV1, host),
    ] {
        assert_eq!(check_engine_selection(profile, true, limits, trees), Ok(()));
        assert_eq!(
            check_engine_selection(profile, false, limits, trees),
            Err(Error::Lifecycle)
        );
        for changed in [
            engine::Limits {
                managed_bytes: MANAGED - 1,
                ..limits
            },
            engine::Limits {
                managed_bytes: MANAGED + 1,
                ..limits
            },
            engine::Limits {
                tile_bytes: (128 << 20) - 1,
                ..limits
            },
            engine::Limits {
                staging_bytes: STAGING - 1,
                ..limits
            },
        ] {
            assert_eq!(
                check_engine_selection(profile, true, changed, trees),
                Err(Error::Lifecycle)
            );
        }
    }
    for (profile, trees) in [
        (TreeProfile::Device, host),
        (TreeProfile::OuterHostV1, device),
        (
            TreeProfile::Device,
            engine::retained_storage::Selection {
                host_bytes: 1,
                ..device
            },
        ),
        (
            TreeProfile::OuterHostV1,
            engine::retained_storage::Selection {
                host_bytes: OUTER_TREE_HOST - 1,
                ..host
            },
        ),
    ] {
        assert_eq!(
            check_engine_selection(profile, true, limits, trees),
            Err(Error::Lifecycle)
        );
    }
}

#[cfg(feature = "stream")]
#[test]
fn outer_host_plan_accounts_payload_and_wrapper_without_allocating_or_device_access() {
    use crate::spill_alloc::allocation_requests::measure;
    let values = outer_host();
    let (result, requests) = measure(|| {
        check_profile(TreeProfile::OuterHostV1, &values)?;
        Ok::<_, Error>((StartupPlan::new()?, StartupPlan::outer_host_v1()?))
    });
    let (device, host) = result.unwrap();
    let device = device.footprint();
    let host = host.footprint();
    assert_eq!(requests.calls, 0);
    assert_eq!(requests.bytes, 0);
    assert!(!requests.overflow);
    assert_eq!(device.retained_tree_host_bytes, 0);
    assert_eq!(device.retained_tree_quota_wrapper_bytes, 0);
    assert_eq!(host.retained_tree_host_bytes, 8 << 30);
    assert_eq!(
        host.retained_tree_quota_wrapper_bytes,
        crate::block_v2::gpu_hash::cache_metadata::arc_bytes::<engine::retained_storage::HostQuota>(
        )
    );
    assert_eq!(
        host.requested_host_bytes,
        device.requested_host_bytes
            + host.retained_tree_host_bytes
            + host.retained_tree_quota_wrapper_bytes
    );
    assert_eq!(host.managed_device_bytes, device.managed_device_bytes);
    assert_eq!(host.managed_device_bytes, STAGING + CONSTANT_BYTES);
    assert_eq!(host.driver_context_reserve, CONTEXT);
    assert_eq!(host.source_sha3, device.source_sha3);
    assert_eq!(host.source_bytes, device.source_bytes);
}

#[test]
fn fixed_runtime_environment_rejects_policy_drift_before_initialization() {
    let valid = canonical();
    assert_eq!(check(&valid), Ok(()));
    for index in 0..25 {
        for replacement in [None, Some(&b""[..]), Some(&b"invalid"[..])] {
            let mut wrong = valid;
            wrong[index] = replacement;
            assert_eq!(check(&wrong), Err(Error::Configuration));
        }
    }
    for index in 25..32 {
        let mut wrong = valid;
        wrong[index] = Some(b"1");
        assert_eq!(check(&wrong), Err(Error::Configuration));
        wrong[index] = Some(b"0");
        assert_eq!(check(&wrong), Ok(()));
    }
    for index in (32..44).chain(48..61) {
        let mut wrong = valid;
        wrong[index] = Some(b"");
        assert_eq!(check(&wrong), Err(Error::Configuration));
    }
    for (index, invalid) in [(44, &b"events"[..]), (45, &b"2"[..])] {
        let mut wrong = valid;
        wrong[index] = Some(invalid);
        assert_eq!(check(&wrong), Err(Error::Configuration));
    }
}

#[cfg(feature = "stream")]
#[test]
fn runtime_source_plan_and_policy_validation_make_no_allocations() {
    use crate::spill_alloc::allocation_requests::measure;
    let values = canonical();
    let (result, requests) = measure(|| {
        check(&values)?;
        StartupPlan::new()
    });
    let plan = result.unwrap();
    assert_eq!(requests.calls, 0);
    assert_eq!(requests.bytes, 0);
    assert!(!requests.overflow);
    assert!(plan.footprint().source_bytes > 0);
    assert_eq!(plan.footprint().driver_context_reserve, CONTEXT);
    assert_eq!(
        plan.footprint().managed_device_bytes,
        STAGING + CONSTANT_BYTES
    );
}
