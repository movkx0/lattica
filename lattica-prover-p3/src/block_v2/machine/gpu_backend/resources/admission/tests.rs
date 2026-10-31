use super::*;
use crate::block_v2::machine::ProgramBuilder;
use crate::spill_alloc::allocation_requests::measure;
use p3_field::PrimeCharacteristicRing;

fn limits() -> RegisteredGpuLimits {
    RegisteredGpuLimits::with_selection(
        HOST_LIMIT,
        DEVICE_LIMIT,
        CONTEXT_RESERVE,
        ROW_LIMIT,
        Selection {
            mode: RetainedTreeStorageMode::Device,
            host_bytes: 0,
        },
    )
    .unwrap()
}

fn inputs() -> (Arc<Program>, [Val; 4], Vec<Val>) {
    let mut builder = ProgramBuilder::new(4).unwrap();
    let x = builder.input();
    let c = builder.constant(Val::ONE);
    let y = builder.mul(x, c);
    builder.assert_equal(x, y);
    (
        Arc::new(builder.finish(None).unwrap()),
        [Val::ZERO; 4],
        vec![Val::ONE],
    )
}

#[test]
fn diagnostics_bind_real_capacities_without_compiling_or_allocating() {
    let (program, public, mut witness) = inputs();
    witness.reserve_exact(23);
    let limits = limits();
    let (plan, requests) =
        measure(|| RegisteredGpuMemoryPlan::new(&program, &public, &witness, limits).unwrap());
    assert_eq!(requests.calls, 0);
    assert!(!requests.overflow);
    let footprint = plan.footprint();
    assert_eq!(
        footprint.input_backing_host_bytes,
        (witness.capacity() * core::mem::size_of::<Val>()) as u64
    );
    assert!(footprint.backend_host_budget_bytes <= NATIVE_HOST_LIMIT);
    assert!(
        footprint.backend_host_budget_bytes
            + footprint.host_tree_quota_bytes
            + footprint.input_backing_host_bytes
            + footprint.caller_reserved_host_bytes
            <= HOST_LIMIT
    );
    assert_eq!(
        footprint.backend_host_budget_bytes + footprint.runtime_host_reserved_bytes,
        footprint.native_host_budget_bytes
    );
    assert!(footprint.native_host_budget_bytes <= NATIVE_HOST_LIMIT);
    assert_eq!(
        footprint.native_host_budget_bytes
            + footprint.host_tree_quota_bytes
            + footprint.input_backing_host_bytes
            + footprint.caller_reserved_host_bytes,
        footprint.worker_committed_host_bytes
    );
    assert!(!footprint.host_phase_bound_complete);
    assert!(!footprint.device_phase_bound_complete);
    // A fitting retained-state floor must not accidentally open execution.
    assert!(plan.admit().is_err());
}

#[test]
fn exact_input_shapes_and_fixed_worker_limits_reject() {
    let (program, public, witness) = inputs();
    assert!(RegisteredGpuMemoryPlan::new(&program, &public[..3], &witness, limits()).is_err());
    assert!(RegisteredGpuMemoryPlan::new(&program, &public, &Vec::new(), limits()).is_err());
    let selection = limits().trees;
    for (host, device, context, rows) in [
        (HOST_LIMIT + 1, DEVICE_LIMIT, CONTEXT_RESERVE, ROW_LIMIT),
        (HOST_LIMIT, DEVICE_LIMIT + 1, CONTEXT_RESERVE, ROW_LIMIT),
        (HOST_LIMIT, DEVICE_LIMIT, CONTEXT_RESERVE - 1, ROW_LIMIT),
        (HOST_LIMIT, DEVICE_LIMIT, CONTEXT_RESERVE, ROW_LIMIT * 2),
        (HOST_LIMIT, DEVICE_LIMIT, CONTEXT_RESERVE, 15),
    ] {
        assert!(
            RegisteredGpuLimits::with_selection(host, device, context, rows, selection).is_err()
        );
    }
    assert!(RegisteredGpuLimits::with_selection(
        1 << 30,
        DEVICE_LIMIT,
        CONTEXT_RESERVE,
        ROW_LIMIT,
        Selection {
            mode: RetainedTreeStorageMode::HostBacking,
            host_bytes: 2 << 30
        }
    )
    .is_err());
}

#[test]
fn host_tree_quota_does_not_erase_device_construction_or_public_salts() {
    let (program, public, witness) = inputs();
    let device = RegisteredGpuMemoryPlan::new(&program, &public, &witness, limits())
        .unwrap()
        .footprint();
    let host_limits = RegisteredGpuLimits::with_selection(
        HOST_LIMIT,
        DEVICE_LIMIT,
        CONTEXT_RESERVE,
        ROW_LIMIT,
        Selection {
            mode: RetainedTreeStorageMode::HostBacking,
            host_bytes: 8 << 30,
        },
    )
    .unwrap();
    let host = RegisteredGpuMemoryPlan::new(&program, &public, &witness, host_limits)
        .unwrap()
        .footprint();
    assert_eq!(
        host.full_tree_device_construction_bytes,
        device.full_tree_device_construction_bytes
    );
    assert_eq!(
        host.public_salt_device_bytes,
        device.public_salt_device_bytes
    );
    assert!(host.witness_reserved_host_bytes > device.witness_reserved_host_bytes);
    assert_eq!(host.host_tree_quota_bytes, 8 << 30);
    if cfg!(feature = "block-v2-wide-lanes") {
        assert_eq!(host.retained_digest_tree_device_bytes, Some(0));
        assert_eq!(
            device.retained_digest_tree_device_bytes,
            Some(5 * device.full_tree_device_construction_bytes)
        );
        assert_eq!(
            host.quotient_payload_floor_bytes,
            device.quotient_payload_floor_bytes
        );
    }
}
