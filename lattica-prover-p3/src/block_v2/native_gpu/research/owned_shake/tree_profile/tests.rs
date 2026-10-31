use super::*;
use crate::{
    block_v2::gpu_hash::engine::retained_storage::Selection,
    ringct_research_quota::WorkerAllowance, spill_alloc::allocation_requests::measure,
};

fn ledger() -> Ledger {
    Ledger::new(WorkerAllowance {
        host: WORKER_HOST,
        device: MANAGED_DEVICE,
    })
}

#[test]
fn host_runtime_requires_original_complete_quota_and_same_ledger() {
    let ledger = ledger();
    let foreign = self::ledger();
    let device = StartupPlan::new().unwrap().footprint();
    let host = StartupPlan::outer_host_v1().unwrap().footprint();
    assert_eq!(host.retained_tree_host_bytes, HOST_TREES);
    assert!(host.retained_tree_quota_wrapper_bytes > 0);
    assert_eq!(
        host.requested_host_bytes - device.requested_host_bytes,
        HOST_TREES + host.retained_tree_quota_wrapper_bytes
    );
    assert_eq!(host.managed_device_bytes, device.managed_device_bytes);
    assert_eq!(host.source_sha3, device.source_sha3);
    let token = ledger
        .reserve(
            Category::PhaseScratch,
            Bytes {
                host: host.requested_host_bytes as u64,
                device: host.managed_device_bytes as u64,
            },
        )
        .unwrap();
    let (_, allocations) = measure(|| {
        assert_eq!(
            TreeProfile::OuterHostV1.check_startup(&token, &ledger),
            Ok(host.managed_device_bytes)
        );
        assert_eq!(
            TreeProfile::OuterHostV1.check_startup(&token, &foreign),
            Err(Error::Authority)
        );
        assert_eq!(
            TreeProfile::OuterHostV1.check_source(device),
            Err(Error::Authority)
        );
        assert_eq!(
            TreeProfile::Device.check_source(host),
            Err(Error::Authority)
        );
        assert_eq!(TreeProfile::Device.additional_wrapper_host_bytes(), Ok(0));
        assert!(
            TreeProfile::OuterHostV1
                .additional_wrapper_host_bytes()
                .unwrap()
                > 0
        );
    });
    assert_eq!(
        (allocations.calls, allocations.bytes, allocations.overflow),
        (0, 0, false)
    );
    drop(token);
    for (category, claimed_host, claimed_device) in [
        (
            Category::PhaseScratch,
            host.requested_host_bytes - 1,
            host.managed_device_bytes,
        ),
        (
            Category::PhaseScratch,
            device.requested_host_bytes,
            host.managed_device_bytes,
        ),
        (
            Category::PhaseScratch,
            host.requested_host_bytes - host.retained_tree_quota_wrapper_bytes,
            host.managed_device_bytes,
        ),
        (
            Category::PhaseScratch,
            host.requested_host_bytes,
            host.managed_device_bytes - 1,
        ),
        (
            Category::Report,
            host.requested_host_bytes,
            host.managed_device_bytes,
        ),
    ] {
        let token = ledger
            .reserve(
                category,
                Bytes {
                    host: claimed_host as u64,
                    device: claimed_device as u64,
                },
            )
            .unwrap();
        assert_eq!(
            TreeProfile::OuterHostV1.check_startup(&token, &ledger),
            Err(Error::Authority)
        );
        drop(token);
        assert_eq!(ledger.snapshot().current, Bytes::ZERO);
    }
}

#[test]
fn complete_host_tree_graph_includes_every_header_and_refuses_maximum_rows() {
    let selection = Selection {
        mode: RetainedTreeStorageMode::HostBacking,
        host_bytes: HOST_TREES,
    };
    // A height-one tree owns one digest plus its one-digest cap. The remaining
    // charge is the real RetainedTree header from the production census.
    let header = selection.charged_tree_bytes(1, 6).unwrap() - 64;
    assert!(header > 0);
    for (rows, payload_and_caps, count) in [
        (4096usize, 33_583_104usize, 16usize),
        (8192, 67_139_552, 17),
        (32768, 268_470_176, 19),
        (524288, 4_295_010_080, 23),
        (1048576, 8_589_979_392, 24),
    ] {
        let height = rows * 32;
        let mut complete = 3 * selection.charged_tree_bytes(height, 6).unwrap();
        let mut layer = height;
        while layer > 16 {
            layer /= 2;
            complete += selection.charged_tree_bytes(layer, 6).unwrap();
        }
        assert_eq!(complete, payload_and_caps + count * header);
        assert_eq!(
            TreeProfile::OuterHostV1
                .check_graph(selection.mode, HOST_TREES, complete)
                .is_ok(),
            rows < 1 << 20
        );
    }
    assert_eq!(
        TreeProfile::OuterHostV1.check_graph(selection.mode, HOST_TREES, HOST_TREES),
        Ok(())
    );
    for (mode, quota, complete) in [
        (selection.mode, HOST_TREES, HOST_TREES + 1),
        (selection.mode, HOST_TREES, 0),
        (selection.mode, HOST_TREES - 1, 1),
        (selection.mode, HOST_TREES + 1, 1),
        (RetainedTreeStorageMode::Device, HOST_TREES, 1),
    ] {
        assert_eq!(
            TreeProfile::OuterHostV1.check_graph(mode, quota, complete),
            Err(Error::Admission)
        );
    }
    assert_eq!(
        TreeProfile::Device.check_graph(RetainedTreeStorageMode::Device, 0, 0),
        Ok(())
    );
    assert_eq!(
        TreeProfile::Device.check_graph(selection.mode, HOST_TREES, 1),
        Err(Error::Admission)
    );
}

#[test]
fn original_host_quota_and_additive_wrappers_reduce_actual_pcs_allowance() {
    let ledger = ledger();
    assert_eq!(operation_host_budget(&ledger), Ok(NATIVE_HOST));
    let host = StartupPlan::outer_host_v1().unwrap().footprint();
    let runtime = ledger
        .reserve(
            Category::PhaseScratch,
            Bytes {
                host: host.requested_host_bytes as u64,
                device: host.managed_device_bytes as u64,
            },
        )
        .unwrap();
    let wrappers = ledger
        .reserve(
            Category::PhaseScratch,
            Bytes {
                host: (wrapper_host_bytes().unwrap()
                    + TreeProfile::OuterHostV1
                        .additional_wrapper_host_bytes()
                        .unwrap()) as u64,
                device: 0,
            },
        )
        .unwrap();
    let remaining = ledger.remaining();
    assert!(remaining.host < NATIVE_HOST as u64);
    assert_eq!(operation_host_budget(&ledger), Ok(remaining.host as usize));
    let rest = ledger
        .reserve(
            Category::PhaseScratch,
            Bytes {
                host: remaining.host,
                device: 0,
            },
        )
        .unwrap();
    assert_eq!(operation_host_budget(&ledger), Err(Error::Admission));
    drop(rest);
    assert_eq!(operation_host_budget(&ledger), Ok(remaining.host as usize));
    drop(wrappers);
    drop(runtime);
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
}
