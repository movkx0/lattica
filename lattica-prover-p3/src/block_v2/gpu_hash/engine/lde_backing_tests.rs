//! Admission boundaries without allocating the symbolically planned matrices.
use super::super::lde_readback::{backing_bytes, ReadbackLayout};
use super::*;

const MIB: usize = 1 << 20;
const HEADER: usize = if cfg!(feature = "stream") { 4096 } else { 0 };

fn plan(
    inputs: &[InputShape],
    retention: LdeRetention,
    layout: ReadbackLayout,
    budget: usize,
) -> Result<LdeCommitPlan, String> {
    let limits = Limits::default();
    LdeCommitPlan::new_with_retention(
        inputs,
        6,
        limits,
        64 * MIB,
        1,
        CONSTANT_BYTES + limits.staging_bytes,
        0,
        budget,
        retention,
        layout,
    )
}

#[test]
fn exact_budget_includes_each_output_and_largest_reorder_backing() {
    let inputs = [InputShape {
        height: 1 << 18,
        width: 16,
        added_bits: 2,
    }; 2];
    for layout in [ReadbackLayout::Direct, ReadbackLayout::Banded] {
        let reorder = if layout == ReadbackLayout::Banded {
            128 * MIB + HEADER
        } else {
            0
        };
        let budget = 2 * (128 * MIB + HEADER) + reorder;
        let admitted = plan(&inputs, LdeRetention::HostPrefix(0), layout, budget).unwrap();
        assert!(admitted.columns_per_tile() < inputs[0].width);
        assert_eq!(admitted.host_output_bytes, 256 * MIB);
        assert_eq!(admitted.host_output_backing_bytes, 256 * MIB + 2 * HEADER);
        assert_eq!(admitted.host_reorder_backing_bytes, reorder);
        assert_eq!(admitted.predicted_host_peak_bytes, budget);
        assert_eq!(admitted.projected_host_readback_bytes, 256 * MIB);
        assert!(plan(&inputs, LdeRetention::HostPrefix(0), layout, budget - 1).is_err());
    }
}

#[test]
fn prefix_crosses_allocator_threshold_and_device_only_has_no_host_backing() {
    let inputs = [InputShape {
        height: 1 << 18,
        width: 8,
        added_bits: 2,
    }];
    for layout in [ReadbackLayout::Direct, ReadbackLayout::Banded] {
        let full = plan(
            &inputs,
            LdeRetention::HostPrefix(0),
            layout,
            64 * MIB + HEADER,
        )
        .unwrap();
        let prefix = plan(&inputs, LdeRetention::HostPrefix(1), layout, 32 * MIB).unwrap();
        assert_eq!(full.host_output_bytes, 64 * MIB);
        assert_eq!(full.host_output_backing_bytes, 64 * MIB + HEADER);
        assert_eq!(prefix.host_output_bytes, full.host_output_bytes / 2);
        assert_eq!(prefix.host_output_backing_bytes, 32 * MIB);
        assert_eq!(prefix.host_reorder_backing_bytes, 0);
        assert_eq!(prefix.predicted_host_peak_bytes, 32 * MIB);
        assert!(plan(&inputs, LdeRetention::HostPrefix(1), layout, 32 * MIB - 1).is_err());
        let device = plan(&inputs, LdeRetention::DeviceOnly, layout, 0).unwrap();
        assert_eq!(device.host_output_backing_bytes, 0);
        assert_eq!(device.host_reorder_backing_bytes, 0);
        assert_eq!(device.predicted_host_peak_bytes, 0);
        assert_eq!(device.projected_host_readback_bytes, 0);
    }
}

#[test]
fn quotient_payload_at_heap_ceiling_accounts_for_its_header() {
    let inputs = [InputShape {
        height: 1 << 18,
        width: 1024,
        added_bits: 0,
    }];
    let admitted = plan(
        &inputs,
        LdeRetention::HostPrefix(0),
        ReadbackLayout::Direct,
        (2 << 30) + HEADER,
    )
    .unwrap();
    assert_eq!(admitted.host_output_bytes, 2 << 30);
    assert_eq!(admitted.host_output_backing_bytes, (2 << 30) + HEADER);
    let result = admitted.validate_quotient_storage();
    if cfg!(feature = "stream") {
        assert_eq!(
            result.unwrap_err(),
            "quotient heap matrix allowance exceeded"
        );
    } else {
        result.unwrap();
    }
}

#[test]
fn backing_layout_handles_zero_rounding_and_overflow_without_allocating() {
    assert_eq!(backing_bytes(0).unwrap(), 0);
    assert_eq!(backing_bytes(64 * MIB / 8 - 1).unwrap(), 64 * MIB - 8);
    assert_eq!(backing_bytes(64 * MIB / 8).unwrap(), 64 * MIB + HEADER);
    let tail = if cfg!(feature = "stream") { 8192 } else { 8 };
    assert_eq!(backing_bytes(64 * MIB / 8 + 1).unwrap(), 64 * MIB + tail);
    assert!(backing_bytes(usize::MAX).is_err());
}

#[cfg(feature = "stream")]
#[test]
fn quotient_heap_ceiling_rejects_before_staging_allocation() {
    use super::super::lde_readback::{HostReadback, OutputStorage};
    for layout in [ReadbackLayout::Direct, ReadbackLayout::Banded] {
        let (result, requests) = crate::spill_alloc::allocation_requests::measure(|| {
            HostReadback::with_layout(1 << 18, 1024, 2, OutputStorage::QuotientHeap, layout)
        });
        assert_eq!(
            result.err().expect("backing exceeds ceiling"),
            "quotient heap matrix allowance exceeded"
        );
        assert!(
            requests.largest < MIB,
            "allocated before rejection: {requests:?}"
        );
    }
}
