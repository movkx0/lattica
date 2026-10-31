use super::*;

#[test]
fn raw_sampler_id_collection_carries_the_source_allocation_capacity() {
    // Exercise the actual owned-array -> compact-ID collector pattern. A
    // length-only ID charge would miss 127/128 of the reused backing.
    for count in [2, 4] {
        let raw: Vec<RawPoly> = (0..count).map(|_| [7; D]).collect();
        let source_pointer = raw.as_ptr() as usize;
        let source_bytes = raw.capacity() * size_of::<RawPoly>();
        let ids: Vec<PolyId> = raw
            .into_iter()
            .map(|values| PolyId {
                owner: values[0],
                index: values[1] as usize,
            })
            .collect();
        assert_eq!(ids.len(), count);
        let retained = ids.capacity() * size_of::<PolyId>();
        if ids.as_ptr() as usize == source_pointer {
            assert_eq!(retained, source_bytes);
            assert!(retained > ids.len() * size_of::<PolyId>());
        } else {
            assert!(retained <= growing::<PolyId>(count).unwrap());
        }
        assert!(retained <= growing::<RawPoly>(count).unwrap() + growing::<PolyId>(count).unwrap());
    }
}

#[test]
fn core_operation_allowance_is_derived_inside_the_full_adapter_charge() {
    let plan = RawAdapterPlan::fixed().unwrap();
    assert_eq!(plan.operation_host_allowance, 3_060_528);
    assert_eq!(
        plan.host_bytes,
        plan.framing
            + plan.crypto_returns
            + plan.sampled_polynomials
            + plan.arithmetic
            + plan.wrappers
            + size_of::<RawAdapterPlan>()
    );
    assert!(plan.host_bytes > plan.operation_host_allowance);
    if cfg!(feature = "opencl") {
        assert_eq!(plan.device_bytes, 1_844_280);
    } else {
        assert_eq!(plan.device_bytes, 0);
    }
}

#[cfg(feature = "native-verification-allocation-audit")]
#[test]
#[ignore = "process-wide allocation observer; coordinator must serialize"]
fn raw_adapter_plan_itself_has_no_allocation_or_dispatch() {
    crate::component_tree::shake_verification_memory::observe_planner_allocations(0, || {
        assert!(RawAdapterPlan::fixed().is_ok());
    });
}
