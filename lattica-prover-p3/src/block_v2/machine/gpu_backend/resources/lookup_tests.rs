use super::*;

fn bounds() -> Bounds {
    Bounds {
        rows: 16,
        main_columns: 98,
        preprocessing_columns: 200,
        metadata_bytes: 65536,
        compiler_host_bytes: 262144,
        compiler_retained_host_bytes: 8192,
        pcs_retained_host_bytes: 0,
        program_host_bytes: 1048576,
        program_retained_host_bytes: 262144,
        wires: 4096,
        input_values: 64,
    }
}

#[test]
fn cached_lookup_graphs_overlap_incoming_construction_and_verification() {
    let b = bounds();
    let lookup = crate::block_v2::machine::symbolic::LOOKUP_RETAINED_HOST_BYTES;
    assert_eq!(lookup, 64 << 20);
    let one = b.reservation(1).unwrap();
    for entries in [1, 3, 12] {
        let reservation = b.reservation(entries).unwrap();
        assert_eq!(
            reservation.host_bytes - one.host_bytes,
            (entries - 1) * (262144 + 8192 + lookup + b.retained_pcs_bytes().unwrap())
        );
        // A miss can build its incoming source before eviction. Raising that
        // peak must add workspace once without consuming any cached graph.
        let mut incoming = b.clone();
        incoming.program_host_bytes += 1 << 20;
        assert_eq!(
            incoming.reservation(entries).unwrap().host_bytes - reservation.host_bytes,
            1 << 20
        );
        // Both the symbolic construction and independent verifier components
        // remain reserved while the cache lives, including a single entry.
        assert!(
            reservation.host_bytes
                >= entries * lookup
                    + crate::block_v2::machine::symbolic::HOST_BYTES
                    + crate::block_v2::machine::backend::NATIVE_VERIFIER_COMPONENT_BYTES
                    + b.program_host_bytes
        );
    }
    eprintln!("cached_lookup_overlap entries=1,3,12 retained_bytes_per_entry={lookup} incoming_peak_once=true symbolic_workspace_preserved=true independent_verifier_preserved=true");
}

#[test]
fn workers_reject_stale_lookup_reservations_even_with_spare_physical_memory() {
    let b = bounds();
    for entries in [1, 3, 12] {
        let reserve = b.reservation(entries).unwrap();
        let mut value = serde_json::json!({
            "gpu_witness":true,"gpu_pcs_device_only":true,"gpu_quotient_eval":true,
            "gpu_quotient_resident":true,"gpu_lookup":true,"gpu_opening_eval":true,"gpu_fri_resident":true,
            "preprocessing_cache":{"entries":entries},
            "witness_bounds":b,"witness_reservation":reserve,
            "owned_quotient_reservation":{"managed_bytes":67108864},
            "gpu":{"managed_bytes":2147483648u64,"max_allocation_bytes":1073741824u64},
            "host":{"worker_bytes":3221225472u64}
        });
        validate_assignment(&value, true, Some(&b)).unwrap();
        value["witness_reservation"]["host_bytes"] = serde_json::json!(
            reserve.host_bytes
                - entries * crate::block_v2::machine::symbolic::LOOKUP_RETAINED_HOST_BYTES
        );
        assert!(validate_assignment(&value, true, Some(&b))
            .unwrap_err()
            .contains("bounds or reservation"));
        value["witness_reservation"]["host_bytes"] = (reserve.host_bytes - 1).into();
        assert!(validate_assignment(&value, true, Some(&b)).is_err());
        value["witness_reservation"]["host_bytes"] = reserve.host_bytes.into();
        value["host"]["worker_bytes"] = (reserve.host_bytes - 1).into();
        assert!(validate_assignment(&value, true, Some(&b))
            .unwrap_err()
            .contains("worker allowance"));
        value["host"]["worker_bytes"] = reserve.host_bytes.into();
        validate_assignment(&value, true, Some(&b)).unwrap();
    }
    eprintln!("cached_lookup_assignment entries=1,3,12 stale_rejected=true one_byte_short_rejected=true exact_boundary=true");
}

#[test]
fn host_admission_keeps_cached_lookup_storage_at_its_exact_boundary() {
    use crate::spill_alloc::allocation_requests::measure;
    let b = bounds();
    let (reserve, measured) = measure(|| b.reservation(1).unwrap());
    assert_eq!(measured.calls, 0);
    assert!(b.admit_host(reserve.host_bytes - (64 << 20)).is_err());
    assert!(b.admit_host(reserve.host_bytes - 1).is_err());
    let (admitted, measured) = measure(|| b.admit_host(reserve.host_bytes).unwrap());
    assert_eq!(admitted, reserve);
    assert_eq!(measured.calls, 0);
    eprintln!("cached_lookup_host_admission exact_boundary=true planning_allocation_free=true");
}
