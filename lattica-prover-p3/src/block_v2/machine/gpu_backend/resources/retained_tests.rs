use super::*;
use crate::spill_alloc::allocation_requests::measure;
use p3_field::PrimeCharacteristicRing;

fn bounds() -> Bounds {
    Bounds {
        rows: 16,
        main_columns: 98,
        preprocessing_columns: 200,
        metadata_bytes: 65536,
        compiler_host_bytes: 262144,
        compiler_retained_host_bytes: 0,
        pcs_retained_host_bytes: 0,
        program_host_bytes: 1048576,
        program_retained_host_bytes: 0,
        wires: 4096,
        input_values: 64,
    }
}

#[test]
fn schedule_cache_bound_does_not_scale_transient_compiler_workspace() {
    let mut historical = bounds();
    historical.program_host_bytes = 1 << 16;
    let mut precise = historical.clone();
    precise.compiler_retained_host_bytes = 8192;
    for entries in [1, 3, 12] {
        let old = historical.reservation(entries).unwrap();
        let new = precise.reservation(entries).unwrap();
        assert_eq!(old.host_bytes - new.host_bytes, entries * (196608 - 8192));
        assert_eq!(old.managed_bytes, new.managed_bytes);
        assert_eq!(old.max_allocation_bytes, new.max_allocation_bytes);
        let mut larger_peak = precise.clone();
        larger_peak.compiler_host_bytes += 1 << 20;
        assert_eq!(
            larger_peak.reservation(entries).unwrap().host_bytes - new.host_bytes,
            1 << 20
        );
        let mut larger_schedule = precise.clone();
        larger_schedule.compiler_retained_host_bytes += 128;
        assert_eq!(
            larger_schedule.reservation(entries).unwrap().host_bytes - new.host_bytes,
            entries * 128
        );
    }
    let mut old_json = serde_json::to_value(&historical).unwrap();
    old_json
        .as_object_mut()
        .unwrap()
        .remove("compiler_retained_host_bytes");
    assert_eq!(
        serde_json::from_value::<Bounds>(old_json.clone()).unwrap(),
        historical
    );
    for invalid in [
        serde_json::Value::Null,
        serde_json::json!(true),
        serde_json::json!(-1),
        serde_json::json!("1"),
    ] {
        old_json["compiler_retained_host_bytes"] = invalid;
        assert!(serde_json::from_value::<Bounds>(old_json.clone()).is_err());
    }
    for retained in [196609, u64::MAX] {
        let mut bad = historical.clone();
        bad.compiler_retained_host_bytes = retained;
        assert!(bad.reservation(1).is_err());
    }
    eprintln!("schedule_reservation legacy_unchanged=true cache_entries=1,3,12 compiler_peak_transient=true malformed_rejected=true");
}

#[test]
fn worker_rejects_schedule_understatement_despite_a_larger_compiler_peak() {
    let mut actual = bounds();
    actual.compiler_retained_host_bytes = 8192;
    let mut declared = actual.clone();
    declared.compiler_host_bytes *= 2;
    declared.compiler_retained_host_bytes -= 1;
    assert!(!declared.covers(&actual));
    let mut value = serde_json::json!({
        "gpu_witness":true,"gpu_pcs_device_only":true,"gpu_quotient_eval":true,
        "gpu_quotient_resident":true,"gpu_lookup":true,"gpu_opening_eval":true,"gpu_fri_resident":true,
        "witness_bounds":declared,"witness_reservation":declared.reservation(1).unwrap(),
        "owned_quotient_reservation":{"managed_bytes":67108864},
        "gpu":{"version":1,"managed_bytes":268435456,"max_allocation_bytes":67108864},
        "host":{"worker_bytes":1073741824}
    });
    validate_assignment(&value, true, None).unwrap();
    assert!(validate_assignment(&value, true, Some(&actual)).is_err());
    declared.compiler_retained_host_bytes += 1;
    value["witness_bounds"] = serde_json::to_value(&declared).unwrap();
    value["witness_reservation"] = serde_json::to_value(declared.reservation(1).unwrap()).unwrap();
    validate_assignment(&value, true, Some(&actual)).unwrap();
    assert!(validate_assignment(&value, true, Some(&bounds())).is_err());
    eprintln!("schedule_admission exact_boundary=true understatement_rejected=true historical_actual_conservative=true");
}

#[test]
fn construction_is_transient_and_legacy_reservations_remain_conservative() {
    let historical = bounds();
    let mut precise = historical.clone();
    precise.program_retained_host_bytes = 1 << 18;
    for entries in [1, 3, 12] {
        let old = historical.reservation(entries).unwrap();
        let new = precise.reservation(entries).unwrap();
        assert_eq!(new.managed_bytes, old.managed_bytes);
        assert_eq!(new.max_allocation_bytes, old.max_allocation_bytes);
        assert_eq!(old.host_bytes - new.host_bytes, entries * (3 << 18));
        let mut higher_peak = precise.clone();
        higher_peak.program_host_bytes += 1 << 20;
        assert_eq!(
            higher_peak.reservation(entries).unwrap().host_bytes - new.host_bytes,
            1 << 20
        );
        let mut higher_retained = precise.clone();
        higher_retained.program_retained_host_bytes += 4096;
        assert_eq!(
            higher_retained.reservation(entries).unwrap().host_bytes - new.host_bytes,
            entries * 4096
        );
    }
    let mut legacy_json = serde_json::to_value(&historical).unwrap();
    legacy_json
        .as_object_mut()
        .unwrap()
        .remove("program_retained_host_bytes");
    assert_eq!(
        serde_json::from_value::<Bounds>(legacy_json.clone()).unwrap(),
        historical
    );
    for invalid in [
        serde_json::Value::Null,
        serde_json::json!(true),
        serde_json::json!(-1),
        serde_json::json!("1"),
    ] {
        legacy_json["program_retained_host_bytes"] = invalid;
        assert!(serde_json::from_value::<Bounds>(legacy_json.clone()).is_err());
    }
    for retained in [historical.program_host_bytes + 1, u64::MAX] {
        let mut bad = historical.clone();
        bad.program_retained_host_bytes = retained;
        assert!(bad.reservation(1).is_err());
    }
    eprintln!("retained_source_reservation legacy_unchanged=true cache_entries=1,3,12 construction_transient=true malformed_rejected=true");
}

#[test]
fn worker_rejects_retained_understatement_even_with_a_larger_construction_peak() {
    let mut actual = bounds();
    actual.program_retained_host_bytes = 1 << 18;
    let mut declared = actual.clone();
    declared.program_host_bytes *= 2;
    declared.program_retained_host_bytes -= 1;
    assert!(!declared.covers(&actual));
    let mut value = serde_json::json!({
        "gpu_witness":true,"gpu_pcs_device_only":true,"gpu_quotient_eval":true,
        "gpu_quotient_resident":true,"gpu_lookup":true,"gpu_opening_eval":true,"gpu_fri_resident":true,
        "witness_bounds":declared,"witness_reservation":declared.reservation(1).unwrap(),
        "owned_quotient_reservation":{"managed_bytes":67108864},
        "gpu":{"version":1,"managed_bytes":268435456,"max_allocation_bytes":67108864},
        "host":{"worker_bytes":1073741824}
    });
    validate_assignment(&value, true, None).unwrap();
    assert!(validate_assignment(&value, true, Some(&actual)).is_err());
    declared.program_retained_host_bytes += 1;
    value["witness_bounds"] = serde_json::to_value(&declared).unwrap();
    value["witness_reservation"] = serde_json::to_value(declared.reservation(1).unwrap()).unwrap();
    validate_assignment(&value, true, Some(&actual)).unwrap();
    assert!(validate_assignment(&value, true, Some(&bounds())).is_err());
    eprintln!("retained_source_admission exact_boundary=true understatement_rejected=true legacy_actual_conservative=true");
}

#[test]
fn source_counts_arc_and_nested_spare_capacity_without_allocating() {
    let mut builder = ProgramBuilder::new(1).unwrap();
    let x = builder.input();
    let bit = builder.bit_hint(x, 0);
    let _hint = builder.select_hint(vec![x, x], &[bit]);
    let one = builder.constant(Val::ONE);
    let _product = builder.mul(x, one);
    let mut program = builder.finish(None).unwrap();
    let identity = program.clone();
    let before = Bounds::for_program(&program).unwrap();
    let mut extra = 0;
    macro_rules! grow {
        ($values:expr, $ty:ty, $count:expr) => {{
            let values = &mut $values;
            let old = values.capacity();
            values.reserve_exact($count);
            extra += bytes::<$ty>(values.capacity() - old).unwrap();
        }};
    }
    grow!(program.operations, Op, 1024);
    grow!(program.rows, Row, 128);
    grow!(program.references, u32, 256);
    let mut hints = 0;
    for op in &mut program.operations {
        if let Op::SelectHint { entries, bits, .. } = op {
            grow!(*entries, Wire, 32);
            grow!(*bits, Wire, 16);
            hints += 1;
        }
    }
    let mut packed = 0;
    for row in &mut program.rows {
        if let Row::Alu(ops) | Row::Cubic(ops) = row {
            grow!(*ops, u32, 128);
            packed += 1;
        }
    }
    assert!(extra > 0 && hints > 0 && packed > 0);
    let (after, planning) = measure(|| Bounds::for_program(&program));
    let after = after.unwrap();
    assert_eq!(planning.calls, 0);
    assert_eq!(
        after.program_retained_host_bytes - before.program_retained_host_bytes,
        extra
    );
    assert_eq!(program, identity);
    assert_eq!(after.metadata_bytes, before.metadata_bytes);
    let (air, allocation) = measure(|| air::MachineAir::new(program));
    let expected = std::mem::size_of::<Program>() + 2 * std::mem::size_of::<usize>();
    assert_eq!((allocation.calls, allocation.bytes), (1, expected));
    assert_eq!(Bounds::for_program(air.program()).unwrap(), after);
    eprintln!("retained_source_capacity planning_allocation_free=true arc_bytes={expected} spare_bytes={extra} hint_buffers={hints} packed_rows={packed} identity_unchanged=true");
}
