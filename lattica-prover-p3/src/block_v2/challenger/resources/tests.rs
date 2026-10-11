use super::*;

fn assignment() -> serde_json::Value {
    let random = crate::block_v2::randomness::resources::Bounds {
        rows: 16,
        main_columns: 98,
        preprocessing_columns: 200,
        lookup_columns: 55,
        quotient_rows: 256,
        quotient_chunks: 16,
    };
    serde_json::json!({
        "gpu_transcript":true,"transcript_bounds":BOUNDS,"transcript_reservation":reservation(),
        "gpu_randomness":true,"gpu_witness":true,"gpu_pcs_device_only":true,
        "gpu_quotient_eval":true,"gpu_quotient_resident":true,"gpu_lookup":true,
        "gpu_opening_eval":true,"gpu_fri_resident":true,
        "randomness_bounds":random,"randomness_reservation":random.reservation(1).unwrap(),
        "witness_bounds":{"rows":16,"main_columns":98,"preprocessing_columns":200},
        "owned_quotient_reservation":{"managed_bytes":1073741824},
        "witness_reservation":{"managed_bytes":2097152,"host_bytes":2097152},
        "gpu":{"managed_bytes":2147483648u64,"max_allocation_bytes":67108864},
        "host":{"worker_bytes":8388608}
    })
}

#[test]
fn transcript_reservation_covers_simultaneous_buffers_and_matches_python() {
    assert_eq!(
        reservation(),
        Reservation {
            managed_bytes: 723272,
            max_allocation_bytes: 524288,
            host_bytes: 1048576
        }
    );
    assert!(crate::block_v2::profile::QUERY_POW_BITS <= GRIND_BITS);
    assert!(crate::block_v2::profile::NUM_QUERIES <= BATCH_WORDS);
    let value = assignment();
    validate_assignment(&value, true).unwrap();
    assert!(validate_assignment(&value, false).is_err());
    validate_assignment(&serde_json::json!({}), false).unwrap();
    assert!(validate_assignment(&serde_json::json!({}), true).is_err());
}

#[test]
fn transcript_worker_rejects_bound_tampering_and_aggregate_shortfalls() {
    let value = assignment();
    for parent in ["transcript_bounds", "transcript_reservation"] {
        for key in value[parent].as_object().unwrap().keys() {
            for replacement in [
                serde_json::json!(false),
                serde_json::json!(0),
                serde_json::json!(u64::MAX),
            ] {
                let mut bad = value.clone();
                bad[parent][key] = replacement;
                assert!(validate_assignment(&bad, true).is_err(), "{parent}.{key}");
            }
        }
        let mut bad = value.clone();
        bad[parent]["extra"] = 0.into();
        assert!(validate_assignment(&bad, true).is_err());
    }
    for key in [
        "gpu_randomness",
        "gpu_witness",
        "gpu_lookup",
        "gpu_fri_resident",
    ] {
        let mut bad = value.clone();
        bad[key] = false.into();
        assert!(validate_assignment(&bad, true).is_err());
    }
    for (parent, key, total) in [
        (
            "gpu",
            "managed_bytes",
            [
                "owned_quotient_reservation",
                "witness_reservation",
                "randomness_reservation",
                "transcript_reservation",
            ]
            .iter()
            .map(|p| value[p]["managed_bytes"].as_u64().unwrap())
            .sum::<u64>(),
        ),
        (
            "gpu",
            "max_allocation_bytes",
            reservation().max_allocation_bytes,
        ),
        (
            "host",
            "worker_bytes",
            [
                "witness_reservation",
                "randomness_reservation",
                "transcript_reservation",
            ]
            .iter()
            .map(|p| value[p]["host_bytes"].as_u64().unwrap())
            .sum::<u64>(),
        ),
    ] {
        let mut bad = value.clone();
        bad[parent][key] = (total - 1).into();
        assert!(validate_assignment(&bad, true).is_err());
    }
    let mut bad = value;
    bad["owned_quotient_reservation"]["managed_bytes"] = u64::MAX.into();
    assert!(validate_assignment(&bad, true).is_err());
}
