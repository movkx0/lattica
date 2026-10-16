use super::*;
use crate::block_v2::machine::symbolic;
use p3_air::Air;

fn cold(limits: Limits) -> Plan {
    Plan {
        phases: Vec::new(),
        quotient_tiles: Vec::new(),
        operations: Vec::new(),
        randomness: Vec::new(),
        fri: Vec::new(),
        commitments: Vec::new(),
        inputs: Vec::new(),
        ceiling: limits.managed_bytes,
        max_allocation: 4 << 30,
        baseline: engine::CONSTANT_BYTES + limits.staging_bytes + engine::transport_bytes(limits),
        initial_hash: limits.tile_bytes,
        initial_lde: 0,
    }
}

#[cfg(feature = "gpu")]
fn geometry<A: Air<symbolic::Builder> + crate::block_v2::machine::verifier::periodic::Source>(
    air: A,
    rows: usize,
    extension: Extension,
) -> WalletProofMinimum {
    // Match the request allowance: symbolic compilation and retained periodic
    // tables now share it, so the compiler envelope alone cannot admit an AIR.
    crate::block_v2::gpu_quotient_prover::uni::Prepared::new(&air, rows, extension, 1 << 30)
        .unwrap()
        .minimum()
        .unwrap()
}

#[test]
#[cfg(feature = "gpu")]
fn witness_staging_checks_the_request_host_allowance() {
    for extension in [Extension::Quadratic, Extension::Cubic] {
        let mut shape = geometry(
            crate::joinsplit_air::JoinSplitAir,
            crate::joinsplit_air::HEIGHT,
            extension,
        );
        shape.host_allowance = 1;
        let mut plan = cold(Limits::default());
        let error = plan
            .build(shape, Limits::default(), 1, 0, true)
            .unwrap_err();
        assert!(
            error.contains("input staging exceeds host allowance"),
            "{error}"
        );
        assert!(plan.phases.is_empty());
    }
}

#[test]
#[cfg(feature = "gpu")]
fn complete_wallet_shapes_fit_original_budget_including_maximum_padded_batches() {
    use crate::{
        batch_htlc_air as hb, batch_joinsplit_air as jsb, htlc_air as htlc, joinsplit_air as js,
    };
    let limits = Limits::default();
    let mut shapes = Vec::new();
    for extension in [Extension::Quadratic, Extension::Cubic] {
        shapes.push(geometry(js::JoinSplitAir, js::HEIGHT, extension));
        shapes.push(geometry(htlc::HtlcAir, htlc::HEIGHT, extension));
    }
    for count in [0usize, 1, 3, crate::batch_common::MAX_BATCH_TILES] {
        let tiles = count.max(1).next_power_of_two();
        shapes.push(geometry(
            jsb::JoinSplitBatchAir,
            tiles * jsb::device_batch_geometry().height,
            Extension::Quadratic,
        ));
        shapes.push(geometry(
            hb::HtlcBatchAir,
            tiles * hb::device_batch_geometry().height,
            Extension::Quadratic,
        ));
    }
    for shape in shapes {
        let mut plan = cold(limits);
        plan.build(shape, limits, 1, 0, true)
            .unwrap_or_else(|e| panic!("{shape:?}: {e}"));
        assert!(plan.phases.iter().all(|p| p.bytes <= limits.managed_bytes));
        assert_eq!(plan.quotient_tiles.len(), 5);
        assert_eq!(plan.operations.len(), 15);
        assert_eq!(plan.randomness.len(), 43);
        assert_eq!(plan.commitments.len(), 11);
        assert_eq!(plan.inputs.len(), 10);
        for input in &plan.inputs {
            let phase = plan
                .phases
                .iter()
                .find(|p| p.name == input.name && p.chunks == input.chunks)
                .unwrap();
            assert!(input.peak <= phase.bytes && input.largest <= plan.max_allocation);
            if input.name == "quotient_evaluation" {
                assert_eq!(input.coset_rows * input.cosets, shape.rows * input.chunks);
                assert_eq!(input.coset_rows, shape.rows * 2);
            }
        }
        for input in &plan.commitments {
            let phase = plan
                .phases
                .iter()
                .find(|p| p.name == input.name && p.chunks == input.chunks)
                .unwrap();
            assert!(input.storage.peak_bytes <= phase.bytes);
            assert!(input
                .storage
                .allocation_bytes
                .iter()
                .all(|&n| n <= plan.max_allocation));
            assert_eq!(
                input.storage.pending_bytes,
                input.storage.allocation_bytes[2]
            );
            assert_eq!(input.storage.location, SampleLocation::Resident);
        }
        let max_arity = if shape.extension == Extension::Quadratic {
            4
        } else {
            1
        };
        assert_eq!(plan.fri.len(), (2 * max_arity + 2) * 5);
        for operation in &plan.fri {
            let report = operation.report();
            let phase_name = if report["name"].as_str().unwrap().starts_with("fri_query") {
                "pcs_and_fri_queries"
            } else {
                "fri_commit_fold_and_final"
            };
            let phase = plan
                .phases
                .iter()
                .find(|p| {
                    p.name == phase_name
                        && p.chunks == report["quotient_chunks"].as_u64().unwrap() as usize
                })
                .unwrap();
            assert!(report["managed_bytes_at_bound"].as_u64().unwrap() <= phase.bytes as u64);
            assert!(report["max_allocation_bytes"].as_u64().unwrap() <= plan.max_allocation as u64);
            assert!(
                report["host_output_bytes_at_bound"].as_u64().unwrap()
                    <= shape.host_allowance as u64
            );
            assert!(report["log_arity"].as_u64().unwrap() <= max_arity as u64);
        }
        for random in &plan.randomness {
            let report = random.report();
            assert!(
                report["managed_bytes_at_bound"].as_u64().unwrap() <= limits.managed_bytes as u64
            );
            assert!(report["max_allocation_bytes"].as_u64().unwrap() <= plan.max_allocation as u64);
            let phase = plan
                .phases
                .iter()
                .find(|p| {
                    p.name == report["name"].as_str().unwrap()
                        && p.chunks == report["quotient_chunks"].as_u64().unwrap() as usize
                })
                .unwrap();
            assert!(report["managed_bytes_at_bound"].as_u64().unwrap() <= phase.bytes as u64);
            match report["name"].as_str().unwrap() {
                "quotient_samples" => assert_eq!(report["requests"], 2),
                "quotient_salt_draw" => assert_eq!(report["requests"], report["quotient_chunks"]),
                "fri_commit_fold_and_final" => assert_eq!(
                    report["requests"],
                    (shape.rows * 2 << profile::LOG_BLOWUP).ilog2()
                ),
                _ => assert_eq!(report["requests"], 1),
            }
        }
        assert!(
            plan.operations
                .iter()
                .all(|p| p.peak <= limits.managed_bytes
                    && p.host_buffer_bytes <= shape.host_allowance)
        );
        let queries = if shape.extension == Extension::Quadratic {
            crate::config::NUM_QUERIES
        } else {
            profile::NUM_QUERIES
        };
        assert!(plan
            .operations
            .iter()
            .filter(|p| p.name == "pcs_query_reconstruction")
            .all(|p| p.query_count == queries));
        assert!(plan
            .quotient_tiles
            .iter()
            .all(|p| p.rows > 0 && p.peak <= limits.managed_bytes));
    }
}

#[test]
#[cfg(feature = "gpu")]
fn prior_transform_cache_is_charged_until_replacement_without_becoming_permanent() {
    let shape = geometry(
        crate::joinsplit_air::JoinSplitAir,
        crate::joinsplit_air::HEIGHT,
        Extension::Cubic,
    );
    let limits = Limits::default();
    let mut cold = cold(limits);
    let mut warm = Plan {
        initial_lde: 1 << 30,
        ..self::cold(limits)
    };
    cold.build(shape, limits, 1, 1 << 30, true).unwrap();
    warm.build(shape, limits, 1, 1 << 30, true).unwrap();
    let amount = |p: &Plan, name| p.phases.iter().find(|p| p.name == name).unwrap().bytes;
    assert_eq!(
        amount(&warm, "witness_and_publics") - amount(&cold, "witness_and_publics"),
        1 << 30
    );
    for name in [
        "main_commitment",
        "quotient_evaluation",
        "opening_reduction",
        "pcs_and_fri_queries",
    ] {
        assert_eq!(amount(&warm, name), amount(&cold, name));
    }
}

#[test]
#[cfg(feature = "gpu")]
fn every_supported_quotient_partition_and_the_final_query_phase_are_admitted() {
    let shape = geometry(
        crate::joinsplit_air::JoinSplitAir,
        crate::joinsplit_air::HEIGHT,
        Extension::Quadratic,
    );
    let limits = Limits::default();
    let mut plan = cold(limits);
    plan.build(shape, limits, 1, 0, true).unwrap();
    let chunks: Vec<_> = plan
        .phases
        .iter()
        .filter(|p| p.name == "pcs_and_fri_queries")
        .map(|p| p.chunks)
        .collect();
    assert_eq!(chunks, vec![2, 4, 8, 16, 32]);
    for chunks in chunks {
        let phases: Vec<_> = plan
            .phases
            .iter()
            .filter(|p| p.chunks == chunks)
            .map(|p| p.name)
            .collect();
        for required in [
            "quotient_samples",
            "quotient_commitment",
            "randomization_commitment",
            "opening_reduction",
            "fri_commit_fold_and_final",
            "pcs_and_fri_queries",
        ] {
            assert!(phases.contains(&required));
        }
    }
}

#[test]
#[cfg(feature = "gpu")]
fn a_storage_floor_can_fit_while_the_complete_phase_bound_is_refused() {
    let shape = geometry(
        crate::joinsplit_air::JoinSplitAir,
        crate::joinsplit_air::HEIGHT,
        Extension::Quadratic,
    );
    let limits = Limits {
        managed_bytes: shape.simultaneous_bytes + (2 << 20),
        tile_bytes: 1 << 20,
        staging_bytes: 32 << 10,
    };
    shape.check(limits.managed_bytes, 4 << 30).unwrap();
    assert!(cold(limits).build(shape, limits, 1, 0, true).is_err());
}

#[test]
#[cfg(feature = "gpu")]
fn quotient_rows_reject_small_tiles_and_fit_the_previous_one_mib_setting() {
    for extension in [Extension::Quadratic, Extension::Cubic] {
        let shape = geometry(
            crate::joinsplit_air::JoinSplitAir,
            crate::joinsplit_air::HEIGHT,
            extension,
        );
        let program = shape.program.unwrap();
        let row_bytes = (program.row_words + program.registers * extension.degree()) * 8;
        let limits = Limits {
            tile_bytes: row_bytes - 1,
            staging_bytes: 32 << 10,
            ..Limits::default()
        };
        shape.check(limits.managed_bytes, 4 << 30).unwrap();
        assert_eq!(
            cold(limits).build(shape, limits, 1, 0, true).unwrap_err(),
            "GPU quotient workspace cannot fit one row"
        );
        let limits = Limits {
            tile_bytes: 1 << 20,
            ..limits
        };
        let mut plan = cold(limits);
        plan.build(shape, limits, 1, 0, true).unwrap();
        assert_eq!(plan.quotient_tiles.len(), 5);
        assert!(plan
            .quotient_tiles
            .iter()
            .all(|t| t.rows.is_power_of_two() && t.peak <= limits.managed_bytes));
        let mut unbound = shape;
        unbound.program = None;
        assert_eq!(
            cold(limits).build(unbound, limits, 1, 0, true).unwrap_err(),
            "wallet phase admission requires recorded program geometry"
        );
    }
}

#[test]
#[cfg(feature = "gpu")]
fn opening_planner_can_reject_a_tile_that_fits_the_quotient_row() {
    // Future wider AIRs must not inherit admission just because their
    // quotient register count is small. Two-point partial sums scale by width.
    use p3_air::{AirBuilder, BaseAir};
    use p3_field::PrimeCharacteristicRing;
    struct Wide;
    impl crate::block_v2::machine::verifier::periodic::Source for Wide {
        fn count(&self) -> usize {
            0
        }
        fn len(&self, _: usize) -> Option<usize> {
            None
        }
        fn fill(
            &self,
            _: usize,
            _: &mut [crate::config::Val],
        ) -> Result<(), crate::block_v2::machine::verifier::CompileError> {
            panic!("zero-column AIR cannot fill periodic data")
        }
    }
    impl BaseAir<crate::config::Val> for Wide {
        fn width(&self) -> usize {
            4092
        }
    }
    impl<AB: AirBuilder<F = crate::config::Val>> Air<AB> for Wide {
        fn eval(&self, b: &mut AB) {
            b.assert_zero(AB::Expr::ZERO);
        }
    }
    let shape = geometry(Wide, 256, Extension::Cubic);
    let program = shape.program.unwrap();
    let limits = Limits {
        tile_bytes: 128 << 10,
        // A salted 4096-column row itself exceeds 32 KiB. Allow it through
        // the earlier hash planner so this fixture isolates opening scratch.
        staging_bytes: 64 << 10,
        ..Limits::default()
    };
    engine::quotient::Plan::for_shape(program, 512, 0, limits, 4 << 30).unwrap();
    assert_eq!(
        cold(limits).build(shape, limits, 1, 0, true).unwrap_err(),
        "device opening budget cannot fit one row"
    );
}

#[test]
fn query_host_admission_covers_larger_runtime_tiles_than_the_live_snapshot() {
    let limits = Limits::default();
    let prefix = MatrixSpec::new(5, 16, Extension::Base, RowOrder::BitReversed, 1).unwrap();
    let queries = 128;
    let one_column =
        query::QueryPlan::new(prefix, 10, queries, 20 << 10, 4 << 30, usize::MAX).unwrap();
    assert_eq!(one_column.columns, 1);
    let largest =
        query::QueryPlan::new(prefix, 10, queries, usize::MAX, 4 << 30, usize::MAX).unwrap();
    assert!(largest.host_peak_bytes > one_column.host_peak_bytes);
    let live = limits.managed_bytes - (20 << 10);
    let mut plan = cold(limits);
    assert_eq!(
        plan.admit_queries(prefix, 10, 2, queries, live, one_column.host_peak_bytes)
            .unwrap_err(),
        "owned query result and staging exceed host allowance"
    );
    assert!(plan.operations.is_empty());
    plan.admit_queries(prefix, 10, 2, queries, live, largest.host_peak_bytes)
        .unwrap();
    assert_eq!(plan.operations[0].columns, Some(1));
    assert_eq!(
        plan.operations[0].host_buffer_bytes,
        largest.host_peak_bytes
    );
}

#[test]
fn opening_and_query_operation_checks_reject_host_limits_without_device_work() {
    let limits = Limits::default();
    let prefix = MatrixSpec::new(8, 23, Extension::Base, RowOrder::BitReversed, 1).unwrap();
    let mut plan = cold(limits);
    assert_eq!(
        plan.admit_openings(prefix, 12, 2, Extension::Cubic, 0, limits, 0)
            .unwrap_err(),
        "wallet opening values exceed host allowance"
    );
    assert_eq!(
        plan.admit_queries(prefix, 12, 2, 96, 0, 0).unwrap_err(),
        "owned query result and staging exceed host allowance"
    );
    assert!(plan.operations.is_empty());
}

#[test]
fn random_preflight_checks_raw_buffers_beyond_the_output_allocation() {
    let mut plan = cold(Limits::default());
    plan.max_allocation = 127;
    // A valid 64-byte output does not establish that raw sampling fits.
    assert!(plan
        .admit_randomness("test", 0, [8].into_iter(), false, 0)
        .is_err());
    assert!(plan.randomness.is_empty());
    plan.max_allocation = 128;
    plan.admit_randomness("test", 0, [8].into_iter(), false, 0)
        .unwrap();
    assert_eq!(plan.randomness[0].report()["max_allocation_bytes"], 128);
}

#[test]
fn fri_query_admission_preserves_profile_arity_and_host_output_boundaries() {
    let quadratic = MatrixSpec::new(8, 1, Extension::Quadratic, RowOrder::BitReversed, 1).unwrap();
    let cubic = MatrixSpec::new(8, 1, Extension::Cubic, RowOrder::BitReversed, 1).unwrap();
    let limits = Limits::default();
    assert!(cold(limits)
        .admit_fri_queries(quadratic, 2, 96, 0, 24575)
        .is_err());
    let mut quad_plan = cold(limits);
    quad_plan
        .admit_fri_queries(quadratic, 2, 96, 0, 24576)
        .unwrap();
    assert_eq!(quad_plan.fri.len(), 5);
    let mut cubic_plan = cold(limits);
    cubic_plan
        .admit_fri_queries(cubic, 2, 128, 0, 6144)
        .unwrap();
    assert_eq!(cubic_plan.fri.len(), 2);
}
