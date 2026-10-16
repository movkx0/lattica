use super::*;

#[test]
fn opening_storage_includes_all_three_commitments_and_minimum_quotient_chunks() {
    for (extension, expected) in [
        (Extension::Quadratic, 1_871_776),
        (Extension::Cubic, 1_949_600),
    ] {
        let minimum = WalletProofMinimum::new(256, 19, 0, extension).unwrap();
        assert_eq!(minimum.largest_allocation, 524_256);
        assert_eq!(minimum.simultaneous_bytes, expected);
        assert!(minimum.check(expected, 524_256).is_ok());
        assert!(minimum
            .check(expected - 1, usize::MAX)
            .unwrap_err()
            .contains("managed"));
        assert!(minimum
            .check(usize::MAX, 524_255)
            .unwrap_err()
            .contains("per-allocation"));
    }
}

#[test]
fn periodic_transform_includes_borrowed_trace_input_output_scratch_and_constants() {
    let minimum = WalletProofMinimum::new(256, 1, 512, Extension::Cubic).unwrap();
    assert_eq!(minimum.largest_allocation, 1_048_576);
    assert_eq!(minimum.simultaneous_bytes, 3_147_920);
    assert!(minimum.check(3_147_920, 1_048_576).is_ok());
    assert!(minimum.check(3_147_919, usize::MAX).is_err());
}

#[test]
fn malformed_or_overflowing_geometry_is_rejected_without_storage() {
    for rows in [0, 1, 3, 1 << 21, 1usize << (usize::BITS - 1)] {
        assert!(WalletProofMinimum::new(rows, 19, 1, Extension::Quadratic).is_err());
    }
    for width in [0, usize::MAX, u32::MAX as usize] {
        assert!(WalletProofMinimum::new(256, width, 1, Extension::Cubic).is_err());
    }
    assert!(WalletProofMinimum::new(256, 19, usize::MAX, Extension::Cubic).is_err());
    assert!(WalletProofMinimum::new(256, 19, 1, Extension::Base).is_err());
    assert!(sum(&[usize::MAX, 1]).is_err());
    assert!(WalletProofMinimum::new(1 << 20, 1, 0, Extension::Cubic).is_ok());
}

#[test]
fn maintained_single_and_padded_batch_geometries_fit_the_existing_ceiling() {
    use crate::{htlc_air as htlc, joinsplit_air as js};
    use p3_air::BaseAir;
    for extension in [Extension::Quadratic, Extension::Cubic] {
        for (rows, columns, periodic) in [
            (
                js::HEIGHT,
                js::WIDTH,
                js::JoinSplitAir.num_periodic_columns(),
            ),
            (
                htlc::HEIGHT,
                htlc::WIDTH,
                htlc::HtlcAir.num_periodic_columns(),
            ),
        ] {
            WalletProofMinimum::new(rows, columns, periodic, extension)
                .unwrap()
                .check(7 << 30, 7 << 30)
                .unwrap();
        }
    }
    #[cfg(feature = "gpu")]
    for count in [0usize, 1, 3, crate::batch_common::MAX_BATCH_TILES] {
        use crate::{batch_htlc_air as hb, batch_joinsplit_air as jsb};
        for (tile, columns, periodic) in [
            (
                jsb::device_batch_geometry().height,
                jsb::JoinSplitBatchAir.width(),
                jsb::JoinSplitBatchAir.num_periodic_columns(),
            ),
            (
                hb::device_batch_geometry().height,
                hb::HtlcBatchAir.width(),
                hb::HtlcBatchAir.num_periodic_columns(),
            ),
        ] {
            let rows = count.max(1).next_power_of_two() * tile;
            WalletProofMinimum::new(rows, columns, periodic, Extension::Quadratic)
                .unwrap()
                .check(7 << 30, 7 << 30)
                .unwrap();
        }
    }
}

#[test]
#[cfg(feature = "gpu")]
#[ignore = "requires complete owned OpenCL path in a <=3 GiB zero-swap service"]
fn gpu_wallet_shape_rejects_before_arithmetic_and_valid_proofs_survive() {
    use crate::block_v2::{
        commitment::Context, gpu_hash, leaf, legacy_wallet, quotient_pcs, typed_leaf,
    };
    use crate::proving::{Error, Policy, Request};
    use crate::{
        batch_htlc_air as hb, batch_joinsplit_air as jsb, htlc_air as htlc, joinsplit_air as js,
    };
    use gpu_hash::{device::DeviceSession, engine};
    use p3_air::BaseAir;
    use p3_field::PrimeCharacteristicRing;

    // Restrict only the admitted engine's test ceiling; the outer controller
    // still requires the entire production GPU admission budget. Restore it
    // on unwind too, without reallocating or resetting the context/cache.
    struct Restrict {
        limits: gpu_hash::Limits,
        max_alloc: usize,
    }
    impl Drop for Restrict {
        fn drop(&mut self) {
            let mut slot = engine::ENGINE.get().unwrap().lock().unwrap();
            let engine = slot.as_mut().unwrap();
            engine.limits = self.limits;
            engine.max_alloc = self.max_alloc;
        }
    }
    let _shutdown = gpu_hash::TestShutdownGuard;
    let fusion = quotient_pcs::initialize_research_from_env().unwrap();
    quotient_pcs::initialize_gpu_quotient_from_env(true, fusion).unwrap();
    gpu_hash::initialize_quotient_test_engine(gpu_hash::Limits {
        managed_bytes: std::env::var("LATTICA_V2_GPU_MANAGED_BYTES")
            .unwrap()
            .parse()
            .unwrap(),
        tile_bytes: 1 << 20,
        staging_bytes: 32 << 10,
    })
    .unwrap();
    gpu_hash::ENABLED.store(true, std::sync::atomic::Ordering::Release);
    assert!(gpu_hash::initialize_resident_from_env().unwrap());
    let session = DeviceSession::new().unwrap();
    let request = Request {
        policy: Policy::GpuRequired,
        emit_report: true,
    };
    let spend = js::demo_witness();
    let htlc = htlc::demo_witness();
    let mut issue = js::demo_witness();
    issue.mint = 17;
    issue.fee = 0;
    issue.outputs[0].value = 17;
    issue.outputs[1].value = issue.inputs.iter().map(|v| v.value).sum();
    let context = Context {
        profile_id: profile::CANDIDATE_PROFILE_ID,
        chain_id: [53; 32],
    };
    let snapshot = || {
        let slot = engine::ENGINE.get().unwrap().lock().unwrap();
        let a = *slot.as_ref().unwrap().accounting.lock().unwrap();
        (
            a.live,
            a.allocations,
            a.capacity_generation,
            a.proof_capacity.is_some(),
        )
    };
    let reject = |minimum: WalletProofMinimum, attempt: &dyn Fn()| {
        for per_allocation in [false, true] {
            let guard = session
                .with_engine(|engine| {
                    minimum.check(engine.limits.managed_bytes, engine.max_alloc)?;
                    if engine.accounting.lock().unwrap().live >= minimum.simultaneous_bytes {
                        return Err("test workspace must fit below the tested storage floor".into());
                    }
                    let guard = Restrict {
                        limits: engine.limits,
                        max_alloc: engine.max_alloc,
                    };
                    if per_allocation {
                        engine.max_alloc = minimum.largest_allocation - 1;
                    } else {
                        engine.limits.managed_bytes = minimum.simultaneous_bytes - 1;
                    }
                    Ok(guard)
                })
                .unwrap();
            let before = snapshot();
            let stats = session.stats();
            attempt();
            assert_eq!(snapshot(), before, "admission must not allocate or reserve");
            assert_eq!(session.stats().uploaded_bytes, stats.uploaded_bytes);
            assert_eq!(session.stats().downloaded_bytes, stats.downloaded_bytes);
            drop(guard);
        }
    };
    let shape =
        |rows, width, periodic, ext| WalletProofMinimum::new(rows, width, periodic, ext).unwrap();
    reject(
        shape(
            js::HEIGHT,
            js::WIDTH,
            js::JoinSplitAir.num_periodic_columns(),
            Extension::Quadratic,
        ),
        &|| {
            assert!(matches!(
                legacy_wallet::prove_joinsplit_with_public(&spend, request),
                Err(Error::ComponentRejected)
            ));
        },
    );
    reject(
        shape(
            htlc::HEIGHT,
            htlc::WIDTH,
            htlc::HtlcAir.num_periodic_columns(),
            Extension::Quadratic,
        ),
        &|| {
            assert!(matches!(
                legacy_wallet::prove_htlc_with_public(&htlc, request),
                Err(Error::ComponentRejected)
            ));
        },
    );
    for count in [0usize, 3] {
        let spends: Vec<_> = (0..count).map(|_| js::demo_witness()).collect();
        let htlcs: Vec<_> = (0..count).map(|_| htlc::demo_witness()).collect();
        reject(
            shape(
                count.max(1).next_power_of_two() * jsb::device_batch_geometry().height,
                jsb::JoinSplitBatchAir.width(),
                jsb::JoinSplitBatchAir.num_periodic_columns(),
                Extension::Quadratic,
            ),
            &|| {
                assert!(matches!(
                    legacy_wallet::prove_joinsplit_batch_with_public(&spends, request),
                    Err(Error::ComponentRejected)
                ));
            },
        );
        reject(
            shape(
                count.max(1).next_power_of_two() * hb::device_batch_geometry().height,
                hb::HtlcBatchAir.width(),
                hb::HtlcBatchAir.num_periodic_columns(),
                Extension::Quadratic,
            ),
            &|| {
                assert!(matches!(
                    legacy_wallet::prove_htlc_batch_with_public(&htlcs, request),
                    Err(Error::ComponentRejected)
                ));
            },
        );
    }
    let cubic = shape(
        js::HEIGHT,
        js::WIDTH,
        js::JoinSplitAir.num_periodic_columns(),
        Extension::Cubic,
    );
    reject(cubic, &|| {
        assert_eq!(
            leaf::prove_joinsplit_with_request(&spend, &context, request),
            Err(leaf::LeafError::GpuFailure)
        );
    });
    // The necessary retained-storage floor alone is no longer the admission
    // contract. Both profiles must reject an insufficient complete phase bound
    // without consuming a capacity generation or touching the GPU.
    for extension in [Extension::Quadratic, Extension::Cubic] {
        let minimum = shape(
            js::HEIGHT,
            js::WIDTH,
            js::JoinSplitAir.num_periodic_columns(),
            extension,
        );
        let guard = session
            .with_engine(|engine| {
                let live = engine.accounting.lock().unwrap().live;
                let ceiling = live.checked_add(minimum.simultaneous_bytes).unwrap();
                minimum.check(ceiling, engine.max_alloc)?;
                let guard = Restrict {
                    limits: engine.limits,
                    max_alloc: engine.max_alloc,
                };
                engine.limits.managed_bytes = ceiling;
                Ok(guard)
            })
            .unwrap();
        let before = snapshot();
        let stats = session.stats();
        if extension == Extension::Quadratic {
            assert!(matches!(
                legacy_wallet::prove_joinsplit_with_public(&spend, request),
                Err(Error::ComponentRejected)
            ));
        } else {
            assert_eq!(
                leaf::prove_joinsplit_with_request(&spend, &context, request),
                Err(leaf::LeafError::GpuFailure)
            );
        }
        assert_eq!(snapshot(), before);
        assert_eq!(session.stats().uploaded_bytes, stats.uploaded_bytes);
        assert_eq!(session.stats().downloaded_bytes, stats.downloaded_bytes);
        drop(guard);
    }
    reject(
        shape(
            htlc::HEIGHT,
            htlc::WIDTH,
            htlc::HtlcAir.num_periodic_columns(),
            Extension::Cubic,
        ),
        &|| {
            assert_eq!(
                typed_leaf::prove_htlc_with_request(&htlc, &context, request),
                Err(leaf::LeafError::GpuFailure.into())
            );
        },
    );
    reject(cubic, &|| {
        assert_eq!(
            typed_leaf::prove_issuance_with_request(&issue, &context, 17, request),
            Err(leaf::LeafError::GpuFailure.into())
        );
    });
    // Storage floors and the aggregate phase bound fit; only the recorded
    // quotient row exceeds the selected tile. Neither normalization nor witness
    // arithmetic may start, and the capacity generation remains unchanged.
    for extension in [Extension::Quadratic, Extension::Cubic] {
        use crate::block_v2::gpu_quotient_prover::uni::Prepared;
        let prepared = if extension == Extension::Quadratic {
            Prepared::new(&js::JoinSplitAir, js::HEIGHT, extension, 1 << 30).unwrap()
        } else {
            Prepared::new(&leaf::ContextJoinSplitAir, js::HEIGHT, extension, 1 << 30).unwrap()
        };
        let minimum = prepared.minimum().unwrap();
        let program = minimum.program.unwrap();
        let guard = session
            .with_engine(|engine| {
                let live = engine.accounting.lock().unwrap().live;
                minimum.plan(engine, live)?;
                let guard = Restrict {
                    limits: engine.limits,
                    max_alloc: engine.max_alloc,
                };
                engine.limits.tile_bytes =
                    (program.row_words + program.registers * extension.degree()) * 8 - 1;
                assert_eq!(
                    minimum.plan(engine, live).unwrap_err(),
                    "GPU quotient workspace cannot fit one row"
                );
                Ok(guard)
            })
            .unwrap();
        let before = snapshot();
        let stats = session.stats();
        if extension == Extension::Quadratic {
            assert!(matches!(
                legacy_wallet::prove_joinsplit_with_public(&spend, request),
                Err(Error::ComponentRejected)
            ));
        } else {
            assert_eq!(
                leaf::prove_joinsplit_with_request(&spend, &context, request),
                Err(leaf::LeafError::GpuFailure)
            );
        }
        assert_eq!(snapshot(), before);
        assert_eq!(session.stats().uploaded_bytes, stats.uploaded_bytes);
        assert_eq!(session.stats().downloaded_bytes, stats.downloaded_bytes);
        drop(guard);
    }
    let public = js::public_values(&spend); // independent fixture oracle
    let (quadratic, report) = js::prove_to_bytes_with_request(&spend, request).unwrap();
    assert!(report.succeeded && report.stage_coverage_complete);
    let cubic = leaf::prove_joinsplit_with_request(&spend, &context, request).unwrap();
    assert!(!snapshot().3);
    drop(session);
    gpu_hash::shutdown().unwrap();
    assert!(js::verify_bytes(&quadratic, &public));
    leaf::verify_joinsplit_research(&cubic, &context, &public).unwrap();
    let mut wrong = public;
    wrong[0] += crate::config::Val::ONE;
    assert!(!js::verify_bytes(&quadratic, &wrong));
    assert!(leaf::verify_joinsplit_research(&cubic, &context, &wrong).is_err());
    eprintln!("gpu_wallet_shape_regression rejected_before_work=22 storage_floor_rejections=18 phase_bound_rejections=2 program_tile_rejections=2 fresh_proofs=2 cpu_verified=2 altered_publics_rejected=2");
}
