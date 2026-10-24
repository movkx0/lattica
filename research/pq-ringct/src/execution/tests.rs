use super::*;
use lattica_prover_p3::block_v2::machine::ProgramBuilder;
use p3_field::PrimeCharacteristicRing;

fn equality_program(publics: usize, height: usize, increment: u64) -> Program {
    let mut builder = ProgramBuilder::new(publics).unwrap();
    for index in 0..publics {
        let public = builder.public(index).unwrap();
        let input = builder.input();
        let constant = builder.constant(Val::from_u64(increment));
        let value = builder.add(input, constant);
        builder.assert_equal(public, value);
    }
    builder.finish(Some(height)).unwrap()
}

fn cache_identity(index: usize) -> Identity {
    let mut manifest = [0; 32];
    manifest[..8].copy_from_slice(&(index as u64).to_le_bytes());
    Identity {
        manifest,
        registration: [11; 32],
    }
}

#[test]
fn identity_receipt_lru_is_bounded_and_nomination_does_not_promote() {
    // Dummy scalar payloads exercise cache mechanics without fabricating an
    // opaque GPU identity receipt or performing any GPU work.
    let mut cache = IdentityHintCache::<u64>::new();
    let capacity = cache.max_entries;
    let allocated = cache.backing_bytes();
    assert_eq!(capacity, MAX_IDENTITY_HINT_ENTRIES);
    assert!(allocated <= IDENTITY_HINT_LIMIT_BYTES);
    for index in 0..capacity {
        cache.remember(cache_identity(index), index as u64);
    }
    assert_eq!(cache.get(cache_identity(0)), Some(&0));
    assert!(cache.get(cache_identity(capacity)).is_none());
    cache.remember(cache_identity(capacity), capacity as u64);
    // A candidate lookup did not keep the oldest receipt alive.
    assert!(cache.get(cache_identity(0)).is_none());
    assert_eq!(cache.evictions, 1);
    cache.remember(cache_identity(1), 99);
    cache.remember(cache_identity(capacity + 1), 100);
    assert_eq!(cache.get(cache_identity(1)), Some(&99));
    assert!(cache.get(cache_identity(2)).is_none());
    assert_eq!(cache.evictions, 2);
    assert_eq!(cache.entries.len(), capacity);
    assert_eq!(cache.backing_bytes(), allocated);
    cache.remove(cache_identity(1));
    assert!(cache.get(cache_identity(1)).is_none());
    assert_eq!(cache.evictions, 3);
    assert_eq!(cache.entries.len(), capacity - 1);
    assert_eq!(cache.backing_bytes(), allocated);
}

#[test]
fn identity_receipt_subcap_limits_layout_growth() {
    let mut cache = IdentityHintCache::<[u8; 1024]>::new();
    let capacity = cache.max_entries;
    let allocated = cache.backing_bytes();
    assert!(capacity > 0 && capacity < MAX_IDENTITY_HINT_ENTRIES);
    assert!(allocated <= IDENTITY_HINT_LIMIT_BYTES);
    for index in 0..=capacity {
        cache.remember(cache_identity(index), [7; 1024]);
    }
    assert_eq!(cache.entries.len(), capacity);
    assert_eq!(cache.backing_bytes(), allocated);
    assert_eq!(cache.evictions, 1);
    assert!(cache.get(cache_identity(0)).is_none());
    let oversized = IdentityHintCache::<[u8; IDENTITY_HINT_LIMIT_BYTES]>::new();
    assert_eq!(oversized.max_entries, 0);
    assert_eq!(oversized.backing_bytes(), 0);
}

#[test]
fn identity_and_verifier_metadata_share_the_existing_byte_allowance() {
    let registry = Registry::new();
    let verifier_backing = registry.metadata.capacity() * std::mem::size_of::<Metadata>();
    let receipt_backing = registry.identity_hints.backing_bytes();
    assert_eq!(registry.metadata_bytes, verifier_backing + receipt_backing);
    assert!(receipt_backing > 0 && receipt_backing <= IDENTITY_HINT_LIMIT_BYTES);
    assert!(registry.identity_hints.max_entries <= MAX_IDENTITY_HINT_ENTRIES);
    assert!(registry.metadata_bytes <= PUBLIC_METADATA_LIMIT_BYTES);
}

#[test]
fn metadata_experiments_and_observations_share_the_same_byte_limits() {
    for capacity in [MetadataCapacity::Entries256, MetadataCapacity::Entries512] {
        for telemetry in [
            RegistrationTelemetry::Disabled,
            RegistrationTelemetry::Bounded,
        ] {
            let registry = Registry::with_options(capacity, telemetry);
            assert_eq!(registry.maximum_metadata_entries, capacity.entries());
            assert_eq!(
                registry.metadata_bytes,
                registry.metadata.capacity() * std::mem::size_of::<Metadata>()
                    + registry.identity_hints.backing_bytes()
                    + registry.trace.accounted_bytes()
            );
            assert!(registry.metadata_bytes <= PUBLIC_METADATA_LIMIT_BYTES);
            assert!(registry.identity_hints.backing_bytes() <= IDENTITY_HINT_LIMIT_BYTES);
            assert_eq!(
                registry.trace.accounted_bytes() == 0,
                telemetry == RegistrationTelemetry::Disabled
            );
        }
    }
}

#[test]
fn registration_options_reject_late_and_reentrant_changes() {
    let context = ProvingContext::cpu(1 << 30).unwrap();
    assert_eq!(context.report()["maximum_metadata_entries"], 256);
    assert_eq!(context.report()["registration_telemetry"]["enabled"], false);
    context
        .configure_registration(MetadataCapacity::Entries512, RegistrationTelemetry::Bounded)
        .unwrap();
    assert_eq!(context.report()["maximum_metadata_entries"], 512);
    let busy = context.registry.borrow_mut();
    assert!(context
        .configure_registration(
            MetadataCapacity::Entries256,
            RegistrationTelemetry::Disabled
        )
        .is_err());
    drop(busy);
    assert!(context
        .with_native_cpu(|| Err::<(), _>("injected native failure".into()))
        .is_err());
    assert!(context
        .configure_registration(
            MetadataCapacity::Entries256,
            RegistrationTelemetry::Disabled
        )
        .is_err());
    assert_eq!(context.report()["maximum_metadata_entries"], 512);
}

#[test]
fn bounded_identity_trace_preserves_order_and_marks_truncation() {
    let mut trace = RegistrationTrace::new(RegistrationTelemetry::Bounded);
    let program = equality_program(2, 32, 1);
    let bytes = trace.accounted_bytes();
    let first = trace.begin(cache_identity(1), 1024, &program);
    trace.outcome(first, AccessOutcome::Registered, 0.25);
    trace.callback(first, true);
    let second = trace.begin(cache_identity(2), 1024, &program);
    trace.outcome(second, AccessOutcome::Registered, 0.5);
    trace.callback(second, true);
    let third = trace.begin(cache_identity(1), 1024, &program);
    trace.outcome(third, AccessOutcome::Registered, 0.75);
    trace.callback(third, true);
    let fourth = trace.begin(cache_identity(1), 2048, &program);
    trace.outcome(fourth, AccessOutcome::SetupFailed, 0.125);
    trace.release(third, ReleaseReason::HostBudgetChanged);
    let report = trace.report();
    assert_eq!(report["complete"], true);
    assert_eq!(report["rows"][0][5], Value::Null);
    assert_eq!(report["rows"][1][5], Value::Null); // Same registration hash, different manifest.
    assert_eq!(report["rows"][2][5], 1);
    assert_eq!(report["rows"][3][5], Value::Null); // Different admitted allowance.
    assert_eq!(report["rows"][2][6], ReleaseReason::HostBudgetChanged as u8);
    let limit = report["maximum_accesses"].as_u64().unwrap();
    for _ in 4..limit + 1 {
        let index = trace.begin(cache_identity(1), 1024, &program);
        trace.outcome(index, AccessOutcome::PreparedHit, 0.0);
    }
    let report = trace.report();
    assert_eq!(report["recorded_accesses"], limit);
    assert_eq!(report["dropped_accesses"], 1);
    assert_eq!(report["complete"], false);
    assert_eq!(trace.accounted_bytes(), bytes);
    assert_eq!(report["prepared_retained_host_bytes"], Value::Null);
    assert_eq!(report["prepared_retained_device_bytes"], Value::Null);
}

#[test]
fn metadata_512_keeps_exact_lru_order_and_byte_eviction_reasons() {
    let (verifier, cap) = public_verifier_fixture();
    let context = ProvingContext::cpu(1 << 30).unwrap();
    let mut registry = Registry::with_options(
        MetadataCapacity::Entries512,
        RegistrationTelemetry::Disabled,
    );
    for index in 0..512 {
        registry
            .remember(cache_identity(index), &cap, Arc::clone(&verifier))
            .unwrap();
    }
    assert_eq!(registry.metadata.len(), 512);
    assert!(registry
        .cached_verifier(cache_identity(0), &cap, &context.diagnostics)
        .unwrap()
        .is_some());
    registry
        .remember(cache_identity(512), &cap, Arc::clone(&verifier))
        .unwrap();
    assert_eq!(
        registry.metadata.front().unwrap().identity,
        cache_identity(2)
    );
    assert_eq!(registry.metadata_capacity_evictions, 1);
    assert_eq!(registry.metadata_byte_evictions, 0);

    // Larger public cap backing reaches the shared byte limit before 512 entries.
    // It needs no GPU state and exercises actual capacities, not synthetic counters.
    let large_cap = vec![cap[0]; 16_384];
    for index in 513..650 {
        registry
            .remember(cache_identity(index), &large_cap, Arc::clone(&verifier))
            .unwrap();
        assert!(registry.metadata_bytes <= PUBLIC_METADATA_LIMIT_BYTES);
    }
    assert!(registry.metadata_byte_evictions > 0);
    assert_eq!(
        registry.metadata_evictions,
        registry.metadata_capacity_evictions + registry.metadata_byte_evictions
    );
    assert!(registry.metadata.len() < 512);
}

#[test]
fn failed_callbacks_and_retirement_remain_observable_without_private_inputs() {
    let context = ProvingContext::cpu(1 << 30).unwrap();
    context
        .configure_registration(MetadataCapacity::Entries512, RegistrationTelemetry::Bounded)
        .unwrap();
    context
        .with_registered(equality_program(2, 32, 1), |_| Ok(()))
        .unwrap();
    assert!(context
        .with_registered(equality_program(2, 32, 1), |_| Err::<(), _>(
            "injected callback".into()
        ))
        .is_err());
    let report = context.close_without_completion().unwrap();
    assert_eq!(report["prepared_entries"], 0);
    assert_eq!(report["session_closed"], true);
    assert_eq!(report["completion_claimed"], false);
    assert_eq!(
        report["registration_telemetry"]["rows"][1][4],
        AccessOutcome::PreparedHit as u8
    );
    assert_eq!(report["registration_telemetry"]["rows"][1][12], false);
    assert_eq!(
        report["registration_telemetry"]["rows"][1][6],
        ReleaseReason::Cleanup as u8
    );
}

fn public_verifier_fixture() -> (Arc<RegisteredVerifier>, Vec<[Val; 4]>) {
    let registered = RegisteredProgram::new_with_request(
        MachineAir::new(equality_program(2, 32, 1)),
        1 << 30,
        Request {
            policy: Policy::CpuRequired,
            emit_report: false,
        },
    )
    .unwrap();
    assert!(registered.identity_receipt().is_none());
    assert!(!registered.identity_hint_hit());
    (
        Arc::new(registered.verifier()),
        registered.preprocessing_cap().roots().to_vec(),
    )
}

#[test]
fn verifier_metadata_eviction_preserves_combined_accounting() {
    let (verifier, cap) = public_verifier_fixture();
    let mut registry = Registry::new();
    let fixed_bytes = registry.metadata_bytes;
    for index in 0..=MAX_METADATA_ENTRIES {
        registry
            .remember(cache_identity(index), &cap, Arc::clone(&verifier))
            .unwrap();
        assert_eq!(
            registry.metadata_bytes,
            fixed_bytes
                + registry
                    .metadata
                    .iter()
                    .map(|entry| entry.payload_bytes)
                    .sum::<usize>()
        );
        assert!(registry.metadata_bytes <= PUBLIC_METADATA_LIMIT_BYTES);
    }
    assert_eq!(registry.metadata.len(), MAX_METADATA_ENTRIES);
    assert_eq!(registry.metadata_evictions, 1);
    assert_eq!(
        registry.metadata.front().unwrap().identity,
        cache_identity(1)
    );
    assert!(registry.identity_hints.entries.is_empty());
    assert!(registry.identity_hint(cache_identity(1)).is_none());
}

#[test]
fn stale_verifier_cap_is_rejected_and_evicted_before_reuse() {
    let (verifier, cap) = public_verifier_fixture();
    assert!(!cap.is_empty());
    let context = ProvingContext::cpu(1 << 30).unwrap();
    let mut registry = Registry::new();
    let fixed_bytes = registry.metadata_bytes;
    let identity = cache_identity(3);
    registry.remember(identity, &cap, verifier).unwrap();
    assert!(registry
        .cached_verifier(cache_identity(4), &cap, &context.diagnostics)
        .unwrap()
        .is_none());
    assert_eq!(registry.metadata_hits, 0);
    let mut wrong_cap = cap;
    wrong_cap[0][0] += Val::ONE;
    assert!(registry
        .cached_verifier(identity, &wrong_cap, &context.diagnostics)
        .is_err());
    assert!(registry.metadata.is_empty());
    assert_eq!(registry.metadata_bytes, fixed_bytes);
    assert_eq!(registry.metadata_evictions, 1);
    assert_eq!(registry.metadata_hits, 0);
    assert_eq!(
        context.diagnostics.report()["failures"][0]["stage"],
        "registration_cap_mismatch"
    );
}

#[test]
fn canonical_identity_covers_program_shape_and_constants() {
    let original = equality_program(2, 32, 1);
    assert_eq!(
        manifest(&original).unwrap(),
        manifest(&equality_program(2, 32, 1)).unwrap()
    );
    for different in [
        equality_program(2, 64, 1),
        equality_program(1, 32, 1),
        equality_program(2, 32, 2),
    ] {
        assert_ne!(manifest(&original).unwrap(), manifest(&different).unwrap());
        assert_ne!(original, different);
    }
}

#[test]
fn contexts_have_separate_sessions_and_reject_reentrant_work() {
    assert!(ProvingContext::cpu(0).is_err());
    assert!(ProvingContext::cpu((32u64 << 30) + 1).is_err());
    let first = ProvingContext::cpu(1 << 30).unwrap();
    let second = ProvingContext::cpu(1 << 30).unwrap();
    assert_ne!(first.identity_seed, second.identity_seed);
    assert_ne!(first.session_id, second.session_id);
    first
        .with_native_cpu(|| {
            assert_eq!(first.report()["busy"], true);
            assert!(first.release_prepared().is_err());
            assert!(first.with_native_cpu(|| Ok(())).is_err());
            assert!(first
                .with_registered(equality_program(2, 32, 1), |_| Ok(()))
                .is_err());
            Ok(())
        })
        .unwrap();
    let report = first.finish().unwrap();
    assert_eq!(report["session_closed"], true);
    assert_eq!(report["prepared_entries"], 0);
    assert_eq!(report["registrations"], 0);
    assert_eq!(report["operations"]["native_cpu_calls"], 1);
    assert!(
        report["metadata_cache_payload_bytes"].as_u64().unwrap()
            <= PUBLIC_METADATA_LIMIT_BYTES as u64
    );
    second.finish().unwrap();
}

fn reuse_distinct_inputs(context: ProvingContext) {
    context
        .configure_registration(MetadataCapacity::Entries512, RegistrationTelemetry::Bounded)
        .unwrap();
    let program = equality_program(2, 32, 1);
    let mut returned = Vec::new();
    let mut first_bytes = None;
    for offset in [17, 117, 17] {
        let public = [Val::from_u64(offset + 1), Val::from_u64(offset + 2)];
        let witness = [Val::from_u64(offset), Val::from_u64(offset + 1)];
        let (proof, verifier) = context
            .with_registered(program.clone(), |registered| {
                let proof = registered.prove(&public, &witness)?;
                registered.verify(&proof, &public)?;
                let mut wrong = public;
                wrong[1] += Val::ONE;
                assert!(registered.verifier().verify(&proof, &wrong).is_err());
                Ok((proof, registered.verifier()))
            })
            .unwrap();
        let bytes = postcard::to_allocvec(&proof).unwrap();
        if returned.is_empty() {
            first_bytes = Some(bytes);
        } else if offset == 17 {
            // Identical inputs still receive newly sampled proving randomness.
            assert_ne!(first_bytes.as_ref().unwrap(), &bytes);
        }
        returned.push((proof, public, verifier));
    }
    let report = context.report();
    assert_eq!(report["registrations"], 1);
    assert_eq!(report["prepared_cache_hits"], 2);
    assert_eq!(report["prepared_entries"], 1);
    assert_eq!(report["maximum_prepared_entries"], 1);
    assert!(
        report["metadata_cache_payload_bytes"].as_u64().unwrap()
            <= PUBLIC_METADATA_LIMIT_BYTES as u64
    );

    if context.policy() == Policy::GpuRequired {
        assert!(context.with_native_cpu(|| Ok(())).is_err());
        context.release_prepared().unwrap();
        #[cfg(feature = "opencl")]
        assert_eq!(
            lattica_prover_p3::block_v2::gpu_hash::report("worker reuse release")
                .unwrap()
                .device_matrix_live_bytes,
            0
        );
    } else {
        context.with_native_cpu(|| Ok(())).unwrap();
    }
    assert_eq!(context.report()["prepared_entries"], 0);
    context.with_registered(program, |_| Ok(())).unwrap();
    assert_eq!(context.report()["metadata_cache_hits"], 1);
    if context.policy() == Policy::GpuRequired {
        assert_eq!(context.report()["identity_hints_supplied"], 1);
        assert_eq!(context.report()["identity_hint_hits"], 1);
        assert_eq!(context.report()["identity_receipt_entries"], 1);
    } else {
        assert_eq!(context.report()["identity_hints_supplied"], 0);
        assert_eq!(context.report()["identity_hint_hits"], 0);
        assert_eq!(context.report()["identity_receipt_entries"], 0);
    }
    let report = context.report();
    assert_eq!(
        report["metadata_cache_payload_bytes"].as_u64().unwrap(),
        report["verifier_metadata_cache_bytes"].as_u64().unwrap()
            + report["identity_receipt_cache_bytes"].as_u64().unwrap()
            + report["registration_telemetry_reserved_bytes"]
                .as_u64()
                .unwrap()
    );
    let finished = context.finish().unwrap();
    assert_eq!(finished["prepared_entries"], 0);
    assert_eq!(finished["session_closed"], true);
    assert_eq!(finished["registration_telemetry"]["complete"], true);
    assert_eq!(finished["registration_telemetry"]["recorded_accesses"], 4);
    assert_eq!(
        finished["registration_telemetry"]["rows"][3][6],
        ReleaseReason::SessionRetired as u8
    );
    // Only public verification state escapes the context/session lifetime.
    for (proof, public, verifier) in returned {
        verifier.verify(&proof, &public).unwrap();
    }
}

#[test]
#[ignore = "three real CPU proofs; run in a serialized resource window"]
fn cpu_worker_reuses_program_with_fresh_inputs_and_randomness() {
    reuse_distinct_inputs(ProvingContext::cpu(2 << 30).unwrap());
}

#[cfg(feature = "opencl")]
#[test]
#[ignore = "requires an exclusive OpenCL GPU, zero swap and serialized admitted resources"]
fn gpu_worker_reuses_program_with_fresh_inputs_and_randomness() {
    // Match the explicit serialized guard instead of silently replacing its
    // managed-device or host-output allowances. This small test stays within
    // the existing smoke profile's 8 GiB budgets even under another runner.
    let device_bytes = std::env::var("LATTICA_V2_GPU_MANAGED_BYTES")
        .expect("explicit guarded managed-device allowance required")
        .parse::<u64>()
        .expect("managed-device allowance must be an integer byte count");
    let host_bytes = std::env::var("LATTICA_V2_HOST_OUTPUT_BYTES")
        .expect("explicit guarded host-output allowance required")
        .parse::<u64>()
        .expect("host-output allowance must be an integer byte count");
    assert!(
        (256_u64 << 20..=8_u64 << 30).contains(&device_bytes),
        "managed-device allowance must be between 256 MiB and 8 GiB"
    );
    assert!(
        (1_u64 << 30..=8_u64 << 30).contains(&host_bytes),
        "host-output allowance must be between 1 GiB and 8 GiB"
    );
    reuse_distinct_inputs(
        ProvingContext::opencl(crate::opencl::Limits {
            host_bytes,
            device_bytes,
            max_rows: 1024,
        })
        .unwrap(),
    );
}
