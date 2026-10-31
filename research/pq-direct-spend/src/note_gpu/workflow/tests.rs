use super::*;

struct Hex<'a>(&'a [u8; 32]);
impl std::fmt::Display for Hex<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

#[test]
fn stable_statement_digests_bind_recipe_context_and_all_seven_publics() {
    let session = DecodeSession::new(WORKER_HOST_BYTES).unwrap();
    let a = session.research_fixtures(Context([109; 32])).unwrap();
    let b = session.research_fixtures(Context([109; 32])).unwrap();
    let c = session.research_fixtures(Context([110; 32])).unwrap();
    let mut prior = [[0u8; 32]; CASE_COUNT];
    for id in FixtureId::ALL {
        let digest = statement_digest(a.get(id));
        assert_eq!(digest, statement_digest(b.get(id)));
        assert_ne!(digest, statement_digest(c.get(id)));
        assert!(!prior[..id.ordinal()].contains(&digest));
        prior[id.ordinal()] = digest;
        eprintln!(
            "private_note_expected_case ordinal={} fixture_recipe={} public_statement_digest={}",
            id.ordinal(),
            FIXTURE_RECIPE,
            Hex(&digest)
        );
    }
    drop((a, b, c));
    assert_eq!(session.snapshot().live_reserved_bytes, LEDGER_BYTES);
}

#[test]
fn roundtrip_capacity_is_reserved_before_any_packet_or_producer() {
    let verifier = VerificationPlan::new().unwrap();
    let large = DecodeSession::new(WORKER_HOST_BYTES).unwrap();
    let claim = RoundtripAdmission::reserve(&large, &verifier).unwrap();
    let required = claim.reservation.reserved_bytes();
    assert_eq!(required, claim.decoder_bytes + claim.verifier_bytes);
    assert!(claim.decoder_bytes > 2 * MAX_PROOF_BYTES);
    assert!(claim.verifier_bytes > 0);
    drop(claim);
    assert_eq!(large.snapshot().live_reserved_bytes, LEDGER_BYTES);
    let short = DecodeSession::new(LEDGER_BYTES + required - 1).unwrap();
    assert!(matches!(
        RoundtripAdmission::reserve(&short, &verifier),
        Err(Error::ResourceLimit)
    ));
    assert_eq!(short.snapshot().admitted_attempts, 0);
    assert_eq!(short.snapshot().live_reserved_bytes, LEDGER_BYTES);
    let exact = DecodeSession::new(LEDGER_BYTES + required).unwrap();
    let marker = exact.reserve_for_producer(0).unwrap();
    let claim = RoundtripAdmission::reserve(&exact, &verifier).unwrap();
    assert!(claim.reservation.same_ledger(&marker));
    drop(exact);
    let moved = Some(claim);
    assert_eq!(
        marker.snapshot().live_reserved_bytes,
        LEDGER_BYTES + required
    );
    drop(moved);
    assert_eq!(marker.snapshot().live_reserved_bytes, LEDGER_BYTES);
}

#[test]
fn workflow_report_and_fixed_case_storage_have_a_preceding_charge() {
    let plan = WorkflowPlan::new().unwrap();
    assert!(
        plan.report_bytes >= size_of::<OwnedWorkflowReport>() + size_of::<WorkflowMeasurement>()
    );
    let exact = DecodeSession::new(LEDGER_BYTES + plan.report_bytes).unwrap();
    let token = exact.reserve_for_producer(plan.report_bytes).unwrap();
    let before = exact.snapshot().live_reserved_bytes;
    assert!(matches!(
        exact.research_fixtures(Context([108; 32])),
        Err(Error::ResourceLimit)
    ));
    assert_eq!(exact.snapshot().live_reserved_bytes, before);
    drop(token);
    assert_eq!(exact.snapshot().live_reserved_bytes, LEDGER_BYTES);
}

#[test]
#[ignore = "exact dedicated immutable env-clear RTX 5080 worker, coordinator process/VRAM guard only"]
fn gpu_seven_distinct_note_workflow_verifies_roundtrips_and_cleans_up() {
    // SAFETY: only the coordinator's exact ignored-test worker may select this
    // entry. It fixes the environment and serializes the complete GPU interval.
    let report = unsafe { run_gpu_for_qualification(Context([109; 32])) }.unwrap();
    let measurement = report.measurement();
    assert_eq!(measurement.distinct_statements, 7);
    assert_eq!(measurement.distinct_nullifiers, 14);
    assert_eq!(measurement.native_proofs, 7);
    assert_eq!(measurement.native_gpu_runtimes, 7);
    assert_eq!(measurement.fresh_cpu_proof_configurations, 0);
    assert_eq!(measurement.recursive_proofs, 0);
    assert_eq!(measurement.fresh_public_preparations, 7);
    assert_eq!(measurement.independent_cpu_verifications, 14);
    assert_eq!(measurement.canonical_roundtrips, 7);
    assert_eq!(measurement.value_bits, 52);
    assert_eq!(measurement.active_rows_per_case, 2560);
    assert_eq!(measurement.padded_rows_per_case, 4096);
    assert!(measurement.all_native_runtimes_retired && measurement.all_proof_payloads_destroyed);
    assert!(!measurement.complete_ringct_workflow);
    assert!(!measurement.recursive_aggregation_performed && !measurement.production_acceptance);
    assert!(!measurement.cpu_baseline_qualified);
    assert!(measurement.external_guard_memory_telemetry_required);
    assert_eq!(measurement.actual_process_host_peak_bytes, None);
    assert_eq!(measurement.actual_process_device_peak_bytes, None);
    let managed_peak = measurement
        .managed_device_peak_bytes
        .expect("all seven exact GPU engines retired with managed peaks");
    assert!((1..=(8usize << 30)).contains(&managed_peak));
    assert_eq!(
        Some(managed_peak),
        measurement
            .cases
            .iter()
            .filter_map(|case| case.managed_device_peak_bytes)
            .max()
    );
    let mut sequential_ns = measurement.fixture_generation_and_distinctness_ns;
    for (ordinal, case) in measurement.cases.iter().enumerate() {
        assert_eq!(case.id.ordinal(), ordinal);
        let case_managed_peak = case
            .managed_device_peak_bytes
            .expect("this exact GPU engine retired");
        assert!((1..=managed_peak).contains(&case_managed_peak));
        eprintln!("private_note_case_managed_memory backend=fresh_gpu_required ordinal={ordinal} managed_device_peak_bytes={case_managed_peak} actual_process_device_peak_bytes=external_guard_only");
        assert!(case.native_proof_bytes > 0 && case.native_proof_bytes <= MAX_PROOF_BYTES);
        assert!(case.reported_native_proof_scope_ns > 0);
        assert!(case.reported_native_proof_scope_ns <= case.native_dispatch_and_retirement_ns);
        assert!(case.independent_cpu_verification_ns > 0 && case.artifact_roundtrip_ns > 0);
        sequential_ns += case.prepare_through_payload_cleanup_ns;
        eprintln!("private_note_seven_case_identity backend=fresh_gpu_required ordinal={ordinal} fixture_recipe={} public_statement_digest={} canonical_packet_hash={}",
            measurement.fixture_recipe, Hex(&case.public_statement_digest), Hex(&case.canonical_packet_hash));
        eprintln!("private_note_seven_case ordinal={ordinal} fixture_generation_ns={} public_preparation_ns={} native_dispatch_and_retirement_ns={} reported_native_proof_scope_ns={} canonical_handoff_decode_ns={} independent_cpu_verification_ns={} artifact_roundtrip_ns={} proof_payload_destruction_ns={} prepare_through_payload_cleanup_ns={} native_proof_bytes={} native_proofs=1 recursive_proofs=0 active_rows=2560 padded_rows=4096 fresh_public_preparation=true runtime_retired=true proof_payloads_destroyed=true",
            case.fixture_generation_ns, case.public_preparation_ns,
            case.native_dispatch_and_retirement_ns, case.reported_native_proof_scope_ns,
            case.canonical_handoff_decode_ns, case.independent_cpu_verification_ns,
            case.artifact_roundtrip_ns, case.proof_payload_destruction_ns,
            case.prepare_through_payload_cleanup_ns, case.native_proof_bytes);
    }
    assert!(sequential_ns <= measurement.complete_note_research_workflow_ns);
    let snapshot = report.quota_snapshot();
    assert_eq!(
        snapshot.live_reserved_bytes,
        LEDGER_BYTES + measurement.report_retained_bytes
    );
    assert!(snapshot.peak_reserved_bytes <= WORKER_HOST_BYTES);
    eprintln!("private_note_seven_workflow cases=7 distinct_statements=7 distinct_nullifiers=14 native_proofs=7 recursive_proofs=0 independent_cpu_verifications=14 canonical_roundtrips=7 fixture_generation_and_distinctness_ns={} complete_note_research_workflow_ns={} host_payload_reservation_peak_bytes={} report_retained_bytes={} actual_memory_source=external_guard cpu_baseline_qualified=false complete_ringct_workflow=false production_acceptance=false",
        measurement.fixture_generation_and_distinctness_ns,
        measurement.complete_note_research_workflow_ns,
        measurement.host_payload_reservation_peak_bytes, measurement.report_retained_bytes);
    eprintln!("private_note_workflow_managed_memory backend=fresh_gpu_required managed_device_peak_bytes={managed_peak} source=exact_retired_engine_max actual_process_device_peak_bytes=external_guard_only");
    let marker = report.reservation.reserve_related(0).unwrap();
    drop(report);
    assert_eq!(marker.snapshot().live_reserved_bytes, LEDGER_BYTES);
    eprintln!("private_note_seven_workflow_terminal original_quota_released=true all_native_runtimes_retired=true all_proof_payloads_destroyed=true complete_ringct_workflow=false");
}

#[test]
#[ignore = "exact dedicated immutable env-clear CPU-required worker, coordinator process guard only"]
fn cpu_seven_distinct_note_workflow_verifies_roundtrips_and_cleans_up() {
    // This selector has its own CPU-required worker policy. The GPU-required
    // guard must never select it, even though the binary contains both paths.
    assert_eq!(
        std::env::var("LATTICA_PROVING_POLICY").as_deref(),
        Ok("cpu-required")
    );
    assert_eq!(std::env::var("RAYON_NUM_THREADS").as_deref(), Ok("8"));
    // SAFETY: the coordinator's exact selector enforces the complete external
    // CPU worker contract and serializes this whole benchmark interval.
    let report = unsafe { run_cpu_for_qualification(Context([109; 32])) }.unwrap();
    let m = report.measurement();
    assert_eq!(m.backend, "fresh_cpu_required");
    assert_eq!(m.fixture_recipe, FIXTURE_RECIPE);
    assert_eq!((m.distinct_statements, m.distinct_nullifiers), (7, 14));
    assert_eq!((m.native_proofs, m.recursive_proofs), (7, 0));
    assert_eq!(
        (m.native_gpu_runtimes, m.fresh_cpu_proof_configurations),
        (0, 7)
    );
    assert_eq!(
        (m.independent_cpu_verifications, m.canonical_roundtrips),
        (14, 7)
    );
    assert_eq!(
        (m.value_bits, m.active_rows_per_case, m.padded_rows_per_case),
        (52, 2560, 4096)
    );
    assert!(m.cpu_baseline_qualified && m.all_proof_payloads_destroyed);
    assert!(
        !m.complete_ringct_workflow
            && !m.recursive_aggregation_performed
            && !m.production_acceptance
    );
    assert!(m.external_guard_memory_telemetry_required);
    assert_eq!(m.managed_device_peak_bytes, None);
    assert_eq!(
        (
            m.actual_process_host_peak_bytes,
            m.actual_process_device_peak_bytes
        ),
        (None, None)
    );
    let mut sequential_ns = m.fixture_generation_and_distinctness_ns;
    for (ordinal, case) in m.cases.iter().enumerate() {
        assert_eq!(case.id.ordinal(), ordinal);
        assert_eq!(case.managed_device_peak_bytes, None);
        eprintln!("private_note_case_managed_memory backend=fresh_cpu_required ordinal={ordinal} managed_device_peak_bytes=none actual_process_device_peak_bytes=external_guard_only");
        assert!(case.native_proof_bytes > 0 && case.native_proof_bytes <= MAX_PROOF_BYTES);
        assert!(case.cpu.fresh_configuration_ns > 0 && case.cpu.trace_generation_ns > 0);
        assert!(case.cpu.proof_ns > 0 && case.cpu.canonical_encoding_ns > 0);
        assert_eq!(case.reported_native_proof_scope_ns, case.cpu.proof_ns);
        assert!(
            case.cpu.fresh_configuration_ns
                + case.cpu.trace_generation_ns
                + case.cpu.proof_ns
                + case.cpu.canonical_encoding_ns
                + case.cpu.configuration_and_proof_cleanup_ns
                <= case.native_dispatch_and_retirement_ns
        );
        assert!(case.independent_cpu_verification_ns > 0 && case.artifact_roundtrip_ns > 0);
        sequential_ns += case.prepare_through_payload_cleanup_ns;
        eprintln!("private_note_seven_case_identity backend=fresh_cpu_required ordinal={ordinal} fixture_recipe={} public_statement_digest={} canonical_packet_hash={}",
            m.fixture_recipe, Hex(&case.public_statement_digest), Hex(&case.canonical_packet_hash));
        eprintln!("private_note_cpu_seven_case ordinal={ordinal} fixture_generation_ns={} public_preparation_ns={} native_dispatch_and_retirement_ns={} reported_native_proof_scope_ns={} canonical_handoff_decode_ns={} independent_cpu_verification_ns={} artifact_roundtrip_ns={} proof_payload_destruction_ns={} prepare_through_payload_cleanup_ns={} native_proof_bytes={} fresh_configuration_ns={} trace_generation_ns={} canonical_encoding_ns={} configuration_and_proof_cleanup_ns={} native_proofs=1 recursive_proofs=0 active_rows=2560 padded_rows=4096 fresh_public_preparation=true cpu_required=true gpu_work_performed=false proof_payloads_destroyed=true",
            case.fixture_generation_ns, case.public_preparation_ns,
            case.native_dispatch_and_retirement_ns, case.reported_native_proof_scope_ns,
            case.canonical_handoff_decode_ns, case.independent_cpu_verification_ns,
            case.artifact_roundtrip_ns, case.proof_payload_destruction_ns,
            case.prepare_through_payload_cleanup_ns, case.native_proof_bytes,
            case.cpu.fresh_configuration_ns, case.cpu.trace_generation_ns,
            case.cpu.canonical_encoding_ns, case.cpu.configuration_and_proof_cleanup_ns);
    }
    assert!(sequential_ns <= m.complete_note_research_workflow_ns);
    let snapshot = report.quota_snapshot();
    assert_eq!(
        snapshot.live_reserved_bytes,
        LEDGER_BYTES + m.report_retained_bytes
    );
    assert!(snapshot.peak_reserved_bytes <= WORKER_HOST_BYTES);
    eprintln!("private_note_cpu_seven_workflow cases=7 distinct_statements=7 distinct_nullifiers=14 native_proofs=7 recursive_proofs=0 independent_cpu_verifications=14 canonical_roundtrips=7 fixture_generation_and_distinctness_ns={} complete_note_research_workflow_ns={} host_payload_reservation_peak_bytes={} report_retained_bytes={} actual_memory_source=external_guard cpu_baseline_qualified=true native_gpu_runtimes=0 fresh_cpu_proof_configurations=7 complete_ringct_workflow=false production_acceptance=false",
        m.fixture_generation_and_distinctness_ns, m.complete_note_research_workflow_ns,
        m.host_payload_reservation_peak_bytes, m.report_retained_bytes);
    eprintln!("private_note_workflow_managed_memory backend=fresh_cpu_required managed_device_peak_bytes=none source=no_gpu_runtime actual_process_device_peak_bytes=external_guard_only");
    let marker = report.reservation.reserve_related(0).unwrap();
    drop(report);
    assert_eq!(marker.snapshot().live_reserved_bytes, LEDGER_BYTES);
    eprintln!("private_note_cpu_seven_workflow_terminal original_quota_released=true all_cpu_configurations_destroyed=true all_proof_payloads_destroyed=true gpu_work_performed=false complete_ringct_workflow=false");
}
