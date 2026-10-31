use super::*;
use lattica_prover_p3::proving::Capabilities;

fn refused_report() -> Report {
    Report { schema: "lattica-proving-stages-v1", entry_point: "ringct_owned_native_shake",
        policy: Policy::GpuRequired, capabilities: Capabilities::cpu(Profile::BlockV2Cubic, true, false),
        elapsed_ns: 7, succeeded: false, stage_coverage_complete: false,
        completion_rejected: true, observation_errors: 0,
        observations: Vec::new(), components: Vec::new() }
}

#[test]
fn rejected_native_report_never_adds_credit_and_latches_refusal() {
    let observations = OwnedWorkflowObservations::default();
    let before = observations.totals.get();
    assert_eq!(observations.native_report(&refused_report(), b"owned_native_report ", 1, 4096, 13), Err(ObservationError::Report));
    assert_eq!(observations.totals.get(), before);
    assert_eq!(observations.snapshot(1), Err(ObservationError::Poisoned));
    assert_eq!(observations.update(Ok), Err(ObservationError::Poisoned));
    assert!(!observations.pristine());
}

#[test]
fn rejected_outer_and_preparation_reports_leave_every_counter_unchanged() {
    for outer in [false, true] {
        let observations = OwnedWorkflowObservations::default();
        let before = observations.totals.get();
        let result = if outer { observations.outer_report(&refused_report(), CoverageScope::RegisteredProof, 1, Some((100, 128))) }
            else { observations.preparation_report(&refused_report()) };
        assert_eq!(result, Err(ObservationError::Report));
        assert_eq!(observations.totals.get(), before);
        assert!(observations.snapshot(1).is_err());
    }
}

#[test]
fn overflow_does_not_publish_partial_counter_updates() {
    for count_overflow in [false, true] {
        let observations = OwnedWorkflowObservations::default();
        let mut initial = Totals::default();
        initial.machine_preprocessing = if count_overflow {
            ReportTotals { reports: u64::MAX, elapsed_ns: 1 }
        } else { ReportTotals { reports: 1, elapsed_ns: u128::MAX } };
        observations.totals.set(initial);
        let result = observations.update(|mut totals| {
            // Exercise transactional update ordering independently of reports.
            totals.machine_proofs = ReportTotals { reports: 2, elapsed_ns: 3 };
            totals.machine_preprocessing = totals.machine_preprocessing.add(1)?;
            Ok(totals)
        });
        assert_eq!(result, Err(ObservationError::Overflow));
        assert_eq!(observations.totals.get(), initial);
        assert_eq!(observations.snapshot(1), Err(ObservationError::Poisoned));
    }
}

#[test]
fn fixed_empty_snapshot_preserves_session_and_exact_entry_inventory() {
    let observations = OwnedWorkflowObservations::default();
    let snapshot = observations.snapshot(71).unwrap();
    assert_eq!(snapshot.session_id, 71);
    assert_eq!(snapshot.schema, "ringct-owned-workflow-observations-v2");
    assert_eq!(snapshot.row_receipts, 0);
    assert_eq!(snapshot.machine_rows, ProofRowTotals::recursive());
    assert!(observations.pristine());
    for (index, entry) in snapshot.native_proofs.iter().enumerate() {
        assert_eq!(entry.entry_point, NATIVE_ENTRIES[index]);
        assert_eq!(entry.totals, ReportTotals::default());
        assert_eq!(entry.rows, ProofRowTotals::native());
        assert!(!NATIVE_ENTRIES[..index].contains(&entry.entry_point));
    }
}

#[test]
fn cpu_context_cannot_report_owned_gpu_work() {
    let context = ProvingContext::cpu(8192).unwrap();
    assert_eq!(context.owned_workflow_snapshot(), Err(ObservationError::Context));
    assert_eq!(context.source_preparation_snapshot(), Err(ObservationError::Context));
}


#[test]
fn native_rows_distinguish_hiding_domain_and_refuse_inconsistent_degree() {
    let rows = ProofRows::native(4096, 13).unwrap();
    assert_eq!(rows.padded_rows, 4096);
    assert_eq!(rows.active_rows, None);
    assert_eq!(rows.native_degree_bits, Some(13));
    for (padded, degree) in [(0, 0), (3, 3), (4096, 12), (4096, 14), (4096, 0)] {
        assert_eq!(ProofRows::native(padded, degree), Err(ObservationError::Rows));
    }
    assert_eq!(ProofRows::native(4096, 64), Err(ObservationError::Overflow));
    assert_eq!(ProofRows::native(4096, usize::MAX), Err(ObservationError::Overflow));
    #[cfg(target_pointer_width = "64")]
    assert_eq!(ProofRows::native(1usize << 63, 63), Err(ObservationError::Overflow));
}

#[test]
fn recursive_rows_preserve_actual_active_count_and_validate_padding() {
    let rows = ProofRows::recursive(100, 128).unwrap();
    assert_eq!(rows.active_rows, Some(100));
    assert_eq!(rows.padded_rows, 128);
    assert_eq!(rows.native_degree_bits, None);
    assert_eq!(ProofRows::recursive(0, 8).unwrap().active_rows, Some(0));
    for (active, padded) in [(1, 0), (3, 4), (128, 127), (129, 128)] {
        assert_eq!(ProofRows::recursive(active, padded), Err(ObservationError::Rows));
    }
}

#[test]
fn row_totals_preserve_unknown_native_active_and_refuse_mixed_semantics() {
    let native = ProofRows::native(4096, 13).unwrap();
    let recursive = ProofRows::recursive(100, 128).unwrap();
    let totals = ProofRowTotals::native().add(native).unwrap().add(native).unwrap();
    assert_eq!(totals, ProofRowTotals { proofs: 2, active_rows: None, padded_rows: 8192 });
    let totals = ProofRowTotals::recursive().add(recursive).unwrap().add(recursive).unwrap();
    assert_eq!(totals, ProofRowTotals { proofs: 2, active_rows: Some(200), padded_rows: 256 });
    assert_eq!(ProofRowTotals::native().add(recursive), Err(ObservationError::Rows));
    assert_eq!(ProofRowTotals::recursive().add(native), Err(ObservationError::Rows));
}

#[test]
fn every_row_sum_overflow_is_transactional_and_poisons_observations() {
    let actual = ProofRows::recursive(1, 8).unwrap();
    for initial_rows in [
        ProofRowTotals { proofs: u64::MAX, active_rows: Some(0), padded_rows: 0 },
        ProofRowTotals { proofs: 0, active_rows: Some(u128::MAX), padded_rows: 0 },
        ProofRowTotals { proofs: 0, active_rows: Some(0), padded_rows: u128::MAX },
    ] {
        let observations = OwnedWorkflowObservations::default();
        let mut initial = Totals::default();
        initial.machine_rows = initial_rows;
        observations.totals.set(initial);
        assert_eq!(observations.update(|mut totals| {
            totals.machine_proofs = totals.machine_proofs.add(7)?;
            totals.machine_rows = totals.machine_rows.add(actual)?;
            Ok(totals)
        }), Err(ObservationError::Overflow));
        assert_eq!(observations.totals.get(), initial);
        assert_eq!(observations.snapshot(1), Err(ObservationError::Poisoned));
    }
}

#[test]
fn partial_row_publication_cannot_commit_or_retry_the_counter_update() {
    let observations = OwnedWorkflowObservations::default();
    let before = observations.totals.get();
    assert_eq!(observations.update(|mut totals| {
        totals.machine_rows = totals.machine_rows.add(ProofRows::recursive(100, 128)?)?;
        totals.machine_proofs = totals.machine_proofs.add(7)?;
        totals.row_receipts = 1;
        let _ = totals;
        Err(ObservationError::Write)
    }), Err(ObservationError::Write));
    assert_eq!(observations.totals.get(), before);
    assert_eq!(observations.snapshot(1), Err(ObservationError::Poisoned));
    assert_eq!(observations.update(Ok), Err(ObservationError::Poisoned));
}

#[test]
fn row_receipt_serialization_keeps_native_absence_and_exact_proof_degree() {
    let actual = ProofRows::native(4096, 13).unwrap();
    assert_eq!(ProofRowReceipt::new(0, 0, NATIVE_ENTRIES[11], actual), Err(ObservationError::Context));
    let receipt = ProofRowReceipt::new(2, 0, NATIVE_ENTRIES[11], actual).unwrap();
    assert_eq!(serde_json::to_value(receipt).unwrap(), serde_json::json!({
        "schema": "ringct-owned-proof-rows-v1", "session_id": 2, "sequence": 0,
        "entry_point": "ringct_owned_native_shake", "active_rows": null,
        "padded_rows": 4096, "native_degree_bits": 13,
    }));
    let receipt = ProofRowReceipt::new(2, 1, "block_v2_registered_program",
        ProofRows::recursive(100, 128).unwrap()).unwrap();
    assert_eq!(serde_json::to_value(receipt).unwrap(), serde_json::json!({
        "schema": "ringct-owned-proof-rows-v1", "session_id": 2, "sequence": 1,
        "entry_point": "block_v2_registered_program", "active_rows": 100,
        "padded_rows": 128, "native_degree_bits": null,
    }));
}


#[test]
fn global_row_sequence_overflow_never_wraps_or_publishes_partial_totals() {
    let observations = OwnedWorkflowObservations::default();
    let mut initial = Totals::default();
    initial.row_receipts = u64::MAX;
    observations.totals.set(initial);
    assert_eq!(observations.update(|mut totals| {
        totals.machine_proofs = totals.machine_proofs.add(7)?;
        totals.machine_rows = totals.machine_rows.add(ProofRows::recursive(100, 128)?)?;
        totals.row_receipts = totals.row_receipts.checked_add(1).ok_or(ObservationError::Overflow)?;
        Ok(totals)
    }), Err(ObservationError::Overflow));
    assert_eq!(observations.totals.get(), initial);
    assert_eq!(observations.snapshot(1), Err(ObservationError::Poisoned));
}
