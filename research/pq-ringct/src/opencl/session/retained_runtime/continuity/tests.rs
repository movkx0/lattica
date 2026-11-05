use super::*;
use crate::execution::retained_resources::WorkerAllowance;

fn ledger() -> Ledger {
    Ledger::new(WorkerAllowance {
        host: WORKER_HOST,
        device: MANAGED_DEVICE,
    })
}

fn limits() -> Limits {
    Limits {
        host_bytes: WORKER_HOST,
        device_bytes: MANAGED_DEVICE,
        max_rows: MAX_ROWS,
    }
}

// CPU tests exercise only the pure source validation with real unstarted
// owners. No Runtime, selected device, binding, or sealed retirement owner is
// fabricated. Actual typed restoration requires the separate GPU qualifier.
#[test]
fn original_host_source_plan_preserves_all_counters_and_ownership() {
    let ledger = ledger();
    let pending = PendingRuntime::reserve_outer_host_v1(&ledger, limits()).unwrap();
    let original = pending.reservation.requirements();
    let before = ledger.snapshot();
    let plan = restoration_plan(original, pending.belongs_to(&ledger), &ledger, limits())
        .expect("exact original source plan refused");
    assert_eq!(ledger.snapshot(), before);
    assert_eq!(pending.reservation.requirements(), original);
    assert!(pending.belongs_to(&ledger));
    assert!(pending.selection.is_none());
    assert_eq!(plan.footprint().retained_tree_host_bytes, 8 << 30);
    drop(plan);
    drop(pending);
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
}

#[test]
fn source_plan_refuses_foreign_ledger_and_wrong_profile_without_changes() {
    let ledger = ledger();
    let foreign = self::ledger();
    let pending = PendingRuntime::reserve_outer_host_v1(&ledger, limits()).unwrap();
    let original = pending.reservation.requirements();
    let before = ledger.snapshot();
    let error = match restoration_plan(original, pending.belongs_to(&foreign), &foreign, limits()) {
        Err(error) => error,
        Ok(_) => panic!("foreign source plan accepted"),
    };
    assert_eq!(error, RuntimeError::WrongLedger);
    assert!(pending.belongs_to(&ledger));
    assert_eq!(pending.reservation.requirements(), original);
    assert_eq!(ledger.snapshot(), before);
    assert_eq!(foreign.snapshot().current, Bytes::ZERO);
    drop(pending);
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);

    let pending = PendingRuntime::reserve(&ledger, limits()).unwrap();
    let original = pending.reservation.requirements();
    let before = ledger.snapshot();
    let error = match restoration_plan(original, pending.belongs_to(&ledger), &ledger, limits()) {
        Err(error) => error,
        Ok(_) => panic!("device source plan retargeted to host"),
    };
    assert_eq!(error, RuntimeError::Admission);
    assert!(pending.belongs_to(&ledger));
    assert_eq!(pending.reservation.requirements(), original);
    assert_eq!(ledger.snapshot(), before);
    drop(pending);
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
}

#[test]
#[ignore = "exclusive guarded owned host runtime; CPU identity workers start after GPU retirement"]
fn gpu_owned_identity_cohort_retires_before_cpu_workers() {
    use lattica_prover_p3::block_v2::machine::{
        backend::identity_cpu::{IdentityBatchFootprint, IdentityCpuContext, IdentityCpuOptions},
        ProgramBuilder,
    };
    use lattica_prover_p3::proving::{Policy, Request};
    use std::sync::Arc;
    assert_eq!(
        std::env::var("LATTICA_OWNED_IDENTITY_COHORT_QUALIFICATION").as_deref(),
        Ok("1")
    );
    for streams in [2, 16] {
        let ledger = ledger();
        // Fixed tiny test-program construction precedes the independently
        // charged prefix workspace and authentic owned runtime startup.
        let program_original = ledger
            .reserve(
                Category::PhaseScratch,
                Bytes {
                    host: 1 << 20,
                    device: 0,
                },
            )
            .unwrap();
        let mut builder = ProgramBuilder::new(1).unwrap();
        let input = builder.input();
        builder.assert_equal(builder.public(0).unwrap(), input);
        let program = Arc::new(builder.finish(Some(64)).unwrap());
        let footprint =
            IdentityBatchFootprint::for_borrowed_program_bounds(streams, 1 << 20).unwrap();
        let prefix_original = ledger
            .reserve(
                Category::PhaseScratch,
                Bytes {
                    host: footprint.host_bytes,
                    device: footprint.managed_bytes,
                },
            )
            .unwrap();
        let pending = PendingRuntime::reserve_outer_host_v1(&ledger, limits()).unwrap();
        // SAFETY: the exact guard supplies an immutable, exclusive host profile.
        let session = unsafe { pending.start().unwrap() };
        let context = IdentityCpuContext::new();
        let programs = (0..streams).map(|job| (job as u64, &program)).collect();
        let batch = context
            .plan_borrowed(
                IdentityCpuOptions::workers(streams).unwrap(),
                programs,
                footprint.host_bytes,
                footprint.managed_bytes,
            )
            .unwrap();
        assert!(batch.footprint().borrowed_program_host_bytes < 1 << 20);
        let batch = batch
            .execute(Request {
                policy: Policy::GpuRequired,
                emit_report: false,
            })
            .unwrap();
        let retired = session
            .finish_reserved_with_owner(&ledger)
            .unwrap_or_else(|error| panic!("identity cohort runtime retirement: {error:?}"));
        let startup_original =
            retired
                .into_outer_host_original(&ledger)
                .unwrap_or_else(|(error, _owner)| {
                    panic!("identity cohort startup restoration: {error:?}")
                });
        let (tokens, report) = batch.complete_after_retirement().unwrap();
        assert_eq!(tokens.len(), streams);
        assert_eq!(report.streams, streams);
        assert_eq!(report.effective_workers, streams);
        println!("OWNED_IDENTITY_COHORT streams={streams} retirement_complete=true prefixes_complete=true");
        drop((tokens, report, context));
        drop(prefix_original);
        drop(program);
        drop(program_original);
        drop(startup_original);
        assert_eq!(ledger.snapshot().current, Bytes::ZERO);
    }
}
