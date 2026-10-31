use super::*;
use crate::execution::retained_resources::{Snapshot as QuotaSnapshot, WorkerAllowance};
use lattica_prover_p3::proving::Capabilities;
use std::cell::RefCell;
use std::rc::Rc;

fn identity() -> PhaseIdentity {
    PhaseIdentity {
        kind: PhaseKind::NativeChild,
        ordinal: 7,
        first_segment: 9,
        segment_count: 1,
        profile: [31; 32],
    }
}

fn caller_requirements() -> Requirements {
    Requirements::single(
        Category::PhaseScratch,
        Bytes {
            host: PhaseReportOwner::reclamation_caller_host_bytes() as u64,
            device: 0,
        },
    )
}

fn fixture(caller_request: Requirements) -> (Ledger, PhaseReportOwner, Reservation) {
    let report_request = PhaseReportOwner::requirements();
    let report_bytes = report_request.total().unwrap();
    let caller_bytes = caller_request.total().unwrap();
    let ledger = Ledger::new(WorkerAllowance {
        host: report_bytes.host + caller_bytes.host,
        device: report_bytes.device + caller_bytes.device,
    });
    let original = ledger.admit_phase(report_request).unwrap();
    let caller = ledger.admit_phase(caller_request).unwrap();
    let mut owner = PhaseReportOwner::from_reservation(original, &ledger, identity())
        .unwrap_or_else(|_| panic!("valid report fixture"));
    // A storage fixture, not a backend execution or proof-success assertion.
    let source = Report {
        schema: "lattica-proving-stages-v1",
        entry_point: "reclamation_storage_fixture",
        policy: Policy::CpuRequired,
        capabilities: Capabilities::cpu(Profile::BlockV2Cubic, false, false),
        elapsed_ns: 17,
        succeeded: false,
        stage_coverage_complete: false,
        completion_rejected: true,
        observation_errors: 2,
        observations: vec![],
        components: vec![],
    };
    owner.record_proving(&source).unwrap();
    owner
        .record_failure(FailureStage::Proving, "bounded failure evidence")
        .unwrap();
    owner.encode().unwrap();
    (ledger, owner, caller)
}

struct OwnerState {
    payload: *const Payload,
    encoding: *const u8,
    encoding_capacity: usize,
    backing: Vec<u8>,
    used: usize,
}

impl OwnerState {
    fn capture(owner: &PhaseReportOwner) -> Self {
        Self {
            payload: &*owner.payload,
            encoding: owner.encoding.bytes.as_ptr(),
            encoding_capacity: owner.encoding.bytes.capacity(),
            backing: owner.encoding.bytes.clone(),
            used: owner.encoding.used,
        }
    }

    fn assert_intact(&self, owner: &mut PhaseReportOwner) {
        assert_eq!(&*owner.payload as *const Payload, self.payload);
        assert_eq!(owner.payload.identity, identity());
        assert!(owner.payload.reports[0].is_some());
        assert!(owner.payload.reports[1].is_none());
        assert!(owner.payload.failure.is_some());
        assert_eq!(owner.encoding.bytes.as_ptr(), self.encoding);
        assert_eq!(owner.encoding.bytes.capacity(), self.encoding_capacity);
        assert_eq!(owner.encoding.bytes.as_slice(), self.backing.as_slice());
        assert_eq!(owner.encoding.used, self.used);
        // Re-encoding also observes every retained payload field after refusal.
        assert_eq!(owner.encode().unwrap(), &self.backing[..self.used]);
    }
}

fn assert_terminal(ledger: &Ledger, before: QuotaSnapshot) {
    let terminal = ledger.snapshot();
    assert_eq!(terminal.current, Bytes::ZERO);
    assert_eq!(terminal.peak, before.peak);
    for category in Category::ALL {
        assert_eq!(terminal.categories[category as usize].current, Bytes::ZERO);
        assert_eq!(
            terminal.categories[category as usize].peak,
            before.categories[category as usize].peak
        );
    }
}

#[test]
fn successful_reclamation_keeps_original_charge_at_full_allowance() {
    let (ledger, owner, caller) = fixture(caller_requirements());
    let before = ledger.snapshot();
    assert_eq!(ledger.remaining(), Bytes::ZERO);
    assert!(ledger
        .reserve(Category::Report, Bytes { host: 1, device: 0 })
        .is_err());
    let original = owner
        .reclaim_original(identity(), &caller, &ledger)
        .unwrap_or_else(|_| panic!("exact original report reclamation"));
    assert!(original.belongs_to(&ledger));
    assert_eq!(original.requirements(), PhaseReportOwner::requirements());
    assert_eq!(ledger.snapshot(), before);
    // The stored failure does not block cleanup or become proof authority.
    drop(original);
    let released = ledger.snapshot();
    assert_eq!(released.current, caller_requirements().total().unwrap());
    assert_eq!(
        released.categories[Category::Report as usize].current,
        Bytes::ZERO
    );
    assert_eq!(released.peak, before.peak);
    drop(caller);
    assert_terminal(&ledger, before);
}

#[test]
fn every_identity_mismatch_returns_the_entire_report_unchanged() {
    let (ledger, mut owner, caller) = fixture(caller_requirements());
    let state = OwnerState::capture(&owner);
    let before = ledger.snapshot();
    let expected = identity();
    let mut changed_profile = expected.profile;
    changed_profile[0] ^= 1;
    for wrong in [
        PhaseIdentity {
            kind: PhaseKind::RegisteredWrapper,
            ..expected
        },
        PhaseIdentity {
            ordinal: expected.ordinal + 1,
            ..expected
        },
        PhaseIdentity {
            first_segment: expected.first_segment + 1,
            ..expected
        },
        PhaseIdentity {
            segment_count: 2,
            ..expected
        },
        PhaseIdentity {
            profile: changed_profile,
            ..expected
        },
    ] {
        let (error, returned) = owner
            .reclaim_original(wrong, &caller, &ledger)
            .err()
            .unwrap();
        assert_eq!(error, Error::InvalidIdentity);
        owner = returned;
        state.assert_intact(&mut owner);
        assert_eq!(ledger.snapshot(), before);
    }
    drop(owner);
    drop(caller);
    assert_terminal(&ledger, before);
}

#[test]
fn foreign_ledger_or_caller_preserves_both_ledgers_and_all_report_storage() {
    let (ledger, owner, caller) = fixture(caller_requirements());
    let foreign = Ledger::new(ledger.snapshot().allowance);
    let foreign_caller = foreign.admit_phase(caller_requirements()).unwrap();
    let before = ledger.snapshot();
    let foreign_before = foreign.snapshot();
    let state = OwnerState::capture(&owner);
    let (error, mut owner) = owner
        .reclaim_original(identity(), &caller, &foreign)
        .err()
        .unwrap();
    assert_eq!(error, Error::WrongLedger);
    state.assert_intact(&mut owner);
    assert_eq!(ledger.snapshot(), before);
    assert_eq!(foreign.snapshot(), foreign_before);
    let (error, mut owner) = owner
        .reclaim_original(identity(), &foreign_caller, &ledger)
        .err()
        .unwrap();
    assert_eq!(error, Error::WrongLedger);
    state.assert_intact(&mut owner);
    assert_eq!(ledger.snapshot(), before);
    assert_eq!(foreign.snapshot(), foreign_before);
    drop(owner);
    drop(caller);
    drop(foreign_caller);
    assert_terminal(&ledger, before);
    assert_terminal(&foreign, foreign_before);
}

#[test]
fn short_or_wrong_category_caller_returns_intact_ownership() {
    let full = caller_requirements().total().unwrap();
    for request in [
        Requirements::single(
            Category::PhaseScratch,
            Bytes {
                host: full.host - 1,
                device: 0,
            },
        ),
        Requirements::single(Category::Report, full),
        Requirements::single(
            Category::PhaseScratch,
            Bytes {
                host: 0,
                device: full.host,
            },
        ),
    ] {
        let (ledger, owner, caller) = fixture(request);
        let state = OwnerState::capture(&owner);
        let before = ledger.snapshot();
        let (error, mut returned) = owner
            .reclaim_original(identity(), &caller, &ledger)
            .err()
            .unwrap();
        assert_eq!(error, Error::WrongReservation);
        state.assert_intact(&mut returned);
        assert_eq!(ledger.snapshot(), before);
        assert_eq!(caller.requirements(), request);
        drop(returned);
        drop(caller);
        assert_terminal(&ledger, before);
    }
}

#[test]
fn inexact_report_reservation_refuses_without_destroying_its_storage() {
    let (ledger, mut owner, caller) = fixture(caller_requirements());
    // The public constructor cannot make this state. Move one original byte
    // aside without releasing it to exercise the defensive consuming check.
    let held = owner
        .reservation
        .split(Requirements::single(
            Category::Report,
            Bytes { host: 1, device: 0 },
        ))
        .unwrap();
    let expected_request = owner.reservation.requirements();
    let state = OwnerState::capture(&owner);
    let before = ledger.snapshot();
    let (error, mut returned) = owner
        .reclaim_original(identity(), &caller, &ledger)
        .err()
        .unwrap();
    assert_eq!(error, Error::WrongReservation);
    assert_eq!(returned.reservation.requirements(), expected_request);
    state.assert_intact(&mut returned);
    assert_eq!(ledger.snapshot(), before);
    drop(returned);
    drop(held);
    drop(caller);
    assert_terminal(&ledger, before);
}

struct DropProbe {
    ordinal: usize,
    seen: Rc<RefCell<Vec<usize>>>,
    ledger: Ledger,
    expected: QuotaSnapshot,
    panic: bool,
}

impl Drop for DropProbe {
    fn drop(&mut self) {
        assert_eq!(self.ledger.snapshot(), self.expected);
        self.seen.borrow_mut().push(self.ordinal);
        assert!(!self.panic, "injected payload destructor failure");
    }
}

fn retiring_probes(
    panic_in_payload: bool,
) -> (
    Ledger,
    Retiring<DropProbe, DropProbe>,
    Rc<RefCell<Vec<usize>>>,
) {
    let bytes = Bytes {
        host: 17,
        device: 0,
    };
    let ledger = Ledger::new(WorkerAllowance {
        host: bytes.host,
        device: 0,
    });
    let original = ledger.reserve(Category::Report, bytes).unwrap();
    let expected = ledger.snapshot();
    let seen = Rc::new(RefCell::new(Vec::new()));
    let probe = |ordinal, panic| DropProbe {
        ordinal,
        seen: Rc::clone(&seen),
        ledger: ledger.clone(),
        expected,
        panic,
    };
    let retiring = Retiring {
        payload: Some(probe(0, panic_in_payload)),
        encoding: Some(probe(1, false)),
        original,
    };
    (ledger, retiring, seen)
}

#[test]
fn payload_and_encoding_drop_in_order_while_original_remains_charged() {
    let (ledger, retiring, seen) = retiring_probes(false);
    let before = ledger.snapshot();
    let original = retiring.finish();
    assert_eq!(seen.borrow().as_slice(), &[0, 1]);
    assert_eq!(ledger.snapshot(), before);
    assert!(original.belongs_to(&ledger));
    drop(original);
    assert_terminal(&ledger, before);
}

#[test]
fn payload_unwind_drops_encoding_before_original_quota() {
    let (ledger, retiring, seen) = retiring_probes(true);
    let before = ledger.snapshot();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| retiring.finish()));
    assert!(result.is_err());
    assert_eq!(seen.borrow().as_slice(), &[0, 1]);
    assert_terminal(&ledger, before);
}
