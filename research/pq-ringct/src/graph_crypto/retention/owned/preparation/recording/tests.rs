use super::*;
use crate::{
    execution::retained_resources::WorkerAllowance,
    graph_crypto::{Policy, ShakeRequestPlan},
};
use lattica_prover_p3::config::Val;
use p3_air::symbolic::{get_symbolic_constraints, AirLayout};
use p3_field::PrimeCharacteristicRing;

fn ledger() -> Ledger {
    Ledger::new(WorkerAllowance {
        host: 32 << 30,
        device: 0,
    })
}

fn owned(ledger: &Ledger, input: &[u8], output_len: usize) -> ReservedShakeRequest {
    let plan = ShakeRequestPlan::new([71; 32], 4, 0, input, output_len, Policy::default()).unwrap();
    let token = ledger.admit_phase(plan.requirements()).unwrap();
    plan.construct(token, ledger).unwrap()
}

fn pending<'request>(
    owner: &'request ReservedShakeRequest,
    index: usize,
    ledger: &Ledger,
) -> PendingNativePreparation<'request> {
    let plan = NativePreparationPlan::new(owner, index).unwrap();
    let token = ledger.admit_phase(plan.requirements()).unwrap();
    plan.claim_for(owner, index, token, ledger).unwrap()
}

#[test]
fn actual_single_batch_padding_and_squeeze_sources_record_against_reference_metadata() {
    let mut saw_single = false;
    let mut saw_absorb_batch = false;
    let mut saw_squeeze_batch = false;
    for (input_len, output_len) in [(0, 0), (135, 272), (8 * 136 + 7, 10 * 136 + 1)] {
        let ledger = ledger();
        let input = vec![19; input_len];
        let owner = owned(&ledger, &input, output_len);
        let original = ledger.snapshot().current;
        for index in 0..owner.request().segments().len() {
            let mut preparation = pending(&owner, index, &ledger);
            let air = preparation.plan.air;
            match air {
                ShakeSegmentAir::Single(_) => saw_single = true,
                ShakeSegmentAir::Batch(source) => {
                    if source.first_permutation() < input_len / 136 {
                        saw_absorb_batch = true;
                    } else {
                        saw_squeeze_batch = true;
                    }
                }
            }
            // The test's independent native symbolic graph/periodic table has
            // a second complete preparation claim. Production uses only the
            // closed recorder and never builds these reference tables.
            let reference_claim = ledger.admit_phase(preparation.plan.requirements()).unwrap();
            let reference =
                get_symbolic_constraints::<Val, _>(air, AirLayout::from_air::<Val>(air));
            assert!(!reference.is_empty());
            assert_eq!(
                reference.iter().map(|expr| expr.degree_multiple()).max(),
                Some(7)
            );
            let expected_columns = air.periodic_columns();
            assert_eq!(expected_columns.len(), 42);
            for (column, expected) in expected_columns.iter().enumerate() {
                let mut actual = [Val::ZERO; 128];
                match air {
                    ShakeSegmentAir::Single(source) => source.fill_column(column, &mut actual),
                    ShakeSegmentAir::Batch(source) => source.fill_column(column, &mut actual),
                }
                .unwrap();
                assert_eq!(actual.as_slice(), expected);
            }
            let census = preparation.census();
            let reserved = ledger.snapshot().current;
            let recorded = preparation.record(&ledger).unwrap();
            assert_eq!(recorded.census(), census);
            assert_eq!(recorded.constraints(), reference.len());
            assert!(recorded.node_bound() >= recorded.constraints());
            assert!(recorded.reservation().belongs_to(&ledger));
            assert_eq!(recorded.ledger().snapshot().current, reserved);
            drop(recorded);
            drop(expected_columns);
            drop(reference);
            drop(reference_claim);
            drop(preparation);
            assert_eq!(ledger.snapshot().current, original);
        }
        drop(owner);
        assert_eq!(ledger.snapshot().current, Bytes::ZERO);
    }
    assert!(saw_single && saw_absorb_batch && saw_squeeze_batch);
}

#[test]
fn closed_recording_refuses_foreign_ledger_and_preserves_original_ownership() {
    let ledger = ledger();
    let unrelated = self::ledger();
    let owner = owned(&ledger, &[4; 136], 137);
    let mut preparation = pending(&owner, 0, &ledger);
    let reserved = ledger.snapshot().current;
    assert!(matches!(
        preparation.record(&unrelated),
        Err(Error::WrongReservation)
    ));
    assert_eq!(ledger.snapshot().current, reserved);
    let recorded = preparation.record(&ledger).unwrap();
    assert!(!recorded.reservation().belongs_to(&unrelated));
    let moved = Some(recorded);
    assert_eq!(ledger.snapshot().current, reserved);
    drop(moved);
    // Sequential recording is allowed only after the prior prepared owner is
    // destroyed. The exclusive API prevents concurrent reuse at compile time.
    drop(preparation.record(&ledger).unwrap());
    assert_eq!(ledger.snapshot().current, reserved);
    drop(preparation);
    drop(owner);
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
    assert_eq!(unrelated.snapshot().current, Bytes::ZERO);
}

#[test]
fn different_input_owners_share_no_recording_or_original_reservation() {
    let ledger = ledger();
    let first_owner = owned(&ledger, &[1; 137], 137);
    let second_owner = owned(&ledger, &[2; 137], 137);
    let mut first = pending(&first_owner, 0, &ledger);
    let mut second = pending(&second_owner, 0, &ledger);
    assert_ne!(first.input(), second.input());
    let reserved = ledger.snapshot().current;
    let a = first.record(&ledger).unwrap();
    let b = second.record(&ledger).unwrap();
    assert_eq!(a.census(), b.census());
    assert_eq!(a.constraints(), b.constraints());
    assert!(!core::ptr::eq(a.reservation(), b.reservation()));
    assert_eq!(ledger.snapshot().current, reserved);
    drop(a);
    drop(b);
    drop(first);
    drop(second);
    drop(first_owner);
    drop(second_owner);
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
}
