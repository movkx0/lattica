use super::super::{expression::Base, tests::lookup_encoding as encoding};
use super::*;
use crate::block_v2::machine::{MachineAir, ProgramBuilder};
use p3_air::{AirBuilder, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_lookup::{Count, InteractionBuilder, Lookups};
use std::sync::atomic::{AtomicUsize, Ordering};

#[test]
fn machine_layout_matches_upstream_order_degree_and_topology() {
    for publics in [0, 1, 33, 64] {
        for height in [8, 64, 2048] {
            let air = MachineAir::new(
                ProgramBuilder::new(publics)
                    .unwrap()
                    .finish(Some(height))
                    .unwrap(),
            );
            let selected = prepare(&air, Limits::default()).unwrap();
            let unpacked = Lookups::from_air::<Challenge, _>(&air);
            let gadget = LogUpGadget::new();
            let chunks =
                p3_batch_stark::symbolic::get_log_num_quotient_chunks::<Val, Challenge, _, _>(
                    &air,
                    AirLayout::from_air::<Val>(&air),
                    &unpacked,
                    1,
                    &gadget,
                );
            assert_eq!(selected.log_chunks, chunks);
            let reference = unpacked.pack_same_bus(&gadget, 1 << chunks);
            assert_eq!(encoding(&selected.lookups), encoding(&reference));
        }
    }
}

#[derive(Default)]
struct Instrumented {
    layout_calls: AtomicUsize,
    eval_calls: AtomicUsize,
    panic: bool,
}
impl BaseAir<Val> for Instrumented {
    fn width(&self) -> usize {
        self.layout_calls.fetch_add(1, Ordering::SeqCst);
        1
    }
}
impl Air<Builder> for Instrumented {
    fn eval(&self, b: &mut Builder) {
        self.eval_calls.fetch_add(1, Ordering::SeqCst);
        assert!(!self.panic, "instrumented AIR panic");
        let x: Base = b.main().current_slice()[0].into();
        b.assert_zero(x.clone().square());
        b.push_interaction("verifier-test", [x], Count::bounded(Base::ONE, 1));
    }
}

#[test]
fn every_graph_quota_rejects_and_allows_subsequent_preparation() {
    let air = Instrumented::default();
    for (limits, expected) in [
        (
            Limits {
                recording: 0,
                ..Limits::default()
            },
            "symbolic recording allowance",
        ),
        (
            Limits {
                normalization: 0,
                ..Limits::default()
            },
            "symbolic normalization allowance",
        ),
        (
            Limits {
                packing: 0,
                ..Limits::default()
            },
            "symbolic lookup packing allowance",
        ),
        (
            Limits {
                retained: 0,
                ..Limits::default()
            },
            "symbolic lookup retained allowance",
        ),
    ] {
        assert!(
            matches!(prepare(&air, limits), Err(CompileError::Shape(message)) if message == expected)
        );
        assert_eq!(prepare(&air, Limits::default()).unwrap().lookups.len(), 1);
    }
}

#[test]
fn invalid_limits_reject_before_layout_or_eval_callbacks() {
    let air = Instrumented::default();
    for excessive in [(64 << 20) + 1, usize::MAX] {
        for limits in [
            Limits {
                recording: excessive,
                ..Limits::default()
            },
            Limits {
                normalization: excessive,
                ..Limits::default()
            },
            Limits {
                packing: excessive,
                ..Limits::default()
            },
            Limits {
                retained: excessive,
                ..Limits::default()
            },
        ] {
            assert!(matches!(
                prepare(&air, limits),
                Err(CompileError::Shape(
                    "verifier metadata allowance exceeds ceiling"
                ))
            ));
        }
    }
    assert_eq!(air.layout_calls.load(Ordering::SeqCst), 0);
    assert_eq!(air.eval_calls.load(Ordering::SeqCst), 0);
}

#[test]
fn recording_rejects_windows_before_eval() {
    let air = Instrumented::default();
    assert!(prepare(
        &air,
        Limits {
            recording: 0,
            ..Limits::default()
        }
    )
    .is_err());
    assert!(air.layout_calls.load(Ordering::SeqCst) > 0);
    assert_eq!(air.eval_calls.load(Ordering::SeqCst), 0);
}

#[test]
fn callback_unwind_releases_the_recording_scope() {
    let air = Instrumented {
        panic: true,
        ..Instrumented::default()
    };
    assert!(std::panic::catch_unwind(|| prepare(&air, Limits::default())).is_err());
    assert_eq!(air.eval_calls.load(Ordering::SeqCst), 1);
    assert!(prepare(&Instrumented::default(), Limits::default()).is_ok());
}

struct DegreeAir {
    squarings: usize,
    hint: Option<usize>,
}
impl BaseAir<Val> for DegreeAir {
    fn width(&self) -> usize {
        1
    }
    fn max_constraint_degree(&self) -> Option<usize> {
        self.hint
    }
}
impl Air<Builder> for DegreeAir {
    fn eval(&self, b: &mut Builder) {
        let mut x: Base = b.main().current_slice()[0].into();
        for _ in 0..self.squarings {
            x = x.square();
        }
        b.assert_zero(x);
    }
}
#[test]
fn underestimated_degree_hint_is_rejected() {
    assert!(matches!(
        prepare(
            &DegreeAir {
                squarings: 1,
                hint: Some(1)
            },
            Limits::default()
        ),
        Err(CompileError::Shape("symbolic degree hint"))
    ));
    assert_eq!(
        prepare(
            &DegreeAir {
                squarings: 1,
                hint: Some(2)
            },
            Limits::default()
        )
        .unwrap()
        .log_chunks,
        1
    );
}
#[test]
fn excessive_quotient_degree_is_rejected() {
    assert!(matches!(
        prepare(
            &DegreeAir {
                squarings: crate::block_v2::profile::LOG_BLOWUP + 1,
                hint: None
            },
            Limits::default()
        ),
        Err(CompileError::Shape("symbolic quotient degree"))
    ));
}
