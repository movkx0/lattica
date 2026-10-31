use super::*;
use crate::{
    block_v2::{
        machine::{compiler_constants::Constants, fingerprint},
        native_gpu::AesTraceSpec,
    },
    ringct_research_quota::{Requirements, WorkerAllowance},
};
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};

fn census() -> AesPreparationPlan {
    AesPreparationPlan::new(AesTraceSpec {
        domain: 7,
        start_counter: 9,
        output_len: 1,
        first_block: 0,
        blocks: 1,
    }).unwrap()
}

fn ledger() -> Ledger {
    Ledger::new(WorkerAllowance {
        host: 32 << 30,
        device: 0,
    })
}

fn requirements(census: AesPreparationPlan) -> Requirements {
    let symbolic = census.host().prepared_partition_bytes().unwrap();
    let other = census.host().required_host_bytes() - symbolic + additional_host_bytes();
    let mut request = Requirements::single(
        Category::SymbolicCompiler,
        Bytes {
            host: symbolic as u64,
            device: 0,
        },
    );
    request
        .add(
            Category::PhaseScratch,
            Bytes {
                host: other as u64,
                device: 0,
            },
        )
        .unwrap();
    request
}

// Test-only fixed-layout source exercises the bridge's normalization against
// the upstream symbolic builder. Actual AES eval is covered in research tests.
struct Fixture;
impl BaseAir<Val> for Fixture {
    fn width(&self) -> usize {
        census().geometry().width()
    }
    fn num_public_values(&self) -> usize {
        12
    }
    fn num_periodic_columns(&self) -> usize {
        COLUMNS
    }
}
impl<AB: AirBuilder<F = Val>> Air<AB> for Fixture {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let x: AB::Expr = main.current_slice()[0].into();
        let y: AB::Expr = main.next_slice()[1].into();
        let public: AB::Expr = builder.public_values()[0].into();
        let periodic: AB::Expr = builder.periodic_values()[0].into();
        let shared = (x.clone() + y.clone()).square();
        builder.assert_zero(shared.clone() - public);
        builder.assert_zero(shared * periodic);
        builder.when_transition().assert_zero(y - x);
    }
}

fn filled(recorder: &mut AesRecorder<'_>) {
    Fixture.eval(recorder.builder_mut());
    for index in 0..COLUMNS {
        for (row, value) in recorder
            .periodic_column_mut(index)
            .unwrap()
            .iter_mut()
            .enumerate()
        {
            *value = Val::from_bool((row + index) % 2 == 0);
        }
    }
}

#[test]
fn retained_recording_matches_upstream_normalization_and_exact_periodic_columns() {
    let ledger = ledger();
    let mut token = ledger.admit_phase(requirements(census())).unwrap();
    let reference_token = ledger.admit_phase(requirements(census())).unwrap();
    let before = ledger.snapshot().current;
    let mut recorder = AesRecorder::begin(census(), &mut token, &ledger).unwrap();
    filled(&mut recorder);
    let result = recorder.finish().unwrap();
    assert_eq!(result.constraints(), 3);
    assert!(result.node_bound() >= result.constraints());
    for (index, column) in result.columns.iter().enumerate() {
        assert_eq!(column.len(), PERIOD);
        for (row, value) in column.iter().enumerate() {
            assert_eq!(*value, Val::from_bool((row + index) % 2 == 0));
        }
    }
    let selected = result.recorded.normalize(Constants::cpu()).unwrap();
    let reference = p3_air::symbolic::get_symbolic_constraints::<Val, _>(
        &Fixture,
        AirLayout::from_air::<Val>(&Fixture),
    );
    assert_eq!(selected.base.len(), reference.len());
    assert_eq!(
        fingerprint::encode(&selected.base, &selected.extension, &selected.order),
        fingerprint::encode(&reference, &[], &selected.order),
    );
    assert_eq!(ledger.snapshot().current, before);
    drop(reference);
    drop(selected);
    drop(result.columns);
    drop(reference_token);
    drop(token);
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
}

#[test]
fn core_continuation_keeps_the_same_exclusive_original_claim() {
    let ledger = ledger();
    let mut token = ledger.admit_phase(requirements(census())).unwrap();
    let identity = &token as *const Reservation;
    let mut recorder = AesRecorder::begin(census(), &mut token, &ledger).unwrap();
    filled(&mut recorder);
    let recorded = recorder.finish().unwrap();
    let before = ledger.snapshot().current;
    let (prepared, original) = recorded.into_prepared(1 << 20).unwrap();
    assert_eq!(original as *const Reservation, identity);
    assert!(original.belongs_to(&ledger));
    assert_eq!(prepared.operation_host_allowance().unwrap(), 1 << 20);
    assert_eq!(ledger.snapshot().current, before);
    drop(prepared);
    assert!(original.belongs_to(&ledger));
    drop(token);
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
}

#[test]
fn original_ledger_and_exact_preparation_partition_precede_recording() {
    let ledger = ledger();
    let unrelated = self::ledger();
    let mut token = ledger.admit_phase(requirements(census())).unwrap();
    assert!(matches!(
        AesRecorder::begin(census(), &mut token, &unrelated),
        Err(Error::Authority)
    ));
    let exact = requirements(census());
    for (symbolic, scratch, extra) in [
        (
            exact.get(Category::SymbolicCompiler).host - 1,
            exact.get(Category::PhaseScratch).host,
            false,
        ),
        (
            exact.get(Category::SymbolicCompiler).host,
            exact.get(Category::PhaseScratch).host - 1,
            false,
        ),
        (
            exact.get(Category::SymbolicCompiler).host,
            exact.get(Category::PhaseScratch).host,
            true,
        ),
    ] {
        let mut request = Requirements::single(
            Category::SymbolicCompiler,
            Bytes {
                host: symbolic,
                device: 0,
            },
        );
        request
            .add(
                Category::PhaseScratch,
                Bytes {
                    host: scratch,
                    device: 0,
                },
            )
            .unwrap();
        if extra {
            request
                .add(Category::Report, Bytes { host: 1, device: 0 })
                .unwrap();
        }
        let mut wrong = ledger.admit_phase(request).unwrap();
        assert!(matches!(
            AesRecorder::begin(census(), &mut wrong, &ledger),
            Err(Error::Authority)
        ));
    }
    let mut recorder = AesRecorder::begin(census(), &mut token, &ledger).unwrap();
    filled(&mut recorder);
    drop(recorder.finish().unwrap());
    drop(token);
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
    assert_eq!(unrelated.snapshot().current, Bytes::ZERO);
}

#[test]
fn missing_repeated_out_of_range_and_nonbinary_columns_are_refused() {
    let ledger = ledger();
    let mut token = ledger.admit_phase(requirements(census())).unwrap();
    let mut recorder = AesRecorder::begin(census(), &mut token, &ledger).unwrap();
    Fixture.eval(recorder.builder_mut());
    assert!(matches!(recorder.finish(), Err(Error::Shape)));
    for index in [0, COLUMNS] {
        let mut recorder = AesRecorder::begin(census(), &mut token, &ledger).unwrap();
        filled(&mut recorder);
        assert!(matches!(
            recorder.periodic_column_mut(index),
            Err(Error::Shape)
        ));
        assert!(matches!(recorder.finish(), Err(Error::Recording)));
    }
    let mut recorder = AesRecorder::begin(census(), &mut token, &ledger).unwrap();
    Fixture.eval(recorder.builder_mut());
    for index in 0..COLUMNS {
        recorder.periodic_column_mut(index).unwrap()[0] = Val::TWO;
    }
    assert!(matches!(recorder.finish(), Err(Error::Shape)));
    // No emitted base constraint is not a usable recording.
    let mut recorder = AesRecorder::begin(census(), &mut token, &ledger).unwrap();
    for index in 0..COLUMNS {
        recorder.periodic_column_mut(index).unwrap();
    }
    assert!(matches!(recorder.finish(), Err(Error::Recording)));
    drop(token);
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
}

#[test]
fn nested_recording_and_unwinding_retire_tls_before_the_next_attempt() {
    let ledger = ledger();
    let mut first = ledger.admit_phase(requirements(census())).unwrap();
    let mut second = ledger.admit_phase(requirements(census())).unwrap();
    let mut recorder = AesRecorder::begin(census(), &mut first, &ledger).unwrap();
    filled(&mut recorder);
    assert!(matches!(
        AesRecorder::begin(census(), &mut second, &ledger),
        Err(Error::Recording)
    ));
    assert!(matches!(recorder.finish(), Err(Error::Recording)));
    let before = ledger.snapshot().current;
    let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut recorder = AesRecorder::begin(census(), &mut first, &ledger).unwrap();
        filled(&mut recorder);
        panic!("fixed recorder cleanup fixture");
    }));
    assert!(unwind.is_err());
    assert_eq!(ledger.snapshot().current, before);
    let mut recorder = AesRecorder::begin(census(), &mut first, &ledger).unwrap();
    filled(&mut recorder);
    drop(recorder.finish().unwrap());
    drop(first);
    drop(second);
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
}
