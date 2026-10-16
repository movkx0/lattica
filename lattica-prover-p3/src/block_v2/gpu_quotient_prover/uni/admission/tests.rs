use super::*;
use crate::block_v2::{leaf, profile, typed_leaf};
use p3_air::{AirBuilder, BaseAir, WindowAccess};
use std::sync::atomic::{AtomicUsize, Ordering};

fn compare<A: Air<symbolic::Builder> + StaticPeriodicSource, E: PcsField>(air: &A, rows: usize) {
    let prepared = Prepared::new(air, rows, E::DEVICE_EXTENSION, 1 << 30).unwrap();
    let operations = prepared.operation_host_allowance().unwrap();
    assert_eq!(
        operations + prepared.required_host_bytes().unwrap(),
        1 << 30
    );
    assert!(prepared.check_operation_host_allowance(operations).is_ok());
    assert!(prepared.check_operation_host_allowance(1 << 30).is_err());
    let shape = prepared.shape;
    let layout = prepared.recorded.layout();
    let constraints = prepared.recorded.normalize(Constants::cpu()).unwrap();
    let reference = symbolic::uni(air, Constants::cpu()).unwrap();
    assert_eq!(constraints.max_degree(), reference.max_degree());
    assert_eq!(constraints.order.base_indices, reference.order.base_indices);
    let program =
        Program::from_periodic_constraints(layout, &constraints.into_base_only::<E>().unwrap())
            .unwrap();
    let reference =
        Program::from_periodic_constraints(layout, &reference.into_base_only::<E>().unwrap())
            .unwrap();
    assert_eq!(program.instructions, reference.instructions);
    assert_eq!(program.registers, reference.registers);
    shape.check(&program).unwrap();
    // The conservative bound leaves the preceding 1 MiB tile supported.
    assert!((shape.row_words + shape.registers * E::DIMENSION) * 8 <= 1 << 20);
    eprintln!("wallet_recorded_program nodes_bound={} instructions_bound={} actual_instructions={} registers={} constraints={} degree={}",
        shape.registers, shape.instruction_words / 5, program.instruction_count(), program.registers, program.constraints, E::DIMENSION);
}

#[test]
fn recorded_wallet_bounds_cover_both_fields_and_every_maintained_air() {
    use crate::{htlc_air as h, joinsplit_air as js};
    compare::<_, crate::config::Challenge>(&js::JoinSplitAir, js::HEIGHT);
    compare::<_, crate::config::Challenge>(&h::HtlcAir, h::HEIGHT);
    compare::<_, profile::Challenge>(&leaf::ContextJoinSplitAir, js::HEIGHT);
    compare::<_, profile::Challenge>(&typed_leaf::ContextAir(h::HtlcAir), h::HEIGHT);
    compare::<_, profile::Challenge>(&typed_leaf::ContextAir(js::JoinSplitAir), js::HEIGHT);
    for count in [0usize, 1, 3, crate::batch_common::MAX_BATCH_TILES] {
        let tiles = count.max(1).next_power_of_two();
        compare::<_, crate::config::Challenge>(
            &crate::batch_joinsplit_air::JoinSplitBatchAir,
            tiles * crate::batch_joinsplit_air::device_batch_geometry().height,
        );
        compare::<_, crate::config::Challenge>(
            &crate::batch_htlc_air::HtlcBatchAir,
            tiles * crate::batch_htlc_air::device_batch_geometry().height,
        );
    }
}

struct FoldingAir(AtomicUsize);
impl StaticPeriodicSource for FoldingAir {
    fn count(&self) -> usize {
        0
    }
    fn len(&self, _: usize) -> Option<usize> {
        None
    }
    fn fill(
        &self,
        _: usize,
        _: &mut [Val],
    ) -> Result<(), crate::block_v2::machine::verifier::CompileError> {
        panic!("zero-column AIR cannot fill periodic data")
    }
}
impl BaseAir<Val> for FoldingAir {
    fn width(&self) -> usize {
        2
    }
}
impl<AB: AirBuilder<F = Val>> Air<AB> for FoldingAir {
    fn eval(&self, b: &mut AB) {
        self.0.fetch_add(1, Ordering::SeqCst);
        let m = b.main();
        let x: AB::Expr = m.current_slice()[0].into();
        let y: AB::Expr = m.current_slice()[1].into();
        let shared = (x.clone() + y.clone()).square();
        // Exercise constant folding, zero/one elimination, zero subtraction,
        // double negation and shared nodes whose normalized identities merge.
        let zero = AB::Expr::from(Val::NEG_ONE) + AB::Expr::ONE;
        let one = AB::Expr::from_u64(11) - AB::Expr::from_u64(10);
        for c in [
            Val::ZERO,
            Val::ONE,
            Val::TWO,
            Val::NEG_ONE,
            Val::from_u64(7),
        ] {
            let c = AB::Expr::from(c);
            for value in [
                c.clone() + zero.clone(),
                c.clone() - one.clone(),
                c.clone() * one.clone(),
                -c,
            ] {
                b.assert_zero(shared.clone() * value.clone() + zero.clone());
                b.assert_zero(value - shared.clone());
            }
        }
        b.assert_zero(-(-shared.clone()));
        b.assert_zero(shared.clone() * zero.clone());
        b.assert_zero(shared + x + y);
    }
}

#[test]
fn retained_recording_normalizes_once_with_reported_backend_and_preserves_degree() {
    use crate::proving::{Capabilities, Profile, Request, Run};
    let air = FoldingAir(AtomicUsize::new(0));
    let run = Run::new(
        "recorded_metadata",
        Request::compatible(),
        Capabilities::cpu(Profile::BlockV2Cubic, true, false),
    )
    .unwrap();
    let prepared =
        Prepared::new(&air, 256, Extension::Cubic, symbolic::HOST_BYTES as usize).unwrap();
    assert!(run.finish(false).unwrap().observations.is_empty());
    let bound = prepared.shape;
    let layout = prepared.recorded.layout();
    let run = Run::new(
        "explicit_normalization",
        Request::compatible(),
        Capabilities::cpu(Profile::BlockV2Cubic, true, false),
    )
    .unwrap();
    let normalized = prepared
        .recorded
        .normalize(Constants::cpu_reported(&run))
        .unwrap();
    assert_eq!(
        air.0.load(Ordering::SeqCst),
        1,
        "normalization must reuse the admitted recording"
    );
    assert!(!run.finish(false).unwrap().observations.is_empty());
    assert_eq!(normalized.max_degree(), 2);
    let program = Program::from_periodic_constraints(layout, &normalized).unwrap();
    bound.check(&program).unwrap();
    let mut short = bound;
    short.registers = program.registers - 1;
    assert!(short.check(&program).is_err());
    short = bound;
    short.instruction_words = program.instructions.len() - 1;
    assert!(short.check(&program).is_err());
    compare::<_, crate::config::Challenge>(&air, 256);
}

#[test]
fn malformed_geometry_and_host_allowance_reject_before_air_evaluation() {
    let air = FoldingAir(AtomicUsize::new(0));
    assert!(Prepared::new(
        &air,
        256,
        Extension::Cubic,
        symbolic::HOST_BYTES as usize - 1
    )
    .is_err());
    assert!(Prepared::new(&air, 3, Extension::Cubic, symbolic::HOST_BYTES as usize).is_err());
    assert!(Prepared::new(&air, 256, Extension::Base, symbolic::HOST_BYTES as usize).is_err());
    assert_eq!(air.0.load(Ordering::SeqCst), 0);
}
