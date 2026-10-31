use super::*;
use crate::execution::retained_resources::WorkerAllowance;
use lattica_prover_p3::block_v2::native_gpu::{
    g_bound_recording::{self, GBoundRecorder},
};

fn recorded_replay(air: &SourceAir) -> GBoundSymbolicReplay {
    let source = GBoundPreparationPlan::new(air.kind()).unwrap();
    let ledger = ResourceLedger::new(WorkerAllowance { host: 32 << 30, device: 0 });
    let symbolic = source.host().prepared_partition_bytes().unwrap();
    let other = source.host().required_host_bytes() - symbolic + g_bound_recording::additional_host_bytes();
    let mut requirements = Requirements::single(Category::SymbolicCompiler, Bytes { host: symbolic as u64, device: 0 });
    requirements.add(Category::PhaseScratch, Bytes { host: other as u64, device: 0 }).unwrap();
    let mut original = ledger.admit_phase(requirements).unwrap();
    let mut recorder = GBoundRecorder::begin(source, &mut original, &ledger).unwrap();
    air.eval(recorder.builder_mut());
    let prepared = recorder.finish().unwrap();
    let replay = prepared.symbolic_replay_census();
    assert!(replay.required_host_bytes() > 0);
    drop(prepared);
    drop(original);
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
    replay
}

#[test]
fn g_bound_owned_verifier_preserves_both_default_degrees_and_original_budget() {
    for bound in [6_825_771, 1_137_628] {
        let air = SourceAir::new(GBoundDescriptor::new(bound).unwrap());
        assert_eq!(air.max_constraint_degree(), None);
        let replay = recorded_replay(&air);
        let log_chunks = p3_uni_stark::get_log_num_quotient_chunks::<Val, _>(&air,
            p3_air::symbolic::AirLayout::from_air::<Val>(&air), 1);
        assert_eq!(1 << (log_chunks + 1), QUOTIENT);
        let plan = Plan::for_recorded(&air, replay).unwrap();
        assert_eq!(plan.bounds().symbolic_replay_bytes, replay.required_host_bytes());
        assert!(plan.bounds().cumulative_requested_bytes + plan.bounds().entry_frame_bytes <= COMPONENT_BYTES);
    }
}

#[test]
fn g_bound_owned_verifier_refuses_changed_bound_at_identical_geometry() {
    let a = SourceAir::new(GBoundDescriptor::new(6_825_771).unwrap());
    let b = SourceAir::new(GBoundDescriptor::new(1_137_628).unwrap());
    assert_eq!((a.height(), a.width(), a.num_public_values()), (b.height(), b.width(), b.num_public_values()));
    assert_ne!(Shape::new(&a).unwrap(), Shape::new(&b).unwrap());
    let replay = recorded_replay(&a);
    assert!(Plan::for_recorded(&b, replay).is_err());
}

#[test]
fn g_bound_owned_verifier_charges_original_period128_and_rejects_budget_overflow() {
    let config = CpuVerificationConfigPlan::new().unwrap();
    let air = SourceAir::new(GBoundDescriptor::new(6_825_771).unwrap());
    let shape = Shape::new(&air).unwrap();
    assert_eq!(Bounds::new(shape, config.requested_bytes(), COMPONENT_BYTES), Err(BUDGET));
    let bounds = Bounds::new(shape, config.requested_bytes(), 0).unwrap();
    let mut periodic = Ledger::default();
    periodic.growing::<Vec<Val>>(shape.periodic).unwrap();
    periodic.exact::<Val>(shape.periodic * SCHEDULE_PERIOD).unwrap();
    assert_eq!(bounds.periodic_construction_bytes, periodic.0);
    assert_eq!(bounds.periodic_evaluation_bytes, periodic_evaluation(SCHEDULE_PERIOD).unwrap());
    assert_eq!(Plan::component_requirement(), Requirements::single(Category::IndependentVerifier,
        Bytes { host: 64 << 20, device: 0 }));
}
