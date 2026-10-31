use super::*;
use lattica_prover_p3::block_v2::native_gpu::permutation_preparation::PermutationOperation;
use crate::execution::retained_resources::WorkerAllowance;
use lattica_prover_p3::block_v2::native_gpu::{
    permutation_recording::{self, PermutationRecorder},
};

fn recorded_replay(air: &SourceAir) -> PermutationSymbolicReplay {
    let source = PermutationPreparationPlan::new(air.kind()).unwrap();
    let ledger = ResourceLedger::new(WorkerAllowance { host: 32 << 30, device: 0 });
    let symbolic = source.host().prepared_partition_bytes().unwrap();
    let other = source.host().required_host_bytes() - symbolic + permutation_recording::additional_host_bytes();
    let mut requirements = Requirements::single(Category::SymbolicCompiler, Bytes { host: symbolic as u64, device: 0 });
    requirements.add(Category::PhaseScratch, Bytes { host: other as u64, device: 0 }).unwrap();
    let mut original = ledger.admit_phase(requirements).unwrap();
    let mut recorder = PermutationRecorder::begin(source, &mut original, &ledger).unwrap();
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
fn permutation_owned_verifier_preserves_both_default_predicates_and_budget() {
    for operation in [PermutationOperation::AutomorphismQ,
        PermutationOperation::InverseChallenge] {
        let air = SourceAir::new(PermutationDescriptor::new(operation));
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
fn permutation_owned_verifier_refuses_cross_predicate_recording_identity() {
    let a = SourceAir::new(PermutationDescriptor::from_code(1).unwrap());
    let b = SourceAir::new(PermutationDescriptor::from_code(2).unwrap());
    assert_ne!(Shape::new(&a).unwrap(), Shape::new(&b).unwrap());
    assert!(Plan::for_recorded(&b, recorded_replay(&a)).is_err());
}
#[test]
fn permutation_owned_verifier_charges_full_period256_and_refuses_budget_overflow() {
    let config = CpuVerificationConfigPlan::new().unwrap();
    let air = SourceAir::new(PermutationDescriptor::from_code(1).unwrap());
    let shape = Shape::new(&air).unwrap();
    let bounds = Bounds::new(shape, config.requested_bytes(), 0).unwrap();
    assert!(bounds.periodic_construction_bytes >= 134 * 256 * size_of::<Val>());
    assert_eq!(bounds.periodic_evaluation_bytes, periodic_evaluation(256).unwrap());
    assert_eq!(Bounds::new(shape, config.requested_bytes(), COMPONENT_BYTES), Err(BUDGET));
    assert_eq!(Plan::component_requirement(), Requirements::single(Category::IndependentVerifier,
        Bytes { host: 64 << 20, device: 0 }));
}
