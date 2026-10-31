use super::*;
use crate::execution::retained_resources::WorkerAllowance;
use lattica_prover_p3::block_v2::native_gpu::{
    affine_recording::{self, AffineRecorder},
    affine_preparation::{AffineGeometry, Q, QHAT},
};
use p3_air::symbolic::AirLayout;

fn recorded_replay(air: &SourceAir) -> AffineSymbolicReplay {
    let source = AffinePreparationPlan::new(air.kind()).unwrap();
    let ledger = ResourceLedger::new(WorkerAllowance { host: 32 << 30, device: 0 });
    let symbolic = source.host().prepared_partition_bytes().unwrap();
    let other = source.host().required_host_bytes() - symbolic + affine_recording::additional_host_bytes();
    let mut requirements = Requirements::single(Category::SymbolicCompiler, Bytes { host: symbolic as u64, device: 0 });
    requirements.add(Category::PhaseScratch, Bytes { host: other as u64, device: 0 }).unwrap();
    let mut original = ledger.admit_phase(requirements).unwrap();
    let mut recorder = AffineRecorder::begin(source, &mut original, &ledger).unwrap();
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
fn affine_owned_periodic_metadata_matches_unchanged_air_across_profiles() {
    for modulus in [Q, QHAT] {
        for count in [1, 8, 64] {
            for operation in [AffineOperation::Add, AffineOperation::Subtract,
                AffineOperation::SignedToCanonical { bound: 565 }]
            {
                let descriptor = AffineDescriptor::new(operation, modulus, count).unwrap();
                let geometry = AffineGeometry::for_kind(descriptor);
                let air = SourceAir::new(descriptor);
                let actual = air.periodic_columns();
                assert_eq!((air.height(), air.width(), air.num_public_values(), air.num_periodic_columns()),
                    descriptor.geometry_tuple());
                assert_eq!(actual.len(), geometry.periodic_columns());
                for (index, column) in actual.iter().enumerate() {
                    assert_eq!(column.len(), geometry.period());
                    for (row, value) in column.iter().enumerate() {
                        assert_eq!(*value, geometry.periodic_value(index, row).unwrap());
                    }
                }
            }
        }
    }
}

#[test]
fn affine_owned_verifier_preserves_default_degree_and_original_budget() {
    for (operation, modulus, count) in [
        (AffineOperation::Add, Q, 1),
        (AffineOperation::Subtract, QHAT, 64),
        (AffineOperation::SignedToCanonical { bound: 565 }, QHAT, 64),
    ] {
        let air = SourceAir::new(AffineDescriptor::new(operation, modulus, count).unwrap());
        assert_eq!(air.max_constraint_degree(), None);
        let replay = recorded_replay(&air);
        let log_chunks = p3_uni_stark::get_log_num_quotient_chunks::<Val, _>(&air,
            AirLayout::from_air::<Val>(&air), 1);
        assert_eq!(1 << (log_chunks + 1), QUOTIENT);
        let plan = Plan::for_recorded(&air, replay).unwrap();
        let bounds = plan.bounds();
        assert_eq!(bounds.symbolic_replay_bytes, replay.required_host_bytes());
        assert!(bounds.cumulative_requested_bytes >= bounds.symbolic_replay_bytes);
        assert!(bounds.cumulative_requested_bytes + bounds.entry_frame_bytes <= COMPONENT_BYTES);
    }
}

#[test]
fn affine_owned_verifier_binds_operation_modulus_count_and_symbolic_room() {
    let a = SourceAir::new(AffineDescriptor::new(AffineOperation::Add, Q, 1).unwrap());
    let b = SourceAir::new(AffineDescriptor::new(AffineOperation::Subtract, Q, 1).unwrap());
    let c = SourceAir::new(AffineDescriptor::new(AffineOperation::Add, Q, 2).unwrap());
    let d = SourceAir::new(AffineDescriptor::new(AffineOperation::Add, QHAT, 1).unwrap());
    assert_ne!(Shape::new(&a).unwrap(), Shape::new(&b).unwrap());
    assert_ne!(Shape::new(&a).unwrap(), Shape::new(&c).unwrap());
    assert_ne!(Shape::new(&a).unwrap(), Shape::new(&d).unwrap());
    let config = CpuVerificationConfigPlan::new().unwrap();
    assert_eq!(Bounds::new(Shape::new(&a).unwrap(), config.requested_bytes(), COMPONENT_BYTES), Err(BUDGET));
    assert_eq!(Plan::component_requirement(), Requirements::single(Category::IndependentVerifier,
        Bytes { host: 64 << 20, device: 0 }));
}
