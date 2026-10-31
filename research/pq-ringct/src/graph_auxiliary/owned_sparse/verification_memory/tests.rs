use super::*;
use crate::execution::retained_resources::WorkerAllowance;
use lattica_prover_p3::block_v2::native_gpu::sparse_recording::{self, SparseRecorder};
use p3_air::symbolic::AirLayout;

fn recorded_replay(air: &SourceAir) -> SparseSymbolicReplay {
    let source = SparsePreparationPlan::new(air.kind()).unwrap();
    let ledger = ResourceLedger::new(WorkerAllowance { host: 32 << 30, device: 0 });
    let symbolic = source.host().prepared_partition_bytes().unwrap();
    let other = source.host().required_host_bytes() - symbolic + sparse_recording::additional_host_bytes();
    let mut requirements = Requirements::single(Category::SymbolicCompiler,
        Bytes { host: symbolic as u64, device: 0 });
    requirements.add(Category::PhaseScratch, Bytes { host: other as u64, device: 0 }).unwrap();
    let mut original = ledger.admit_phase(requirements).unwrap();
    let mut recorder = SparseRecorder::begin(source, &mut original, &ledger).unwrap();
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
fn sparse_replay_census_preserves_default_symbolic_geometry_and_budget() {
    for kind in [SparseKind::AlphaPrime39, SparseKind::ChallengeX44] {
        {
            let air = SourceAir::new(kind);
            assert_eq!(air.max_constraint_degree(), None);
            let replay = recorded_replay(&air);
            // The owned profile uses core's stream allocator. The separate
            // process-global observation feature cannot coexist with it.
            // This test checks inference geometry and admission arithmetic;
            // it deliberately makes no measured-allocation claim.
            let log_chunks = p3_uni_stark::get_log_num_quotient_chunks::<Val, _>(
                &air, AirLayout::from_air::<Val>(&air), 1);
            assert_eq!(1 << (log_chunks + 1), QUOTIENT);
            let plan = Plan::for_recorded(&air, replay).unwrap();
            let bounds = plan.bounds();
            assert_eq!(bounds.symbolic_replay_bytes, replay.required_host_bytes());
            assert!(bounds.cumulative_requested_bytes > bounds.symbolic_replay_bytes);
            assert!(bounds.cumulative_requested_bytes + bounds.entry_frame_bytes <= COMPONENT_BYTES);
        }
    }
}

#[test]
fn sparse_verifier_plan_rejects_other_family_recording_and_full_component_replay() {
    let statement = SourceAir::new(SparseKind::AlphaPrime39);
    let private = SourceAir::new(SparseKind::ChallengeX44);
    let replay = recorded_replay(&statement);
    assert!(Plan::for_recorded(&private, replay).is_err());
    let shape = Shape::new(&statement).unwrap();
    let config = CpuVerificationConfigPlan::new().unwrap();
    assert_eq!(Bounds::new(shape, config.requested_bytes(), COMPONENT_BYTES), Err(BUDGET));
    assert_eq!(Plan::component_requirement(), Requirements::single(Category::IndependentVerifier,
        Bytes { host: 64 << 20, device: 0 }));
}

#[test]
fn sparse_mixed_periods_match_the_unchanged_reference_air_exactly() {
    for kind in [SparseKind::AlphaPrime39, SparseKind::ChallengeX44] {
        let air = SourceAir::new(kind);
        let reference = air.periodic_columns();
        let geometry = SparsePreparationPlan::new(kind).unwrap().geometry();
        assert_eq!(reference.len(), 82);
        assert_eq!(reference.iter().map(Vec::len).sum::<usize>(), 6720);
        assert_eq!(reference.iter().map(Vec::len).collect::<Vec<_>>(),
            geometry.periodic_lengths().collect::<Vec<_>>());
        for (column, values) in reference.iter().enumerate() {
            for (row, value) in values.iter().enumerate() {
                assert_eq!(geometry.periodic_value(column, row).unwrap(), *value,
                    "source periodic column {column} row {row}");
            }
            assert!(geometry.periodic_value(column, values.len()).is_err());
        }
    }
}
