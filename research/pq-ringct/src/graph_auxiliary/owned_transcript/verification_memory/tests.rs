use super::*;
use crate::execution::retained_resources::WorkerAllowance;
use crate::transcript_air::PartKind;
use lattica_prover_p3::block_v2::native_gpu::transcript_recording::{self, TranscriptRecorder};
use p3_air::symbolic::AirLayout;

fn recorded_replay(air: &SourceAir<'_>) -> TranscriptSymbolicReplay {
    let source = TranscriptPreparationPlan::new(air.kind()).unwrap();
    let ledger = ResourceLedger::new(WorkerAllowance { host: 32 << 30, device: 0 });
    let symbolic = source.host().prepared_partition_bytes().unwrap();
    let other = source.host().required_host_bytes() - symbolic + transcript_recording::additional_host_bytes();
    let mut requirements = Requirements::single(Category::SymbolicCompiler,
        Bytes { host: symbolic as u64, device: 0 });
    requirements.add(Category::PhaseScratch, Bytes { host: other as u64, device: 0 }).unwrap();
    let mut original = ledger.admit_phase(requirements).unwrap();
    let mut recorder = TranscriptRecorder::begin(source, &mut original, &ledger).unwrap();
    air.eval(recorder.builder_mut());
    let prepared = recorder.finish().unwrap();
    let replay = prepared.symbolic_replay_census();
    assert!(replay.required_host_bytes() > 0);
    drop(prepared); drop(original);
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
    replay
}

#[test]
fn transcript_default_replay_and_verifier_budget_cover_source_and_maximum_event_layouts() {
    use PartKind::*;
    for kinds in [vec![Bytes32], vec![Bytes32, PolynomialQ, PolynomialQhat],
        (0..256).map(|i| if i % 2 == 0 { Bytes32 } else { PolynomialQhat }).collect()] {
        let original = TranscriptAir::new(kinds).unwrap();
        let layout = crate::graph_auxiliary::owned_transcript::layout_for_air(&original).unwrap();
        let air = SourceAir::new(&original, layout);
        assert_eq!(air.max_constraint_degree(), None);
        let replay = recorded_replay(&air);
        let log_chunks = p3_uni_stark::get_log_num_quotient_chunks::<Val, _>(
            &air, AirLayout::from_air::<Val>(&air), 1);
        assert_eq!(1 << (log_chunks + 1), QUOTIENT);
        let plan = Plan::for_recorded(&air, replay).unwrap();
        let bounds = plan.bounds();
        assert_eq!(bounds.symbolic_replay_bytes, replay.required_host_bytes());
        assert!(bounds.periodic_construction_bytes >= (4 * 128 + 2) * size_of::<Val>());
        assert!(bounds.cumulative_requested_bytes + bounds.entry_frame_bytes <= COMPONENT_BYTES);
    }
}

#[test]
fn transcript_verifier_rejects_reordered_layouts_even_with_the_same_shape() {
    use PartKind::*;
    let left = TranscriptAir::new(vec![Bytes32, PolynomialQ]).unwrap();
    let right = TranscriptAir::new(vec![PolynomialQ, Bytes32]).unwrap();
    let left_layout = crate::graph_auxiliary::owned_transcript::layout_for_air(&left).unwrap();
    let right_layout = crate::graph_auxiliary::owned_transcript::layout_for_air(&right).unwrap();
    assert_eq!((left.height(), left.width()), (right.height(), right.width()));
    assert_ne!(left_layout, right_layout);
    let original = SourceAir::new(&left, left_layout);
    let replay = recorded_replay(&original);
    assert!(Plan::for_recorded(&SourceAir::new(&right, right_layout), replay).is_err());
    assert!(Plan::for_recorded(&SourceAir::new(&left, right_layout), replay).is_err());
    let shape = Shape::new(&original).unwrap();
    let config = CpuVerificationConfigPlan::new().unwrap();
    assert_eq!(Bounds::new(shape, config.requested_bytes(), COMPONENT_BYTES), Err(BUDGET));
}

#[test]
fn transcript_periods_and_every_value_match_the_unchanged_air_schedule() {
    use PartKind::*;
    let air = TranscriptAir::new(vec![Bytes32, PolynomialQ, PolynomialQhat]).unwrap();
    let layout = crate::graph_auxiliary::owned_transcript::layout_for_air(&air).unwrap();
    let geometry = TranscriptPreparationPlan::new(layout).unwrap().geometry();
    let reference = air.periodic_columns();
    assert_eq!(reference.iter().map(Vec::len).collect::<Vec<_>>(), [128, 128, 2, 128]);
    for (column, values) in reference.iter().enumerate() {
        assert_eq!(geometry.periodic_length(column).unwrap(), values.len());
        for (row, value) in values.iter().enumerate() {
            assert_eq!(geometry.periodic_value(column, row).unwrap(), *value);
        }
        assert!(geometry.periodic_value(column, values.len()).is_err());
    }
}

#[test]
fn transcript_typed_input_rejects_wrong_layout_and_overflow_before_trace_dispatch() {
    use lattica_prover_p3::block_v2::native_gpu::{TranscriptPart as DevicePart,
        owned_transcript::TranscriptInput};
    const ZERO: [u8; 32] = [0; 32];
    let polynomial = [0u64; 256];
    let kind = TranscriptLayout::new(&[TranscriptPartKind::PolynomialQ]).unwrap();
    let parts = core::array::from_fn(|_| DevicePart::Bytes32(&ZERO));
    assert!(TranscriptInput::new(kind, parts).is_err());
    let mut parts = core::array::from_fn(|_| DevicePart::Bytes32(&ZERO));
    parts[0] = DevicePart::PolynomialQ(&polynomial);
    assert!(TranscriptInput::new(kind, parts).is_ok());
    let mut overflow = polynomial; overflow[255] = u32::MAX as u64 + 1;
    let mut parts = core::array::from_fn(|_| DevicePart::Bytes32(&ZERO));
    parts[0] = DevicePart::PolynomialQ(&overflow);
    assert!(TranscriptInput::new(kind, parts).is_err());
}
