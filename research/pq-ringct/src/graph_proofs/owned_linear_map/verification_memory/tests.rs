use super::*;

use crate::execution::retained_resources::WorkerAllowance;
use lattica_prover_p3::block_v2::native_gpu::{
    linear_map_recording::{self, LinearMapRecorder},
};

fn recorded_replay(air: &SourceAir) -> LinearMapSymbolicReplay {
    let source = LinearMapPreparationPlan::new(air.kind()).unwrap();
    let ledger = ResourceLedger::new(WorkerAllowance { host: 32 << 30, device: 0 });
    let symbolic = source.host().prepared_partition_bytes().unwrap();
    let other = source.host().required_host_bytes() - symbolic + linear_map_recording::additional_host_bytes();
    let mut requirements = Requirements::single(Category::SymbolicCompiler, Bytes { host: symbolic as u64, device: 0 });
    requirements.add(Category::PhaseScratch, Bytes { host: other as u64, device: 0 }).unwrap();
    let mut original = ledger.admit_phase(requirements).unwrap();
    let mut recorder = LinearMapRecorder::begin(source, &mut original, &ledger).unwrap();
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
fn linear_map_verifier_accounts_full_height_capacity_and_exact_minimal_evaluation() {
    for inputs in [1,3,16] {
        for kind in [[crate::rust_verify::Q,0],[crate::rust_verify::QHAT,0],[0,3]] {
            let mut coefficients=vec![[1;256];inputs];coefficients[0][252]=-2;
            let descriptor=LinearMapDescriptor::new(&vec![kind;inputs+1],&coefficients,&[0;256]).unwrap();
            let air=SourceAir::new(descriptor);
            let geometry=LinearMapGeometry::for_kind(descriptor);
            let plan=Plan::for_recorded(&air,recorded_replay(&air)).unwrap();
            let bounds=plan.bounds();
            let expected=(0..geometry.periodic_columns()).map(|i|periodic_evaluation(geometry.column_len(i).unwrap()).unwrap()).sum::<usize>();
            assert_eq!(bounds.periodic_evaluation_bytes,expected);
            assert!(bounds.periodic_construction_bytes>=geometry.rows()*geometry.periodic_columns()*size_of::<Val>());
            assert!(expected<=geometry.periodic_columns()*periodic_evaluation(geometry.rows()).unwrap());
            assert!(bounds.cumulative_requested_bytes+bounds.entry_frame_bytes<=COMPONENT_BYTES);
            assert_eq!(Plan::component_requirement(),Requirements::single(Category::IndependentVerifier,Bytes{host:64<<20,device:0}));
        }
    }
}
#[test]
fn linear_map_verifier_rejects_another_valid_descriptor_recording() {
    let first=SourceAir::new(LinearMapDescriptor::new(&[[0,3];2],&[[1;256]],&[0;256]).unwrap());
    let other=SourceAir::new(LinearMapDescriptor::new(&[[0,3];2],&[[2;256]],&[0;256]).unwrap());
    assert!(Plan::for_recorded(&first,recorded_replay(&other)).is_err());
}
