//! Worker-local numeric census using the unchanged retained recorder. The
//! coordinator holds a real additional original for the whole job. This local
//! ledger partitions that funded sublimit; it grants no workflow authority and
//! neither it nor its recording can escape this function.
use super::*;
use crate::execution::retained_resources::WorkerAllowance;
use lattica_prover_p3::block_v2::native_gpu::{
    linear_map_recording::LinearMapRecorder,
    owned_linear_map::NativeLinearMapReservationPlan,
};
const FRAMES: usize = 64 << 10;
fn requirements(kind: LinearMapDescriptor) -> Result<Requirements> {
    let source = LinearMapPreparationPlan::new(kind).map_err(|_| GEOMETRY)?;
    NativeLinearMapReservationPlan::outer_host_v1(source, 1)
        .and_then(|plan| plan.preparation_requirement()).map_err(|_| BUDGET)
}
pub(crate) fn numeric_host_bytes(kind: LinearMapDescriptor) -> Result<usize> {
    Shape::new(&SourceAir::new(kind))?;
    let request = requirements(kind)?.total().map_err(|_| BUDGET)?;
    require(request.device == 0, BUDGET)?;
    add(usize::try_from(request.host).map_err(|_| OVERFLOW)?, FRAMES)
}
pub(crate) fn numeric_plan(kind: LinearMapDescriptor, admitted: usize) -> Result<Plan> {
    require(admitted == numeric_host_bytes(kind)? && admitted <= 32usize << 30, BUDGET)?;
    let source = LinearMapPreparationPlan::new(kind).map_err(|_| GEOMETRY)?;
    let requirements = requirements(kind)?;
    let ledger = ResourceLedger::new(WorkerAllowance { host: admitted as u64, device: 0 });
    let mut original = ledger.admit_phase(requirements).map_err(|_| BUDGET)?;
    let air = SourceAir::new(kind);
    let mut recorder = LinearMapRecorder::begin(source, &mut original, &ledger).map_err(|_| BUDGET)?;
    air.eval(recorder.builder_mut());
    let prepared = recorder.finish().map_err(|_| BUDGET)?;
    let result = Plan::for_recorded(&air, prepared.symbolic_replay_census());
    drop(prepared);
    drop(original);
    require(ledger.snapshot().current == Bytes::ZERO, BUDGET)?;
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn numeric_recording_matches_the_retained_reference_and_exact_admission() {
        for input in [[0, 3], [crate::rust_verify::Q, 0], [crate::rust_verify::QHAT, 0]] {
            let kind = LinearMapDescriptor::new(&[input; 2], &[[1; 256]], &[0; 256]).unwrap();
            let bytes = numeric_host_bytes(kind).unwrap();
            let actual = numeric_plan(kind, bytes).unwrap();
            let expected = super::super::recorded_test_plan(kind);
            assert_eq!(actual.descriptor(), expected.descriptor());
            assert_eq!(actual.shape, expected.shape);
            assert_eq!(actual.bounds, expected.bounds);
            assert!(numeric_plan(kind, bytes - 1).is_err());
            assert!(numeric_plan(kind, bytes + 1).is_err());
        }
    }
}
