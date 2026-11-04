//! Worker-local numeric census using the unchanged retained recorder. The
//! coordinator holds a real additional original for the whole job. This local
//! ledger partitions that funded sublimit; it grants no workflow authority and
//! neither it nor its recording can escape this function.
use super::*;
use crate::execution::retained_resources::WorkerAllowance;
use lattica_prover_p3::block_v2::native_gpu::{
    mul_recording::MulRecorder,
    owned_mul::NativeMulReservationPlan,
};
const FRAMES: usize = 64 << 10;
fn requirements(kind: MulDescriptor) -> Result<Requirements> {
    let source = MulPreparationPlan::new(kind).map_err(|_| GEOMETRY)?;
    NativeMulReservationPlan::outer_host_v1(source, 1)
        .and_then(|plan| plan.preparation_requirement()).map_err(|_| BUDGET)
}
pub(crate) fn numeric_host_bytes(kind: MulDescriptor) -> Result<usize> {
    Shape::new(&SourceAir::new(kind))?;
    let request = requirements(kind)?.total().map_err(|_| BUDGET)?;
    require(request.device == 0, BUDGET)?;
    add(usize::try_from(request.host).map_err(|_| OVERFLOW)?, FRAMES)
}
pub(crate) fn numeric_plan(kind: MulDescriptor, admitted: usize) -> Result<Plan> {
    require(admitted == numeric_host_bytes(kind)? && admitted <= 32usize << 30, BUDGET)?;
    let source = MulPreparationPlan::new(kind).map_err(|_| GEOMETRY)?;
    let requirements = requirements(kind)?;
    let ledger = ResourceLedger::new(WorkerAllowance { host: admitted as u64, device: 0 });
    let mut original = ledger.admit_phase(requirements).map_err(|_| BUDGET)?;
    let air = SourceAir::new(kind);
    let mut recorder = MulRecorder::begin(source, &mut original, &ledger).map_err(|_| BUDGET)?;
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
    fn numeric_job_preserves_retained_recording_and_refuses_unfunded_work() {
        let kind = MulDescriptor::new(crate::rust_verify::Q, 3).unwrap();
        let bytes = numeric_host_bytes(kind).unwrap();
        assert!(numeric_plan(kind, bytes - 1).is_err());
        let numeric = numeric_plan(kind, bytes).unwrap();
        assert!(numeric.same_census(super::super::recorded_test_plan(kind)));
    }
}
