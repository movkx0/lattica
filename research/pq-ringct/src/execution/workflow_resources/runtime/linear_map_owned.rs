//! Typed native linear_map arithmetic from preproof packets and original owners.
//! No legacy Session, proof cache factory, new quota or retry enters this path.
use super::*;
use super::native_retirement::{RetirementGuard, RetirementState};
use super::super::owners::{OriginalOutput, RetainedNative};
use crate::{
    execution::{
        phase_lifecycle::owned_partition::OriginalPhasePartition,
        retained_resources::Ledger,
    },
    spend_pipeline::full_workflow::linear_map_native::{LinearMapNativeOperationPlan, LinearMapNativeOperation,
        OwnedLinearMapOutput, ProducedLinearMap, LinearMapNativeOperationFailure},
    graph_proofs::owned_linear_map::verification_memory::Plan as VerificationPlan,
    opencl::{RetiredSourceSession, StartupTiming},
};
use lattica_prover_p3::{
    block_v2::{
        gpu_hash::device::ringct_runtime::Retirement,
        native_gpu::{
            owned_linear_map::{NativeLinearMapPhase, NativeLinearMapReservationPlan, PreissuedNativeLinearMapPlan},
            linear_map_output::PendingLinearMapOutput,
        },
    },
    proving::Policy,
};
use std::time::Instant;

mod partition;
mod preissue;
mod restore;
use partition::NativePartitionPlan;
pub(crate) use preissue::PreissuedLinearMapNative;
pub(crate) use preissue::linear_map_native_packet_metadata_host_bytes;

impl OriginalOutput for OwnedLinearMapOutput<'_> {
    fn destroy_into_originals(self) -> [Option<Reservation>; 4] {
        let (proof, report) = self.into_originals();
        [Some(proof), Some(report), None, None]
    }
}

#[derive(Default, serde::Serialize)]
struct EpochTelemetry {
    source: Option<lattica_prover_p3::block_v2::native_gpu::linear_map_preparation::LinearMapDescriptor>,
    preissue_ns: u128,
    preparation_ns: u128,
    startup: Option<StartupTiming>,
    proving_ns: Option<u128>,
    retirement: Option<Retirement>,
    cpu_verification_ns: Option<u128>,
    independent_verification_complete: bool,
}

impl EpochTelemetry {
    fn native_report(&mut self, access: &ExecutionAccess<'_>, produced: &ProducedLinearMap<'_>)
        -> Result<(), LinearMapNativeOperationFailure>
    {
        let report = produced.report();
        let (padded_rows, degree_bits) = produced.actual_row_geometry();
        access.context().record_owned_native_report(report, b"owned_linear_map_native_report ", padded_rows, degree_bits)
            .map_err(|error| match error {
                crate::execution::owned_workflow_observation::ObservationError::Write => LinearMapNativeOperationFailure::Resource,
                _ => LinearMapNativeOperationFailure::Authority,
            })?;
        self.proving_ns = Some(report.elapsed_ns);
        Ok(())
    }

    fn emit(&self, binding: &PhaseBinding) -> Result<(), LinearMapNativeOperationFailure> {
        crate::execution::report_transport::emit(b"owned_linear_map_native_epoch ", &EpochEntry {
            schema: "ringct-owned-source-native-epoch-v2", ordinal: binding.ordinal(), binding: binding.verification_binding(), epoch: self,
        }).map_err(|_| LinearMapNativeOperationFailure::Resource)
    }
}

#[derive(serde::Serialize)]
struct EpochEntry<'a> { schema: &'static str, ordinal: usize, binding: VerificationBinding, epoch: &'a EpochTelemetry }
impl crate::execution::report_transport::FixedPayload for EpochEntry<'_> {}

/// Every forwarding/result/serialization frame introduced by this concrete
/// issuer is additive to the source preparation and core wrapper inventories.
pub(crate) fn linear_map_native_issuer_scratch_requirements() -> Result<Requirements, WorkflowError> {
    use core::mem::size_of;
    let frames = [
        verification_binding_frame_bytes()?,
        size_of::<EpochTelemetry>(), size_of::<EpochEntry<'static>>(),
        size_of::<(usize, usize)>(), size_of::<&ProducedLinearMap<'static>>(),
        size_of::<&lattica_prover_p3::proving::Report>(),
        size_of::<lattica_prover_p3::block_v2::native_gpu::linear_map_preparation::LinearMapGeometry>(),
        size_of::<[&(); 4]>(),
        size_of::<Result<(), crate::execution::owned_workflow_observation::ObservationError>>(),
        size_of::<NativePartitionPlan>(), size_of::<[Reservation; 5]>(),
        size_of::<OriginalPhasePartition<'static, 'static>>(),
        size_of::<PreissuedNativeLinearMapPlan>(), size_of::<NativeLinearMapPhase>(),
        size_of::<PendingLinearMapOutput>(), size_of::<ProducedLinearMap<'static>>(),
        size_of::<VerificationPlan>(), size_of::<Result<VerificationPlan, LinearMapNativeOperationFailure>>(),
        size_of::<Result<ProducedLinearMap<'static>, LinearMapNativeOperationFailure>>(),
        size_of::<Result<(OwnedLinearMapOutput<'static>, Reservation),
            (LinearMapNativeOperationFailure, ProducedLinearMap<'static>, Reservation)>>(),
        size_of::<Result<RetainedNative<OwnedLinearMapOutput<'static>>, PhaseFailure<LinearMapNativeOperationFailure>>>(),
        size_of::<Result<PreissuedLinearMapNative<'static, 'static>, WorkflowError>>(),
        size_of::<RetirementState>(), size_of::<&RetirementState>(),
        2 * size_of::<RetirementGuard<'static, Reservation>>(),
        size_of::<RetirementGuard<'static, NativeLinearMapPhase>>(),
        size_of::<RetirementGuard<'static, Result<ProducedLinearMap<'static>, LinearMapNativeOperationFailure>>>(),
        size_of::<Ledger>(), size_of::<Requirements>(),
    ].into_iter().try_fold(0usize, |sum, bytes| sum.checked_add(bytes))
        .and_then(|sum| sum.checked_mul(8))
        .and_then(|sum| sum.checked_add(crate::execution::report_transport::required_host_bytes()))
        .ok_or(WorkflowError::Overflow)?;
    Ok(Requirements::single(Category::PhaseScratch, Bytes {
        host: u64::try_from(frames).map_err(|_| WorkflowError::Overflow)?, device: 0,
    }))
}

/// # Safety
/// The closed runner keeps the original physical-device/process selection
/// immutable and exclusive from preissue through real runtime destruction.
unsafe fn attempt<'request>(
    access: &ExecutionAccess<'_>, phase: &mut OwnedPhase<'_>,
    source: &RetiredSourceSession<'_>, output: &mut SlotClaim,
    operation: LinearMapNativeOperation<'_, 'request>,
    packet: PreissuedLinearMapNative<'_, 'request>, telemetry: &mut EpochTelemetry,
) -> Result<OwnedLinearMapOutput<'request>, LinearMapNativeOperationFailure> {
    if access.binding() != operation.binding() || packet.binding != operation.binding()
        || !core::ptr::eq(operation.plan(), packet.plan)
        || PhaseBinding::for_linear_map_native(packet.plan, packet.binding.ordinal())
            .map_err(|_| LinearMapNativeOperationFailure::Authority)? != packet.binding
        || access.context().policy() != Policy::GpuRequired
        || !core::ptr::eq(access.context(), operation.plan().context())
        || !access.owns_source(operation.plan().sources())
        || !output.belongs_to(phase.ledger())
        || operation.plan().policy() != crate::proof_cache_policy::ProofCachePolicy::FreshOnly
    {
        return Err(LinearMapNativeOperationFailure::Authority);
    }
    let PreissuedLinearMapNative { plan: _, binding: _, partition: plan, core, verification, preissue_ns } = packet;
    telemetry.source = Some(operation.plan().kind());
    telemetry.preissue_ns = preissue_ns;
    let (source_output, source_scratch) = operation.source_requirements()?;
    if !contains(access.binding().facts().output, source_output)
        || !contains(access.binding().facts().scratch, source_scratch)
        || !contains(source_scratch, combine(plan.preparation, plan.verifier)
            .map_err(|_| LinearMapNativeOperationFailure::Resource)?)
        || !contains(access.binding().facts().scratch,
            linear_map_native_issuer_scratch_requirements().map_err(|_| LinearMapNativeOperationFailure::Resource)?)
    {
        return Err(LinearMapNativeOperationFailure::Authority);
    }
    let runtime_plan = plan.runtime()?;
    let output_plan = operation.output_plan()?;
    let mut partition = phase.partition_originals(plan.complete).map_err(|_| LinearMapNativeOperationFailure::Resource)?;
    let ledger = partition.ledger().clone();
    let startup = partition.split(plan.startup).map_err(|_| LinearMapNativeOperationFailure::Resource)?;
    let wrappers = partition.split(plan.wrappers).map_err(|_| LinearMapNativeOperationFailure::Resource)?;
    let pcs = partition.split(plan.pcs).map_err(|_| LinearMapNativeOperationFailure::Resource)?;
    let preparation = partition.split(plan.preparation).map_err(|_| LinearMapNativeOperationFailure::Resource)?;
    let verifier = partition.split(plan.verifier).map_err(|_| LinearMapNativeOperationFailure::Resource)?;
    let proof = output.split(output_plan.proof_requirement()).map_err(|_| LinearMapNativeOperationFailure::Resource)?;
    let report = match output.split(output_plan.report_requirement()) {
        Ok(report) => report,
        Err(_) => {
            if let Err((_error, original)) = output.reunite(proof) { core::mem::forget(original); }
            restore::phase(partition, [startup, wrappers, pcs, preparation, verifier])?;
            return Err(LinearMapNativeOperationFailure::Resource);
        }
    };
    let pending_output = match output_plan.claim_preserving(proof, report, &ledger) {
        Ok(pending) => pending,
        Err((_error, proof, report)) => {
            restore::all(partition, [startup, wrappers, pcs, preparation, verifier],
                output, Some((proof, report)))?;
            return Err(LinearMapNativeOperationFailure::Authority);
        }
    };
    let mut pending = match runtime_plan.claim(startup, &ledger, source) {
        Ok(pending) => pending,
        Err((_error, startup)) => {
            restore::all(partition, [startup, wrappers, pcs, preparation, verifier],
                output, Some(pending_output.into_originals()))?;
            return Err(LinearMapNativeOperationFailure::Resource);
        }
    };
    let constructed = {
        let checked = unsafe { pending.preflight() };
        match checked {
            Ok(guard) => unsafe { NativeLinearMapPhase::from_preissued_originals(
                core, &preparation, guard.reservation(), pending_output, &verifier,
                wrappers, pcs, &ledger,
            ) }.map_err(|(_error, output, wrappers, pcs)| (output, wrappers, pcs)),
            Err(_) => { drop(core); Err((pending_output, wrappers, pcs)) }
        }
    };
    let native = match constructed {
        Ok(native) => native,
        Err((pending_output, wrappers, pcs)) => {
            let startup = pending.into_unstarted_original();
            restore::all(partition, [startup, wrappers, pcs, preparation, verifier],
                output, Some(pending_output.into_originals()))?;
            return Err(LinearMapNativeOperationFailure::Resource);
        }
    };
    // Each split original stays pinned independently of the partition's residual.
    // Borrowing through the preparation guard preserves the recorder's exclusive
    // original borrow without an Rc, allocation, or replacement reservation.
    let retirement = RetirementState::new();
    let mut preparation = RetirementGuard::new(preparation, &retirement);
    let verifier = RetirementGuard::new(verifier, &retirement);
    let mut native = RetirementGuard::new(native, &retirement);
    let preparation_started = Instant::now();
    let recorded = match operation.record(preparation.get_mut(), &ledger, verification) {
        Ok(recorded) => recorded,
        Err(error) => {
            telemetry.preparation_ns = preparation_started.elapsed().as_nanos();
            let startup = pending.into_unstarted_original();
            let (empty, wrappers, pcs) = native.into_original().into_unstarted_originals()
                .map_err(|unrecoverable| { core::mem::forget(unrecoverable); LinearMapNativeOperationFailure::Authority })?;
            restore::all(partition, [startup, wrappers, pcs,
                preparation.into_original(), verifier.into_original()],
                output, Some(empty.into_originals()))?;
            return Err(error);
        }
    };
    telemetry.preparation_ns = preparation_started.elapsed().as_nanos();
    retirement.arm();
    let (session, timing) = match unsafe { pending.start_preserving() } {
        Ok(started) => started,
        Err((_error, timing, startup)) => {
            // start_preserving returns this original only after partial-runtime
            // destruction; uncertain cleanup aborts rather than returning Err.
            retirement.after_failed_start();
            telemetry.startup = Some(timing);
            drop(recorded);
            let (empty, wrappers, pcs) = native.into_original().into_unstarted_originals()
                .map_err(|unrecoverable| { core::mem::forget(unrecoverable); LinearMapNativeOperationFailure::Authority })?;
            restore::all(partition, [startup, wrappers, pcs,
                preparation.into_original(), verifier.into_original()],
                output, Some(empty.into_originals()))?;
            return Err(LinearMapNativeOperationFailure::Native);
        }
    };
    telemetry.startup = Some(timing);
    let produced = RetirementGuard::new((|| {
        let guard = session.check_reserved_runtime(&ledger).map_err(|_| LinearMapNativeOperationFailure::Authority)?;
        let runtime = guard.borrow_core().map_err(|_| LinearMapNativeOperationFailure::Authority)?;
        unsafe { operation.produce(access, native.get_mut(), recorded, runtime.runtime(),
            runtime.reservation(), verifier.get()) }
    })(), &retirement);
    let retired = match session.finish_reserved_with_owner(&ledger) {
        Ok(retired) => retired,
        // All guards retain their payloads AND original claims, including a
        // successfully produced proof, until actual retirement is authenticated.
        Err(_) => return Err(LinearMapNativeOperationFailure::Native),
    };
    telemetry.retirement = Some(retired.receipt());
    let (startup, wrappers, pcs, refused_output) = if native.get().attempted() {
        if native.get().check_retired_originals(&retired, &ledger).is_err() {
            core::mem::forget(retired);
            return Err(LinearMapNativeOperationFailure::Native);
        }
        retirement.after_authenticated_retirement();
        match native.into_original().into_retired_reservations(retired, &ledger) {
            Ok(originals) => originals.into_originals_and_output(),
            Err((_error, native, retired)) => {
                core::mem::forget(native); core::mem::forget(retired);
                return Err(LinearMapNativeOperationFailure::Native);
            }
        }
    } else {
        // A source/guard refusal can precede the core attempt. The sealed outer
        // extraction authenticates real retirement and its original ledger.
        let startup = retired.into_outer_host_original(&ledger)
            .map_err(|(_error, unrecoverable)| { core::mem::forget(unrecoverable); LinearMapNativeOperationFailure::Authority })?;
        retirement.after_authenticated_retirement();
        let (empty, wrappers, pcs) = native.into_original().into_unstarted_originals()
            .map_err(|unrecoverable| { core::mem::forget(unrecoverable); LinearMapNativeOperationFailure::Authority })?;
        (startup, wrappers, pcs, Some(empty.into_originals()))
    };
    let preparation = preparation.into_original();
    let verifier = verifier.into_original();
    let produced = produced.into_original();
    let produced = match produced {
        Ok(produced) if refused_output.is_none() => produced,
        other => {
            // Every payload dies before the exact core output originals return.
            let output_result = match other {
                Ok(produced) => restore::output(output, produced.into_originals()),
                Err(_) => Ok(()),
            };
            let original_result = restore::all(partition,
                [startup, wrappers, pcs, preparation, verifier], output, refused_output);
            output_result.and(original_result)?;
            return Err(LinearMapNativeOperationFailure::Native);
        }
    };
    if let Err(error) = telemetry.native_report(access, &produced) {
        restore::all(partition, [startup, wrappers, pcs, preparation, verifier],
            output, Some(produced.into_originals()))?;
        return Err(error);
    }
    let verification_started = Instant::now();
    let verified = operation.verify_and_finish(produced, verifier, &ledger);
    telemetry.cpu_verification_ns = Some(verification_started.elapsed().as_nanos());
    match verified {
        Ok((payload, verifier)) => {
            restore::phase(partition, [startup, wrappers, pcs, preparation, verifier])?;
            telemetry.independent_verification_complete = true;
            Ok(payload)
        }
        Err((error, produced, verifier)) => {
            restore::all(partition, [startup, wrappers, pcs, preparation, verifier],
                output, Some(produced.into_originals()))?;
            Err(error)
        }
    }
}

impl WorkflowPhase<'_, '_, '_> {
    pub(crate) fn produce_linear_map_native<'request>(mut self,
        operation: LinearMapNativeOperation<'_, 'request>, packet: PreissuedLinearMapNative<'_, 'request>,
    ) -> Result<RetainedNative<OwnedLinearMapOutput<'request>>, PhaseFailure<LinearMapNativeOperationFailure>> {
        if self.step.binding != operation.binding() || packet.binding != operation.binding()
            || !self.admission.retired_context.belongs_to(self.admission.context)
        { return Err(PhaseFailure::Admission(WorkflowError::Identity)); }
        let binding = self.step.binding;
        let mut telemetry = EpochTelemetry::default();
        let result = {
            let access = ExecutionAccess { context: self.admission.context, binding,
                backend: self.step.backend, pool: &self.admission.pool };
            unsafe { attempt(&access, self.admission.phase.as_mut().expect("active closed workflow"),
                self.admission.retired_context.source(), self.output.as_mut().expect("preissued output"),
                operation, packet, &mut telemetry) }
        };
        let result = match telemetry.emit(&binding) {
            Ok(()) => result,
            Err(error) => {
                if let Ok(payload) = result {
                    let claim = self.output.as_mut().expect("preissued output");
                    if restore::output(claim, payload.into_originals()).is_err() { self.admission.pool.poison(); }
                }
                Err(error)
            }
        };
        let output_claim = self.output.take().expect("preissued output");
        let failure_claim = self.failure.take().expect("preissued failure");
        match result {
            Ok(payload) => {
                let output = RetainedNative::produced(payload, output_claim, binding);
                match self.cleanup() {
                    Ok(()) => {
                        drop(failure_claim); self.admission.next += 1; self.completed = true; Ok(output)
                    }
                    Err(status) => {
                        drop(output); self.admission.failed = true; self.admission.pool.poison();
                        self.completed = true;
                        Err(PhaseFailure::Retained(RetainedFailure::produced(None, Some(status), failure_claim)))
                    }
                }
            }
            Err(error) => {
                let mut failure = RetainedFailure::produced(Some(error), None, failure_claim);
                drop(output_claim);
                if let Err(status) = self.cleanup() { failure = failure.with_status(status); self.admission.pool.poison(); }
                self.admission.failed = true; self.completed = true;
                Err(PhaseFailure::Retained(failure))
            }
        }
    }
}
