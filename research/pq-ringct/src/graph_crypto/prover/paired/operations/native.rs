//! The native segment comes only from its immutable request and original
//! workflow claims. No cache decoder, generic factory or legacy Session runs.
use super::*;
use crate::{
    component_tree::shake_verification_memory::{Plan as VerificationPlan, VerificationReceipt},
    execution::retained_resources::{Ledger, Reservation},
    graph_crypto::{Payload, RequestDescriptor},
    proof_cache_policy::ProofCachePolicy,
    shake_air::lane::batch::ShakeSegmentAir,
};
use lattica_prover_p3::block_v2::{
    gpu_hash::device::ringct_runtime::Runtime,
    native_gpu::{
        owned_shake::{NativeShakePhase, NativeShakeReservationPlan},
        shake_output::{OwnedShakeProof, ShakeOutputPlan},
        shake_preparation::ShakePreparationPlan,
        shake_recording::{PreparedShake, ShakeRecorder},
        PeriodicSource, ShakeTraceSpec,
    },
};
use p3_air::{Air, BaseAir};

pub(crate) struct OwnedShakeNativeSource<'request> {
    request: &'request Request,
    index: usize,
    air: &'request ShakeSegmentAir,
    preparation: ShakePreparationPlan,
    output: ShakeOutputPlan,
    verifier: VerificationPlan,
}

impl<'request> OwnedShakeNativeSource<'request> {
    pub(crate) fn new(request: &'request Request, index: usize) -> Result<Self> {
        let RequestDescriptor::Shake(descriptor) = request.descriptor() else {
            return Err(PairedFailure::Source);
        };
        let Payload::Shake(input) = &request.payload else { return Err(PairedFailure::Source); };
        if input.len() != descriptor.input_len { return Err(PairedFailure::SourceDrift); }
        let air = request.shake_partition().ok_or(PairedFailure::Source)?
            .segments().get(index).ok_or(PairedFailure::Coverage)?;
        let segment = request.segments().get(index).ok_or(PairedFailure::Coverage)?;
        let spec = ShakeTraceSpec {
            input_len: descriptor.input_len,
            output_len: descriptor.output_len,
            first_permutation: segment.first_unit,
            permutations: segment.units,
        };
        let preparation = match air {
            ShakeSegmentAir::Single(_) => ShakePreparationPlan::singleton(spec),
            ShakeSegmentAir::Batch(_) => ShakePreparationPlan::batch(spec),
        }.map_err(|_| PairedFailure::Source)?;
        let geometry = preparation.geometry();
        if geometry.rows() != segment.height || geometry.width() != segment.width
            || air.height() != geometry.rows() || air.width() != geometry.width()
            || air.first_permutation() != segment.first_unit || air.permutations() != segment.units
            || air.num_public_values() != geometry.public_values()
            || air.num_periodic_columns() != geometry.periodic_columns()
            || air.max_constraint_degree() != Some(7)
        { return Err(PairedFailure::SourceDrift); }
        let output = ShakeOutputPlan::new(preparation).map_err(|_| PairedFailure::Resource)?;
        let verifier = VerificationPlan::new(air).map_err(|_| PairedFailure::Resource)?;
        Ok(Self { request, index, air, preparation, output, verifier })
    }

    pub(crate) fn reservation_plan(&self, operation_host: usize) -> Result<NativeShakeReservationPlan> {
        NativeShakeReservationPlan::device(self.preparation, operation_host)
            .map_err(|_| PairedFailure::Resource)
    }
    pub(crate) fn reservation_plan_outer_host_v1(&self, operation_host: usize)
        -> Result<NativeShakeReservationPlan> {
        NativeShakeReservationPlan::outer_host_v1(self.preparation, operation_host)
            .map_err(|_| PairedFailure::Resource)
    }
    pub(crate) fn output_plan(&self) -> ShakeOutputPlan { self.output }

    /// Pure requirements outside the separately preissued native backend.
    pub(crate) fn source_requirements(&self) -> Result<(Requirements, Requirements)> {
        use source::{bytes, combine, requirement};
        let output = combine(&[
            self.output.proof_requirement(), self.output.report_requirement(),
            requirement(Category::RegisteredMetadata,
                add(add(bytes::<ProducedShakeNative<'static>>(8)?,
                    bytes::<PairedNativeOutput<'static>>(8)?)?,
                    bytes::<crate::execution::workflow_resources::RetainedNative<
                        PairedNativeOutput<'static>>>(8)?)?)?,
        ])?;
        let frames = [
            bytes::<Self>(8)?, bytes::<RecordedShakeNative<'static, 'static>>(8)?,
            bytes::<ProducedShakeNative<'static>>(8)?, bytes::<PairedNativeOutput<'static>>(8)?,
            bytes::<Vec<lattica_prover_p3::block_v2::machine::program::Val>>(8)?,
            bytes::<lattica_prover_p3::block_v2::machine::program::Val>(2 * crate::shake_air::PUBLIC_VALUES)?,
            bytes::<Reservation>(16)?, bytes::<Requirements>(16)?,
            bytes::<Result<OwnedShakeProof>>(8)?,
            VerificationPlan::retaining_original_caller_host_bytes().map_err(|_| PairedFailure::Resource)?,
        ].into_iter().try_fold(64 << 10, add)?;
        let scratch = combine(&[
            self.reservation_plan(1)?.preparation_requirement().map_err(|_| PairedFailure::Resource)?,
            VerificationPlan::component_requirement(),
            requirement(Category::PhaseScratch, frames)?,
        ])?;
        Ok((output, scratch))
    }
}

pub(crate) struct RecordedShakeNative<'claim, 'request> {
    prepared: PreparedShake<'claim>,
    request: &'request Request,
    index: usize,
    binding: PhaseBinding,
}

pub(crate) struct ProducedShakeNative<'request> {
    proof: OwnedShakeProof,
    request: &'request Request,
    index: usize,
    binding: PhaseBinding,
}
impl ProducedShakeNative<'_> {
pub(crate) fn report(&self) -> &lattica_prover_p3::proving::Report { self.proof.report() }
    /// Exact immutable retained trace geometry and the actual proof degree.
    /// These numbers describe output already produced; they admit no work.
    pub(crate) fn actual_row_geometry(&self) -> (usize, usize) {
        (self.proof.geometry().rows(), self.proof.artifact().proof.degree_bits)
    }
    pub(crate) fn into_originals(self) -> (Reservation, Reservation) { self.proof.into_originals() }
}

impl<'request> PairedNativeOperation<'_, 'request> {
    pub(crate) fn source(&self) -> Result<OwnedShakeNativeSource<'request>> {
        OwnedShakeNativeSource::new(self.plan.request, self.index)
    }
    pub(crate) fn output_plan(&self) -> Result<ShakeOutputPlan> { Ok(self.source()?.output_plan()) }
    pub(crate) fn reservation_plan(&self, operation_host: usize) -> Result<NativeShakeReservationPlan> {
        self.source()?.reservation_plan(operation_host)
    }
    pub(crate) fn reservation_plan_outer_host_v1(&self, operation_host: usize)
        -> Result<NativeShakeReservationPlan> {
        self.source()?.reservation_plan_outer_host_v1(operation_host)
    }
    pub(crate) fn source_requirements(&self) -> Result<(Requirements, Requirements)> {
        self.source()?.source_requirements()
    }

    pub(crate) fn record<'claim>(&self, original: &'claim mut Reservation, ledger: &'claim Ledger)
        -> Result<RecordedShakeNative<'claim, 'request>> {
        let source = self.source()?;
        let columns = source.preparation.geometry().periodic_columns();
        if source.air.column_count() != columns || (0..columns).any(|i|
            source.air.column_len(i) != Some(source.preparation.geometry().periodic_length())) {
            return Err(PairedFailure::SourceDrift);
        }
        let mut recorder = ShakeRecorder::begin(source.preparation, original, ledger)
            .map_err(|_| PairedFailure::Preparation)?;
        match source.air {
            ShakeSegmentAir::Single(air) => air.eval(recorder.builder_mut()),
            ShakeSegmentAir::Batch(air) => air.eval(recorder.builder_mut()),
        }
        for index in 0..columns {
            let output = recorder.periodic_column_mut(index).map_err(|_| PairedFailure::Preparation)?;
            match source.air {
                ShakeSegmentAir::Single(air) => air.fill_column(index, output),
                ShakeSegmentAir::Batch(air) => air.fill_column(index, output),
            }.map_err(|_| PairedFailure::Preparation)?;
        }
        let prepared = recorder.finish().map_err(|_| PairedFailure::Preparation)?;
        if source.air.num_constraints().is_some_and(|n| n != prepared.constraints()) {
            return Err(PairedFailure::SourceDrift);
        }
        Ok(RecordedShakeNative { prepared, request: self.plan.request, index: self.index,
            binding: self.binding })
    }

    /// # Safety
    /// Only the concrete workflow issuer may call this after owning the exact
    /// Runtime/startup pair and original native phase through retirement. The
    /// process guard excludes environment mutation and unrelated GPU work.
    pub(crate) unsafe fn produce(
        &self, execution: &ExecutionAccess<'_>, phase: &mut NativeShakePhase,
        recorded: RecordedShakeNative<'_, 'request>, runtime: &Runtime,
        startup: &Reservation, verifier: &Reservation,
    ) -> Result<ProducedShakeNative<'request>> {
        access(self.binding, execution)?;
        if self.cache.policy() != ProofCachePolicy::FreshOnly
            || !core::ptr::eq(recorded.request, self.plan.request)
            || recorded.index != self.index || recorded.binding != self.binding {
            return Err(PairedFailure::Authority);
        }
        let Payload::Shake(input) = &self.plan.request.payload else {
            return Err(PairedFailure::Source);
        };
        self.cache.proof_attempt();
        let proof = unsafe { phase.produce(recorded.prepared, input, runtime, startup, verifier) }
            .map_err(|_| PairedFailure::Native)?;
        Ok(ProducedShakeNative { proof, request: self.plan.request, index: self.index,
            binding: self.binding })
    }

    pub(crate) fn verify_and_finish(
        self, produced: ProducedShakeNative<'request>, verifier_original: Reservation, ledger: &Ledger,
    ) -> core::result::Result<(PairedNativeOutput<'request>, Reservation),
        (PairedFailure, ProducedShakeNative<'request>, Reservation)> {
        let source = match self.source() {
            Ok(value) => value,
            Err(error) => return Err((error, produced, verifier_original)),
        };
        if !core::ptr::eq(produced.request, source.request) || produced.index != source.index
            || produced.binding != self.binding || !produced.proof.belongs_to(ledger)
            || produced.proof.geometry() != source.preparation.geometry() {
            return Err((PairedFailure::Authority, produced, verifier_original));
        }
        let (receipt, original) = match verify_produced(&source, &produced, verifier_original, ledger) {
            Ok(value) => value,
            Err((error, original)) => return Err((error, produced, original)),
        };
        self.cache.fresh_proof();
        Ok((PairedNativeOutput { request: self.plan.request, index: self.index,
            proof: produced.proof, verification: receipt, elapsed_ns: self.started.elapsed().as_nanos() }, original))
    }
}

fn verify_produced(
    source: &OwnedShakeNativeSource<'_>, produced: &ProducedShakeNative<'_>,
    verifier_original: Reservation, ledger: &Ledger,
) -> core::result::Result<(VerificationReceipt, Reservation), (PairedFailure, Reservation)> {
    // This exact separate public vector is precharged in source scratch. All
    // borrows and verification temporaries die before ownership is returned.
    let mut public = Vec::new();
    if public.try_reserve_exact(crate::shake_air::PUBLIC_VALUES).is_err() {
        return Err((PairedFailure::Capacity, verifier_original));
    }
    public.extend_from_slice(&produced.proof.artifact().public_values);
    if public.capacity() > crate::shake_air::PUBLIC_VALUES {
        return Err((PairedFailure::Capacity, verifier_original));
    }
    let admitted = source.verifier.admit_pre_reserved_preserving(source.air,
        &produced.proof.artifact().proof, &public, produced.proof.proof_reservation(),
        verifier_original, ledger).map_err(|(_error, original)| (PairedFailure::Verification, original))?;
    admitted.verify_retaining_original()
        .map_err(|(_error, original)| (PairedFailure::Verification, original))
}

impl PairedNativeOutput<'_> {
pub(crate) fn report(&self) -> &lattica_prover_p3::proving::Report { self.proof.report() }
    pub(crate) fn into_originals(self) -> (Reservation, Reservation) { self.proof.into_originals() }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> Request {
        let input = vec![7; 16 * crate::shake_air::RATE + 3];
        Request::new([3; 32], 0, 0,
            RequestDescriptor::Shake(crate::shake_air::Descriptor { input_len: input.len(), output_len: 273 }),
            Payload::Shake(input), crate::graph_crypto::Policy {
                maximum_aes_blocks: 64,
                maximum_shake_permutations: 8,
                child_memory_budget_bytes: 8 << 30,
                admission: crate::graph_crypto::Admission::Estimated,
            }).unwrap()
    }

    #[test]
    fn source_requires_exact_native_segment_metadata_before_claims_or_recording() {
        let mut request = request();
        assert!(request.segments().len() > 1);
        for index in 0..request.segments().len() {
            let source = OwnedShakeNativeSource::new(&request, index).unwrap();
            let (output, scratch) = source.source_requirements().unwrap();
            assert_eq!(output.get(Category::NativeProof).host, 64 << 20);
            assert!(output.get(Category::Report).host > 0);
            assert!(scratch.get(Category::SymbolicCompiler).host > 0);
            assert_eq!(scratch.get(Category::IndependentVerifier).host, 64 << 20);
        }
        request.segments[0].width += 1;
        assert!(matches!(OwnedShakeNativeSource::new(&request, 0), Err(PairedFailure::SourceDrift)));
        request.segments[0].width -= 1;
        request.segments[0].first_unit += 1;
        assert!(OwnedShakeNativeSource::new(&request, 0).is_err());
    }

    #[test]
    fn source_refuses_wrong_payload_and_missing_native_segment() {
        let mut request = request();
        assert!(OwnedShakeNativeSource::new(&request, request.segments().len()).is_err());
        request.payload = Payload::Shake(vec![0]);
        assert!(matches!(OwnedShakeNativeSource::new(&request, 0), Err(PairedFailure::SourceDrift)));
        request.payload = Payload::Aes([0; 32]);
        assert!(matches!(OwnedShakeNativeSource::new(&request, 0), Err(PairedFailure::Source)));
    }
}
