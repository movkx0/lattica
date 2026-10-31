//! Fresh N3/N4 inputs and the one-way transition into source planning.
//! This stage creates native MatRiCT spends, not STARK or recursive proofs.
mod inputs;
mod retirement_guard;
mod observation;
pub(crate) mod case_lifetime;
pub(crate) use observation::FreshLedgerObservation;
use retirement_guard::GenerationRetirementGuard;

use inputs::{FreshNativeInput, GeneratedInputSlot, InputPlan, VerifiedInput};
use super::InitialNativeSource;
use crate::{
    execution::{
            generation_terminal::{GenerationContextPlan, GenerationError, GenerationFailure,
            GenerationSpendSummary, NativeGenerationTerminal,
        planning_startup::{PlanningStartupPlan, FreshPlanningContext}},
        retained_resources::{Bytes, Category, Ledger, Requirements, Reservation, Snapshot, WorkerAllowance},
    },
    native::{self, declared_footprint::DeclaredNativeFootprint,
        private_spend_fixture::{self, generate_spend_fixture}, FixtureAmounts, NativeError},
    opencl::Limits,
};
use core::mem::size_of;
use lattica_prover_p3::block_v2::native_gpu::private_spend::{NativeSpendOperationPlan, SpendLimits};
use std::time::Instant;

#[derive(Debug)]
pub(crate) enum FreshGenerationError {
    Workflow { stage: super::driver::metadata_driver::DriverStage, cause: crate::execution::workflow_resources::WorkflowError },
    ProducerMetadata { stage: super::metadata_planning::MetadataPlanningStage, cause: super::ClosureError },
    Resource(&'static str), Context(GenerationError), Retirement(GenerationFailure), Native(NativeError),
}
type Result<T> = core::result::Result<T, FreshGenerationError>;
fn source(error: &'static str) -> FreshGenerationError { FreshGenerationError::Resource(error) }
fn combine(mut left: Requirements, right: Requirements) -> Result<Requirements> {
    for category in Category::ALL {
        left.add(category, right.get(category)).map_err(|_| source("generation requirements overflow"))?;
    }
    Ok(left)
}
fn host(category: Category, bytes: usize) -> Result<Requirements> {
    Ok(Requirements::single(category, Bytes {
        host: u64::try_from(bytes).map_err(|_| source("generation source width"))?, device: 0,
    }))
}
fn split(original: &mut Reservation, requirements: Requirements) -> Result<Reservation> {
    original.split(requirements).map_err(|_| source("generation original split failed"))
}

struct FreshGenerationPlan<const N: usize> {
    context: GenerationContextPlan,
    native: NativeSpendOperationPlan,
    inputs: InputPlan,
    shared: Requirements,
    frames: Requirements,
    operation: Requirements,
    complete: Requirements,
}
impl<const N: usize> FreshGenerationPlan<N> {
    fn new() -> Result<Self> { Self::with_host_profile(crate::host_memory_profile::HostMemoryProfile::Standard) }
    fn with_host_profile(profile: crate::host_memory_profile::HostMemoryProfile) -> Result<Self> {
        if !matches!(N, 3 | 4) { return Err(source("fresh generation requires N3 or N4")); }
        let context = GenerationContextPlan::new(N, Limits {
            host_bytes: profile.worker_bytes(), device_bytes: 8 << 30, max_rows: 1 << 20,
        }).map_err(FreshGenerationError::Context)?;
        let native = NativeSpendOperationPlan::new(SpendLimits::bounded(24 << 30))
            .map_err(|_| source("native spend source plan rejected"))?;
        let c = DeclaredNativeFootprint::reviewed().map_err(source)?;
        let inputs = InputPlan::new(c).map_err(source)?;
        for minimum in [native.output_requirements(),
            GenerationContextPlan::minimum_output_requirements().map_err(FreshGenerationError::Context)?]
        {
            if Category::ALL.into_iter().any(|category| {
                let have = inputs.output_requirements().get(category);
                let need = minimum.get(category);
                have.host < need.host || have.device < need.device
            }) { return Err(source("native output source exceeds generated-input original")); }
        }
        let shared = combine(native.shared_static_requirements(),
            host(Category::RegisteredMetadata, usize::try_from(c.shared_static_bytes())
                .map_err(|_| source("native shared census width"))?)?)?;
        let inspection = usize::try_from(DeclaredNativeFootprint::inspection_frame_bytes().map_err(source)?)
            .map_err(|_| source("native inspection census width"))?;
        let fixture = private_spend_fixture::footprint::requested_host_bytes().map_err(source)?
            .checked_add(usize::try_from(c.fixture_bytes()).map_err(|_| source("fixture census width"))?)
            .and_then(|bytes| bytes.checked_add(inspection))
            .ok_or_else(|| source("fixture and inspection census overflow"))?;
        let operation = combine(native.requirements(), host(Category::PhaseScratch, fixture)?)?;
        let inline = [size_of::<Self>(), size_of::<FreshGenerationBatch<N>>(),
            size_of::<GenerationHoldings<N>>(), size_of::<GenerationRetirementGuard<GenerationHoldings<N>>>(),
            size_of::<[Option<VerifiedInput>; N]>(), size_of::<Result<GenerationHoldings<N>>>(),
            size_of::<[Option<GeneratedInputSlot>; N]>(), size_of::<[Option<FreshNativeInput>; N]>(),
            size_of::<[Option<GenerationSpendSummary>; N]>(), size_of::<Result<FreshGenerationBatch<N>>>(),
            size_of::<Ledger>(), size_of::<Snapshot>() + 2 * size_of::<usize>(),
            size_of::<[Reservation; 8]>(), size_of::<[Requirements; 8]>(),
            size_of::<[InitialNativeSource<'static>; N]>(), size_of::<Instant>(),
        ].into_iter().try_fold(0usize, |sum, value| sum.checked_add(value)
            .ok_or_else(|| source("generation driver frame overflow")))?
            .checked_mul(4)
            // The fixed endpoint-query census already includes its multiplier.
            // Admit it before native startup; this same frames original stays
            // in the generated batch through source derivation and retirement.
            .and_then(|bytes| bytes.checked_add(
                crate::execution::workflow_resources::METADATA_ENDPOINT_QUERY_FRAME_BYTES))
            .ok_or_else(|| source("generation driver transport overflow"))?;
        let frames = host(Category::PhaseScratch, inline)?;
        let mut complete = combine(combine(shared, frames)?, operation)?;
        complete = combine(complete, context.total_requirements().map_err(FreshGenerationError::Context)?)?;
        for _ in 0..N {
            complete = combine(combine(complete, inputs.output_requirements())?, inputs.scratch_requirements())?;
        }
        let total = complete.total().map_err(|_| source("generation total overflow"))?;
        if total.host > profile.worker_bytes() || total.device > 8 << 30 {
            return Err(source("fresh generation exceeds selected worker allowance"));
        }
        Ok(Self { context, native, inputs, shared, frames, operation, complete })
    }
}

/// All generation slot originals stay owned here through actual retirement.
/// Verified CPU payloads are kept before claims in destruction order.
struct GenerationHoldings<const N: usize> {
    verified: [Option<VerifiedInput>; N],
    slots: [Option<GeneratedInputSlot>; N],
    shared: Reservation,
    frames: Reservation,
    operation: Reservation,
}

/// Private owners prevent release/recharge between generation and planning.
/// The terminal can only be obtained by consuming the actual native context.
pub(crate) struct FreshGenerationBatch<const N: usize> {
    started: Instant,
    planning_started: std::cell::Cell<bool>,
    inputs: [Option<FreshNativeInput>; N],
    summaries: [Option<GenerationSpendSummary>; N],
    terminal: NativeGenerationTerminal,
    shared: Reservation,
    frames: Reservation,
    ledger: Ledger,
}
impl<const N: usize> FreshGenerationBatch<N> {
    pub(crate) fn generate(setup_seed: [u8; 32], context: [u8; 32], first_case_index: usize) -> Result<Self> {
        Self::generate_with_host_profile(setup_seed, context, first_case_index, crate::host_memory_profile::HostMemoryProfile::Standard)
    }
    pub(crate) fn generate_with_host_profile(setup_seed: [u8; 32], context: [u8; 32], first_case_index: usize, profile: crate::host_memory_profile::HostMemoryProfile) -> Result<Self> {
        // Includes source census, fixture setup, native context startup and
        // real retirement. The full driver keeps this timer through final audit.
        let started = Instant::now();
        let plan = FreshGenerationPlan::<N>::with_host_profile(profile)?;
        if !matches!((N, first_case_index), (3, 0) | (4, 3)) {
            return Err(source("fresh screening index outside seven-transaction inventory"));
        }
        let ledger = Ledger::new(WorkerAllowance { host: profile.worker_bytes(), device: 8 << 30 });
        let mut original = ledger.admit_phase(plan.complete).map_err(|_| source("fresh generation admission failed"))?;
        let shared = split(&mut original, plan.shared)?;
        let frames = split(&mut original, plan.frames)?;
        let operation = split(&mut original, plan.operation)?;
        let runtime = split(&mut original, plan.context.total_requirements().map_err(FreshGenerationError::Context)?)?;
        let mut slots: [Option<GeneratedInputSlot>; N] = core::array::from_fn(|_| None);
        for slot in &mut slots {
            let output = split(&mut original, plan.inputs.output_requirements())?;
            let scratch = split(&mut original, plan.inputs.scratch_requirements())?;
            *slot = Some(plan.inputs.bind(output, scratch, &ledger).map_err(source)?);
        }
        if original.requirements().total().map_err(|_| source("generation original total"))? != Bytes::ZERO {
            return Err(source("generation preissue left unmatched credit"));
        }
        drop(original);
        let holdings = GenerationHoldings { verified: core::array::from_fn(|_| None),
            slots, shared, frames, operation };
        // Declared before the runtime: unwinding destroys the runtime first.
        // Without its terminal receipt, the guard preserves every original.
        let mut guarded = GenerationRetirementGuard::new(holdings);
        let mut summaries: [Option<GenerationSpendSummary>; N] = core::array::from_fn(|_| None);
        let mut generation = plan.context.start(runtime, &ledger).map_err(FreshGenerationError::Retirement)?;
        guarded.started();
        for ordinal in 0..N {
            let index = (first_case_index + ordinal) as u64;
            let fixture = generate_spend_fixture(context, Some(setup_seed), index % native::RING_PAIRS,
                FixtureAmounts { input: [7 + index, 11], output: [9, 9 + index] })
                .map_err(FreshGenerationError::Native)?;
            let request = fixture.into_gpu_request().map_err(FreshGenerationError::Native)?;
            plan.native.check_request(&request).map_err(|_| source("fresh fixture request source mismatch"))?;
            let held = guarded.get();
            let slot = held.slots[ordinal].as_ref().ok_or_else(|| source("fresh input slot reused"))?;
            let (output, summary) = generation.create_matrict_spend_on_gpu(request, &plan.native,
                &held.operation, slot.original()).map_err(FreshGenerationError::Context)?;
            if summary.ordinal != ordinal { return Err(source("fresh generation report order mismatch")); }
            let verified = slot.finish(output, setup_seed, context).map_err(source)?;
            guarded.get_mut().verified[ordinal] = Some(verified);
            summaries[ordinal] = Some(summary);
        }
        let terminal = generation.finish().map_err(FreshGenerationError::Retirement)?;
        let GenerationHoldings { mut verified, mut slots, shared, frames, operation } =
            guarded.after_retirement(&terminal, &ledger, N).map_err(source)?;
        // Neither native queue nor operation backing survives this terminal.
        drop(operation);
        let mut inputs: [Option<FreshNativeInput>; N] = core::array::from_fn(|_| None);
        for ordinal in 0..N {
            let slot = slots[ordinal].take().ok_or_else(|| source("missing retired generation slot"))?;
            let payload = verified[ordinal].take().ok_or_else(|| source("missing retired generation input"))?;
            inputs[ordinal] = Some(slot.attach_after_retirement(payload));
        }
        drop(slots);
        let batch = Self { started, planning_started: std::cell::Cell::new(false), inputs, summaries, terminal, shared, frames, ledger };
        batch.original_enclosing_bytes()?;
        Ok(batch)
    }

    pub(crate) fn started(&self) -> Instant { self.started }
    pub(crate) fn generation_totals(&self) -> crate::execution::generation_terminal::NativeGenerationTotals {
        self.terminal.totals()
    }
    pub(crate) fn generation_session_id(&self) -> u64 { self.terminal.session_id() }
    /// Claims startup and permanent planning storage in the same generation
    /// ledger before opening the next OpenCL session. This batch never retries.
    pub(crate) fn begin_planning(&self) -> Result<FreshPlanningContext<'_>> {
        self.original_enclosing_bytes()?;
        self.start_planning()
    }
    // Called only after pristine-generation or exact named case-entry checks.
    fn start_planning(&self) -> Result<FreshPlanningContext<'_>> {
        if self.planning_started.replace(true) {
            return Err(source("fresh generation already entered planning"));
        }
        let plan = PlanningStartupPlan::new().map_err(FreshGenerationError::Context)?;
        let original = self.ledger.admit_phase(plan.requirements()
            .map_err(FreshGenerationError::Context)?)
            .map_err(|_| source("planning startup admission failed"))?;
        plan.start(&self.terminal, original, &self.ledger).map_err(FreshGenerationError::Context)
    }
    pub(crate) fn validate_planning_context(&self, context: &FreshPlanningContext<'_>) -> Result<()> {
        self.owned_generation_bytes()?;
        if !self.planning_started.get() || !context.belongs_to_generation(&self.terminal) {
            return Err(source("fresh planning context belongs to another generation"));
        }
        context.validate_source_entry().map_err(FreshGenerationError::Context)
    }
    /// Actual original generation owners, independent of later claims added
    /// to this same ledger. This subtotal is descriptive, never a new budget.
    pub(crate) fn owned_generation_bytes(&self) -> Result<Bytes> {
        if !self.terminal.belongs_to(&self.ledger) || self.terminal.spend_count() != N
            || !self.shared.belongs_to(&self.ledger) || !self.frames.belongs_to(&self.ledger)
        { return Err(source("generation terminal owner mismatch")); }
        let mut expected = combine(combine(self.shared.requirements(), self.frames.requirements())?,
            self.terminal.requirements())?;
        for (ordinal, (input, summary)) in self.inputs.iter().zip(&self.summaries).enumerate() {
            let input = input.as_ref().ok_or_else(|| source("missing fresh native input"))?;
            if !input.belongs_to(&self.ledger) || !summary.is_some_and(|summary|
                summary.ordinal == ordinal && summary.session_id == self.terminal.session_id()) {
                return Err(source("fresh input owner mismatch"));
            }
            expected = combine(expected, input.original_requirements())?;
        }
        let expected = expected.total().map_err(|_| source("generation live subtotal overflow"))?;
        if expected.device != 0 || expected.host > self.terminal.live_generation_bytes().host {
            return Err(source("generation originals did not close before source planning"));
        }
        Ok(expected)
    }
    /// Descriptive same-ledger originals, including case owner slots and
    /// planning startup. This never issues credit or replaces a reservation.
    pub(super) fn current_original_bytes(&self) -> Result<Bytes> {
        self.owned_generation_bytes()?;
        Ok(self.ledger.snapshot().current)
    }
    pub(crate) fn original_enclosing_bytes(&self) -> Result<Bytes> {
        let expected = self.owned_generation_bytes()?;
        if expected != self.ledger.snapshot().current {
            return Err(source("generation ledger is not pristine before planning startup"));
        }
        Ok(expected)
    }
    // Only the source descriptor's private constructor calls this, using its
    // fixed frame/closure census. This owns bytes, not execution authority.
    pub(super) fn claim_source_descriptor(&self, requirements: Requirements) -> Result<Reservation> {
        if !self.planning_started.get() || requirements.total()
            .map_err(|_| source("descriptor requirements overflow"))?.device != 0 {
            return Err(source("source descriptor requires the original planning ledger"));
        }
        self.ledger.admit_phase(requirements).map_err(|_| source("source descriptor admission failed"))
    }

    pub(crate) fn owns_sources(&self, views: &[InitialNativeSource<'_>]) -> bool {
        views.len() == N && self.inputs.iter().zip(views).all(|(input, view)| {
            input.as_ref().and_then(|input| input.view().ok()).is_some_and(|owned| {
                core::ptr::eq(owned.statement(), view.statement())
                    && core::ptr::eq(owned.proof(), view.proof()) && owned.identity() == view.identity()
            })
        })
    }
}
impl FreshGenerationBatch<3> {
    pub(crate) fn views(&self) -> Result<[InitialNativeSource<'_>; 3]> {
        Ok([self.inputs[0].as_ref().ok_or_else(|| source("missing input 0"))?.view().map_err(source)?,
            self.inputs[1].as_ref().ok_or_else(|| source("missing input 1"))?.view().map_err(source)?,
            self.inputs[2].as_ref().ok_or_else(|| source("missing input 2"))?.view().map_err(source)?])
    }
}
impl FreshGenerationBatch<4> {
    pub(crate) fn views(&self) -> Result<[InitialNativeSource<'_>; 4]> {
        Ok([self.inputs[0].as_ref().ok_or_else(|| source("missing input 0"))?.view().map_err(source)?,
            self.inputs[1].as_ref().ok_or_else(|| source("missing input 1"))?.view().map_err(source)?,
            self.inputs[2].as_ref().ok_or_else(|| source("missing input 2"))?.view().map_err(source)?,
            self.inputs[3].as_ref().ok_or_else(|| source("missing input 3"))?.view().map_err(source)?])
    }
}

pub(crate) mod caches;
