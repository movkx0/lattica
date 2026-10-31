//! Original-owned native generation context and actual terminal shutdown.
//! The root generation driver separately owns fixed native input/output,
//! decoder and reference-verifier claims; this wrapper owns only context,
//! reports and the small final terminal record. No JSON escapes these owners.
use super::*;
use crate::execution::retained_resources::{Bytes, Category, Ledger, Requirements, Reservation};
use crate::opencl::{Limits, NativeSessionRecord, RetiredGenerationSession, WorkflowRuntimePlan};
use lattica_prover_p3::block_v2::native_gpu::private_spend::{
    NativeSpendOperationPlan, PrivateSpendOutput, PrivateSpendRequest, SpendEvidence, SpendLimits,
};
use lattica_prover_p3::proving::Report;
use core::mem::size_of;

pub(crate) use super::diagnostics::{NativeGenerationCompletion, NativeGenerationTotals};
mod memory;
pub(crate) mod planning_startup;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum GenerationError {
    Authority, Overflow, Resource, Startup, Busy, NativeSpend, Output, Report,
    Completion, Observation, Drain, Shutdown,
}
type GenerationResult<T> = core::result::Result<T, GenerationError>;

/// Source-only fixed plan, never dispatch authority on its own.
pub(crate) struct GenerationContextPlan {
    expected: usize,
    limits: Limits,
    runtime: Requirements,
    terminal: Requirements,
}

/// Fixed public operation summary. It is an observation, never authority to
/// accept a spend, adopt a runtime or create a terminal owner.
#[derive(Clone, Copy, serde::Serialize)]
pub(crate) struct GenerationSpendSummary {
    pub(crate) session_id: u64,
    pub(crate) ordinal: usize,
    pub(crate) elapsed_ns: u128,
    pub(crate) witness_completed_calls: u64,
    pub(crate) witness_device_calls: u64,
    pub(crate) witness_device_ns: u128,
    pub(crate) managed_bytes: usize,
    pub(crate) prelude_steps: u32,
    pub(crate) accepted_attempt_steps: u32,
    pub(crate) source_fingerprint: [u8; 32],
    pub(crate) kernel_source_sha256: &'static str,
}
impl report_transport::FixedPayload for GenerationSpendSummary {}
impl report_transport::FixedPayload for NativeSessionRecord {}
impl report_transport::FixedPayload for NativeGenerationTotals {}

#[derive(serde::Serialize)]
struct TerminalRecord {
    schema: &'static str,
    session_id: u64,
    operations: NativeGenerationTotals,
    session: NativeSessionRecord,
    stark_proofs: u64,
    registrations: u64,
}
impl report_transport::FixedPayload for TerminalRecord {}

/// Nonclone proof of the exact finished generation context. The runtime and
/// its original are gone; only this small terminal original remains retained.
pub(crate) struct NativeGenerationTerminal {
    record: TerminalRecord,
    ledger: Ledger,
    original: Reservation,
}
impl NativeGenerationTerminal {
    pub(crate) fn session_id(&self) -> u64 { self.record.session_id }
    pub(crate) fn spend_count(&self) -> usize { self.record.operations.spends as usize }
    pub(crate) fn totals(&self) -> NativeGenerationTotals { self.record.operations }
    pub(crate) fn belongs_to(&self, ledger: &Ledger) -> bool { self.original.belongs_to(ledger) }
    pub(crate) fn requirements(&self) -> Requirements { self.original.requirements() }
    /// The private root bridge must subtract ALL original generation charges
    /// still live in this ledger, including its packet/data/static claims.
    /// This numeric observation alone cannot issue a fresh planning context.
    pub(crate) fn live_generation_bytes(&self) -> Bytes { self.ledger.snapshot().current }
    /// Read-only ordering and pristine-context check. The terminal can only
    /// be constructed by consuming the actual retired generation Session.
    /// It cannot adopt a context that predates that retirement.
    pub(crate) fn validate_planning_context(&self, context: &ProvingContext) -> GenerationResult<()> {
        if !self.original.belongs_to(&self.ledger)
            || !matches!(self.spend_count(), 3 | 4)
            || context.session_id <= self.session_id()
        { return Err(GenerationError::Authority); }
        pristine_registry(context)?;
        context.workflow_enclosing_footprint().map_err(|_| GenerationError::Authority)?;
        Ok(())
    }
}

/// Fixed refusal payload, retained under its pre-start terminal/report original.
/// If cleanup was uncertain, the runtime original has been permanently kept.
pub(crate) struct GenerationFailure {
    error: GenerationError,
    original: Reservation,
}
impl GenerationFailure {
    pub(crate) fn error(&self) -> GenerationError { self.error }
}
impl core::fmt::Debug for GenerationFailure {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("GenerationFailure").field("error", &self.error).finish()
    }
}

/// Only the concrete creation method is exposed; no registry, native-STARK,
/// arbitrary callback, legacy Session or raw context reference escapes.
pub(crate) struct OwnedGenerationContext {
    context: Option<ProvingContext>,
    plan: GenerationContextPlan,
    ledger: Ledger,
    issued: usize,
    failed: bool,
    runtime: Option<Reservation>,
    terminal: Option<Reservation>,
}

fn contains(have: Requirements, need: Requirements) -> bool {
    Category::ALL.into_iter().all(|category| {
        let a = have.get(category); let b = need.get(category);
        a.host >= b.host && a.device >= b.device
    })
}

impl GenerationContextPlan {
    pub(crate) fn new(expected: usize, limits: Limits) -> GenerationResult<Self> {
        if cfg!(debug_assertions) || !matches!(expected, 3 | 4)
            || crate::host_memory_profile::HostMemoryProfile::from_worker_bytes(limits.host_bytes).is_err() || limits.device_bytes != 8 << 30
            || limits.max_rows != 1 << 20
        { return Err(GenerationError::Authority); }
        Ok(Self { expected, limits, runtime: memory::runtime_requirements()?,
            terminal: memory::terminal_requirements()? })
    }
    pub(crate) fn runtime_requirements(&self) -> Requirements { self.runtime }
    pub(crate) fn terminal_requirements(&self) -> Requirements { self.terminal }
    pub(crate) fn minimum_output_requirements() -> GenerationResult<Requirements> {
        memory::minimum_output_requirements()
    }
    pub(crate) fn total_requirements(&self) -> GenerationResult<Requirements> {
        memory::combine(self.runtime, self.terminal)
    }
    pub(crate) fn start(self, mut original: Reservation, ledger: &Ledger)
        -> Result<OwnedGenerationContext, GenerationFailure>
    {
        let valid = self.total_requirements().is_ok_and(|needed|
            original.belongs_to(ledger) && original.requirements() == needed
                && ledger.snapshot().allowance.host == self.limits.host_bytes
                && ledger.snapshot().allowance.device == 8 << 30);
        if !valid { return Err(GenerationFailure { error: GenerationError::Authority, original }); }
        let terminal = match original.split(self.terminal) {
            Ok(terminal) => terminal,
            Err(_) => return Err(GenerationFailure { error: GenerationError::Resource, original }),
        };
        // Both original owners precede all identity/Session/context allocation.
        // Ordinary startup errors cannot provide a typed cleanup receipt.
        let mut context = match ProvingContext::opencl_with_host_profile(self.limits,
            crate::host_memory_profile::HostMemoryProfile::from_worker_bytes(self.limits.host_bytes).expect("validated generation profile")) {
            Ok(context) => context,
            Err(error) => {
                // Public startup diagnostics only; bounded before any witness exists.
                eprintln!("owned_generation_startup_refused detail={:.512}", error);
                drop(error);
                core::mem::forget(original);
                return Err(GenerationFailure { error: GenerationError::Startup, original: terminal });
            }
        };
        let valid = context.workflow_enclosing_footprint().is_ok_and(|actual| {
            let expected = actual.enclosing_host_bytes.checked_add(8 << 30)
                .and_then(|bytes| bytes.checked_add(PUBLIC_METADATA_LIMIT_BYTES as u64));
            expected.is_some_and(|bytes| self.runtime.total().is_ok_and(|have| bytes <= have.host))
                && actual.managed_device_bytes == 8 << 30
        });
        if !valid {
            let retired = retire_context(context, None);
            if retired.is_ok() { drop(original); } else { core::mem::forget(original); }
            return Err(GenerationFailure { error: GenerationError::Authority, original: terminal });
        }
        // This isolated wrapper transports each actual Report under its own
        // original owner. Default ProvingContext construction is unchanged.
        context.request.emit_report = false;
        Ok(OwnedGenerationContext { context: Some(context), plan: self, ledger: ledger.clone(),
            issued: 0, failed: false, runtime: Some(original), terminal: Some(terminal) })
    }
}

fn pristine_registry(context: &ProvingContext) -> GenerationResult<()> {
    let state = context.registry.try_borrow().map_err(|_| GenerationError::Busy)?;
    if state.prepared.is_some() || !state.metadata.is_empty()
        || !state.identity_hints.entries.is_empty() || state.trace.attempted() != 0
        || state.registrations != 0 || state.prepared_hits != 0 || state.metadata_hits != 0
        || state.identity_hints_supplied != 0 || state.identity_hint_hits != 0
        || state.prepared_evictions != 0 || state.metadata_evictions != 0
        || state.metadata_capacity_evictions != 0 || state.metadata_byte_evictions != 0
        || state.metadata_identity_evictions != 0 || state.metadata_oversized_rejections != 0
        || state.registration_seconds != 0.0 || state.registration_setup_seconds != 0.0
        || state.registered_active_rows != 0 || state.registered_padded_rows != 0
        || !context.phases.workflow_census_is_unbound().map_err(|_| GenerationError::Authority)?
    { return Err(GenerationError::Completion); }
    Ok(())
}

/// The returned seal certifies only actual shutdown. All context-owned Rust
/// payloads are destroyed here before the caller releases its runtime original.
fn retire_context(mut context: ProvingContext, completion: Option<&NativeGenerationCompletion>)
    -> GenerationResult<RetiredGenerationSession>
{
    let session = context.session.take().ok_or(GenerationError::Authority)?;
    let result = session.retire_native_generation(completion);
    drop(context);
    result
}

impl OwnedGenerationContext {
    pub(crate) fn create_matrict_spend_on_gpu(&mut self, input: PrivateSpendRequest,
        source: &NativeSpendOperationPlan, operation_original: &Reservation, output_original: &Reservation)
        -> GenerationResult<(PrivateSpendOutput, GenerationSpendSummary)>
    {
        let context = self.context.as_ref().ok_or(GenerationError::Authority)?;
        // This wrapper takes the request by value, so its four backing Vecs
        // must remain covered by the same operation original while packing.
        // Root's fixture census already includes these bytes and is additive
        // to source.requirements(); this is a coverage check, not a new claim.
        let mut operation_needed = source.requirements();
        operation_needed.add(Category::PhaseScratch, Bytes {
            host: u64::try_from(source.input_backing_bytes()).map_err(|_| GenerationError::Overflow)?,
            device: 0,
        }).map_err(|_| GenerationError::Overflow)?;
        if self.failed || self.issued >= self.plan.expected
            || !operation_original.belongs_to(&self.ledger) || !output_original.belongs_to(&self.ledger)
            || core::ptr::eq(operation_original, output_original)
            || !contains(operation_original.requirements(), operation_needed)
            || !contains(output_original.requirements(), source.output_requirements())
            || !contains(output_original.requirements(), memory::minimum_output_requirements()?)
        {
            self.failed = true;
            return Err(GenerationError::Authority);
        }
        self.failed = true; // Every refusal after entry is terminal.
        source.check_request(&input).map_err(|_| GenerationError::Authority)?;
        pristine_registry(context)?;
        let (output, report, evidence) = context.create_matrict_spend_on_gpu(input, source.limits())
            .map_err(|error| { drop(error); GenerationError::NativeSpend })?;
        source.check_output(&output).map_err(|_| GenerationError::Output)?;
        source.check_evidence(&evidence).map_err(|_| GenerationError::Output)?;
        let observation = report.observations.first().ok_or(GenerationError::Report)?;
        let summary = GenerationSpendSummary { session_id: context.session_id, ordinal: self.issued,
            elapsed_ns: report.elapsed_ns, witness_completed_calls: observation.completed_calls,
            witness_device_calls: observation.device_calls, witness_device_ns: observation.device_ns,
            managed_bytes: evidence.managed_bytes, prelude_steps: evidence.prelude_steps,
            accepted_attempt_steps: evidence.accepted_attempt_steps,
            source_fingerprint: source.source_fingerprint(),
            kernel_source_sha256: evidence.kernel_source_sha256 };
        report_transport::emit(b"owned_generation_report ", &report).map_err(|_| GenerationError::Report)?;
        report_transport::emit(b"owned_generation_spend ", &summary).map_err(|_| GenerationError::Report)?;
        drop(report);
        drop(evidence);
        self.issued += 1;
        self.failed = false;
        Ok((output, summary))
    }

    pub(crate) fn finish(mut self) -> Result<NativeGenerationTerminal, GenerationFailure> {
        let context = self.context.take().expect("owned generation context");
        let completion = (|| {
            if self.failed || self.issued != self.plan.expected { return Err(GenerationError::Completion); }
            pristine_registry(&context)?;
            context.diagnostics.native_generation_completion(context.session_id, self.plan.expected)
        })();
        let retired = retire_context(context, completion.as_ref().ok());
        let runtime = self.runtime.take().expect("owned generation runtime");
        let terminal = self.terminal.take().expect("owned generation terminal");
        let retired = match retired {
            Ok(retired) => { drop(runtime); retired }
            Err(error) => {
                core::mem::forget(runtime);
                return Err(GenerationFailure { error, original: terminal });
            }
        };
        let result = completion.and_then(|completion| {
            let record = TerminalRecord { schema: "ringct-native-generation-terminal-v1",
                session_id: completion.session_id(), operations: completion.totals(),
                session: retired.record()?, stark_proofs: 0, registrations: 0 };
            report_transport::emit(b"owned_generation_terminal ", &record)
                .map_err(|_| GenerationError::Report)?;
            Ok(record)
        });
        match result {
            Ok(record) => Ok(NativeGenerationTerminal { record, ledger: self.ledger.clone(), original: terminal }),
            Err(error) => Err(GenerationFailure { error, original: terminal }),
        }
    }
}
impl Drop for OwnedGenerationContext {
    fn drop(&mut self) {
        if let Some(context) = self.context.take() {
            let retired = retire_context(context, None);
            if let Some(runtime) = self.runtime.take() {
                if retired.is_ok() { drop(runtime); } else { core::mem::forget(runtime); }
            }
        }
    }
}

#[cfg(test)]
mod tests;
