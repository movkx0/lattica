//! Closed, test-only inspection of a completed SHAKE compiler owner.
//!
//! This binds diagnostic declarations to actual same-ledger owners and keeps
//! scratch/backend host charges through report use. It cannot produce a proof,
//! extract a token, start an execution phase, or authorize native production.
//! Source-derived output/key/lifecycle ceilings are held before backend planning.
//! The private payload owner has no callable producer or authentication path,
//! so the diagnostic still cannot admit native production or a workflow.
use super::{output, OwnedCompiledShake, HEADER, MAX_ROWS};
use crate::{
    execution::{
        phase_lifecycle::{PhaseCapability, Status},
        retained_resources::{Bytes, Category, Ledger, Requirements, Reservation, Snapshot},
    },
    graph_crypto::ReservedShakeRequest,
};
use core::mem::size_of;
use lattica_prover_p3::block_v2::machine::{
    inspect_registered_gpu_outer, RegisteredGpuLimits, RegisteredGpuOuterFootprint,
    RegisteredGpuOuterHostBounds,
};

const WORKER_HOST: u64 = 32 << 30;
const MANAGED_DEVICE: u64 = 8 << 30;
const CONTEXT_DEVICE: u64 = 4 << 30;
const CALLER_HOST: u64 = 1 << 20;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Error {
    Phase,
    Authority,
    Source,
    Shape,
    ScratchAdmission,
    ExecutionSelection,
    BackendFootprint,
    BackendReservation,
    OutputReservation,
    Overflow,
}

#[derive(Clone, Copy, Debug)]
pub(super) struct Report {
    pub(super) footprint: RegisteredGpuOuterFootprint,
    pub(super) before: Snapshot,
    pub(super) while_reserved: Snapshot,
    pub(super) enclosing_host_bytes: u64,
    pub(super) compiled_program_token_host_bytes: u64,
    pub(super) compiled_input_token_host_bytes: u64,
    pub(super) request_host_bytes: u64,
    pub(super) backend_host_reserved_bytes: u64,
    pub(super) device_required_bytes: u64,
    pub(super) device_reserved_bytes: u64,
    pub(super) recursive_output_bound_bytes: Option<u64>,
    pub(super) output: output::Report,
    pub(super) native_production_admitted: bool,
    pub(super) transaction_context_authenticated: bool,
    pub(super) workflow_admitted: bool,
}

/// Immutable input borrows and the exclusive capability borrow outlive both
/// diagnostic reservations. Copying its report never copies their authority.
pub(super) struct Inspection<'scope, 'context, 'request> {
    _output: &'scope OwnedCompiledShake<'request>,
    _request: &'scope ReservedShakeRequest,
    _capability: &'scope mut PhaseCapability<'context>,
    report: Report,
    _backend: Reservation,
    _output_claim: output::OutputClaim<'scope, 'scope, 'request>,
    _scratch: Reservation,
}
impl Inspection<'_, '_, '_> {
    pub(super) fn report(&self) -> Report {
        self.report
    }
}

// The remaining fixed caller envelope covers the maintained core planner's
// bounded Vec scratch, physical-selection metadata and short error strings.
// All headers here are inline; no report Vec or JSON tree is constructed.
const _: () = assert!(
    size_of::<Inspection<'static, 'static, 'static>>() + 8 * size_of::<Snapshot>() + (64 << 10)
        < CALLER_HOST as usize
);

fn add(a: u64, b: u64) -> Result<u64, Error> {
    a.checked_add(b).ok_or(Error::Overflow)
}

fn source_token(token: &Reservation, category: Category, ledger: &Ledger) -> Result<u64, Error> {
    let request = token.requirements();
    let bytes = request.get(category);
    if !token.belongs_to(ledger)
        || bytes.device != 0
        || request != Requirements::single(category, bytes)
    {
        return Err(Error::Authority);
    }
    Ok(bytes.host)
}

fn hold_backend(ledger: &Ledger, native: u64, trees: u64) -> Result<(Reservation, u64), Error> {
    let current = ledger.snapshot();
    if current.allowance.host > WORKER_HOST || current.allowance.device > MANAGED_DEVICE {
        return Err(Error::Authority);
    }
    if native == 0 || native > 24 << 30 || trees > 8 << 30 {
        return Err(Error::BackendReservation);
    }
    // A CPU compiler capability has no GPU allowance. Report that missing
    // authority rather than manufacturing it from a numerical device plan.
    let device = if current
        .allowance
        .device
        .checked_sub(current.current.device)
        .is_some_and(|bytes| bytes >= MANAGED_DEVICE)
    {
        MANAGED_DEVICE
    } else {
        0
    };
    let token = ledger
        .admit_phase(Requirements::single(
            Category::PhaseScratch,
            Bytes {
                host: add(native, trees)?,
                device,
            },
        ))
        .map_err(|_| Error::BackendReservation)?;
    Ok((token, device))
}

pub(super) fn inspect<'scope, 'context, 'request>(
    output: &'scope OwnedCompiledShake<'request>,
    request: &'scope ReservedShakeRequest,
    capability: &'scope mut PhaseCapability<'context>,
) -> Result<Inspection<'scope, 'context, 'request>, Error> {
    if capability.status() != Status::Ready {
        return Err(Error::Phase);
    }
    let ledger = capability.ledger();
    let before = ledger.snapshot();
    if before.allowance.host > WORKER_HOST
        || before.allowance.device > MANAGED_DEVICE
        || !request.belongs_to(ledger)
        || !output.is_for(request.request())
        || !output.report.belongs_to(ledger)
    {
        return Err(Error::Authority);
    }
    let program_token = source_token(&output._program, Category::SymbolicCompiler, ledger)?;
    let input_token = source_token(&output._inputs, Category::CompilerInputs, ledger)?;
    let scratch = ledger
        .admit_phase(Requirements::single(
            Category::PhaseScratch,
            Bytes {
                host: CALLER_HOST,
                device: 0,
            },
        ))
        .map_err(|_| Error::ScratchAdmission)?;
    let compiled = &output.compiled;
    let summary = output.summary;
    let program = &compiled.program;
    if HEADER + 8 != 46
        || program.public_values() != 46
        || compiled.public.len() != 46
        || compiled.witness.len() != program.witness_values()
        || summary.padded_rows != program.height()
        || summary.active_rows != program.active_rows()
        || summary.wires != program.wire_count()
        || summary.input_values != program.witness_values()
        || !(1..=2).contains(&summary.span.segment_count)
        || summary.independent_native_verifications != summary.span.segment_count
        || !(8..=MAX_ROWS).contains(&program.height())
        || !program.height().is_power_of_two()
    {
        return Err(Error::Shape);
    }
    let source_program = program.retained_host_bytes().map_err(|_| Error::Source)? as u64;
    let source_inputs = compiled
        .public
        .capacity()
        .checked_add(compiled.witness.capacity())
        .and_then(|values| values.checked_mul(size_of::<super::Val>()))
        .ok_or(Error::Overflow)? as u64;
    if source_program > program_token || source_inputs > input_token {
        return Err(Error::Source);
    }
    // Enclosing storage was deducted before the context created this ledger.
    // Carry that deduction into the complete worker equation; do not restore it.
    let enclosing_host = WORKER_HOST - before.allowance.host;
    let output_claim = output::OutputClaim::reserve(output, request, ledger)
        .map_err(|_| Error::OutputReservation)?;
    let output_report = output_claim.report();
    let outer = RegisteredGpuOuterHostBounds {
        existing_host_bytes: add(enclosing_host, before.current.host)?,
        output_host_bytes: output_report.total_claimed_host_bytes,
        adapter_scratch_host_bytes: CALLER_HOST,
    };
    let limits = RegisteredGpuLimits::new(WORKER_HOST, MANAGED_DEVICE, CONTEXT_DEVICE, MAX_ROWS)
        .map_err(|_| Error::ExecutionSelection)?;
    let footprint =
        inspect_registered_gpu_outer(program, &compiled.public, &compiled.witness, limits, outer)
            .map_err(|_| Error::BackendFootprint)?;
    let backend_host = add(
        footprint.native_host_budget_bytes,
        footprint.full_tree_quota_host_bytes,
    )?;
    let (backend, device) = hold_backend(
        ledger,
        footprint.native_host_budget_bytes,
        footprint.full_tree_quota_host_bytes,
    )?;
    let while_reserved = ledger.snapshot();
    if add(enclosing_host, while_reserved.current.host)? != footprint.worker_committed_host_bytes {
        return Err(Error::BackendReservation);
    }
    let report = Report {
        footprint,
        before,
        while_reserved,
        enclosing_host_bytes: enclosing_host,
        compiled_program_token_host_bytes: program_token,
        compiled_input_token_host_bytes: input_token,
        request_host_bytes: request.bounds().requested_bytes as u64,
        backend_host_reserved_bytes: backend_host,
        device_required_bytes: MANAGED_DEVICE,
        device_reserved_bytes: device,
        recursive_output_bound_bytes: Some(output_report.recursive_output_host_bytes),
        output: output_report,
        native_production_admitted: false,
        transaction_context_authenticated: false,
        workflow_admitted: false,
    };
    Ok(Inspection {
        _output: output,
        _request: request,
        _capability: capability,
        report,
        _backend: backend,
        _output_claim: output_claim,
        _scratch: scratch,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::execution::retained_resources::WorkerAllowance;

    #[test]
    fn host_hold_uses_actual_ledger_and_does_not_invent_cpu_device_capacity() {
        let ledger = Ledger::new(WorkerAllowance {
            host: WORKER_HOST,
            device: 0,
        });
        let prior = ledger
            .reserve(
                Category::CompilerInputs,
                Bytes {
                    host: 2 << 30,
                    device: 0,
                },
            )
            .unwrap();
        let (hold, device) = hold_backend(&ledger, 24 << 30, 6 << 30).unwrap();
        assert_eq!(device, 0);
        assert_eq!(ledger.snapshot().current.host, WORKER_HOST);
        assert!(ledger
            .reserve(Category::Report, Bytes { host: 1, device: 0 })
            .is_err());
        drop(hold);
        assert_eq!(ledger.snapshot().current.host, 2 << 30);
        drop(prior);
        assert_eq!(ledger.snapshot().current, Bytes::ZERO);
    }

    #[test]
    fn held_backend_device_bytes_prevent_other_ledger_allocations() {
        let ledger = Ledger::new(WorkerAllowance {
            host: WORKER_HOST,
            device: MANAGED_DEVICE,
        });
        let before = ledger.snapshot();
        let (hold, device) = hold_backend(&ledger, 24 << 30, 8 << 30).unwrap();
        assert_eq!(device, MANAGED_DEVICE);
        assert!(ledger
            .reserve(Category::Report, Bytes { host: 0, device: 1 })
            .is_err());
        drop(hold);
        assert_eq!(ledger.snapshot().current, before.current);
        assert!(hold_backend(&ledger, 24 << 30, (8 << 30) + 1).is_err());
        assert!(hold_backend(&ledger, (24 << 30) + 1, 0).is_err());
        assert_eq!(ledger.snapshot().current, before.current);
    }
}
