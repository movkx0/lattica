//! Closed owner-bound inspection and an opt-in fixed outer producer.
//!
//! Holds the actual compiled source, copied child inputs, compiler report and
//! request through immutable borrows, with preclaimed P/K/V and backend scope.
//! The original inspection API confers no dispatch authority. The separate
//! owned-gpu-runtime producer owns runtime and report storage before executing
//! its exact compiled source; complete graph authentication remains separate.
use super::{output, OwnedCompiledShake, HEADER, MAX_ROWS};
use crate::{
    execution::{
        pre_session_outer::{self, ClosedBackendScope, PlanningLease},
        retained_resources::{Category, Ledger, Requirements, Reservation, Snapshot},
    },
    graph_crypto::ReservedShakeRequest,
};
use core::mem::size_of;

#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    feature = "owned-gpu-runtime"
))]
mod production;
#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    feature = "owned-gpu-runtime"
))]
pub(super) use production::PreparedOuter;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Error {
    Authority,
    Source,
    Shape,
    Overflow,
    PreSession(pre_session_outer::Error),
    Output(output::Error),
}

#[derive(Clone, Copy, Debug)]
pub(super) struct Report {
    pub(super) before: Snapshot,
    pub(super) backend: pre_session_outer::Report,
    pub(super) output: output::Report,
    pub(super) source_program_token_bytes: u64,
    pub(super) source_input_token_bytes: u64,
    pub(super) request_token_bytes: u64,
    pub(super) authenticated_source_key: bool,
    pub(super) transaction_context_authenticated: bool,
    pub(super) native_production_admitted: bool,
    pub(super) workflow_admitted: bool,
}

/// No Clone/extraction/prove API. Payload borrows and output/backend claims
/// cannot outlive the actual source/request owners in their original ledger.
pub(super) struct Inspection<'compiled, 'owner, 'request> {
    _compiled: &'compiled OwnedCompiledShake<'request>,
    _request: &'owner ReservedShakeRequest,
    report: Report,
    _output: output::OutputClaim<'compiled, 'owner, 'request>,
    _backend: ClosedBackendScope<'compiled>,
}
impl Inspection<'_, '_, '_> {
    pub(super) fn report(&self) -> Report {
        self.report
    }
}

fn source_token(token: &Reservation, category: Category, ledger: &Ledger) -> Result<u64, Error> {
    let requirements = token.requirements();
    let bytes = requirements.get(category);
    if !token.belongs_to(ledger)
        || bytes.device != 0
        || requirements != Requirements::single(category, bytes)
    {
        return Err(Error::Authority);
    }
    Ok(bytes.host)
}

pub(super) fn inspect<'compiled, 'owner, 'request>(
    compiled: &'compiled OwnedCompiledShake<'request>,
    request: &'owner ReservedShakeRequest,
    ledger: &Ledger,
) -> Result<Inspection<'compiled, 'owner, 'request>, Error> {
    let before = ledger.snapshot();
    if !request.belongs_to(ledger)
        || !compiled.is_for(request.request())
        || !compiled.report.belongs_to(ledger)
    {
        return Err(Error::Authority);
    }
    // Claim fixed planner/error/report storage before inspecting source or
    // asking the core for any output, source, or backend footprint.
    let planning = PlanningLease::reserve(ledger).map_err(Error::PreSession)?;
    let program_token = source_token(&compiled._program, Category::SymbolicCompiler, ledger)?;
    let input_token = source_token(&compiled._inputs, Category::CompilerInputs, ledger)?;
    let node = &compiled.compiled;
    let summary = compiled.summary;
    if HEADER + 8 != 46
        || node.program.public_values() != 46
        || node.public.len() != 46
        || node.witness.len() != node.program.witness_values()
        || summary.padded_rows != node.program.height()
        || summary.active_rows != node.program.active_rows()
        || summary.wires != node.program.wire_count()
        || summary.input_values != node.program.witness_values()
        || !(1..=2).contains(&summary.span.segment_count)
        || summary.independent_native_verifications != summary.span.segment_count
        || !(8..=MAX_ROWS).contains(&node.program.height())
        || !node.program.height().is_power_of_two()
    {
        return Err(Error::Shape);
    }
    let program_bytes = node
        .program
        .retained_host_bytes()
        .map_err(|_| Error::Source)? as u64;
    let input_bytes = node
        .public
        .capacity()
        .checked_add(node.witness.capacity())
        .and_then(|n| n.checked_mul(size_of::<super::Val>()))
        .ok_or(Error::Overflow)? as u64;
    if program_bytes > program_token || input_bytes > input_token {
        return Err(Error::Source);
    }
    let output = output::OutputClaim::reserve(compiled, request, ledger).map_err(Error::Output)?;
    let backend = planning
        .inspect(&node.program, &node.public, &node.witness, MAX_ROWS)
        .map_err(Error::PreSession)?;
    let report = Report {
        before,
        backend: backend.report(),
        output: output.report(),
        source_program_token_bytes: program_token,
        source_input_token_bytes: input_token,
        request_token_bytes: request.bounds().requested_bytes as u64,
        authenticated_source_key: false,
        transaction_context_authenticated: false,
        native_production_admitted: false,
        workflow_admitted: false,
    };
    Ok(Inspection {
        _compiled: compiled,
        _request: request,
        report,
        _output: output,
        _backend: backend,
    })
}

const _: () = assert!(
    size_of::<Inspection<'static, 'static, 'static>>() + 8 * size_of::<Report>() + (64 << 10)
        < pre_session_outer::PLANNING_HOST as usize
);

#[cfg(all(test, feature = "owned-native-shake", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
pub(super) use production::{RetiredLeafAttempt, RetiredOuterOriginals};

#[cfg(all(test, feature = "owned-native-shake", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
pub(super) use production::{FutureHashxLeaf, PreissuedHashxLeaf, PreparedHashxLeaf, RetiredHashxLeafAttempt, RetiredHashxLeafOriginals};

#[cfg(all(target_os = "linux", target_arch = "x86_64", feature = "owned-gpu-runtime"))]
pub(super) use production::{emit_receipt, fixed_producer_report_host_bytes, validate_report, Error as ProductionError};
