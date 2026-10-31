//! First paired leaf using A040's opaque original native-to-outer attempt.
//! Every extra owner is preclaimed before native PCS assignment. No legacy
//! raw-token continuation or complete-request dispatch is constructed here.
use super::*;
use crate::{
    component_tree::owned_shake::request_merge::{
        authenticate_retired_hashx_leaf, AcceptedHashxLeafCompletion, AcceptedLeaf,
        CapturedLeafAcceptance, ParentCompileError, PreissuedLeafAcceptance,
    },
    execution::retained_resources::Snapshot,
    graph_crypto::{
        ActiveHashxOuter, CompletedNativeHashx, OuterContinuationCapacity, PreissuedHashxOuter,
        PreparedHashxOuter, PreparedNativeHashx, RetiredHashxOuter, RetiredHashxOuterOriginals,
    },
};
use core::mem::size_of_val;
use lattica_prover_p3::block_v2::{
    gpu_hash::device::ringct_runtime::Retirement,
    machine::{analysis::AdmissionError, ExecutionError},
    profile::Config,
};
use p3_batch_stark::BatchProof;

/// Pre-native source, output and independent-verifier claims. These claims must
/// all be live before PendingNativeHashx::with_outer_bridge(...).prepare().
pub(in crate::component_tree::owned_shake) struct FutureHashxLeaf<'group, 'bound, 'source, 'request>
{
    future: FutureOuter<'group, 'request, 'request>,
    acceptance: PreissuedLeafAcceptance<'bound, 'source, 'request>,
    original: Reservation,
}

pub(in crate::component_tree::owned_shake) struct PreissuedHashxLeaf<
    'group,
    'bound,
    'source,
    'request,
> {
    ticket: PreissuedHashxOuter<'request>,
    future: FutureOuter<'group, 'request, 'request>,
    acceptance: PreissuedLeafAcceptance<'bound, 'source, 'request>,
    original: Reservation,
}

struct Support<'request> {
    request: &'request ReservedShakeRequest,
    ledger: Ledger,
    wrappers: Reservation,
    reports: Reservation,
    metadata: Reservation,
    planning: PlanningLease,
    original: Reservation,
}

pub(in crate::component_tree::owned_shake) struct PreparedHashxLeaf<
    'compiled,
    'bound,
    'source,
    'request,
> {
    outer: PreparedHashxOuter<'compiled, 'request>,
    compiled: &'compiled OwnedCompiledShake<'request>,
    output: output::OutputClaim<'compiled, 'request, 'request>,
    acceptance: PreissuedLeafAcceptance<'bound, 'source, 'request>,
    support: Support<'request>,
}

/// The same retired A owner and the original B support claims. No compiler,
/// Program or witness borrow survives. There is no raw reservation extractor.
pub(in crate::component_tree::owned_shake) struct RetiredHashxLeafOriginals<'request> {
    originals: RetiredHashxOuterOriginals<'request>,
    support: Support<'request>,
}

/// Only the actual producer below constructs this correlated success owner.
pub(in crate::component_tree::owned_shake) struct RetiredHashxLeafAttempt<
    'compiled,
    'bound,
    'source,
    'request,
> {
    captured: CapturedLeafAcceptance<'compiled, 'bound, 'source, 'request>,
    output: output::RetainedNodeOutput<'request>,
    originals: RetiredHashxLeafOriginals<'request>,
}

// Obtain exact returned layouts without naming A's private error type. Function
// items are never called: these helpers only evaluate size_of::<Output>(). No
// fake runtime, ticket, retirement, result or proof is constructed for a census.
fn unary_result_bytes<Input, Output>(_: fn(Input) -> Output) -> usize {
    size_of::<Output>()
}
fn binary_result_bytes<First, Second, Output>(_: fn(First, Second) -> Output) -> usize {
    size_of::<Output>()
}
fn three_result_bytes<First, Second, Third, Output>(
    _: fn(First, Second, Third) -> Output,
) -> usize {
    size_of::<Output>()
}
fn unsafe_unary_result_bytes<Input, Output>(_: unsafe fn(Input) -> Output) -> usize {
    size_of::<Output>()
}
fn unsafe_binary_result_bytes<First, Second, Output>(
    _: unsafe fn(First, Second) -> Output,
) -> usize {
    size_of::<Output>()
}
fn unsafe_four_result_bytes<First, Second, Third, Fourth, Output>(
    _: unsafe fn(First, Second, Third, Fourth) -> Output,
) -> usize {
    size_of::<Output>()
}

fn bridge_requirement() -> Result<Requirements> {
    let parts = [
        size_of::<FutureHashxLeaf<'static, 'static, 'static, 'static>>(),
        size_of::<PreissuedHashxLeaf<'static, 'static, 'static, 'static>>(),
        size_of::<PreparedHashxLeaf<'static, 'static, 'static, 'static>>(),
        size_of::<RetiredHashxLeafAttempt<'static, 'static, 'static, 'static>>(),
        size_of::<RetiredHashxLeafOriginals<'static>>(),
        size_of::<Support<'static>>(),
        size_of::<Result<FutureHashxLeaf<'static, 'static, 'static, 'static>>>(),
        size_of::<Result<PreissuedHashxLeaf<'static, 'static, 'static, 'static>>>(),
        size_of::<Result<PreparedHashxLeaf<'static, 'static, 'static, 'static>>>(),
        size_of::<Result<RetiredHashxLeafAttempt<'static, 'static, 'static, 'static>>>(),
        size_of::<Result<AcceptedHashxLeafCompletion<'static, 'static, 'static>>>(),
        size_of::<AcceptedHashxLeafCompletion<'static, 'static, 'static>>(),
        size_of::<FutureOuter<'static, 'static, 'static>>(),
        size_of::<Result<FutureOuter<'static, 'static, 'static>>>(),
        size_of::<ReadyOuter<'static, 'static, 'static>>(),
        size_of::<Result<ReadyOuter<'static, 'static, 'static>>>(),
        size_of::<PreissuedHashxOuter<'static>>(),
        size_of::<PreparedNativeHashx<'static>>(),
        size_of::<CompletedNativeHashx<'static>>(),
        size_of::<Result<CompletedNativeHashx<'static>>>(),
        size_of::<RetiredHashxOuter<'static>>(),
        size_of::<PreparedHashxOuter<'static, 'static>>(),
        size_of::<ActiveHashxOuter<'static, 'static>>(),
        size_of::<RetiredHashxOuterOriginals<'static>>(),
        size_of::<OuterContinuationCapacity>(),
        three_result_bytes(PreparedNativeHashx::check_outer_request),
        unary_result_bytes(PreparedNativeHashx::outer_continuation_capacity),
        binary_result_bytes(PreparedNativeHashx::bind_outer_backend),
        unsafe_binary_result_bytes(PreparedNativeHashx::produce_for_outer),
        binary_result_bytes(PreissuedHashxOuter::finish_native),
        unsafe_four_result_bytes(RetiredHashxOuter::bind),
        unsafe_unary_result_bytes(PreparedHashxOuter::start),
        unary_result_bytes(ActiveHashxOuter::finish),
        binary_result_bytes(crate::opencl::Session::check_reserved_runtime),
        size_of::<PreissuedLeafAcceptance<'static, 'static, 'static>>(),
        size_of::<CapturedLeafAcceptance<'static, 'static, 'static, 'static>>(),
        size_of::<core::result::Result<(), ParentCompileError>>(),
        size_of::<core::result::Result<(), crate::component_tree::owned_shake::source_shape::Error>>(
        ),
        size_of::<
            core::result::Result<
                AcceptedHashxLeafCompletion<'static, 'static, 'static>,
                ParentCompileError,
            >,
        >(),
        size_of::<(
            AcceptedLeaf<'static, 'static, 'static>,
            RetiredHashxLeafOriginals<'static>,
        )>(),
        size_of::<
            core::result::Result<
                CapturedLeafAcceptance<'static, 'static, 'static, 'static>,
                ParentCompileError,
            >,
        >(),
        size_of::<
            core::result::Result<output::OutputClaim<'static, 'static, 'static>, output::Error>,
        >(),
        size_of::<core::result::Result<output::RetainedNodeOutput<'static>, output::Error>>(),
        size_of::<(
            output::RetainedNodeOutput<'static>,
            CapturedLeafAcceptance<'static, 'static, 'static, 'static>,
        )>(),
        size_of::<
            Result<(
                output::RetainedNodeOutput<'static>,
                CapturedLeafAcceptance<'static, 'static, 'static, 'static>,
            )>,
        >(),
        size_of::<(
            CapturedLeafAcceptance<'static, 'static, 'static, 'static>,
            output::RetainedNodeOutput<'static>,
            RetiredHashxLeafOriginals<'static>,
            Ledger,
        )>(),
        size_of::<RegisteredProgram>(),
        size_of::<(RegisteredProgram, Report)>(),
        size_of::<core::result::Result<(RegisteredProgram, Report), AdmissionError>>(),
        size_of::<AdmissionError>(),
        size_of::<(BatchProof<Config>, Report)>(),
        size_of::<core::result::Result<(BatchProof<Config>, Report), ExecutionError>>(),
        size_of::<NodeKey>(),
        size_of::<NodeProof>(),
        size_of::<Report>(),
        size_of::<Request>(),
        size_of::<Retirement>(),
        size_of::<Result<Retirement>>(),
        size_of::<Snapshot>(),
        size_of::<Requirements>(),
        size_of::<Result<Requirements>>(),
        size_of::<Reservation>(),
        size_of::<Ledger>(),
        size_of::<Bytes>(),
        size_of::<Result<()>>(),
        size_of::<core::result::Result<(), String>>(),
        size_of::<std::time::Instant>(),
    ];
    // All entries count eight caller/forwarding/destructure/closure/result
    // copies. Helper arrays, checked arithmetic, function pointers and bounded
    // diagnostics are additional; no move/inlining/tail-call credit is used.
    let helper = size_of_val(&parts)
        .checked_add(32 << 10)
        .and_then(|bytes| bytes.checked_mul(8))
        .ok_or(Error::Shape)?;
    let host = parts.into_iter().try_fold(helper, |sum, bytes| {
        bytes
            .checked_mul(8)
            .and_then(|bytes| sum.checked_add(bytes))
            .ok_or(Error::Shape)
    })?;
    Ok(Requirements::single(
        Category::PhaseScratch,
        Bytes {
            host: u64::try_from(host).map_err(|_| Error::Shape)?,
            device: 0,
        },
    ))
}

fn check_bridge(original: &Reservation, ledger: &Ledger) -> Result<()> {
    if !original.belongs_to(ledger) || original.requirements() != bridge_requirement()? {
        return Err(Error::Authority);
    }
    Ok(())
}

impl<'group, 'bound, 'source, 'request> FutureHashxLeaf<'group, 'bound, 'source, 'request> {
    pub(in crate::component_tree::owned_shake) fn reserve_before_native(
        source: &'group GroupSourceBound<'request>,
        group: &GroupCompilePlan<'request>,
        request: &'request ReservedShakeRequest,
        acceptance: PreissuedLeafAcceptance<'bound, 'source, 'request>,
        ledger: &Ledger,
    ) -> Result<Self> {
        let original = ledger
            .admit_phase(bridge_requirement()?)
            .map_err(|_| Error::Shape)?;
        acceptance
            .check_first_hashx_source(source, group, request, ledger)
            .map_err(|_| Error::Shape)?;
        let future = FutureOuter::reserve_before_native(source, group, request, ledger)?;
        Ok(Self {
            future,
            acceptance,
            original,
        })
    }

    /// The actual native preparation must already include both original bridge
    /// claims and every B compiler/output/verifier/planner/source claim.
    pub(in crate::component_tree::owned_shake) fn complete_before_native(
        self,
        native: &mut PreparedNativeHashx<'request>,
    ) -> Result<PreissuedHashxLeaf<'group, 'bound, 'source, 'request>> {
        check_bridge(&self.original, &self.future.ledger)?;
        native
            .check_outer_request(self.future.request, &self.future.ledger)
            .map_err(|_| Error::Authority)?;
        let capacity = native
            .outer_continuation_capacity()
            .map_err(|_| Error::Authority)?;
        let ready = self.future.complete_before_native(
            capacity.startup,
            capacity.pcs,
            capacity.retained_tree_host_bytes,
        )?;
        let ReadyOuter {
            future, backend, ..
        } = ready;
        let ticket = native
            .bind_outer_backend(backend)
            .map_err(|_| Error::Authority)?;
        Ok(PreissuedHashxLeaf {
            ticket,
            future,
            acceptance: self.acceptance,
            original: self.original,
        })
    }
}

impl<'bound, 'source, 'request> PreissuedHashxLeaf<'_, 'bound, 'source, 'request> {
    /// # Safety
    /// Preserve the immutable process and exclusive physical-device guard
    /// through all native and later outer retirement, including failures.
    pub(in crate::component_tree::owned_shake) unsafe fn produce_native(
        &self,
        native: PreparedNativeHashx<'request>,
    ) -> Result<CompletedNativeHashx<'request>> {
        check_bridge(&self.original, &self.future.ledger)?;
        unsafe { native.produce_for_outer(&self.ticket) }.map_err(|_| Error::Proof)
    }

    /// All ten native children must have moved into separately preclaimed B
    /// ownership. Only the exact original compiled paired Leaf0 is accepted.
    /// # Safety
    /// The same original immutable/exclusive guard survives outer completion.
    pub(in crate::component_tree::owned_shake) unsafe fn finish_native<'compiled>(
        self,
        native: CompletedNativeHashx<'request>,
        compiled: &'compiled OwnedCompiledShake<'request>,
    ) -> Result<PreparedHashxLeaf<'compiled, 'bound, 'source, 'request>> {
        check_bridge(&self.original, &self.future.ledger)?;
        self.future
            .source
            .check_compiled(compiled, &self.future.ledger)
            .map_err(|_| Error::Shape)?;
        self.acceptance
            .check_compiled(compiled, self.future.request, &self.future.ledger)
            .map_err(|_| Error::Shape)?;
        let outer = self
            .ticket
            .finish_native(native)
            .map_err(|_| Error::Authority)?;
        let FutureOuter {
            request,
            output,
            ledger,
            wrappers,
            reports,
            metadata,
            planning,
            ..
        } = self.future;
        let support = Support {
            request,
            ledger,
            wrappers,
            reports,
            metadata,
            planning,
            original: self.original,
        };
        support.check(&support.ledger)?;
        let output = output
            .attach(compiled, &support.ledger)
            .map_err(Error::Output)?;
        let node = &compiled.compiled;
        let outer = unsafe { outer.bind(&node.program, &node.public, &node.witness) }
            .map_err(|_| Error::Shape)?;
        Ok(PreparedHashxLeaf {
            outer,
            compiled,
            output,
            acceptance: self.acceptance,
            support,
        })
    }
}

impl Support<'_> {
    fn check(&self, ledger: &Ledger) -> Result<()> {
        check_bridge(&self.original, ledger)?;
        let wrappers = Requirements::single(
            Category::PhaseScratch,
            Bytes {
                host: FixedOuterOclStorage::fixed()
                    .map_err(|_| Error::Shape)?
                    .required_host_bytes() as u64,
                device: 0,
            },
        );
        if !self.request.belongs_to(ledger)
            || !self.wrappers.belongs_to(ledger)
            || self.wrappers.requirements() != wrappers
            || !self.reports.belongs_to(ledger)
            || self.reports.requirements() != report_requirement()?
            || !self.metadata.belongs_to(ledger)
            || self.metadata.requirements() != metadata_requirement()?
            || !self.planning.belongs_to(ledger)
        {
            return Err(Error::Authority);
        }
        Ok(())
    }
}

impl RetiredHashxLeafOriginals<'_> {
    pub(in crate::component_tree::owned_shake) fn source_authentication_retirement(
        &self,
        ledger: &Ledger,
    ) -> Result<Retirement> {
        self.support.check(ledger)?;
        self.originals
            .check(self.support.request, ledger)
            .map_err(|_| Error::Authority)
    }
}

impl<'compiled, 'bound, 'source, 'request>
    RetiredHashxLeafAttempt<'compiled, 'bound, 'source, 'request>
{
    pub(in crate::component_tree::owned_shake) fn into_original_parts(
        self,
    ) -> (
        CapturedLeafAcceptance<'compiled, 'bound, 'source, 'request>,
        output::RetainedNodeOutput<'request>,
        RetiredHashxLeafOriginals<'request>,
        Ledger,
    ) {
        let ledger = self.originals.support.ledger.clone();
        (self.captured, self.output, self.originals, ledger)
    }
}

impl<'compiled, 'bound, 'source, 'request> PreparedHashxLeaf<'compiled, 'bound, 'source, 'request> {
    /// # Safety
    /// Preserve the original process/device guard through this actual outer
    /// attempt and exact retirement. No fallback, retry or new admission exists.
    pub(in crate::component_tree::owned_shake) unsafe fn produce_authenticated_leaf(
        self,
    ) -> Result<AcceptedHashxLeafCompletion<'bound, 'source, 'request>> {
        let attempt = unsafe { self.produce_source_attempt() }?;
        authenticate_retired_hashx_leaf(attempt).map_err(|_| Error::Shape)
    }

    unsafe fn produce_source_attempt(
        self,
    ) -> Result<RetiredHashxLeafAttempt<'compiled, 'bound, 'source, 'request>> {
        let Self {
            outer,
            compiled,
            output,
            acceptance,
            support,
        } = self;
        support.check(&support.ledger)?;
        acceptance
            .check_compiled(compiled, support.request, &support.ledger)
            .map_err(|_| Error::Shape)?;
        let active = unsafe { outer.start() }.map_err(|_| Error::Runtime)?;
        let attempted: Result<(
            output::RetainedNodeOutput<'request>,
            CapturedLeafAcceptance<'compiled, 'bound, 'source, 'request>,
        )> = (|| {
            let runtime_guard = active
                .session()
                .check_reserved_runtime(&support.ledger)
                .map_err(|_| Error::Runtime)?;
            let backend = active.backend();
            backend
                .check_execution_selection()
                .map_err(|_| Error::Runtime)?;
            let request = Request {
                policy: Policy::GpuRequired,
                emit_report: false,
            };
            let node = &compiled.compiled;
            let (registered, report) =
                RegisteredProgram::new_with_request_and_identity_hint_and_report(
                    MachineAir::from_shared_program(Arc::clone(&node.program)),
                    backend.host_budget_bytes(),
                    request,
                    None,
                )
                .map_err(|_| Error::Setup)?;
            validate_report(&report, CoverageScope::Preprocessing)?;
            emit_receipt(&report)?;
            let setup_elapsed_ns = report.elapsed_ns;
            drop(report);
            let captured = acceptance
                .capture(compiled, &registered, &support.ledger)
                .map_err(|_| Error::Shape)?;
            let key = NodeKey {
                spec: node.spec.clone(),
                height: node.program.height(),
                cap: registered.preprocessing_cap().roots().to_vec(),
                verifier: Arc::new(registered.verifier()),
            };
            let (proof, report) = registered
                .into_prove_outer_with_request_and_report(backend, request)
                .map_err(|_| Error::Proof)?;
            validate_report(&report, CoverageScope::RegisteredProof)?;
            emit_receipt(&report)?;
            let proving_elapsed_ns = report.elapsed_ns;
            drop(report);
            let output = output
                .verify_and_retain(
                    key,
                    NodeProof {
                        public: node.public.clone(),
                        proof,
                    },
                    setup_elapsed_ns,
                    proving_elapsed_ns,
                )
                .map_err(Error::Output)?;
            drop(runtime_guard);
            Ok((output, captured))
        })();
        // Every returned setup/proof/output failure first consumes the same
        // actual active Session; no successful output can bypass retirement.
        let before = support.ledger.snapshot();
        let originals = active.finish().map_err(|_| Error::Runtime)?;
        if support.ledger.snapshot() != before {
            return Err(Error::Authority);
        }
        let (output, captured) = attempted?;
        if !output.belongs_to(&support.ledger) || !output.report().independent_verification_complete
        {
            return Err(Error::Authority);
        }
        let originals = RetiredHashxLeafOriginals { originals, support };
        originals.source_authentication_retirement(&originals.support.ledger)?;
        Ok(RetiredHashxLeafAttempt {
            captured,
            output,
            originals,
        })
    }
}

#[cfg(test)]
mod tests;
