//! Closed parent component production from exact authenticated child compiler.
//! All output/verifier/report/wrapper/caller claims precede native preparation.
//! A's succession proves lifecycle/order; this module separately verifies the
//! actual registered source and output. Complete-request dispatch stays closed.
use super::Error as ParentCompileError;
use super::*;
use crate::{
    component_tree::owned_shake::{
        outer_producer::{
            emit_receipt, fixed_producer_report_host_bytes, validate_report,
            ProductionError as Error,
        },
        output, MAX_ROWS,
    },
    execution::{pre_session_outer::PlanningLease, retained_resources::Snapshot},
    graph_crypto::{
        ActiveHashxOuter, HashxOuterStep, OuterContinuationCapacity, PreparedHashxOuter,
        PreparedNativeHashx, ReservedShakeRequest, RetiredHashxOuterOriginals,
    },
};
use lattica_prover_p3::{
    block_v2::machine::{
        OuterSourceEnvelope, OuterSourceShape, PreissuedOuterBackend, RegisteredGpuLimits,
    },
    proving::{
        proof_storage::outer_ocl::FixedOuterOclStorage, CoverageScope, Policy, Report, Request,
    },
};
type Result<T> = core::result::Result<T, Error>;
use lattica_prover_p3::block_v2::{
    gpu_hash::device::ringct_runtime::Retirement,
    machine::{analysis::AdmissionError, ExecutionError},
    profile::Config,
};
use p3_batch_stark::BatchProof;

// This child alone composes actual native production, the original compiler
// bank and every accepted edge. No standalone completion is converted into it.
mod sequence;
#[cfg(all(test, feature = "owned-native-shake", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
pub(in crate::component_tree::owned_shake) use sequence::{
    InteriorOpeningAction, InteriorOpeningMeasurements,
    RootOpeningRecheckAction, RootOpeningMeasurements,
    RootTransportAction, RootTransportMeasurements,
    RootPublicRecheckAction, RootPublicRecheckReport,
};

pub(super) struct FutureHashxParent<'bound, 'source, 'request> {
    source: &'bound ParentSourceBound<'source, 'request>,
    ordinal: usize,
    shape: OuterSourceShape,
    output: output::PreissuedParentOutput<'request>,
    acceptance: PreissuedParentAcceptance<'bound, 'source, 'request>,
    support: Support<'request>,
}

pub(super) struct PreissuedHashxParent<'bound, 'source, 'request> {
    future: FutureHashxParent<'bound, 'source, 'request>,
}

// Report/output/verifier owners die before original enclosing claims.
struct Support<'request> {
    request: &'request ReservedShakeRequest,
    ledger: Ledger,
    wrappers: Reservation,
    reports: Reservation,
    metadata: Reservation,
    planning: PlanningLease,
    original: Reservation,
}

pub(super) struct AcceptedHashxParentCompletion<'bound, 'source, 'request> {
    parent: AcceptedParent<'bound, 'source, 'request>,
    originals: RetiredHashxOuterOriginals<'request>,
    support: Support<'request>,
}

fn result_bytes<I, O>(_: fn(I) -> O) -> usize {
    size_of::<O>()
}
fn two_result_bytes<A, B, O>(_: fn(A, B) -> O) -> usize {
    size_of::<O>()
}
fn three_result_bytes<A, B, C, O>(_: fn(A, B, C) -> O) -> usize {
    size_of::<O>()
}
fn unsafe_result_bytes<I, O>(_: unsafe fn(I) -> O) -> usize {
    size_of::<O>()
}
fn bind_result_bytes<A, B, C, D, E, O>(_: unsafe fn(A, B, C, D, E) -> O) -> usize {
    size_of::<O>()
}

fn caller_requirement() -> Result<Requirements> {
    let parts = [
        size_of::<FutureHashxParent<'static, 'static, 'static>>(),
        size_of::<PreissuedHashxParent<'static, 'static, 'static>>(),
        size_of::<AcceptedHashxParentCompletion<'static, 'static, 'static>>(),
        size_of::<Result<FutureHashxParent<'static, 'static, 'static>>>(),
        size_of::<Result<PreissuedHashxParent<'static, 'static, 'static>>>(),
        size_of::<Result<AcceptedHashxParentCompletion<'static, 'static, 'static>>>(),
        size_of::<(
            PreissuedHashxParent<'static, 'static, 'static>,
            PreissuedOuterBackend,
        )>(),
        size_of::<
            Result<(
                PreissuedHashxParent<'static, 'static, 'static>,
                PreissuedOuterBackend,
            )>,
        >(),
        size_of::<Support<'static>>(),
        size_of::<OuterSourceShape>(),
        size_of::<OuterSourceEnvelope>(),
        size_of::<PreissuedOuterBackend>(),
        size_of::<RegisteredGpuLimits>(),
        size_of::<OuterContinuationCapacity>(),
        size_of::<PreparedHashxOuter<'static, 'static>>(),
        size_of::<ActiveHashxOuter<'static, 'static>>(),
        size_of::<RetiredHashxOuterOriginals<'static>>(),
        size_of::<HashxOuterStep>(),
        size_of::<(HashxOuterStep, HashxOuterStep)>(),
        size_of::<Result<(HashxOuterStep, HashxOuterStep)>>(),
        size_of::<PreissuedParentAcceptance<'static, 'static, 'static>>(),
        size_of::<CapturedParentAcceptance<'static, 'static, 'static, 'static>>(),
        size_of::<AcceptedParent<'static, 'static, 'static>>(),
        size_of::<
            core::result::Result<
                PreissuedParentAcceptance<'static, 'static, 'static>,
                ParentCompileError,
            >,
        >(),
        size_of::<
            core::result::Result<
                CapturedParentAcceptance<'static, 'static, 'static, 'static>,
                ParentCompileError,
            >,
        >(),
        size_of::<
            core::result::Result<AcceptedParent<'static, 'static, 'static>, ParentCompileError>,
        >(),
        size_of::<output::PreissuedParentOutput<'static>>(),
        size_of::<core::result::Result<output::PreissuedParentOutput<'static>, output::Error>>(),
        size_of::<output::RetainedNodeOutput<'static>>(),
        size_of::<core::result::Result<output::RetainedNodeOutput<'static>, output::Error>>(),
        size_of::<(
            output::RetainedNodeOutput<'static>,
            CapturedParentAcceptance<'static, 'static, 'static, 'static>,
        )>(),
        size_of::<
            Result<(
                output::RetainedNodeOutput<'static>,
                CapturedParentAcceptance<'static, 'static, 'static, 'static>,
            )>,
        >(),
        size_of::<RegisteredProgram>(),
        size_of::<(RegisteredProgram, Report)>(),
        size_of::<core::result::Result<(RegisteredProgram, Report), AdmissionError>>(),
        size_of::<(BatchProof<Config>, Report)>(),
        size_of::<core::result::Result<(BatchProof<Config>, Report), ExecutionError>>(),
        size_of::<NodeKey>(),
        size_of::<NodeProof>(),
        size_of::<Report>(),
        size_of::<Request>(),
        size_of::<Retirement>(),
        size_of::<Snapshot>(),
        size_of::<Requirements>(),
        size_of::<Result<Requirements>>(),
        size_of::<Reservation>(),
        size_of::<Ledger>(),
        size_of::<Bytes>(),
        size_of::<Result<()>>(),
        size_of::<core::result::Result<(), String>>(),
        size_of::<std::time::Instant>(),
        size_of::<&CompiledLeafParent<'static, 'static, 'static>>(),
        three_result_bytes(PreparedNativeHashx::check_outer_request),
        result_bytes(PreparedNativeHashx::outer_continuation_capacity),
        three_result_bytes(RetiredHashxOuterOriginals::check),
        result_bytes(RetiredHashxOuterOriginals::outer_step),
        bind_result_bytes(RetiredHashxOuterOriginals::bind_successor),
        unsafe_result_bytes(PreparedHashxOuter::start),
        result_bytes(ActiveHashxOuter::finish),
        two_result_bytes(crate::opencl::Session::check_reserved_runtime),
        three_result_bytes(OuterSourceEnvelope::inspect),
        result_bytes(OuterSourceEnvelope::preissue),
        size_of::<&ParentSourceBound<'static, 'static>>(),
        size_of::<core::result::Result<OuterSourceShape, ParentCompileError>>(),
        size_of::<core::result::Result<(), ParentCompileError>>(),
    ];
    let helpers = 64usize << 10;
    let array = 8usize
        .checked_mul(core::mem::size_of_val(&parts))
        .ok_or(Error::Shape)?;
    let host = parts.into_iter().try_fold(
        helpers.checked_add(array).ok_or(Error::Shape)?,
        |sum, part| {
            sum.checked_add(part.checked_mul(8).ok_or(Error::Shape)?)
                .ok_or(Error::Shape)
        },
    )?;
    Ok(Requirements::single(
        Category::PhaseScratch,
        Bytes {
            host: u64::try_from(host).map_err(|_| Error::Shape)?,
            device: 0,
        },
    ))
}

fn steps(ordinal: usize) -> Result<(HashxOuterStep, HashxOuterStep)> {
    Ok(match ordinal {
        0 => (HashxOuterStep::Leaf1, HashxOuterStep::Parent0),
        1 => (HashxOuterStep::Leaf3, HashxOuterStep::Parent1),
        2 => (HashxOuterStep::Parent1, HashxOuterStep::Parent2),
        3 => (HashxOuterStep::Leaf4, HashxOuterStep::Parent3),
        _ => return Err(Error::Shape),
    })
}

impl<'bound, 'source, 'request> FutureHashxParent<'bound, 'source, 'request> {
    pub(super) fn reserve_before_native(
        source: &'bound ParentSourceBound<'source, 'request>,
        ordinal: usize,
        request: &'request ReservedShakeRequest,
        ledger: &Ledger,
    ) -> Result<Self> {
        let original = ledger
            .admit_phase(caller_requirement()?)
            .map_err(|_| Error::Shape)?;
        steps(ordinal)?;
        source
            .check_original_request(request, ledger)
            .map_err(|_| Error::Shape)?;
        let shape = source
            .parent_outer_shape(ordinal, ledger)
            .map_err(|_| Error::Shape)?;
        let planning = PlanningLease::reserve(ledger).map_err(|_| Error::Shape)?;
        let metadata = ledger
            .admit_phase(metadata_requirement()?)
            .map_err(|_| Error::Shape)?;
        let reports = ledger
            .admit_phase(report_requirement()?)
            .map_err(|_| Error::Shape)?;
        let wrappers = ledger
            .admit_phase(wrapper_requirement()?)
            .map_err(|_| Error::Shape)?;
        let acceptance = source
            .preissue_parent_acceptance(ordinal, ledger)
            .map_err(|_| Error::Shape)?;
        let output = output::PreissuedParentOutput::reserve_before_native(shape, request, ledger)
            .map_err(Error::Output)?;
        Ok(Self {
            source,
            ordinal,
            shape,
            output,
            acceptance,
            support: Support {
                request,
                ledger: ledger.clone(),
                wrappers,
                reports,
                metadata,
                planning,
                original,
            },
        })
    }

    /// Return a source-backed member of the eight-successor array before native0.
    /// The array must be consumed by A042's original ticket before any execution.
    pub(super) fn complete_before_native(
        self,
        native: &mut PreparedNativeHashx<'request>,
    ) -> Result<(
        PreissuedHashxParent<'bound, 'source, 'request>,
        PreissuedOuterBackend,
    )> {
        self.support.check(&self.support.ledger)?;
        native
            .check_outer_request(self.support.request, &self.support.ledger)
            .map_err(|_| Error::Authority)?;
        let capacity = native
            .outer_continuation_capacity()
            .map_err(|_| Error::Authority)?;
        if capacity.retained_tree_host_bytes != 8 << 30
            || capacity.startup.host < capacity.retained_tree_host_bytes
            || capacity.pcs.host == 0
            || capacity.pcs.host > 24 << 30
            || capacity.startup.device.checked_add(capacity.pcs.device) != Some(8 << 30)
        {
            return Err(Error::Authority);
        }
        let limits = RegisteredGpuLimits::new(32 << 30, 8 << 30, 4 << 30, MAX_ROWS)
            .map_err(|_| Error::Runtime)?;
        let backend = OuterSourceEnvelope::inspect(self.shape, limits, capacity.pcs.host)
            .and_then(OuterSourceEnvelope::preissue)
            .map_err(|_| Error::Shape)?;
        Ok((PreissuedHashxParent { future: self }, backend))
    }
}

fn metadata_requirement() -> Result<Requirements> {
    let host = OuterSourceEnvelope::additional_metadata_host_bytes().map_err(|_| Error::Shape)?;
    Ok(Requirements::single(
        Category::PhaseScratch,
        Bytes {
            host: u64::try_from(host).map_err(|_| Error::Shape)?,
            device: 0,
        },
    ))
}
fn report_requirement() -> Result<Requirements> {
    Ok(Requirements::single(
        Category::Report,
        Bytes {
            host: u64::try_from(fixed_producer_report_host_bytes()?).map_err(|_| Error::Shape)?,
            device: 0,
        },
    ))
}

fn wrapper_requirement() -> Result<Requirements> {
    Ok(Requirements::single(
        Category::PhaseScratch,
        Bytes {
            host: u64::try_from(
                FixedOuterOclStorage::fixed()
                    .map_err(|_| Error::Shape)?
                    .required_host_bytes(),
            )
            .map_err(|_| Error::Shape)?,
            device: 0,
        },
    ))
}
impl Support<'_> {
    fn check(&self, ledger: &Ledger) -> Result<()> {
        if !self.request.belongs_to(ledger)
            || !self.original.belongs_to(ledger)
            || self.original.requirements() != caller_requirement()?
            || !self.wrappers.belongs_to(ledger)
            || self.wrappers.requirements() != wrapper_requirement()?
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

impl<'bound, 'source, 'request> PreissuedHashxParent<'bound, 'source, 'request> {
    /// # Safety
    /// Preserve the original immutable process/exclusive-device guard through
    /// every setup/proof/output failure and the same actual session retirement.
    pub(super) unsafe fn produce(
        self,
        originals: RetiredHashxOuterOriginals<'request>,
        compiled: &CompiledLeafParent<'bound, 'source, 'request>,
    ) -> Result<AcceptedHashxParentCompletion<'bound, 'source, 'request>> {
        let FutureHashxParent {
            source,
            ordinal,
            shape: _,
            output,
            acceptance,
            support,
        } = self.future;
        support.check(&support.ledger)?;
        source
            .check_original_request(support.request, &support.ledger)
            .map_err(|_| Error::Shape)?;
        acceptance
            .check_compiled(compiled, &support.ledger)
            .map_err(|_| Error::Shape)?;
        let (previous, expected) = steps(ordinal)?;
        originals
            .check(support.request, &support.ledger)
            .map_err(|_| Error::Authority)?;
        if originals.outer_step().map_err(|_| Error::Authority)? != previous {
            return Err(Error::Authority);
        }
        // The sealed compiler consumed and independently authenticated both exact
        // child owners, including this phase's immediately preceding right child.
        let node = &compiled.payload.0;
        let prepared = unsafe {
            originals.bind_successor(expected, &node.program, &node.public, &node.witness)
        }
        .map_err(|_| Error::Shape)?;
        let active = unsafe { prepared.start() }.map_err(|_| Error::Runtime)?;
        let attempted: Result<(
            output::RetainedNodeOutput<'request>,
            CapturedParentAcceptance<'_, 'bound, 'source, 'request>,
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
            let setup_ns = report.elapsed_ns;
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
            let prove_ns = report.elapsed_ns;
            drop(report);
            let retained = output
                .retain_after_proof(
                    key,
                    NodeProof {
                        public: node.public.clone(),
                        proof,
                    },
                    setup_ns,
                    prove_ns,
                    &support.ledger,
                )
                .map_err(Error::Output)?;
            drop(runtime_guard);
            Ok((retained, captured))
        })();
        // No returned setup/proof/report/output error bypasses actual retirement.
        let before = support.ledger.snapshot();
        let originals = active.finish().map_err(|_| Error::Runtime)?;
        if support.ledger.snapshot() != before {
            return Err(Error::Authority);
        }
        let (retained, captured) = attempted?;
        let parent = captured
            .accept_retired(retained, &originals, &support.ledger)
            .map_err(|_| Error::Shape)?;
        Ok(AcceptedHashxParentCompletion {
            parent,
            originals,
            support,
        })
    }
}

// Deliberately no raw continuation extraction yet. The next private sequence
// capsule must carry original-attempt identity through the compiler bank; this
// component result alone cannot dispatch a complete request.
impl AcceptedHashxParentCompletion<'_, '_, '_> {
    pub(super) fn report(&self) -> ParentAcceptanceReport {
        self.parent.report()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::execution::retained_resources::WorkerAllowance;

    #[test]
    fn parent_caller_claim_is_additive_exact_and_releases() {
        let requirements = caller_requirement().unwrap();
        let total = requirements.total().unwrap();
        assert_eq!(total.device, 0);
        assert_eq!(requirements.get(Category::PhaseScratch).host, total.host);
        assert!(total.host > 64 << 10);
        let ledger = Ledger::new(WorkerAllowance {
            host: total.host,
            device: 0,
        });
        let original = ledger.admit_phase(requirements).unwrap();
        assert_eq!(ledger.snapshot().current, total);
        assert!(ledger
            .reserve(Category::PhaseScratch, Bytes { host: 1, device: 0 })
            .is_err());
        drop(original);
        assert_eq!(ledger.snapshot().current, Bytes::ZERO);
    }
}
