//! Couple a source-captured verifier, output and the same actual outer attempt.
//! No raw proof, report, cap, retirement or numeric reservation is accepted.
use super::*;
use crate::component_tree::owned_shake::request_merge::{
    authenticate_retired_leaf, AcceptedLeafCompletion, CapturedLeafAcceptance,
    PreissuedLeafAcceptance,
};

/// Constructed only at the terminal boundary of the actual producer below.
/// The numerical acceptance entry consumes this whole owner, so an unrelated
/// completed runtime/output or a matching summary cannot be substituted.
pub(in crate::component_tree::owned_shake) struct RetiredLeafAttempt<
    'compiled,
    'bound,
    'source,
    'request,
> {
    captured: CapturedLeafAcceptance<'compiled, 'bound, 'source, 'request>,
    output: output::RetainedNodeOutput<'request>,
    originals: RetiredOuterOriginals<'request>,
    ledger: Ledger,
}

impl<'compiled, 'bound, 'source, 'request>
    RetiredLeafAttempt<'compiled, 'bound, 'source, 'request>
{
    pub(in crate::component_tree::owned_shake) fn into_original_parts(
        self,
    ) -> (
        CapturedLeafAcceptance<'compiled, 'bound, 'source, 'request>,
        output::RetainedNodeOutput<'request>,
        RetiredOuterOriginals<'request>,
        Ledger,
    ) {
        (self.captured, self.output, self.originals, self.ledger)
    }

    pub(in crate::component_tree::owned_shake) fn additional_host_bytes() -> Option<usize> {
        [
            8 * size_of::<Continuation<'static, 'static, 'static>>(),
            8 * size_of::<PreparedOuter<'static, 'static, 'static>>(),
            8 * size_of::<RetiredOuterOriginals<'static>>(),
            8 * size_of::<RetiredLeafAttempt<'static, 'static, 'static, 'static>>(),
            8 * size_of::<Result<RetiredLeafAttempt<'static, 'static, 'static, 'static>>>(),
            8 * size_of::<Result<AcceptedLeafCompletion<'static, 'static, 'static>>>(),
            8 * size_of::<
                Result<(
                    output::RetainedNodeOutput<'static>,
                    CapturedLeafAcceptance<'static, 'static, 'static, 'static>,
                )>,
            >(),
            8 * size_of::<(
                output::RetainedNodeOutput<'static>,
                CapturedLeafAcceptance<'static, 'static, 'static, 'static>,
            )>(),
            8 * size_of::<RegisteredProgram>(),
            8 * size_of::<NodeKey>(),
            8 * size_of::<NodeProof>(),
            8 * size_of::<Snapshot>(),
            8 * size_of::<Result<Retirement>>(),
            8 * size_of::<Requirements>(),
            8 * size_of::<Bytes>(),
            8 * size_of::<Summary>(),
            8 * size_of::<Report>(),
            8 * size_of::<lattica_prover_p3::block_v2::machine::backend::identity_cpu::RegistrationReports>(),
            8 * size_of::<Request>(),
            8 * size_of::<std::time::Instant>(),
            8 * size_of::<Ledger>(),
            8 * size_of::<Reservation>(),
            32 << 10,
        ]
        .into_iter()
        .try_fold(0usize, usize::checked_add)
    }
}

impl RetiredOuterOriginals<'_> {
    /// Diagnostic validation only. It cannot construct RetiredLeafAttempt or
    /// turn a free-standing original owner into an authenticated source proof.
    pub(in crate::component_tree::owned_shake) fn source_authentication_retirement(
        &self,
        ledger: &Ledger,
    ) -> Result<Retirement> {
        let receipt = self.runtime.receipt();
        if !self.runtime.belongs_to(ledger)
            || !self.request.belongs_to(ledger)
            || !self.backend.belongs_to(ledger)
            || !self.wrappers.belongs_to(ledger)
            || self.wrappers.requirements() != wrapper_requirement()?
            || !self.reports.belongs_to(ledger)
            || self.reports.requirements() != report_requirement()?
            || !self.metadata.belongs_to(ledger)
            || self.metadata.requirements() != metadata_requirement()?
            || !self.planning.belongs_to(ledger)
            || !self.native_wrappers.belongs_to(ledger)
            || !retired(receipt)
            || receipt.managed_peak_bytes == 0
            || receipt.managed_peak_bytes as u64 > 8 << 30
        {
            return Err(Error::Authority);
        }
        Ok(receipt)
    }
}

impl<'compiled, 'request> Continuation<'compiled, 'request, 'request> {
    /// The extra acceptance owner is preissued from the complete five-leaf
    /// source before native work. This is a single component seam; B051 still
    /// refuses complete request dispatch until the entire graph is admitted.
    ///
    /// # Safety
    /// Preserve the original immutable/exclusive physical-device/process guard
    /// from source preissue through this runtime's actual terminal retirement.
    pub(in crate::component_tree::owned_shake) unsafe fn produce_authenticated_leaf<
        'bound,
        'source,
    >(
        self,
        acceptance: PreissuedLeafAcceptance<'bound, 'source, 'request>,
    ) -> Result<AcceptedLeafCompletion<'bound, 'source, 'request>> {
        let attempt = unsafe { self.produce_source_attempt(acceptance) }?;
        // Reconstructing the independent verifier occurred under its own full
        // claim at the original registration. Numerical verification is now
        // strictly after actual retirement and uses no output-supplied verifier.
        authenticate_retired_leaf(attempt).map_err(|_| Error::Shape)
    }

    unsafe fn produce_source_attempt<'bound, 'source>(
        self,
        acceptance: PreissuedLeafAcceptance<'bound, 'source, 'request>,
    ) -> Result<RetiredLeafAttempt<'compiled, 'bound, 'source, 'request>> {
        let Self {
            producer,
            native_wrappers,
            metadata,
        } = self;
        let PreparedOuter {
            compiled,
            request,
            output,
            backend,
            runtime,
            ledger,
            backend_token,
            wrappers,
            reports,
            planning,
        } = producer;
        acceptance
            .check_compiled(compiled, request, &ledger)
            .map_err(|_| Error::Shape)?;
        let startup = runtime.reserved_bytes();
        let footprint = backend.footprint();
        if !runtime.belongs_to(&ledger)
            || runtime.reserved_tree_host_bytes() != 8 << 30
            || !request.belongs_to(&ledger)
            || !compiled.is_for(request.request())
            || !backend_token.belongs_to(&ledger)
            || !wrappers.belongs_to(&ledger)
            || wrappers.requirements() != wrapper_requirement()?
            || !reports.belongs_to(&ledger)
            || reports.requirements() != report_requirement()?
            || !planning.belongs_to(&ledger)
            || !native_wrappers.belongs_to(&ledger)
            || !metadata.belongs_to(&ledger)
            || metadata.requirements() != metadata_requirement()?
            || backend_token.requirements()
                != Requirements::single(
                    Category::PhaseScratch,
                    Bytes {
                        host: footprint
                            .backend_scope_host_bytes
                            .checked_sub(8 << 30)
                            .ok_or(Error::Shape)?,
                        device: (8u64 << 30)
                            .checked_sub(startup.device)
                            .ok_or(Error::Shape)?,
                    },
                )
        {
            return Err(Error::Authority);
        }
        let completed = compiled.summary();
        let session = unsafe { runtime.start() }.map_err(|_| Error::Runtime)?;
        let attempted: Result<(
            output::RetainedNodeOutput<'request>,
            CapturedLeafAcceptance<'compiled, 'bound, 'source, 'request>,
        )> = (|| {
            let runtime_guard = session
                .check_reserved_runtime(&ledger)
                .map_err(|_| Error::Runtime)?;
            backend
                .check_execution_selection()
                .map_err(|_| Error::Runtime)?;
            let proof_request = Request {
                policy: Policy::GpuRequired,
                emit_report: false,
            };
            let node = &compiled.compiled;
            let (registered, report) =
                RegisteredProgram::new_with_cpu_identity_and_report(
                    MachineAir::from_shared_program(Arc::clone(&node.program)),
                    backend.host_budget_bytes(),
                    proof_request,
                )
                .map_err(|_| Error::Setup)?;
            validate_report(&report.preprocessing, CoverageScope::Preprocessing)?;
            validate_report(&report.identity, CoverageScope::Operation)?;
            emit_receipt(&report.preprocessing)?;
            emit_receipt(&report.identity)?;
            let setup_elapsed_ns = report.preprocessing.elapsed_ns;
            drop(report);
            let captured = acceptance
                .capture(compiled, &registered, &ledger)
                .map_err(|_| Error::Shape)?;
            let key = NodeKey {
                spec: node.spec.clone(),
                height: node.program.height(),
                cap: registered.preprocessing_cap().roots().to_vec(),
                verifier: Arc::new(registered.verifier()),
            };
            let (proof, report) = registered
                .into_prove_outer_with_request_and_report(&backend, proof_request)
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
        let before = ledger.snapshot();
        let runtime = session
            .finish_reserved_with_owner(&ledger)
            .map_err(|_| Error::Runtime)?;
        if !retired(runtime.receipt()) {
            std::process::abort();
        }
        if ledger.snapshot() != before {
            return Err(Error::Authority);
        }
        let (output, captured) = attempted?;
        if !output.belongs_to(&ledger) || !output.report().independent_verification_complete {
            return Err(Error::Authority);
        }
        let originals = RetiredOuterOriginals {
            runtime,
            request,
            completed,
            ledger: ledger.clone(),
            backend: backend_token,
            wrappers,
            reports,
            planning,
            native_wrappers,
            metadata,
        };
        originals.source_authentication_retirement(&ledger)?;
        Ok(RetiredLeafAttempt {
            captured,
            output,
            originals,
            ledger,
        })
    }
}
