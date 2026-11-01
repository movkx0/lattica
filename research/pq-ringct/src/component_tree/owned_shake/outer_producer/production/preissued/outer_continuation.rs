//! Outer-to-outer ownership seam. The separate ignored qualifier restores and
//! drops actual first-outer startup; it never dispatches a second outer proof.
//! Every next group must be preissued before the original native work.
use super::*;
use crate::{component_tree::owned_shake::Summary, execution::retained_resources::Snapshot};
use lattica_prover_p3::block_v2::gpu_hash::device::ringct_runtime::{RetiredRuntime, Retirement};

/// Issued only after this module's actual consuming producer has independently
/// verified its output and retired the exact private Session runtime. No raw
/// reservation, numeric receipt or caller-supplied proof constructs this owner.
pub(in crate::component_tree::owned_shake) struct RetiredOuterOriginals<'owner> {
    runtime: RetiredRuntime,
    request: &'owner ReservedShakeRequest,
    completed: Summary,
    ledger: Ledger,
    backend: Reservation,
    wrappers: Reservation,
    reports: Reservation,
    planning: PlanningLease,
    native_wrappers: Reservation,
    metadata: Reservation,
}

pub(in crate::component_tree::owned_shake) struct ContinuedOuter<'owner> {
    output: output::RetainedNodeOutput<'owner>,
    originals: RetiredOuterOriginals<'owner>,
}

impl<'owner> ContinuedOuter<'owner> {
    pub(in crate::component_tree::owned_shake) fn into_parts(
        self,
    ) -> (
        output::RetainedNodeOutput<'owner>,
        RetiredOuterOriginals<'owner>,
    ) {
        (self.output, self.originals)
    }
}

pub(super) fn additional_host_bytes() -> Result<usize> {
    [
        4 * size_of::<RetiredOuterOriginals<'static>>(),
        4 * size_of::<ContinuedOuter<'static>>(),
        4 * size_of::<Result<ContinuedOuter<'static>>>(),
        4 * size_of::<Result<output::RetainedNodeOutput<'static>>>(),
        4 * size_of::<RetiredRuntime>(),
        4 * size_of::<PendingRuntime>(),
        4 * size_of::<
            core::result::Result<PendingRuntime, (crate::opencl::RuntimeError, RetiredRuntime)>,
        >(),
        4 * size_of::<std::fmt::Arguments<'static>>(),
        4 * size_of::<Limits>(),
        4 * size_of::<Retirement>(),
        8 * size_of::<Snapshot>(),
        8 * size_of::<Requirements>(),
        8 * size_of::<Reservation>(),
        4 * size_of::<Summary>(),
        2 * size_of::<PreparedOuter<'static, 'static, 'static>>(),
        2 * size_of::<Continuation<'static, 'static, 'static>>(),
    ]
    .into_iter()
    .try_fold(0usize, |sum, bytes| {
        sum.checked_add(bytes).ok_or(Error::Shape)
    })
}

fn retired(receipt: Retirement) -> bool {
    receipt.managed_live_bytes == 0 && receipt.host_tree_live_bytes == 0 && receipt.lease_released
}

fn wrapper_requirement() -> Result<Requirements> {
    Ok(Requirements::single(
        Category::PhaseScratch,
        Bytes {
            host: FixedOuterOclStorage::fixed()
                .map_err(|_| Error::Shape)?
                .required_host_bytes() as u64,
            device: 0,
        },
    ))
}

fn include(total: &mut Requirements, next: Requirements) -> Result<()> {
    for category in Category::ALL {
        total
            .add(category, next.get(category))
            .map_err(|_| Error::Shape)?;
    }
    Ok(())
}

fn after_release(mut before: Snapshot, released: Requirements) -> Result<Snapshot> {
    let total = released.total().map_err(|_| Error::Shape)?;
    before.current.host = before
        .current
        .host
        .checked_sub(total.host)
        .ok_or(Error::Shape)?;
    before.current.device = before
        .current
        .device
        .checked_sub(total.device)
        .ok_or(Error::Shape)?;
    for category in Category::ALL {
        let bytes = released.get(category);
        let current = &mut before.categories[category as usize].current;
        current.host = current.host.checked_sub(bytes.host).ok_or(Error::Shape)?;
        current.device = current
            .device
            .checked_sub(bytes.device)
            .ok_or(Error::Shape)?;
    }
    Ok(before)
}

fn consecutive(prior: Summary, next: Summary) -> bool {
    next.layout == prior.layout
        && prior.ordinal.checked_add(1) == Some(next.ordinal)
        && prior
            .span
            .first_segment
            .checked_add(prior.span.segment_count)
            == Some(next.span.first_segment)
        && prior.span.first_unit.checked_add(prior.span.units) == Some(next.span.first_unit)
}

impl<'owner, 'request> Continuation<'_, 'owner, 'request> {
    /// Preserve the exact startup/PCS and support owners after one fresh outer
    /// proof. Only the preissued Continuation exposes this opt-in source path;
    /// existing produce/produce_reported retain their original release behavior.
    ///
    /// # Safety
    /// The same immutable physical selection/exclusive process contract must
    /// hold from the first source preissue through this exact runtime retirement.
    pub(in crate::component_tree::owned_shake) unsafe fn produce_retaining_outer_originals(
        self,
    ) -> Result<ContinuedOuter<'owner>> {
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
        // Session is created after all backing owners. Unwinding destroys the
        // actual runtime before their original claims can be released.
        let session = unsafe { runtime.start() }.map_err(|_| Error::Runtime)?;
        let attempted: Result<output::RetainedNodeOutput<'owner>> = (|| {
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
            let produced = output
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
            Ok(produced)
        })();
        // Retire even after setup/proof/verification refusal. No successful
        // continuation can escape a failed attempt or uncertain cleanup.
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
        let output = attempted?;
        if !output.belongs_to(&ledger) || !output.report().independent_verification_complete {
            return Err(Error::Authority);
        }
        Ok(ContinuedOuter {
            output,
            originals: RetiredOuterOriginals {
                runtime,
                request,
                completed,
                ledger,
                backend: backend_token,
                wrappers,
                reports,
                planning,
                native_wrappers,
                metadata,
            },
        })
    }
}

impl<'owner, 'request> ReadyOuter<'_, 'owner, 'request> {
    /// Bind the next already-preissued consecutive group. The previous outer
    /// runtime is actually retired. Its original startup/PCS/native-wrapper
    /// claims move unchanged; only its obsolete outer support claims retire.
    ///
    /// # Safety
    /// Same immutable/exclusive host profile from pre-native issuance through
    /// eventual next runtime retirement. No new claim or planner is admitted.
    pub(in crate::component_tree::owned_shake) unsafe fn finish_outer<'compiled>(
        self,
        compiled: &'compiled OwnedCompiledShake<'request>,
        originals: RetiredOuterOriginals<'owner>,
    ) -> Result<Continuation<'compiled, 'owner, 'request>> {
        let Self {
            future,
            backend,
            original_startup,
            original_pcs,
        } = self;
        let FutureOuter {
            source,
            request,
            output,
            ledger,
            wrappers,
            reports,
            metadata,
            planning,
        } = future;
        source
            .check_compiled(compiled, &ledger)
            .map_err(|_| Error::Shape)?;
        let next = compiled.summary();
        let prior = originals.completed;
        if !core::ptr::eq(request, originals.request)
            || !originals.runtime.belongs_to(&ledger)
            || !originals.backend.belongs_to(&ledger)
            || originals.backend.requirements()
                != Requirements::single(Category::PhaseScratch, original_pcs)
            || originals.runtime.startup_requirements()
                != Requirements::single(Category::PhaseScratch, original_startup)
            || !originals.wrappers.belongs_to(&ledger)
            || originals.wrappers.requirements() != wrapper_requirement()?
            || !originals.reports.belongs_to(&ledger)
            || originals.reports.requirements() != report_requirement()?
            || !originals.planning.belongs_to(&ledger)
            || !originals.native_wrappers.belongs_to(&ledger)
            || !originals.metadata.belongs_to(&ledger)
            || originals.metadata.requirements() != metadata_requirement()?
            || !planning.belongs_to(&ledger)
            || !wrappers.belongs_to(&ledger)
            || wrappers.requirements() != wrapper_requirement()?
            || !reports.belongs_to(&ledger)
            || reports.requirements() != report_requirement()?
            || !metadata.belongs_to(&ledger)
            || metadata.requirements() != metadata_requirement()?
            || !consecutive(prior, next)
            || !retired(originals.runtime.receipt())
        {
            return Err(Error::Authority);
        }
        let footprint = backend.footprint();
        if footprint.backend_scope_host_bytes.checked_sub(8 << 30) != Some(original_pcs.host)
            || footprint
                .complete_device_phase_ceiling
                .checked_sub(original_startup.device)
                != Some(original_pcs.device)
        {
            return Err(Error::Authority);
        }
        let before = ledger.snapshot();
        let mut released = Requirements::single(
            Category::PhaseScratch,
            Bytes {
                host: crate::execution::pre_session_outer::PLANNING_HOST,
                device: 0,
            },
        );
        include(&mut released, originals.wrappers.requirements())?;
        include(&mut released, originals.reports.requirements())?;
        include(&mut released, originals.metadata.requirements())?;
        let expected = after_release(before, released)?;
        let RetiredOuterOriginals {
            runtime,
            request: _,
            completed: _,
            ledger: prior_ledger,
            backend: pcs,
            wrappers: old_wrappers,
            reports: old_reports,
            planning: old_planning,
            native_wrappers,
            metadata: old_metadata,
        } = originals;
        // This A-owned entry accepts only the actual sealed retired runtime,
        // including proof that no native phase binding survived its retirement.
        let mut runtime = match PendingRuntime::restore_retired_outer_host_v1(
            runtime,
            &ledger,
            Limits {
                host_bytes: 32 << 30,
                device_bytes: 8 << 30,
                max_rows: MAX_ROWS,
            },
        ) {
            Ok(runtime) => runtime,
            Err(_) => return Err(Error::Runtime),
        };
        if !runtime.belongs_to(&ledger)
            || runtime.reserved_bytes() != original_startup
            || runtime.reserved_tree_host_bytes() != 8 << 30
        {
            return Err(Error::Authority);
        }
        let output = output.attach(compiled, &ledger).map_err(Error::Output)?;
        let preflight = unsafe { runtime.preflight() }.map_err(|_| Error::Runtime)?;
        let node = &compiled.compiled;
        let backend = backend
            .bind(&node.program, &node.public, &node.witness)
            .map_err(|_| Error::Shape)?;
        drop(preflight);
        if ledger.snapshot() != before {
            return Err(Error::Authority);
        }
        let continued = Continuation {
            producer: PreparedOuter {
                compiled,
                request,
                output,
                backend,
                runtime,
                ledger: ledger.clone(),
                backend_token: pcs,
                wrappers,
                reports,
                planning,
            },
            native_wrappers,
            metadata,
        };
        // These payloads are gone after actual prior retirement. The next
        // group's distinct support claims were already held before native work.
        drop(old_wrappers);
        drop(old_reports);
        drop(old_planning);
        drop(prior_ledger);
        drop(old_metadata);
        if ledger.snapshot() != expected {
            return Err(Error::Authority);
        }
        Ok(continued)
    }
}

#[cfg(test)]
mod tests;

#[cfg(all(test, feature = "owned-native-shake", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
mod authenticated;
#[cfg(all(test, feature = "owned-native-shake", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
pub(in crate::component_tree::owned_shake) use authenticated::RetiredLeafAttempt;
