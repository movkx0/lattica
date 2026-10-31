//! Closed CPU-reference coupling of the owned SHAKE compiler to a real phase.
//!
//! The execution-owned entry admits the exact immutable plan before creating a
//! sealed borrowed handle. The compiler receives only fixed output/verifier
//! splits; its PhaseScratch remains in the context until actual cleanup. No
//! standalone token, caller requirement or generic callback grants admission.
//!
//! This is still a prerequisite, not complete-workflow or dispatch authority.
//! Enclosing graph/request/source owners, original backend/report/error
//! transients and GPU preparation require separate source-derived coverage.
//! Native production remains uninhabited and paired runtime dispatch disabled.
//! CPU-required context checks do not alter baseline methods or claim global
//! exclusivity against those methods. No GPU-required-to-CPU fallback exists.

use super::{
    phase_lifecycle::{Error as LifecycleError, PhaseCapability, PhaseLease},
    phase_report::PhaseReportOwner,
    retained_resources::{Ledger, Reservation},
};
use crate::{
    component_tree::{
        owned_shake::{CompilationFailure, GroupCompilePlan, OwnedCompiledShake},
        shake_verification_memory::Plan as VerificationPlan,
    },
    graph_crypto::ReservedNativeChild,
};

/// Private fields and no public constructor couple one exact borrowed plan to
/// one actual context phase. There is no raw lease accessor or arbitrary split.
/// Borrowing the plan separately permits fixed splits without substituting the
/// plan while the linear phase borrow is live.
pub(crate) struct AdmittedShakeCompilation<'scope, 'phase, 'context, 'request> {
    plan: &'scope GroupCompilePlan<'request>,
    lease: &'scope mut PhaseLease<'phase, 'context>,
}

impl<'scope, 'phase, 'context, 'request>
    AdmittedShakeCompilation<'scope, 'phase, 'context, 'request>
{
    pub(crate) fn plan(&self) -> &'scope GroupCompilePlan<'request> {
        self.plan
    }

    pub(crate) fn ledger(&self) -> &Ledger {
        self.lease.ledger()
    }

    pub(crate) fn split_report(&mut self) -> Result<Reservation, LifecycleError> {
        self.lease.split(PhaseReportOwner::requirements())
    }

    pub(crate) fn split_independent_verifier(&mut self) -> Result<Reservation, LifecycleError> {
        self.lease.split(VerificationPlan::component_requirement())
    }

    pub(crate) fn split_program(&mut self) -> Result<Reservation, LifecycleError> {
        self.lease.split(self.plan.program_requirement())
    }

    pub(crate) fn split_inputs(&mut self) -> Result<Reservation, LifecycleError> {
        self.lease.split(self.plan.input_requirement())
    }
}

/// Fixed lifecycle codes and at most the compiler's already-reserved bounded
/// failure report. No String or newly allocated diagnostic escapes cleanup.
#[derive(Debug)]
pub(crate) enum PhaseCompilationFailure {
    Admission(LifecycleError),
    Compilation(CompilationFailure),
    Cleanup {
        error: LifecycleError,
        compilation: Option<CompilationFailure>,
    },
}

impl PhaseCapability<'_> {
    /// CPU-reference prerequisite only. This takes neither requirements nor a
    /// generic reservation: the closed plan determines all admitted splits.
    /// Exact native owner/request/ledger checks precede compiler allocations.
    pub(super) fn compile_shake_cpu_reference<'request>(
        &mut self,
        plan: GroupCompilePlan<'request>,
        children: [Option<ReservedNativeChild<'request>>; 2],
    ) -> Result<OwnedCompiledShake<'request>, PhaseCompilationFailure> {
        self.check_cpu_reference_compilation()
            .map_err(PhaseCompilationFailure::Admission)?;
        let mut lease = self
            .admit(plan.requirements())
            .map_err(PhaseCompilationFailure::Admission)?;
        let result = GroupCompilePlan::compile_in_admitted_cpu_phase(
            AdmittedShakeCompilation {
                plan: &plan,
                lease: &mut lease,
            },
            children,
        );
        // The compiler's local temporaries and consumed children have died.
        // Only sealed outputs or an owned failure report may still be live.
        finish_compilation(lease, result)
    }
}

// No injectable cleanup or success receipt. Both normal execution and tests
// complete the exact actual context lease, retaining its scratch on failure.
fn finish_compilation<'request>(
    lease: PhaseLease<'_, '_>,
    result: Result<OwnedCompiledShake<'request>, CompilationFailure>,
) -> Result<OwnedCompiledShake<'request>, PhaseCompilationFailure> {
    match (result, lease.complete_after_cleanup()) {
        (Ok(compiled), Ok(())) => Ok(compiled),
        (Err(compilation), Ok(())) => Err(PhaseCompilationFailure::Compilation(compilation)),
        (Err(compilation), Err(error)) => Err(PhaseCompilationFailure::Cleanup {
            error,
            compilation: Some(compilation),
        }),
        (Ok(compiled), Err(error)) => {
            let compilation = if let LifecycleError::Cleanup(stage) = &error {
                // Drop payload/input/program owners, retaining only the
                // already-charged report with a fixed cleanup failure code.
                Some(compiled.into_cleanup_failure(*stage))
            } else {
                // An impossible stale-state failure must not release a usable
                // compiled output either. The fixed lifecycle error survives.
                drop(compiled);
                None
            };
            Err(PhaseCompilationFailure::Cleanup { error, compilation })
        }
    }
}

#[cfg(all(test, not(debug_assertions), target_arch = "x86_64"))]
mod tests;

// Fixed CPU correctness-harness bridges only. The enclosing test admits its
// immutable fixture/request storage separately on this same fresh context.
// Neither bridge exists in a production build or accepts a caller quota,
// generic callback, raw compiled program, or native dispatch permit.
#[cfg(all(test, not(debug_assertions), target_arch = "x86_64"))]
impl super::ProvingContext {
    pub(crate) fn endpoint_qualification_capability(
        &self,
    ) -> Result<PhaseCapability<'_>, LifecycleError> {
        self.phase_capability(super::retained_resources::Bytes::ZERO)
    }
}

#[cfg(all(test, not(debug_assertions), target_arch = "x86_64"))]
impl PhaseCapability<'_> {
    pub(crate) fn compile_shake_endpoint_qualification<'request>(
        &mut self,
        plan: GroupCompilePlan<'request>,
        children: [Option<ReservedNativeChild<'request>>; 2],
    ) -> Result<OwnedCompiledShake<'request>, PhaseCompilationFailure> {
        self.compile_shake_cpu_reference(plan, children)
    }
}
