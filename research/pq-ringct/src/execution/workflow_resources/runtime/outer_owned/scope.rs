//! Borrow-only scope created by the concrete owned outer producer.
use super::*;
use crate::execution::outer_report;
use crate::opencl::Session;
use lattica_prover_p3::{
    block_v2::machine::{OuterBackendAdmission, Program},
    proving::{CoverageScope, Report},
};
use std::sync::Arc;

/// No caller constructor or claim extraction. Every borrow spans actual
/// registration, consuming proof production and independent verification.
pub(crate) struct OwnedOuterScope<'scope, 'context> {
    access: &'scope ExecutionAccess<'context>,
    program: &'scope Arc<Program>,
    backend: &'scope OuterBackendAdmission<'scope>,
    session: &'scope Session,
    ledger: &'scope Ledger,
    output: &'scope SlotClaim,
    failure: &'scope SlotClaim,
    receipts: outer_report::Sequence,
}

impl<'scope, 'context> OwnedOuterScope<'scope, 'context> {
    // This constructor is confined to the typed runtime driver module.
    // The driver first validates the exact operation, complete phase
    // partition, bound backend and live output/failure originals.
    pub(super) fn new(
        access: &'scope ExecutionAccess<'context>,
        program: &'scope Arc<Program>,
        backend: &'scope OuterBackendAdmission<'scope>,
        session: &'scope Session,
        ledger: &'scope Ledger,
        output: &'scope SlotClaim,
        failure: &'scope SlotClaim,
    ) -> Result<Self, OuterOwnedError> {
        if !output.belongs_to(ledger) || !failure.belongs_to(ledger) {
            return Err(OuterOwnedError::Authority);
        }
        let guard = session.check_reserved_runtime(ledger)
            .map_err(|_| OuterOwnedError::Runtime)?;
        backend.check_execution_selection().map_err(|_| OuterOwnedError::Runtime)?;
        drop(guard);
        Ok(Self { access, program, backend, session, ledger, output, failure,
            receipts: outer_report::Sequence::new() })
    }

    pub(crate) fn binding(&self) -> PhaseBinding { self.access.binding() }
    pub(crate) fn execution(&self) -> &ExecutionAccess<'context> { self.access }
    pub(crate) fn matches_program(&self, program: &Arc<Program>) -> bool {
        Arc::ptr_eq(self.program, program)
    }
    pub(crate) fn matches_backend(&self, backend: &OuterBackendAdmission<'_>) -> bool {
        core::ptr::eq(self.backend, backend)
    }
    pub(crate) fn record_report(&mut self, report: &Report, scope: CoverageScope)
        -> Result<(), OuterOwnedError>
    {
        if !self.output.belongs_to(self.ledger) || !self.failure.belongs_to(self.ledger) {
            return Err(OuterOwnedError::Authority);
        }
        let guard = self.session.check_reserved_runtime(self.ledger)
            .map_err(|_| OuterOwnedError::Runtime)?;
        self.receipts.record(report, scope).map_err(|_| OuterOwnedError::Report)?;
        let rows = match scope {
            CoverageScope::RegisteredProof => Some((self.program.active_rows(), self.program.height())),
            _ => None,
        };
        self.access.context().record_owned_outer_report(report, scope, rows)
            .map_err(|_| OuterOwnedError::Report)?;
        drop(guard);
        Ok(())
    }
    pub(crate) fn timings(&self) -> Result<(u128, u128), OuterOwnedError> {
        self.receipts.timings().map_err(|_| OuterOwnedError::Report)
    }
}
