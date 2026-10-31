//! Fixed observations of real owned-runtime reports, separate from the legacy
//! worker registry. These numbers grant no execution or acceptance authority.
use super::ProvingContext;
use core::{cell::Cell, mem::size_of};
use lattica_prover_p3::proving::{CoverageScope, Policy, Profile, Report};
use serde::Serialize;

mod rows;
mod identity;
pub(crate) use identity::IdentityPreprocessingTotals;
pub(crate) use rows::ProofRowTotals;
use rows::{ProofRowReceipt, ProofRows};

pub(crate) const NATIVE_ENTRIES: [&str; 12] = [
    "ringct_owned_native_graph_source", "ringct_owned_native_uniform",
    "ringct_owned_native_sparse", "ringct_owned_native_transcript",
    "ringct_owned_native_affine", "ringct_owned_native_ntt", "ringct_owned_native_mul",
    "ringct_owned_native_g_bound", "ringct_owned_native_permutation",
    "ringct_owned_native_linear_map", "ringct_owned_native_aes", "ringct_owned_native_shake",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ObservationError { Report, Rows, Write, Overflow, Poisoned, Context, Busy }
type Result<T> = core::result::Result<T, ObservationError>;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub(crate) struct ReportTotals {
    pub(crate) reports: u64,
    pub(crate) elapsed_ns: u128,
}
impl ReportTotals {
    fn add(self, elapsed_ns: u128) -> Result<Self> {
        Ok(Self { reports: self.reports.checked_add(1).ok_or(ObservationError::Overflow)?,
            elapsed_ns: self.elapsed_ns.checked_add(elapsed_ns).ok_or(ObservationError::Overflow)? })
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub(crate) struct PreparationTotals {
    pub(crate) reports: u64,
    pub(crate) elapsed_ns: u128,
    pub(crate) witness_completed_calls: u64,
    pub(crate) witness_device_calls: u64,
    pub(crate) witness_device_ns: u128,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct NativeProofObservation {
    pub(crate) entry_point: &'static str,
    pub(crate) totals: ReportTotals,
    pub(crate) rows: ProofRowTotals,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Totals {
    identity_preprocessing: IdentityPreprocessingTotals,
    machine_preprocessing: ReportTotals,
    machine_proofs: ReportTotals,
    native_proofs: [ReportTotals; 12],
    witness_preparation: PreparationTotals,
    row_receipts: u64,
    machine_rows: ProofRowTotals,
    native_rows: [ProofRowTotals; 12],
}
impl Default for Totals {
    fn default() -> Self {
        Self { identity_preprocessing: IdentityPreprocessingTotals::default(),
            machine_preprocessing: ReportTotals::default(), machine_proofs: ReportTotals::default(),
            native_proofs: [ReportTotals::default(); 12], witness_preparation: PreparationTotals::default(),
            row_receipts: 0, machine_rows: ProofRowTotals::recursive(),
            native_rows: [ProofRowTotals::native(); 12] }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct OwnedWorkflowSnapshot {
    #[serde(skip_serializing_if = "IdentityPreprocessingTotals::is_empty")]
    pub(crate) identity_preprocessing: IdentityPreprocessingTotals,
    pub(crate) schema: &'static str,
    pub(crate) session_id: u64,
    pub(crate) machine_preprocessing: ReportTotals,
    pub(crate) machine_proofs: ReportTotals,
    pub(crate) native_proofs: [NativeProofObservation; 12],
    pub(crate) witness_preparation: PreparationTotals,
    pub(crate) row_receipts: u64,
    pub(crate) machine_rows: ProofRowTotals,
}

/// Direct fixed projection of the source context's existing diagnostics. In
/// particular, calls and successes are read independently, never inferred.
#[derive(Clone, Copy, Debug, PartialEq, Serialize)]
pub(crate) struct SourcePreparationSnapshot {
    pub(crate) session_id: u64,
    pub(crate) calls: u64,
    pub(crate) succeeded: u64,
    pub(crate) complete_reports: u64,
    pub(crate) seconds: f64,
    pub(crate) witness_completed_calls: u64,
    pub(crate) witness_device_calls: u64,
    pub(crate) witness_device_ns: u128,
    pub(crate) native_cpu_calls: u64,
    pub(crate) native_cpu_succeeded: u64,
    pub(crate) failure_events: u64,
}

/// Inline storage is covered by the owning ProvingContext census. Cell updates
/// allocate nothing and cannot panic because a destructor holds a RefCell borrow.
#[derive(Default)]
pub(super) struct OwnedWorkflowObservations {
    totals: Cell<Totals>,
    poisoned: Cell<bool>,
}
impl OwnedWorkflowObservations {
    pub(super) fn pristine(&self) -> bool {
        !self.poisoned.get() && self.totals.get() == Totals::default()
    }

    fn update(&self, change: impl FnOnce(Totals) -> Result<Totals>) -> Result<()> {
        if self.poisoned.get() { return Err(ObservationError::Poisoned); }
        match change(self.totals.get()) {
            Ok(totals) => { self.totals.set(totals); Ok(()) }
            Err(error) => { self.poisoned.set(true); Err(error) }
        }
    }

    fn native_report(&self, report: &Report, prefix: &'static [u8], session_id: u64,
        padded_rows: usize, degree_bits: usize) -> Result<()> {
        self.update(|mut totals| {
            super::native::validate_native_report_fixed(report).map_err(|_| ObservationError::Report)?;
            if report.schema != "lattica-proving-stages-v1"
                || report.capabilities.profile() != Profile::BlockV2Cubic
                || report.capabilities.max_log_fri_arity() != 1
            { return Err(ObservationError::Report); }
            let index = NATIVE_ENTRIES.iter().position(|entry| *entry == report.entry_point)
                .ok_or(ObservationError::Report)?;
            let rows = ProofRows::native(padded_rows, degree_bits)?;
            let receipt = ProofRowReceipt::new(session_id, totals.row_receipts, report.entry_point, rows)?;
            totals.native_proofs[index] = totals.native_proofs[index].add(report.elapsed_ns)?;
            totals.native_rows[index] = totals.native_rows[index].add(rows)?;
            totals.row_receipts = totals.row_receipts.checked_add(1).ok_or(ObservationError::Overflow)?;
            // No new allocation or retained proof enters this observation. A
            // partial publication poisons all totals and cannot be retried.
            super::report_transport::emit(prefix, report).map_err(|_| ObservationError::Write)?;
            receipt.emit()?;
            Ok(totals)
        })
    }

    fn outer_report(&self, report: &Report, scope: CoverageScope, session_id: u64,
        program_rows: Option<(usize, usize)>) -> Result<()> {
        self.update(|mut totals| {
            super::outer_report::validate_report(report, scope).map_err(|_| ObservationError::Report)?;
            match scope {
                CoverageScope::Preprocessing => {
                    if program_rows.is_some() { return Err(ObservationError::Rows); }
                    totals.machine_preprocessing = totals.machine_preprocessing.add(report.elapsed_ns)?;
                }
                CoverageScope::RegisteredProof => {
                    let (active, padded) = program_rows.ok_or(ObservationError::Rows)?;
                    let rows = ProofRows::recursive(active, padded)?;
                    let receipt = ProofRowReceipt::new(session_id, totals.row_receipts, report.entry_point, rows)?;
                    totals.machine_proofs = totals.machine_proofs.add(report.elapsed_ns)?;
                    totals.machine_rows = totals.machine_rows.add(rows)?;
                    totals.row_receipts = totals.row_receipts.checked_add(1).ok_or(ObservationError::Overflow)?;
                    // Sequence already published the real validated proof
                    // report. Only RegisteredProof owns a row observation.
                    receipt.emit()?;
                }
                _ => return Err(ObservationError::Report),
            }
            Ok(totals)
        })
    }

    pub(in crate::execution) fn preparation_report(&self, report: &Report) -> Result<()> {
        self.update(|mut totals| {
            super::preparation::validate_preparation_report_fixed(report).map_err(|_| ObservationError::Report)?;
            if report.schema != "lattica-proving-stages-v1" { return Err(ObservationError::Report); }
            let observed = &report.observations[0];
            let before = totals.witness_preparation;
            totals.witness_preparation = PreparationTotals {
                reports: before.reports.checked_add(1).ok_or(ObservationError::Overflow)?,
                elapsed_ns: before.elapsed_ns.checked_add(report.elapsed_ns).ok_or(ObservationError::Overflow)?,
                witness_completed_calls: before.witness_completed_calls.checked_add(observed.completed_calls).ok_or(ObservationError::Overflow)?,
                witness_device_calls: before.witness_device_calls.checked_add(observed.device_calls).ok_or(ObservationError::Overflow)?,
                witness_device_ns: before.witness_device_ns.checked_add(observed.device_ns).ok_or(ObservationError::Overflow)?,
            };
            Ok(totals)
        })
    }

    fn snapshot(&self, session_id: u64) -> Result<OwnedWorkflowSnapshot> {
        if self.poisoned.get() { return Err(ObservationError::Poisoned); }
        let totals = self.totals.get();
        Ok(OwnedWorkflowSnapshot { schema: "ringct-owned-workflow-observations-v2", session_id,
            identity_preprocessing: totals.identity_preprocessing,
            machine_preprocessing: totals.machine_preprocessing, machine_proofs: totals.machine_proofs,
            native_proofs: core::array::from_fn(|index| NativeProofObservation {
                entry_point: NATIVE_ENTRIES[index], totals: totals.native_proofs[index], rows: totals.native_rows[index],
            }), witness_preparation: totals.witness_preparation,
            row_receipts: totals.row_receipts, machine_rows: totals.machine_rows })
    }
}

impl ProvingContext {
    pub(in crate::execution) fn record_owned_native_report(&self, report: &Report,
        prefix: &'static [u8], padded_rows: usize, degree_bits: usize) -> Result<()> {
        if self.policy() != Policy::GpuRequired { return Err(ObservationError::Context); }
        self.owned_workflow_observations.native_report(report, prefix, self.session_id,
            padded_rows, degree_bits)
    }
    pub(in crate::execution) fn record_owned_outer_report(&self, report: &Report,
        scope: CoverageScope, program_rows: Option<(usize, usize)>) -> Result<()> {
        if self.policy() != Policy::GpuRequired { return Err(ObservationError::Context); }
        self.owned_workflow_observations.outer_report(report, scope, self.session_id, program_rows)
    }
    pub(crate) fn owned_workflow_snapshot(&self) -> Result<OwnedWorkflowSnapshot> {
        if self.policy() != Policy::GpuRequired { return Err(ObservationError::Context); }
        self.owned_workflow_observations.snapshot(self.session_id)
    }
    pub(crate) fn source_preparation_snapshot(&self) -> Result<SourcePreparationSnapshot> {
        if self.policy() != Policy::GpuRequired { return Err(ObservationError::Context); }
        self.diagnostics.source_preparation_snapshot(self.session_id)
    }
}

/// Additive forwarding, checked-update and snapshot shells, held by the same
/// permanent context original. Output-summary shells are charged by its caller.
pub(in crate::execution) fn additional_host_bytes() -> Result<usize> {
    let source = super::Diagnostics::source_observation_host_bytes()?;
    [size_of::<IdentityPreprocessingTotals>(), size_of::<Result<IdentityPreprocessingTotals>>(),
        size_of::<Totals>(), size_of::<OwnedWorkflowSnapshot>(), size_of::<SourcePreparationSnapshot>(),
        size_of::<Result<Totals>>(), size_of::<Result<ReportTotals>>(), size_of::<Result<OwnedWorkflowSnapshot>>(),
        size_of::<Result<SourcePreparationSnapshot>>(), size_of::<Result<()>>(),
        size_of::<ReportTotals>(), size_of::<PreparationTotals>(), size_of::<NativeProofObservation>(),
        size_of::<[&Report; 4]>(), size_of::<[u128; 8]>(), size_of::<&OwnedWorkflowObservations>(),
        size_of::<&ProvingContext>(), size_of::<Option<usize>>(), size_of::<Option<u64>>(),
        size_of::<Option<u128>>(), size_of::<Result<usize>>(),
        size_of::<[usize; 8]>(), size_of::<CoverageScope>(), size_of::<ObservationError>(),
        // Concrete row helpers, checked updates, receipt constructors, derive
        // serialization scalars and forwarding shells remain held by the same
        // permanent context original before any proof callback can run.
        size_of::<ProofRows>(), size_of::<ProofRowTotals>(), size_of::<ProofRowReceipt>(),
        size_of::<Result<ProofRows>>(), size_of::<Result<ProofRowTotals>>(),
        size_of::<Result<ProofRowReceipt>>(), size_of::<Option<(usize, usize)>>(),
        size_of::<Option<u32>>(), size_of::<[u32; 8]>(), size_of::<[u64; 8]>(),
        size_of::<[Option<u64>; 4]>(), size_of::<[Option<u128>; 4]>(),
        size_of::<[&'static str; 4]>(), size_of::<[&'static [u8]; 4]>(),
        size_of::<&ProofRowReceipt>(), size_of::<core::result::Result<(), super::report_transport::Error>>(),
    ].into_iter().try_fold(0usize, |sum, bytes| sum.checked_add(bytes))
        .and_then(|bytes| bytes.checked_mul(8))
        .and_then(|bytes| bytes.checked_add(source))
        .ok_or(ObservationError::Overflow)
}

#[cfg(test)]
mod tests;
