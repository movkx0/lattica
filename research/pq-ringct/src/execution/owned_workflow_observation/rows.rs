//! Actual retained execution shapes only. These scalar observations are not
//! memory bounds, reusable proof claims, or permission to dispatch a producer.
use super::{ObservationError, Result};
use serde::Serialize;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct ProofRows {
    pub(super) active_rows: Option<u64>,
    pub(super) padded_rows: u64,
    pub(super) native_degree_bits: Option<u32>,
}

impl ProofRows {
    /// All twelve owned native producers pin config.is_zk() to one and audit
    /// retained proof degree == exact output geometry log2(rows) + one. Repeat
    /// that exact relationship here; the proof domain is twice the padded
    /// execution trace. Never infer native active work from that trace height.
    pub(super) fn native(padded_rows: usize, degree_bits: usize) -> Result<Self> {
        let padded_rows = u64::try_from(padded_rows).map_err(|_| ObservationError::Overflow)?;
        let degree_bits = u32::try_from(degree_bits).map_err(|_| ObservationError::Overflow)?;
        if !padded_rows.is_power_of_two() { return Err(ObservationError::Rows); }
        let proof_domain = 1u64.checked_shl(degree_bits).ok_or(ObservationError::Overflow)?;
        let expanded = padded_rows.checked_mul(2).ok_or(ObservationError::Overflow)?;
        if proof_domain != expanded { return Err(ObservationError::Rows); }
        Ok(Self { active_rows: None, padded_rows, native_degree_bits: Some(degree_bits) })
    }

    pub(super) fn recursive(active_rows: usize, padded_rows: usize) -> Result<Self> {
        let active_rows = u64::try_from(active_rows).map_err(|_| ObservationError::Overflow)?;
        let padded_rows = u64::try_from(padded_rows).map_err(|_| ObservationError::Overflow)?;
        if padded_rows < 8 || !padded_rows.is_power_of_two() || active_rows > padded_rows {
            return Err(ObservationError::Rows);
        }
        Ok(Self { active_rows: Some(active_rows), padded_rows, native_degree_bits: None })
    }
}

/// Fixed totals preserve absence: native active rows are unknown, including
/// the zero-proof case. A null value must never be substituted with padding.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct ProofRowTotals {
    pub(crate) proofs: u64,
    pub(crate) active_rows: Option<u128>,
    pub(crate) padded_rows: u128,
}
impl ProofRowTotals {
    pub(super) const fn native() -> Self {
        Self { proofs: 0, active_rows: None, padded_rows: 0 }
    }
    pub(super) const fn recursive() -> Self {
        Self { proofs: 0, active_rows: Some(0), padded_rows: 0 }
    }
    pub(super) fn add(self, rows: ProofRows) -> Result<Self> {
        let active_rows = match (self.active_rows, rows.active_rows) {
            (None, None) => None,
            (Some(before), Some(actual)) => Some(before.checked_add(u128::from(actual))
                .ok_or(ObservationError::Overflow)?),
            _ => return Err(ObservationError::Rows),
        };
        Ok(Self { proofs: self.proofs.checked_add(1).ok_or(ObservationError::Overflow)?,
            active_rows, padded_rows: self.padded_rows.checked_add(u128::from(rows.padded_rows))
                .ok_or(ObservationError::Overflow)? })
    }
}

/// One bounded record immediately following its real successful proof report.
/// Sequence is global across native and recursive proofs within this session.
/// Recording precedes independent verification: only a completed case may use
/// these records as a complete-workflow inventory; failed attempts remain logs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub(super) struct ProofRowReceipt {
    schema: &'static str,
    session_id: u64,
    sequence: u64,
    entry_point: &'static str,
    active_rows: Option<u64>,
    padded_rows: u64,
    native_degree_bits: Option<u32>,
}
impl ProofRowReceipt {
    pub(super) fn new(session_id: u64, sequence: u64, entry_point: &'static str,
        rows: ProofRows) -> Result<Self> {
        if session_id == 0 { return Err(ObservationError::Context); }
        Ok(Self { schema: "ringct-owned-proof-rows-v1", session_id, sequence, entry_point,
            active_rows: rows.active_rows, padded_rows: rows.padded_rows,
            native_degree_bits: rows.native_degree_bits })
    }
    pub(super) fn emit(&self) -> Result<()> {
        super::super::report_transport::emit(b"owned_proof_rows ", self)
            .map_err(|_| ObservationError::Write)
    }
}
impl super::super::report_transport::FixedPayload for ProofRowReceipt {}
