//! Quota-owned public preparation for the unchanged private-note GPU AIR.
//! Default dispatch stays disabled. The separate opt-in qualification module
//! admits a complete fixed producer, owned output and independent CPU verifier.
use super::{codec, quota::Reservation, DecodeSession, Error, NATIVE_HOST_BYTES};
use crate::{note, Context};
use lattica_prover_p3::block_v2::note_admission as core;
use serde::Serialize;
use std::mem::size_of;

#[cfg(all(
    feature = "note-gpu-proving-experiment",
    target_os = "linux",
    target_arch = "x86_64"
))]
pub(super) mod qualification;
#[cfg(all(
    feature = "note-gpu-proving-experiment",
    target_os = "linux",
    target_arch = "x86_64"
))]
pub use qualification::ProducedNote;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PreparationError {
    Statement(Error),
    Core(core::Error),
    ResourceLimit,
}
impl std::fmt::Display for PreparationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for PreparationError {}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct PreparationReceipt {
    pub preparation_payload_bytes: usize,
    pub expected_statement_backing_bytes: usize,
    pub additional_owner_bytes: usize,
    pub aggregate_reserved_bytes: usize,
    pub metadata_prepared: bool,
    pub gpu_work_performed: bool,
    pub full_prover_lifetime_admitted: bool,
    pub dispatch_enabled: bool,
}

/// No Clone or borrowed-view escape. The core owner retains its own charge and
/// drops before this enclosing owner's residual same-session reservation. A
/// move or dropped DecodeSession never releases either live reservation.
pub struct PreparedNote<'w> {
    prepared: core::PreparedNote<'w>,
    context: Context,
    receipt: PreparationReceipt,
    #[cfg(all(
        feature = "note-gpu-proving-experiment",
        target_os = "linux",
        target_arch = "x86_64"
    ))]
    public: [lattica_prover_p3::config::Val; 26],
    _reservation: Reservation,
}

impl PreparedNote<'_> {
    pub fn context(&self) -> Context {
        self.context
    }
    pub fn receipt(&self) -> PreparationReceipt {
        self.receipt
    }
    pub fn diagnostics(&self) -> core::Diagnostics {
        self.prepared.diagnostics()
    }
    pub fn require_dispatch(&self) -> Result<(), Error> {
        Err(Error::IncompleteLifetimeAdmission)
    }
}

impl DecodeSession {
    /// Public metadata only: reserves the cumulative charge before preparing
    /// even the first periodic/compiler vector. Private proof arithmetic,
    /// entropy consumption and GPU initialization do not occur in this phase.
    pub fn prepare_note<'w>(
        &self,
        witness: &'w note::Witness,
        expected: &note::Statement,
        context: Context,
    ) -> Result<PreparedNote<'w>, PreparationError> {
        let plan = core::PreparationPlan::new(NATIVE_HOST_BYTES).map_err(PreparationError::Core)?;
        let receipt = requirements(plan, expected)?;
        let mut reservation = self
            .reserve_for_producer(receipt.aggregate_reserved_bytes)
            .map_err(|_| PreparationError::ResourceLimit)?;
        let public =
            codec::expected_public(expected, context).map_err(PreparationError::Statement)?;
        let core_reservation = reservation
            .split_off(plan.required_host_bytes())
            .map_err(|_| PreparationError::ResourceLimit)?;
        let prepared = plan
            .prepare(witness, public, core_reservation)
            .map_err(PreparationError::Core)?;
        Ok(PreparedNote {
            prepared,
            context,
            receipt,
            #[cfg(all(
                feature = "note-gpu-proving-experiment",
                target_os = "linux",
                target_arch = "x86_64"
            ))]
            public,
            _reservation: reservation,
        })
    }
}

fn requirements(
    plan: core::PreparationPlan,
    expected: &note::Statement,
) -> Result<PreparationReceipt, PreparationError> {
    let expected_statement_backing_bytes = expected
        .public
        .capacity()
        .checked_mul(size_of::<u64>())
        .ok_or(PreparationError::ResourceLimit)?;
    // Core already includes its inline owner/token, borrowed witness and public
    // values. Add the enclosing owner, receipt and residual token exactly once.
    let additional_owner_bytes = size_of::<PreparedNote<'static>>()
        .checked_sub(size_of::<core::PreparedNote<'static>>())
        .ok_or(PreparationError::ResourceLimit)?;
    let preparation_payload_bytes = plan.required_host_bytes();
    let aggregate_reserved_bytes = preparation_payload_bytes
        .checked_add(expected_statement_backing_bytes)
        .and_then(|n| n.checked_add(additional_owner_bytes))
        .ok_or(PreparationError::ResourceLimit)?;
    Ok(PreparationReceipt {
        preparation_payload_bytes,
        expected_statement_backing_bytes,
        additional_owner_bytes,
        aggregate_reserved_bytes,
        metadata_prepared: true,
        gpu_work_performed: false,
        full_prover_lifetime_admitted: false,
        dispatch_enabled: false,
    })
}

#[cfg(all(test, not(debug_assertions), target_arch = "x86_64"))]
mod tests {
    use super::*;

    #[test]
    fn prepared_owner_uses_decoder_quota_through_move_and_session_drop() {
        let context = Context([93; 32]);
        let (statement, witness) = note::fixture(context).unwrap();
        let plan = core::PreparationPlan::new(NATIVE_HOST_BYTES).unwrap();
        let required = requirements(plan, &statement)
            .unwrap()
            .aggregate_reserved_bytes;
        let session = DecodeSession::new(required + super::super::quota::LEDGER_BYTES).unwrap();
        let prepared = session.prepare_note(&witness, &statement, context).unwrap();
        assert_eq!(
            session.snapshot().live_reserved_bytes,
            required + super::super::quota::LEDGER_BYTES
        );
        assert!(matches!(
            session.prepare_note(&witness, &statement, context),
            Err(PreparationError::ResourceLimit)
        ));
        assert!(!prepared.receipt().gpu_work_performed);
        assert!(!prepared.diagnostics().dispatch_enabled);
        assert!(prepared.require_dispatch().is_err());
        let moved = prepared;
        assert_eq!(
            moved._reservation.reserved_bytes(),
            required - plan.required_host_bytes()
        );
        let retained_ledger = moved._reservation.reserve_related(0).unwrap();
        drop(session);
        assert!(retained_ledger.reserve_related(1).is_err());
        drop(moved);
        let reclaimed = retained_ledger.reserve_related(required).unwrap();
        drop(reclaimed);
    }

    #[test]
    fn invalid_inputs_release_same_quota_before_preparation() {
        let context = Context([94; 32]);
        let (statement, witness) = note::fixture(context).unwrap();
        let session = DecodeSession::new(NATIVE_HOST_BYTES).unwrap();
        let baseline = session.snapshot().live_reserved_bytes;
        let wrong_context = Context([95; 32]);
        assert!(matches!(
            session.prepare_note(&witness, &statement, wrong_context),
            Err(PreparationError::Statement(Error::Context))
        ));
        assert_eq!(session.snapshot().live_reserved_bytes, baseline);
        let mut bad = witness.clone();
        bad.outputs[0].value += 1;
        assert!(matches!(
            session.prepare_note(&bad, &statement, context),
            Err(PreparationError::Core(core::Error::Statement))
        ));
        assert_eq!(session.snapshot().live_reserved_bytes, baseline);
        bad = witness.clone();
        bad.inputs[0].nk[0] = crate::GOLDILOCKS_MODULUS;
        assert!(matches!(
            session.prepare_note(&bad, &statement, context),
            Err(PreparationError::Core(core::Error::Statement))
        ));
        assert_eq!(session.snapshot().live_reserved_bytes, baseline);
    }
}
