//! Concrete final aggregation issuers. Source facts and preissued originals
//! close before proof zero; no caller callback or replacement ledger enters.
use super::*;
use crate::ordered_aggregation::owned_final::{
    FinalCompileOperation, FinalCompiled, FinalFailure, FinalNode, FinalReport,
    FinalVerification, FinalVerifyOperation,
};
use core::mem::size_of;

mod compile;
mod verify;
pub(super) mod guard;
pub(crate) use compile::final_compile_issuer_requirements;
pub(crate) use verify::final_verify_issuer_requirements;

#[derive(Clone, Copy, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Stage { Compile, Outer, Verify }
#[derive(serde::Serialize)]
struct StageEntry<'a> {
    schema: &'static str,
    ordinal: usize,
    stage: Stage,
    report: &'a FinalReport,
}
impl crate::execution::report_transport::FixedPayload for StageEntry<'_> {}

pub(super) fn emit_stage(ordinal: usize, stage: Stage, report: &FinalReport)
    -> Result<(), FinalFailure>
{
    let mut measured = *report;
    // A retained node carries its compile summary for later inspection. Each
    // phase entry reports only that phase's measured work, avoiding a second
    // count of the earlier compile when the outer proof is reported.
    match stage {
        Stage::Compile => { measured.setup_ns = 0; measured.proving_ns = 0; measured.recursive_proofs = 0; }
        Stage::Outer => measured.compile_ns = 0,
        Stage::Verify => {
            measured.compile_ns = 0; measured.setup_ns = 0; measured.proving_ns = 0;
            measured.recursive_proofs = 0;
        }
    }
    crate::execution::report_transport::emit(b"owned_final_stage ", &StageEntry {
        schema: "ringct-owned-final-stage-v1", ordinal, stage, report: &measured,
    }).map_err(|_| FinalFailure::Report)
}

/// Fixed transport backing is additive to each concrete issuer's frame census.
/// This source-only helper grants no admission or serialization authority.
pub(crate) fn final_report_transport_host_bytes() -> usize {
    crate::execution::report_transport::required_host_bytes()
        + 8 * size_of::<StageEntry<'static>>()
        + 8 * size_of::<FinalReport>()
}

pub(crate) fn final_outer_forwarding_host_bytes() -> Result<u64, WorkflowError> {
    let base = super::outer_owned::forwarding_host_bytes().map_err(|_| WorkflowError::Planning)?;
    let extra = [
        size_of::<FinalReport>(), size_of::<Option<u128>>(),
        size_of::<guard::RetirementGuard<'static,
            crate::ordered_aggregation::owned_final::FinalOuterOperation<'static, 'static>>>(),
        size_of::<guard::RetirementGuard<'static, Reservation>>(),
        size_of::<guard::RetirementGuard<'static, Option<FinalNode<'static>>>>(),
        size_of::<guard::RetirementGuard<'static, SlotClaim>>(),
        size_of::<Result<SlotClaim, FinalFailure>>(),
        size_of::<Option<FinalNode<'static>>>(),
        size_of::<Result<Option<FinalNode<'static>>, FinalFailure>>(),
        size_of::<Result<(), super::OuterOwnedError>>(),
        size_of::<Result<FinalNode<'static>, super::OuterOwnedError>>(),
        size_of::<Result<Retained<FinalNode<'static>>, PhaseFailure<super::OuterOwnedError>>>(),
        size_of::<std::cell::Cell<bool>>(), size_of::<StageEntry<'static>>(),
    ].into_iter().try_fold(0usize, |sum, next| sum.checked_add(next))
        .and_then(|sum| sum.checked_mul(8)).ok_or(WorkflowError::Overflow)?;
    base.checked_add(u64::try_from(extra).map_err(|_| WorkflowError::Overflow)?)
        .ok_or(WorkflowError::Overflow)
}
