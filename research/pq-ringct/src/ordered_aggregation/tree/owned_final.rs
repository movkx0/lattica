//! Concrete final merge compiler, producer and independent acceptance stages.
//!
//! Graph inputs are actual retained OwnedGraphNode values. Their producer is a
//! required dependency: this module cannot manufacture a graph proof or turn a
//! numerical source census into workflow admission.
use super::*;
use crate::{
    execution::{
        retained_resources::{Bytes, Category, Ledger, Requirements, Reservation},
        workflow_resources::{ExecutionAccess, PhaseBinding, PhaseFacts, PhaseKind,
            Retained, SlotId},
    },
    graph_crypto::OuterProofCache,
    proof_cache_policy::ProofCachePolicy,
    graph_tree::owned_parent::{GraphChildSource, OwnedGraphNode},
    ordered_aggregation::source::{ChildSource, FinalAggregationPlan, MergeSource, ROW_LIMIT},
};
use core::mem::size_of;

mod memory;
mod operations;
mod outer;
mod plan;
mod qualification;

pub(crate) use operations::{FinalChild, FinalCompileOperation, FinalCompiled, FinalNode,
    FinalOuterOperation, FinalVerification, FinalVerifyOperation};
pub(crate) use outer::{BoundFinalOuter, PreissuedFinalOuter};
pub(crate) use plan::{FinalDependencies, FinalPhasePlan, FinalStepKind};
pub(crate) use qualification::FinalQualificationReport;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FinalFailure {
    Authority, Order, Coverage, Source, Capacity, Overflow, Compile, Preparation,
    Proof, Verification, Runtime, Partition, Report,
}
type OwnedResult<T> = core::result::Result<T, FinalFailure>;

fn add(a: usize, b: usize) -> OwnedResult<usize> {
    a.checked_add(b).ok_or(FinalFailure::Overflow)
}
fn mul(a: usize, b: usize) -> OwnedResult<usize> {
    a.checked_mul(b).filter(|n| *n <= isize::MAX as usize).ok_or(FinalFailure::Overflow)
}
fn bytes<T>(count: usize) -> OwnedResult<usize> { mul(size_of::<T>(), count) }
fn requirement(category: Category, host: usize) -> OwnedResult<Requirements> {
    Ok(Requirements::single(category, Bytes {
        host: u64::try_from(host).map_err(|_| FinalFailure::Overflow)?, device: 0,
    }))
}
fn combine(parts: &[Requirements]) -> OwnedResult<Requirements> {
    let mut total = Requirements::default();
    for part in parts {
        for category in Category::ALL {
            total.add(category, part.get(category)).map_err(|_| FinalFailure::Overflow)?;
        }
    }
    Ok(total)
}
fn contains(have: Requirements, need: Requirements) -> bool {
    Category::ALL.into_iter().all(|category| {
        let a = have.get(category); let b = need.get(category);
        a.host >= b.host && a.device >= b.device
    })
}

/// Fixed retained report. No proof, program, diagnostic String or detached
/// backend report is hidden in this transport payload.
#[derive(Clone, Copy, Default, serde::Serialize)]
pub(crate) struct FinalReport {
    pub(crate) merge: usize,
    pub(crate) first: usize,
    pub(crate) count: usize,
    pub(crate) active_rows: usize,
    pub(crate) padded_rows: usize,
    pub(crate) recursive_proofs: usize,
    pub(crate) compile_ns: u128,
    pub(crate) setup_ns: u128,
    pub(crate) proving_ns: u128,
    pub(crate) cpu_verification_ns: u128,
    pub(crate) qualification: FinalQualificationReport,
}
