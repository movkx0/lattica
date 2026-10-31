//! Concrete 28-public graph parents. Private graph construction/registration
//! stays inside tree; an arithmetic source bound cannot attach a raw proof.
//! Real leaf producers must supply their source owner and original GraphOuter
//! binding. Until those producers exist the whole-case closure still refuses.
use super::*;
use crate::execution::{
    retained_resources::{Bytes, Category, Ledger, Requirements, Reservation},
    workflow_resources::{ExecutionAccess, PhaseBinding, PhaseFacts, PhaseKind, Retained, SlotId},
};
use crate::{graph_crypto::OuterProofCache, proof_cache_policy::ProofCachePolicy};
use core::mem::size_of;
use lattica_prover_p3::block_v2::machine::{
    program::{ConstructionLimits, MAX_WIRES},
    verifier::batch::shape::{self, OperationCounts, PlanningStorage, RegisteredChildShape},
    OuterSourceShape,
};
use p3_field::PrimeField64;
use sha3::{Digest, Sha3_256};
use std::time::Instant;

mod source;
mod memory;
mod operations;
mod outer;
mod native_leaf;
mod fixed_leaf;
pub(crate) use fixed_leaf::{FixedLeafOuterPlan, FixedLeafOuterOperation,
    PreissuedFixedLeafOuter, BoundFixedLeafOuter};
mod auxiliary;
pub(crate) use auxiliary::{AuxiliaryGraphKind, AuxiliaryGraphSources, AuxiliaryGraphOutputs,
    AuxiliaryGraphPlan, AuxiliaryPreparedInventory, AuxiliaryDependencies, AuxiliaryCompileOperation, AuxiliaryOuterOperation,
    PreissuedAuxiliaryOuter, BoundAuxiliaryOuter};
mod equality;
pub(crate) use equality::{EqualityGraphPlan, EqualityDependencies, EqualityCompileOperation,
    EqualityOuterOperation, PreissuedEqualityOuter, BoundEqualityOuter};
mod parameters_pp;
pub(crate) use parameters_pp::{ParametersPpGraphPlan, ParametersPpCompileOperation,
    ParametersPpOuterOperation, PreissuedParametersPpOuter, BoundParametersPpOuter};
pub(crate) use native_leaf::{NativeLeafOuterPlan, NativeLeafOuterOperation,
    PreissuedNativeLeafOuter, BoundNativeLeafOuter};
pub(crate) use operations::{GraphParentCompileOperation, GraphParentOuterOperation};
pub(crate) use outer::{BoundGraphParentOuter, PreissuedGraphParentOuter};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum GraphParentFailure {
    Authority, Order, Coverage, Source, Resource, Capacity, Overflow,
    Compilation, Proof, Verification, Report,
}
type OwnedResult<T> = core::result::Result<T, GraphParentFailure>;
fn add(a: usize, b: usize) -> OwnedResult<usize> {
    a.checked_add(b).ok_or(GraphParentFailure::Overflow)
}
fn mul(a: usize, b: usize) -> OwnedResult<usize> {
    a.checked_mul(b).filter(|n| *n <= isize::MAX as usize).ok_or(GraphParentFailure::Overflow)
}
fn bytes<T>(count: usize) -> OwnedResult<usize> { mul(size_of::<T>(), count) }
fn requirement(category: Category, host: usize) -> OwnedResult<Requirements> {
    Ok(Requirements::single(category, Bytes {
        host: u64::try_from(host).map_err(|_| GraphParentFailure::Overflow)?, device: 0,
    }))
}
fn combine(parts: &[Requirements]) -> OwnedResult<Requirements> {
    let mut result = Requirements::default();
    for part in parts { for category in Category::ALL {
        result.add(category, part.get(category)).map_err(|_| GraphParentFailure::Overflow)?;
    } }
    Ok(result)
}
fn contains(have: Requirements, need: Requirements) -> bool {
    Category::ALL.into_iter().all(|category| {
        let a = have.get(category); let b = need.get(category);
        a.host >= b.host && a.device >= b.device
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct GraphSpan { pub(super) first: u32, pub(super) count: u32, pub(super) level: u32 }
impl GraphSpan {
    fn merge(left: Self, right: Self, total: usize) -> OwnedResult<Self> {
        let end = left.first.checked_add(left.count).ok_or(GraphParentFailure::Overflow)?;
        let count = left.count.checked_add(right.count).ok_or(GraphParentFailure::Overflow)?;
        let complete_end = left.first.checked_add(count).ok_or(GraphParentFailure::Overflow)?;
        if left.count == 0 || right.count == 0 || end != right.first
            || usize::try_from(complete_end).ok().is_none_or(|end| end > total)
        { return Err(GraphParentFailure::Coverage); }
        Ok(Self { first: left.first, count, level: left.level.max(right.level)
            .checked_add(1).ok_or(GraphParentFailure::Overflow)? })
    }
    fn agrees(self, spec: &Spec) -> bool {
        self.first == spec.first && self.count == spec.count && self.level == spec.level
    }
    pub(crate) fn interval(self) -> (usize, usize) { (self.first as usize, self.count as usize) }
}

/// Source facts only. Fields are private to the graph tree's concrete producers;
/// no public numeric constructor or proof/header-derived source exists.
#[derive(Clone, Copy)]
pub(crate) struct GraphNodeSource<'graph> {
    pub(super) plan: &'graph Plan,
    pub(super) context: &'graph GraphContext,
    pub(super) span: GraphSpan,
    pub(super) operations: OperationCounts,
    pub(super) maximum_active_rows: usize,
    pub(super) maximum_padded_rows: usize,
    pub(super) maximum_wires: usize,
    pub(super) maximum_inputs: usize,
    pub(super) maximum_hint_words: usize,
    pub(super) source_fingerprint: [u8; 32],
    pub(super) compiled_source_fingerprint: [u8; 32],
}

/// Borrow keeps the concrete child source/metadata owner alive. Only graph
/// producers in this private tree module can construct a leaf input source.
#[derive(Clone, Copy)]
pub(crate) struct GraphChildSource<'source, 'graph> {
    pub(super) source: &'source GraphNodeSource<'graph>,
    pub(super) binding: PhaseBinding,
}
impl GraphChildSource<'_, '_> {
    pub(crate) fn binding(&self) -> PhaseBinding { self.binding }
    pub(crate) fn source(&self) -> &GraphNodeSource<'_> { self.source }
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct GraphNodeReport {
    pub(crate) active_rows: usize,
    pub(crate) padded_rows: usize,
    pub(crate) compile_ns: u128,
    pub(crate) setup_ns: u128,
    pub(crate) proving_ns: u128,
    pub(crate) cpu_verification_ns: u128,
    pub(crate) registered_phase_ns: u128,
}
pub(crate) struct OwnedGraphCompiled<'graph> {
    pub(super) node: CompiledNode,
    pub(super) source: GraphNodeSource<'graph>,
    pub(super) report: GraphNodeReport,
}
impl Drop for OwnedGraphCompiled<'_> {
    fn drop(&mut self) {
        self.node.witness.fill(Val::ZERO);
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }
}
pub(crate) struct OwnedGraphNode<'graph> {
    pub(super) key: NodeKey,
    pub(super) proof: NodeProof,
    pub(super) source: GraphNodeSource<'graph>,
    pub(super) report: GraphNodeReport,
}
impl<'graph> OwnedGraphNode<'graph> {
    pub(crate) fn key(&self) -> &NodeKey { &self.key }
    pub(crate) fn proof(&self) -> &NodeProof { &self.proof }
    pub(crate) fn graph_plan(&self) -> &'graph Plan { self.source.plan }
    pub(crate) fn context(&self) -> &'graph GraphContext { self.source.context }
    pub(crate) fn source(&self) -> &GraphNodeSource<'graph> { &self.source }
    pub(crate) fn report(&self) -> GraphNodeReport { self.report }
}

/// One concrete adjacent merge, exactly compile then owned outer proof. A
/// whole-case source plan retains every parent and both original child plans.
pub(crate) struct GraphParentPlan<'source, 'graph> {
    children: [GraphChildSource<'source, 'graph>; 2],
    source: GraphNodeSource<'graph>,
    facts: [PhaseFacts; 2],
    cache: &'source OuterProofCache,
    original: Reservation,
}
impl<'source, 'graph> GraphParentPlan<'source, 'graph> {
    pub(crate) fn planning_requirements() -> OwnedResult<Requirements> {
        // Keep every plan/result shell and the complete outer preissue owner.
        // Temporary caller frames have separate construction/runtime originals.
        requirement(Category::RegisteredMetadata, add(memory::retained_planning_frames()?,
            PreissuedGraphParentOuter::metadata_host_bytes()?)?)
    }
    pub(crate) fn planning_scratch_requirements() -> OwnedResult<Requirements> {
        source::planning_scratch_requirements()
    }
    // Validate the concrete original and separately admitted construction
    // scratch before inspecting any child. This issues no source authority.
    fn check_planning_claims(original: &Reservation, scratch: &Reservation,
        ledger: &Ledger) -> OwnedResult<()>
    {
        if !original.belongs_to(ledger)
            || original.requirements() != Self::planning_requirements()?
            || !scratch.belongs_to(ledger)
            || !contains(scratch.requirements(), Self::planning_scratch_requirements()?)
            || !crate::host_memory_profile::HostMemoryProfile::valid_worker_ceiling(ledger.snapshot().allowance.host)
            || ledger.snapshot().allowance.device > 8 << 30
        { return Err(GraphParentFailure::Authority); }
        Ok(())
    }
    pub(crate) fn derive_pre_reserved(children: [GraphChildSource<'source, 'graph>; 2],
        cache: &'source OuterProofCache, original: Reservation, scratch: &Reservation,
        ledger: &Ledger) -> OwnedResult<Self>
    {
        if cache.policy() != ProofCachePolicy::FreshOnly { return Err(GraphParentFailure::Authority); }
        Self::check_planning_claims(&original, scratch, ledger)?;
        for child in children {
            let facts = child.binding.facts();
            if facts.kind != PhaseKind::GraphOuter
                || facts.source_fingerprint != child.source.source_fingerprint
                || facts.compiled_source_fingerprint != child.source.compiled_source_fingerprint
                || facts.output != child.source.output_requirements()?.0
            { return Err(GraphParentFailure::Authority); }
        }
        let source = GraphNodeSource::parent(children[0].source, children[1].source)?;
        let (compiled, compile_scratch) = memory::compiler_requirements()?;
        let (output, verifier) = source.output_requirements()?;
        let failure = memory::failure_requirements()?;
        let facts = |kind, output, scratch| PhaseFacts { kind, output, scratch, failure,
            source_fingerprint: source.source_fingerprint,
            compiled_source_fingerprint: source.compiled_source_fingerprint };
        Ok(Self { children, source, facts: [
            facts(PhaseKind::GraphParentCompile, compiled, compile_scratch),
            facts(PhaseKind::GraphOuter, output, combine(&[verifier, outer::caller_requirements()?,
                PreissuedGraphParentOuter::planning_scratch_requirement()?])?),
        ], cache, original })
    }
    pub(crate) fn phase_facts(&self, ordinal: usize) -> Option<PhaseFacts> { self.facts.get(ordinal).copied() }
    pub(crate) fn source(&self) -> &GraphNodeSource<'graph> { &self.source }
    pub(crate) fn child_sources(&self) -> &[GraphChildSource<'source, 'graph>; 2] { &self.children }
    pub(crate) fn belongs_to(&self, ledger: &Ledger) -> bool { self.original.belongs_to(ledger) }
    pub(crate) fn child_source(&'source self) -> OwnedResult<GraphChildSource<'source, 'graph>> {
        Ok(GraphChildSource { source: &self.source, binding: self.binding(1)? })
    }
    pub(crate) fn binding(&self, ordinal: usize) -> OwnedResult<PhaseBinding> {
        PhaseBinding::for_graph_parent(self, ordinal).map_err(|_| GraphParentFailure::Authority)
    }
}

mod affine_leaf;
pub(crate) use affine_leaf::{AffineLeafOuterPlan, AffineLeafOuterOperation, PreissuedAffineLeafOuter, BoundAffineLeafOuter};

mod ntt_leaf;
pub(crate) use ntt_leaf::{NttLeafOuterPlan, NttLeafOuterOperation, PreissuedNttLeafOuter, BoundNttLeafOuter};

mod mul_leaf;
pub(crate) use mul_leaf::{MulLeafOuterPlan, MulLeafOuterOperation, PreissuedMulLeafOuter, BoundMulLeafOuter};

mod g_bound_leaf;
pub(crate) use g_bound_leaf::{GBoundLeafOuterPlan, GBoundLeafOuterOperation, PreissuedGBoundLeafOuter, BoundGBoundLeafOuter};

mod permutation_leaf;
pub(crate) use permutation_leaf::{PermutationLeafOuterPlan, PermutationLeafOuterOperation, PreissuedPermutationLeafOuter, BoundPermutationLeafOuter};

mod linear_map_leaf;
pub(crate) use linear_map_leaf::{LinearMapLeafOuterPlan, LinearMapLeafOuterOperation, PreissuedLinearMapLeafOuter, BoundLinearMapLeafOuter};
