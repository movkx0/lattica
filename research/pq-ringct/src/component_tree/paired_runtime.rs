//! Owned paired-request compiler/prover operations used only by a preissued
//! whole-workflow phase. Defaults and the public layout refusal stay unchanged.

use super::*;
use crate::{
    execution::workflow_resources::ExecutionAccess,
    graph_crypto::{Request, ShakeWrapperSpan},
    graph_tree::GraphContext,
    proof_cache_policy::ProofCachePolicy,
};
use core::mem::size_of;
use lattica_prover_p3::block_v2::profile;
use std::time::Instant;

pub(crate) mod source;
pub(crate) use source::ComponentSourceFacts;
mod aes;
pub(crate) use aes::compile_aes;
mod owned_outer;
pub(crate) use owned_outer::{owned_outer_requirements, produce_owned_outer};
#[cfg(test)]
mod routing_tests;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PairedFailure {
    Unsupported,
    Resource,
    Authority,
    Source,
    SourceDrift,
    Coverage,
    Context,
    Order,
    Overflow,
    Rows,
    Capacity,
    Preparation,
    Native,
    Compilation,
    Proof,
    Verification,
    Cleanup,
}
pub(crate) type Result<T> = core::result::Result<T, PairedFailure>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ComponentSpan {
    pub(crate) first: u32,
    pub(crate) count: u32,
    pub(crate) level: u32,
}
impl ComponentSpan {
    pub(crate) fn leaf(span: ShakeWrapperSpan) -> Result<Self> {
        Ok(Self { first: u32::try_from(span.first_unit).map_err(|_| PairedFailure::Overflow)?,
            count: u32::try_from(span.units).map_err(|_| PairedFailure::Overflow)?, level: 0 })
    }
    pub(crate) fn merge(left: Self, right: Self) -> Result<Self> {
        if left.count == 0 || right.count == 0 || left.first.checked_add(left.count) != Some(right.first) {
            return Err(PairedFailure::Coverage);
        }
        Ok(Self { first: left.first,
            count: left.count.checked_add(right.count).ok_or(PairedFailure::Overflow)?,
            level: left.level.max(right.level).checked_add(1).ok_or(PairedFailure::Overflow)? })
    }
    fn agrees(self, spec: &Spec) -> bool {
        self.first == spec.first && self.count == spec.count && self.level == spec.level
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct PairedNodeReport {
    pub(crate) active_rows: usize,
    pub(crate) padded_rows: usize,
    pub(crate) compile_ns: u128,
    pub(crate) setup_ns: u128,
    pub(crate) registered_phase_ns: u128,
    pub(crate) proving_ns: u128,
    pub(crate) cpu_verification_ns: u128,
}

/// Only a bounded compile operation constructs this payload. A's Retained
/// owner keeps its original compiler/input claim while proving borrows it.
pub(crate) struct PairedCompiled<'request> {
    #[cfg(feature = "full-workflow-experiment")]
    identity_prefix: std::cell::RefCell<Option<lattica_prover_p3::block_v2::machine::backend::identity_cpu::CompletedIdentityPrefix>>,
    node: CompiledNode,
    request: &'request Request,
    context: GraphContext,
    endpoints: EndpointContext,
    span: ComponentSpan,
    source: ComponentSourceFacts,
    report: PairedNodeReport,
}
impl PairedCompiled<'_> {
    #[cfg(feature = "full-workflow-experiment")]
    pub(crate) fn identity_prefix_is_empty(&self) -> Result<bool> {
        Ok(self.identity_prefix.try_borrow().map_err(|_| PairedFailure::Authority)?.is_none())
    }
    #[cfg(feature = "full-workflow-experiment")]
    pub(crate) fn install_identity_prefix(&self,
        prefix: lattica_prover_p3::block_v2::machine::backend::identity_cpu::CompletedIdentityPrefix) -> Result<()> {
        use lattica_prover_p3::block_v2::machine::backend::identity_cpu::IDENTITY_PREFIX_HOST_BYTES;
        let mut target = self.identity_prefix.try_borrow_mut().map_err(|_| PairedFailure::Authority)?;
        if target.is_some() || prefix.retained_host_bytes() > IDENTITY_PREFIX_HOST_BYTES {
            return Err(PairedFailure::Capacity);
        }
        *target = Some(prefix);
        Ok(())
    }
    #[cfg(feature = "full-workflow-experiment")]
    pub(crate) fn take_identity_prefix(&self)
        -> Result<Option<lattica_prover_p3::block_v2::machine::backend::identity_cpu::CompletedIdentityPrefix>> {
        Ok(self.identity_prefix.try_borrow_mut().map_err(|_| PairedFailure::Authority)?.take())
    }
    /// Borrows stay inside the charged compiler owner throughout outer work.
    pub(crate) fn borrowed_parts(&self) -> (&Arc<lattica_prover_p3::block_v2::machine::Program>, &Vec<Val>, &Vec<Val>) {
        (&self.node.program, &self.node.public, &self.node.witness)
    }
    pub(crate) fn source(&self) -> ComponentSourceFacts { self.source }
    pub(crate) fn report(&self) -> PairedNodeReport { self.report }
    pub(crate) fn matches_source(&self, request: &Request, context: &GraphContext,
        span: ComponentSpan, source: ComponentSourceFacts) -> bool {
        core::ptr::eq(self.request, request) && &self.context == context
            && self.span == span && self.source == source
    }
}
impl Drop for PairedCompiled<'_> {
    fn drop(&mut self) {
        for value in &mut self.node.witness {
            // SAFETY: this owner exclusively owns its witness vector.
            unsafe { core::ptr::write_volatile(value, Val::ZERO) };
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}

/// Actual registered key/proof provenance remains private. No clone, mutable
/// access or into_parts operation detaches either payload from its owner.
pub(crate) struct PairedNode<'request> {
    key: NodeKey,
    proof: NodeProof,
    request: &'request Request,
    context: GraphContext,
    endpoints: EndpointContext,
    span: ComponentSpan,
    source: ComponentSourceFacts,
    report: PairedNodeReport,
}
impl<'request> PairedNode<'request> {
    pub(crate) fn request(&self) -> &'request Request { self.request }
    pub(crate) fn context(&self) -> &GraphContext { &self.context }
    pub(crate) fn span(&self) -> ComponentSpan { self.span }
    pub(crate) fn source(&self) -> ComponentSourceFacts { self.source }
    pub(crate) fn report(&self) -> PairedNodeReport { self.report }
    pub(crate) fn endpoints(&self) -> &EndpointContext { &self.endpoints }
    pub(crate) fn graph_aes_artifact(&self) -> Result<crate::graph_tree::AesProof<'_>> {
        if !matches!(self.key.spec.contract.kind, Kind::Aes(_)) { return Err(PairedFailure::Source); }
        Ok(crate::graph_tree::AesProof::Tree { key: &self.key, proof: &self.proof })
    }
    pub(crate) fn graph_artifact(&self) -> crate::graph_tree::ShakeProof<'_> {
        crate::graph_tree::ShakeProof::Tree { key: &self.key, proof: &self.proof }
    }
    pub(crate) fn check_root(&self, request: &Request, context: &GraphContext) -> Result<()> {
        if !core::ptr::eq(self.request, request) || &self.context != context
            || self.span.first != 0 || usize::try_from(self.span.count).ok() != Some(request.units())
            || !self.span.agrees(&self.key.spec)
            || self.key.spec.end() != self.key.spec.contract.total {
            return Err(PairedFailure::Authority);
        }
        Ok(())
    }
}

pub(crate) fn caller_bytes() -> Result<usize> {
    use source::{add, bytes};
    let parts = [
        bytes::<PairedCompiled<'static>>(8)?, bytes::<PairedNode<'static>>(8)?,
        bytes::<Result<PairedCompiled<'static>>>(8)?, bytes::<Result<PairedNode<'static>>>(8)?,
        bytes::<PairedNodeReport>(8)?, bytes::<ComponentSourceFacts>(8)?,
        bytes::<ComponentSpan>(8)?, bytes::<EndpointContext>(8)?, bytes::<GraphContext>(8)?,
        bytes::<Spec>(8)?, bytes::<NodeKey>(8)?, bytes::<NodeProof>(8)?,
        bytes::<CompiledNode>(8)?, bytes::<[Val; source::PUBLICS]>(8)?,
        bytes::<[Wire; source::PUBLICS]>(8)?, bytes::<ProgramBuilder>(8)?,
        bytes::<[[Wire; source::PUBLICS]; 2]>(4)?,
        bytes::<[[Wire; 4]; 1 << profile::CAP_HEIGHT]>(4)?,
        bytes::<MachineAir>(4)?, bytes::<RegisteredVerifier>(4)?,
        bytes::<ProofInputs>(8)?, bytes::<String>(8)?, bytes::<Instant>(8)?,
        bytes::<PairedFailure>(8)?, bytes::<Result<()>>(8)?, 64 << 10,
    ];
    parts.into_iter().try_fold(8 * size_of::<[usize; 22]>(), add)
}

fn compiled<'request>(node: CompiledNode, request: &'request Request, context: &GraphContext,
    endpoints: &EndpointContext, span: ComponentSpan, source: ComponentSourceFacts,
    compile_ns: u128) -> Result<PairedCompiled<'request>> {
    source.check_compiled(&node)?;
    if !span.agrees(&node.spec) || node.spec.contract != request.contract().map_err(|_| PairedFailure::Source)?
        || endpoints.context != context.context || endpoints.statement != context.statement {
        return Err(PairedFailure::Context);
    }
    let report = PairedNodeReport { active_rows: node.program.active_rows(),
        padded_rows: node.program.height(), compile_ns, ..PairedNodeReport::default() };
    Ok(PairedCompiled {
        #[cfg(feature = "full-workflow-experiment")]
        identity_prefix: std::cell::RefCell::new(None),
        node, request, context: context.clone(), endpoints: endpoints.clone(),
        span, source, report })
}

pub(crate) fn compile_group<'request>(request: &'request Request, context: &GraphContext,
    endpoints: &EndpointContext, span: ShakeWrapperSpan, source: ComponentSourceFacts,
    children: &[&shake_air::lane::LaneShakeProof], access: &ExecutionAccess<'_>,
    operations: &lattica_prover_p3::block_v2::native_gpu::OperationContext<'_>)
    -> Result<PairedCompiled<'request>> {
    if !(1..=2).contains(&span.segment_count) || children.len() != span.segment_count
        || access.context().policy() != lattica_prover_p3::proving::Policy::GpuRequired {
        return Err(PairedFailure::Authority);
    }
    let segment = |offset: usize| request.segments().get(span.first_segment + offset)
        .ok_or(PairedFailure::Coverage);
    let first = segment(0)?;
    let second = if children.len() == 2 { segment(1)? } else { first };
    let members = [
        ShakeGroupMember { first: u32::try_from(first.first_unit).map_err(|_| PairedFailure::Overflow)?,
            count: u32::try_from(first.units).map_err(|_| PairedFailure::Overflow)?, proof: children[0] },
        ShakeGroupMember { first: u32::try_from(second.first_unit).map_err(|_| PairedFailure::Overflow)?,
            count: u32::try_from(second.units).map_err(|_| PairedFailure::Overflow)?,
            proof: children[children.len() - 1] },
    ];
    let contract = request.contract().map_err(|_| PairedFailure::Source)?;
    let footprint = ShakeGroupCompileFootprint::for_group(children.len(), source::construction())
        .map_err(|_| PairedFailure::Capacity)?;
    let started = Instant::now();
    // Endpoint hashing borrows the concrete driver's already-admitted owned
    // epoch; it must never reopen the retired source ProvingContext Session.
    check_shake_group_members(&contract, &members[..children.len()])
        .map_err(|_| PairedFailure::Coverage)?;
    for member in &members[..children.len()] {
        shake_compile_memory::air(&contract, member).map_err(|_| PairedFailure::Source)?;
    }
    let result = preparation::with_endpoint_operations(operations, |hasher| {
        compile_shake_group_bounded_body(&contract, &members[..children.len()], endpoints,
            source::construction(), footprint, hasher)
    }).map_err(|_| PairedFailure::Compilation)?;
    let node = match result {
        ShakeGroupCompileOutcome::Compiled(node) => node,
        ShakeGroupCompileOutcome::ResourceRefused(_) => return Err(PairedFailure::Capacity),
    };
    compiled(node, request, context, endpoints, ComponentSpan::leaf(span)?, source, started.elapsed().as_nanos())
}

pub(crate) fn compile_parent<'request>(left: &PairedNode<'request>, right: &PairedNode<'request>,
    source: ComponentSourceFacts, _access: &ExecutionAccess<'_>) -> Result<PairedCompiled<'request>> {
    if !core::ptr::eq(left.request, right.request) || left.context != right.context
        || left.endpoints != right.endpoints || !left.span.agrees(&left.key.spec)
        || !right.span.agrees(&right.key.spec) {
        return Err(PairedFailure::Authority);
    }
    let span = ComponentSpan::merge(left.span, right.span)?;
    let spec = Spec::merge(&left.key.spec, &right.key.spec).map_err(|_| PairedFailure::Coverage)?;
    if !span.agrees(&spec) { return Err(PairedFailure::SourceDrift); }
    let started = Instant::now();
    let mut public = left.proof.public.clone();
    if public.len() != source::PUBLICS || right.proof.public.len() != source::PUBLICS {
        return Err(PairedFailure::SourceDrift);
    }
    public[FIRST] = Val::from_u32(span.first);
    public[COUNT] = Val::from_u32(span.count);
    public[LEVEL] = Val::from_u32(span.level);
    public[HEADER + 4..].copy_from_slice(&right.proof.public[HEADER + 4..]);
    let mut builder = ProgramBuilder::new_with_construction_limits(source::PUBLICS, source::construction())
        .map_err(|_| PairedFailure::Capacity)?;
    let outer: [Wire; source::PUBLICS] = public_wires(&mut builder, &spec)
        .map_err(|_| PairedFailure::Compilation)?.try_into().map_err(|_| PairedFailure::SourceDrift)?;
    let mut inputs = ProofInputs::default();
    let mut wires = [[outer[0]; source::PUBLICS]; 2];
    for (index, child) in [left, right].into_iter().enumerate() {
        let actual = source::registered_shape(child.key.height)?;
        if child.key.cap.len() != actual.preprocessing_cap_roots { return Err(PairedFailure::SourceDrift); }
        wires[index] = inputs.bases(&mut builder, &child.proof.public)
            .map_err(|_| PairedFailure::Compilation)?.try_into().map_err(|_| PairedFailure::SourceDrift)?;
        let mut cap = [[outer[0]; 4]; 1 << profile::CAP_HEIGHT];
        for (target, root) in cap.iter_mut().zip(&child.key.cap) {
            *target = root.map(|value| builder.constant(value));
        }
        verifier::batch::verify_with_bounded_cpu_symbolic(&mut builder, &mut inputs,
            &child.key.air().map_err(|_| PairedFailure::Source)?, &wires[index],
            &cap[..child.key.cap.len()], &child.proof.proof).map_err(|_| PairedFailure::Compilation)?;
    }
    bind_merge(&mut builder, &spec, &outer, &wires[0], &wires[1]);
    let node = CompiledNode { spec, program: Arc::new(builder.finish(None).map_err(|_| PairedFailure::Capacity)?),
        public, witness: inputs.values };
    compiled(node, left.request, &left.context, &left.endpoints, span, source, started.elapsed().as_nanos())
}
