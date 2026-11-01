use super::*;
use crate::{
    component_tree::EndpointContext,
    execution::workflow_resources::{ExecutionAccess, PhaseBinding, Retained, RetainedNative},
    graph_crypto::{OuterProofCache, ProofCache},
};
use std::time::Instant;

pub(super) mod native;
#[cfg(all(feature = "full-workflow-experiment", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
pub(super) mod retaining;
pub(crate) use native::{OwnedShakeNativeSource, ProducedShakeNative, RecordedShakeNative};

#[derive(Clone)]
pub(crate) struct PairedEndpoints<'request> {
    request: &'request Request,
    context: GraphContext,
    endpoints: EndpointContext,
    elapsed_ns: u128,
}
pub(crate) struct PairedNativeOutput<'request> {
    request: &'request Request,
    index: usize,
    proof: lattica_prover_p3::block_v2::native_gpu::shake_output::OwnedShakeProof,
    verification: crate::component_tree::shake_verification_memory::VerificationReceipt,
    elapsed_ns: u128,
}
impl<'request> PairedEndpoints<'request> {
    pub(super) fn prepared(request: &'request Request, context: GraphContext,
        endpoints: EndpointContext, elapsed_ns: u128) -> Self {
        Self { request, context, endpoints, elapsed_ns }
    }
    pub(super) fn check_source(&self, request: &Request, context: &GraphContext) -> Result<()> {
        if !core::ptr::eq(self.request, request) || &self.context != context
            || self.endpoints.context != context.context || self.endpoints.statement != context.statement {
            return Err(PairedFailure::Authority);
        }
        Ok(())
    }
    #[cfg(test)]
    pub(super) fn assert_fixed_copy(&self, request: &Request, context: &GraphContext,
        endpoints: &EndpointContext, elapsed_ns: u128) {
        assert!(core::ptr::eq(self.request, request));
        assert_eq!(&self.context, context);
        assert_eq!(&self.endpoints, endpoints);
        assert_eq!(self.elapsed_ns, elapsed_ns);
    }
    pub(super) fn elapsed_ns(&self) -> u128 { self.elapsed_ns }
}
impl PairedNativeOutput<'_> {
    pub(super) fn elapsed_ns(&self) -> u128 { self.elapsed_ns }
}

fn access(binding: PhaseBinding, access: &ExecutionAccess<'_>) -> Result<()> {
    if access.binding() != binding
        || access.context().policy() != lattica_prover_p3::proving::Policy::GpuRequired {
        return Err(PairedFailure::Authority);
    }
    Ok(())
}
fn owner<T>(value: &Retained<T>, binding: PhaseBinding, access: &ExecutionAccess<'_>) -> Result<()> {
    if !value.belongs_to(access) || value.binding() != binding {
        return Err(PairedFailure::Authority);
    }
    Ok(())
}

impl<'request> PairedRequestPlan<'request> {
    fn binding(&self, ordinal: usize, expected: RequestStepKind) -> Result<PhaseBinding> {
        if self.steps.get(ordinal).map(|step| step.kind) != Some(expected) {
            return Err(PairedFailure::Order);
        }
        PhaseBinding::for_paired(self, ordinal).map_err(|_| PairedFailure::Authority)
    }
    fn binding_of(&self, expected: RequestStepKind) -> Result<PhaseBinding> {
        let ordinal = self.steps.iter().position(|step| step.kind == expected).ok_or(PairedFailure::Order)?;
        self.binding(ordinal, expected)
    }

    pub(crate) fn endpoint_operation(&self, ordinal: usize) -> Result<PairedEndpointOperation<'_, 'request>> {
        Ok(PairedEndpointOperation { plan: self, binding: self.binding(ordinal, RequestStepKind::Endpoints)? })
    }
    pub(crate) fn native_operation<'plan>(&'plan self, ordinal: usize, cache: &'plan ProofCache)
        -> Result<PairedNativeOperation<'plan, 'request>> {
        let RequestStepKind::Native { index } = self.steps.get(ordinal).ok_or(PairedFailure::Order)?.kind else {
            return Err(PairedFailure::Order);
        };
        Ok(PairedNativeOperation { plan: self, index, cache, started: Instant::now(),
            binding: self.binding(ordinal, RequestStepKind::Native { index })? })
    }
    pub(crate) fn group_operation<'plan>(&'plan self, ordinal: usize,
        endpoints: &'plan Retained<PairedEndpoints<'request>>,
        children: [Option<RetainedNative<PairedNativeOutput<'request>>>; 2])
        -> Result<PairedGroupOperation<'plan, 'request>> {
        let RequestStepKind::Group { node } = self.steps.get(ordinal).ok_or(PairedFailure::Order)?.kind else {
            return Err(PairedFailure::Order);
        };
        Ok(PairedGroupOperation { plan: self, node, endpoints, children,
            binding: self.binding(ordinal, RequestStepKind::Group { node })? })
    }
    pub(crate) fn merge_operation<'plan>(&'plan self, ordinal: usize,
        left: Retained<PairedNode<'request>>, right: Retained<PairedNode<'request>>)
        -> Result<PairedMergeOperation<'plan, 'request>> {
        let kind @ RequestStepKind::Merge { node, left: left_id, right: right_id } =
            self.steps.get(ordinal).ok_or(PairedFailure::Order)?.kind else { return Err(PairedFailure::Order); };
        Ok(PairedMergeOperation { plan: self, node, left_id, right_id, left, right,
            binding: self.binding(ordinal, kind)? })
    }
    pub(crate) fn outer_operation<'plan>(&'plan self, ordinal: usize,
        compiled: Retained<PairedCompiled<'request>>, cache: &'plan OuterProofCache)
        -> Result<PairedOuterOperation<'plan, 'request>> {
        let RequestStepKind::Outer { node } = self.steps.get(ordinal).ok_or(PairedFailure::Order)?.kind else {
            return Err(PairedFailure::Order);
        };
        Ok(PairedOuterOperation { plan: self, node, compiled, cache,
            binding: self.binding(ordinal, RequestStepKind::Outer { node })? })
    }
}

pub(crate) struct PairedEndpointOperation<'plan, 'request> {
    plan: &'plan PairedRequestPlan<'request>,
    binding: PhaseBinding,
}
impl<'request> PairedEndpointOperation<'_, 'request> {
    pub(crate) fn binding(&self) -> PhaseBinding { self.binding }
    pub(crate) fn execute(self, execution: &ExecutionAccess<'_>) -> Result<PairedEndpoints<'request>> {
        access(self.binding, execution)?;
        // Validate and copy fixed data with the original immutable binding.
        // No Session, report, GPU command or dynamic allocation is opened.
        self.plan.prepared_endpoint_output()
    }
}

pub(crate) struct PairedNativeOperation<'plan, 'request> {
    plan: &'plan PairedRequestPlan<'request>,
    index: usize,
    cache: &'plan ProofCache,
    started: Instant,
    binding: PhaseBinding,
}
impl<'request> PairedNativeOperation<'_, 'request> {
    pub(crate) fn binding(&self) -> PhaseBinding { self.binding }
    pub(crate) fn native_cache(&self) -> &ProofCache { self.cache }
    pub(crate) fn request(&self) -> &'request Request { self.plan.request }
    pub(crate) fn index(&self) -> usize { self.index }

}

pub(crate) struct PairedGroupOperation<'plan, 'request> {
    plan: &'plan PairedRequestPlan<'request>,
    node: usize,
    endpoints: &'plan Retained<PairedEndpoints<'request>>,
    children: [Option<RetainedNative<PairedNativeOutput<'request>>>; 2],
    binding: PhaseBinding,
}
impl<'request> PairedGroupOperation<'_, 'request> {
    pub(crate) fn binding(&self) -> PhaseBinding { self.binding }
    pub(crate) fn preparation_requirements(&self)
        -> Result<(Requirements, crate::execution::retained_resources::Bytes)> {
        self.plan.group_preparation_requirements(self.binding.ordinal())
    }
    pub(crate) fn execute_with_operations(self, execution: &ExecutionAccess<'_>,
        operations: &lattica_prover_p3::block_v2::native_gpu::OperationContext<'_>)
        -> Result<PairedCompiled<'request>> {
        access(self.binding, execution)?;
        owner(self.endpoints, self.plan.binding_of(RequestStepKind::Endpoints)?, execution)?;
        let endpoints = self.endpoints.get();
        let node = self.plan.nodes.get(self.node).ok_or(PairedFailure::Order)?;
        let span = node.group.ok_or(PairedFailure::Order)?;
        if !core::ptr::eq(endpoints.request, self.plan.request) || endpoints.context != self.plan.context
            || self.children.iter().filter(|child| child.is_some()).count() != span.segment_count
            || self.children[0].is_none() || (span.segment_count == 1 && self.children[1].is_some()) {
            return Err(PairedFailure::Authority);
        }
        let mut proofs = [None, None];
        for (offset, child) in self.children.iter().take(span.segment_count).enumerate() {
            let child = child.as_ref().ok_or(PairedFailure::Coverage)?;
            let index = add(span.first_segment, offset)?;
            if !child.belongs_to(execution)
                || child.binding() != self.plan.binding_of(RequestStepKind::Native { index })? {
                return Err(PairedFailure::Authority);
            }
            if !core::ptr::eq(child.get().request, self.plan.request) || child.get().index != index {
                return Err(PairedFailure::Authority);
            }
            proofs[offset] = Some(child.get().proof.artifact());
        }
        let first = proofs[0].ok_or(PairedFailure::Coverage)?;
        let children = [first, proofs[1].unwrap_or(first)];
        let result = paired_runtime::compile_group(self.plan.request, &self.plan.context,
            &endpoints.endpoints, span, node.source, &children[..span.segment_count], execution, operations);
        // No proof extraction: both retained owners die before A's backend
        // cleanup barrier makes their original slots eligible for reuse.
        drop(self.children);
        result
    }
}

pub(crate) struct PairedMergeOperation<'plan, 'request> {
    plan: &'plan PairedRequestPlan<'request>,
    node: usize,
    left_id: usize,
    right_id: usize,
    left: Retained<PairedNode<'request>>,
    right: Retained<PairedNode<'request>>,
    binding: PhaseBinding,
}
impl<'request> PairedMergeOperation<'_, 'request> {
    pub(crate) fn binding(&self) -> PhaseBinding { self.binding }
    pub(crate) fn execute(self, execution: &ExecutionAccess<'_>) -> Result<PairedCompiled<'request>> {
        access(self.binding, execution)?;
        owner(&self.left, self.plan.binding_of(RequestStepKind::Outer { node: self.left_id })?, execution)?;
        owner(&self.right, self.plan.binding_of(RequestStepKind::Outer { node: self.right_id })?, execution)?;
        let node = self.plan.nodes.get(self.node).ok_or(PairedFailure::Order)?;
        if node.children != Some([self.left_id, self.right_id])
            || !core::ptr::eq(self.left.get().request(), self.plan.request)
            || !core::ptr::eq(self.right.get().request(), self.plan.request)
            || self.left.get().context() != &self.plan.context || self.right.get().context() != &self.plan.context
            || ComponentSpan::merge(self.left.get().span(), self.right.get().span())? != node.span {
            return Err(PairedFailure::Authority);
        }
        let result = paired_runtime::compile_parent(self.left.get(), self.right.get(), node.source, execution);
        drop((self.left, self.right));
        result
    }
}

pub(crate) struct PairedOuterOperation<'plan, 'request> {
    plan: &'plan PairedRequestPlan<'request>,
    node: usize,
    compiled: Retained<PairedCompiled<'request>>,
    cache: &'plan OuterProofCache,
    binding: PhaseBinding,
}
impl<'request> PairedOuterOperation<'_, 'request> {
    #[cfg(feature = "full-workflow-experiment")]
    pub(crate) fn identity_plan(&self) -> &PairedRequestPlan<'request> { self.plan }
    #[cfg(feature = "full-workflow-experiment")]
    pub(crate) fn identity_node(&self) -> usize { self.node }
    #[cfg(feature = "full-workflow-experiment")]
    pub(crate) fn identity_compiler(&self) -> &PairedCompiled<'request> { self.compiled.get() }
    #[cfg(feature = "full-workflow-experiment")]
    pub(crate) fn validate_identity_peer(&self, peer: &Retained<PairedCompiled<'request>>,
        node: usize, execution: &ExecutionAccess<'_>) -> Result<()> {
        self.borrowed_parts(execution)?;
        let source = self.plan.nodes.get(node).ok_or(PairedFailure::Order)?;
        if source.group.is_none() { return Err(PairedFailure::Source); }
        owner(peer, self.plan.binding_of(RequestStepKind::Group { node })?, execution)?;
        if !peer.get().matches_source(self.plan.request, &self.plan.context, source.span, source.source) {
            return Err(PairedFailure::SourceDrift);
        }
        Ok(())
    }
    pub(crate) fn binding(&self) -> PhaseBinding { self.binding }
    pub(crate) fn input_slot(&self) -> crate::execution::workflow_resources::SlotId { self.compiled.slot_id() }
    pub(crate) fn source_shape(&self) -> Result<lattica_prover_p3::block_v2::machine::OuterSourceShape> {
        self.plan.nodes.get(self.node).ok_or(PairedFailure::Order)?.source.outer_shape()
    }
    pub(crate) fn borrowed_parts<'a>(&'a self, execution: &ExecutionAccess<'_>)
        -> Result<(&'a std::sync::Arc<lattica_prover_p3::block_v2::machine::Program>,
            &'a Vec<lattica_prover_p3::block_v2::machine::program::Val>, &'a Vec<lattica_prover_p3::block_v2::machine::program::Val>)> {
        access(self.binding, execution)?;
        let node = self.plan.nodes.get(self.node).ok_or(PairedFailure::Order)?;
        let compiler = match node.children {
            None => RequestStepKind::Group { node: self.node },
            Some([left, right]) => RequestStepKind::Merge { node: self.node, left, right },
        };
        owner(&self.compiled, self.plan.binding_of(compiler)?, execution)?;
        if !self.compiled.get().matches_source(self.plan.request, &self.plan.context, node.span, node.source) {
            return Err(PairedFailure::SourceDrift);
        }
        Ok(self.compiled.get().borrowed_parts())
    }
    pub(crate) fn compiled_report(&self) -> paired_runtime::PairedNodeReport { self.compiled.get().report() }
    pub(super) fn prove_registered(&self,
        scope: &mut crate::execution::workflow_resources::OwnedOuterScope<'_, '_>,
        registered: lattica_prover_p3::block_v2::machine::backend::RegisteredProgram,
        backend: &lattica_prover_p3::block_v2::machine::OuterBackendAdmission<'_>) -> Result<PairedNode<'request>> {
        self.borrowed_parts(scope.execution())?;
        paired_runtime::produce_owned_outer(self.compiled.get(), self.cache, scope,
            registered, backend)
    }
}
