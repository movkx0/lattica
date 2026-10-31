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
pub(crate) use native::{OwnedAesNativeSource, ProducedAesNative, RecordedAesNative};

#[derive(Clone)]
pub(crate) struct OwnedAesEndpoints<'request> {
    request: &'request Request,
    context: GraphContext,
    endpoints: EndpointContext,
    elapsed_ns: u128,
}
pub(crate) struct OwnedAesNativeOutput<'request> {
    request: &'request Request,
    index: usize,
    proof: lattica_prover_p3::block_v2::native_gpu::aes_output::OwnedAesProof,
    verification: crate::component_tree::aes_verification_memory::VerificationReceipt,
    elapsed_ns: u128,
}
impl<'request> OwnedAesEndpoints<'request> {
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
impl OwnedAesNativeOutput<'_> {
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

impl<'request> OwnedAesRequestPlan<'request> {
    fn binding(&self, ordinal: usize, expected: OwnedAesStepKind) -> Result<PhaseBinding> {
        if self.steps.get(ordinal).map(|step| step.kind) != Some(expected) {
            return Err(PairedFailure::Order);
        }
        PhaseBinding::for_aes(self, ordinal).map_err(|_| PairedFailure::Authority)
    }
    fn binding_of(&self, expected: OwnedAesStepKind) -> Result<PhaseBinding> {
        let ordinal = self.steps.iter().position(|step| step.kind == expected).ok_or(PairedFailure::Order)?;
        self.binding(ordinal, expected)
    }

    pub(crate) fn endpoint_operation(&self, ordinal: usize) -> Result<OwnedAesEndpointOperation<'_, 'request>> {
        Ok(OwnedAesEndpointOperation { plan: self, binding: self.binding(ordinal, OwnedAesStepKind::Endpoints)? })
    }
    pub(crate) fn native_operation<'plan>(&'plan self, ordinal: usize, cache: &'plan ProofCache)
        -> Result<OwnedAesNativeOperation<'plan, 'request>> {
        let OwnedAesStepKind::Native { index } = self.steps.get(ordinal).ok_or(PairedFailure::Order)?.kind else {
            return Err(PairedFailure::Order);
        };
        Ok(OwnedAesNativeOperation { plan: self, index, cache, started: Instant::now(),
            binding: self.binding(ordinal, OwnedAesStepKind::Native { index })? })
    }
    pub(crate) fn compile_operation<'plan>(&'plan self, ordinal: usize,
        endpoints: &'plan Retained<OwnedAesEndpoints<'request>>,
        child: RetainedNative<OwnedAesNativeOutput<'request>>)
        -> Result<OwnedAesCompileOperation<'plan, 'request>> {
        let OwnedAesStepKind::Compile { node } = self.steps.get(ordinal).ok_or(PairedFailure::Order)?.kind else {
            return Err(PairedFailure::Order);
        };
        Ok(OwnedAesCompileOperation { plan: self, node, endpoints, child,
            binding: self.binding(ordinal, OwnedAesStepKind::Compile { node })? })
    }
    pub(crate) fn merge_operation<'plan>(&'plan self, ordinal: usize,
        left: Retained<PairedNode<'request>>, right: Retained<PairedNode<'request>>)
        -> Result<OwnedAesMergeOperation<'plan, 'request>> {
        let kind @ OwnedAesStepKind::Merge { node, left: left_id, right: right_id } =
            self.steps.get(ordinal).ok_or(PairedFailure::Order)?.kind else { return Err(PairedFailure::Order); };
        Ok(OwnedAesMergeOperation { plan: self, node, left_id, right_id, left, right,
            binding: self.binding(ordinal, kind)? })
    }
    pub(crate) fn outer_operation<'plan>(&'plan self, ordinal: usize,
        compiled: Retained<PairedCompiled<'request>>, cache: &'plan OuterProofCache)
        -> Result<OwnedAesOuterOperation<'plan, 'request>> {
        let OwnedAesStepKind::Outer { node } = self.steps.get(ordinal).ok_or(PairedFailure::Order)?.kind else {
            return Err(PairedFailure::Order);
        };
        Ok(OwnedAesOuterOperation { plan: self, node, compiled, cache,
            binding: self.binding(ordinal, OwnedAesStepKind::Outer { node })? })
    }
}

pub(crate) struct OwnedAesEndpointOperation<'plan, 'request> {
    plan: &'plan OwnedAesRequestPlan<'request>,
    binding: PhaseBinding,
}
impl<'request> OwnedAesEndpointOperation<'_, 'request> {
    pub(crate) fn binding(&self) -> PhaseBinding { self.binding }
    pub(crate) fn execute(self, execution: &ExecutionAccess<'_>) -> Result<OwnedAesEndpoints<'request>> {
        access(self.binding, execution)?;
        // Validate and copy fixed data with the original immutable binding.
        // No Session, report, GPU command or dynamic allocation is opened.
        self.plan.prepared_endpoint_output()
    }
}

pub(crate) struct OwnedAesNativeOperation<'plan, 'request> {
    plan: &'plan OwnedAesRequestPlan<'request>,
    index: usize,
    cache: &'plan ProofCache,
    started: Instant,
    binding: PhaseBinding,
}
impl<'request> OwnedAesNativeOperation<'_, 'request> {
    pub(crate) fn binding(&self) -> PhaseBinding { self.binding }
    pub(crate) fn native_cache(&self) -> &ProofCache { self.cache }
    pub(crate) fn request(&self) -> &'request Request { self.plan.request }
    pub(crate) fn index(&self) -> usize { self.index }

}

pub(crate) struct OwnedAesCompileOperation<'plan, 'request> {
    plan: &'plan OwnedAesRequestPlan<'request>,
    node: usize,
    endpoints: &'plan Retained<OwnedAesEndpoints<'request>>,
    child: RetainedNative<OwnedAesNativeOutput<'request>>,
    binding: PhaseBinding,
}
impl<'request> OwnedAesCompileOperation<'_, 'request> {
    pub(crate) fn binding(&self) -> PhaseBinding { self.binding }
    pub(crate) fn preparation_requirements(&self)
        -> Result<(Requirements, crate::execution::retained_resources::Bytes)> {
        self.plan.group_preparation_requirements(self.binding.ordinal())
    }
    pub(crate) fn execute_with_operations(self, execution: &ExecutionAccess<'_>,
        operations: &lattica_prover_p3::block_v2::native_gpu::OperationContext<'_>)
        -> Result<PairedCompiled<'request>> {
        access(self.binding, execution)?;
        owner(self.endpoints, self.plan.binding_of(OwnedAesStepKind::Endpoints)?, execution)?;
        let endpoints = self.endpoints.get();
        endpoints.check_source(self.plan.request, &self.plan.context)?;
        let node = self.plan.nodes.get(self.node).ok_or(PairedFailure::Order)?;
        let index = node.segment.ok_or(PairedFailure::Order)?;
        if !self.child.belongs_to(execution)
            || self.child.binding() != self.plan.binding_of(OwnedAesStepKind::Native { index })?
            || !core::ptr::eq(self.child.get().request, self.plan.request)
            || self.child.get().index != index {
            return Err(PairedFailure::Authority);
        }
        let result = paired_runtime::compile_aes(self.plan.request, &self.plan.context,
            &endpoints.endpoints, index, node.source, self.child.get().proof.artifact(), execution, operations);
        // Destruction follows the native owner; no proof fields are detached.
        // The concrete driver retires its epoch before original slot reuse.
        drop(self.child);
        result
    }
}

pub(crate) struct OwnedAesMergeOperation<'plan, 'request> {
    plan: &'plan OwnedAesRequestPlan<'request>,
    node: usize,
    left_id: usize,
    right_id: usize,
    left: Retained<PairedNode<'request>>,
    right: Retained<PairedNode<'request>>,
    binding: PhaseBinding,
}
impl<'request> OwnedAesMergeOperation<'_, 'request> {
    pub(crate) fn binding(&self) -> PhaseBinding { self.binding }
    pub(crate) fn execute(self, execution: &ExecutionAccess<'_>) -> Result<PairedCompiled<'request>> {
        access(self.binding, execution)?;
        owner(&self.left, self.plan.binding_of(OwnedAesStepKind::Outer { node: self.left_id })?, execution)?;
        owner(&self.right, self.plan.binding_of(OwnedAesStepKind::Outer { node: self.right_id })?, execution)?;
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

pub(crate) struct OwnedAesOuterOperation<'plan, 'request> {
    plan: &'plan OwnedAesRequestPlan<'request>,
    node: usize,
    compiled: Retained<PairedCompiled<'request>>,
    cache: &'plan OuterProofCache,
    binding: PhaseBinding,
}
impl<'request> OwnedAesOuterOperation<'_, 'request> {
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
            None => OwnedAesStepKind::Compile { node: self.node },
            Some([left, right]) => OwnedAesStepKind::Merge { node: self.node, left, right },
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
