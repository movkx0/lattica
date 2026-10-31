use super::*;
impl AuxiliaryGraphOutputs<'_> {
    pub(crate) fn kind(&self) -> AuxiliaryGraphKind {
        match self { Self::SampleG { .. } => AuxiliaryGraphKind::SampleG, Self::ExpandAlpha { .. } => AuxiliaryGraphKind::ExpandAlpha,
            Self::HashAlpha { .. } => AuxiliaryGraphKind::HashAlpha, Self::HashX { .. } => AuxiliaryGraphKind::HashX }
    }
    /// Only the returned prefix is a dependency list. Remaining entries repeat
    /// its first slot to avoid constructing an unauthenticated SlotId sentinel.
    pub(crate) fn input_slots(&self) -> ([SlotId; 6], usize) {
        let slots = match self {
            Self::SampleG { aes, uniform } => [aes.root_slot(), aes.endpoint_slot(), uniform.slot_id(),
                aes.root_slot(), aes.root_slot(), aes.root_slot()],
            Self::ExpandAlpha { uniform_aes: a, uniform, sparse_aes: b, sparse } =>
                [a.root_slot(), a.endpoint_slot(), uniform.slot_id(), b.root_slot(), b.endpoint_slot(), sparse.slot_id()],
            Self::HashAlpha { shake, transcript } => [shake.root_slot(), shake.endpoint_slot(), transcript.slot_id(),
                shake.root_slot(), shake.root_slot(), shake.root_slot()],
            Self::HashX { shake, transcript, sparse } => [shake.root_slot(), shake.endpoint_slot(), transcript.slot_id(),
                sparse.slot_id(), shake.root_slot(), shake.root_slot()],
        };
        (slots, self.kind().input_count())
    }
    pub(crate) fn check_source(&self, sources: AuxiliaryGraphSources<'_, '_>, execution: &ExecutionAccess<'_>) -> OwnedResult<()> {
        macro_rules! native {
            ($output:expr, $plan:expr, $binding:ident) => {{
                let output = $output; let plan = $plan;
                let binding = PhaseBinding::$binding(plan, 0).map_err(|_| GraphParentFailure::Authority)?;
                if !output.belongs_to(execution) || output.binding() != binding || output.get().binding() != binding
                    || !core::ptr::eq(output.get().sources(), plan.sources())
                    || !output.get().source().same_source(plan.source())
                    || !core::ptr::eq(output.get().request(), plan.request())
                    || output.get().operation_index() != plan.operation_index()
                    || output.get().role() != plan.role() || output.get().kind() != plan.kind()
                { return Err(GraphParentFailure::Authority); }
            }};
        }
        use AuxiliaryGraphSources as S;
        match (self, sources) {
            (Self::SampleG { aes, uniform }, S::SampleG { aes: a, uniform: u }) => {
                aes.check_source(a, execution).map_err(|_| GraphParentFailure::Authority)?;
                native!(uniform, u, for_uniform_native);
            }
            (Self::ExpandAlpha { uniform_aes, uniform, sparse_aes, sparse },
                S::ExpandAlpha { uniform_aes: a, uniform: u, sparse_aes: b, sparse: s }) => {
                uniform_aes.check_source(a, execution).map_err(|_| GraphParentFailure::Authority)?;
                sparse_aes.check_source(b, execution).map_err(|_| GraphParentFailure::Authority)?;
                native!(uniform, u, for_uniform_native); native!(sparse, s, for_sparse_native);
            }
            (Self::HashAlpha { shake, transcript }, S::HashAlpha { shake: s, transcript: t }) => {
                shake.check_source(s, execution).map_err(|_| GraphParentFailure::Authority)?;
                native!(transcript, t, for_transcript_native);
            }
            (Self::HashX { shake, transcript, sparse }, S::HashX { shake: s, transcript: t, sparse: p }) => {
                shake.check_source(s, execution).map_err(|_| GraphParentFailure::Authority)?;
                native!(transcript, t, for_transcript_native); native!(sparse, p, for_sparse_native);
            }
            _ => return Err(GraphParentFailure::Source),
        }
        let (slots, count) = self.input_slots();
        if slots[..count].iter().enumerate().any(|(i, slot)| slots[..i].contains(slot)) {
            return Err(GraphParentFailure::Authority);
        }
        Ok(())
    }
}
impl<'source, 'a> AuxiliaryGraphPlan<'source, 'a> {
    pub(crate) fn compile_operation<'plan>(&'plan self, outputs: AuxiliaryGraphOutputs<'a>)
        -> OwnedResult<AuxiliaryCompileOperation<'plan, 'source, 'a>> {
        if outputs.kind() != self.kind() { return Err(GraphParentFailure::Source); }
        Ok(AuxiliaryCompileOperation { plan: self, outputs, binding: self.binding(0)? })
    }
    pub(crate) fn compile_operation_retaining<'plan>(&'plan self,
        outputs: AuxiliaryGraphOutputs<'a>)
        -> core::result::Result<AuxiliaryCompileOperation<'plan, 'source, 'a>,
            (GraphParentFailure, AuxiliaryGraphOutputs<'a>)>
    {
        if outputs.kind() != self.kind() { return Err((GraphParentFailure::Source, outputs)); }
        match self.binding(0) {
            Ok(binding) => Ok(AuxiliaryCompileOperation { plan: self, outputs, binding }),
            Err(error) => Err((error, outputs)),
        }
    }
    /// Every refusal returns exactly these typed owners, in input order.
    pub(crate) fn sample_g_operation_retaining<'plan>(&'plan self, aes: OwnedAesRequestOutput<'a>, uniform: RetainedNative<OwnedUniformOutput<'a>>)
        -> core::result::Result<AuxiliaryCompileOperation<'plan, 'source, 'a>, (GraphParentFailure, OwnedAesRequestOutput<'a>, RetainedNative<OwnedUniformOutput<'a>>)>
    {
        if self.kind() != AuxiliaryGraphKind::SampleG {
            return Err((GraphParentFailure::Source, aes, uniform));
        }
        let binding = match self.binding(0) {
            Ok(binding) => binding,
            Err(error) => return Err((error, aes, uniform)),
        };
        Ok(AuxiliaryCompileOperation { plan: self, binding,
            outputs: AuxiliaryGraphOutputs::SampleG { aes, uniform } })
    }
    /// Every refusal returns exactly these typed owners, in input order.
    pub(crate) fn expand_alpha_operation_retaining<'plan>(&'plan self, uniform_aes: OwnedAesRequestOutput<'a>, uniform: RetainedNative<OwnedUniformOutput<'a>>, sparse_aes: OwnedAesRequestOutput<'a>, sparse: RetainedNative<OwnedSparseOutput<'a>>)
        -> core::result::Result<AuxiliaryCompileOperation<'plan, 'source, 'a>, (GraphParentFailure, OwnedAesRequestOutput<'a>, RetainedNative<OwnedUniformOutput<'a>>, OwnedAesRequestOutput<'a>, RetainedNative<OwnedSparseOutput<'a>>)>
    {
        if self.kind() != AuxiliaryGraphKind::ExpandAlpha {
            return Err((GraphParentFailure::Source, uniform_aes, uniform, sparse_aes, sparse));
        }
        let binding = match self.binding(0) {
            Ok(binding) => binding,
            Err(error) => return Err((error, uniform_aes, uniform, sparse_aes, sparse)),
        };
        Ok(AuxiliaryCompileOperation { plan: self, binding,
            outputs: AuxiliaryGraphOutputs::ExpandAlpha { uniform_aes, uniform, sparse_aes, sparse } })
    }
    /// Every refusal returns exactly these typed owners, in input order.
    pub(crate) fn hash_alpha_operation_retaining<'plan>(&'plan self, shake: PairedRequestOutput<'a>, transcript: RetainedNative<OwnedTranscriptOutput<'a>>)
        -> core::result::Result<AuxiliaryCompileOperation<'plan, 'source, 'a>, (GraphParentFailure, PairedRequestOutput<'a>, RetainedNative<OwnedTranscriptOutput<'a>>)>
    {
        if self.kind() != AuxiliaryGraphKind::HashAlpha {
            return Err((GraphParentFailure::Source, shake, transcript));
        }
        let binding = match self.binding(0) {
            Ok(binding) => binding,
            Err(error) => return Err((error, shake, transcript)),
        };
        Ok(AuxiliaryCompileOperation { plan: self, binding,
            outputs: AuxiliaryGraphOutputs::HashAlpha { shake, transcript } })
    }
    /// Every refusal returns exactly these typed owners, in input order.
    pub(crate) fn hash_x_operation_retaining<'plan>(&'plan self, shake: PairedRequestOutput<'a>, transcript: RetainedNative<OwnedTranscriptOutput<'a>>, sparse: RetainedNative<OwnedSparseOutput<'a>>)
        -> core::result::Result<AuxiliaryCompileOperation<'plan, 'source, 'a>, (GraphParentFailure, PairedRequestOutput<'a>, RetainedNative<OwnedTranscriptOutput<'a>>, RetainedNative<OwnedSparseOutput<'a>>)>
    {
        if self.kind() != AuxiliaryGraphKind::HashX {
            return Err((GraphParentFailure::Source, shake, transcript, sparse));
        }
        let binding = match self.binding(0) {
            Ok(binding) => binding,
            Err(error) => return Err((error, shake, transcript, sparse)),
        };
        Ok(AuxiliaryCompileOperation { plan: self, binding,
            outputs: AuxiliaryGraphOutputs::HashX { shake, transcript, sparse } })
    }
    pub(crate) fn outer_operation<'plan>(&'plan self, compiled: Retained<OwnedGraphCompiled<'a>>)
        -> OwnedResult<AuxiliaryOuterOperation<'plan, 'source, 'a>> {
        Ok(AuxiliaryOuterOperation { plan: self, compiled, binding: self.binding(1)? })
    }
    /// Refusal preserves the original compiled owner; the caller must poison.
    pub(crate) fn outer_operation_retaining<'plan>(&'plan self,
        compiled: Retained<OwnedGraphCompiled<'a>>)
        -> core::result::Result<AuxiliaryOuterOperation<'plan, 'source, 'a>,
            (GraphParentFailure, Retained<OwnedGraphCompiled<'a>>)>
    {
        match self.binding(1) {
            Ok(binding) => Ok(AuxiliaryOuterOperation { plan: self, compiled, binding }),
            Err(error) => Err((error, compiled)),
        }
    }
}
pub(crate) struct AuxiliaryCompileOperation<'plan, 'source, 'a> {
    plan: &'plan AuxiliaryGraphPlan<'source, 'a>,
    outputs: AuxiliaryGraphOutputs<'a>, binding: PhaseBinding,
}
impl<'a> AuxiliaryCompileOperation<'_, '_, 'a> {
    pub(crate) fn binding(&self) -> PhaseBinding { self.binding }
    pub(crate) fn input_slots(&self) -> ([SlotId; 6], usize) { self.outputs.input_slots() }
    pub(crate) fn execute(self, execution: &ExecutionAccess<'_>) -> OwnedResult<OwnedGraphCompiled<'a>> {
        self.plan.check_execution(self.binding, execution)?;
        self.plan.sources.validate(self.plan.prepared, self.plan.context, self.plan.source.span.first as usize)?;
        self.outputs.check_source(self.plan.sources, execution)?;
        let started = Instant::now();
        let artifact = crate::graph_tree::leaf::BoundedAuxiliaryLeaf::from_owned(&self.outputs,
            self.plan.sources, self.plan.source.context, execution).map_err(|_| GraphParentFailure::Source)?;
        let mut artifacts = Vec::new();
        artifacts.try_reserve_exact(1).map_err(|_| GraphParentFailure::Capacity)?;
        if artifacts.capacity() > 1 { return Err(GraphParentFailure::Capacity); }
        artifacts.push(crate::graph_tree::LeafArtifact::OwnedAuxiliary(artifact));
        let node = crate::graph_tree::owned_components::compile_group(self.plan.source.plan,
            self.plan.prepared.get().graph(), self.plan.source.span.first as usize,
            self.plan.source.context, artifacts, super::super::source::construction(), execution)
            .map_err(|_| GraphParentFailure::Compilation)?;
        // The wiping compiled owner precedes all post-compilation refusals.
        // Every original request/native/endpoint claim survives the final read.
        let compiled = OwnedGraphCompiled { report: GraphNodeReport { active_rows: node.program.active_rows(),
            padded_rows: node.program.height(), compile_ns: started.elapsed().as_nanos(),
            ..GraphNodeReport::default() }, node, source: self.plan.source };
        self.plan.source.check_compiled(&compiled.node)?;
        drop(self.outputs);
        Ok(compiled)
    }
}
pub(crate) struct AuxiliaryOuterOperation<'plan, 'source, 'a> {
    plan: &'plan AuxiliaryGraphPlan<'source, 'a>,
    compiled: Retained<OwnedGraphCompiled<'a>>, binding: PhaseBinding,
}
impl<'a> AuxiliaryOuterOperation<'_, '_, 'a> {
    pub(crate) fn binding(&self) -> PhaseBinding { self.binding }
    pub(crate) fn input_slot(&self) -> SlotId { self.compiled.slot_id() }
    pub(crate) fn source_shape(&self) -> OwnedResult<OuterSourceShape> { self.plan.source.outer_shape() }
    pub(crate) fn borrowed_parts<'borrow>(&'borrow self, execution: &ExecutionAccess<'_>)
        -> OwnedResult<(&'borrow Arc<Program>, &'borrow Vec<Val>, &'borrow Vec<Val>)> {
        self.plan.check_execution(self.binding, execution)?;
        if self.compiled.binding() != self.plan.binding(0)? || !self.compiled.belongs_to(execution)
            || !self.compiled.get().source.same_source(self.plan.source) { return Err(GraphParentFailure::Authority); }
        self.plan.source.check_compiled(&self.compiled.get().node)?;
        let node = &self.compiled.get().node;
        Ok((&node.program, &node.public, &node.witness))
    }
    pub(crate) fn compiled_report(&self) -> GraphNodeReport { self.compiled.get().report }
    pub(super) fn prove_registered(&self,
        scope: &mut crate::execution::workflow_resources::OwnedOuterScope<'_, '_>, registered: RegisteredProgram,
        backend: &lattica_prover_p3::block_v2::machine::OuterBackendAdmission<'_>,
    ) -> OwnedResult<OwnedGraphNode<'a>> {
        self.borrowed_parts(scope.execution())?;
        super::super::outer::produce(self.compiled.get(), self.plan.cache, scope, registered, backend)
    }
}
