use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FinalStepKind { Compile(usize), Outer(usize), Verify }
#[derive(Clone, Copy)]
struct FinalStep { kind: FinalStepKind, facts: PhaseFacts }

/// Immutable exact input identities for the complete scheduler. This is source
/// metadata only; constructing it does not allocate slots or admit execution.
#[derive(Clone, Copy)]
pub(crate) struct FinalDependencies {
    pub(crate) bindings: [Option<PhaseBinding>; 2],
    pub(crate) count: usize,
    pub(crate) consume: usize,
}

/// All final stage facts are frozen before proof0. The incoming graph bindings
/// must name real graph-root producers in the complete scheduler. No such
/// producer is supplied here and no missing-family closure guard is removed.
pub(crate) struct FinalPhasePlan<'source> {
    pub(super) source: &'source FinalAggregationPlan<'source>,
    pub(super) statements: &'source [LeafStatement],
    pub(super) cache: &'source OuterProofCache,
    graph_bindings: [Option<PhaseBinding>; 4],
    graph_sources: [Option<GraphChildSource<'source, 'source>>; 4],
    steps: [Option<FinalStep>; 7],
    original: Reservation,
}
impl<'source> FinalPhasePlan<'source> {
    pub(crate) fn planning_requirements() -> OwnedResult<Requirements> {
        let host = [
            bytes::<Self>(8)?, bytes::<[Option<FinalStep>; 7]>(8)?,
            bytes::<[Option<PhaseBinding>; 4]>(8)?,
            bytes::<[Option<GraphChildSource<'static, 'static>>; 4]>(8)?,
            bytes::<FinalDependencies>(8)?,
            bytes::<OwnedResult<Self>>(8)?, bytes::<Ledger>(8)?,
            bytes::<Reservation>(8)?, bytes::<[LeafStatement; 4]>(4)?,
            memory::forwarding_frames()?,
            mul(3, PreissuedFinalOuter::metadata_host_bytes()?)?,
        ].into_iter().try_fold(0, add)?;
        requirement(Category::RegisteredMetadata, host)
    }
    pub(crate) fn planning_scratch_requirements() -> OwnedResult<Requirements> {
        PreissuedFinalOuter::planning_scratch_requirement()
    }

    pub(crate) fn derive_pre_reserved(source: &'source FinalAggregationPlan<'source>,
        statements: &'source [LeafStatement], graph_producers: &[GraphChildSource<'source, 'source>],
        cache: &'source OuterProofCache, original: Reservation,
        scratch: &Reservation, ledger: &Ledger) -> OwnedResult<Self>
    {
        let total = source.graphs().len();
        if !matches!(total, 3 | 4) || source.merge_count() != total - 1
            || statements.len() != total || graph_producers.len() != total
            || cache.policy() != ProofCachePolicy::FreshOnly
            || !source.belongs_to(ledger) || !original.belongs_to(ledger)
            || !scratch.belongs_to(ledger)
            || !contains(original.requirements(), Self::planning_requirements()?)
            || !contains(scratch.requirements(), Self::planning_scratch_requirements()?)
            || source.compiled_source_fingerprint() != crate::graph_proofs::compiled_source_fingerprint()
        { return Err(FinalFailure::Authority); }
        source.scope().validate_expected(statements).map_err(|_| FinalFailure::Source)?;
        let mut graph_bindings = [None; 4];
        let mut graph_sources = [None; 4];
        for (index, ((graph, statement), producer)) in source.graphs().iter()
            .zip(statements).zip(graph_producers).enumerate()
        {
            let binding = producer.binding();
            let node = producer.source();
            if binding.kind() != PhaseKind::GraphOuter
                || binding.facts().compiled_source_fingerprint != source.compiled_source_fingerprint()
                || binding.facts().source_fingerprint != node.source_fingerprint()
                || binding.facts().compiled_source_fingerprint != node.compiled_source_fingerprint()
                || binding.facts().output != node.output_requirements().map_err(|_| FinalFailure::Source)?.0
                || !core::ptr::eq(node.graph_plan(), graph.plan)
                || !core::ptr::eq(node.context(), graph.context)
                || node.span().interval() != (0, graph.plan.leaves().len())
                || node.maximum_height() > ROW_LIMIT
                || graph.plan.label() != statement.profile
                || graph.context.context != statement.context
                || graph.context.statement.map(|v| v.as_canonical_u64()) != statement.digest
                || graph_producers[..index].iter().any(|prior| prior.binding() == binding)
                || binding.facts().output.get(Category::RecursiveProof).host == 0
                || binding.facts().output.get(Category::RegisteredMetadata).host == 0
            { return Err(FinalFailure::Source); }
            graph_bindings[index] = Some(binding);
            graph_sources[index] = Some(*producer);
        }
        let failure = memory::failure()?;
        let mut steps = [None; 7];
        for merge in 0..source.merge_count() {
            let child = source.merge(merge).ok_or(FinalFailure::Order)?;
            if child.ordinal() != merge || child.rows().1 > ROW_LIMIT {
                return Err(FinalFailure::Source);
            }
            for (offset, kind, output, scratch) in [
                (0, FinalStepKind::Compile(merge), memory::compiler_output(child)?,
                    memory::compiler_scratch(child)?),
                (1, FinalStepKind::Outer(merge), memory::outer_output(child)?.0,
                    memory::outer_scratch(child)?),
            ] {
                steps[2 * merge + offset] = Some(FinalStep { kind, facts: PhaseFacts {
                    kind: if offset == 0 { PhaseKind::FinalCompile } else { PhaseKind::FinalOuter },
                    compiled_source_fingerprint: source.compiled_source_fingerprint(),
                    source_fingerprint: source.source_fingerprint(),
                    output, failure, scratch,
                } });
            }
        }
        let last = source.merge(source.merge_count() - 1).ok_or(FinalFailure::Order)?;
        if last.span() != (0, total) { return Err(FinalFailure::Coverage); }
        steps[2 * source.merge_count()] = Some(FinalStep {
            kind: FinalStepKind::Verify,
            facts: PhaseFacts { kind: PhaseKind::FinalVerify,
                compiled_source_fingerprint: source.compiled_source_fingerprint(),
                source_fingerprint: source.source_fingerprint(),
                output: memory::verification_output()?, failure,
                scratch: memory::verification_scratch(last)? },
        });
        Ok(Self { source, statements, cache, graph_bindings, graph_sources, steps, original })
    }
    pub(crate) fn source(&self) -> &FinalAggregationPlan<'source> { self.source }
    pub(crate) fn statements(&self) -> &[LeafStatement] { self.statements }
    pub(crate) fn step_count(&self) -> usize { 2 * self.source.merge_count() + 1 }
    pub(crate) fn step_kind(&self, ordinal: usize) -> Option<FinalStepKind> {
        self.steps.get(ordinal)?.map(|step| step.kind)
    }
    pub(crate) fn phase_facts(&self, ordinal: usize) -> Option<PhaseFacts> {
        self.steps.get(ordinal)?.map(|step| step.facts)
    }
    pub(crate) fn phase_binding(&self, ordinal: usize) -> OwnedResult<PhaseBinding> {
        self.binding(ordinal, self.step_kind(ordinal).ok_or(FinalFailure::Order)?)
    }
    pub(crate) fn dependencies(&self, ordinal: usize) -> OwnedResult<FinalDependencies> {
        match self.step_kind(ordinal).ok_or(FinalFailure::Order)? {
            FinalStepKind::Compile(merge) => {
                let children = self.source.merge(merge).ok_or(FinalFailure::Order)?.children();
                let mut bindings = [None; 2];
                for (position, child) in children.into_iter().enumerate() {
                    bindings[position] = Some(match child {
                        ChildSource::Graph(index) => self.graph_binding(index)?,
                        ChildSource::Merge(index) if index < merge =>
                            self.binding(2 * index + 1, FinalStepKind::Outer(index))?,
                        ChildSource::Merge(_) => return Err(FinalFailure::Order),
                    });
                }
                Ok(FinalDependencies { bindings, count: 2, consume: 2 })
            }
            FinalStepKind::Outer(merge) => Ok(FinalDependencies {
                bindings: [Some(self.binding(2 * merge, FinalStepKind::Compile(merge))?), None],
                count: 1, consume: 1,
            }),
            FinalStepKind::Verify => {
                let merge = self.source.merge_count().checked_sub(1).ok_or(FinalFailure::Order)?;
                Ok(FinalDependencies {
                    bindings: [Some(self.binding(2 * merge + 1, FinalStepKind::Outer(merge))?), None],
                    count: 1, consume: 0,
                })
            }
        }
    }
    pub(crate) fn belongs_to(&self, ledger: &Ledger) -> bool {
        self.original.belongs_to(ledger) && self.source.belongs_to(ledger)
    }
    pub(crate) fn fresh_only(&self) -> bool { self.cache.policy() == ProofCachePolicy::FreshOnly }
    pub(crate) fn graph_binding(&self, index: usize) -> OwnedResult<PhaseBinding> {
        self.graph_bindings.get(index).copied().flatten().ok_or(FinalFailure::Order)
    }
    pub(super) fn graph_source(&self, index: usize) -> OwnedResult<GraphChildSource<'source, 'source>> {
        self.graph_sources.get(index).copied().flatten().ok_or(FinalFailure::Order)
    }
    pub(super) fn binding(&self, ordinal: usize, kind: FinalStepKind) -> OwnedResult<PhaseBinding> {
        if self.step_kind(ordinal) != Some(kind) { return Err(FinalFailure::Order); }
        PhaseBinding::for_final(self, ordinal).map_err(|_| FinalFailure::Authority)
    }
    pub(crate) fn compile_backend(&self, ordinal: usize) -> OwnedResult<Bytes> {
        if !matches!(self.step_kind(ordinal), Some(FinalStepKind::Compile(_))) {
            return Err(FinalFailure::Order);
        }
        Ok(memory::preparation_backend())
    }
}
