//! Pure numeric request plan. The caller keeps all original claims live.
use super::*;

pub(crate) struct PairedRequestNumbers<'request> {
    pub(super) request: &'request Request,
    pub(super) context: GraphContext,
    pub(super) layout: ShakeWrapperLayout,
    pub(super) source_fingerprint: [u8; 32],
    pub(super) compiled_source_fingerprint: [u8; 32],
    pub(super) nodes: Vec<RequestNodeSource>,
    pub(super) steps: Vec<RequestStep>,
    pub(super) slots: RequestSlotRequirements,
    pub(super) root: usize,
}
impl<'request> PairedRequestNumbers<'request> {
    pub(crate) fn derive(request: &'request Request, context: GraphContext, layout: ShakeWrapperLayout) -> Result<Self> {
        Self::derive_with_keys(request, context, layout, None)
    }
    pub(crate) fn derive_with_keys(request: &'request Request, context: GraphContext, layout: ShakeWrapperLayout,
        keys: Option<&crate::graph_crypto::RequestIdentityKeys<'_>>) -> Result<Self>
    {
        let keys = keys.map(|keys| keys.for_request(request)).transpose()?;
        let (leaves, node_count, step_count) = counts(request, layout)?;
        let code = crate::graph_proofs::compiled_source_fingerprint();
        let mut hash = Sha3_256::new();
        hash.update(b"lattica/owned-paired-request-source/v1");
        hash.update(code);
        hash.update(layout.name().as_bytes());
        hash.update(context.context);
        for value in context.statement.into_iter().chain(context.node_manifest) {
            hash.update(value.as_canonical_u64().to_le_bytes());
        }
        for index in 0..request.segments().len() {
            hash.update(match keys { Some(keys) => keys[index],
                None => request.cache_key(index).map_err(|_| PairedFailure::Source)? });
        }
        let mut plan = Self { request, context, layout, source_fingerprint: hash.finalize().into(),
            compiled_source_fingerprint: code, nodes: Vec::new(), steps: Vec::new(),
            slots: RequestSlotRequirements::default(), root: 0 };
        plan.nodes.try_reserve_exact(node_count).map_err(|_| PairedFailure::Capacity)?;
        plan.steps.try_reserve_exact(step_count).map_err(|_| PairedFailure::Capacity)?;
        if plan.nodes.capacity() > source::mul(2, node_count)?
            || plan.steps.capacity() > source::mul(2, step_count)? {
            return Err(PairedFailure::Capacity);
        }
        plan.slots.failure = memory::failure_requirements()?;
        plan.slots.endpoint = memory::endpoint_output()?;
        plan.push(RequestStepKind::Endpoints, PhaseKind::EndpointAttach,
            plan.slots.endpoint, requirement(Category::PhaseScratch,
                endpoints::OUTPUT_COPY_FRAME_BYTES)?)?;
        let mut carry = [None; usize::BITS as usize];
        let mut live = 0usize;
        let mut maximum_live = 0usize;
        for span in request.shake_wrapper_schedule(layout).map_err(|_| PairedFailure::Coverage)?.groups() {
            let leaf_source = source::GroupBlueprint::new(request, span)?.inspect()?;
            for index in span.first_segment..add(span.first_segment, span.segment_count)? {
                let (output, scratch) = memory::native_requirements(request, index)?;
                plan.slots.native = maxima(plan.slots.native, output);
                plan.push(RequestStepKind::Native { index }, PhaseKind::Native, output, scratch)?;
            }
            let id = plan.nodes.len();
            plan.nodes.push(RequestNodeSource { id, span: ComponentSpan::leaf(span)?, source: leaf_source,
                children: None, group: Some(span) });
            let (output, scratch) = source::compiler_requirements(leaf_source, source::CompilerGeometry::Group(span.segment_count))?;
            plan.slots.compiled = maxima(plan.slots.compiled, output);
            plan.push(RequestStepKind::Group { node: id }, PhaseKind::GroupCompile, output,
                combine(&[scratch, endpoints::group_preparation_requirements(request)?.0])?)?;
            plan.push_outer(id)?;
            live = add(live, 1)?;
            maximum_live = maximum_live.max(live);
            let mut value = id;
            let mut level = 0;
            loop {
                let slot = carry.get_mut(level).ok_or(PairedFailure::Overflow)?;
                match slot.take() {
                    None => { *slot = Some(value); break; }
                    Some(left) => { value = plan.merge(left, value)?; live -= 1; level += 1; }
                }
            }
        }
        let mut right = None;
        for left in carry.into_iter().flatten() {
            right = Some(match right {
                None => left,
                Some(right) => { live -= 1; plan.merge(left, right)? }
            });
        }
        plan.root = right.ok_or(PairedFailure::Coverage)?;
        let root = plan.nodes[plan.root];
        if root.span.first != 0 || usize::try_from(root.span.count).ok() != Some(request.units())
            || plan.nodes.len() != node_count || plan.steps.len() != step_count || live != 1 || leaves == 0 {
            return Err(PairedFailure::Coverage);
        }
        // Parent outputs are produced only after compiler phase destroys its
        // two children, so maximum occupied frontier slots already suffices.
        plan.slots.frontier_slots = maximum_live;
        Ok(plan)
    }

    fn push(&mut self, kind: RequestStepKind, phase: PhaseKind, output: Requirements, scratch: Requirements) -> Result<()> {
        if self.steps.len() == self.steps.capacity() { return Err(PairedFailure::Capacity); }
        self.steps.push(RequestStep { kind, facts: PhaseFacts { kind: phase,
            source_fingerprint: self.source_fingerprint,
            compiled_source_fingerprint: self.compiled_source_fingerprint,
            output, failure: self.slots.failure, scratch } });
        Ok(())
    }

    fn push_outer(&mut self, id: usize) -> Result<()> {
        let (output, verifier) = self.nodes.get(id).ok_or(PairedFailure::Order)?.source.output_requirements()?;
        self.slots.node = maxima(self.slots.node, output);
        self.push(RequestStepKind::Outer { node: id }, PhaseKind::OuterProve, output,
            combine(&[verifier, paired_runtime::owned_outer_requirements()?,
                PreissuedPairedOuter::planning_scratch_requirement()?])?)
    }

    fn merge(&mut self, left: usize, right: usize) -> Result<usize> {
        let a = *self.nodes.get(left).ok_or(PairedFailure::Order)?;
        let b = *self.nodes.get(right).ok_or(PairedFailure::Order)?;
        let rows = [a.source.maximum_padded_rows, b.source.maximum_padded_rows];
        let source = source::parent_source(rows[0], rows[1])?;
        let id = self.nodes.len();
        if id == self.nodes.capacity() { return Err(PairedFailure::Capacity); }
        self.nodes.push(RequestNodeSource { id, span: ComponentSpan::merge(a.span, b.span)?, source,
            children: Some([left, right]), group: None });
        let (output, scratch) = source::compiler_requirements(source, source::CompilerGeometry::Parent(rows))?;
        self.slots.compiled = maxima(self.slots.compiled, output);
        self.push(RequestStepKind::Merge { node: id, left, right }, PhaseKind::ParentCompile, output, scratch)?;
        self.push_outer(id)?;
        Ok(id)
    }

}
