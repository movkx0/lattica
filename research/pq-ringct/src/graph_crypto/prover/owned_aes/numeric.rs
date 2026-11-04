//! Pure numeric request plan. The caller keeps all original claims live.
use super::*;

pub(crate) struct OwnedAesRequestNumbers<'request> {
    pub(super) request: &'request Request,
    pub(super) context: GraphContext,
    pub(super) source_fingerprint: [u8; 32],
    pub(super) compiled_source_fingerprint: [u8; 32],
    pub(super) nodes: Vec<OwnedAesNodeSource>,
    pub(super) steps: Vec<OwnedAesStep>,
    pub(super) slots: OwnedAesSlotRequirements,
    pub(super) root: usize,
}
impl<'request> OwnedAesRequestNumbers<'request> {
    pub(crate) fn derive(request: &'request Request, context: GraphContext, backing: Option<(&Reservation, &Ledger)>) -> Result<Self> {
        Self::derive_with_keys(request, context, backing, None)
    }
    pub(crate) fn derive_with_keys(request: &'request Request, context: GraphContext, backing: Option<(&Reservation, &Ledger)>,
        keys: Option<&crate::graph_crypto::RequestIdentityKeys<'_>>) -> Result<Self>
    {
        Self::derive_prepared(request, context, backing, keys, None)
    }
    pub(crate) fn derive_prepared(request: &'request Request, context: GraphContext, backing: Option<(&Reservation, &Ledger)>,
        keys: Option<&crate::graph_crypto::RequestIdentityKeys<'_>>, leaves: Option<&crate::graph_crypto::RequestLeaves<'_>>) -> Result<Self>
    {
        let keys = keys.map(|keys| keys.for_request(request)).transpose()?;
        // AES has no wrapper layout; its leaf plan uses the case layout only as a sealed tag.
        let leaves = leaves.map(|leaves| leaves.for_aes_request(request)).transpose()?;
        let (leaf_count, node_count, step_count) = counts(request)?;
        let code = crate::graph_proofs::compiled_source_fingerprint();
        let mut hash = Sha3_256::new();
        hash.update(b"lattica/owned-aes-request-source/v1");
        hash.update(code);
        hash.update(context.context);
        for value in context.statement.into_iter().chain(context.node_manifest) {
            hash.update(value.as_canonical_u64().to_le_bytes());
        }
        for index in 0..request.segments().len() {
            hash.update(match keys { Some(keys) => keys[index],
                None => request.cache_key(index).map_err(|_| PairedFailure::Source)? });
        }
        let mut plan = Self { request, context, source_fingerprint: hash.finalize().into(),
            compiled_source_fingerprint: code, nodes: Vec::new(), steps: Vec::new(),
            slots: OwnedAesSlotRequirements::default(), root: 0 };
        plan.nodes.try_reserve_exact(node_count).map_err(|_| PairedFailure::Capacity)?;
        plan.steps.try_reserve_exact(step_count).map_err(|_| PairedFailure::Capacity)?;
        if plan.nodes.capacity() > source::mul(2, node_count)?
            || plan.steps.capacity() > source::mul(2, step_count)? {
            return Err(PairedFailure::Capacity);
        }
        plan.slots.failure = memory::failure_requirements()?;
        plan.slots.endpoint = memory::endpoint_output()?;
        plan.push(OwnedAesStepKind::Endpoints, PhaseKind::EndpointAttach,
            plan.slots.endpoint, requirement(Category::PhaseScratch,
                endpoints::OUTPUT_COPY_FRAME_BYTES)?)?;
        let mut carry = [None; usize::BITS as usize];
        let mut live = 0usize;
        let mut maximum_live = 0usize;
        use crate::component_tree::native_shape::cohort;
        let mut cores = [None; cohort::MAX];
        for index in 0..request.segments().len() {
            let blueprint = source::AesBlueprint::new(request, index)?;
            if leaves.is_none() && index % cohort::MAX == 0 {
                let count = cohort::MAX.min(request.segments().len() - index);
                let mut requests = [blueprint.metadata_request(); cohort::MAX];
                for (offset, slot) in requests[..count].iter_mut().enumerate() {
                    *slot = source::AesBlueprint::new(request, index + offset)?.metadata_request();
                }
                // The original scratch above covers the largest source planner.
                // Consume returned numbers directly, also without a cache scope.
                cores = match backing { Some((scratch, ledger)) => cohort::bounds_exact_in_ledger(&requests[..count], source::construction(), scratch, ledger),
                    None => cohort::bounds_exact(&requests[..count], source::construction()) }
                    .map_err(|_| PairedFailure::Source)?;
            }
            let prepared = leaves.map(|leaves| leaves.aes(index)).transpose()?;
            let leaf_source = match prepared { Some((source, _, _)) => source,
                None => blueprint.inspect_bound(cores[index % cohort::MAX].take().ok_or(PairedFailure::SourceDrift)?)? };
            let segment = request.segments().get(index).ok_or(PairedFailure::Coverage)?;
            let (output, scratch) = match prepared { Some((_, native, _)) => native,
                None => memory::native_requirements(request, index)? };
            plan.slots.native = maxima(plan.slots.native, output);
            plan.push(OwnedAesStepKind::Native { index }, PhaseKind::Native, output, scratch)?;
            let id = plan.nodes.len();
            plan.nodes.push(OwnedAesNodeSource { id,
                span: ComponentSpan {
                    first: u32::try_from(segment.first_unit).map_err(|_| PairedFailure::Overflow)?,
                    count: u32::try_from(segment.units).map_err(|_| PairedFailure::Overflow)?, level: 0 },
                source: leaf_source, children: None, segment: Some(index) });
            let (output, scratch) = match prepared { Some((_, _, compiler)) => compiler,
                None => blueprint.compiler_requirements(leaf_source)? };
            plan.slots.compiled = maxima(plan.slots.compiled, output);
            plan.push(OwnedAesStepKind::Compile { node: id }, PhaseKind::GroupCompile, output,
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
            || plan.nodes.len() != node_count || plan.steps.len() != step_count || live != 1 || leaf_count == 0 {
            return Err(PairedFailure::Coverage);
        }
        // Parent outputs are produced only after compiler phase destroys its
        // two children, so maximum occupied frontier slots already suffices.
        plan.slots.frontier_slots = maximum_live;
        Ok(plan)
    }

    fn push(&mut self, kind: OwnedAesStepKind, phase: PhaseKind, output: Requirements, scratch: Requirements) -> Result<()> {
        if self.steps.len() == self.steps.capacity() { return Err(PairedFailure::Capacity); }
        self.steps.push(OwnedAesStep { kind, facts: PhaseFacts { kind: phase,
            source_fingerprint: self.source_fingerprint,
            compiled_source_fingerprint: self.compiled_source_fingerprint,
            output, failure: self.slots.failure, scratch } });
        Ok(())
    }

    fn push_outer(&mut self, id: usize) -> Result<()> {
        let (output, verifier) = self.nodes.get(id).ok_or(PairedFailure::Order)?.source.output_requirements()?;
        self.slots.node = maxima(self.slots.node, output);
        self.push(OwnedAesStepKind::Outer { node: id }, PhaseKind::OuterProve, output,
            combine(&[verifier, paired_runtime::owned_outer_requirements()?,
                PreissuedAesOuter::planning_scratch_requirement()?])?)
    }

    fn merge(&mut self, left: usize, right: usize) -> Result<usize> {
        let a = *self.nodes.get(left).ok_or(PairedFailure::Order)?;
        let b = *self.nodes.get(right).ok_or(PairedFailure::Order)?;
        let rows = [a.source.maximum_padded_rows, b.source.maximum_padded_rows];
        let source = source::parent_source(rows[0], rows[1])?;
        let id = self.nodes.len();
        if id == self.nodes.capacity() { return Err(PairedFailure::Capacity); }
        self.nodes.push(OwnedAesNodeSource { id, span: ComponentSpan::merge(a.span, b.span)?, source,
            children: Some([left, right]), segment: None });
        let (output, scratch) = source::compiler_requirements(source, source::CompilerGeometry::Parent(rows))?;
        self.slots.compiled = maxima(self.slots.compiled, output);
        self.push(OwnedAesStepKind::Merge { node: id, left, right }, PhaseKind::ParentCompile, output, scratch)?;
        self.push_outer(id)?;
        Ok(id)
    }

}
