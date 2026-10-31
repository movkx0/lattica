use super::*;
mod ready;

// Additional live state for readiness/count helpers and their callers. The
// enclosing inspection census applies its existing x8 forwarding multiplier.
// Enumerate complete values/results and loop state; assume no inlining or
// optimizer stack reuse. Parent table/program/proof owners remain unchanged.
pub(super) const PARENT_READY_FRAME_BYTES: usize =
    size_of::<&mut SupportedSchedule<'static>>()
    + size_of::<&CompleteProducerTables<'static>>() + size_of::<&Ledger>()
    + size_of::<&mut [usize; PARENT_LEVELS]>() + size_of::<&mut CompleteStage>()
    + size_of::<[usize; 32]>() + size_of::<[core::ops::Range<usize>; 3]>()
    + size_of::<Option<&dyn ParentPlans>>()
    + size_of::<&crate::graph_tree::owned_parent::GraphParentPlan<'static, 'static>>()
    + size_of::<[GraphRecord<'static>; 2]>() + size_of::<[Result<GraphRecord<'static>>; 2]>()
    + size_of::<[&GraphNodeSource<'static>; 4]>()
    + size_of::<[GraphChildSource<'static, 'static>; 3]>()
    + size_of::<[PhaseBinding; 4]>() + size_of::<[Option<PhaseBinding>; 2]>()
    + size_of::<SlotId>() + size_of::<ready::Pair>()
    + size_of::<Option<ready::Pair>>() + size_of::<Result<Option<ready::Pair>>>()
    + size_of::<[Result<usize>; 4]>() + size_of::<[Result<(usize, usize)>; 2]>()
    + size_of::<[Result<PhaseBinding>; 2]>() + size_of::<Result<SlotId>>()
    + size_of::<Result<GraphChildSource<'static, 'static>>>()
    + size_of::<Result<&crate::graph_tree::owned_parent::GraphParentPlan<'static, 'static>>>()
    + size_of::<[bool; 8]>();

fn interval(leaves: usize, level: usize, ordinal: usize) -> Result<(usize, usize)> {
    let block = 1usize.checked_shl(u32::try_from(level).map_err(|_| ClosureError::Overflow)?)
        .ok_or(ClosureError::Overflow)?;
    let first = mul(block, ordinal)?;
    let remaining = leaves.checked_sub(first).filter(|n| *n > 0).ok_or(ClosureError::Coverage)?;
    Ok((first, block.min(remaining)))
}

impl<'a> SupportedSchedule<'a> {
    pub(super) fn append_graph(&mut self, member: usize, child: GraphChildSource<'a, 'a>,
        expected: Option<(usize, usize)>) -> Result<()>
    {
        let prepared = self.members.get(member).ok_or(ClosureError::Order)?.get();
        let node = child.source();
        let span = node.span().interval();
        let binding = child.binding();
        if !core::ptr::eq(node.graph_plan(), prepared.plan()) || !core::ptr::eq(node.context(), prepared.context())
            || node.maximum_height() > 1 << 20 || node.maximum_height() < 8 || !node.maximum_height().is_power_of_two()
            || binding.kind() != PhaseKind::GraphOuter
            || binding.facts().source_fingerprint != node.source_fingerprint()
            || binding.facts().compiled_source_fingerprint != node.compiled_source_fingerprint()
            || binding.facts().compiled_source_fingerprint != self.scope.compiled_source_fingerprint()
            || binding.facts().output != node.output_requirements().map_err(|_| ClosureError::Resource)?.0
            || expected.is_some_and(|expected| span != expected)
            || (expected.is_none() && span.1 != 1)
            || span.1 == 0 || add(span.0, span.1)? > prepared.plan().leaves().len()
            || self.graph_nodes.iter().any(|record| record.child.binding() == binding
                || (record.member == member && record.child.source().span().interval() == span))
        { return Err(ClosureError::Coverage); }
        self.slot_for_binding(binding)?;
        push(&mut self.graph_nodes, GraphRecord { member, child })
    }

    pub(super) fn graph_record(&self, member: usize, interval: (usize, usize)) -> Result<GraphRecord<'a>> {
        let mut matches = self.graph_nodes.iter().filter(|record|
            record.member == member && record.child.source().span().interval() == interval);
        let record = *matches.next().ok_or(ClosureError::Coverage)?;
        if matches.next().is_some() { return Err(ClosureError::Coverage); }
        Ok(record)
    }

    /// Emit only original parent-table entries whose exact child intervals
    /// belong to the already-produced leaf prefix. Each level's global cursor
    /// keeps the original member/pair order expected by runtime preflight.
    pub(super) fn complete_ready_parents(&mut self, tables: &'a CompleteProducerTables<'a>,
        ledger: &Ledger, member: usize, ready_leaves: usize, next: &mut [usize; PARENT_LEVELS],
        stage: &mut CompleteStage) -> Result<()>
    {
        let leaves = self.members.get(member).ok_or(ClosureError::Order)?.get().plan().leaves().len();
        if ready_leaves == 0 || ready_leaves > leaves { return Err(ClosureError::Coverage); }
        for level in 0..PARENT_LEVELS {
            *stage = CompleteStage::Parent { level, member: Some(member),
                ordinal: Some(next[level]), action: "ready_parent_range" };
            let mut first = 0;
            for prior in 0..member {
                first = add(first, ready::count(self.members[prior].get().plan().leaves().len(), level)?)?;
            }
            let end = add(first, ready::count(leaves, level)?)?;
            if next[level] < first || next[level] > end || end > tables.parents.expected[level] {
                return Err(ClosureError::Coverage);
            }
            if next[level] == end { continue; }
            let table = tables.parents.levels[level].ok_or(ClosureError::Coverage)?;
            if table.len() != tables.parents.expected[level] { return Err(ClosureError::Coverage); }
            while next[level] < end {
                let ordinal = next[level];
                *stage = CompleteStage::Parent { level, member: Some(member),
                    ordinal: Some(ordinal), action: "parent_readiness" };
                let pair = ordinal.checked_sub(first).ok_or(ClosureError::Overflow)?;
                let Some(spans) = ready::pair(leaves, level, pair, ready_leaves)? else { break; };
                stage.action("parent_plan");
                let plan = table.plan(ordinal)?;
                stage.action("parent_identity");
                if !plan.belongs_to(ledger) { return Err(ClosureError::Identity); }
                // Readiness is established from the immutable leaf prefix.
                // Missing original children remain a hard coverage error.
                stage.action("left_graph_record");
                let left = self.graph_record(member, spans.left)?;
                stage.action("right_graph_record");
                let right = self.graph_record(member, spans.right)?;
                stage.action("parent_children");
                let children = plan.child_sources();
                if children[0].binding() != left.child.binding()
                    || !core::ptr::eq(children[0].source(), left.child.source())
                    || children[1].binding() != right.child.binding()
                    || !core::ptr::eq(children[1].source(), right.child.source())
                { return Err(ClosureError::Identity); }
                stage.action("parent_coverage");
                if plan.source().span().interval() != spans.parent { return Err(ClosureError::Coverage); }
                let inputs = [Some(left.child.binding()), Some(right.child.binding())];
                stage.action("parent_binding");
                let compile = plan.binding(0).map_err(|_| ClosureError::Source)?;
                if compile.kind() != PhaseKind::GraphParentCompile { return Err(ClosureError::Source); }
                stage.action("parent_dependencies");
                let compiled = self.record_dependencies(compile, &inputs, 2, 2, Bytes::ZERO,
                    ProducerRoute::Parent { level, ordinal, phase: GraphPhase::Compile })?;
                stage.action("parent_outer_source");
                let child = plan.child_source().map_err(|_| ClosureError::Source)?;
                stage.action("parent_outer_record");
                self.record_routed(child.binding(), &[compiled], 1, Bytes::ZERO,
                    ProducerRoute::Parent { level, ordinal, phase: GraphPhase::Outer })?;
                stage.action("parent_append_graph");
                self.append_graph(member, child, Some(spans.parent))?;
                stage.action("parent_ordinal");
                next[level] = add(ordinal, 1)?;
            }
        }
        Ok(())
    }

    pub(super) fn validate_graph_roots(&self, stage: &mut CompleteStage) -> Result<()> {
        for member in 0..self.members.len() {
            *stage = CompleteStage::Member { member: Some(member), family: None,
                ordinal: None, action: "graph_root_record" };
            let record = self.graph_record(member, (0, self.members[member].get().plan().leaves().len()))?;
            stage.action("graph_root_slot");
            self.slot_for_binding(record.child.binding())?;
        }
        Ok(())
    }

    pub(super) fn complete_final(&mut self, plan: &'a FinalPhasePlan<'a>, ledger: &Ledger,
        stage: &mut CompleteStage) -> Result<()> {
        *stage = CompleteStage::Final { step: None, action: "final_plan_identity" };
        if !plan.belongs_to(ledger) || !plan.fresh_only() || !core::ptr::eq(plan.source(), self.final_source)
            || plan.step_count() != add(mul(self.members.len() - 1, 2)?, 1)?
        { return Err(ClosureError::Identity); }
        for member in 0..self.members.len() {
            *stage = CompleteStage::Member { member: Some(member), family: None,
                ordinal: None, action: "final_graph_record" };
            let root = self.graph_record(member, (0, self.members[member].get().plan().leaves().len()))?;
            stage.action("final_graph_binding");
            if plan.graph_binding(member).map_err(|_| ClosureError::Source)? != root.child.binding() {
                return Err(ClosureError::Identity);
            }
        }
        for ordinal in 0..plan.step_count() {
            *stage = CompleteStage::Final { step: Some(ordinal), action: "final_phase_binding" };
            let binding = plan.phase_binding(ordinal).map_err(|_| ClosureError::Source)?;
            stage.action("final_phase_kind");
            let (kind, backend, output) = match plan.step_kind(ordinal).ok_or(ClosureError::Order)? {
                FinalStepKind::Compile(merge) if ordinal == 2 * merge => (PhaseKind::FinalCompile,
                    plan.compile_backend(ordinal).map_err(|_| ClosureError::Resource)?, FinalOutput::Compiled(merge)),
                FinalStepKind::Outer(merge) if ordinal == 2 * merge + 1 => (PhaseKind::FinalOuter,
                    Bytes::ZERO, FinalOutput::Outer(merge)),
                FinalStepKind::Verify if ordinal + 1 == plan.step_count() => (PhaseKind::FinalVerify,
                    Bytes::ZERO, FinalOutput::Verified),
                _ => return Err(ClosureError::Order),
            };
            stage.action("final_phase_identity");
            if binding.kind() != kind { return Err(ClosureError::Source); }
            stage.action("final_dependencies");
            let dependencies = plan.dependencies(ordinal).map_err(|_| ClosureError::Source)?;
            stage.action("final_record");
            self.record_dependencies(binding, &dependencies.bindings, dependencies.count, dependencies.consume,
                backend, ProducerRoute::Final { step: ordinal, output })?;
        }
        // Independent verification borrows its original final root. Both the
        // root and verification report must survive; every other proof/compiler
        // output must have been consumed by a concrete scheduled producer.
        *stage = CompleteStage::Final { step: None, action: "final_verification_slot" };
        let verification = self.slot_for_binding(plan.phase_binding(plan.step_count() - 1)
            .map_err(|_| ClosureError::Source)?)?;
        stage.action("final_root_slot");
        let root = self.slot_for_binding(plan.phase_binding(plan.step_count() - 2)
            .map_err(|_| ClosureError::Source)?)?;
        stage.action("final_live_coverage");
        if root == verification || self.live.iter().enumerate().any(|(index, live)|
            *live && index != root.index() && index != verification.index())
            || self.live.iter().filter(|live| **live).count() != 2
        { return Err(ClosureError::Coverage); }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn odd_graph_tail_carries_its_exact_interval() {
        assert_eq!(interval(5, 0, 4), Ok((4, 1)));
        assert_eq!(interval(5, 1, 2), Ok((4, 1)));
        assert_eq!(interval(5, 2, 1), Ok((4, 1)));
        assert_eq!(interval(5, 2, 0), Ok((0, 4)));
        assert_eq!(interval(5, 3, 0), Ok((0, 5)));
        assert_eq!(interval(5, 1, 3), Err(ClosureError::Coverage));
        assert_eq!(interval(5, usize::BITS as usize, 0), Err(ClosureError::Overflow));
    }
}
