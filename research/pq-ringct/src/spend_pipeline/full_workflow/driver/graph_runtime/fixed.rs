use super::*;
pub(crate) struct FixedRuntime<'tables, 'case, 'plans, 'source, 'graph> {
    pub(crate) compilers: &'source FixedPlanTable<'case, 'graph>,
    pub(crate) plans: &'plans FixedOuterPlanTable<'case, 'source, 'graph>,
    pub(crate) compiled: &'tables FixedCompiledOutputs<'case, 'graph>,
    pub(crate) outer: &'tables FixedOuterOutputs<'case, 'graph>,
    pub(crate) packets: &'tables FixedOuterPreissues<'case, 'plans, 'source, 'graph>,
}
impl<'tables, 'case, 'plans, 'source, 'graph> FixedRuntime<'tables, 'case, 'plans, 'source, 'graph> {
    fn plan(&self, ordinal: usize) -> Result<&'plans FixedLeafOuterPlan<'source, 'graph>> {
        plan(self.plans, ordinal)
    }
    fn compiler(&self, ordinal: usize) -> Result<&'source SourceOperationPlan<'graph>> {
        plan(self.compilers, ordinal)
    }
    pub(crate) fn initialize(&self, planning: &mut WorkflowPlanning<'_>,
        metadata: &SourceMetadataPlanningPlan<'_>, case: &CaseRetirementState) -> Result<()>
    {
        let mut guard = InitGuard { planning, completed: false };
        guard.planning.validate_metadata_driver(metadata, case)?;
        let count = metadata.counts().family(ProducerFamily::Fixed);
        original_table(self.compilers, case, count)?;
        original_table(self.plans, case, count)?;
        for ordinal in 0..count {
            if !core::ptr::eq(self.plan(ordinal)?.compiler_plan(), self.compiler(ordinal)?) {
                return Err(WorkflowError::Identity);
            }
        }
        uninitialized_table(self.compiled, case, count)?;
        uninitialized_table(self.outer, case, count)?;
        uninitialized_table(self.packets, case, count)?;
        initialize_table(self.compiled)?;
        initialize_table(self.outer)?;
        initialize_table(self.packets)?;
        guard.planning.validate_metadata_driver(metadata, case)?;
        guard.completed = true; Ok(())
    }
    /// Recheck this exact descriptor on every entry. Whole schedule edge replay
    /// belongs to preflight; current owners are rechecked before each move.
    fn validate_tables(&self, inventory: &ValidatedCompleteInventory<'_, '_>,
        case: &CaseRetirementState) -> Result<()>
    {
        let count = inventory.producer_counts().family(ProducerFamily::Fixed);
        original_table(self.compilers, case, count)?;
        original_table(self.plans, case, count)?;
        original_table(self.compiled, case, count)?;
        original_table(self.outer, case, count)?;
        original_table(self.packets, case, count)?;
        Ok(())
    }
    pub(crate) fn preflight(&self, workflow: &mut WorkflowAdmission<'_, '_>,
        inventory: &ValidatedCompleteInventory<'_, '_>, case: &CaseRetirementState) -> Result<()>
    {
        let mut guard = DriverGuard { workflow, completed: false };
        guard.workflow.validate_driver(inventory, case)?;
        self.validate_tables(inventory, case)?;
        let mut counts = [0usize; 2];
        for (closed_ordinal, (dispatch, step)) in inventory.closed_plan().dispatch().iter().zip(inventory.closed_plan().steps()).enumerate() {
            let ProducerRoute::Fixed { ordinal, phase } = dispatch.producer() else { continue; };
            let index = match phase { GraphPhase::Compile => 0, GraphPhase::Outer => 1 };
            if ordinal != counts[index] { return Err(WorkflowError::Sequence); }
            let compiler = self.compiler(ordinal)?;
            let outer = self.plan(ordinal)?;
            if !core::ptr::eq(outer.compiler_plan(), compiler) { return Err(WorkflowError::Identity); }
            let binding = match phase {
                GraphPhase::Compile => PhaseBinding::for_source(compiler, 0)?,
                GraphPhase::Outer => outer.binding().map_err(|_| WorkflowError::Source)?,
            };
            same_binding(binding, step.binding)?;
            match phase {
                GraphPhase::Compile => expected_edges(inventory, closed_ordinal, dispatch, &[], 0, 0)?,
                GraphPhase::Outer => expected_edges(inventory, closed_ordinal, dispatch,
                    &[Some(PhaseBinding::for_source(compiler, 0)?)], 1, 1)?,
            }
            increment(&mut counts[index])?;
        }
        if counts[0] != counts[1] { return Err(WorkflowError::Sequence); }
        original_table(self.compilers, case, counts[0])?;
        original_table(self.plans, case, counts[0])?;
        empty_table(self.compiled, case, counts[0])?;
        empty_table(self.outer, case, counts[0])?;
        empty_table(self.packets, case, counts[0])?;
        guard.completed = true; Ok(())
    }
    pub(crate) fn preissue(&self, workflow: &mut WorkflowAdmission<'_, '_>,
        inventory: &ValidatedCompleteInventory<'_, '_>, case: &CaseRetirementState,
        closed_ordinal: usize) -> Result<()>
    {
        let mut guard = DriverGuard { workflow, completed: false };
        guard.workflow.validate_driver(inventory, case)?;
        self.validate_tables(inventory, case)?;
        let dispatch = inventory.closed_plan().dispatch().get(closed_ordinal).ok_or(WorkflowError::Sequence)?;
        let ProducerRoute::Fixed { ordinal, phase: GraphPhase::Outer } = dispatch.producer()
            else { return Err(WorkflowError::Identity); };
        let mut target = write(cell(self.packets, ordinal)?)?;
        empty(&target)?;
        *target = Some(guard.workflow.preissue_fixed_leaf_outer(self.plan(ordinal)?));
        ready(&target)?;
        guard.completed = true; Ok(())
    }
    pub(crate) fn execute_step(&self, workflow: &mut WorkflowAdmission<'_, '_>,
        inventory: &ValidatedCompleteInventory<'_, '_>, case: &CaseRetirementState,
        closed_ordinal: usize) -> Result<()>
    {
        let mut guard = DriverGuard { workflow, completed: false };
        let dispatch = guard.workflow.validate_driver_step(inventory, case, closed_ordinal)?;
        self.validate_tables(inventory, case)?;
        let ProducerRoute::Fixed { ordinal, phase } = dispatch.producer()
            else { return Err(WorkflowError::Identity); };
        let plan = self.plan(ordinal)?;
        match phase {
            GraphPhase::Compile => {
                shape(&dispatch, 0, 0)?;
                let mut target = write(cell(self.compiled, ordinal)?)?;
                empty(&target)?;
                let compiler = self.compiler(ordinal)?;
                if !core::ptr::eq(plan.compiler_plan(), compiler) { return Err(WorkflowError::Identity); }
                let operation = compiler.compile().map_err(|_| WorkflowError::Source)?;
                let phase = guard.workflow.next_phase(operation.binding())?;
                *target = Some(phase.compile_fixed_sources(operation));
                ready(&target)?;
            }
            GraphPhase::Outer => {
                shape(&dispatch, 1, 1)?;
                require_input(&dispatch, 0, ProducerRoute::Fixed { ordinal, phase: GraphPhase::Compile })?;
                let mut compiled = write(cell(self.compiled, ordinal)?)?;
                let mut packet = write(cell(self.packets, ordinal)?)?;
                let mut target = write(cell(self.outer, ordinal)?)?;
                empty(&target)?;
                let binding = plan.binding().map_err(|_| WorkflowError::Source)?;
                same_binding(ready(&compiled)?.binding(), PhaseBinding::for_source(plan.compiler_plan(), 0)?)?;
                check_owner(ready(&compiled)?, inventory, closed_ordinal, 0)?;
                same_binding(ready(&packet)?.binding(), binding)?;
                ready(&packet)?.check_before_native().map_err(|_| WorkflowError::Source)?;
                let phase = guard.workflow.next_phase(binding)?;
                let packet_owner = take_ready(&mut packet)?;
                let owner = match take_ready(&mut compiled) {
                    Ok(owner) => owner,
                    Err(error) => { *packet = Some(Ok(packet_owner)); return Err(error); }
                };
                let operation = match plan.outer_operation_retaining(owner) {
                    Ok(operation) => operation,
                    Err((_error, owner)) => {
                        *compiled = Some(Ok(owner)); *packet = Some(Ok(packet_owner));
                        return Err(WorkflowError::Source);
                    }
                };
                *target = Some(phase.prove_owned_fixed_leaf_outer(operation, packet_owner));
                ready(&target)?;
            }
        }
        guard.completed = true; Ok(())
    }
}
